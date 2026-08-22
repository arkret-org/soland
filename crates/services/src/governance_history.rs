use std::sync::Arc;

use arkret_models_collaboration::governance_dependencies::{
    GovernanceDependency, GovernanceDependencyResolveOutcome, GovernanceDependencyResolveRequest,
};
use arkret_models_collaboration::history_key::{
    HistoryKeyResponseAckRequest, HistoryKeyResponseLostRecord, HistoryResponseId,
    OrganizationRecoveryArchiveListQuery, OrganizationRecoveryArchiveReplica,
    OrganizationRecoveryArchiveReplicaOutcome, PeerHistoryTraversalAccess,
    SelfHistoryTraversalAccess,
};
use arkret_wire::{DidCoreId, Event, Hash, HistoryEffectiveScope, RealmId, Seal};
use chrono::{DateTime, Utc};
use soland_storage::{
    ExactWriteOutcome, HistoryRequestPage, HistoryRequestRecord, HistoryRequestWrite,
    HistoryResponseAckTokenWrite, HistoryResponseCompleteOutcome, HistoryResponseCompleteWrite,
    HistoryResponseReadPage, HistoryResponseReservationInput, HistoryResponseReservationRecord,
    HistoryResponseRetryRecord, HistoryTraversalAccess, PendingRrkAcquisitionInput,
    PendingRrkAcquisitionRecord, PersistenceStore, StorageCasOutcome,
};

use crate::{ServiceError, ServiceResult};

const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy)]
enum TraversalCaller<'a> {
    SelfPrincipal(&'a DidCoreId),
    PeerService(&'a DidCoreId),
}

#[derive(Clone)]
pub struct GovernanceHistoryService {
    persistence: Arc<dyn PersistenceStore>,
}

impl GovernanceHistoryService {
    #[must_use]
    pub fn new(persistence: Arc<dyn PersistenceStore>) -> Self {
        Self { persistence }
    }

    pub async fn resolve_self_dependencies(
        &self,
        request: GovernanceDependencyResolveRequest<SelfHistoryTraversalAccess>,
        ordinary_realm_visible: bool,
        caller: &DidCoreId,
        now: DateTime<Utc>,
    ) -> ServiceResult<GovernanceDependencyResolveOutcome> {
        let access = request
            .history_traversal_access
            .clone()
            .map(HistoryTraversalAccess::SelfAccess);
        self.resolve_dependencies(
            request,
            access,
            ordinary_realm_visible,
            Some(TraversalCaller::SelfPrincipal(caller)),
            now,
        )
        .await
    }

    pub async fn resolve_peer_dependencies(
        &self,
        request: GovernanceDependencyResolveRequest<PeerHistoryTraversalAccess>,
        ordinary_realm_visible: bool,
        caller: &DidCoreId,
        now: DateTime<Utc>,
    ) -> ServiceResult<GovernanceDependencyResolveOutcome> {
        let access = request
            .history_traversal_access
            .clone()
            .map(HistoryTraversalAccess::PeerAccess);
        self.resolve_dependencies(
            request,
            access,
            ordinary_realm_visible,
            Some(TraversalCaller::PeerService(caller)),
            now,
        )
        .await
    }

    async fn resolve_dependencies<A>(
        &self,
        request: GovernanceDependencyResolveRequest<A>,
        access: Option<HistoryTraversalAccess>,
        ordinary_realm_visible: bool,
        caller: Option<TraversalCaller<'_>>,
        now: DateTime<Utc>,
    ) -> ServiceResult<GovernanceDependencyResolveOutcome> {
        request
            .validate()
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;

        let retained_dependencies = match access.as_ref() {
            Some(access) => Some(
                self.retained_dependencies(&request.realm_id, access, caller, now)
                    .await?,
            ),
            None if ordinary_realm_visible => None,
            None => Some(Vec::new()),
        };
        let mut items = Vec::new();
        let mut missing_selectors = Vec::new();
        for selector in &request.selectors {
            let item = if let Some(retained) = &retained_dependencies {
                retained
                    .iter()
                    .find(|item| item.selector() == selector)
                    .cloned()
            } else {
                let realm_item = self
                    .persistence
                    .governance_dependencies()
                    .get(&request.realm_id, selector)
                    .await?;
                match realm_item {
                    Some(item) => Some(item),
                    None => {
                        self.persistence
                            .governance_dependencies()
                            .get_unscoped_signer_evidence(selector)
                            .await?
                    }
                }
            };
            match item {
                Some(item) => items.push(item),
                None => missing_selectors.push(selector.clone()),
            }
        }
        let outcome = GovernanceDependencyResolveOutcome {
            items,
            missing_selectors,
        };
        outcome
            .validate()
            .map_err(|error| ServiceError::Internal(error.to_string()))?;
        let encoded = arkret_canonical::canonical_json_bytes(&outcome)
            .map_err(|error| ServiceError::Internal(error.to_string()))?;
        let byte_limit = usize::try_from(request.byte_limit).unwrap_or(usize::MAX);
        if encoded.len() > byte_limit || encoded.len() > MAX_RESPONSE_BYTES {
            return Err(ServiceError::SchemaViolation(
                "limit_exceeded: complete governance dependency outcome exceeds byte_limit"
                    .to_owned(),
            ));
        }
        Ok(outcome)
    }

    async fn retained_dependencies(
        &self,
        realm_id: &arkret_wire::RealmId,
        access: &HistoryTraversalAccess,
        caller: Option<TraversalCaller<'_>>,
        now: DateTime<Utc>,
    ) -> ServiceResult<Vec<GovernanceDependency>> {
        let Some(record) = self
            .retention_for_access(realm_id, access, caller, now)
            .await?
        else {
            return Ok(Vec::new());
        };
        Ok(record
            .write
            .objects
            .into_iter()
            .filter_map(|object| match object {
                soland_storage::HistoryTraversalRetainedObject::GovernanceDependency(item) => {
                    Some(item)
                }
                _ => None,
            })
            .collect())
    }

    pub async fn resolve_self_retained_events(
        &self,
        realm_id: &RealmId,
        access: SelfHistoryTraversalAccess,
        caller: &DidCoreId,
        now: DateTime<Utc>,
    ) -> ServiceResult<Vec<Event>> {
        self.retained_events(
            realm_id,
            HistoryTraversalAccess::SelfAccess(access),
            Some(TraversalCaller::SelfPrincipal(caller)),
            now,
        )
        .await
    }

    pub async fn resolve_self_retained_events_for_access(
        &self,
        access: SelfHistoryTraversalAccess,
        caller: &DidCoreId,
        now: DateTime<Utc>,
    ) -> ServiceResult<Vec<Event>> {
        let access = HistoryTraversalAccess::SelfAccess(access);
        let Some(record) = self
            .retention_record_for_access(&access, Some(TraversalCaller::SelfPrincipal(caller)), now)
            .await?
        else {
            return Ok(Vec::new());
        };
        Ok(record
            .write
            .objects
            .into_iter()
            .filter_map(|object| match object {
                soland_storage::HistoryTraversalRetainedObject::ControlEvent(event) => Some(event),
                _ => None,
            })
            .collect())
    }

    pub async fn resolve_peer_retained_events(
        &self,
        realm_id: &RealmId,
        access: PeerHistoryTraversalAccess,
        caller: &DidCoreId,
        now: DateTime<Utc>,
    ) -> ServiceResult<Vec<Event>> {
        self.retained_events(
            realm_id,
            HistoryTraversalAccess::PeerAccess(access),
            Some(TraversalCaller::PeerService(caller)),
            now,
        )
        .await
    }

    async fn retained_events(
        &self,
        realm_id: &RealmId,
        access: HistoryTraversalAccess,
        caller: Option<TraversalCaller<'_>>,
        now: DateTime<Utc>,
    ) -> ServiceResult<Vec<Event>> {
        let Some(record) = self
            .retention_for_access(realm_id, &access, caller, now)
            .await?
        else {
            return Ok(Vec::new());
        };
        Ok(record
            .write
            .objects
            .into_iter()
            .filter_map(|object| match object {
                soland_storage::HistoryTraversalRetainedObject::ControlEvent(event) => Some(event),
                _ => None,
            })
            .collect())
    }

    pub async fn resolve_self_retained_seals(
        &self,
        realm_id: &RealmId,
        access: SelfHistoryTraversalAccess,
        caller: &DidCoreId,
        now: DateTime<Utc>,
    ) -> ServiceResult<Vec<Seal>> {
        self.retained_seals(
            realm_id,
            HistoryTraversalAccess::SelfAccess(access),
            Some(TraversalCaller::SelfPrincipal(caller)),
            now,
        )
        .await
    }

    pub async fn resolve_peer_retained_seals(
        &self,
        realm_id: &RealmId,
        access: PeerHistoryTraversalAccess,
        caller: &DidCoreId,
        now: DateTime<Utc>,
    ) -> ServiceResult<Vec<Seal>> {
        self.retained_seals(
            realm_id,
            HistoryTraversalAccess::PeerAccess(access),
            Some(TraversalCaller::PeerService(caller)),
            now,
        )
        .await
    }

    async fn retained_seals(
        &self,
        realm_id: &RealmId,
        access: HistoryTraversalAccess,
        caller: Option<TraversalCaller<'_>>,
        now: DateTime<Utc>,
    ) -> ServiceResult<Vec<Seal>> {
        let Some(record) = self
            .retention_for_access(realm_id, &access, caller, now)
            .await?
        else {
            return Ok(Vec::new());
        };
        Ok(record
            .write
            .objects
            .into_iter()
            .filter_map(|object| match object {
                soland_storage::HistoryTraversalRetainedObject::Seal(seal) => Some(seal),
                _ => None,
            })
            .collect())
    }

    async fn retention_for_access(
        &self,
        realm_id: &RealmId,
        access: &HistoryTraversalAccess,
        caller: Option<TraversalCaller<'_>>,
        now: DateTime<Utc>,
    ) -> ServiceResult<Option<soland_storage::HistoryTraversalRetentionRecord>> {
        let Some(record) = self
            .retention_record_for_access(access, caller, now)
            .await?
        else {
            return Ok(None);
        };
        let canonical = soland_storage::history_traversal_canonical(&record.write)?;
        if canonical.realm_id != *realm_id {
            return Ok(None);
        }
        Ok(Some(record))
    }

    async fn retention_record_for_access(
        &self,
        access: &HistoryTraversalAccess,
        caller: Option<TraversalCaller<'_>>,
        now: DateTime<Utc>,
    ) -> ServiceResult<Option<soland_storage::HistoryTraversalRetentionRecord>> {
        let (_, digest) = access.storage_parts();
        let Some(record) = self
            .persistence
            .history_traversal_retentions()
            .get(digest)
            .await?
        else {
            return Ok(None);
        };
        if record.write.access != *access {
            return Ok(None);
        }
        let caller_authorized = match (
            access,
            caller,
            &record.write.retention.traversal_intent,
        ) {
            (
                HistoryTraversalAccess::SelfAccess(
                    SelfHistoryTraversalAccess::RequestReceipt {
                        request_receipt_digest,
                    },
                ),
                Some(TraversalCaller::SelfPrincipal(caller)),
                arkret_models_collaboration::history_key::HistoryGovernanceTraversalIntent::MemberHistoryDelivery { .. },
            ) => self
                .persistence
                .history_response_streams()
                .get_request_by_receipt_digest(request_receipt_digest)
                .await?
                .is_some_and(|request| request.write.request.requester_actor_id == *caller),
            (
                HistoryTraversalAccess::SelfAccess(
                    SelfHistoryTraversalAccess::ArchiveReplica { .. },
                ),
                Some(TraversalCaller::SelfPrincipal(caller)),
                arkret_models_collaboration::history_key::HistoryGovernanceTraversalIntent::OrganizationRecoveryArchive {
                    archive_authorization_tuple,
                    ..
                },
            ) => &archive_authorization_tuple.holder_principal_id == caller,
            (
                HistoryTraversalAccess::PeerAccess(
                    PeerHistoryTraversalAccess::PendingArchiveReplica { .. },
                ),
                Some(TraversalCaller::PeerService(caller)),
                arkret_models_collaboration::history_key::HistoryGovernanceTraversalIntent::OrganizationRecoveryArchive {
                    archive_authorization_tuple,
                    ..
                },
            ) => &archive_authorization_tuple.holder_service_id == caller,
            _ => false,
        };
        if !caller_authorized {
            return Ok(None);
        }
        let canonical = soland_storage::history_traversal_canonical(&record.write)?;
        if canonical.expires_at.is_some_and(|expiry| expiry <= now) {
            return Ok(None);
        }
        Ok(Some(record))
    }

    pub async fn enqueue_rrk_replica(
        &self,
        replica: OrganizationRecoveryArchiveReplica,
        now: DateTime<Utc>,
    ) -> ServiceResult<(Hash, ExactWriteOutcome)> {
        replica
            .validate()
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let archive_replica_digest = proof_free_digest(&replica)?;
        let input = PendingRrkAcquisitionInput {
            acquisition_digest: archive_replica_digest.clone(),
            archive_replica_digest: archive_replica_digest.clone(),
            archive_replica: replica,
            next_attempt_at: now,
        };
        let outcome = self
            .persistence
            .pending_rrk_acquisitions()
            .enqueue_exact(input, now)
            .await?;
        Ok((archive_replica_digest, outcome))
    }

    pub async fn persist_history_traversal_retention(
        &self,
        write: soland_storage::HistoryTraversalRetentionWrite,
    ) -> ServiceResult<ExactWriteOutcome> {
        Ok(self
            .persistence
            .history_traversal_retentions()
            .persist_exact(write)
            .await?)
    }

    pub async fn rrk_acquisition(
        &self,
        acquisition_digest: &Hash,
    ) -> ServiceResult<Option<PendingRrkAcquisitionRecord>> {
        Ok(self
            .persistence
            .pending_rrk_acquisitions()
            .get(acquisition_digest)
            .await?)
    }

    pub async fn list_accepted_rrk(
        &self,
        after_archive_sequence: Option<u64>,
        limit: usize,
    ) -> ServiceResult<Vec<PendingRrkAcquisitionRecord>> {
        Ok(self
            .persistence
            .pending_rrk_acquisitions()
            .list_accepted(after_archive_sequence, limit)
            .await?)
    }

    pub async fn list_accepted_rrk_for_authority(
        &self,
        effective_scope: &HistoryEffectiveScope,
        holder_principal_id: &DidCoreId,
        holder_service_id: &DidCoreId,
        from_epoch: u64,
        to_epoch: u64,
        limit: usize,
    ) -> ServiceResult<Vec<PendingRrkAcquisitionRecord>> {
        Ok(self
            .persistence
            .pending_rrk_acquisitions()
            .list_accepted_for_authority(
                effective_scope,
                holder_principal_id,
                holder_service_id,
                from_epoch,
                to_epoch,
                limit,
            )
            .await?)
    }

    pub async fn list_accepted_rrk_for_archive_query(
        &self,
        query: &OrganizationRecoveryArchiveListQuery,
        holder_principal_id: &DidCoreId,
        after_archive_sequence: Option<u64>,
        limit: usize,
    ) -> ServiceResult<Vec<PendingRrkAcquisitionRecord>> {
        Ok(self
            .persistence
            .pending_rrk_acquisitions()
            .list_accepted_for_archive_query(
                query,
                holder_principal_id,
                after_archive_sequence,
                limit,
            )
            .await?)
    }

    pub async fn claim_due_rrk(
        &self,
        now: DateTime<Utc>,
        claim_token: &str,
        claim_until: DateTime<Utc>,
        limit: usize,
    ) -> ServiceResult<Vec<PendingRrkAcquisitionRecord>> {
        Ok(self
            .persistence
            .pending_rrk_acquisitions()
            .claim_due(now, claim_token, claim_until, limit)
            .await?)
    }

    pub async fn retry_rrk(
        &self,
        acquisition_digest: &Hash,
        claim_token: &str,
        expected_attempt_count: u64,
        next_attempt_at: DateTime<Utc>,
        error_code: &str,
        now: DateTime<Utc>,
    ) -> ServiceResult<StorageCasOutcome> {
        Ok(self
            .persistence
            .pending_rrk_acquisitions()
            .record_retry(
                acquisition_digest,
                claim_token,
                expected_attempt_count,
                next_attempt_at,
                error_code,
                now,
            )
            .await?)
    }

    pub async fn mark_rrk_ready(
        &self,
        acquisition_digest: &Hash,
        claim_token: &str,
        expected_attempt_count: u64,
        ready_at: DateTime<Utc>,
    ) -> ServiceResult<StorageCasOutcome> {
        Ok(self
            .persistence
            .pending_rrk_acquisitions()
            .mark_ready(
                acquisition_digest,
                claim_token,
                expected_attempt_count,
                ready_at,
            )
            .await?)
    }

    pub async fn accept_rrk(
        &self,
        acquisition_digest: &Hash,
        claim_token: &str,
        expected_attempt_count: u64,
        outcome: OrganizationRecoveryArchiveReplicaOutcome,
    ) -> ServiceResult<StorageCasOutcome> {
        Ok(self
            .persistence
            .pending_rrk_acquisitions()
            .mark_accepted(
                acquisition_digest,
                claim_token,
                expected_attempt_count,
                outcome,
            )
            .await?)
    }

    pub async fn store_history_request(
        &self,
        write: HistoryRequestWrite,
    ) -> ServiceResult<soland_storage::HistoryRequestPutOutcome> {
        Ok(self
            .persistence
            .history_response_streams()
            .put_request_exact(write)
            .await?)
    }

    pub async fn history_request_by_id(
        &self,
        request_id: &str,
    ) -> ServiceResult<Option<HistoryRequestRecord>> {
        Ok(self
            .persistence
            .history_response_streams()
            .get_request_by_id(request_id)
            .await?)
    }

    pub async fn history_request_by_digest(
        &self,
        request_digest: &Hash,
    ) -> ServiceResult<Option<HistoryRequestRecord>> {
        Ok(self
            .persistence
            .history_response_streams()
            .get_request_by_digest(request_digest)
            .await?)
    }

    pub async fn history_request_by_capability_commitment(
        &self,
        response_capability_commitment: &Hash,
    ) -> ServiceResult<Option<HistoryRequestRecord>> {
        Ok(self
            .persistence
            .history_response_streams()
            .get_request_by_capability_commitment(response_capability_commitment)
            .await?)
    }

    pub async fn list_history_requests(
        &self,
        effective_scope: &HistoryEffectiveScope,
        after_sequence: Option<u64>,
        limit: usize,
    ) -> ServiceResult<HistoryRequestPage> {
        Ok(self
            .persistence
            .history_response_streams()
            .list_requests(effective_scope, after_sequence, limit)
            .await?)
    }

    pub async fn read_history_response_stream(
        &self,
        response_capability_commitment: &Hash,
        after_cursor: Option<&str>,
        limit: usize,
        now: DateTime<Utc>,
    ) -> ServiceResult<HistoryResponseReadPage> {
        Ok(self
            .persistence
            .history_response_streams()
            .read_response_page(response_capability_commitment, after_cursor, limit, now)
            .await?)
    }

    pub async fn reserve_history_response(
        &self,
        input: HistoryResponseReservationInput,
        reserved_at: DateTime<Utc>,
    ) -> ServiceResult<(ExactWriteOutcome, HistoryResponseReservationRecord)> {
        Ok(self
            .persistence
            .history_response_streams()
            .reserve_response_exact(input, reserved_at)
            .await?)
    }

    pub async fn complete_history_response(
        &self,
        write: HistoryResponseCompleteWrite,
    ) -> ServiceResult<HistoryResponseCompleteOutcome> {
        Ok(self
            .persistence
            .history_response_streams()
            .complete_response_exact(write)
            .await?)
    }

    pub async fn history_response_retry(
        &self,
        response_id: &HistoryResponseId,
    ) -> ServiceResult<Option<HistoryResponseRetryRecord>> {
        Ok(self
            .persistence
            .history_response_streams()
            .response_retry(response_id)
            .await?)
    }

    pub async fn accepted_history_manifest(
        &self,
        request_digest: &Hash,
        manifest_digest: &Hash,
        manifest_admission_digest: &Hash,
    ) -> ServiceResult<Option<soland_storage::HistoryAcceptedManifestRecord>> {
        Ok(self
            .persistence
            .history_response_streams()
            .get_accepted_manifest(request_digest, manifest_digest, manifest_admission_digest)
            .await?)
    }

    pub async fn replace_history_response_with_lost(
        &self,
        response_id: &HistoryResponseId,
        expected_record_digest: &Hash,
        lost_record: HistoryKeyResponseLostRecord,
        signer_dependencies: Vec<
            arkret_models_collaboration::governance_dependencies::GovernanceDependency,
        >,
    ) -> ServiceResult<ExactWriteOutcome> {
        Ok(self
            .persistence
            .history_response_streams()
            .replace_response_with_lost_exact(
                response_id,
                expected_record_digest,
                lost_record,
                signer_dependencies,
            )
            .await?)
    }

    pub async fn store_history_ack_token(
        &self,
        response_capability_commitment: &Hash,
        write: HistoryResponseAckTokenWrite,
        now: DateTime<Utc>,
    ) -> ServiceResult<ExactWriteOutcome> {
        Ok(self
            .persistence
            .history_response_streams()
            .put_ack_token_exact(response_capability_commitment, write, now)
            .await?)
    }

    pub async fn ack_history_response_stream(
        &self,
        response_capability_commitment: &Hash,
        request: &HistoryKeyResponseAckRequest,
        now: DateTime<Utc>,
    ) -> ServiceResult<String> {
        Ok(self
            .persistence
            .history_response_streams()
            .ack_response_stream(response_capability_commitment, request, now)
            .await?)
    }
}

fn proof_free_digest(replica: &OrganizationRecoveryArchiveReplica) -> ServiceResult<Hash> {
    soland_storage::rrk_archive_replica_digest(replica).map_err(ServiceError::from)
}
