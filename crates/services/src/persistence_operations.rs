use std::sync::Arc;

use serde_json::Value;
use soland_storage::*;

use crate::federation::FederationService;
use crate::governance::{GovernanceService, RuntimeSettingsPort};
use crate::jobs::{JobsService, RuntimeHealthPort};
use crate::sync::SyncService;

struct PersistenceFederationOutbox(Arc<dyn PersistenceStore>);
struct PersistenceAuditLog(Arc<dyn PersistenceStore>);
struct PersistenceModeration(Arc<dyn PersistenceStore>);
struct PersistenceGovernanceRecords(Arc<dyn PersistenceStore>);
struct PersistenceCursorStore(Arc<dyn PersistenceStore>);
struct PersistenceWebsocketAuth(Arc<dyn PersistenceStore>);
struct PersistenceMaintenance(Arc<dyn PersistenceStore>);

fn federation_delivery_record(
    record: crate::federation::FederationDeliveryRecord,
) -> FederationOutboxRecord {
    let coalescing_key = record.coalescing_key.clone();
    let coalescing_position = record.coalescing_position;
    let mut persisted = match record.realm_fanout {
        Some(binding) => FederationOutboxRecord::realm_fanout(RealmFanoutOutboxInput {
            id: record.id,
            peer_service_id: record.peer_service_id,
            peer_url: record.peer_url,
            endpoint: record.endpoint,
            idempotency_key: record.idempotency_key,
            payload_json: record.payload_json,
            binding,
            created_at: record.created_at,
        }),
        None => FederationOutboxRecord::pending(
            record.id,
            record.peer_service_id,
            record
                .peer_url
                .expect("generic federation delivery requires a route"),
            record.endpoint,
            record.idempotency_key,
            record.payload_json,
            record.created_at,
        ),
    };
    persisted.coalescing_key = coalescing_key;
    persisted.coalescing_position = coalescing_position;
    persisted
}

fn application_delivery_record(
    record: &FederationOutboxRecord,
) -> crate::federation::FederationDeliveryRecord {
    crate::federation::FederationDeliveryRecord {
        id: record.id.clone(),
        peer_service_id: record.peer_service_id.clone(),
        peer_url: record.peer_url.clone(),
        endpoint: record.endpoint.clone(),
        idempotency_key: record.idempotency_key.clone(),
        payload_json: record.payload_json.clone(),
        coalescing_key: record.coalescing_key.clone(),
        coalescing_position: record.coalescing_position,
        realm_fanout: record.realm_fanout.clone(),
        created_at: record.created_at,
    }
}

fn application_pending_delivery(
    record: FederationOutboxRecord,
) -> crate::federation::PendingFederationDelivery {
    crate::federation::PendingFederationDelivery {
        delivery: application_delivery_record(&record),
        state: record.state,
        leased_from_state: record.leased_from_state,
        attempts: record.attempts,
        semantic_attempts: record.semantic_attempts,
        next_attempt_at: record.next_attempt_at,
        last_http_status: record.last_http_status,
        last_error_code: record.last_error_code,
        last_response_excerpt: record.last_response_excerpt,
        lease_owner: record.lease_owner,
        lease_token: record.lease_token,
        lease_expires_at: record.lease_expires_at,
        policy_version: record.policy_version,
        supersedes_outbox_id: record.supersedes_outbox_id,
        completed_at: record.completed_at,
    }
}

fn application_dead_letter(
    record: FederationOutboxDeadLetterRecord,
) -> crate::federation::FederationDeadLetter {
    crate::federation::FederationDeadLetter {
        id: record.id,
        outbox_id: record.outbox_id,
        peer_service_id: record.peer_service_id,
        endpoint: record.endpoint,
        idempotency_key: record.idempotency_key,
        last_http_status: record.last_http_status,
        attempts: record.attempts,
        response_excerpt: record.response_excerpt,
        reason: record.reason,
        failed_at: record.failed_at,
        requeued_outbox_id: record.requeued_outbox_id,
        requeued_by: record.requeued_by,
        requeue_reason: record.requeue_reason,
        requeue_request_digest: record.requeue_request_digest,
        requeued_at: record.requeued_at,
    }
}

fn persistence_dead_letter(
    record: &crate::federation::FederationDeadLetter,
) -> FederationOutboxDeadLetterRecord {
    FederationOutboxDeadLetterRecord {
        id: record.id.clone(),
        outbox_id: record.outbox_id.clone(),
        peer_service_id: record.peer_service_id.clone(),
        endpoint: record.endpoint.clone(),
        idempotency_key: record.idempotency_key.clone(),
        last_http_status: record.last_http_status,
        attempts: record.attempts,
        response_excerpt: record.response_excerpt.clone(),
        reason: record.reason.clone(),
        failed_at: record.failed_at,
        requeued_outbox_id: record.requeued_outbox_id.clone(),
        requeued_by: record.requeued_by.clone(),
        requeue_reason: record.requeue_reason.clone(),
        requeue_request_digest: record.requeue_request_digest.clone(),
        requeued_at: record.requeued_at,
    }
}

fn application_frontier_exchange(
    record: soland_storage::FederationFrontierExchangeRecord,
) -> crate::federation::FederationFrontierExchangeRecord {
    crate::federation::FederationFrontierExchangeRecord {
        realm_id: record.realm_id,
        peer_service_id: record.peer_service_id,
        status: record.status,
        consecutive_failures: record.consecutive_failures,
        last_success_at: record.last_success_at,
        last_failure_at: record.last_failure_at,
        last_frontier_root: record.last_frontier_root,
        last_error: record.last_error,
        updated_at: record.updated_at,
    }
}

#[async_trait::async_trait]
impl crate::federation::FederationOutboxPort for PersistenceFederationOutbox {
    async fn enqueue(
        &self,
        delivery: &crate::federation::FederationDeliveryRecord,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .0
            .federation_outbox()
            .enqueue(&federation_delivery_record(delivery.clone()))
            .await?)
    }

    async fn find(
        &self,
        peer_service_id: &arkret_identifiers::DidCoreId,
        idempotency_key: &str,
    ) -> crate::ServiceResult<Option<crate::federation::FederationDeliveryRecord>> {
        Ok(self
            .0
            .federation_outbox()
            .snapshot_all()
            .await?
            .into_iter()
            .find(|row| {
                &row.peer_service_id == peer_service_id && row.idempotency_key == idempotency_key
            })
            .map(|row| application_delivery_record(&row)))
    }

    async fn claim_due(
        &self,
        command: &crate::federation::ClaimFederationDeliveriesCommand,
    ) -> crate::ServiceResult<Vec<crate::federation::PendingFederationDelivery>> {
        Ok(self
            .0
            .federation_outbox()
            .claim_due(&FederationOutboxClaim {
                now_unix_secs: command.now,
                limit: command.limit,
                lease_owner: command.lease_owner.clone(),
                lease_token: command.lease_token.clone(),
                lease_duration_secs: command.lease_duration_secs,
            })
            .await?
            .into_iter()
            .map(application_pending_delivery)
            .collect())
    }

    async fn record_attempt(
        &self,
        command: &crate::federation::RecordFederationAttemptCommand,
    ) -> crate::ServiceResult<bool> {
        let outcome = match &command.outcome {
            crate::federation::FederationDeliveryOutcome::Retry { next_attempt_at } => {
                FederationOutboxOutcome::Retry {
                    next_attempt_at: *next_attempt_at,
                }
            }
            crate::federation::FederationDeliveryOutcome::RouteUnavailable { next_attempt_at } => {
                FederationOutboxOutcome::RouteUnavailable {
                    next_attempt_at: *next_attempt_at,
                }
            }
            crate::federation::FederationDeliveryOutcome::Delivered => {
                FederationOutboxOutcome::Delivered
            }
            crate::federation::FederationDeliveryOutcome::CancelledAuthorityLost => {
                FederationOutboxOutcome::CancelledAuthorityLost
            }
            crate::federation::FederationDeliveryOutcome::PolicySuppressed { policy_version } => {
                FederationOutboxOutcome::PolicySuppressed {
                    policy_version: policy_version.clone(),
                }
            }
            crate::federation::FederationDeliveryOutcome::DeadLettered(record) => {
                FederationOutboxOutcome::DeadLettered(Box::new(persistence_dead_letter(record)))
            }
            crate::federation::FederationDeliveryOutcome::Superseded {
                delivery,
                next_attempt_at,
            } => {
                let mut successor = federation_delivery_record((**delivery).clone());
                successor.semantic_attempts = command.semantic_attempts;
                successor.supersedes_outbox_id = Some(command.id.clone());
                successor.next_attempt_at = *next_attempt_at;
                FederationOutboxOutcome::Superseded(Box::new(successor))
            }
        };
        Ok(self
            .0
            .federation_outbox()
            .complete(&FederationOutboxTransition {
                id: command.id.clone(),
                lease_token: command.lease_token.clone(),
                attempts: command.attempts,
                semantic_attempts: command.semantic_attempts,
                last_http_status: command.last_http_status,
                last_error_code: command.last_error_code.clone(),
                last_response_excerpt: command.last_response_excerpt.clone(),
                observed_at: command.observed_at,
                outcome,
            })
            .await?)
    }

    async fn policy_suppressed_stale(
        &self,
        current_policy_version: &str,
        limit: usize,
    ) -> crate::ServiceResult<Vec<crate::federation::PendingFederationDelivery>> {
        Ok(self
            .0
            .federation_outbox()
            .policy_suppressed_stale(current_policy_version, limit)
            .await?
            .into_iter()
            .map(application_pending_delivery)
            .collect())
    }

    async fn resolve_policy_suppressed(
        &self,
        id: &str,
        resolution: &soland_storage::FederationOutboxPolicyResolution,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .0
            .federation_outbox()
            .resolve_policy_suppressed(id, resolution)
            .await?)
    }

    async fn delivery(
        &self,
        id: &str,
    ) -> crate::ServiceResult<Option<crate::federation::PendingFederationDelivery>> {
        Ok(self
            .0
            .federation_outbox()
            .get(id)
            .await?
            .map(application_pending_delivery))
    }

    async fn deliveries_for_event(
        &self,
        event_id: &str,
    ) -> crate::ServiceResult<Vec<crate::federation::PendingFederationDelivery>> {
        Ok(self
            .0
            .events()
            .federation_outbox_for_event(event_id)
            .await?
            .into_iter()
            .map(application_pending_delivery)
            .collect())
    }

    async fn deliveries_by_state(
        &self,
        state: soland_storage::FederationOutboxState,
        limit: usize,
    ) -> crate::ServiceResult<Vec<crate::federation::PendingFederationDelivery>> {
        Ok(self
            .0
            .federation_outbox()
            .list_by_state(state, limit)
            .await?
            .into_iter()
            .map(application_pending_delivery)
            .collect())
    }

    async fn state_depth(
        &self,
    ) -> crate::ServiceResult<Vec<soland_storage::FederationOutboxStateDepth>> {
        Ok(self.0.federation_outbox().state_depth().await?)
    }

    async fn dead_letter(
        &self,
        id: &str,
    ) -> crate::ServiceResult<Option<crate::federation::FederationDeadLetter>> {
        Ok(self
            .0
            .federation_outbox()
            .dead_letter(id)
            .await?
            .map(application_dead_letter))
    }

    async fn dead_letters(
        &self,
    ) -> crate::ServiceResult<Vec<crate::federation::FederationDeadLetter>> {
        Ok(self
            .0
            .federation_outbox()
            .dead_letters_snapshot()
            .await?
            .into_iter()
            .map(application_dead_letter)
            .collect())
    }

    async fn requeue_dead_letter(
        &self,
        command: &crate::federation::RequeueFederationDeadLetterCommand,
    ) -> crate::ServiceResult<bool> {
        let mut record = federation_delivery_record(command.delivery.clone());
        record.supersedes_outbox_id = Some(command.supersedes_outbox_id.clone());
        Ok(self
            .0
            .federation_outbox()
            .requeue_dead_letter(&FederationOutboxRequeue {
                dead_letter_id: command.dead_letter_id.clone(),
                record,
                operator: command.operator.clone(),
                reason: command.reason.clone(),
                request_digest: command.request_digest.clone(),
                requeued_at: command.requeued_at,
            })
            .await?)
    }

    async fn deliveries(
        &self,
    ) -> crate::ServiceResult<Vec<crate::federation::PendingFederationDelivery>> {
        Ok(self
            .0
            .federation_outbox()
            .snapshot_all()
            .await?
            .into_iter()
            .map(application_pending_delivery)
            .collect())
    }
}

#[async_trait::async_trait]
impl crate::federation::FederationStatePort for PersistenceFederationOutbox {
    async fn append_operation(
        &self,
        operation: arkret_event_draft::ProjectedEventOperation,
    ) -> crate::ServiceResult<()> {
        self.0.federation_operations().append(operation).await?;
        Ok(())
    }
    async fn has_operation(&self, operation_id: &str) -> crate::ServiceResult<bool> {
        Ok(self
            .0
            .federation_operations()
            .contains(operation_id)
            .await?)
    }
    async fn operations_for_realm(
        &self,
        realm_id: &str,
    ) -> crate::ServiceResult<Vec<arkret_event_draft::ProjectedEventOperation>> {
        Ok(self
            .0
            .federation_operations()
            .list_for_realm(realm_id)
            .await?)
    }
    async fn operations(
        &self,
    ) -> crate::ServiceResult<Vec<arkret_event_draft::ProjectedEventOperation>> {
        Ok(self.0.federation_operations().snapshot_all().await?)
    }
    async fn frontier_exchange(
        &self,
        realm_id: &str,
        peer_service_id: &arkret_identifiers::DidCoreId,
    ) -> crate::ServiceResult<Option<crate::federation::FederationFrontierExchangeRecord>> {
        Ok(self
            .0
            .federation_frontier_exchange()
            .get(realm_id, peer_service_id)
            .await?
            .map(application_frontier_exchange))
    }
    async fn record_frontier_success(
        &self,
        realm_id: &str,
        peer_service_id: &arkret_identifiers::DidCoreId,
        frontier_root: &str,
        observed_at: i64,
    ) -> crate::ServiceResult<crate::federation::FederationFrontierExchangeRecord> {
        Ok(application_frontier_exchange(
            self.0
                .federation_frontier_exchange()
                .record_success(realm_id, peer_service_id, frontier_root, observed_at)
                .await?,
        ))
    }
    async fn record_frontier_failure(
        &self,
        realm_id: &str,
        peer_service_id: &arkret_identifiers::DidCoreId,
        reason: &str,
        observed_at: i64,
    ) -> crate::ServiceResult<crate::federation::FederationFrontierExchangeRecord> {
        Ok(application_frontier_exchange(
            self.0
                .federation_frontier_exchange()
                .record_failure(realm_id, peer_service_id, reason, observed_at)
                .await?,
        ))
    }
}

#[async_trait::async_trait]
impl crate::governance::AuditLogPort for PersistenceAuditLog {
    async fn append(&self, entry: Value) -> crate::ServiceResult<()> {
        self.0.audit().append(entry).await?;
        Ok(())
    }

    async fn entries(&self) -> crate::ServiceResult<Vec<Value>> {
        Ok(self.0.audit().snapshot_all().await?)
    }

    async fn entries_for_actor(&self, actor_id: &str) -> crate::ServiceResult<Vec<Value>> {
        Ok(self.0.audit().list_for_actor(actor_id).await?)
    }
}

#[async_trait::async_trait]
impl crate::governance::ModerationPort for PersistenceModeration {
    async fn append_report(&self, report: Value) -> crate::ServiceResult<()> {
        self.0.moderation().append_report(report).await?;
        Ok(())
    }
    async fn reports(&self) -> crate::ServiceResult<Vec<Value>> {
        Ok(self.0.moderation().list_reports().await?)
    }
    async fn upsert_queue_item(&self, item: Value) -> crate::ServiceResult<()> {
        self.0.moderation().upsert_queue_item(item).await?;
        Ok(())
    }
    async fn queue_items(&self) -> crate::ServiceResult<Vec<Value>> {
        Ok(self.0.moderation().list_queue_items().await?)
    }
    async fn queue_item(&self, id: &str) -> crate::ServiceResult<Option<Value>> {
        Ok(self.0.moderation().get_queue_item(id).await?)
    }
    async fn append_appeal(&self, appeal: Value) -> crate::ServiceResult<()> {
        self.0.moderation().append_appeal(appeal).await?;
        Ok(())
    }
    async fn appeals(&self) -> crate::ServiceResult<Vec<Value>> {
        Ok(self.0.moderation().list_appeals().await?)
    }
    async fn appeal_history(&self, appeal_id: &str) -> crate::ServiceResult<Vec<Value>> {
        Ok(self.0.moderation().appeal_history(appeal_id).await?)
    }
}

fn application_organization(
    row: soland_storage::OrganizationRecord,
) -> crate::governance::OrganizationRecord {
    crate::governance::OrganizationRecord {
        organization_id: row.organization_id,
        organization_principal_id: row.organization_principal_id,
        handle: row.handle,
        display_name: row.display_name,
        source_refs: row.source_refs,
        policy_revision: row.policy_revision,
        verified: row.verified,
        members: row.members,
        member_count: row.member_count,
        created_by: row.created_by,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

fn persistence_organization(
    row: &crate::governance::OrganizationRecord,
) -> soland_storage::OrganizationRecord {
    soland_storage::OrganizationRecord {
        organization_id: row.organization_id.clone(),
        organization_principal_id: row.organization_principal_id.clone(),
        handle: row.handle.clone(),
        display_name: row.display_name.clone(),
        source_refs: row.source_refs.clone(),
        policy_revision: row.policy_revision.clone(),
        verified: row.verified,
        members: row.members.clone(),
        member_count: row.member_count,
        created_by: row.created_by.clone(),
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

fn application_organization_policy(
    row: soland_storage::OrganizationPolicyRecord,
) -> crate::governance::OrganizationPolicyRecord {
    crate::governance::OrganizationPolicyRecord {
        organization_id: row.organization_id,
        policy_id: row.policy_id,
        payload: row.payload,
        version: row.version,
        updated_by: row.updated_by,
        updated_at: row.updated_at,
    }
}

fn persistence_organization_policy(
    row: &crate::governance::OrganizationPolicyRecord,
) -> soland_storage::OrganizationPolicyRecord {
    soland_storage::OrganizationPolicyRecord {
        organization_id: row.organization_id.clone(),
        policy_id: row.policy_id.clone(),
        payload: row.payload.clone(),
        version: row.version,
        updated_by: row.updated_by.clone(),
        updated_at: row.updated_at,
    }
}

fn application_policy_document(
    row: soland_storage::PolicyDocumentRecord,
) -> crate::governance::PolicyDocumentRecord {
    crate::governance::PolicyDocumentRecord {
        policy_id: row.policy_id,
        owner: row.owner,
        scope: row.scope,
        subject_ref: row.subject_ref,
        policy_kind: row.policy_kind,
        payload: row.payload,
        active: row.active,
        updated_at: row.updated_at,
    }
}

fn persistence_policy_document(
    row: crate::governance::PolicyDocumentRecord,
) -> soland_storage::PolicyDocumentRecord {
    soland_storage::PolicyDocumentRecord {
        policy_id: row.policy_id,
        owner: row.owner,
        scope: row.scope,
        subject_ref: row.subject_ref,
        policy_kind: row.policy_kind,
        payload: row.payload,
        active: row.active,
        updated_at: row.updated_at,
    }
}

fn application_retention_policy(
    row: soland_storage::RetentionPolicyRecord,
) -> crate::governance::RetentionPolicyRecord {
    crate::governance::RetentionPolicyRecord {
        realm_id: row.realm_id,
        ttl_seconds: row.ttl_seconds,
        updated_by: row.updated_by,
        updated_at: row.updated_at,
    }
}

fn persistence_retention_policy(
    row: &crate::governance::RetentionPolicyRecord,
) -> soland_storage::RetentionPolicyRecord {
    soland_storage::RetentionPolicyRecord {
        realm_id: row.realm_id.clone(),
        ttl_seconds: row.ttl_seconds,
        updated_by: row.updated_by.clone(),
        updated_at: row.updated_at,
    }
}

fn application_retention_tombstone(
    row: soland_storage::RetentionTombstoneRecord,
) -> crate::governance::RetentionTombstoneRecord {
    crate::governance::RetentionTombstoneRecord {
        event_id: row.event_id,
        realm_id: row.realm_id,
        reason: row.reason,
        policy_ttl_seconds: row.policy_ttl_seconds,
        expired_at: row.expired_at,
        tombstoned_at: row.tombstoned_at,
        sealed: row.sealed,
    }
}

fn persistence_retention_tombstone(
    row: &crate::governance::RetentionTombstoneRecord,
) -> soland_storage::RetentionTombstoneRecord {
    soland_storage::RetentionTombstoneRecord {
        event_id: row.event_id.clone(),
        realm_id: row.realm_id.clone(),
        reason: row.reason.clone(),
        policy_ttl_seconds: row.policy_ttl_seconds,
        expired_at: row.expired_at,
        tombstoned_at: row.tombstoned_at,
        sealed: row.sealed,
    }
}

fn application_multisig_pending(
    row: soland_storage::MultisigPendingRecord,
) -> crate::governance::MultisigPendingRecord {
    crate::governance::MultisigPendingRecord {
        seal_id: row.seal_id,
        realm_id: row.realm_id,
        digest_suite: row.digest_suite,
        threshold_k: row.threshold_k,
        threshold_n: row.threshold_n,
        members: row.members,
        canonical_b64: row.canonical_b64,
        partials: row.partials,
        created_at: row.created_at,
        expires_at: row.expires_at,
        claimed_by_node_id: row.claimed_by_node_id,
        claimed_until: row.claimed_until,
        claim_seq: row.claim_seq,
    }
}

fn persistence_multisig_pending(
    row: crate::governance::MultisigPendingRecord,
) -> soland_storage::MultisigPendingRecord {
    soland_storage::MultisigPendingRecord {
        seal_id: row.seal_id,
        realm_id: row.realm_id,
        digest_suite: row.digest_suite,
        threshold_k: row.threshold_k,
        threshold_n: row.threshold_n,
        members: row.members,
        canonical_b64: row.canonical_b64,
        partials: row.partials,
        created_at: row.created_at,
        expires_at: row.expires_at,
        claimed_by_node_id: row.claimed_by_node_id,
        claimed_until: row.claimed_until,
        claim_seq: row.claim_seq,
    }
}

#[async_trait::async_trait]
impl crate::governance::GovernanceRecordsPort for PersistenceGovernanceRecords {
    async fn organization(
        &self,
        organization_id: &str,
    ) -> crate::ServiceResult<Option<crate::governance::OrganizationRecord>> {
        Ok(self
            .0
            .organizations()
            .get(organization_id)
            .await?
            .map(application_organization))
    }

    async fn store_organization(
        &self,
        record: &crate::governance::OrganizationRecord,
    ) -> crate::ServiceResult<()> {
        self.0
            .organizations()
            .put(&persistence_organization(record))
            .await?;
        Ok(())
    }

    async fn organizations(
        &self,
    ) -> crate::ServiceResult<Vec<crate::governance::OrganizationRecord>> {
        Ok(self
            .0
            .organizations()
            .list()
            .await?
            .into_iter()
            .map(application_organization)
            .collect())
    }

    async fn organization_policy(
        &self,
        organization_id: &str,
    ) -> crate::ServiceResult<Option<crate::governance::OrganizationPolicyRecord>> {
        Ok(self
            .0
            .organization_policies()
            .get(organization_id)
            .await?
            .map(application_organization_policy))
    }

    async fn store_organization_policy(
        &self,
        record: &crate::governance::OrganizationPolicyRecord,
    ) -> crate::ServiceResult<()> {
        self.0
            .organization_policies()
            .put(&persistence_organization_policy(record))
            .await?;
        Ok(())
    }

    async fn organization_policies(
        &self,
    ) -> crate::ServiceResult<Vec<crate::governance::OrganizationPolicyRecord>> {
        Ok(self
            .0
            .organization_policies()
            .snapshot_all()
            .await?
            .into_iter()
            .map(application_organization_policy)
            .collect())
    }

    async fn link_realm_organization(
        &self,
        realm_id: &str,
        organization_id: &str,
    ) -> crate::ServiceResult<()> {
        self.0
            .realm_organizations()
            .link(realm_id, organization_id)
            .await?;
        Ok(())
    }

    async fn realm_organization_links(
        &self,
    ) -> crate::ServiceResult<Vec<(String, std::collections::BTreeSet<String>)>> {
        Ok(self.0.realm_organizations().snapshot_all().await?)
    }

    async fn policy_document(
        &self,
        policy_id: &str,
    ) -> crate::ServiceResult<Option<crate::governance::PolicyDocumentRecord>> {
        Ok(self
            .0
            .policy_documents()
            .get(policy_id)
            .await?
            .map(application_policy_document))
    }

    async fn store_policy_document(
        &self,
        record: crate::governance::PolicyDocumentRecord,
    ) -> crate::ServiceResult<()> {
        self.0
            .policy_documents()
            .put(persistence_policy_document(record))
            .await?;
        Ok(())
    }

    async fn delete_policy_document(&self, policy_id: &str) -> crate::ServiceResult<bool> {
        Ok(self.0.policy_documents().delete(policy_id).await?)
    }

    async fn policy_documents_for_owner(
        &self,
        owner: &str,
    ) -> crate::ServiceResult<Vec<crate::governance::PolicyDocumentRecord>> {
        Ok(self
            .0
            .policy_documents()
            .list_for_owner(owner)
            .await?
            .into_iter()
            .map(application_policy_document)
            .collect())
    }

    async fn policy_documents(
        &self,
    ) -> crate::ServiceResult<Vec<crate::governance::PolicyDocumentRecord>> {
        Ok(self
            .0
            .policy_documents()
            .snapshot_all()
            .await?
            .into_iter()
            .map(application_policy_document)
            .collect())
    }

    async fn active_policy_documents(
        &self,
    ) -> crate::ServiceResult<Vec<crate::governance::PolicyDocumentRecord>> {
        Ok(self
            .0
            .policy_documents()
            .list_active()
            .await?
            .into_iter()
            .map(application_policy_document)
            .collect())
    }

    async fn retention_policy(
        &self,
        realm_id: &str,
    ) -> crate::ServiceResult<Option<crate::governance::RetentionPolicyRecord>> {
        Ok(self
            .0
            .retention_policies()
            .get(realm_id)
            .await?
            .map(application_retention_policy))
    }

    async fn store_retention_policy(
        &self,
        record: &crate::governance::RetentionPolicyRecord,
    ) -> crate::ServiceResult<()> {
        self.0
            .retention_policies()
            .put(&persistence_retention_policy(record))
            .await?;
        Ok(())
    }

    async fn retention_tombstone(
        &self,
        event_id: &str,
    ) -> crate::ServiceResult<Option<crate::governance::RetentionTombstoneRecord>> {
        Ok(self
            .0
            .retention_tombstones()
            .get(event_id)
            .await?
            .map(application_retention_tombstone))
    }

    async fn retention_tombstones(
        &self,
    ) -> crate::ServiceResult<Vec<crate::governance::RetentionTombstoneRecord>> {
        Ok(self
            .0
            .retention_tombstones()
            .snapshot_all()
            .await?
            .into_iter()
            .map(application_retention_tombstone)
            .collect())
    }

    async fn store_retention_tombstone(
        &self,
        record: &crate::governance::RetentionTombstoneRecord,
    ) -> crate::ServiceResult<()> {
        self.0
            .retention_tombstones()
            .put(&persistence_retention_tombstone(record))
            .await?;
        Ok(())
    }

    async fn multisig_pending(
        &self,
        seal_id: &str,
    ) -> crate::ServiceResult<Option<crate::governance::MultisigPendingRecord>> {
        Ok(self
            .0
            .multisig_pending()
            .get(seal_id)
            .await?
            .map(application_multisig_pending))
    }

    async fn store_multisig_pending(
        &self,
        record: crate::governance::MultisigPendingRecord,
    ) -> crate::ServiceResult<()> {
        self.0
            .multisig_pending()
            .upsert(persistence_multisig_pending(record))
            .await?;
        Ok(())
    }

    async fn multisig_pending_for_realm(
        &self,
        realm_id: &str,
    ) -> crate::ServiceResult<Vec<crate::governance::MultisigPendingRecord>> {
        Ok(self
            .0
            .multisig_pending()
            .list_for_realm(realm_id)
            .await?
            .into_iter()
            .map(application_multisig_pending)
            .collect())
    }

    async fn multisig_pending_all(
        &self,
    ) -> crate::ServiceResult<Vec<crate::governance::MultisigPendingRecord>> {
        Ok(self
            .0
            .multisig_pending()
            .snapshot_all()
            .await?
            .into_iter()
            .map(application_multisig_pending)
            .collect())
    }

    async fn claim_multisig_pending(
        &self,
        seal_id: &str,
        node_id: &str,
        now: chrono::DateTime<chrono::Utc>,
        claimed_until: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<(bool, i64)> {
        Ok(self
            .0
            .multisig_pending()
            .try_claim(seal_id, node_id, now, claimed_until)
            .await?)
    }

    async fn release_multisig_claim(
        &self,
        seal_id: &str,
        node_id: &str,
    ) -> crate::ServiceResult<()> {
        self.0
            .multisig_pending()
            .release_claim(seal_id, node_id)
            .await?;
        Ok(())
    }

    async fn delete_multisig_with_fence(
        &self,
        seal_id: &str,
        node_id: &str,
        claim_seq: i64,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .0
            .multisig_pending()
            .delete_with_fence(seal_id, node_id, claim_seq)
            .await?)
    }

    async fn renew_multisig_claim(
        &self,
        seal_id: &str,
        node_id: &str,
        claim_seq: i64,
        new_claimed_until: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .0
            .multisig_pending()
            .renew_claim(seal_id, node_id, claim_seq, new_claimed_until)
            .await?)
    }
}

#[async_trait::async_trait]
impl crate::jobs::MaintenancePort for PersistenceMaintenance {
    async fn prune_expired_idempotency(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<usize> {
        Ok(self.0.idempotency_keys().prune_expired(now).await?)
    }

    async fn idempotency_record(
        &self,
        principal_id: &arkret_identifiers::DidCoreId,
        key: &str,
    ) -> crate::ServiceResult<Option<crate::jobs::IdempotencyState>> {
        Ok(self
            .0
            .idempotency_keys()
            .get(principal_id, key)
            .await?
            .map(application_idempotency))
    }

    async fn store_idempotency_record(
        &self,
        record: crate::jobs::IdempotencyState,
    ) -> crate::ServiceResult<()> {
        self.0
            .idempotency_keys()
            .record(&persistence_idempotency(record))
            .await?;
        Ok(())
    }

    async fn control_proposal_authority_ack(
        &self,
        ack_key: &str,
    ) -> crate::ServiceResult<Option<crate::jobs::ControlProposalAuthorityAckState>> {
        Ok(self
            .0
            .control_proposal_authority_acks()
            .get(ack_key)
            .await?
            .map(|record| crate::jobs::ControlProposalAuthorityAckState {
                ack_key: record.ack_key,
                request_hash: record.request_hash,
                response_body: record.response_body,
                created_at: record.created_at,
            }))
    }

    async fn store_control_proposal_authority_ack(
        &self,
        record: crate::jobs::ControlProposalAuthorityAckState,
    ) -> crate::ServiceResult<()> {
        self.0
            .control_proposal_authority_acks()
            .record(&soland_storage::ControlProposalAuthorityAckRecord {
                ack_key: record.ack_key,
                request_hash: record.request_hash,
                response_body: record.response_body,
                created_at: record.created_at,
            })
            .await?;
        Ok(())
    }
}

fn application_idempotency(
    record: soland_storage::IdempotencyRecord,
) -> crate::jobs::IdempotencyState {
    crate::jobs::IdempotencyState {
        principal_id: record.principal_id,
        idempotency_key: record.idempotency_key,
        service_id: record.service_id,
        request_hash: record.request_hash,
        response_status: record.response_status,
        response_body: record.response_body,
        created_at: record.created_at,
        expires_at: record.expires_at,
    }
}
fn persistence_idempotency(
    record: crate::jobs::IdempotencyState,
) -> soland_storage::IdempotencyRecord {
    soland_storage::IdempotencyRecord {
        principal_id: record.principal_id,
        idempotency_key: record.idempotency_key,
        service_id: record.service_id,
        request_hash: record.request_hash,
        response_status: record.response_status,
        response_body: record.response_body,
        created_at: record.created_at,
        expires_at: record.expires_at,
    }
}

fn application_cursor_state(record: soland_storage::SyncCursorRecord) -> crate::sync::CursorState {
    crate::sync::CursorState {
        handle: record.handle,
        binding_subject: record.binding_subject,
        device_id: record.device_id,
        service_id: record.service_id,
        filter_digest: record.filter_digest,
        purpose: record.purpose,
        positions: record.positions,
        target: record.target,
        issued_at_ms: record.issued_at_ms,
        expires_at_ms: record.expires_at_ms,
    }
}

fn persistence_cursor_state(record: &crate::sync::CursorState) -> soland_storage::SyncCursorRecord {
    soland_storage::SyncCursorRecord {
        handle: record.handle.clone(),
        binding_subject: record.binding_subject.clone(),
        device_id: record.device_id.clone(),
        service_id: record.service_id.clone(),
        filter_digest: record.filter_digest.clone(),
        purpose: record.purpose.clone(),
        positions: record.positions.clone(),
        target: record.target.clone(),
        issued_at_ms: record.issued_at_ms,
        expires_at_ms: record.expires_at_ms,
    }
}

fn application_cursor_revocation(record: CursorRevocation) -> crate::sync::CursorRevocationState {
    crate::sync::CursorRevocationState {
        cursor_digest: record.cursor_digest,
        principal_id: record.principal_id,
        device_id: record.device_id,
        scope: record.scope,
        reason_code: record.reason_code,
        revoked_at: record.revoked_at,
        expires_at: record.expires_at,
    }
}

fn persistence_cursor_revocation(record: &crate::sync::CursorRevocationState) -> CursorRevocation {
    CursorRevocation {
        cursor_digest: record.cursor_digest.clone(),
        principal_id: record.principal_id.clone(),
        device_id: record.device_id.clone(),
        scope: record.scope.clone(),
        reason_code: record.reason_code.clone(),
        revoked_at: record.revoked_at,
        expires_at: record.expires_at,
    }
}

#[async_trait::async_trait]
impl crate::sync::CursorStorePort for PersistenceCursorStore {
    async fn get(&self, handle: &str) -> crate::ServiceResult<Option<crate::sync::CursorState>> {
        Ok(self
            .0
            .sync_cursors()
            .get(handle)
            .await?
            .map(application_cursor_state))
    }

    async fn upsert(&self, record: &crate::sync::CursorState) -> crate::ServiceResult<()> {
        self.0
            .sync_cursors()
            .upsert(&persistence_cursor_state(record))
            .await?;
        Ok(())
    }

    async fn delete(&self, handle: &str) -> crate::ServiceResult<bool> {
        Ok(self.0.sync_cursors().delete(handle).await?)
    }

    async fn prune_stream_superseded(
        &self,
        binding_subject: &str,
        device_id: &str,
        filter_digest: &str,
        presented_issued_at_ms: i64,
    ) -> crate::ServiceResult<usize> {
        Ok(self
            .0
            .sync_cursors()
            .prune_stream_superseded(
                binding_subject,
                device_id,
                filter_digest,
                presented_issued_at_ms,
            )
            .await?)
    }

    async fn prune_expired(&self, now_ms: i64) -> crate::ServiceResult<usize> {
        Ok(self.0.sync_cursors().prune_expired(now_ms).await?)
    }

    async fn record_revocation(
        &self,
        record: &crate::sync::CursorRevocationState,
    ) -> crate::ServiceResult<()> {
        self.0
            .sync_cursors()
            .record_revocation(&persistence_cursor_revocation(record))
            .await?;
        Ok(())
    }

    async fn active_revocations(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<Vec<crate::sync::CursorRevocationState>> {
        Ok(self
            .0
            .sync_cursors()
            .active_revocations(now)
            .await?
            .into_iter()
            .map(application_cursor_revocation)
            .collect())
    }
}

#[derive(Clone)]
pub struct PersistenceOperationalServices {
    pub federation: FederationService,
    pub governance: GovernanceService,
    pub sync: SyncService,
    pub jobs: JobsService,
}

#[async_trait::async_trait]
impl crate::sync::WebsocketAuthPort for PersistenceWebsocketAuth {
    async fn prepare_challenge(
        &self,
        record: &crate::sync::WebsocketChallengeState,
    ) -> crate::ServiceResult<()> {
        Ok(self
            .0
            .websocket_auth()
            .prepare_challenge(&persistence_websocket_challenge(record))
            .await?)
    }

    async fn challenge(
        &self,
        connection_id: &str,
        nonce: &str,
    ) -> crate::ServiceResult<Option<crate::sync::WebsocketChallengeState>> {
        Ok(self
            .0
            .websocket_auth()
            .get_challenge(connection_id, nonce)
            .await?
            .map(application_websocket_challenge))
    }

    async fn replay_ledger_contains(
        &self,
        cnf_jkt: &str,
        jti: &str,
        proof_context: &str,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .0
            .websocket_auth()
            .replay_ledger_contains(cnf_jkt, jti, proof_context)
            .await?)
    }

    async fn consume_challenge(
        &self,
        connection_id: &str,
        nonce: &str,
        replay: &crate::sync::WebsocketReplayState,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .0
            .websocket_auth()
            .consume_challenge(
                connection_id,
                nonce,
                &soland_storage::WebsocketAuthReplayRecord {
                    cnf_jkt: replay.cnf_jkt.clone(),
                    jti: replay.jti.clone(),
                    proof_context: replay.proof_context.clone(),
                    consumed_at: replay.consumed_at,
                    retain_until: replay.retain_until,
                },
            )
            .await?)
    }

    async fn prune_expired(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<usize> {
        Ok(self.0.websocket_auth().prune_expired(now).await?)
    }
}

fn persistence_websocket_challenge(
    record: &crate::sync::WebsocketChallengeState,
) -> soland_storage::WebsocketAuthChallengeRecord {
    soland_storage::WebsocketAuthChallengeRecord {
        connection_id: record.connection_id.clone(),
        nonce: record.nonce.clone(),
        canonical_origin: record.canonical_origin.clone(),
        canonical_base_url: record.canonical_base_url.clone(),
        issued_at: record.issued_at,
        expires_at: record.expires_at,
        consumed: record.consumed,
        retain_until: record.retain_until,
    }
}

fn application_websocket_challenge(
    record: soland_storage::WebsocketAuthChallengeRecord,
) -> crate::sync::WebsocketChallengeState {
    crate::sync::WebsocketChallengeState {
        connection_id: record.connection_id,
        nonce: record.nonce,
        canonical_origin: record.canonical_origin,
        canonical_base_url: record.canonical_base_url,
        issued_at: record.issued_at,
        expires_at: record.expires_at,
        consumed: record.consumed,
        retain_until: record.retain_until,
    }
}

pub fn build_persistence_operational_services(
    persistence: Arc<dyn PersistenceStore>,
    runtime_settings: Arc<dyn RuntimeSettingsPort>,
    runtime_health: Arc<dyn RuntimeHealthPort>,
    sync_cursor_hmac_key: [u8; 32],
) -> PersistenceOperationalServices {
    PersistenceOperationalServices {
        federation: FederationService::new(
            Arc::new(PersistenceFederationOutbox(persistence.clone())),
            Arc::new(PersistenceFederationOutbox(persistence.clone())),
        ),
        governance: GovernanceService::new(
            Arc::new(PersistenceAuditLog(persistence.clone())),
            Arc::new(PersistenceModeration(persistence.clone())),
            Arc::new(PersistenceGovernanceRecords(persistence.clone())),
            runtime_settings,
        ),
        sync: SyncService::new(
            Arc::new(PersistenceCursorStore(persistence.clone())),
            Arc::new(PersistenceWebsocketAuth(persistence.clone())),
            sync_cursor_hmac_key,
        ),
        jobs: JobsService::new(
            Arc::new(PersistenceMaintenance(persistence)),
            runtime_health,
        ),
    }
}
