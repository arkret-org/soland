//! Current governance-Station application boundary.

use arkret_models_collaboration::authority_commit::{
    DirectConversationFoundingAcceptanceOutcome, DirectConversationFoundingFederationSubmission,
    DirectConversationFoundingUnitSubmission, MembershipCompensationAcceptanceOutcome,
    MembershipCompensationFederationSubmission, MembershipCompensationUnitSubmission,
    PeerAuthoritySubmitOutcome, PeerAuthoritySubmitRequest, PeerCommittedReplicationOutcome,
    PeerCommittedReplicationRequest, PeerRegisteredAtomicUnit, PeerRegisteredAtomicUnitOutcome,
    PeerRegisteredAtomicUnitOutcomeValue, SelfAuthoritySubmitOutcome, SelfAuthoritySubmitRequest,
};
use arkret_wire::{
    AuthorityBundleRequest, AuthorityHandoffRequest, AuthoritySubmitOutcome, CommitStreamHead,
    CommitStreamRef, DetachedSignatureContext, DidCoreId, DidUrl, Event, EventCommitSubmission,
    MlsCommitSubmission, RealmAuthorityBundle, RealmAuthorityHandoff, RealmCommit, RealmCommitId,
    RealmStateSnapshot, StreamScanOutcome, StreamScanRequest,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use serde::Serialize;
use soland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, AuthorityCommitWriteOutcome,
    CurrentRealmAuthority, QueuedEventRecord,
};

use crate::persistence::PersistenceHandle;
use crate::{ServiceError, ServiceResult};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorityEventAdmissionOutcome {
    Committed(RealmCommit),
    Duplicate(RealmCommit),
    NotCurrentAuthority,
}

#[derive(Serialize)]
struct RealmCommitIdentityBody<'a> {
    realm_id: &'a arkret_wire::RealmId,
    stream_ref: &'a CommitStreamRef,
    stream_position: u64,
    previous_commit_ref: &'a Option<RealmCommitId>,
    event_ref: &'a arkret_wire::EventId,
    governance_generation: u64,
    authority_ref: &'a arkret_wire::RealmCommitAuthorityRef,
    committed_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct RealmCommitUnsignedBody<'a> {
    commit_id: &'a RealmCommitId,
    realm_id: &'a arkret_wire::RealmId,
    stream_ref: &'a CommitStreamRef,
    stream_position: u64,
    previous_commit_ref: &'a Option<RealmCommitId>,
    event_ref: &'a arkret_wire::EventId,
    governance_generation: u64,
    authority_ref: &'a arkret_wire::RealmCommitAuthorityRef,
    committed_at: DateTime<Utc>,
}

fn build_signed_event_commit(
    event: &Event,
    authority: &CurrentRealmAuthority,
    head: Option<&CommitStreamHead>,
    verification_method: DidUrl,
    signing_key: &SigningKey,
    committed_at: DateTime<Utc>,
) -> ServiceResult<RealmCommit> {
    let stream_ref = CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    if head.is_some_and(|value| value.stream_ref != stream_ref) {
        return Err(ServiceError::Internal(
            "authority store returned a head for the wrong stream".to_owned(),
        ));
    }
    let (stream_position, previous_commit_ref) = match head {
        Some(head) => (
            head.stream_position.checked_add(1).ok_or_else(|| {
                ServiceError::Internal("authority stream position overflow".to_owned())
            })?,
            Some(head.commit_id.clone()),
        ),
        None => (0, None),
    };
    let committed_at = arkret_canonical::normalize_timestamp_canonical(committed_at);
    let identity_body = RealmCommitIdentityBody {
        realm_id: &event.realm_id,
        stream_ref: &stream_ref,
        stream_position,
        previous_commit_ref: &previous_commit_ref,
        event_ref: &event.event_id,
        governance_generation: authority.generation,
        authority_ref: &authority.authority_ref,
        committed_at,
    };
    // `commit_id` is the typed content address of the closed commit body.
    // Like every self-identifying object, its identity preimage excludes the
    // identity field itself as well as the detached signature.
    let identity_bytes = arkret_canonical::canonical_json_bytes(&identity_body)
        .map_err(|error| ServiceError::Internal(error.to_string()))?;
    let commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(&identity_bytes));
    let unsigned_body = RealmCommitUnsignedBody {
        commit_id: &commit_id,
        realm_id: &event.realm_id,
        stream_ref: &stream_ref,
        stream_position,
        previous_commit_ref: &previous_commit_ref,
        event_ref: &event.event_id,
        governance_generation: authority.generation,
        authority_ref: &authority.authority_ref,
        committed_at,
    };
    let signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned_body,
        DetachedSignatureContext::RealmCommit,
        verification_method,
        committed_at,
        signing_key,
    )
    .map_err(|error| ServiceError::Internal(error.to_string()))?;
    let commit = RealmCommit {
        commit_id,
        realm_id: event.realm_id.clone(),
        stream_ref,
        stream_position,
        previous_commit_ref,
        event_ref: event.event_id.clone(),
        governance_generation: authority.generation,
        authority_ref: authority.authority_ref.clone(),
        committed_at,
        signature,
    };
    commit
        .validate_shape()
        .map_err(|error| ServiceError::Internal(error.to_string()))?;
    Ok(commit)
}

/// Durable queued-to-committed lifecycle used by the governance Station.
///
/// Signature verification, policy evaluation, MLS installation, and commit
/// signing happen before [`Self::install_commit`]. The store then performs one
/// atomic authority-generation check, stream append, Event state transition,
/// and Welcome enqueue.
#[derive(Clone)]
pub struct AuthorityCommitApplication {
    persistence: PersistenceHandle,
}

impl AuthorityCommitApplication {
    pub fn new(persistence: PersistenceHandle) -> Self {
        Self { persistence }
    }

    fn store(&self) -> &dyn AuthorityCommitStore {
        self.persistence.authority_commit_store()
    }

    pub async fn install_genesis_authority(
        &self,
        authority: &CurrentRealmAuthority,
    ) -> ServiceResult<()> {
        self.store().install_genesis_authority(authority).await?;
        Ok(())
    }

    /// Optional authoring preparation may read current membership only while
    /// this service is the verified governing Station. This read grants no
    /// Event authority; admission still checks the current commit cut.
    pub async fn local_current_member_joined(
        &self,
        realm_id: &arkret_wire::RealmId,
        member: &arkret_wire::ActorId,
        service_id: &DidCoreId,
    ) -> ServiceResult<bool> {
        Ok(self
            .store()
            .local_current_member_joined(realm_id, member, service_id)
            .await?)
    }

    pub async fn queue_event(&self, event: &Event, queued_at: DateTime<Utc>) -> ServiceResult<()> {
        event.validate_for_submit_structural().map_err(|error| {
            crate::ServiceError::SchemaViolation(format!("invalid producer Event: {error}"))
        })?;
        self.store().queue_event(event, queued_at).await?;
        Ok(())
    }

    pub async fn queued_event(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> ServiceResult<Option<QueuedEventRecord>> {
        Ok(self.store().queued_event(event_id).await?)
    }

    pub async fn install_commit(
        &self,
        transaction: &AuthorityCommitTransaction,
    ) -> ServiceResult<AuthorityCommitWriteOutcome> {
        transaction.validate().map_err(|error| {
            crate::ServiceError::SchemaViolation(format!("invalid authority transaction: {error}"))
        })?;
        Ok(self.store().commit_transaction(transaction).await?)
    }

    /// Admit one already-validated producer Event as this Realm's current
    /// governance Station.
    ///
    /// The storage call is deliberately a single queue+commit transaction.
    /// A failed authority/head CAS therefore cannot leave a queued Event that
    /// a later path might mistake for accepted state.
    pub async fn admit_event(
        &self,
        event: &Event,
        local_service_id: &DidCoreId,
        verification_method: DidUrl,
        signing_key: &SigningKey,
        committed_at: DateTime<Utc>,
    ) -> ServiceResult<AuthorityEventAdmissionOutcome> {
        event.validate_for_submit_structural().map_err(|error| {
            ServiceError::SchemaViolation(format!("invalid producer Event: {error}"))
        })?;
        if let Some(record) = self.store().committed_event(&event.event_id).await? {
            if record.event != *event {
                return Err(ServiceError::Conflict(
                    "event_id is already committed with different canonical content".to_owned(),
                ));
            }
            return Ok(AuthorityEventAdmissionOutcome::Duplicate(record.commit));
        }
        let Some(authority) = self.store().current_authority(&event.realm_id).await? else {
            return Ok(AuthorityEventAdmissionOutcome::NotCurrentAuthority);
        };
        if &authority.service_id != local_service_id {
            return Ok(AuthorityEventAdmissionOutcome::NotCurrentAuthority);
        }
        let stream_ref =
            CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))
                .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let head = self.store().stream_head(&stream_ref).await?;
        let commit = build_signed_event_commit(
            event,
            &authority,
            head.as_ref(),
            verification_method,
            signing_key,
            committed_at,
        )?;
        let transaction = AuthorityCommitTransaction {
            expected_authority: authority,
            event: event.clone(),
            commit: commit.clone(),
            mls_state: None,
            welcomes: Vec::new(),
        };
        transaction.validate().map_err(|error| {
            ServiceError::SchemaViolation(format!("invalid authority transaction: {error}"))
        })?;
        match self
            .store()
            .admit_event_transaction(&transaction, committed_at)
            .await?
        {
            AuthorityCommitWriteOutcome::Committed => {
                Ok(AuthorityEventAdmissionOutcome::Committed(commit))
            }
            AuthorityCommitWriteOutcome::Duplicate => {
                let record = self
                    .store()
                    .committed_event(&event.event_id)
                    .await?
                    .ok_or_else(|| {
                        ServiceError::Internal(
                            "duplicate authority admission has no durable committed Event"
                                .to_owned(),
                        )
                    })?;
                if record.event != *event {
                    return Err(ServiceError::Conflict(
                        "event_id is already committed with different canonical content".to_owned(),
                    ));
                }
                Ok(AuthorityEventAdmissionOutcome::Duplicate(record.commit))
            }
            AuthorityCommitWriteOutcome::StaleAuthority(_) => {
                Ok(AuthorityEventAdmissionOutcome::NotCurrentAuthority)
            }
        }
    }

    pub async fn current_authority(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> ServiceResult<Option<CurrentRealmAuthority>> {
        Ok(self.store().current_authority(realm_id).await?)
    }

    pub async fn stream_head(
        &self,
        stream_ref: &CommitStreamRef,
    ) -> ServiceResult<Option<CommitStreamHead>> {
        Ok(self.store().stream_head(stream_ref).await?)
    }

    /// Keyset page over one independent commit stream.
    ///
    /// Paging is a `stream_position` keyset inside a single
    /// [`CommitStreamRef`]: the caller passes the last position it already
    /// holds as `after_position` (`None` starts at genesis position 0) and the
    /// store returns at most `limit` consecutive rows. There is no opaque
    /// page token, no reverse direction and no `has_more` flag; `truncated`
    /// alone says whether the stream continued past the returned page, and the
    /// next request resumes from the last returned `commit.stream_position`.
    pub async fn scan_stream(
        &self,
        request: &StreamScanRequest,
    ) -> ServiceResult<StreamScanOutcome> {
        request.validate().map_err(|error| {
            crate::ServiceError::SchemaViolation(format!("invalid stream scan request: {error}"))
        })?;
        let outcome = self.store().scan_stream(request).await?;
        outcome.validate_for_request(request).map_err(|error| {
            crate::ServiceError::SchemaViolation(format!("invalid stream scan outcome: {error}"))
        })?;
        Ok(outcome)
    }

    pub async fn install_handoff(&self, request: &AuthorityHandoffRequest) -> ServiceResult<()> {
        request.validate_shape().map_err(|error| {
            crate::ServiceError::SchemaViolation(format!("invalid authority handoff: {error}"))
        })?;
        self.store()
            .install_handoff(
                &request.handoff,
                &request.final_stream_heads,
                &request.snapshot,
            )
            .await?;
        Ok(())
    }

    pub async fn latest_snapshot(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> ServiceResult<Option<RealmStateSnapshot>> {
        Ok(self.store().latest_snapshot(realm_id).await?)
    }
}

/// HTTP-facing protocol port.
///
/// The concrete Station implementation performs authorization and signing;
/// HTTP only validates/deserializes current SDK DTOs and delegates. Keeping
/// the port in services makes the protocol operations directly testable
/// without transport concerns.
#[async_trait]
pub trait AuthorityProtocolPort: Send + Sync {
    async fn submit_self_event(
        &self,
        request: EventCommitSubmission,
    ) -> ServiceResult<AuthoritySubmitOutcome>;

    /// An accepted MLS result is forbidden until the MLS state, every Welcome,
    /// and its authority Commit are visible through one transaction.
    async fn submit_self_mls(
        &self,
        request: MlsCommitSubmission,
    ) -> ServiceResult<AuthoritySubmitOutcome>;

    async fn submit_self_direct_conversation_founding(
        &self,
        _request: DirectConversationFoundingUnitSubmission,
    ) -> ServiceResult<DirectConversationFoundingAcceptanceOutcome> {
        Err(crate::ServiceError::internal(
            "Direct Conversation founding is not connected to the authority transaction path",
        ))
    }

    async fn submit_self_membership_compensation(
        &self,
        _request: MembershipCompensationUnitSubmission,
    ) -> ServiceResult<MembershipCompensationAcceptanceOutcome> {
        Err(crate::ServiceError::internal(
            "membership compensation is not connected to the authority transaction path",
        ))
    }

    /// Closed self-endpoint dispatcher. It validates both sides at the service
    /// boundary so a handler cannot return the response branch for a different
    /// request or degrade an aggregate into a partial ordinary outcome.
    async fn submit_self(
        &self,
        request: SelfAuthoritySubmitRequest,
    ) -> ServiceResult<SelfAuthoritySubmitOutcome> {
        request.validate().map_err(|error| {
            crate::ServiceError::SchemaViolation(format!(
                "invalid self authority submission: {error}"
            ))
        })?;
        let outcome = match request.clone() {
            SelfAuthoritySubmitRequest::Event(value) => {
                SelfAuthoritySubmitOutcome::Ordinary(self.submit_self_event(value).await?)
            }
            SelfAuthoritySubmitRequest::MlsCommit(value) => {
                SelfAuthoritySubmitOutcome::Ordinary(self.submit_self_mls(value).await?)
            }
            SelfAuthoritySubmitRequest::DirectConversationFounding(value) => {
                SelfAuthoritySubmitOutcome::DirectConversationFounding(
                    self.submit_self_direct_conversation_founding(value).await?,
                )
            }
            SelfAuthoritySubmitRequest::MembershipCompensation(value) => {
                SelfAuthoritySubmitOutcome::MembershipCompensation(
                    self.submit_self_membership_compensation(value).await?,
                )
            }
        };
        outcome.validate_for_request(&request).map_err(|error| {
            crate::ServiceError::Internal(format!(
                "self authority dispatcher produced an invalid outcome: {error}"
            ))
        })?;
        Ok(outcome)
    }

    async fn submit_peer_committed_replication(
        &self,
        _request: PeerCommittedReplicationRequest,
    ) -> ServiceResult<PeerCommittedReplicationOutcome> {
        Err(crate::ServiceError::internal(
            "committed replication is not connected to durable replica persistence",
        ))
    }

    async fn submit_peer_direct_conversation_founding(
        &self,
        _request: DirectConversationFoundingFederationSubmission,
    ) -> ServiceResult<DirectConversationFoundingAcceptanceOutcome> {
        Err(crate::ServiceError::internal(
            "peer Direct Conversation founding is not connected to atomic materialization",
        ))
    }

    async fn submit_peer_membership_compensation(
        &self,
        _request: MembershipCompensationFederationSubmission,
    ) -> ServiceResult<MembershipCompensationAcceptanceOutcome> {
        Err(crate::ServiceError::internal(
            "peer membership compensation is not connected to atomic materialization",
        ))
    }

    /// Dispatch the closed peer carrier. Canonical Station-to-own-Account-
    /// Authority forwarding has been retired; the enum branches remain only
    /// until the shared SDK carrier is cleaned up and always fail closed here.
    async fn submit_peer(
        &self,
        request: PeerAuthoritySubmitRequest,
    ) -> ServiceResult<PeerAuthoritySubmitOutcome> {
        request.validate().map_err(|error| {
            crate::ServiceError::SchemaViolation(format!(
                "invalid peer authority submission: {error}"
            ))
        })?;
        let outcome = match request.clone() {
            PeerAuthoritySubmitRequest::AuthorityForwardEvent(_)
            | PeerAuthoritySubmitRequest::AuthorityForwardMls(_) => {
                return Err(crate::ServiceError::SchemaViolation(
                    "canonical authority-forward submission is retired; use the product-private Account Authority adapter"
                        .to_owned(),
                ));
            }
            PeerAuthoritySubmitRequest::CommittedReplication(value) => {
                PeerAuthoritySubmitOutcome::CommittedReplication(
                    self.submit_peer_committed_replication(value).await?,
                )
            }
            PeerAuthoritySubmitRequest::RegisteredAtomicUnit(value) => {
                let branch = value.branch;
                let unit = match value.unit {
                    PeerRegisteredAtomicUnit::DirectConversationFounding(unit) => {
                        PeerRegisteredAtomicUnitOutcomeValue::DirectConversationFounding(
                            self.submit_peer_direct_conversation_founding(unit).await?,
                        )
                    }
                    PeerRegisteredAtomicUnit::MembershipCompensation(unit) => {
                        PeerRegisteredAtomicUnitOutcomeValue::MembershipCompensation(
                            self.submit_peer_membership_compensation(unit).await?,
                        )
                    }
                };
                PeerAuthoritySubmitOutcome::RegisteredAtomicUnit(PeerRegisteredAtomicUnitOutcome {
                    branch,
                    outcome: unit,
                })
            }
        };
        outcome.validate_for_request(&request).map_err(|error| {
            crate::ServiceError::Internal(format!(
                "peer authority dispatcher produced an invalid outcome: {error}"
            ))
        })?;
        Ok(outcome)
    }

    async fn scan_stream(&self, request: StreamScanRequest) -> ServiceResult<StreamScanOutcome>;

    async fn authority_bundle(
        &self,
        request: AuthorityBundleRequest,
    ) -> ServiceResult<RealmAuthorityBundle>;

    async fn install_authority_handoff(
        &self,
        request: AuthorityHandoffRequest,
    ) -> ServiceResult<RealmAuthorityHandoff>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_commit_identity_and_signature_cover_the_closed_body() {
        let genesis_event =
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x11; 32]);
        let realm_id = arkret_wire::RealmId::from_event_id(&genesis_event);
        let service_id =
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example".to_owned()).unwrap();
        let event = arkret_wire::test_support::raw_event_at(
            arkret_wire::EventKind::MessageCreate.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            arkret_wire::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
            service_id.clone(),
            serde_json::json!({"body": "atomic admission"}),
            chrono::DateTime::parse_from_rfc3339("2026-09-20T08:00:00.123Z")
                .unwrap()
                .with_timezone(&Utc),
        )
        .unwrap();
        let authority = CurrentRealmAuthority {
            realm_id,
            generation: 3,
            service_id,
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                genesis_event,
            ),
            last_handoff_ref: None,
        };
        let signing_key = SigningKey::from_bytes(&[0x44; 32]);
        let committed_at = chrono::DateTime::parse_from_rfc3339("2026-09-20T08:00:01.456789Z")
            .unwrap()
            .with_timezone(&Utc);
        let commit = build_signed_event_commit(
            &event,
            &authority,
            None,
            DidUrl::new("did:web:station.example#notary-key").unwrap(),
            &signing_key,
            committed_at,
        )
        .unwrap();

        assert_eq!(commit.stream_position, 0);
        assert!(commit.previous_commit_ref.is_none());
        assert_eq!(commit.committed_at.timestamp_subsec_micros(), 456_000);
        let unsigned = arkret_canonical::unsigned_value(&commit, &["signature"]).unwrap();
        assert_eq!(
            commit.signature.signed_digest,
            arkret_signatures::detached_object::detached_object_signed_digest(&unsigned).unwrap(),
            "the signature must seal the exact wire Commit minus signature"
        );
        let replay = build_signed_event_commit(
            &event,
            &authority,
            None,
            DidUrl::new("did:web:station.example#notary-key").unwrap(),
            &signing_key,
            committed_at,
        )
        .unwrap();
        assert_eq!(commit, replay, "same closed input must produce one Commit");
    }
}
