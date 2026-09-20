//! Current governance-Station application boundary.

use std::sync::Arc;

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
    CommitStreamRef, Event, EventCommitSubmission, MlsCommitSubmission, RealmAuthorityBundle,
    RealmAuthorityHandoff, RealmStateSnapshot, StreamScanOutcome, StreamScanRequest,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use soland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, AuthorityCommitWriteOutcome,
    CurrentRealmAuthority, QueuedEventRecord,
};

use crate::ServiceResult;

/// Durable queued-to-committed lifecycle used by the governance Station.
///
/// Signature verification, policy evaluation, MLS installation, and commit
/// signing happen before [`Self::install_commit`]. The store then performs one
/// atomic authority-generation check, stream append, Event state transition,
/// and Welcome enqueue.
#[derive(Clone)]
pub struct AuthorityCommitApplication {
    store: Arc<dyn AuthorityCommitStore>,
}

impl AuthorityCommitApplication {
    pub fn new(store: Arc<dyn AuthorityCommitStore>) -> Self {
        Self { store }
    }

    pub async fn install_genesis_authority(
        &self,
        authority: &CurrentRealmAuthority,
    ) -> ServiceResult<()> {
        self.store.install_genesis_authority(authority).await?;
        Ok(())
    }

    pub async fn queue_event(&self, event: &Event, queued_at: DateTime<Utc>) -> ServiceResult<()> {
        event.validate_for_submit_structural().map_err(|error| {
            crate::ServiceError::SchemaViolation(format!("invalid producer Event: {error}"))
        })?;
        self.store.queue_event(event, queued_at).await?;
        Ok(())
    }

    pub async fn queued_event(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> ServiceResult<Option<QueuedEventRecord>> {
        Ok(self.store.queued_event(event_id).await?)
    }

    pub async fn install_commit(
        &self,
        transaction: &AuthorityCommitTransaction,
    ) -> ServiceResult<AuthorityCommitWriteOutcome> {
        transaction.validate().map_err(|error| {
            crate::ServiceError::SchemaViolation(format!("invalid authority transaction: {error}"))
        })?;
        Ok(self.store.commit_transaction(transaction).await?)
    }

    pub async fn current_authority(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> ServiceResult<Option<CurrentRealmAuthority>> {
        Ok(self.store.current_authority(realm_id).await?)
    }

    pub async fn stream_head(
        &self,
        stream_ref: &CommitStreamRef,
    ) -> ServiceResult<Option<CommitStreamHead>> {
        Ok(self.store.stream_head(stream_ref).await?)
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
        let outcome = self.store.scan_stream(request).await?;
        outcome.validate_for_request(request).map_err(|error| {
            crate::ServiceError::SchemaViolation(format!("invalid stream scan outcome: {error}"))
        })?;
        Ok(outcome)
    }

    pub async fn install_handoff(&self, request: &AuthorityHandoffRequest) -> ServiceResult<()> {
        request.validate_shape().map_err(|error| {
            crate::ServiceError::SchemaViolation(format!("invalid authority handoff: {error}"))
        })?;
        self.store
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
        Ok(self.store.latest_snapshot(realm_id).await?)
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
