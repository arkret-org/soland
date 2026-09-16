//! Current governance-Station application boundary.

use std::sync::Arc;

use arkret_wire::{
    AuthorityBundleRequest, AuthorityHandoffRequest, AuthoritySubmitOutcome,
    AuthoritySubmitRequest, CommitStreamHead, CommitStreamRef, CommittedEventResolveOutcome,
    CommittedEventResolveRequest, Event, RealmAuthorityBundle, RealmAuthorityHandoff,
    RealmStateSnapshot, StreamScanOutcome, StreamScanRequest,
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
/// the port in services makes the five protocol operations directly testable
/// without transport concerns.
#[async_trait]
pub trait AuthorityProtocolPort: Send + Sync {
    /// Queue and adjudicate one producer submission at the current authority.
    ///
    /// For `MlsCommit`, an `Accepted` result is forbidden until the MLS state
    /// has been installed and every addressed Welcome has entered the durable
    /// delivery queue. Implementations use [`AuthorityCommitTransaction`] so
    /// those Welcome rows and the stream commit become visible atomically.
    async fn submit(
        &self,
        request: AuthoritySubmitRequest,
    ) -> ServiceResult<AuthoritySubmitOutcome>;

    async fn scan_stream(&self, request: StreamScanRequest) -> ServiceResult<StreamScanOutcome>;

    async fn resolve_committed(
        &self,
        request: CommittedEventResolveRequest,
    ) -> ServiceResult<CommittedEventResolveOutcome>;

    async fn authority_bundle(
        &self,
        request: AuthorityBundleRequest,
    ) -> ServiceResult<RealmAuthorityBundle>;

    async fn install_authority_handoff(
        &self,
        request: AuthorityHandoffRequest,
    ) -> ServiceResult<RealmAuthorityHandoff>;
}
