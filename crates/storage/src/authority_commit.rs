//! Durable authority-commit persistence boundary.
//!
//! Producer Events are queued without ordering metadata. Only the current
//! governance Station may atomically append a [`RealmCommit`], mark the Event
//! committed, and enqueue any MLS Welcome deliveries. Each Realm, Circle and
//! Sidecar stream advances independently.

use arkret_wire::{
    CommitStreamHead, CommitStreamRef, Event, MlsWelcomeDelivery, RealmAuthorityHandoff,
    RealmCommit, RealmStateSnapshot,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::PersistenceResult;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueuedEventStatus {
    Queued,
    Committed,
    Rejected,
}

#[derive(Clone, Debug, PartialEq)]
pub struct QueuedEventRecord {
    pub event: Event,
    pub status: QueuedEventStatus,
    pub queued_at: DateTime<Utc>,
    pub committed: Option<RealmCommit>,
    pub rejection_reason: Option<String>,
}

/// Exact durable pair used to materialize a caller-scoped committed-event
/// read view. This is an internal persistence carrier, not a third protocol
/// object and has no identity or signature of its own.
#[derive(Clone, Debug, PartialEq)]
pub struct CommittedEventRecord {
    pub commit: RealmCommit,
    pub event: Event,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentRealmAuthority {
    pub realm_id: arkret_wire::RealmId,
    pub generation: u64,
    pub service_id: arkret_wire::DidCoreId,
    pub authority_ref: arkret_wire::RealmCommitAuthorityRef,
    pub last_handoff_ref: Option<arkret_wire::RealmAuthorityHandoffId>,
}

/// One durable-cut maximal Realm snapshot projection before identity and
/// Station signature are attached by the serving layer.
#[derive(Clone, Debug, PartialEq)]
pub struct RealmStateSnapshotMaterial {
    pub realm_id: arkret_wire::RealmId,
    pub governance_generation: u64,
    pub visible_stream_heads: Vec<arkret_wire::CommitStreamHead>,
    pub current_state_entries: Vec<arkret_wire::TypedCurrentResult>,
    pub retention_and_history_floor: arkret_wire::RetentionAndHistoryFloor,
}

/// One transaction installed after all Event, authority and MLS checks pass.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthorityCommitTransaction {
    pub expected_authority: CurrentRealmAuthority,
    pub event: Event,
    pub commit: RealmCommit,
    pub mls_state: Option<MlsStateInstallation>,
    pub welcomes: Vec<MlsWelcomeDelivery>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsStateInstallation {
    pub group_id: String,
    pub effective_scope: arkret_wire::ScopeRef,
    pub epoch: u64,
    pub state_bytes: Vec<u8>,
}

impl AuthorityCommitTransaction {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        self.event.validate_for_submit_structural()?;
        self.commit.validate_shape()?;
        let expected_stream =
            CommitStreamRef::from_scope(&self.event.scope_ref, Some(self.event.realm_id.clone()))?;
        if self.expected_authority.realm_id != self.event.realm_id
            || self.commit.realm_id != self.event.realm_id
            || self.commit.event_ref != self.event.event_id
            || self.commit.stream_ref != expected_stream
            || self.commit.governance_generation != self.expected_authority.generation
            || self.commit.authority_ref != self.expected_authority.authority_ref
        {
            return Err(arkret_wire::WireError::Protocol(
                "authority commit transaction bindings disagree".to_owned(),
            ));
        }
        match (
            &self.mls_state,
            self.event.kind == arkret_wire::EventKind::MlsCommit,
        ) {
            (Some(state), true)
                if state.effective_scope == self.event.scope_ref
                    && !state.group_id.is_empty()
                    && !state.state_bytes.is_empty() => {}
            (None, false) => {}
            _ => {
                return Err(arkret_wire::WireError::Protocol(
                    "MLS Commit acceptance requires exactly one installed group state".to_owned(),
                ));
            }
        }
        for welcome in &self.welcomes {
            welcome.validate_shape()?;
            if welcome.realm_id != self.event.realm_id
                || welcome.effective_scope != self.event.scope_ref
                || welcome.commit_event_ref != self.event.event_id
            {
                return Err(arkret_wire::WireError::Protocol(
                    "MLS Welcome does not bind the committed Event and stream".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorityCommitWriteOutcome {
    Committed,
    Duplicate,
    StaleAuthority(CurrentRealmAuthority),
}

#[async_trait]
pub trait AuthorityCommitStore: Send + Sync {
    async fn install_genesis_authority(
        &self,
        authority: &CurrentRealmAuthority,
    ) -> PersistenceResult<()>;

    async fn current_authority(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Option<CurrentRealmAuthority>>;

    /// Read one accepted current membership only when this service is the
    /// Realm's current governing Station. Missing, remote, or inconsistent
    /// authority/member rows fail closed for optional authoring preparation.
    async fn local_current_member_joined(
        &self,
        realm_id: &arkret_wire::RealmId,
        member: &arkret_wire::ActorId,
        service_id: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<bool>;

    async fn queue_event(&self, event: &Event, queued_at: DateTime<Utc>) -> PersistenceResult<()>;

    async fn queued_event(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> PersistenceResult<Option<QueuedEventRecord>>;

    /// Atomically queues a producer Event and installs its authority Commit.
    ///
    /// Unlike calling [`Self::queue_event`] followed by
    /// [`Self::commit_transaction`], this boundary guarantees that any
    /// authority, predecessor, or persistence failure leaves no queued Event
    /// behind. Product-private Account Authority admission uses this method so
    /// it cannot expose a half-admitted Event after a failed request.
    async fn admit_event_transaction(
        &self,
        transaction: &AuthorityCommitTransaction,
        queued_at: DateTime<Utc>,
    ) -> PersistenceResult<AuthorityCommitWriteOutcome>;

    /// Atomically checks current authority, appends the per-stream commit,
    /// changes the Event from queued to committed, and enqueues every Welcome.
    async fn commit_transaction(
        &self,
        transaction: &AuthorityCommitTransaction,
    ) -> PersistenceResult<AuthorityCommitWriteOutcome>;

    async fn stream_head(
        &self,
        stream_ref: &CommitStreamRef,
    ) -> PersistenceResult<Option<CommitStreamHead>>;

    /// Resolve the unique successful RealmCommit for one Event id.
    ///
    /// A missing row returns `None`; storage uniqueness guarantees that this
    /// method never chooses between two successful commits for the same Event.
    async fn committed_event(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> PersistenceResult<Option<CommittedEventRecord>>;

    /// Current heads for every independent Realm, Circle, and Sidecar stream
    /// belonging to one Realm, sorted by `stream_ref`.
    async fn realm_stream_heads(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Vec<CommitStreamHead>>;

    /// Read the maximal-disclosure snapshot material from one consistent
    /// durable cut. Implementations must sort every repeated field.
    async fn realm_state_snapshot_material(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Option<RealmStateSnapshotMaterial>>;

    /// Keyset page over one independent commit stream.
    ///
    /// The only paging key is `realm_commits.stream_position` inside the
    /// single `CommitStreamRef` named by the request: rows start at genesis
    /// position 0 when `after_position` is `None` and otherwise at
    /// `after_position + 1`, run consecutively, and stop after `limit` rows.
    /// No opaque page token, no reverse direction, and no separate
    /// `has_more`: `StreamScanOutcome::truncated` carries that alone.
    async fn scan_stream(
        &self,
        request: &arkret_wire::StreamScanRequest,
    ) -> PersistenceResult<arkret_wire::StreamScanOutcome>;

    async fn install_handoff(
        &self,
        handoff: &RealmAuthorityHandoff,
        final_stream_heads: &[CommitStreamHead],
        snapshot: &RealmStateSnapshot,
    ) -> PersistenceResult<()>;

    /// Returns the consecutive, durable handoff chain used to verify the
    /// current Station from the Realm's genesis authority.
    async fn authority_handoffs(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Vec<RealmAuthorityHandoff>>;

    async fn latest_snapshot(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Option<RealmStateSnapshot>>;
}
