use arkret_models_identity::{
    ServiceResolutionArtifactKey, ServiceResolutionLastSeenFloor, ServiceResolutionPublishAck,
    ServiceResolutionPublishRequest, ServiceResolutionRecord, ServiceRouteCacheEntry,
    ServiceRouteHandoverNotice, ServiceRouteNoticeState,
};
use arkret_wire::{Hash, RealmId, RequestId, ServiceId};
use chrono::{DateTime, Utc};

use super::{PersistenceResult, async_trait};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceResolutionMirrorEntry {
    pub source_service_id: ServiceId,
    pub realm_id: RealmId,
    pub request_id: RequestId,
    pub request_digest: Hash,
    pub artifact_key: ServiceResolutionArtifactKey,
    pub artifact_digest: Hash,
    pub request: ServiceResolutionPublishRequest,
    pub ack: ServiceResolutionPublishAck,
    pub accepted_at: DateTime<Utc>,
}

impl ServiceResolutionMirrorEntry {
    pub fn validate(&self) -> PersistenceResult<()> {
        let artifact_key = self
            .request
            .validate()
            .map_err(|error| super::PersistenceError::SchemaViolation(error.to_string()))?;
        let request_digest = self
            .request
            .canonical_digest()
            .map_err(|error| super::PersistenceError::SchemaViolation(error.to_string()))?;
        self.ack
            .validate_request_binding(&self.source_service_id, &self.request)
            .map_err(|error| super::PersistenceError::SchemaViolation(error.to_string()))?;
        if self.request_id != self.request.request_id
            || self.realm_id != self.request.realm_id
            || self.request_digest != request_digest
            || self.artifact_key != artifact_key
            || self.artifact_digest != self.request.artifact_digest
            || self.accepted_at != self.ack.ack.accepted_at
        {
            return Err(super::PersistenceError::SchemaViolation(
                "service resolution mirror entry cross-binding mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceResolutionMirrorCommit {
    Stored(ServiceResolutionPublishAck),
    Replay(ServiceResolutionPublishAck),
    TransportConflict,
    ArtifactConflict {
        accepted_digest: Hash,
    },
    /// The artifact is a fork at an already-accepted sequence/revision.
    SequenceConflict {
        accepted_digest: Hash,
    },
    /// The artifact is a rollback, gap, or is based on the wrong durable floor.
    SequenceRejected,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MonotonicRouteWrite {
    Applied,
    Replay,
    Stale,
    Conflict { accepted_digest: Hash },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceResolutionForkEvidence {
    pub service_id: ServiceId,
    pub service_kind: String,
    pub artifact_family: String,
    pub artifact_key: String,
    pub accepted_digest: Hash,
    pub conflicting_digest: Hash,
    pub evidence: serde_json::Value,
    pub quarantined_at: DateTime<Utc>,
}

/// Durable safety state for remote route material. Mirror artifacts and ACKs are
/// exact bytes represented by their typed canonical values; the TTL cache is
/// explicitly disposable and never supplies an authority decision.
#[async_trait]
pub trait ServiceRouteStore: Send + Sync {
    async fn last_seen_floor(
        &self,
        service_id: &ServiceId,
        service_kind: &str,
    ) -> PersistenceResult<Option<ServiceResolutionLastSeenFloor>>;

    async fn advance_last_seen_floor(
        &self,
        floor: ServiceResolutionLastSeenFloor,
    ) -> PersistenceResult<MonotonicRouteWrite>;

    async fn notice_state(
        &self,
        service_id: &ServiceId,
        service_kind: &str,
        handover_id: &str,
    ) -> PersistenceResult<Option<ServiceRouteNoticeState>>;

    async fn advance_notice_state(
        &self,
        state: ServiceRouteNoticeState,
    ) -> PersistenceResult<MonotonicRouteWrite>;

    /// Atomically validates and advances the record/notice monotonic floor,
    /// stores the exact mirrored artifact, binds both transport
    /// `(source, realm, request_id)` and artifact
    /// `(source, realm, artifact_key)` idempotency keys, and durably stores the
    /// signed ACK. Only an identical request digest may replay that ACK.
    ///
    /// Implementations MUST perform the complete write on one lock/transaction;
    /// returning `Stored` means a crash cannot retain the ACK without its
    /// corresponding monotonic safety state (or vice versa).
    async fn commit_mirror(
        &self,
        entry: ServiceResolutionMirrorEntry,
    ) -> PersistenceResult<ServiceResolutionMirrorCommit>;

    async fn successor_records(
        &self,
        source_service_id: &ServiceId,
        realm_id: &RealmId,
        target_service_id: &ServiceId,
        service_kind: &str,
        after_sequence: u64,
        limit: usize,
    ) -> PersistenceResult<Vec<ServiceResolutionRecord>>;

    async fn latest_notice(
        &self,
        source_service_id: &ServiceId,
        realm_id: &RealmId,
        target_service_id: &ServiceId,
        service_kind: &str,
    ) -> PersistenceResult<Option<ServiceRouteHandoverNotice>>;

    async fn quarantine_fork(
        &self,
        evidence: ServiceResolutionForkEvidence,
    ) -> PersistenceResult<()>;

    async fn is_quarantined(
        &self,
        service_id: &ServiceId,
        service_kind: &str,
    ) -> PersistenceResult<bool>;

    async fn route_cache(
        &self,
        service_id: &ServiceId,
        service_kind: &str,
    ) -> PersistenceResult<Option<ServiceRouteCacheEntry>>;

    async fn put_route_cache(&self, entry: ServiceRouteCacheEntry) -> PersistenceResult<()>;

    async fn evict_route_cache(
        &self,
        service_id: &ServiceId,
        service_kind: &str,
    ) -> PersistenceResult<()>;
}
