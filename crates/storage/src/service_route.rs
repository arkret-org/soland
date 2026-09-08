use arkret_models_identity::{ServiceMethodState, ServiceRouteCacheEntry};
use arkret_wire::{DidCoreId, Hash};
use chrono::{DateTime, Utc};

use super::{PersistenceResult, async_trait};
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MonotonicRouteWrite {
    Applied,
    Replay,
    Stale,
    Conflict { accepted_digest: Hash },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceResolutionForkEvidence {
    pub service_id: DidCoreId,
    pub service_kind: String,
    pub artifact_family: String,
    pub artifact_key: String,
    pub accepted_digest: Hash,
    pub conflicting_digest: Hash,
    pub evidence: serde_json::Value,
    pub quarantined_at: DateTime<Utc>,
}

/// Stable key for one locally persisted, independently verified service-route
/// projection. It is deployment-local inventory data, not a protocol
/// discovery or authorization statement.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ServiceRouteStoredKey {
    pub service_id: DidCoreId,
    pub service_kind: String,
}

/// Durable safety state for remote route material. The TTL cache is disposable; accepted native
/// method state survives eviction.
#[async_trait]
pub trait ServiceRouteStore: Send + Sync {
    /// Keyset-paginated inventory across method state, quarantine,
    /// and disposable-cache tables. Implementations must clamp `limit` to a
    /// bounded value and return at most that many keys.
    async fn list_stored_route_keys(
        &self,
        after: Option<&ServiceRouteStoredKey>,
        limit: usize,
    ) -> PersistenceResult<Vec<ServiceRouteStoredKey>>;

    async fn quarantine_evidence(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<ServiceResolutionForkEvidence>>;

    async fn method_state(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> PersistenceResult<Option<ServiceMethodState>>;

    async fn publish_route_cache(
        &self,
        evidence: arkret_models_identity::AuthenticatedServiceResolution,
        entry: ServiceRouteCacheEntry,
    ) -> PersistenceResult<MonotonicRouteWrite>;

    async fn quarantine_fork(
        &self,
        evidence: ServiceResolutionForkEvidence,
    ) -> PersistenceResult<()>;

    async fn is_quarantined(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> PersistenceResult<bool>;

    async fn route_cache(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> PersistenceResult<Option<ServiceRouteCacheEntry>>;

    async fn evict_route_cache(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> PersistenceResult<()>;
}
