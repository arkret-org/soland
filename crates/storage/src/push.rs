use super::{OutboundPushBridgeCacheRecord, PersistenceResult, Utc, Value, async_trait};
/// Push device registrations. Unstructured `Value` while the schema is in
/// flux; the trait gives us a single point to upgrade later.
#[async_trait]
pub trait PushDeviceStore: Send + Sync {
    async fn register(&self, device: Value) -> PersistenceResult<()>;
    async fn unregister(
        &self,
        actor: &str,
        device_id: &str,
        push_key: Option<&str>,
        app_id: Option<&str>,
    ) -> PersistenceResult<usize>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>>;
}
/// Canonical push-gateway `ServiceDescribe` cache (describe URL → snapshot).
///
/// C33.1 (T0-3a): the cache row doubles as the canonical gateway-contract
/// snapshot. The internal refresh path stores a complete validated snapshot;
/// `current_contract` reads it back, and `verify_contract_freshness` is the
/// fail-closed gate the push outbound publish path calls before fan-out.
#[async_trait]
pub trait PushBridgeCacheStore: Send + Sync {
    async fn put(
        &self,
        bridge_describe_url: &str,
        record: OutboundPushBridgeCacheRecord,
    ) -> PersistenceResult<()>;
    /// Read the current persisted contract snapshot for a gateway, if any.
    async fn current_contract(
        &self,
        gateway_describe_url: &str,
    ) -> PersistenceResult<Option<OutboundPushBridgeCacheRecord>>;

    /// Compare a freshly observed contract digest against the persisted
    /// snapshot. Used by `push_notify` (and any other outbound publish
    /// surface) to fail closed before fan-out. The decision is:
    ///
    /// * `Match`           — observed digest matches the persisted digest, trust_level is
    ///   `trusted`, freshness within `max_age`. Caller may proceed.
    /// * `Stale`           — digest matches but `freshness_at` is older than `max_age`. Caller must
    ///   NOT proceed.
    /// * `DigestMismatch`  — persisted snapshot exists but `observed_digest` differs (or persisted
    ///   trust_level is `revoked`).
    /// * `Unknown`         — no snapshot persisted, OR the snapshot is still `pending` / has empty
    ///   digest. Fail-closed.
    async fn verify_contract_freshness(
        &self,
        gateway_describe_url: &str,
        observed_digest: &str,
        max_age: chrono::Duration,
    ) -> PersistenceResult<DriftResult>;
}
/// Outcome of `PushBridgeCacheStore::verify_contract_freshness`. The push
/// outbound publish path treats anything other than `Match` as fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftResult {
    /// Observed digest matches a trusted, fresh snapshot.
    Match,
    /// Digest matches but the snapshot is older than `max_age`.
    Stale,
    /// Persisted digest differs from observed (or snapshot revoked).
    DigestMismatch,
    /// No snapshot persisted, or snapshot still pending / empty digest.
    Unknown,
}
impl DriftResult {
    /// Stable string label suitable for audit `outcome` fields and the
    /// `drift_result` field on rejection responses.
    pub fn as_str(self) -> &'static str {
        match self {
            DriftResult::Match => "match",
            DriftResult::Stale => "stale",
            DriftResult::DigestMismatch => "digest_mismatch",
            DriftResult::Unknown => "unknown",
        }
    }
}
/// Pure decision function shared by Memory + Pg backends. Keeps the
/// fail-closed semantics in one place so the two impls cannot drift.
#[doc(hidden)]
pub fn evaluate_drift(
    snapshot: Option<&OutboundPushBridgeCacheRecord>,
    observed_digest: &str,
    max_age: chrono::Duration,
) -> DriftResult {
    let Some(record) = snapshot else {
        return DriftResult::Unknown;
    };
    if record.contract_digest.is_empty() || record.trust_level == "pending" {
        return DriftResult::Unknown;
    }
    if record.trust_level == "revoked" {
        return DriftResult::DigestMismatch;
    }
    if record.contract_digest != observed_digest {
        return DriftResult::DigestMismatch;
    }
    let age = Utc::now().signed_duration_since(record.freshness_at);
    if age > max_age {
        return DriftResult::Stale;
    }
    DriftResult::Match
}
