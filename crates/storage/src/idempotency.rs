use super::*;
/// A persisted generic `Idempotency-Key` mapping (api-conventions.md §6).
///
/// One row per `(principal_id, idempotency_key)`: the first request under a key
/// records its canonical request hash plus the full first response (status +
/// body). A replay carrying the same key MUST return this cached first response
/// when its canonical request body hashes to `request_hash`, and MUST be
/// rejected with `duplicate_conflict` when the same key arrives with a
/// different canonical body. Durable so the mapping survives a restart at least
/// until `expires_at`, per §6 ("server SHOULD record the idempotency mapping at
/// least until the related Event is fully synced or expired").
#[derive(Clone, Debug, PartialEq)]
pub struct IdempotencyRecord {
    pub principal_id: String,
    pub idempotency_key: String,
    pub service_id: String,
    pub request_hash: String,
    pub response_status: i32,
    pub response_body: Value,
    pub created_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
}
/// Durable `(principal_id, idempotency_key) -> first response` table.
#[async_trait]
pub trait IdempotencyStore: Send + Sync {
    /// Read the cached record for a key, if any (used to decide Fresh / Replay /
    /// Conflict against the request hash at the call site).
    async fn get(
        &self,
        principal_id: &str,
        idempotency_key: &str,
    ) -> PersistenceResult<Option<IdempotencyRecord>>;
    /// Persist the FIRST response under a key. `ON CONFLICT DO NOTHING`: a
    /// concurrent first-writer race keeps the earliest landed row, so a later
    /// racer reads it back as a `Replay` instead of clobbering it.
    async fn record(&self, record: &IdempotencyRecord) -> PersistenceResult<()>;
    /// TTL sweep: drop every row whose `expires_at` is at or before `now`.
    async fn prune_expired(&self, now: chrono::DateTime<Utc>) -> PersistenceResult<usize>;
}
