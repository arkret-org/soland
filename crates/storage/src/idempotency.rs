use super::{PersistenceResult, Utc, Value, async_trait};
/// A persisted generic `Idempotency-Key` mapping (api-conventions.md §6).
///
/// One row per `(authenticated_actor, operation_id, idempotency_key)`: the first request under a
/// key records its canonical request hash plus the full first response (status +
/// body). A replay carrying the same key MUST return this cached first response
/// when its canonical request body hashes to `request_hash`, and MUST be
/// rejected with `duplicate_conflict` when the same key arrives with a
/// different canonical body. Durable so the mapping survives a restart at least
/// until `expires_at`, per §6 ("server SHOULD record the idempotency mapping at
/// least until the related Event is fully synced or expired").
#[derive(Clone, Debug, PartialEq)]
pub struct IdempotencyRecord {
    pub authenticated_actor: arkret_wire::ActorId,
    pub operation_id: String,
    pub idempotency_key: String,
    pub request_hash: String,
    pub response_status: i32,
    pub response_body: Value,
    pub created_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
}

/// Durable first result for one PCR Seal signing position.
///
/// Unlike ordinary idempotency rows, this record has no expiry. A signer may
/// have signed the returned body while offline, so lease expiry, cache eviction
/// and process restart can never make the position available for another body.
#[derive(Clone, Debug, PartialEq)]
pub struct SealPreparationFenceRecord {
    pub realm_id: arkret_wire::RealmId,
    pub signer_slot: String,
    pub predecessor_basis: String,
    pub request_hash: String,
    pub response_body: Value,
    pub body_digest: String,
    pub created_at: chrono::DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SealPreparationFenceOutcome {
    Frozen(SealPreparationFenceRecord),
    Replay(SealPreparationFenceRecord),
    Fenced,
}
/// Durable `(authenticated actor, operation id, key) -> first response` table.
#[async_trait]
pub trait IdempotencyStore: Send + Sync {
    /// Read the cached record for a key, if any (used to decide Fresh / Replay /
    /// Conflict against the request hash at the call site).
    async fn get(
        &self,
        authenticated_actor: &arkret_wire::ActorId,
        operation_id: &str,
        idempotency_key: &str,
    ) -> PersistenceResult<Option<IdempotencyRecord>>;
    /// Persist the FIRST response under a key. `ON CONFLICT DO NOTHING`: a
    /// concurrent first-writer race keeps the earliest landed row, so a later
    /// racer reads it back as a `Replay` instead of clobbering it.
    async fn record(&self, record: &IdempotencyRecord) -> PersistenceResult<()>;
    /// Atomically replace an exact first-writer reservation with its terminal
    /// response. The compare includes the entire expected row, so a worker can
    /// complete only the reservation token it acquired; a stale or competing
    /// worker cannot overwrite the landed outcome.
    async fn complete_reservation(
        &self,
        expected: &IdempotencyRecord,
        completed: &IdempotencyRecord,
    ) -> PersistenceResult<bool>;
    /// TTL sweep: drop every row whose `expires_at` is at or before `now`.
    async fn prune_expired(&self, now: chrono::DateTime<Utc>) -> PersistenceResult<usize>;

    /// Read the immutable result for one PCR signing position, if it exists.
    async fn seal_preparation_fence(
        &self,
        realm_id: &arkret_wire::RealmId,
        signer_slot: &str,
        predecessor_basis: &str,
    ) -> PersistenceResult<Option<SealPreparationFenceRecord>>;

    /// Atomically freeze the first complete response for a PCR signing
    /// position. A matching request replays the landed response; a different
    /// request is fenced without changing the durable row.
    async fn freeze_seal_preparation(
        &self,
        record: &SealPreparationFenceRecord,
    ) -> PersistenceResult<SealPreparationFenceOutcome>;
}
