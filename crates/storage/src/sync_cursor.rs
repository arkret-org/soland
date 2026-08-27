use super::{CursorRevocation, PersistenceResult, Utc, Value, async_trait};
/// Stateful sync-cursor handle binding (`cursor.schema.json` `h`).
///
/// One row per distinct cursor content: the handle is an HMAC digest of the
/// binding (principal, device, service, filter, purpose, positions/target),
/// so re-minting an unchanged cursor upserts the same row instead of growing
/// the table. Durable so a server restart does not invalidate every client's
/// resume cursor with `cursor_integrity_invalid`.
///
/// `principal_id` / `device_id` / `filter_digest` are `None` for generic
/// service-level cursors (`sync_token_for_state`), which bind no session and
/// are rejected by `parse_and_validate_sync_cursor` by construction.
#[derive(Clone, Debug, PartialEq)]
pub struct SyncCursorRecord {
    pub handle: String,
    pub principal_id: Option<String>,
    pub device_id: Option<String>,
    pub service_id: String,
    pub filter_digest: Option<String>,
    pub purpose: String,
    pub positions: Option<Value>,
    pub target: Option<Value>,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}
/// Durable handle table behind the stateful sync cursor.
///
/// `upsert` keeps the FIRST `issued_at_ms` on conflict (refreshing only the
/// expiry): `issued_at_ms` is used for forward-progress pruning of older
/// handles. Account subscribe freshness is represented by `positions.realms`
/// plus `positions.account_realms`, so a projection-only delta must advance
/// the relevant position instead of relying on a refreshed issue timestamp.
#[async_trait]
pub trait SyncCursorStore: Send + Sync {
    async fn get(&self, handle: &str) -> PersistenceResult<Option<SyncCursorRecord>>;
    async fn upsert(&self, record: &SyncCursorRecord) -> PersistenceResult<()>;
    /// Delete one handle (cursor revoke).
    async fn delete(&self, handle: &str) -> PersistenceResult<bool>;
    /// Forward-progress cleanup: delete this stream's rows STRICTLY older
    /// than the cursor the client just presented (presenting a cursor proves
    /// everything older was persisted client-side). Never deletes the
    /// presented row itself or anything newer.
    async fn prune_stream_superseded(
        &self,
        principal_id: &str,
        device_id: &str,
        filter_digest: &str,
        presented_issued_at_ms: i64,
    ) -> PersistenceResult<usize>;
    /// TTL sweep: drop every row whose `expires_at_ms` is at or before `now_ms`.
    async fn prune_expired(&self, now_ms: i64) -> PersistenceResult<usize>;
    /// Append a cursor-authority revocation (`ak.self.account.command.revoke_cursor.v1`)
    /// to the durable ledger. Expired ledger rows are swept opportunistically
    /// on every write so the table stays bounded by `CURSOR_MAX_TTL_SECONDS`.
    ///
    /// Durability here is a security property: a revoked cursor MUST stay
    /// revoked across a process restart (spec `client-sync.md` cursor-revoke
    /// semantics), so the in-memory revocation cache on `AppState` is
    /// hydrated from this ledger at boot.
    async fn record_revocation(&self, record: &CursorRevocation) -> PersistenceResult<()>;
    /// Every revocation whose GC horizon (`expires_at`) is still in the
    /// future. Used to hydrate the in-memory revocation cache at boot.
    async fn active_revocations(
        &self,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<Vec<CursorRevocation>>;
}
