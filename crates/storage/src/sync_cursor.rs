use super::{CursorRevocation, PersistenceResult, Utc, Value, async_trait};
/// Private durable account summary read position; never a wire cursor.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AccountSummaryKey {
    pub activity_position: i64,
    pub realm_id: String,
    pub revision: i64,
}

#[derive(Clone, Debug)]
pub struct AccountSummaryVersion {
    pub key: AccountSummaryKey,
    pub membership: Option<String>,
    pub title: Option<String>,
    pub default_strand_id: Option<String>,
    pub valid_until: Option<i64>,
    pub current_membership: Option<String>,
    pub current_available: bool,
    pub invalidated: bool,
}

#[derive(Clone, Debug)]
pub struct AccountGlobalVersion {
    pub item_key: String,
    pub revision: i64,
    pub deleted: bool,
    pub payload: Value,
}

/// Stateful sync-cursor handle binding (`cursor.schema.json` `h`).
///
/// One row per distinct cursor content: the handle is an HMAC digest of the
/// binding (subject, device, service, filter, purpose, positions/target),
/// so re-minting an unchanged cursor upserts the same row instead of growing
/// the table. Durable so a server restart does not invalidate every client's
/// resume cursor with `cursor_integrity_invalid`.
///
/// `binding_subject` / `device_id` / `filter_digest` are `None` for generic
/// service-level cursors (`sync_token_for_state`), which bind no session and
/// are rejected by `parse_and_validate_sync_cursor` by construction.
#[derive(Clone, Debug, PartialEq)]
pub struct SyncCursorRecord {
    pub handle: String,
    pub binding_subject: Option<String>,
    pub device_id: Option<String>,
    pub service_id: arkret_identifiers::DidCoreId,
    pub filter_digest: Option<String>,
    pub purpose: String,
    pub positions: Option<Value>,
    pub target: Option<Value>,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}
/// Durable handle table behind the stateful sync cursor.
///
/// Reminted handles retain their original identity and extend retention only.
/// Presenting another cursor never revokes older immutable retry authorities.
#[async_trait]
pub trait SyncCursorStore: Send + Sync {
    async fn current_detail_page(
        &self,
        request: &super::CurrentDetailRequest,
        progress: Option<&super::CurrentDetailProgress>,
        byte_budget: usize,
        registry: &dyn arkret_state::state::CellRegistry,
    ) -> PersistenceResult<super::CurrentDetailOutcome>;
    async fn account_summary_has_join(
        &self,
        actor_key: &str,
        realm_id: &str,
    ) -> PersistenceResult<bool>;
    async fn account_sync_watermarks(&self) -> PersistenceResult<(i64, i64)>;
    async fn account_global_watermark(&self) -> PersistenceResult<i64>;
    async fn account_global_page(
        &self,
        actor_key: &str,
        channel: &str,
        watermark: i64,
        after_key: &str,
        after_revision: Option<i64>,
        limit: usize,
    ) -> PersistenceResult<Vec<AccountGlobalVersion>>;
    async fn account_summary_watermark(&self) -> PersistenceResult<i64>;
    async fn account_summary_page(
        &self,
        actor_key: &str,
        watermark: i64,
        after: Option<&AccountSummaryKey>,
        limit: usize,
    ) -> PersistenceResult<Vec<AccountSummaryVersion>>;
    async fn account_summary_changes(
        &self,
        actor_key: &str,
        after_revision: i64,
        limit: usize,
    ) -> PersistenceResult<Vec<AccountSummaryVersion>>;
    async fn get(&self, handle: &str) -> PersistenceResult<Option<SyncCursorRecord>>;
    async fn upsert(&self, record: &SyncCursorRecord) -> PersistenceResult<()>;
    /// Delete one handle (cursor revoke).
    async fn delete(&self, handle: &str) -> PersistenceResult<bool>;

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
