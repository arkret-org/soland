use super::*;
/// Trait for durable federation transaction replay records.
#[async_trait]
pub trait FederationTransactionStore: Send + Sync {
    async fn get(
        &self,
        origin: &str,
        txn_id: &str,
    ) -> PersistenceResult<Option<FederationTransactionRecord>>;
    /// Atomically claim the `(origin, txn_id)` idempotency slot *before*
    /// running any side-effecting ingest. Inserts `record` (a
    /// `status="processing"` placeholder) only when no row exists yet —
    /// `INSERT ... ON CONFLICT DO NOTHING` semantics. Returns `Ok(true)`
    /// when this caller now owns the slot and must run the ingest plus the
    /// finalising [`put`](Self::put); `Ok(false)` when another in-flight or
    /// completed request already holds it. This closes the get→ingest→put
    /// TOCTOU window: two concurrent deliveries of the same txn_id can
    /// never both execute the operation batch.
    async fn try_begin(&self, record: &FederationTransactionRecord) -> PersistenceResult<bool>;
    async fn put(&self, record: &FederationTransactionRecord) -> PersistenceResult<()>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<FederationTransactionRecord>>;
}
/// G3.S0 — durable outbound federation HTTP delivery queue.
///
/// Rows are inserted synchronously on the inbound write path
/// (`routing::federation::federation::broadcast_move_to_peers` and
/// `broadcast_seal_to_peers`); the `FederationDispatcher` background
/// worker (`routing::federation::outbox::FederationDispatcher`) polls
/// pending rows and posts them to peers.
///
/// Idempotency: `(peer_did, idempotency_key)` is UNIQUE. Callers that
/// re-enqueue the same logical request (replay of an accepted Move /
/// Seal on restart) MUST see `enqueue` return `Ok(false)` rather than
/// a duplicate-row error; the worker treats the existing row as the
/// authoritative delivery state.
#[async_trait]
pub trait FederationOutboxStore: Send + Sync {
    /// Insert a new outbox row. Returns `Ok(true)` if a fresh row was
    /// stored, `Ok(false)` if `(peer_did, idempotency_key)` already
    /// exists (callers MUST treat that as "already enqueued" rather
    /// than an error — see trait-doc idempotency note).
    async fn enqueue(&self, record: &FederationOutboxRecord) -> PersistenceResult<bool>;
    /// Returns rows where `delivered_at IS NULL` and `next_attempt_at
    /// <= now_unix_secs`, ordered by `next_attempt_at` ascending. The
    /// `limit` caps the per-poll batch so a backlog never starves
    /// other workers on the same tokio runtime.
    async fn pending_due(
        &self,
        now_unix_secs: i64,
        limit: usize,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>>;
    /// Replace the row by `id`. Used by the worker after every delivery
    /// attempt to record the new `attempts` / `last_status` /
    /// `next_attempt_at` / `delivered_at` columns.
    async fn update(&self, record: &FederationOutboxRecord) -> PersistenceResult<()>;
    /// Fetch a single row by primary key. Used by the integration test
    /// (and the optional admin observability endpoint, not wired in
    /// G3.S0).
    async fn get(&self, id: &str) -> PersistenceResult<Option<FederationOutboxRecord>>;
    /// Snapshot the full table — diagnostics + the integration test
    /// rely on it. Production deployments SHOULD NOT call this on a
    /// large outbox; use `pending_due` instead.
    async fn snapshot_all(&self) -> PersistenceResult<Vec<FederationOutboxRecord>>;
    /// Append a terminal failure to the dead-letter queue. The outbox row
    /// remains in place for idempotency and diagnostics; this queue is the
    /// operator-facing replay/quarantine surface.
    async fn insert_dead_letter(
        &self,
        record: &FederationOutboxDeadLetterRecord,
    ) -> PersistenceResult<()>;
    async fn dead_letters_snapshot(
        &self,
    ) -> PersistenceResult<Vec<FederationOutboxDeadLetterRecord>>;
}
pub const FEDERATION_FRONTIER_STALE_FAILURES: i32 = 3;
pub const FEDERATION_FRONTIER_STATUS_HEALTHY: &str = "healthy";
pub const FEDERATION_FRONTIER_STATUS_STALE_PEER: &str = "stale_peer";
#[async_trait]
pub trait FederationFrontierExchangeStore: Send + Sync {
    async fn get(
        &self,
        realm_id: &str,
        peer_service_id: &str,
    ) -> PersistenceResult<Option<FederationFrontierExchangeRecord>>;
    async fn record_success(
        &self,
        realm_id: &str,
        peer_service_id: &str,
        frontier_root: &str,
        observed_at: i64,
    ) -> PersistenceResult<FederationFrontierExchangeRecord>;
    async fn record_failure(
        &self,
        realm_id: &str,
        peer_service_id: &str,
        reason: &str,
        observed_at: i64,
    ) -> PersistenceResult<FederationFrontierExchangeRecord>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<FederationFrontierExchangeRecord>>;
}
#[doc(hidden)]
pub fn frontier_exchange_success_record(
    existing: Option<FederationFrontierExchangeRecord>,
    realm_id: &str,
    peer_service_id: &str,
    frontier_root: &str,
    observed_at: i64,
) -> FederationFrontierExchangeRecord {
    FederationFrontierExchangeRecord {
        realm_id: realm_id.to_owned(),
        peer_service_id: peer_service_id.to_owned(),
        status: FEDERATION_FRONTIER_STATUS_HEALTHY.to_owned(),
        consecutive_failures: 0,
        last_success_at: Some(observed_at),
        last_failure_at: existing.and_then(|record| record.last_failure_at),
        last_frontier_root: Some(frontier_root.to_owned()),
        last_error: None,
        updated_at: observed_at,
    }
}
#[doc(hidden)]
pub fn frontier_exchange_failure_record(
    existing: Option<FederationFrontierExchangeRecord>,
    realm_id: &str,
    peer_service_id: &str,
    reason: &str,
    observed_at: i64,
) -> FederationFrontierExchangeRecord {
    let failures = existing
        .as_ref()
        .map(|record| record.consecutive_failures.saturating_add(1))
        .unwrap_or(1);
    let status = if failures >= FEDERATION_FRONTIER_STALE_FAILURES {
        FEDERATION_FRONTIER_STATUS_STALE_PEER
    } else {
        FEDERATION_FRONTIER_STATUS_HEALTHY
    };
    FederationFrontierExchangeRecord {
        realm_id: realm_id.to_owned(),
        peer_service_id: peer_service_id.to_owned(),
        status: status.to_owned(),
        consecutive_failures: failures,
        last_success_at: existing.as_ref().and_then(|record| record.last_success_at),
        last_failure_at: Some(observed_at),
        last_frontier_root: existing.and_then(|record| record.last_frontier_root),
        last_error: Some(reason.to_owned()),
        updated_at: observed_at,
    }
}
/// Replay log of federation operations the local service has accepted from
/// peers (and emitted itself). Currently in-memory but the trait shape is
/// what the durable Pg implementation will follow.
#[async_trait]
pub trait FederationOperationsStore: Send + Sync {
    async fn append(&self, operation: Operation) -> PersistenceResult<()>;
    async fn contains(&self, operation_id: &str) -> PersistenceResult<bool>;
    async fn list_for_realm(&self, realm_id: &str) -> PersistenceResult<Vec<Operation>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<Operation>>;
}
