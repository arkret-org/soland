use super::{
    FederationFrontierExchangeRecord, FederationOutboxDeadLetterRecord, FederationOutboxRecord,
    FederationOutboxState, Operation, PersistenceResult, async_trait,
};

/// One atomic "read due rows and take ownership of them" operation.
///
/// Claiming and reading are deliberately one storage call: a bare `SELECT`
/// lets two replicas send the same row concurrently, which the receiver's
/// idempotency absorbs but which inflates traffic, attempt counters and
/// diagnostic noise (`sync/federation.md` §8.5).
#[derive(Clone, Debug)]
pub struct FederationOutboxClaim {
    pub now_unix_secs: i64,
    pub limit: usize,
    /// Stable worker identity, e.g. `<service_id>#<process uuid>`.
    pub lease_owner: String,
    /// Random per-claim token. A row re-claimed later carries a different
    /// token, which is what invalidates the previous holder's writes.
    pub lease_token: String,
    pub lease_duration_secs: i64,
}

/// The terminal or retry decision one delivery attempt produced.
#[derive(Clone, Debug)]
pub enum FederationOutboxOutcome {
    /// Keep the same transport identity (same canonical body, same
    /// `Idempotency-Key`) and try again at `next_attempt_at`.
    Retry { next_attempt_at: i64 },
    /// Peer accepted or confirmed the batch as a duplicate.
    Delivered,
    /// Local egress policy denied the target before any socket was opened.
    /// Not a network failure and not a delivery — it stays recoverable
    /// through revalidation when the policy version changes.
    PolicySuppressed { policy_version: String },
    /// Terminal failure. The dead-letter row is written in the same
    /// transaction as the state change, so "stopped delivering" and "has a
    /// failure ledger entry" can never disagree.
    // Boxed for the same reason as `FederationDeliveryOutcome::DeadLettered`.
    DeadLettered(Box<FederationOutboxDeadLetterRecord>),
    /// A response was received that requires re-evaluation. The old transport
    /// identity is finished and a fresh pending row (new body, new
    /// `Idempotency-Key`, `supersedes_outbox_id` back-reference) replaces it in
    /// the same transaction (`sync/federation.md` §8.5).
    Superseded(Box<FederationOutboxRecord>),
}

/// The full result of one delivery attempt, applied atomically.
#[derive(Clone, Debug)]
pub struct FederationOutboxTransition {
    pub id: String,
    /// Lease token the caller holds. The write only lands when it matches the
    /// row's current `lease_token`.
    pub lease_token: String,
    pub attempts: i32,
    pub semantic_attempts: i32,
    pub last_http_status: Option<i32>,
    pub last_error_code: Option<String>,
    pub last_response_excerpt: Option<String>,
    pub observed_at: i64,
    pub outcome: FederationOutboxOutcome,
}

/// Verdict of one `policy_suppressed` revalidation.
#[derive(Clone, Debug)]
pub enum FederationOutboxPolicyResolution {
    /// Revalidation passed under the new policy — return the row to `pending`.
    Release { next_attempt_at: i64 },
    /// Still denied. Pin the current policy version so the sweep stops
    /// re-checking this row until the policy changes again.
    Repin { policy_version: String },
}

/// Operator replay of one dead letter (`sync/federation.md` §8.5: a response
/// was received, so re-evaluation MUST use a new key).
#[derive(Clone, Debug)]
pub struct FederationOutboxRequeue {
    pub dead_letter_id: String,
    /// Fresh pending row with a new id, a new `Idempotency-Key` and
    /// `supersedes_outbox_id` pointing at the dead-lettered row.
    pub record: FederationOutboxRecord,
    pub operator: String,
    pub reason: String,
    pub request_digest: String,
    pub requeued_at: i64,
}

/// G3.S0 — durable outbound federation HTTP delivery queue.
///
/// Rows are inserted inside the same transaction that accepts the Event; the
/// `FederationDispatcher` background worker
/// (`routing::federation::outbox::FederationDispatcher`) claims due rows under
/// a lease and posts them to peers.
///
/// Idempotency: `(peer_did, idempotency_key)` is UNIQUE. Callers that
/// re-enqueue the same logical request MUST see `enqueue` return `Ok(false)`
/// rather than a duplicate-row error; the worker treats the existing row as
/// the authoritative delivery state.
#[async_trait]
pub trait FederationOutboxStore: Send + Sync {
    /// Insert a new outbox row. Returns `Ok(true)` if a fresh row was
    /// stored, `Ok(false)` if `(peer_did, idempotency_key)` already
    /// exists (callers MUST treat that as "already enqueued" rather
    /// than an error — see trait-doc idempotency note).
    async fn enqueue(&self, record: &FederationOutboxRecord) -> PersistenceResult<bool>;
    /// Atomically claim up to `limit` rows in `pending` state whose
    /// `next_attempt_at <= now`, plus rows whose `leased` state has an expired
    /// lease, ordered by `next_attempt_at` ascending. Implementations MUST
    /// stamp `lease_owner` / `lease_token` / `lease_expires_at` and move the
    /// rows to `leased` in the same statement that selects them, so two
    /// replicas never claim the same row.
    async fn claim_due(
        &self,
        claim: &FederationOutboxClaim,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>>;
    /// Apply one delivery attempt's result. Returns `Ok(false)` when the lease
    /// token no longer matches, i.e. the caller is a stale holder whose write
    /// MUST be dropped. Terminal transitions and their dead-letter or successor
    /// rows commit together or not at all.
    async fn complete(&self, transition: &FederationOutboxTransition) -> PersistenceResult<bool>;
    /// Rows currently parked in `policy_suppressed` whose recorded
    /// `policy_version` differs from `current_policy_version`. Those are the
    /// only candidates for revalidation; a bare restart never re-opens a row
    /// the still-current policy denied.
    async fn policy_suppressed_stale(
        &self,
        current_policy_version: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>>;
    /// Apply the revalidation verdict to one `policy_suppressed` row. Returns
    /// `Ok(false)` when the row left `policy_suppressed` meanwhile.
    async fn resolve_policy_suppressed(
        &self,
        id: &str,
        resolution: &FederationOutboxPolicyResolution,
    ) -> PersistenceResult<bool>;
    /// Fetch a single row by primary key.
    async fn get(&self, id: &str) -> PersistenceResult<Option<FederationOutboxRecord>>;
    /// Snapshot the full table — diagnostics + the integration test
    /// rely on it. Production deployments SHOULD NOT call this on a
    /// large outbox; use `claim_due` instead.
    async fn snapshot_all(&self) -> PersistenceResult<Vec<FederationOutboxRecord>>;
    /// Rows in one lifecycle state, newest first, for the operator surfaces.
    async fn list_by_state(
        &self,
        state: FederationOutboxState,
        limit: usize,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>>;
    /// Aggregate depth per `(state, peer_did)` for the gauge exporter.
    async fn state_depth(&self) -> PersistenceResult<Vec<FederationOutboxStateDepth>>;
    async fn dead_letter(
        &self,
        id: &str,
    ) -> PersistenceResult<Option<FederationOutboxDeadLetterRecord>>;
    async fn dead_letters_snapshot(
        &self,
    ) -> PersistenceResult<Vec<FederationOutboxDeadLetterRecord>>;
    /// Insert the replay row and stamp the operator audit onto the dead letter
    /// in one transaction. Returns `Ok(false)` when the dead letter is missing
    /// or was already requeued.
    async fn requeue_dead_letter(
        &self,
        command: &FederationOutboxRequeue,
    ) -> PersistenceResult<bool>;
}

/// One `(state, peer_did)` bucket of the outbox depth gauge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederationOutboxStateDepth {
    pub state: FederationOutboxState,
    pub peer_did: String,
    pub depth: i64,
    /// Unix seconds of the oldest row in this bucket, for the pending-age
    /// alert. `None` when the bucket is empty.
    pub oldest_created_at: Option<i64>,
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
