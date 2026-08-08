use super::{BTreeMap, MultisigPendingRecord, PersistenceResult, Value, async_trait};
/// MAL-11 — persistent multisig partial-signature buffer.
///
/// The notary coordinator writes partials to this store so they survive
/// restarts and can be picked up by a leader-election watchdog once the
/// threshold is met. The read-only admin endpoint exposes pending status.
/// Memory backend is fine for dev/tests; the Pg backend writes to the
/// `multisig_pending` table.
#[async_trait]
pub trait MultisigPendingStore: Send + Sync {
    async fn upsert(&self, record: MultisigPendingRecord) -> PersistenceResult<()>;
    async fn get(&self, seal_id: &str) -> PersistenceResult<Option<MultisigPendingRecord>>;
    async fn add_partial(
        &self,
        seal_id: &str,
        signer_did: &str,
        partial: Value,
    ) -> PersistenceResult<MultisigPendingRecord>;
    async fn list_for_realm(&self, realm_id: &str)
    -> PersistenceResult<Vec<MultisigPendingRecord>>;
    async fn delete(&self, seal_id: &str) -> PersistenceResult<bool>;

    /// List every row across all Realms. Used by the leader-election
    /// watchdog to scan for threshold-met rows that need aggregation +
    /// publication.
    async fn snapshot_all(&self) -> PersistenceResult<Vec<MultisigPendingRecord>>;

    /// Atomically claim a row for `node_id` until `claimed_until` if (a)
    /// the row exists, (b) it is currently unclaimed or its existing lease
    /// has expired (relative to `now`).
    ///
    /// On success the row's monotonic `claim_seq` is bumped by 1 and the
    /// new value is returned alongside the success flag. The watchdog
    /// snapshots this value as its **fencing token**: any
    /// follow-up `delete_with_fence` / `renew_claim` it issues against
    /// the row carries the same `claim_seq`, and a stale leader (whose
    /// lease was silently re-issued to another node after a partition
    /// healed) finds its `claim_seq` no longer matches and is rejected
    /// at the row level. Returns `Ok((true, new_seq))` when this caller
    /// now owns the lease, `Ok((false, current_seq))` otherwise.
    async fn try_claim(
        &self,
        seal_id: &str,
        node_id: &str,
        now: chrono::DateTime<chrono::Utc>,
        claimed_until: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<(bool, i64)>;

    /// Release a held lease (called after the row was successfully
    /// aggregated + deleted, or when the caller decided to give up
    /// early). Idempotent — safe to call on a row that was already
    /// deleted.
    async fn release_claim(&self, seal_id: &str, node_id: &str) -> PersistenceResult<()>;

    /// Fenced delete. Only deletes the row when both the lease holder
    /// *and* the fencing token match. A stale leader (one whose lease
    /// was superseded after a partition heal) carries a mismatched
    /// `claim_seq`, so this returns `Ok(false)` and the row stays intact
    /// for the live leader to publish. Returns `Ok(true)` iff the delete
    /// happened.
    async fn delete_with_fence(
        &self,
        seal_id: &str,
        node_id: &str,
        claim_seq: i64,
    ) -> PersistenceResult<bool>;

    /// Happy-path lease renewal during long aggregation. Pushes
    /// `claimed_until` forward without bumping `claim_seq` (so the
    /// watchdog's snapshotted fencing token stays valid). Only succeeds
    /// when the lease is still held by `node_id` AND the supplied
    /// `claim_seq` matches the row — a stale leader's renewal is
    /// rejected. Returns `Ok(true)` iff the renewal landed.
    async fn renew_claim(
        &self,
        seal_id: &str,
        node_id: &str,
        claim_seq: i64,
        new_claimed_until: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool>;
}
#[doc(hidden)]
pub fn partials_to_jsonb(partials: &BTreeMap<String, Value>) -> Value {
    let mut map = serde_json::Map::new();
    for (k, v) in partials {
        map.insert(k.clone(), v.clone());
    }
    Value::Object(map)
}
