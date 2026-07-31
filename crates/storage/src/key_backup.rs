use super::{PersistenceResult, Utc, Value, async_trait};

/// A server-issued key-backup delete challenge
/// (`key-management.md` §7.8.1,
/// `keys-operations.schema.json#/$defs/keys_backups_delete_challenge`).
///
/// `challenge` holds the whole serialized challenge so the wire shape keeps one
/// definition (the SDK type) instead of a column per member; the columns beside
/// it are exactly the ones the two lookups need — by `challenge_id` to verify a
/// DELETE, and by `(principal_id, backup_id, request_id)` to re-issue the same
/// challenge while it is still valid.
///
/// `consumed_at` is what makes the challenge single-use. It is set in the same
/// transaction as the delete it authorizes, so a replay finds it consumed.
#[derive(Clone, Debug, PartialEq)]
pub struct KeyBackupDeleteChallengeRecord {
    pub challenge_id: String,
    pub principal_id: String,
    pub backup_id: String,
    pub request_id: String,
    pub challenge: Value,
    pub issued_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
    pub consumed_at: Option<chrono::DateTime<Utc>>,
}

/// Encrypted key-backup envelopes (one row per `backup_id`), plus the durable
/// delete-challenge ledger the high-risk DELETE path consumes.
#[async_trait]
pub trait KeyBackupStore: Send + Sync {
    async fn put(&self, backup_id: String, payload: Value) -> PersistenceResult<()>;
    async fn get(&self, backup_id: &str) -> PersistenceResult<Option<Value>>;
    async fn delete(&self, backup_id: &str) -> PersistenceResult<bool>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>>;
    async fn list_for_actor(&self, actor_id: &str) -> PersistenceResult<Vec<Value>>;

    /// Issue `record`, or return the still-valid challenge already issued for
    /// the same `(principal_id, backup_id, request_id)`.
    ///
    /// §7.8.1 requires re-issuing the *same* challenge while it is valid, so a
    /// client retrying the issue call does not invalidate the challenge it is
    /// already signing. "Still valid" is unconsumed and unexpired; a consumed or
    /// expired row is replaced.
    async fn issue_delete_challenge(
        &self,
        record: KeyBackupDeleteChallengeRecord,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<KeyBackupDeleteChallengeRecord>;

    /// Read a challenge by id, consumed or not. The caller distinguishes
    /// "expired", "already consumed" and "belongs to another principal or
    /// backup" so each is reported as its own failure.
    async fn delete_challenge(
        &self,
        challenge_id: &str,
    ) -> PersistenceResult<Option<KeyBackupDeleteChallengeRecord>>;

    /// Atomically mark a challenge consumed. Returns `false` when it was
    /// already consumed or does not exist, which is what makes a concurrent
    /// double-DELETE lose exactly once.
    async fn consume_delete_challenge(
        &self,
        challenge_id: &str,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<bool>;

    /// TTL sweep for challenges at or past `now`.
    async fn prune_expired_delete_challenges(
        &self,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<usize>;
}
