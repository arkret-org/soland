/// Storage key for an ordered backup metadata page; never exposed in cursor wire bytes.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBackupListPosition {
    pub backup_kind: String,
    pub series_id: String,
    pub series_seq: i64,
    pub backup_id: String,
}

#[derive(Clone, Debug)]
pub struct KeyBackupListQuery {
    pub actor_id: String,
    pub backup_kind: Option<String>,
    pub series_id: Option<String>,
    pub after: Option<KeyBackupListPosition>,
    pub limit: u32,
}

#[derive(Clone, Debug)]
pub struct KeyBackupListPage {
    pub revision: i64,
    pub byte_limited: bool,
    pub payloads: Vec<serde_json::Value>,
}

use super::{PersistenceResult, Utc, Value, async_trait};

/// A server-issued key-backup delete challenge
/// (`key-management.md` §7.8.1,
/// `keys-operations.schema.json#/$defs/keys_backups_delete_challenge`).
///
/// `challenge` holds the whole serialized challenge so the wire shape keeps one
/// definition (the SDK type) instead of a column per member; the columns beside
/// it are exactly the ones the two lookups need — by `challenge_id` to verify a
/// DELETE, and by `(account_id, backup_id, request_id)` to re-issue the same
/// challenge while it is still valid.
///
/// `consumed_at` is what makes the challenge single-use. It is set in the same
/// transaction as the delete it authorizes, so a replay finds it consumed.
#[derive(Clone, Debug, PartialEq)]
pub struct KeyBackupDeleteChallengeRecord {
    pub challenge_id: String,
    pub account_id: arkret_wire::AccountId,
    pub backup_id: String,
    pub request_id: String,
    pub challenge: Value,
    pub issued_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
    pub consumed_at: Option<chrono::DateTime<Utc>>,
}

/// Frozen authorization inputs rechecked inside the destructive transaction.
#[derive(Clone, Debug)]
pub struct KeyBackupDeleteGate {
    pub active_basis: Value,
    pub device_gates: Vec<crate::DeviceRevocationGateSelector>,
    pub expected_policy: Option<Value>,
}

/// Encrypted key-backup envelopes (one row per `backup_id`), plus the durable
/// delete-challenge ledger the high-risk DELETE path consumes.
#[async_trait]
pub trait KeyBackupStore: Send + Sync {
    async fn issue_unlock_challenge(
        &self,
        challenge: Value,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<Value>;
    async fn reserve_recovery_unlock_attempt(
        &self,
        authority_id: &str,
        holder: &str,
        request_digest: &str,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<bool>;
    async fn unlock_challenge(&self, authority_id: &str) -> PersistenceResult<Option<Value>>;
    async fn consume_unlock(
        &self,
        device_gate: Option<&crate::DeviceRevocationGateSelector>,
        active_basis: Value,
        authority_id: &str,
        backup: Value,
        request_digest: &str,
        holder: &str,
        ip: &str,
        now: chrono::DateTime<Utc>,
        daily_limit: u32,
    ) -> PersistenceResult<Value>;
    async fn put(&self, backup_id: String, payload: Value) -> PersistenceResult<()>;
    async fn get(&self, backup_id: &str) -> PersistenceResult<Option<Value>>;
    async fn delete(&self, backup_id: &str) -> PersistenceResult<bool>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>>;
    async fn list_for_actor(&self, actor_id: &str) -> PersistenceResult<Vec<Value>>;
    async fn list_page(&self, query: &KeyBackupListQuery) -> PersistenceResult<KeyBackupListPage>;

    /// Issue `record`, or return the still-valid challenge already issued for
    /// the same `(account_id, backup_id, request_id)`.
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

    /// Recheck current authority, delete the exact backup snapshot and consume
    /// its challenge in one transaction. Returns `false` for an unavailable
    /// challenge; a changed backup rolls back without consuming authorization.
    async fn consume_delete_challenge(
        &self,
        gate: &KeyBackupDeleteGate,
        challenge_id: &str,
        backup: Value,
        recovery_session_id: Option<&str>,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<bool>;

    /// TTL sweep for challenges at or past `now`.
    async fn prune_expired_delete_challenges(
        &self,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<usize>;
}
