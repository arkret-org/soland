use super::{
    BTreeMap, PersistenceResult, RecoveryPolicyRecord, RecoveryReceiptRecord,
    RecoverySessionRecord, async_trait,
};
/// Durable recovery policy store. Implementations enforce policy_id
/// uniqueness, `(principal_id, version)` uniqueness, and the per-principal
/// supersedes/version monotonicity check before accepting a new snapshot.
#[async_trait]
pub trait RecoveryPolicyStore: Send + Sync {
    async fn get_by_policy_id(
        &self,
        policy_id: &str,
    ) -> PersistenceResult<Option<RecoveryPolicyRecord>>;
    async fn get_active_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Option<RecoveryPolicyRecord>>;
    /// All policies for a principal, newest version first (REC-1 read API /
    /// UI audit history).
    async fn list_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Vec<RecoveryPolicyRecord>>;
    async fn insert(&self, record: RecoveryPolicyRecord) -> PersistenceResult<()>;
}
/// Durable recovery receipt store. `recovery_session_id` is globally unique
/// because it is the replay fence for completed recovery attempts.
#[async_trait]
pub trait RecoveryReceiptStore: Send + Sync {
    async fn get_by_session_id(
        &self,
        recovery_session_id: &str,
    ) -> PersistenceResult<Option<RecoveryReceiptRecord>>;
    /// All receipts for a principal, newest accepted first (REC-1 read API /
    /// recovery history).
    async fn list_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Vec<RecoveryReceiptRecord>>;
    async fn insert(&self, record: RecoveryReceiptRecord) -> PersistenceResult<()>;
}
/// C-P2 (REC-1) — recovery session lifecycle store.
///
/// A session is created on `POST recovery-sessions` (snapshot of the active
/// policy + server challenge), read on `GET recovery-sessions/{id}`, and
/// advanced by `POST .../{id}/proofs` (records the submitted proof; C-P3
/// verifies it) and `POST .../{id}/complete` (only when `state == verified`).
#[async_trait]
pub trait RecoverySessionStore: Send + Sync {
    async fn get(
        &self,
        recovery_session_id: &str,
    ) -> PersistenceResult<Option<RecoverySessionRecord>>;
    async fn insert(&self, record: RecoverySessionRecord) -> PersistenceResult<()>;
    async fn update(&self, record: RecoverySessionRecord) -> PersistenceResult<()>;
}
#[doc(hidden)]
pub fn recovery_active_policy_locked(
    data: &BTreeMap<String, RecoveryPolicyRecord>,
    principal_id: &str,
) -> Option<RecoveryPolicyRecord> {
    data.values()
        .filter(|record| record.principal_id == principal_id)
        .max_by_key(|record| record.version)
        .cloned()
}
