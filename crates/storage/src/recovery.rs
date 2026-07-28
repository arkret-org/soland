use super::{
    BTreeMap, PersistenceError, PersistenceResult, RecoveryPolicyRecord, RecoveryReceiptRecord,
    RecoverySessionRecord, SecurityTransactionRecord, async_trait,
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
/// Durable recovery session lifecycle store.
///
/// A verified session is consumed only by atomically binding it to a recovery
/// security transaction. Completion is represented by the transaction's
/// accepted terminal result, never by a parallel session-complete command.
#[async_trait]
pub trait RecoverySessionStore: Send + Sync {
    async fn get(
        &self,
        recovery_session_id: &str,
    ) -> PersistenceResult<Option<RecoverySessionRecord>>;
    async fn insert(&self, record: RecoverySessionRecord) -> PersistenceResult<()>;
    async fn update(&self, record: RecoverySessionRecord) -> PersistenceResult<()>;
}

#[async_trait]
pub trait SecurityTransactionStore: Send + Sync {
    /// Persists the canonical request and initial resource atomically.
    ///
    /// Recovery transactions additionally CAS-bind their already verified
    /// recovery session in the same durable commit.
    async fn create(
        &self,
        record: SecurityTransactionRecord,
    ) -> PersistenceResult<SecurityTransactionRecord>;
    async fn get(
        &self,
        transaction_id: &str,
    ) -> PersistenceResult<Option<SecurityTransactionRecord>>;
    async fn update(&self, record: SecurityTransactionRecord) -> PersistenceResult<()>;
}

#[doc(hidden)]
pub fn validate_security_transaction_update(
    existing: &SecurityTransactionRecord,
    proposed: &SecurityTransactionRecord,
) -> PersistenceResult<()> {
    let current = &existing.resource;
    let next = &proposed.resource;
    if existing.canonical_request != proposed.canonical_request
        || current.transaction_id != next.transaction_id
        || current.kind != next.kind
        || current.principal_id != next.principal_id
        || current.coordinator_service_id != next.coordinator_service_id
        || current.expires_at != next.expires_at
        || current.created_at != next.created_at
        || current.request_digest != next.request_digest
        || current.binding != next.binding
        || current.prepared_plan != next.prepared_plan
        || current.prepared_plan_digest != next.prepared_plan_digest
    {
        return Err(PersistenceError::Conflict(
            "security transaction immutable request, identity, binding, or plan changed".to_owned(),
        ));
    }
    if current == next {
        return Ok(());
    }
    if current.state.is_terminal() {
        return Err(PersistenceError::Conflict(
            "terminal security transaction cannot change".to_owned(),
        ));
    }
    if next.accepted_steps.len() < current.accepted_steps.len()
        || next.accepted_steps.len() > current.accepted_steps.len() + 1
        || !next
            .accepted_steps
            .starts_with(current.accepted_steps.as_slice())
    {
        return Err(PersistenceError::Conflict(
            "security transaction accepted steps must advance by at most one immutable step"
                .to_owned(),
        ));
    }
    if next.accepted_steps.len() == current.accepted_steps.len()
        && !matches!(
            (current.state, next.state),
            (
                arkret_wire::SecurityTransactionState::Pending,
                arkret_wire::SecurityTransactionState::Running
            ) | (
                arkret_wire::SecurityTransactionState::Pending
                    | arkret_wire::SecurityTransactionState::Running
                    | arkret_wire::SecurityTransactionState::AwaitingDeviceAttestation,
                arkret_wire::SecurityTransactionState::Aborted
                    | arkret_wire::SecurityTransactionState::Expired
            )
        )
    {
        return Err(PersistenceError::Conflict(
            "security transaction state changed without accepting its next step".to_owned(),
        ));
    }
    Ok(())
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
