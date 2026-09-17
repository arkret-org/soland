use super::{
    BackupSeriesEraseProgressRecord, PersistenceError, PersistenceResult, RecoveryPolicyRecord,
    RecoverySessionRecord, SecurityTransactionRecord, SecurityTransactionStepAttemptRecord,
    SecurityTransactionStepOutcomeRecord, async_trait,
};
/// Durable recovery policy store. Implementations enforce policy_id
/// uniqueness, `(account_id, version)` uniqueness, and the per-account
/// supersedes/version monotonicity check before accepting a new snapshot.
#[async_trait]
pub trait RecoveryPolicyStore: Send + Sync {
    async fn get_by_policy_id(
        &self,
        policy_id: &str,
    ) -> PersistenceResult<Option<RecoveryPolicyRecord>>;
    async fn get_active_for_account(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<RecoveryPolicyRecord>>;
    /// All policies for a principal, newest version first (REC-1 read API /
    /// UI audit history).
    async fn list_for_account(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<Vec<RecoveryPolicyRecord>>;
    async fn insert(&self, record: RecoveryPolicyRecord) -> PersistenceResult<()>;
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
    async fn get_by_grant_id(
        &self,
        session_grant_id: &str,
    ) -> PersistenceResult<Option<RecoverySessionRecord>>;
    async fn get_by_grant_request(
        &self,
        session_grant_id: &str,
        request_id: &str,
    ) -> PersistenceResult<Option<RecoverySessionRecord>>;
    async fn insert(&self, record: RecoverySessionRecord) -> PersistenceResult<()>;
    async fn save_verified_with_unlock_manifest(
        &self,
        record: RecoverySessionRecord,
        manifest: serde_json::Value,
    ) -> PersistenceResult<()>;
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
    async fn step_outcome(
        &self,
        transaction_id: &str,
        step: arkret_models_crypto::SecurityTransactionStep,
    ) -> PersistenceResult<Option<SecurityTransactionStepOutcomeRecord>>;
    async fn step_attempt(
        &self,
        transaction_id: &str,
        step: arkret_models_crypto::SecurityTransactionStep,
    ) -> PersistenceResult<Option<SecurityTransactionStepAttemptRecord>>;
    /// Durably fixes the first canonical request bytes before a participant
    /// side effect. Identical retries return the first attempt; different
    /// bytes conflict.
    async fn begin_step(
        &self,
        attempt: SecurityTransactionStepAttemptRecord,
    ) -> PersistenceResult<SecurityTransactionStepAttemptRecord>;
    /// Atomically appends exactly one accepted step, persists its first
    /// response, and advances the authoritative resource. A byte-identical
    /// replay returns the stored outcome; different bytes conflict.
    async fn accept_step(
        &self,
        record: SecurityTransactionRecord,
        outcome: SecurityTransactionStepOutcomeRecord,
    ) -> PersistenceResult<SecurityTransactionStepOutcomeRecord>;
    async fn backup_erase_progress(
        &self,
        transaction_id: &str,
    ) -> PersistenceResult<Option<BackupSeriesEraseProgressRecord>>;
    /// Fixes the first complete erase request and its initial all-remaining
    /// progress before the first object deletion.
    async fn begin_backup_erase(
        &self,
        progress: BackupSeriesEraseProgressRecord,
    ) -> PersistenceResult<BackupSeriesEraseProgressRecord>;
    /// Persists a monotonic progress snapshot. Implementations must serialize
    /// concurrent updates for the same transaction.
    async fn update_backup_erase(
        &self,
        progress: BackupSeriesEraseProgressRecord,
    ) -> PersistenceResult<BackupSeriesEraseProgressRecord>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum SecurityTransactionFirstWriteDecision {
    Insert,
    ExactRetry,
}

/// Classifies the immutable canonical bytes fixed by the first writer for a
/// transaction, step, outcome, or transaction-bound erase operation.
#[doc(hidden)]
pub fn classify_security_transaction_first_write(
    existing: Option<&[u8]>,
    proposed: &[u8],
) -> PersistenceResult<SecurityTransactionFirstWriteDecision> {
    match existing {
        None => Ok(SecurityTransactionFirstWriteDecision::Insert),
        Some(existing) if existing == proposed => {
            Ok(SecurityTransactionFirstWriteDecision::ExactRetry)
        }
        Some(_) => Err(PersistenceError::Conflict(
            "security transaction first canonical request bytes changed".to_owned(),
        )),
    }
}

#[doc(hidden)]
pub fn validate_backup_erase_progress_initial(
    progress: &BackupSeriesEraseProgressRecord,
) -> PersistenceResult<()> {
    if progress.transaction_id.is_empty()
        || progress.canonical_request.is_empty()
        || !progress.outcome.is_object()
    {
        return Err(PersistenceError::SchemaViolation(
            "backup erase progress requires a transaction, request, and object outcome".to_owned(),
        ));
    }
    Ok(())
}

#[doc(hidden)]
pub fn validate_backup_erase_progress_update(
    existing: &BackupSeriesEraseProgressRecord,
    proposed: &BackupSeriesEraseProgressRecord,
) -> PersistenceResult<()> {
    if existing.transaction_id != proposed.transaction_id
        || existing.canonical_request != proposed.canonical_request
    {
        return Err(PersistenceError::Conflict(
            "backup erase progress changed its immutable request".to_owned(),
        ));
    }
    validate_backup_erase_progress_initial(proposed)?;
    Ok(())
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
        || current.account_id != next.account_id
        || current.expires_at != next.expires_at
        || current.created_at != next.created_at
        || current.request_digest != next.request_digest
        || current.prepared_plan != next.prepared_plan
        || current.prepared_plan_digest != next.prepared_plan_digest
    {
        return Err(PersistenceError::Conflict(
            "security transaction immutable request, identity, or plan changed".to_owned(),
        ));
    }
    if current == next {
        return Ok(());
    }
    if current.terminal_outcome.is_some() {
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
    Ok(())
}

#[doc(hidden)]
pub fn validate_security_transaction_step_accept(
    existing: &SecurityTransactionRecord,
    proposed: &SecurityTransactionRecord,
    attempt: &SecurityTransactionStepAttemptRecord,
    outcome: &SecurityTransactionStepOutcomeRecord,
) -> PersistenceResult<()> {
    proposed
        .resource
        .validate_structural()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let transaction_id = proposed.resource.transaction_id.as_str();
    if attempt.transaction_id != transaction_id
        || outcome.transaction_id != transaction_id
        || attempt.step != outcome.step
    {
        return Err(PersistenceError::SchemaViolation(
            "security transaction step records belong to different transactions or steps"
                .to_owned(),
        ));
    }
    if attempt.canonical_request != outcome.canonical_request {
        return Err(PersistenceError::Conflict(format!(
            "security transaction step {:?} outcome changed the durable request bytes",
            outcome.step
        )));
    }
    validate_security_transaction_update(existing, proposed)?;
    if proposed.resource.accepted_steps.len() != existing.resource.accepted_steps.len() + 1
        || existing
            .resource
            .next_required_step()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?
            != Some(outcome.step)
    {
        return Err(PersistenceError::SchemaViolation(
            "accepted step outcome must match the single appended transaction step".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_transaction_first_writer_distinguishes_insert_retry_and_conflict() {
        assert_eq!(
            classify_security_transaction_first_write(None, b"request").unwrap(),
            SecurityTransactionFirstWriteDecision::Insert
        );
        assert_eq!(
            classify_security_transaction_first_write(Some(b"request"), b"request").unwrap(),
            SecurityTransactionFirstWriteDecision::ExactRetry
        );
        assert!(classify_security_transaction_first_write(Some(b"request"), b"changed").is_err());
    }
}
