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
        step: arkret_wire::SecurityTransactionStep,
    ) -> PersistenceResult<Option<SecurityTransactionStepOutcomeRecord>>;
    async fn step_attempt(
        &self,
        transaction_id: &str,
        step: arkret_wire::SecurityTransactionStep,
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

fn decode_backup_erase_request(
    progress: &BackupSeriesEraseProgressRecord,
) -> PersistenceResult<arkret_models_crypto::BackupSeriesEraseRequestBody> {
    let request = arkret_canonical::from_canonical_json_slice(&progress.canonical_request)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let request: arkret_models_crypto::BackupSeriesEraseRequestBody =
        serde_json::from_value(request)
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if request.transaction_id.as_str() != progress.transaction_id {
        return Err(PersistenceError::SchemaViolation(
            "backup erase progress belongs to a different transaction".to_owned(),
        ));
    }
    progress
        .outcome
        .validate_for_request(&request)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    Ok(request)
}

#[doc(hidden)]
pub fn validate_backup_erase_progress_initial(
    progress: &BackupSeriesEraseProgressRecord,
) -> PersistenceResult<()> {
    let request = decode_backup_erase_request(progress)?;
    if progress.outcome.status != arkret_models_crypto::BackupSeriesEraseStatus::Partial
        || progress.outcome.confirmation.is_some()
        || progress
            .outcome
            .series_results
            .iter()
            .zip(&request.series)
            .any(|(result, binding)| {
                result.status != arkret_models_crypto::BackupSeriesEraseRowStatus::Pending
                    || !result.erased_backups.is_empty()
                    || result.remaining_backups != {
                        let mut refs = binding.old_backups.clone();
                        refs.sort_by(|left, right| {
                            left.backup_id.as_str().cmp(right.backup_id.as_str())
                        });
                        refs
                    }
                    || result.reason_code.is_some()
            })
    {
        return Err(PersistenceError::SchemaViolation(
            "initial backup erase progress must contain the exact all-remaining plan".to_owned(),
        ));
    }
    Ok(())
}

#[doc(hidden)]
pub fn validate_backup_erase_progress_update(
    existing: &BackupSeriesEraseProgressRecord,
    proposed: &BackupSeriesEraseProgressRecord,
) -> PersistenceResult<()> {
    let existing_request = decode_backup_erase_request(existing)?;
    let proposed_request = decode_backup_erase_request(proposed)?;
    if existing.transaction_id != proposed.transaction_id
        || existing.canonical_request != proposed.canonical_request
        || existing_request != proposed_request
        || existing.outcome.transaction_id != proposed.outcome.transaction_id
        || existing.outcome.request_digest != proposed.outcome.request_digest
    {
        return Err(PersistenceError::Conflict(
            "backup erase progress changed its immutable request".to_owned(),
        ));
    }
    for (before, after) in existing
        .outcome
        .series_results
        .iter()
        .zip(&proposed.outcome.series_results)
    {
        let before_erased = before
            .erased_backups
            .iter()
            .map(|reference| reference.backup_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let after_erased = after
            .erased_backups
            .iter()
            .map(|reference| reference.backup_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let before_remaining = before
            .remaining_backups
            .iter()
            .map(|reference| reference.backup_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let after_remaining = after
            .remaining_backups
            .iter()
            .map(|reference| reference.backup_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if !before_erased.is_subset(&after_erased)
            || !after_remaining.is_subset(&before_remaining)
            || !after_erased.is_disjoint(&after_remaining)
        {
            return Err(PersistenceError::Conflict(
                "backup erase progress attempted to resurrect or rewrite an erased object"
                    .to_owned(),
            ));
        }
    }
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
        || current.coordinator_id != next.coordinator_id
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
    if current.is_terminal() {
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
            .accepted_step_kind(existing.resource.accepted_steps.len())
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?
            != outcome.step
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
