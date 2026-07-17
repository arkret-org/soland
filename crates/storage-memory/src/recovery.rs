use super::{
    BTreeMap, BTreeSet, Mutex, PersistenceError, PersistenceResult, RecoveryPolicyRecord,
    RecoveryPolicyStore, RecoveryReceiptRecord, RecoveryReceiptStore, RecoverySessionRecord,
    RecoverySessionStore, async_trait, recovery_active_policy_locked,
};
#[derive(Default)]
pub(crate) struct MemoryRecoveryPolicyStore {
    data: Mutex<BTreeMap<String, RecoveryPolicyRecord>>,
}
impl MemoryRecoveryPolicyStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl RecoveryPolicyStore for MemoryRecoveryPolicyStore {
    async fn get_by_policy_id(
        &self,
        policy_id: &str,
    ) -> PersistenceResult<Option<RecoveryPolicyRecord>> {
        Ok(self.data.lock().get(policy_id).cloned())
    }

    async fn get_active_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Option<RecoveryPolicyRecord>> {
        let data = self.data.lock();
        Ok(recovery_active_policy_locked(&data, principal_id))
    }

    async fn list_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Vec<RecoveryPolicyRecord>> {
        let data = self.data.lock();
        let mut out: Vec<RecoveryPolicyRecord> = data
            .values()
            .filter(|record| record.principal_id == principal_id)
            .cloned()
            .collect();
        out.sort_by_key(|p| std::cmp::Reverse(p.version));
        Ok(out)
    }

    async fn insert(&self, record: RecoveryPolicyRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        if data.contains_key(&record.policy_id) {
            return Err(PersistenceError::Conflict(format!(
                "recovery policy_id `{}` already exists",
                record.policy_id
            )));
        }
        if data.values().any(|existing| {
            existing.principal_id == record.principal_id && existing.version == record.version
        }) {
            return Err(PersistenceError::Conflict(format!(
                "recovery policy principal/version ({}, {}) already exists",
                record.principal_id, record.version
            )));
        }
        if let Some(active) = recovery_active_policy_locked(&data, &record.principal_id) {
            if record.version <= active.version {
                return Err(PersistenceError::Conflict(format!(
                    "recovery policy version {} is not greater than active {}",
                    record.version, active.version
                )));
            }
            if record.supersedes.as_deref() != Some(active.policy_id.as_str()) {
                return Err(PersistenceError::Conflict(format!(
                    "recovery policy supersedes {:?} does not match active `{}`",
                    record.supersedes, active.policy_id
                )));
            }
        } else if record.version != 1 {
            return Err(PersistenceError::Conflict(format!(
                "recovery genesis policy for `{}` must have version=1",
                record.principal_id
            )));
        }
        data.insert(record.policy_id.clone(), record);
        Ok(())
    }
}
#[derive(Default)]
pub(crate) struct MemoryRecoveryReceiptStore {
    by_session: Mutex<BTreeMap<String, RecoveryReceiptRecord>>,
    receipt_ids: Mutex<BTreeSet<String>>,
}
impl MemoryRecoveryReceiptStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl RecoveryReceiptStore for MemoryRecoveryReceiptStore {
    async fn get_by_session_id(
        &self,
        recovery_session_id: &str,
    ) -> PersistenceResult<Option<RecoveryReceiptRecord>> {
        Ok(self.by_session.lock().get(recovery_session_id).cloned())
    }

    async fn list_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Vec<RecoveryReceiptRecord>> {
        let by_session = self.by_session.lock();
        let mut out: Vec<RecoveryReceiptRecord> = by_session
            .values()
            .filter(|record| record.principal_id == principal_id)
            .cloned()
            .collect();
        out.sort_by_key(|r| std::cmp::Reverse(r.accepted_at));
        Ok(out)
    }

    async fn insert(&self, record: RecoveryReceiptRecord) -> PersistenceResult<()> {
        let mut by_session = self.by_session.lock();
        let mut receipt_ids = self.receipt_ids.lock();
        if receipt_ids.contains(&record.receipt_id) {
            return Err(PersistenceError::Conflict(format!(
                "recovery receipt_id `{}` already exists",
                record.receipt_id
            )));
        }
        if by_session.contains_key(&record.recovery_session_id) {
            return Err(PersistenceError::Conflict(format!(
                "recovery_session_id `{}` already accepted",
                record.recovery_session_id
            )));
        }
        receipt_ids.insert(record.receipt_id.clone());
        by_session.insert(record.recovery_session_id.clone(), record);
        Ok(())
    }
}
#[derive(Default)]
pub(crate) struct MemoryRecoverySessionStore {
    by_id: Mutex<BTreeMap<String, RecoverySessionRecord>>,
}
impl MemoryRecoverySessionStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl RecoverySessionStore for MemoryRecoverySessionStore {
    async fn get(
        &self,
        recovery_session_id: &str,
    ) -> PersistenceResult<Option<RecoverySessionRecord>> {
        Ok(self.by_id.lock().get(recovery_session_id).cloned())
    }

    async fn insert(&self, record: RecoverySessionRecord) -> PersistenceResult<()> {
        let mut by_id = self.by_id.lock();
        if by_id.contains_key(&record.recovery_session_id) {
            return Err(PersistenceError::Conflict(format!(
                "recovery_session_id `{}` already exists",
                record.recovery_session_id
            )));
        }
        by_id.insert(record.recovery_session_id.clone(), record);
        Ok(())
    }

    async fn update(&self, record: RecoverySessionRecord) -> PersistenceResult<()> {
        let mut by_id = self.by_id.lock();
        if !by_id.contains_key(&record.recovery_session_id) {
            return Err(PersistenceError::NotFound(format!(
                "recovery_session_id `{}` not found",
                record.recovery_session_id
            )));
        }
        by_id.insert(record.recovery_session_id.clone(), record);
        Ok(())
    }
}
