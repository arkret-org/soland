use super::*;
#[derive(Default)]
pub(crate) struct MemoryPolicyDocumentStore {
    data: Mutex<BTreeMap<String, PolicyDocumentRecord>>,
}
impl MemoryPolicyDocumentStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl PolicyDocumentStore for MemoryPolicyDocumentStore {
    async fn get(&self, policy_id: &str) -> PersistenceResult<Option<PolicyDocumentRecord>> {
        Ok(self.data.lock().get(policy_id).cloned())
    }

    async fn put(&self, record: PolicyDocumentRecord) -> PersistenceResult<()> {
        let id = record.policy_id.clone();
        self.data.lock().insert(id, record);
        Ok(())
    }

    async fn delete(&self, policy_id: &str) -> PersistenceResult<bool> {
        Ok(self.data.lock().remove(policy_id).is_some())
    }

    async fn list_for_owner(&self, owner: &str) -> PersistenceResult<Vec<PolicyDocumentRecord>> {
        Ok(self
            .data
            .lock()
            .values()
            .filter(|record| record.owner == owner)
            .cloned()
            .collect())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<PolicyDocumentRecord>> {
        Ok(self.data.lock().values().cloned().collect())
    }

    async fn list_active(&self) -> PersistenceResult<Vec<PolicyDocumentRecord>> {
        let guard = self.data.lock();
        Ok(guard
            .values()
            .filter(|record| record.active)
            .cloned()
            .collect())
    }
}
