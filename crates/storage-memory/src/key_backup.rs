use super::{BTreeMap, KeyBackupStore, Mutex, PersistenceResult, Value, async_trait};
#[derive(Default)]
pub(crate) struct MemoryKeyBackupStore {
    backups: Mutex<BTreeMap<String, Value>>,
}
impl MemoryKeyBackupStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl KeyBackupStore for MemoryKeyBackupStore {
    async fn put(&self, backup_id: String, payload: Value) -> PersistenceResult<()> {
        self.backups.lock().insert(backup_id, payload);
        Ok(())
    }

    async fn get(&self, backup_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self.backups.lock().get(backup_id).cloned())
    }

    async fn delete(&self, backup_id: &str) -> PersistenceResult<bool> {
        Ok(self.backups.lock().remove(backup_id).is_some())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.backups.lock().values().cloned().collect())
    }

    async fn list_for_actor(&self, actor_id: &str) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .backups
            .lock()
            .values()
            .filter(|backup| backup.get("actor_id").and_then(Value::as_str) == Some(actor_id))
            .cloned()
            .collect())
    }
}
