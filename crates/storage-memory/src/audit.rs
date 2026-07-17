use super::*;
#[derive(Default)]
pub(crate) struct MemoryAuditStore {
    data: Mutex<Vec<Value>>,
}
impl MemoryAuditStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl AuditStore for MemoryAuditStore {
    async fn append(&self, entry: Value) -> PersistenceResult<()> {
        self.data.lock().push(entry);
        Ok(())
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .data
            .lock()
            .iter()
            .filter(|event| event.get("actor").and_then(Value::as_str) == Some(actor))
            .cloned()
            .collect())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.data.lock().clone())
    }
}
