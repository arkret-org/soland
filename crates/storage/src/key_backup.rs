use super::{PersistenceResult, Value, async_trait};
/// Encrypted key-backup envelopes (one row per `backup_id`).
#[async_trait]
pub trait KeyBackupStore: Send + Sync {
    async fn put(&self, backup_id: String, payload: Value) -> PersistenceResult<()>;
    async fn get(&self, backup_id: &str) -> PersistenceResult<Option<Value>>;
    async fn delete(&self, backup_id: &str) -> PersistenceResult<bool>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>>;
    async fn list_for_actor(&self, actor_id: &str) -> PersistenceResult<Vec<Value>>;
}
