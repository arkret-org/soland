use super::{PersistenceResult, Value, async_trait};
/// Authenticated push registration storage.
#[async_trait]
pub trait PushDeviceStore: Send + Sync {
    async fn register(&self, device: Value) -> PersistenceResult<()>;
    async fn unregister(
        &self,
        actor: &arkret_wire::AccountId,
        device_id: &str,
        push_key: Option<&str>,
        app_id: Option<&str>,
    ) -> PersistenceResult<usize>;
    async fn purge_principal_device(
        &self,
        actor: &str,
        device_id: &str,
    ) -> PersistenceResult<usize>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>>;
}
