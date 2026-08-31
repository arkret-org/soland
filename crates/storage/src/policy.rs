use super::{PersistenceResult, PolicyDocumentRecord, async_trait};
/// Per-owner policy documents.
#[async_trait]
pub trait PolicyDocumentStore: Send + Sync {
    async fn get(&self, policy_id: &str) -> PersistenceResult<Option<PolicyDocumentRecord>>;
    async fn put(&self, record: PolicyDocumentRecord) -> PersistenceResult<()>;
    async fn delete(&self, policy_id: &str) -> PersistenceResult<bool>;
    async fn list_for_owner(&self, owner: &str) -> PersistenceResult<Vec<PolicyDocumentRecord>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<PolicyDocumentRecord>>;
}
