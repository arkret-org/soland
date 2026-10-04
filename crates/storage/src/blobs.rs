use super::{BlobRecord, PersistenceResult, async_trait};
/// Trait for blob storage operations.
#[async_trait]
pub trait BlobStore: Send + Sync {
    async fn get(&self, blob_ref: &str) -> PersistenceResult<Option<BlobRecord>>;
    async fn put(&self, blob_ref: &str, record: &BlobRecord) -> PersistenceResult<()>;
    /// Cache immutable public material without changing any existing Blob row.
    async fn put_if_absent(&self, blob_ref: &str, record: &BlobRecord) -> PersistenceResult<bool>;
    async fn delete(&self, blob_ref: &str) -> PersistenceResult<()>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<BlobRecord>>;
}
