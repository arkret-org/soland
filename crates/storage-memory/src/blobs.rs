use super::{Arc, BTreeMap, BlobRecord, BlobStore, Mutex, PersistenceResult, async_trait};
// In-memory blob store
pub(crate) struct MemoryBlobStore {
    data: Arc<Mutex<BTreeMap<String, BlobRecord>>>,
}
impl MemoryBlobStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}
#[async_trait]
impl BlobStore for MemoryBlobStore {
    async fn get(&self, blob_ref: &str) -> PersistenceResult<Option<BlobRecord>> {
        let data = self.data.lock();
        Ok(data.get(blob_ref).cloned())
    }

    async fn put(&self, blob_ref: &str, record: &BlobRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.insert(blob_ref.to_owned(), record.clone());
        Ok(())
    }

    async fn delete(&self, blob_ref: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.remove(blob_ref);
        Ok(())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<BlobRecord>> {
        Ok(self.data.lock().values().cloned().collect())
    }
}
