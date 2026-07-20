use arkret_core::StoredServiceIdentity;

use super::{Mutex, PersistenceResult, ServiceIdentityStore, async_trait};
#[derive(Default)]
pub(crate) struct MemoryServiceIdentityStore {
    row: Mutex<Option<StoredServiceIdentity>>,
}
impl MemoryServiceIdentityStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl ServiceIdentityStore for MemoryServiceIdentityStore {
    async fn get(&self) -> PersistenceResult<Option<StoredServiceIdentity>> {
        Ok(self.row.lock().clone())
    }

    async fn put(&self, identity: StoredServiceIdentity) -> PersistenceResult<()> {
        *self.row.lock() = Some(identity);
        Ok(())
    }
}
