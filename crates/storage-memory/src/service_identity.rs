use arkret_identity::service_identity::StoredDidCoreIdentity;
use arkret_models_identity::ServiceResolutionRecord;
use arkret_wire::Hash;

use super::{Mutex, PersistenceResult, ServiceIdentityStore, async_trait};
#[derive(Default)]
pub(crate) struct MemoryServiceIdentityStore {
    row: Mutex<MemoryDidCoreIdentityState>,
}

#[derive(Default)]
struct MemoryDidCoreIdentityState {
    identity: Option<StoredDidCoreIdentity>,
    resolution: Option<ServiceResolutionRecord>,
}
impl MemoryServiceIdentityStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn seed(&self, identity: StoredDidCoreIdentity) {
        self.row.lock().identity = Some(identity);
    }
}
#[async_trait]
impl ServiceIdentityStore for MemoryServiceIdentityStore {
    async fn get(&self) -> PersistenceResult<Option<StoredDidCoreIdentity>> {
        Ok(self.row.lock().identity.clone())
    }

    async fn put(&self, identity: StoredDidCoreIdentity) -> PersistenceResult<()> {
        self.row.lock().identity = Some(identity);
        Ok(())
    }

    async fn get_resolution(&self) -> PersistenceResult<Option<ServiceResolutionRecord>> {
        Ok(self.row.lock().resolution.clone())
    }

    async fn compare_and_set_resolution(
        &self,
        expected_digest: Option<&Hash>,
        record: ServiceResolutionRecord,
    ) -> PersistenceResult<bool> {
        let mut state = self.row.lock();
        let current_digest = state
            .resolution
            .as_ref()
            .map(arkret_canonical::canonical_sha256)
            .transpose()
            .map_err(|error| soland_storage::PersistenceError::Internal(error.to_string()))?
            .map(Hash::new)
            .transpose()
            .map_err(|error| soland_storage::PersistenceError::Internal(error.to_string()))?;
        if current_digest.as_ref() != expected_digest {
            return Ok(false);
        }
        state.resolution = Some(record);
        Ok(true)
    }
}
