use serde_json::Value;

use super::{
    Arc, BTreeMap, MorphProjectionRecord, MorphProjectionStore, Mutex, PersistenceResult,
    ProjectionEventAppendOutcome, ProjectionEventRecord, ProjectionEventStore, RealmMetaRecord,
    RealmMetaStore, SpaceContainerProjectionRecord, SpaceContainerProjectionStore,
    StrandProjectionRecord, StrandProjectionStore, async_trait,
};
// In-memory Realm meta store
pub(crate) struct MemoryRealmMetaStore {
    data: Arc<Mutex<BTreeMap<String, RealmMetaRecord>>>,
}
impl MemoryRealmMetaStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub(crate) fn seed(&self, realm_id: &str, record: RealmMetaRecord) {
        self.data.lock().insert(realm_id.to_owned(), record);
    }
}
#[async_trait]
impl RealmMetaStore for MemoryRealmMetaStore {
    async fn get(&self, realm_id: &str) -> PersistenceResult<Option<RealmMetaRecord>> {
        let data = self.data.lock();
        Ok(data.get(realm_id).cloned())
    }

    async fn put(&self, realm_id: &str, record: &RealmMetaRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.insert(realm_id.to_owned(), record.clone());
        Ok(())
    }

    async fn list(&self) -> PersistenceResult<Vec<(String, RealmMetaRecord)>> {
        let data = self.data.lock();
        Ok(data.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
    }

    async fn delete(&self, realm_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.remove(realm_id);
        Ok(())
    }
}
// ── Memory impls for Space-container/Strand/Morph projection stores ────────

pub(crate) struct MemorySpaceContainerProjectionStore {
    data: Arc<Mutex<BTreeMap<String, SpaceContainerProjectionRecord>>>,
}
impl MemorySpaceContainerProjectionStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}
#[async_trait]
impl SpaceContainerProjectionStore for MemorySpaceContainerProjectionStore {
    async fn get(
        &self,
        container_space_id: &str,
    ) -> PersistenceResult<Option<SpaceContainerProjectionRecord>> {
        let data = self.data.lock();
        Ok(data.get(container_space_id).cloned())
    }

    async fn put(&self, record: &SpaceContainerProjectionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.insert(record.container_space_id.clone(), record.clone());
        Ok(())
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<SpaceContainerProjectionRecord>> {
        let data = self.data.lock();
        Ok(data
            .values()
            .filter(|r| r.realm_id == realm_id)
            .cloned()
            .collect())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<SpaceContainerProjectionRecord>> {
        let data = self.data.lock();
        Ok(data.values().cloned().collect())
    }

    async fn delete(&self, container_space_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.remove(container_space_id);
        Ok(())
    }
}
pub(crate) struct MemoryStrandProjectionStore {
    data: Arc<Mutex<BTreeMap<String, StrandProjectionRecord>>>,
}
impl MemoryStrandProjectionStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}
#[async_trait]
impl StrandProjectionStore for MemoryStrandProjectionStore {
    async fn get(&self, strand_id: &str) -> PersistenceResult<Option<StrandProjectionRecord>> {
        let data = self.data.lock();
        Ok(data.get(strand_id).cloned())
    }

    async fn put(&self, record: &StrandProjectionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.insert(record.strand_id.clone(), record.clone());
        Ok(())
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<StrandProjectionRecord>> {
        let data = self.data.lock();
        Ok(data
            .values()
            .filter(|r| r.realm_id == realm_id)
            .cloned()
            .collect())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<StrandProjectionRecord>> {
        let data = self.data.lock();
        Ok(data.values().cloned().collect())
    }

    async fn delete(&self, strand_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.remove(strand_id);
        Ok(())
    }
}
pub(crate) struct MemoryMorphProjectionStore {
    data: Arc<Mutex<BTreeMap<String, MorphProjectionRecord>>>,
}
impl MemoryMorphProjectionStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}
#[async_trait]
impl MorphProjectionStore for MemoryMorphProjectionStore {
    async fn get(&self, morph_id: &str) -> PersistenceResult<Option<MorphProjectionRecord>> {
        let data = self.data.lock();
        Ok(data.get(morph_id).cloned())
    }

    async fn put(&self, record: &MorphProjectionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.insert(record.morph_id.clone(), record.clone());
        Ok(())
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<MorphProjectionRecord>> {
        let data = self.data.lock();
        Ok(data
            .values()
            .filter(|r| r.realm_id == realm_id)
            .cloned()
            .collect())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MorphProjectionRecord>> {
        let data = self.data.lock();
        Ok(data.values().cloned().collect())
    }

    async fn delete(&self, morph_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.remove(morph_id);
        Ok(())
    }
}
#[derive(Default)]
pub(crate) struct MemoryProjectionEventStore {
    pub(crate) data: Mutex<Vec<ProjectionEventRecord>>,
}
impl MemoryProjectionEventStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl ProjectionEventStore for MemoryProjectionEventStore {
    async fn append(
        &self,
        record: ProjectionEventRecord,
    ) -> PersistenceResult<ProjectionEventAppendOutcome> {
        let mut data = self.data.lock();
        if data.iter().any(|event| event.event_id == record.event_id) {
            return Ok(ProjectionEventAppendOutcome::AlreadyExists);
        }
        data.push(record);
        Ok(ProjectionEventAppendOutcome::Inserted)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<ProjectionEventRecord>> {
        Ok(self.data.lock().clone())
    }

    async fn snapshot_kind(
        &self,
        event_kind: &str,
    ) -> PersistenceResult<Vec<ProjectionEventRecord>> {
        Ok(self
            .data
            .lock()
            .iter()
            .filter(|event| event.event_kind == event_kind)
            .cloned()
            .collect())
    }

    async fn get(&self, event_id: &str) -> PersistenceResult<Option<ProjectionEventRecord>> {
        Ok(self
            .data
            .lock()
            .iter()
            .find(|event| event.event_id == event_id)
            .cloned())
    }

    async fn get_by_operation_id(
        &self,
        operation_id: &str,
    ) -> PersistenceResult<Option<ProjectionEventRecord>> {
        Ok(self
            .data
            .lock()
            .iter()
            .find(|event| event.operation_id.as_deref() == Some(operation_id))
            .cloned())
    }

    async fn snapshot_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<ProjectionEventRecord>> {
        Ok(self
            .data
            .lock()
            .iter()
            .filter(|event| event.realm_id == realm_id)
            .cloned()
            .collect())
    }

    async fn snapshot_actor(
        &self,
        actor_id: &str,
    ) -> PersistenceResult<Vec<ProjectionEventRecord>> {
        Ok(self
            .data
            .lock()
            .iter()
            .filter(|event| {
                event.sender.as_deref() == Some(actor_id)
                    || event.payload.get("sender").and_then(Value::as_str) == Some(actor_id)
                    || event.payload.get("actor_id").and_then(Value::as_str) == Some(actor_id)
                    || event.payload.get("actor").and_then(Value::as_str) == Some(actor_id)
                    || event
                        .payload
                        .get("object")
                        .and_then(Value::as_object)
                        .and_then(|object| object.get("created_by"))
                        .and_then(Value::as_str)
                        == Some(actor_id)
            })
            .cloned()
            .collect())
    }

    async fn snapshot_capped(&self, limit: usize) -> PersistenceResult<Vec<ProjectionEventRecord>> {
        Ok(self.data.lock().iter().take(limit).cloned().collect())
    }
}
