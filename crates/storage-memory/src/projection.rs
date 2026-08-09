use serde_json::Value;

use super::{
    Arc, BTreeMap, CircleMemberProjectionRecord, CircleProjectionRecord, CircleProjectionStore,
    MorphProjectionRecord, MorphProjectionStore, Mutex, PersistenceError, PersistenceResult,
    ProjectionEventAppendOutcome, ProjectionEventRecord, ProjectionEventStore, RealmMetaRecord,
    RealmMetaStore, SpaceContainerProjectionRecord, SpaceContainerProjectionStore,
    StrandProjectionRecord, StrandProjectionStore, StrandWatchProjectionRecord,
    StrandWatchProjectionStore, async_trait,
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
pub(crate) struct MemoryProjectionEventStore {
    pub(crate) data: Arc<Mutex<Vec<ProjectionEventRecord>>>,
    accepted_events: Arc<Mutex<BTreeMap<String, soland_storage::CanonicalEventRecord>>>,
}
impl MemoryProjectionEventStore {
    pub(crate) fn new(
        accepted_events: Arc<Mutex<BTreeMap<String, soland_storage::CanonicalEventRecord>>>,
    ) -> Self {
        Self {
            data: Arc::new(Mutex::new(Vec::new())),
            accepted_events,
        }
    }
}
#[async_trait]
impl ProjectionEventStore for MemoryProjectionEventStore {
    async fn append(
        &self,
        record: ProjectionEventRecord,
    ) -> PersistenceResult<ProjectionEventAppendOutcome> {
        let accepted_events = self.accepted_events.lock();
        if !accepted_events.contains_key(&record.event_id) {
            return Err(PersistenceError::Conflict("event_not_accepted".to_owned()));
        }
        let mut data = self.data.lock();
        if let Some(existing) = data.iter().find(|event| event.event_id == record.event_id) {
            if existing.realm_id == record.realm_id
                && existing.event_kind == record.event_kind
                && existing.operation_kind == record.operation_kind
                && existing.operation_id == record.operation_id
                && existing.sender == record.sender
                && existing.payload == record.payload
                && existing.created_at == record.created_at
                && existing.received_at == record.received_at
            {
                return Ok(ProjectionEventAppendOutcome::AlreadyExists);
            }
            return Err(PersistenceError::Conflict(
                "duplicate_conflict: projection differs for Event identity".to_owned(),
            ));
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
            .filter(|event| event.sender.as_deref() == Some(actor_id))
            .cloned()
            .collect())
    }

    async fn snapshot_capped(&self, limit: usize) -> PersistenceResult<Vec<ProjectionEventRecord>> {
        Ok(self.data.lock().iter().take(limit).cloned().collect())
    }
}

pub(crate) struct MemoryCircleProjectionStore {
    data: Arc<Mutex<BTreeMap<String, CircleProjectionRecord>>>,
    members: Arc<Mutex<BTreeMap<String, Vec<CircleMemberProjectionRecord>>>>,
}
impl MemoryCircleProjectionStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
            members: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}
#[async_trait]
impl CircleProjectionStore for MemoryCircleProjectionStore {
    async fn get(&self, circle_id: &str) -> PersistenceResult<Option<CircleProjectionRecord>> {
        let data = self.data.lock();
        Ok(data.get(circle_id).cloned())
    }

    async fn put(&self, record: &CircleProjectionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.insert(record.circle_id.clone(), record.clone());
        Ok(())
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<CircleProjectionRecord>> {
        let data = self.data.lock();
        Ok(data
            .values()
            .filter(|r| r.realm_id == realm_id)
            .cloned()
            .collect())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<CircleProjectionRecord>> {
        let data = self.data.lock();
        Ok(data.values().cloned().collect())
    }

    async fn delete(&self, circle_id: &str) -> PersistenceResult<()> {
        self.data.lock().remove(circle_id);
        self.members.lock().remove(circle_id);
        Ok(())
    }

    async fn put_members(
        &self,
        circle_id: &str,
        members: &[CircleMemberProjectionRecord],
    ) -> PersistenceResult<()> {
        let mut data = self.members.lock();
        if members.is_empty() {
            data.remove(circle_id);
        } else {
            data.insert(circle_id.to_owned(), members.to_vec());
        }
        Ok(())
    }

    async fn snapshot_all_members(&self) -> PersistenceResult<Vec<CircleMemberProjectionRecord>> {
        let data = self.members.lock();
        Ok(data.values().flatten().cloned().collect())
    }
}
pub(crate) struct MemoryStrandWatchProjectionStore {
    data: Arc<Mutex<BTreeMap<(String, String), StrandWatchProjectionRecord>>>,
}
impl MemoryStrandWatchProjectionStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}
#[async_trait]
impl StrandWatchProjectionStore for MemoryStrandWatchProjectionStore {
    async fn put(&self, record: &StrandWatchProjectionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.insert(
            (record.strand_id.clone(), record.actor_id.clone()),
            record.clone(),
        );
        Ok(())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<StrandWatchProjectionRecord>> {
        let data = self.data.lock();
        Ok(data.values().cloned().collect())
    }
}
