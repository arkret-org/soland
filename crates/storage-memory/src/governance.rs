use super::{
    Arc, BTreeMap, BTreeSet, HandleReleaseStore, Mutex, OrganizationPolicyRecord,
    OrganizationPolicyStore, OrganizationRecord, OrganizationStore, PersistenceResult,
    RealmModerationPolicyRecord, RealmModerationPolicyStore, RealmOrganizationStatementRecord,
    RealmOrganizationStatementStore, RealmOrganizationStore, RetentionPolicyRecord,
    RetentionPolicyStore, RetentionTombstoneRecord, RetentionTombstoneStore, async_trait,
};
pub(crate) struct MemoryHandleReleaseStore {
    data: Arc<Mutex<BTreeMap<String, chrono::DateTime<chrono::Utc>>>>,
}
impl MemoryHandleReleaseStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}
#[async_trait]
impl HandleReleaseStore for MemoryHandleReleaseStore {
    async fn put(
        &self,
        localpart: &str,
        released_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        self.data.lock().insert(localpart.to_owned(), released_at);
        Ok(())
    }

    async fn snapshot_all(
        &self,
    ) -> PersistenceResult<Vec<(String, chrono::DateTime<chrono::Utc>)>> {
        Ok(self
            .data
            .lock()
            .iter()
            .map(|(localpart, released_at)| (localpart.clone(), *released_at))
            .collect())
    }
}
pub(crate) struct MemoryRetentionPolicyStore {
    data: Arc<Mutex<BTreeMap<String, RetentionPolicyRecord>>>,
}
impl MemoryRetentionPolicyStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}
#[async_trait]
impl RetentionPolicyStore for MemoryRetentionPolicyStore {
    async fn get(&self, realm_id: &str) -> PersistenceResult<Option<RetentionPolicyRecord>> {
        Ok(self.data.lock().get(realm_id).cloned())
    }

    async fn put(&self, record: &RetentionPolicyRecord) -> PersistenceResult<()> {
        self.data
            .lock()
            .insert(record.realm_id.clone(), record.clone());
        Ok(())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<RetentionPolicyRecord>> {
        Ok(self.data.lock().values().cloned().collect())
    }
}
pub(crate) struct MemoryRetentionTombstoneStore {
    data: Arc<Mutex<BTreeMap<String, RetentionTombstoneRecord>>>,
}
impl MemoryRetentionTombstoneStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}
#[async_trait]
impl RetentionTombstoneStore for MemoryRetentionTombstoneStore {
    async fn get(&self, event_id: &str) -> PersistenceResult<Option<RetentionTombstoneRecord>> {
        Ok(self.data.lock().get(event_id).cloned())
    }

    async fn put(&self, record: &RetentionTombstoneRecord) -> PersistenceResult<()> {
        self.data
            .lock()
            .insert(record.event_id.clone(), record.clone());
        Ok(())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<RetentionTombstoneRecord>> {
        Ok(self.data.lock().values().cloned().collect())
    }
}
pub(crate) struct MemoryOrganizationStore {
    data: Arc<Mutex<BTreeMap<String, OrganizationRecord>>>,
}
impl MemoryOrganizationStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}
#[async_trait]
impl OrganizationStore for MemoryOrganizationStore {
    async fn get(&self, organization_id: &str) -> PersistenceResult<Option<OrganizationRecord>> {
        Ok(self.data.lock().get(organization_id).cloned())
    }

    async fn put(&self, record: &OrganizationRecord) -> PersistenceResult<()> {
        self.data
            .lock()
            .insert(record.organization_id.clone(), record.clone());
        Ok(())
    }

    async fn list(&self) -> PersistenceResult<Vec<OrganizationRecord>> {
        Ok(self.data.lock().values().cloned().collect())
    }
}
pub(crate) struct MemoryOrganizationPolicyStore {
    data: Arc<Mutex<BTreeMap<String, OrganizationPolicyRecord>>>,
}
impl MemoryOrganizationPolicyStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}
#[async_trait]
impl OrganizationPolicyStore for MemoryOrganizationPolicyStore {
    async fn get(
        &self,
        organization_id: &str,
    ) -> PersistenceResult<Option<OrganizationPolicyRecord>> {
        Ok(self.data.lock().get(organization_id).cloned())
    }

    async fn put(&self, record: &OrganizationPolicyRecord) -> PersistenceResult<()> {
        self.data
            .lock()
            .insert(record.organization_id.clone(), record.clone());
        Ok(())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<OrganizationPolicyRecord>> {
        Ok(self.data.lock().values().cloned().collect())
    }
}
pub(crate) struct MemoryRealmOrganizationStore {
    data: Arc<Mutex<BTreeMap<String, BTreeSet<String>>>>,
}
impl MemoryRealmOrganizationStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}
#[async_trait]
impl RealmOrganizationStore for MemoryRealmOrganizationStore {
    async fn link(&self, realm_id: &str, organization_id: &str) -> PersistenceResult<()> {
        self.data
            .lock()
            .entry(realm_id.to_owned())
            .or_default()
            .insert(organization_id.to_owned());
        Ok(())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<(String, BTreeSet<String>)>> {
        Ok(self
            .data
            .lock()
            .iter()
            .map(|(realm_id, organizations)| (realm_id.clone(), organizations.clone()))
            .collect())
    }
}
pub(crate) struct MemoryRealmOrganizationStatementStore {
    data: Arc<Mutex<BTreeMap<(String, String, String), RealmOrganizationStatementRecord>>>,
}
impl MemoryRealmOrganizationStatementStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}
#[async_trait]
impl RealmOrganizationStatementStore for MemoryRealmOrganizationStatementStore {
    async fn put(&self, record: &RealmOrganizationStatementRecord) -> PersistenceResult<()> {
        self.data.lock().insert(
            (
                record.realm_id.clone(),
                record.organization_id.clone(),
                record.relationship.clone(),
            ),
            record.clone(),
        );
        Ok(())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<RealmOrganizationStatementRecord>> {
        Ok(self.data.lock().values().cloned().collect())
    }
}
pub(crate) struct MemoryRealmModerationPolicyStore {
    data: Arc<Mutex<BTreeMap<String, RealmModerationPolicyRecord>>>,
}
impl MemoryRealmModerationPolicyStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}
#[async_trait]
impl RealmModerationPolicyStore for MemoryRealmModerationPolicyStore {
    async fn get(&self, realm_id: &str) -> PersistenceResult<Option<RealmModerationPolicyRecord>> {
        Ok(self.data.lock().get(realm_id).cloned())
    }

    async fn put(&self, record: &RealmModerationPolicyRecord) -> PersistenceResult<()> {
        self.data
            .lock()
            .insert(record.realm_id.clone(), record.clone());
        Ok(())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<RealmModerationPolicyRecord>> {
        Ok(self.data.lock().values().cloned().collect())
    }
}
