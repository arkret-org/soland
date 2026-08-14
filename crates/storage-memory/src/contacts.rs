use super::{
    Arc, BTreeMap, ConsentCellKey, ConsentCellRecord, ConsentCellStore, ContactKey, ContactRecord,
    ContactStore, InviteReceivePolicyStore, MimiConsentCorrelationRecord,
    MimiConsentCorrelationStore, Mutex, PersistenceResult, async_trait,
};
pub(crate) struct MemoryContactStore {
    pub(crate) data: Arc<Mutex<BTreeMap<ContactKey, ContactRecord>>>,
}
impl MemoryContactStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}
#[async_trait]
impl ContactStore for MemoryContactStore {
    async fn get(&self, requester: &str, target: &str) -> PersistenceResult<Option<ContactRecord>> {
        Ok(self
            .data
            .lock()
            .get(&(requester.to_owned(), target.to_owned()))
            .cloned())
    }

    async fn put(&self, record: &ContactRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.insert(
            (record.requester.clone(), record.target.clone()),
            record.clone(),
        );
        Ok(())
    }

    async fn put_if_updated_at(
        &self,
        expected_updated_at: chrono::DateTime<chrono::Utc>,
        record: &ContactRecord,
    ) -> PersistenceResult<bool> {
        let mut data = self.data.lock();
        let key = (record.requester.clone(), record.target.clone());
        let reverse_key = (record.target.clone(), record.requester.clone());
        let current_key = if data.contains_key(&key) {
            key.clone()
        } else {
            reverse_key
        };
        let Some(current) = data.get(&current_key) else {
            return Ok(false);
        };
        if current.updated_at != expected_updated_at || record.updated_at <= expected_updated_at {
            return Ok(false);
        }
        if current_key != key {
            data.remove(&current_key);
        }
        data.insert(key, record.clone());
        Ok(true)
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<ContactRecord>> {
        let data = self.data.lock();
        Ok(data
            .values()
            .filter(|c| c.requester == actor || c.target == actor)
            .cloned()
            .collect())
    }

    async fn delete(&self, requester: &str, target: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.retain(|(row_requester, row_target), _| {
            row_requester != requester || row_target != target
        });
        Ok(())
    }
}
// In-memory invite-receive policy store
pub(crate) struct MemoryInviteReceivePolicyStore {
    pub(crate) data: Arc<
        Mutex<
            BTreeMap<
                String,
                arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
            >,
        >,
    >,
}
impl MemoryInviteReceivePolicyStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}
#[async_trait]
impl InviteReceivePolicyStore for MemoryInviteReceivePolicyStore {
    async fn get(
        &self,
        subject_id: &str,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy>,
    > {
        Ok(self.data.lock().get(subject_id).cloned())
    }

    async fn put(
        &self,
        policy: &arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
    ) -> PersistenceResult<()> {
        self.data
            .lock()
            .insert(policy.subject_id.as_str().to_owned(), policy.clone());
        Ok(())
    }

    async fn snapshot_all(
        &self,
    ) -> PersistenceResult<
        Vec<(
            String,
            arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
        )>,
    > {
        Ok(self
            .data
            .lock()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }
}
// In-memory consent-cell store
pub(crate) struct MemoryConsentCellStore {
    data: Arc<Mutex<BTreeMap<ConsentCellKey, ConsentCellRecord>>>,
}
impl MemoryConsentCellStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}
#[async_trait]
impl ConsentCellStore for MemoryConsentCellStore {
    async fn get(
        &self,
        holder: &str,
        peer: &str,
        scope: &str,
    ) -> PersistenceResult<Option<ConsentCellRecord>> {
        let key = ConsentCellKey {
            holder: holder.to_owned(),
            peer: peer.to_owned(),
            scope: scope.to_owned(),
        };
        Ok(self.data.lock().get(&key).cloned())
    }

    async fn put(&self, record: &ConsentCellRecord) -> PersistenceResult<()> {
        let key = ConsentCellKey {
            holder: record.holder.clone(),
            peer: record.peer.clone(),
            scope: record.scope.clone(),
        };
        self.data.lock().insert(key, record.clone());
        Ok(())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<(ConsentCellKey, ConsentCellRecord)>> {
        Ok(self
            .data
            .lock()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }
}

pub(crate) struct MemoryMimiConsentCorrelationStore {
    data: Arc<Mutex<BTreeMap<String, MimiConsentCorrelationRecord>>>,
}

impl MemoryMimiConsentCorrelationStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl MimiConsentCorrelationStore for MemoryMimiConsentCorrelationStore {
    async fn get(
        &self,
        consent_id: &str,
    ) -> PersistenceResult<Option<MimiConsentCorrelationRecord>> {
        Ok(self.data.lock().get(consent_id).cloned())
    }

    async fn put(&self, record: &MimiConsentCorrelationRecord) -> PersistenceResult<()> {
        self.data
            .lock()
            .entry(record.consent_id.clone())
            .or_insert_with(|| record.clone());
        Ok(())
    }
}
