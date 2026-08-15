use super::{
    Arc, BTreeMap, ConsentCellKey, ConsentCellRecord, ConsentCellStore, ContactKey, ContactRecord,
    ContactStore, ContactVerifiedMirrorRecord, ContactVerifiedMirrorStore,
    InviteReceivePolicyStore, MimiConsentCorrelationRecord, MimiConsentCorrelationStore, Mutex,
    PersistenceError, PersistenceResult, async_trait,
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

pub(crate) struct MemoryContactVerifiedMirrorStore {
    data: Arc<Mutex<BTreeMap<(String, String), ContactVerifiedMirrorRecord>>>,
}

impl MemoryContactVerifiedMirrorStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl ContactVerifiedMirrorStore for MemoryContactVerifiedMirrorStore {
    async fn get(
        &self,
        target_holder_id: &str,
        request_event_id: &str,
    ) -> PersistenceResult<Option<ContactVerifiedMirrorRecord>> {
        Ok(self
            .data
            .lock()
            .get(&(target_holder_id.to_owned(), request_event_id.to_owned()))
            .cloned())
    }

    async fn get_by_digest(
        &self,
        target_holder_id: &str,
        request_digest: &str,
    ) -> PersistenceResult<Option<ContactVerifiedMirrorRecord>> {
        Ok(self
            .data
            .lock()
            .values()
            .find(|record| {
                record.target_holder_id == target_holder_id
                    && record.request_digest == request_digest
            })
            .cloned())
    }

    async fn put_verified(&self, record: &ContactVerifiedMirrorRecord) -> PersistenceResult<()> {
        let key = (
            record.target_holder_id.clone(),
            record.request_event_id.clone(),
        );
        let mut data = self.data.lock();
        if let Some(existing) = data.get(&key) {
            if existing == record {
                return Ok(());
            }
            return Err(PersistenceError::Internal(
                "cas_conflict: Contact verified mirror binding mismatch".to_owned(),
            ));
        }
        data.insert(key, record.clone());
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

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn verified_mirror() -> ContactVerifiedMirrorRecord {
        ContactVerifiedMirrorRecord {
            target_holder_id: "did:web:holder.example".to_owned(),
            request_event_id: "ak:event:request".to_owned(),
            request_digest: "sha256:request".to_owned(),
            canonical_event_bytes: br#"{"event_id":"ak:event:request"}"#.to_vec(),
            source_receipt: serde_json::json!({"request_event_ref":"ak:event:request"}),
            issuer_service_id: "did:web:requester.example".to_owned(),
            verified_at: chrono::Utc
                .timestamp_opt(1_700_000_000, 0)
                .single()
                .expect("fixture timestamp"),
        }
    }

    #[tokio::test]
    async fn verified_mirror_is_holder_scoped_and_cas_immutable() {
        let store = MemoryContactVerifiedMirrorStore::new();
        let record = verified_mirror();

        store.put_verified(&record).await.unwrap();
        store.put_verified(&record).await.unwrap();
        assert_eq!(
            store
                .get(&record.target_holder_id, &record.request_event_id)
                .await
                .unwrap(),
            Some(record.clone())
        );
        assert_eq!(
            store
                .get_by_digest(&record.target_holder_id, &record.request_digest)
                .await
                .unwrap(),
            Some(record.clone())
        );
        assert!(
            store
                .get("did:web:other.example", &record.request_event_id)
                .await
                .unwrap()
                .is_none()
        );

        let mut conflicting = record;
        conflicting.source_receipt = serde_json::json!({"request_event_ref":"ak:event:other"});
        assert!(store.put_verified(&conflicting).await.is_err());
    }
}
