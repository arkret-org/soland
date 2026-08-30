use arkret_wire::{ActorId, CellRef, DidCoreId};

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
    async fn get(
        &self,
        requester_id: &ActorId,
        target_id: &ActorId,
    ) -> PersistenceResult<Option<ContactRecord>> {
        Ok(self
            .data
            .lock()
            .get(&(requester_id.clone(), target_id.clone()))
            .cloned())
    }

    async fn put(&self, record: &ContactRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.insert(
            (record.requester_id.clone(), record.target_id.clone()),
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
        let key = (record.requester_id.clone(), record.target_id.clone());
        let reverse_key = (record.target_id.clone(), record.requester_id.clone());
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

    async fn list_for_actor(&self, actor_id: &ActorId) -> PersistenceResult<Vec<ContactRecord>> {
        let data = self.data.lock();
        Ok(data
            .values()
            .filter(|c| &c.requester_id == actor_id || &c.target_id == actor_id)
            .cloned()
            .collect())
    }

    async fn delete(&self, requester_id: &ActorId, target_id: &ActorId) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.retain(|(row_requester, row_target), _| {
            row_requester != requester_id || row_target != target_id
        });
        Ok(())
    }
}

pub(crate) struct MemoryContactVerifiedMirrorStore {
    pub(crate) data: Arc<Mutex<BTreeMap<(String, String), ContactVerifiedMirrorRecord>>>,
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
                arkret_wire::AccountId,
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
        account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy>,
    > {
        Ok(self.data.lock().get(account_id).cloned())
    }

    async fn put(
        &self,
        account_id: &arkret_wire::AccountId,
        policy: &arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
    ) -> PersistenceResult<()> {
        soland_storage::validate_invite_policy_account(account_id, policy)?;
        self.data.lock().insert(account_id.clone(), policy.clone());
        Ok(())
    }

    async fn snapshot_all(
        &self,
    ) -> PersistenceResult<
        Vec<(
            arkret_wire::AccountId,
            arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
        )>,
    > {
        Ok(self
            .data
            .lock()
            .iter()
            .map(|(account, policy)| (account.clone(), policy.clone()))
            .collect())
    }
}
// In-memory consent-cell store. Rows land here only through the Event commit
// unit of work, which is why the store itself has no writer.
pub(crate) struct MemoryConsentCellStore {
    pub(crate) data: Arc<Mutex<BTreeMap<ConsentCellKey, ConsentCellRecord>>>,
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
        holder_principal_id: &DidCoreId,
        cell_id: &CellRef,
    ) -> PersistenceResult<Option<ConsentCellRecord>> {
        let key = ConsentCellKey {
            holder_principal_id: holder_principal_id.clone(),
            cell_id: cell_id.clone(),
        };
        Ok(self.data.lock().get(&key).cloned())
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

    #[tokio::test]
    async fn invite_policy_is_scoped_to_the_complete_account() {
        use arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy;
        let store = MemoryInviteReceivePolicyStore::new();
        let principal = DidCoreId::new("ak:did_core:web:holder.example".to_owned()).unwrap();
        let first_account = arkret_wire::AccountId::new(
            principal.clone(),
            DidCoreId::new("ak:did_core:web:first-station.example".to_owned()).unwrap(),
        );
        let second_account = arkret_wire::AccountId::new(
            principal,
            DidCoreId::new("ak:did_core:web:second-station.example".to_owned()).unwrap(),
        );
        let first = InviteReceivePolicy::spec_default(first_account.clone());
        let second = InviteReceivePolicy::spec_default(second_account.clone());
        store.put(&first_account, &first).await.unwrap();
        assert_eq!(
            store.get(&first_account).await.unwrap(),
            Some(first.clone())
        );
        assert_eq!(store.get(&second_account).await.unwrap(), None);
        assert!(store.put(&second_account, &first).await.is_err());
        store.put(&second_account, &second).await.unwrap();
        assert_eq!(store.get(&first_account).await.unwrap(), Some(first));
        assert_eq!(store.get(&second_account).await.unwrap(), Some(second));
        let snapshot = store.snapshot_all().await.unwrap();
        assert_eq!(snapshot.len(), 2);
        assert!(
            snapshot
                .iter()
                .any(|(account_id, _)| account_id == &first_account)
        );
        assert!(
            snapshot
                .iter()
                .any(|(account_id, _)| account_id == &second_account)
        );
    }

    fn verified_mirror() -> ContactVerifiedMirrorRecord {
        ContactVerifiedMirrorRecord {
            target_holder_id: "ak:did_core:web:holder.example".to_owned(),
            request_event_id: "ak:event:request".to_owned(),
            request_digest: "sha256:request".to_owned(),
            canonical_event_bytes: br#"{"event_id":"ak:event:request"}"#.to_vec(),
            source_receipt: serde_json::from_value(serde_json::json!({
                "core": {
                    "holder": {"kind": "human", "account_id": {"principal_id": "ak:did_core:web:holder.example", "station_id": "ak:did_core:web:holder-station.example"}},
                    "peer": {"kind": "human", "account_id": {"principal_id": "ak:did_core:web:peer.example", "station_id": "ak:did_core:web:peer-station.example"}},
                    "slot_version": 1,
                    "request_event_ref": "ak:event:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                    "source_checkpoint": format!("sha256:{}", "b".repeat(64)),
                    "accepted_at": "2026-08-09T00:00:00.000Z",
                    "issuer_id": "ak:did_core:web:issuer.example"
                },
                "receipt_digest": format!("sha256:{}", "c".repeat(64)),
                "signature": {
                    "verification_method": "did:web:issuer.example#federation-signing-key",
                    "created_at": "2026-08-09T00:00:00.000Z",
                    "jws": "YWJj"
                }
            }))
            .expect("typed Contact receipt fixture"),
            issuer_id: "ak:did_core:web:requester_id.example".to_owned(),
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
        conflicting.source_receipt.core.request_event_ref =
            arkret_wire::EventId::new("ak:event:ARTzU1T6HTPffn8VGBicK6XWx4KIC4PXvv0NX-EMSj4G")
                .unwrap();
        assert!(store.put_verified(&conflicting).await.is_err());
    }
}
