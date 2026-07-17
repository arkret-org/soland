use super::{
    Arc, BTreeMap, MultisigPendingRecord, MultisigPendingStore, Mutex, PersistenceError,
    PersistenceResult, Value, async_trait,
};
// ── G3.S1: MLS / E2EE lifecycle stores ────────────────────────────────
//
// Three independent durable surfaces — KeyPackages, Welcomes, commit
// epochs — backing the reducer's projection of the same shape. The
// reducer keeps an in-process projection (`ProjectionState::mls_*`); the
// stores are the persistent mirror. The routing layer in
// `routing/mls.rs` writes through to the stores AND updates the
// projection; on restart `AppState::new` will eventually hydrate the
// projection from the stores (TODO(G3.S1-followup): hydration is not
// wired in this slice — the Memory store is in-process anyway, and the
// Pg store is a stub pending migrations landing in production).

// In-memory multisig pending store
pub(crate) struct MemoryMultisigPendingStore {
    data: Arc<Mutex<BTreeMap<String, MultisigPendingRecord>>>,
}
impl MemoryMultisigPendingStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}
#[async_trait]
impl MultisigPendingStore for MemoryMultisigPendingStore {
    async fn upsert(&self, record: MultisigPendingRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.insert(record.seal_id.clone(), record);
        Ok(())
    }

    async fn get(&self, seal_id: &str) -> PersistenceResult<Option<MultisigPendingRecord>> {
        let data = self.data.lock();
        Ok(data.get(seal_id).cloned())
    }

    async fn add_partial(
        &self,
        seal_id: &str,
        signer_did: &str,
        partial: Value,
    ) -> PersistenceResult<MultisigPendingRecord> {
        let mut data = self.data.lock();
        let record = data.get_mut(seal_id).ok_or_else(|| {
            PersistenceError::NotFound(format!("multisig_pending row {seal_id} not found"))
        })?;
        record.partials.insert(signer_did.to_owned(), partial);
        Ok(record.clone())
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<MultisigPendingRecord>> {
        let data = self.data.lock();
        Ok(data
            .values()
            .filter(|r| r.realm_id == realm_id)
            .cloned()
            .collect())
    }

    async fn delete(&self, seal_id: &str) -> PersistenceResult<bool> {
        let mut data = self.data.lock();
        Ok(data.remove(seal_id).is_some())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MultisigPendingRecord>> {
        let data = self.data.lock();
        Ok(data.values().cloned().collect())
    }

    async fn try_claim(
        &self,
        seal_id: &str,
        node_id: &str,
        now: chrono::DateTime<chrono::Utc>,
        claimed_until: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<(bool, i64)> {
        let mut data = self.data.lock();
        let Some(record) = data.get_mut(seal_id) else {
            return Ok((false, 0));
        };
        let claimable = match (&record.claimed_by_node_id, record.claimed_until) {
            (None, _) => true,
            (Some(_), None) => true,
            (Some(_), Some(deadline)) => deadline <= now,
        };
        if !claimable {
            return Ok((false, record.claim_seq));
        }
        record.claimed_by_node_id = Some(node_id.to_owned());
        record.claimed_until = Some(claimed_until);
        record.claim_seq += 1;
        Ok((true, record.claim_seq))
    }

    async fn release_claim(&self, seal_id: &str, node_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        if let Some(record) = data.get_mut(seal_id)
            && record.claimed_by_node_id.as_deref() == Some(node_id)
        {
            record.claimed_by_node_id = None;
            record.claimed_until = None;
        }
        Ok(())
    }

    async fn delete_with_fence(
        &self,
        seal_id: &str,
        node_id: &str,
        claim_seq: i64,
    ) -> PersistenceResult<bool> {
        let mut data = self.data.lock();
        let matches = data
            .get(seal_id)
            .map(|r| r.claimed_by_node_id.as_deref() == Some(node_id) && r.claim_seq == claim_seq)
            .unwrap_or(false);
        if !matches {
            return Ok(false);
        }
        Ok(data.remove(seal_id).is_some())
    }

    async fn renew_claim(
        &self,
        seal_id: &str,
        node_id: &str,
        claim_seq: i64,
        new_claimed_until: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        let mut data = self.data.lock();
        let Some(record) = data.get_mut(seal_id) else {
            return Ok(false);
        };
        if record.claimed_by_node_id.as_deref() != Some(node_id) {
            return Ok(false);
        }
        if record.claim_seq != claim_seq {
            return Ok(false);
        }
        record.claimed_until = Some(new_claimed_until);
        Ok(true)
    }
}
