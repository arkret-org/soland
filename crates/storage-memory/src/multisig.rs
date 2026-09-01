use soland_storage::{
    MultisigLeaseCommand, MultisigLeaseDecision, MultisigLeaseState, decide_multisig_lease,
};

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
// projection; on boot `hydrate_projections_from_persistence` rebuilds the
// projection from the durable stores. The PostgreSQL counterpart
// (`PgMultisigPendingStore` in `storage-postgres`) is fully implemented
// and serves the production routing path.

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
        let state = MultisigLeaseState::from(&*record);
        let decision = decide_multisig_lease(
            Some(&state),
            &MultisigLeaseCommand::TryClaim {
                node_id: node_id.to_owned(),
                now,
                claimed_until,
            },
        )?;
        match decision {
            MultisigLeaseDecision::Update(next) => {
                apply_lease_state(record, &next);
                Ok((true, next.claim_seq))
            }
            MultisigLeaseDecision::Rejected { current_claim_seq } => Ok((false, current_claim_seq)),
            MultisigLeaseDecision::Missing | MultisigLeaseDecision::Delete => Err(
                PersistenceError::Internal("multisig claim decision is inconsistent".to_owned()),
            ),
        }
    }

    async fn release_claim(&self, seal_id: &str, node_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        let Some(record) = data.get_mut(seal_id) else {
            return Ok(());
        };
        let state = MultisigLeaseState::from(&*record);
        match decide_multisig_lease(
            Some(&state),
            &MultisigLeaseCommand::Release {
                node_id: node_id.to_owned(),
            },
        )? {
            MultisigLeaseDecision::Update(next) => {
                apply_lease_state(record, &next);
                Ok(())
            }
            MultisigLeaseDecision::Rejected { .. } => Ok(()),
            MultisigLeaseDecision::Missing | MultisigLeaseDecision::Delete => Err(
                PersistenceError::Internal("multisig release decision is inconsistent".to_owned()),
            ),
        }
    }

    async fn delete_with_fence(
        &self,
        seal_id: &str,
        node_id: &str,
        claim_seq: i64,
    ) -> PersistenceResult<bool> {
        let mut data = self.data.lock();
        let Some(record) = data.get(seal_id) else {
            return Ok(false);
        };
        let state = MultisigLeaseState::from(record);
        match decide_multisig_lease(
            Some(&state),
            &MultisigLeaseCommand::DeleteWithFence {
                node_id: node_id.to_owned(),
                claim_seq,
            },
        )? {
            MultisigLeaseDecision::Delete => Ok(data.remove(seal_id).is_some()),
            MultisigLeaseDecision::Rejected { .. } => Ok(false),
            MultisigLeaseDecision::Missing | MultisigLeaseDecision::Update(_) => Err(
                PersistenceError::Internal("multisig delete decision is inconsistent".to_owned()),
            ),
        }
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
        let state = MultisigLeaseState::from(&*record);
        match decide_multisig_lease(
            Some(&state),
            &MultisigLeaseCommand::RenewWithFence {
                node_id: node_id.to_owned(),
                claim_seq,
                claimed_until: new_claimed_until,
            },
        )? {
            MultisigLeaseDecision::Update(next) => {
                apply_lease_state(record, &next);
                Ok(true)
            }
            MultisigLeaseDecision::Rejected { .. } => Ok(false),
            MultisigLeaseDecision::Missing | MultisigLeaseDecision::Delete => Err(
                PersistenceError::Internal("multisig renew decision is inconsistent".to_owned()),
            ),
        }
    }
}

fn apply_lease_state(record: &mut MultisigPendingRecord, state: &MultisigLeaseState) {
    record
        .claimed_by_node_id
        .clone_from(&state.claimed_by_node_id);
    record.claimed_until = state.claimed_until;
    record.claim_seq = state.claim_seq;
}

#[cfg(test)]
mod tests {
    use soland_storage::transition_contract_tests::assert_multisig_lease_contract;

    use super::MemoryMultisigPendingStore;

    #[tokio::test]
    async fn memory_adapter_satisfies_shared_multisig_lease_contract() {
        assert_multisig_lease_contract(
            &MemoryMultisigPendingStore::new(),
            "memory-multisig-contract",
        )
        .await;
    }
}
