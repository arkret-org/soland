use super::{
    Arc, BTreeMap, ControlProposalAuthorityAckRecord, ControlProposalAuthorityAckStore, Mutex,
    PersistenceResult, async_trait,
};

pub(crate) struct MemoryControlProposalAuthorityAckStore {
    data: Arc<Mutex<BTreeMap<String, ControlProposalAuthorityAckRecord>>>,
}

impl MemoryControlProposalAuthorityAckStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl ControlProposalAuthorityAckStore for MemoryControlProposalAuthorityAckStore {
    async fn get(
        &self,
        ack_key: &str,
    ) -> PersistenceResult<Option<ControlProposalAuthorityAckRecord>> {
        Ok(self.data.lock().get(ack_key).cloned())
    }

    async fn record(&self, record: &ControlProposalAuthorityAckRecord) -> PersistenceResult<()> {
        self.data
            .lock()
            .entry(record.ack_key.clone())
            .or_insert_with(|| record.clone());
        Ok(())
    }
}
