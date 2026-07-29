use super::{
    Arc, BTreeMap, Mutex, PersistenceResult, ProposalMemberReceiptRecord,
    ProposalMemberReceiptStore, async_trait,
};

pub(crate) struct MemoryProposalMemberReceiptStore {
    data: Arc<Mutex<BTreeMap<String, ProposalMemberReceiptRecord>>>,
}

impl MemoryProposalMemberReceiptStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl ProposalMemberReceiptStore for MemoryProposalMemberReceiptStore {
    async fn get(
        &self,
        receipt_key: &str,
    ) -> PersistenceResult<Option<ProposalMemberReceiptRecord>> {
        Ok(self.data.lock().get(receipt_key).cloned())
    }

    async fn record(&self, record: &ProposalMemberReceiptRecord) -> PersistenceResult<()> {
        self.data
            .lock()
            .entry(record.receipt_key.clone())
            .or_insert_with(|| record.clone());
        Ok(())
    }
}
