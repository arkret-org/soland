use super::*;
pub(crate) struct MemoryAppletStore {
    records: Mutex<BTreeMap<String, Value>>,
    transactions: Mutex<BTreeMap<(String, String), AppletTransactionReplayRecord>>,
}
impl MemoryAppletStore {
    pub(crate) fn new() -> Self {
        Self {
            records: Mutex::new(BTreeMap::new()),
            transactions: Mutex::new(BTreeMap::new()),
        }
    }
}
#[async_trait]
impl AppletStore for MemoryAppletStore {
    async fn get(&self, applet_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self.records.lock().get(applet_id).cloned())
    }

    async fn put(&self, applet_id: &str, record: Value) -> PersistenceResult<()> {
        self.records.lock().insert(applet_id.to_owned(), record);
        Ok(())
    }

    async fn list(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.records.lock().values().cloned().collect())
    }

    async fn begin_transaction_replay(
        &self,
        record: AppletTransactionReplayRecord,
    ) -> PersistenceResult<AppletTransactionReplayBegin> {
        let key = (
            record.source_service_id.clone(),
            record.idempotency_key.clone(),
        );
        let mut transactions = self.transactions.lock();
        if let Some(existing) = transactions.get(&key) {
            return Ok(AppletTransactionReplayBegin::Existing(existing.clone()));
        }
        transactions.insert(key, record);
        Ok(AppletTransactionReplayBegin::Fresh)
    }

    async fn complete_transaction_replay(
        &self,
        source_service_id: &str,
        idempotency_key: &str,
        outcome: Value,
    ) -> PersistenceResult<()> {
        let key = (source_service_id.to_owned(), idempotency_key.to_owned());
        let mut transactions = self.transactions.lock();
        let Some(record) = transactions.get_mut(&key) else {
            return Err(PersistenceError::NotFound(format!(
                "applet transaction replay missing for {source_service_id}/{idempotency_key}"
            )));
        };
        record.outcome = Some(outcome);
        record.completed_at = Some(chrono::Utc::now());
        Ok(())
    }
}
