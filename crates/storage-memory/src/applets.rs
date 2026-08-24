use super::{
    AppletStore, AppletTransactionReplayBegin, AppletTransactionReplayRecord, BTreeMap, Mutex,
    PersistenceError, PersistenceResult, Value, async_trait,
};
pub(crate) struct MemoryAppletStore {
    pub(crate) records: Mutex<BTreeMap<String, Value>>,
    transactions: Mutex<BTreeMap<(String, String, String), AppletTransactionReplayRecord>>,
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

    async fn compare_and_swap(
        &self,
        applet_id: &str,
        expected: &Value,
        replacement: Value,
    ) -> PersistenceResult<bool> {
        let mut records = self.records.lock();
        if records.get(applet_id) != Some(expected) {
            return Ok(false);
        }
        records.insert(applet_id.to_owned(), replacement);
        Ok(true)
    }

    async fn list(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.records.lock().values().cloned().collect())
    }

    async fn begin_transaction_replay(
        &self,
        record: AppletTransactionReplayRecord,
    ) -> PersistenceResult<AppletTransactionReplayBegin> {
        let key = (
            record.applet_id.to_string(),
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
        applet_id: &str,
        source_service_id: &str,
        idempotency_key: &str,
        outcome: Value,
    ) -> PersistenceResult<()> {
        let key = (
            applet_id.to_owned(),
            source_service_id.to_owned(),
            idempotency_key.to_owned(),
        );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stale_record_mutation_cannot_overwrite_a_concurrent_ghost_append() {
        let store = MemoryAppletStore::new();
        let applet_id = "ak:applet:01994137-0000-7000-8000-000000000001";
        let original = serde_json::json!({"status": "installed", "ghosts": []});
        store
            .records
            .lock()
            .insert(applet_id.to_owned(), original.clone());
        let appended = serde_json::json!({
            "status": "installed",
            "ghosts": [{"ghost_actor_id": "ak:did_core:webvh:z6mkghost"}],
        });
        assert!(
            store
                .compare_and_swap(applet_id, &original, appended.clone())
                .await
                .unwrap()
        );
        let stale_revoke = serde_json::json!({"status": "revoked", "ghosts": []});
        assert!(
            !store
                .compare_and_swap(applet_id, &original, stale_revoke)
                .await
                .unwrap()
        );
        assert_eq!(store.get(applet_id).await.unwrap(), Some(appended));
    }
}
