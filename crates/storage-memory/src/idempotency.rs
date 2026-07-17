use super::*;
/// In-memory `(principal_id, idempotency_key) -> IdempotencyRecord` table.
/// Mirrors the `idempotency_keys` Pg table on the same composite key.
pub(crate) struct MemoryIdempotencyStore {
    data: Arc<Mutex<BTreeMap<(String, String), IdempotencyRecord>>>,
}
impl MemoryIdempotencyStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}
#[async_trait]
impl IdempotencyStore for MemoryIdempotencyStore {
    async fn get(
        &self,
        principal_id: &str,
        idempotency_key: &str,
    ) -> PersistenceResult<Option<IdempotencyRecord>> {
        let data = self.data.lock();
        Ok(data
            .get(&(principal_id.to_owned(), idempotency_key.to_owned()))
            .cloned())
    }

    async fn record(&self, record: &IdempotencyRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        // First-writer-wins: keep the earliest landed row (mirrors the Pg
        // `ON CONFLICT DO NOTHING`), so a concurrent racer reads back the
        // original first response rather than overwriting it.
        data.entry((record.principal_id.clone(), record.idempotency_key.clone()))
            .or_insert_with(|| record.clone());
        Ok(())
    }

    async fn prune_expired(&self, now: chrono::DateTime<Utc>) -> PersistenceResult<usize> {
        let mut data = self.data.lock();
        let before = data.len();
        data.retain(|_, record| record.expires_at > now);
        Ok(before - data.len())
    }
}
