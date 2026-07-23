use super::{
    Arc, BTreeMap, IdempotencyRecord, IdempotencyStore, Mutex, PersistenceResult, Utc, async_trait,
};
/// In-memory `(principal_id, idempotency_key) -> IdempotencyRecord` table.
/// Mirrors the `idempotency_keys` Pg table on the same composite key.
pub(crate) struct MemoryIdempotencyStore {
    #[cfg(feature = "fault-injection")]
    fault_injector: Arc<crate::FaultInjector>,
    pub(crate) data: Arc<Mutex<BTreeMap<(String, String), IdempotencyRecord>>>,
}
impl MemoryIdempotencyStore {
    #[cfg(not(feature = "fault-injection"))]
    pub(crate) fn new() -> Self {
        Self {
            #[cfg(feature = "fault-injection")]
            fault_injector: Arc::new(crate::FaultInjector::default()),
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    #[cfg(feature = "fault-injection")]
    pub(crate) fn with_fault_injector(fault_injector: Arc<crate::FaultInjector>) -> Self {
        Self {
            fault_injector,
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
        #[cfg(feature = "fault-injection")]
        self.fault_injector.check(
            crate::FaultPoint::IdempotencyRecord,
            crate::FaultTiming::Before,
        )?;
        let mut data = self.data.lock();
        // First-writer-wins: keep the earliest landed row (mirrors the Pg
        // `ON CONFLICT DO NOTHING`), so a concurrent racer reads back the
        // original first response rather than overwriting it.
        data.entry((record.principal_id.clone(), record.idempotency_key.clone()))
            .or_insert_with(|| record.clone());
        #[cfg(feature = "fault-injection")]
        self.fault_injector.check(
            crate::FaultPoint::IdempotencyRecord,
            crate::FaultTiming::After,
        )?;
        Ok(())
    }

    async fn prune_expired(&self, now: chrono::DateTime<Utc>) -> PersistenceResult<usize> {
        let mut data = self.data.lock();
        let before = data.len();
        data.retain(|_, record| record.expires_at > now);
        Ok(before - data.len())
    }
}
