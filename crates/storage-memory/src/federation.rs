use super::*;
// In-memory federation transaction replay store
pub(crate) struct MemoryFederationTransactionStore {
    data: Arc<Mutex<BTreeMap<(String, String), FederationTransactionRecord>>>,
}
impl MemoryFederationTransactionStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}
#[async_trait]
impl FederationTransactionStore for MemoryFederationTransactionStore {
    async fn get(
        &self,
        origin: &str,
        txn_id: &str,
    ) -> PersistenceResult<Option<FederationTransactionRecord>> {
        let data = self.data.lock();
        Ok(data.get(&(origin.to_owned(), txn_id.to_owned())).cloned())
    }

    async fn try_begin(&self, record: &FederationTransactionRecord) -> PersistenceResult<bool> {
        let mut data = self.data.lock();
        let key = (record.origin.clone(), record.txn_id.clone());
        if data.contains_key(&key) {
            return Ok(false);
        }
        data.insert(key, record.clone());
        Ok(true)
    }

    async fn put(&self, record: &FederationTransactionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.insert(
            (record.origin.clone(), record.txn_id.clone()),
            record.clone(),
        );
        Ok(())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<FederationTransactionRecord>> {
        let data = self.data.lock();
        Ok(data.values().cloned().collect())
    }
}
// G3.S0 — in-memory outbound federation HTTP delivery queue.
// Keyed by `id` (the row PK) with a secondary `(peer_did,
// idempotency_key)` uniqueness guard implemented at insert time so the
// Memory backend matches the Pg `federation_outbox_peer_idem` UNIQUE
// INDEX semantics.
pub(crate) struct MemoryFederationOutboxStore {
    data: Arc<Mutex<BTreeMap<String, FederationOutboxRecord>>>,
    dead_letters: Arc<Mutex<BTreeMap<String, FederationOutboxDeadLetterRecord>>>,
}
impl MemoryFederationOutboxStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
            dead_letters: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}
#[async_trait]
impl FederationOutboxStore for MemoryFederationOutboxStore {
    async fn enqueue(&self, record: &FederationOutboxRecord) -> PersistenceResult<bool> {
        let mut data = self.data.lock();
        // Match the Pg `(peer_did, idempotency_key)` UNIQUE INDEX —
        // duplicate enqueue returns Ok(false) so re-broadcast on
        // restart is structurally idempotent.
        let already_present = data.values().any(|existing| {
            existing.peer_did == record.peer_did
                && existing.idempotency_key == record.idempotency_key
        });
        if already_present {
            return Ok(false);
        }
        data.insert(record.id.clone(), record.clone());
        Ok(true)
    }

    async fn pending_due(
        &self,
        now_unix_secs: i64,
        limit: usize,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>> {
        let data = self.data.lock();
        let mut rows: Vec<FederationOutboxRecord> = data
            .values()
            .filter(|row| row.delivered_at.is_none() && row.next_attempt_at <= now_unix_secs)
            .cloned()
            .collect();
        rows.sort_by_key(|a| a.next_attempt_at);
        rows.truncate(limit);
        Ok(rows)
    }

    async fn update(&self, record: &FederationOutboxRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn get(&self, id: &str) -> PersistenceResult<Option<FederationOutboxRecord>> {
        let data = self.data.lock();
        Ok(data.get(id).cloned())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<FederationOutboxRecord>> {
        let data = self.data.lock();
        Ok(data.values().cloned().collect())
    }

    async fn insert_dead_letter(
        &self,
        record: &FederationOutboxDeadLetterRecord,
    ) -> PersistenceResult<()> {
        let mut dead_letters = self.dead_letters.lock();
        dead_letters.insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn dead_letters_snapshot(
        &self,
    ) -> PersistenceResult<Vec<FederationOutboxDeadLetterRecord>> {
        let dead_letters = self.dead_letters.lock();
        Ok(dead_letters.values().cloned().collect())
    }
}
// ── New in-memory sub-stores ────────────────────────────────────────────────
//
// The structs below back every former `Arc<Mutex<...>>` field on `AppState`.
// The trait shape is the architectural contract; the Pg-backed
// implementations land in T0-3.

pub(crate) struct MemoryFederationFrontierExchangeStore {
    data: Arc<Mutex<BTreeMap<(String, String), FederationFrontierExchangeRecord>>>,
}
impl MemoryFederationFrontierExchangeStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}
#[async_trait]
impl FederationFrontierExchangeStore for MemoryFederationFrontierExchangeStore {
    async fn get(
        &self,
        realm_id: &str,
        peer_service_id: &str,
    ) -> PersistenceResult<Option<FederationFrontierExchangeRecord>> {
        let data = self.data.lock();
        Ok(data
            .get(&(realm_id.to_owned(), peer_service_id.to_owned()))
            .cloned())
    }

    async fn record_success(
        &self,
        realm_id: &str,
        peer_service_id: &str,
        frontier_root: &str,
        observed_at: i64,
    ) -> PersistenceResult<FederationFrontierExchangeRecord> {
        let mut data = self.data.lock();
        let key = (realm_id.to_owned(), peer_service_id.to_owned());
        let record = frontier_exchange_success_record(
            data.get(&key).cloned(),
            realm_id,
            peer_service_id,
            frontier_root,
            observed_at,
        );
        data.insert(key, record.clone());
        Ok(record)
    }

    async fn record_failure(
        &self,
        realm_id: &str,
        peer_service_id: &str,
        reason: &str,
        observed_at: i64,
    ) -> PersistenceResult<FederationFrontierExchangeRecord> {
        let mut data = self.data.lock();
        let key = (realm_id.to_owned(), peer_service_id.to_owned());
        let record = frontier_exchange_failure_record(
            data.get(&key).cloned(),
            realm_id,
            peer_service_id,
            reason,
            observed_at,
        );
        data.insert(key, record.clone());
        Ok(record)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<FederationFrontierExchangeRecord>> {
        let data = self.data.lock();
        Ok(data.values().cloned().collect())
    }
}
#[derive(Default)]
pub(crate) struct MemoryFederationOperationsStore {
    data: Mutex<Vec<Operation>>,
}
impl MemoryFederationOperationsStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl FederationOperationsStore for MemoryFederationOperationsStore {
    async fn append(&self, operation: Operation) -> PersistenceResult<()> {
        self.data.lock().push(operation);
        Ok(())
    }

    async fn contains(&self, operation_id: &str) -> PersistenceResult<bool> {
        Ok(self
            .data
            .lock()
            .iter()
            .any(|known| known.operation_id.as_str() == operation_id))
    }

    async fn list_for_realm(&self, realm_id: &str) -> PersistenceResult<Vec<Operation>> {
        Ok(self
            .data
            .lock()
            .iter()
            .filter(|operation| operation.realm_id.as_str() == realm_id)
            .cloned()
            .collect())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Operation>> {
        Ok(self.data.lock().clone())
    }
}
