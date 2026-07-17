use super::{
    Arc, BTreeMap, CursorRevocation, Mutex, PersistenceResult, SyncCursorRecord, SyncCursorStore,
    Utc, async_trait,
};
/// In-memory `handle -> SyncCursorRecord` table. Mirrors the
/// `sync_cursor_handles` Pg table on the same primary key.
pub(crate) struct MemorySyncCursorStore {
    data: Arc<Mutex<BTreeMap<String, SyncCursorRecord>>>,
    revocations: Arc<Mutex<Vec<CursorRevocation>>>,
}
impl MemorySyncCursorStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
            revocations: Arc::new(Mutex::new(Vec::new())),
        }
    }
}
#[async_trait]
impl SyncCursorStore for MemorySyncCursorStore {
    async fn get(&self, handle: &str) -> PersistenceResult<Option<SyncCursorRecord>> {
        let data = self.data.lock();
        Ok(data.get(handle).cloned())
    }

    async fn upsert(&self, record: &SyncCursorRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        match data.get_mut(&record.handle) {
            // Dedup re-mint: refresh the expiry only; `issued_at_ms`
            // remains the pruning watermark for this handle (see trait doc).
            Some(existing) => existing.expires_at_ms = record.expires_at_ms,
            None => {
                data.insert(record.handle.clone(), record.clone());
            }
        }
        Ok(())
    }

    async fn delete(&self, handle: &str) -> PersistenceResult<bool> {
        let mut data = self.data.lock();
        Ok(data.remove(handle).is_some())
    }

    async fn prune_stream_superseded(
        &self,
        principal_id: &str,
        device_id: &str,
        filter_digest: &str,
        presented_issued_at_ms: i64,
    ) -> PersistenceResult<usize> {
        let mut data = self.data.lock();
        let before = data.len();
        data.retain(|_, record| {
            !(record.purpose == "stream"
                && record.principal_id.as_deref() == Some(principal_id)
                && record.device_id.as_deref() == Some(device_id)
                && record.filter_digest.as_deref() == Some(filter_digest)
                && record.issued_at_ms < presented_issued_at_ms)
        });
        Ok(before - data.len())
    }

    async fn prune_expired(&self, now_ms: i64) -> PersistenceResult<usize> {
        let mut data = self.data.lock();
        let before = data.len();
        data.retain(|_, record| record.expires_at_ms > now_ms);
        Ok(before - data.len())
    }

    async fn record_revocation(&self, record: &CursorRevocation) -> PersistenceResult<()> {
        let mut revocations = self.revocations.lock();
        revocations.retain(|entry| entry.expires_at > record.revoked_at);
        revocations.push(record.clone());
        Ok(())
    }

    async fn active_revocations(
        &self,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<Vec<CursorRevocation>> {
        let revocations = self.revocations.lock();
        Ok(revocations
            .iter()
            .filter(|entry| entry.expires_at > now)
            .cloned()
            .collect())
    }
}
