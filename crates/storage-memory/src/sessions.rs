use super::*;
// In-memory session store
pub(crate) struct MemorySessionStore {
    data: Arc<Mutex<BTreeMap<String, SessionRecord>>>,
}
impl MemorySessionStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}
#[async_trait]
impl SessionStore for MemorySessionStore {
    async fn get(&self, token: &str) -> PersistenceResult<Option<SessionRecord>> {
        let data = self.data.lock();
        Ok(data.get(token).cloned())
    }

    async fn put(&self, record: &SessionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.insert(record.token_hash.clone(), record.clone());
        Ok(())
    }

    async fn delete(&self, token: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.remove(token);
        Ok(())
    }

    async fn cleanup_expired(&self) -> PersistenceResult<usize> {
        let mut data = self.data.lock();
        let now = Utc::now();
        let before = data.len();
        data.retain(|_, session| session.expires_at > now);
        Ok(before - data.len())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<SessionRecord>> {
        Ok(self.data.lock().values().cloned().collect())
    }
}
