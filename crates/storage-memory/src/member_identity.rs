use super::{
    Arc, BTreeMap, HandleClaimEvidenceRecord, MemberIdentityEventRecord, MemberIdentityStore,
    Mutex, PersistenceResult, async_trait,
};

/// In-memory member-identity registry store retained for tests. Runtime
/// durability lives in `PgMemberIdentityStore`.
pub(crate) struct MemoryMemberIdentityStore {
    events: Arc<Mutex<BTreeMap<String, MemberIdentityEventRecord>>>,
    handle_claims: Arc<Mutex<BTreeMap<(String, String), HandleClaimEvidenceRecord>>>,
}

impl MemoryMemberIdentityStore {
    pub(crate) fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(BTreeMap::new())),
            handle_claims: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl MemberIdentityStore for MemoryMemberIdentityStore {
    async fn put_event(&self, record: &MemberIdentityEventRecord) -> PersistenceResult<()> {
        self.events
            .lock()
            .insert(record.event_id.clone(), record.clone());
        Ok(())
    }

    async fn snapshot_events(&self) -> PersistenceResult<Vec<MemberIdentityEventRecord>> {
        Ok(self.events.lock().values().cloned().collect())
    }

    async fn put_handle_claim(&self, record: &HandleClaimEvidenceRecord) -> PersistenceResult<()> {
        self.handle_claims.lock().insert(
            (record.subject_id.clone(), record.digest.clone()),
            record.clone(),
        );
        Ok(())
    }

    async fn delete_handle_claims_for_subject(&self, subject_id: &str) -> PersistenceResult<usize> {
        let mut claims = self.handle_claims.lock();
        let before = claims.len();
        claims.retain(|(subject, _), _| subject != subject_id);
        Ok(before - claims.len())
    }

    async fn snapshot_handle_claims(&self) -> PersistenceResult<Vec<HandleClaimEvidenceRecord>> {
        Ok(self.handle_claims.lock().values().cloned().collect())
    }
}
