use super::*;
#[derive(Default)]
pub(crate) struct MemoryRealmInviteStore {
    data: Mutex<BTreeMap<String, RealmInviteRecord>>,
}
impl MemoryRealmInviteStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl RealmInviteStore for MemoryRealmInviteStore {
    async fn get(&self, invite_id: &str) -> PersistenceResult<Option<RealmInviteRecord>> {
        Ok(self.data.lock().get(invite_id).cloned())
    }

    async fn put(&self, record: RealmInviteRecord) -> PersistenceResult<()> {
        let id = record.invite_id.clone();
        self.data.lock().insert(id, record);
        Ok(())
    }

    async fn consume_third_party_token(
        &self,
        token_digest: &str,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<Option<RealmInviteRecord>> {
        let mut data = self.data.lock();
        let Some(record) = data
            .values_mut()
            .find(|record| record.third_party_id.is_some() && record.invite_token == token_digest)
        else {
            return Ok(None);
        };
        if record.status != "pending" {
            record.invite_token.clear();
            record.updated_at = Some(now);
            return Ok(None);
        }
        if record
            .expires_at
            .is_some_and(|expires_at| expires_at <= now)
        {
            record.status = "expired".to_owned();
            record.invite_token.clear();
            remove_third_party_active_material(&mut record.third_party_id, true);
            record.updated_at = Some(now);
            return Ok(None);
        }
        record.invite_token.clear();
        record.updated_at = Some(now);
        Ok(Some(record.clone()))
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<RealmInviteRecord>> {
        Ok(self.data.lock().values().cloned().collect())
    }
}
