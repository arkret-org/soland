use super::{
    BTreeMap, KeyBackupDeleteChallengeRecord, KeyBackupStore, Mutex, PersistenceResult, Utc, Value,
    async_trait,
};
#[derive(Default)]
pub(crate) struct MemoryKeyBackupStore {
    backups: Mutex<BTreeMap<String, Value>>,
    delete_challenges: Mutex<BTreeMap<String, KeyBackupDeleteChallengeRecord>>,
}
impl MemoryKeyBackupStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl KeyBackupStore for MemoryKeyBackupStore {
    async fn put(&self, backup_id: String, payload: Value) -> PersistenceResult<()> {
        self.backups.lock().insert(backup_id, payload);
        Ok(())
    }

    async fn get(&self, backup_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self.backups.lock().get(backup_id).cloned())
    }

    async fn delete(&self, backup_id: &str) -> PersistenceResult<bool> {
        Ok(self.backups.lock().remove(backup_id).is_some())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.backups.lock().values().cloned().collect())
    }

    async fn list_for_actor(&self, actor_id: &str) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .backups
            .lock()
            .values()
            .filter(|backup| {
                backup
                    .get("actor_id")
                    .cloned()
                    .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value).ok())
                    .is_some_and(|owner| owner.to_string() == actor_id)
            })
            .cloned()
            .collect())
    }

    async fn issue_delete_challenge(
        &self,
        record: KeyBackupDeleteChallengeRecord,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<KeyBackupDeleteChallengeRecord> {
        let mut challenges = self.delete_challenges.lock();
        if let Some(existing) = challenges.values().find(|held| {
            held.principal_id == record.principal_id
                && held.backup_id == record.backup_id
                && held.request_id == record.request_id
                && held.consumed_at.is_none()
                && held.expires_at > now
        }) {
            return Ok(existing.clone());
        }
        // Drop any superseded row for the same triple so a stale challenge id
        // cannot be presented later.
        challenges.retain(|_, held| {
            !(held.principal_id == record.principal_id
                && held.backup_id == record.backup_id
                && held.request_id == record.request_id)
        });
        challenges.insert(record.challenge_id.clone(), record.clone());
        Ok(record)
    }

    async fn delete_challenge(
        &self,
        challenge_id: &str,
    ) -> PersistenceResult<Option<KeyBackupDeleteChallengeRecord>> {
        Ok(self.delete_challenges.lock().get(challenge_id).cloned())
    }

    async fn consume_delete_challenge(
        &self,
        challenge_id: &str,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<bool> {
        let mut challenges = self.delete_challenges.lock();
        let Some(held) = challenges.get_mut(challenge_id) else {
            return Ok(false);
        };
        if held.consumed_at.is_some() {
            return Ok(false);
        }
        held.consumed_at = Some(now);
        Ok(true)
    }

    async fn prune_expired_delete_challenges(
        &self,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<usize> {
        let mut challenges = self.delete_challenges.lock();
        let before = challenges.len();
        challenges.retain(|_, held| held.expires_at > now);
        Ok(before - challenges.len())
    }
}
