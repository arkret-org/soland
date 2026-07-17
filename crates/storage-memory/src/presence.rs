use super::*;
#[derive(Default)]
pub(crate) struct MemoryPresenceStore {
    data: Mutex<BTreeMap<(String, String), PresenceRecord>>,
}
impl MemoryPresenceStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl PresenceStore for MemoryPresenceStore {
    async fn put(&self, presence: PresenceRecord) -> PersistenceResult<()> {
        let key = (presence.actor.clone(), presence.device_id.clone());
        self.data.lock().insert(key, presence);
        Ok(())
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<PresenceRecord>> {
        Ok(self
            .data
            .lock()
            .values()
            .filter(|record| record.actor == actor)
            .cloned()
            .collect())
    }

    async fn delete(&self, actor: &str) -> PersistenceResult<()> {
        self.data
            .lock()
            .retain(|(record_actor, _), _| record_actor != actor);
        Ok(())
    }
}
#[derive(Default)]
pub(crate) struct MemoryTypingStore {
    data: Mutex<BTreeMap<(String, String), TypingRecord>>,
}
impl MemoryTypingStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl TypingStore for MemoryTypingStore {
    async fn put(&self, typing: TypingRecord) -> PersistenceResult<()> {
        let key = (typing.actor.clone(), typing.realm_id.clone());
        self.data.lock().insert(key, typing);
        Ok(())
    }

    async fn remove(&self, actor: &str, realm_id: &str) -> PersistenceResult<()> {
        self.data
            .lock()
            .remove(&(actor.to_owned(), realm_id.to_owned()));
        Ok(())
    }

    async fn list_for_realm(&self, realm_id: &str) -> PersistenceResult<Vec<TypingRecord>> {
        let now = Utc::now();
        Ok(self
            .data
            .lock()
            .values()
            .filter(|record| record.realm_id == realm_id && record.expires_at > now)
            .cloned()
            .collect())
    }

    async fn prune_expired(&self) -> PersistenceResult<usize> {
        let now = Utc::now();
        let mut data = self.data.lock();
        let before = data.len();
        data.retain(|_, record| record.expires_at > now);
        Ok(before - data.len())
    }
}
#[derive(Default)]
pub(crate) struct MemoryCallSignalRelayStore {
    data: Mutex<BTreeMap<String, Vec<CallSignalRelayRecord>>>,
    /// Monotonic per-Realm position counter. Never resets (even when the bucket
    /// is fully pruned) so positions stay strictly increasing for the lifetime
    /// of the process and a watermark can never be re-crossed by a recycled id.
    next_position: Mutex<BTreeMap<String, u64>>,
    /// Per-subscriber-device deliver-once watermark keyed by `(actor, device,
    /// realm_id)`: the highest per-Realm `position` already delivered to that
    /// device.
    watermark: Mutex<BTreeMap<(String, String, String), u64>>,
}
impl MemoryCallSignalRelayStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl CallSignalRelayStore for MemoryCallSignalRelayStore {
    async fn append(&self, mut record: CallSignalRelayRecord) -> PersistenceResult<()> {
        let now = Utc::now();
        let realm_id = record.realm_id.clone();
        // Assign the monotonic per-Realm position before storing so every
        // delivered record carries a stable deliver-once key.
        let position = {
            let mut counters = self.next_position.lock();
            let counter = counters.entry(realm_id.clone()).or_insert(0);
            *counter += 1;
            *counter
        };
        record.position = position;
        let mut data = self.data.lock();
        let bucket = data.entry(realm_id).or_default();
        bucket.retain(|existing| existing.expires_at > now);
        bucket.push(record);
        if bucket.len() > CALL_SIGNAL_RELAY_MAX_PER_REALM {
            let overflow = bucket.len() - CALL_SIGNAL_RELAY_MAX_PER_REALM;
            bucket.drain(0..overflow);
        }
        Ok(())
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<CallSignalRelayRecord>> {
        let now = Utc::now();
        Ok(self
            .data
            .lock()
            .get(realm_id)
            .map(|bucket| {
                bucket
                    .iter()
                    .filter(|record| record.expires_at > now)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn prune_expired(&self) -> PersistenceResult<usize> {
        let now = Utc::now();
        let mut data = self.data.lock();
        let mut removed = 0usize;
        for bucket in data.values_mut() {
            let before = bucket.len();
            bucket.retain(|record| record.expires_at > now);
            removed += before - bucket.len();
        }
        data.retain(|_, bucket| !bucket.is_empty());
        Ok(removed)
    }

    async fn delivered_through(
        &self,
        actor: &str,
        device: &str,
        realm_id: &str,
    ) -> PersistenceResult<u64> {
        let key = (actor.to_owned(), device.to_owned(), realm_id.to_owned());
        Ok(self.watermark.lock().get(&key).copied().unwrap_or(0))
    }

    async fn advance(
        &self,
        actor: &str,
        device: &str,
        realm_id: &str,
        position: u64,
    ) -> PersistenceResult<()> {
        let key = (actor.to_owned(), device.to_owned(), realm_id.to_owned());
        let mut watermark = self.watermark.lock();
        let entry = watermark.entry(key).or_insert(0);
        if position > *entry {
            *entry = position;
        }
        Ok(())
    }
}
