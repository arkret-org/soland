use super::*;
#[derive(Default)]
pub(crate) struct MemoryReadReceiptRelayStore {
    data: Mutex<BTreeMap<String, Vec<ReadReceiptRelayRecord>>>,
    next_position: Mutex<BTreeMap<String, u64>>,
    watermark: Mutex<BTreeMap<(String, String, String), u64>>,
}
impl MemoryReadReceiptRelayStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl ReadReceiptRelayStore for MemoryReadReceiptRelayStore {
    async fn append(&self, mut record: ReadReceiptRelayRecord) -> PersistenceResult<()> {
        let now = Utc::now();
        let realm_id = record.realm_id.clone();
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
        if bucket.len() > READ_RECEIPT_RELAY_MAX_PER_REALM {
            let overflow = bucket.len() - READ_RECEIPT_RELAY_MAX_PER_REALM;
            bucket.drain(0..overflow);
        }
        Ok(())
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<ReadReceiptRelayRecord>> {
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

    async fn list_for_event(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Vec<ReadReceiptRelayRecord>> {
        let now = Utc::now();
        Ok(self
            .data
            .lock()
            .values()
            .flat_map(|bucket| bucket.iter())
            .filter(|record| record.event_id == event_id && record.expires_at > now)
            .cloned()
            .collect())
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
