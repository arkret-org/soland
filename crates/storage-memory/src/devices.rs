use super::{
    Arc, BTreeMap, DeviceInventoryRecord, DeviceInventoryStore, DeviceKeyStore,
    DeviceMessageAckTokenRecord, DeviceMessageBatchCommitOutcome, DeviceMessageBatchInspection,
    DeviceMessageBatchRecord, DeviceMessageIntentRecord, DeviceMessageRecord, DeviceMessageStore,
    Mutex, OneTimeKeyStore, PersistenceResult, Utc, Value, VecDeque, async_trait,
    cross_signing_reset_blocks_queued_message, device_message_expires_at, ensure_device_message_id,
    fresh_device_message_ack_token,
};
// In-memory device inventory store
pub(crate) struct MemoryDeviceInventoryStore {
    data: Arc<Mutex<BTreeMap<(String, String), DeviceInventoryRecord>>>,
}
impl MemoryDeviceInventoryStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub(crate) fn shared_data(
        &self,
    ) -> Arc<Mutex<BTreeMap<(String, String), DeviceInventoryRecord>>> {
        self.data.clone()
    }
}
#[async_trait]
impl DeviceInventoryStore for MemoryDeviceInventoryStore {
    async fn get(
        &self,
        actor: &str,
        device_id: &str,
    ) -> PersistenceResult<Option<DeviceInventoryRecord>> {
        let data = self.data.lock();
        Ok(data.get(&(actor.to_owned(), device_id.to_owned())).cloned())
    }

    async fn put(&self, record: &DeviceInventoryRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.insert(
            (record.actor.clone(), record.device_id.clone()),
            record.clone(),
        );
        Ok(())
    }

    async fn put_if_absent(&self, record: &DeviceInventoryRecord) -> PersistenceResult<bool> {
        let mut data = self.data.lock();
        let key = (record.actor.clone(), record.device_id.clone());
        if data.contains_key(&key) {
            return Ok(false);
        }
        data.insert(key, record.clone());
        Ok(true)
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
        let data = self.data.lock();
        Ok(data
            .values()
            .filter(|record| record.actor == actor && record.revoked_at.is_none())
            .cloned()
            .collect())
    }

    async fn list_for_actor_including_revoked(
        &self,
        actor: &str,
    ) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
        let data = self.data.lock();
        Ok(data
            .values()
            .filter(|record| record.actor == actor)
            .cloned()
            .collect())
    }

    async fn list(&self) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
        let data = self.data.lock();
        Ok(data
            .values()
            .filter(|record| record.revoked_at.is_none())
            .cloned()
            .collect())
    }
}
type DeviceMessageTransaction = (String, BTreeMap<String, bool>, chrono::DateTime<Utc>);
type DeviceMessageIntent = (String, bool, chrono::DateTime<Utc>);

#[derive(Default)]
pub(crate) struct MemoryDeviceMessageStore {
    queue: Mutex<VecDeque<DeviceMessageRecord>>,
    txns: Mutex<BTreeMap<String, DeviceMessageTransaction>>,
    message_intents: Mutex<BTreeMap<String, DeviceMessageIntent>>,
    ack_tokens: Mutex<BTreeMap<String, DeviceMessageAckTokenRecord>>,
    lost_watermarks: Mutex<BTreeMap<(String, String), i64>>,
}
impl MemoryDeviceMessageStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl DeviceMessageStore for MemoryDeviceMessageStore {
    async fn append(&self, mut message: DeviceMessageRecord) -> PersistenceResult<()> {
        ensure_device_message_id(&mut message);
        self.queue.lock().push_back(message);
        Ok(())
    }

    async fn inspect_batch(
        &self,
        request_key: &str,
        request_digest: &str,
        items: &[DeviceMessageIntentRecord],
    ) -> PersistenceResult<DeviceMessageBatchInspection> {
        let now = Utc::now();
        let mut txns = self.txns.lock();
        let mut intents = self.message_intents.lock();
        txns.retain(|_, (_, _, expires_at)| *expires_at > now);
        intents.retain(|_, (_, _, expires_at)| *expires_at > now);
        if let Some((digest, outcome, _)) = txns.get(request_key) {
            return if digest == request_digest {
                Ok(DeviceMessageBatchInspection::Duplicate(outcome.clone()))
            } else {
                Ok(DeviceMessageBatchInspection::RequestConflict)
            };
        }
        let mut batch_digests = BTreeMap::new();
        let mut existing_message_outcomes = BTreeMap::new();
        for item in items {
            if let Some(digest) =
                batch_digests.insert(item.message_key.clone(), item.intent_digest.clone())
                && digest != item.intent_digest
            {
                return Ok(DeviceMessageBatchInspection::MessageConflict {
                    message_key: item.message_key.clone(),
                });
            }
            if let Some((digest, delivered, _)) = intents.get(&item.message_key) {
                if digest != &item.intent_digest {
                    return Ok(DeviceMessageBatchInspection::MessageConflict {
                        message_key: item.message_key.clone(),
                    });
                }
                existing_message_outcomes.insert(item.message_key.clone(), *delivered);
            }
        }
        Ok(DeviceMessageBatchInspection::Fresh {
            existing_message_outcomes,
        })
    }

    async fn commit_batch(
        &self,
        mut batch: DeviceMessageBatchRecord,
    ) -> PersistenceResult<DeviceMessageBatchCommitOutcome> {
        let now = Utc::now();
        let mut txns = self.txns.lock();
        let mut intents = self.message_intents.lock();
        txns.retain(|_, (_, _, expires_at)| *expires_at > now);
        intents.retain(|_, (_, _, expires_at)| *expires_at > now);

        if let Some((digest, outcome, _)) = txns.get(&batch.request_key) {
            return if digest == &batch.request_digest {
                Ok(DeviceMessageBatchCommitOutcome::Duplicate(outcome.clone()))
            } else {
                Ok(DeviceMessageBatchCommitOutcome::RequestConflict)
            };
        }
        let mut batch_digests = BTreeMap::new();
        for item in &batch.items {
            if let Some(digest) =
                batch_digests.insert(item.message_key.clone(), item.intent_digest.clone())
                && digest != item.intent_digest
            {
                return Ok(DeviceMessageBatchCommitOutcome::MessageConflict {
                    message_key: item.message_key.clone(),
                });
            }
            if let Some((digest, ..)) = intents.get(&item.message_key)
                && digest != &item.intent_digest
            {
                return Ok(DeviceMessageBatchCommitOutcome::MessageConflict {
                    message_key: item.message_key.clone(),
                });
            }
        }

        let mut queue = self.queue.lock();
        let mut outcomes = BTreeMap::new();
        for item in &mut batch.items {
            if let Some((_, delivered, _)) = intents.get(&item.message_key) {
                outcomes.insert(item.message_key.clone(), *delivered);
                continue;
            }
            let delivered = item.message.is_some();
            intents.insert(
                item.message_key.clone(),
                (
                    item.intent_digest.clone(),
                    delivered,
                    item.idempotency_expires_at,
                ),
            );
            outcomes.insert(item.message_key.clone(), delivered);
            if let Some(message) = item.message.as_mut() {
                ensure_device_message_id(message);
                queue.push_back(message.clone());
            }
        }
        txns.insert(
            batch.request_key,
            (
                batch.request_digest,
                outcomes.clone(),
                batch.idempotency_expires_at,
            ),
        );
        Ok(DeviceMessageBatchCommitOutcome::Stored(outcomes))
    }

    async fn issue_ack_token(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
    ) -> PersistenceResult<Option<String>> {
        if queue_position <= 0 {
            return Ok(None);
        }
        let now = Utc::now();
        let token = fresh_device_message_ack_token();
        let mut tokens = self.ack_tokens.lock();
        tokens.retain(|_, record| record.expires_at > now);
        tokens.insert(
            token.clone(),
            DeviceMessageAckTokenRecord {
                recipient: recipient.to_owned(),
                device_id: device_id.to_owned(),
                queue_position,
                expires_at: now + chrono::Duration::hours(24),
                consumed_at: None,
            },
        );
        Ok(Some(token))
    }

    async fn ack_with_token(
        &self,
        recipient: &str,
        device_id: &str,
        ack_token: &str,
    ) -> PersistenceResult<Option<usize>> {
        let now = Utc::now();
        let mut tokens = self.ack_tokens.lock();
        tokens.retain(|_, record| record.expires_at > now);
        let Some(record) = tokens.get_mut(ack_token) else {
            return Ok(None);
        };
        if record.recipient != recipient || record.device_id != device_id {
            return Ok(None);
        }
        if record.consumed_at.is_some() {
            return Ok(Some(0));
        }
        let ack_position = record.queue_position;
        let mut queue = self.queue.lock();
        let before = queue.len();
        queue.retain(|message| {
            !(message.recipient == recipient
                && message.device_id == device_id
                && message.position <= ack_position)
        });
        record.consumed_at = Some(now);
        Ok(Some(before - queue.len()))
    }

    async fn list_after(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
    ) -> PersistenceResult<Vec<DeviceMessageRecord>> {
        Ok(self
            .queue
            .lock()
            .iter()
            .filter(|message| {
                message.recipient == recipient
                    && message.device_id == device_id
                    && message.position > queue_position
            })
            .cloned()
            .collect())
    }

    async fn prune_expired(&self, now: chrono::DateTime<Utc>) -> PersistenceResult<usize> {
        let mut queue = self.queue.lock();
        let before = queue.len();
        let mut watermarks = self.lost_watermarks.lock();
        for message in queue.iter() {
            if device_message_expires_at(message) <= now {
                let key = (message.recipient.clone(), message.device_id.clone());
                let entry = watermarks.entry(key).or_default();
                *entry = (*entry).max(message.position);
            }
        }
        queue.retain(|message| device_message_expires_at(message) > now);
        Ok(before - queue.len())
    }

    async fn prune_over_capacity(
        &self,
        per_device_capacity: usize,
        _now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<usize> {
        if per_device_capacity == 0 {
            return Ok(0);
        }
        let mut queue = self.queue.lock();
        let before = queue.len();
        let mut positions_by_device: BTreeMap<(String, String), Vec<i64>> = BTreeMap::new();
        for message in queue.iter() {
            positions_by_device
                .entry((message.recipient.clone(), message.device_id.clone()))
                .or_default()
                .push(message.position);
        }
        let mut lost_through_by_device = BTreeMap::new();
        for (key, positions) in &mut positions_by_device {
            positions.sort_unstable();
            if positions.len() > per_device_capacity {
                let dropped_count = positions.len() - per_device_capacity;
                if let Some(lost_through) = positions.get(dropped_count - 1).copied() {
                    lost_through_by_device.insert(key.clone(), lost_through);
                }
            }
        }
        if lost_through_by_device.is_empty() {
            return Ok(0);
        }
        {
            let mut watermarks = self.lost_watermarks.lock();
            for (key, lost_through) in &lost_through_by_device {
                let entry = watermarks.entry(key.clone()).or_default();
                *entry = (*entry).max(*lost_through);
            }
        }
        queue.retain(|message| {
            lost_through_by_device
                .get(&(message.recipient.clone(), message.device_id.clone()))
                .is_none_or(|lost_through| message.position > *lost_through)
        });
        Ok(before - queue.len())
    }

    async fn lost_watermark(
        &self,
        recipient: &str,
        device_id: &str,
    ) -> PersistenceResult<Option<i64>> {
        Ok(self
            .lost_watermarks
            .lock()
            .get(&(recipient.to_owned(), device_id.to_owned()))
            .copied())
    }

    async fn purge(&self, recipient: &str, device_id: &str) -> PersistenceResult<usize> {
        let mut queue = self.queue.lock();
        let before = queue.len();
        queue.retain(|message| !(message.recipient == recipient && message.device_id == device_id));
        self.ack_tokens
            .lock()
            .retain(|_, token| !(token.recipient == recipient && token.device_id == device_id));
        Ok(before - queue.len())
    }

    async fn purge_cross_signing_reset_stale_messages(
        &self,
        recipient: &str,
        new_generation: u64,
    ) -> PersistenceResult<usize> {
        let mut queue = self.queue.lock();
        let before = queue.len();
        let mut lost_by_device: BTreeMap<String, i64> = BTreeMap::new();
        for message in queue.iter().filter(|message| {
            message.recipient == recipient
                && cross_signing_reset_blocks_queued_message(&message.content, new_generation)
        }) {
            let entry = lost_by_device.entry(message.device_id.clone()).or_default();
            *entry = (*entry).max(message.position);
        }
        if lost_by_device.is_empty() {
            return Ok(0);
        }
        {
            let mut watermarks = self.lost_watermarks.lock();
            for (device_id, lost_through) in &lost_by_device {
                let key = (recipient.to_owned(), device_id.clone());
                let entry = watermarks.entry(key).or_default();
                *entry = (*entry).max(*lost_through);
            }
        }
        queue.retain(|message| {
            !(message.recipient == recipient
                && cross_signing_reset_blocks_queued_message(&message.content, new_generation))
        });
        self.ack_tokens
            .lock()
            .retain(|_, token| token.recipient != recipient);
        Ok(before - queue.len())
    }
}
#[derive(Default)]
pub(crate) struct MemoryDeviceKeyStore {
    data: Mutex<BTreeMap<(String, String), Value>>,
}
impl MemoryDeviceKeyStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl DeviceKeyStore for MemoryDeviceKeyStore {
    async fn put(&self, actor: String, device_id: String, payload: Value) -> PersistenceResult<()> {
        self.data.lock().insert((actor, device_id), payload);
        Ok(())
    }

    async fn get(&self, actor: &str, device_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self
            .data
            .lock()
            .get(&(actor.to_owned(), device_id.to_owned()))
            .cloned())
    }
}
#[derive(Default)]
pub(crate) struct MemoryOneTimeKeyStore {
    data: Mutex<BTreeMap<(String, String), Vec<Value>>>,
}
impl MemoryOneTimeKeyStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl OneTimeKeyStore for MemoryOneTimeKeyStore {
    async fn put(
        &self,
        actor: String,
        device_id: String,
        keys: Vec<Value>,
    ) -> PersistenceResult<()> {
        self.data.lock().insert((actor, device_id), keys);
        Ok(())
    }

    async fn claim(&self, actor: &str, device_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self
            .data
            .lock()
            .get_mut(&(actor.to_owned(), device_id.to_owned()))
            .and_then(|pool| pool.pop()))
    }
}
