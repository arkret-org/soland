use super::{
    Arc, BTreeMap, BTreeSet, CanonicalEventRecord, DeviceInventoryRecord, EventBatchReceipt,
    EventStore, IdentityAnchorCommitOutcome, IdentityAnchorFrontierCas, IdentityAnchorReanchorSlot,
    MessageRecord, MessageStore, Mutex, PeerEventsPageQuery, PersistenceError, PersistenceResult,
    RealmEventStats, async_trait, event_position_cmp, identity_anchor_slot_conflicts,
    peer_page_record_after_cursor, peer_page_record_matches, receipt_covers_event,
    record_is_peer_authz_state_record, stage_identity_anchor_events,
};
// In-memory message store
pub(crate) struct MemoryMessageStore {
    data: Arc<Mutex<Vec<MessageRecord>>>,
}
impl MemoryMessageStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(Vec::new())),
        }
    }
}
#[async_trait]
impl MessageStore for MemoryMessageStore {
    async fn get(&self, event_id: &str) -> PersistenceResult<Option<MessageRecord>> {
        let data = self.data.lock();
        Ok(data.iter().find(|m| m.event_id == event_id).cloned())
    }

    async fn put(&self, record: &MessageRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.push(record.clone());
        Ok(())
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<MessageRecord>> {
        let data = self.data.lock();
        let messages: Vec<_> = data
            .iter()
            .filter(|m| m.realm_id == realm_id)
            .rev()
            .take(limit)
            .cloned()
            .collect();
        Ok(messages)
    }

    async fn list_for_thread(
        &self,
        thread_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<MessageRecord>> {
        let data = self.data.lock();
        // Return in chronological order (oldest first) so thread readers get a
        // natural conversation timeline. The caller decides whether to reverse.
        let messages: Vec<_> = data
            .iter()
            .filter(|m| m.thread_id == thread_id)
            .take(limit)
            .cloned()
            .collect();
        Ok(messages)
    }

    async fn delete(&self, event_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.retain(|m| m.event_id != event_id);
        Ok(())
    }
}
pub(crate) struct MemoryEventStore {
    pub(crate) data: Mutex<BTreeMap<String, CanonicalEventRecord>>,
    devices: Arc<Mutex<BTreeMap<(String, String), DeviceInventoryRecord>>>,
    receipts: Mutex<BTreeMap<String, EventBatchReceipt>>,
}
impl MemoryEventStore {
    pub(crate) fn with_devices(
        devices: Arc<Mutex<BTreeMap<(String, String), DeviceInventoryRecord>>>,
    ) -> Self {
        Self {
            data: Mutex::new(BTreeMap::new()),
            devices,
            receipts: Mutex::new(BTreeMap::new()),
        }
    }
}
#[async_trait]
impl EventStore for MemoryEventStore {
    async fn put(&self, record: CanonicalEventRecord) -> PersistenceResult<()> {
        let id = record.event_id.clone();
        let mut data = self.data.lock();
        if record.kind == "ak.realm.create"
            && record.realm_id.is_some()
            && data.values().any(|existing| {
                existing.kind == "ak.realm.create" && existing.realm_id == record.realm_id
            })
        {
            return Err(PersistenceError::Conflict(
                "realm_already_exists".to_owned(),
            ));
        }
        data.insert(id, record);
        Ok(())
    }

    async fn put_identity_anchor_batch_atomic(
        &self,
        records: Vec<CanonicalEventRecord>,
        receipt: Option<EventBatchReceipt>,
        device: Option<DeviceInventoryRecord>,
        _frontier_cas: Option<IdentityAnchorFrontierCas>,
        reanchor_slot: Option<IdentityAnchorReanchorSlot>,
    ) -> PersistenceResult<IdentityAnchorCommitOutcome> {
        let mut data = self.data.lock();
        let mut devices = self.devices.lock();
        let mut receipts = self.receipts.lock();
        let mut staged_events = data.clone();
        let mut staged_devices = devices.clone();
        let mut staged_receipts = receipts.clone();
        let reanchor_conflict = reanchor_slot
            .as_ref()
            .is_some_and(|slot| identity_anchor_slot_conflicts(staged_events.values(), slot));
        stage_identity_anchor_events(&mut staged_events, records)?;
        if !reanchor_conflict && let Some(device) = device {
            staged_devices.insert((device.actor.clone(), device.device_id.clone()), device);
        }
        if !reanchor_conflict && let Some(receipt) = receipt {
            staged_receipts.insert(receipt.receipt_id.as_str().to_owned(), receipt);
        }
        *data = staged_events;
        *devices = staged_devices;
        *receipts = staged_receipts;
        Ok(IdentityAnchorCommitOutcome { reanchor_conflict })
    }

    async fn batch_receipts_for_event(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Vec<EventBatchReceipt>> {
        Ok(self
            .receipts
            .lock()
            .values()
            .filter(|receipt| receipt_covers_event(receipt, event_id))
            .cloned()
            .collect())
    }

    async fn get(&self, event_id: &str) -> PersistenceResult<Option<CanonicalEventRecord>> {
        Ok(self.data.lock().get(event_id).cloned())
    }

    async fn contains(&self, event_id: &str) -> PersistenceResult<bool> {
        Ok(self.data.lock().contains_key(event_id))
    }

    async fn max_actor_seq(&self, actor_id: &str) -> PersistenceResult<Option<u64>> {
        Ok(self
            .data
            .lock()
            .values()
            .filter(|record| record.actor_id == actor_id)
            .map(|record| record.actor_seq)
            .max())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        Ok(self.data.lock().values().cloned().collect())
    }

    async fn realm_event_stats(&self, realm_id: &str) -> PersistenceResult<RealmEventStats> {
        let data = self.data.lock();
        let mut stats = RealmEventStats::default();
        for record in data
            .values()
            .filter(|record| record.realm_id.as_deref() == Some(realm_id))
        {
            stats.count = stats.count.saturating_add(1);
            stats.canonical_bytes = stats
                .canonical_bytes
                .saturating_add(record.canonical_bytes.len() as u64);
        }
        Ok(stats)
    }

    async fn list_for_actor(&self, actor_id: &str) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let mut records = self
            .data
            .lock()
            .values()
            .filter(|record| record.actor_id == actor_id)
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by(event_position_cmp);
        Ok(records)
    }

    async fn peer_authz_state_records(&self) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let mut records = self
            .data
            .lock()
            .values()
            .filter(|record| record_is_peer_authz_state_record(record))
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by(event_position_cmp);
        Ok(records)
    }

    async fn peer_events_query_page(
        &self,
        query: &PeerEventsPageQuery,
    ) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let data = self.data.lock();
        let realms = query
            .realms
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let actors = query
            .actors
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let cursor = query
            .cursor_event_id
            .as_deref()
            .and_then(|event_id| data.get(event_id));
        if query.cursor_event_id.is_some() && cursor.is_none() {
            return Ok(Vec::new());
        }
        let mut records = data
            .values()
            .filter(|record| {
                peer_page_record_matches(record, &realms, &actors, query.kind_filter.as_deref())
                    && peer_page_record_after_cursor(record, cursor, query.backward)
            })
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by(event_position_cmp);
        if query.backward {
            records.reverse();
        }
        records.truncate(query.limit);
        Ok(records)
    }

    async fn realm_events_newest_first(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let mut events: Vec<CanonicalEventRecord> = self
            .data
            .lock()
            .values()
            .filter(|record| record.realm_id.as_deref() == Some(realm_id))
            .cloned()
            .collect();
        // Newest first: match the Pg `received_at DESC, id DESC` ordering.
        events.sort_by(|a, b| {
            b.received_at
                .cmp(&a.received_at)
                .then_with(|| b.event_id.cmp(&a.event_id))
        });
        Ok(events)
    }
}
