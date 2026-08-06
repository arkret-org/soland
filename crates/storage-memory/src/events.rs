use super::{
    Arc, BTreeMap, BTreeSet, CanonicalEventRecord, DeviceInventoryRecord, EventBatchReceipt,
    EventStore, FederationOutboxRecord, IdentityAnchorCommitOutcome, IdentityAnchorFrontierCas,
    IdentityAnchorReanchorSlot, MessageRecord, MessageStore, Mutex, PeerEventsPageQuery,
    PersistenceError, PersistenceResult, PublicationEvidenceRecord, RealmEventStats, async_trait,
    event_position_cmp, identity_anchor_slot_conflicts, peer_page_record_after_cursor,
    peer_page_record_matches, receipt_covers_event, record_is_peer_authz_state_record,
    stage_identity_anchor_events,
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
    pub(crate) control_proposal_acks:
        Mutex<BTreeMap<String, arkret_wire::ControlProposalAck>>,
    devices: Arc<Mutex<BTreeMap<(String, String), DeviceInventoryRecord>>>,
    receipts: Mutex<BTreeMap<String, EventBatchReceipt>>,
    publication_evidence: Arc<Mutex<BTreeMap<String, PublicationEvidenceRecord>>>,
    /// Shared with `MemoryFederationOutboxStore` so the atomic Event batches
    /// commit their delivery intents in the same staged mutation as the Events,
    /// mirroring the single PostgreSQL transaction.
    federation_outbox: Arc<Mutex<BTreeMap<String, FederationOutboxRecord>>>,
}
impl MemoryEventStore {
    pub(crate) fn with_devices(
        devices: Arc<Mutex<BTreeMap<(String, String), DeviceInventoryRecord>>>,
        publication_evidence: Arc<Mutex<BTreeMap<String, PublicationEvidenceRecord>>>,
        federation_outbox: Arc<Mutex<BTreeMap<String, FederationOutboxRecord>>>,
    ) -> Self {
        Self {
            data: Mutex::new(BTreeMap::new()),
            control_proposal_acks: Mutex::new(BTreeMap::new()),
            devices,
            receipts: Mutex::new(BTreeMap::new()),
            publication_evidence,
            federation_outbox,
        }
    }
}

/// Stage outbox rows with exactly the uniqueness PostgreSQL enforces:
/// `(peer_id, idempotency_key)` is `ON CONFLICT DO NOTHING` — a retried
/// admission collapses onto the existing intent — while a colliding primary key
/// is a hard conflict that aborts the whole batch.
fn stage_federation_outbox(
    staged: &mut BTreeMap<String, FederationOutboxRecord>,
    outbox: Vec<FederationOutboxRecord>,
) -> PersistenceResult<()> {
    for record in outbox {
        let already_enqueued = staged.values().any(|existing| {
            existing.peer_did == record.peer_did
                && existing.idempotency_key == record.idempotency_key
        });
        if already_enqueued {
            continue;
        }
        if staged.contains_key(&record.id) {
            return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()));
        }
        staged.insert(record.id.clone(), record);
    }
    Ok(())
}

fn stage_control_proposal_acks(
    staged: &mut BTreeMap<String, arkret_wire::ControlProposalAck>,
    records: &[CanonicalEventRecord],
    control_proposal_acks: Vec<arkret_wire::ControlProposalAck>,
    receipts_required: bool,
) -> PersistenceResult<()> {
    if control_proposal_acks.is_empty() && !receipts_required {
        return Ok(());
    }
    if control_proposal_acks.len() != records.len() {
        return Err(PersistenceError::Conflict(
            "schema_violation: Control Proposal Ack cardinality mismatch".to_owned(),
        ));
    }
    let mut by_digest = BTreeMap::new();
    for receipt in control_proposal_acks {
        receipt.validate_protocol_bounds().map_err(|error| {
            PersistenceError::Conflict(format!(
                "schema_violation: invalid Control Proposal Ack: {error}"
            ))
        })?;
        if by_digest
            .insert(receipt.proposal_digest.as_str().to_owned(), receipt)
            .is_some()
        {
            return Err(PersistenceError::Conflict(
                "schema_violation: duplicate Control Proposal Ack".to_owned(),
            ));
        }
    }
    for record in records {
        let receipt = by_digest.get(&record.canonical_digest).ok_or_else(|| {
            PersistenceError::Conflict(
                "schema_violation: accepted Control Move is missing Control Proposal Ack".to_owned(),
            )
        })?;
        if record.realm_id.as_deref() != Some(receipt.realm_id.as_str()) {
            return Err(PersistenceError::Conflict(
                "schema_violation: Control Proposal Ack does not bind Control Move".to_owned(),
            ));
        }
        if let Some(existing) = staged.get(&record.event_id)
            && existing != receipt
        {
            return Err(PersistenceError::Conflict(
                "duplicate_conflict: Control Move has a different Control Proposal Ack".to_owned(),
            ));
        }
        staged.insert(record.event_id.clone(), receipt.clone());
    }
    Ok(())
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

    async fn put_realm_bootstrap_batch_atomic(
        &self,
        records: Vec<CanonicalEventRecord>,
        control_proposal_acks: Vec<arkret_wire::ControlProposalAck>,
        outbox: Vec<FederationOutboxRecord>,
    ) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        let mut stored_control_proposal_acks = self.control_proposal_acks.lock();
        let mut federation_outbox = self.federation_outbox.lock();
        let mut staged = data.clone();
        let mut staged_control_proposal_acks = stored_control_proposal_acks.clone();
        let mut staged_outbox = federation_outbox.clone();
        stage_control_proposal_acks(
            &mut staged_control_proposal_acks,
            &records,
            control_proposal_acks,
            true,
        )?;
        stage_identity_anchor_events(&mut staged, records)?;
        stage_federation_outbox(&mut staged_outbox, outbox)?;
        *data = staged;
        *stored_control_proposal_acks = staged_control_proposal_acks;
        *federation_outbox = staged_outbox;
        Ok(())
    }

    async fn put_identity_anchor_batch_atomic(
        &self,
        records: Vec<CanonicalEventRecord>,
        control_proposal_acks: Vec<arkret_wire::ControlProposalAck>,
        receipt: Option<EventBatchReceipt>,
        device: Option<DeviceInventoryRecord>,
        _frontier_cas: Option<IdentityAnchorFrontierCas>,
        reanchor_slot: Option<IdentityAnchorReanchorSlot>,
        publication_evidence: Vec<PublicationEvidenceRecord>,
        outbox: Vec<FederationOutboxRecord>,
    ) -> PersistenceResult<IdentityAnchorCommitOutcome> {
        let mut data = self.data.lock();
        let mut stored_control_proposal_acks = self.control_proposal_acks.lock();
        let mut devices = self.devices.lock();
        let mut receipts = self.receipts.lock();
        let mut evidence = self.publication_evidence.lock();
        let mut federation_outbox = self.federation_outbox.lock();
        let mut staged_events = data.clone();
        let mut staged_control_proposal_acks = stored_control_proposal_acks.clone();
        let mut staged_devices = devices.clone();
        let mut staged_receipts = receipts.clone();
        let mut staged_evidence = evidence.clone();
        let mut staged_outbox = federation_outbox.clone();
        let reanchor_conflict = reanchor_slot
            .as_ref()
            .is_some_and(|slot| {
                identity_anchor_slot_conflicts(
                    &staged_events.values().collect::<Vec<_>>(),
                    slot,
                )
            });
        if reanchor_conflict {
            if !control_proposal_acks.is_empty() {
                return Err(PersistenceError::Conflict(
                    "schema_violation: conflicting identity anchor cannot carry Control Proposal Acks"
                        .to_owned(),
                ));
            }
        } else {
            stage_control_proposal_acks(
                &mut staged_control_proposal_acks,
                &records,
                control_proposal_acks,
                true,
            )?;
        }
        stage_identity_anchor_events(&mut staged_events, records)?;
        if !reanchor_conflict && let Some(device) = device {
            staged_devices.insert((device.actor.clone(), device.device_id.clone()), device);
        }
        if !reanchor_conflict && let Some(receipt) = receipt {
            staged_receipts.insert(receipt.receipt_id.as_str().to_owned(), receipt);
        }
        if !reanchor_conflict {
            for record in publication_evidence {
                staged_evidence
                    .entry(record.event_digest.clone())
                    .or_insert(record);
            }
            // A quarantined re-anchor conflict is not accepted locally, so it
            // owes no peer anything.
            stage_federation_outbox(&mut staged_outbox, outbox)?;
        }
        *data = staged_events;
        *stored_control_proposal_acks = staged_control_proposal_acks;
        *devices = staged_devices;
        *receipts = staged_receipts;
        *evidence = staged_evidence;
        *federation_outbox = staged_outbox;
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

    async fn control_proposal_ack_for_event(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Option<arkret_wire::ControlProposalAck>> {
        Ok(self.control_proposal_acks.lock().get(event_id).cloned())
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

    async fn list_for_realm_actor(
        &self,
        realm_id: &str,
        actor_id: &str,
    ) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let mut records = self
            .data
            .lock()
            .values()
            .filter(|record| {
                record.actor_id == actor_id && record.realm_id.as_deref() == Some(realm_id)
            })
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            left.actor_seq
                .cmp(&right.actor_seq)
                .then_with(|| left.event_id.cmp(&right.event_id))
        });
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

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;

    fn record(event_id: &str, canonical_bytes: &[u8]) -> CanonicalEventRecord {
        CanonicalEventRecord {
            event_id: event_id.to_owned(),
            actor_id: "did:web:founder.example".to_owned(),
            actor_seq: 1,
            realm_id: Some("ak:realm:019f9000-0000-8000-8000-000000000001".to_owned()),
            kind: "ak.realm.join_rule".to_owned(),
            schema_id: "arkret://events/realm/join-rule/v1".to_owned(),
            canonical_digest: format!("sha256:{}", "0".repeat(64)),
            canonical_bytes: canonical_bytes.to_vec(),
            envelope: serde_json::json!({"event_id": event_id}),
            received_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn realm_bootstrap_batch_rolls_back_every_prior_insert_on_late_conflict() {
        let outbox = Arc::new(Mutex::new(BTreeMap::new()));
        let store = MemoryEventStore::with_devices(
            Arc::new(Mutex::new(BTreeMap::new())),
            Arc::new(Mutex::new(BTreeMap::new())),
            outbox.clone(),
        );
        let conflict_id = "ak:event:019f9000-0000-8000-8000-000000000002";
        store.put(record(conflict_id, b"existing")).await.unwrap();

        let first_id = "ak:event:019f9000-0000-8000-8000-000000000001";
        let error = store
            .put_realm_bootstrap_batch_atomic(
                vec![
                    record(first_id, b"first"),
                    record(conflict_id, b"different"),
                ],
                Vec::new(),
                vec![FederationOutboxRecord::pending(
                    "outbox:rollback".to_owned(),
                    "did:web:peer.example".to_owned(),
                    "https://peer.example".to_owned(),
                    "/_arkret/peer/events".to_owned(),
                    "ak:outbox:event:rollback".to_owned(),
                    "{}".to_owned(),
                    1,
                )],
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            PersistenceError::Conflict(reason) if reason == "duplicate_conflict"
        ));
        assert!(!store.contains(first_id).await.unwrap());
        assert!(
            outbox.lock().is_empty(),
            "a rolled-back genesis unit leaves no delivery intent behind"
        );
        assert_eq!(
            store
                .get(conflict_id)
                .await
                .unwrap()
                .unwrap()
                .canonical_bytes,
            b"existing"
        );
    }
}
