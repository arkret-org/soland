use super::{
    Arc, BTreeMap, BTreeSet, CanonicalEventRecord, DeviceInventoryRecord,
    DirectConversationFoundingCommitOutcome, DirectConversationFoundingSlotRecord,
    EventBatchReceipt, EventStore, FederationOutboxRecord, FederationOutboxState,
    IdentityAnchorAccountSlot, IdentityAnchorCommitOutcome, IdentityAnchorFrontierCas,
    IdentityAnchorReanchorSlot, MessageRecord, MessageStore, Mutex, PeerEventsPageQuery,
    PersistenceError, PersistenceResult, ProjectionEventRecord, PublicationEvidenceRecord,
    RealmEventStats, async_trait, event_position_cmp, identity_anchor_slot_conflicts, ids,
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
    pub(crate) data: Arc<Mutex<BTreeMap<String, CanonicalEventRecord>>>,
    pub(crate) quarantined: Mutex<BTreeMap<String, CanonicalEventRecord>>,
    pub(crate) collision_variants: Mutex<BTreeMap<String, Vec<CanonicalEventRecord>>>,
    pub(crate) control_proposal_acks: Mutex<BTreeMap<String, arkret_wire::ControlProposalAck>>,
    devices: Arc<Mutex<BTreeMap<(String, String), DeviceInventoryRecord>>>,
    receipts: Mutex<BTreeMap<String, EventBatchReceipt>>,
    publication_evidence: Arc<Mutex<BTreeMap<String, PublicationEvidenceRecord>>>,
    /// Shared with `MemoryFederationOutboxStore` so the atomic Event batches
    /// commit their delivery intents in the same staged mutation as the Events,
    /// mirroring the single PostgreSQL transaction.
    federation_outbox: Arc<Mutex<BTreeMap<String, FederationOutboxRecord>>>,
    pub(crate) projections: Arc<Mutex<Vec<ProjectionEventRecord>>>,
    pub(crate) event_outbox_ids: Mutex<BTreeMap<String, BTreeSet<String>>>,
    direct_conversation_founding_slots:
        Mutex<BTreeMap<(String, String, String), DirectConversationFoundingSlotRecord>>,
    identity_anchor_account_slots: Mutex<BTreeMap<(String, String), IdentityAnchorAccountSlot>>,
}
impl MemoryEventStore {
    pub(crate) fn with_devices(
        data: Arc<Mutex<BTreeMap<String, CanonicalEventRecord>>>,
        devices: Arc<Mutex<BTreeMap<(String, String), DeviceInventoryRecord>>>,
        publication_evidence: Arc<Mutex<BTreeMap<String, PublicationEvidenceRecord>>>,
        federation_outbox: Arc<Mutex<BTreeMap<String, FederationOutboxRecord>>>,
        projections: Arc<Mutex<Vec<ProjectionEventRecord>>>,
    ) -> Self {
        Self {
            data,
            quarantined: Mutex::new(BTreeMap::new()),
            collision_variants: Mutex::new(BTreeMap::new()),
            control_proposal_acks: Mutex::new(BTreeMap::new()),
            devices,
            receipts: Mutex::new(BTreeMap::new()),
            publication_evidence,
            federation_outbox,
            projections,
            event_outbox_ids: Mutex::new(BTreeMap::new()),
            direct_conversation_founding_slots: Mutex::new(BTreeMap::new()),
            identity_anchor_account_slots: Mutex::new(BTreeMap::new()),
        }
    }
}

pub(crate) fn quarantine_memory_event(
    accepted: &mut BTreeMap<String, CanonicalEventRecord>,
    quarantined: &mut BTreeMap<String, CanonicalEventRecord>,
    variants: &mut BTreeMap<String, Vec<CanonicalEventRecord>>,
    projections: &mut Vec<ProjectionEventRecord>,
    event_outbox_ids: &BTreeMap<String, BTreeSet<String>>,
    outbox: &mut BTreeMap<String, FederationOutboxRecord>,
    incoming: CanonicalEventRecord,
) {
    let event_id = incoming.event_id.clone();
    let original = accepted
        .remove(&event_id)
        .or_else(|| quarantined.get(&event_id).cloned());
    if let Some(original) = original {
        quarantined.insert(event_id.clone(), original.clone());
        let evidence = variants.entry(event_id.clone()).or_default();
        if !evidence
            .iter()
            .any(|variant| variant.canonical_bytes == original.canonical_bytes)
        {
            evidence.push(original);
        }
        if !evidence
            .iter()
            .any(|variant| variant.canonical_bytes == incoming.canonical_bytes)
        {
            evidence.push(incoming);
        }
    }
    projections.retain(|projection| projection.event_id != event_id);
    if let Some(ids) = event_outbox_ids.get(&event_id) {
        for id in ids {
            if let Some(delivery) = outbox.get_mut(id)
                && matches!(
                    delivery.state,
                    FederationOutboxState::Pending
                        | FederationOutboxState::PendingRoute
                        | FederationOutboxState::Leased
                )
            {
                delivery.state = if delivery.realm_fanout.is_some() {
                    FederationOutboxState::CancelledAuthorityLost
                } else {
                    FederationOutboxState::PolicySuppressed
                };
                delivery.last_error_code = Some("witness_disagreement".to_owned());
                delivery.lease_owner = None;
                delivery.lease_token = None;
                delivery.lease_expires_at = None;
                delivery.leased_from_state = None;
                delivery.completed_at = Some(delivery.created_at);
            }
        }
    }
}

fn preflight_memory_events(
    records: &[CanonicalEventRecord],
    accepted: &mut BTreeMap<String, CanonicalEventRecord>,
    quarantined: &mut BTreeMap<String, CanonicalEventRecord>,
    variants: &mut BTreeMap<String, Vec<CanonicalEventRecord>>,
    projections: &mut Vec<ProjectionEventRecord>,
    event_outbox_ids: &BTreeMap<String, BTreeSet<String>>,
    outbox: &mut BTreeMap<String, FederationOutboxRecord>,
) -> PersistenceResult<()> {
    let mut seen = accepted.clone();
    for record in records {
        ids::validated_event_identity_parts(
            &record.event_id,
            &record.canonical_digest,
            &record.canonical_bytes,
        )?;
        if quarantined.contains_key(&record.event_id) {
            let known = variants.get(&record.event_id).is_some_and(|items| {
                items
                    .iter()
                    .any(|item| item.canonical_bytes == record.canonical_bytes)
            });
            if !known {
                quarantine_memory_event(
                    accepted,
                    quarantined,
                    variants,
                    projections,
                    event_outbox_ids,
                    outbox,
                    record.clone(),
                );
            }
            return Err(PersistenceError::Conflict(
                "event_hash_collision".to_owned(),
            ));
        }
        if let Some(existing) = seen.get(&record.event_id) {
            if existing.canonical_bytes != record.canonical_bytes {
                if !accepted.contains_key(&record.event_id) {
                    accepted.insert(record.event_id.clone(), existing.clone());
                }
                quarantine_memory_event(
                    accepted,
                    quarantined,
                    variants,
                    projections,
                    event_outbox_ids,
                    outbox,
                    record.clone(),
                );
                return Err(PersistenceError::Conflict(
                    "event_hash_collision".to_owned(),
                ));
            }
        } else {
            seen.insert(record.event_id.clone(), record.clone());
        }
    }
    Ok(())
}

/// Stage outbox rows with exactly the uniqueness PostgreSQL enforces:
/// `(peer_id, idempotency_key)` is `ON CONFLICT DO NOTHING` — a retried
/// admission collapses onto the existing intent — while a colliding primary key
/// is a hard conflict that aborts the whole batch.
fn stage_federation_outbox(
    staged: &mut BTreeMap<String, FederationOutboxRecord>,
    outbox: Vec<FederationOutboxRecord>,
) -> PersistenceResult<Vec<String>> {
    let mut resolved_ids = Vec::with_capacity(outbox.len());
    for record in outbox {
        record
            .validate_shape()
            .map_err(|error| PersistenceError::Conflict(format!("schema_violation: {error}")))?;
        let existing_id = staged.values().find_map(|existing| {
            (existing.peer_did == record.peer_did
                && existing.idempotency_key == record.idempotency_key)
                .then(|| existing.id.clone())
        });
        if let Some(existing_id) = existing_id {
            resolved_ids.push(existing_id);
            continue;
        }
        if staged.contains_key(&record.id) {
            return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()));
        }
        resolved_ids.push(record.id.clone());
        staged.insert(record.id.clone(), record);
    }
    resolved_ids.sort_unstable();
    resolved_ids.dedup();
    Ok(resolved_ids)
}

fn stage_control_proposal_acks(
    staged: &mut BTreeMap<String, arkret_wire::ControlProposalAck>,
    records: &[CanonicalEventRecord],
    control_proposal_acks: Vec<arkret_wire::ControlProposalAck>,
    acks_required: bool,
) -> PersistenceResult<()> {
    if control_proposal_acks.is_empty() && !acks_required {
        return Ok(());
    }
    if control_proposal_acks.len() != records.len() {
        return Err(PersistenceError::Conflict(
            "schema_violation: Control Proposal Ack cardinality mismatch".to_owned(),
        ));
    }
    let mut by_digest = BTreeMap::new();
    for ack in control_proposal_acks {
        ack.validate_protocol_bounds().map_err(|error| {
            PersistenceError::Conflict(format!(
                "schema_violation: invalid Control Proposal Ack: {error}"
            ))
        })?;
        if by_digest
            .insert(ack.proposal_digest.as_str().to_owned(), ack)
            .is_some()
        {
            return Err(PersistenceError::Conflict(
                "schema_violation: duplicate Control Proposal Ack".to_owned(),
            ));
        }
    }
    for record in records {
        let ack = by_digest.get(&record.canonical_digest).ok_or_else(|| {
            PersistenceError::Conflict(
                "schema_violation: accepted Control Move is missing Control Proposal Ack"
                    .to_owned(),
            )
        })?;
        if record.realm_id.as_deref() != Some(ack.realm_id.as_str()) {
            return Err(PersistenceError::Conflict(
                "schema_violation: Control Proposal Ack does not bind Control Move".to_owned(),
            ));
        }
        if let Some(existing) = staged.get(&record.event_id)
            && existing != ack
        {
            return Err(PersistenceError::Conflict(
                "duplicate_conflict: Control Move has a different Control Proposal Ack".to_owned(),
            ));
        }
        staged.insert(record.event_id.clone(), ack.clone());
    }
    Ok(())
}

#[async_trait]
impl EventStore for MemoryEventStore {
    async fn put(&self, record: CanonicalEventRecord) -> PersistenceResult<()> {
        ids::validated_event_identity_parts(
            &record.event_id,
            &record.canonical_digest,
            &record.canonical_bytes,
        )?;
        let mut data = self.data.lock();
        let mut quarantined = self.quarantined.lock();
        let mut variants = self.collision_variants.lock();
        let mut projections = self.projections.lock();
        let event_outbox_ids = self.event_outbox_ids.lock();
        let mut outbox = self.federation_outbox.lock();
        if let Some(existing) = quarantined.get(&record.event_id) {
            return if variants.get(&record.event_id).is_some_and(|items| {
                items
                    .iter()
                    .any(|item| item.canonical_bytes == record.canonical_bytes)
            }) || existing.canonical_bytes == record.canonical_bytes
            {
                Err(PersistenceError::Conflict(
                    "event_hash_collision".to_owned(),
                ))
            } else {
                quarantine_memory_event(
                    &mut data,
                    &mut quarantined,
                    &mut variants,
                    &mut projections,
                    &event_outbox_ids,
                    &mut outbox,
                    record,
                );
                Err(PersistenceError::Conflict(
                    "event_hash_collision".to_owned(),
                ))
            };
        }
        if let Some(existing) = data.get(&record.event_id) {
            return if existing.canonical_bytes == record.canonical_bytes {
                Ok(())
            } else {
                quarantine_memory_event(
                    &mut data,
                    &mut quarantined,
                    &mut variants,
                    &mut projections,
                    &event_outbox_ids,
                    &mut outbox,
                    record,
                );
                Err(PersistenceError::Conflict(
                    "event_hash_collision".to_owned(),
                ))
            };
        }
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
        data.insert(record.event_id.clone(), record);
        Ok(())
    }

    async fn collision_variants(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        ids::parse_event_id(event_id).ok_or_else(|| {
            PersistenceError::SchemaViolation(format!("malformed canonical Event id: {event_id:?}"))
        })?;
        Ok(self
            .collision_variants
            .lock()
            .get(event_id)
            .cloned()
            .unwrap_or_default())
    }

    async fn federation_outbox_for_event(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>> {
        ids::parse_event_id(event_id).ok_or_else(|| {
            PersistenceError::SchemaViolation(format!("malformed canonical Event id: {event_id:?}"))
        })?;
        let ids = self
            .event_outbox_ids
            .lock()
            .get(event_id)
            .cloned()
            .unwrap_or_default();
        let outbox = self.federation_outbox.lock();
        Ok(ids
            .into_iter()
            .filter_map(|id| outbox.get(&id).cloned())
            .collect())
    }

    async fn put_realm_bootstrap_batch_atomic(
        &self,
        records: Vec<CanonicalEventRecord>,
        control_proposal_acks: Vec<arkret_wire::ControlProposalAck>,
        outbox: Vec<FederationOutboxRecord>,
    ) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        let mut quarantined = self.quarantined.lock();
        let mut variants = self.collision_variants.lock();
        let mut stored_control_proposal_acks = self.control_proposal_acks.lock();
        let mut projections = self.projections.lock();
        let mut event_outbox_ids = self.event_outbox_ids.lock();
        let mut federation_outbox = self.federation_outbox.lock();
        preflight_memory_events(
            &records,
            &mut data,
            &mut quarantined,
            &mut variants,
            &mut projections,
            &event_outbox_ids,
            &mut federation_outbox,
        )?;
        let event_ids = records
            .iter()
            .map(|record| record.event_id.clone())
            .collect::<Vec<_>>();
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
        let outbox_ids = stage_federation_outbox(&mut staged_outbox, outbox)?;
        *data = staged;
        *stored_control_proposal_acks = staged_control_proposal_acks;
        *federation_outbox = staged_outbox;
        for event_id in event_ids {
            event_outbox_ids
                .entry(event_id)
                .or_default()
                .extend(outbox_ids.iter().cloned());
        }
        Ok(())
    }

    async fn put_direct_conversation_founding_batch_atomic(
        &self,
        records: Vec<CanonicalEventRecord>,
        control_proposal_acks: Vec<arkret_wire::ControlProposalAck>,
        slot: DirectConversationFoundingSlotRecord,
        outbox: Vec<FederationOutboxRecord>,
    ) -> PersistenceResult<DirectConversationFoundingCommitOutcome> {
        let key = (
            slot.founder_id.clone(),
            slot.trust_domain_id.clone(),
            slot.pair_key.clone(),
        );
        let mut slots = self.direct_conversation_founding_slots.lock();
        if let Some(existing) = slots.get(&key) {
            return Ok(if existing.idempotency_key == slot.idempotency_key {
                if existing.founding_unit_digest == slot.founding_unit_digest {
                    DirectConversationFoundingCommitOutcome::ExactRetry(existing.clone())
                } else {
                    DirectConversationFoundingCommitOutcome::IdempotencyConflict
                }
            } else {
                DirectConversationFoundingCommitOutcome::SlotConflict(existing.clone())
            });
        }
        if records.len() != 3
            || slot.event_ids
                != records
                    .iter()
                    .map(|record| record.event_id.clone())
                    .collect::<Vec<_>>()
        {
            return Err(PersistenceError::Conflict(
                "direct_conversation_founding_unit_invalid".to_owned(),
            ));
        }
        let mut data = self.data.lock();
        let mut quarantined = self.quarantined.lock();
        let mut variants = self.collision_variants.lock();
        let mut stored_control_proposal_acks = self.control_proposal_acks.lock();
        let mut projections = self.projections.lock();
        let mut event_outbox_ids = self.event_outbox_ids.lock();
        let mut federation_outbox = self.federation_outbox.lock();
        preflight_memory_events(
            &records,
            &mut data,
            &mut quarantined,
            &mut variants,
            &mut projections,
            &event_outbox_ids,
            &mut federation_outbox,
        )?;
        let event_ids = slot.event_ids.clone();
        let mut staged = data.clone();
        let mut staged_acks = stored_control_proposal_acks.clone();
        let mut staged_outbox = federation_outbox.clone();
        stage_control_proposal_acks(&mut staged_acks, &records, control_proposal_acks, true)?;
        stage_identity_anchor_events(&mut staged, records)?;
        let outbox_ids = stage_federation_outbox(&mut staged_outbox, outbox)?;
        slots.insert(key, slot);
        *data = staged;
        *stored_control_proposal_acks = staged_acks;
        *federation_outbox = staged_outbox;
        for event_id in event_ids {
            event_outbox_ids
                .entry(event_id)
                .or_default()
                .extend(outbox_ids.iter().cloned());
        }
        Ok(DirectConversationFoundingCommitOutcome::Committed)
    }

    async fn direct_conversation_founding_slot(
        &self,
        founder_id: &str,
        trust_domain_id: &str,
        pair_key: &str,
    ) -> PersistenceResult<Option<DirectConversationFoundingSlotRecord>> {
        Ok(self
            .direct_conversation_founding_slots
            .lock()
            .get(&(
                founder_id.to_owned(),
                trust_domain_id.to_owned(),
                pair_key.to_owned(),
            ))
            .cloned())
    }

    async fn put_identity_anchor_batch_atomic(
        &self,
        records: Vec<CanonicalEventRecord>,
        control_proposal_acks: Vec<arkret_wire::ControlProposalAck>,
        receipt: Option<EventBatchReceipt>,
        device: Option<DeviceInventoryRecord>,
        account_slot: Option<IdentityAnchorAccountSlot>,
        _frontier_cas: Option<IdentityAnchorFrontierCas>,
        reanchor_slot: Option<IdentityAnchorReanchorSlot>,
        publication_evidence: Vec<PublicationEvidenceRecord>,
        outbox: Vec<FederationOutboxRecord>,
    ) -> PersistenceResult<IdentityAnchorCommitOutcome> {
        let mut data = self.data.lock();
        let mut quarantined = self.quarantined.lock();
        let mut variants = self.collision_variants.lock();
        let mut stored_control_proposal_acks = self.control_proposal_acks.lock();
        let mut devices = self.devices.lock();
        let mut receipts = self.receipts.lock();
        let mut account_slots = self.identity_anchor_account_slots.lock();
        let mut evidence = self.publication_evidence.lock();
        let mut projections = self.projections.lock();
        let mut event_outbox_ids = self.event_outbox_ids.lock();
        let mut federation_outbox = self.federation_outbox.lock();
        preflight_memory_events(
            &records,
            &mut data,
            &mut quarantined,
            &mut variants,
            &mut projections,
            &event_outbox_ids,
            &mut federation_outbox,
        )?;
        let event_ids = records
            .iter()
            .map(|record| record.event_id.clone())
            .collect::<Vec<_>>();
        let mut staged_events = data.clone();
        let mut staged_control_proposal_acks = stored_control_proposal_acks.clone();
        let mut staged_devices = devices.clone();
        let mut staged_receipts = receipts.clone();
        let mut staged_account_slots = account_slots.clone();
        let mut staged_evidence = evidence.clone();
        let mut staged_outbox = federation_outbox.clone();
        let reanchor_conflict = reanchor_slot.as_ref().is_some_and(|slot| {
            identity_anchor_slot_conflicts(&staged_events.values().collect::<Vec<_>>(), slot)
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
        if !reanchor_conflict && let Some(slot) = account_slot {
            let key = (
                slot.account_authority_id.clone(),
                slot.account_subject.clone(),
            );
            if staged_account_slots
                .get(&key)
                .is_some_and(|existing| existing != &slot)
            {
                return Err(PersistenceError::Conflict(
                    "account_principal_control_realm_already_exists".to_owned(),
                ));
            }
            staged_account_slots.insert(key, slot);
        }
        if !reanchor_conflict && let Some(device) = device {
            staged_devices.insert((device.actor.clone(), device.device_id.clone()), device);
        }
        if !reanchor_conflict && let Some(receipt) = receipt {
            staged_receipts.insert(receipt.receipt_id.as_str().to_owned(), receipt);
        }
        let outbox_ids = if !reanchor_conflict {
            for record in publication_evidence {
                staged_evidence
                    .entry(record.event_digest.clone())
                    .or_insert(record);
            }
            // A quarantined re-anchor conflict is not accepted locally, so it
            // owes no peer anything.
            stage_federation_outbox(&mut staged_outbox, outbox)?
        } else {
            Vec::new()
        };
        *data = staged_events;
        *stored_control_proposal_acks = staged_control_proposal_acks;
        *devices = staged_devices;
        *receipts = staged_receipts;
        *account_slots = staged_account_slots;
        *evidence = staged_evidence;
        *federation_outbox = staged_outbox;
        if !reanchor_conflict {
            for event_id in event_ids {
                event_outbox_ids
                    .entry(event_id)
                    .or_default()
                    .extend(outbox_ids.iter().cloned());
            }
        }
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

    async fn identity_anchor_account_slot_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Option<IdentityAnchorAccountSlot>> {
        let matches = self
            .identity_anchor_account_slots
            .lock()
            .values()
            .filter(|slot| slot.principal_id == principal_id)
            .cloned()
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [] => Ok(None),
            [slot] => Ok(Some(slot.clone())),
            _ => Err(PersistenceError::Conflict(
                "principal has multiple identity-anchor account slots".to_owned(),
            )),
        }
    }

    async fn control_proposal_ack_for_event(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Option<arkret_wire::ControlProposalAck>> {
        Ok(self.control_proposal_acks.lock().get(event_id).cloned())
    }

    async fn get(&self, event_id: &str) -> PersistenceResult<Option<CanonicalEventRecord>> {
        ids::parse_event_id(event_id).ok_or_else(|| {
            PersistenceError::SchemaViolation(format!("malformed canonical Event id: {event_id:?}"))
        })?;
        Ok(self.data.lock().get(event_id).cloned())
    }

    async fn contains(&self, event_id: &str) -> PersistenceResult<bool> {
        ids::parse_event_id(event_id).ok_or_else(|| {
            PersistenceError::SchemaViolation(format!("malformed canonical Event id: {event_id:?}"))
        })?;
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

    fn record(canonical_bytes: &[u8]) -> CanonicalEventRecord {
        let digest = arkret_canonical::sha256_bytes(canonical_bytes);
        let mut id = [0_u8; ids::EVENT_ID_BYTES];
        id[0] = 0x01;
        id[1..].copy_from_slice(&digest);
        let event_id = ids::format_event_id(&id);
        CanonicalEventRecord {
            event_id: event_id.clone(),
            actor_id: "did:web:founder.example".to_owned(),
            actor_seq: 1,
            realm_id: Some("ak:realm:AYcO0aKZZvKELI-s58wUjRHsrz5v8Y51T0_sGUTciDVw".to_owned()),
            kind: "ak.realm.join_rule".to_owned(),
            schema_id: "arkret://events/realm/join-rule/v1".to_owned(),
            canonical_digest: ids::format_event_digest(0x01, &digest).unwrap(),
            canonical_bytes: canonical_bytes.to_vec(),
            envelope: serde_json::json!({"event_id": event_id}),
            received_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn realm_bootstrap_batch_rejects_forged_preimage_without_committing_prefix() {
        let outbox = Arc::new(Mutex::new(BTreeMap::new()));
        let store = MemoryEventStore::with_devices(
            Arc::new(Mutex::new(BTreeMap::new())),
            Arc::new(Mutex::new(BTreeMap::new())),
            Arc::new(Mutex::new(BTreeMap::new())),
            outbox.clone(),
            Arc::new(Mutex::new(Vec::new())),
        );
        let existing = record(b"existing");
        let conflict_id = existing.event_id.clone();
        store.put(existing).await.unwrap();

        let first = record(b"first");
        let first_id = first.event_id.clone();
        let mut forged = store.get(&conflict_id).await.unwrap().unwrap();
        forged.canonical_bytes = b"different".to_vec();
        let error = store
            .put_realm_bootstrap_batch_atomic(
                vec![first, forged],
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
            PersistenceError::Conflict(reason) if reason == "event_id_digest_mismatch"
        ));
        assert!(!store.contains(&first_id).await.unwrap());
        assert!(
            outbox.lock().is_empty(),
            "a rolled-back genesis unit leaves no delivery intent behind"
        );
        assert_eq!(
            store
                .get(&conflict_id)
                .await
                .unwrap()
                .unwrap()
                .canonical_bytes,
            b"existing"
        );
    }

    #[tokio::test]
    async fn collision_state_machine_quarantines_all_variants_and_withdraws_unfinal_writes() {
        let store = MemoryEventStore::with_devices(
            Arc::new(Mutex::new(BTreeMap::new())),
            Arc::new(Mutex::new(BTreeMap::new())),
            Arc::new(Mutex::new(BTreeMap::new())),
            Arc::new(Mutex::new(BTreeMap::new())),
            Arc::new(Mutex::new(Vec::new())),
        );
        let first = record(b"first");
        let mut colliding = first.clone();
        colliding.canonical_bytes = b"hypothetical-second-preimage".to_vec();
        colliding.envelope = serde_json::json!({"variant": 2});
        store
            .data
            .lock()
            .insert(first.event_id.clone(), first.clone());
        store.projections.lock().push(ProjectionEventRecord {
            event_id: first.event_id.clone(),
            realm_id: first.realm_id.clone().unwrap(),
            event_kind: first.kind.clone(),
            operation_kind: "test".to_owned(),
            operation_id: None,
            sender: None,
            payload: serde_json::json!({}),
            created_at: first.received_at,
            received_at: first.received_at,
        });
        let outbox_id = "outbox:collision".to_owned();
        store
            .event_outbox_ids
            .lock()
            .entry(first.event_id.clone())
            .or_default()
            .insert(outbox_id.clone());
        store.federation_outbox.lock().insert(
            outbox_id.clone(),
            FederationOutboxRecord::pending(
                outbox_id.clone(),
                "did:web:peer.example".to_owned(),
                "https://peer.example".to_owned(),
                "/_arkret/peer/events".to_owned(),
                "collision".to_owned(),
                "{}".to_owned(),
                1,
            ),
        );

        quarantine_memory_event(
            &mut store.data.lock(),
            &mut store.quarantined.lock(),
            &mut store.collision_variants.lock(),
            &mut store.projections.lock(),
            &store.event_outbox_ids.lock(),
            &mut store.federation_outbox.lock(),
            colliding.clone(),
        );
        assert!(store.get(&first.event_id).await.unwrap().is_none());
        assert_eq!(
            store
                .collision_variants(&first.event_id)
                .await
                .unwrap()
                .len(),
            2
        );
        assert!(store.projections.lock().is_empty());
        let delivery = store.federation_outbox.lock()[&outbox_id].clone();
        assert_eq!(delivery.state, FederationOutboxState::PolicySuppressed);
        assert_eq!(
            delivery.last_error_code.as_deref(),
            Some("witness_disagreement")
        );

        quarantine_memory_event(
            &mut store.data.lock(),
            &mut store.quarantined.lock(),
            &mut store.collision_variants.lock(),
            &mut store.projections.lock(),
            &store.event_outbox_ids.lock(),
            &mut store.federation_outbox.lock(),
            colliding,
        );
        assert_eq!(
            store
                .collision_variants(&first.event_id)
                .await
                .unwrap()
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn envelope_only_proof_difference_is_an_idempotent_replay() {
        let store = MemoryEventStore::with_devices(
            Arc::new(Mutex::new(BTreeMap::new())),
            Arc::new(Mutex::new(BTreeMap::new())),
            Arc::new(Mutex::new(BTreeMap::new())),
            Arc::new(Mutex::new(BTreeMap::new())),
            Arc::new(Mutex::new(Vec::new())),
        );
        let first = record(b"digest-covered-preimage");
        let mut replay = first.clone();
        replay.envelope = serde_json::json!({"proofs": [{"jws": "different"}]});
        store.put(first.clone()).await.unwrap();
        store.put(replay).await.unwrap();
        assert!(store.contains(&first.event_id).await.unwrap());
        assert!(
            store
                .collision_variants(&first.event_id)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
