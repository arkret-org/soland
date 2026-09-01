use serde_json::Value;

use super::{
    Arc, BTreeMap, BTreeSet, CanonicalEventRecord, DeviceInventoryRecord,
    DirectConversationFoundingCommitOutcome, DirectConversationFoundingSlotRecord,
    EventBatchReceipt, EventStore, FederationOutboxRecord, FederationOutboxState,
    IdentityAnchorAccountSlot, IdentityAnchorCommitOutcome, IdentityAnchorFrontierCas,
    IdentityAnchorReanchorSlot, MembershipCompensationEvidenceRecord,
    MemoryGovernanceDependencyStore, MessageRecord, MessageStore, Mutex, PeerEventsPageQuery,
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
        // Replayed projection writes dedup idempotently on the Event id,
        // mirroring the Pg `ON CONFLICT (event_id) DO NOTHING`.
        if data.iter().any(|m| m.event_id == record.event_id) {
            return Ok(());
        }
        data.push(record.clone());
        Ok(())
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<MessageRecord>> {
        let data = self.data.lock();
        // Newest first, mirroring the Pg `created_at DESC, pk DESC` ordering
        // (insertion position stands in for `pk`).
        let mut messages: Vec<_> = data
            .iter()
            .enumerate()
            .filter(|(_, m)| m.realm_id == realm_id)
            .collect();
        messages.sort_by(|(left_pos, left), (right_pos, right)| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| right_pos.cmp(left_pos))
        });
        Ok(messages
            .into_iter()
            .take(limit)
            .map(|(_, m)| m.clone())
            .collect())
    }

    async fn list_for_thread(
        &self,
        thread_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<MessageRecord>> {
        let data = self.data.lock();
        // Return in chronological order (oldest first) so thread readers get a
        // natural conversation timeline. The caller decides whether to reverse.
        let mut messages: Vec<_> = data
            .iter()
            .enumerate()
            .filter(|(_, m)| m.thread_id == thread_id)
            .collect();
        messages.sort_by(|(left_pos, left), (right_pos, right)| {
            left.created_at
                .cmp(&right.created_at)
                .then_with(|| left_pos.cmp(right_pos))
        });
        Ok(messages
            .into_iter()
            .take(limit)
            .map(|(_, m)| m.clone())
            .collect())
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
    pub(crate) membership_compensation_evidence:
        Mutex<BTreeMap<String, MembershipCompensationEvidenceRecord>>,
    /// Shared with `MemoryFederationOutboxStore` so the atomic Event batches
    /// commit their delivery intents in the same staged mutation as the Events,
    /// mirroring the single PostgreSQL transaction.
    federation_outbox: Arc<Mutex<BTreeMap<String, FederationOutboxRecord>>>,
    pub(crate) projections: Arc<Mutex<Vec<ProjectionEventRecord>>>,
    pub(crate) event_outbox_ids: Mutex<BTreeMap<String, BTreeSet<String>>>,
    direct_conversation_founding_slots:
        Mutex<BTreeMap<(String, String, String), DirectConversationFoundingSlotRecord>>,
    identity_anchor_account_slots: Mutex<BTreeMap<(String, String), IdentityAnchorAccountSlot>>,
    governance_dependencies: MemoryGovernanceDependencyStore,
}
impl MemoryEventStore {
    pub(crate) fn with_devices(
        data: Arc<Mutex<BTreeMap<String, CanonicalEventRecord>>>,
        devices: Arc<Mutex<BTreeMap<(String, String), DeviceInventoryRecord>>>,
        publication_evidence: Arc<Mutex<BTreeMap<String, PublicationEvidenceRecord>>>,
        federation_outbox: Arc<Mutex<BTreeMap<String, FederationOutboxRecord>>>,
        projections: Arc<Mutex<Vec<ProjectionEventRecord>>>,
        governance_dependencies: MemoryGovernanceDependencyStore,
    ) -> Self {
        Self {
            data,
            quarantined: Mutex::new(BTreeMap::new()),
            collision_variants: Mutex::new(BTreeMap::new()),
            control_proposal_acks: Mutex::new(BTreeMap::new()),
            devices,
            receipts: Mutex::new(BTreeMap::new()),
            publication_evidence,
            membership_compensation_evidence: Mutex::new(BTreeMap::new()),
            federation_outbox,
            projections,
            event_outbox_ids: Mutex::new(BTreeMap::new()),
            direct_conversation_founding_slots: Mutex::new(BTreeMap::new()),
            identity_anchor_account_slots: Mutex::new(BTreeMap::new()),
            governance_dependencies,
        }
    }
}

fn stage_event_batch_governance_dependencies(
    data: &mut crate::governance_history::GovernanceDependencyData,
    records: &[CanonicalEventRecord],
    dependencies: &[soland_storage::GovernanceDependencyWrite],
) -> PersistenceResult<()> {
    for dependency in dependencies {
        let soland_storage::GovernanceDependencySource::ControlEvent(event_digest) =
            &dependency.source
        else {
            return Err(PersistenceError::Conflict(
                "schema_violation: Event batch cannot carry a Seal governance dependency"
                    .to_owned(),
            ));
        };
        let matches = records.iter().any(|record| {
            event_digest.as_str() == record.canonical_digest
                && record.realm_id.as_deref() == Some(dependency.realm_id.as_str())
        });
        if !matches {
            return Err(PersistenceError::Conflict(
                "schema_violation: governance dependency source is not in Event batch".to_owned(),
            ));
        }
        crate::governance_history::stage_governance_dependency_exact(data, dependency)?;
    }
    Ok(())
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
        ids::validated_event_identity_parts_for_suite(
            &record.event_id,
            &record.canonical_digest,
            &record.canonical_bytes,
            record.digest_suite,
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
            (existing.peer_id == record.peer_id
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
    let by_digest =
        super::control_proposal_acks_by_digest(records, control_proposal_acks, acks_required)?;
    for record in records {
        let Some(ack) = by_digest.get(&record.canonical_digest) else {
            continue;
        };
        if let Some(existing) = staged.get(&record.canonical_digest)
            && existing != ack
        {
            return Err(PersistenceError::Conflict(
                "duplicate_conflict: Control Move has a different Control Proposal Ack".to_owned(),
            ));
        }
        staged.insert(record.canonical_digest.clone(), ack.clone());
    }
    Ok(())
}

#[async_trait]
impl EventStore for MemoryEventStore {
    async fn put(&self, record: CanonicalEventRecord) -> PersistenceResult<()> {
        ids::validated_event_identity_parts_for_suite(
            &record.event_id,
            &record.canonical_digest,
            &record.canonical_bytes,
            record.digest_suite,
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
        if record.kind == arkret_wire::event_kind_str::REALM_CREATE
            && record.realm_id.is_some()
            && data.values().any(|existing| {
                existing.kind == arkret_wire::event_kind_str::REALM_CREATE
                    && existing.realm_id == record.realm_id
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

    async fn membership_compensation_evidence(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Option<MembershipCompensationEvidenceRecord>> {
        ids::parse_event_id(event_id).ok_or_else(|| {
            PersistenceError::SchemaViolation(format!("malformed canonical Event id: {event_id:?}"))
        })?;
        Ok(self
            .membership_compensation_evidence
            .lock()
            .get(event_id)
            .cloned())
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
        governance_dependencies: Vec<soland_storage::GovernanceDependencyWrite>,
        outbox: Vec<FederationOutboxRecord>,
    ) -> PersistenceResult<soland_storage::RealmBootstrapCommitOutcome> {
        let mut data = self.data.lock();
        let mut quarantined = self.quarantined.lock();
        let mut variants = self.collision_variants.lock();
        let mut stored_control_proposal_acks = self.control_proposal_acks.lock();
        let mut projections = self.projections.lock();
        let mut event_outbox_ids = self.event_outbox_ids.lock();
        let mut federation_outbox = self.federation_outbox.lock();
        let mut stored_governance_dependencies = self.governance_dependencies.data.lock();
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
        let replay_count = records
            .iter()
            .filter(|record| {
                data.get(&record.event_id)
                    .is_some_and(|existing| existing.canonical_bytes == record.canonical_bytes)
            })
            .count();
        let outcome = if replay_count == 0 {
            soland_storage::RealmBootstrapCommitOutcome::Committed
        } else if replay_count == records.len() {
            soland_storage::RealmBootstrapCommitOutcome::ExactRetry {
                event_ids: event_ids.clone(),
            }
        } else {
            return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()));
        };
        let mut staged = data.clone();
        let mut staged_control_proposal_acks = stored_control_proposal_acks.clone();
        let mut staged_outbox = federation_outbox.clone();
        let mut staged_governance_dependencies = stored_governance_dependencies.clone();
        stage_control_proposal_acks(
            &mut staged_control_proposal_acks,
            &records,
            control_proposal_acks,
            true,
        )?;
        stage_event_batch_governance_dependencies(
            &mut staged_governance_dependencies,
            &records,
            &governance_dependencies,
        )?;
        stage_identity_anchor_events(&mut staged, records)?;
        let outbox_ids = stage_federation_outbox(&mut staged_outbox, outbox)?;
        *data = staged;
        *stored_control_proposal_acks = staged_control_proposal_acks;
        *federation_outbox = staged_outbox;
        *stored_governance_dependencies = staged_governance_dependencies;
        for event_id in event_ids {
            event_outbox_ids
                .entry(event_id)
                .or_default()
                .extend(outbox_ids.iter().cloned());
        }
        Ok(outcome)
    }

    async fn put_direct_conversation_founding_batch_atomic(
        &self,
        records: Vec<CanonicalEventRecord>,
        control_proposal_acks: Vec<arkret_wire::ControlProposalAck>,
        governance_dependencies: Vec<soland_storage::GovernanceDependencyWrite>,
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
        if records.len() != 4
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
        let mut stored_governance_dependencies = self.governance_dependencies.data.lock();
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
        let mut staged_governance_dependencies = stored_governance_dependencies.clone();
        stage_control_proposal_acks(&mut staged_acks, &records, control_proposal_acks, true)?;
        stage_event_batch_governance_dependencies(
            &mut staged_governance_dependencies,
            &records,
            &governance_dependencies,
        )?;
        stage_identity_anchor_events(&mut staged, records)?;
        let outbox_ids = stage_federation_outbox(&mut staged_outbox, outbox)?;
        slots.insert(key, slot);
        *data = staged;
        *stored_control_proposal_acks = staged_acks;
        *federation_outbox = staged_outbox;
        *stored_governance_dependencies = staged_governance_dependencies;
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
        governance_dependencies: Vec<soland_storage::GovernanceDependencyWrite>,
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
        let mut stored_governance_dependencies = self.governance_dependencies.data.lock();
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
        let mut staged_governance_dependencies = stored_governance_dependencies.clone();
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
            stage_event_batch_governance_dependencies(
                &mut staged_governance_dependencies,
                &records,
                &governance_dependencies,
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
                || staged_account_slots
                    .values()
                    .any(|existing| existing.account_id == slot.account_id && existing != &slot)
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
        *stored_governance_dependencies = staged_governance_dependencies;
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

    async fn identity_anchor_account_slot(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<IdentityAnchorAccountSlot>> {
        let matches = self
            .identity_anchor_account_slots
            .lock()
            .values()
            .filter(|slot| &slot.account_id == account_id)
            .cloned()
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [] => Ok(None),
            [slot] => Ok(Some(slot.clone())),
            _ => Err(PersistenceError::Conflict(
                "account has multiple identity-anchor account slots".to_owned(),
            )),
        }
    }

    async fn control_proposal_ack_for_digest(
        &self,
        proposal_digest: &str,
    ) -> PersistenceResult<Option<arkret_wire::ControlProposalAck>> {
        arkret_wire::Hash::new(proposal_digest.to_owned()).map_err(|error| {
            PersistenceError::SchemaViolation(format!("malformed Control Proposal digest: {error}"))
        })?;
        Ok(self
            .control_proposal_acks
            .lock()
            .get(proposal_digest)
            .cloned())
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

    async fn franking_proofs_for_target(
        &self,
        realm_id: &str,
        received_by: &arkret_wire::DidCoreId,
        target_event_id: &str,
    ) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let mut records = self
            .data
            .lock()
            .values()
            .filter(|record| {
                record.realm_id.as_deref() == Some(realm_id)
                    && record.actor_id == received_by.as_str()
                    && record.kind == arkret_wire::EventKind::ModerationFrankingProof.as_str()
                    && record
                        .envelope
                        .pointer("/payload/event_id")
                        .and_then(Value::as_str)
                        == Some(target_event_id)
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
    use arkret_wire::{AccountId, DidCoreId};
    use chrono::Utc;

    use super::*;

    fn account(principal: &str, station: &str) -> AccountId {
        AccountId::new(
            DidCoreId::new(principal).unwrap(),
            DidCoreId::new(station).unwrap(),
        )
    }

    fn account_slot(account_id: AccountId, suffix: &str) -> IdentityAnchorAccountSlot {
        IdentityAnchorAccountSlot {
            account_authority_id: format!("ak:did_core:web:authority-{suffix}.example"),
            account_subject: format!("subject-{suffix}"),
            account_id,
            realm_id: format!("ak:realm:{suffix}"),
            create_event_id: format!("ak:event:{suffix}"),
        }
    }

    #[tokio::test]
    async fn identity_anchor_slots_isolate_same_principal_at_different_stations() {
        let store = MemoryEventStore::with_devices(
            Arc::new(Mutex::new(BTreeMap::new())),
            Arc::new(Mutex::new(BTreeMap::new())),
            Arc::new(Mutex::new(BTreeMap::new())),
            Arc::new(Mutex::new(BTreeMap::new())),
            Arc::new(Mutex::new(Vec::new())),
            MemoryGovernanceDependencyStore::default(),
        );
        let first_account = account(
            "ak:did_core:web:shared-principal.example",
            "ak:did_core:web:station-a.example",
        );
        let second_account = account(
            "ak:did_core:web:shared-principal.example",
            "ak:did_core:web:station-b.example",
        );
        let first_slot = account_slot(first_account.clone(), "a");
        let second_slot = account_slot(second_account.clone(), "b");
        {
            let mut slots = store.identity_anchor_account_slots.lock();
            slots.insert(
                (
                    first_slot.account_authority_id.clone(),
                    first_slot.account_subject.clone(),
                ),
                first_slot.clone(),
            );
            slots.insert(
                (
                    second_slot.account_authority_id.clone(),
                    second_slot.account_subject.clone(),
                ),
                second_slot.clone(),
            );
        }

        assert_eq!(
            store
                .identity_anchor_account_slot(&first_account)
                .await
                .unwrap(),
            Some(first_slot)
        );
        assert_eq!(
            store
                .identity_anchor_account_slot(&second_account)
                .await
                .unwrap(),
            Some(second_slot)
        );
    }

    fn record(canonical_bytes: &[u8]) -> CanonicalEventRecord {
        let digest = arkret_canonical::sha256_bytes(canonical_bytes);
        let mut id = [0_u8; ids::EVENT_ID_BYTES];
        id[0] = 0x01;
        id[1..].copy_from_slice(&digest);
        let event_id = ids::format_event_id(&id);
        CanonicalEventRecord {
            event_id: event_id.clone(),
            actor_id: "ak:did_core:web:founder.example".to_owned(),
            actor_seq: 1,
            realm_id: Some("ak:realm:AYcO0aKZZvKELI-s58wUjRHsrz5v8Y51T0_sGUTciDVw".to_owned()),
            kind: "ak.realm.join_rule".to_owned(),
            schema_id: "arkret://events/realm/join-rule/v1".to_owned(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
            canonical_digest: ids::format_event_digest(0x01, &digest).unwrap(),
            canonical_bytes: canonical_bytes.to_vec(),
            envelope: serde_json::json!({"event_id": event_id}),
            received_at: Utc::now(),
        }
    }

    fn control_proposal_ack(record: &CanonicalEventRecord) -> arkret_wire::ControlProposalAck {
        let created_at = record.received_at;
        let policy = arkret_wire::ControlProposalDecisionPolicy::default();
        let mut authority_ack = arkret_wire::ControlProposalAuthorityAck {
            realm_id: arkret_wire::RealmId::new(record.realm_id.clone().unwrap()).unwrap(),
            proposal_digest: arkret_wire::Hash::new(record.canonical_digest.clone()).unwrap(),
            received_at: created_at,
            decision_due_at: created_at + policy.decision_window,
            absolute_due_at: created_at + policy.absolute_horizon,
            authority_set_ref: arkret_wire::Hash::new(format!("sha256:{}", "a".repeat(64)))
                .unwrap(),
            signature: arkret_wire::PayloadSignature {
                verification_method: arkret_wire::DidUrl::new(
                    "did:web:soland.example#authority-1".to_owned(),
                )
                .unwrap(),
                payload_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))
                    .unwrap(),
                created_at,
                jws: "e30..c2ln".to_owned(),
            },
        };
        authority_ack.signature.payload_digest = authority_ack.authority_ack_digest().unwrap();
        arkret_wire::ControlProposalAck::from_authority_acks(vec![authority_ack], policy).unwrap()
    }

    #[tokio::test]
    async fn batch_ack_storage_and_recovery_use_only_the_proposal_digest_key() {
        let record = record(b"control-proposal");
        let ack = control_proposal_ack(&record);
        let mut staged = BTreeMap::new();
        stage_control_proposal_acks(
            &mut staged,
            std::slice::from_ref(&record),
            vec![ack.clone()],
            true,
        )
        .unwrap();
        assert_eq!(staged.get(&record.canonical_digest), Some(&ack));
        assert!(!staged.contains_key(&record.event_id));

        let store = MemoryEventStore::with_devices(
            Arc::new(Mutex::new(BTreeMap::new())),
            Arc::new(Mutex::new(BTreeMap::new())),
            Arc::new(Mutex::new(BTreeMap::new())),
            Arc::new(Mutex::new(BTreeMap::new())),
            Arc::new(Mutex::new(Vec::new())),
            MemoryGovernanceDependencyStore::default(),
        );
        *store.control_proposal_acks.lock() = staged;
        assert_eq!(
            store
                .control_proposal_ack_for_digest(&record.canonical_digest)
                .await
                .unwrap(),
            Some(ack)
        );
        assert!(
            store
                .control_proposal_ack_for_digest(&record.event_id)
                .await
                .is_err(),
            "EventId lookup is not a compatibility path for a proposal digest"
        );
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
            MemoryGovernanceDependencyStore::default(),
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
                Vec::new(),
                vec![FederationOutboxRecord::pending(
                    "outbox:rollback".to_owned(),
                    DidCoreId::new("ak:did_core:web:peer.example").expect("peer service id"),
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
            MemoryGovernanceDependencyStore::default(),
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
                DidCoreId::new("ak:did_core:web:peer.example").expect("peer service id"),
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
            MemoryGovernanceDependencyStore::default(),
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
