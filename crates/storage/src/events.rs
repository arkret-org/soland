use arkret_models_collaboration::contact_operations::{
    DeviceBootstrapDecision, DeviceBootstrapDecisionRecord, DeviceBootstrapDecisionRequestBody,
};

use super::{
    BTreeMap, BTreeSet, CanonicalEventRecord, DeviceInventoryRecord,
    DirectConversationFoundingCommitOutcome, DirectConversationFoundingSlotRecord,
    EventBatchReceipt, FederationOutboxRecord, MessageRecord, PersistenceError, PersistenceResult,
    PublicationEvidenceRecord, Value, async_trait,
};

/// True when two authority rows describe the same accepted founding unit.
///
/// Receipt ids, timestamps, signatures, and encoded outcomes are deliberately
/// excluded: two Principal Server processes may prepare those independently
/// before the unique decision fence chooses one durable receipt.
pub fn same_accepted_device_bootstrap_binding(
    existing: &DeviceBootstrapDecisionRecord,
    candidate: &DeviceBootstrapDecisionRecord,
) -> bool {
    let left = &existing.receipt;
    let right = &candidate.receipt;
    existing.decision == DeviceBootstrapDecision::Accepted
        && candidate.decision == DeviceBootstrapDecision::Accepted
        && existing.account_authority_id == candidate.account_authority_id
        && existing.transaction_id == candidate.transaction_id
        && existing.binding_digest == candidate.binding_digest
        && left.principal_server_id == right.principal_server_id
        && left.account_authority_id == right.account_authority_id
        && left.transaction_id == right.transaction_id
        && left.principal_id == right.principal_id
        && left.device_id == right.device_id
        && left.grant_id == right.grant_id
        && left.canonical_request_digest == right.canonical_request_digest
        && left.founding_event_ids == right.founding_event_ids
        && left.founding_batch_digest == right.founding_batch_digest
        && left.bootstrap_transaction_expires_at == right.bootstrap_transaction_expires_at
}

/// Closed receipt-time rule for the three terminal decisions. Database time
/// separately decides whether a first write is currently eligible.
pub fn device_bootstrap_receipt_time_is_valid(record: &DeviceBootstrapDecisionRecord) -> bool {
    match record.decision {
        DeviceBootstrapDecision::Accepted => {
            record.receipt.decided_at <= record.receipt.bootstrap_transaction_expires_at
        }
        DeviceBootstrapDecision::Cancelled => {
            record.receipt.decided_at < record.receipt.bootstrap_transaction_expires_at
        }
        DeviceBootstrapDecision::Expired => {
            record.receipt.decided_at >= record.receipt.bootstrap_transaction_expires_at
        }
    }
}
/// Trait for message storage operations.
#[async_trait]
pub trait MessageStore: Send + Sync {
    async fn get(&self, event_id: &str) -> PersistenceResult<Option<MessageRecord>>;
    async fn put(&self, record: &MessageRecord) -> PersistenceResult<()>;
    async fn list_for_realm(
        &self,
        realm_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<MessageRecord>>;
    async fn list_for_thread(
        &self,
        thread_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<MessageRecord>>;
    async fn delete(&self, event_id: &str) -> PersistenceResult<()>;
}
/// Canonical Event log keyed by the 33-byte Event id, which losslessly encodes
/// the full `(digest_suite, digest)` identity. Implementations must never
/// overwrite a row when identical digest bytes bind different digest-preimage
/// canonical bytes. Envelope-only proof/unsigned differences are not hash
/// collisions and must be handled by admission proof validation.
#[async_trait]
pub trait EventStore: Send + Sync {
    async fn put(&self, record: CanonicalEventRecord) -> PersistenceResult<()>;
    /// Full forensic evidence for an Event identity that was quarantined after
    /// two distinct canonical byte strings claimed the same full hash.
    /// Ordinary Event reads MUST exclude these records.
    async fn collision_variants(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Vec<CanonicalEventRecord>>;
    /// Commit one validated ordinary-Realm bootstrap unit. Implementations
    /// MUST insert every canonical Event **and every federation outbox row** in
    /// one transaction or insert none: an accepted Event whose delivery intent
    /// did not land is exactly the silent-loss window this unit exists to close.
    async fn put_realm_bootstrap_batch_atomic(
        &self,
        records: Vec<CanonicalEventRecord>,
        control_proposal_acks: Vec<arkret_wire::ControlProposalAck>,
        outbox: Vec<FederationOutboxRecord>,
    ) -> PersistenceResult<()>;
    /// Commit the accepted Direct Conversation founding unit, its immutable slot, receipt bytes,
    /// Control Proposal Acks and peer delivery outbox in one transaction.
    async fn put_direct_conversation_founding_batch_atomic(
        &self,
        records: Vec<CanonicalEventRecord>,
        control_proposal_acks: Vec<arkret_wire::ControlProposalAck>,
        slot: DirectConversationFoundingSlotRecord,
        outbox: Vec<FederationOutboxRecord>,
    ) -> PersistenceResult<DirectConversationFoundingCommitOutcome>;
    async fn direct_conversation_founding_slot(
        &self,
        founder_id: &str,
        trust_domain_id: &str,
        pair_key: &str,
    ) -> PersistenceResult<Option<DirectConversationFoundingSlotRecord>>;
    /// Commit the closed identity-anchor unit, its signed receipt (for
    /// re-anchor), the replacement device projection and its federation outbox
    /// rows as one durable unit.
    #[allow(clippy::too_many_arguments)]
    async fn put_identity_anchor_batch_atomic(
        &self,
        records: Vec<CanonicalEventRecord>,
        control_proposal_acks: Vec<arkret_wire::ControlProposalAck>,
        receipt: Option<EventBatchReceipt>,
        device: Option<DeviceInventoryRecord>,
        frontier_cas: Option<IdentityAnchorFrontierCas>,
        reanchor_slot: Option<IdentityAnchorReanchorSlot>,
        publication_evidence: Vec<PublicationEvidenceRecord>,
        outbox: Vec<FederationOutboxRecord>,
        bootstrap_decision: Option<DeviceBootstrapDecisionRecord>,
    ) -> PersistenceResult<IdentityAnchorCommitOutcome>;
    /// Read the immutable Principal-Server decision authority row. Absence is
    /// the only representation of an undecided founding bootstrap.
    async fn device_bootstrap_decision(
        &self,
        account_authority_id: &str,
        transaction_id: &str,
    ) -> PersistenceResult<Option<DeviceBootstrapDecisionRecord>>;
    /// Atomically install a cancelled/expired tombstone, or return the row that
    /// won the same unique fence. Implementations must never update a row.
    async fn put_device_bootstrap_decision_atomic(
        &self,
        request: &DeviceBootstrapDecisionRequestBody,
        record: DeviceBootstrapDecisionRecord,
    ) -> PersistenceResult<DeviceBootstrapDecisionWriteOutcome>;
    async fn batch_receipts_for_event(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Vec<EventBatchReceipt>>;
    /// Control Proposal Ack committed in the same durable unit as `event_id`.
    ///
    /// This is the recovery source for adapters whose online control-event
    /// index is rebuilt after an ambiguous post-commit failure. PostgreSQL's
    /// control-event store is already the transactional source of truth, so
    /// adapters that do not maintain a separate index may use the default.
    async fn control_proposal_ack_for_event(
        &self,
        _event_id: &str,
    ) -> PersistenceResult<Option<arkret_wire::ControlProposalAck>> {
        Ok(None)
    }
    async fn get(&self, event_id: &str) -> PersistenceResult<Option<CanonicalEventRecord>>;
    async fn contains(&self, event_id: &str) -> PersistenceResult<bool>;
    async fn max_actor_seq(&self, actor_id: &str) -> PersistenceResult<Option<u64>>;
    async fn list_for_actor(&self, actor_id: &str) -> PersistenceResult<Vec<CanonicalEventRecord>>;
    /// Accepted records for one Realm-scoped actor chain, ordered by
    /// `(actor_seq, event_id)`. Frontier producers and admission use this same
    /// typed source instead of filtering a full-store snapshot.
    async fn list_for_realm_actor(
        &self,
        realm_id: &str,
        actor_id: &str,
    ) -> PersistenceResult<Vec<CanonicalEventRecord>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<CanonicalEventRecord>>;
    /// Cheap Realm-local cardinality/byte preflight for bounded proof
    /// materialization. Implementations must not load Event envelopes.
    async fn realm_event_stats(&self, realm_id: &str) -> PersistenceResult<RealmEventStats>;
    async fn peer_authz_state_records(&self) -> PersistenceResult<Vec<CanonicalEventRecord>>;
    async fn peer_events_query_page(
        &self,
        query: &PeerEventsPageQuery,
    ) -> PersistenceResult<Vec<CanonicalEventRecord>>;
    /// Events for a single Realm, newest first. Pushes the `realm_id` filter
    /// and `received_at DESC` ordering into the query so hot-path latest-policy
    /// lookups do not full-scan the whole `canonical_events` table.
    async fn realm_events_newest_first(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<CanonicalEventRecord>>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RealmEventStats {
    pub count: u64,
    pub canonical_bytes: u64,
}
#[derive(Clone, Debug)]
pub struct IdentityAnchorFrontierCas {
    pub realm_id: String,
    pub raw_leaves: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeviceBootstrapDecisionWriteOutcome {
    Inserted,
    Existing(DeviceBootstrapDecisionRecord),
}
#[derive(Clone, Debug)]
pub struct IdentityAnchorReanchorSlot {
    pub actor_id: String,
    pub version_number: u64,
    pub did_version_id: String,
    pub reanchor_digest: String,
    pub authorize_digest: String,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IdentityAnchorCommitOutcome {
    pub reanchor_conflict: bool,
}
#[derive(Clone, Debug)]
pub struct PeerEventsPageQuery {
    pub realms: Vec<String>,
    pub actors: Vec<String>,
    pub kind_filter: Option<String>,
    pub cursor_event_id: Option<String>,
    pub backward: bool,
    pub limit: usize,
}
#[doc(hidden)]
pub fn stage_identity_anchor_events(
    staged: &mut BTreeMap<String, CanonicalEventRecord>,
    records: Vec<CanonicalEventRecord>,
) -> PersistenceResult<()> {
    for record in records {
        crate::ids::validated_event_identity_parts(
            &record.event_id,
            &record.canonical_digest,
            &record.canonical_bytes,
        )?;
        if let Some(existing) = staged.get(&record.event_id) {
            if existing.canonical_bytes == record.canonical_bytes {
                continue;
            }
            return Err(PersistenceError::Conflict(
                "event_hash_collision".to_owned(),
            ));
        }
        if record.kind == arkret_wire::EventKind::REALM_CREATE
            && record.realm_id.is_some()
            && staged.values().any(|existing| {
                existing.kind == arkret_wire::EventKind::REALM_CREATE
                    && existing.realm_id == record.realm_id
            })
        {
            return Err(PersistenceError::Conflict(
                "realm_already_exists".to_owned(),
            ));
        }
        staged.insert(record.event_id.clone(), record);
    }
    Ok(())
}
/// Locate the replacement `ak.device.authorize` that belongs to one accepted
/// re-anchor.
///
/// The pairing lives in the authorize envelope: its `prev_refs` is exactly the
/// re-anchor id (`key-management.md` §5.0.7). The re-anchor payload commits
/// only to the authorize *payload* digest, because the authorize envelope
/// already names the re-anchor and every `event_id` derives from its own
/// signed content — an id or envelope-digest binding would make the two Events
/// preimages of each other.
#[doc(hidden)]
pub fn paired_replacement_authorize<'a>(
    reanchor: &CanonicalEventRecord,
    records: impl IntoIterator<Item = &'a CanonicalEventRecord>,
) -> Option<&'a CanonicalEventRecord> {
    records.into_iter().find(|candidate| {
        candidate.kind == arkret_wire::EventKind::DEVICE_AUTHORIZE
            && candidate.actor_id == reanchor.actor_id
            && candidate
                .envelope
                .pointer("/prev_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| {
                    refs.len() == 1 && refs[0].as_str() == Some(reanchor.event_id.as_str())
                })
    })
}

/// Does the accepted history already hold a different unit in this re-anchor
/// slot?
///
/// `records` MUST carry the actor's `ak.device.authorize` Events as well as the
/// re-anchors: the replacement digest comparison reads the paired authorize
/// Event, not a payload claim.
#[doc(hidden)]
pub fn identity_anchor_slot_conflicts(
    records: &[&CanonicalEventRecord],
    slot: &IdentityAnchorReanchorSlot,
) -> bool {
    records.iter().any(|record| {
        if record.actor_id != slot.actor_id || record.kind != "ak.device.reanchor" {
            return false;
        }
        let Some(candidate_version) = record
            .envelope
            .pointer("/payload/did_version_id")
            .and_then(Value::as_str)
        else {
            return false;
        };
        let same_slot = candidate_version
            .split_once('-')
            .and_then(|(number, _)| number.parse::<u64>().ok())
            == Some(slot.version_number);
        same_slot
            && (candidate_version != slot.did_version_id
                || record.canonical_digest != slot.reanchor_digest
                || paired_replacement_authorize(record, records.iter().copied())
                    .map(|paired| paired.canonical_digest.as_str())
                    != Some(slot.authorize_digest.as_str()))
    })
}
#[doc(hidden)]
pub fn receipt_covers_event(receipt: &EventBatchReceipt, event_id: &str) -> bool {
    receipt.events.iter().any(|event| match event {
        arkret_wire::EventBatchReceiptEvent::Item(item) => item.event_id.as_str() == event_id,
        arkret_wire::EventBatchReceiptEvent::Digest(_) => false,
    })
}
#[doc(hidden)]
pub fn event_position_cmp(
    left: &CanonicalEventRecord,
    right: &CanonicalEventRecord,
) -> std::cmp::Ordering {
    left.received_at
        .cmp(&right.received_at)
        .then_with(|| left.event_id.cmp(&right.event_id))
}
#[doc(hidden)]
pub fn peer_page_record_after_cursor(
    record: &CanonicalEventRecord,
    cursor: Option<&CanonicalEventRecord>,
    backward: bool,
) -> bool {
    let Some(cursor) = cursor else {
        return true;
    };
    let order = event_position_cmp(record, cursor);
    if backward {
        order.is_lt()
    } else {
        order.is_gt()
    }
}
#[doc(hidden)]
pub fn peer_page_record_matches(
    record: &CanonicalEventRecord,
    realms: &BTreeSet<&str>,
    actors: &BTreeSet<&str>,
    kind_filter: Option<&str>,
) -> bool {
    if let Some(kind) = kind_filter
        && record.kind != kind
    {
        return false;
    }
    let realm_match = realms.is_empty()
        || record
            .realm_id
            .as_deref()
            .is_some_and(|realm_id| realms.contains(realm_id));
    let actor_match = actors.is_empty() || actors.contains(record.actor_id.as_str());
    realm_match && actor_match
}
#[doc(hidden)]
pub fn record_is_peer_authz_state_record(record: &CanonicalEventRecord) -> bool {
    matches!(
        record.kind.as_str(),
        arkret_wire::EventKind::MEMBER_STATE
            | arkret_wire::EventKind::CIRCLE_MEMBER_STATE
            | arkret_wire::EventKind::INVITE_CREATE
            | arkret_wire::EventKind::INVITE_ACCEPT
    ) || event_payload_field(&record.envelope, "sync_endpoints").is_some()
}
#[doc(hidden)]
pub fn event_payload_field<'a>(envelope: &'a Value, field: &str) -> Option<&'a Value> {
    let payload = envelope.get("payload")?;
    payload
        .get(field)
        .or_else(|| payload.get("object").and_then(|object| object.get(field)))
        .or_else(|| payload.get("patch").and_then(|patch| patch.get(field)))
}
