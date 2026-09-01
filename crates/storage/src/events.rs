use super::{
    BTreeMap, BTreeSet, CanonicalEventRecord, DeviceInventoryRecord,
    DirectConversationFoundingCommitOutcome, DirectConversationFoundingSlotRecord,
    EventBatchReceipt, FederationOutboxRecord, MessageRecord, PersistenceError, PersistenceResult,
    PublicationEvidenceRecord, Value, async_trait,
};

/// Canonical transport-only evidence accepted with one membership
/// compensation Event. These bytes are not part of the Event envelope or
/// digest; they are retained separately so replay and federation can use the
/// exact evidence that passed admission.
#[derive(Clone, Debug, PartialEq)]
pub struct MembershipCompensationEvidenceRecord {
    pub event_id: String,
    pub event_digest: String,
    pub admission_id: String,
    pub delegation_digest: String,
    pub canonical_bytes: Vec<u8>,
    pub evidence: arkret_wire::MembershipCompensationSubmissionEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmBootstrapCommitOutcome {
    /// This transaction inserted the complete unit.
    Committed,
    /// Every Event identity already held the same canonical bytes. Storage
    /// still verifies the Ack, governance-dependency and outbox inputs
    /// idempotently before returning the original ordered identities.
    ExactRetry { event_ids: Vec<String> },
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
    /// Durable fanout intents atomically associated with one accepted Event.
    /// The join is authoritative for batch rows that cover multiple Events.
    async fn federation_outbox_for_event(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>>;
    /// Accepted membership-compensation transport evidence for one Event.
    async fn membership_compensation_evidence(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Option<MembershipCompensationEvidenceRecord>>;
    /// Commit one validated ordinary-Realm bootstrap unit. Implementations
    /// MUST insert every canonical Event **and every federation outbox row** in
    /// one transaction or insert none: an accepted Event whose delivery intent
    /// did not land is exactly the silent-loss window this unit exists to close.
    /// A batch with all Events already present byte-identically returns
    /// [`RealmBootstrapCommitOutcome::ExactRetry`]; a partial replay is a
    /// conflict and MUST NOT fill in the missing suffix.
    async fn put_realm_bootstrap_batch_atomic(
        &self,
        records: Vec<CanonicalEventRecord>,
        control_proposal_acks: Vec<arkret_wire::ControlProposalAck>,
        governance_dependencies: Vec<crate::GovernanceDependencyWrite>,
        outbox: Vec<FederationOutboxRecord>,
    ) -> PersistenceResult<RealmBootstrapCommitOutcome>;
    /// Commit the accepted Direct Conversation founding unit, its immutable slot, receipt bytes,
    /// Control Proposal Acks and peer delivery outbox in one transaction.
    async fn put_direct_conversation_founding_batch_atomic(
        &self,
        records: Vec<CanonicalEventRecord>,
        control_proposal_acks: Vec<arkret_wire::ControlProposalAck>,
        governance_dependencies: Vec<crate::GovernanceDependencyWrite>,
        slot: DirectConversationFoundingSlotRecord,
        outbox: Vec<FederationOutboxRecord>,
    ) -> PersistenceResult<DirectConversationFoundingCommitOutcome>;
    async fn direct_conversation_founding_slot(
        &self,
        founder_id: &str,
        trust_domain_id: &str,
        pair_key: &str,
    ) -> PersistenceResult<Option<DirectConversationFoundingSlotRecord>>;
    /// Commit the closed identity-anchor unit, its signed accepted-unit
    /// receipt, the device projection and its federation outbox rows as one
    /// durable unit. PCR genesis carries no Control Proposal Ack; an accepted
    /// re-anchor carries one Ack per Control Move.
    #[allow(clippy::too_many_arguments)]
    async fn put_identity_anchor_batch_atomic(
        &self,
        records: Vec<CanonicalEventRecord>,
        control_proposal_acks: Vec<arkret_wire::ControlProposalAck>,
        governance_dependencies: Vec<crate::GovernanceDependencyWrite>,
        receipt: Option<EventBatchReceipt>,
        device: Option<DeviceInventoryRecord>,
        account_slot: Option<IdentityAnchorAccountSlot>,
        frontier_cas: Option<IdentityAnchorFrontierCas>,
        reanchor_slot: Option<IdentityAnchorReanchorSlot>,
        publication_evidence: Vec<PublicationEvidenceRecord>,
        outbox: Vec<FederationOutboxRecord>,
    ) -> PersistenceResult<IdentityAnchorCommitOutcome>;
    async fn batch_receipts_for_event(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Vec<EventBatchReceipt>>;
    /// Accepted identity-anchor binding for one exact protocol Account.
    /// This is service-internal authority evidence and is never projected to
    /// holder sync as AccountData.
    async fn identity_anchor_account_slot(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<IdentityAnchorAccountSlot>>;
    /// Control Proposal Ack committed in the same durable unit as `proposal_digest`.
    ///
    /// This is the recovery source for adapters whose online control-event
    /// index is rebuilt after an ambiguous post-commit failure. PostgreSQL's
    /// control-event store is already the transactional source of truth, so
    /// adapters that do not maintain a separate index may use the default.
    async fn control_proposal_ack_for_digest(
        &self,
        _proposal_digest: &str,
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
    /// Indexed lookup for durable franking proof Events that bind one target.
    /// Callers still compare the complete typed payload before trusting a row.
    async fn franking_proofs_for_target(
        &self,
        realm_id: &str,
        received_by: &arkret_identifiers::DidCoreId,
        target_event_id: &str,
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

/// Durable account-scoped create-once slot for a principal-control Realm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityAnchorAccountSlot {
    pub account_authority_id: String,
    pub account_subject: String,
    pub account_id: arkret_wire::AccountId,
    pub realm_id: String,
    pub create_event_id: String,
}

#[derive(Clone, Debug)]
pub struct IdentityAnchorReanchorSlot {
    pub actor_id: String,
    pub station_id: String,
    pub new_device_generation: u64,
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
        crate::ids::validated_event_identity_parts_for_suite(
            &record.event_id,
            &record.canonical_digest,
            &record.canonical_bytes,
            record.digest_suite,
        )?;
        if let Some(existing) = staged.get(&record.event_id) {
            if existing.canonical_bytes == record.canonical_bytes {
                continue;
            }
            return Err(PersistenceError::Conflict(
                "event_hash_collision".to_owned(),
            ));
        }
        if record.kind == arkret_wire::EventKind::RealmCreate.as_str()
            && record.realm_id.is_some()
            && staged.values().any(|existing| {
                existing.kind == arkret_wire::EventKind::RealmCreate.as_str()
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
        candidate.kind == arkret_wire::EventKind::DeviceAuthorize.as_str()
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
        if record.actor_id != slot.actor_id
            || record.kind != arkret_wire::event_kind_str::DEVICE_REANCHOR
        {
            return false;
        }
        let Some(candidate_generation) = record
            .envelope
            .pointer("/payload/new_device_generation")
            .and_then(Value::as_u64)
        else {
            return false;
        };
        let candidate_station_id = record
            .envelope
            .pointer("/station_id")
            .and_then(Value::as_str);
        let same_slot = candidate_generation == slot.new_device_generation;
        same_slot
            && (candidate_station_id != Some(slot.station_id.as_str())
                || record.canonical_digest != slot.reanchor_digest
                || paired_replacement_authorize(record, records.iter().copied())
                    .map(|paired| paired.canonical_digest.as_str())
                    != Some(slot.authorize_digest.as_str()))
    })
}
#[doc(hidden)]
pub fn receipt_covers_event(receipt: &EventBatchReceipt, event_id: &str) -> bool {
    receipt
        .events
        .iter()
        .any(|event| event.event_id.as_str() == event_id)
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
        arkret_wire::EventKind::from_wire(&record.kind),
        arkret_wire::EventKind::MemberState
            | arkret_wire::EventKind::CircleMemberState
            | arkret_wire::EventKind::InviteCreate
            | arkret_wire::EventKind::InviteAccept
    )
}
