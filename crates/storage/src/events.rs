use super::{
    BTreeMap, CanonicalEventRecord, DeviceInventoryRecord, DirectConversationFoundingCommitOutcome,
    DirectConversationFoundingSlotRecord, EventBatchReceipt, FederationOutboxRecord, MessageRecord,
    PersistenceError, PersistenceResult, PublicationEvidenceRecord, Value, async_trait,
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
    pub delegation_id: String,
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

/// Validate the storage-neutral binding of one Control Proposal Ack to the
/// canonical Event record committed in the same atomic unit.
pub fn validate_control_proposal_ack_binding(
    record: &CanonicalEventRecord,
    ack: &arkret_wire::ControlProposalAck,
) -> PersistenceResult<()> {
    ack.validate_protocol_bounds().map_err(|error| {
        PersistenceError::Conflict(format!(
            "schema_violation: invalid Control Proposal Ack: {error}"
        ))
    })?;
    if ack.proposal_digest.as_str() != record.canonical_digest
        || record.realm_id.as_deref() != Some(ack.realm_id.as_str())
    {
        return Err(PersistenceError::Conflict(
            "schema_violation: Control Proposal Ack does not bind Control Move".to_owned(),
        ));
    }
    Ok(())
}

/// Validate and index the complete Ack set for an atomic Control Move unit.
///
/// The returned map is keyed only by canonical proposal digest. Adapters add
/// their own persistence conflict checks after this shared preflight.
pub fn control_proposal_acks_by_digest(
    records: &[CanonicalEventRecord],
    control_proposal_acks: Vec<arkret_wire::ControlProposalAck>,
    acks_required: bool,
) -> PersistenceResult<BTreeMap<String, arkret_wire::ControlProposalAck>> {
    if control_proposal_acks.is_empty() && !acks_required {
        return Ok(BTreeMap::new());
    }
    if control_proposal_acks.len() != records.len() {
        return Err(PersistenceError::Conflict(
            "schema_violation: Control Proposal Ack cardinality mismatch".to_owned(),
        ));
    }
    let mut by_digest = BTreeMap::new();
    for ack in control_proposal_acks {
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
        validate_control_proposal_ack_binding(record, ack)?;
    }
    Ok(by_digest)
}

#[cfg(test)]
mod control_proposal_ack_tests {
    use super::*;

    fn record(canonical_bytes: &[u8]) -> CanonicalEventRecord {
        let digest = arkret_canonical::sha256_bytes(canonical_bytes);
        let mut id = [0_u8; crate::ids::EVENT_ID_BYTES];
        id[0] = 0x01;
        id[1..].copy_from_slice(&digest);
        CanonicalEventRecord {
            event_id: crate::ids::format_event_id(&id),
            actor_id: "ak:did_core:web:founder.example".to_owned(),
            actor_seq: 1,
            realm_id: Some("ak:realm:AYcO0aKZZvKELI-s58wUjRHsrz5v8Y51T0_sGUTciDVw".to_owned()),
            kind: "ak.realm.join_rule".to_owned(),
            schema_id: "arkret://events/realm/join-rule/v1".to_owned(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
            canonical_digest: crate::ids::format_event_digest(0x01, &digest).unwrap(),
            canonical_bytes: canonical_bytes.to_vec(),
            envelope: serde_json::json!({}),
            received_at: chrono::Utc::now(),
        }
    }

    fn ack(record: &CanonicalEventRecord) -> arkret_wire::ControlProposalAck {
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

    #[test]
    fn complete_ack_set_is_indexed_only_by_proposal_digest() {
        let record = record(b"one");
        let ack = ack(&record);
        let indexed =
            control_proposal_acks_by_digest(std::slice::from_ref(&record), vec![ack.clone()], true)
                .unwrap();
        assert_eq!(indexed.get(&record.canonical_digest), Some(&ack));
        assert!(!indexed.contains_key(&record.event_id));
    }

    #[test]
    fn incomplete_duplicate_and_cross_realm_ack_sets_fail_closed() {
        let first = record(b"one");
        let second = record(b"two");
        let first_ack = ack(&first);
        assert!(
            control_proposal_acks_by_digest(
                &[first.clone(), second.clone()],
                vec![first_ack.clone()],
                true,
            )
            .is_err()
        );
        assert!(
            control_proposal_acks_by_digest(
                &[first.clone(), second],
                vec![first_ack.clone(), first_ack.clone()],
                true,
            )
            .is_err()
        );

        let mut wrong_realm = first_ack;
        wrong_realm.realm_id = arkret_wire::RealmId::new(
            "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K".to_owned(),
        )
        .unwrap();
        assert!(control_proposal_acks_by_digest(&[first], vec![wrong_realm], true).is_err());
    }

    #[test]
    fn optional_empty_ack_set_is_valid() {
        let record = record(b"ackless");
        assert!(
            control_proposal_acks_by_digest(&[record], Vec::new(), false)
                .unwrap()
                .is_empty()
        );
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
    /// Durable fanout intents atomically associated with one accepted Event.
    /// The join is authoritative for batch rows that cover multiple Events.
    async fn federation_outbox_for_event(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>>;
    /// Accepted membership-compensation transport evidence for one Event.
    async fn mls_frontier_leaves(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Option<Vec<arkret_wire::mls_transition::MlsSecurityFrontierLeaf>>>;
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
    /// Whether this Station holds any position at all for one
    /// `(realm_id, actor_id)`, in every state.
    ///
    /// `sync/federation.md` section 5.3.4 condition 3: the enumeration behind a
    /// decidable empty actor frontier MUST cover pending outbound, submitted
    /// but undecided, accepted, quarantined and fork-resolution voided
    /// positions. It therefore reads the raw event table plus the fork
    /// normalization ledger, never the accepted-only view: a quarantined or
    /// adjudicated-loser Event still occupies its sequence, and a normalization
    /// row can name a position whose winning Event this Station never held.
    async fn realm_actor_position_occupied(
        &self,
        realm_id: &str,
        actor_id: &str,
    ) -> PersistenceResult<bool>;
    /// Accepted siblings at one exact Realm/actor sequence position. The
    /// caller supplies a small hard ceiling so over-fork detection never
    /// degenerates into an actor-history scan.
    async fn list_at_realm_actor_position(
        &self,
        realm_id: &str,
        actor_id: &str,
        actor_seq: u64,
        limit: usize,
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
