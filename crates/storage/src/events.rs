use super::{
    BTreeMap, BTreeSet, CanonicalEventRecord, DeviceInventoryRecord, EventBatchReceipt,
    MessageRecord, PersistenceError, PersistenceResult, Value, async_trait,
};
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
/// Canonical event log keyed by `event_id`.
#[async_trait]
pub trait EventStore: Send + Sync {
    async fn put(&self, record: CanonicalEventRecord) -> PersistenceResult<()>;
    /// Commit one validated ordinary-Realm bootstrap unit. Implementations
    /// MUST insert every canonical Event in one transaction or insert none.
    async fn put_realm_bootstrap_batch_atomic(
        &self,
        records: Vec<CanonicalEventRecord>,
    ) -> PersistenceResult<()>;
    /// Commit the closed identity-anchor unit, its signed receipt (for
    /// re-anchor), and the replacement device projection as one durable unit.
    async fn put_identity_anchor_batch_atomic(
        &self,
        records: Vec<CanonicalEventRecord>,
        receipt: Option<EventBatchReceipt>,
        device: Option<DeviceInventoryRecord>,
        frontier_cas: Option<IdentityAnchorFrontierCas>,
        reanchor_slot: Option<IdentityAnchorReanchorSlot>,
    ) -> PersistenceResult<IdentityAnchorCommitOutcome>;
    async fn batch_receipts_for_event(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Vec<EventBatchReceipt>>;
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
        if let Some(existing) = staged.get(&record.event_id) {
            if existing.canonical_bytes == record.canonical_bytes {
                continue;
            }
            return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()));
        }
        if record.kind == arkret_core::events::EventKind::REALM_CREATE
            && record.realm_id.is_some()
            && staged.values().any(|existing| {
                existing.kind == arkret_core::events::EventKind::REALM_CREATE
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
#[doc(hidden)]
pub fn identity_anchor_slot_conflicts<'a>(
    records: impl IntoIterator<Item = &'a CanonicalEventRecord>,
    slot: &IdentityAnchorReanchorSlot,
) -> bool {
    records.into_iter().any(|record| {
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
                || record
                    .envelope
                    .pointer("/payload/replacement_authorize_digest")
                    .and_then(Value::as_str)
                    != Some(slot.authorize_digest.as_str()))
    })
}
#[doc(hidden)]
pub fn receipt_covers_event(receipt: &EventBatchReceipt, event_id: &str) -> bool {
    receipt.events.iter().any(|event| match event {
        arkret_core::EventBatchReceiptEvent::Item(item) => item.event_id.as_str() == event_id,
        arkret_core::EventBatchReceiptEvent::Digest(_) => false,
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
        arkret_core::events::EventKind::MEMBER_STATE
            | arkret_core::events::EventKind::CIRCLE_MEMBER_STATE
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
