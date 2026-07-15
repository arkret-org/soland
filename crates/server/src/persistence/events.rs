use super::*;

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
    async fn snapshot_all(&self) -> PersistenceResult<Vec<CanonicalEventRecord>>;
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
    data: Mutex<BTreeMap<String, CanonicalEventRecord>>,
    devices: Arc<Mutex<BTreeMap<(String, String), DeviceInventoryRecord>>>,
    receipts: Mutex<BTreeMap<String, EventBatchReceipt>>,
}

impl MemoryEventStore {
    pub(crate) fn new() -> Self {
        Self::with_devices(Arc::new(Mutex::new(BTreeMap::new())))
    }

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

fn stage_identity_anchor_events(
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
        if record.kind == arkret_sdk::events::kinds::REALM_CREATE
            && record.realm_id.is_some()
            && staged.values().any(|existing| {
                existing.kind == arkret_sdk::events::kinds::REALM_CREATE
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

fn identity_anchor_slot_conflicts<'a>(
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

fn receipt_covers_event(receipt: &EventBatchReceipt, event_id: &str) -> bool {
    receipt.events.iter().any(|event| match event {
        arkret_sdk::EventBatchReceiptEvent::Event(id) => id.as_str() == event_id,
        arkret_sdk::EventBatchReceiptEvent::Item(item) => item.event_id.as_str() == event_id,
        arkret_sdk::EventBatchReceiptEvent::Digest(_) => false,
    })
}

fn event_position_cmp(
    left: &CanonicalEventRecord,
    right: &CanonicalEventRecord,
) -> std::cmp::Ordering {
    left.received_at
        .cmp(&right.received_at)
        .then_with(|| left.event_id.cmp(&right.event_id))
}

fn peer_page_record_after_cursor(
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

fn peer_page_record_matches(
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

fn record_is_peer_authz_state_record(record: &CanonicalEventRecord) -> bool {
    matches!(
        record.kind.as_str(),
        arkret_sdk::events::kinds::MEMBER_STATE | arkret_sdk::events::kinds::CIRCLE_MEMBER_STATE
    ) || event_payload_field(&record.envelope, "sync_endpoints").is_some()
}

fn event_payload_field<'a>(envelope: &'a Value, field: &str) -> Option<&'a Value> {
    let payload = envelope.get("payload")?;
    payload
        .get(field)
        .or_else(|| payload.get("object").and_then(|object| object.get(field)))
        .or_else(|| payload.get("patch").and_then(|patch| patch.get(field)))
}

pub(crate) struct PgEventStore {
    pub(crate) pool: PgPool,
}

fn map_canonical_event_put_error(error: diesel::result::Error) -> PersistenceError {
    use diesel::result::{DatabaseErrorKind, Error as DieselError};
    if let DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, info) = &error
        && info.constraint_name() == Some("canonical_events_realm_create_unique_idx")
    {
        return PersistenceError::Conflict("realm_already_exists".to_owned());
    }
    if let DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, info) = &error
        && info.constraint_name() == Some("canonical_events_pkey")
    {
        return PersistenceError::Conflict("duplicate_conflict".to_owned());
    }
    PersistenceError::from(error)
}

#[derive(QueryableByName)]
struct CanonicalEventRow {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = Text)]
    actor_id: String,
    #[diesel(sql_type = BigInt)]
    actor_seq: i64,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    realm_id: Option<Uuid>,
    #[diesel(sql_type = Text)]
    kind: String,
    #[diesel(sql_type = Text)]
    schema_id: String,
    #[diesel(sql_type = Text)]
    canonical_digest: String,
    #[diesel(sql_type = Binary)]
    canonical_bytes: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Timestamptz)]
    received_at: chrono::DateTime<chrono::Utc>,
}

#[derive(QueryableByName)]
struct EventBatchReceiptRow {
    #[diesel(sql_type = Text)]
    schema: String,
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = Text)]
    issuer: String,
    #[diesel(sql_type = Jsonb)]
    scope: Value,
    #[diesel(sql_type = Jsonb)]
    frontier: Value,
    #[diesel(sql_type = Jsonb)]
    events: Value,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Jsonb)]
    proofs: Value,
}

#[derive(QueryableByName)]
struct SealLeafIdRow {
    #[diesel(sql_type = Text)]
    id: String,
}

impl TryFrom<EventBatchReceiptRow> for EventBatchReceipt {
    type Error = PersistenceError;

    fn try_from(row: EventBatchReceiptRow) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::json!({
            "schema": row.schema,
            "receipt_id": ids::format_typed_uuid("receipt", &row.id),
            "issuer": row.issuer,
            "scope": row.scope,
            "frontier": row.frontier,
            "events": row.events,
            "created_at": row.created_at,
            "proofs": row.proofs,
        }))
        .map_err(|error| {
            PersistenceError::Internal(format!("stored Event Batch Receipt is invalid: {error}"))
        })
    }
}

async fn insert_canonical_event(
    conn: &mut AsyncPgConnection,
    record: &CanonicalEventRecord,
) -> PersistenceResult<()> {
    let event_id_uuid = ids::typed_uuid_part_expect_internal(&record.event_id);
    let realm_id_uuid = record
        .realm_id
        .as_deref()
        .map(ids::typed_uuid_part_expect_internal);
    sql_query(
        "INSERT INTO canonical_events \
         (id, actor_id, actor_seq, realm_id, kind, schema_id, canonical_digest, canonical_bytes, envelope, received_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind::<SqlUuid, _>(event_id_uuid)
    .bind::<Text, _>(&record.actor_id)
    .bind::<BigInt, _>(record.actor_seq as i64)
    .bind::<Nullable<SqlUuid>, _>(realm_id_uuid)
    .bind::<Text, _>(&record.kind)
    .bind::<Text, _>(&record.schema_id)
    .bind::<Text, _>(&record.canonical_digest)
    .bind::<Binary, _>(&record.canonical_bytes)
    .bind::<Jsonb, _>(&record.envelope)
    .bind::<Timestamptz, _>(record.received_at)
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(map_canonical_event_put_error)
}

async fn assert_identity_anchor_frontier(
    conn: &mut AsyncPgConnection,
    expected: &IdentityAnchorFrontierCas,
) -> PersistenceResult<()> {
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind::<Text, _>(&expected.realm_id)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
    sql_query("LOCK TABLE state_seals IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
    let rows = sql_query(
        "SELECT candidate.id \
         FROM state_seals candidate \
         WHERE candidate.realm_id = $1 \
           AND NOT EXISTS ( \
             SELECT 1 FROM state_seals successor \
             WHERE successor.realm_id = candidate.realm_id \
               AND successor.predecessor_refs @> to_jsonb(ARRAY[candidate.id]::text[]) \
           ) \
         ORDER BY candidate.id",
    )
    .bind::<Text, _>(&expected.realm_id)
    .load::<SealLeafIdRow>(&mut *conn)
    .await
    .map_err(PersistenceError::from)?;
    let actual = rows.into_iter().map(|row| row.id).collect::<Vec<_>>();
    let mut raw_declared = expected.raw_leaves.clone();
    raw_declared.sort_unstable();
    if actual != raw_declared {
        return Err(PersistenceError::Conflict(
            "device_reanchor_frontier_mismatch".to_owned(),
        ));
    }
    Ok(())
}

async fn insert_event_batch_receipt(
    conn: &mut AsyncPgConnection,
    receipt: &EventBatchReceipt,
) -> PersistenceResult<()> {
    let scope = serde_json::to_value(&receipt.scope).map_err(|error| {
        PersistenceError::Internal(format!("Event Batch Receipt scope encode failed: {error}"))
    })?;
    let frontier = serde_json::to_value(&receipt.frontier).map_err(|error| {
        PersistenceError::Internal(format!(
            "Event Batch Receipt frontier encode failed: {error}"
        ))
    })?;
    let events = serde_json::to_value(&receipt.events).map_err(|error| {
        PersistenceError::Internal(format!("Event Batch Receipt events encode failed: {error}"))
    })?;
    let proofs = serde_json::to_value(&receipt.proofs).map_err(|error| {
        PersistenceError::Internal(format!("Event Batch Receipt proofs encode failed: {error}"))
    })?;
    let event_ids = receipt
        .events
        .iter()
        .filter_map(|event| match event {
            arkret_sdk::EventBatchReceiptEvent::Event(id) => Some(id.as_str()),
            arkret_sdk::EventBatchReceiptEvent::Item(item) => Some(item.event_id.as_str()),
            arkret_sdk::EventBatchReceiptEvent::Digest(_) => None,
        })
        .map(ids::typed_uuid_part_expect_internal)
        .collect::<Vec<_>>();
    sql_query(
        "INSERT INTO event_batch_receipts \
         (schema, id, issuer, scope, frontier, events, created_at, proofs, event_ids) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind::<Text, _>(&receipt.schema)
    .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(
        receipt.receipt_id.as_str(),
    ))
    .bind::<Text, _>(receipt.issuer.as_str())
    .bind::<Jsonb, _>(scope)
    .bind::<Jsonb, _>(frontier)
    .bind::<Jsonb, _>(events)
    .bind::<Timestamptz, _>(receipt.created_at)
    .bind::<Jsonb, _>(proofs)
    .bind::<Array<SqlUuid>, _>(event_ids)
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(PersistenceError::from)
}

impl From<CanonicalEventRow> for CanonicalEventRecord {
    fn from(row: CanonicalEventRow) -> Self {
        Self {
            event_id: ids::format_typed_uuid("event", &row.id),
            actor_id: row.actor_id,
            actor_seq: row.actor_seq.max(0) as u64,
            realm_id: row
                .realm_id
                .as_ref()
                .map(|u| ids::format_typed_uuid("realm", u)),
            kind: row.kind,
            schema_id: row.schema_id,
            canonical_digest: row.canonical_digest,
            canonical_bytes: row.canonical_bytes,
            envelope: row.envelope,
            received_at: row.received_at,
        }
    }
}

#[async_trait]
impl EventStore for PgEventStore {
    async fn put(&self, record: CanonicalEventRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let event_id_uuid = ids::typed_uuid_part_expect_internal(&record.event_id);
        let realm_id_uuid: Option<Uuid> = record
            .realm_id
            .as_deref()
            .map(ids::typed_uuid_part_expect_internal);
        sql_query(
            "INSERT INTO canonical_events \
             (id, actor_id, actor_seq, realm_id, kind, schema_id, canonical_digest, canonical_bytes, envelope, received_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(event_id_uuid)
        .bind::<Text, _>(&record.actor_id)
        .bind::<BigInt, _>(record.actor_seq as i64)
        .bind::<Nullable<SqlUuid>, _>(realm_id_uuid)
        .bind::<Text, _>(&record.kind)
        .bind::<Text, _>(&record.schema_id)
        .bind::<Text, _>(&record.canonical_digest)
        .bind::<Binary, _>(&record.canonical_bytes)
        .bind::<Jsonb, _>(&record.envelope)
        .bind::<Timestamptz, _>(record.received_at)
        .execute(&mut *conn).await
        .map(|_| ())
        .map_err(map_canonical_event_put_error)
    }

    async fn put_identity_anchor_batch_atomic(
        &self,
        records: Vec<CanonicalEventRecord>,
        receipt: Option<EventBatchReceipt>,
        device: Option<DeviceInventoryRecord>,
        frontier_cas: Option<IdentityAnchorFrontierCas>,
        reanchor_slot: Option<IdentityAnchorReanchorSlot>,
    ) -> PersistenceResult<IdentityAnchorCommitOutcome> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PersistenceError, _>(async move |conn| {
                let reanchor_conflict = if let Some(slot) = reanchor_slot.as_ref() {
                    sql_query("LOCK TABLE canonical_events IN SHARE ROW EXCLUSIVE MODE")
                        .execute(&mut *conn)
                        .await
                        .map_err(PersistenceError::from)?;
                    let existing = sql_query(
                        "SELECT id, actor_id, actor_seq, realm_id, kind, schema_id, canonical_digest, canonical_bytes, envelope, received_at \
                         FROM canonical_events WHERE actor_id = $1 AND kind = 'ak.device.reanchor'",
                    )
                    .bind::<Text, _>(&slot.actor_id)
                    .load::<CanonicalEventRow>(&mut *conn)
                    .await
                    .map_err(PersistenceError::from)?
                    .into_iter()
                    .map(CanonicalEventRecord::from)
                    .collect::<Vec<_>>();
                    identity_anchor_slot_conflicts(existing.iter(), slot)
                } else {
                    false
                };
                if let Some(frontier_cas) = frontier_cas {
                    assert_identity_anchor_frontier(conn, &frontier_cas).await?;
                }
                for record in records {
                    insert_canonical_event(conn, &record).await?;
                }
                if !reanchor_conflict
                    && let Some(device) = device
                {
                    sql_query(
                        "INSERT INTO devices (id, actor_id, device_id, payload, verification_state, created_at, updated_at, revoked_at) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                         ON CONFLICT (actor_id, device_id) DO UPDATE SET payload = EXCLUDED.payload, \
                         verification_state = EXCLUDED.verification_state, updated_at = EXCLUDED.updated_at, revoked_at = EXCLUDED.revoked_at",
                    )
                    .bind::<SqlUuid, _>(Uuid::now_v7())
                    .bind::<Text, _>(&device.actor)
                    .bind::<Text, _>(&device.device_id)
                    .bind::<Jsonb, _>(&device.payload)
                    .bind::<Text, _>(&device.verification_state)
                    .bind::<Timestamptz, _>(device.created_at)
                    .bind::<Timestamptz, _>(device.updated_at)
                    .bind::<Nullable<Timestamptz>, _>(device.revoked_at)
                    .execute(conn)
                    .await
                    .map_err(PersistenceError::from)?;
                }
                if !reanchor_conflict
                    && let Some(receipt) = receipt
                {
                    insert_event_batch_receipt(conn, &receipt).await?;
                }
            Ok(IdentityAnchorCommitOutcome {
                reanchor_conflict,
            })
        })
        .await
    }

    async fn batch_receipts_for_event(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Vec<EventBatchReceipt>> {
        let mut conn = pg_conn(&self.pool).await?;
        let event_id = ids::typed_uuid_part_expect_internal(event_id);
        let rows = sql_query(
            "SELECT schema, id, issuer, scope, frontier, events, created_at, proofs \
             FROM event_batch_receipts WHERE event_ids @> ARRAY[$1]::uuid[] ORDER BY created_at, id",
        )
        .bind::<SqlUuid, _>(event_id)
        .load::<EventBatchReceiptRow>(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        rows.into_iter().map(EventBatchReceipt::try_from).collect()
    }

    async fn get(&self, event_id: &str) -> PersistenceResult<Option<CanonicalEventRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let event_id_uuid = ids::typed_uuid_part_expect_internal(event_id);
        sql_query(
            "SELECT id, actor_id, actor_seq, realm_id, kind, schema_id, canonical_digest, canonical_bytes, envelope, received_at \
             FROM canonical_events WHERE id = $1",
        )
        .bind::<SqlUuid, _>(event_id_uuid)
        .get_result::<CanonicalEventRow>(&mut *conn).await
        .optional()
        .map(|row| row.map(CanonicalEventRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn contains(&self, event_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        let event_id_uuid = ids::typed_uuid_part_expect_internal(event_id);
        sql_query("SELECT EXISTS(SELECT 1 FROM canonical_events WHERE id = $1) AS present")
            .bind::<SqlUuid, _>(event_id_uuid)
            .get_result::<ExistsRow>(&mut *conn)
            .await
            .map(|row| row.present)
            .map_err(PersistenceError::from)
    }

    async fn max_actor_seq(&self, actor_id: &str) -> PersistenceResult<Option<u64>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("SELECT MAX(actor_seq) AS max_seq FROM canonical_events WHERE actor_id = $1")
            .bind::<Text, _>(actor_id)
            .get_result::<MaxSeqRow>(&mut *conn)
            .await
            .map(|row| row.max_seq.map(|n| n.max(0) as u64))
            .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id, actor_id, actor_seq, realm_id, kind, schema_id, canonical_digest, canonical_bytes, envelope, received_at \
             FROM canonical_events ORDER BY received_at ASC, id ASC",
        )
        .load::<CanonicalEventRow>(&mut *conn).await
        .map(|rows| rows.into_iter().map(CanonicalEventRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn peer_authz_state_records(&self) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id, actor_id, actor_seq, realm_id, kind, schema_id, canonical_digest, canonical_bytes, envelope, received_at \
             FROM canonical_events \
             WHERE kind IN ('ak.member.state', 'ak.circle.member.state') \
                OR (envelope #> '{payload,sync_endpoints}') IS NOT NULL \
                OR (envelope #> '{payload,object,sync_endpoints}') IS NOT NULL \
                OR (envelope #> '{payload,patch,sync_endpoints}') IS NOT NULL \
             ORDER BY received_at ASC, id ASC",
        )
        .load::<CanonicalEventRow>(&mut *conn).await
        .map(|rows| rows.into_iter().map(CanonicalEventRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn peer_events_query_page(
        &self,
        query: &PeerEventsPageQuery,
    ) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let realm_ids = query
            .realms
            .iter()
            .map(|realm_id| {
                ids::parse_typed_uuid(realm_id, "realm").ok_or_else(|| {
                    PersistenceError::Internal(format!("invalid peer events realm id: {realm_id}"))
                })
            })
            .collect::<PersistenceResult<Vec<_>>>()?;
        let cursor_id = match query.cursor_event_id.as_deref() {
            Some(event_id) => ids::parse_typed_uuid(event_id, "event").ok_or_else(|| {
                PersistenceError::Internal(format!(
                    "invalid peer events cursor event id: {event_id}"
                ))
            })?,
            None => Uuid::nil(),
        };
        let no_cursor = query.cursor_event_id.is_none();
        let kind_filter = query.kind_filter.as_deref().unwrap_or_default();
        let limit = query.limit.min(i64::MAX as usize) as i64;
        let page_sql = if query.backward {
            "SELECT id, actor_id, actor_seq, realm_id, kind, schema_id, canonical_digest, canonical_bytes, envelope, received_at \
             FROM canonical_events \
             WHERE ($1 OR realm_id = ANY($2)) \
               AND ($3 OR actor_id = ANY($4)) \
               AND ($5 OR kind = $6) \
               AND ($7 OR (received_at, id) < (SELECT received_at, id FROM canonical_events WHERE id = $8)) \
             ORDER BY received_at DESC, id DESC \
             LIMIT $9"
        } else {
            "SELECT id, actor_id, actor_seq, realm_id, kind, schema_id, canonical_digest, canonical_bytes, envelope, received_at \
             FROM canonical_events \
             WHERE ($1 OR realm_id = ANY($2)) \
               AND ($3 OR actor_id = ANY($4)) \
               AND ($5 OR kind = $6) \
               AND ($7 OR (received_at, id) > (SELECT received_at, id FROM canonical_events WHERE id = $8)) \
             ORDER BY received_at ASC, id ASC \
             LIMIT $9"
        };
        sql_query(page_sql)
            .bind::<Bool, _>(realm_ids.is_empty())
            .bind::<Array<SqlUuid>, _>(realm_ids)
            .bind::<Bool, _>(query.actors.is_empty())
            .bind::<Array<Text>, _>(query.actors.clone())
            .bind::<Bool, _>(query.kind_filter.is_none())
            .bind::<Text, _>(kind_filter)
            .bind::<Bool, _>(no_cursor)
            .bind::<SqlUuid, _>(cursor_id)
            .bind::<BigInt, _>(limit)
            .load::<CanonicalEventRow>(&mut *conn)
            .await
            .map(|rows| rows.into_iter().map(CanonicalEventRecord::from).collect())
            .map_err(PersistenceError::from)
    }

    async fn realm_events_newest_first(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let realm_id_uuid = ids::typed_uuid_part_expect_internal(realm_id);
        sql_query(
            "SELECT id, actor_id, actor_seq, realm_id, kind, schema_id, canonical_digest, canonical_bytes, envelope, received_at \
             FROM canonical_events WHERE realm_id = $1 ORDER BY received_at DESC, id DESC",
        )
        .bind::<SqlUuid, _>(realm_id_uuid)
        .load::<CanonicalEventRow>(&mut *conn).await
        .map(|rows| rows.into_iter().map(CanonicalEventRecord::from).collect())
        .map_err(PersistenceError::from)
    }
}

// ── Pg-backed FederationOperationsStore ──────────────────────────────────
