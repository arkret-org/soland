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
        let data = self.data.lock().expect("lock");
        Ok(data.iter().find(|m| m.event_id == event_id).cloned())
    }

    async fn put(&self, record: &MessageRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.push(record.clone());
        Ok(())
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<MessageRecord>> {
        let data = self.data.lock().expect("lock");
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
        let data = self.data.lock().expect("lock");
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
        let mut data = self.data.lock().expect("lock");
        data.retain(|m| m.event_id != event_id);
        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct MemoryEventStore {
    data: Mutex<BTreeMap<String, CanonicalEventRecord>>,
}

impl MemoryEventStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl EventStore for MemoryEventStore {
    async fn put(&self, record: CanonicalEventRecord) -> PersistenceResult<()> {
        let id = record.event_id.clone();
        let mut data = self.data.lock().expect("events lock");
        if record.kind == "ck.realm.create"
            && record.realm_id.is_some()
            && data.values().any(|existing| {
                existing.kind == "ck.realm.create" && existing.realm_id == record.realm_id
            })
        {
            return Err(PersistenceError::Conflict(
                "realm_already_exists".to_owned(),
            ));
        }
        data.insert(id, record);
        Ok(())
    }

    async fn get(&self, event_id: &str) -> PersistenceResult<Option<CanonicalEventRecord>> {
        Ok(self
            .data
            .lock()
            .expect("events lock")
            .get(event_id)
            .cloned())
    }

    async fn contains(&self, event_id: &str) -> PersistenceResult<bool> {
        Ok(self
            .data
            .lock()
            .expect("events lock")
            .contains_key(event_id))
    }

    async fn max_actor_seq(&self, actor_id: &str) -> PersistenceResult<Option<u64>> {
        Ok(self
            .data
            .lock()
            .expect("events lock")
            .values()
            .filter(|record| record.actor_id == actor_id)
            .map(|record| record.actor_seq)
            .max())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        Ok(self
            .data
            .lock()
            .expect("events lock")
            .values()
            .cloned()
            .collect())
    }

    async fn peer_authz_state_records(&self) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let mut records = self
            .data
            .lock()
            .expect("events lock")
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
        let data = self.data.lock().expect("events lock");
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
            .expect("events lock")
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
        cokret_sdk::events::kinds::MEMBER_STATE | cokret_sdk::events::kinds::CIRCLE_MEMBER_STATE
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
             WHERE kind IN ('ck.member.state', 'ck.circle.member.state') \
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
