use super::*;

/// Trait for durable federation transaction replay records.
#[async_trait]
pub trait FederationTransactionStore: Send + Sync {
    async fn get(
        &self,
        origin: &str,
        txn_id: &str,
    ) -> PersistenceResult<Option<FederationTransactionRecord>>;
    async fn put(&self, record: &FederationTransactionRecord) -> PersistenceResult<()>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<FederationTransactionRecord>>;
}

/// G3.S0 — durable outbound federation HTTP delivery queue.
///
/// Rows are inserted synchronously on the inbound write path
/// (`routing::federation::federation::broadcast_move_to_peers` and
/// `broadcast_anchor_to_peers`); the `FederationDispatcher` background
/// worker (`routing::federation::outbox::FederationDispatcher`) polls
/// pending rows and posts them to peers.
///
/// Idempotency: `(peer_did, idempotency_key)` is UNIQUE. Callers that
/// re-enqueue the same logical request (replay of an accepted Move /
/// Anchor on restart) MUST see `enqueue` return `Ok(false)` rather than
/// a duplicate-row error; the worker treats the existing row as the
/// authoritative delivery state.
#[async_trait]
pub trait FederationOutboxStore: Send + Sync {
    /// Insert a new outbox row. Returns `Ok(true)` if a fresh row was
    /// stored, `Ok(false)` if `(peer_did, idempotency_key)` already
    /// exists (callers MUST treat that as "already enqueued" rather
    /// than an error — see trait-doc idempotency note).
    async fn enqueue(&self, record: &FederationOutboxRecord) -> PersistenceResult<bool>;
    /// Returns rows where `delivered_at IS NULL` and `next_attempt_at
    /// <= now_unix_secs`, ordered by `next_attempt_at` ascending. The
    /// `limit` caps the per-poll batch so a backlog never starves
    /// other workers on the same tokio runtime.
    async fn pending_due(
        &self,
        now_unix_secs: i64,
        limit: usize,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>>;
    /// Replace the row by `id`. Used by the worker after every delivery
    /// attempt to record the new `attempts` / `last_status` /
    /// `next_attempt_at` / `delivered_at` columns.
    async fn update(&self, record: &FederationOutboxRecord) -> PersistenceResult<()>;
    /// Fetch a single row by primary key. Used by the integration test
    /// (and the optional admin observability endpoint, not wired in
    /// G3.S0).
    async fn get(&self, id: &str) -> PersistenceResult<Option<FederationOutboxRecord>>;
    /// Snapshot the full table — diagnostics + the integration test
    /// rely on it. Production deployments SHOULD NOT call this on a
    /// large outbox; use `pending_due` instead.
    async fn snapshot_all(&self) -> PersistenceResult<Vec<FederationOutboxRecord>>;
    /// Append a terminal failure to the dead-letter queue. The outbox row
    /// remains in place for idempotency and diagnostics; this queue is the
    /// operator-facing replay/quarantine surface.
    async fn insert_dead_letter(
        &self,
        record: &FederationOutboxDeadLetterRecord,
    ) -> PersistenceResult<()>;
    async fn dead_letters_snapshot(
        &self,
    ) -> PersistenceResult<Vec<FederationOutboxDeadLetterRecord>>;
}

/// Replay log of federation operations the local service has accepted from
/// peers (and emitted itself). Currently in-memory but the trait shape is
/// what the durable Pg implementation will follow.
#[async_trait]
pub trait FederationOperationsStore: Send + Sync {
    async fn append(&self, operation: Operation) -> PersistenceResult<()>;
    async fn contains(&self, operation_id: &str) -> PersistenceResult<bool>;
    async fn list_for_realm(&self, realm_id: &str) -> PersistenceResult<Vec<Operation>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<Operation>>;
}

// In-memory federation transaction replay store
pub(crate) struct MemoryFederationTransactionStore {
    data: Arc<Mutex<BTreeMap<(String, String), FederationTransactionRecord>>>,
}

impl MemoryFederationTransactionStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl FederationTransactionStore for MemoryFederationTransactionStore {
    async fn get(
        &self,
        origin: &str,
        txn_id: &str,
    ) -> PersistenceResult<Option<FederationTransactionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(&(origin.to_owned(), txn_id.to_owned())).cloned())
    }

    async fn put(&self, record: &FederationTransactionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(
            (record.origin.clone(), record.txn_id.clone()),
            record.clone(),
        );
        Ok(())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<FederationTransactionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.values().cloned().collect())
    }
}

// G3.S0 — in-memory outbound federation HTTP delivery queue.
// Keyed by `id` (the row PK) with a secondary `(peer_did,
// idempotency_key)` uniqueness guard implemented at insert time so the
// Memory backend matches the Pg `federation_outbox_peer_idem` UNIQUE
// INDEX semantics.
pub(crate) struct MemoryFederationOutboxStore {
    data: Arc<Mutex<BTreeMap<String, FederationOutboxRecord>>>,
    dead_letters: Arc<Mutex<BTreeMap<String, FederationOutboxDeadLetterRecord>>>,
}

impl MemoryFederationOutboxStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
            dead_letters: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl FederationOutboxStore for MemoryFederationOutboxStore {
    async fn enqueue(&self, record: &FederationOutboxRecord) -> PersistenceResult<bool> {
        let mut data = self.data.lock().expect("federation_outbox lock");
        // Match the Pg `(peer_did, idempotency_key)` UNIQUE INDEX —
        // duplicate enqueue returns Ok(false) so re-broadcast on
        // restart is structurally idempotent.
        let already_present = data.values().any(|existing| {
            existing.peer_did == record.peer_did
                && existing.idempotency_key == record.idempotency_key
        });
        if already_present {
            return Ok(false);
        }
        data.insert(record.id.clone(), record.clone());
        Ok(true)
    }

    async fn pending_due(
        &self,
        now_unix_secs: i64,
        limit: usize,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>> {
        let data = self.data.lock().expect("federation_outbox lock");
        let mut rows: Vec<FederationOutboxRecord> = data
            .values()
            .filter(|row| row.delivered_at.is_none() && row.next_attempt_at <= now_unix_secs)
            .cloned()
            .collect();
        rows.sort_by_key(|a| a.next_attempt_at);
        rows.truncate(limit);
        Ok(rows)
    }

    async fn update(&self, record: &FederationOutboxRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("federation_outbox lock");
        data.insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn get(&self, id: &str) -> PersistenceResult<Option<FederationOutboxRecord>> {
        let data = self.data.lock().expect("federation_outbox lock");
        Ok(data.get(id).cloned())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<FederationOutboxRecord>> {
        let data = self.data.lock().expect("federation_outbox lock");
        Ok(data.values().cloned().collect())
    }

    async fn insert_dead_letter(
        &self,
        record: &FederationOutboxDeadLetterRecord,
    ) -> PersistenceResult<()> {
        let mut dead_letters = self
            .dead_letters
            .lock()
            .expect("federation_outbox_dead_letter lock");
        dead_letters.insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn dead_letters_snapshot(
        &self,
    ) -> PersistenceResult<Vec<FederationOutboxDeadLetterRecord>> {
        let dead_letters = self
            .dead_letters
            .lock()
            .expect("federation_outbox_dead_letter lock");
        Ok(dead_letters.values().cloned().collect())
    }
}

// ── New in-memory sub-stores ────────────────────────────────────────────────
//
// The structs below back every former `Arc<Mutex<...>>` field on `AppState`.
// The trait shape is the architectural contract; the Pg-backed
// implementations land in T0-3.

#[derive(Default)]
pub(crate) struct MemoryFederationOperationsStore {
    data: Mutex<Vec<Operation>>,
}

impl MemoryFederationOperationsStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl FederationOperationsStore for MemoryFederationOperationsStore {
    async fn append(&self, operation: Operation) -> PersistenceResult<()> {
        self.data.lock().expect("federation lock").push(operation);
        Ok(())
    }

    async fn contains(&self, operation_id: &str) -> PersistenceResult<bool> {
        Ok(self
            .data
            .lock()
            .expect("federation lock")
            .iter()
            .any(|known| known.operation_id.as_str() == operation_id))
    }

    async fn list_for_realm(&self, realm_id: &str) -> PersistenceResult<Vec<Operation>> {
        Ok(self
            .data
            .lock()
            .expect("federation lock")
            .iter()
            .filter(|operation| operation.realm_id.as_str() == realm_id)
            .cloned()
            .collect())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Operation>> {
        Ok(self.data.lock().expect("federation lock").clone())
    }
}

pub(crate) struct PgFederationTransactionStore {
    pub(crate) pool: PgPool,
}

#[async_trait]
impl FederationTransactionStore for PgFederationTransactionStore {
    async fn get(
        &self,
        origin: &str,
        txn_id: &str,
    ) -> PersistenceResult<Option<FederationTransactionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT source_service AS origin, txn_id, destination_service AS destination, \
             realm_id, content_digest, status, payload AS response, received_at, processed_at \
             FROM federation_transactions WHERE source_service = $1 AND txn_id = $2",
        )
        .bind::<Text, _>(origin)
        .bind::<Text, _>(txn_id)
        .get_result::<FederationTransactionRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(FederationTransactionRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn put(&self, record: &FederationTransactionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let realm_id_uuid: Option<Uuid> = record
            .realm_id
            .as_deref()
            .map(ids::typed_uuid_part_or_panic);
        sql_query(
            "INSERT INTO federation_transactions \
             (id, txn_id, source_service, destination_service, realm_id, status, content_digest, payload, received_at, processed_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (source_service, txn_id) DO UPDATE SET \
             destination_service = EXCLUDED.destination_service, \
             realm_id = EXCLUDED.realm_id, \
             status = EXCLUDED.status, \
             content_digest = EXCLUDED.content_digest, \
             payload = EXCLUDED.payload, \
             received_at = EXCLUDED.received_at, \
             processed_at = EXCLUDED.processed_at",
        )
        .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::now_v7())
        .bind::<Text, _>(&record.txn_id)
        .bind::<Text, _>(&record.origin)
        .bind::<Text, _>(&record.destination)
        .bind::<Nullable<SqlUuid>, _>(realm_id_uuid)
        .bind::<Text, _>(&record.status)
        .bind::<Text, _>(&record.content_digest)
        .bind::<Jsonb, _>(&record.response)
        .bind::<Timestamptz, _>(record.received_at)
        .bind::<Nullable<Timestamptz>, _>(record.processed_at)
        .execute(&mut *conn).await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<FederationTransactionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT source_service AS origin, txn_id, destination_service AS destination, \
             realm_id, content_digest, status, payload AS response, received_at, processed_at \
             FROM federation_transactions ORDER BY received_at ASC, txn_id ASC",
        )
        .load::<FederationTransactionRow>(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        Ok(rows
            .into_iter()
            .map(FederationTransactionRecord::from)
            .collect())
    }
}

// G3.S0 — Postgres-backed durable outbound federation HTTP delivery queue.
// Mirrors `MemoryFederationOutboxStore`. The `(peer_did,
// idempotency_key)` UNIQUE INDEX in the migration is what makes
// `enqueue` structurally idempotent across worker restarts; we catch
// the conflict here and return Ok(false).
pub(crate) struct PgFederationOutboxStore {
    pub(crate) pool: PgPool,
}

#[async_trait]
impl FederationOutboxStore for PgFederationOutboxStore {
    async fn enqueue(&self, record: &FederationOutboxRecord) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        let inserted = sql_query(
            "INSERT INTO federation_outbox \
             (id, peer_id, peer_url, endpoint, idempotency_key, payload_json, attempts, \
              next_attempt_at, last_status, last_response_excerpt, created_at, delivered_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
             ON CONFLICT (peer_id, idempotency_key) DO NOTHING",
        )
        .bind::<Text, _>(&record.id)
        .bind::<Text, _>(&record.peer_did)
        .bind::<Text, _>(&record.peer_url)
        .bind::<Text, _>(&record.endpoint)
        .bind::<Text, _>(&record.idempotency_key)
        .bind::<Text, _>(&record.payload_json)
        .bind::<Integer, _>(record.attempts)
        .bind::<BigInt, _>(record.next_attempt_at)
        .bind::<Nullable<Integer>, _>(record.last_status)
        .bind::<Nullable<Text>, _>(record.last_response_excerpt.as_deref())
        .bind::<BigInt, _>(record.created_at)
        .bind::<Nullable<BigInt>, _>(record.delivered_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        Ok(inserted > 0)
    }

    async fn pending_due(
        &self,
        now_unix_secs: i64,
        limit: usize,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT id, peer_id AS peer_did, peer_url, endpoint, idempotency_key, payload_json, attempts, \
             next_attempt_at, last_status, last_response_excerpt, created_at, delivered_at \
             FROM federation_outbox \
             WHERE delivered_at IS NULL AND next_attempt_at <= $1 \
             ORDER BY next_attempt_at ASC LIMIT $2",
        )
        .bind::<BigInt, _>(now_unix_secs)
        .bind::<BigInt, _>(limit as i64)
        .load::<FederationOutboxRow>(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        Ok(rows.into_iter().map(FederationOutboxRecord::from).collect())
    }

    async fn update(&self, record: &FederationOutboxRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "UPDATE federation_outbox SET \
             attempts = $2, next_attempt_at = $3, last_status = $4, \
             last_response_excerpt = $5, delivered_at = $6 \
             WHERE id = $1",
        )
        .bind::<Text, _>(&record.id)
        .bind::<Integer, _>(record.attempts)
        .bind::<BigInt, _>(record.next_attempt_at)
        .bind::<Nullable<Integer>, _>(record.last_status)
        .bind::<Nullable<Text>, _>(record.last_response_excerpt.as_deref())
        .bind::<Nullable<BigInt>, _>(record.delivered_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn get(&self, id: &str) -> PersistenceResult<Option<FederationOutboxRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id, peer_id AS peer_did, peer_url, endpoint, idempotency_key, payload_json, attempts, \
             next_attempt_at, last_status, last_response_excerpt, created_at, delivered_at \
             FROM federation_outbox WHERE id = $1",
        )
        .bind::<Text, _>(id)
        .get_result::<FederationOutboxRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(FederationOutboxRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<FederationOutboxRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT id, peer_id AS peer_did, peer_url, endpoint, idempotency_key, payload_json, attempts, \
             next_attempt_at, last_status, last_response_excerpt, created_at, delivered_at \
             FROM federation_outbox ORDER BY created_at ASC, id ASC",
        )
        .load::<FederationOutboxRow>(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        Ok(rows.into_iter().map(FederationOutboxRecord::from).collect())
    }

    async fn insert_dead_letter(
        &self,
        record: &FederationOutboxDeadLetterRecord,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO federation_outbox_dead_letter \
             (id, outbox_id, peer_id, endpoint, idempotency_key, terminal_status, attempts, \
              response_excerpt, failed_at, reason) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<Text, _>(&record.id)
        .bind::<Text, _>(&record.outbox_id)
        .bind::<Text, _>(&record.peer_did)
        .bind::<Text, _>(&record.endpoint)
        .bind::<Text, _>(&record.idempotency_key)
        .bind::<Integer, _>(record.terminal_status)
        .bind::<Integer, _>(record.attempts)
        .bind::<Nullable<Text>, _>(record.response_excerpt.as_deref())
        .bind::<BigInt, _>(record.failed_at)
        .bind::<Text, _>(&record.reason)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn dead_letters_snapshot(
        &self,
    ) -> PersistenceResult<Vec<FederationOutboxDeadLetterRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT id, outbox_id, peer_id AS peer_did, endpoint, idempotency_key, terminal_status, \
             attempts, response_excerpt, failed_at, reason \
             FROM federation_outbox_dead_letter ORDER BY failed_at ASC, id ASC",
        )
        .load::<FederationOutboxDeadLetterRow>(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        Ok(rows
            .into_iter()
            .map(FederationOutboxDeadLetterRecord::from)
            .collect())
    }
}

pub(crate) struct PgFederationOperationsStore {
    pub(crate) pool: PgPool,
}

#[derive(QueryableByName)]
struct FederationOperationRow {
    #[diesel(sql_type = Jsonb)]
    payload: Value,
}

#[async_trait]
impl FederationOperationsStore for PgFederationOperationsStore {
    async fn append(&self, operation: Operation) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let payload = serde_json::to_value(&operation).map_err(|error| {
            PersistenceError::Internal(format!("federation operation serialize: {error}"))
        })?;
        let object_id = operation.object_id.clone();
        let operation_type = serde_json::to_value(&operation.operation_type)
            .ok()
            .and_then(|v| v.as_str().map(ToOwned::to_owned))
            .unwrap_or_else(|| "create".to_owned());
        let operation_id_uuid = ids::typed_uuid_part_or_panic(operation.operation_id.as_str());
        let realm_id_uuid = ids::typed_uuid_part_or_panic(operation.realm_id.as_str());
        sql_query(
            "INSERT INTO federation_operations \
             (id, realm_id, object_type, object_id, operation_type, payload, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(operation_id_uuid)
        .bind::<SqlUuid, _>(realm_id_uuid)
        .bind::<Text, _>(&operation.object_type)
        .bind::<Nullable<Text>, _>(&object_id)
        .bind::<Text, _>(&operation_type)
        .bind::<Jsonb, _>(&payload)
        .bind::<Timestamptz, _>(operation.created_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn contains(&self, operation_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        #[derive(QueryableByName)]
        struct ExistsRow {
            #[diesel(sql_type = diesel::sql_types::Bool)]
            present: bool,
        }
        let operation_id_uuid = ids::typed_uuid_part_or_panic(operation_id);
        sql_query("SELECT EXISTS(SELECT 1 FROM federation_operations WHERE id = $1) AS present")
            .bind::<SqlUuid, _>(operation_id_uuid)
            .get_result::<ExistsRow>(&mut *conn)
            .await
            .map(|row| row.present)
            .map_err(PersistenceError::from)
    }

    async fn list_for_realm(&self, realm_id: &str) -> PersistenceResult<Vec<Operation>> {
        let mut conn = pg_conn(&self.pool).await?;
        let realm_id_uuid = ids::typed_uuid_part_or_panic(realm_id);
        let rows: Vec<FederationOperationRow> = sql_query(
            "SELECT payload FROM federation_operations \
             WHERE realm_id = $1 ORDER BY created_at ASC, id ASC",
        )
        .bind::<SqlUuid, _>(realm_id_uuid)
        .load::<FederationOperationRow>(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        rows.into_iter()
            .map(|row| {
                serde_json::from_value::<Operation>(row.payload).map_err(|error| {
                    PersistenceError::Internal(format!("federation operation deserialize: {error}"))
                })
            })
            .collect()
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Operation>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows: Vec<FederationOperationRow> = sql_query(
            "SELECT payload FROM federation_operations \
             ORDER BY created_at ASC, id ASC",
        )
        .load::<FederationOperationRow>(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        rows.into_iter()
            .map(|row| {
                serde_json::from_value::<Operation>(row.payload).map_err(|error| {
                    PersistenceError::Internal(format!("federation operation deserialize: {error}"))
                })
            })
            .collect()
    }
}

// ── Pg-backed wire-facing sub-stores ─────────────────────────────────────
//
// ModerationStore / PresenceStore / WebvhStore / RealmInviteStore. Each
// follows the same pattern: a typed-column header (extracted from the JSON
// payload where applicable) plus the full canonical envelope in a JSONB
// column. The trait surface itself is the architectural contract; the
// Pg + Memory backends both implement it identically.

#[derive(QueryableByName)]
struct FederationTransactionRow {
    #[diesel(sql_type = Text)]
    origin: String,
    #[diesel(sql_type = Text)]
    txn_id: String,
    #[diesel(sql_type = Text)]
    destination: String,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    realm_id: Option<Uuid>,
    #[diesel(sql_type = Text)]
    content_digest: String,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = Jsonb)]
    response: Value,
    #[diesel(sql_type = Timestamptz)]
    received_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    processed_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<FederationTransactionRow> for FederationTransactionRecord {
    fn from(row: FederationTransactionRow) -> Self {
        Self {
            origin: row.origin,
            txn_id: row.txn_id,
            destination: row.destination,
            realm_id: row
                .realm_id
                .as_ref()
                .map(|u| ids::format_typed_uuid("space", u)),
            content_digest: row.content_digest,
            status: row.status,
            response: row.response,
            received_at: row.received_at,
            processed_at: row.processed_at,
        }
    }
}

#[derive(QueryableByName)]
struct FederationOutboxRow {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Text)]
    peer_did: String,
    #[diesel(sql_type = Text)]
    peer_url: String,
    #[diesel(sql_type = Text)]
    endpoint: String,
    #[diesel(sql_type = Text)]
    idempotency_key: String,
    #[diesel(sql_type = Text)]
    payload_json: String,
    #[diesel(sql_type = Integer)]
    attempts: i32,
    #[diesel(sql_type = BigInt)]
    next_attempt_at: i64,
    #[diesel(sql_type = Nullable<Integer>)]
    last_status: Option<i32>,
    #[diesel(sql_type = Nullable<Text>)]
    last_response_excerpt: Option<String>,
    #[diesel(sql_type = BigInt)]
    created_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    delivered_at: Option<i64>,
}

impl From<FederationOutboxRow> for FederationOutboxRecord {
    fn from(row: FederationOutboxRow) -> Self {
        Self {
            id: row.id,
            peer_did: row.peer_did,
            peer_url: row.peer_url,
            endpoint: row.endpoint,
            idempotency_key: row.idempotency_key,
            payload_json: row.payload_json,
            attempts: row.attempts,
            next_attempt_at: row.next_attempt_at,
            last_status: row.last_status,
            last_response_excerpt: row.last_response_excerpt,
            created_at: row.created_at,
            delivered_at: row.delivered_at,
        }
    }
}

#[derive(QueryableByName)]
struct FederationOutboxDeadLetterRow {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Text)]
    outbox_id: String,
    #[diesel(sql_type = Text)]
    peer_did: String,
    #[diesel(sql_type = Text)]
    endpoint: String,
    #[diesel(sql_type = Text)]
    idempotency_key: String,
    #[diesel(sql_type = Integer)]
    terminal_status: i32,
    #[diesel(sql_type = Integer)]
    attempts: i32,
    #[diesel(sql_type = Nullable<Text>)]
    response_excerpt: Option<String>,
    #[diesel(sql_type = BigInt)]
    failed_at: i64,
    #[diesel(sql_type = Text)]
    reason: String,
}

impl From<FederationOutboxDeadLetterRow> for FederationOutboxDeadLetterRecord {
    fn from(row: FederationOutboxDeadLetterRow) -> Self {
        Self {
            id: row.id,
            outbox_id: row.outbox_id,
            peer_did: row.peer_did,
            endpoint: row.endpoint,
            idempotency_key: row.idempotency_key,
            terminal_status: row.terminal_status,
            attempts: row.attempts,
            response_excerpt: row.response_excerpt,
            failed_at: row.failed_at,
            reason: row.reason,
        }
    }
}
