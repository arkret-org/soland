use super::{
    BigInt, ExistsRow, FederationFrontierExchangeRecord, FederationFrontierExchangeStore,
    FederationOperationsStore, FederationOutboxDeadLetterRecord, FederationOutboxRecord,
    FederationOutboxStore, Integer, JsonPayloadRow, Jsonb, Nullable, Operation, OptionalExtension,
    PersistenceError, PersistenceResult, PgPool, QueryableByName, RunQueryDsl, SqlUuid, Text,
    Timestamptz, Uuid, async_trait, frontier_exchange_failure_record,
    frontier_exchange_success_record, ids, pg_conn, sql_query,
};
// G3.S0 — Postgres-backed durable outbound federation HTTP delivery queue.
// Mirrors `MemoryFederationOutboxStore`. The `(peer_did,
// idempotency_key)` UNIQUE INDEX in the migration is what makes
// `enqueue` structurally idempotent across worker restarts; we catch
// the conflict here and return Ok(false).
pub struct PgFederationOutboxStore {
    pub pool: PgPool,
}
#[async_trait]
impl FederationOutboxStore for PgFederationOutboxStore {
    async fn enqueue(&self, record: &FederationOutboxRecord) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
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
        .map_err(PersistenceError::database)?;
        Ok(inserted > 0)
    }

    async fn pending_due(
        &self,
        now_unix_secs: i64,
        limit: usize,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
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
        .map_err(PersistenceError::database)?;
        Ok(rows.into_iter().map(FederationOutboxRecord::from).collect())
    }

    async fn update(&self, record: &FederationOutboxRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
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
        .map_err(PersistenceError::database)
    }

    async fn get(&self, id: &str) -> PersistenceResult<Option<FederationOutboxRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
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
        .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<FederationOutboxRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT id, peer_id AS peer_did, peer_url, endpoint, idempotency_key, payload_json, attempts, \
             next_attempt_at, last_status, last_response_excerpt, created_at, delivered_at \
             FROM federation_outbox ORDER BY created_at ASC, id ASC",
        )
        .load::<FederationOutboxRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        Ok(rows.into_iter().map(FederationOutboxRecord::from).collect())
    }

    async fn insert_dead_letter(
        &self,
        record: &FederationOutboxDeadLetterRecord,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
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
        .map_err(PersistenceError::database)
    }

    async fn dead_letters_snapshot(
        &self,
    ) -> PersistenceResult<Vec<FederationOutboxDeadLetterRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT id, outbox_id, peer_id AS peer_did, endpoint, idempotency_key, terminal_status, \
             attempts, response_excerpt, failed_at, reason \
             FROM federation_outbox_dead_letter ORDER BY failed_at ASC, id ASC",
        )
        .load::<FederationOutboxDeadLetterRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        Ok(rows
            .into_iter()
            .map(FederationOutboxDeadLetterRecord::from)
            .collect())
    }
}
pub struct PgFederationFrontierExchangeStore {
    pub pool: PgPool,
}
#[async_trait]
impl FederationFrontierExchangeStore for PgFederationFrontierExchangeStore {
    async fn get(
        &self,
        realm_id: &str,
        peer_service_id: &str,
    ) -> PersistenceResult<Option<FederationFrontierExchangeRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let realm_id_uuid = ids::typed_uuid_part_expect_internal(realm_id);
        sql_query(
            "SELECT realm_id, peer_service_id, status, consecutive_failures, \
             last_success_at, last_failure_at, last_frontier_root, last_error, updated_at \
             FROM federation_frontier_exchange \
             WHERE realm_id = $1 AND peer_service_id = $2",
        )
        .bind::<SqlUuid, _>(realm_id_uuid)
        .bind::<Text, _>(peer_service_id)
        .get_result::<FederationFrontierExchangeRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(FederationFrontierExchangeRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn record_success(
        &self,
        realm_id: &str,
        peer_service_id: &str,
        frontier_root: &str,
        observed_at: i64,
    ) -> PersistenceResult<FederationFrontierExchangeRecord> {
        let existing = self
            .get(realm_id, peer_service_id)
            .await
            .map_err(PersistenceError::database)?;
        let record = frontier_exchange_success_record(
            existing,
            realm_id,
            peer_service_id,
            frontier_root,
            observed_at,
        );
        self.put_record(&record)
            .await
            .map_err(PersistenceError::database)?;
        Ok(record)
    }

    async fn record_failure(
        &self,
        realm_id: &str,
        peer_service_id: &str,
        reason: &str,
        observed_at: i64,
    ) -> PersistenceResult<FederationFrontierExchangeRecord> {
        let existing = self
            .get(realm_id, peer_service_id)
            .await
            .map_err(PersistenceError::database)?;
        let record = frontier_exchange_failure_record(
            existing,
            realm_id,
            peer_service_id,
            reason,
            observed_at,
        );
        self.put_record(&record)
            .await
            .map_err(PersistenceError::database)?;
        Ok(record)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<FederationFrontierExchangeRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT realm_id, peer_service_id, status, consecutive_failures, \
             last_success_at, last_failure_at, last_frontier_root, last_error, updated_at \
             FROM federation_frontier_exchange ORDER BY updated_at ASC, realm_id ASC, peer_service_id ASC",
        )
        .load::<FederationFrontierExchangeRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        Ok(rows
            .into_iter()
            .map(FederationFrontierExchangeRecord::from)
            .collect())
    }
}
impl PgFederationFrontierExchangeStore {
    async fn put_record(&self, record: &FederationFrontierExchangeRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let realm_id_uuid = ids::typed_uuid_part_expect_internal(&record.realm_id);
        sql_query(
            "INSERT INTO federation_frontier_exchange \
             (realm_id, peer_service_id, status, consecutive_failures, last_success_at, \
              last_failure_at, last_frontier_root, last_error, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (realm_id, peer_service_id) DO UPDATE SET \
             status = EXCLUDED.status, \
             consecutive_failures = EXCLUDED.consecutive_failures, \
             last_success_at = EXCLUDED.last_success_at, \
             last_failure_at = EXCLUDED.last_failure_at, \
             last_frontier_root = EXCLUDED.last_frontier_root, \
             last_error = EXCLUDED.last_error, \
             updated_at = EXCLUDED.updated_at",
        )
        .bind::<SqlUuid, _>(realm_id_uuid)
        .bind::<Text, _>(&record.peer_service_id)
        .bind::<Text, _>(&record.status)
        .bind::<Integer, _>(record.consecutive_failures)
        .bind::<Nullable<BigInt>, _>(record.last_success_at)
        .bind::<Nullable<BigInt>, _>(record.last_failure_at)
        .bind::<Nullable<Text>, _>(record.last_frontier_root.as_deref())
        .bind::<Nullable<Text>, _>(record.last_error.as_deref())
        .bind::<BigInt, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }
}
pub struct PgFederationOperationsStore {
    pub pool: PgPool,
}
#[async_trait]
impl FederationOperationsStore for PgFederationOperationsStore {
    async fn append(&self, operation: Operation) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let payload = serde_json::to_value(&operation).map_err(|error| {
            PersistenceError::Internal(format!("federation operation serialize: {error}"))
        })?;
        let object_id = operation.object_id.clone();
        let operation_type = serde_json::to_value(&operation.operation_type)
            .ok()
            .and_then(|v| v.as_str().map(ToOwned::to_owned))
            .unwrap_or_else(|| "create".to_owned());
        let operation_id_uuid =
            ids::typed_uuid_part_expect_internal(operation.operation_id.as_str());
        let realm_id_uuid = ids::typed_uuid_part_expect_internal(operation.realm_id.as_str());
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
        .map_err(PersistenceError::database)
    }

    async fn contains(&self, operation_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let operation_id_uuid = ids::typed_uuid_part_expect_internal(operation_id);
        sql_query("SELECT EXISTS(SELECT 1 FROM federation_operations WHERE id = $1) AS present")
            .bind::<SqlUuid, _>(operation_id_uuid)
            .get_result::<ExistsRow>(&mut *conn)
            .await
            .map(|row| row.present)
            .map_err(PersistenceError::database)
    }

    async fn list_for_realm(&self, realm_id: &str) -> PersistenceResult<Vec<Operation>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let realm_id_uuid = ids::typed_uuid_part_expect_internal(realm_id);
        let rows: Vec<JsonPayloadRow> = sql_query(
            "SELECT payload FROM federation_operations \
             WHERE realm_id = $1 ORDER BY created_at ASC, id ASC",
        )
        .bind::<SqlUuid, _>(realm_id_uuid)
        .load::<JsonPayloadRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(|row| {
                serde_json::from_value::<Operation>(row.payload).map_err(|error| {
                    PersistenceError::Internal(format!("federation operation deserialize: {error}"))
                })
            })
            .collect()
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Operation>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows: Vec<JsonPayloadRow> = sql_query(
            "SELECT payload FROM federation_operations \
             ORDER BY created_at ASC, id ASC",
        )
        .load::<JsonPayloadRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
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
struct FederationFrontierExchangeRow {
    #[diesel(sql_type = SqlUuid)]
    realm_id: Uuid,
    #[diesel(sql_type = Text)]
    peer_service_id: String,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = Integer)]
    consecutive_failures: i32,
    #[diesel(sql_type = Nullable<BigInt>)]
    last_success_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    last_failure_at: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    last_frontier_root: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    last_error: Option<String>,
    #[diesel(sql_type = BigInt)]
    updated_at: i64,
}
impl From<FederationFrontierExchangeRow> for FederationFrontierExchangeRecord {
    fn from(row: FederationFrontierExchangeRow) -> Self {
        Self {
            realm_id: ids::format_typed_uuid("realm", &row.realm_id),
            peer_service_id: row.peer_service_id,
            status: row.status,
            consecutive_failures: row.consecutive_failures,
            last_success_at: row.last_success_at,
            last_failure_at: row.last_failure_at,
            last_frontier_root: row.last_frontier_root,
            last_error: row.last_error,
            updated_at: row.updated_at,
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
