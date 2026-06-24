use super::*;

/// A persisted generic `Idempotency-Key` mapping (api-conventions.md §6).
///
/// One row per `(principal_id, idempotency_key)`: the first request under a key
/// records its canonical request hash plus the full first response (status +
/// body). A replay carrying the same key MUST return this cached first response
/// when its canonical request body hashes to `request_hash`, and MUST be
/// rejected with `duplicate_conflict` when the same key arrives with a
/// different canonical body. Durable so the mapping survives a restart at least
/// until `expires_at`, per §6 ("server SHOULD record the idempotency mapping at
/// least until the related Event is fully synced or expired").
#[derive(Clone, Debug, PartialEq)]
pub struct IdempotencyRecord {
    pub principal_id: String,
    pub idempotency_key: String,
    pub service_id: String,
    pub request_hash: String,
    pub response_status: i32,
    pub response_body: Value,
    pub created_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
}

/// Durable `(principal_id, idempotency_key) -> first response` table.
#[async_trait]
pub trait IdempotencyStore: Send + Sync {
    /// Read the cached record for a key, if any (used to decide Fresh / Replay /
    /// Conflict against the request hash at the call site).
    async fn get(
        &self,
        principal_id: &str,
        idempotency_key: &str,
    ) -> PersistenceResult<Option<IdempotencyRecord>>;
    /// Persist the FIRST response under a key. `ON CONFLICT DO NOTHING`: a
    /// concurrent first-writer race keeps the earliest landed row, so a later
    /// racer reads it back as a `Replay` instead of clobbering it.
    async fn record(&self, record: &IdempotencyRecord) -> PersistenceResult<()>;
    /// TTL sweep: drop every row whose `expires_at` is at or before `now`.
    async fn prune_expired(&self, now: chrono::DateTime<Utc>) -> PersistenceResult<usize>;
}

/// In-memory `(principal_id, idempotency_key) -> IdempotencyRecord` table.
/// Mirrors the `idempotency_keys` Pg table on the same composite key.
pub(crate) struct MemoryIdempotencyStore {
    data: Arc<Mutex<BTreeMap<(String, String), IdempotencyRecord>>>,
}

impl MemoryIdempotencyStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl IdempotencyStore for MemoryIdempotencyStore {
    async fn get(
        &self,
        principal_id: &str,
        idempotency_key: &str,
    ) -> PersistenceResult<Option<IdempotencyRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .get(&(principal_id.to_owned(), idempotency_key.to_owned()))
            .cloned())
    }

    async fn record(&self, record: &IdempotencyRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        // First-writer-wins: keep the earliest landed row (mirrors the Pg
        // `ON CONFLICT DO NOTHING`), so a concurrent racer reads back the
        // original first response rather than overwriting it.
        data.entry((record.principal_id.clone(), record.idempotency_key.clone()))
            .or_insert_with(|| record.clone());
        Ok(())
    }

    async fn prune_expired(&self, now: chrono::DateTime<Utc>) -> PersistenceResult<usize> {
        let mut data = self.data.lock().expect("lock");
        let before = data.len();
        data.retain(|_, record| record.expires_at > now);
        Ok(before - data.len())
    }
}

pub(crate) struct PgIdempotencyStore {
    pub(crate) pool: PgPool,
}

#[derive(QueryableByName)]
struct IdempotencyRow {
    #[diesel(sql_type = Text)]
    principal_id: String,
    #[diesel(sql_type = Text)]
    idempotency_key: String,
    #[diesel(sql_type = Text)]
    service_id: String,
    #[diesel(sql_type = Text)]
    request_hash: String,
    #[diesel(sql_type = Integer)]
    response_status: i32,
    #[diesel(sql_type = Jsonb)]
    response_body: Value,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<Utc>,
}

impl From<IdempotencyRow> for IdempotencyRecord {
    fn from(row: IdempotencyRow) -> Self {
        IdempotencyRecord {
            principal_id: row.principal_id,
            idempotency_key: row.idempotency_key,
            service_id: row.service_id,
            request_hash: row.request_hash,
            response_status: row.response_status,
            response_body: row.response_body,
            created_at: row.created_at,
            expires_at: row.expires_at,
        }
    }
}

#[async_trait]
impl IdempotencyStore for PgIdempotencyStore {
    async fn get(
        &self,
        principal_id: &str,
        idempotency_key: &str,
    ) -> PersistenceResult<Option<IdempotencyRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT principal_id, idempotency_key, service_id, request_hash, response_status, \
             response_body, created_at, expires_at \
             FROM idempotency_keys WHERE principal_id = $1 AND idempotency_key = $2",
        )
        .bind::<Text, _>(principal_id)
        .bind::<Text, _>(idempotency_key)
        .get_result::<IdempotencyRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(IdempotencyRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn record(&self, record: &IdempotencyRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        // First-writer-wins under a concurrent race: the earliest row stays,
        // and a racer's later read returns it as a Replay.
        sql_query(
            "INSERT INTO idempotency_keys \
             (principal_id, idempotency_key, service_id, request_hash, response_status, \
              response_body, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (principal_id, idempotency_key) DO NOTHING",
        )
        .bind::<Text, _>(&record.principal_id)
        .bind::<Text, _>(&record.idempotency_key)
        .bind::<Text, _>(&record.service_id)
        .bind::<Text, _>(&record.request_hash)
        .bind::<Integer, _>(record.response_status)
        .bind::<Jsonb, _>(&record.response_body)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.expires_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn prune_expired(&self, now: chrono::DateTime<Utc>) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM idempotency_keys WHERE expires_at <= $1")
            .bind::<Timestamptz, _>(now)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::from)
    }
}
