use super::*;
pub struct PgIdempotencyStore {
    pub pool: PgPool,
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
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
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
        .map_err(PersistenceError::database)
    }

    async fn record(&self, record: &IdempotencyRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
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
        .map_err(PersistenceError::database)
    }

    async fn prune_expired(&self, now: chrono::DateTime<Utc>) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM idempotency_keys WHERE expires_at <= $1")
            .bind::<Timestamptz, _>(now)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)
    }
}
