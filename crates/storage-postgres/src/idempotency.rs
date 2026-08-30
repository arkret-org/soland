use super::{
    IdempotencyRecord, IdempotencyStore, Integer, Jsonb, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, QueryableByName, RunQueryDsl, Text, Timestamptz, Utc, Value,
    async_trait, pg_conn, sql_query,
};
pub struct PgIdempotencyStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct IdempotencyRow {
    #[diesel(sql_type = Text)]
    principal_id: arkret_identifiers::DidCoreId,
    #[diesel(sql_type = Text)]
    idempotency_key: String,
    #[diesel(sql_type = Text)]
    service_id: arkret_identifiers::DidCoreId,
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
        Self {
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
        principal_id: &arkret_identifiers::DidCoreId,
        idempotency_key: &str,
    ) -> PersistenceResult<Option<IdempotencyRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        Ok(sql_query(
            "SELECT principal_id, idempotency_key, service_id, request_hash, response_status, \
             response_body, created_at, expires_at \
             FROM idempotency_keys WHERE principal_id = $1 AND idempotency_key = $2",
        )
        .bind::<Text, _>(principal_id)
        .bind::<Text, _>(idempotency_key)
        .get_result::<IdempotencyRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(IdempotencyRecord::from))
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

    async fn complete_reservation(
        &self,
        expected: &IdempotencyRecord,
        completed: &IdempotencyRecord,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "UPDATE idempotency_keys SET service_id = $9, request_hash = $10, \
             response_status = $11, response_body = $12, created_at = $13, expires_at = $14 \
             WHERE principal_id = $1 AND idempotency_key = $2 AND service_id = $3 \
             AND request_hash = $4 AND response_status = $5 AND response_body = $6 \
             AND created_at = $7 AND expires_at = $8",
        )
        .bind::<Text, _>(&expected.principal_id)
        .bind::<Text, _>(&expected.idempotency_key)
        .bind::<Text, _>(&expected.service_id)
        .bind::<Text, _>(&expected.request_hash)
        .bind::<Integer, _>(expected.response_status)
        .bind::<Jsonb, _>(&expected.response_body)
        .bind::<Timestamptz, _>(expected.created_at)
        .bind::<Timestamptz, _>(expected.expires_at)
        .bind::<Text, _>(&completed.service_id)
        .bind::<Text, _>(&completed.request_hash)
        .bind::<Integer, _>(completed.response_status)
        .bind::<Jsonb, _>(&completed.response_body)
        .bind::<Timestamptz, _>(completed.created_at)
        .bind::<Timestamptz, _>(completed.expires_at)
        .execute(&mut *conn)
        .await
        .map(|affected| affected == 1)
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
