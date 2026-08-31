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
    #[diesel(sql_type = Jsonb)]
    authenticated_actor: Value,
    #[diesel(sql_type = Text)]
    operation_id: String,
    #[diesel(sql_type = Text)]
    idempotency_key: String,
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
impl TryFrom<IdempotencyRow> for IdempotencyRecord {
    type Error = PersistenceError;

    fn try_from(row: IdempotencyRow) -> Result<Self, Self::Error> {
        Ok(Self {
            authenticated_actor: serde_json::from_value(row.authenticated_actor).map_err(
                |error| {
                    PersistenceError::SchemaViolation(format!(
                        "stored authenticated ActorId is invalid: {error}"
                    ))
                },
            )?,
            operation_id: row.operation_id,
            idempotency_key: row.idempotency_key,
            request_hash: row.request_hash,
            response_status: row.response_status,
            response_body: row.response_body,
            created_at: row.created_at,
            expires_at: row.expires_at,
        })
    }
}

fn actor_key(actor: &arkret_wire::ActorId) -> PersistenceResult<String> {
    actor.canonical_key().map_err(|error| {
        PersistenceError::SchemaViolation(format!("authenticated ActorId is invalid: {error}"))
    })
}

fn actor_value(actor: &arkret_wire::ActorId) -> PersistenceResult<Value> {
    serde_json::to_value(actor).map_err(|error| {
        PersistenceError::SchemaViolation(format!("authenticated ActorId encode failed: {error}"))
    })
}
#[async_trait]
impl IdempotencyStore for PgIdempotencyStore {
    async fn get(
        &self,
        authenticated_actor: &arkret_wire::ActorId,
        operation_id: &str,
        idempotency_key: &str,
    ) -> PersistenceResult<Option<IdempotencyRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let actor_key = actor_key(authenticated_actor)?;
        Ok(sql_query(
            "SELECT authenticated_actor, operation_id, idempotency_key, request_hash, response_status, \
             response_body, created_at, expires_at \
             FROM idempotency_keys WHERE actor_key = $1 AND operation_id = $2 AND idempotency_key = $3",
        )
        .bind::<Text, _>(&actor_key)
        .bind::<Text, _>(operation_id)
        .bind::<Text, _>(idempotency_key)
        .get_result::<IdempotencyRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(IdempotencyRecord::try_from)
        .transpose()?)
    }

    async fn record(&self, record: &IdempotencyRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let actor_key = actor_key(&record.authenticated_actor)?;
        let actor_value = actor_value(&record.authenticated_actor)?;
        // First-writer-wins under a concurrent race: the earliest row stays,
        // and a racer's later read returns it as a Replay.
        sql_query(
            "INSERT INTO idempotency_keys \
             (actor_key, authenticated_actor, operation_id, idempotency_key, request_hash, response_status, \
              response_body, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (actor_key, operation_id, idempotency_key) DO NOTHING",
        )
        .bind::<Text, _>(&actor_key)
        .bind::<Jsonb, _>(&actor_value)
        .bind::<Text, _>(&record.operation_id)
        .bind::<Text, _>(&record.idempotency_key)
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
        if expected.authenticated_actor != completed.authenticated_actor
            || expected.operation_id != completed.operation_id
            || expected.idempotency_key != completed.idempotency_key
        {
            return Ok(false);
        }
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let actor_key = actor_key(&expected.authenticated_actor)?;
        sql_query(
            "UPDATE idempotency_keys SET request_hash = $9, response_status = $10, \
             response_body = $11, created_at = $12, expires_at = $13 \
             WHERE actor_key = $1 AND operation_id = $2 AND idempotency_key = $3 \
             AND request_hash = $4 AND response_status = $5 AND response_body = $6 \
             AND created_at = $7 AND expires_at = $8",
        )
        .bind::<Text, _>(&actor_key)
        .bind::<Text, _>(&expected.operation_id)
        .bind::<Text, _>(&expected.idempotency_key)
        .bind::<Text, _>(&expected.request_hash)
        .bind::<Integer, _>(expected.response_status)
        .bind::<Jsonb, _>(&expected.response_body)
        .bind::<Timestamptz, _>(expected.created_at)
        .bind::<Timestamptz, _>(expected.expires_at)
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
