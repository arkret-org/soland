use super::{
    BigInt, CursorRevocation, Jsonb, Nullable, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, QueryableByName, RunQueryDsl, SqlUuid, SyncCursorRecord,
    SyncCursorStore, Text, Timestamptz, Utc, Value, async_trait, pg_conn, sql_query,
};
pub struct PgSyncCursorStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct SyncCursorRow {
    #[diesel(sql_type = Text)]
    handle: String,
    #[diesel(sql_type = Nullable<Text>)]
    principal_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    device_id: Option<String>,
    #[diesel(sql_type = Text)]
    service_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    filter_digest: Option<String>,
    #[diesel(sql_type = Text)]
    purpose: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    positions: Option<Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    target: Option<Value>,
    #[diesel(sql_type = BigInt)]
    issued_at_ms: i64,
    #[diesel(sql_type = BigInt)]
    expires_at_ms: i64,
}
impl From<SyncCursorRow> for SyncCursorRecord {
    fn from(row: SyncCursorRow) -> Self {
        SyncCursorRecord {
            handle: row.handle,
            principal_id: row.principal_id,
            device_id: row.device_id,
            service_id: row.service_id,
            filter_digest: row.filter_digest,
            purpose: row.purpose,
            positions: row.positions,
            target: row.target,
            issued_at_ms: row.issued_at_ms,
            expires_at_ms: row.expires_at_ms,
        }
    }
}
#[async_trait]
impl SyncCursorStore for PgSyncCursorStore {
    async fn get(&self, handle: &str) -> PersistenceResult<Option<SyncCursorRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id AS handle, principal_id, device_id, service_id, filter_digest, purpose, \
             positions, target, issued_at_ms, expires_at_ms \
             FROM sync_cursor_handles WHERE id = $1",
        )
        .bind::<Text, _>(handle)
        .get_result::<SyncCursorRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(SyncCursorRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn upsert(&self, record: &SyncCursorRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        // Dedup re-mint refreshes the expiry only; `issued_at_ms` remains
        // the pruning watermark for this handle (see trait doc).
        sql_query(
            "INSERT INTO sync_cursor_handles \
             (id, principal_id, device_id, service_id, filter_digest, purpose, positions, target, issued_at_ms, expires_at_ms) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (id) DO UPDATE SET expires_at_ms = EXCLUDED.expires_at_ms",
        )
        .bind::<Text, _>(&record.handle)
        .bind::<Nullable<Text>, _>(&record.principal_id)
        .bind::<Nullable<Text>, _>(&record.device_id)
        .bind::<Text, _>(&record.service_id)
        .bind::<Nullable<Text>, _>(&record.filter_digest)
        .bind::<Text, _>(&record.purpose)
        .bind::<Nullable<Jsonb>, _>(&record.positions)
        .bind::<Nullable<Jsonb>, _>(&record.target)
        .bind::<BigInt, _>(record.issued_at_ms)
        .bind::<BigInt, _>(record.expires_at_ms)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn delete(&self, handle: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM sync_cursor_handles WHERE id = $1")
            .bind::<Text, _>(handle)
            .execute(&mut *conn)
            .await
            .map(|rows| rows > 0)
            .map_err(PersistenceError::database)
    }

    async fn prune_stream_superseded(
        &self,
        principal_id: &str,
        device_id: &str,
        filter_digest: &str,
        presented_issued_at_ms: i64,
    ) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "DELETE FROM sync_cursor_handles \
             WHERE purpose = 'stream' AND principal_id = $1 AND device_id = $2 \
             AND filter_digest = $3 AND issued_at_ms < $4",
        )
        .bind::<Text, _>(principal_id)
        .bind::<Text, _>(device_id)
        .bind::<Text, _>(filter_digest)
        .bind::<BigInt, _>(presented_issued_at_ms)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)
    }

    async fn prune_expired(&self, now_ms: i64) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM sync_cursor_handles WHERE expires_at_ms <= $1")
            .bind::<BigInt, _>(now_ms)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)
    }

    async fn record_revocation(&self, record: &CursorRevocation) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        // Opportunistic TTL sweep on every write keeps the ledger bounded by
        // CURSOR_MAX_TTL_SECONDS — mirrors the in-memory cache's retain-then-
        // push behaviour.
        sql_query("DELETE FROM sync_cursor_revocations WHERE expires_at <= $1")
            .bind::<Timestamptz, _>(record.revoked_at)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO sync_cursor_revocations \
             (id, cursor_digest, principal_id, device_id, scope, reason_code, revoked_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind::<SqlUuid, _>(uuid::Uuid::now_v7())
        .bind::<Text, _>(&record.cursor_digest)
        .bind::<Text, _>(&record.principal_id)
        .bind::<Nullable<Text>, _>(&record.device_id)
        .bind::<Text, _>(&record.scope)
        .bind::<Text, _>(&record.reason_code)
        .bind::<Timestamptz, _>(record.revoked_at)
        .bind::<Timestamptz, _>(record.expires_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn active_revocations(
        &self,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<Vec<CursorRevocation>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT cursor_digest, principal_id, device_id, scope, reason_code, revoked_at, expires_at \
             FROM sync_cursor_revocations WHERE expires_at > $1 \
             ORDER BY revoked_at ASC",
        )
        .bind::<Timestamptz, _>(now)
        .load::<CursorRevocationRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        Ok(rows.into_iter().map(CursorRevocation::from).collect())
    }
}
#[derive(QueryableByName)]
struct CursorRevocationRow {
    #[diesel(sql_type = Text)]
    cursor_digest: String,
    #[diesel(sql_type = Text)]
    principal_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    device_id: Option<String>,
    #[diesel(sql_type = Text)]
    scope: String,
    #[diesel(sql_type = Text)]
    reason_code: String,
    #[diesel(sql_type = Timestamptz)]
    revoked_at: chrono::DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<Utc>,
}
impl From<CursorRevocationRow> for CursorRevocation {
    fn from(row: CursorRevocationRow) -> Self {
        Self {
            cursor_digest: row.cursor_digest,
            principal_id: row.principal_id,
            device_id: row.device_id,
            scope: row.scope,
            reason_code: row.reason_code,
            revoked_at: row.revoked_at,
            expires_at: row.expires_at,
        }
    }
}
