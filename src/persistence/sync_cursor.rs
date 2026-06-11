use super::*;

/// Stateful sync-cursor handle binding (`cursor.schema.json` `h`).
///
/// One row per distinct cursor content: the handle is an HMAC digest of the
/// binding (principal, device, service, filter, purpose, positions/target),
/// so re-minting an unchanged cursor upserts the same row instead of growing
/// the table. Durable so a server restart does not invalidate every client's
/// resume cursor with `cursor_integrity_invalid`.
///
/// `principal_id` / `device_id` / `filter_digest` are `None` for generic
/// service-level cursors (`sync_token_for_state`), which bind no session and
/// are rejected by `parse_and_validate_sync_cursor` by construction.
#[derive(Clone, Debug, PartialEq)]
pub struct SyncCursorRecord {
    pub handle: String,
    pub principal_id: Option<String>,
    pub device_id: Option<String>,
    pub service_id: String,
    pub filter_digest: Option<String>,
    pub purpose: String,
    pub positions: Option<Value>,
    pub target: Option<Value>,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}

/// Durable handle table behind the stateful sync cursor.
///
/// `upsert` keeps the FIRST `issued_at_ms` on conflict (refreshing only the
/// expiry): `issued_at_ms` means "when this position frontier was reached",
/// and the incremental-sync skip optimisation reads it to elide unchanged
/// realms — advancing it on a dedup re-mint could skip deltas a crashed
/// client never persisted.
#[async_trait]
pub trait SyncCursorStore: Send + Sync {
    async fn get(&self, handle: &str) -> PersistenceResult<Option<SyncCursorRecord>>;
    async fn upsert(&self, record: &SyncCursorRecord) -> PersistenceResult<()>;
    /// Delete one handle (cursor revoke).
    async fn delete(&self, handle: &str) -> PersistenceResult<bool>;
    /// Forward-progress cleanup: delete this stream's rows STRICTLY older
    /// than the cursor the client just presented (presenting a cursor proves
    /// everything older was persisted client-side). Never deletes the
    /// presented row itself or anything newer.
    async fn prune_stream_superseded(
        &self,
        principal_id: &str,
        device_id: &str,
        filter_digest: &str,
        presented_issued_at_ms: i64,
    ) -> PersistenceResult<usize>;
    /// TTL sweep: drop every row whose `expires_at_ms` is at or before `now_ms`.
    async fn prune_expired(&self, now_ms: i64) -> PersistenceResult<usize>;
    /// Append a cursor-authority revocation (`ck.self.account.cursor_revoke`)
    /// to the durable ledger. Expired ledger rows are swept opportunistically
    /// on every write so the table stays bounded by `CURSOR_MAX_TTL_SECONDS`.
    ///
    /// Durability here is a security property: a revoked cursor MUST stay
    /// revoked across a process restart (spec `client-sync.md` cursor-revoke
    /// semantics), so the in-memory revocation cache on `AppState` is
    /// hydrated from this ledger at boot.
    async fn record_revocation(&self, record: &CursorRevocation) -> PersistenceResult<()>;
    /// Every revocation whose GC horizon (`expires_at`) is still in the
    /// future. Used to hydrate the in-memory revocation cache at boot.
    async fn active_revocations(
        &self,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<Vec<CursorRevocation>>;
}

/// In-memory `handle -> SyncCursorRecord` table. Mirrors the
/// `sync_cursor_handles` Pg table on the same primary key.
pub(crate) struct MemorySyncCursorStore {
    data: Arc<Mutex<BTreeMap<String, SyncCursorRecord>>>,
    revocations: Arc<Mutex<Vec<CursorRevocation>>>,
}

impl MemorySyncCursorStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
            revocations: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait]
impl SyncCursorStore for MemorySyncCursorStore {
    async fn get(&self, handle: &str) -> PersistenceResult<Option<SyncCursorRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(handle).cloned())
    }

    async fn upsert(&self, record: &SyncCursorRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        match data.get_mut(&record.handle) {
            // Dedup re-mint: refresh the expiry only; `issued_at_ms` keeps
            // marking when this position frontier was first reached (see
            // trait doc).
            Some(existing) => existing.expires_at_ms = record.expires_at_ms,
            None => {
                data.insert(record.handle.clone(), record.clone());
            }
        }
        Ok(())
    }

    async fn delete(&self, handle: &str) -> PersistenceResult<bool> {
        let mut data = self.data.lock().expect("lock");
        Ok(data.remove(handle).is_some())
    }

    async fn prune_stream_superseded(
        &self,
        principal_id: &str,
        device_id: &str,
        filter_digest: &str,
        presented_issued_at_ms: i64,
    ) -> PersistenceResult<usize> {
        let mut data = self.data.lock().expect("lock");
        let before = data.len();
        data.retain(|_, record| {
            !(record.purpose == "stream"
                && record.principal_id.as_deref() == Some(principal_id)
                && record.device_id.as_deref() == Some(device_id)
                && record.filter_digest.as_deref() == Some(filter_digest)
                && record.issued_at_ms < presented_issued_at_ms)
        });
        Ok(before - data.len())
    }

    async fn prune_expired(&self, now_ms: i64) -> PersistenceResult<usize> {
        let mut data = self.data.lock().expect("lock");
        let before = data.len();
        data.retain(|_, record| record.expires_at_ms > now_ms);
        Ok(before - data.len())
    }

    async fn record_revocation(&self, record: &CursorRevocation) -> PersistenceResult<()> {
        let mut revocations = self.revocations.lock().expect("lock");
        revocations.retain(|entry| entry.expires_at > record.revoked_at);
        revocations.push(record.clone());
        Ok(())
    }

    async fn active_revocations(
        &self,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<Vec<CursorRevocation>> {
        let revocations = self.revocations.lock().expect("lock");
        Ok(revocations
            .iter()
            .filter(|entry| entry.expires_at > now)
            .cloned()
            .collect())
    }
}

pub(crate) struct PgSyncCursorStore {
    pub(crate) pool: PgPool,
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
        let mut conn = pg_conn(&self.pool).await?;
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
        .map_err(PersistenceError::from)
    }

    async fn upsert(&self, record: &SyncCursorRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        // Dedup re-mint refreshes the expiry only; `issued_at_ms` keeps
        // marking when this position frontier was first reached (see trait
        // doc).
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
        .map_err(PersistenceError::from)
    }

    async fn delete(&self, handle: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM sync_cursor_handles WHERE id = $1")
            .bind::<Text, _>(handle)
            .execute(&mut *conn)
            .await
            .map(|rows| rows > 0)
            .map_err(PersistenceError::from)
    }

    async fn prune_stream_superseded(
        &self,
        principal_id: &str,
        device_id: &str,
        filter_digest: &str,
        presented_issued_at_ms: i64,
    ) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .map_err(PersistenceError::from)
    }

    async fn prune_expired(&self, now_ms: i64) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM sync_cursor_handles WHERE expires_at_ms <= $1")
            .bind::<BigInt, _>(now_ms)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::from)
    }

    async fn record_revocation(&self, record: &CursorRevocation) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        // Opportunistic TTL sweep on every write keeps the ledger bounded by
        // CURSOR_MAX_TTL_SECONDS — mirrors the in-memory cache's retain-then-
        // push behaviour.
        sql_query("DELETE FROM sync_cursor_revocations WHERE expires_at <= $1")
            .bind::<Timestamptz, _>(record.revoked_at)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::from)?;
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
        .map_err(PersistenceError::from)
    }

    async fn active_revocations(
        &self,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<Vec<CursorRevocation>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT cursor_digest, principal_id, device_id, scope, reason_code, revoked_at, expires_at \
             FROM sync_cursor_revocations WHERE expires_at > $1 \
             ORDER BY revoked_at ASC",
        )
        .bind::<Timestamptz, _>(now)
        .load::<CursorRevocationRow>(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
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

// ── G3.S1: Pg MLS lifecycle stores ────────────────────────────────────
