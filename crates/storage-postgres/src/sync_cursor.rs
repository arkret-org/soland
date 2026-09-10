use super::{
    BigInt, CursorRevocation, Jsonb, Nullable, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, QueryableByName, RunQueryDsl, SyncCursorRecord, SyncCursorStore,
    Text, Timestamptz, Utc, Value, async_trait, pg_conn, sql_query, sql_types,
};
mod current_detail;
mod retention;
use diesel_async::AsyncConnection;
pub struct PgSyncCursorStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct AccountWatermarksRow {
    #[diesel(sql_type = BigInt)]
    summary_revision: i64,
    #[diesel(sql_type = BigInt)]
    global_revision: i64,
}
#[derive(QueryableByName)]
struct GlobalReadRow {
    #[diesel(sql_type = Text)]
    item_key: String,
    #[diesel(sql_type = BigInt)]
    revision: i64,
    #[diesel(sql_type = sql_types::Bool)]
    deleted: bool,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
}
#[derive(QueryableByName)]
struct SummaryWatermarkRow {
    #[diesel(sql_type = BigInt)]
    revision: i64,
}
#[derive(QueryableByName)]
struct SummaryReadRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = BigInt)]
    revision: i64,
    #[diesel(sql_type = BigInt)]
    activity_position: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    valid_until: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    membership: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    title: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    default_strand_id: Option<String>,
    #[diesel(sql_type = sql_types::Bool)]
    invalidated: bool,
    #[diesel(sql_type = Nullable<Text>)]
    current_membership: Option<String>,
    #[diesel(sql_type = sql_types::Bool)]
    current_available: bool,
}
impl From<SummaryReadRow> for soland_storage::AccountSummaryVersion {
    fn from(row: SummaryReadRow) -> Self {
        Self {
            key: soland_storage::AccountSummaryKey {
                realm_id: row.realm_id,
                revision: row.revision,
                activity_position: row.activity_position,
            },
            valid_until: row.valid_until,
            membership: row.membership,
            title: row.title,
            default_strand_id: row.default_strand_id,
            invalidated: row.invalidated,
            current_membership: row.current_membership,
            current_available: row.current_available,
        }
    }
}

#[derive(QueryableByName)]
struct SyncCursorRow {
    #[diesel(sql_type = Text)]
    handle: String,
    #[diesel(sql_type = Nullable<Text>)]
    binding_subject: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    device_id: Option<String>,
    #[diesel(sql_type = Text)]
    service_id: arkret_identifiers::DidCoreId,
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
            binding_subject: row.binding_subject,
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
    async fn current_detail_page(
        &self,
        request: &soland_storage::CurrentDetailRequest,
        progress: Option<&soland_storage::CurrentDetailProgress>,
        byte_budget: usize,
        registry: &dyn arkret_state::state::CellRegistry,
    ) -> PersistenceResult<soland_storage::CurrentDetailOutcome> {
        current_detail::page(&self.pool, request, progress, byte_budget, registry).await
    }
    async fn account_summary_has_join(
        &self,
        actor_key: &str,
        realm_id: &str,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("SELECT revision FROM account_summary_current WHERE actor_key = $1 AND realm_id = $2 AND membership = 'join'")
            .bind::<Text, _>(actor_key).bind::<Text, _>(realm_id)
            .get_result::<SummaryWatermarkRow>(&mut *conn).await.optional()
            .map(|row| row.is_some()).map_err(PersistenceError::database)
    }

    async fn account_sync_watermarks(&self) -> PersistenceResult<(i64, i64)> {
        retention::freeze(&self.pool).await
    }
    async fn account_global_watermark(&self) -> PersistenceResult<i64> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("SELECT revision FROM account_global_clock WHERE singleton")
            .get_result::<SummaryWatermarkRow>(&mut *conn)
            .await
            .map(|row| row.revision)
            .map_err(PersistenceError::database)
    }
    async fn account_global_page(
        &self,
        actor_key: &str,
        channel: &str,
        watermark: i64,
        after_key: &str,
        after_revision: Option<i64>,
        limit: usize,
    ) -> PersistenceResult<Vec<soland_storage::AccountGlobalVersion>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, crate::PgTransactionError, _>(async |conn| {
            retention::check(conn, None, Some(after_revision.unwrap_or(watermark))).await?;
            let result: PersistenceResult<_> = async {
        let rows = sql_query("WITH candidates AS MATERIALIZED (SELECT item_key,revision,(deleted OR (channel='account_data_events' AND NOT EXISTS (SELECT 1 FROM accepted_events e WHERE e.kind='ak.account_data.set' AND e.envelope->>'event_id'=v.payload->'value'->>'event_id')) OR (channel='device_lists' AND NOT COALESCE(account_device_interest_visible(v.actor_key,v.item_key),FALSE))) AS deleted,CASE WHEN channel='account_data_events' AND NOT EXISTS (SELECT 1 FROM accepted_events e WHERE e.kind='ak.account_data.set' AND e.envelope->>'event_id'=v.payload->'value'->>'event_id') THEN jsonb_build_object('source','invalidated') ELSE payload END AS payload,octet_length(payload::text)+256 AS byte_count FROM account_global_versions v WHERE actor_key=$1 AND channel=$2 AND revision<=$3 AND (($5::bigint IS NULL AND item_key>$4 AND (valid_until IS NULL OR valid_until>$3)) OR ($5::bigint IS NOT NULL AND revision>$5)) ORDER BY CASE WHEN $5::bigint IS NULL THEN item_key ELSE '' END, revision LIMIT $6), bounded AS (SELECT *,sum(byte_count) OVER (ORDER BY CASE WHEN $5::bigint IS NULL THEN item_key ELSE '' END, revision) AS total FROM candidates) SELECT item_key,revision,deleted,CASE WHEN total>6291456 THEN jsonb_build_object('_budget_boundary',true,'_oversized',byte_count>6291456) ELSE payload END AS payload FROM bounded WHERE total-byte_count<=6291456 ORDER BY CASE WHEN $5::bigint IS NULL THEN item_key ELSE '' END,revision")
            .bind::<Text,_>(actor_key).bind::<Text,_>(channel).bind::<BigInt,_>(watermark).bind::<Text,_>(after_key).bind::<Nullable<BigInt>,_>(after_revision).bind::<BigInt,_>(limit.min(101) as i64)
            .load::<GlobalReadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(|row| {
                let mut payload = row.payload;
                if payload.get("_budget_boundary").is_some() {
                    return Ok(soland_storage::AccountGlobalVersion {
                        item_key: row.item_key,
                        revision: row.revision,
                        deleted: row.deleted,
                        payload,
                    });
                }
                if channel == "notifications" {
                    payload = crate::notifications::global_notification_payload(payload)?;
                }
                Ok(soland_storage::AccountGlobalVersion {
                    item_key: row.item_key,
                    revision: row.revision,
                    deleted: row.deleted,
                    payload,
                })
            })
            .collect()
            }.await;
            Ok(result?)
        }).await.map_err(crate::PgTransactionError::into_persistence)
    }

    async fn account_summary_watermark(&self) -> PersistenceResult<i64> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("SELECT revision FROM account_summary_clock WHERE singleton")
            .get_result::<SummaryWatermarkRow>(&mut *conn)
            .await
            .map(|row| row.revision)
            .map_err(PersistenceError::database)
    }

    async fn account_summary_page(
        &self,
        actor_key: &str,
        watermark: i64,
        after: Option<&soland_storage::AccountSummaryKey>,
        limit: usize,
    ) -> PersistenceResult<Vec<soland_storage::AccountSummaryVersion>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, crate::PgTransactionError, _>(async |conn| {
            retention::check(conn, Some(watermark), None).await?;
            let result: PersistenceResult<_> = async {
                // Limit the index scan itself before applying snapshot validity. Old
                // versions consume the scan budget and still advance the private key.
                sql_query(
                    "WITH candidates AS MATERIALIZED (
            SELECT * FROM account_summary_versions v WHERE actor_key = $1
              AND ($3::bigint IS NULL OR activity_position < $3
                OR (activity_position = $3 AND realm_id COLLATE \"C\" > $4 COLLATE \"C\")
                OR (activity_position = $3 AND realm_id = $4 AND revision < $5))
            ORDER BY activity_position DESC, realm_id COLLATE \"C\", revision DESC LIMIT $6
        ) SELECT v.realm_id, v.revision, v.activity_position, v.valid_until,
            v.membership, v.title, v.default_strand_id, v.invalidated,
            c.membership AS current_membership, COALESCE(c.available, FALSE) AS current_available
          FROM candidates v LEFT JOIN account_summary_current c
            ON c.actor_key = v.actor_key AND c.realm_id = v.realm_id
          WHERE $2 >= 0
          ORDER BY v.activity_position DESC, v.realm_id COLLATE \"C\", v.revision DESC",
                )
                .bind::<Text, _>(actor_key)
                .bind::<BigInt, _>(watermark)
                .bind::<Nullable<BigInt>, _>(after.map(|key| key.activity_position))
                .bind::<Nullable<Text>, _>(after.map(|key| key.realm_id.as_str()))
                .bind::<Nullable<BigInt>, _>(after.map(|key| key.revision))
                .bind::<BigInt, _>(limit.clamp(1, 200) as i64)
                .load::<SummaryReadRow>(&mut *conn)
                .await
                .map(|rows| rows.into_iter().map(Into::into).collect())
                .map_err(PersistenceError::database)
            }
            .await;
            Ok(result?)
        })
        .await
        .map_err(crate::PgTransactionError::into_persistence)
    }

    async fn account_summary_changes(
        &self,
        actor_key: &str,
        after: i64,
        limit: usize,
    ) -> PersistenceResult<Vec<soland_storage::AccountSummaryVersion>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, crate::PgTransactionError, _>(async |conn| {
            retention::check(conn, Some(after), None).await?;
            let result: PersistenceResult<_> = async {
                sql_query(
                    "WITH candidates AS MATERIALIZED (
            SELECT * FROM account_summary_versions WHERE actor_key = $1 AND revision > $2
            ORDER BY revision, realm_id COLLATE \"C\" LIMIT $3
        ) SELECT v.realm_id, v.revision, v.activity_position, v.valid_until,
            v.membership, v.title, v.default_strand_id, v.invalidated,
            c.membership AS current_membership, COALESCE(c.available, FALSE) AS current_available
          FROM candidates v LEFT JOIN account_summary_current c
            ON c.actor_key = v.actor_key AND c.realm_id = v.realm_id
          ORDER BY v.revision, v.realm_id COLLATE \"C\"",
                )
                .bind::<Text, _>(actor_key)
                .bind::<BigInt, _>(after)
                .bind::<BigInt, _>(limit.clamp(1, 100) as i64)
                .load::<SummaryReadRow>(&mut *conn)
                .await
                .map(|rows| rows.into_iter().map(Into::into).collect())
                .map_err(PersistenceError::database)
            }
            .await;
            Ok(result?)
        })
        .await
        .map_err(crate::PgTransactionError::into_persistence)
    }

    async fn get(&self, handle: &str) -> PersistenceResult<Option<SyncCursorRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id AS handle, binding_subject, device_id, service_id, filter_digest, purpose, \
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
        let floors = retention::cursor_floors(record)?;
        conn.transaction::<_, crate::PgTransactionError, _>(async |conn| {
            if let Some((summary, global)) = floors {
                retention::check(conn, Some(summary), Some(global)).await?;
            }
        // Dedup re-mint refreshes the expiry only; `issued_at_ms` remains
        // the original handle issuance time.
        sql_query(
            "INSERT INTO sync_cursor_handles \
             (id, binding_subject, device_id, service_id, filter_digest, purpose, positions, target, issued_at_ms, expires_at_ms) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (id) DO UPDATE SET expires_at_ms = EXCLUDED.expires_at_ms",
        )
        .bind::<Text, _>(&record.handle)
        .bind::<Nullable<Text>, _>(&record.binding_subject)
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
        .map_err(PersistenceError::database)?;
            retention::save_cursor(conn, record, floors).await?;
            Ok(())
        }).await.map_err(crate::PgTransactionError::into_persistence)
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

    async fn prune_expired(&self, now_ms: i64) -> PersistenceResult<usize> {
        retention::prune(&self.pool, now_ms).await
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
             (id, cursor_digest, account_id, device_id, scope, reason_code, revoked_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind::<sql_types::Uuid, _>(uuid::Uuid::now_v7())
        .bind::<Text, _>(&record.cursor_digest)
        .bind::<Jsonb, _>(serde_json::to_value(&record.account_id).map_err(PersistenceError::database)?)
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
            "SELECT cursor_digest, account_id, device_id, scope, reason_code, revoked_at, expires_at \
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
    #[diesel(sql_type = Jsonb)]
    account_id: Value,
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
            account_id: serde_json::from_value(row.account_id)
                .expect("stored cursor revocation account_id passed the database constraint"),
            device_id: row.device_id,
            scope: row.scope,
            reason_code: row.reason_code,
            revoked_at: row.revoked_at,
            expires_at: row.expires_at,
        }
    }
}

#[cfg(test)]
mod account_summary_query_tests {
    use diesel_async::SimpleAsyncConnection;

    use super::*;

    #[tokio::test]
    async fn frozen_pages_keep_scan_keys_and_recheck_current_permission() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let mut conn = pg_conn(&pool).await.unwrap();
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            "ak:did_core:web:exact.example".parse().unwrap(),
            "ak:did_core:web:station.example".parse().unwrap(),
        ))
        .canonical_key()
        .unwrap();
        let other = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            "ak:did_core:web:other.example".parse().unwrap(),
            "ak:did_core:web:station.example".parse().unwrap(),
        ))
        .canonical_key()
        .unwrap();
        let fixture = "INSERT INTO account_summary_current
            (actor_key, realm_id, revision, membership, title, available) VALUES
            ('exact-account', 'a', 4, 'knock', NULL, TRUE),
            ('exact-account', 'b', 5, NULL, NULL, TRUE),
            ('other-account', 'secret', 6, 'join', 'secret', TRUE);
            INSERT INTO account_summary_versions
            (actor_key, realm_id, revision, activity_position, valid_until, membership, title, invalidated) VALUES
            ('exact-account', 'a', 1, 1, 4, 'join', 'old private title', FALSE),
            ('exact-account', 'b', 2, 2, 5, 'join', 'revoked title', FALSE),
            ('exact-account', 'a', 4, 4, NULL, 'knock', NULL, TRUE),
            ('exact-account', 'b', 5, 5, NULL, NULL, NULL, TRUE),
            ('other-account', 'secret', 6, 6, NULL, 'join', 'secret', FALSE);"
            .replace("exact-account", &actor).replace("other-account", &other);
        conn.batch_execute(&fixture).await.unwrap();
        drop(conn);
        let store = PgSyncCursorStore { pool };
        let first = store
            .account_summary_page(&actor, 2, None, 2)
            .await
            .unwrap();
        assert_eq!(
            first.iter().map(|row| row.key.revision).collect::<Vec<_>>(),
            vec![5, 4]
        );
        let second = store
            .account_summary_page(&actor, 2, Some(&first[1].key), 2)
            .await
            .unwrap();
        assert_eq!(
            second
                .iter()
                .map(|row| row.key.revision)
                .collect::<Vec<_>>(),
            vec![2, 1]
        );
        assert!(second[0].current_membership.is_none());
        assert_eq!(second[1].current_membership.as_deref(), Some("knock"));
        assert_eq!(second[1].membership.as_deref(), Some("join"));
        let tail = store
            .account_summary_page(&actor, 2, Some(&second[1].key), 2)
            .await
            .unwrap();
        assert!(tail.is_empty());
        let changes = store.account_summary_changes(&actor, 2, 1).await.unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].key.revision, 4);
        assert_eq!(
            store.account_summary_changes(&actor, 4, 1).await.unwrap()[0]
                .key
                .revision,
            5
        );
    }
}
