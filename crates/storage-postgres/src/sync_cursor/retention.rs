//! Durable read retention, shared by snapshot creation, cursor writes and GC.
use super::*;
use crate::{AsyncPgConnection, PgTransactionError};

const LOCK_KEY: i64 = 0x414b_5359_4e43;

#[derive(QueryableByName)]
struct Floors {
    #[diesel(sql_type = BigInt)]
    summary_floor: i64,
    #[diesel(sql_type = BigInt)]
    global_floor: i64,
}

pub(super) async fn lock(
    conn: &mut AsyncPgConnection,
    exclusive: bool,
) -> Result<(), PgTransactionError> {
    let sql = if exclusive {
        "SELECT pg_advisory_xact_lock($1)"
    } else {
        "SELECT pg_advisory_xact_lock_shared($1)"
    };
    sql_query(sql)
        .bind::<BigInt, _>(LOCK_KEY)
        .execute(conn)
        .await?;
    Ok(())
}

/// The caller keeps the transaction open through its indexed read/write.
pub(super) async fn check(
    conn: &mut AsyncPgConnection,
    summary: Option<i64>,
    global: Option<i64>,
) -> Result<(), PgTransactionError> {
    lock(conn, false).await?;
    let floors =
        sql_query("SELECT summary_floor,global_floor FROM account_sync_retention WHERE singleton")
            .get_result::<Floors>(conn)
            .await?;
    if summary.is_some_and(|cut| cut < floors.summary_floor)
        || global.is_some_and(|cut| cut < floors.global_floor)
    {
        return Err(PersistenceError::Conflict(
            "cursor_expired: account read position was reclaimed".into(),
        )
        .into());
    }
    Ok(())
}

pub(super) async fn freeze(pool: &PgPool) -> PersistenceResult<(i64, i64)> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async |conn| freeze_on_connection(conn).await)
        .await
        .map_err(PgTransactionError::into_persistence)
}

/// Call before reading window authority or coverage, in the same transaction.
/// The caller must not hold a clock/source row lock before taking this lease.
pub(super) async fn freeze_on_connection(
    conn: &mut AsyncPgConnection,
) -> Result<(i64, i64), PgTransactionError> {
    // Acquire before taking the statement snapshot: waiting on GC with an
    // earlier MVCC snapshot could otherwise register an already-reclaimed cut.
    lock(conn, true).await?;
    let cut = sql_query("SELECT s.revision AS summary_revision,g.revision AS global_revision FROM account_summary_clock s CROSS JOIN account_global_clock g WHERE s.singleton AND g.singleton FOR SHARE OF s")
            .get_result::<AccountWatermarksRow>(&mut *conn).await?;
    // One global protection bucket per minute coalesces concurrent initial
    // reads. It grants no access authority and contains no account data.
    sql_query("INSERT INTO account_sync_snapshot_reservations(bucket,summary_floor,global_floor,expires_at_ms) VALUES(floor(extract(epoch FROM clock_timestamp())/60)::bigint,$1,$2,(extract(epoch FROM clock_timestamp())*1000)::bigint+3660000) ON CONFLICT(bucket) DO UPDATE SET summary_floor=LEAST(account_sync_snapshot_reservations.summary_floor,EXCLUDED.summary_floor),global_floor=LEAST(account_sync_snapshot_reservations.global_floor,EXCLUDED.global_floor),expires_at_ms=GREATEST(account_sync_snapshot_reservations.expires_at_ms,EXCLUDED.expires_at_ms)")
            .bind::<BigInt,_>(cut.summary_revision).bind::<BigInt,_>(cut.global_revision).execute(&mut *conn).await?;
    Ok((cut.summary_revision, cut.global_revision))
}

fn integer(value: Option<&Value>) -> PersistenceResult<i64> {
    value
        .and_then(Value::as_i64)
        .filter(|value| *value >= 0)
        .ok_or_else(|| {
            PersistenceError::SchemaViolation(
                "account retention position is absent or negative".into(),
            )
        })
}

pub(super) fn cursor_floors(record: &SyncCursorRecord) -> PersistenceResult<Option<(i64, i64)>> {
    match record.purpose.as_str() {
        "realm_list" => {
            let target = record
                .target
                .as_ref()
                .ok_or_else(|| PersistenceError::SchemaViolation("list target absent".into()))?;
            Ok(Some((
                integer(target.get("watermark"))?,
                integer(target.get("global_watermark"))?,
            )))
        }
        "ak.self.account.stream.subscribe.v1" => {
            let positions = record.positions.as_ref().ok_or_else(|| {
                PersistenceError::SchemaViolation("account positions absent".into())
            })?;
            let mut summary = integer(positions.get("account_summary"))?;
            if let Some(details) = positions.get("detail_positions") {
                let details = details.as_object().ok_or_else(|| {
                    PersistenceError::SchemaViolation(
                        "current detail positions are not an object".into(),
                    )
                })?;
                for detail in details.values() {
                    summary = summary.min(integer(detail.get("retained_revision"))?);
                }
            }
            let Some(progress) = positions
                .get("global_baseline")
                .filter(|value| !value.is_null())
            else {
                return Ok(Some((summary, 0)));
            };
            let snapshot = integer(progress.get("snapshot_watermark"))?;
            let completed = progress
                .get("completed")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    PersistenceError::SchemaViolation("global completed channels absent".into())
                })?;
            let mut global = i64::MAX;
            for channel in [
                "account_data_events",
                "station_cas",
                "notifications",
                "device_lists",
            ] {
                let position = if completed
                    .iter()
                    .any(|value| value.as_str() == Some(channel))
                {
                    integer(
                        progress
                            .get("positions")
                            .and_then(|positions| positions.get(channel)),
                    )?
                } else {
                    snapshot
                };
                global = global.min(position);
            }
            Ok(Some((summary, global)))
        }
        _ => Ok(None),
    }
}

pub(super) async fn save_cursor(
    conn: &mut AsyncPgConnection,
    record: &SyncCursorRecord,
    floors: Option<(i64, i64)>,
) -> Result<(), PgTransactionError> {
    if let Some((summary, global)) = floors {
        sql_query("INSERT INTO account_sync_cursor_retention(handle,summary_floor,global_floor) VALUES($1,$2,$3) ON CONFLICT(handle) DO NOTHING")
            .bind::<Text,_>(&record.handle).bind::<BigInt,_>(summary).bind::<BigInt,_>(global).execute(conn).await?;
    }
    Ok(())
}

pub(super) async fn prune(pool: &PgPool, now_ms: i64) -> PersistenceResult<usize> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_,PgTransactionError,_>(async |conn| {
        lock(conn,true).await?;
        let pruned = sql_query("DELETE FROM sync_cursor_handles WHERE id IN (SELECT id FROM sync_cursor_handles WHERE expires_at_ms<=$1 ORDER BY expires_at_ms LIMIT 10000)")
            .bind::<BigInt,_>(now_ms).execute(&mut *conn).await?;
        sql_query("DELETE FROM account_sync_snapshot_reservations WHERE expires_at_ms<=$1")
            .bind::<BigInt,_>(now_ms).execute(&mut *conn).await?;
        // Indexed minima avoid scanning every active handle. Expired handles
        // awaiting the next bounded deletion batch conservatively retain data.
        let floors = sql_query("SELECT LEAST(COALESCE((SELECT min(summary_floor) FROM account_sync_snapshot_reservations),s.revision),COALESCE((SELECT summary_floor FROM account_sync_cursor_retention ORDER BY summary_floor LIMIT 1),s.revision)) AS summary_floor,LEAST(COALESCE((SELECT min(global_floor) FROM account_sync_snapshot_reservations),g.revision),COALESCE((SELECT global_floor FROM account_sync_cursor_retention ORDER BY global_floor LIMIT 1),g.revision)) AS global_floor FROM account_summary_clock s CROSS JOIN account_global_clock g WHERE s.singleton AND g.singleton")
            .get_result::<Floors>(&mut *conn).await?;
        sql_query("UPDATE account_sync_retention SET summary_floor=GREATEST(summary_floor,$1),global_floor=GREATEST(global_floor,$2) WHERE singleton")
            .bind::<BigInt,_>(floors.summary_floor).bind::<BigInt,_>(floors.global_floor).execute(&mut *conn).await?;
        // Closed versions only. Current values and tombstones remain available
        // to a fresh baseline. Work per sweep is bounded independently of history.
        sql_query("DELETE FROM account_summary_versions WHERE ctid IN (SELECT ctid FROM account_summary_versions WHERE valid_until<=$1 ORDER BY valid_until LIMIT 10000)")
            .bind::<BigInt,_>(floors.summary_floor).execute(&mut *conn).await?;
        sql_query("DELETE FROM current_result_versions WHERE ctid IN (SELECT ctid FROM current_result_versions WHERE valid_until<=$1 ORDER BY valid_until LIMIT 10000)")
            .bind::<BigInt,_>(floors.summary_floor).execute(&mut *conn).await?;
        sql_query("DELETE FROM account_global_versions WHERE ctid IN (SELECT ctid FROM account_global_versions WHERE valid_until<=$1 ORDER BY valid_until LIMIT 10000)")
            .bind::<BigInt,_>(floors.global_floor).execute(&mut *conn).await?;
        Ok(pruned)
    }).await.map_err(PgTransactionError::into_persistence)
}

#[cfg(test)]
mod tests {
    use diesel_async::SimpleAsyncConnection;

    use super::*;

    #[tokio::test]
    async fn snapshot_then_cursor_retains_versions_and_expiry_rejects_old_positions() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let store = PgSyncCursorStore { pool: pool.clone() };
        let mut conn = pg_conn(&pool).await.unwrap();
        conn.batch_execute("UPDATE account_summary_clock SET revision=1; UPDATE account_global_clock SET revision=1;
            INSERT INTO account_summary_versions(actor_key,realm_id,revision,activity_position,membership,title,invalidated) VALUES('actor','realm',1,1,'join','old',false);
            INSERT INTO account_global_versions(actor_key,channel,item_key,channel_position,revision,payload) VALUES('actor','station_cas','key',1,1,'{}');
            INSERT INTO current_result_versions(realm_id,selector_key,revision,target_kind,target_key,payload) VALUES('realm','selector',1,'realm','','{}');").await.unwrap();
        assert_eq!(store.account_sync_watermarks().await.unwrap(), (1, 1));
        conn.batch_execute("UPDATE account_summary_clock SET revision=2; UPDATE account_global_clock SET revision=2;
            UPDATE account_summary_versions SET valid_until=2;
            INSERT INTO account_summary_versions(actor_key,realm_id,revision,activity_position,membership,title,invalidated) VALUES('actor','realm',2,2,'join','new',false);
            UPDATE account_global_versions SET valid_until=2;
            INSERT INTO account_global_versions(actor_key,channel,item_key,channel_position,revision,payload) VALUES('actor','station_cas','key',2,2,'{}');
            UPDATE current_result_versions SET valid_until=2;
            INSERT INTO current_result_versions(realm_id,selector_key,revision,target_kind,target_key,payload) VALUES('realm','selector',2,'realm','','{}');").await.unwrap();
        let now = Utc::now().timestamp_millis();
        store.prune_expired(now).await.unwrap();
        let frozen = store
            .account_global_page("actor", "station_cas", 1, "", None, 10)
            .await
            .unwrap();
        assert_eq!(frozen.len(), 1);
        assert_eq!(frozen[0].revision, 1);
        let retained_current =
            sql_query("SELECT count(*)::bigint AS revision FROM current_result_versions")
                .get_result::<SummaryWatermarkRow>(&mut *conn)
                .await
                .unwrap();
        assert_eq!(retained_current.revision, 2);
        let cursor = SyncCursorRecord {
            handle: "retained-list".into(),
            binding_subject: Some("account".into()),
            device_id: Some("device".into()),
            service_id: arkret_identifiers::DidCoreId::new("ak:did_core:web:station.example")
                .unwrap(),
            filter_digest: None,
            purpose: "realm_list".into(),
            positions: None,
            target: Some(serde_json::json!({"watermark":1,"global_watermark":1})),
            issued_at_ms: now,
            expires_at_ms: now + 3_600_000,
        };
        store.upsert(&cursor).await.unwrap();
        conn.batch_execute("UPDATE account_sync_snapshot_reservations SET expires_at_ms=0")
            .await
            .unwrap();
        store.prune_expired(now).await.unwrap();
        let restarted = PgSyncCursorStore { pool: pool.clone() };
        assert_eq!(
            restarted
                .account_global_page("actor", "station_cas", 1, "", None, 10)
                .await
                .unwrap()[0]
                .revision,
            1
        );
        store.delete(&cursor.handle).await.unwrap();
        store.prune_expired(now).await.unwrap();
        assert!(
            store
                .account_global_page("actor", "station_cas", 1, "", None, 10)
                .await
                .is_err()
        );
        assert!(
            store
                .account_summary_page("actor", 1, None, 10)
                .await
                .is_err()
        );
        assert!(store.account_summary_changes("actor", 1, 10).await.is_err());
        assert!(store.upsert(&cursor).await.is_err());
        assert_eq!(
            store
                .account_global_page("actor", "station_cas", 2, "", None, 10)
                .await
                .unwrap()
                .len(),
            1
        );
        let count = sql_query("SELECT count(*)::bigint AS revision FROM account_global_versions")
            .get_result::<SummaryWatermarkRow>(&mut *conn)
            .await
            .unwrap();
        assert_eq!(count.revision, 1);
        let count = sql_query("SELECT count(*)::bigint AS revision FROM current_result_versions")
            .get_result::<SummaryWatermarkRow>(&mut *conn)
            .await
            .unwrap();
        assert_eq!(count.revision, 1);
    }

    #[tokio::test]
    async fn waiting_snapshot_reads_its_cut_after_the_gc_lock() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let mut conn = pg_conn(&pool).await.unwrap();
        conn.batch_execute("BEGIN").await.unwrap();
        lock(&mut conn, true)
            .await
            .map_err(PgTransactionError::into_persistence)
            .unwrap();
        let freeze_pool = pool.clone();
        let mut pending = tokio::spawn(async move { freeze(&freeze_pool).await });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut pending)
                .await
                .is_err()
        );
        conn.batch_execute("UPDATE account_summary_clock SET revision=7; UPDATE account_global_clock SET revision=9;
            UPDATE account_sync_retention SET summary_floor=7,global_floor=9; COMMIT").await.unwrap();
        assert_eq!(pending.await.unwrap().unwrap(), (7, 9));
        let reserved =
            sql_query("SELECT summary_floor,global_floor FROM account_sync_snapshot_reservations")
                .get_result::<Floors>(&mut *conn)
                .await
                .unwrap();
        assert_eq!((reserved.summary_floor, reserved.global_floor), (7, 9));
    }
}
