use arkret_identifiers::RealmId;
use arkret_state::state::{
    ControlSealAttemptCompletion, ControlSealAttemptOutcome, ControlSealScheduleClaim,
    ControlSealScheduleRepairStats, ControlSealScheduleStats,
};
use diesel::sql_types::{BigInt, Bool, Integer, Nullable, Text};
use diesel::{OptionalExtension, QueryResult, QueryableByName, sql_query};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};

#[derive(QueryableByName)]
struct ClaimRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = BigInt)]
    generation: i64,
    #[diesel(sql_type = BigInt)]
    claim_fence: i64,
    #[diesel(sql_type = Nullable<Text>)]
    scan_cursor: Option<String>,
    #[diesel(sql_type = Bool)]
    isolate_candidates: bool,
}

#[derive(QueryableByName)]
struct ScheduleRow {
    #[diesel(sql_type = BigInt)]
    generation: i64,
    #[diesel(sql_type = Nullable<Text>)]
    claim_holder: Option<String>,
    #[diesel(sql_type = BigInt)]
    claim_fence: i64,
    #[diesel(sql_type = Integer)]
    consecutive_failures: i32,
}

#[derive(QueryableByName)]
struct PendingRealmRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = BigInt)]
    generation: i64,
}

#[derive(QueryableByName)]
struct GenerationRow {
    #[diesel(sql_type = BigInt)]
    generation: i64,
}

#[derive(QueryableByName)]
struct CursorRow {
    #[diesel(sql_type = Nullable<Text>)]
    after_realm_id: Option<String>,
}

#[derive(QueryableByName)]
struct ExistsRow {
    #[diesel(sql_type = Bool)]
    present: bool,
}

#[derive(QueryableByName)]
struct StatsRow {
    #[diesel(sql_type = BigInt)]
    pending: i64,
    #[diesel(sql_type = BigInt)]
    eligible: i64,
    #[diesel(sql_type = BigInt)]
    claimed: i64,
    #[diesel(sql_type = BigInt)]
    expired_claims: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    oldest_pending_at_ms: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    oldest_eligible_at_ms: Option<i64>,
}

fn invalid_stored_realm(error: arkret_identifiers::IdentifierError) -> diesel::result::Error {
    diesel::result::Error::DeserializationError(Box::new(error))
}

pub(crate) async fn upsert_for_control_event(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
) -> QueryResult<()> {
    sql_query(
        "WITH current_generation AS ( \
             SELECT COUNT(*)::bigint AS generation \
             FROM state_control_events WHERE realm_id = $1 \
         ), clock AS ( \
             SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint AS now_ms \
         ) \
         INSERT INTO state_control_seal_schedule \
           (realm_id, generation, first_pending_at_ms, next_attempt_at_ms) \
         SELECT $1, current_generation.generation, clock.now_ms, clock.now_ms \
         FROM current_generation, clock WHERE current_generation.generation > 0 \
         ON CONFLICT (realm_id) DO UPDATE SET \
           generation = EXCLUDED.generation, \
           next_attempt_at_ms = CASE \
             WHEN state_control_seal_schedule.generation < EXCLUDED.generation \
               THEN LEAST(state_control_seal_schedule.next_attempt_at_ms, EXCLUDED.next_attempt_at_ms) \
             ELSE state_control_seal_schedule.next_attempt_at_ms \
           END, \
           consecutive_failures = CASE \
             WHEN state_control_seal_schedule.generation < EXCLUDED.generation THEN 0 \
             ELSE state_control_seal_schedule.consecutive_failures \
           END, \
           last_outcome = CASE \
             WHEN state_control_seal_schedule.generation < EXCLUDED.generation THEN NULL \
             ELSE state_control_seal_schedule.last_outcome \
           END",
    )
    .bind::<Text, _>(realm_id)
    .execute(conn)
    .await?;
    Ok(())
}

pub(crate) async fn claim_due(
    conn: &mut AsyncPgConnection,
    holder: &str,
    now_ms: i64,
    claim_until_ms: i64,
    limit: usize,
) -> QueryResult<Vec<ControlSealScheduleClaim>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let rows = sql_query(
        "WITH due AS ( \
             SELECT realm_id, (consecutive_failures > 0 OR claim_holder IS NOT NULL) AS isolate_candidates \
             FROM state_control_seal_schedule \
             WHERE next_attempt_at_ms <= $1 \
               AND (claim_holder IS NULL OR claim_until_ms <= $1) \
             ORDER BY next_attempt_at_ms, first_pending_at_ms, realm_id \
             LIMIT $2 FOR UPDATE SKIP LOCKED \
         ) \
         UPDATE state_control_seal_schedule AS schedule SET \
           claim_holder = $3, \
           claim_fence = schedule.claim_fence + 1, \
           claim_until_ms = $4, \
           last_attempt_at_ms = $1 \
         FROM due WHERE schedule.realm_id = due.realm_id \
         RETURNING schedule.realm_id, schedule.generation, schedule.claim_fence, schedule.scan_cursor, due.isolate_candidates",
    )
    .bind::<BigInt, _>(now_ms)
    .bind::<BigInt, _>(limit as i64)
    .bind::<Text, _>(holder)
    .bind::<BigInt, _>(claim_until_ms)
    .load::<ClaimRow>(conn)
    .await?;
    let mut claims = rows
        .into_iter()
        .map(|row| {
            Ok(ControlSealScheduleClaim {
                isolate_candidates: row.isolate_candidates,
                scan_cursor: row
                    .scan_cursor
                    .map(arkret_identifiers::Hash::new)
                    .transpose()
                    .map_err(|error| {
                        diesel::result::Error::DeserializationError(Box::new(error))
                    })?,
                realm_id: RealmId::new(row.realm_id).map_err(invalid_stored_realm)?,
                generation: u64::try_from(row.generation).map_err(|error| {
                    diesel::result::Error::DeserializationError(Box::new(error))
                })?,
                holder: holder.to_owned(),
                fence: u64::try_from(row.claim_fence).map_err(|error| {
                    diesel::result::Error::DeserializationError(Box::new(error))
                })?,
                claimed_at_ms: now_ms,
                claim_until_ms,
            })
        })
        .collect::<QueryResult<Vec<_>>>()?;
    claims.sort_by(|left, right| left.realm_id.cmp(&right.realm_id));
    Ok(claims)
}

pub(crate) async fn complete_attempt(
    conn: &mut AsyncPgConnection,
    claim: &ControlSealScheduleClaim,
    outcome: &ControlSealAttemptOutcome,
    observed_at_ms: i64,
) -> QueryResult<ControlSealAttemptCompletion> {
    conn.transaction::<_, diesel::result::Error, _>(async move |conn| {
        let row = sql_query(
            "SELECT generation, claim_holder, claim_fence, consecutive_failures \
             FROM state_control_seal_schedule WHERE realm_id = $1 FOR UPDATE",
        )
        .bind::<Text, _>(claim.realm_id.as_str())
        .get_result::<ScheduleRow>(&mut *conn)
        .await
        .optional()?;
        let Some(row) = row else {
            return Ok(ControlSealAttemptCompletion::StaleClaim);
        };
        if row.claim_holder.as_deref() != Some(claim.holder.as_str())
            || u64::try_from(row.claim_fence).ok() != Some(claim.fence)
        {
            return Ok(ControlSealAttemptCompletion::StaleClaim);
        }
        if u64::try_from(row.generation).ok() != Some(claim.generation) {
            sql_query(
                "UPDATE state_control_seal_schedule SET \
                   claim_holder = NULL, claim_until_ms = NULL, \
                   next_attempt_at_ms = LEAST(next_attempt_at_ms, $2) \
                 WHERE realm_id = $1 AND claim_holder = $3 AND claim_fence = $4",
            )
            .bind::<Text, _>(claim.realm_id.as_str())
            .bind::<BigInt, _>(observed_at_ms)
            .bind::<Text, _>(&claim.holder)
            .bind::<BigInt, _>(claim.fence as i64)
            .execute(&mut *conn)
            .await?;
            return Ok(ControlSealAttemptCompletion::ReleasedNewGeneration);
        }
        let pending = sql_query(
            "SELECT EXISTS( \
               SELECT 1 FROM state_control_events c \
               WHERE c.realm_id = $1 \
                 AND c.is_pending \
             ) AS present",
        )
        .bind::<Text, _>(claim.realm_id.as_str())
        .get_result::<ExistsRow>(&mut *conn)
        .await?
        .present;
        if !pending {
            sql_query(
                "DELETE FROM state_control_seal_schedule \
                 WHERE realm_id = $1 AND claim_holder = $2 AND claim_fence = $3",
            )
            .bind::<Text, _>(claim.realm_id.as_str())
            .bind::<Text, _>(&claim.holder)
            .bind::<BigInt, _>(claim.fence as i64)
            .execute(&mut *conn)
            .await?;
            return Ok(ControlSealAttemptCompletion::Applied);
        }
        let failures = if outcome.is_failure() {
            row.consecutive_failures.saturating_add(1)
        } else {
            0
        };
        let next_attempt_at_ms = outcome
            .next_eligible_at_ms(observed_at_ms, u32::try_from(failures).unwrap_or(u32::MAX));
        sql_query(
            "UPDATE state_control_seal_schedule SET \
               next_attempt_at_ms = $2, consecutive_failures = $3, last_outcome = $4, \
               claim_holder = NULL, claim_until_ms = NULL \
             WHERE realm_id = $1 AND claim_holder = $5 AND claim_fence = $6",
        )
        .bind::<Text, _>(claim.realm_id.as_str())
        .bind::<BigInt, _>(next_attempt_at_ms)
        .bind::<Integer, _>(failures)
        .bind::<Text, _>(outcome.as_str())
        .bind::<Text, _>(&claim.holder)
        .bind::<BigInt, _>(claim.fence as i64)
        .execute(&mut *conn)
        .await?;
        Ok(ControlSealAttemptCompletion::Applied)
    })
    .await
}

async fn pending_repair_page(
    conn: &mut AsyncPgConnection,
    after_realm_id: Option<&str>,
    limit: usize,
) -> QueryResult<Vec<PendingRealmRow>> {
    sql_query(
        "WITH pending_realms AS ( \
             SELECT DISTINCT c.realm_id FROM state_control_events c \
             WHERE c.is_pending \
               AND ($1::text IS NULL OR c.realm_id > $1) \
             ORDER BY c.realm_id LIMIT $2 \
         ) \
         SELECT pending_realms.realm_id, \
                (SELECT COUNT(*)::bigint FROM state_control_events all_events \
                 WHERE all_events.realm_id = pending_realms.realm_id) AS generation \
         FROM pending_realms ORDER BY pending_realms.realm_id",
    )
    .bind::<Nullable<Text>, _>(after_realm_id)
    .bind::<BigInt, _>(limit as i64)
    .load::<PendingRealmRow>(conn)
    .await
}

pub(crate) async fn repair(
    conn: &mut AsyncPgConnection,
    now_ms: i64,
    limit: usize,
) -> QueryResult<ControlSealScheduleRepairStats> {
    if limit == 0 {
        return Ok(ControlSealScheduleRepairStats::default());
    }
    conn.transaction::<_, diesel::result::Error, _>(async move |conn| {
        sql_query(
            "INSERT INTO state_control_seal_repair_cursor (singleton, after_realm_id, updated_at_ms) \
             VALUES (true, NULL, $1) ON CONFLICT (singleton) DO NOTHING",
        )
        .bind::<BigInt, _>(now_ms)
        .execute(&mut *conn)
        .await?;
        let cursor = sql_query(
            "SELECT after_realm_id FROM state_control_seal_repair_cursor \
             WHERE singleton = true FOR UPDATE",
        )
        .get_result::<CursorRow>(&mut *conn)
        .await?
        .after_realm_id;
        let mut rows = pending_repair_page(&mut *conn, cursor.as_deref(), limit).await?;
        let mut cursor_wrapped = false;
        if rows.is_empty() && cursor.is_some() {
            cursor_wrapped = true;
            rows = pending_repair_page(&mut *conn, None, limit).await?;
        }
        let mut stats = ControlSealScheduleRepairStats {
            scanned: rows.len(),
            cursor_wrapped,
            ..ControlSealScheduleRepairStats::default()
        };
        for row in &rows {
            let existing = sql_query(
                "SELECT generation FROM state_control_seal_schedule WHERE realm_id = $1",
            )
            .bind::<Text, _>(&row.realm_id)
            .get_result::<GenerationRow>(&mut *conn)
            .await
            .optional()?;
            sql_query(
                "INSERT INTO state_control_seal_schedule \
                   (realm_id, generation, first_pending_at_ms, next_attempt_at_ms) \
                 VALUES ($1, $2, $3, $3) \
                 ON CONFLICT (realm_id) DO UPDATE SET \
                   generation = GREATEST(state_control_seal_schedule.generation, EXCLUDED.generation), \
                   next_attempt_at_ms = CASE \
                     WHEN state_control_seal_schedule.generation < EXCLUDED.generation \
                       THEN LEAST(state_control_seal_schedule.next_attempt_at_ms, EXCLUDED.next_attempt_at_ms) \
                     ELSE state_control_seal_schedule.next_attempt_at_ms END, \
                   consecutive_failures = CASE \
                     WHEN state_control_seal_schedule.generation < EXCLUDED.generation THEN 0 \
                     ELSE state_control_seal_schedule.consecutive_failures END, \
                   last_outcome = CASE \
                     WHEN state_control_seal_schedule.generation < EXCLUDED.generation THEN NULL \
                     ELSE state_control_seal_schedule.last_outcome END",
            )
            .bind::<Text, _>(&row.realm_id)
            .bind::<BigInt, _>(row.generation)
            .bind::<BigInt, _>(now_ms)
            .execute(&mut *conn)
            .await?;
            match existing {
                None => stats.inserted += 1,
                Some(existing) if existing.generation < row.generation => {
                    stats.generation_repaired += 1;
                }
                Some(_) => {}
            }
        }
        let next_cursor = rows.last().map(|row| row.realm_id.as_str());
        sql_query(
            "UPDATE state_control_seal_repair_cursor SET after_realm_id = $1, updated_at_ms = $2 \
             WHERE singleton = true",
        )
        .bind::<Nullable<Text>, _>(next_cursor)
        .bind::<BigInt, _>(now_ms)
        .execute(&mut *conn)
        .await?;
        let stale_deleted = sql_query(
            "WITH stale AS ( \
               SELECT schedule.realm_id FROM state_control_seal_schedule schedule \
               WHERE schedule.claim_holder IS NULL \
                 AND NOT EXISTS ( \
                   SELECT 1 FROM state_control_events c WHERE c.realm_id = schedule.realm_id \
                     AND c.is_pending \
                 ) \
               ORDER BY schedule.realm_id LIMIT $1 FOR UPDATE SKIP LOCKED \
             ) \
             DELETE FROM state_control_seal_schedule schedule USING stale \
             WHERE schedule.realm_id = stale.realm_id",
        )
        .bind::<BigInt, _>(limit as i64)
        .execute(&mut *conn)
        .await?;
        stats.stale_deleted = stale_deleted;
        Ok(stats)
    })
    .await
}

pub(crate) async fn stats(
    conn: &mut AsyncPgConnection,
    now_ms: i64,
) -> QueryResult<ControlSealScheduleStats> {
    let row = sql_query(
        "SELECT \
           COUNT(*)::bigint AS pending, \
           COUNT(*) FILTER (WHERE next_attempt_at_ms <= $1 \
             AND (claim_holder IS NULL OR claim_until_ms <= $1))::bigint AS eligible, \
           COUNT(*) FILTER (WHERE claim_holder IS NOT NULL \
             AND claim_until_ms > $1)::bigint AS claimed, \
           COUNT(*) FILTER (WHERE claim_holder IS NOT NULL \
             AND claim_until_ms <= $1)::bigint AS expired_claims, \
           MIN(first_pending_at_ms) AS oldest_pending_at_ms, \
           MIN(next_attempt_at_ms) FILTER (WHERE next_attempt_at_ms <= $1 \
             AND (claim_holder IS NULL OR claim_until_ms <= $1)) AS oldest_eligible_at_ms \
         FROM state_control_seal_schedule schedule \
         WHERE EXISTS ( \
           SELECT 1 FROM state_control_events event \
           WHERE event.realm_id = schedule.realm_id \
             AND event.is_pending \
         )",
    )
    .bind::<BigInt, _>(now_ms)
    .get_result::<StatsRow>(conn)
    .await?;
    Ok(ControlSealScheduleStats {
        pending: usize::try_from(row.pending).unwrap_or(usize::MAX),
        eligible: usize::try_from(row.eligible).unwrap_or(usize::MAX),
        claimed: usize::try_from(row.claimed).unwrap_or(usize::MAX),
        expired_claims: usize::try_from(row.expired_claims).unwrap_or(usize::MAX),
        oldest_pending_at_ms: row.oldest_pending_at_ms,
        oldest_eligible_at_ms: row.oldest_eligible_at_ms,
    })
}
