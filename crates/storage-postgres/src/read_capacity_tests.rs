//! Real PostgreSQL capacity matrix for the per-stream read paths (0436).
//!
//! Every Realm gets a short Realm stream and one hot Realm a long one; the
//! matrix grows the number of Realms through 1, 100 and 1000. Each hot read
//! is run under `EXPLAIN (ANALYZE, FORMAT JSON)`, and the rows its scans
//! of `realm_commits` and `canonical_events` actually produced must stay
//! within a bound set by the page size or the stream count, never by the
//! hot Realm's history or the number of Realms. A sequential scan of either
//! table fails the matrix outright.

use diesel::sql_types::{Array, BigInt, Json, Text};
use diesel_async::{RunQueryDsl, SimpleAsyncConnection};
use serde_json::Value;

use crate::{AsyncPgConnection, QueryableByName, pg_conn, sql_query};

const HOT_HISTORY: i64 = 20_000;
const COLD_HISTORY: i64 = 20;
const PAGE: i64 = 100;

#[derive(QueryableByName)]
struct PlanRow {
    #[diesel(sql_type = Json)]
    #[diesel(column_name = "QUERY PLAN")]
    plan: Value,
}

/// Rows every scan node over the two history tables produced or discarded,
/// and the execution time in milliseconds.
struct Measured {
    history_rows: f64,
    execution_ms: f64,
}

fn walk(node: &Value, rows: &mut f64, label: &str) {
    let relation = node.get("Relation Name").and_then(Value::as_str);
    let node_type = node.get("Node Type").and_then(Value::as_str).unwrap_or("");
    if let Some(relation @ ("realm_commits" | "canonical_events")) = relation {
        assert!(
            node_type != "Seq Scan",
            "{label}: sequential scan of {relation}"
        );
        // Rows an index or filter visited and discarded are read too.
        let visited = [
            "Actual Rows",
            "Rows Removed by Filter",
            "Rows Removed by Index Recheck",
        ]
        .into_iter()
        .filter_map(|field| node.get(field).and_then(Value::as_f64))
        .sum::<f64>();
        let loops = node
            .get("Actual Loops")
            .and_then(Value::as_f64)
            .unwrap_or(1.0);
        *rows += visited * loops;
    }
    for child in node
        .get("Plans")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        walk(child, rows, label);
    }
}

fn measure(plan: Value, label: &str) -> Measured {
    let root = &plan[0];
    let mut history_rows = 0.0;
    walk(&root["Plan"], &mut history_rows, label);
    Measured {
        history_rows,
        execution_ms: root["Execution Time"].as_f64().unwrap_or(f64::NAN),
    }
}

async fn seed(conn: &mut AsyncPgConnection, first: i64, last: i64, history: i64) {
    conn.batch_execute(&format!(
        "INSERT INTO canonical_events \
           (id, digest_suite, digest, actor_id, realm_id, scope_ref, kind, canonical_bytes, \
            envelope, state, committed_at) \
         SELECT '\\x01'::bytea || d.digest, 1, d.digest, 'actor', 'ak:realm:capacity-' || r, \
                '{{}}'::jsonb, \
                CASE WHEN p = 0 THEN 'ak.realm.create' ELSE 'ak.message.create' END, \
                '\\x00'::bytea, \
                jsonb_build_object('event_id', 'ak:event:capacity-' || r || '-' || p, \
                                   'payload', '{{}}'::jsonb), \
                'committed', now() \
         FROM generate_series({first}, {last}) r, generate_series(0, {history} - 1) p, \
              LATERAL (SELECT sha256(convert_to(r || ':' || p, 'UTF8')) AS digest) d; \
         INSERT INTO realm_commits \
           (commit_id, realm_id, stream_key, stream_ref, stream_position, previous_commit_ref, \
            event_pk, governance_generation, commit_json, committed_at) \
         SELECT 'capacity-' || r || '-' || p, 'ak:realm:capacity-' || r, 'stream-' || r, \
                '{{}}'::jsonb, p, \
                CASE WHEN p = 0 THEN NULL ELSE 'capacity-' || r || '-' || (p - 1) END, \
                e.pk, 0, '{{}}'::jsonb, now() \
         FROM generate_series({first}, {last}) r CROSS JOIN generate_series(0, {history} - 1) p \
         JOIN canonical_events e ON e.digest_suite = 1 \
           AND e.digest = sha256(convert_to(r || ':' || p, 'UTF8'));"
    ))
    .await
    .unwrap();
}

#[tokio::test]
async fn per_stream_reads_stay_bounded_across_one_hundred_and_one_thousand_realms() {
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let mut conn = pg_conn(&pool).await.unwrap();
    seed(&mut *conn, 1, 1, HOT_HISTORY).await;
    let mut seeded = 1;
    let hot_realm = "ak:realm:capacity-1";
    let hot_stream = "stream-1";
    for realms in [1_i64, 100, 1000] {
        if realms > seeded {
            seed(&mut *conn, seeded + 1, realms, COLD_HISTORY).await;
            seeded = realms;
        }
        conn.batch_execute(
            "ANALYZE canonical_events; ANALYZE realm_commits; ANALYZE realm_commit_event_kinds;",
        )
        .await
        .unwrap();
        let explain = |sql: &str| format!("EXPLAIN (ANALYZE, FORMAT JSON) {sql}");
        let mut report = Vec::new();

        // The first and the last Realm in key order: neither may walk the
        // hot history or the other Realms' streams.
        let last_realm = format!("ak:realm:capacity-{realms}");
        for (label, realm) in [
            ("stream heads (hot Realm)", hot_realm),
            ("stream heads (last Realm)", last_realm.as_str()),
        ] {
            let heads = measure(
                sql_query(explain(crate::authority_commit::REALM_STREAM_HEADS_SQL))
                    .bind::<Text, _>(realm)
                    .get_result::<PlanRow>(&mut *conn)
                    .await
                    .unwrap()
                    .plan,
                label,
            );
            assert!(
                heads.history_rows <= 8.0,
                "{label} read {}",
                heads.history_rows
            );
            report.push((label, heads));
        }

        let floor = measure(
            sql_query(explain(crate::authority_commit::STREAM_FLOOR_SQL))
                .bind::<Text, _>(hot_stream)
                .get_result::<PlanRow>(&mut *conn)
                .await
                .unwrap()
                .plan,
            "stream floor",
        );
        assert!(
            floor.history_rows <= 2.0,
            "stream floor read {}",
            floor.history_rows
        );
        report.push(("stream floor", floor));

        for (label, sql, position) in [
            (
                "page after",
                crate::authority_commit::STREAM_PAGE_AFTER_SQL,
                Some(HOT_HISTORY / 2),
            ),
            (
                "page before",
                crate::authority_commit::STREAM_PAGE_BEFORE_SQL,
                Some(HOT_HISTORY / 2),
            ),
            (
                "page newest",
                crate::authority_commit::STREAM_PAGE_NEWEST_SQL,
                None,
            ),
        ] {
            let query = sql_query(explain(sql)).bind::<Text, _>(hot_stream);
            let plan = match position {
                Some(position) => {
                    query
                        .bind::<BigInt, _>(position)
                        .bind::<BigInt, _>(PAGE + 1)
                        .get_result::<PlanRow>(&mut *conn)
                        .await
                }
                None => {
                    query
                        .bind::<BigInt, _>(PAGE + 1)
                        .get_result::<PlanRow>(&mut *conn)
                        .await
                }
            }
            .unwrap()
            .plan;
            let measured = measure(plan, label);
            assert!(
                measured.history_rows <= 2.0 * (PAGE as f64 + 1.0),
                "{label} read {}",
                measured.history_rows
            );
            report.push((label, measured));
        }

        let page_commits = (HOT_HISTORY - PAGE..HOT_HISTORY)
            .map(|position| format!("capacity-1-{position}"))
            .collect::<Vec<_>>();
        let withheld = measure(
            sql_query(explain(crate::committed_disclosure::WITHHELD_COMMITS_SQL))
                .bind::<Array<Text>, _>(&page_commits)
                .get_result::<PlanRow>(&mut *conn)
                .await
                .unwrap()
                .plan,
            "withheld decision",
        );
        assert!(
            withheld.history_rows <= 3.0 * PAGE as f64,
            "withheld decision read {}",
            withheld.history_rows
        );
        report.push(("withheld decision", withheld));

        for (label, sql) in [
            (
                "undisclosed kind audit",
                crate::snapshot_disclosure_gate::undisclosed_kind_sql(),
            ),
            (
                "unsettled commit audit",
                crate::snapshot_disclosure_gate::UNSETTLED_COMMIT_SQL.to_owned(),
            ),
        ] {
            let measured = measure(
                sql_query(explain(&sql))
                    .bind::<Text, _>(hot_realm)
                    .get_result::<PlanRow>(&mut *conn)
                    .await
                    .unwrap()
                    .plan,
                label,
            );
            assert!(
                measured.history_rows <= 2.0,
                "{label} read {}",
                measured.history_rows
            );
            report.push((label, measured));
        }

        for (label, measured) in report {
            println!(
                "capacity realms={realms} hot_history={HOT_HISTORY} {label}: history_rows={} execution_ms={:.3}",
                measured.history_rows, measured.execution_ms
            );
        }
    }
}

// These are query-plan fixtures, not admission evidence. The larger member
// and message families expose a scan hidden by tiny bootstrap-only Realms.
async fn seed_current(conn: &mut AsyncPgConnection, first: i64, last: i64, width: i64) {
    conn.batch_execute(&format!(
        "INSERT INTO member_state_current_results
           (realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at)
         SELECT 'ak:realm:capacity-' || r, jsonb_build_object('member',m)::text, 'join',
                'capacity-' || r || '-0', 0, '{{\"membership\":\"join\"}}'::jsonb, now()
         FROM generate_series({first},{last}) r, generate_series(1,{width}) m;
         INSERT INTO message_revision_current_results
           (realm_id,message_id,current_commit_id,current_stream_position,value,updated_at)
         SELECT 'ak:realm:capacity-' || r, 'message-' || r || '-' || m,
                'capacity-' || r || '-0', 0,
                '{{\"strand_id\":\"strand\",\"track_name\":\"discussion\"}}'::jsonb, now()
         FROM generate_series({first},{last}) r, generate_series(1,{width}) m;
         INSERT INTO relation_current_results
           (realm_id,domain_key,domain,relation_id,state,current_commit_id,current_stream_position,value,updated_at)
         SELECT 'ak:realm:capacity-' || r, 'domain-' || m, '{{}}'::jsonb, 'relation-' || r || '-' || m,
                'active', 'capacity-' || r || '-0', 0,
                jsonb_build_object('id','relation-' || r || '-' || m,'state','active'), now()
         FROM generate_series({first},{last}) r, generate_series(1,{width}) m;
         INSERT INTO moderation_state_current_results
           (realm_id,target_ref,current_commit_id,current_stream_position,value,updated_at)
         SELECT 'ak:realm:capacity-' || r, 'target-' || m, 'capacity-' || r || '-0', 0,
                '{{}}'::jsonb, now()
         FROM generate_series({first},{last}) r, generate_series(1,{width}) m;"
    )).await.unwrap();
}

fn measured_current(plan: Value, label: &str, bound: f64) {
    fn visit(node: &Value, label: &str, rows: &mut f64) {
        if let Some(relation) = node.get("Relation Name").and_then(Value::as_str) {
            let visited = [
                "Actual Rows",
                "Rows Removed by Filter",
                "Rows Removed by Index Recheck",
            ]
            .into_iter()
            .filter_map(|field| node.get(field).and_then(Value::as_f64))
            .sum::<f64>()
                * node["Actual Loops"].as_f64().unwrap_or(1.0);
            // Current-table scans are judged by the total output-relative
            // row budget below: PostgreSQL can prefer one when the requested
            // Realm is a large fraction of the table. History scans must
            // never grow with its length. Do not disable seqscan.
            let current_table = relation.ends_with("_current_results");
            assert!(
                node["Node Type"] != "Seq Scan" || visited <= 32.0 || current_table,
                "{label}: unbounded sequential scan of {relation}: {visited}: {node}"
            );
            *rows += visited;
        }
        for child in node["Plans"].as_array().into_iter().flatten() {
            visit(child, label, rows);
        }
    }
    let mut rows = 0.0;
    visit(&plan[0]["Plan"], label, &mut rows);
    assert!(
        rows <= bound,
        "{label}: visited {rows} rows, bound {bound}: {plan}"
    );
    println!(
        "{label}: visited={rows} execution_ms={}",
        plan[0]["Execution Time"]
    );
}

#[tokio::test]
async fn typed_current_and_self_reads_stay_bounded_across_one_hundred_and_one_thousand_realms() {
    let database = crate::test_database::TestDatabase::lease().await;
    let mut conn = pg_conn(&database.pool()).await.unwrap();
    seed(&mut conn, 1, 1, HOT_HISTORY).await;
    seed_current(&mut conn, 1, 1, 1000).await;
    let mut seeded = 1;
    for realms in [1_i64, 100, 1000] {
        if realms > seeded {
            seed(&mut conn, seeded + 1, realms, COLD_HISTORY).await;
            seed_current(&mut conn, seeded + 1, realms, 20).await;
            seeded = realms;
        }
        conn.batch_execute("ANALYZE").await.unwrap();
        for realm in [
            "ak:realm:capacity-1".to_owned(),
            format!("ak:realm:capacity-{realms}"),
        ] {
            let label = format!("typed current realms={realms} realm={realm}");
            let plan = sql_query(format!(
                "EXPLAIN (ANALYZE, FORMAT JSON) {}",
                crate::authority_commit::SNAPSHOT_CURRENT_SQL
            ))
            .bind::<Text, _>(&realm)
            .get_result::<PlanRow>(&mut *conn)
            .await
            .unwrap()
            .plan;
            // Three published families plus their covering Commit probes.
            // Relation is read by its exact endpoint, not this snapshot union.
            let width = if realm == "ak:realm:capacity-1" {
                1000.0
            } else {
                20.0
            };
            assert_eq!(plan[0]["Plan"]["Actual Rows"].as_f64(), Some(3.0 * width));
            // Up to four visited rows per output permits the planner's
            // low-selectivity current-table scan, but never a history scan
            // or a scan that grows with unrelated Realms.
            measured_current(plan, &label, 12.0 * width + 32.0);
            for (name, sql, key) in [
                (
                    "member present",
                    crate::self_current_reads::MEMBER_PRESENT_SQL,
                    "{\"member\": 1}",
                ),
                (
                    "member absent",
                    crate::self_current_reads::MEMBER_PRESENT_SQL,
                    "{\"member\": 0}",
                ),
                (
                    "no scoped stream",
                    crate::self_current_reads::SCOPED_STREAMS_SQL,
                    "stream-1",
                ),
                (
                    "stream above",
                    crate::self_current_reads::SCOPED_STREAMS_SQL,
                    "stream-0",
                ),
                (
                    "stream below",
                    crate::self_current_reads::SCOPED_STREAMS_SQL,
                    "stream-zzzz",
                ),
                (
                    "media absent",
                    crate::self_current_reads::MEDIA_ANCHOR_SQL,
                    "ak.realm.media_service",
                ),
                (
                    "media present",
                    crate::self_current_reads::MEDIA_ANCHOR_SQL,
                    "ak.realm.create",
                ),
                (
                    "relation present",
                    crate::self_current_reads::RELATION_CURRENT_SQL,
                    "domain-1",
                ),
                (
                    "relation absent",
                    crate::self_current_reads::RELATION_CURRENT_SQL,
                    "domain-0",
                ),
                (
                    "moderation present",
                    crate::self_current_reads::MODERATION_CURRENT_SQL,
                    "target-1",
                ),
                (
                    "moderation absent",
                    crate::self_current_reads::MODERATION_CURRENT_SQL,
                    "target-0",
                ),
            ] {
                let label = format!("self current realms={realms} realm={realm} {name}");
                let realm_stream = realm.replace("ak:realm:capacity-", "stream-");
                let key = if name == "no scoped stream" {
                    realm_stream.as_str()
                } else {
                    key
                };
                let plan = sql_query(format!("EXPLAIN (ANALYZE, FORMAT JSON) {sql}"))
                    .bind::<Text, _>(&realm)
                    .bind::<Text, _>(key)
                    .get_result::<PlanRow>(&mut *conn)
                    .await
                    .unwrap()
                    .plan;
                measured_current(plan, &label, 4.0);
            }
            for (sql, key, expected) in [
                (
                    crate::self_current_reads::MEMBER_PRESENT_SQL,
                    "{\"member\": 1}".to_owned(),
                    true,
                ),
                (
                    crate::self_current_reads::MEMBER_PRESENT_SQL,
                    "{\"member\": 0}".to_owned(),
                    false,
                ),
                (
                    crate::self_current_reads::SCOPED_STREAMS_SQL,
                    realm.replace("ak:realm:capacity-", "stream-"),
                    false,
                ),
                (
                    crate::self_current_reads::SCOPED_STREAMS_SQL,
                    "stream-0".to_owned(),
                    true,
                ),
                (
                    crate::self_current_reads::SCOPED_STREAMS_SQL,
                    "stream-zzzz".to_owned(),
                    true,
                ),
                (
                    crate::self_current_reads::MEDIA_ANCHOR_SQL,
                    "ak.realm.media_service".to_owned(),
                    false,
                ),
                (
                    crate::self_current_reads::MEDIA_ANCHOR_SQL,
                    "ak.realm.create".to_owned(),
                    true,
                ),
            ] {
                let result = sql_query(sql)
                    .bind::<Text, _>(&realm)
                    .bind::<Text, _>(key)
                    .get_result::<crate::ExistsRow>(&mut *conn)
                    .await
                    .unwrap();
                assert_eq!(
                    result.present, expected,
                    "realms={realms} realm={realm} {sql}"
                );
            }
        }
    }
}
