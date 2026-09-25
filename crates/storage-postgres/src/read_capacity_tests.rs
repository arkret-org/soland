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

/// Rows produced by every scan node over the two history tables, and the
/// execution time in milliseconds.
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
        let actual = node
            .get("Actual Rows")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let loops = node
            .get("Actual Loops")
            .and_then(Value::as_f64)
            .unwrap_or(1.0);
        *rows += actual * loops;
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

        let heads = measure(
            sql_query(explain(crate::authority_commit::REALM_STREAM_HEADS_SQL))
                .bind::<Text, _>(hot_realm)
                .get_result::<PlanRow>(&mut *conn)
                .await
                .unwrap()
                .plan,
            "stream heads",
        );
        assert!(
            heads.history_rows <= 8.0,
            "stream heads read {}",
            heads.history_rows
        );
        report.push(("stream heads", heads));

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
