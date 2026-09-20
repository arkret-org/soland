mod support;

use std::sync::OnceLock;

use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::RunQueryDsl;
use soland_storage::{CapabilityGrantCurrentResultStore, CapabilityGrantCurrentStatus};
use soland_storage_postgres::{Db, PgCapabilityGrantCurrentResultStore, PgPool};

const REALM_ID: &str = "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru";
const GRANT_ID: &str = "ak:grant:AcFfzgdHkT6eFkto1gjLaKniVuMXx9sD0GKQwk8BXykz";
const COMMIT_ID: &str = "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4";

static TEST_POOL: OnceLock<PgPool> = OnceLock::new();

async fn test_pool() -> PgPool {
    if let Some(pool) = TEST_POOL.get() {
        return pool.clone();
    }
    let url = support::contract_database_url();
    support::ensure_contract_database(&url).await;
    let pool = Db::connect(Some(&url), Default::default())
        .await
        .expect("initialize test database")
        .pool
        .expect("a configured URL always yields a pool");
    let _ = TEST_POOL.set(pool.clone());
    pool
}

#[tokio::test]
async fn postgres_reads_capability_value_and_revision_from_one_current_row() {
    let pool = test_pool().await;
    let value = serde_json::json!({
        "id": GRANT_ID,
        "schema": "ak.schema.capability.v1",
        "realm_id": REALM_ID,
        "status": "active"
    });
    let now = chrono::Utc::now();
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO capability_grant_current_results \
         (realm_id,grant_id,status,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,'active',$3,$4,$5,$6) \
         ON CONFLICT(realm_id,grant_id) DO UPDATE SET \
           status=EXCLUDED.status,current_commit_id=EXCLUDED.current_commit_id, \
           current_stream_position=EXCLUDED.current_stream_position, \
           value=EXCLUDED.value,updated_at=EXCLUDED.updated_at",
    )
    .bind::<Text, _>(REALM_ID)
    .bind::<Text, _>(GRANT_ID)
    .bind::<Text, _>(COMMIT_ID)
    .bind::<BigInt, _>(41_i64)
    .bind::<Jsonb, _>(&value)
    .bind::<Timestamptz, _>(now)
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);

    let realm_id = REALM_ID.parse().unwrap();
    let grant_id = GRANT_ID.parse().unwrap();
    let store = PgCapabilityGrantCurrentResultStore { pool };
    let record = store
        .get(&realm_id, &grant_id)
        .await
        .unwrap()
        .expect("current grant row");
    assert_eq!(record.status, CapabilityGrantCurrentStatus::Active);
    assert_eq!(record.value, value);
    assert_eq!(record.revision.commit_id.as_str(), COMMIT_ID);
    assert_eq!(record.revision.stream_position, 41);

    let snapshot = store.snapshot_for_realm(&realm_id).await.unwrap();
    let listed = snapshot
        .into_iter()
        .find(|row| row.grant_id == grant_id)
        .expect("grant appears in the same-statement Realm snapshot");
    assert_eq!(listed.value, record.value);
    assert_eq!(listed.revision, record.revision);
}
