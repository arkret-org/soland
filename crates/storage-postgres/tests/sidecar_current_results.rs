//! Native Sidecar genesis current is accepted with its RealmCommit, under
//! the same singleton reservation. The public ensure route remains closed.

#[path = "../../test-support/src/device_authorization_history.rs"]
#[allow(dead_code)]
mod device_authorization_history;
#[path = "support/ordinary_realm.rs"]
mod ordinary_realm;
#[path = "../../test-support/src/pcr_genesis.rs"]
#[allow(dead_code)]
mod pcr_genesis;

use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel_async::RunQueryDsl;
use ordinary_realm::{bootstrap_unit_with_join_rule, founder, next_request};
use soland_storage::{AuthorityCommitStore, ConflictCode, EventCommitUnitOfWork};
use soland_storage_postgres::test_database::TestDatabase;
use soland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork};

#[derive(diesel::QueryableByName)]
struct SidecarRow {
    #[diesel(sql_type = Text)]
    sidecar_id: String,
    #[diesel(sql_type = Jsonb)]
    controller_account_id: serde_json::Value,
    #[diesel(sql_type = Text)]
    create_event_id: String,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

async fn rows(pool: &soland_storage_postgres::PgPool) -> Vec<SidecarRow> {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT sidecar_id,controller_account_id,create_event_id,current_commit_id,current_stream_position,value \
         FROM sidecar_current_results ORDER BY sidecar_id",
    )
    .load::<SidecarRow>(&mut *conn)
    .await
    .unwrap()
}

#[tokio::test]
async fn sidecar_genesis_reserves_exact_controller_and_current_in_one_commit() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let unit = bootstrap_unit_with_join_rule("sidecar-current", "public");
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let last = unit.transactions.last().unwrap();
    let at = last.commit.committed_at;
    let create = next_request(
        last,
        arkret_wire::EventKind::SidecarCreate,
        &founder(),
        serde_json::json!({}),
        at,
    );
    uow.commit_event(create.clone()).await.unwrap();
    let stored = rows(&pool).await;
    assert_eq!(stored.len(), 1);
    let row = &stored[0];
    assert_eq!(
        row.sidecar_id,
        arkret_wire::SidecarId::from_event_id(&create.authority_commit.event.event_id).as_str()
    );
    assert_eq!(
        row.controller_account_id,
        serde_json::json!(
            create
                .authority_commit
                .event
                .actor_id
                .as_account_id()
                .unwrap()
        )
    );
    assert_eq!(
        row.create_event_id,
        create.authority_commit.event.event_id.as_str()
    );
    assert_eq!(
        row.current_commit_id,
        create.authority_commit.commit.commit_id.as_str()
    );
    assert_eq!(
        row.current_stream_position,
        create.authority_commit.commit.stream_position as i64
    );
    assert_eq!(row.value["id"], row.sidecar_id);
    assert_eq!(row.value["schema"], "ak.schema.agent_sidecar.v1");
    assert_eq!(
        row.value["realm_id"],
        create.authority_commit.event.realm_id.as_str()
    );
    assert_eq!(
        row.value["controller_account_id"],
        row.controller_account_id
    );
    assert_eq!(row.value["state"], "active");
    assert_eq!(row.value["created_at"], row.value["updated_at"]);

    let second = next_request(
        &create.authority_commit,
        arkret_wire::EventKind::SidecarCreate,
        &founder(),
        serde_json::json!({}),
        at + chrono::Duration::seconds(1),
    );
    let error = uow.commit_event(second.clone()).await.unwrap_err();
    assert_eq!(
        error.conflict_code(),
        Some(ConflictCode::FailedPrecondition)
    );
    assert_eq!(rows(&pool).await.len(), 1);
    assert!(
        PgAuthorityCommitStore { pool: pool.clone() }
            .committed_event(&second.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );

    // A service actor cannot become the controller by presenting a Realm
    // Event with the same syntactic kind. Refusal preserves the whole cut.
    let service = arkret_wire::ActorId::service(
        arkret_wire::DidCoreId::new("ak:did_core:web:sidecar-service.example").unwrap(),
    );
    let wrong_actor = ordinary_realm::next_request_for_actor(
        &create.authority_commit,
        arkret_wire::EventKind::SidecarCreate,
        service,
        serde_json::json!({}),
        at,
    );
    let error = uow.commit_event(wrong_actor.clone()).await.unwrap_err();
    assert_eq!(error.conflict_code(), Some(ConflictCode::CapabilityDenied));
    assert_eq!(rows(&pool).await.len(), 1);
    assert!(
        PgAuthorityCommitStore { pool: pool.clone() }
            .committed_event(&wrong_actor.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
}
