//! `ak.space.create` writes all three registered current families atomically.
//! The HTTP guarded-unit tests separately prove capability denial before
//! entering this UoW; this suite exercises its PG cut, parent basis and CAS.

#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel_async::RunQueryDsl;
use ordinary_realm::{bootstrap_unit, founder, next_request};
use serde_json::{Value, json};
use soland_storage::{AuthorityCommitStore, EventCommitUnitOfWork};
use soland_storage_postgres::test_database::TestDatabase;
use soland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgPool};

#[derive(diesel::QueryableByName, Debug, PartialEq)]
struct Current {
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct Count {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

async fn current(pool: &PgPool, table: &str, space_id: &arkret_wire::SpaceId) -> Current {
    let mut conn = pool.get().await.unwrap();
    let query = format!(
        "SELECT current_commit_id,current_stream_position,value FROM {table} WHERE space_id=$1"
    );
    diesel::sql_query(query)
        .bind::<Text, _>(space_id.as_str())
        .get_result(&mut conn)
        .await
        .unwrap()
}

async fn count(pool: &PgPool, table: &str, realm_id: &arkret_wire::RealmId) -> i64 {
    let mut conn = pool.get().await.unwrap();
    let query = format!("SELECT COUNT(*) AS count FROM {table} WHERE realm_id=$1");
    let row: Count = diesel::sql_query(query)
        .bind::<Text, _>(realm_id.as_str())
        .get_result(&mut conn)
        .await
        .unwrap();
    row.count
}

async fn cut_counts(pool: &PgPool, realm_id: &arkret_wire::RealmId) -> [i64; 5] {
    let mut counts = [0; 5];
    for (index, table) in [
        "canonical_events",
        "realm_commits",
        "space_current_results",
        "space_parent_current_results",
        "space_child_scope_policy_current_results",
    ]
    .iter()
    .enumerate()
    {
        counts[index] = count(pool, table, realm_id).await;
    }
    counts
}

fn payload(
    realm_id: &arkret_wire::RealmId,
    actor_id: &arkret_wire::ActorId,
    at: chrono::DateTime<chrono::Utc>,
    kind: &str,
    title: &str,
    parent_id: Option<&arkret_wire::SpaceId>,
    policy: Option<Value>,
) -> Value {
    let mut object = json!({
        "schema": "ak.schema.space.v1",
        "realm_id": realm_id,
        "kind": kind,
        "title": title,
        "created_by": actor_id,
        "created_at": at,
    });
    if let Some(parent_id) = parent_id {
        object["parent_space_id"] = json!(parent_id);
    }
    if let Some(policy) = policy {
        object["child_scope_policy"] = policy;
    }
    json!({"object": object})
}

#[tokio::test]
async fn space_create_root_and_child_have_three_sibling_results_and_exact_replay() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let unit = bootstrap_unit("space-create-root-child");
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let last = unit.transactions.last().unwrap();
    let realm_id = last.event.realm_id.clone();
    let at = last.commit.committed_at;
    let baseline = cut_counts(&pool, &realm_id).await;

    let root = next_request(
        last,
        arkret_wire::EventKind::SpaceCreate,
        &founder(),
        payload(
            &realm_id,
            &last.event.actor_id,
            at,
            "board",
            "Board",
            None,
            Some(json!({"kind":"allow_any"})),
        ),
        at,
    );
    let root_id = arkret_wire::SpaceId::from_event_id(&root.authority_commit.event.event_id);
    assert!(uow.commit_event(root.clone()).await.unwrap().event_inserted);
    let root_space = current(&pool, "space_current_results", &root_id).await;
    let root_parent = current(&pool, "space_parent_current_results", &root_id).await;
    let root_policy = current(&pool, "space_child_scope_policy_current_results", &root_id).await;
    assert_eq!(root_space.value["id"], json!(root_id));
    assert_eq!(root_space.value["state"], "active");
    assert!(root_space.value.get("parent_space_id").is_none());
    assert!(root_space.value.get("child_scope_policy").is_none());
    assert_eq!(root_parent.value, json!({"parent_space_id": null}));
    assert_eq!(root_policy.value, json!({"kind":"allow_any"}));
    for row in [&root_space, &root_parent, &root_policy] {
        assert_eq!(
            row.current_commit_id,
            root.authority_commit.commit.commit_id.as_str()
        );
        assert_eq!(
            row.current_stream_position,
            root.authority_commit.commit.stream_position as i64
        );
    }

    let child = next_request(
        &root.authority_commit,
        arkret_wire::EventKind::SpaceCreate,
        &founder(),
        payload(
            &realm_id,
            &last.event.actor_id,
            at,
            "list",
            "List",
            Some(&root_id),
            None,
        ),
        at,
    );
    let child_id = arkret_wire::SpaceId::from_event_id(&child.authority_commit.event.event_id);
    assert!(
        uow.commit_event(child.clone())
            .await
            .unwrap()
            .event_inserted
    );
    let child_space = current(&pool, "space_current_results", &child_id).await;
    let child_parent = current(&pool, "space_parent_current_results", &child_id).await;
    let child_policy = current(&pool, "space_child_scope_policy_current_results", &child_id).await;
    assert_eq!(child_space.value["id"], json!(child_id));
    assert_eq!(child_parent.value, json!({"parent_space_id": root_id}));
    assert_eq!(child_policy.value, Value::Null);
    assert_eq!(
        cut_counts(&pool, &realm_id).await,
        [baseline[0] + 2, baseline[1] + 2, 2, 2, 2]
    );
    let before_retry = cut_counts(&pool, &realm_id).await;
    assert!(!uow.commit_event(child).await.unwrap().event_inserted);
    assert_eq!(cut_counts(&pool, &realm_id).await, before_retry);
    assert_eq!(
        current(&pool, "space_current_results", &child_id).await,
        child_space
    );

    let snapshot = soland_storage_postgres::account_snapshot_material(
        &pool,
        &realm_id,
        &arkret_wire::AccountId::new(founder(), ordinary_realm::station()),
    )
    .await
    .unwrap()
    .unwrap();
    for (space_id, metadata, parent, policy) in [
        (&root_id, &root_space, &root_parent, &root_policy),
        (&child_id, &child_space, &child_parent, &child_policy),
    ] {
        for (selector, expected) in [
            (
                arkret_wire::CurrentSelector::Space {
                    space_id: space_id.clone(),
                },
                metadata,
            ),
            (
                arkret_wire::CurrentSelector::SpaceParent {
                    space_id: space_id.clone(),
                },
                parent,
            ),
            (
                arkret_wire::CurrentSelector::SpaceChildScopePolicy {
                    space_id: space_id.clone(),
                },
                policy,
            ),
        ] {
            assert!(snapshot.current_state_entries.iter().any(|entry| matches!(
                entry,
                arkret_wire::TypedCurrentResult::Value {
                    selector: found,
                    revision,
                    value,
                    ..
                } if found == &selector
                    && revision.commit_id.as_str() == expected.current_commit_id
                    && revision.stream_position as i64 == expected.current_stream_position
                    && value == &expected.value
            )));
        }
    }
}

#[tokio::test]
async fn space_create_unknown_parent_and_stale_stream_leave_no_pg_writes() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let unit = bootstrap_unit("space-create-zero-write");
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let last = unit.transactions.last().unwrap();
    let realm_id = last.event.realm_id.clone();
    let at = last.commit.committed_at;
    let missing_id = arkret_wire::SpaceId::from_event_id(&last.event.event_id);
    let intruder = arkret_wire::DidCoreId::new("ak:did_core:web:space-intruder.example").unwrap();
    let intruder_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        intruder.clone(),
        ordinary_realm::station(),
    ));
    let denied = next_request(
        last,
        arkret_wire::EventKind::SpaceCreate,
        &intruder,
        payload(
            &realm_id,
            &intruder_actor,
            at,
            "board",
            "Intruder board",
            None,
            None,
        ),
        at,
    );
    let baseline = cut_counts(&pool, &realm_id).await;
    let error = uow.commit_event(denied).await.unwrap_err().to_string();
    assert!(error.contains("capability_denied"), "{error}");
    assert_eq!(cut_counts(&pool, &realm_id).await, baseline);

    let missing_parent = next_request(
        last,
        arkret_wire::EventKind::SpaceCreate,
        &founder(),
        payload(
            &realm_id,
            &last.event.actor_id,
            at,
            "list",
            "Orphan",
            Some(&missing_id),
            None,
        ),
        at,
    );
    let error = uow
        .commit_event(missing_parent)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("space_parent_unreadable"), "{error}");
    assert_eq!(cut_counts(&pool, &realm_id).await, baseline);

    let root = next_request(
        last,
        arkret_wire::EventKind::SpaceCreate,
        &founder(),
        payload(
            &realm_id,
            &last.event.actor_id,
            at,
            "board",
            "Board",
            None,
            None,
        ),
        at,
    );
    assert!(uow.commit_event(root).await.unwrap().event_inserted);
    let after = cut_counts(&pool, &realm_id).await;
    let stale = next_request(
        last,
        arkret_wire::EventKind::SpaceCreate,
        &founder(),
        payload(
            &realm_id,
            &last.event.actor_id,
            at,
            "board",
            "Stale",
            None,
            None,
        ),
        at,
    );
    assert!(uow.commit_event(stale).await.is_err());
    assert_eq!(cut_counts(&pool, &realm_id).await, after);
}

#[tokio::test]
async fn space_create_child_policy_denial_leaves_event_commit_and_all_results_untouched() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let unit = bootstrap_unit("space-create-policy-denial");
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let last = unit.transactions.last().unwrap();
    let realm_id = last.event.realm_id.clone();
    let at = last.commit.committed_at;
    let root = next_request(
        last,
        arkret_wire::EventKind::SpaceCreate,
        &founder(),
        payload(
            &realm_id,
            &last.event.actor_id,
            at,
            "board",
            "Encrypted-only board",
            None,
            Some(json!({"kind":"require_e2ee"})),
        ),
        at,
    );
    let root_id = arkret_wire::SpaceId::from_event_id(&root.authority_commit.event.event_id);
    uow.commit_event(root.clone()).await.unwrap();
    let before = cut_counts(&pool, &realm_id).await;
    let child = next_request(
        &root.authority_commit,
        arkret_wire::EventKind::SpaceCreate,
        &founder(),
        payload(
            &realm_id,
            &last.event.actor_id,
            at,
            "list",
            "Plaintext list",
            Some(&root_id),
            None,
        ),
        at,
    );
    let error = uow.commit_event(child).await.unwrap_err().to_string();
    assert!(error.contains("policy_violation"), "{error}");
    assert_eq!(cut_counts(&pool, &realm_id).await, before);
    assert_eq!(
        current(&pool, "space_child_scope_policy_current_results", &root_id)
            .await
            .value,
        json!({"kind":"require_e2ee"})
    );
}
