//! Same-cut admission of `ak.relation.create`, `ak.space.archive` /
//! `ak.space.restore` and `ak.reaction.add` / `ak.reaction.remove` through the
//! Event unit of work: the capability verdict, the typed current writer and
//! every refusal's zero-write guarantee.

#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel_async::RunQueryDsl;
use ordinary_realm::{bootstrap_unit, founder, next_request, open_discussion};
use serde_json::{Value, json};
use soland_storage::{AuthorityCommitStore, EventCommitUnitOfWork};
use soland_storage_postgres::test_database::TestDatabase;
use soland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgPool};

#[derive(diesel::QueryableByName)]
struct Count {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[derive(diesel::QueryableByName)]
struct ValueRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

async fn count(pool: &PgPool, table: &str, realm_id: &arkret_wire::RealmId) -> i64 {
    let mut conn = pool.get().await.unwrap();
    let row: Count = diesel::sql_query(format!(
        "SELECT COUNT(*) AS count FROM {table} WHERE realm_id=$1"
    ))
    .bind::<Text, _>(realm_id.as_str())
    .get_result(&mut conn)
    .await
    .unwrap();
    row.count
}

async fn value(pool: &PgPool, query: &str, key: &str) -> Value {
    let mut conn = pool.get().await.unwrap();
    let row: ValueRow = diesel::sql_query(query)
        .bind::<Text, _>(key)
        .get_result(&mut conn)
        .await
        .unwrap();
    row.value
}

fn founder_actor() -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        founder(),
        ordinary_realm::station(),
    ))
}

fn intruder() -> arkret_wire::DidCoreId {
    arkret_wire::DidCoreId::new("ak:did_core:web:admission-intruder.example").unwrap()
}

fn relation_create(relation_kind: &str, domain_kind: &str, from: Value, to: Value) -> Value {
    let mut domain = json!({
        "domain_kind": domain_kind,
        "relation_kind": relation_kind,
        "from_ref": from,
    });
    if domain_kind == "tuple" {
        domain["to_ref"] = to.clone();
    }
    json!({
        "primary_conflict_domain": domain,
        "expected_revision": null,
        "relation": {"relation_kind": relation_kind, "from_ref": from, "to_ref": to},
    })
}

#[tokio::test]
async fn relation_create_is_authorized_cas_guarded_and_rejects_cross_realm_structure() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let discussion = open_discussion(&pool, "relation-admission-a").await;
    let other = open_discussion(&pool, "relation-admission-b").await;
    let realm_id = discussion.realm_id();
    let at = discussion.committed_at();
    let head = &discussion.head.authority_commit;

    let assign = relation_create(
        "assigned_to",
        "tuple",
        json!(discussion.strand_id),
        json!(founder_actor()),
    );
    let denied = next_request(
        head,
        arkret_wire::EventKind::RelationCreate,
        &intruder(),
        assign.clone(),
        at,
    );
    let before = count(&pool, "realm_commits", &realm_id).await;
    let error = uow.commit_event(denied).await.unwrap_err().to_string();
    assert!(error.contains("capability_denied"), "{error}");
    assert_eq!(count(&pool, "realm_commits", &realm_id).await, before);
    assert_eq!(count(&pool, "relation_current_results", &realm_id).await, 0);

    let accepted = next_request(
        head,
        arkret_wire::EventKind::RelationCreate,
        &founder(),
        assign.clone(),
        at,
    );
    assert!(
        uow.commit_event(accepted.clone())
            .await
            .unwrap()
            .event_inserted
    );
    let relation_id =
        arkret_wire::RelationId::from_event_id(&accepted.authority_commit.event.event_id);
    let stored = value(
        &pool,
        "SELECT value FROM relation_current_results WHERE relation_id=$1",
        relation_id.as_str(),
    )
    .await;
    assert_eq!(stored["state"], "active");
    assert_eq!(stored["to_ref"], json!(founder_actor()));
    assert_eq!(stored["created_by"], json!(founder_actor()));
    // An exact replay returns the original Commit without a second write.
    assert!(
        !uow.commit_event(accepted.clone())
            .await
            .unwrap()
            .event_inserted
    );

    // relation.md section 6.2: create on an active domain is refused even
    // by a different Event, with zero writes.
    let mut second_payload = assign.clone();
    second_payload["relation"]["fields"] = json!({"role": "second"});
    let second = next_request(
        &accepted.authority_commit,
        arkret_wire::EventKind::RelationCreate,
        &founder(),
        second_payload,
        at,
    );
    let before = count(&pool, "realm_commits", &realm_id).await;
    let error = uow.commit_event(second).await.unwrap_err().to_string();
    assert!(error.contains("failed_precondition"), "{error}");
    assert_eq!(count(&pool, "realm_commits", &realm_id).await, before);

    // relation.md section 4.4: a structural edge to another Realm's object.
    let cross = next_request(
        &accepted.authority_commit,
        arkret_wire::EventKind::RelationCreate,
        &founder(),
        relation_create(
            "belongs_to",
            "from",
            json!(discussion.strand_id),
            json!(other.strand_id),
        ),
        at,
    );
    let error = uow.commit_event(cross).await.unwrap_err().to_string();
    assert!(error.contains("cross_realm_structural_relation"), "{error}");
    assert_eq!(count(&pool, "realm_commits", &realm_id).await, before);
    assert_eq!(count(&pool, "relation_current_results", &realm_id).await, 1);
}

fn board(
    realm_id: &arkret_wire::RealmId,
    at: chrono::DateTime<chrono::Utc>,
    kind: &str,
    parent: Option<&arkret_wire::SpaceId>,
) -> Value {
    let mut object = json!({
        "schema": "ak.schema.space.v1",
        "realm_id": realm_id,
        "kind": kind,
        "title": kind,
        "created_by": founder_actor(),
        "created_at": at,
    });
    if let Some(parent) = parent {
        object["parent_space_id"] = json!(parent);
    }
    json!({"object": object})
}

#[tokio::test]
async fn space_archive_and_restore_move_only_the_lifecycle_members() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let unit = bootstrap_unit("space-lifecycle-admission");
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let last = unit.transactions.last().unwrap();
    let realm_id = last.event.realm_id.clone();
    let at = last.commit.committed_at;
    let space_query = "SELECT value FROM space_current_results WHERE space_id=$1";

    let root = next_request(
        last,
        arkret_wire::EventKind::SpaceCreate,
        &founder(),
        board(&realm_id, at, "board", None),
        at,
    );
    uow.commit_event(root.clone()).await.unwrap();
    let root_id = arkret_wire::SpaceId::from_event_id(&root.authority_commit.event.event_id);
    let created = value(&pool, space_query, root_id.as_str()).await;

    let transition = |previous: &soland_storage::AuthorityCommitTransaction,
                      kind: arkret_wire::EventKind,
                      actor: &arkret_wire::DidCoreId| {
        next_request(previous, kind, actor, json!({"space_id": root_id}), at)
    };
    let denied = transition(
        &root.authority_commit,
        arkret_wire::EventKind::SpaceArchive,
        &intruder(),
    );
    let error = uow.commit_event(denied).await.unwrap_err().to_string();
    assert!(error.contains("capability_denied"), "{error}");

    let restore_active = transition(
        &root.authority_commit,
        arkret_wire::EventKind::SpaceRestore,
        &founder(),
    );
    let error = uow
        .commit_event(restore_active)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("space_not_archived"), "{error}");

    let archive = transition(
        &root.authority_commit,
        arkret_wire::EventKind::SpaceArchive,
        &founder(),
    );
    uow.commit_event(archive.clone()).await.unwrap();
    let archived = value(&pool, space_query, root_id.as_str()).await;
    assert_eq!(archived["state"], "archived");
    assert_eq!(archived["updated_by"], json!(founder_actor()));
    assert!(archived.get("state_changed_at").is_some());
    for retained in [
        "id",
        "schema",
        "realm_id",
        "kind",
        "title",
        "created_by",
        "created_at",
    ] {
        assert_eq!(archived[retained], created[retained], "{retained}");
    }

    // A distinct Event: the same bytes would be the exact replay instead.
    let again = next_request(
        &archive.authority_commit,
        arkret_wire::EventKind::SpaceArchive,
        &founder(),
        json!({"space_id": root_id, "reason": "second archive"}),
        at,
    );
    let before = count(&pool, "realm_commits", &realm_id).await;
    let error = uow.commit_event(again).await.unwrap_err().to_string();
    assert!(error.contains("space_not_active"), "{error}");
    assert_eq!(count(&pool, "realm_commits", &realm_id).await, before);
    // An archived parent admits no new child.
    let child_of_archived = next_request(
        &archive.authority_commit,
        arkret_wire::EventKind::SpaceCreate,
        &founder(),
        board(&realm_id, at, "list", Some(&root_id)),
        at,
    );
    assert!(uow.commit_event(child_of_archived).await.is_err());

    let restore = transition(
        &archive.authority_commit,
        arkret_wire::EventKind::SpaceRestore,
        &founder(),
    );
    uow.commit_event(restore.clone()).await.unwrap();
    assert_eq!(
        value(&pool, space_query, root_id.as_str()).await["state"],
        "active"
    );
    // A restored parent is again a readable parent basis for a new child.
    let child = next_request(
        &restore.authority_commit,
        arkret_wire::EventKind::SpaceCreate,
        &founder(),
        board(&realm_id, at, "list", Some(&root_id)),
        at,
    );
    uow.commit_event(child).await.unwrap();
    assert_eq!(count(&pool, "space_current_results", &realm_id).await, 2);
}

#[tokio::test]
async fn reactions_join_one_keyed_set_per_target_message() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let discussion = open_discussion(&pool, "reaction-admission").await;
    let realm_id = discussion.realm_id();
    let at = discussion.committed_at();
    let message = discussion.message_after(&discussion.head.authority_commit, "react to me", at);
    uow.commit_event(message.clone()).await.unwrap();
    let message_id =
        arkret_wire::MessageId::from_event_id(&message.authority_commit.event.event_id);
    let set_query = "SELECT value FROM message_reactions_current_results WHERE target_ref=$1";

    let missing =
        arkret_wire::MessageId::from_event_id(&discussion.head.authority_commit.event.event_id);
    let dangling = next_request(
        &message.authority_commit,
        arkret_wire::EventKind::ReactionAdd,
        &founder(),
        json!({"target_ref": missing, "key": "+1"}),
        at,
    );
    let before = count(&pool, "realm_commits", &realm_id).await;
    let error = uow.commit_event(dangling).await.unwrap_err().to_string();
    assert!(error.contains("dependency_missing"), "{error}");
    assert_eq!(count(&pool, "realm_commits", &realm_id).await, before);

    let denied = next_request(
        &message.authority_commit,
        arkret_wire::EventKind::ReactionAdd,
        &intruder(),
        json!({"target_ref": message_id, "key": "+1"}),
        at,
    );
    let error = uow.commit_event(denied).await.unwrap_err().to_string();
    assert!(error.contains("capability_denied"), "{error}");
    assert_eq!(
        count(&pool, "message_reactions_current_results", &realm_id).await,
        0
    );

    let add = next_request(
        &message.authority_commit,
        arkret_wire::EventKind::ReactionAdd,
        &founder(),
        json!({"target_ref": message_id, "key": "+1"}),
        at,
    );
    uow.commit_event(add.clone()).await.unwrap();
    let remove = next_request(
        &add.authority_commit,
        arkret_wire::EventKind::ReactionRemove,
        &founder(),
        json!({"target_ref": message_id, "key": "+1"}),
        at,
    );
    uow.commit_event(remove.clone()).await.unwrap();
    let set = value(&pool, set_query, message_id.as_str()).await;
    let assertions = set["assertions"].as_array().unwrap();
    assert_eq!(assertions.len(), 2, "{set}");
    let mut tags = [
        format!("{}:0", add.authority_commit.event.event_id),
        format!("{}:0", remove.authority_commit.event.event_id),
    ];
    tags.sort();
    assert_eq!(assertions[0]["tag_id"], tags[0]);
    assert_eq!(assertions[1]["tag_id"], tags[1]);
    for assertion in assertions {
        assert_eq!(
            assertion["value"],
            json!({"target_ref": message_id, "key": "+1"})
        );
    }

    // The reaction set is a state family: the founder's signed snapshot
    // carries it keyed by its target, with the stored dot set verbatim.
    let founder_account = arkret_wire::AccountId::new(founder(), ordinary_realm::station());
    let material =
        soland_storage_postgres::account_snapshot_material(&pool, &realm_id, &founder_account)
            .await
            .unwrap()
            .expect("the founder's snapshot is disclosable");
    let disclosed = material
        .current_state_entries
        .iter()
        .find_map(|row| match row {
            arkret_wire::TypedCurrentResult::Value {
                selector: arkret_wire::CurrentSelector::MessageReactions { target_ref },
                source_stream_ref,
                value,
                ..
            } if target_ref == message_id.as_str() => Some((source_stream_ref, value)),
            _ => None,
        })
        .expect("the snapshot carries the reaction set");
    assert_eq!(
        disclosed.0,
        &arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone()
        }
    );
    assert_eq!(disclosed.1, &set);
    let typed: arkret_models_collaboration::events_payloads::reaction::MessageReactionsCurrentValue =
        serde_json::from_value(disclosed.1.clone()).unwrap();
    typed.validate_for_target(message_id.as_str()).unwrap();
}
