//! A real ordinary Realm cut drives Board/List placement; rejected writes
//! leave both the Realm stream and the typed-pair current result unchanged.

#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel_async::RunQueryDsl;
use ordinary_realm::{founder, next_request, open_discussion};
use serde_json::{Value, json};
use soland_storage::{ConflictCode, EventCommitUnitOfWork};
use soland_storage_postgres::test_database::TestDatabase;
use soland_storage_postgres::{PgEventCommitUnitOfWork, PgPool};

#[derive(diesel::QueryableByName)]
struct Count {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[derive(diesel::QueryableByName)]
struct Position {
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
}

async fn count(pool: &PgPool, realm: &arkret_wire::RealmId, table: &str) -> i64 {
    let mut conn = pool.get().await.unwrap();
    let row: Count = diesel::sql_query(format!(
        "SELECT COUNT(*) AS count FROM {table} WHERE realm_id=$1"
    ))
    .bind::<Text, _>(realm.as_str())
    .get_result(&mut conn)
    .await
    .unwrap();
    row.count
}

async fn position(
    pool: &PgPool,
    board: &arkret_wire::SpaceId,
    strand: &arkret_wire::StrandId,
) -> Position {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT value,current_stream_position FROM strand_position_current_results WHERE board_space_id=$1 AND strand_id=$2")
        .bind::<Text, _>(board.as_str()).bind::<Text, _>(strand.as_str())
        .get_result(&mut conn).await.unwrap()
}

fn space_payload(
    realm: &arkret_wire::RealmId,
    actor: &arkret_wire::ActorId,
    at: chrono::DateTime<chrono::Utc>,
    kind: &str,
    title: &str,
    parent: Option<&arkret_wire::SpaceId>,
    fields: Value,
) -> Value {
    let mut object = json!({"schema":"ak.schema.space.v1","realm_id":realm,
        "kind":kind,"title":title,"fields":fields,"created_by":actor,"created_at":at});
    if let Some(parent) = parent {
        object["parent_space_id"] = json!(parent);
    }
    json!({"object":object})
}

#[tokio::test]
async fn placement_has_whole_position_cas_reorder_and_postimage_wip_at_accepting_cut() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let opened = open_discussion(&pool, "strand-position-authority").await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let realm = opened.head.authority_commit.event.realm_id.clone();
    let actor = opened.head.authority_commit.event.actor_id.clone();
    let at = opened.head.authority_commit.commit.committed_at;
    let board = next_request(
        &opened.head.authority_commit,
        arkret_wire::EventKind::SpaceCreate,
        &founder(),
        space_payload(&realm, &actor, at, "board", "Board", None, json!({})),
        at,
    );
    let board_id = arkret_wire::SpaceId::from_event_id(&board.authority_commit.event.event_id);
    uow.commit_event(board.clone()).await.unwrap();
    let list_a = next_request(
        &board.authority_commit,
        arkret_wire::EventKind::SpaceCreate,
        &founder(),
        space_payload(
            &realm,
            &actor,
            at,
            "list",
            "A",
            Some(&board_id),
            json!({"wip_limit":1,"wip_limit_enforcement":"reject"}),
        ),
        at,
    );
    let list_a_id = arkret_wire::SpaceId::from_event_id(&list_a.authority_commit.event.event_id);
    uow.commit_event(list_a.clone()).await.unwrap();
    let list_b = next_request(
        &list_a.authority_commit,
        arkret_wire::EventKind::SpaceCreate,
        &founder(),
        space_payload(&realm, &actor, at, "list", "B", Some(&board_id), json!({})),
        at,
    );
    let list_b_id = arkret_wire::SpaceId::from_event_id(&list_b.authority_commit.event.event_id);
    uow.commit_event(list_b.clone()).await.unwrap();

    let first = next_request(
        &list_b.authority_commit,
        arkret_wire::EventKind::StrandMove,
        &founder(),
        json!({"board_space_id":board_id,"strand_id":opened.strand_id,
            "target_space_id":list_a_id,"rank":"a"}),
        at,
    );
    uow.commit_event(first.clone()).await.unwrap();
    let initial = position(&pool, &board_id, &opened.strand_id).await;
    assert_eq!(initial.value, json!({"list_space_id":list_a_id,"rank":"a"}));
    assert_eq!(
        initial.current_stream_position,
        first.authority_commit.commit.stream_position as i64
    );

    let bad = next_request(
        &first.authority_commit,
        arkret_wire::EventKind::StrandReorder,
        &founder(),
        json!({"board_space_id":board_id,"strand_id":opened.strand_id,
            "space_id":list_a_id,"rank":"b",
            "expected_position":{"list_space_id":list_a_id,"rank":"stale"}}),
        at,
    );
    let events_before = count(&pool, &realm, "canonical_events").await;
    let commits_before = count(&pool, &realm, "realm_commits").await;
    assert_eq!(
        uow.commit_event(bad).await.unwrap_err().conflict_code(),
        Some(ConflictCode::FailedPrecondition)
    );
    assert_eq!(
        count(&pool, &realm, "canonical_events").await,
        events_before
    );
    assert_eq!(count(&pool, &realm, "realm_commits").await, commits_before);
    assert_eq!(
        position(&pool, &board_id, &opened.strand_id).await.value,
        initial.value
    );

    let stranger =
        arkret_wire::DidCoreId::new("ak:did_core:web:placement-stranger.example").unwrap();
    let unauthorized = next_request(
        &first.authority_commit,
        arkret_wire::EventKind::StrandReorder,
        &stranger,
        json!({"board_space_id":board_id,"strand_id":opened.strand_id,
            "space_id":list_a_id,"rank":"unauthorized",
            "expected_position":{"list_space_id":list_a_id,"rank":"a"}}),
        at,
    );
    assert_eq!(
        uow.commit_event(unauthorized)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::CapabilityDenied)
    );
    assert_eq!(
        count(&pool, &realm, "canonical_events").await,
        events_before
    );
    assert_eq!(count(&pool, &realm, "realm_commits").await, commits_before);

    let reordered = next_request(
        &first.authority_commit,
        arkret_wire::EventKind::StrandReorder,
        &founder(),
        json!({"board_space_id":board_id,"strand_id":opened.strand_id,
            "space_id":list_a_id,"rank":"b",
            "expected_position":{"list_space_id":list_a_id,"rank":"a"}}),
        at,
    );
    uow.commit_event(reordered.clone()).await.unwrap();
    assert_eq!(
        position(&pool, &board_id, &opened.strand_id).await.value,
        json!({"list_space_id":list_a_id,"rank":"b"})
    );

    let second_strand = next_request(
        &reordered.authority_commit,
        arkret_wire::EventKind::StrandCreate,
        &founder(),
        json!({"object":{"schema":"ak.schema.strand.v1","realm_id":realm,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Second"},"state":"active","created_by":actor,
            "created_at":arkret_canonical::format_timestamp_canonical(at)}}),
        at,
    );
    let second_id =
        arkret_wire::StrandId::from_event_id(&second_strand.authority_commit.event.event_id);
    uow.commit_event(second_strand.clone()).await.unwrap();
    let over_wip = next_request(
        &second_strand.authority_commit,
        arkret_wire::EventKind::StrandMove,
        &founder(),
        json!({"board_space_id":board_id,"strand_id":second_id,
            "target_space_id":list_a_id,"rank":"c"}),
        at,
    );
    let before = (
        count(&pool, &realm, "canonical_events").await,
        count(&pool, &realm, "realm_commits").await,
    );
    assert_eq!(
        uow.commit_event(over_wip)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::FailedPrecondition)
    );
    assert_eq!(
        before,
        (
            count(&pool, &realm, "canonical_events").await,
            count(&pool, &realm, "realm_commits").await
        )
    );

    let move_out = next_request(
        &second_strand.authority_commit,
        arkret_wire::EventKind::StrandMove,
        &founder(),
        json!({"board_space_id":board_id,"strand_id":opened.strand_id,
            "from_space_id":list_a_id,"target_space_id":list_b_id,"rank":"a",
            "expected_position":{"list_space_id":list_a_id,"rank":"b"}}),
        at,
    );
    uow.commit_event(move_out.clone()).await.unwrap();
    let now_fits = next_request(
        &move_out.authority_commit,
        arkret_wire::EventKind::StrandMove,
        &founder(),
        json!({"board_space_id":board_id,"strand_id":second_id,
            "target_space_id":list_a_id,"rank":"a"}),
        at,
    );
    uow.commit_event(now_fits.clone()).await.unwrap();
    assert_eq!(
        position(&pool, &board_id, &second_id).await.value,
        json!({"list_space_id":list_a_id,"rank":"a"})
    );
}

#[tokio::test]
async fn wip_warn_accepts_but_require_review_without_proof_refuses_without_writes() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let opened = open_discussion(&pool, "strand-position-wip-enforcement").await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let realm = opened.head.authority_commit.event.realm_id.clone();
    let actor = opened.head.authority_commit.event.actor_id.clone();
    let at = opened.head.authority_commit.commit.committed_at;
    let board = next_request(
        &opened.head.authority_commit,
        arkret_wire::EventKind::SpaceCreate,
        &founder(),
        space_payload(&realm, &actor, at, "board", "Board", None, json!({})),
        at,
    );
    let board_id = arkret_wire::SpaceId::from_event_id(&board.authority_commit.event.event_id);
    uow.commit_event(board.clone()).await.unwrap();
    let warn_list = next_request(
        &board.authority_commit,
        arkret_wire::EventKind::SpaceCreate,
        &founder(),
        space_payload(
            &realm,
            &actor,
            at,
            "list",
            "Warn",
            Some(&board_id),
            json!({"wip_limit":1,"wip_limit_enforcement":"warn"}),
        ),
        at,
    );
    let warn_id = arkret_wire::SpaceId::from_event_id(&warn_list.authority_commit.event.event_id);
    uow.commit_event(warn_list.clone()).await.unwrap();
    let review_list = next_request(
        &warn_list.authority_commit,
        arkret_wire::EventKind::SpaceCreate,
        &founder(),
        space_payload(
            &realm,
            &actor,
            at,
            "list",
            "Review",
            Some(&board_id),
            json!({"wip_limit":1,"wip_limit_enforcement":"require_review"}),
        ),
        at,
    );
    let review_id =
        arkret_wire::SpaceId::from_event_id(&review_list.authority_commit.event.event_id);
    uow.commit_event(review_list.clone()).await.unwrap();
    let second_strand = next_request(
        &review_list.authority_commit,
        arkret_wire::EventKind::StrandCreate,
        &founder(),
        json!({"object":{"schema":"ak.schema.strand.v1","realm_id":realm,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Second"},"state":"active","created_by":actor,
            "created_at":arkret_canonical::format_timestamp_canonical(at)}}),
        at,
    );
    let second_id =
        arkret_wire::StrandId::from_event_id(&second_strand.authority_commit.event.event_id);
    uow.commit_event(second_strand.clone()).await.unwrap();

    let warn_first = next_request(
        &second_strand.authority_commit,
        arkret_wire::EventKind::StrandMove,
        &founder(),
        json!({"board_space_id":board_id,"strand_id":opened.strand_id,
            "target_space_id":warn_id,"rank":"a"}),
        at,
    );
    uow.commit_event(warn_first.clone()).await.unwrap();
    let warn_over_limit = next_request(
        &warn_first.authority_commit,
        arkret_wire::EventKind::StrandMove,
        &founder(),
        json!({"board_space_id":board_id,"strand_id":second_id,
            "target_space_id":warn_id,"rank":"b"}),
        at,
    );
    uow.commit_event(warn_over_limit.clone()).await.unwrap();
    assert_eq!(
        position(&pool, &board_id, &second_id).await.value,
        json!({"list_space_id":warn_id,"rank":"b"})
    );

    let review_first = next_request(
        &warn_over_limit.authority_commit,
        arkret_wire::EventKind::StrandMove,
        &founder(),
        json!({"board_space_id":board_id,"strand_id":opened.strand_id,
            "from_space_id":warn_id,"target_space_id":review_id,"rank":"a",
            "expected_position":{"list_space_id":warn_id,"rank":"a"}}),
        at,
    );
    uow.commit_event(review_first.clone()).await.unwrap();
    let review_over_limit = next_request(
        &review_first.authority_commit,
        arkret_wire::EventKind::StrandMove,
        &founder(),
        json!({"board_space_id":board_id,"strand_id":second_id,
            "from_space_id":warn_id,"target_space_id":review_id,"rank":"b",
            "expected_position":{"list_space_id":warn_id,"rank":"b"}}),
        at,
    );
    let before = (
        count(&pool, &realm, "canonical_events").await,
        count(&pool, &realm, "realm_commits").await,
    );
    assert_eq!(
        uow.commit_event(review_over_limit)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::FailedPrecondition)
    );
    assert_eq!(
        before,
        (
            count(&pool, &realm, "canonical_events").await,
            count(&pool, &realm, "realm_commits").await
        )
    );
    assert_eq!(
        position(&pool, &board_id, &second_id).await.value,
        json!({"list_space_id":warn_id,"rank":"b"})
    );
}
