//! Circle-scoped Strand and plaintext Poll use the signed Circle source and
//! confirmed membership at the accepting PostgreSQL transaction cut.
#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use arkret_wire::{CircleId, CommitStreamRef, EventKind, MessageId, ScopeRef, StrandId};
use diesel::sql_types::BigInt;
use diesel_async::RunQueryDsl;
use serde_json::{Value, json};
use soland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, EventCommitRequest, EventCommitUnitOfWork,
};
use soland_storage_postgres::test_database::TestDatabase;
use soland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgPool};

#[derive(diesel::QueryableByName)]
struct Counts {
    #[diesel(sql_type = BigInt)]
    events: i64,
    #[diesel(sql_type = BigInt)]
    commits: i64,
    #[diesel(sql_type = BigInt)]
    strands: i64,
    #[diesel(sql_type = BigInt)]
    messages: i64,
    #[diesel(sql_type = BigInt)]
    votes: i64,
}

async fn counts(pool: &PgPool) -> (i64, i64, i64, i64, i64) {
    let mut conn = pool.get().await.unwrap();
    let row = diesel::sql_query(
        "SELECT (SELECT count(*) FROM canonical_events) AS events, \
        (SELECT count(*) FROM realm_commits) AS commits, \
        (SELECT count(*) FROM strand_current_results) AS strands, \
        (SELECT count(*) FROM message_revision_current_results) AS messages, \
        (SELECT count(*) FROM poll_response_inputs) AS votes",
    )
    .get_result::<Counts>(&mut *conn)
    .await
    .unwrap();
    (
        row.events,
        row.commits,
        row.strands,
        row.messages,
        row.votes,
    )
}

fn circle_request(
    previous: &AuthorityCommitTransaction,
    circle: &CircleId,
    kind: EventKind,
    payload: Value,
) -> EventCommitRequest {
    let event = ordinary_realm::event_for_actor(
        kind,
        ScopeRef::Circle {
            realm_id: previous.event.realm_id.clone(),
            circle_id: circle.clone(),
        },
        previous.event.actor_id.clone(),
        payload,
        previous.commit.committed_at,
    );
    let mut request =
        ordinary_realm::request_for_event(previous, event, previous.commit.committed_at);
    let stream = CommitStreamRef::Circle {
        realm_id: previous.event.realm_id.clone(),
        circle_id: circle.clone(),
    };
    if previous.commit.stream_ref != stream {
        request.authority_commit.commit.stream_position = 0;
        request.authority_commit.commit.previous_commit_ref = None;
    }
    request.authority_commit.commit.stream_ref = stream;
    request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        request.authority_commit.event.clone(),
    ));
    request
}

#[tokio::test]
async fn circle_strand_and_plaintext_poll_require_exact_scope_and_current_membership() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let unit = ordinary_realm::bootstrap_unit(&uuid::Uuid::now_v7().to_string());
    let root = unit.transactions.last().unwrap();
    let realm = root.event.realm_id.clone();
    let actor = root.event.actor_id.clone();
    let at = root.commit.committed_at;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());

    let create = ordinary_realm::next_request_for_actor(
        root,
        EventKind::CircleCreate,
        actor.clone(),
        json!({"object":{"schema":"ak.schema.circle.v1","realm_id":realm,
            "title":"Poll Circle","display":{"short_name":"Poll","color_token":"blue","symbol":{"glyph":"lock"}},
            "directory_visibility":"members","join_rule":"public","history_access":"since_join",
            "state":"active","created_by":actor,"created_at":arkret_canonical::format_timestamp_canonical(at)}}),
        at,
    );
    uow.commit_event(create.clone()).await.unwrap();
    let circle = CircleId::from_event_id(&create.authority_commit.event.event_id);
    let strand_body = json!({"object":{"schema":"ak.schema.strand.v1","realm_id":realm,
        "scope_circle_id":circle,"tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
        "metadata":{"title":"Private poll"},"state":"active","created_by":actor,
        "created_at":arkret_canonical::format_timestamp_canonical(at)}});
    let not_member = circle_request(
        &create.authority_commit,
        &circle,
        EventKind::StrandCreate,
        strand_body.clone(),
    );
    let baseline = counts(&pool).await;
    assert!(uow.commit_event(not_member.clone()).await.is_err());
    assert_eq!(counts(&pool).await, baseline);
    assert!(
        store
            .committed_event(&not_member.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );

    let join = circle_request(
        &create.authority_commit,
        &circle,
        EventKind::CircleMemberState,
        json!({"circle_id":circle,"member_id":actor,"membership":"join","expected_membership":null}),
    );
    uow.commit_event(join.clone()).await.unwrap();
    // Realm-signed source cannot create an object that declares Circle scope.
    let wrong_scope = ordinary_realm::next_request_for_actor(
        &create.authority_commit,
        EventKind::StrandCreate,
        actor.clone(),
        strand_body.clone(),
        at,
    );
    let baseline = counts(&pool).await;
    assert!(uow.commit_event(wrong_scope.clone()).await.is_err());
    assert_eq!(counts(&pool).await, baseline);
    let strand = circle_request(
        &join.authority_commit,
        &circle,
        EventKind::StrandCreate,
        strand_body,
    );
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let poll = circle_request(
        &strand.authority_commit,
        &circle,
        EventKind::MessageCreate,
        json!({"strand_id":strand_id,"track_name":"discussion","content":{
            "kind":"ak.content.poll","body":"Choose","poll":{"kind":"disclosed","max_selections":1,
            "answers":[{"id":"a","text":{"kind":"ak.content.text","body":"A"}}]}}}),
    );
    uow.commit_event(poll.clone()).await.unwrap();
    let vote = circle_request(
        &poll.authority_commit,
        &circle,
        EventKind::MessageCreate,
        json!({"strand_id":strand_id,"track_name":"discussion","content":{
            "kind":"ak.content.poll.response","body":"Vote","poll_response":{
            "poll_ref":MessageId::from_event_id(&poll.authority_commit.event.event_id),"selections":["a"]}}}),
    );
    uow.commit_event(vote.clone()).await.unwrap();
    assert_eq!(counts(&pool).await.4, 1);

    // A second Circle has a distinct stream even inside the same Realm.
    // A response there cannot consume the first Circle's Poll.
    let second_create = ordinary_realm::next_request_for_actor(
        &create.authority_commit,
        EventKind::CircleCreate,
        actor.clone(),
        json!({"object":{"schema":"ak.schema.circle.v1","realm_id":realm,
            "title":"Other Circle","display":{"short_name":"Other","color_token":"blue","symbol":{"glyph":"lock"}},
            "directory_visibility":"members","join_rule":"public","history_access":"since_join",
            "state":"active","created_by":actor,"created_at":arkret_canonical::format_timestamp_canonical(at)}}),
        at,
    );
    uow.commit_event(second_create.clone()).await.unwrap();
    let second_circle = CircleId::from_event_id(&second_create.authority_commit.event.event_id);
    let second_join = circle_request(
        &second_create.authority_commit,
        &second_circle,
        EventKind::CircleMemberState,
        json!({"circle_id":second_circle,"member_id":actor,"membership":"join","expected_membership":null}),
    );
    uow.commit_event(second_join.clone()).await.unwrap();
    let second_strand = circle_request(
        &second_join.authority_commit,
        &second_circle,
        EventKind::StrandCreate,
        json!({"object":{"schema":"ak.schema.strand.v1","realm_id":realm,
            "scope_circle_id":second_circle,"tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Other private poll"},"state":"active","created_by":actor,
            "created_at":arkret_canonical::format_timestamp_canonical(at)}}),
    );
    uow.commit_event(second_strand.clone()).await.unwrap();
    let second_strand_id = StrandId::from_event_id(&second_strand.authority_commit.event.event_id);
    let cross_circle_vote = circle_request(
        &second_strand.authority_commit,
        &second_circle,
        EventKind::MessageCreate,
        json!({"strand_id":second_strand_id,"track_name":"discussion","content":{
            "kind":"ak.content.poll.response","body":"Vote","poll_response":{
            "poll_ref":MessageId::from_event_id(&poll.authority_commit.event.event_id),"selections":["a"]}}}),
    );
    let baseline = counts(&pool).await;
    let error = uow.commit_event(cross_circle_vote.clone()).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Message reference differs from its effective stream"),
        "{error}"
    );
    assert_eq!(counts(&pool).await, baseline);
    assert!(
        store
            .committed_event(&cross_circle_vote.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );

    let leave = circle_request(
        &vote.authority_commit,
        &circle,
        EventKind::CircleMemberState,
        json!({"circle_id":circle,"member_id":actor,"membership":"leave","expected_membership":"join"}),
    );
    uow.commit_event(leave.clone()).await.unwrap();
    let after_leave = circle_request(
        &leave.authority_commit,
        &circle,
        EventKind::MessageCreate,
        ordinary_realm::message_payload(&strand_id, "after leave"),
    );
    let baseline = counts(&pool).await;
    assert!(uow.commit_event(after_leave.clone()).await.is_err());
    assert_eq!(counts(&pool).await, baseline);
    assert!(
        store
            .committed_event(&after_leave.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
}
