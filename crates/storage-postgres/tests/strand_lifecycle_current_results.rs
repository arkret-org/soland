//! Strand progress and lifecycle transitions through the accepting PostgreSQL UOW.
//! Signatures use the ordinary structural fixture; these are storage-cut tests.
#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use arkret_wire::{ActorId, EventKind, StrandId};
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel_async::{RunQueryDsl, SimpleAsyncConnection};
use ordinary_realm::{founder, next_request, open_discussion};
use serde_json::{Value, json};
use soland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, EventCommitRequest, EventCommitUnitOfWork,
};
use soland_storage_postgres::test_database::TestDatabase;
use soland_storage_postgres::{PgEventCommitUnitOfWork, PgPool};

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
struct Footprint {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}
async fn current(pool: &PgPool, strand: &StrandId) -> Current {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT current_commit_id,current_stream_position,value FROM strand_current_results WHERE strand_id=$1")
        .bind::<Text,_>(strand.as_str()).get_result(&mut *conn).await.unwrap()
}
async fn footprint(pool: &PgPool) -> Value {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_object('events',(SELECT count(*) FROM canonical_events),'commits',(SELECT count(*) FROM realm_commits),'currents',(SELECT count(*) FROM strand_current_results),'outbox',(SELECT count(*) FROM federation_outbox)) AS value")
        .get_result::<Footprint>(&mut *conn).await.unwrap().value
}
fn stage(
    previous: &AuthorityCommitTransaction,
    strand: &StrandId,
    value: &str,
    expected: Option<&str>,
    seconds: i64,
) -> EventCommitRequest {
    let mut payload = json!({"strand_id":strand,"stage":value});
    if let Some(expected) = expected {
        payload["expected_stage"] = json!(expected);
    }
    next_request(
        previous,
        EventKind::StrandStageSet,
        &founder(),
        payload,
        previous.commit.committed_at + chrono::Duration::seconds(seconds),
    )
}
fn lifecycle(
    previous: &AuthorityCommitTransaction,
    strand: &StrandId,
    kind: EventKind,
    seconds: i64,
) -> EventCommitRequest {
    next_request(
        previous,
        kind,
        &founder(),
        json!({"target_ref":strand}),
        previous.commit.committed_at + chrono::Duration::seconds(seconds),
    )
}
async fn assert_refused(
    pool: &PgPool,
    strand: &StrandId,
    request: EventCommitRequest,
    reason: &str,
) {
    let before = current(pool, strand).await;
    let counts = footprint(pool).await;
    let error = PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(request)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains(reason), "wanted {reason}, got {error}");
    assert_eq!(current(pool, strand).await, before);
    assert_eq!(footprint(pool).await, counts);
}

#[tokio::test]
async fn stage_initial_cas_concurrent_winner_and_noop_revision_are_durable() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = open_discussion(&pool, "strand-stage-cas").await;
    let initial = current(&pool, &discussion.strand_id).await;
    assert!(initial.value.get("stage").is_none());
    assert!(initial.value.get("stage_changed_at").is_none());
    let first = stage(
        &discussion.head.authority_commit,
        &discussion.strand_id,
        "planned",
        None,
        1,
    );
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    uow.commit_event(first.clone()).await.unwrap();
    let planned = current(&pool, &discussion.strand_id).await;
    assert_eq!(planned.value["stage"], "planned");
    assert_eq!(
        planned.value["stage_changed_at"],
        arkret_canonical::format_timestamp_canonical(first.authority_commit.event.created_at)
    );
    assert_eq!(
        planned.current_commit_id,
        first.authority_commit.commit.commit_id.as_str()
    );
    for expected in [None, Some("draft")] {
        assert_refused(
            &pool,
            &discussion.strand_id,
            stage(
                &first.authority_commit,
                &discussion.strand_id,
                "in_progress",
                expected,
                2,
            ),
            "expected_stage",
        )
        .await;
    }
    let left = stage(
        &first.authority_commit,
        &discussion.strand_id,
        "in_progress",
        Some("planned"),
        3,
    );
    let right = stage(
        &first.authority_commit,
        &discussion.strand_id,
        "blocked",
        Some("planned"),
        3,
    );
    let second_uow = PgEventCommitUnitOfWork::new(pool.clone());
    let baseline = footprint(&pool).await;
    let (left_result, right_result) = tokio::join!(
        uow.commit_event(left.clone()),
        second_uow.commit_event(right.clone())
    );
    assert_ne!(
        left_result.is_ok(),
        right_result.is_ok(),
        "exactly one competing Commit may advance the shared basis"
    );
    let winner = if left_result.is_ok() { left } else { right };
    let won = current(&pool, &discussion.strand_id).await;
    assert_eq!(
        won.current_commit_id,
        winner.authority_commit.commit.commit_id.as_str()
    );
    let after = footprint(&pool).await;
    assert_eq!(
        after["events"].as_i64(),
        baseline["events"].as_i64().map(|n| n + 1)
    );
    assert_eq!(
        after["commits"].as_i64(),
        baseline["commits"].as_i64().map(|n| n + 1)
    );
    assert_eq!(after["outbox"], baseline["outbox"]);
    let value = won.value["stage"].as_str().unwrap();
    let noop = stage(
        &winner.authority_commit,
        &discussion.strand_id,
        value,
        Some(value),
        4,
    );
    uow.commit_event(noop.clone()).await.unwrap();
    let settled = current(&pool, &discussion.strand_id).await;
    assert_eq!(
        settled.value, won.value,
        "same stage preserves all semantic and audit timestamps"
    );
    assert_eq!(
        settled.current_stream_position,
        won.current_stream_position + 1
    );
    assert_eq!(
        settled.current_commit_id,
        noop.authority_commit.commit.commit_id.as_str()
    );
    let counts = footprint(&pool).await;
    let reopened = PgEventCommitUnitOfWork::new(pool.clone());
    assert!(
        !reopened
            .commit_event(noop.clone())
            .await
            .unwrap()
            .event_inserted
    );
    assert!(
        !reopened
            .commit_event(first.clone())
            .await
            .unwrap()
            .event_inserted
    );
    let reader = soland_storage_postgres::PgAuthorityCommitStore { pool: pool.clone() };
    for request in [&first, &noop] {
        assert_eq!(
            reader
                .committed_event(&request.authority_commit.event.event_id)
                .await
                .unwrap()
                .unwrap()
                .commit,
            request.authority_commit.commit
        );
    }
    assert_eq!(current(&pool, &discussion.strand_id).await, settled);
    assert_eq!(footprint(&pool).await, counts);
    let account = arkret_wire::AccountId::new(founder(), ordinary_realm::station());
    let snapshot =
        soland_storage_postgres::account_snapshot_material(&pool, &discussion.realm_id(), &account)
            .await
            .unwrap()
            .unwrap();
    assert!(snapshot.current_state_entries.iter().any(|entry| matches!(entry, arkret_wire::TypedCurrentResult::Value {selector:arkret_wire::CurrentSelector::Strand {strand_id}, revision, value,..} if strand_id == &discussion.strand_id && revision.commit_id == noop.authority_commit.commit.commit_id && value == &settled.value)));
}

#[tokio::test]
async fn archive_restore_fsm_and_accepting_time_replay_do_not_diverge() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = open_discussion(&pool, "strand-lifecycle-fsm").await;
    assert_refused(
        &pool,
        &discussion.strand_id,
        lifecycle(
            &discussion.head.authority_commit,
            &discussion.strand_id,
            EventKind::StrandRestore,
            1,
        ),
        "strand_not_archived",
    )
    .await;
    let mut archive = lifecycle(
        &discussion.head.authority_commit,
        &discussion.strand_id,
        EventKind::StrandArchive,
        2,
    );
    let accepted_at = archive.authority_commit.event.created_at + chrono::Duration::seconds(7);
    archive.authority_commit.commit.committed_at = accepted_at;
    archive.authority_commit.commit.signature =
        ordinary_realm::signature(&ordinary_realm::station(), accepted_at);
    archive.event.received_at = accepted_at;
    for projection in &mut archive.projections {
        projection.received_at = accepted_at;
    }
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    uow.commit_event(archive.clone()).await.unwrap();
    let archived = current(&pool, &discussion.strand_id).await;
    assert_eq!(archived.value["state"], "archived");
    assert_eq!(
        archived.value["state_changed_at"],
        arkret_canonical::format_timestamp_canonical(accepted_at)
    );
    assert_eq!(
        archived.value["updated_at"],
        archived.value["state_changed_at"]
    );
    assert_refused(
        &pool,
        &discussion.strand_id,
        lifecycle(
            &archive.authority_commit,
            &discussion.strand_id,
            EventKind::StrandArchive,
            1,
        ),
        "strand_not_active",
    )
    .await;
    assert_refused(
        &pool,
        &discussion.strand_id,
        stage(
            &archive.authority_commit,
            &discussion.strand_id,
            "done",
            None,
            1,
        ),
        "strand_not_active",
    )
    .await;
    let restore = lifecycle(
        &archive.authority_commit,
        &discussion.strand_id,
        EventKind::StrandRestore,
        2,
    );
    uow.commit_event(restore.clone()).await.unwrap();
    let restored = current(&pool, &discussion.strand_id).await;
    assert_eq!(restored.value["state"], "active");
    assert_eq!(
        restored.current_commit_id,
        restore.authority_commit.commit.commit_id.as_str()
    );
    let baseline = footprint(&pool).await;
    let reopened = PgEventCommitUnitOfWork::new(pool.clone());
    let reader = soland_storage_postgres::PgAuthorityCommitStore { pool: pool.clone() };
    for request in [archive, restore] {
        assert!(
            !reopened
                .commit_event(request.clone())
                .await
                .unwrap()
                .event_inserted
        );
        assert_eq!(
            reader
                .committed_event(&request.authority_commit.event.event_id)
                .await
                .unwrap()
                .unwrap()
                .commit,
            request.authority_commit.commit
        );
    }
    assert_eq!(current(&pool, &discussion.strand_id).await, restored);
    assert_eq!(footprint(&pool).await, baseline);
}

#[tokio::test]
async fn transition_actor_realm_and_scope_refusals_leave_no_durable_footprint() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = open_discussion(&pool, "strand-transition-gates").await;
    let other = open_discussion(&pool, "strand-transition-other-realm").await;
    let previous = &discussion.head.authority_commit;
    for actor in [
        ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:transition-outsider.example").unwrap(),
            ordinary_realm::station(),
        )),
        ActorId::account(arkret_wire::AccountId::new(
            founder(),
            arkret_wire::DidCoreId::new("ak:did_core:web:other-transition-station.example")
                .unwrap(),
        )),
    ] {
        let request = ordinary_realm::next_request_for_actor(
            previous,
            EventKind::StrandStageSet,
            actor,
            json!({"strand_id":discussion.strand_id,"stage":"done"}),
            previous.commit.committed_at + chrono::Duration::seconds(1),
        );
        assert_refused(&pool, &discussion.strand_id, request, "capability_denied").await;
    }
    assert_refused(
        &pool,
        &discussion.strand_id,
        stage(previous, &other.strand_id, "done", None, 2),
        "target",
    )
    .await;
    let event = ordinary_realm::event(
        EventKind::StrandStageSet,
        arkret_wire::ScopeRef::Circle {
            realm_id: discussion.realm_id(),
            circle_id: arkret_wire::CircleId::from_event_id(&previous.event.event_id),
        },
        &founder(),
        &ordinary_realm::station(),
        json!({"strand_id":discussion.strand_id,"stage":"done"}),
        previous.commit.committed_at + chrono::Duration::seconds(3),
    );
    let request = ordinary_realm::request_for_event(
        previous,
        event,
        previous.commit.committed_at + chrono::Duration::seconds(3),
    );
    // The malformed request's Event scope does not match its Realm Commit;
    // either transaction validation or the writer must reject it before writes.
    assert_refused(&pool, &discussion.strand_id, request, "bindings disagree").await;
}

#[tokio::test]
async fn transition_update_fault_rolls_back_event_commit_and_current_together() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = open_discussion(&pool, "strand-transition-fault").await;
    let mut previous = discussion.head.authority_commit.clone();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    for kind in [EventKind::StrandStageSet, EventKind::StrandArchive] {
        let request = if kind == EventKind::StrandStageSet {
            stage(&previous, &discussion.strand_id, "done", None, 1)
        } else {
            lifecycle(&previous, &discussion.strand_id, kind, 1)
        };
        let before = current(&pool, &discussion.strand_id).await;
        let baseline = footprint(&pool).await;
        let mut conn = pool.get().await.unwrap();
        conn.batch_execute("CREATE FUNCTION strand_transition_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'strand transition fault'; END $$; CREATE TRIGGER strand_transition_fault BEFORE UPDATE ON strand_current_results FOR EACH ROW EXECUTE FUNCTION strand_transition_fault();").await.unwrap();
        drop(conn);
        let result = uow.commit_event(request.clone()).await;
        let mut conn = pool.get().await.unwrap();
        conn.batch_execute("DROP TRIGGER strand_transition_fault ON strand_current_results; DROP FUNCTION strand_transition_fault();").await.unwrap();
        drop(conn);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("strand transition fault")
        );
        assert_eq!(current(&pool, &discussion.strand_id).await, before);
        assert_eq!(footprint(&pool).await, baseline);
        assert!(
            uow.commit_event(request.clone())
                .await
                .unwrap()
                .event_inserted
        );
        assert_eq!(
            current(&pool, &discussion.strand_id)
                .await
                .current_commit_id,
            request.authority_commit.commit.commit_id.as_str()
        );
        previous = request.authority_commit;
    }
}
