#[path = "support/accepted_human_profile.rs"]
mod accepted_human_profile;
#[path = "../../test-support/src/device_authorization_history.rs"]
#[allow(dead_code)]
mod device_authorization_history;
#[path = "support/ordinary_realm.rs"]
mod ordinary_realm;
#[path = "../../test-support/src/pcr_genesis.rs"]
#[allow(dead_code)]
mod pcr_genesis;

use arkret_wire::{ActorId, CommitStreamRef, EventKind};
use soland_storage::{AuthorityCommitStore, AuthorityCommitTransaction, EventCommitUnitOfWork};
use soland_storage_postgres::test_database::TestDatabase;
use soland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork};

fn membership(
    previous: &AuthorityCommitTransaction,
    circle: &arkret_wire::CircleId,
    actor: &ActorId,
    state: &str,
    expected: Option<&str>,
) -> soland_storage::EventCommitRequest {
    let scope = arkret_wire::ScopeRef::Circle {
        realm_id: previous.event.realm_id.clone(),
        circle_id: circle.clone(),
    };
    let event = ordinary_realm::event_for_actor(
        EventKind::CircleMemberState,
        scope,
        actor.clone(),
        serde_json::json!({"circle_id":circle,"member_id":actor,"membership":state,"expected_membership":expected}),
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
async fn durable_circle_directory_and_member_details_follow_accepted_current() {
    check_circle_convenience("realm_members").await;
    check_circle_convenience("members").await;
}

async fn check_circle_convenience(visibility: &str) {
    use arkret_models_collaboration::governance::circle::CircleMembership;
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let did = device_authorization_history::did_web_station(&ordinary_realm::station());
    let actor = accepted_human_profile::accepted_human_profile(&pool, did.clone()).await;
    let unit = ordinary_realm::bootstrap_unit_for_account(
        &uuid::Uuid::now_v7().to_string(),
        actor.as_account_id().unwrap(),
        &did,
    );
    let head = unit.transactions.last().unwrap();
    let realm = head.event.realm_id.clone();
    let at = head.commit.committed_at;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool);
    let short = "Durable";
    let create = ordinary_realm::next_request_for_actor(
        head,
        EventKind::CircleCreate,
        actor.clone(),
        serde_json::json!({"object":{"schema":"ak.schema.circle.v1","realm_id":realm,"title":short,
            "display":{"short_name":short,"color_token":"blue","symbol":{"glyph":"lock"}},
            "directory_visibility":visibility,"join_rule":"public","history_access":"since_join","state":"active",
            "created_by":actor,"created_at":arkret_canonical::format_timestamp_canonical(at)}}),
        at,
    );
    uow.commit_event(create.clone()).await.unwrap();
    let id = arkret_wire::CircleId::from_event_id(&create.authority_commit.event.event_id);
    let before = store.circle_view_for_actor(&id, &actor).await.unwrap();
    let listed = store.circle_views_for_actor(&realm, &actor).await.unwrap();
    if visibility == "realm_members" {
        let before = before.unwrap();
        assert!(before.viewer_membership.is_none());
        assert!(
            before.member_ids.is_empty(),
            "Realm root has no implicit Circle body membership"
        );
        assert!(before.mls_group_id.is_none());
        assert_eq!(listed.len(), 1);
    } else {
        assert!(
            before.is_none(),
            "Circle creator has no implicit private Circle access"
        );
        assert!(listed.is_empty());
    }
    let join = membership(&create.authority_commit, &id, &actor, "join", None);
    uow.commit_event(join.clone()).await.unwrap();
    let joined = store
        .circle_view_for_actor(&id, &actor)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(joined.viewer_membership, Some(CircleMembership::Join));
    assert_eq!(joined.member_ids, vec![actor.clone()]);
    let leave = membership(&join.authority_commit, &id, &actor, "leave", Some("join"));
    uow.commit_event(leave).await.unwrap();
    let ended = store.circle_view_for_actor(&id, &actor).await.unwrap();
    if visibility == "realm_members" {
        let ended = ended.unwrap();
        assert_eq!(ended.viewer_membership, Some(CircleMembership::Leave));
        assert!(ended.member_ids.is_empty());
    } else {
        assert!(ended.is_none());
        assert!(
            store
                .circle_views_for_actor(&realm, &actor)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
