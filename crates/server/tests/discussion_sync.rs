//! Retired discussion sync coverage uses committed stream positions and the
//! current membership/history policy. Equal Event timestamps deliberately
//! prove that the join Commit, rather than arrival time, defines the floor.

#[path = "../../storage-postgres/tests/support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use arkret_wire::{
    CommitStreamRef, CommittedEventView, EventKind, StrandId, StreamScanDirection,
    StreamScanOutcome, StreamScanRequest,
};
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use soland_http::config::AppConfig;
use soland_http::service;
use soland_test_support::AppStateTestExt as _;

const SCAN_PATH: &str = "/_arkret/self/streams/scan";

async fn persisted_read_session(
    state: &soland_http::state::AppState,
    actor: &arkret_wire::DidCoreId,
) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    let store = state.test_persistence();
    let now = chrono::Utc::now();
    let account_pk = store
        .accounts()
        .put(&soland_storage::AccountRecord {
            pk: soland_storage::AccountPk(0),
            principal_id: actor.clone(),
            station_id: state.service_core_id(),
            localpart: format!("history-{}", uuid::Uuid::now_v7().simple()),
            display_name: None,
            bio: None,
            avatar_blob_ref: None,
            created_at: now,
        })
        .await
        .unwrap();
    let token = format!("history-reader-{}", uuid::Uuid::now_v7());
    let mut hash = Sha256::new();
    hash.update(state.service_id().as_bytes());
    hash.update(b":");
    hash.update(token.as_bytes());
    let token_hash = format!(
        "sha256:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash.finalize())
    );
    let device_id = format!("ak:device:{}", uuid::Uuid::now_v7());
    store
        .devices()
        .put_if_absent(&soland_storage::DeviceInventoryRecord {
            actor: actor.to_string(),
            device_id: device_id.clone(),
            display_name: None,
            verification_state: "unverified".to_owned(),
            payload: json!({}),
            created_at: now,
            updated_at: now,
            revoked_at: None,
        })
        .await
        .unwrap();
    store
        .sessions()
        .put(&soland_storage::SessionRecord {
            token_hash,
            account_pk,
            actor: actor.to_string(),
            device_id,
            audience: state.service_id().clone(),
            session_public_key: None,
            agent_session: None,
            expires_at: now + chrono::Duration::hours(1),
            created_at: now,
            revoked_at: None,
        })
        .await
        .unwrap();
    token
}
async fn scan(
    state: &soland_http::state::AppState,
    token: &str,
    request: &StreamScanRequest,
) -> (StatusCode, Value) {
    let canonical_body = String::from_utf8(
        arkret_canonical::canonical_json_bytes(request).expect("canonical scan request"),
    )
    .expect("canonical JSON is UTF-8");
    let mut response = TestClient::post(format!("http://server{SCAN_PATH}"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1,
            true,
        )
        .raw_json(canonical_body)
        .send(&service(state.clone()))
        .await;
    (
        response.status_code.expect("scan status"),
        response.take_json().await.expect("scan JSON"),
    )
}

fn next(
    previous: &soland_storage::AuthorityCommitTransaction,
    kind: EventKind,
    payload: Value,
    station_did: &arkret_wire::Did,
) -> soland_storage::EventCommitRequest {
    let mut request = ordinary_realm::next_request(
        previous,
        kind,
        &ordinary_realm::human_profile::account(&ordinary_realm::station(), "ordinary-founder")
            .principal_id,
        payload,
        previous.commit.committed_at,
    );
    request.authority_commit.commit.signature =
        ordinary_realm::signature_for_did(station_did, previous.commit.committed_at);
    request
}

async fn history_scenario(history: &str, via_invite: bool) {
    let (state, pool) = soland_test_support::app_state_with_pool(AppConfig {
        development_mode: true,
        ..soland_test_support::app_config()
    });
    let human =
        ordinary_realm::human_profile::admit(&pool, &state.service_core_id(), "ordinary-founder")
            .await;
    let persistence = state.test_persistence();
    let unit = ordinary_realm::bootstrap_unit_with_history_for_account(
        &format!("discussion-{history}-{}", uuid::Uuid::now_v7()),
        if via_invite { "invite" } else { "public" },
        history,
        &human,
        &state.service_did(),
    );
    unit.validate().unwrap();
    persistence
        .authority_commits()
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let initial = unit.transactions.last().unwrap();
    let realm_id = initial.event.realm_id.clone();
    let strand = next(
        initial,
        EventKind::StrandCreate,
        json!({"object": {
            "schema":"ak.schema.strand.v1", "realm_id":realm_id,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"History floor"}, "state":"active",
            "created_by":initial.event.actor_id, "created_at":initial.commit.committed_at,
        }}),
        &state.service_did(),
    );
    persistence.commit_event(strand.clone()).await.unwrap();
    let strand_id = StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let default = next(
        &strand.authority_commit,
        EventKind::RealmSetDefaultStrand,
        json!({
            "realm_id":realm_id, "strand_id":strand_id, "expected_default_strand_id":null,
        }),
        &state.service_did(),
    );
    persistence.commit_event(default.clone()).await.unwrap();
    let before = next(
        &default.authority_commit,
        EventKind::MessageCreate,
        ordinary_realm::message_payload(&strand_id, "before join"),
        &state.service_did(),
    );
    persistence.commit_event(before.clone()).await.unwrap();
    let bob = arkret_wire::DidCoreId::new("ak:did_core:web:discussion-reader.example").unwrap();
    let bob_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        bob.clone(),
        state.service_core_id(),
    ));
    let token = persisted_read_session(&state, &bob).await;
    let (previous, kind, payload) = if via_invite {
        let invite = next(
            &before.authority_commit,
            EventKind::InviteCreate,
            json!({
                "invitee_account_id": bob_actor.as_account_id().unwrap(),
                "introduction_evidence_digest": format!("sha256:{}", "a".repeat(64)),
                "expires_at": arkret_canonical::format_timestamp_canonical(initial.commit.committed_at + chrono::Duration::days(7)),
            }),
            &state.service_did(),
        );
        persistence.commit_event(invite.clone()).await.unwrap();
        let payload = json!({
            "invite_id": arkret_wire::InviteId::from_event_id(&invite.authority_commit.event.event_id),
            "previous_state": "pending",
            "invitee_account_id": bob_actor.as_account_id().unwrap(),
        });
        (invite.authority_commit, EventKind::InviteAccept, payload)
    } else {
        (
            before.authority_commit.clone(),
            EventKind::MemberState,
            json!({"member_id":bob_actor,"membership":"join"}),
        )
    };
    let mut join =
        ordinary_realm::next_request(&previous, kind, &bob, payload, initial.commit.committed_at);
    join.authority_commit.commit.signature =
        ordinary_realm::signature_for_did(&state.service_did(), initial.commit.committed_at);
    persistence.commit_event(join.clone()).await.unwrap();
    let after = next(
        &join.authority_commit,
        EventKind::MessageCreate,
        ordinary_realm::message_payload(&strand_id, "after join"),
        &state.service_did(),
    );
    persistence.commit_event(after.clone()).await.unwrap();
    assert_eq!(
        before.authority_commit.event.created_at,
        after.authority_commit.event.created_at
    );
    let request = StreamScanRequest {
        realm_id: realm_id.clone(),
        stream_ref: CommitStreamRef::Realm { realm_id },
        direction: StreamScanDirection::After(None),
        limit: 100,
    };
    let (status, body) = scan(&state, &token, &request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let page: StreamScanOutcome = serde_json::from_value(body).unwrap();
    page.validate_for_request(&request).unwrap();
    let event_ids = page
        .committed_events
        .iter()
        .filter_map(|view| {
            if let CommittedEventView::Full(full) = view {
                Some(full.event.event_id.clone())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    assert!(event_ids.contains(&after.authority_commit.event.event_id));
    let floor = page.readable_floor.as_ref().unwrap();
    if history == "since_join" {
        assert!(!event_ids.contains(&before.authority_commit.event.event_id));
        assert_eq!(
            floor.oldest_position,
            join.authority_commit.commit.stream_position
        );
        assert_eq!(
            floor.floor_commit_id,
            join.authority_commit.commit.commit_id
        );
        assert_eq!(
            floor.floor_reason,
            arkret_wire::ReadableFloorReason::MembershipJoin
        );
    } else {
        assert!(event_ids.contains(&before.authority_commit.event.event_id));
        assert_eq!(floor.oldest_position, 0);
        assert_eq!(
            floor.floor_reason,
            arkret_wire::ReadableFloorReason::StreamStart
        );
    }
    let continuation = StreamScanRequest {
        direction: StreamScanDirection::After(Some(join.authority_commit.commit.stream_position)),
        ..request
    };
    let (status, body) = scan(&state, &token, &continuation).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let tail: StreamScanOutcome = serde_json::from_value(body).unwrap();
    tail.validate_for_request(&continuation).unwrap();
    assert_eq!(tail.committed_events.len(), 1);
    assert_eq!(
        tail.committed_events[0].commit(),
        &after.authority_commit.commit
    );
    assert_eq!(tail.readable_floor, page.readable_floor);
}

#[tokio::test]
async fn since_join_hides_prior_messages_and_continues_from_join_commit() {
    history_scenario("since_join", false).await;
}

#[tokio::test]
async fn shared_history_backfills_prior_messages_for_a_current_member() {
    history_scenario("all_history_for_current_members", false).await;
}

#[tokio::test]
async fn invite_accept_sets_the_since_join_floor_and_continuation() {
    history_scenario("since_join", true).await;
}
