//! Integration tests for `ck.receipt.read` relay and read-side visibility.

#![allow(unused_imports)]
use super::common::*;

const ALICE: &str = "did:web:alice.example";
const ALICE_DEVICE: &str = "ck:device:01904100-0000-7000-8000-a11ce0000001";
const BOB: &str = "did:web:bob.example";
const BOB_DEVICE: &str = "ck:device:01904100-0000-7000-8000-b0b000000001";
const CAROL: &str = "did:web:carol.example";
const CAROL_DEVICE: &str = "ck:device:01904100-0000-7000-8000-ca0010000001";
const DAVE: &str = "did:web:dave.example";
const DAVE_DEVICE: &str = "ck:device:01904100-0000-7000-8000-da0010000001";

async fn set_demo_realm_visibility(
    state: &AppState,
    discoverability: &str,
    history_visibility: &str,
) {
    let now = chrono::Utc::now();
    let mut meta = state
        .persistence
        .realm_meta()
        .get(DEMO_REALM_ID)
        .await
        .unwrap()
        .unwrap_or_else(|| RealmMetaRecord {
            owner: ALICE.to_owned(),
            deleted: false,
            discoverability: discoverability.to_owned(),
            history_visibility: history_visibility.to_owned(),
            history_sharing_policy: None,
            history_sharing_policy_digest: None,
            preview_policy: None,
            preview_policy_digest: None,
            encryption_profile: Some("none".to_owned()),
            plaintext_visible_services: std::collections::BTreeSet::from([state
                .config
                .service_did
                .clone()]),
            minimal_metadata_realm: false,
            created_at: now,
            updated_at: now,
        });
    meta.discoverability = discoverability.to_owned();
    meta.history_visibility = history_visibility.to_owned();
    meta.encryption_profile = Some("none".to_owned());
    meta.plaintext_visible_services =
        std::collections::BTreeSet::from([state.config.service_did.clone()]);
    meta.updated_at = now;
    state
        .persistence
        .realm_meta()
        .put(DEMO_REALM_ID, &meta)
        .await
        .unwrap();
}

async fn set_read_receipt_policy(
    state: AppState,
    token: &str,
    visibility: &str,
    allow_public_world_readable: bool,
) {
    let response = submit_read_receipt_policy(
        state,
        token,
        "optional",
        visibility,
        allow_public_world_readable,
        false,
    )
    .await;
    assert!(
        response["status"] == "accepted"
            || response["accepted"]
                .as_array()
                .is_some_and(|events| !events.is_empty()),
        "read receipt policy event: {response}"
    );
}

async fn submit_read_receipt_policy(
    state: AppState,
    token: &str,
    disclosure: &str,
    visibility: &str,
    allow_public_world_readable: bool,
    allow_forced_public_world_readable: bool,
) -> Value {
    submit_actor_private_event(
        state,
        token,
        ALICE,
        ALICE_DEVICE,
        DEMO_REALM_ID,
        "ck.realm.read_receipt_policy",
        serde_json::json!({
            "disclosure": disclosure,
            "visibility": visibility,
            "scope_overrides_allowed": true,
            "allow_public_receipts_on_world_readable": allow_public_world_readable,
            "allow_forced_public_world_readable_receipts": allow_forced_public_world_readable
        }),
    )
    .await
}

#[tokio::test]
async fn read_receipt_policy_rejects_public_world_readable_without_opt_in() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice_token = dev_token(state.clone()).await;
    set_demo_realm_visibility(&state, "public", "world_readable").await;

    let response = submit_read_receipt_policy(
        state.clone(),
        &alice_token,
        "optional",
        "public",
        false,
        false,
    )
    .await;

    assert_ne!(
        response["status"], "accepted",
        "public world_readable policy must be rejected: {response}"
    );
    let encoded = serde_json::to_string(&response).unwrap();
    assert!(
        encoded.contains("read_receipt_visibility_combination_invalid"),
        "response must include read_receipt_visibility_combination_invalid: {response}"
    );
}

#[tokio::test]
async fn read_receipt_policy_rejects_forced_public_world_readable_without_second_opt_in() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice_token = dev_token(state.clone()).await;
    set_demo_realm_visibility(&state, "public", "world_readable").await;

    let response = submit_read_receipt_policy(
        state.clone(),
        &alice_token,
        "required",
        "public",
        true,
        false,
    )
    .await;

    assert_ne!(
        response["status"], "accepted",
        "forced public world_readable policy must be rejected: {response}"
    );
    let encoded = serde_json::to_string(&response).unwrap();
    assert!(
        encoded.contains("read_receipt_forced_public_world_readable_forbidden"),
        "response must include read_receipt_forced_public_world_readable_forbidden: {response}"
    );
}

fn read_receipt_envelope(actor: &str, device_id: &str, event_id: &str, ttl_ms: i64) -> Value {
    let sent_at = chrono::Utc::now();
    let expires_at = sent_at + chrono::Duration::milliseconds(ttl_ms);
    serde_json::json!({
        "kind": "ck.receipt.read",
        "realm_id": DEMO_REALM_ID,
        "actor_id": actor,
        "device_id": device_id,
        "sent_at": sent_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "expires_at": expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "payload": {
            "receipt_type": "read",
            "schema": "ck.schema.read_receipt.v1",
            "realm_id": DEMO_REALM_ID,
            "actor_id": actor,
            "event_id": event_id,
            "read_scope": {"kind": "realm"},
            "created_at": sent_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        }
    })
}

async fn post_read_receipt(
    state: AppState,
    token: &str,
    envelope: &Value,
) -> salvo::http::Response {
    TestClient::post("http://server/_cokret/self/ephemeral")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(envelope)
        .send(&app_from_state(state))
        .await
}

fn receipts_in_subscribe(frame: &Value, realm_id: &str) -> Vec<Value> {
    let Some(realm) = frame["realms"].get(realm_id) else {
        return Vec::new();
    };
    let Some(ephemeral) = realm["ephemeral"].as_array() else {
        return Vec::new();
    };
    ephemeral
        .iter()
        .filter(|item| item["type"] == "ck.receipt.read")
        .flat_map(|item| item["receipts"].as_array().cloned().unwrap_or_default())
        .collect()
}

async fn event_view_receipts(state: AppState, token: &str, event_id: &str) -> Vec<Value> {
    let view: Value = TestClient::get(format!("http://server/_cokret/self/events/{event_id}"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    view["receipts"].as_array().cloned().unwrap_or_default()
}

async fn submit_alice_target_message(state: AppState, token: &str, body: &str) -> String {
    let message = submit_message_event(
        state,
        token,
        ALICE,
        DEMO_REALM_ID,
        "ck:strand:0196419b-0000-7000-8000-000000000000",
        serde_json::json!({"body": body}),
        false,
    )
    .await;
    message["event_id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn private_read_receipt_visible_only_to_target_sender() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice_token = dev_token(state.clone()).await;
    add_test_realm_member(&state, DEMO_REALM_ID, BOB);
    add_test_realm_member(&state, DEMO_REALM_ID, CAROL);
    let bob_token = dev_token_for_device(state.clone(), BOB, BOB_DEVICE, "Bob Desktop").await;
    let carol_token =
        dev_token_for_device(state.clone(), CAROL, CAROL_DEVICE, "Carol Desktop").await;
    set_demo_realm_visibility(&state, "invite_only", "shared").await;

    let target_event_id =
        submit_alice_target_message(state.clone(), &alice_token, "private receipt target").await;
    set_read_receipt_policy(state.clone(), &alice_token, "private", false).await;
    let envelope = read_receipt_envelope(BOB, BOB_DEVICE, &target_event_id, 30_000);
    let submit = post_read_receipt(state.clone(), &bob_token, &envelope).await;
    assert_eq!(submit.status_code, Some(StatusCode::OK));

    let alice_frame =
        account_subscribe_frame(state.clone(), Some(&alice_token), "catchup=true").await;
    let alice_receipts = receipts_in_subscribe(&alice_frame, DEMO_REALM_ID);
    assert_eq!(alice_receipts.len(), 1);
    assert_eq!(alice_receipts[0]["actor_id"], BOB);
    assert_eq!(alice_receipts[0]["event_id"], target_event_id);

    let bob_frame = account_subscribe_frame(state.clone(), Some(&bob_token), "catchup=true").await;
    assert!(receipts_in_subscribe(&bob_frame, DEMO_REALM_ID).is_empty());
    let carol_frame =
        account_subscribe_frame(state.clone(), Some(&carol_token), "catchup=true").await;
    assert!(receipts_in_subscribe(&carol_frame, DEMO_REALM_ID).is_empty());

    let alice_view = event_view_receipts(state.clone(), &alice_token, &target_event_id).await;
    assert_eq!(alice_view.len(), 1);
    let bob_view = event_view_receipts(state.clone(), &bob_token, &target_event_id).await;
    assert!(bob_view.is_empty());
}

#[tokio::test]
async fn members_and_public_read_receipts_are_cropped() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice_token = dev_token(state.clone()).await;
    add_test_realm_member(&state, DEMO_REALM_ID, BOB);
    let bob_token = dev_token_for_device(state.clone(), BOB, BOB_DEVICE, "Bob Desktop").await;
    let dave_token = dev_token_for_device(state.clone(), DAVE, DAVE_DEVICE, "Dave Desktop").await;
    set_demo_realm_visibility(&state, "public", "world_readable").await;

    let target_event_id =
        submit_alice_target_message(state.clone(), &alice_token, "members public crop").await;
    set_read_receipt_policy(state.clone(), &alice_token, "members", false).await;
    let members_envelope = read_receipt_envelope(BOB, BOB_DEVICE, &target_event_id, 30_000);
    assert_eq!(
        post_read_receipt(state.clone(), &bob_token, &members_envelope)
            .await
            .status_code,
        Some(StatusCode::OK)
    );

    let alice_view = event_view_receipts(state.clone(), &alice_token, &target_event_id).await;
    assert_eq!(alice_view.len(), 1);
    let dave_view = event_view_receipts(state.clone(), &dave_token, &target_event_id).await;
    assert!(dave_view.is_empty());
    let dave_members_frame =
        account_subscribe_frame(state.clone(), Some(&dave_token), "catchup=true").await;
    assert!(receipts_in_subscribe(&dave_members_frame, DEMO_REALM_ID).is_empty());

    set_read_receipt_policy(state.clone(), &alice_token, "public", true).await;
    let public_envelope = read_receipt_envelope(BOB, BOB_DEVICE, &target_event_id, 30_000);
    assert_eq!(
        post_read_receipt(state.clone(), &bob_token, &public_envelope)
            .await
            .status_code,
        Some(StatusCode::OK)
    );

    let dave_public_view = event_view_receipts(state.clone(), &dave_token, &target_event_id).await;
    assert_eq!(dave_public_view.len(), 1);
    assert_eq!(dave_public_view[0]["actor_id"], BOB);
    let dave_public_frame =
        account_subscribe_frame(state.clone(), Some(&dave_token), "catchup=true").await;
    let dave_public_receipts = receipts_in_subscribe(&dave_public_frame, DEMO_REALM_ID);
    assert_eq!(dave_public_receipts.len(), 1);
    assert_eq!(dave_public_receipts[0]["actor_id"], BOB);
}

#[tokio::test]
async fn read_receipt_ttl_expiry_suppresses_sync_and_event_view() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice_token = dev_token(state.clone()).await;
    add_test_realm_member(&state, DEMO_REALM_ID, BOB);
    let bob_token = dev_token_for_device(state.clone(), BOB, BOB_DEVICE, "Bob Desktop").await;
    set_demo_realm_visibility(&state, "invite_only", "shared").await;

    let target_event_id =
        submit_alice_target_message(state.clone(), &alice_token, "ttl receipt target").await;
    set_read_receipt_policy(state.clone(), &alice_token, "members", false).await;
    let envelope = read_receipt_envelope(BOB, BOB_DEVICE, &target_event_id, 500);
    assert_eq!(
        post_read_receipt(state.clone(), &bob_token, &envelope)
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    tokio::time::sleep(Duration::from_millis(650)).await;

    let alice_frame =
        account_subscribe_frame(state.clone(), Some(&alice_token), "catchup=true").await;
    assert!(receipts_in_subscribe(&alice_frame, DEMO_REALM_ID).is_empty());
    let alice_view = event_view_receipts(state.clone(), &alice_token, &target_event_id).await;
    assert!(alice_view.is_empty());
}
