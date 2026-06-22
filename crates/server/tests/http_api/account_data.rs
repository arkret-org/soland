//! Integration tests — `account_data` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

#![allow(unused_imports)]
use super::common::*;

#[tokio::test]
async fn account_data_accepts_fresh_principal_control_realm() {
    const FRESH_DID: &str = "did:web:fresh-avatar.example";
    const FRESH_DEVICE: &str = "ck:device:01904100-0000-7000-8000-a11ce0000010";
    const BOB_DEVICE: &str = "ck:device:01904100-0000-7000-8000-b0b000000010";

    let state = AppState::new(test_config(), Db { pool: None });
    let fresh = dev_token_for_device(state.clone(), FRESH_DID, FRESH_DEVICE, "Fresh").await;
    let bob = dev_token_for_device(state.clone(), "did:web:bob.example", BOB_DEVICE, "Bob").await;

    let principal: Value = TestClient::get(format!(
        "http://server/_soland/self/account/{FRESH_DID}/principal-realm"
    ))
    .add_header("authorization", format!("Bearer {fresh}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let principal_realm = principal["realm_id"].as_str().unwrap();
    assert!(
        principal_realm.starts_with("ck:realm:"),
        "principal realm response: {principal}"
    );

    let body = serde_json::json!({
        "theme": "night",
        "avatar_blob_ref": "ck:blob:sha256:1111111111111111111111111111111111111111111111111111111111111111"
    });
    let put = submit_actor_private_event(
        state.clone(),
        &fresh,
        FRESH_DID,
        FRESH_DEVICE,
        principal_realm,
        "ck.account_data.set",
        serde_json::json!({
            "key": "client.ui",
            "owner": FRESH_DID,
            "body": body.clone(),
            "updated_at": "2026-06-08T00:00:00Z"
        }),
    )
    .await;
    assert_eq!(
        put["status"], "accepted",
        "fresh principal account_data response: {put}"
    );

    let sync = account_subscribe_frame(
        state.clone(),
        Some(&fresh),
        "catchup=true&set_presence=online",
    )
    .await;
    let entry = account_data_entry(&sync, "client.ui");
    assert_eq!(entry["content"], body);

    let denied = submit_actor_private_event(
        state.clone(),
        &bob,
        "did:web:bob.example",
        BOB_DEVICE,
        principal_realm,
        "ck.account_data.set",
        serde_json::json!({
            "key": "client.ui",
            "owner": "did:web:bob.example",
            "body": {"theme": "light"},
            "updated_at": "2026-06-08T00:01:00Z"
        }),
    )
    .await;
    assert_eq!(denied["error"]["code"], "capability_denied", "{denied}");
}

#[tokio::test]
async fn encrypted_account_data_realm_remark_round_trip() {
    const ALICE_DEVICE: &str = "ck:device:01904100-0000-7000-8000-a11ce0000001";
    const BOB_DEVICE: &str = "ck:device:01904100-0000-7000-8000-b0b000000001";

    let state = AppState::new(test_config(), Db { pool: None });
    let alice = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        ALICE_DEVICE,
        "Alice",
    )
    .await;
    let bob = dev_token_for_device(state.clone(), "did:web:bob.example", BOB_DEVICE, "Bob").await;

    let realm_id = "ck:realm:0196419b-0000-7000-8000-000000000000";
    let key = format!("ck.contacts.realm.{realm_id}");
    let remark = account_data_client_side_marker("44", "opaque-realm-remark-v1");

    let first = submit_actor_private_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        ALICE_DEVICE,
        DEMO_REALM_ID,
        "ck.account_data.set",
        serde_json::json!({
            "key": key.as_str(),
            "owner": "did:web:alice.example",
            "encrypted_payload": remark.clone(),
            "updated_at": "2026-05-08T10:00:00Z"
        }),
    )
    .await;
    assert_eq!(
        first["status"], "accepted",
        "first account_data response: {first}"
    );

    let initial_sync = account_subscribe_frame(
        state.clone(),
        Some(&alice),
        "catchup=true&set_presence=online",
    )
    .await;
    let initial_entry = account_data_entry(&initial_sync, &key);
    assert_eq!(initial_entry["content"], remark);

    // Second event updates the same key with the new payload.
    let updated_remark = account_data_client_side_marker("55", "opaque-realm-remark-v2");
    let updated = submit_actor_private_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        ALICE_DEVICE,
        DEMO_REALM_ID,
        "ck.account_data.set",
        serde_json::json!({
            "key": key.as_str(),
            "owner": "did:web:alice.example",
            "encrypted_payload": updated_remark.clone(),
            "updated_at": "2026-05-09T10:00:00Z"
        }),
    )
    .await;
    assert_eq!(
        updated["status"], "accepted",
        "updated account_data response: {updated}"
    );

    let sync_resp = account_subscribe_frame(
        state.clone(),
        Some(&alice),
        "catchup=true&set_presence=online",
    )
    .await;
    let entry = account_data_entry(&sync_resp, &key);
    assert_eq!(entry["content"], updated_remark);

    // Actor isolation: Bob's /sync does NOT see Alice's remark.
    let bob_sync = account_subscribe_frame(
        state.clone(),
        Some(&bob),
        "catchup=true&set_presence=online",
    )
    .await;
    let bob_entries = bob_sync["account_data"]["events"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        bob_entries.iter().all(|e| e["data_type"] != key.as_str()),
        "bob must not see alice's account_data"
    );

    let tombstone = submit_actor_private_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        ALICE_DEVICE,
        DEMO_REALM_ID,
        "ck.account_data.set",
        serde_json::json!({
            "key": key.as_str(),
            "owner": "did:web:alice.example",
            "tombstone": true,
            "updated_at": "2026-05-10T10:00:00Z"
        }),
    )
    .await;
    assert_eq!(
        tombstone["status"], "accepted",
        "tombstone account_data response: {tombstone}"
    );
    let after_delete = account_subscribe_frame(
        state.clone(),
        Some(&alice),
        "catchup=true&set_presence=online",
    )
    .await;
    assert!(
        after_delete["account_data"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["data_type"] != key.as_str()),
        "tombstoned account_data must not appear in account subscribe"
    );
}

#[tokio::test]
async fn encrypted_account_data_requires_envelope_metadata_or_marker() {
    const ALICE_DEVICE: &str = "ck:device:01904100-0000-7000-8000-a11ce0000001";

    let state = AppState::new(test_config(), Db { pool: None });
    let alice = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        ALICE_DEVICE,
        "Alice",
    )
    .await;
    let key = "ck.saved.v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    let envelope = account_data_encrypted_envelope();

    let accepted = submit_actor_private_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        ALICE_DEVICE,
        DEMO_REALM_ID,
        "ck.account_data.set",
        serde_json::json!({
            "key": key,
            "owner": "did:web:alice.example",
            "encrypted_payload": envelope.clone(),
            "updated_at": "2026-06-18T00:00:00Z"
        }),
    )
    .await;
    assert_eq!(
        accepted["status"], "accepted",
        "encrypted account_data response: {accepted}"
    );

    let sync = account_subscribe_frame(
        state.clone(),
        Some(&alice),
        "catchup=true&set_presence=online",
    )
    .await;
    let entry = account_data_entry(&sync, key);
    assert_eq!(entry["content"], envelope);

    let rejected = submit_actor_private_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        ALICE_DEVICE,
        DEMO_REALM_ID,
        "ck.account_data.set",
        serde_json::json!({
            "key": key,
            "owner": "did:web:alice.example",
            "encrypted_payload": {"ciphertext": "opaque"},
            "updated_at": "2026-06-18T00:01:00Z"
        }),
    )
    .await;
    assert_eq!(
        rejected["error"]["code"], "schema_violation",
        "invalid encrypted account_data response: {rejected}"
    );

    let marker_key = "ck.file_transfer.v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let marker = serde_json::json!({
        "client_side_conformance": {
            "encrypted_account_data": true,
            "profile_id": "ck.profile.e2ee_client.v1",
            "plaintext_schema_id": "ck.schema.file_transfer.v1",
            "payload_digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444"
        },
        "content_type": "application/vnd.cokret.account-data+json",
        "ciphertext": "opaque-client-envelope"
    });
    let put: Value = TestClient::put(format!(
        "http://server/_cokret/self/account_data/{marker_key}"
    ))
    .add_header("authorization", format!("Bearer {alice}"), true)
    .json(&serde_json::json!({"content": marker.clone()}))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        put["data_type"], marker_key,
        "marker account_data PUT: {put}"
    );
    assert_eq!(put["content"], marker);
}

#[tokio::test]
async fn encrypted_realm_remark_rejects_plaintext_carrier() {
    const ALICE_DEVICE: &str = "ck:device:01904100-0000-7000-8000-a11ce0000001";

    let state = AppState::new(test_config(), Db { pool: None });
    let alice = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        ALICE_DEVICE,
        "Alice",
    )
    .await;
    let key = format!("ck.contacts.realm.{DEMO_REALM_ID}");

    let rejected = submit_actor_private_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        ALICE_DEVICE,
        DEMO_REALM_ID,
        "ck.account_data.set",
        serde_json::json!({
            "key": key,
            "owner": "did:web:alice.example",
            "encrypted_payload": {
                "local_name": "Acme",
                "note": "plaintext remark"
            },
            "updated_at": "2026-06-18T00:01:00Z"
        }),
    )
    .await;

    assert_eq!(
        rejected["error"]["code"], "schema_violation",
        "plaintext realm remark carrier must be rejected: {rejected}"
    );
}

#[tokio::test]
async fn account_data_requires_auth() {
    let event = signed_actor_private_event_envelope(
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-a11ce0000001",
        DEMO_REALM_ID,
        "ck.account_data.set",
        serde_json::json!({
            "key": "ck.contacts.realm.ck:realm:0196419b-0000-7000-8000-000000000000",
            "owner": "did:web:alice.example",
            "body": {"local_name": "x"},
            "updated_at": "2026-05-08T10:00:00Z"
        }),
    );
    let resp = TestClient::post("http://server/_cokret/self/events")
        .json(&event)
        .send(&app())
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 401);
}

fn account_data_entry<'a>(sync: &'a Value, key: &str) -> &'a Value {
    sync["account_data"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["data_type"] == key)
        .expect("account_data entry present in sync response")
}

fn account_data_encrypted_envelope() -> Value {
    serde_json::json!({
        "scheme": "mls-rfc9420",
        "version": "1.0",
        "group_id": "testGroup",
        "epoch": 1,
        "content_type": "application/vnd.cokret.account-data+json",
        "ciphertext": "b3BhcXVl",
        "aad_visibility_event_id": "hidden",
        "aad": {
            "realm_id": DEMO_REALM_ID,
            "event_kind": "ck.account_data.set"
        },
        "key_ref": {
            "algorithm": "MLS",
            "group_state_ref": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
        },
        "aad_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "payload_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    })
}

fn account_data_client_side_marker(hex_pair: &str, ciphertext: &str) -> Value {
    let digest = hex_pair.repeat(32);
    serde_json::json!({
        "client_side_conformance": {
            "encrypted_account_data": true,
            "profile_id": "ck.profile.e2ee_client.v1",
            "plaintext_schema_id": "ck.schema.realm_remark.v1",
            "payload_digest": format!("sha256:{digest}")
        },
        "content_type": "application/vnd.cokret.account-data+json",
        "ciphertext": ciphertext
    })
}
