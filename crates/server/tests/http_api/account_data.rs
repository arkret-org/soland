//! Integration tests — `account_data` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

use super::common::*;

fn canonical_request_body<T: serde::Serialize>(value: &T) -> Vec<u8> {
    arkret_canonical::canonical_json_bytes(value).expect("canonical request body")
}

#[tokio::test]
async fn account_data_accepts_fresh_principal_control_realm() {
    const FRESH_DID: &str = "did:web:fresh-avatar.example";
    const FRESH_DEVICE: &str = "ak:device:01904100-0000-7000-8000-a11ce0000010";
    const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-b0b000000010";

    let state = soland_test_support::app_state(test_config());
    let fresh =
        verified_dev_token_for_device(state.clone(), FRESH_DID, FRESH_DEVICE, "Fresh").await;
    let bob =
        verified_dev_token_for_device(state.clone(), "did:web:bob.example", BOB_DEVICE, "Bob")
            .await;

    let principal_realm = soland_test_support::fixture_principal_control_realm(FRESH_DID);
    assert!(
        principal_realm.starts_with("ak:realm:"),
        "principal realm response: {principal_realm}"
    );

    let plaintext = serde_json::json!({
        "theme": "night",
        "avatar_blob_ref": "ak:blob:sha256:1111111111111111111111111111111111111111111111111111111111111111"
    });
    let body = account_data_encrypted_value(FRESH_DID, "ak.client.ui_state", &plaintext, 1);
    let put = submit_actor_private_event(
        state.clone(),
        &fresh,
        FRESH_DID,
        FRESH_DEVICE,
        &principal_realm,
        arkret_wire::EventKind::AccountDataSet.as_str(),
        serde_json::json!({
            "key": "ak.client.ui_state",
            "expected_revision": 0,
            "owner": FRESH_DID,
            "body": body.clone(),
            "updated_at": "2026-06-08T00:00:00.000Z"
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
    let entry = account_data_entry(&sync, "ak.client.ui_state");
    assert_eq!(entry["payload"]["body"], body);

    let mut denied_event = signed_actor_private_event_envelope(
        "did:web:bob.example",
        BOB_DEVICE,
        &principal_realm,
        arkret_wire::EventKind::AccountDataSet.as_str(),
        serde_json::json!({
            "key": "ak.client.ui_state",
            "expected_revision": 0,
            "owner": "did:web:bob.example",
            "body": account_data_encrypted_value(
                "did:web:bob.example",
                "ak.client.ui_state",
                &serde_json::json!({"theme": "light"}),
                2,
            ),
            "updated_at": "2026-06-08T00:01:00.000Z"
        }),
    );
    denied_event["actor_seq"] = serde_json::json!(0);
    denied_event["prev_refs"] = serde_json::json!([]);
    resign_canonical_event(&mut denied_event);
    let denied: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_request_body(&denied_event))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(denied["error"]["code"], "capability_denied", "{denied}");
}

#[tokio::test]
async fn encrypted_account_data_realm_remark_round_trip() {
    const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-b0b000000001";

    let state = soland_test_support::app_state(test_config());
    let alice = verified_dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        ALICE_DEVICE,
        "Alice",
    )
    .await;
    let bob =
        verified_dev_token_for_device(state.clone(), "did:web:bob.example", BOB_DEVICE, "Bob")
            .await;

    let realm_id = DEMO_REALM_ID;
    let key = format!("ak.contacts.realm.{realm_id}");
    let remark = account_data_encrypted_value(
        "did:web:alice.example",
        &key,
        &serde_json::json!({"local_name": "Realm one"}),
        3,
    );

    let first = submit_actor_private_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        ALICE_DEVICE,
        DEMO_REALM_ID,
        arkret_wire::EventKind::AccountDataSet.as_str(),
        serde_json::json!({
            "key": key.as_str(),
            "expected_revision": 0,
            "owner": "did:web:alice.example",
            "encrypted_payload": remark.clone(),
            "updated_at": "2026-05-08T10:00:00.000Z"
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
    assert_eq!(initial_entry["payload"]["encrypted_payload"], remark);

    // Second event updates the same key with the new payload.
    let updated_remark = account_data_encrypted_value(
        "did:web:alice.example",
        &key,
        &serde_json::json!({"local_name": "Realm two"}),
        4,
    );
    let updated = submit_actor_private_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        ALICE_DEVICE,
        DEMO_REALM_ID,
        arkret_wire::EventKind::AccountDataSet.as_str(),
        serde_json::json!({
            "key": key.as_str(),
            "expected_revision": 1,
            "owner": "did:web:alice.example",
            "encrypted_payload": updated_remark.clone(),
            "updated_at": "2026-05-09T10:00:00.000Z"
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
    assert_eq!(entry["payload"]["encrypted_payload"], updated_remark);

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
        bob_entries
            .iter()
            .all(|entry| entry["payload"]["key"] != key.as_str()),
        "bob must not see alice's account_data"
    );

    let tombstone = submit_actor_private_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        ALICE_DEVICE,
        DEMO_REALM_ID,
        arkret_wire::EventKind::AccountDataSet.as_str(),
        serde_json::json!({
            "key": key.as_str(),
            "expected_revision": 2,
            "owner": "did:web:alice.example",
            "tombstone": true,
            "updated_at": "2026-05-10T10:00:00.000Z"
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
            .all(|entry| entry["payload"]["key"] != key.as_str()),
        "tombstoned account_data must not appear in account subscribe"
    );
}

#[tokio::test]
async fn encrypted_account_data_requires_standard_envelope_metadata() {
    const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-a11ce0000001";

    let state = soland_test_support::app_state(test_config());
    let alice = verified_dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        ALICE_DEVICE,
        "Alice",
    )
    .await;
    let key = "ak.saved.v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    let envelope = account_data_encrypted_value(
        "did:web:alice.example",
        key,
        &serde_json::json!({"private": true}),
        5,
    );

    let accepted = submit_actor_private_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        ALICE_DEVICE,
        DEMO_REALM_ID,
        arkret_wire::EventKind::AccountDataSet.as_str(),
        serde_json::json!({
            "key": key,
            "expected_revision": 0,
            "owner": "did:web:alice.example",
            "encrypted_payload": envelope.clone(),
            "updated_at": "2026-06-18T00:00:00.000Z"
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
    assert_eq!(entry["payload"]["encrypted_payload"], envelope);

    let rejected = submit_actor_private_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        ALICE_DEVICE,
        DEMO_REALM_ID,
        arkret_wire::EventKind::AccountDataSet.as_str(),
        serde_json::json!({
            "key": key,
            "expected_revision": 1,
            "owner": "did:web:alice.example",
            "encrypted_payload": {"ciphertext": "opaque"},
            "updated_at": "2026-06-18T00:01:00.000Z"
        }),
    )
    .await;
    assert_eq!(
        rejected["error"]["code"], "schema_violation",
        "invalid encrypted account_data response: {rejected}"
    );

    let marker_key = "ak.file_transfer.v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let marker = serde_json::json!({
        "client_side_conformance": {
            "encrypted_account_data": true,
            "profile_id": "ak.profile.e2ee_client.v1",
            "plaintext_schema_id": "ak.schema.file_transfer.v1",
            "payload_digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444"
        },
        "content_type": "application/vnd.arkret.account-data+json",
        "ciphertext": "opaque-client-envelope"
    });
    let principal_realm =
        soland_test_support::fixture_principal_control_realm("did:web:alice.example");
    let mut event = signed_actor_private_event_envelope(
        "did:web:alice.example",
        ALICE_DEVICE,
        &principal_realm,
        arkret_wire::EventKind::AccountDataSet.as_str(),
        serde_json::json!({
            "key": marker_key,
            "expected_revision": 0,
            "owner": "did:web:alice.example",
            "body": marker,
            "updated_at": arkret_canonical::format_timestamp_canonical(chrono::Utc::now())
        }),
    );
    move_event_to_actor_realm_frontier(
        &state,
        &alice,
        "did:web:alice.example",
        &principal_realm,
        &mut event,
    )
    .await;
    let request = arkret_models_identity::account::AccountDataReplaceRequestBody {
        set_event: arkret_wire::EventInitialSubmission::online(
            serde_json::from_value(event).expect("signed account_data Event"),
        ),
    };
    let mut response = TestClient::put(format!(
        "http://server/_arkret/self/account_data/{marker_key}"
    ))
    .add_header("authorization", format!("Bearer {alice}"), true)
    .add_header("content-type", "application/json", true)
    .body(canonical_request_body(&request))
    .send(&app_from_state(state.clone()))
    .await;
    let status = response.status_code.unwrap();
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status.as_u16(), 400, "body: {body}");
}

#[tokio::test]
async fn encrypted_realm_remark_rejects_plaintext_carrier() {
    const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-a11ce0000001";

    let state = soland_test_support::app_state(test_config());
    let alice = verified_dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        ALICE_DEVICE,
        "Alice",
    )
    .await;
    let key = format!("ak.contacts.realm.{DEMO_REALM_ID}");

    let rejected = submit_actor_private_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        ALICE_DEVICE,
        DEMO_REALM_ID,
        arkret_wire::EventKind::AccountDataSet.as_str(),
        serde_json::json!({
            "key": key,
            "expected_revision": 0,
            "owner": "did:web:alice.example",
            "encrypted_payload": {
                "local_name": "Acme",
                "note": "plaintext remark"
            },
            "updated_at": "2026-06-18T00:01:00.000Z"
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
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        DEMO_REALM_ID,
        arkret_wire::EventKind::AccountDataSet.as_str(),
        serde_json::json!({
            "key": format!("ak.contacts.realm.{DEMO_REALM_ID}"),
            "expected_revision": 0,
            "owner": "did:web:alice.example",
            "body": {"local_name": "x"},
            "updated_at": "2026-05-08T10:00:00.000Z"
        }),
    );
    let resp = TestClient::post("http://server/_arkret/self/events")
        .add_header("content-type", "application/json", true)
        .body(canonical_request_body(&event))
        .send(&app())
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 401);
}

fn account_data_entry<'a>(sync: &'a Value, key: &str) -> &'a Value {
    sync["account_data"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["payload"]["key"] == key)
        .expect("account_data entry present in sync response")
}

fn account_data_encrypted_value(
    actor_id: &str,
    account_data_key: &str,
    plaintext: &Value,
    nonce_byte: u8,
) -> Value {
    serde_json::to_value(
        arkret_crypto::account_data_crypto::seal_account_data_value_with_nonce(
            &[7u8; 32],
            actor_id,
            account_data_key,
            plaintext,
            [nonce_byte; 24],
        )
        .unwrap(),
    )
    .unwrap()
}
