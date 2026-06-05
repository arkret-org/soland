//! Integration tests — `account_data` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

#![allow(unused_imports)]
use super::common::*;

#[tokio::test]
async fn account_data_realm_remark_round_trip() {
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
    let remark = serde_json::json!({
        "version": 1,
        "subject": {"kind": "realm", "id": realm_id},
        "local_name": "Acme 内部 · 工程",
        "note": "和外包侧 Engineering Realm 同名",
        "tags": ["work"],
        "pinned": true,
        "verified_title_at_save": "Engineering",
        "saved_at": "2026-05-08T10:00:00Z"
    });

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
            "body": remark.clone(),
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
    assert_eq!(initial_entry["content"]["local_name"], "Acme 内部 · 工程");
    assert_eq!(initial_entry["content"]["tags"][0], "work");

    // Second event updates the same key with the new payload.
    let updated_remark = serde_json::json!({
        "version": 1,
        "subject": {"kind": "realm", "id": realm_id},
        "local_name": "Acme · Eng (final)",
        "pinned": false,
        "saved_at": "2026-05-08T10:00:00Z",
        "updated_at": "2026-05-09T10:00:00Z"
    });
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
            "body": updated_remark.clone(),
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
    assert_eq!(entry["content"]["local_name"], "Acme · Eng (final)");
    assert_eq!(entry["content"]["pinned"], false);

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
