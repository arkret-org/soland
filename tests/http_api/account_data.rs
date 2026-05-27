//! Integration tests — `account_data` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

#![allow(unused_imports)]
use super::common::*;

#[tokio::test]
async fn account_data_space_remark_round_trip() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        "device-alice-1",
        "Alice",
    )
    .await;
    let bob =
        dev_token_for_device(state.clone(), "did:web:bob.example", "device-bob-1", "Bob").await;

    let space_id = "cx:space:0196419b-0000-7000-8000-000000000000";
    let key = format!("cx.contacts.space.{space_id}");
    let remark = serde_json::json!({
        "version": 1,
        "subject": {"kind": "space", "id": space_id},
        "local_name": "Acme 内部 · 工程",
        "note": "和外包侧 Engineering Space 同名",
        "tags": ["work"],
        "pinned": true,
        "verified_title_at_save": "Engineering",
        "saved_at": "2026-05-08T10:00:00Z"
    });

    // First PUT → 201 Created with the echoed entry.
    let mut put_resp = TestClient::put(format!("http://server/api/v1/account_data/{key}"))
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({"content": remark.clone()}))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(put_resp.status_code.unwrap().as_u16(), 201);
    let body: Value = put_resp.take_json().await.unwrap();
    assert_eq!(body["data_type"], key);
    assert_eq!(body["content"]["local_name"], "Acme 内部 · 工程");

    // GET round-trips the same payload.
    let fetched: Value = TestClient::get(format!("http://server/api/v1/account_data/{key}"))
        .add_header("authorization", format!("Bearer {alice}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(fetched["content"]["pinned"], true);
    assert_eq!(fetched["content"]["tags"][0], "work");

    // Second PUT (update) → 200 OK with the new payload.
    let updated_remark = serde_json::json!({
        "version": 1,
        "subject": {"kind": "space", "id": space_id},
        "local_name": "Acme · Eng (final)",
        "pinned": false,
        "saved_at": "2026-05-08T10:00:00Z",
        "updated_at": "2026-05-09T10:00:00Z"
    });
    let put_again = TestClient::put(format!("http://server/api/v1/account_data/{key}"))
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({"content": updated_remark.clone()}))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(put_again.status_code.unwrap().as_u16(), 200);

    // /sync hydrates the actor's account_data entries.
    let sync_resp_body =
        TestClient::get("http://server/api/v1/account/subscribe?catchup=true&set_presence=online")
            .add_header("authorization", format!("Bearer {alice}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_string()
            .await
            .unwrap();
    let sync_resp: Value = serde_json::from_str(sync_resp_body.lines().next().unwrap()).unwrap();
    let entries = sync_resp["account_data"]["events"].as_array().unwrap();
    let entry = entries
        .iter()
        .find(|e| e["data_type"] == key.as_str())
        .expect("account_data entry present in sync response");
    assert_eq!(entry["content"]["local_name"], "Acme · Eng (final)");
    assert_eq!(entry["content"]["pinned"], false);

    // Actor isolation: Bob's /sync does NOT see Alice's remark.
    let bob_sync_body =
        TestClient::get("http://server/api/v1/account/subscribe?catchup=true&set_presence=online")
            .add_header("authorization", format!("Bearer {bob}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_string()
            .await
            .unwrap();
    let bob_sync: Value = serde_json::from_str(bob_sync_body.lines().next().unwrap()).unwrap();
    let bob_entries = bob_sync["account_data"]["events"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        bob_entries.iter().all(|e| e["data_type"] != key.as_str()),
        "bob must not see alice's account_data"
    );

    // DELETE removes the entry; subsequent GET → 404.
    let del = TestClient::delete(format!("http://server/api/v1/account_data/{key}"))
        .add_header("authorization", format!("Bearer {alice}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(del.status_code.unwrap().as_u16(), 200);
    let not_found = TestClient::get(format!("http://server/api/v1/account_data/{key}"))
        .add_header("authorization", format!("Bearer {alice}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(not_found.status_code.unwrap().as_u16(), 404);
}

#[tokio::test]
async fn account_data_requires_auth() {
    let resp = TestClient::put("http://server/api/v1/account_data/cx.contacts.space.cx:space:0196419b-0000-7000-8000-000000000000")
        .json(&serde_json::json!({"content": {"local_name": "x"}}))
        .send(&app())
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 401);
}
