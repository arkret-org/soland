//! Integration tests for sodmin-driven admin B-track endpoints.

use soland_storage::BlobRecord;

use super::common::*;

#[tokio::test]
async fn admin_actor_detail_includes_account_lifecycle_linkage() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;

    let alice = fixture_actor_core_id("did:web:alice.example");
    let actor: Value = TestClient::get(format!(
        "http://server/_soland/admin/actors/{}",
        alice.as_str()
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state))
    .await
    .take_json()
    .await
    .unwrap();

    // D14 — detail row is the typed production `AdminActor` projection.
    assert_eq!(actor["id"], alice.as_str());
    assert_eq!(actor["did"], alice.as_str());
    assert!(
        actor["account_id"]
            .as_str()
            .is_some_and(|value| value.starts_with("ak:account:")),
        "actor row must include the durable account row id: {actor}"
    );
    assert!(
        actor["status"].as_str().is_some(),
        "lifecycle status must be answered authoritatively: {actor}"
    );
    assert!(
        actor["is_admin"].is_boolean(),
        "is_admin must be answered authoritatively: {actor}"
    );
}

#[tokio::test]
async fn admin_account_status_aliases_keep_protocol_state_closed() {
    let state = soland_test_support::app_state(test_config());
    let admin = dev_token(state.clone()).await;
    let _bob = register_account(
        state.clone(),
        "did:web:bob.example",
        "@bob",
        "ak:device:01904100-0000-7000-8000-b0b0b0000002",
    )
    .await;
    let bob = fixture_actor_core_id("did:web:bob.example");

    let recovery_locked: Value = TestClient::post(format!(
        "http://server/_soland/admin/accounts/{}/status",
        bob.as_str()
    ))
    .add_header("authorization", format!("Bearer {admin}"), true)
    .json(&serde_json::json!({"status": "recovery_locked"}))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();

    assert_eq!(recovery_locked["state"], "locked");
    assert_eq!(recovery_locked["protocol_state"], "locked");
    assert_eq!(recovery_locked["status"], "recovery_locked");
    assert_eq!(recovery_locked["management_status"], "recovery_locked");
    assert_eq!(recovery_locked["reason"], "recovery_locked");
    assert_eq!(state.account_lifecycle_state(bob.as_str()), "locked");

    let _carol = register_account(
        state.clone(),
        "did:web:carol.example",
        "@carol",
        "ak:device:01904100-0000-7000-8000-ca2010000003",
    )
    .await;
    let carol = fixture_actor_core_id("did:web:carol.example");
    let disabled: Value = TestClient::post(format!(
        "http://server/_soland/admin/accounts/{}/status",
        carol.as_str()
    ))
    .add_header("authorization", format!("Bearer {admin}"), true)
    .json(&serde_json::json!({"status": "disabled"}))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();

    assert_eq!(disabled["state"], "deactivated");
    assert_eq!(disabled["protocol_state"], "deactivated");
    assert_eq!(disabled["status"], "disabled");
    assert_eq!(disabled["management_status"], "disabled");
    assert_eq!(disabled["reason"], "disabled");
    assert_eq!(state.account_lifecycle_state(carol.as_str()), "deactivated");

    let pending = TestClient::post(format!(
        "http://server/_soland/admin/accounts/{}/status",
        bob.as_str()
    ))
    .add_header("authorization", format!("Bearer {admin}"), true)
    .json(&serde_json::json!({"status": "pending_deletion"}))
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(pending.status_code.unwrap().as_u16(), 400);
}

#[tokio::test]
async fn admin_media_statistics_and_by_actor_are_derived_from_blobs() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let now = chrono::Utc::now();
    state
        .test_persistence()
        .blobs()
        .put(
            "ak:blob:test-1",
            &BlobRecord {
                sha256: "sha256-1".to_owned(),
                size_bytes: 128,
                storage_backend: "memory".to_owned(),
                storage_key: "test-1".to_owned(),
                media_type: "image/png".to_owned(),
                filename: Some("one.png".to_owned()),
                realm_id: Some(DEMO_REALM_ID.to_owned()),
                encryption: None,
                legal_hold: false,
                redacted: false,
                visibility: arkret_models_collaboration::objects::blob::BlobVisibility::RealmBound,
                uploaded_by: "did:web:alice.example".to_owned(),
                created_at: now,
            },
        )
        .await
        .unwrap();
    state
        .test_persistence()
        .blobs()
        .put(
            "ak:blob:test-2",
            &BlobRecord {
                sha256: "sha256-2".to_owned(),
                size_bytes: 64,
                storage_backend: "memory".to_owned(),
                storage_key: "test-2".to_owned(),
                media_type: "text/plain".to_owned(),
                filename: Some("two.txt".to_owned()),
                realm_id: Some(DEMO_REALM_ID.to_owned()),
                encryption: Some(serde_json::json!({"encryption_algorithm": "test"})),
                legal_hold: false,
                redacted: false,
                visibility: arkret_models_collaboration::objects::blob::BlobVisibility::RealmBound,
                uploaded_by: "did:web:alice.example".to_owned(),
                created_at: now,
            },
        )
        .await
        .unwrap();

    let stats: Value = TestClient::get("http://server/_soland/admin/media/statistics")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(stats["total_blobs"], 2);
    assert_eq!(stats["total_size"], 192);
    assert_eq!(stats["encrypted_count"], 1);
    assert_eq!(stats["by_media_type"]["image/png"]["count"], 1);
    assert_eq!(stats["by_realm"][DEMO_REALM_ID]["total_size"], 192);

    let by_actor: Value = TestClient::get("http://server/_soland/admin/media/by-actor")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    let row = by_actor["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["actor_id"] == "did:web:alice.example")
        .expect("alice media row");
    assert_eq!(row["blob_count"], 2);
    assert_eq!(row["total_size"], 192);
}
