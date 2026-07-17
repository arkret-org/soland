//! Integration tests for sodmin-driven admin B-track endpoints.

use soland_storage::BlobRecord;

use super::common::*;

#[tokio::test]
async fn admin_actor_detail_includes_account_lifecycle_linkage() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let actor: Value = TestClient::get("http://server/_soland/admin/actors/did:web:alice.example")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();

    // D14 — detail row is the typed production `AdminActor` projection.
    assert_eq!(actor["id"], "did:web:alice.example");
    assert_eq!(actor["did"], "did:web:alice.example");
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
    let state = AppState::new(test_config(), Db { pool: None });
    let admin = dev_token(state.clone()).await;
    let _bob = register_account(
        state.clone(),
        "did:web:bob.example",
        "@bob",
        "ak:device:01904100-0000-7000-8000-b0b0b0000002",
    )
    .await;

    let recovery_locked: Value =
        TestClient::post("http://server/_soland/admin/accounts/did:web:bob.example/status")
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
    assert_eq!(
        state.account_lifecycle_state("did:web:bob.example"),
        "locked"
    );

    let _carol = register_account(
        state.clone(),
        "did:web:carol.example",
        "@carol",
        "ak:device:01904100-0000-7000-8000-ca2010000003",
    )
    .await;
    let disabled: Value =
        TestClient::post("http://server/_soland/admin/accounts/did:web:carol.example/status")
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
    assert_eq!(
        state.account_lifecycle_state("did:web:carol.example"),
        "deactivated"
    );

    let pending =
        TestClient::post("http://server/_soland/admin/accounts/did:web:bob.example/status")
            .add_header("authorization", format!("Bearer {admin}"), true)
            .json(&serde_json::json!({"status": "pending_deletion"}))
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(pending.status_code.unwrap().as_u16(), 400);
}

#[tokio::test]
async fn admin_invite_token_create_and_revoke_round_trip() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let created: Value = TestClient::post("http://server/_soland/admin/invite-tokens")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "uses_allowed": 1,
            "expires_at": "2030-01-01T00:00:00Z"
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let invite_id = created["id"].as_str().expect("invite id").to_owned();
    assert!(invite_id.starts_with("ak:invite:"));
    assert_eq!(created["invite_id"], invite_id);
    assert_eq!(created["realm_id"], DEMO_REALM_ID);
    assert_eq!(created["status"], "pending");
    assert!(
        created["token"]
            .as_str()
            .is_some_and(|value| value.starts_with("ak:invite-token:")),
        "create response must include the plaintext token once: {created}"
    );

    let revoked: Value = TestClient::delete(format!(
        "http://server/_soland/admin/invite-tokens/{invite_id}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(revoked["id"], invite_id);
    assert_eq!(revoked["status"], "revoked");

    let list: Value = TestClient::get("http://server/_soland/admin/invite-tokens")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    let row = list["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == invite_id)
        .expect("revoked invite remains in admin snapshot");
    assert_eq!(row["status"], "revoked");
}

#[tokio::test]
async fn admin_media_statistics_and_by_actor_are_derived_from_blobs() {
    let state = AppState::new(test_config(), Db { pool: None });
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
                visibility: arkret_sdk::BlobVisibility::RealmBound,
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
                encryption: Some(serde_json::json!({"alg": "test"})),
                legal_hold: false,
                redacted: false,
                visibility: arkret_sdk::BlobVisibility::RealmBound,
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
    assert_eq!(stats["by_realm"][DEMO_REALM_ID]["size_bytes"], 192);

    let by_actor: Value = TestClient::get("http://server/_soland/admin/media/by-actor")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    let row = by_actor["actors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["actor_id"] == "did:web:alice.example")
        .expect("alice media row");
    assert_eq!(row["blob_count"], 2);
    assert_eq!(row["total_size"], 192);
}
