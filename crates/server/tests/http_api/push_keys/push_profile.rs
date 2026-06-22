//! Integration tests — `push_keys` domain: push / profile / blob / presence /
//! call-signal contracts.

#![allow(unused_imports)]
use super::helpers::*;
use crate::common::*;

#[tokio::test]
async fn file_transfer_blob_upload_uses_encrypted_metadata_and_blocks_presign() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let file_transfer_bytes = b"file-transfer-ciphertext";
    let file_transfer_digest = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(file_transfer_bytes))
    );
    let raw_upload = TestClient::post("http://server/_cokret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/octet-stream", true)
        .body(file_transfer_bytes.as_slice())
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(raw_upload.status_code.unwrap().as_u16(), 400);

    let (file_transfer_content_type, file_transfer_body) =
        multipart_blob_upload_body(file_transfer_bytes, "text/plain");
    let file_transfer_blob: Value = TestClient::post("http://server/_cokret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", file_transfer_content_type, true)
        .add_header("x-cokret-filename", "private.txt", true)
        .add_header("x-cokret-blob-encrypted", "true", true)
        .add_header("x-cokret-blob-purpose", "file_transfer", true)
        .add_header(
            "x-cokret-content-digest",
            file_transfer_digest.clone(),
            true,
        )
        .body(file_transfer_body)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(file_transfer_blob["media_type"], "application/octet-stream");
    assert_eq!(file_transfer_blob["content_digest"], file_transfer_digest);
    assert!(
        file_transfer_blob["upload_receipt"]
            .get("filename")
            .is_none()
    );
    assert!(
        file_transfer_blob["upload_receipt"]
            .get("purpose")
            .is_none()
    );
    assert_eq!(
        file_transfer_blob["upload_receipt"]["content_digest"],
        file_transfer_digest
    );
    assert!(
        file_transfer_blob["upload_receipt"]
            .get("encrypted_attachment")
            .is_none()
    );
    let stored_file_transfer_blob = state
        .persistence
        .blobs()
        .get(file_transfer_blob["blob_ref"].as_str().unwrap())
        .await
        .unwrap()
        .expect("uploaded file-transfer blob metadata is stored");
    let encrypted_attachment = stored_file_transfer_blob
        .encryption
        .as_ref()
        .expect("file-transfer encrypted metadata is persisted");
    assert_eq!(
        encrypted_attachment["scheme"],
        "ck.file_transfer.encrypted_blob.v1"
    );

    let file_transfer_presign = TestClient::post("http://server/_cokret/self/blob/presign")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "blob_ref": file_transfer_blob["blob_ref"].as_str().unwrap(),
            "purpose": "file_transfer"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(file_transfer_presign.status_code.unwrap().as_u16(), 403);
}

#[tokio::test]
async fn profile_avatar_get_recovers_existing_local_object_without_metadata() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let avatar_bytes = b"\x89PNG\r\n\x1a\navatar-bytes".to_vec();
    let avatar_sha256 = hex::encode(Sha256::digest(&avatar_bytes));
    let blob_ref = format!("ck:blob:sha256:{avatar_sha256}");
    let storage_key = state.object_storage.object_key_for_sha256(&avatar_sha256);
    state
        .object_storage
        .put(&storage_key, avatar_bytes.clone())
        .await
        .unwrap();
    assert!(
        state
            .persistence
            .blobs()
            .get(&blob_ref)
            .await
            .unwrap()
            .is_none()
    );

    let mut response = TestClient::get(format!(
        "http://server/_cokret/self/blob/get?blob_ref={blob_ref}&purpose=profile_avatar"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(response.status_code.unwrap().as_u16(), 200);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "image/png"
    );
    assert_eq!(
        response.take_bytes(None).await.unwrap().to_vec(),
        avatar_bytes
    );

    let recovered = state
        .persistence
        .blobs()
        .get(&blob_ref)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.sha256, avatar_sha256);
    assert_eq!(recovered.storage_key, storage_key);
    assert_eq!(recovered.media_type, "image/png");
    assert_eq!(recovered.realm_id, None);
}

#[tokio::test]
async fn push_profile_and_moderation_contracts_work() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let sent_at = chrono::Utc::now();
    let expires_at = sent_at + chrono::Duration::seconds(30);
    let unauth_presence = TestClient::post("http://server/_cokret/self/ephemeral")
        .json(&serde_json::json!({
            "kind": "ck.presence",
            "realm_id": DEMO_REALM_ID,
            "actor_id": "did:web:alice.example",
            "sent_at": sent_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "expires_at": expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "payload": {
                "status": "online"
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauth_presence.status_code, Some(StatusCode::UNAUTHORIZED));

    let presence: Value = TestClient::post("http://server/_cokret/self/ephemeral")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "kind": "ck.presence",
            "realm_id": DEMO_REALM_ID,
            "actor_id": "did:web:alice.example",
            "sent_at": sent_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "expires_at": expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "payload": {
                "status": "unavailable"
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(presence["accepted"], true);
    assert_eq!(presence["kind"], "ck.presence");

    let presence_sync = account_subscribe_frame(state.clone(), Some(&token), "catchup=true").await;
    let profile = presence_event(&presence_sync, "did:web:alice.example");
    assert_eq!(profile["actor_id"], "did:web:alice.example");
    assert_eq!(profile["status"], "unavailable");

    state
        .persistence
        .presence()
        .put(PresenceRecord {
            actor: "did:web:alice.example".to_owned(),
            status: "online".to_owned(),
            updated_at: chrono::Utc::now() - chrono::Duration::seconds(10),
        })
        .await
        .unwrap();
    let stale_sync = account_subscribe_frame(state.clone(), Some(&token), "catchup=true").await;
    let stale_profile = presence_event(&stale_sync, "did:web:alice.example");
    assert_eq!(stale_profile["status"], "offline");
    let last_active_at = stale_profile["last_active_at"]
        .as_str()
        .expect("stale presence emits bucketed last_active_at");
    assert!(last_active_at.ends_with("/PT1H"));
    assert!(stale_profile.get("last_active").is_none());

    let unauth_typing = TestClient::post("http://server/_cokret/self/ephemeral")
        .json(&serde_json::json!({
            "kind": "ck.typing",
            "realm_id": DEMO_REALM_ID,
            "actor_id": "did:web:alice.example",
            "sent_at": sent_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "expires_at": expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "payload": {
                "typing": true
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauth_typing.status_code, Some(StatusCode::UNAUTHORIZED));

    let typing: Value = TestClient::post("http://server/_cokret/self/ephemeral")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "kind": "ck.typing",
            "realm_id": DEMO_REALM_ID,
            "actor_id": "did:web:alice.example",
            "sent_at": sent_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "expires_at": expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "payload": {
                "typing": true
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(typing["accepted"], true);
    assert_eq!(typing["kind"], "ck.typing");

    let active_typing = state
        .persistence
        .typing()
        .list_for_realm(DEMO_REALM_ID)
        .await
        .unwrap();
    assert_eq!(active_typing.len(), 1);
    assert_eq!(active_typing[0].actor, "did:web:alice.example");
    assert_eq!(active_typing[0].scope_id.as_deref(), None);

    let stop_sent_at = chrono::Utc::now();
    let stop_expires_at = stop_sent_at + chrono::Duration::seconds(30);
    let typing_stopped: Value = TestClient::post("http://server/_cokret/self/ephemeral")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "kind": "ck.typing",
            "realm_id": DEMO_REALM_ID,
            "actor_id": "did:web:alice.example",
            "sent_at": stop_sent_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "expires_at": stop_expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "payload": {
                "typing": false
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(typing_stopped["accepted"], true);

    let cleared_typing = state
        .persistence
        .typing()
        .list_for_realm(DEMO_REALM_ID)
        .await
        .unwrap();
    assert!(cleared_typing.is_empty());

    let push: Value = TestClient::post("http://server/_cokret/edge/push/register-device")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "push_gateway": "https://push.example",
            "push_key": "opaque",
            "platform": "desktop",
            "app_id": "yougen"
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(push["ok"], true);

    let initial_rules = account_subscribe_frame(state.clone(), Some(&token), "catchup=true").await;
    assert!(
        account_data_entry(&initial_rules, "ck.push_rules").is_none(),
        "initial account_data must not include ck.push_rules: {initial_rules}"
    );

    let plaintext_push_rule = submit_actor_private_event(
        state.clone(),
        &token,
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-a11ce0000001",
        DEMO_REALM_ID,
        "ck.account_data.set",
        serde_json::json!({
            "key": "ck.push_rules",
            "owner": "did:web:alice.example",
            "body": {
                "rules": [{
                    "rule_id": "mute-device",
                    "enabled": true,
                    "actions": ["dont_notify"],
                    "conditions": {
                        "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
                        "wakeup_kind": "message"
                    }
                }]
            },
            "updated_at": "2026-05-08T10:00:00Z"
        }),
    )
    .await;
    assert_ne!(
        plaintext_push_rule["status"], "accepted",
        "ck.push_rules account_data must not accept plaintext content: {plaintext_push_rule}"
    );

    let listed_rules = account_subscribe_frame(state.clone(), Some(&token), "catchup=true").await;
    assert!(
        account_data_entry(&listed_rules, "ck.push_rules").is_none(),
        "rejected plaintext push rules must not appear as account_data: {listed_rules}"
    );

    let notify_after_rejected_rule: Value = TestClient::post("http://server/_cokret/edge/push/notify")
        .json(&serde_json::json!({
            "notification": {
                "push_target_id": "ck:push_target:01904100-0000-7000-8000-000000000001",
                "wakeup_kind": "message",
                "devices": [{"device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001"}, {"device_id": "ck:device:01904100-0000-7000-8000-71551c000004"}]
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let rejected = notify_after_rejected_rule["rejected"].as_array().unwrap();
    assert_eq!(rejected.len(), 1);
    assert!(rejected.iter().any(|device| {
        device["device_id"] == "ck:device:01904100-0000-7000-8000-71551c000004"
            && device["reason"] == "unknown_device"
    }));

    let report: Value = TestClient::post("http://server/_cokret/self/moderation/report")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "target_ref": "ck:event:01904100-0000-7000-8000-4a4116cba4e8",
            "report_reason_code": "spam",
            "reporter": "did:web:alice.example"
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(report["status"], "submitted");
    assert!(
        state
            .persistence
            .audit()
            .snapshot_all()
            .await
            .unwrap()
            .iter()
            .any(|entry| {
                entry["action"] == "moderation.report" && entry["outcome"] == "submitted"
            })
    );
    assert!(
        state
            .persistence
            .moderation()
            .list_actions()
            .await
            .unwrap()
            .iter()
            .any(|action| action["report_id"] == report["report_id"] && action["status"] == "open")
    );

    let unauthenticated_report = TestClient::post("http://server/_cokret/self/moderation/report")
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "target_ref": "ck:event:01904100-0000-7000-8000-4a4116cba4e8",
            "report_reason_code": "spam",
            "reporter": "did:web:alice.example"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthenticated_report.status_code.unwrap().as_u16(), 401);
}

#[tokio::test]
async fn presence_visibility_account_data_requires_encrypted_content() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let plaintext_policy =
        TestClient::put("http://server/_cokret/self/account_data/ck.presence.visibility")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&serde_json::json!({
                "content": {
                    "presence_visibility": "nobody"
                }
            }))
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(plaintext_policy.status_code.unwrap().as_u16(), 400);

    state
        .persistence
        .presence()
        .put(PresenceRecord {
            actor: "did:web:alice.example".to_owned(),
            status: "online".to_owned(),
            updated_at: chrono::Utc::now(),
        })
        .await
        .unwrap();

    let visible_sync = account_subscribe_frame(state.clone(), Some(&token), "catchup=true").await;
    assert!(
        visible_sync["presence"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["actor_id"] == "did:web:alice.example"),
        "encrypted presence account_data must not be parsed as plaintext relay policy: {visible_sync}"
    );

    let sent_at = chrono::Utc::now();
    let expires_at = sent_at + chrono::Duration::seconds(30);
    let presence: Value = TestClient::post("http://server/_cokret/self/ephemeral")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "kind": "ck.presence",
            "realm_id": DEMO_REALM_ID,
            "actor_id": "did:web:alice.example",
            "sent_at": sent_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "expires_at": expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "payload": {
                "status": "online"
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(presence["accepted"], true);
    assert!(
        state
            .persistence
            .presence()
            .get("did:web:alice.example")
            .await
            .unwrap()
            .is_some(),
        "encrypted presence preferences must not clear server-visible presence"
    );

    let typing: Value = TestClient::post("http://server/_cokret/self/ephemeral")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "kind": "ck.typing",
            "realm_id": DEMO_REALM_ID,
            "actor_id": "did:web:alice.example",
            "sent_at": sent_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "expires_at": expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "payload": {
                "typing": true
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(typing["accepted"], true);
    let typing_records = state
        .persistence
        .typing()
        .list_for_realm(DEMO_REALM_ID)
        .await
        .unwrap();
    assert!(
        !typing_records.is_empty(),
        "encrypted presence preferences must not suppress server-visible typing"
    );

    state
        .persistence
        .account_data()
        .put(&soland::state::AccountDataRecord {
            actor: "did:web:alice.example".to_owned(),
            data_type: "ck.presence.visibility".to_owned(),
            payload: serde_json::json!({
                "encrypted_payload": {
                    "ciphertext": "opaque-presence-policy"
                }
            }),
            updated_at: chrono::Utc::now(),
        })
        .await
        .unwrap();

    let hidden_sync = account_subscribe_frame(state.clone(), Some(&token), "catchup=true").await;
    assert!(
        hidden_sync["presence"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|event| event["actor_id"] != "did:web:alice.example"),
        "opaque presence policy must fail closed for cached presence: {hidden_sync}"
    );

    let opaque_sent_at = chrono::Utc::now();
    let opaque_expires_at = opaque_sent_at + chrono::Duration::seconds(30);
    let hidden_presence: Value = TestClient::post("http://server/_cokret/self/ephemeral")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "kind": "ck.presence",
            "realm_id": DEMO_REALM_ID,
            "actor_id": "did:web:alice.example",
            "sent_at": opaque_sent_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "expires_at": opaque_expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "payload": {
                "status": "online"
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(hidden_presence["accepted"], true);
    assert!(
        state
            .persistence
            .presence()
            .get("did:web:alice.example")
            .await
            .unwrap()
            .is_none(),
        "opaque presence policy must clear server-visible presence"
    );

    let hidden_typing: Value = TestClient::post("http://server/_cokret/self/ephemeral")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "kind": "ck.typing",
            "realm_id": DEMO_REALM_ID,
            "actor_id": "did:web:alice.example",
            "sent_at": opaque_sent_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "expires_at": opaque_expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "payload": {
                "typing": true
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(hidden_typing["accepted"], true);
    let hidden_typing_records = state
        .persistence
        .typing()
        .list_for_realm(DEMO_REALM_ID)
        .await
        .unwrap();
    assert!(
        hidden_typing_records.is_empty(),
        "opaque presence policy must suppress server-visible typing"
    );
}

#[tokio::test]
async fn typing_submit_rejects_unknown_strand_scope() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let sent_at = chrono::Utc::now();
    let expires_at = sent_at + chrono::Duration::seconds(30);

    let rejected_typing = TestClient::post("http://server/_cokret/self/ephemeral")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "kind": "ck.typing",
            "realm_id": DEMO_REALM_ID,
            "actor_id": "did:web:alice.example",
            "sent_at": sent_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "expires_at": expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "payload": {
                "scope_id": new_prefixed_uuid7("ck:strand:"),
                "typing": true
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(rejected_typing.status_code, Some(StatusCode::FORBIDDEN));
    let typing_after_reject = state
        .persistence
        .typing()
        .list_for_realm(DEMO_REALM_ID)
        .await
        .unwrap();
    assert!(typing_after_reject.is_empty());
}

#[tokio::test]
async fn typing_submit_rejects_disabled_discussion_strand_scope() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let strand_id = "ck:strand:01904100-0000-7000-8000-7a1c00000001";
    insert_typing_scope_strand(state.clone(), strand_id, Some(false));
    let sent_at = chrono::Utc::now();
    let expires_at = sent_at + chrono::Duration::seconds(30);

    let rejected_typing = TestClient::post("http://server/_cokret/self/ephemeral")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "kind": "ck.typing",
            "realm_id": DEMO_REALM_ID,
            "actor_id": "did:web:alice.example",
            "sent_at": sent_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "expires_at": expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "payload": {
                "scope_id": strand_id,
                "typing": true
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(rejected_typing.status_code, Some(StatusCode::FORBIDDEN));
    let typing_after_reject = state
        .persistence
        .typing()
        .list_for_realm(DEMO_REALM_ID)
        .await
        .unwrap();
    assert!(typing_after_reject.is_empty());
}

#[tokio::test]
async fn public_read_receipt_rejected_for_world_readable_realm_without_opt_in() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let now = chrono::Utc::now();
    state
        .persistence
        .realm_meta()
        .put(
            DEMO_REALM_ID,
            &RealmMetaRecord {
                owner: "did:web:alice.example".to_owned(),
                deleted: false,
                discoverability: "public".to_owned(),
                history_visibility: "world_readable".to_owned(),
                history_sharing_policy: None,
                history_sharing_policy_digest: None,
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: Some("none".to_owned()),
                plaintext_visible_services: Default::default(),
                plaintext_visible_service_classes: Default::default(),
                minimal_metadata_realm: false,
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .unwrap();

    let policy = submit_actor_private_event(
        state.clone(),
        &token,
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-a11ce0000001",
        DEMO_REALM_ID,
        "ck.realm.read_receipt_policy",
        serde_json::json!({
            "disclosure": "optional",
            "visibility": "public",
            "scope_overrides_allowed": true
        }),
    )
    .await;
    assert!(
        policy["status"] == "accepted"
            || policy["accepted"]
                .as_array()
                .is_some_and(|events| !events.is_empty()),
        "read receipt policy event: {policy}"
    );

    let sent_at = chrono::Utc::now();
    let expires_at = sent_at + chrono::Duration::seconds(30);
    let receipt = TestClient::post("http://server/_cokret/self/ephemeral")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "kind": "ck.receipt.read",
            "realm_id": DEMO_REALM_ID,
            "actor_id": "did:web:alice.example",
            "sent_at": sent_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "expires_at": expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "payload": {
                "event_id": new_prefixed_uuid7("ck:event:")
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(receipt.status_code, Some(StatusCode::FORBIDDEN));
}

#[tokio::test]
async fn typing_fanout_respects_receiver_blocklist() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice_token = dev_token(state.clone()).await;
    add_test_realm_member(&state, DEMO_REALM_ID, "did:web:bob.example");
    let bob_token = dev_token_for_device(
        state.clone(),
        "did:web:bob.example",
        "ck:device:01904100-0000-7000-8000-b0b000000001",
        "Bob Desktop",
    )
    .await;
    let bob_blocklist = submit_actor_private_event(
        state.clone(),
        &bob_token,
        "did:web:bob.example",
        "ck:device:01904100-0000-7000-8000-b0b000000001",
        DEMO_REALM_ID,
        "ck.account_data.set",
        serde_json::json!({
            "key": "ck.account.blocklist",
            "owner": "did:web:bob.example",
            "body": {
                "client_side_conformance": {
                    "encrypted_account_data": true,
                    "profile_id": "ck.profile.e2ee_client.v1",
                    "payload_digest": "sha256:abababababababababababababababababababababababababababababababab"
                },
                "content_type": "application/vnd.cokret.account-data+json",
                "ciphertext": "opaque-bob-blocklist"
            },
            "updated_at": "2026-05-21T00:00:00Z",
        }),
    )
    .await;
    assert_eq!(
        bob_blocklist["status"], "accepted",
        "blocklist event: {bob_blocklist}"
    );

    let sent_at = chrono::Utc::now();
    let expires_at = sent_at + chrono::Duration::seconds(30);
    let typing: Value = TestClient::post("http://server/_cokret/self/ephemeral")
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .json(&serde_json::json!({
            "kind": "ck.typing",
            "realm_id": DEMO_REALM_ID,
            "actor_id": "did:web:alice.example",
            "sent_at": sent_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "expires_at": expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "payload": {
                "typing": true
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(typing["accepted"], true);

    let bob_sync = account_subscribe_frame(state.clone(), Some(&bob_token), "catchup=true").await;
    let bob_ephemeral = bob_sync["realms"][DEMO_REALM_ID]["ephemeral"]
        .as_array()
        .expect("demo realm ephemeral segment");
    assert!(
        bob_ephemeral.iter().all(|entry| {
            entry["type"] != "ck.typing"
                || entry["actors"].as_array().is_none_or(|actors| {
                    actors
                        .iter()
                        .all(|actor| actor["actor"] != "did:web:alice.example")
                })
        }),
        "Bob's blocklist must suppress Alice typing fanout: {bob_ephemeral:?}"
    );
}

#[tokio::test]
async fn typing_fanout_hides_cached_record_when_discussion_track_disabled() {
    let state = AppState::new(test_config(), Db { pool: None });
    add_test_realm_member(&state, DEMO_REALM_ID, "did:web:bob.example");
    let bob_token = dev_token_for_device(
        state.clone(),
        "did:web:bob.example",
        "ck:device:01904100-0000-7000-8000-b0b000000002",
        "Bob Desktop",
    )
    .await;
    let strand_id = "ck:strand:01904100-0000-7000-8000-7a1c00000002";
    insert_typing_scope_strand(state.clone(), strand_id, Some(false));
    let now = chrono::Utc::now();
    state
        .persistence
        .typing()
        .put(soland::state::TypingRecord {
            actor: "did:web:alice.example".to_owned(),
            realm_id: DEMO_REALM_ID.to_owned(),
            scope_id: Some(strand_id.to_owned()),
            expires_at: now + chrono::Duration::seconds(30),
            updated_at: now,
        })
        .await
        .unwrap();

    let bob_sync = account_subscribe_frame(state.clone(), Some(&bob_token), "catchup=true").await;
    let bob_ephemeral = bob_sync["realms"][DEMO_REALM_ID]["ephemeral"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        bob_ephemeral.iter().all(|entry| {
            entry["type"] != "ck.typing"
                || entry["actors"].as_array().is_none_or(|actors| {
                    actors
                        .iter()
                        .all(|actor| actor["actor"] != "did:web:alice.example")
                })
        }),
        "disabled discussion track must suppress cached typing fanout: {bob_ephemeral:?}"
    );
}

fn insert_typing_scope_strand(state: AppState, strand_id: &str, discussion_enabled: Option<bool>) {
    let now = chrono::Utc::now();
    state
        .projection
        .lock()
        .expect("projection mutex")
        .strands
        .insert(
            strand_id.to_owned(),
            soland::reducer::StrandProjection {
                strand_id: strand_id.to_owned(),
                realm_id: DEMO_REALM_ID.to_owned(),
                tracks: std::collections::BTreeMap::from([(
                    cokret_sdk::STRAND_TRACK_NAME_DISCUSSION.to_owned(),
                    cokret_sdk::StrandTrackConfig {
                        enabled: discussion_enabled,
                        is_primary: Some(true),
                        profile: Some("discussion".to_owned()),
                        ..Default::default()
                    },
                )]),
                title: "Typing scope".to_owned(),
                summary: None,
                fields: Default::default(),
                state: soland::reducer::ObjectLifecycleState::Active,
                state_changed_at: None,
                created_by: "did:web:alice.example".to_owned(),
                created_at: now,
                history_basis_seals: Vec::new(),
                updated_by: None,
                updated_at: None,
                scope_circle_id: None,
            },
        );
}

#[tokio::test]
async fn ephemeral_call_signal_enforces_structural_contract() {
    // `webrtc-signaling.md` §5 — the /ephemeral relay structurally validates
    // ck.call.signal envelopes (device_id + proof present, payload
    // {call_id, signal_type, seq} with a canonical signal_type incl.
    // moderation). It does NOT cryptographically verify the proof (receiver's
    // job).
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    state.authz.create_grant(
        DEMO_REALM_ID.to_owned(),
        "did:web:alice.example".to_owned(),
        "did:web:alice.example".to_owned(),
        DEMO_REALM_ID.to_owned(),
        vec![cokret_sdk::CAP_CALL_SIGNAL_SEND.to_owned()],
        vec![],
    );
    let call_id = "ck:call:01904100-0000-7000-8000-ca110000001a";
    let device_id = "ck:device:01904100-0000-7000-8000-a11ce0000001";

    let post_signal = |state: AppState, bearer: String, body: Value| async move {
        TestClient::post("http://server/_cokret/self/ephemeral")
            .add_header("authorization", format!("Bearer {bearer}"), true)
            .json(&body)
            .send(&app_from_state(state))
            .await
    };

    let envelope = |signal_type: &str, with_device: bool, with_proof: bool| {
        let sent_at = chrono::Utc::now();
        let expires_at = sent_at + chrono::Duration::seconds(30);
        let mut env = serde_json::json!({
            "kind": "ck.call.signal",
            "realm_id": DEMO_REALM_ID,
            "actor_id": "did:web:alice.example",
            "sent_at": sent_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "expires_at": expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "payload": {
                "call_id": call_id,
                "signal_type": signal_type,
                "seq": 1
            }
        });
        if with_device {
            env["device_id"] = serde_json::json!(device_id);
        }
        if with_proof {
            let canonical = cokret_sdk::canonical::canonical_json_bytes(&env).unwrap();
            let event_digest = cokret_sdk::canonical::sha256_digest(&canonical);
            env["proof"] = serde_json::json!({
                "kind": "detached_jws",
                "alg": "EdDSA",
                "verification_method": "did:web:alice.example#device",
                "event_digest": event_digest,
                "created_at": sent_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                "jws": "eyJhbGciOiJFZERTQSJ9..c2ln"
            });
        }
        env
    };

    // Legal moderation signal with device_id + proof → accepted.
    let accepted: Value = post_signal(
        state.clone(),
        token.clone(),
        envelope("moderation", true, true),
    )
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(accepted["accepted"], true, "accepted body: {accepted}");
    assert_eq!(accepted["kind"], "ck.call.signal");

    // Non-canonical signal_type → invalid_param.
    let mut bad_type = post_signal(
        state.clone(),
        token.clone(),
        envelope("not_a_signal", true, true),
    )
    .await;
    assert_eq!(bad_type.status_code.unwrap().as_u16(), 400);
    let bad_type_body: Value = bad_type.take_json().await.unwrap();
    assert_eq!(bad_type_body["error"]["code"], "invalid_param");

    // Missing device_id → invalid_param.
    let mut no_device = post_signal(
        state.clone(),
        token.clone(),
        envelope("invite", false, true),
    )
    .await;
    assert_eq!(no_device.status_code.unwrap().as_u16(), 400);
    let no_device_body: Value = no_device.take_json().await.unwrap();
    assert_eq!(no_device_body["error"]["code"], "invalid_param");

    // Missing proof → invalid_param.
    let mut no_proof = post_signal(state.clone(), token, envelope("invite", true, false)).await;
    assert_eq!(no_proof.status_code.unwrap().as_u16(), 400);
    let no_proof_body: Value = no_proof.take_json().await.unwrap();
    assert_eq!(no_proof_body["error"]["code"], "invalid_param");
}

#[tokio::test]
async fn push_unregister_mutates_registration_and_gateway_snapshot_gates_notify() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let service = app_from_state(state.clone());
    let device_id = "ck:device:01904100-0000-7000-8000-a11ce0000001";
    let push_gateway = "https://push.example/_cokret/edge/push/notify";
    let bridge_describe = "https://push.example/_floria/push/bridge/describe";
    let stale_at = chrono::Utc::now() - chrono::Duration::hours(25);

    let stale_import: Value = TestClient::post(
        "http://server/_soland/edge/push/outbound/bridge/cache/import",
    )
    .json(&serde_json::json!({
        "replace_existing": true,
        "entries": [{
            "push_gateway_url": push_gateway,
            "service_base_url": "https://push.example",
            "bridge_describe_url": bridge_describe,
            "fetch_state": "cotest_seed",
            "cache_state": "imported_replace_existing",
            "contract_digest": "sha256:stale",
            "fetched_at": stale_at,
            "remote_contract": {
                "contract": "ck.push.bridge.describe",
                "service_did": "did:web:push.example",
                "delivery": {"notify_path": "/_cokret/edge/push/notify", "operation_id": "ck.edge.push.command.notify"}
            },
            "trust_level": "trusted",
            "freshness_at": stale_at,
            "etag": "stale"
        }]
    }))
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(stale_import["imported_count"], 1);

    let registered: Value = TestClient::post("http://server/_cokret/edge/push/register-device")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "device_id": device_id,
            "push_gateway": push_gateway,
            "push_key": "opaque-token",
            "platform": "desktop",
            "app_id": "yougen"
        }))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(registered["ok"], true);

    let stale_notify: Value = TestClient::post("http://server/_cokret/edge/push/notify")
        .json(&serde_json::json!({
            "notification": {
                "push_target_id": "ck:push_target:01904100-0000-7000-8000-000000000003",
                "wakeup_kind": "message",
                "devices": [{"device_id": device_id}]
            }
        }))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(stale_notify["rejected"][0]["reason"], "contract_drift");
    assert_eq!(stale_notify["rejected"][0]["drift_result"], "stale");

    let now = chrono::Utc::now();
    let fresh_import: Value = TestClient::post(
        "http://server/_soland/edge/push/outbound/bridge/cache/import",
    )
    .json(&serde_json::json!({
        "replace_existing": true,
        "entries": [{
            "push_gateway_url": push_gateway,
            "service_base_url": "https://push.example",
            "bridge_describe_url": bridge_describe,
            "fetch_state": "cotest_seed",
            "cache_state": "imported_replace_existing",
            "contract_digest": "sha256:fresh",
            "fetched_at": now,
            "remote_contract": {
                "contract": "ck.push.bridge.describe",
                "service_did": "did:web:push.example",
                "delivery": {"notify_path": "/_cokret/edge/push/notify", "operation_id": "ck.edge.push.command.notify"}
            },
            "trust_level": "trusted",
            "freshness_at": now,
            "etag": "fresh"
        }]
    }))
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(fresh_import["total_entries"], 1);

    let fresh_notify: Value = TestClient::post("http://server/_cokret/edge/push/notify")
        .json(&serde_json::json!({
            "notification": {
                "push_target_id": "ck:push_target:01904100-0000-7000-8000-000000000004",
                "wakeup_kind": "message",
                "devices": [{"device_id": device_id}]
            }
        }))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert!(fresh_notify["rejected"].as_array().unwrap().is_empty());

    let unregistered: Value = TestClient::post("http://server/_cokret/edge/push/unregister-device")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "device_id": device_id,
            "push_key": "opaque-token",
            "app_id": "yougen"
        }))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(unregistered["ok"], true);

    let after_unregister: Value = TestClient::post("http://server/_cokret/edge/push/notify")
        .json(&serde_json::json!({
            "notification": {
                "push_target_id": "ck:push_target:01904100-0000-7000-8000-000000000005",
                "wakeup_kind": "message",
                "devices": [{"device_id": device_id}]
            }
        }))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(after_unregister["rejected"][0]["reason"], "unknown_device");
}
