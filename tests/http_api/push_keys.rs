//! Integration tests — `push_keys` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

#![allow(unused_imports)]
use super::common::*;

fn presence_event<'a>(sync: &'a Value, actor: &str) -> &'a Value {
    sync["presence"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["actor_id"] == actor || event["user_id"] == actor)
        .expect("presence event present in account subscribe frame")
}

fn account_data_entry<'a>(sync: &'a Value, data_type: &str) -> Option<&'a Value> {
    sync["account_data"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["data_type"] == data_type)
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
    assert!(stale_profile["last_active"].is_string());

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
                "scope_id": "ck:flow:demo",
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
        .list_for_space(DEMO_REALM_ID)
        .await
        .unwrap();
    assert_eq!(active_typing.len(), 1);
    assert_eq!(active_typing[0].actor, "did:web:alice.example");
    assert_eq!(active_typing[0].scope_id.as_deref(), Some("ck:flow:demo"));

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
        .list_for_space(DEMO_REALM_ID)
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

    let push_rule = submit_actor_private_event(
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
                        "type": "blind_wakeup"
                    }
                }]
            },
            "updated_at": "2026-05-08T10:00:00Z"
        }),
    )
    .await;
    assert_eq!(
        push_rule["status"], "accepted",
        "ck.push_rules account_data response: {push_rule}"
    );

    let listed_rules = account_subscribe_frame(state.clone(), Some(&token), "catchup=true").await;
    let push_rules = account_data_entry(&listed_rules, "ck.push_rules")
        .expect("ck.push_rules appears in account subscribe");
    assert_eq!(push_rules["content"]["rules"].as_array().unwrap().len(), 1);
    assert_eq!(push_rules["content"]["rules"][0]["rule_id"], "mute-device");

    let muted_notify: Value = TestClient::post("http://server/_cokret/edge/push/notify")
        .json(&serde_json::json!({
            "notification": {
                "type": "blind_wakeup",
                "devices": [{"device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001"}, {"device_id": "ck:device:01904100-0000-7000-8000-71551c000004"}]
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let rejected = muted_notify["rejected"].as_array().unwrap();
    assert_eq!(rejected.len(), 2);
    assert!(rejected.iter().any(|device| {
        device["device_id"] == "ck:device:01904100-0000-7000-8000-a11ce0000001"
            && device["reason"] == "push_rule"
            && device["rule_id"] == "mute-device"
    }));
    assert!(rejected.iter().any(|device| {
        device["device_id"] == "ck:device:01904100-0000-7000-8000-71551c000004"
            && device["reason"] == "unknown_device"
    }));

    let deleted_rule = submit_actor_private_event(
        state.clone(),
        &token,
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-a11ce0000001",
        DEMO_REALM_ID,
        "ck.account_data.set",
        serde_json::json!({
            "key": "ck.push_rules",
            "owner": "did:web:alice.example",
            "tombstone": true,
            "updated_at": "2026-05-08T10:01:00Z"
        }),
    )
    .await;
    assert_eq!(
        deleted_rule["status"], "accepted",
        "ck.push_rules tombstone response: {deleted_rule}"
    );

    let unmuted_notify: Value = TestClient::post("http://server/_cokret/edge/push/notify")
        .json(&serde_json::json!({
            "notification": {
                "type": "blind_wakeup",
                "devices": [{"device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001"}]
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(unmuted_notify["rejected"].as_array().unwrap().is_empty());

    let report: Value = TestClient::post("http://server/_cokret/self/moderation/report")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "target_ref": "ck:event:01904100-0000-7000-8000-4a4116cba4e8",
            "reason": "spam",
            "reporter": "did:web:alice.example"
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(report["status"], "queued");
    assert!(
        state
            .persistence
            .audit()
            .snapshot_all()
            .await
            .unwrap()
            .iter()
            .any(|entry| {
                entry["action"] == "moderation.report" && entry["outcome"] == "queued"
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
            "reason": "spam",
            "reporter": "did:web:alice.example"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthenticated_report.status_code.unwrap().as_u16(), 401);
}

#[tokio::test]
async fn auth_keys_device_messages_and_blobs_work() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let upload: Value = TestClient::post("http://server/_cokret/self/keys/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "device_keys": {"alg": "mls-rfc9420", "key": "alice-device-key"},
            "principal_signing_keys": [{"kid": "did:web:alice.example#principal", "key": "principal-key"}],
            "recovery_keys": [{"kid": "did:web:alice.example#recovery", "key": "recovery-key"}],
            "session_keys": [{"kid": "did:web:alice.example#session", "key": "session-key"}],
            "agent_keys": [{"kid": "did:web:alice.example#agent", "key": "agent-key"}],
            "one_time_keys": [{"key_id": "otk1", "key": "one-time"}],
            "fallback_keys": {"signed_curve25519:fallback": {"key": "fallback-key"}},
            "mls_key_packages": [{"package_id": "mls-package-1", "key": "opaque-package"}],
            "backup_restore_keys": [{"kid": "did:web:alice.example#backup", "key": "backup-key"}],
            "device_signature": {"alg": "none"}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(upload["one_time_key_counts"]["signed_curve25519"], 1);

    let query: Value = TestClient::post("http://server/_cokret/self/keys/query")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "device_keys": {"did:web:alice.example": ["ck:device:01904100-0000-7000-8000-a11ce0000001"]}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(query["device_keys"].is_object());
    assert_eq!(
        query["device_keys"]["did:web:alice.example"]["ck:device:01904100-0000-7000-8000-a11ce0000001"]
            ["device_keys"]["key"],
        "alice-device-key"
    );
    assert_eq!(
        query["device_keys"]["did:web:alice.example"]["ck:device:01904100-0000-7000-8000-a11ce0000001"]
            ["device_signature"]["alg"],
        "none"
    );
    assert_eq!(
        query["device_keys"]["did:web:alice.example"]["ck:device:01904100-0000-7000-8000-a11ce0000001"]
            ["fallback_keys"]["signed_curve25519:fallback"]["key"],
        "fallback-key"
    );
    assert_eq!(
        query["device_keys"]["did:web:alice.example"]["ck:device:01904100-0000-7000-8000-a11ce0000001"]
            ["mls_key_packages"][0]["package_id"],
        "mls-package-1"
    );
    assert_eq!(
        query["device_keys"]["did:web:alice.example"]["ck:device:01904100-0000-7000-8000-a11ce0000001"]
            ["principal_signing_keys"][0]["key"],
        "principal-key"
    );
    assert_eq!(
        query["device_keys"]["did:web:alice.example"]["ck:device:01904100-0000-7000-8000-a11ce0000001"]
            ["recovery_keys"][0]["key"],
        "recovery-key"
    );
    assert_eq!(
        query["device_keys"]["did:web:alice.example"]["ck:device:01904100-0000-7000-8000-a11ce0000001"]
            ["session_keys"][0]["key"],
        "session-key"
    );
    assert_eq!(
        query["device_keys"]["did:web:alice.example"]["ck:device:01904100-0000-7000-8000-a11ce0000001"]
            ["agent_keys"][0]["key"],
        "agent-key"
    );
    assert_eq!(
        query["device_keys"]["did:web:alice.example"]["ck:device:01904100-0000-7000-8000-a11ce0000001"]
            ["backup_restore_keys"][0]["key"],
        "backup-key"
    );

    let claimed_once: Value = TestClient::post("http://server/_cokret/self/keys/claim")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "one_time_keys": {
                "did:web:alice.example": {
                    "ck:device:01904100-0000-7000-8000-a11ce0000001": "signed_curve25519"
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        claimed_once["one_time_keys"]["did:web:alice.example"]["ck:device:01904100-0000-7000-8000-a11ce0000001"]
            ["key_id"],
        "otk1"
    );
    let claimed_replay: Value = TestClient::post("http://server/_cokret/self/keys/claim")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "one_time_keys": {
                "did:web:alice.example": {
                    "ck:device:01904100-0000-7000-8000-a11ce0000001": "signed_curve25519"
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        claimed_replay["one_time_keys"]["did:web:alice.example"]["ck:device:01904100-0000-7000-8000-a11ce0000001"].is_null(),
        "one-time key claim must be single-use"
    );

    let invalid_device_message = TestClient::post("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "bad-txn", true)
        .json(&serde_json::json!({
            "messages": {
                "did:web:alice.example": {
                    "ck:device:01904100-0000-7000-8000-a11ce0000001": {
                        "type": "ck.mls.welcome",
                        "content": {"ciphertext": "opaque"}
                    }
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(invalid_device_message.status_code.unwrap().as_u16(), 400);

    let send: Value = TestClient::post("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "txn1", true)
        .json(&serde_json::json!({
            "messages": {
                "did:web:alice.example": {
                    "ck:device:01904100-0000-7000-8000-a11ce0000001": {
                        "type": "ck.mls.welcome",
                        "content": encrypted_envelope("ck.mls.welcome", "opaque")
                    }
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(send["ok"], true);

    let duplicate: Value = TestClient::post("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "txn1", true)
        .json(&serde_json::json!({
            "messages": {
                "did:web:alice.example": {
                    "ck:device:01904100-0000-7000-8000-a11ce0000001": {
                        "type": "ck.mls.welcome",
                        "content": encrypted_envelope("ck.mls.welcome", "opaque")
                    }
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(duplicate["delivered"].as_object().unwrap().len(), 0);

    let bad_blob = TestClient::post("http://server/_cokret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header(
            "x-cokret-content-digest",
            "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            true,
        )
        .body("encrypted-bytes")
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(bad_blob.status_code.unwrap().as_u16(), 409);

    let bad_attachment = TestClient::post("http://server/_cokret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header(
            "x-cokret-attachment-envelope",
            serde_json::json!({
                "algorithm": "mls-rfc9420",
                "nonce": "nonce",
                "key_ref": {"kid": "did:web:alice.example#device"},
                "ciphertext_digest": "sha256:bad"
            })
            .to_string(),
            true,
        )
        .body("encrypted-bytes")
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(bad_attachment.status_code.unwrap().as_u16(), 400);

    let missing_envelope = TestClient::post("http://server/_cokret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("x-cokret-blob-encrypted", "true", true)
        .body("encrypted-bytes")
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(missing_envelope.status_code.unwrap().as_u16(), 400);

    let large_plaintext = "a".repeat(96 * 1024);
    let large_blob: Value = TestClient::post("http://server/_cokret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "image/jpeg", true)
        .body(large_plaintext.clone())
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(large_blob["size_bytes"], large_plaintext.len());
    assert_eq!(large_blob["media_type"], "image/jpeg");

    let locked_space = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Blob Policy Space",
        None,
        "invite_only",
        &[],
        &[],
    )
    .await;
    let plaintext_private_blob = TestClient::post("http://server/_cokret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header(
            "x-cokret-space-id",
            locked_space["space_id"].as_str().unwrap(),
            true,
        )
        .body("plaintext-private")
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(plaintext_private_blob.status_code.unwrap().as_u16(), 403);

    let encrypted_bytes = b"encrypted-bytes";
    let ciphertext_digest = format!("sha256:{:x}", Sha256::digest(encrypted_bytes));
    let blob: Value = TestClient::post("http://server/_cokret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "Text/Plain; charset=utf-8", true)
        .add_header("x-cokret-filename", "..\\danger<script>.txt", true)
        .add_header("x-cokret-blob-encrypted", "true", true)
        .add_header(
            "x-cokret-space-id",
            locked_space["space_id"].as_str().unwrap(),
            true,
        )
        .add_header("x-cokret-content-digest", ciphertext_digest.clone(), true)
        .add_header(
            "x-cokret-attachment-envelope",
            serde_json::json!({
                "algorithm": "mls-rfc9420",
                "nonce": "nonce",
                "key_ref": {"kid": "did:web:alice.example#device"},
                "ciphertext_digest": ciphertext_digest
            })
            .to_string(),
            true,
        )
        .body("encrypted-bytes")
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(blob["size_bytes"], 15);
    assert_eq!(blob["media_type"], "application/octet-stream");
    assert!(blob["upload_receipt"].get("filename").is_none());
    let upload_receipt = blob["upload_receipt"].to_string();
    assert!(!upload_receipt.contains("danger"));
    assert!(!upload_receipt.to_ascii_lowercase().contains("text/plain"));
    assert!(
        blob["blob_ref"]
            .as_str()
            .unwrap()
            .starts_with("ck:blob:sha256:")
    );
    assert_eq!(
        blob["upload_receipt"]["encrypted_attachment"]["algorithm"],
        "mls-rfc9420"
    );
    let ObjectStorageConfig::Local { root, .. } = test_config().object_storage else {
        panic!("test config uses local object storage");
    };
    let blob_digest = blob["content_digest"]
        .as_str()
        .unwrap()
        .trim_start_matches("sha256:");
    let blob_path = root.join("sha256").join(blob_digest);
    assert_eq!(std::fs::read(blob_path).unwrap(), encrypted_bytes);

    let anonymous_blob = TestClient::get(format!(
        "http://server/_cokret/self/blob/get?blob_ref={}&purpose=message_attachment",
        blob["blob_ref"].as_str().unwrap()
    ))
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(anonymous_blob.status_code.unwrap().as_u16(), 401);

    let mut alice_blob = TestClient::get(format!(
        "http://server/_cokret/self/blob/get?blob_ref={}&purpose=message_attachment",
        blob["blob_ref"].as_str().unwrap()
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(alice_blob.status_code.unwrap().as_u16(), 200);
    assert_eq!(
        alice_blob
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/octet-stream"
    );
    assert_eq!(
        alice_blob.take_string().await.unwrap().as_bytes(),
        encrypted_bytes
    );

    let bob = register_account(
        state.clone(),
        "did:web:blob-bob.example",
        "@blob-bob",
        "ck:device:01904100-0000-7000-8000-b10bb0000003",
    )
    .await;
    add_test_realm_member(
        &state,
        locked_space["space_id"].as_str().unwrap(),
        "did:web:blob-bob.example",
    );

    let service_did = state.config.service_did.clone();
    let shared_plaintext_space = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Shared Plaintext Blob Space",
        None,
        "invite_only",
        &[service_did.as_str()],
        &[],
    )
    .await;
    add_test_realm_member(
        &state,
        shared_plaintext_space["space_id"].as_str().unwrap(),
        "did:web:blob-bob.example",
    );
    let plaintext_blob: Value = TestClient::post("http://server/_cokret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "text/plain; charset=utf-8", true)
        .add_header("x-cokret-filename", "report final.txt", true)
        .add_header(
            "x-cokret-space-id",
            shared_plaintext_space["space_id"].as_str().unwrap(),
            true,
        )
        .body("shared plaintext")
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        plaintext_blob["upload_receipt"]["space_id"],
        shared_plaintext_space["space_id"]
    );
    assert_eq!(
        plaintext_blob["upload_receipt"]["filename"],
        "report_final.txt"
    );

    let mut bob_plaintext = TestClient::get(format!(
        "http://server/_cokret/self/blob/get?blob_ref={}&purpose=message_attachment",
        plaintext_blob["blob_ref"].as_str().unwrap()
    ))
    .add_header("authorization", format!("Bearer {bob}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(bob_plaintext.status_code.unwrap().as_u16(), 200);
    assert_eq!(
        bob_plaintext
            .headers()
            .get("content-disposition")
            .unwrap()
            .to_str()
            .unwrap(),
        "attachment; filename=\"report_final.txt\""
    );
    assert_eq!(
        bob_plaintext.take_string().await.unwrap(),
        "shared plaintext"
    );

    let mut plaintext_presign = TestClient::post("http://server/_cokret/self/blob/presign")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "blob_ref": plaintext_blob["blob_ref"].as_str().unwrap(),
            "purpose": "message_attachment",
            "space_id": shared_plaintext_space["space_id"].as_str().unwrap()
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(plaintext_presign.status_code.unwrap().as_u16(), 200);
    let plaintext_presign_body: Value = plaintext_presign.take_json().await.unwrap();
    let plaintext_presign_url = plaintext_presign_body["url"].as_str().unwrap();
    let mut presigned_plaintext = TestClient::get(plaintext_presign_url)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(presigned_plaintext.status_code.unwrap().as_u16(), 200);
    assert_eq!(
        presigned_plaintext.take_string().await.unwrap(),
        "shared plaintext"
    );
    let forged_presign_url =
        plaintext_presign_url.replace("presign_token=", "presign_token=forged");
    let forged_plaintext = TestClient::get(forged_presign_url)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(forged_plaintext.status_code.unwrap().as_u16(), 401);

    let mut bob_blob = TestClient::get(format!(
        "http://server/_cokret/self/blob/get?blob_ref={}&purpose=message_attachment",
        blob["blob_ref"].as_str().unwrap()
    ))
    .add_header("authorization", format!("Bearer {bob}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(bob_blob.status_code.unwrap().as_u16(), 200);
    let bob_body = bob_blob.take_string().await.unwrap();
    assert_eq!(bob_body.as_bytes(), encrypted_bytes);
    assert_eq!(
        format!("sha256:{:x}", Sha256::digest(bob_body.as_bytes())),
        blob["upload_receipt"]["encrypted_attachment"]["ciphertext_digest"]
            .as_str()
            .unwrap()
    );

    let mut range = TestClient::get(format!(
        "http://server/_cokret/self/blob/get?blob_ref={}&purpose=message_attachment",
        blob["blob_ref"].as_str().unwrap()
    ))
    .add_header("authorization", format!("Bearer {bob}"), true)
    .add_header("range", "bytes=0-8", true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(range.status_code.unwrap().as_u16(), 206);
    assert_eq!(
        range
            .headers()
            .get("content-range")
            .unwrap()
            .to_str()
            .unwrap(),
        "bytes 0-8/15"
    );
    assert_eq!(range.take_string().await.unwrap(), "encrypted");

    let mut presign = TestClient::post("http://server/_cokret/self/blob/presign")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "blob_ref": blob["blob_ref"].as_str().unwrap(),
            "purpose": "message_attachment"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(presign.status_code.unwrap().as_u16(), 403);
    let presign_body: Value = presign.take_json().await.unwrap();
    assert_eq!(presign_body["error"]["code"], "capability_denied");

    let mallory = register_account(
        state.clone(),
        "did:web:blob-mallory.example",
        "@blob-mallory",
        "ck:device:01904100-0000-7000-8000-a11000000004",
    )
    .await;
    let mut invisible_blob = TestClient::get(format!(
        "http://server/_cokret/self/blob/get?blob_ref={}&purpose=message_attachment",
        blob["blob_ref"].as_str().unwrap()
    ))
    .add_header("authorization", format!("Bearer {mallory}"), true)
    .add_header("range", "bytes=0-8", true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(invisible_blob.status_code.unwrap().as_u16(), 404);
    assert!(invisible_blob.headers().get("content-range").is_none());
    assert!(invisible_blob.headers().get("accept-ranges").is_none());
    let invisible_body: Value = invisible_blob.take_json().await.unwrap();
    assert_eq!(invisible_body["error"]["code"], "not_found");
    let invisible_text = invisible_body.to_string();
    assert!(!invisible_text.contains(locked_space["space_id"].as_str().unwrap()));
    assert!(!invisible_text.contains(blob["blob_ref"].as_str().unwrap()));

    let push_registration: Value =
        TestClient::post("http://server/_cokret/edge/push/register-device")
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
    assert_eq!(push_registration["ok"], true);

    let plaintext_push = TestClient::post("http://server/_cokret/edge/push/notify")
        .json(&serde_json::json!({
            "notification": {
                "type": "message",
                "devices": [{"device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001"}],
                "preview": "plaintext should not be sent to push gateway"
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(plaintext_push.status_code.unwrap().as_u16(), 400);

    let notify: Value = TestClient::post("http://server/_cokret/edge/push/notify")
        .json(&serde_json::json!({
            "notification": {
                "type": "blind_wakeup",
                "devices": [{"device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001"}, {"device_id": "ck:device:01904100-0000-7000-8000-71551c000004"}]
            }
        }))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(notify["rejected"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn push_unregister_mutates_registration_and_gateway_snapshot_gates_notify() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let service = app_from_state(state.clone());
    let device_id = "ck:device:01904100-0000-7000-8000-a11ce0000001";
    let push_gateway = "https://push.example/_cokret/edge/push/notify";
    let bridge_describe = "https://push.example/_cokret/edge/push/bridge/describe";
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
                "delivery": {"notify_path": "/_cokret/edge/push/notify", "operation_id": "ck.edge.push.notify"}
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
                "type": "blind_wakeup",
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
                "delivery": {"notify_path": "/_cokret/edge/push/notify", "operation_id": "ck.edge.push.notify"}
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
                "type": "blind_wakeup",
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
                "type": "blind_wakeup",
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

#[tokio::test]
async fn keys_query_hides_revoked_device() {
    let state = AppState::new(test_config(), Db { pool: None });
    let desktop = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-a11ce0000001",
        "Alice Desktop",
    )
    .await;
    let mobile = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-9b04e0000007",
        "Alice Phone",
    )
    .await;

    let _desktop_keys: Value = TestClient::post("http://server/_cokret/self/keys/upload")
        .add_header("authorization", format!("Bearer {desktop}"), true)
        .json(&serde_json::json!({
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "device_keys": {"alg": "mls-rfc9420", "key": "desktop-device-key"},
            "principal_signing_keys": [{"kid": "did:web:alice.example#principal", "key": "principal-key"}],
            "recovery_keys": [{"kid": "did:web:alice.example#recovery", "key": "recovery-key"}],
            "session_keys": [{"kid": "did:web:alice.example#session", "key": "session-key"}],
            "agent_keys": [{"kid": "did:web:alice.example#agent", "key": "agent-key"}],
            "one_time_keys": [{"key_id": "desktop-otk", "key": "one-time"}],
            "fallback_keys": {"signed_curve25519:desktop": {"key": "fallback-desktop"}},
            "mls_key_packages": [{"package_id": "desktop-package", "key": "opaque-package"}],
            "backup_restore_keys": [{"kid": "did:web:alice.example#backup", "key": "backup-key"}],
            "device_signature": {"alg": "none"}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();

    let _phone_keys: Value = TestClient::post("http://server/_cokret/self/keys/upload")
        .add_header("authorization", format!("Bearer {mobile}"), true)
        .json(&serde_json::json!({
            "device_id": "ck:device:01904100-0000-7000-8000-9b04e0000007",
            "device_keys": {"alg": "mls-rfc9420", "key": "phone-device-key"},
            "principal_signing_keys": [{"kid": "did:web:alice.example#principal", "key": "principal-key"}],
            "recovery_keys": [{"kid": "did:web:alice.example#recovery", "key": "recovery-key"}],
            "session_keys": [{"kid": "did:web:alice.example#session", "key": "session-key"}],
            "agent_keys": [{"kid": "did:web:alice.example#agent", "key": "agent-key"}],
            "one_time_keys": [{"key_id": "phone-otk", "key": "one-time"}],
            "fallback_keys": {"signed_curve25519:phone": {"key": "fallback-phone"}},
            "mls_key_packages": [{"package_id": "phone-package", "key": "opaque-package"}],
            "backup_restore_keys": [{"kid": "did:web:alice.example#backup", "key": "backup-key"}],
            "device_signature": {"alg": "none"}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();

    let pre_revoke_query: Value = TestClient::post("http://server/_cokret/self/keys/query")
        .add_header("authorization", format!("Bearer {desktop}"), true)
        .json(&serde_json::json!({
            "device_keys": {"did:web:alice.example": ["ck:device:01904100-0000-7000-8000-a11ce0000001", "ck:device:01904100-0000-7000-8000-9b04e0000007"]}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        pre_revoke_query["device_keys"]["did:web:alice.example"]["ck:device:01904100-0000-7000-8000-a11ce0000001"]
            ["device_keys"]["key"],
        "desktop-device-key"
    );
    assert_eq!(
        pre_revoke_query["device_keys"]["did:web:alice.example"]["ck:device:01904100-0000-7000-8000-9b04e0000007"]
            ["device_keys"]["key"],
        "phone-device-key"
    );

    let logout: Value = TestClient::post("http://server/_soland/gate/auth/logout")
        .add_header("authorization", format!("Bearer {mobile}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(logout["revoked"], true);

    let post_revoke_query: Value = TestClient::post("http://server/_cokret/self/keys/query")
        .add_header("authorization", format!("Bearer {desktop}"), true)
        .json(&serde_json::json!({
            "device_keys": {"did:web:alice.example": ["ck:device:01904100-0000-7000-8000-a11ce0000001", "ck:device:01904100-0000-7000-8000-9b04e0000007"]}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(post_revoke_query["device_keys"]["did:web:alice.example"]["ck:device:01904100-0000-7000-8000-9b04e0000007"].is_null());
    assert_eq!(
        post_revoke_query["device_keys"]["did:web:alice.example"]["ck:device:01904100-0000-7000-8000-a11ce0000001"]
            ["device_keys"]["key"],
        "desktop-device-key"
    );
}

#[tokio::test]
async fn revoked_device_blocks_encrypted_writes() {
    let state = AppState::new(test_config(), Db { pool: None });
    let device_token = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-30b11e000005",
        "Alice Mobile",
    )
    .await;
    let stale_session = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-30b11e000005",
        "Alice Mobile",
    )
    .await;

    let logout: Value = TestClient::post("http://server/_soland/gate/auth/logout")
        .add_header("authorization", format!("Bearer {device_token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(logout["revoked"], true);

    let blocked_send = post_message_event(
        state.clone(),
        &stale_session,
        "did:web:alice.example",
        DEMO_REALM_ID,
        DEMO_REALM_ID,
        encrypted_envelope("ck.message.v1", "blocked-ciphertext"),
        true,
    )
    .await;
    assert_eq!(blocked_send.as_u16(), 401);

    let blocked_upload = TestClient::post("http://server/_cokret/self/keys/upload")
        .add_header("authorization", format!("Bearer {stale_session}"), true)
        .json(&serde_json::json!({
            "device_id": "ck:device:01904100-0000-7000-8000-30b11e000005",
            "device_keys": {"alg": "mls-rfc9420", "key": "new-key"},
            "principal_signing_keys": [],
            "recovery_keys": [],
            "session_keys": [],
            "agent_keys": [],
            "one_time_keys": [],
            "fallback_keys": {},
            "mls_key_packages": [],
            "backup_restore_keys": [],
            "device_signature": {"alg": "none"}
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(blocked_upload.status_code.unwrap().as_u16(), 401);
}

#[tokio::test]
async fn server_preserves_e2ee_payloads_as_opaque_data() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let ciphertext = "base64url-opaque-ciphertext";

    TestClient::post("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "e2ee-txn", true)
        .json(&serde_json::json!({
            "messages": {
                "did:web:alice.example": {
                    "ck:device:01904100-0000-7000-8000-a11ce0000001": {
                        "type": "ck.mls.application",
                        "content": encrypted_envelope("ck.mls.application", ciphertext)
                    }
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;

    let delivered: Value = TestClient::get("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    let content = &delivered["events"][0]["content"]["content"];
    assert_eq!(content["ciphertext"], ciphertext);
    assert!(content.get("plaintext").is_none());
    assert!(delivered["events"][0]["position"].as_i64().unwrap() > 0);
}

#[tokio::test]
async fn to_device_messages_survive_duplicate_sync_until_cursor_ack() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    TestClient::post("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "ack-txn", true)
        .json(&serde_json::json!({
            "messages": {
                "did:web:alice.example": {
                    "ck:device:01904100-0000-7000-8000-a11ce0000001": {
                        "type": "ck.mls.application",
                        "content": encrypted_envelope("ck.mls.application", "ack-ciphertext")
                    }
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;

    let first = account_subscribe_frame(state.clone(), Some(&token), "catchup=true").await;
    assert_eq!(first["to_device"]["messages"].as_array().unwrap().len(), 1);
    let first_cursor = decode_cursor(first["cursor"].as_str().unwrap());
    assert!(first_cursor["h"].as_str().is_some_and(|h| h.len() >= 22));
    assert!(first_cursor.get("_positions").is_none());

    let duplicate = account_subscribe_frame(state.clone(), Some(&token), "catchup=true").await;
    assert_eq!(
        duplicate["to_device"]["messages"].as_array().unwrap().len(),
        1
    );

    let acked = account_subscribe_frame(
        state,
        Some(&token),
        &format!(
            "catchup=true&max_wait_ms=0&after={}",
            first["cursor"].as_str().unwrap()
        ),
    )
    .await;
    assert!(
        acked["to_device"]["messages"].is_array(),
        "acked sync response must be a sync body: {acked}"
    );
    assert!(
        acked["to_device"]["messages"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn device_messages_evicted_after_session_logout() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    TestClient::post("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "logout-txn", true)
        .json(&serde_json::json!({
            "messages": {
                "did:web:alice.example": {
                    "ck:device:01904100-0000-7000-8000-a11ce0000001": {
                        "type": "ck.mls.welcome",
                        "content": encrypted_envelope("ck.mls.welcome", "logout-ciphertext")
                    }
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;

    let pre_logout: Value = TestClient::get("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(pre_logout["events"].as_array().unwrap().len(), 1);

    let logout: Value = TestClient::post("http://server/_soland/gate/auth/logout")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(logout["ok"], true);
    assert_eq!(logout["revoked"], true);

    let revoked_session_messages = TestClient::get("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(revoked_session_messages.status_code.unwrap().as_u16(), 401);

    let new_token = dev_token(state.clone()).await;
    let post_logout: Value = TestClient::get("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {new_token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(post_logout["events"].as_array().unwrap().is_empty());
}
