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

fn device_message_target(kind: &str, content: Value) -> Value {
    serde_json::json!({
        "kind": kind,
        "content": content,
        "expires_at": (chrono::Utc::now() + chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    })
}

#[tokio::test]
async fn file_transfer_blob_upload_uses_encrypted_metadata_and_blocks_presign() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let file_transfer_bytes = b"file-transfer-ciphertext";
    let file_transfer_digest = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(file_transfer_bytes))
    );
    let file_transfer_blob: Value = TestClient::post("http://server/_cokret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "text/plain", true)
        .add_header("x-cokret-filename", "private.txt", true)
        .add_header("x-cokret-blob-encrypted", "true", true)
        .add_header("x-cokret-blob-purpose", "file_transfer", true)
        .add_header(
            "x-cokret-content-digest",
            file_transfer_digest.clone(),
            true,
        )
        .body(file_transfer_bytes.as_slice())
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
    assert_eq!(
        file_transfer_blob["upload_receipt"]["purpose"],
        "file_transfer"
    );
    assert_eq!(
        file_transfer_blob["upload_receipt"]["encrypted_attachment"]["scheme"],
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
                "scope_id": "ck:strand:demo",
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
    assert_eq!(active_typing[0].scope_id.as_deref(), Some("ck:strand:demo"));

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
async fn ephemeral_call_signal_enforces_structural_contract() {
    // `webrtc-signaling.md` §5 — the /ephemeral relay structurally validates
    // ck.call.signal envelopes (device_id + proof present, payload
    // {call_id, signal_type, seq} with a canonical signal_type incl.
    // moderation). It does NOT cryptographically verify the proof (receiver's
    // job).
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
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
            env["proof"] = serde_json::json!({"alg": "EdDSA", "sig": "ZGV2"});
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
    assert_eq!(accepted["accepted"], true);
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
async fn auth_keys_device_messages_and_blobs_work() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let upload: Value = TestClient::post("http://server/_cokret/self/keys/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "one_time_keys": {"signed_curve25519:otk1": {"key": "one-time"}},
            "fallback_keys": {"signed_curve25519:fallback": {"key": "fallback-key"}},
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
    let alice_desktop = &query["device_keys"]["did:web:alice.example"]
        ["ck:device:01904100-0000-7000-8000-a11ce0000001"];
    assert_eq!(
        alice_desktop["algorithms"]["one_time_keys"]["signed_curve25519:otk1"]["key"],
        "one-time"
    );
    assert_eq!(
        alice_desktop["algorithms"]["fallback_keys"]["signed_curve25519:fallback"]["key"],
        "fallback-key"
    );
    assert_eq!(
        alice_desktop["algorithms"]["device_signature"]["alg"],
        "none"
    );
    // dev-login devices carry no authoritative device_public_key, so the
    // signing-key directory facet reports status without a verify key.
    assert_eq!(alice_desktop["device_status"], "active");
    assert!(alice_desktop["device_signing_key"].is_null());

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
            ["key"],
        "one-time"
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
                        "kind": "ck.mls.welcome",
                        "content": "not-an-object",
                        "expires_at": (chrono::Utc::now() + chrono::Duration::hours(1))
                            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
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
                    "ck:device:01904100-0000-7000-8000-a11ce0000001":
                        device_message_target("ck.mls.welcome", encrypted_envelope("ck.mls.welcome", "opaque"))
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
                    "ck:device:01904100-0000-7000-8000-a11ce0000001":
                        device_message_target("ck.mls.welcome", encrypted_envelope("ck.mls.welcome", "opaque"))
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        duplicate
            .get("delivered")
            .and_then(Value::as_object)
            .map(|delivered| delivered.len())
            .unwrap_or(0),
        0,
        "duplicate send must not re-queue messages: {duplicate}"
    );

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

    let locked_realm = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Blob Policy Realm",
        None,
        "invite_only",
        &[],
        &[],
    )
    .await;
    let plaintext_private_blob = TestClient::post("http://server/_cokret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header(
            "x-cokret-realm-id",
            locked_realm["realm_id"].as_str().unwrap(),
            true,
        )
        .body("plaintext-private")
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(plaintext_private_blob.status_code.unwrap().as_u16(), 403);

    let encrypted_bytes = b"encrypted-bytes";
    let ciphertext_digest = format!("sha256:{}", hex::encode(Sha256::digest(encrypted_bytes)));
    let blob: Value = TestClient::post("http://server/_cokret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "Text/Plain; charset=utf-8", true)
        .add_header("x-cokret-filename", "..\\danger<script>.txt", true)
        .add_header("x-cokret-blob-encrypted", "true", true)
        .add_header(
            "x-cokret-realm-id",
            locked_realm["realm_id"].as_str().unwrap(),
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
        locked_realm["realm_id"].as_str().unwrap(),
        "did:web:blob-bob.example",
    );

    let service_did = state.config.service_did.clone();
    let shared_plaintext_realm = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Shared Plaintext Blob Realm",
        None,
        "invite_only",
        &[service_did.as_str()],
        &[],
    )
    .await;
    add_test_realm_member(
        &state,
        shared_plaintext_realm["realm_id"].as_str().unwrap(),
        "did:web:blob-bob.example",
    );
    let plaintext_blob: Value = TestClient::post("http://server/_cokret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "text/plain; charset=utf-8", true)
        .add_header("x-cokret-filename", "report final.txt", true)
        .add_header(
            "x-cokret-realm-id",
            shared_plaintext_realm["realm_id"].as_str().unwrap(),
            true,
        )
        .body("shared plaintext")
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        plaintext_blob["upload_receipt"]["realm_id"],
        shared_plaintext_realm["realm_id"]
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
            "realm_id": shared_plaintext_realm["realm_id"].as_str().unwrap()
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
        format!(
            "sha256:{}",
            hex::encode(Sha256::digest(bob_body.as_bytes()))
        ),
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
    assert!(!invisible_text.contains(locked_realm["realm_id"].as_str().unwrap()));
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

/// Persist a verified device for `actor` carrying an authoritative
/// `device_public_key` (the shape the session-grant exchange and the
/// `ck.device.authorize` projection both write), so the `keys/query`
/// signing-key directory can resolve it.
async fn seed_verified_device_with_public_key(
    state: &AppState,
    actor: &str,
    device_id: &str,
    device_public_key: &str,
) {
    let now = chrono::Utc::now();
    state
        .persistence
        .devices()
        .put(&soland::state::DeviceInventoryRecord {
            actor: actor.to_owned(),
            device_id: device_id.to_owned(),
            display_name: Some("Directory Test Device".to_owned()),
            verification_state: "verified".to_owned(),
            payload: serde_json::json!({
                "device_id": device_id,
                "verification": "verified",
                "device_public_key": device_public_key,
            }),
            created_at: now,
            updated_at: now,
            revoked_at: None,
        })
        .await
        .unwrap();
}

/// Device-identity Phase 1 — a peer (member B) resolves member A's authoritative
/// device verify key via `keys/query`, and the key disappears once A's device is
/// revoked (device-lifecycle.md §8.2).
#[tokio::test]
async fn keys_query_projects_device_signing_key_and_drops_on_revoke() {
    let state = AppState::new(test_config(), Db { pool: None });

    let alice = "did:web:alice.example";
    let alice_device = "ck:device:01904100-0000-7000-8000-a11ce0000001";
    let alice_device_key = SigningKey::from_bytes(&[201u8; 32]);
    let alice_device_multibase = test_ed25519_multibase_public(&alice_device_key);
    let expected_did_key = format!("did:key:{alice_device_multibase}");
    seed_verified_device_with_public_key(&state, alice, alice_device, &alice_device_multibase).await;

    // Member B queries member A's (actor, device) directory entry.
    let bob = dev_token_for_device(
        state.clone(),
        "did:web:bob.example",
        "ck:device:01904100-0000-7000-8000-b0b000000001",
        "Bob Desktop",
    )
    .await;

    let query: Value = TestClient::post("http://server/_cokret/self/keys/query")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .json(&serde_json::json!({
            "device_keys": { alice: [alice_device] }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let entry = &query["device_keys"][alice][alice_device];
    assert_eq!(
        entry["device_signing_key"], expected_did_key,
        "expected authoritative did:key, got {entry}"
    );
    assert_eq!(entry["device_status"], "active");

    // Revoke member A's device, then re-query: the entry MUST be omitted so no
    // signing key leaks for a revoked device.
    let mut revoked = state
        .persistence
        .devices()
        .get(alice, alice_device)
        .await
        .unwrap()
        .unwrap();
    revoked.revoked_at = Some(chrono::Utc::now());
    state.persistence.devices().put(&revoked).await.unwrap();

    let post_revoke: Value = TestClient::post("http://server/_cokret/self/keys/query")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .json(&serde_json::json!({
            "device_keys": { alice: [alice_device] }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        post_revoke["device_keys"][alice][alice_device].is_null(),
        "revoked device must not surface a directory entry: {post_revoke}"
    );
}

/// Device-identity Phase 1 (Task C) — an accepted `ck.device.authorize` carrying
/// `device_public_key` projects that key into the devices table, so a device that
/// was authorized but never opened a session is still directory-resolvable.
#[tokio::test]
async fn device_authorize_projects_public_key_into_devices_table() {
    let state = AppState::new(test_config(), Db { pool: None });

    let alice = "did:web:alice.example";
    let alice_device = "ck:device:01904100-0000-7000-8000-a11ce0000002";
    let device_key = SigningKey::from_bytes(&[202u8; 32]);
    let multibase = test_ed25519_multibase_public(&device_key);

    // No cross_signing_binding → the ingest binding gate is a no-op
    // (bootstrap/first-device authorizations are validated elsewhere), so the
    // projection write is exercised directly.
    let control_realm = soland::test_support::principal_control_realm_for_did(alice);
    let operation = Operation::create(
        OperationId::new(new_prefixed_uuid7("ck:operation:")).unwrap(),
        RealmId::new(control_realm).unwrap(),
        "ck.device.authorize",
        serde_json::json!({
            "principal_id": alice,
            "device_id": alice_device,
            "device_public_key": multibase,
        }),
    );
    soland::test_support::project_accepted_operations(&state, alice, &[operation]).await;

    let device = state
        .persistence
        .devices()
        .get(alice, alice_device)
        .await
        .unwrap()
        .expect("device.authorize projection persisted the device");
    assert_eq!(
        device.payload["device_public_key"].as_str(),
        Some(multibase.as_str())
    );
    assert_eq!(device.verification_state, "verified");
    assert!(device.revoked_at.is_none());
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
            ["algorithms"]["device_keys"]["key"],
        "desktop-device-key"
    );
    assert_eq!(
        pre_revoke_query["device_keys"]["did:web:alice.example"]["ck:device:01904100-0000-7000-8000-9b04e0000007"]
            ["algorithms"]["device_keys"]["key"],
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
            ["algorithms"]["device_keys"]["key"],
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
                    "ck:device:01904100-0000-7000-8000-a11ce0000001":
                        device_message_target("ck.mls.application", encrypted_envelope("ck.mls.application", ciphertext))
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
    let content = &delivered["messages"][0]["content"];
    assert_eq!(content["ciphertext"], ciphertext);
    assert!(content.get("plaintext").is_none());
    assert!(
        delivered["ack_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
    assert!(delivered["next_cursor"].as_str().is_some());
}

#[tokio::test]
async fn to_device_messages_survive_duplicate_sync_until_ack_token_consumed() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    TestClient::post("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "ack-txn", true)
        .json(&serde_json::json!({
            "messages": {
                "did:web:alice.example": {
                    "ck:device:01904100-0000-7000-8000-a11ce0000001":
                        device_message_target("ck.mls.application", encrypted_envelope("ck.mls.application", "ack-ciphertext"))
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;

    let first = account_subscribe_frame(state.clone(), Some(&token), "catchup=true").await;
    assert_eq!(first["to_device"]["messages"].as_array().unwrap().len(), 1);
    let ack_token = first["to_device"]["ack_token"]
        .as_str()
        .expect("to_device ack_token")
        .to_owned();
    let first_cursor = decode_cursor(first["cursor"].as_str().unwrap());
    assert!(first_cursor["h"].as_str().is_some_and(|h| h.len() >= 22));
    assert!(first_cursor.get("_positions").is_none());

    let duplicate = account_subscribe_frame(state.clone(), Some(&token), "catchup=true").await;
    assert_eq!(
        duplicate["to_device"]["messages"].as_array().unwrap().len(),
        1
    );

    let cursor_replay = account_subscribe_frame(
        state.clone(),
        Some(&token),
        &format!(
            "catchup=true&max_wait_ms=0&after={}",
            first["cursor"].as_str().unwrap()
        ),
    )
    .await;
    assert!(
        cursor_replay["to_device"]["messages"].is_array(),
        "cursor replay response must be a sync body: {cursor_replay}"
    );
    assert_eq!(
        cursor_replay["to_device"]["messages"]
            .as_array()
            .unwrap()
            .len(),
        1,
        "account cursor must not prune unacked to-device messages"
    );

    let acked: Value = TestClient::post("http://server/_cokret/self/device_messages/ack")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({ "ack_token": ack_token.clone() }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(acked["ok"], true);
    assert_eq!(acked["pruned_count"], 1);

    let ack_replay: Value = TestClient::post("http://server/_cokret/self/device_messages/ack")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({ "ack_token": ack_token }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(ack_replay["ok"], true);
    assert_eq!(ack_replay["pruned_count"], 0);

    let after_ack =
        account_subscribe_frame(state, Some(&token), "catchup=true&max_wait_ms=0").await;
    assert!(
        after_ack["to_device"]["messages"]
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
                    "ck:device:01904100-0000-7000-8000-a11ce0000001":
                        device_message_target("ck.mls.welcome", encrypted_envelope("ck.mls.welcome", "logout-ciphertext"))
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
    assert_eq!(pre_logout["messages"].as_array().unwrap().len(), 1);

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
    assert!(post_logout["messages"].as_array().unwrap().is_empty());
}
