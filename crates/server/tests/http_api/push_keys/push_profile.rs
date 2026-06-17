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
