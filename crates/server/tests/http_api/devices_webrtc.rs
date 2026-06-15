//! Integration tests — `devices_webrtc` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

#![allow(unused_imports)]
use cokret_sdk::CellRef;
use cokret_sdk::lattice::CellState;

use super::common::*;

fn device_message_target(kind: &str, content: Value) -> Value {
    serde_json::json!({
        "kind": kind,
        "content": content,
        "expires_at": (chrono::Utc::now() + chrono::Duration::minutes(10))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    })
}

#[tokio::test]
async fn account_device_pair_registers_sibling_via_canonical_gate_route() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let sibling = "ck:device:01904100-0000-7000-8000-9b04e0000008";

    let unauthenticated = TestClient::post("http://server/_cokret/gate/account/device-pair")
        .json(&serde_json::json!({
            "pairing_code": "pairing-code",
            "new_device_pubkey": {
                "kty": "OKP",
                "kid": sibling,
                "alg": "EdDSA",
                "public_key": "emtleQ"
            },
            "challenge_signature": "c2ln"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthenticated.status_code, Some(StatusCode::UNAUTHORIZED));

    let paired: Value = TestClient::post("http://server/_cokret/gate/account/device-pair")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "pairing_code": "pairing-code",
            "new_device_pubkey": {
                "kty": "OKP",
                "kid": sibling,
                "alg": "EdDSA",
                "public_key": "emtleQ"
            },
            "challenge_signature": "c2ln",
            "display_name": "Paired Phone",
            "device_metadata": {
                "platform": "ios"
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(paired["device_id"], sibling);
    assert!(
        paired["authorized_event_ref"]
            .as_str()
            .unwrap()
            .starts_with("ck:event:")
    );
    assert_eq!(paired["device_grant"]["status"], "active");

    let viewer: Value = TestClient::get("http://server/_cokret/self/account/viewer")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(viewer["devices"].as_array().unwrap().iter().any(|device| {
        device["device_id"] == sibling
            && device["status"] == "active"
            && device["display_name"] == "Paired Phone"
    }));
    assert!(
        state
            .persistence
            .audit()
            .snapshot_all()
            .await
            .unwrap()
            .iter()
            .any(|event| {
                event["action"] == "account.device_pair"
                    && event["outcome"] == "accepted"
                    && event["payload"]["new_device_id"] == sibling
            })
    );
}

#[tokio::test]
async fn to_device_pairing_request_reaches_existing_device_and_gate_pair_authorizes_new_device() {
    let state = AppState::new(test_config(), Db { pool: None });
    let actor = "did:web:alice.example";
    let existing_device = "ck:device:01904100-0000-7000-8000-a11ce0000001";
    let new_device = "ck:device:01904100-0000-7000-8000-9b04e0000008";
    let existing_token =
        dev_token_for_device(state.clone(), actor, existing_device, "Alice Desktop").await;
    let new_token = dev_token_for_device(state.clone(), actor, new_device, "Alice Browser").await;
    let request_content = serde_json::json!({
        "transaction_id": "txn-device-pair-1",
        "from_device": new_device,
        "timestamp": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "expires_at": (chrono::Utc::now() + chrono::Duration::minutes(10))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "methods": ["ck.sas.v1", "ck.qr.v1"],
        "purpose": "same_principal_device_authorization",
        "pairing_code": "pairing-code",
        "new_device_pubkey": {
            "kty": "OKP",
            "kid": new_device,
            "alg": "EdDSA",
            "public_key": "emtleQ"
        },
        "challenge_signature": "c2ln",
        "gate_audience": "http://server",
        "request_canonical_digest": "sha256:test",
        "device_metadata": {
            "display_name": "Alice Browser",
            "platform": "browser"
        }
    });

    let mut device_targets = serde_json::Map::new();
    device_targets.insert(
        existing_device.to_owned(),
        device_message_target("ck.key.verification.request", request_content.clone()),
    );
    let mut actor_targets = serde_json::Map::new();
    actor_targets.insert(actor.to_owned(), Value::Object(device_targets));
    let sent: Value = TestClient::post("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {new_token}"), true)
        .add_header("Idempotency-Key", "device-pair-request-1", true)
        .json(&serde_json::json!({
            "messages": actor_targets
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(sent["ok"], true);
    assert_eq!(sent["delivered"][actor][0], existing_device);

    let subscribe =
        account_subscribe_frame(state.clone(), Some(&existing_token), "catchup=true").await;
    let subscribe_messages = subscribe["to_device"]["messages"].as_array().unwrap();
    assert_eq!(subscribe_messages.len(), 1);
    assert_eq!(subscribe_messages[0]["kind"], "ck.key.verification.request");
    assert_eq!(subscribe_messages[0]["sender_principal_id"], actor);
    assert_eq!(subscribe_messages[0]["sender_device_id"], new_device);
    assert_eq!(subscribe_messages[0]["recipient_principal_id"], actor);
    assert_eq!(
        subscribe_messages[0]["recipient_device_id"],
        existing_device
    );
    assert_eq!(
        subscribe_messages[0]["content"]["purpose"],
        "same_principal_device_authorization"
    );
    assert_eq!(
        subscribe_messages[0]["content"]["new_device_pubkey"]["public_key"],
        "emtleQ"
    );
    assert!(
        subscribe["to_device"]["ack_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );

    let pulled: Value = TestClient::get("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {existing_token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(pulled["messages"].as_array().unwrap().len(), 1);
    assert_eq!(
        pulled["messages"][0]["content"]["pairing_code"],
        "pairing-code"
    );

    let approved: Value = TestClient::post("http://server/_cokret/gate/account/device-pair")
        .add_header("authorization", format!("Bearer {existing_token}"), true)
        .json(&serde_json::json!({
            "pairing_code": "pairing-code",
            "new_device_pubkey": request_content["new_device_pubkey"],
            "challenge_signature": "c2ln",
            "display_name": "Alice Browser",
            "device_metadata": request_content["device_metadata"]
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(approved["device_id"], new_device);
    assert_eq!(approved["device_grant"]["status"], "active");

    let viewer: Value = TestClient::get("http://server/_cokret/self/account/viewer")
        .add_header("authorization", format!("Bearer {existing_token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(viewer["devices"].as_array().unwrap().iter().any(|device| {
        device["device_id"] == new_device
            && device["status"] == "active"
            && device["display_name"] == "Alice Browser"
    }));
}

#[tokio::test]
async fn protocol_device_surface_excludes_pairing_request_scaffold() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let create = TestClient::post("http://server/_cokret/gate/account/device-pairing-requests")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "pairing_code": "pairing-code",
            "new_device_pubkey": {
                "kid": "ck:device:01904100-0000-7000-8000-9b04e0000007",
                "alg": "EdDSA",
                "public_key": "emtleQ"
            },
            "challenge_signature": "c2ln"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(create.status_code, Some(StatusCode::NOT_FOUND));

    let list = TestClient::get("http://server/_cokret/self/devices/pairing-requests")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(list.status_code, Some(StatusCode::NOT_FOUND));

    let devices = TestClient::get("http://server/_cokret/self/devices")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(devices.status_code, Some(StatusCode::NOT_FOUND));

    let soland_challenge = TestClient::post("http://server/_soland/self/devices/pairing-challenge")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "device_id": "ck:device:01904100-0000-7000-8000-9b04e0000007"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(soland_challenge.status_code, Some(StatusCode::NOT_FOUND));

    let soland_authorize = TestClient::post("http://server/_soland/self/devices/authorize-pairing")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "device_id": "ck:device:01904100-0000-7000-8000-9b04e0000007"
        }))
        .send(&app_from_state(state))
        .await;
    assert_eq!(soland_authorize.status_code, Some(StatusCode::NOT_FOUND));
}

#[tokio::test]
async fn webrtc_signaling_contracts_work() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let unauthenticated = TestClient::post("http://server/_cokret/self/webrtc/sessions")
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthenticated.status_code, Some(StatusCode::UNAUTHORIZED));

    let session: Value = TestClient::post("http://server/_cokret/self/webrtc/sessions")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "participants": ["did:web:alice.example"],
            "mode": "p2p",
            "recording_policy": "none",
            "ttl_ms": 60000
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let session_id = session["session_id"].as_str().unwrap().to_owned();
    assert!(session_id.starts_with("ck:call:"));
    assert_eq!(session["participants"].as_array().unwrap().len(), 1);
    assert_eq!(session["mode"], "p2p");
    assert_eq!(session["recording_policy"], "none");
    assert_eq!(session["call_state"], "ringing");

    let ice: Value = TestClient::post("http://server/_cokret/self/calls/ice-config")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "call_id": session_id,
            "actor_id": "did:web:alice.example",
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001"
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(ice["realm_id"], DEMO_REALM_ID);
    assert_eq!(ice["call_id"], session_id);
    assert_eq!(ice["turn_servers"].as_array().unwrap().len(), 1);
    let turn_username = ice["turn_servers"][0]["username"].as_str().unwrap();
    // `webrtc-signaling.md` §4.1 — per-call pairwise pseudonym shape; no
    // principal DID / handle leaks to the TURN operator.
    assert!(turn_username.starts_with("ck_pseudonym_call_"));
    assert!(!turn_username.contains("alice"));
    assert!(!turn_username.contains("did:web"));
    let turn_credential = ice["turn_servers"][0]["credential"].as_str().unwrap();
    assert!(!turn_credential.is_empty());

    // §4.1 — bucket fields are present, well-formed, and feed the signature.
    assert_eq!(ice["bucket_seconds"], 300);
    let issued_at = chrono::DateTime::parse_from_rfc3339(ice["issued_at"].as_str().unwrap())
        .unwrap()
        .timestamp();
    let issued_at_bucket =
        chrono::DateTime::parse_from_rfc3339(ice["issued_at_bucket"].as_str().unwrap())
            .unwrap()
            .timestamp();
    assert_eq!(
        issued_at_bucket,
        (issued_at.div_euclid(300)) * 300,
        "issued_at_bucket must equal floor(issued_at / bucket_seconds) * bucket_seconds"
    );
    assert!(
        ice["signature"]["sig"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "ICE config must be signed over canonical bytes including the bucket fields"
    );

    let refreshed: Value = TestClient::post(format!(
        "http://server/_cokret/self/calls/{session_id}/ice-config/refresh"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .json(&serde_json::json!({
        "realm_id": DEMO_REALM_ID,
        "actor_id": "did:web:alice.example",
        "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001"
    }))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(refreshed["refreshed"], true);
    assert_eq!(refreshed["turn_servers"][0]["username"], turn_username);
    assert_ne!(
        refreshed["turn_servers"][0]["credential"].as_str().unwrap(),
        turn_credential
    );

    let unsigned_signal = TestClient::post(format!(
        "http://server/_cokret/self/webrtc/sessions/{session_id}/signals"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .json(&serde_json::json!({
        "message_type": "offer",
        "payload": {"description_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
    }))
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(unsigned_signal.status_code.unwrap().as_u16(), 400);

    let signal: Value = TestClient::post(format!(
        "http://server/_cokret/self/webrtc/sessions/{session_id}/signals"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .json(&serde_json::json!({
        "message_type": "offer",
        "payload": {
            "description_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "encrypted_description_ref": "ck:blob:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        },
        "proofs": [{"kid": "did:web:alice.example#device", "sig": "dev"}]
    }))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(signal["seq"], 1);
    assert_eq!(signal["next_cursor"], "1");
    assert_eq!(signal["call_state"], "connecting");

    let events: Value = TestClient::get(format!(
        "http://server/_cokret/self/webrtc/sessions/{session_id}/signals?since=0"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(events["events"].as_array().unwrap().len(), 1);
    assert_eq!(events["events"][0]["type"], "offer");
    assert_eq!(events["events"][0]["sender"], "did:web:alice.example");
    assert_eq!(events["events"][0]["call_state_after"], "connecting");
    assert_eq!(events["call_state"], "connecting");

    let answer: Value = TestClient::post(format!(
        "http://server/_cokret/self/webrtc/sessions/{session_id}/signals"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .json(&serde_json::json!({
        "message_type": "answer",
        "payload": {
            "description_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        },
        "proofs": [{"kid": "did:web:alice.example#device", "sig": "dev"}]
    }))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(answer["seq"], 2);
    assert_eq!(answer["call_state"], "active");

    let hangup: Value = TestClient::post(format!(
        "http://server/_cokret/self/webrtc/sessions/{session_id}/signals"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .json(&serde_json::json!({
        "message_type": "hangup",
        "payload": {"reason": "test-end"},
        "proofs": [{"kid": "did:web:alice.example#device", "sig": "dev"}]
    }))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(hangup["seq"], 3);
    assert_eq!(hangup["call_state"], "ended");

    let mut denied_recording = TestClient::post(format!(
        "http://server/_cokret/self/calls/{session_id}/recording/start"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .json(&serde_json::json!({"realm_id": DEMO_REALM_ID}))
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(
        denied_recording.status_code.unwrap(),
        StatusCode::PRECONDITION_FAILED
    );
    let denied_body: Value = denied_recording.take_json().await.unwrap();
    assert_eq!(denied_body["error"]["code"], "recording_policy_violation");

    let empty_events: Value = TestClient::get(format!(
        "http://server/_cokret/self/webrtc/sessions/{session_id}/signals?since=3"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert!(empty_events["events"].as_array().unwrap().is_empty());

    let recording_session: Value = TestClient::post("http://server/_cokret/self/webrtc/sessions")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "participants": ["did:web:alice.example"],
            "mode": "sfu",
            "recording_policy": "allow",
            "ttl_ms": 60000
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(recording_session["mode"], "sfu");
    assert_eq!(recording_session["recording_policy"], "allow");
    let recording_session_id = recording_session["session_id"].as_str().unwrap();
    // `webrtc-signaling.md` §3 — recording requires `ck.call.record`; the
    // realm-member creator does not implicitly hold it.
    grant_call_capability(
        &state,
        DEMO_REALM_ID,
        "did:web:alice.example",
        "ck.call.record",
    );
    let recording: Value = TestClient::post(format!(
        "http://server/_cokret/self/calls/{recording_session_id}/recording/start"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .json(&serde_json::json!({"realm_id": DEMO_REALM_ID}))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(recording["ok"], true);
    assert_eq!(recording["recording_policy"], "allow");
    assert_eq!(recording["recording_started_by"], "did:web:alice.example");
    assert!(
        recording["recording_blob_ref"]
            .as_str()
            .unwrap()
            .starts_with("ck:blob:sha256:")
    );

    let closed: Value = TestClient::delete(format!(
        "http://server/_cokret/self/webrtc/sessions/{session_id}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(closed["ok"], true);

    let after_close = TestClient::get(format!(
        "http://server/_cokret/self/webrtc/sessions/{session_id}/signals"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state))
    .await;
    assert_eq!(after_close.status_code.unwrap().as_u16(), 404);
}

#[tokio::test]
async fn rtc_media_token_uses_projected_media_service_epoch() {
    let state = AppState::new(test_config(), Db { pool: None });
    install_media_service_epoch(&state, good_media_service_epoch());
    let token = dev_token(state.clone()).await;
    let session_id = create_webrtc_session_for_alice(state.clone(), &token).await;

    let focus_signal: Value = TestClient::post(format!(
        "http://server/_cokret/self/webrtc/sessions/{session_id}/signals"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .json(&serde_json::json!({
        "message_type": "focus_join",
        "payload": {
            "foci_preferred": ["ck:focus:mediasoup:blue", "ck:focus:livekit:green"]
        },
        "proofs": [{"kid": "did:web:alice.example#device", "sig": "dev"}]
    }))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(focus_signal["seq"], 1);

    let issued_before = chrono::Utc::now();
    let token_response: Value = TestClient::post("http://server/_cokret/self/rtc/token")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "call_id": session_id,
            "actor_id": "did:web:alice.example",
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "focus_id": "ck:focus:mediasoup:blue"
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(
        token_response["connect_url"],
        "wss://media.example/mediasoup"
    );
    // Spec `CallMediaTokenExchangeOutcome` required fields: focus_id + type
    // identify the chosen focus and its backend protocol; `todos` is not a
    // schema field and must not appear.
    assert_eq!(token_response["focus_id"], "ck:focus:mediasoup:blue");
    assert_eq!(token_response["type"], "mediasoup");
    assert!(token_response.get("todos").is_none());
    assert_eq!(
        token_response["participant_binding"]["issuer_kid"],
        "did:web:media.example#mediasoup-2026-05"
    );
    assert_eq!(
        token_response["participant_binding"]["realm_id"],
        DEMO_REALM_ID
    );
    assert_eq!(token_response["participant_binding"]["call_id"], session_id);
    assert_eq!(
        token_response["participant_binding"]["device_id"],
        "ck:device:01904100-0000-7000-8000-a11ce0000001"
    );
    assert_eq!(
        token_response["participant_binding"]["focus_id"],
        "ck:focus:mediasoup:blue"
    );
    assert!(
        token_response["service_signature"]
            .as_str()
            .unwrap()
            .starts_with("did:web:media.example#mediasoup-2026-05:eddsa-ed25519:")
    );

    let expires_at =
        chrono::DateTime::parse_from_rfc3339(token_response["expires_at"].as_str().unwrap())
            .unwrap()
            .with_timezone(&chrono::Utc);
    assert!(
        expires_at <= issued_before + chrono::Duration::seconds(605),
        "realm TTL must be capped at the 600s media-token ceiling"
    );

    let backend_token = token_response["backend_token"].as_str().unwrap();
    assert!(backend_token.starts_with("mediasoup."));
    let backend_payload = decode_backend_token_payload(backend_token);
    assert_eq!(
        backend_payload["iss"],
        "did:web:media.example#mediasoup-2026-05"
    );
    assert_eq!(backend_payload["aud"], "mediasoup-demo");
    assert_eq!(backend_payload["provider"], "mediasoup");
    assert_eq!(backend_payload["realm_id"], DEMO_REALM_ID);
    assert_eq!(backend_payload["call_id"], session_id);
    assert_eq!(backend_payload["actor_id"], "did:web:alice.example");
    assert_eq!(
        backend_payload["device_id"],
        "ck:device:01904100-0000-7000-8000-a11ce0000001"
    );

    let second_token_response: Value = TestClient::post("http://server/_cokret/self/rtc/token")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "call_id": session_id,
            "actor_id": "did:web:alice.example",
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "focus_id": "ck:focus:mediasoup:blue"
        }))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert_ne!(
        second_token_response["backend_token"], token_response["backend_token"],
        "backend tokens must include issuer entropy and not be deterministic placeholders"
    );
}

#[tokio::test]
async fn rtc_media_token_rejects_epoch_and_focus_mismatches() {
    let state = AppState::new(test_config(), Db { pool: None });
    install_media_service_epoch(&state, good_media_service_epoch());
    let token = dev_token(state.clone()).await;
    let session_id = create_webrtc_session_for_alice(state.clone(), &token).await;

    let _: Value = TestClient::post(format!(
        "http://server/_cokret/self/webrtc/sessions/{session_id}/signals"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .json(&serde_json::json!({
        "message_type": "focus_join",
        "payload": {"foci_preferred": ["ck:focus:mediasoup:blue"]},
        "proofs": [{"kid": "did:web:alice.example#device", "sig": "dev"}]
    }))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();

    let mut focus_mismatch = TestClient::post("http://server/_cokret/self/rtc/token")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "call_id": session_id,
            "actor_id": "did:web:alice.example",
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "focus_id": "ck:focus:livekit:green"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    let focus_mismatch_body: Value = focus_mismatch.take_json().await.unwrap();
    assert_eq!(focus_mismatch_body["error"]["code"], "focus_mismatch");

    install_media_service_epoch(
        &state,
        serde_json::json!({
            "service_id": "did:web:media.example",
            "foci": [{
                "focus_id": "ck:focus:mediasoup:blue",
                "backend": "mediasoup",
                "connect_url": "wss://media.example/mediasoup",
                "issuer_kid": "did:web:rogue.example#kid-1",
                "audience": "mediasoup-demo"
            }]
        }),
    );
    let mut issuer_mismatch = TestClient::post("http://server/_cokret/self/rtc/token")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "call_id": session_id,
            "actor_id": "did:web:alice.example",
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "focus_id": "ck:focus:mediasoup:blue"
        }))
        .send(&app_from_state(state))
        .await;
    let issuer_mismatch_body: Value = issuer_mismatch.take_json().await.unwrap();
    assert_eq!(
        issuer_mismatch_body["error"]["code"],
        "token_issuer_unauthorised"
    );
}

#[tokio::test]
async fn rtc_media_token_rejects_non_member_actor() {
    let state = AppState::new(test_config(), Db { pool: None });
    install_media_service_epoch(&state, good_media_service_epoch());
    let token = dev_token(state.clone()).await;
    let session_id = create_webrtc_session_for_alice(state.clone(), &token).await;
    let bob_token = dev_token_for_device(
        state.clone(),
        "did:web:bob.example",
        "ck:device:01904100-0000-7000-8000-b0b000000001",
        "Bob Phone",
    )
    .await;

    let mut response = TestClient::post("http://server/_cokret/self/rtc/token")
        .add_header("authorization", format!("Bearer {bob_token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "call_id": session_id,
            "actor_id": "did:web:bob.example",
            "device_id": "ck:device:01904100-0000-7000-8000-b0b000000001",
            "focus_id": "ck:focus:livekit:green"
        }))
        .send(&app_from_state(state))
        .await;
    assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "capability_denied");
}

/// LiveKit API Key used in tests. `bindings/livekit.md` §2 maps the focus
/// `issuer_kid` to the LiveKit API Key, so the configured key MUST equal the
/// `livekit:green` focus `issuer_kid` in [`good_media_service_epoch`].
const TEST_LIVEKIT_API_KEY: &str = "did:web:media.example#livekit-2026-05";
const TEST_LIVEKIT_API_SECRET: &str = "test-livekit-api-secret-0123456789";

/// `test_config()` with the LiveKit API Key/Secret populated so the
/// `livekit` focus can mint a real HS256 JWT instead of failing closed.
fn livekit_test_config() -> AppConfig {
    let mut config = test_config();
    config.livekit.api_key = Some(TEST_LIVEKIT_API_KEY.to_owned());
    config.livekit.api_secret = Some(TEST_LIVEKIT_API_SECRET.to_owned());
    config
}

/// Verify a LiveKit JWT (`header.payload.signature`) HMAC-SHA256 signature
/// over `header.payload` using the configured API Secret. Returns the decoded
/// claims on success.
fn verify_livekit_jwt(token: &str, api_secret: &[u8]) -> Value {
    let parts = token.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 3, "LiveKit token must be a three-segment JWT");
    let header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts[0])
            .expect("jwt header base64url"),
    )
    .expect("jwt header json");
    assert_eq!(header["alg"], "HS256");
    assert_eq!(header["typ"], "JWT");

    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let mut mac =
        <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(api_secret).expect("hmac key");
    mac.update(signing_input.as_bytes());
    let expected = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    assert_eq!(parts[2], expected, "LiveKit JWT HMAC-SHA256 must verify");

    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts[1])
            .expect("jwt payload base64url"),
    )
    .expect("jwt payload json")
}

#[tokio::test]
async fn rtc_media_token_livekit_backend_token_carries_livekit_claims() {
    let state = AppState::new(livekit_test_config(), Db { pool: None });
    install_media_service_epoch(&state, good_media_service_epoch());
    let token = dev_token(state.clone()).await;
    let session_id = create_webrtc_session_for_alice(state.clone(), &token).await;

    // Steer focus selection to the livekit focus via foci_preferred[].
    let _: Value = TestClient::post(format!(
        "http://server/_cokret/self/webrtc/sessions/{session_id}/signals"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .json(&serde_json::json!({
        "message_type": "focus_join",
        "payload": {"foci_preferred": ["ck:focus:livekit:green"]},
        "proofs": [{"kid": "did:web:alice.example#device", "sig": "dev"}]
    }))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();

    let issued_before = chrono::Utc::now();
    let token_response: Value = TestClient::post("http://server/_cokret/self/rtc/token")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "call_id": session_id,
            "actor_id": "did:web:alice.example",
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "focus_id": "ck:focus:livekit:green",
            "desired_media": {"audio": true, "video": true, "screen": false}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(token_response["type"], "livekit");
    assert_eq!(token_response["connect_url"], "wss://media.example/livekit");

    // `bindings/livekit.md` §2 — the backend_token is a real LiveKit JWT:
    // `base64url(header).base64url(payload).base64url(HMAC-SHA256)`. It MUST
    // NOT carry the legacy `livekit.` provider prefix, header MUST be
    // `{alg:HS256,typ:JWT}`, and the signature MUST verify under the
    // configured API Secret.
    let backend_token = token_response["backend_token"].as_str().unwrap();
    assert!(
        !backend_token.starts_with("livekit."),
        "LiveKit backend_token must be a standard JWT, not the legacy envelope"
    );
    let claims = verify_livekit_jwt(backend_token, TEST_LIVEKIT_API_SECRET.as_bytes());
    // §2: `iss` = LiveKit API Key.
    assert_eq!(claims["iss"], TEST_LIVEKIT_API_KEY);
    assert_eq!(claims["sub"], token_response["participant_identity"]);
    // §2: `name` MUST NOT leak actor identity — equals participant_identity.
    assert_eq!(claims["name"], token_response["participant_identity"]);
    assert_eq!(claims["video"]["roomJoin"], true);
    assert_eq!(claims["video"]["canPublish"], true);
    assert_eq!(claims["video"]["canSubscribe"], true);
    assert_eq!(claims["video"]["recorder"], false);
    assert_eq!(claims["video"]["hidden"], false);
    let room = claims["video"]["room"].as_str().unwrap();
    assert!(room.starts_with("ck_call_"));
    assert!(!room.contains(&session_id));
    let sources = claims["video"]["canPublishSources"].as_array().unwrap();
    assert!(sources.iter().any(|s| s == "microphone"));
    assert!(sources.iter().any(|s| s == "camera"));
    assert!(!sources.iter().any(|s| s == "screen_share"));
    // §2: `iat`/`nbf`/`exp` are NumericDate (Unix epoch seconds) and `exp`
    // MUST be ≤ iat + 600s.
    let iat = claims["iat"].as_i64().expect("iat numeric");
    let nbf = claims["nbf"].as_i64().expect("nbf numeric");
    let exp = claims["exp"].as_i64().expect("exp numeric");
    assert_eq!(nbf, iat);
    assert!(exp > iat, "exp must be after iat");
    assert!(
        exp - iat <= 600,
        "LiveKit token exp must be within the 600s media-token ceiling"
    );
    assert!(
        exp <= issued_before.timestamp() + 605,
        "LiveKit token exp must respect the 600s ceiling from issuance"
    );
}

#[tokio::test]
async fn admin_realm_media_service_renders_projected_cell() {
    let state = AppState::new(test_config(), Db { pool: None });
    install_media_service_epoch(&state, good_media_service_epoch());
    let token = dev_token(state.clone()).await;

    let media_service: Value = TestClient::get(format!(
        "http://server/_soland/admin/realms/{DEMO_REALM_ID}/media-service"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(media_service["realm_id"], DEMO_REALM_ID);
    assert_eq!(media_service["service_id"], "did:web:media.example");
    let foci = media_service["foci"].as_array().unwrap();
    assert_eq!(foci.len(), 2);
    assert!(
        foci.iter()
            .any(|focus| focus["focus_id"] == "ck:focus:livekit:green")
    );

    // A Realm with no committed epoch renders an empty (but well-typed) view.
    let other_realm = "ck:realm:0196419b-0000-7000-8000-0000000000ff";
    let empty: Value = TestClient::get(format!(
        "http://server/_soland/admin/realms/{other_realm}/media-service"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(empty["realm_id"], other_realm);
    assert!(empty.get("foci").is_none() || empty["foci"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn webrtc_moderation_signal_projects_removed_participants_and_end_for_all() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    // §3a — the moderator (alice) MUST hold `ck.call.moderate`.
    grant_call_capability(
        &state,
        DEMO_REALM_ID,
        "did:web:alice.example",
        "ck.call.moderate",
    );
    let bob = "did:web:bob.example";
    let bob_device = "ck:device:01904100-0000-7000-8000-b0b000000001";

    // Session with bob as an extra participant so the moderation targets a
    // real call leg.
    let session: Value = TestClient::post("http://server/_cokret/self/webrtc/sessions")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "participants": ["did:web:alice.example", bob],
            "mode": "sfu",
            "recording_policy": "none",
            "ttl_ms": 60000
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let session_id = session["session_id"].as_str().unwrap().to_owned();

    // `moderation{action=kick}` is accepted and projected into
    // `removed_participants[]` with the pinned device id.
    let kick: Value = TestClient::post(format!(
        "http://server/_cokret/self/webrtc/sessions/{session_id}/signals"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .json(&serde_json::json!({
        "message_type": "moderation",
        "payload": {
            "signal_type": "moderation",
            "data": {
                "action": "kick",
                "target_actor_id": bob,
                "target_device_id": bob_device,
                "reason": "policy_violation"
            }
        },
        "proofs": [{"kid": "did:web:alice.example#device", "sig": "dev"}]
    }))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(kick["seq"], 1);
    // kick leaves the call lifecycle running (active is not required, but the
    // call MUST NOT be terminal).
    assert_ne!(kick["call_state"], "ended");

    // The removed-participants projection is materialized on the stored record.
    let record = state
        .persistence
        .webrtc()
        .get(&session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.removed_participants.len(), 1);
    assert_eq!(record.removed_participants[0].actor_id, bob);
    assert_eq!(
        record.removed_participants[0].device_id.as_deref(),
        Some(bob_device)
    );
    assert_eq!(record.removed_participants[0].action, "kick");

    // `moderation{action=end_for_all}` drives the call to the terminal `ended`
    // state (webrtc-signaling.md §3a).
    let end: Value = TestClient::post(format!(
        "http://server/_cokret/self/webrtc/sessions/{session_id}/signals"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .json(&serde_json::json!({
        "message_type": "moderation",
        "payload": { "data": { "action": "end_for_all" } },
        "proofs": [{"kid": "did:web:alice.example#device", "sig": "dev"}]
    }))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(end["seq"], 2);
    assert_eq!(end["call_state"], "ended");
}

#[tokio::test]
async fn webrtc_ban_blocks_removed_participant_token_reissue() {
    let state = AppState::new(livekit_test_config(), Db { pool: None });
    install_media_service_epoch(&state, good_media_service_epoch());
    let alice_token = dev_token(state.clone()).await;
    // §3a — the moderator (alice) MUST hold `ck.call.moderate` to ban.
    grant_call_capability(
        &state,
        DEMO_REALM_ID,
        "did:web:alice.example",
        "ck.call.moderate",
    );
    let bob = "did:web:bob.example";
    let bob_device = "ck:device:01904100-0000-7000-8000-b0b000000001";
    let bob_token = dev_token_for_device(state.clone(), bob, bob_device, "Bob Phone").await;
    add_test_realm_member(&state, DEMO_REALM_ID, bob);

    let session: Value = TestClient::post("http://server/_cokret/self/webrtc/sessions")
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "participants": ["did:web:alice.example", bob],
            "mode": "sfu",
            "recording_policy": "none",
            "ttl_ms": 60000
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let session_id = session["session_id"].as_str().unwrap().to_owned();

    // Before the ban, bob can exchange a media token.
    let pre_ban: Value = TestClient::post("http://server/_cokret/self/rtc/token")
        .add_header("authorization", format!("Bearer {bob_token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "call_id": session_id,
            "actor_id": bob,
            "device_id": bob_device,
            "focus_id": "ck:focus:livekit:green"
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(pre_ban["focus_id"], "ck:focus:livekit:green");

    // Alice bans bob (actor-wide; no device id).
    let ban: Value = TestClient::post(format!(
        "http://server/_cokret/self/webrtc/sessions/{session_id}/signals"
    ))
    .add_header("authorization", format!("Bearer {alice_token}"), true)
    .json(&serde_json::json!({
        "message_type": "moderation",
        "payload": { "data": { "action": "ban", "target_actor_id": bob } },
        "proofs": [{"kid": "did:web:alice.example#device", "sig": "dev"}]
    }))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(ban["seq"], 1);

    let record = state
        .persistence
        .webrtc()
        .get(&session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.removed_participants.len(), 1);
    assert_eq!(record.removed_participants[0].action, "ban");
    // Actor-wide ban omits device_id.
    assert!(record.removed_participants[0].device_id.is_none());

    // After the ban, bob's token re-issue is refused with
    // `call_participant_removed` (webrtc-signaling.md §3a).
    let mut post_ban = TestClient::post("http://server/_cokret/self/rtc/token")
        .add_header("authorization", format!("Bearer {bob_token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "call_id": session_id,
            "actor_id": bob,
            "device_id": bob_device,
            "focus_id": "ck:focus:livekit:green"
        }))
        .send(&app_from_state(state))
        .await;
    assert_eq!(post_ban.status_code, Some(StatusCode::FORBIDDEN));
    let body: Value = post_ban.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "call_participant_removed");
}

/// Grant `subject` a realm-scoped call capability (`action`) in the shared
/// authz engine, mirroring what the capability-grant projection would fold in.
fn grant_call_capability(state: &AppState, realm_id: &str, subject: &str, action: &str) {
    state.authz.create_grant(
        realm_id.to_owned(),
        "did:web:alice.example".to_owned(),
        subject.to_owned(),
        realm_id.to_owned(),
        vec![action.to_owned()],
        vec![],
    );
}

/// Create an sfu session in DEMO_REALM with alice (owner) + bob as
/// participants and bob registered as a realm member. Returns the session id.
async fn create_session_with_bob(state: &AppState, alice_token: &str, bob: &str) -> String {
    add_test_realm_member(state, DEMO_REALM_ID, bob);
    let session: Value = TestClient::post("http://server/_cokret/self/webrtc/sessions")
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "participants": ["did:web:alice.example", bob],
            "mode": "sfu",
            "recording_policy": "allow",
            "ttl_ms": 60000
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    session["session_id"].as_str().unwrap().to_owned()
}

fn dev_proof() -> Value {
    serde_json::json!([{"kid": "did:web:bob.example#device", "sig": "dev"}])
}

#[tokio::test]
async fn webrtc_moderation_requires_moderate_capability() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice_token = dev_token(state.clone()).await;
    let bob = "did:web:bob.example";
    let bob_device = "ck:device:01904100-0000-7000-8000-b0b000000001";
    let bob_token = dev_token_for_device(state.clone(), bob, bob_device, "Bob Phone").await;
    let session_id = create_session_with_bob(&state, &alice_token, bob).await;

    // Bob (realm member + participant, but no `ck.call.moderate`) cannot kick.
    let mut denied = TestClient::post(format!(
        "http://server/_cokret/self/webrtc/sessions/{session_id}/signals"
    ))
    .add_header("authorization", format!("Bearer {bob_token}"), true)
    .json(&serde_json::json!({
        "message_type": "moderation",
        "payload": { "data": { "action": "kick", "target_actor_id": "did:web:alice.example" } },
        "proofs": dev_proof()
    }))
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(denied.status_code, Some(StatusCode::FORBIDDEN));
    let body: Value = denied.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "call_moderation_unauthorised");

    // After granting `ck.call.moderate`, the same moderation frame is accepted.
    grant_call_capability(&state, DEMO_REALM_ID, bob, "ck.call.moderate");
    let accepted: Value = TestClient::post(format!(
        "http://server/_cokret/self/webrtc/sessions/{session_id}/signals"
    ))
    .add_header("authorization", format!("Bearer {bob_token}"), true)
    .json(&serde_json::json!({
        "message_type": "moderation",
        "payload": { "data": { "action": "kick", "target_actor_id": "did:web:alice.example" } },
        "proofs": dev_proof()
    }))
    .send(&app_from_state(state))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(accepted["seq"], 1);
}

#[tokio::test]
async fn webrtc_screen_share_requires_screen_share_capability() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice_token = dev_token(state.clone()).await;
    let bob = "did:web:bob.example";
    let bob_device = "ck:device:01904100-0000-7000-8000-b0b000000001";
    let bob_token = dev_token_for_device(state.clone(), bob, bob_device, "Bob Phone").await;
    let session_id = create_session_with_bob(&state, &alice_token, bob).await;

    let screen_on = serde_json::json!({
        "message_type": "media_state",
        "payload": { "data": { "screen": { "enabled": true, "source_id": "screen_01" } } },
        "proofs": dev_proof()
    });

    // No `ck.call.screen_share` → media_permission_denied.
    let mut denied = TestClient::post(format!(
        "http://server/_cokret/self/webrtc/sessions/{session_id}/signals"
    ))
    .add_header("authorization", format!("Bearer {bob_token}"), true)
    .json(&screen_on)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(denied.status_code, Some(StatusCode::FORBIDDEN));
    let body: Value = denied.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "media_permission_denied");

    // A `media_state` that does NOT enable screen share is not gated.
    let no_screen: Value = TestClient::post(format!(
        "http://server/_cokret/self/webrtc/sessions/{session_id}/signals"
    ))
    .add_header("authorization", format!("Bearer {bob_token}"), true)
    .json(&serde_json::json!({
        "message_type": "media_state",
        "payload": { "data": { "screen": { "enabled": false } } },
        "proofs": dev_proof()
    }))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(no_screen["seq"], 1);

    // After granting `ck.call.screen_share`, screen-on is accepted.
    grant_call_capability(&state, DEMO_REALM_ID, bob, "ck.call.screen_share");
    let accepted: Value = TestClient::post(format!(
        "http://server/_cokret/self/webrtc/sessions/{session_id}/signals"
    ))
    .add_header("authorization", format!("Bearer {bob_token}"), true)
    .json(&screen_on)
    .send(&app_from_state(state))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(accepted["seq"], 2);
}

#[tokio::test]
async fn webrtc_recording_requires_record_capability() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice_token = dev_token(state.clone()).await;
    let bob = "did:web:bob.example";
    let bob_device = "ck:device:01904100-0000-7000-8000-b0b000000001";
    let bob_token = dev_token_for_device(state.clone(), bob, bob_device, "Bob Phone").await;
    let session_id = create_session_with_bob(&state, &alice_token, bob).await;

    // recording_policy=allow but bob lacks `ck.call.record` → recording_denied.
    let mut denied = TestClient::post(format!(
        "http://server/_cokret/self/calls/{session_id}/recording/start"
    ))
    .add_header("authorization", format!("Bearer {bob_token}"), true)
    .json(&serde_json::json!({"realm_id": DEMO_REALM_ID}))
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(denied.status_code, Some(StatusCode::FORBIDDEN));
    let body: Value = denied.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "recording_denied");

    // After granting `ck.call.record`, the recording starts.
    grant_call_capability(&state, DEMO_REALM_ID, bob, "ck.call.record");
    let recording: Value = TestClient::post(format!(
        "http://server/_cokret/self/calls/{session_id}/recording/start"
    ))
    .add_header("authorization", format!("Bearer {bob_token}"), true)
    .json(&serde_json::json!({"realm_id": DEMO_REALM_ID}))
    .send(&app_from_state(state))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(recording["ok"], true);
    assert_eq!(recording["recording_started_by"], bob);
}

async fn create_webrtc_session_for_alice(state: AppState, token: &str) -> String {
    let session: Value = TestClient::post("http://server/_cokret/self/webrtc/sessions")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "participants": ["did:web:alice.example"],
            "mode": "sfu",
            "recording_policy": "none",
            "ttl_ms": 60000
        }))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    session["session_id"].as_str().unwrap().to_owned()
}

fn install_media_service_epoch(state: &AppState, media_service: Value) {
    let cell_id = CellRef::new(format!(
        "ck:cell:ck.component.realm.media_service.v1:{DEMO_REALM_ID}"
    ))
    .unwrap();
    state.projection.lock().unwrap().cells.insert(
        cell_id,
        CellState::Value(serde_json::json!({ "media_service": media_service })),
    );
}

fn good_media_service_epoch() -> Value {
    serde_json::json!({
        "service_id": "did:web:media.example",
        "e2ee_key_sources_allowed": ["mls_epoch"],
        "foci": [
            {
                "focus_id": "ck:focus:livekit:green",
                "backend": "livekit",
                "connect_url": "wss://media.example/livekit",
                "issuer_kid": "did:web:media.example#livekit-2026-05",
                "audience": "livekit-demo",
                "ttl_seconds": 300,
                "e2ee_key_source": "mls_epoch"
            },
            {
                "focus_id": "ck:focus:mediasoup:blue",
                "backend": "mediasoup",
                "connect_url": "wss://media.example/mediasoup",
                "issuer_kid": "did:web:media.example#mediasoup-2026-05",
                "audience": "mediasoup-demo",
                "ttl_seconds": 900,
                "e2ee_key_source": "mls_epoch"
            }
        ]
    })
}

fn decode_backend_token_payload(token: &str) -> Value {
    let parts = token.split('.').collect::<Vec<_>>();
    assert_eq!(
        parts.len(),
        3,
        "backend token should be provider.payload.sig"
    );
    let bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("backend token payload base64url");
    serde_json::from_slice(&bytes).expect("backend token payload json")
}
