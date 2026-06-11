//! Integration tests — `devices_webrtc` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

#![allow(unused_imports)]
use cokret_sdk::CellRef;
use cokret_sdk::lattice::CellState;

use super::common::*;

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
                "key": "emtleQ"
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
                "key": "emtleQ"
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
                    && event["target"]["new_device_id"] == sibling
            })
    );
}

#[tokio::test]
async fn device_pairing_challenge_and_authorization_surface_work() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let unauthenticated = TestClient::post("http://server/_soland/self/devices/pairing-challenge")
        .json(&serde_json::json!({"device_id": "ck:device:01904100-0000-7000-8000-9b04e0000007"}))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthenticated.status_code, Some(StatusCode::UNAUTHORIZED));

    let challenge: Value = TestClient::post("http://server/_soland/self/devices/pairing-challenge")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({"device_id": "ck:device:01904100-0000-7000-8000-9b04e0000007"}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        challenge["challenge_id"]
            .as_str()
            .unwrap()
            .starts_with("ck:device_pairing:")
    );
    assert_eq!(
        challenge["device_id"],
        "ck:device:01904100-0000-7000-8000-9b04e0000007"
    );
    assert_eq!(
        challenge["production_gap"],
        "device_pairing_proof_verification"
    );

    let authorized: Value =
        TestClient::post("http://server/_soland/self/devices/authorize-pairing")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&serde_json::json!({
                "challenge_id": challenge["challenge_id"],
                "device_id": "ck:device:01904100-0000-7000-8000-9b04e0000007",
                "display_name": "Paired Phone",
                "proof": {"alg": "dev-none"}
            }))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(authorized["status"], "authorized");
    assert_eq!(
        authorized["device"]["device_id"],
        "ck:device:01904100-0000-7000-8000-9b04e0000007"
    );
    assert_eq!(
        authorized["authorization_event"]["event_kind"],
        "ck.device.pairing.authorized"
    );
    assert_eq!(
        authorized["production_gap"],
        "authorization_event_not_yet_in_operation_stream"
    );
    let devices: Value = TestClient::get("http://server/_soland/self/devices")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(devices["actor"], "did:web:alice.example");
    assert_eq!(
        devices["current_device_id"],
        "ck:device:01904100-0000-7000-8000-a11ce0000001"
    );
    assert!(devices["devices"].as_array().unwrap().iter().any(|device| {
        device["device_id"] == "ck:device:01904100-0000-7000-8000-9b04e0000007"
            && device["verification_state"] == "verified"
            && device["is_current_session_device"] == false
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
                event["action"] == "device.authorize_pairing"
                    && event["outcome"] == "accepted"
                    && event["target"]["target_device_id"]
                        == "ck:device:01904100-0000-7000-8000-9b04e0000007"
            })
    );
}

#[tokio::test]
async fn device_rename_updates_display_name() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let sibling = "ck:device:01904100-0000-7000-8000-9b04e0000077";

    // Register a sibling device to rename (current session device is
    // alice's own device; pairing gives us a second one).
    let challenge: Value = TestClient::post("http://server/_soland/self/devices/pairing-challenge")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({ "device_id": sibling }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let _: Value = TestClient::post("http://server/_soland/self/devices/authorize-pairing")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "challenge_id": challenge["challenge_id"],
            "device_id": sibling,
            "display_name": "Old Name",
            "proof": {"alg": "dev-none"}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();

    // Unauthenticated rename is rejected.
    let unauth = TestClient::post(format!(
        "http://server/_soland/self/devices/{sibling}/rename"
    ))
    .json(&serde_json::json!({ "display_name": "Hacker" }))
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(unauth.status_code, Some(StatusCode::UNAUTHORIZED));

    // Empty display_name is rejected.
    let empty = TestClient::post(format!(
        "http://server/_soland/self/devices/{sibling}/rename"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .json(&serde_json::json!({ "display_name": "   " }))
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(empty.status_code, Some(StatusCode::BAD_REQUEST));

    // Over-long display_name (>128 chars) is rejected.
    let too_long = TestClient::post(format!(
        "http://server/_soland/self/devices/{sibling}/rename"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .json(&serde_json::json!({ "display_name": "x".repeat(129) }))
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(too_long.status_code, Some(StatusCode::BAD_REQUEST));

    // Renaming an unknown device is a 404.
    let unknown = TestClient::post(
        "http://server/_soland/self/devices/ck:device:01904100-0000-7000-8000-000000000404/rename",
    )
    .add_header("authorization", format!("Bearer {token}"), true)
    .json(&serde_json::json!({ "display_name": "Ghost" }))
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(unknown.status_code, Some(StatusCode::NOT_FOUND));

    // Happy path: rename succeeds and the new name is returned + listed.
    let renamed: Value = TestClient::post(format!(
        "http://server/_soland/self/devices/{sibling}/rename"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .json(&serde_json::json!({ "display_name": "  Work Phone  " }))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(renamed["device_id"], sibling);
    assert_eq!(renamed["display_name"], "Work Phone");

    let devices: Value = TestClient::get("http://server/_soland/self/devices")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(devices["devices"].as_array().unwrap().iter().any(|device| {
        device["device_id"] == sibling && device["display_name"] == "Work Phone"
    }));

    // The rename is audited.
    assert!(
        state
            .persistence
            .audit()
            .snapshot_all()
            .await
            .unwrap()
            .iter()
            .any(|event| {
                event["action"] == "device.rename"
                    && event["outcome"] == "accepted"
                    && event["target"]["display_name"] == "Work Phone"
            })
    );
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
    assert!(turn_username.starts_with("ck-turn-"));
    assert!(!turn_username.contains("alice"));
    assert!(!turn_username.contains("did:web"));
    let turn_credential = ice["turn_servers"][0]["credential"].as_str().unwrap();
    assert!(!turn_credential.is_empty());

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
