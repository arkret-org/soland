//! Integration tests — `devices_webrtc` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

#![allow(unused_imports)]
use super::common::*;

#[tokio::test]
async fn device_pairing_challenge_and_authorization_surface_work() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let unauthenticated = TestClient::post("http://server/api/v1/devices/pairing-challenge")
        .json(&serde_json::json!({"device_id": "cx:device:01904100-0000-7000-8000-9b04e0000007"}))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthenticated.status_code, Some(StatusCode::UNAUTHORIZED));

    let challenge: Value = TestClient::post("http://server/api/v1/devices/pairing-challenge")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({"device_id": "cx:device:01904100-0000-7000-8000-9b04e0000007"}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        challenge["challenge_id"]
            .as_str()
            .unwrap()
            .starts_with("cx:device_pairing:")
    );
    assert_eq!(
        challenge["device_id"],
        "cx:device:01904100-0000-7000-8000-9b04e0000007"
    );
    assert_eq!(
        challenge["production_gap"],
        "device_pairing_proof_verification"
    );

    let authorized: Value = TestClient::post("http://server/api/v1/devices/authorize-pairing")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "challenge_id": challenge["challenge_id"],
            "device_id": "cx:device:01904100-0000-7000-8000-9b04e0000007",
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
        "cx:device:01904100-0000-7000-8000-9b04e0000007"
    );
    assert_eq!(
        authorized["authorization_event"]["event_kind"],
        "cx.device.pairing.authorized"
    );
    assert_eq!(
        authorized["production_gap"],
        "authorization_event_not_yet_in_operation_stream"
    );
    let devices: Value = TestClient::get("http://server/api/v1/devices")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(devices["actor"], "did:web:alice.example");
    assert_eq!(
        devices["current_device_id"],
        "cx:device:01904100-0000-7000-8000-a11ce0000001"
    );
    assert!(devices["devices"].as_array().unwrap().iter().any(|device| {
        device["device_id"] == "cx:device:01904100-0000-7000-8000-9b04e0000007"
            && device["verification_state"] == "verified"
            && device["is_current_session_device"] == false
    }));
    assert!(
        state
            .persistence
            .audit()
            .snapshot_all()
            .unwrap()
            .iter()
            .any(|event| {
                event["action"] == "device.authorize_pairing"
                    && event["outcome"] == "accepted"
                    && event["target"]["target_device_id"]
                        == "cx:device:01904100-0000-7000-8000-9b04e0000007"
            })
    );
}

#[tokio::test]
async fn webrtc_signaling_contracts_work() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let unauthenticated = TestClient::post("http://server/api/v1/webrtc/sessions")
        .json(&serde_json::json!({
            "space_id": DEMO_REALM_ID
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthenticated.status_code, Some(StatusCode::UNAUTHORIZED));

    let session: Value = TestClient::post("http://server/api/v1/webrtc/sessions")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "space_id": DEMO_REALM_ID,
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
    assert!(session_id.starts_with("cx:call:"));
    assert_eq!(session["participants"].as_array().unwrap().len(), 1);
    assert_eq!(session["mode"], "p2p");
    assert_eq!(session["recording_policy"], "none");
    assert_eq!(session["call_state"], "ringing");

    let ice: Value = TestClient::post("http://server/api/v1/calls/ice-config")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "space_id": DEMO_REALM_ID,
            "call_id": session_id,
            "actor_id": "did:web:alice.example",
            "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001"
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(ice["space_id"], DEMO_REALM_ID);
    assert_eq!(ice["call_id"], session_id);
    assert_eq!(ice["turn_servers"].as_array().unwrap().len(), 1);
    let turn_username = ice["turn_servers"][0]["username"].as_str().unwrap();
    assert!(turn_username.starts_with("cx-turn-"));
    assert!(!turn_username.contains("alice"));
    assert!(!turn_username.contains("did:web"));
    let turn_credential = ice["turn_servers"][0]["credential"].as_str().unwrap();
    assert!(!turn_credential.is_empty());

    let refreshed: Value = TestClient::post(format!(
        "http://server/api/v1/calls/{session_id}/ice-config/refresh"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .json(&serde_json::json!({
        "space_id": DEMO_REALM_ID,
        "actor_id": "did:web:alice.example",
        "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001"
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
        "http://server/api/v1/webrtc/sessions/{session_id}/signals"
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
        "http://server/api/v1/webrtc/sessions/{session_id}/signals"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .json(&serde_json::json!({
        "message_type": "offer",
        "payload": {
            "description_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "encrypted_description_ref": "cx:blob:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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
        "http://server/api/v1/webrtc/sessions/{session_id}/signals?since=0"
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
        "http://server/api/v1/webrtc/sessions/{session_id}/signals"
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
        "http://server/api/v1/webrtc/sessions/{session_id}/signals"
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
        "http://server/api/v1/calls/{session_id}/recording/start"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .json(&serde_json::json!({"space_id": DEMO_REALM_ID}))
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(
        denied_recording.status_code.unwrap(),
        StatusCode::PRECONDITION_FAILED
    );
    let denied_body: Value = denied_recording.take_json().await.unwrap();
    assert_eq!(denied_body["error"]["code"], "recording_policy_violation");

    let empty_events: Value = TestClient::get(format!(
        "http://server/api/v1/webrtc/sessions/{session_id}/signals?since=3"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert!(empty_events["events"].as_array().unwrap().is_empty());

    let recording_session: Value = TestClient::post("http://server/api/v1/webrtc/sessions")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "space_id": DEMO_REALM_ID,
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
        "http://server/api/v1/calls/{recording_session_id}/recording/start"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .json(&serde_json::json!({"space_id": DEMO_REALM_ID}))
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
            .starts_with("cx:blob:sha256:")
    );

    let closed: Value =
        TestClient::delete(format!("http://server/api/v1/webrtc/sessions/{session_id}"))
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(closed["ok"], true);

    let after_close = TestClient::get(format!(
        "http://server/api/v1/webrtc/sessions/{session_id}/signals"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state))
    .await;
    assert_eq!(after_close.status_code.unwrap().as_u16(), 404);
}
