//! Integration tests — `devices_webrtc` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

#![allow(unused_imports)]
use arkret_sdk::CellRef;
use arkret_sdk::lattice::CellState;

use super::common::*;

fn device_message_target(kind: &str, content: Value) -> Value {
    serde_json::json!({
        "kind": kind,
        "content": content,
        "expires_at": (chrono::Utc::now() + chrono::Duration::minutes(10))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    })
}

fn pair_device_pubkey(device_id: &str) -> Value {
    let mut seed = [0_u8; 32];
    for (index, byte) in device_id.as_bytes().iter().take(32).enumerate() {
        seed[index] = *byte;
    }
    let signing = SigningKey::from_bytes(&seed);
    serde_json::json!({
        "kty": "OKP",
        "kid": device_id,
        "alg": "EdDSA",
        "public_key": test_ed25519_multibase_public(&signing)
    })
}

async fn post_account_device_pair(
    state: AppState,
    token: &str,
    new_device_id: &str,
    challenge_signature: &str,
) -> (StatusCode, Value) {
    let mut response = TestClient::post("http://server/_arkret/gate/account/device-pair")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "pairing_code": "pairing-code",
            "new_device_pubkey": pair_device_pubkey(new_device_id),
            "challenge_signature": challenge_signature
        }))
        .send(&app_from_state(state))
        .await;
    let status = response.status_code.expect("device-pair status");
    let body = response.take_json().await.expect("device-pair json");
    (status, body)
}

#[tokio::test]
async fn account_device_pair_registers_sibling_via_canonical_gate_route() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let sibling = "ak:device:01904100-0000-7000-8000-9b04e0000008";
    let sibling_pubkey = pair_device_pubkey(sibling);
    let sibling_device_public_key = sibling_pubkey["public_key"].as_str().unwrap();

    let unauthenticated = TestClient::post("http://server/_arkret/gate/account/device-pair")
        .json(&serde_json::json!({
            "pairing_code": "pairing-code",
            "new_device_pubkey": sibling_pubkey.clone(),
            "challenge_signature": "c2ln"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthenticated.status_code, Some(StatusCode::UNAUTHORIZED));

    let paired: Value = TestClient::post("http://server/_arkret/gate/account/device-pair")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "pairing_code": "pairing-code",
            "new_device_pubkey": sibling_pubkey,
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
            .starts_with("ak:event:")
    );
    assert_eq!(paired["device_grant"]["status"], "active");

    let viewer: Value = TestClient::get("http://server/_arkret/self/account/viewer")
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
    let stored = state
        .persistence
        .devices()
        .get("did:web:alice.example", sibling)
        .await
        .unwrap()
        .expect("paired device inventory record");
    assert_eq!(
        stored.payload["device_public_key"],
        sibling_device_public_key
    );
    assert_eq!(
        stored.payload["authorization"]["device_public_key"],
        sibling_device_public_key
    );
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
async fn account_device_pair_rejects_untrusted_authorizers_and_bad_proofs() {
    let state = AppState::new(test_config(), Db { pool: None });
    let actor = "did:web:alice.example";
    let trusted_device = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let unverified_device = "ak:device:01904100-0000-7000-8000-9b04e0000008";
    let first_new_device = "ak:device:01904100-0000-7000-8000-9b04e0000009";
    let second_new_device = "ak:device:01904100-0000-7000-8000-9b04e000000a";
    let third_new_device = "ak:device:01904100-0000-7000-8000-9b04e000000b";

    let trusted_token =
        dev_token_for_device(state.clone(), actor, trusted_device, "Alice Desktop").await;
    let unverified_token =
        dev_token_for_device(state.clone(), actor, unverified_device, "Alice Browser").await;

    let (status, body) =
        post_account_device_pair(state.clone(), &unverified_token, first_new_device, "c2ln").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], "device_not_authorized", "{body}");

    let (status, body) =
        post_account_device_pair(state.clone(), &trusted_token, second_new_device, "!").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "invalid_param", "{body}");

    let (status, body) =
        post_account_device_pair(state.clone(), &trusted_token, trusted_device, "c2ln").await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        body["error"]["code"], "cannot_pair_current_device",
        "{body}"
    );

    let (status, paired) =
        post_account_device_pair(state.clone(), &trusted_token, first_new_device, "c2ln").await;
    assert_eq!(status, StatusCode::OK, "{paired}");
    assert_eq!(paired["device_id"], first_new_device);

    let (status, body) =
        post_account_device_pair(state.clone(), &trusted_token, first_new_device, "c2ln").await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"]["code"], "device_already_authorized", "{body}");

    let mut revoked_target = state
        .persistence
        .devices()
        .get(actor, first_new_device)
        .await
        .unwrap()
        .expect("paired device record");
    revoked_target.revoked_at = Some(chrono::Utc::now());
    state
        .persistence
        .devices()
        .put(&revoked_target)
        .await
        .unwrap();
    let (status, body) =
        post_account_device_pair(state.clone(), &trusted_token, first_new_device, "c2ln").await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"]["code"], "device_revoked", "{body}");

    let mut revoked = state
        .persistence
        .devices()
        .get(actor, trusted_device)
        .await
        .unwrap()
        .expect("trusted device record");
    revoked.revoked_at = Some(chrono::Utc::now());
    state.persistence.devices().put(&revoked).await.unwrap();

    let (status, body) =
        post_account_device_pair(state.clone(), &trusted_token, third_new_device, "c2ln").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["code"], "unauthenticated", "{body}");

    let audit = state.persistence.audit().snapshot_all().await.unwrap();
    assert_eq!(
        audit
            .iter()
            .filter(
                |event| event["action"] == "account.device_pair" && event["outcome"] == "accepted"
            )
            .count(),
        1
    );
}

#[tokio::test]
async fn to_device_pairing_request_reaches_existing_device_and_gate_pair_authorizes_new_device() {
    let state = AppState::new(test_config(), Db { pool: None });
    let actor = "did:web:alice.example";
    let existing_device = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let new_device = "ak:device:01904100-0000-7000-8000-9b04e0000008";
    let existing_token =
        dev_token_for_device(state.clone(), actor, existing_device, "Alice Desktop").await;
    let new_token = dev_token_for_device(state.clone(), actor, new_device, "Alice Browser").await;
    let request_content = serde_json::json!({
        "transaction_id": "txn-device-pair-1",
        "from_device": new_device,
        "timestamp": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "expires_at": (chrono::Utc::now() + chrono::Duration::minutes(10))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "methods": ["ak.sas.v1", "ak.qr.v1"],
        "purpose": "same_principal_device_authorization",
        "pairing_code": "pairing-code",
        "new_device_pubkey": pair_device_pubkey(new_device),
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
        device_message_target("ak.key.verification.request", request_content.clone()),
    );
    let mut actor_targets = serde_json::Map::new();
    actor_targets.insert(actor.to_owned(), Value::Object(device_targets));
    let sent: Value = TestClient::post("http://server/_arkret/self/device_messages")
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
    assert_eq!(subscribe_messages[0]["kind"], "ak.key.verification.request");
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

    let pulled: Value = TestClient::get("http://server/_arkret/self/device_messages")
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

    let approved: Value = TestClient::post("http://server/_arkret/gate/account/device-pair")
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

    let viewer: Value = TestClient::get("http://server/_arkret/self/account/viewer")
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
async fn to_device_capacity_eviction_sets_lost_watermark() {
    let mut config = test_config();
    config.to_device_queue_capacity = 2;
    let state = AppState::new(config, Db { pool: None });
    let alice_token = dev_token(state.clone()).await;
    let bob = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-b0b000000001";
    let bob_token = dev_token_for_device(state.clone(), bob, bob_device, "Bob Phone").await;

    for seq in 1..=3 {
        let mut device_targets = serde_json::Map::new();
        device_targets.insert(
            bob_device.to_owned(),
            device_message_target(
                "ak.key.verification.request",
                serde_json::json!({
                    "transaction_id": format!("capacity-{seq}"),
                    "seq": seq
                }),
            ),
        );
        let mut actor_targets = serde_json::Map::new();
        actor_targets.insert(bob.to_owned(), Value::Object(device_targets));
        let sent: Value = TestClient::post("http://server/_arkret/self/device_messages")
            .add_header("authorization", format!("Bearer {alice_token}"), true)
            .add_header("Idempotency-Key", format!("capacity-{seq}"), true)
            .json(&serde_json::json!({
                "messages": actor_targets
            }))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
        assert_eq!(sent["ok"], true);
        assert_eq!(sent["delivered"][bob][0], bob_device);
    }

    let pulled: Value = TestClient::get("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {bob_token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(pulled["lost"], true);
    let messages = pulled["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["content"]["seq"], 2);
    assert_eq!(messages[1]["content"]["seq"], 3);
    assert!(
        pulled["ack_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );

    let subscribe = account_subscribe_frame(state, Some(&bob_token), "catchup=true").await;
    assert_eq!(subscribe["to_device"]["lost"], true);
    let subscribe_messages = subscribe["to_device"]["messages"].as_array().unwrap();
    assert_eq!(subscribe_messages.len(), 2);
    assert_eq!(subscribe_messages[0]["content"]["seq"], 2);
    assert_eq!(subscribe_messages[1]["content"]["seq"], 3);
}

#[tokio::test]
async fn protocol_device_surface_excludes_pairing_request_scaffold() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let create = TestClient::post("http://server/_arkret/gate/account/device-pairing-requests")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "pairing_code": "pairing-code",
            "new_device_pubkey": {
                "kid": "ak:device:01904100-0000-7000-8000-9b04e0000007",
                "alg": "EdDSA",
                "public_key": "emtleQ"
            },
            "challenge_signature": "c2ln"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(create.status_code, Some(StatusCode::NOT_FOUND));

    let list = TestClient::get("http://server/_arkret/self/devices/pairing-requests")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(list.status_code, Some(StatusCode::NOT_FOUND));

    let devices = TestClient::get("http://server/_arkret/self/devices")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(devices.status_code, Some(StatusCode::NOT_FOUND));

    let soland_challenge = TestClient::post("http://server/_soland/self/devices/pairing-challenge")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "device_id": "ak:device:01904100-0000-7000-8000-9b04e0000007"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(soland_challenge.status_code, Some(StatusCode::NOT_FOUND));

    let soland_authorize = TestClient::post("http://server/_soland/self/devices/authorize-pairing")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "device_id": "ak:device:01904100-0000-7000-8000-9b04e0000007"
        }))
        .send(&app_from_state(state))
        .await;
    assert_eq!(soland_authorize.status_code, Some(StatusCode::NOT_FOUND));
}

#[tokio::test]
async fn rtc_media_token_uses_projected_media_service_epoch() {
    let state = AppState::new(test_config(), Db { pool: None });
    install_media_service_epoch(&state, good_media_service_epoch());
    let token = dev_token(state.clone()).await;
    // Brand-new call: no `ak.call.state` cell yet (the initiator redeems a
    // media token before writing its first `ak.call.state` event). With no
    // committed `session_focus`, the issuer admits the requested focus as long
    // as it is a legal focus within the realm media_service epoch.
    let session_id = new_prefixed_uuid7("ak:call:");

    // `media-service-binding.md` §6 — token exchange requires `ak.call.join`;
    // realm membership alone is insufficient.
    grant_call_capability(
        &state,
        DEMO_REALM_ID,
        "did:web:alice.example",
        "ak.call.join",
    );

    let issued_before = chrono::Utc::now();
    let token_response: Value = TestClient::post("http://server/_arkret/self/rtc/token")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "call_id": session_id,
            "actor_id": "did:web:alice.example",
            "device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001",
            "focus_id": "ak:focus:mediasoup:blue"
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
    assert_eq!(token_response["focus_id"], "ak:focus:mediasoup:blue");
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
        "ak:device:01904100-0000-7000-8000-a11ce0000001"
    );
    assert_eq!(
        token_response["participant_binding"]["focus_id"],
        "ak:focus:mediasoup:blue"
    );
    // `media-service-binding.md` §3 — service_signature is a typed {kid, sig}
    // object, not a packed `<kid>:<alg>:<sig>` string.
    assert_eq!(
        token_response["service_signature"]["kid"],
        "did:web:media.example#mediasoup-2026-05"
    );
    assert!(
        token_response["service_signature"]["sig"]
            .as_str()
            .is_some_and(|sig| !sig.is_empty()),
        "service_signature.sig must be a non-empty base64url detached signature"
    );
    assert!(
        token_response["service_signature"].as_str().is_none(),
        "service_signature must be an object, not a string"
    );

    // §3 — participant_identity is a random `ak:rtc_participant:<uuidv7>` SFU
    // handle, NOT a deterministic hash of the principal tuple.
    let participant_identity = token_response["participant_identity"].as_str().unwrap();
    assert!(
        participant_identity.starts_with("ak:rtc_participant:"),
        "participant_identity must be a typed ak:rtc_participant id"
    );
    assert!(
        arkret_sdk::identifiers::is_lowercase_uuidv7(
            participant_identity
                .strip_prefix("ak:rtc_participant:")
                .unwrap()
        ),
        "participant_identity payload must be a canonical lowercase uuidv7"
    );
    assert_eq!(
        token_response["participant_binding"]["participant_identity"],
        participant_identity
    );

    let issued_at = chrono::DateTime::parse_from_rfc3339(
        token_response["participant_binding"]["issued_at"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
    .with_timezone(&chrono::Utc);
    let expires_at =
        chrono::DateTime::parse_from_rfc3339(token_response["expires_at"].as_str().unwrap())
            .unwrap()
            .with_timezone(&chrono::Utc);
    // §3 — binding carries issued_at and expires_at MUST be strictly later.
    assert!(
        expires_at > issued_at,
        "participant_binding expires_at must be strictly after issued_at"
    );
    assert_eq!(
        token_response["participant_binding"]["expires_at"], token_response["expires_at"],
        "binding expires_at must match the outcome expires_at"
    );
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
        "ak:device:01904100-0000-7000-8000-a11ce0000001"
    );

    let second_token_response: Value = TestClient::post("http://server/_arkret/self/rtc/token")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "call_id": session_id,
            "actor_id": "did:web:alice.example",
            "device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001",
            "focus_id": "ak:focus:mediasoup:blue"
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

/// Keystone acceptance for T4': the inkson flow obtains a media token WITHOUT
/// ever touching any ephemeral signaling session. There is no `ak.call.state`
/// cell yet (the initiator redeems the token before writing its first
/// `ak.call.state` event); authorization is purely realm membership +
/// `ak.call.join`. This is the case the old `participants.contains` /
/// session-not-found gate broke (it 404'd every real inkson call).
#[tokio::test]
async fn rtc_media_token_inkson_flow_no_session_issues_token() {
    let state = AppState::new(livekit_test_config(), Db { pool: None });
    install_media_service_epoch(&state, good_media_service_epoch());
    let token = dev_token(state.clone()).await;
    // A fresh call id with NO `ak.call.state` cell and NO ephemeral session.
    let call_id = new_prefixed_uuid7("ak:call:");

    // Without ak.call.join, even a realm member is denied (§6).
    let mut denied = TestClient::post("http://server/_arkret/self/rtc/token")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "call_id": call_id,
            "actor_id": "did:web:alice.example",
            "device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001",
            "focus_id": "ak:focus:livekit:green"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(denied.status_code, Some(StatusCode::FORBIDDEN));
    assert_eq!(
        denied.take_json::<Value>().await.unwrap()["error"]["code"],
        "capability_denied"
    );

    // Grant ak.call.join → the token is issued against the brand-new call even
    // though no signaling session and no `ak.call.state` cell exist.
    grant_call_capability(
        &state,
        DEMO_REALM_ID,
        "did:web:alice.example",
        "ak.call.join",
    );
    let issued: Value = TestClient::post("http://server/_arkret/self/rtc/token")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "call_id": call_id,
            "actor_id": "did:web:alice.example",
            "device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001",
            "focus_id": "ak:focus:livekit:green"
        }))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(issued["focus_id"], "ak:focus:livekit:green");
    assert_eq!(issued["connect_url"], "wss://media.example/livekit");
    assert!(
        issued["participant_identity"]
            .as_str()
            .unwrap()
            .starts_with("ak:rtc_participant:"),
        "a token MUST be minted with a fresh participant_identity"
    );
    assert_eq!(issued["participant_binding"]["call_id"], call_id);
    assert!(
        issued["service_signature"]["sig"]
            .as_str()
            .is_some_and(|sig| !sig.is_empty()),
        "the issued token MUST carry a detached service signature"
    );
}

#[tokio::test]
async fn rtc_media_token_rejects_epoch_and_focus_mismatches() {
    let state = AppState::new(test_config(), Db { pool: None });
    install_media_service_epoch(&state, good_media_service_epoch());
    let token = dev_token(state.clone()).await;
    let session_id = new_prefixed_uuid7("ak:call:");
    // §6 — grant ak.call.join so the join gate passes and the focus/issuer
    // mismatch errors (not capability_denied) are what surfaces.
    grant_call_capability(
        &state,
        DEMO_REALM_ID,
        "did:web:alice.example",
        "ak.call.join",
    );

    // Commit `session_focus = mediasoup:blue` into the durable `ak.call.state`
    // cell (§4.1 write-once). A token request naming a different focus MUST be
    // rejected with `focus_mismatch`.
    seed_call_state(&state, &session_id, Some("ak:focus:mediasoup:blue"), vec![]);

    let mut focus_mismatch = TestClient::post("http://server/_arkret/self/rtc/token")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "call_id": session_id,
            "actor_id": "did:web:alice.example",
            "device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001",
            "focus_id": "ak:focus:livekit:green"
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
                "focus_id": "ak:focus:mediasoup:blue",
                "backend": "mediasoup",
                "connect_url": "wss://media.example/mediasoup",
                "issuer_kid": "did:web:rogue.example#kid-1",
                "audience": "mediasoup-demo"
            }]
        }),
    );
    let mut issuer_mismatch = TestClient::post("http://server/_arkret/self/rtc/token")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "call_id": session_id,
            "actor_id": "did:web:alice.example",
            "device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001",
            "focus_id": "ak:focus:mediasoup:blue"
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
    let _token = dev_token(state.clone()).await;
    let session_id = new_prefixed_uuid7("ak:call:");
    let bob_token = dev_token_for_device(
        state.clone(),
        "did:web:bob.example",
        "ak:device:01904100-0000-7000-8000-b0b000000001",
        "Bob Phone",
    )
    .await;

    let mut response = TestClient::post("http://server/_arkret/self/rtc/token")
        .add_header("authorization", format!("Bearer {bob_token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "call_id": session_id,
            "actor_id": "did:web:bob.example",
            "device_id": "ak:device:01904100-0000-7000-8000-b0b000000001",
            "focus_id": "ak:focus:livekit:green"
        }))
        .send(&app_from_state(state))
        .await;
    assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "capability_denied");
}

#[tokio::test]
async fn rtc_media_token_requires_call_join_capability() {
    // `media-service-binding.md` §6 — a realm member + call participant that
    // does NOT hold ak.call.join is denied; granting the capability lets the
    // exchange proceed.
    // Use the LiveKit-configured deployment so the oldest-membership default
    // focus (`ak:focus:livekit:green`) can mint a real token once join is held.
    let state = AppState::new(livekit_test_config(), Db { pool: None });
    install_media_service_epoch(&state, good_media_service_epoch());
    // Bootstrap alice (realm owner) so DEMO_REALM exists, then add bob as a
    // member.
    let _alice_token = dev_token(state.clone()).await;
    let bob = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-b0b000000001";
    let bob_token = dev_token_for_device(state.clone(), bob, bob_device, "Bob Phone").await;
    // bob is a realm member; no `ak.call.state` cell exists yet (the new model
    // does not require an ephemeral session to exist before token exchange).
    let session_id = add_member_and_fresh_call(&state, bob);
    let exchange_body = serde_json::json!({
        "realm_id": DEMO_REALM_ID,
        "call_id": session_id,
        "actor_id": bob,
        "device_id": bob_device,
        "focus_id": "ak:focus:livekit:green"
    });

    // No ak.call.join → capability_denied even though bob is a member+participant.
    let mut denied = TestClient::post("http://server/_arkret/self/rtc/token")
        .add_header("authorization", format!("Bearer {bob_token}"), true)
        .json(&exchange_body)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(denied.status_code, Some(StatusCode::FORBIDDEN));
    let denied_body: Value = denied.take_json().await.unwrap();
    assert_eq!(denied_body["error"]["code"], "capability_denied");

    // After granting ak.call.join, the exchange is admitted (focus matches the
    // oldest-membership default).
    grant_call_capability(&state, DEMO_REALM_ID, bob, "ak.call.join");
    let granted: Value = TestClient::post("http://server/_arkret/self/rtc/token")
        .add_header("authorization", format!("Bearer {bob_token}"), true)
        .json(&exchange_body)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(granted["focus_id"], "ak:focus:livekit:green");
    assert!(
        granted["participant_identity"]
            .as_str()
            .unwrap()
            .starts_with("ak:rtc_participant:")
    );
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
    let session_id = new_prefixed_uuid7("ak:call:");
    // §6 — token exchange requires ak.call.join.
    grant_call_capability(
        &state,
        DEMO_REALM_ID,
        "did:web:alice.example",
        "ak.call.join",
    );

    // No committed session_focus: the request directly names the livekit focus,
    // which is admitted because it is a legal focus in the epoch.
    let issued_before = chrono::Utc::now();
    let token_response: Value = TestClient::post("http://server/_arkret/self/rtc/token")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "call_id": session_id,
            "actor_id": "did:web:alice.example",
            "device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001",
            "focus_id": "ak:focus:livekit:green",
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
    assert!(room.starts_with("ak.call_"));
    assert!(!room.contains(&session_id));
    let room_material = format!("{DEMO_REALM_ID}\0{session_id}\0ck:focus:livekit:green");
    let expected_room = format!(
        "ak.call_{}",
        &hex::encode(Sha256::digest(room_material.as_bytes()))[..16]
    );
    assert_eq!(room, expected_room);
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
            .any(|focus| focus["focus_id"] == "ak:focus:livekit:green")
    );

    // A Realm with no committed epoch renders an empty (but well-typed) view.
    let other_realm = "ak:realm:0196419b-0000-7000-8000-0000000000ff";
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
async fn webrtc_ban_blocks_removed_participant_token_reissue() {
    let state = AppState::new(livekit_test_config(), Db { pool: None });
    install_media_service_epoch(&state, good_media_service_epoch());
    let _alice_token = dev_token(state.clone()).await;
    let bob = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-b0b000000001";
    let bob_token = dev_token_for_device(state.clone(), bob, bob_device, "Bob Phone").await;
    add_test_realm_member(&state, DEMO_REALM_ID, bob);

    let session_id = new_prefixed_uuid7("ak:call:");
    // §6 — bob needs ak.call.join to exchange a token before the ban.
    grant_call_capability(&state, DEMO_REALM_ID, bob, "ak.call.join");

    // Before the ban, bob can exchange a media token (no committed focus, so
    // the requested epoch-legal focus is admitted).
    let pre_ban: Value = TestClient::post("http://server/_arkret/self/rtc/token")
        .add_header("authorization", format!("Bearer {bob_token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "call_id": session_id,
            "actor_id": bob,
            "device_id": bob_device,
            "focus_id": "ak:focus:livekit:green"
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(pre_ban["focus_id"], "ak:focus:livekit:green");

    // A moderator actor-wide-bans bob: the durable `ak.call.state.removed_participants[]`
    // projection (`webrtc-signaling.md` §3a) carries a `ban` row with no
    // `device_id`. Seed that cell directly (the reducer writes the same shape
    // from a committed `ak.call.state` event).
    seed_call_state(
        &state,
        &session_id,
        None,
        vec![serde_json::json!({
            "actor_id": bob,
            "action": "ban",
            "removed_at": chrono::Utc::now().to_rfc3339(),
        })],
    );

    // After the ban, bob's token re-issue is refused with
    // `call_participant_removed` (webrtc-signaling.md §3a).
    let mut post_ban = TestClient::post("http://server/_arkret/self/rtc/token")
        .add_header("authorization", format!("Bearer {bob_token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "call_id": session_id,
            "actor_id": bob,
            "device_id": bob_device,
            "focus_id": "ak:focus:livekit:green"
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

/// Register `bob` as a realm member and return a fresh `ak:call:<uuidv7>` id.
/// The media token issuer is decoupled from any ephemeral signaling session
/// (`media-service-binding.md` §3 durable-roster ordering — after token
/// exchange the client MUST land its `participant_binding` in a durable
/// `ak.call.state.participants[]` event, accepted by the server, before
/// the identity counts as a roster member or media is exposed): a
/// brand-new call has no
/// `ak.call.state` cell yet, and the issuer authorizes on realm membership +
/// `ak.call.join` + the durable ban set. This mirrors the inkson flow, which
/// redeems a media token before writing its first `ak.call.state` event.
fn add_member_and_fresh_call(state: &AppState, member: &str) -> String {
    add_test_realm_member(state, DEMO_REALM_ID, member);
    new_prefixed_uuid7("ak:call:")
}

/// Seed the durable `ak.call.state` cell (`ak.component.call.state.v1:{call_id}`)
/// the media token issuer reads, mirroring what the `apply_call_state` reducer
/// writes from a committed `ak.call.state` event. `session_focus` pins the
/// committed focus (write-once §4.1); `removed_participants` carries the §3a ban
/// / kick rows (`{ actor_id, device_id?, action, removed_at }`).
fn seed_call_state(
    state: &AppState,
    call_id: &str,
    session_focus: Option<&str>,
    removed_participants: Vec<Value>,
) {
    let mut value = serde_json::json!({
        "call_id": call_id,
        "state": "active",
        "removed_participants": removed_participants,
    });
    if let Some(focus) = session_focus {
        value["session_focus"] = Value::String(focus.to_owned());
    }
    let cell_id = CellRef::new(format!("ak:cell:ak.component.call.state.v1:{call_id}")).unwrap();
    state
        .projection
        .lock()
        .cells
        .insert(cell_id, CellState::Value(value));
}

fn install_media_service_epoch(state: &AppState, media_service: Value) {
    let cell_id = CellRef::new(format!(
        "ak:cell:ak.component.realm.media_service.v1:{DEMO_REALM_ID}"
    ))
    .unwrap();
    state.projection.lock().cells.insert(
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
                "focus_id": "ak:focus:livekit:green",
                "backend": "livekit",
                "connect_url": "wss://media.example/livekit",
                "issuer_kid": "did:web:media.example#livekit-2026-05",
                "audience": "livekit-demo",
                "ttl_seconds": 300,
                "e2ee_key_source": "mls_epoch"
            },
            {
                "focus_id": "ak:focus:mediasoup:blue",
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

/// Build a signed `ak.call.signal` ephemeral envelope (verbatim wire shape
/// per `ak.schema.ephemeral_envelope.v1` + `webrtc-signaling.md` §5). `proof`
/// is a development detached-signature stub — the relay stores it verbatim and
/// the receiver (not the relay) verifies it.
fn call_signal_envelope(
    actor: &str,
    device_id: &str,
    call_id: &str,
    signal_type: &str,
    seq: u64,
) -> Value {
    let sent_at = chrono::Utc::now();
    let expires_at = sent_at + chrono::Duration::minutes(2);
    let mut envelope = serde_json::json!({
        "kind": "ak.call.signal",
        "realm_id": DEMO_REALM_ID,
        "actor_id": actor,
        "device_id": device_id,
        "sent_at": sent_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "expires_at": expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "payload": {
            "call_id": call_id,
            "signal_type": signal_type,
            "seq": seq,
            "data": {"sdp_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
        }
    });
    let canonical = arkret_sdk::canonical::canonical_json_bytes(&envelope).unwrap();
    let event_digest = arkret_sdk::canonical::sha256_digest(&canonical);
    envelope["proof"] = serde_json::json!({
        "kind": "detached_jws",
        "alg": "EdDSA",
        "verification_method": format!("{actor}#device"),
        "event_digest": event_digest,
        "created_at": sent_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "jws": "eyJhbGciOiJFZERTQSJ9..c2ln"
    });
    envelope
}

async fn post_ephemeral(state: AppState, token: &str, envelope: &Value) -> salvo::http::Response {
    TestClient::post("http://server/_arkret/self/ephemeral")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(envelope)
        .send(&app_from_state(state))
        .await
}

/// Extract the verbatim relayed `ak.call.signal` envelopes from a subscribe
/// frame's per-Realm `ephemeral` segment (the typed `ak.call.signal` item).
fn call_signals_in_subscribe(frame: &Value, realm_id: &str) -> Vec<Value> {
    let Some(realm) = frame["realms"].get(realm_id) else {
        return Vec::new();
    };
    let Some(ephemeral) = realm["ephemeral"].as_array() else {
        return Vec::new();
    };
    ephemeral
        .iter()
        .filter(|item| item["type"] == "ak.call.signal")
        .flat_map(|item| item["call_signals"].as_array().cloned().unwrap_or_default())
        .collect()
}

#[tokio::test]
async fn ephemeral_call_signal_relays_to_other_realm_member_and_filters_self_device() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = "did:web:alice.example";
    let alice_device = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let alice_token = dev_token(state.clone()).await;
    let bob = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-b0b000000001";
    let bob_token = dev_token_for_device(state.clone(), bob, bob_device, "Bob Phone").await;
    add_test_realm_member(&state, DEMO_REALM_ID, bob);
    // §162 — the sender MUST hold `ak.call.signal.send` for the Realm.
    grant_call_capability(
        &state,
        DEMO_REALM_ID,
        alice,
        arkret_sdk::CAP_CALL_SIGNAL_SEND,
    );

    let call_id = "ak:call:0196419b-0000-7000-8000-00000000ca11";
    let envelope = call_signal_envelope(alice, alice_device, call_id, "invite", 1);
    let mut submit = post_ephemeral(state.clone(), &alice_token, &envelope).await;
    assert_eq!(submit.status_code, Some(StatusCode::OK));
    let outcome: Value = submit.take_json().await.unwrap();
    assert_eq!(outcome["accepted"], true);
    // dispatched_to now reflects the realm-broadcast breadth (bob), not None.
    assert_eq!(outcome["dispatched_to"], 1);

    // Bob (other member) receives the verbatim signed envelope (proof intact).
    let bob_frame = account_subscribe_frame(state.clone(), Some(&bob_token), "catchup=true").await;
    let bob_signals = call_signals_in_subscribe(&bob_frame, DEMO_REALM_ID);
    assert_eq!(
        bob_signals.len(),
        1,
        "bob must receive the relayed call signal"
    );
    assert_eq!(bob_signals[0]["kind"], "ak.call.signal");
    assert_eq!(bob_signals[0]["payload"]["call_id"], call_id);
    assert_eq!(bob_signals[0]["payload"]["signal_type"], "invite");
    assert_eq!(bob_signals[0]["payload"]["seq"], 1);
    assert_eq!(bob_signals[0]["proof"]["kind"], "detached_jws");
    assert_eq!(bob_signals[0]["proof"]["alg"], "EdDSA");
    assert!(bob_signals[0]["proof"]["event_digest"].is_string());
    assert!(bob_signals[0]["proof"]["jws"].is_string());
    assert_eq!(
        bob_signals[0]["proof"]["verification_method"], "did:web:alice.example#device",
        "the relay delivers the envelope verbatim so the receiver can verify proof"
    );

    // Alice's own device A subscribe does NOT echo her own signal back.
    let alice_frame =
        account_subscribe_frame(state.clone(), Some(&alice_token), "catchup=true").await;
    let alice_signals = call_signals_in_subscribe(&alice_frame, DEMO_REALM_ID);
    assert!(
        alice_signals.is_empty(),
        "the sending device must not see its own self-echoed call signal"
    );
}

#[tokio::test]
async fn ephemeral_call_signal_reaches_same_actor_other_device() {
    // §7 — a same-actor *other* device receives the signal (multi-device
    // fan-out); only the originating device self-echo is suppressed.
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = "did:web:alice.example";
    let alice_device_a = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let alice_device_b = "ak:device:01904100-0000-7000-8000-a11ce0000002";
    let token_a = dev_token(state.clone()).await;
    let token_b = dev_token_for_device(state.clone(), alice, alice_device_b, "Alice Laptop").await;
    grant_call_capability(
        &state,
        DEMO_REALM_ID,
        alice,
        arkret_sdk::CAP_CALL_SIGNAL_SEND,
    );

    let call_id = "ak:call:0196419b-0000-7000-8000-00000000ca12";
    let envelope = call_signal_envelope(alice, alice_device_a, call_id, "invite", 1);
    let submit = post_ephemeral(state.clone(), &token_a, &envelope).await;
    assert_eq!(submit.status_code, Some(StatusCode::OK));

    // Device B (same actor) receives the signal.
    let frame_b = account_subscribe_frame(state.clone(), Some(&token_b), "catchup=true").await;
    let signals_b = call_signals_in_subscribe(&frame_b, DEMO_REALM_ID);
    assert_eq!(
        signals_b.len(),
        1,
        "a second device of the same actor must receive the call signal"
    );
    assert_eq!(signals_b[0]["payload"]["call_id"], call_id);

    // Device A (originating) still does not see its own echo.
    let frame_a = account_subscribe_frame(state.clone(), Some(&token_a), "catchup=true").await;
    assert!(call_signals_in_subscribe(&frame_a, DEMO_REALM_ID).is_empty());
}

#[tokio::test]
async fn ephemeral_call_signal_not_delivered_after_ttl_expiry() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = "did:web:alice.example";
    let alice_device = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let alice_token = dev_token(state.clone()).await;
    let bob = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-b0b000000001";
    let bob_token = dev_token_for_device(state.clone(), bob, bob_device, "Bob Phone").await;
    add_test_realm_member(&state, DEMO_REALM_ID, bob);
    grant_call_capability(
        &state,
        DEMO_REALM_ID,
        alice,
        arkret_sdk::CAP_CALL_SIGNAL_SEND,
    );

    let call_id = "ak:call:0196419b-0000-7000-8000-00000000ca13";
    let envelope = call_signal_envelope(alice, alice_device, call_id, "invite", 1);
    let submit = post_ephemeral(state.clone(), &alice_token, &envelope).await;
    assert_eq!(submit.status_code, Some(StatusCode::OK));

    // Force-expire the relayed record by rewriting its expires_at into the past.
    {
        let record = state
            .persistence
            .call_signal_relay()
            .list_for_realm(DEMO_REALM_ID)
            .await
            .unwrap();
        assert_eq!(record.len(), 1);
    }
    // Re-submit with an already-near expiry, then prune; simulate expiry by
    // pruning after the relay TTL passes. We drive expiry deterministically by
    // appending an expired record directly and pruning.
    state
        .persistence
        .call_signal_relay()
        .append(soland::state::CallSignalRelayRecord {
            realm_id: DEMO_REALM_ID.to_owned(),
            sender_actor: alice.to_owned(),
            sender_device: alice_device.to_owned(),
            call_id: call_id.to_owned(),
            expires_at: chrono::Utc::now() - chrono::Duration::seconds(1),
            envelope: call_signal_envelope(alice, alice_device, call_id, "hangup", 2),
            position: 0,
        })
        .await
        .unwrap();

    // The expired hangup must not be delivered; only the live invite remains.
    let bob_frame = account_subscribe_frame(state.clone(), Some(&bob_token), "catchup=true").await;
    let bob_signals = call_signals_in_subscribe(&bob_frame, DEMO_REALM_ID);
    assert!(
        bob_signals
            .iter()
            .all(|signal| signal["payload"]["signal_type"] != "hangup"),
        "expired call signals must not be delivered"
    );
}

#[tokio::test]
async fn ephemeral_call_signal_without_send_capability_is_denied() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = "did:web:alice.example";
    let alice_device = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let alice_token = dev_token(state.clone()).await;
    // No `ak.call.signal.send` grant.
    let call_id = "ak:call:0196419b-0000-7000-8000-00000000ca14";
    let envelope = call_signal_envelope(alice, alice_device, call_id, "invite", 1);
    let denied = post_ephemeral(state.clone(), &alice_token, &envelope).await;
    assert_eq!(denied.status_code, Some(StatusCode::FORBIDDEN));

    // Nothing entered the relay.
    let relayed = state
        .persistence
        .call_signal_relay()
        .list_for_realm(DEMO_REALM_ID)
        .await
        .unwrap();
    assert!(relayed.is_empty());
}

/// Incremental subscribe (with an `after` cursor) for `token`, returning the
/// relayed `ak.call.signal` envelopes and the next cursor. `is_incremental` on
/// the server is `body.after.is_some()`, so passing `after=` exercises the
/// deliver-once watermark path rather than a full sync.
async fn incremental_call_signals(
    state: AppState,
    token: &str,
    after: &str,
) -> (Vec<Value>, String) {
    let frame =
        account_subscribe_frame(state, Some(token), &format!("max_wait_ms=0&after={after}")).await;
    let signals = call_signals_in_subscribe(&frame, DEMO_REALM_ID);
    let next = frame["cursor"].as_str().unwrap().to_owned();
    (signals, next)
}

#[tokio::test]
async fn ephemeral_call_signal_incremental_resubscribe_does_not_redeliver() {
    // Deliver-once: a subscriber-device that already received a relayed
    // `ak.call.signal` on one sync MUST NOT receive it again on a later
    // incremental sync inside the TTL window; a *new* signal still arrives;
    // and a full sync (catchup, no `after`) still re-delivers pending signals.
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = "did:web:alice.example";
    let alice_device = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let alice_token = dev_token(state.clone()).await;
    let bob = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-b0b000000001";
    let bob_token = dev_token_for_device(state.clone(), bob, bob_device, "Bob Phone").await;
    add_test_realm_member(&state, DEMO_REALM_ID, bob);
    grant_call_capability(
        &state,
        DEMO_REALM_ID,
        alice,
        arkret_sdk::CAP_CALL_SIGNAL_SEND,
    );

    let call_id = "ak:call:0196419b-0000-7000-8000-00000000ca20";
    let first = call_signal_envelope(alice, alice_device, call_id, "invite", 1);
    assert_eq!(
        post_ephemeral(state.clone(), &alice_token, &first)
            .await
            .status_code,
        Some(StatusCode::OK)
    );

    // First (full) sync: bob receives the invite once and the watermark aligns.
    let baseline = account_subscribe_frame(state.clone(), Some(&bob_token), "catchup=true").await;
    let baseline_signals = call_signals_in_subscribe(&baseline, DEMO_REALM_ID);
    assert_eq!(baseline_signals.len(), 1, "bob receives the first invite");
    assert_eq!(baseline_signals[0]["payload"]["seq"], 1);
    let cursor = baseline["cursor"].as_str().unwrap().to_owned();

    // Incremental re-subscribe inside the TTL window: the already-delivered
    // invite MUST NOT be re-emitted.
    let (repeat, cursor) = incremental_call_signals(state.clone(), &bob_token, &cursor).await;
    assert!(
        repeat.is_empty(),
        "an incremental re-subscribe must not re-deliver an already-seen signal"
    );

    // A second, distinct signal is still delivered on the next incremental sync.
    let second = call_signal_envelope(alice, alice_device, call_id, "answer", 2);
    assert_eq!(
        post_ephemeral(state.clone(), &alice_token, &second)
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    let (after_second, cursor) = incremental_call_signals(state.clone(), &bob_token, &cursor).await;
    assert_eq!(
        after_second.len(),
        1,
        "a new signal must still be delivered incrementally"
    );
    assert_eq!(after_second[0]["payload"]["signal_type"], "answer");

    // And it is not re-delivered on a subsequent incremental sync.
    let (after_second_repeat, _cursor) =
        incremental_call_signals(state.clone(), &bob_token, &cursor).await;
    assert!(
        after_second_repeat.is_empty(),
        "the second signal must not be re-delivered incrementally either"
    );

    // A full sync (catchup, no `after`) re-delivers all still-pending signals so
    // a reconnecting device recovers a pending invite.
    let full = account_subscribe_frame(state.clone(), Some(&bob_token), "catchup=true").await;
    let full_signals = call_signals_in_subscribe(&full, DEMO_REALM_ID);
    assert_eq!(
        full_signals.len(),
        2,
        "a full sync re-delivers all non-expired pending signals (catchup recovery)"
    );

    // The sending device still never sees its own self-echo, even on full sync.
    let alice_frame =
        account_subscribe_frame(state.clone(), Some(&alice_token), "catchup=true").await;
    assert!(
        call_signals_in_subscribe(&alice_frame, DEMO_REALM_ID).is_empty(),
        "the sending device must not see its own self-echoed call signal"
    );
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
