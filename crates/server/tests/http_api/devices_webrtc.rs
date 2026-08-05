//! Integration tests — `devices_webrtc` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

use arkret_identifiers::CellRef;
use arkret_state::lattice::CellState;

use super::common::*;

fn device_message_target(kind: &str, content: Value) -> Value {
    serde_json::json!({
        "message_id": new_prefixed_uuid7("ak:device_message:"),
        "kind": kind,
        "content": content,
        "expires_at": arkret_canonical::format_timestamp_canonical(
            chrono::Utc::now() + chrono::Duration::minutes(10)
        ),
    })
}

fn pair_device_pubkey(device_id: &str) -> Value {
    let signing = pair_device_signing_key(device_id);
    serde_json::json!({
        "kty": "OKP",
        "kid": device_id,
        "algorithm": "Ed25519",
        "key": URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes())
    })
}

fn pair_device_signing_key(device_id: &str) -> SigningKey {
    let mut seed = [0_u8; 32];
    for (index, byte) in device_id.as_bytes().iter().take(32).enumerate() {
        seed[index] = *byte;
    }
    SigningKey::from_bytes(&seed)
}

fn account_device_pair_body(new_device_id: &str) -> Value {
    let public_key_value = pair_device_pubkey(new_device_id);
    let public_key = serde_json::from_value(public_key_value.clone()).unwrap();
    let pairing_code =
        arkret_models_collaboration::http_bodies::DevicePairingCode::new("7H2K9M4Q".to_owned())
            .unwrap();
    let challenge =
        arkret_models_collaboration::http_bodies::DevicePairingToDeviceChallengeTranscript {
            transaction_id: arkret_wire::NonEmptyString::new("txn-device-pair-fixture").unwrap(),
            request_canonical_digest: arkret_identifiers::Hash::new(format!(
                "sha256:{}",
                "a".repeat(64)
            ))
            .unwrap(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
        };
    let proof = arkret_signatures::device_pairing::sign_to_device_pairing_challenge(
        &public_key,
        &pairing_code,
        "http://server",
        &challenge,
        &pair_device_signing_key(new_device_id),
    )
    .unwrap();
    serde_json::json!({
        "pairing_code": pairing_code,
        "new_device_pubkey": public_key_value,
        "challenge_proof": proof,
        "challenge_transcript": challenge
    })
}

async fn post_account_device_pair(
    state: AppState,
    token: &str,
    new_device_id: &str,
    challenge_signature: &str,
) -> (StatusCode, Value) {
    let mut body = account_device_pair_body(new_device_id);
    if challenge_signature == "!" {
        body["challenge_proof"]["signature"] = Value::String("!".to_owned());
    }
    let mut response = TestClient::post("http://server/_arkret/gate/account/device-pair")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&body)
        .send(&app_from_state(state))
        .await;
    let status = response.status_code.expect("device-pair status");
    let body = response.take_json().await.expect("device-pair json");
    (status, body)
}

#[tokio::test]
async fn account_device_pair_registers_sibling_via_canonical_gate_route() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let sibling = "ak:device:01904100-0000-7000-8000-9b04e0000008";
    let sibling_device_public_key =
        arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase(
            pair_device_signing_key(sibling).verifying_key().as_bytes(),
        );
    let sibling_pair_body = account_device_pair_body(sibling);

    let unauthenticated = TestClient::post("http://server/_arkret/gate/account/device-pair")
        .json(&sibling_pair_body)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthenticated.status_code, Some(StatusCode::UNAUTHORIZED));

    let mut sibling_pair_body = sibling_pair_body;
    sibling_pair_body["display_name"] = Value::String("Paired Phone".to_owned());
    sibling_pair_body["device_metadata"] = serde_json::json!({"platform": "ios"});
    let paired: Value = TestClient::post("http://server/_arkret/gate/account/device-pair")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&sibling_pair_body)
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
    // The durable device inventory is the authorization truth. The gate may
    // omit the optional capability-grant snapshot when no separate grant is
    // minted for same-principal pairing.
    assert!(paired.get("device_grant").is_none_or(Value::is_null));

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
        .test_persistence()
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
            .test_persistence()
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
    let state = soland_test_support::app_state(test_config());
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
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"]["code"], "schema_violation", "{body}");

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
        .test_persistence()
        .devices()
        .get(actor, first_new_device)
        .await
        .unwrap()
        .expect("paired device record");
    revoked_target.revoked_at = Some(chrono::Utc::now());
    state
        .test_persistence()
        .devices()
        .put(&revoked_target)
        .await
        .unwrap();
    let (status, body) =
        post_account_device_pair(state.clone(), &trusted_token, first_new_device, "c2ln").await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"]["code"], "device_revoked", "{body}");

    let mut revoked = state
        .test_persistence()
        .devices()
        .get(actor, trusted_device)
        .await
        .unwrap()
        .expect("trusted device record");
    revoked.revoked_at = Some(chrono::Utc::now());
    state
        .test_persistence()
        .devices()
        .put(&revoked)
        .await
        .unwrap();

    let (status, body) =
        post_account_device_pair(state.clone(), &trusted_token, third_new_device, "c2ln").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["code"], "unauthenticated", "{body}");

    let audit = state
        .test_persistence()
        .audit()
        .snapshot_all()
        .await
        .unwrap();
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
    let state = soland_test_support::app_state(test_config());
    let actor = "did:web:alice.example";
    let existing_device = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let new_device = "ak:device:01904100-0000-7000-8000-9b04e0000008";
    let existing_token =
        dev_token_for_device(state.clone(), actor, existing_device, "Alice Desktop").await;
    let new_token = dev_token_for_device(state.clone(), actor, new_device, "Alice Browser").await;
    let pair_body = account_device_pair_body(new_device);
    let request_content = serde_json::json!({
        "transaction_id": "txn-device-pair-1",
        "from_device": new_device,
        "timestamp": arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
        "expires_at": arkret_canonical::format_timestamp_canonical(
            chrono::Utc::now() + chrono::Duration::minutes(10)
        ),
        "methods": ["ak.sas.v1", "ak.qr.v1"],
        "purpose": "same_principal_device_authorization",
        "pairing_code": "7H2K9M4Q",
        "new_device_pubkey": pair_body["new_device_pubkey"],
        "challenge_proof": pair_body["challenge_proof"],
        "challenge_transcript": pair_body["challenge_transcript"],
        "gate_audience": "http://server",
        "request_canonical_digest": format!("sha256:{}", "a".repeat(64)),
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
        subscribe_messages[0]["content"]["new_device_pubkey"]["key"],
        request_content["new_device_pubkey"]["key"]
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
    assert_eq!(pulled["messages"][0]["content"]["pairing_code"], "7H2K9M4Q");

    let mut approved_body = pair_body;
    approved_body["display_name"] = Value::String("Alice Browser".to_owned());
    approved_body["device_metadata"] = request_content["device_metadata"].clone();
    let approved: Value = TestClient::post("http://server/_arkret/gate/account/device-pair")
        .add_header("authorization", format!("Bearer {existing_token}"), true)
        .json(&approved_body)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(approved["device_id"], new_device);
    assert!(
        approved.get("device_grant").is_none(),
        "the optional grant is omitted when pairing does not mint one: {approved}"
    );

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
    let state = soland_test_support::app_state(config);
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
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;

    let create = TestClient::post("http://server/_arkret/gate/account/device-pairing-requests")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "pairing_code": "7H2K9M4Q",
            "new_device_pubkey": {
                "kid": "ak:device:01904100-0000-7000-8000-9b04e0000007",
                "algorithm": "Ed25519",
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
    let state = soland_test_support::app_state(test_config());
    install_media_service_epoch(&state, good_media_service_epoch());
    let token = dev_token(state.clone()).await;
    // Brand-new call: no durable call cells exist yet (the initiator redeems a
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
    // Spec `CallMediaTokenExchangeOutcome` required fields: focus_id + backend_kind
    // identify the chosen focus and its backend protocol; `todos` is not a
    // schema field and must not appear.
    assert_eq!(token_response["focus_id"], "ak:focus:mediasoup:blue");
    assert_eq!(token_response["backend_kind"], "mediasoup");
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
        arkret_identifiers::is_lowercase_typed_uuid(
            participant_identity
                .strip_prefix("ak:rtc_participant:")
                .unwrap(),
            arkret_identifiers::UUID_VERSION_PRODUCER_ALLOCATED,
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
/// ever touching any ephemeral signaling session. No durable call cell exists
/// yet (the initiator redeems the token before writing its first
/// `ak.call.state` event); authorization is purely realm membership +
/// `ak.call.join`. This is the case the old `participants.contains` /
/// session-not-found gate broke (it 404'd every real inkson call).
#[tokio::test]
async fn rtc_media_token_inkson_flow_no_session_issues_token() {
    let state = soland_test_support::app_state(livekit_test_config());
    install_media_service_epoch(&state, good_media_service_epoch());
    // Use a non-owner member so the pre-grant assertion actually isolates
    // `ak.call.join`; the seeded Alice account is the demo Realm owner and
    // owners receive ordinary Realm-level capabilities by default.
    let actor = "did:web:bob.example";
    let device_id = "ak:device:01904100-0000-7000-8000-b0b000000003";
    add_test_realm_member(&state, DEMO_REALM_ID, actor);
    let token = dev_token_for_device(state.clone(), actor, device_id, "Bob Phone").await;
    // A fresh call id with no durable call cell and no ephemeral session.
    let call_id = new_prefixed_uuid7("ak:call:");

    // Without ak.call.join, even a realm member is denied (§6).
    let mut denied = TestClient::post("http://server/_arkret/self/rtc/token")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "call_id": call_id,
            "actor_id": actor,
            "device_id": device_id,
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
    // though no signaling session or durable call cell exists.
    grant_call_capability(&state, DEMO_REALM_ID, actor, "ak.call.join");
    let issued: Value = TestClient::post("http://server/_arkret/self/rtc/token")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "call_id": call_id,
            "actor_id": actor,
            "device_id": device_id,
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
    let state = soland_test_support::app_state(test_config());
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

    // Commit `session_focus = mediasoup:blue` into the durable focus cell
    // (§4.1 write-once). A token request naming a different focus MUST be
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
                "type": "mediasoup",
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
    let state = soland_test_support::app_state(test_config());
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
    let state = soland_test_support::app_state(livekit_test_config());
    install_media_service_epoch(&state, good_media_service_epoch());
    // Bootstrap alice (realm owner) so DEMO_REALM exists, then add bob as a
    // member.
    let _alice_token = dev_token(state.clone()).await;
    let bob = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-b0b000000001";
    let bob_token = dev_token_for_device(state.clone(), bob, bob_device, "Bob Phone").await;
    // bob is a realm member; no durable call cell exists yet (the new model
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
    let state = soland_test_support::app_state(livekit_test_config());
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
    assert_eq!(token_response["backend_kind"], "livekit");
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
    assert!(room.starts_with("ak_call_"));
    assert!(!room.contains(&session_id));
    let room_material = format!("{DEMO_REALM_ID}\0{session_id}\0ak:focus:livekit:green");
    let expected_room = format!(
        "ak_call_{}",
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
    let state = soland_test_support::app_state(test_config());
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
    let state = soland_test_support::app_state(livekit_test_config());
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

    // A moderator actor-wide-bans bob: the durable call moderation OR-Set
    // carries a `ban` value with no `device_id`. Seed that effective cell
    // directly (the reducer writes the same tag/value shape).
    seed_call_state(
        &state,
        &session_id,
        None,
        vec![serde_json::json!({
            "actor_id": bob,
            "action": "ban",
            "removed_at": arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
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
    soland_http::authz::install_projected_grant(
        state.test_authz(),
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
/// `ak.call.state` roster-delta event, accepted by the server, before
/// the identity counts as a roster member or media is exposed): a
/// brand-new call has no
/// call cells yet, and the issuer authorizes on realm membership +
/// `ak.call.join` + the durable ban set. This mirrors the inkson flow, which
/// redeems a media token before writing its first `ak.call.state` event.
fn add_member_and_fresh_call(state: &AppState, member: &str) -> String {
    add_test_realm_member(state, DEMO_REALM_ID, member);
    new_prefixed_uuid7("ak:call:")
}

/// Seed the independent durable focus and moderation cells the media token
/// issuer reads. `session_focus` pins the committed focus (write-once §4.1);
/// `moderation_values` contains effective ban / kick OR-Set values.
fn seed_call_state(
    state: &AppState,
    call_id: &str,
    session_focus: Option<&str>,
    moderation_values: Vec<Value>,
) {
    if let Some(focus) = session_focus {
        let cell_id =
            CellRef::new(format!("ak:cell:ak.component.call.focus.v1:{call_id}")).unwrap();
        state.test_projection().lock().cells.insert(
            cell_id,
            CellState::Value(serde_json::json!({"session_focus": focus})),
        );
    }
    if !moderation_values.is_empty() {
        let effective = moderation_values
            .into_iter()
            .enumerate()
            .map(|(index, value)| {
                serde_json::json!({
                    "tag": format!("ak:orset-tag:test-{index}"),
                    "value": value,
                })
            })
            .collect::<Vec<_>>();
        let cell_id =
            CellRef::new(format!("ak:cell:ak.component.call.moderation.v1:{call_id}")).unwrap();
        state
            .test_projection()
            .lock()
            .cells
            .insert(cell_id, CellState::Value(Value::Array(effective)));
    }
}

fn install_media_service_epoch(state: &AppState, media_service: Value) {
    let cell_id = CellRef::new(arkret_wire::null_subject_cell(
        arkret_wire::CellFamilyId::REALM_MEDIA_SERVICE_V1,
    ))
    .unwrap();
    state
        .test_projection()
        .lock()
        .realm_null_subject_cells
        .insert(
            (DEMO_REALM_ID.to_owned(), cell_id.as_str().to_owned()),
            CellState::Value(media_service),
        );
}

fn good_media_service_epoch() -> Value {
    serde_json::json!({
        "service_id": "did:web:media.example",
        "foci": [
            {
                "focus_id": "ak:focus:livekit:green",
                "type": "livekit",
                "connect_url": "wss://media.example/livekit",
                "issuer_kid": "did:web:media.example#livekit-2026-05",
                "audience": "livekit-demo",
                "ttl_seconds": 300
            },
            {
                "focus_id": "ak:focus:mediasoup:blue",
                "type": "mediasoup",
                "connect_url": "wss://media.example/mediasoup",
                "issuer_kid": "did:web:media.example#mediasoup-2026-05",
                "audience": "mediasoup-demo",
                "ttl_seconds": 900
            }
        ]
    })
}

/// A call signalling frame on the Signal rail (`webrtc-signaling.md` §5).
///
/// `call_id`, `signal_kind` and `seq` are inside `encrypted_payload`; the outer
/// envelope exposes only `signal_class`. `invite` and other wake-up frames use
/// `setup`, everything else `session`. `opaque_payload` stands in for that
/// ciphertext: it varies the envelope digest exactly as a differing plaintext
/// would, and nothing the server may read depends on it.
fn call_signal(
    actor: &str,
    device_id: &str,
    seal_ref: &arkret_wire::SealId,
    signal_class: arkret_wire::SignalClass,
    opaque_payload: &str,
    signing_key: &SigningKey,
) -> arkret_wire::SignalEnvelope {
    // `signal.md` §2 per-class TTL ceilings.
    let ttl_seconds = match signal_class {
        arkret_wire::SignalClass::Setup => 120,
        arkret_wire::SignalClass::Moderation => 60,
        // `SignalClass` is `#[non_exhaustive]`; the narrowest ceiling is the
        // safe default for a class this fixture does not yet know.
        _ => 30,
    };
    call_signal_at(
        actor,
        device_id,
        seal_ref,
        signal_class,
        chrono::Utc::now(),
        ttl_seconds,
        opaque_payload,
        signing_key,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "the TTL-expiry case needs an explicit sent_at and lifetime"
)]
fn call_signal_at(
    actor: &str,
    device_id: &str,
    seal_ref: &arkret_wire::SealId,
    signal_class: arkret_wire::SignalClass,
    sent_at: chrono::DateTime<chrono::Utc>,
    ttl_seconds: i64,
    opaque_payload: &str,
    signing_key: &SigningKey,
) -> arkret_wire::SignalEnvelope {
    signed_signal_envelope(
        DEMO_REALM_ID,
        arkret_wire::ScopeRef::Realm {
            realm_id: RealmId::new(DEMO_REALM_ID.to_owned()).unwrap(),
        },
        actor,
        device_id,
        seal_ref,
        signal_class,
        sent_at,
        ttl_seconds,
        opaque_payload,
        signing_key,
    )
}

const WEBRTC_ALICE: &str = "did:web:alice.example";
const WEBRTC_ALICE_DEVICE_A: &str = "ak:device:01904100-0000-7000-8000-a11ce0000001";
const WEBRTC_BOB: &str = "did:web:bob.example";
const WEBRTC_BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-b0b000000001";

/// Restates `ephemeral_call_signal_relays_to_other_realm_member_and_filters_self_device`.
///
/// Same premise, new rail: an admitted call frame reaches the other Realm
/// member's device verbatim — so that receiver can verify `proof` over the exact
/// canonical bytes the sender signed — and the originating device never gets its
/// own frame echoed back.
#[tokio::test]
async fn call_signal_relays_to_other_realm_member_and_filters_self_device() {
    let state = soland_test_support::app_state(test_config());
    add_test_realm_member(&state, DEMO_REALM_ID, WEBRTC_BOB);
    let (alice_token, alice_key) =
        seed_signal_sender_device(&state, WEBRTC_ALICE, WEBRTC_ALICE_DEVICE_A, "Alice Desktop")
            .await;
    let (bob_token, _bob_key) =
        seed_signal_sender_device(&state, WEBRTC_BOB, WEBRTC_BOB_DEVICE, "Bob Phone").await;
    let seal_ref = seed_signal_basis_seal(&state, DEMO_REALM_ID, WEBRTC_ALICE).await;

    let invite = call_signal(
        WEBRTC_ALICE,
        WEBRTC_ALICE_DEVICE_A,
        &seal_ref,
        arkret_wire::SignalClass::Setup,
        "invite",
        &alice_key,
    );
    let mut submit = post_signal(state.clone(), &alice_token, &invite).await;
    assert_eq!(submit.status_code, Some(StatusCode::OK));
    let outcome: arkret_models_collaboration::http_bodies::SignalSubmitOutcome =
        submit.take_json().await.unwrap();
    assert!(outcome.accepted);
    assert_eq!(
        outcome.dispatched_recipient_count,
        Some(1),
        "eligibility count is Realm breadth minus the sender, not a delivery guarantee"
    );

    let bob_signals = signal_subscribe_envelopes(state.clone(), &bob_token, 400).await;
    assert_eq!(
        bob_signals.len(),
        1,
        "bob must receive the relayed call signal"
    );
    assert_eq!(
        bob_signals[0], invite,
        "the relay delivers the envelope verbatim so the receiver can verify proof"
    );
    assert_eq!(bob_signals[0].signal_class, arkret_wire::SignalClass::Setup);

    let alice_signals = signal_subscribe_envelopes(state.clone(), &alice_token, 400).await;
    assert!(
        alice_signals.is_empty(),
        "the sending device must not see its own self-echoed call signal"
    );
}

/// Restates `ephemeral_call_signal_reaches_same_actor_other_device`:
/// `webrtc-signaling.md` §7 multi-device fan-out. Only the originating device is
/// suppressed, so a sibling device of the same actor still rings.
#[tokio::test]
async fn call_signal_reaches_same_actor_other_device() {
    let state = soland_test_support::app_state(test_config());
    let device_b = "ak:device:01904100-0000-7000-8000-a11ce0000002";
    let (token_a, key_a) =
        seed_signal_sender_device(&state, WEBRTC_ALICE, WEBRTC_ALICE_DEVICE_A, "Alice Desktop")
            .await;
    let (token_b, _key_b) =
        seed_signal_sender_device(&state, WEBRTC_ALICE, device_b, "Alice Laptop").await;
    let seal_ref = seed_signal_basis_seal(&state, DEMO_REALM_ID, WEBRTC_ALICE).await;

    let invite = call_signal(
        WEBRTC_ALICE,
        WEBRTC_ALICE_DEVICE_A,
        &seal_ref,
        arkret_wire::SignalClass::Setup,
        "invite",
        &key_a,
    );
    assert_eq!(
        post_signal(state.clone(), &token_a, &invite)
            .await
            .status_code,
        Some(StatusCode::OK)
    );

    let signals_b = signal_subscribe_envelopes(state.clone(), &token_b, 400).await;
    assert_eq!(
        signals_b.len(),
        1,
        "a second device of the same actor must receive the call signal"
    );
    assert_eq!(signals_b[0], invite);

    let signals_a = signal_subscribe_envelopes(state.clone(), &token_a, 400).await;
    assert!(signals_a.is_empty());
}

/// Restates `ephemeral_call_signal_not_delivered_after_ttl_expiry`.
///
/// The relay TTL premise is unchanged; only its carrier moved. `expires_at` is
/// now a signed member of the envelope with a §2 per-class ceiling, and the
/// subscriber path skips any record whose `expires_at` has passed. The expired
/// record is appended directly because an already-expired envelope can no longer
/// be admitted through the endpoint at all — which is itself the stronger half
/// of the rule.
#[tokio::test]
async fn call_signal_not_delivered_after_ttl_expiry() {
    let state = soland_test_support::app_state(test_config());
    add_test_realm_member(&state, DEMO_REALM_ID, WEBRTC_BOB);
    let (alice_token, alice_key) =
        seed_signal_sender_device(&state, WEBRTC_ALICE, WEBRTC_ALICE_DEVICE_A, "Alice Desktop")
            .await;
    let (bob_token, _bob_key) =
        seed_signal_sender_device(&state, WEBRTC_BOB, WEBRTC_BOB_DEVICE, "Bob Phone").await;
    let seal_ref = seed_signal_basis_seal(&state, DEMO_REALM_ID, WEBRTC_ALICE).await;

    let invite = call_signal(
        WEBRTC_ALICE,
        WEBRTC_ALICE_DEVICE_A,
        &seal_ref,
        arkret_wire::SignalClass::Setup,
        "invite",
        &alice_key,
    );
    assert_eq!(
        post_signal(state.clone(), &alice_token, &invite)
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    assert_eq!(
        state
            .test_persistence()
            .signal_relay()
            .list_for_realm(DEMO_REALM_ID)
            .await
            .unwrap()
            .len(),
        1
    );

    let expired = call_signal_at(
        WEBRTC_ALICE,
        WEBRTC_ALICE_DEVICE_A,
        &seal_ref,
        arkret_wire::SignalClass::Setup,
        chrono::Utc::now() - chrono::Duration::seconds(121),
        120,
        "hangup",
        &alice_key,
    );
    state
        .test_persistence()
        .signal_relay()
        .append(soland_storage::SignalRelayRecord {
            realm_id: DEMO_REALM_ID.to_owned(),
            scope_ref: expired.scope_ref.clone(),
            sender_actor_id: expired.sender_actor_id.as_str().to_owned(),
            sender_device_id: expired.sender_device_id.as_str().to_owned(),
            signal_class: expired.signal_class,
            envelope_digest: expired.envelope_digest().unwrap().as_str().to_owned(),
            sent_at: expired.sent_at,
            expires_at: expired.expires_at,
            envelope: expired.clone(),
            position: 0,
        })
        .await
        .unwrap();

    let bob_signals = signal_subscribe_envelopes(state.clone(), &bob_token, 400).await;
    assert!(
        bob_signals.iter().all(|signal| signal != &expired),
        "expired call signals must not be delivered"
    );
    assert_eq!(
        bob_signals,
        vec![invite],
        "only the live invite is delivered"
    );

    // §2 defines the TTL bound relative to `sent_at`, not to the ingress clock,
    // so an envelope whose window has already closed is still *structurally*
    // valid and is admitted. Expiry bites at delivery, which is the assertion
    // above. A lifetime that exceeds the class ceiling is the case that fails
    // closed at admission.
    let mut over_ceiling = post_signal(
        state.clone(),
        &alice_token,
        &call_signal_at(
            WEBRTC_ALICE,
            WEBRTC_ALICE_DEVICE_A,
            &seal_ref,
            arkret_wire::SignalClass::Setup,
            chrono::Utc::now(),
            121,
            "hangup",
            &alice_key,
        ),
    )
    .await;
    assert_eq!(over_ceiling.status_code, Some(StatusCode::BAD_REQUEST));
    let over_ceiling_body: Value = over_ceiling.take_json().await.unwrap();
    assert_eq!(
        over_ceiling_body["error"]["code"],
        "signal_ttl_out_of_range"
    );
}

/// Restates `ephemeral_call_signal_without_send_capability_is_denied`.
///
/// The old test asserted `ak.call.signal.send` at the ingress. That gate cannot
/// exist on this rail: `webrtc-signaling.md` §5 and `signal.md` §1 put
/// `signal_kind` and `call_id` inside the ciphertext, so a service cannot tell a
/// call frame from a typing frame — both are `setup` / `session` — and
/// `signal.md` §3's admission list deliberately contains only the `moderation`
/// action gate. `ak.call.signal.send` therefore binds the sender and the
/// receiving client, not this endpoint. The send-side denial that does survive
/// at the ingress is §3(2) eligibility: a non-member of the Realm may not send
/// into it, and nothing enters the relay.
#[tokio::test]
async fn call_signal_from_a_non_member_is_denied_and_never_relayed() {
    let state = soland_test_support::app_state(test_config());
    // Bob is deliberately not added to the demo Realm.
    let outsider_device = "ak:device:01904100-0000-7000-8000-b0b000000004";
    let (token, signing_key) =
        seed_signal_sender_device(&state, WEBRTC_BOB, outsider_device, "Bob Phone").await;
    let seal_ref = seed_signal_basis_seal(&state, DEMO_REALM_ID, WEBRTC_BOB).await;

    let denied = post_signal(
        state.clone(),
        &token,
        &call_signal(
            WEBRTC_BOB,
            outsider_device,
            &seal_ref,
            arkret_wire::SignalClass::Setup,
            "invite",
            &signing_key,
        ),
    )
    .await;
    assert_eq!(denied.status_code, Some(StatusCode::FORBIDDEN));

    assert!(
        state
            .test_persistence()
            .signal_relay()
            .list_for_realm(DEMO_REALM_ID)
            .await
            .unwrap()
            .is_empty()
    );
}

/// Restates `ephemeral_call_signal_incremental_resubscribe_does_not_redeliver`.
///
/// Deliver-once is now the per-`(actor, device, realm)` relay watermark rather
/// than a sync cursor: a reconnecting subscriber inside the TTL window sees
/// nothing it already took, a genuinely new frame still arrives, and the sending
/// device is never in its own fanout. The old "a full catchup re-delivers
/// everything pending" half is gone with the cursor — §4 gives this stream no
/// `after` token and no catchup mode, so the watermark is the only resume state.
#[tokio::test]
async fn call_signal_resubscribe_does_not_redeliver() {
    let state = soland_test_support::app_state(test_config());
    add_test_realm_member(&state, DEMO_REALM_ID, WEBRTC_BOB);
    let (alice_token, alice_key) =
        seed_signal_sender_device(&state, WEBRTC_ALICE, WEBRTC_ALICE_DEVICE_A, "Alice Desktop")
            .await;
    let (bob_token, _bob_key) =
        seed_signal_sender_device(&state, WEBRTC_BOB, WEBRTC_BOB_DEVICE, "Bob Phone").await;
    let seal_ref = seed_signal_basis_seal(&state, DEMO_REALM_ID, WEBRTC_ALICE).await;

    let invite = call_signal(
        WEBRTC_ALICE,
        WEBRTC_ALICE_DEVICE_A,
        &seal_ref,
        arkret_wire::SignalClass::Setup,
        "invite",
        &alice_key,
    );
    assert_eq!(
        post_signal(state.clone(), &alice_token, &invite)
            .await
            .status_code,
        Some(StatusCode::OK)
    );

    let baseline = signal_subscribe_envelopes(state.clone(), &bob_token, 400).await;
    assert_eq!(baseline, vec![invite], "bob receives the first invite");

    let repeat = signal_subscribe_envelopes(state.clone(), &bob_token, 400).await;
    assert!(
        repeat.is_empty(),
        "a resubscribe must not re-deliver an already-seen signal"
    );

    let answer = call_signal(
        WEBRTC_ALICE,
        WEBRTC_ALICE_DEVICE_A,
        &seal_ref,
        arkret_wire::SignalClass::Session,
        "answer",
        &alice_key,
    );
    assert_eq!(
        post_signal(state.clone(), &alice_token, &answer)
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    let after_second = signal_subscribe_envelopes(state.clone(), &bob_token, 400).await;
    assert_eq!(
        after_second,
        vec![answer],
        "a new signal must still be delivered"
    );
    assert!(
        signal_subscribe_envelopes(state.clone(), &bob_token, 400)
            .await
            .is_empty(),
        "the second signal must not be re-delivered either"
    );

    assert!(
        signal_subscribe_envelopes(state.clone(), &alice_token, 400)
            .await
            .is_empty(),
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
