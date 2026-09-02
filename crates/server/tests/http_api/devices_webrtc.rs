//! Integration tests — `devices_webrtc` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

use arkret_identifiers::CellRef;
use arkret_state::lattice::CellState;

use super::common::*;

fn canonical_request_body<T: serde::Serialize>(value: &T) -> Vec<u8> {
    arkret_canonical::canonical_json_bytes(value).expect("canonical request body")
}

fn local_media_actor(state: &AppState, principal: &str) -> arkret_wire::ActorId {
    // These media fixtures register local Accounts, not remote principal projections.
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        fixture_actor_core_id(principal),
        state.service_core_id(),
    ))
}

async fn post_authenticated_canonical<T: serde::Serialize>(
    state: AppState,
    token: &str,
    uri: &str,
    body: &T,
) -> salvo::http::Response {
    TestClient::post(uri)
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_request_body(body))
        .send(&app_from_state(state))
        .await
}

async fn post_canonical_signal(
    state: AppState,
    token: &str,
    envelope: &arkret_wire::SignalEnvelope,
) -> salvo::http::Response {
    post_authenticated_canonical(state, token, "http://server/_arkret/self/signal", envelope).await
}

fn authored_call_id() -> String {
    static NEXT_ACTOR_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(10_000);
    let actor_seq = NEXT_ACTOR_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let event = signed_canonical_event(
        "call-create-fixture-label",
        arkret_wire::EventKind::CallCreate.as_str(),
        WEBRTC_ALICE,
        WEBRTC_ALICE_DEVICE_A,
        demo_realm_id(),
        actor_seq,
        vec![],
        serde_json::json!({
            "initial_state": "ringing",
            "focus": {"mode": "sfu", "session_focus": "fixture"}
        }),
    );
    let event_id = arkret_identifiers::EventId::new(
        event["event_id"]
            .as_str()
            .expect("authored call create Event has event_id")
            .to_owned(),
    )
    .expect("authored call create Event has canonical event_id");
    arkret_identifiers::CallId::from_event_id(&event_id).to_string()
}

fn device_message_target(kind: &str, mut content: Value) -> Value {
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);
    if kind == "ak.key.verification.request" {
        let content = content
            .as_object_mut()
            .expect("key verification fixture content is an object");
        content
            .entry("transaction_id")
            .or_insert_with(|| Value::String(uuid::Uuid::now_v7().to_string()));
        content.entry("from_device_id").or_insert_with(|| {
            Value::String("ak:device:01904100-0000-7000-8000-a11ce0000001".to_owned())
        });
        content
            .entry("methods")
            .or_insert_with(|| serde_json::json!(["ak.key.verification.sas_v1"]));
        content.entry("timestamp").or_insert_with(|| {
            Value::String(arkret_canonical::format_timestamp_canonical(
                chrono::Utc::now(),
            ))
        });
        content.entry("expires_at").or_insert_with(|| {
            Value::String(arkret_canonical::format_timestamp_canonical(expires_at))
        });
    }
    serde_json::json!({
        "device_message_id": new_prefixed_uuid7("ak:device_message:"),
        "kind": kind,
        "content": content,
        "expires_at": arkret_canonical::format_timestamp_canonical(expires_at),
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
    use arkret_models_collaboration::events_payloads::device_identity::{
        DeviceAuthorizationBindingKind, DeviceOrPrincipalRef,
    };
    use arkret_models_collaboration::http_bodies::UnsignedDevicePairingTargetAttestation;

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
        "https://server.test",
        &challenge,
        &pair_device_signing_key(new_device_id),
    )
    .unwrap();
    let hpke_key = arkret_wire::NonEmptyString::new("z6LSDevicePairingHpkeKey".to_owned()).unwrap();
    let algorithms = vec![
        arkret_wire::NonEmptyString::new("Ed25519".to_owned()).unwrap(),
        arkret_wire::NonEmptyString::new("HPKE-X25519-HKDF-SHA256".to_owned()).unwrap(),
    ];
    let target_key = &pair_device_signing_key(new_device_id);
    let target_attestation =
        arkret_signatures::device_pairing::sign_device_pairing_target_attestation(
            UnsignedDevicePairingTargetAttestation::new(
                arkret_wire::DeviceId::new(new_device_id.to_owned()).unwrap(),
                arkret_wire::DidKey::new(format!(
                    "did:key:{}",
                    arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                        target_key.verifying_key().as_bytes()
                    )
                ))
                .unwrap(),
                hpke_key.clone(),
                algorithms.clone(),
                proof.transcript_digest.clone(),
            )
            .unwrap(),
            target_key,
        )
        .unwrap();
    let actor = "did:web:alice.example";
    let authorizing_device =
        arkret_wire::DeviceId::new("ak:device:01904100-0000-7000-8000-a11ce0000001".to_owned())
            .unwrap();
    // The Event envelope `actor_id` carries the principal; the payload does not
    // mirror it.
    let authorize_payload = serde_json::json!({
        "device_id": new_device_id,
        "device_public_key_did": target_attestation.device_public_key_did,
        "hpke_key": hpke_key,
        "algorithms": algorithms,
        "device_key_algorithm": "Ed25519",
        "authorized_by": DeviceOrPrincipalRef::DeviceId(authorizing_device.clone()),
        "not_before": arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
        "authorization_binding_kind": DeviceAuthorizationBindingKind::AcceptedDevice,
        "device_signature": target_attestation.device_signature,
    });
    let authorize_event: arkret_wire::Event = serde_json::from_value(signed_canonical_event(
        "device-pair-authorize-fixture",
        arkret_wire::EventKind::DeviceAuthorize.as_str(),
        actor,
        authorizing_device.as_str(),
        &soland_test_support::fixture_principal_control_realm(actor),
        2,
        vec![],
        authorize_payload,
    ))
    .unwrap();
    serde_json::json!({
        "pairing_code": pairing_code,
        "new_device_pubkey": public_key_value,
        "challenge_proof": proof,
        "challenge_transcript": challenge,
        "authorize_event": arkret_wire::EventInitialSubmission::online(authorize_event),
    })
}

fn bind_pair_authorize_predecessor(body: &mut Value, predecessor: &str) {
    body["authorize_event"]["event"]["prev_refs"] = serde_json::json!([predecessor]);
    resign_canonical_event(&mut body["authorize_event"]["event"]);
}

async fn post_account_device_pair(
    state: AppState,
    token: &str,
    new_device_id: &str,
    challenge_signature: &str,
    predecessor: &str,
) -> (StatusCode, Value) {
    let mut body = account_device_pair_body(new_device_id);
    bind_pair_authorize_predecessor(&mut body, predecessor);
    if challenge_signature == "!" {
        body["challenge_proof"]["signature"] = Value::String("!".to_owned());
    }
    let mut response = TestClient::post("http://server/_arkret/gate/account/device-pair")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_request_body(&body))
        .send(&app_from_state(state))
        .await;
    let status = response.status_code.expect("device-pair status");
    let body = response.take_json().await.expect("device-pair json");
    (status, body)
}

#[test]
fn account_device_pair_registers_sibling_via_canonical_gate_route() {
    run_on_deep_stack(
        "account_device_pair_registers_sibling_via_canonical_gate_route",
        account_device_pair_registers_sibling_via_canonical_gate_route_body,
    );
}

async fn account_device_pair_registers_sibling_via_canonical_gate_route_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let predecessor = project_test_authorized_device(
        &state,
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        &SigningKey::from_bytes(&[21_u8; 32]),
    )
    .await;
    let sibling = "ak:device:01904100-0000-7000-8000-9b04e0000008";
    let mut sibling_pair_body = account_device_pair_body(sibling);
    bind_pair_authorize_predecessor(&mut sibling_pair_body, &predecessor);

    let unauthenticated = TestClient::post("http://server/_arkret/gate/account/device-pair")
        .add_header("content-type", "application/json", true)
        .body(canonical_request_body(&sibling_pair_body))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthenticated.status_code, Some(StatusCode::UNAUTHORIZED));

    sibling_pair_body["display_name"] = Value::String("Paired Phone".to_owned());
    sibling_pair_body["device_metadata"] = serde_json::json!({"platform": "ios"});
    let mut paired = post_authenticated_canonical(
        state.clone(),
        &token,
        "http://server/_arkret/gate/account/device-pair",
        &sibling_pair_body,
    )
    .await;
    let status = paired.status_code;
    let body: Value = paired.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "{body}");
    assert_eq!(body["device_id"], sibling);
    assert!(body["authorized_event_ref"].as_str().is_some());
    let paired_device = state
        .test_persistence()
        .devices()
        .get(
            fixture_actor_core_id("did:web:alice.example").as_str(),
            sibling,
        )
        .await
        .unwrap()
        .expect("accepted pairing projects the sibling device");
    assert_eq!(paired_device.verification_state, "verified");
}

#[test]
fn account_device_pair_rejects_untrusted_authorizers_and_bad_proofs() {
    run_on_deep_stack(
        "account_device_pair_rejects_untrusted_authorizers_and_bad_proofs",
        account_device_pair_rejects_untrusted_authorizers_and_bad_proofs_body,
    );
}

async fn account_device_pair_rejects_untrusted_authorizers_and_bad_proofs_body() {
    let state = soland_test_support::app_state(test_config());
    let actor = "did:web:alice.example";
    let trusted_device = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let unverified_device = "ak:device:01904100-0000-7000-8000-9b04e0000008";
    let first_new_device = "ak:device:01904100-0000-7000-8000-9b04e0000009";
    let second_new_device = "ak:device:01904100-0000-7000-8000-9b04e000000a";

    let trusted_token =
        dev_token_for_device(state.clone(), actor, trusted_device, "Alice Desktop").await;
    let unverified_token =
        dev_token_for_device(state.clone(), actor, unverified_device, "Alice Browser").await;
    let predecessor = project_test_authorized_device(
        &state,
        actor,
        trusted_device,
        &SigningKey::from_bytes(&[21_u8; 32]),
    )
    .await;

    let (status, body) = post_account_device_pair(
        state.clone(),
        &unverified_token,
        first_new_device,
        "c2ln",
        &predecessor,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(problem_code(&body), "device_unauthorized", "{body}");

    let (status, body) = post_account_device_pair(
        state.clone(),
        &trusted_token,
        second_new_device,
        "!",
        &predecessor,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(problem_code(&body), "schema_violation", "{body}");

    let (status, body) = post_account_device_pair(
        state.clone(),
        &trusted_token,
        trusted_device,
        "c2ln",
        &predecessor,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(problem_code(&body), "cannot_pair_current_device", "{body}");

    let (status, body) = post_account_device_pair(
        state.clone(),
        &trusted_token,
        first_new_device,
        "c2ln",
        &predecessor,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["device_id"], first_new_device);
    let paired = state
        .test_persistence()
        .devices()
        .get(fixture_actor_core_id(actor).as_str(), first_new_device)
        .await
        .unwrap()
        .expect("valid pairing persists the candidate device");
    assert_eq!(paired.verification_state, "verified");
}

#[test]
fn to_device_pairing_request_reaches_existing_device_and_gate_pair_authorizes_new_device() {
    run_on_deep_stack(
        "to_device_pairing_request_reaches_existing_device_and_gate_pair_authorizes_new_device",
        to_device_pairing_request_reaches_existing_device_and_gate_pair_authorizes_new_device_body,
    );
}

async fn to_device_pairing_request_reaches_existing_device_and_gate_pair_authorizes_new_device_body()
 {
    let state = soland_test_support::app_state(test_config());
    let actor = "did:web:alice.example";
    let existing_device = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let new_device = "ak:device:01904100-0000-7000-8000-9b04e0000008";
    let existing_token =
        dev_token_for_device(state.clone(), actor, existing_device, "Alice Desktop").await;
    let new_token = dev_token_for_device(state.clone(), actor, new_device, "Alice Browser").await;
    let predecessor = project_test_authorized_device(
        &state,
        actor,
        existing_device,
        &SigningKey::from_bytes(&[21_u8; 32]),
    )
    .await;
    let mut pair_body = account_device_pair_body(new_device);
    bind_pair_authorize_predecessor(&mut pair_body, &predecessor);
    let request_content = serde_json::json!({
        "transaction_id": "txn-device-pair-1",
        "from_device_id": new_device,
        "timestamp": arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
        "expires_at": arkret_canonical::format_timestamp_canonical(
            chrono::Utc::now() + chrono::Duration::minutes(10)
        ),
        "methods": ["ak.key.verification.sas_v1", "ak.key.verification.qr_v1"],
        "purpose": "same_principal_device_authorization",
        "pairing_code": "7H2K9M4Q",
        "new_device_pubkey": pair_body["new_device_pubkey"],
        "challenge_proof": pair_body["challenge_proof"],
        "challenge_transcript": pair_body["challenge_transcript"],
        "gate_audience_uri": "http://server",
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
    let actor_core = fixture_actor_core_id(actor).to_string();
    actor_targets.insert(actor_core.clone(), Value::Object(device_targets));
    let message_batch = serde_json::json!({"messages": actor_targets});
    let sent: Value = TestClient::post("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {new_token}"), true)
        .add_header("Idempotency-Key", "device-pair-request-1", true)
        .add_header("content-type", "application/json", true)
        .body(canonical_request_body(&message_batch))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(sent["delivered"][&actor_core][0], existing_device);

    let subscribe =
        account_subscribe_frame(state.clone(), Some(&existing_token), "catchup=true").await;
    let subscribe_messages = subscribe["to_device"]["messages"].as_array().unwrap();
    assert_eq!(
        subscribe_messages.len(),
        1,
        "subscribe response: {subscribe}"
    );
    assert_eq!(subscribe_messages[0]["kind"], "ak.key.verification.request");
    assert_eq!(
        subscribe_messages[0]["sender_account_id"],
        serde_json::json!({"principal_id": actor_core, "station_id": state.service_id()})
    );
    assert_eq!(subscribe_messages[0]["sender_device_id"], new_device);
    assert_eq!(
        subscribe_messages[0]["recipient_account_id"],
        serde_json::json!({"principal_id": actor_core, "station_id": state.service_id()})
    );
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
    let before = state
        .test_persistence()
        .devices()
        .get(&actor_core, new_device)
        .await
        .unwrap()
        .expect("unverified device fixture");
    let mut paired = post_authenticated_canonical(
        state.clone(),
        &existing_token,
        "http://server/_arkret/gate/account/device-pair",
        &approved_body,
    )
    .await;
    let status = paired.status_code;
    let body: Value = paired.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "{body}");
    assert_eq!(body["device_id"], new_device);
    let after = state
        .test_persistence()
        .devices()
        .get(&actor_core, new_device)
        .await
        .unwrap()
        .expect("paired device projection");
    assert_eq!(before.verification_state, "unverified");
    assert_eq!(after.verification_state, "verified");
    assert_ne!(after.payload, before.payload);
    assert!(after.updated_at >= before.updated_at);
}

#[test]
fn to_device_capacity_eviction_sets_lost_watermark() {
    run_on_deep_stack(
        "to_device_capacity_eviction_sets_lost_watermark",
        to_device_capacity_eviction_sets_lost_watermark_body,
    );
}

async fn to_device_capacity_eviction_sets_lost_watermark_body() {
    let mut config = test_config();
    config.to_device_queue_capacity = 2;
    let state = soland_test_support::app_state(config);
    let alice_token = dev_token(state.clone()).await;
    let bob = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-b0b000000001";
    let bob_token =
        verified_dev_token_for_device(state.clone(), bob, bob_device, "Bob Phone").await;

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
        let bob_core = fixture_actor_core_id(bob).to_string();
        actor_targets.insert(bob_core.clone(), Value::Object(device_targets));
        let sent: Value = TestClient::post("http://server/_arkret/self/device_messages")
            .add_header("authorization", format!("Bearer {alice_token}"), true)
            .add_header("Idempotency-Key", format!("capacity-{seq}"), true)
            .add_header("content-type", "application/json", true)
            .body(canonical_request_body(&serde_json::json!({
                "messages": actor_targets
            })))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
        assert_eq!(sent["delivered"][&bob_core][0], bob_device);
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
    assert_eq!(messages.len(), 2, "device messages response: {pulled}");
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

#[test]
fn protocol_device_surface_excludes_pairing_request_scaffold() {
    run_on_deep_stack(
        "protocol_device_surface_excludes_pairing_request_scaffold",
        protocol_device_surface_excludes_pairing_request_scaffold_body,
    );
}

async fn protocol_device_surface_excludes_pairing_request_scaffold_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;

    let create = TestClient::post("http://server/_arkret/gate/account/device-pairing-requests")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_request_body(&serde_json::json!({
            "pairing_code": "7H2K9M4Q",
            "new_device_pubkey": {
                "kid": "ak:device:01904100-0000-7000-8000-9b04e0000007",
                "algorithm": "Ed25519",
                "public_key": "emtleQ"
            },
            "challenge_signature": "c2ln"
        })))
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
        .add_header("content-type", "application/json", true)
        .body(canonical_request_body(&serde_json::json!({
            "device_id": "ak:device:01904100-0000-7000-8000-9b04e0000007"
        })))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(soland_challenge.status_code, Some(StatusCode::NOT_FOUND));

    let soland_authorize = TestClient::post("http://server/_soland/self/devices/authorize-pairing")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_request_body(&serde_json::json!({
            "device_id": "ak:device:01904100-0000-7000-8000-9b04e0000007"
        })))
        .send(&app_from_state(state))
        .await;
    assert_eq!(soland_authorize.status_code, Some(StatusCode::NOT_FOUND));
}

#[test]
fn rtc_media_token_uses_projected_media_service_epoch() {
    run_on_deep_stack(
        "rtc_media_token_uses_projected_media_service_epoch",
        rtc_media_token_uses_projected_media_service_epoch_body,
    );
}

async fn rtc_media_token_uses_projected_media_service_epoch_body() {
    let state = soland_test_support::app_state(test_config());
    install_media_service_epoch(&state, good_media_service_epoch(&state));
    let token = dev_token(state.clone()).await;
    assert_eq!(
        add_test_realm_member(&state, demo_realm_id(), "did:web:alice.example")["ok"],
        true
    );
    // Brand-new call: no durable call cells exist yet (the initiator redeems a
    // media token before writing its first `ak.call.state` event). With no
    // committed `session_focus`, the issuer admits the requested focus as long
    // as it is a legal focus within the realm media_service epoch.
    let session_id = authored_call_id();

    // `media-service-binding.md` §6 — token exchange requires `ak.call.join`;
    // realm membership alone is insufficient.
    grant_call_capability(
        &state,
        demo_realm_id(),
        "did:web:alice.example",
        arkret_wire::CapabilityActionId::CallJoin.as_str(),
    );

    let issued_before = chrono::Utc::now();
    let token_response: Value = TestClient::post("http://server/_arkret/self/rtc/token")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_request_body(&serde_json::json!({
            "realm_id": demo_realm_id(),
            "call_id": session_id,
            "actor_id": local_media_actor(&state, "did:web:alice.example"),
            "device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001",
            "focus_id": "arkret_native_blue"
        })))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(
        token_response["connect_url"], "wss://media.example/arkret-native",
        "{token_response}"
    );
    // Spec `CallMediaTokenExchangeOutcome` required fields: focus_id + backend_kind
    // identify the chosen focus and its backend protocol; `todos` is not a
    // schema field and must not appear.
    assert_eq!(token_response["focus_id"], "arkret_native_blue");
    assert_eq!(token_response["backend_kind"], "arkret_native");
    assert!(token_response.get("todos").is_none());
    // §3 — the signing key is this deployment's configuration, not a cell
    // field; the cell only anchors it through `service_id`.
    assert_eq!(
        token_response["participant_binding"]["issuer_kid"],
        test_media_issuer_kid(&state)
    );
    assert_eq!(
        token_response["participant_binding"]["realm_id"],
        demo_realm_id()
    );
    assert_eq!(token_response["participant_binding"]["call_id"], session_id);
    assert_eq!(
        token_response["participant_binding"]["actor_id"],
        serde_json::to_value(local_media_actor(&state, "did:web:alice.example")).unwrap(),
        "the signed participant binding must retain the exact Station account"
    );
    assert_eq!(
        token_response["participant_binding"]["device_id"],
        "ak:device:01904100-0000-7000-8000-a11ce0000001"
    );
    assert_eq!(
        token_response["participant_binding"]["focus_id"],
        "arkret_native_blue"
    );
    // `media-service-binding.md` §3 — participant_binding.sig is the single
    // issuer assertion over the seven-tuple signing input; there is no parallel
    // service_signature covering the same bytes.
    assert_eq!(
        token_response["participant_binding"]["issuer_kid"],
        test_media_issuer_kid(&state)
    );
    assert!(
        token_response["participant_binding"]["sig"]
            .as_str()
            .is_some_and(|sig| !sig.is_empty()),
        "participant_binding.sig must be a non-empty base64url detached signature"
    );
    assert!(
        token_response.get("service_signature").is_none(),
        "the outcome MUST NOT carry a redundant second signature over the same bytes"
    );

    // §3 — participant_id is a random `ak:rtc_participant:<uuidv7>` SFU
    // handle, NOT a deterministic hash of the principal tuple.
    let participant_id = token_response["participant_id"].as_str().unwrap();
    assert!(
        participant_id.starts_with("ak:rtc_participant:"),
        "participant_id must be a typed ak:rtc_participant id"
    );
    assert!(
        arkret_identifiers::is_lowercase_typed_uuid(
            participant_id.strip_prefix("ak:rtc_participant:").unwrap(),
            arkret_identifiers::UUID_VERSION_PRODUCER_ALLOCATED,
        ),
        "participant_id payload must be a canonical lowercase uuidv7"
    );
    assert_eq!(
        token_response["participant_binding"]["participant_id"],
        participant_id
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

    // `bindings/arkret-native.md` §2 — the backend token is that binding's own
    // object, and its payload carries no long-term actor identity: the SFU sees
    // only the per-exchange `participant_id` pseudonym.
    let backend_token = &token_response["backend_token"];
    assert_eq!(backend_token["kid"], test_media_issuer_kid(&state));
    assert_eq!(backend_token["signature_algorithm"], "Ed25519");
    assert!(
        backend_token["sig"]
            .as_str()
            .is_some_and(|sig| !sig.is_empty())
    );
    let backend_payload = &backend_token["payload"];
    assert_eq!(backend_payload["call_id"], session_id);
    assert_eq!(backend_payload["focus_id"], "arkret_native_blue");
    assert_eq!(backend_payload["participant_id"], participant_id);
    for forbidden in ["actor_id", "device_id", "realm_id", "aud", "provider"] {
        assert!(
            backend_payload.get(forbidden).is_none(),
            "backend token must not carry {forbidden}"
        );
    }

    let second_token_response: Value = TestClient::post("http://server/_arkret/self/rtc/token")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_request_body(&serde_json::json!({
            "realm_id": demo_realm_id(),
            "call_id": session_id,
            "actor_id": local_media_actor(&state, "did:web:alice.example"),
            "device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001",
            "focus_id": "arkret_native_blue"
        })))
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
#[test]
fn rtc_media_token_inkson_flow_no_session_issues_token() {
    run_on_deep_stack(
        "rtc_media_token_inkson_flow_no_session_issues_token",
        rtc_media_token_inkson_flow_no_session_issues_token_body,
    );
}

async fn rtc_media_token_inkson_flow_no_session_issues_token_body() {
    let state = soland_test_support::app_state(livekit_test_config());
    install_media_service_epoch(&state, good_media_service_epoch(&state));
    // Use a non-owner member so the pre-grant assertion actually isolates
    // `ak.call.join`; the seeded Alice account is the demo Realm owner and
    // owners receive ordinary Realm-level capabilities by default.
    let actor = "did:web:bob.example";
    let device_id = "ak:device:01904100-0000-7000-8000-b0b000000003";
    add_test_realm_member(&state, demo_realm_id(), actor);
    let token = dev_token_for_device(state.clone(), actor, device_id, "Bob Phone").await;
    // A fresh call id with no durable call cell and no ephemeral session.
    let call_id = authored_call_id();

    // Without ak.call.join, even a realm member is denied (§6).
    let mut denied = TestClient::post("http://server/_arkret/self/rtc/token")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_request_body(&serde_json::json!({
            "realm_id": demo_realm_id(),
            "call_id": call_id,
            "actor_id": local_media_actor(&state, actor),
            "device_id": device_id,
            "focus_id": "livekit_green"
        })))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(denied.status_code, Some(StatusCode::FORBIDDEN));
    let denied_body: Value = denied.take_json().await.unwrap();
    assert_eq!(problem_code(&denied_body), "capability_denied");

    // Grant ak.call.join → the token is issued against the brand-new call even
    // though no signaling session or durable call cell exists.
    grant_call_capability(
        &state,
        demo_realm_id(),
        actor,
        arkret_wire::CapabilityActionId::CallJoin.as_str(),
    );
    let issued: Value = TestClient::post("http://server/_arkret/self/rtc/token")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_request_body(&serde_json::json!({
            "realm_id": demo_realm_id(),
            "call_id": call_id,
            "actor_id": local_media_actor(&state, actor),
            "device_id": device_id,
            "focus_id": "livekit_green"
        })))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(issued["focus_id"], "livekit_green", "{issued}");
    assert_eq!(issued["connect_url"], "wss://media.example/livekit");
    assert!(
        issued["participant_id"]
            .as_str()
            .unwrap()
            .starts_with("ak:rtc_participant:"),
        "a token MUST be minted with a fresh participant_id"
    );
    assert_eq!(issued["participant_binding"]["call_id"], call_id);
    assert!(
        issued["participant_binding"]["sig"]
            .as_str()
            .is_some_and(|sig| !sig.is_empty()),
        "the issued token MUST carry a detached participant-binding signature"
    );
}

#[test]
fn rtc_media_token_rejects_epoch_and_focus_mismatches() {
    run_on_deep_stack(
        "rtc_media_token_rejects_epoch_and_focus_mismatches",
        rtc_media_token_rejects_epoch_and_focus_mismatches_body,
    );
}

async fn rtc_media_token_rejects_epoch_and_focus_mismatches_body() {
    let state = soland_test_support::app_state(test_config());
    install_media_service_epoch(&state, good_media_service_epoch(&state));
    let token = dev_token(state.clone()).await;
    assert_eq!(
        add_test_realm_member(&state, demo_realm_id(), "did:web:alice.example")["ok"],
        true
    );
    let session_id = authored_call_id();
    // §6 — grant ak.call.join so the join gate passes and the focus/issuer
    // mismatch errors (not capability_denied) are what surfaces.
    grant_call_capability(
        &state,
        demo_realm_id(),
        "did:web:alice.example",
        arkret_wire::CapabilityActionId::CallJoin.as_str(),
    );

    // Commit `session_focus = arkret_native:blue` into the durable focus cell
    // (§4.1 write-once). A token request naming a different focus MUST be
    // rejected with `focus_mismatch`.
    seed_call_state(&state, &session_id, Some("arkret_native_blue"), vec![]);

    let mut focus_mismatch = TestClient::post("http://server/_arkret/self/rtc/token")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_request_body(&serde_json::json!({
            "realm_id": demo_realm_id(),
            "call_id": session_id,
            "actor_id": local_media_actor(&state, "did:web:alice.example"),
            "device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001",
            "focus_id": "livekit_green"
        })))
        .send(&app_from_state(state.clone()))
        .await;
    let focus_mismatch_body: Value = focus_mismatch.take_json().await.unwrap();
    assert_eq!(problem_code(&focus_mismatch_body), "focus_mismatch");

    // A cell sealed to somebody else's media service: this deployment's signing
    // key does not project onto that `service_id`, so it must refuse to mint.
    install_media_service_epoch(
        &state,
        serde_json::json!({
            "service_id": "ak:did_core:webvh:z6mkrogueexampleservice",
            "foci": [{
                "focus_id": "arkret_native_blue",
                "focus_kind": "arkret_native",
                "token_endpoint": "https://server.test/_arkret/self/rtc/token",
                "connect_url": "wss://media.example/arkret-native"
            }]
        }),
    );
    let mut issuer_mismatch = TestClient::post("http://server/_arkret/self/rtc/token")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_request_body(&serde_json::json!({
            "realm_id": demo_realm_id(),
            "call_id": session_id,
            "actor_id": local_media_actor(&state, "did:web:alice.example"),
            "device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001",
            "focus_id": "arkret_native_blue"
        })))
        .send(&app_from_state(state))
        .await;
    let issuer_mismatch_body: Value = issuer_mismatch.take_json().await.unwrap();
    assert_eq!(
        problem_code(&issuer_mismatch_body),
        "token_issuer_unauthorised"
    );
}

#[test]
fn rtc_media_token_rejects_non_member_actor() {
    run_on_deep_stack(
        "rtc_media_token_rejects_non_member_actor",
        rtc_media_token_rejects_non_member_actor_body,
    );
}

async fn rtc_media_token_rejects_non_member_actor_body() {
    let state = soland_test_support::app_state(test_config());
    install_media_service_epoch(&state, good_media_service_epoch(&state));
    let _token = dev_token(state.clone()).await;
    let session_id = authored_call_id();
    let bob_token = dev_token_for_device(
        state.clone(),
        "did:web:bob.example",
        "ak:device:01904100-0000-7000-8000-b0b000000001",
        "Bob Phone",
    )
    .await;

    let mut response = TestClient::post("http://server/_arkret/self/rtc/token")
        .add_header("authorization", format!("Bearer {bob_token}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_request_body(&serde_json::json!({
            "realm_id": demo_realm_id(),
            "call_id": session_id,
            "actor_id": local_media_actor(&state, "did:web:bob.example"),
            "device_id": "ak:device:01904100-0000-7000-8000-b0b000000001",
            "focus_id": "livekit_green"
        })))
        .send(&app_from_state(state))
        .await;
    assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(problem_code(&body), "capability_denied");
}

#[test]
fn rtc_media_token_requires_call_join_capability() {
    run_on_deep_stack(
        "rtc_media_token_requires_call_join_capability",
        rtc_media_token_requires_call_join_capability_body,
    );
}

async fn rtc_media_token_requires_call_join_capability_body() {
    // `media-service-binding.md` §6 — a realm member + call participant that
    // does NOT hold ak.call.join is denied; granting the capability lets the
    // exchange proceed.
    // Use the LiveKit-configured deployment so the oldest-membership default
    // focus (`livekit_green`) can mint a real token once join is held.
    let state = soland_test_support::app_state(livekit_test_config());
    install_media_service_epoch(&state, good_media_service_epoch(&state));
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
        "realm_id": demo_realm_id(),
        "call_id": session_id,
        "actor_id": local_media_actor(&state, bob),
        "device_id": bob_device,
        "focus_id": "livekit_green"
    });

    // No ak.call.join → capability_denied even though bob is a member+participant.
    let mut denied = TestClient::post("http://server/_arkret/self/rtc/token")
        .add_header("authorization", format!("Bearer {bob_token}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_request_body(&exchange_body))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(denied.status_code, Some(StatusCode::FORBIDDEN));
    let denied_body: Value = denied.take_json().await.unwrap();
    assert_eq!(problem_code(&denied_body), "capability_denied");

    // After granting ak.call.join, the exchange is admitted (focus matches the
    // oldest-membership default).
    grant_call_capability(
        &state,
        demo_realm_id(),
        bob,
        arkret_wire::CapabilityActionId::CallJoin.as_str(),
    );
    let granted: Value = TestClient::post("http://server/_arkret/self/rtc/token")
        .add_header("authorization", format!("Bearer {bob_token}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_request_body(&exchange_body))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(granted["focus_id"], "livekit_green", "{granted}");
    assert!(
        granted["participant_id"]
            .as_str()
            .unwrap()
            .starts_with("ak:rtc_participant:")
    );
}

/// LiveKit API Key used in tests. `bindings/livekit.md` §2 maps it to the JWT
/// `iss`. It is deployment configuration and never a Realm cell field: a
/// backend API credential has no business inside signed Realm policy.
const TEST_LIVEKIT_API_KEY: &str = "livekit-test-api-key";
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

#[test]
fn rtc_media_token_livekit_backend_token_carries_livekit_claims() {
    run_on_deep_stack(
        "rtc_media_token_livekit_backend_token_carries_livekit_claims",
        rtc_media_token_livekit_backend_token_carries_livekit_claims_body,
    );
}

async fn rtc_media_token_livekit_backend_token_carries_livekit_claims_body() {
    let state = soland_test_support::app_state(livekit_test_config());
    install_media_service_epoch(&state, good_media_service_epoch(&state));
    let token = dev_token(state.clone()).await;
    assert_eq!(
        add_test_realm_member(&state, demo_realm_id(), "did:web:alice.example")["ok"],
        true
    );
    let session_id = authored_call_id();
    // §6 — token exchange requires ak.call.join.
    grant_call_capability(
        &state,
        demo_realm_id(),
        "did:web:alice.example",
        arkret_wire::CapabilityActionId::CallJoin.as_str(),
    );

    // No committed session_focus: the request directly names the livekit focus,
    // which is admitted because it is a legal focus in the epoch.
    let issued_before = chrono::Utc::now();
    let token_response: Value = TestClient::post("http://server/_arkret/self/rtc/token")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_request_body(&serde_json::json!({
            "realm_id": demo_realm_id(),
            "call_id": session_id,
            "actor_id": local_media_actor(&state, "did:web:alice.example"),
            "device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001",
            "focus_id": "livekit_green",
            "desired_media": {"audio": true, "video": true, "screen": false}
        })))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        token_response["backend_kind"], "livekit",
        "{token_response}"
    );
    assert_eq!(token_response["connect_url"], "wss://media.example/livekit");

    // `bindings/livekit.md` §2 — the backend_token is a real LiveKit JWT:
    // `base64url(header).base64url(payload).base64url(HMAC-SHA256)`. It MUST
    // The header MUST be
    // `{alg:HS256,typ:JWT}`, and the signature MUST verify under the
    // configured API Secret.
    let backend_token = token_response["backend_token"].as_str().unwrap();
    assert!(
        !backend_token.starts_with("livekit."),
        "LiveKit backend_token must be a standard JWT"
    );
    let claims = verify_livekit_jwt(backend_token, TEST_LIVEKIT_API_SECRET.as_bytes());
    // §2: `iss` = LiveKit API Key.
    assert_eq!(claims["iss"], TEST_LIVEKIT_API_KEY);
    assert_eq!(claims["sub"], token_response["participant_id"]);
    // §2: `name` MUST NOT leak actor identity — equals participant_id.
    assert_eq!(claims["name"], token_response["participant_id"]);
    assert_eq!(claims["video"]["roomJoin"], true);
    assert_eq!(claims["video"]["canPublish"], true);
    assert_eq!(claims["video"]["canSubscribe"], true);
    assert_eq!(claims["video"]["recorder"], false);
    assert_eq!(claims["video"]["hidden"], false);
    let room = claims["video"]["room"].as_str().unwrap();
    assert!(room.starts_with("ak_call_"));
    assert!(!room.contains(&session_id));
    let room_material = format!("{}\0{session_id}\0livekit_green", demo_realm_id());
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

#[test]
fn admin_realm_media_service_renders_projected_cell() {
    run_on_deep_stack(
        "admin_realm_media_service_renders_projected_cell",
        admin_realm_media_service_renders_projected_cell_body,
    );
}

async fn admin_realm_media_service_renders_projected_cell_body() {
    let state = soland_test_support::app_state(test_config());
    install_media_service_epoch(&state, good_media_service_epoch(&state));
    let token = dev_token(state.clone()).await;

    let media_service: Value = TestClient::get(format!(
        "http://server/_soland/admin/realms/{}/media-service",
        demo_realm_id()
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(media_service["realm_id"], demo_realm_id());
    assert_eq!(media_service["service_id"], state.service_id().as_str());
    let foci = media_service["foci"].as_array().unwrap();
    assert_eq!(foci.len(), 2);
    let livekit = foci
        .iter()
        .find(|focus| focus["focus_id"] == "livekit_green")
        .expect("livekit focus renders");
    // `token_endpoint` / `connect_url` are normative required fields, so the
    // operator view shows them verbatim rather than falling back to a dash.
    assert_eq!(livekit["focus_kind"], "livekit");
    assert_eq!(
        livekit["token_endpoint"],
        "https://server.test/_arkret/self/rtc/token"
    );
    assert_eq!(livekit["connect_url"], "wss://media.example/livekit");

    // A Realm with no committed epoch renders an empty (but well-typed) view.
    let other_realm = "ak:realm:ASdf4eIWF6PRMc-8Gd-gIixaHGjUJGN1G-tVBdF9xOQy";
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

#[test]
fn webrtc_ban_blocks_removed_participant_token_reissue() {
    run_on_deep_stack(
        "webrtc_ban_blocks_removed_participant_token_reissue",
        webrtc_ban_blocks_removed_participant_token_reissue_body,
    );
}

async fn webrtc_ban_blocks_removed_participant_token_reissue_body() {
    let state = soland_test_support::app_state(livekit_test_config());
    install_media_service_epoch(&state, good_media_service_epoch(&state));
    let _alice_token = dev_token(state.clone()).await;
    let bob = "did:web:bob.example";
    let bob_actor = local_media_actor(&state, bob);
    let bob_device = "ak:device:01904100-0000-7000-8000-b0b000000001";
    let bob_token = dev_token_for_device(state.clone(), bob, bob_device, "Bob Phone").await;
    add_test_realm_member(&state, demo_realm_id(), bob);

    let session_id = authored_call_id();
    // §6 — bob needs ak.call.join to exchange a token before the ban.
    grant_call_capability(
        &state,
        demo_realm_id(),
        bob,
        arkret_wire::CapabilityActionId::CallJoin.as_str(),
    );

    // Before the ban, bob can exchange a media token (no committed focus, so
    // the requested epoch-legal focus is admitted).
    let pre_ban: Value = TestClient::post("http://server/_arkret/self/rtc/token")
        .add_header("authorization", format!("Bearer {bob_token}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_request_body(&serde_json::json!({
            "realm_id": demo_realm_id(),
            "call_id": session_id,
            "actor_id": bob_actor,
            "device_id": bob_device,
            "focus_id": "livekit_green"
        })))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(pre_ban["focus_id"], "livekit_green", "{pre_ban}");

    // A moderator actor-wide-bans bob: the durable call moderation OR-Set
    // carries a `ban` value with no `device_id`. Seed that effective cell
    // directly (the reducer writes the same tag/value shape).
    seed_call_state(
        &state,
        &session_id,
        None,
        vec![serde_json::json!({
            "actor_id": bob_actor,
            "action": "ban",
            "removed_at": arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
        })],
    );

    // After the ban, bob's token re-issue is refused with
    // `call_participant_removed` (webrtc-signaling.md §3a).
    let mut post_ban = TestClient::post("http://server/_arkret/self/rtc/token")
        .add_header("authorization", format!("Bearer {bob_token}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_request_body(&serde_json::json!({
            "realm_id": demo_realm_id(),
            "call_id": session_id,
            "actor_id": bob_actor,
            "device_id": bob_device,
            "focus_id": "livekit_green"
        })))
        .send(&app_from_state(state))
        .await;
    assert_eq!(post_ban.status_code, Some(StatusCode::FORBIDDEN));
    let body: Value = post_ban.take_json().await.unwrap();
    assert_eq!(problem_code(&body), "call_participant_removed");
}

/// Grant `subject` a realm-scoped call capability (`action`) in the shared
/// authz engine, mirroring what the capability-grant projection would fold in.
fn grant_call_capability(state: &AppState, realm_id: &str, subject: &str, action: &str) {
    let mut grant = soland_http::authz::projected_grant_fixture(
        realm_id.to_owned(),
        fixture_actor_core_id("did:web:alice.example").to_string(),
        fixture_actor_core_id(subject).to_string(),
        realm_id.to_owned(),
        vec![action.to_owned()],
        vec![],
    );
    grant.issuer_id = local_media_actor(state, "did:web:alice.example");
    grant.subject_id = local_media_actor(state, subject);
    state.test_authz().upsert_projected_grant(grant);
}

/// Register `bob` as a realm member and return a fresh `ak:call:<44-char-event-token>` id.
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
    add_test_realm_member(state, demo_realm_id(), member);
    authored_call_id()
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
            (demo_realm_id().to_owned(), cell_id.as_str().to_owned()),
            CellState::Value(serde_json::json!({"value": media_service})),
        );
}

/// Default media signing key: `<service DID>#media-1`
/// (`SOLAND_MEDIA_ISSUER_KID` overrides it).
fn test_media_issuer_kid(state: &AppState) -> String {
    format!("{}#media-1", state.service_did())
}

/// A spec-shaped `ak.realm.media_service` cell
/// (`event-payload.schema.json#/$defs/realm_media_service_payload`).
///
/// `token_endpoint` names this deployment, because a focus whose token endpoint
/// is somebody else's service is one this server must refuse to mint for. The
/// two backends are the only ones v1 gives a normative binding.
fn good_media_service_epoch(state: &AppState) -> Value {
    serde_json::json!({
        "service_id": state.service_id(),
        "foci": [
            {
                "focus_id": "livekit_green",
                "focus_kind": "livekit",
                "token_endpoint": "https://server.test/_arkret/self/rtc/token",
                "connect_url": "wss://media.example/livekit"
            },
            {
                "focus_id": "arkret_native_blue",
                "focus_kind": "arkret_native",
                "token_endpoint": "https://server.test/_arkret/self/rtc/token",
                "connect_url": "wss://media.example/arkret-native"
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
        demo_realm_id(),
        arkret_wire::ScopeRef::Realm {
            realm_id: RealmId::new(demo_realm_id().to_owned()).unwrap(),
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
#[test]
fn call_signal_relays_to_other_realm_member_and_filters_self_device() {
    run_on_deep_stack(
        "call_signal_relays_to_other_realm_member_and_filters_self_device",
        call_signal_relays_to_other_realm_member_and_filters_self_device_body,
    );
}

async fn call_signal_relays_to_other_realm_member_and_filters_self_device_body() {
    let state = soland_test_support::app_state(test_config());
    add_test_realm_member(&state, demo_realm_id(), WEBRTC_BOB);
    let (alice_token, alice_key) =
        seed_signal_sender_device(&state, WEBRTC_ALICE, WEBRTC_ALICE_DEVICE_A, "Alice Desktop")
            .await;
    let (bob_token, _bob_key) =
        seed_signal_sender_device(&state, WEBRTC_BOB, WEBRTC_BOB_DEVICE, "Bob Phone").await;
    let seal_ref = seed_signal_basis_seal(&state, demo_realm_id(), WEBRTC_ALICE).await;

    let invite = call_signal(
        WEBRTC_ALICE,
        WEBRTC_ALICE_DEVICE_A,
        &seal_ref,
        arkret_wire::SignalClass::Setup,
        "invite",
        &alice_key,
    );
    let mut submit = post_canonical_signal(state.clone(), &alice_token, &invite).await;
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
#[test]
fn call_signal_reaches_same_actor_other_device() {
    run_on_deep_stack(
        "call_signal_reaches_same_actor_other_device",
        call_signal_reaches_same_actor_other_device_body,
    );
}

async fn call_signal_reaches_same_actor_other_device_body() {
    let state = soland_test_support::app_state(test_config());
    let device_b = "ak:device:01904100-0000-7000-8000-a11ce0000002";
    let (token_a, key_a) =
        seed_signal_sender_device(&state, WEBRTC_ALICE, WEBRTC_ALICE_DEVICE_A, "Alice Desktop")
            .await;
    let (token_b, _key_b) =
        seed_signal_sender_device(&state, WEBRTC_ALICE, device_b, "Alice Laptop").await;
    let seal_ref = seed_signal_basis_seal(&state, demo_realm_id(), WEBRTC_ALICE).await;

    let invite = call_signal(
        WEBRTC_ALICE,
        WEBRTC_ALICE_DEVICE_A,
        &seal_ref,
        arkret_wire::SignalClass::Setup,
        "invite",
        &key_a,
    );
    assert_eq!(
        post_canonical_signal(state.clone(), &token_a, &invite)
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
#[test]
fn call_signal_not_delivered_after_ttl_expiry() {
    run_on_deep_stack(
        "call_signal_not_delivered_after_ttl_expiry",
        call_signal_not_delivered_after_ttl_expiry_body,
    );
}

async fn call_signal_not_delivered_after_ttl_expiry_body() {
    let state = soland_test_support::app_state(test_config());
    add_test_realm_member(&state, demo_realm_id(), WEBRTC_BOB);
    let (alice_token, alice_key) =
        seed_signal_sender_device(&state, WEBRTC_ALICE, WEBRTC_ALICE_DEVICE_A, "Alice Desktop")
            .await;
    let (bob_token, _bob_key) =
        seed_signal_sender_device(&state, WEBRTC_BOB, WEBRTC_BOB_DEVICE, "Bob Phone").await;
    let seal_ref = seed_signal_basis_seal(&state, demo_realm_id(), WEBRTC_ALICE).await;

    let invite = call_signal(
        WEBRTC_ALICE,
        WEBRTC_ALICE_DEVICE_A,
        &seal_ref,
        arkret_wire::SignalClass::Setup,
        "invite",
        &alice_key,
    );
    assert_eq!(
        post_canonical_signal(state.clone(), &alice_token, &invite)
            .await
            .status_code,
        Some(StatusCode::OK)
    );
    assert_eq!(
        state
            .test_persistence()
            .signal_relay()
            .list_for_realm(demo_realm_id())
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
            realm_id: demo_realm_id().to_owned(),
            scope_ref: expired.scope_ref.clone(),
            sender_actor_id: expired.sender_actor_id.to_string(),
            sender_device_id: expired.sender_device_id.as_ref().map(ToString::to_string),
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
    let mut over_ceiling = post_canonical_signal(
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
    assert_eq!(problem_code(&over_ceiling_body), "signal_ttl_out_of_range");
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
#[test]
fn call_signal_from_a_non_member_is_denied_and_never_relayed() {
    run_on_deep_stack(
        "call_signal_from_a_non_member_is_denied_and_never_relayed",
        call_signal_from_a_non_member_is_denied_and_never_relayed_body,
    );
}

async fn call_signal_from_a_non_member_is_denied_and_never_relayed_body() {
    let state = soland_test_support::app_state(test_config());
    // Bob is deliberately not added to the demo Realm.
    let outsider_device = "ak:device:01904100-0000-7000-8000-b0b000000004";
    let (token, signing_key) =
        seed_signal_sender_device(&state, WEBRTC_BOB, outsider_device, "Bob Phone").await;
    let seal_ref = seed_signal_basis_seal(&state, demo_realm_id(), WEBRTC_BOB).await;

    let denied = post_canonical_signal(
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
            .list_for_realm(demo_realm_id())
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
#[test]
fn call_signal_resubscribe_does_not_redeliver() {
    run_on_deep_stack(
        "call_signal_resubscribe_does_not_redeliver",
        call_signal_resubscribe_does_not_redeliver_body,
    );
}

async fn call_signal_resubscribe_does_not_redeliver_body() {
    let state = soland_test_support::app_state(test_config());
    add_test_realm_member(&state, demo_realm_id(), WEBRTC_BOB);
    let (alice_token, alice_key) =
        seed_signal_sender_device(&state, WEBRTC_ALICE, WEBRTC_ALICE_DEVICE_A, "Alice Desktop")
            .await;
    let (bob_token, _bob_key) =
        seed_signal_sender_device(&state, WEBRTC_BOB, WEBRTC_BOB_DEVICE, "Bob Phone").await;
    let seal_ref = seed_signal_basis_seal(&state, demo_realm_id(), WEBRTC_ALICE).await;

    let invite = call_signal(
        WEBRTC_ALICE,
        WEBRTC_ALICE_DEVICE_A,
        &seal_ref,
        arkret_wire::SignalClass::Setup,
        "invite",
        &alice_key,
    );
    assert_eq!(
        post_canonical_signal(state.clone(), &alice_token, &invite)
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
        post_canonical_signal(state.clone(), &alice_token, &answer)
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
