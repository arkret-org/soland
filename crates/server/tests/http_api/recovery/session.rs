//! Integration tests — C-P2..C-P5 recovery session lifecycle + completion.

#![allow(unused_imports)]

use std::sync::Arc;

use soland::persistence::SolandMemoryPersistenceStore;

use super::helpers::*;
use crate::common::*;

#[tokio::test(flavor = "multi_thread")]
async fn recovery_session_create_and_get_roundtrip() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[101u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let token = dev_token_for_device(
        state.clone(),
        &principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery",
    )
    .await;

    let session = open_recovery_session(state.clone(), &token, &signing, &principal_id, &vm).await;
    assert_eq!(session["state"], "pending");
    assert_eq!(session["principal_id"], principal_id);
    assert_eq!(session["policy_version"], 1);
    let challenge = session["challenge"].as_str().unwrap();
    assert!(!challenge.is_empty(), "challenge must be issued");
    let session_id = session["recovery_session_id"].as_str().unwrap();
    assert!(session_id.starts_with("ck:recovery_session:"));

    let fetched = get_recovery(
        state,
        &token,
        &format!("/_cokret/root/identity/recovery-sessions/{session_id}"),
        StatusCode::OK,
    )
    .await;
    assert_eq!(fetched["recovery_session_id"], session_id);
    assert_eq!(fetched["challenge"], challenge);
    assert_eq!(fetched["state"], "pending");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_session_create_requires_active_policy() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[102u8; 32]);
    let (principal_id, _vm) = did_key_principal(&signing);
    let token = dev_token_for_device(
        state.clone(),
        &principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery",
    )
    .await;

    let create_body = serde_json::json!({
        "principal_id": principal_id,
        "trust_domain": "ck:trust_domain:soland.local",
        "requesting_device_id": "ck:device:01904100-0000-7000-8000-000000000099",
        "ssk_generation": 1,
    });
    let body = post_recovery(
        state,
        &token,
        "/_cokret/root/identity/recovery-sessions",
        &create_body,
        StatusCode::CONFLICT,
    )
    .await;
    assert_eq!(body["error"]["code"], "recovery_policy_mismatch");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_session_get_enforces_principal_isolation() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing_a = SigningKey::from_bytes(&[103u8; 32]);
    let (principal_a, vm_a) = did_key_principal(&signing_a);
    let token_a = dev_token_for_device(
        state.clone(),
        &principal_a,
        RECOVERY_TEST_DEVICE,
        "RecoveryA",
    )
    .await;
    let session =
        open_recovery_session(state.clone(), &token_a, &signing_a, &principal_a, &vm_a).await;
    let session_id = session["recovery_session_id"].as_str().unwrap();

    // A different principal must NOT be able to read A's session.
    let signing_b = SigningKey::from_bytes(&[104u8; 32]);
    let (principal_b, _vm_b) = did_key_principal(&signing_b);
    let token_b = dev_token_for_device(
        state.clone(),
        &principal_b,
        RECOVERY_TEST_DEVICE_B,
        "RecoveryB",
    )
    .await;
    let body = get_recovery(
        state,
        &token_b,
        &format!("/_cokret/root/identity/recovery-sessions/{session_id}"),
        StatusCode::FORBIDDEN,
    )
    .await;
    assert_eq!(body["error"]["code"], "recovery_principal_isolation");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_session_principal_signing_proof_verifies() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[105u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let token = dev_token_for_device(
        state.clone(),
        &principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery",
    )
    .await;
    let session = open_recovery_session(state.clone(), &token, &signing, &principal_id, &vm).await;
    let session_id = session["recovery_session_id"].as_str().unwrap().to_owned();
    let challenge = session["challenge"].as_str().unwrap().to_owned();
    let signature = sign_recovery_proof(&signing, &session);

    let proof_body = serde_json::json!({
        "proof": {
            "kind": "principal_signing",
            "challenge": challenge,
            "verification_method": vm,
            "alg": "EdDSA",
            "signature": signature,
        },
    });
    let body = post_recovery(
        state.clone(),
        &token,
        &format!("/_cokret/root/identity/recovery-sessions/{session_id}/proofs"),
        &proof_body,
        StatusCode::OK,
    )
    .await;
    assert_eq!(
        body["state"], "verified",
        "valid proof advances to verified"
    );
    assert_eq!(body["verification"], "verified");
    assert_eq!(body["proof_summary"]["kind"], "principal_signing");
    assert!(
        body["proof_summary"]["proof_digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"),
        "proof_digest present: {body}"
    );

    // Verified on re-read, with schema + ssk_generation + proof_summary.
    let fetched = get_recovery(
        state,
        &token,
        &format!("/_cokret/root/identity/recovery-sessions/{session_id}"),
        StatusCode::OK,
    )
    .await;
    assert_eq!(fetched["schema"], "ck.schema.recovery_session.v1");
    assert_eq!(fetched["state"], "verified");
    assert_eq!(fetched["ssk_generation"], 1);
    assert_eq!(fetched["proof_summary"]["kind"], "principal_signing");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_session_principal_signing_rejects_bad_signature() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[111u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let token = dev_token_for_device(
        state.clone(),
        &principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery",
    )
    .await;
    let session = open_recovery_session(state.clone(), &token, &signing, &principal_id, &vm).await;
    let session_id = session["recovery_session_id"].as_str().unwrap().to_owned();
    let challenge = session["challenge"].as_str().unwrap().to_owned();
    // Sign with a DIFFERENT key than the principal's — verification must fail.
    let attacker = SigningKey::from_bytes(&[222u8; 32]);
    let signature = sign_recovery_proof(&attacker, &session);

    let proof_body = serde_json::json!({
        "proof": {
            "kind": "principal_signing",
            "challenge": challenge,
            "verification_method": vm,
            "alg": "EdDSA",
            "signature": signature,
        },
    });
    let body = post_recovery(
        state.clone(),
        &token,
        &format!("/_cokret/root/identity/recovery-sessions/{session_id}/proofs"),
        &proof_body,
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_eq!(body["error"]["code"], "proof_invalid");

    // Session stays pending after a rejected proof.
    let fetched = get_recovery(
        state,
        &token,
        &format!("/_cokret/root/identity/recovery-sessions/{session_id}"),
        StatusCode::OK,
    )
    .await;
    assert_eq!(fetched["state"], "pending");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_session_proof_rejects_challenge_mismatch() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[106u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let token = dev_token_for_device(
        state.clone(),
        &principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery",
    )
    .await;
    let session = open_recovery_session(state.clone(), &token, &signing, &principal_id, &vm).await;
    let session_id = session["recovery_session_id"].as_str().unwrap().to_owned();

    let proof_body = serde_json::json!({
        "proof": { "kind": "principal_signing", "challenge": "not-the-real-challenge" },
    });
    let body = post_recovery(
        state,
        &token,
        &format!("/_cokret/root/identity/recovery-sessions/{session_id}/proofs"),
        &proof_body,
        StatusCode::CONFLICT,
    )
    .await;
    assert_eq!(body["error"]["code"], "recovery_session_challenge_mismatch");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_session_proof_rejects_kind_not_allowed_by_policy() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[107u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let token = dev_token_for_device(
        state.clone(),
        &principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery",
    )
    .await;
    let session = open_recovery_session(state.clone(), &token, &signing, &principal_id, &vm).await;
    let session_id = session["recovery_session_id"].as_str().unwrap().to_owned();
    let challenge = session["challenge"].as_str().unwrap().to_owned();

    // `device_quorum` is a valid enum value but the policy only allows
    // `principal_signing`.
    let proof_body = serde_json::json!({
        "proof": { "kind": "device_quorum", "challenge": challenge },
    });
    let body = post_recovery(
        state,
        &token,
        &format!("/_cokret/root/identity/recovery-sessions/{session_id}/proofs"),
        &proof_body,
        StatusCode::CONFLICT,
    )
    .await;
    assert_eq!(body["error"]["code"], "recovery_proof_kind_not_allowed");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_session_complete_rejects_unverified() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[108u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let token = dev_token_for_device(
        state.clone(),
        &principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery",
    )
    .await;
    let session = open_recovery_session(state.clone(), &token, &signing, &principal_id, &vm).await;
    let session_id = session["recovery_session_id"].as_str().unwrap().to_owned();

    let body = post_recovery(
        state,
        &token,
        &format!("/_cokret/root/identity/recovery-sessions/{session_id}/complete"),
        &serde_json::json!({}),
        StatusCode::CONFLICT,
    )
    .await;
    assert_eq!(body["error"]["code"], "failed_precondition");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_session_complete_authorizes_device_after_verify() {
    // C-P4: a verified session completes by authorizing the requesting device
    // into inventory (real, auth-consulted) + transitioning to `completed`. The
    // canonical operation-stream emission is the acknowledged `production_gap`.
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[112u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let ssk = SigningKey::from_bytes(&[212u8; 32]);
    let usk = SigningKey::from_bytes(&[213u8; 32]);
    seed_cross_signing(&state, &principal_id, &vm, &signing, &ssk, &usk);
    let token = dev_token_for_device(
        state.clone(),
        &principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery",
    )
    .await;
    let session = open_recovery_session(state.clone(), &token, &signing, &principal_id, &vm).await;
    let session_id = session["recovery_session_id"].as_str().unwrap().to_owned();
    let device_id = session["requesting_device_id"].as_str().unwrap().to_owned();
    let challenge = session["challenge"].as_str().unwrap().to_owned();
    let signature = sign_recovery_proof(&signing, &session);

    post_recovery(
        state.clone(),
        &token,
        &format!("/_cokret/root/identity/recovery-sessions/{session_id}/proofs"),
        &serde_json::json!({
            "proof": {
                "kind": "principal_signing",
                "challenge": challenge,
                "verification_method": vm,
                "alg": "EdDSA",
                "signature": signature,
            },
        }),
        StatusCode::OK,
    )
    .await;

    // Client has submitted authorize + list_update to /events (seeded here);
    // completion references their ids.
    let complete_body =
        seed_completion_events(&state, &session, device_authorize_material(&session, &ssk)).await;
    let body = post_recovery(
        state.clone(),
        &token,
        &format!("/_cokret/root/identity/recovery-sessions/{session_id}/complete"),
        &complete_body,
        StatusCode::OK,
    )
    .await;
    // recovery-session.schema.json complete_response (references the durable ids).
    assert_eq!(body["ok"], true);
    assert_eq!(body["state"], "completed");
    assert_eq!(body["device_id"], device_id);
    assert_eq!(body["authorization_event_id"], AUTH_EVENT_ID);
    assert_eq!(body["device_list_update_event_id"], LIST_EVENT_ID);
    assert!(
        body.get("production_gap").is_none(),
        "no production_gap: {body}"
    );

    // The requesting device is now a verified device for the principal.
    let device = state
        .persistence
        .devices()
        .get(&principal_id, &device_id)
        .await
        .unwrap()
        .expect("recovered device authorized");
    assert_eq!(device.verification_state, "verified");

    // Re-read shows completed; a second complete is rejected (not verified)
    // before the body is even inspected.
    let again = post_recovery(
        state,
        &token,
        &format!("/_cokret/root/identity/recovery-sessions/{session_id}/complete"),
        &complete_body,
        StatusCode::CONFLICT,
    )
    .await;
    assert_eq!(again["error"]["code"], "failed_precondition");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_session_complete_rejects_ssk_generation_mismatch() {
    // The authorize event's cross_signing_binding MUST bind the CURRENT accepted
    // generation; a stale/forged generation is rejected.
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[113u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let ssk = SigningKey::from_bytes(&[214u8; 32]);
    let usk = SigningKey::from_bytes(&[215u8; 32]);
    seed_cross_signing(&state, &principal_id, &vm, &signing, &ssk, &usk);
    let token = dev_token_for_device(
        state.clone(),
        &principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery",
    )
    .await;
    let (session, session_id) =
        verified_session_for(&state, &token, &signing, &principal_id, &vm).await;

    let mut material = device_authorize_material(&session, &ssk);
    material["cross_signing_binding"]["ssk_generation"] = serde_json::json!(999);
    let complete_body = seed_completion_events(&state, &session, material).await;
    let body = post_recovery(
        state,
        &token,
        &format!("/_cokret/root/identity/recovery-sessions/{session_id}/complete"),
        &complete_body,
        StatusCode::CONFLICT,
    )
    .await;
    assert_eq!(
        body["error"]["code"],
        "device_recovery_ssk_generation_mismatch"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_complete_rejected_after_cross_signing_reset() {
    // A ck.cross_signing.reset retires the current generation (removes the
    // accepted publish). A device-authorize binding can then no longer verify —
    // completion MUST reject (cross_signing_state_missing), proving reset
    // invalidates stale bindings.
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[117u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let ssk = SigningKey::from_bytes(&[219u8; 32]);
    let usk = SigningKey::from_bytes(&[220u8; 32]);
    seed_cross_signing(&state, &principal_id, &vm, &signing, &ssk, &usk);
    let token = dev_token_for_device(
        state.clone(),
        &principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery",
    )
    .await;
    let (session, session_id) =
        verified_session_for(&state, &token, &signing, &principal_id, &vm).await;

    // Record a cross-signing reset (gen 1 -> 2): drops the accepted publish.
    let reset = serde_json::json!({
        "principal_id": principal_id,
        "trust_domain": "ck:trust_domain:soland.local",
        "reset_event_id": "ck:event:01964137-0000-7000-8000-0000000000aa",
        "previous_generation": 1,
        "new_generation": 2,
        "reset_reason_code": "test-reset",
        "proof": { "kind": "principal_signing", "verification_method": vm, "alg": "EdDSA", "signature": "cGxhY2Vob2xkZXI" },
        "issued_at": "2026-05-30T00:00:00Z",
    });
    let content: cokret_sdk::CrossSigningResetContent =
        serde_json::from_value(reset).expect("reset content");
    state
        .cross_signing
        .lock()
        .unwrap()
        .record_cross_signing_reset(&content)
        .expect("record reset");

    let complete_body =
        seed_completion_events(&state, &session, device_authorize_material(&session, &ssk)).await;
    let body = post_recovery(
        state,
        &token,
        &format!("/_cokret/root/identity/recovery-sessions/{session_id}/complete"),
        &complete_body,
        StatusCode::CONFLICT,
    )
    .await;
    assert_eq!(body["error"]["code"], "cross_signing_state_missing");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_session_complete_rejects_missing_cross_signing_state() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[115u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let ssk = SigningKey::from_bytes(&[215u8; 32]);
    let token = dev_token_for_device(
        state.clone(),
        &principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery",
    )
    .await;
    let (session, session_id) =
        verified_session_for(&state, &token, &signing, &principal_id, &vm).await;
    let complete_body =
        seed_completion_events(&state, &session, device_authorize_material(&session, &ssk)).await;
    let body = post_recovery(
        state,
        &token,
        &format!("/_cokret/root/identity/recovery-sessions/{session_id}/complete"),
        &complete_body,
        StatusCode::CONFLICT,
    )
    .await;
    assert_eq!(body["error"]["code"], "cross_signing_state_missing");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_session_complete_rejects_wrong_ssk_signature() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[116u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let ssk = SigningKey::from_bytes(&[216u8; 32]);
    let usk = SigningKey::from_bytes(&[217u8; 32]);
    seed_cross_signing(&state, &principal_id, &vm, &signing, &ssk, &usk);
    let token = dev_token_for_device(
        state.clone(),
        &principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery",
    )
    .await;
    let (session, session_id) =
        verified_session_for(&state, &token, &signing, &principal_id, &vm).await;
    // Sign with an ATTACKER key, not the accepted SSK.
    let attacker = SigningKey::from_bytes(&[218u8; 32]);
    let complete_body = seed_completion_events(
        &state,
        &session,
        device_authorize_material(&session, &attacker),
    )
    .await;
    let body = post_recovery(
        state,
        &token,
        &format!("/_cokret/root/identity/recovery-sessions/{session_id}/complete"),
        &complete_body,
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_eq!(body["error"]["code"], "proof_invalid");
}
