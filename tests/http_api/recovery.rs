//! Integration tests — REC-1 recovery policy / receipt verification.

use std::sync::Arc;

use serde_json::{Map, Value};
use soland::persistence::{MemoryPersistenceStore, PersistenceStore};
use soland::state::{DeviceInventoryRecord, SessionRecord};

use super::common::*;

const POLICY_FIELDS: &[&str] = &[
    "schema",
    "policy_id",
    "principal_id",
    "version",
    "trust_domain",
    "allowed_proof_kinds",
    "supersedes",
    "issued_at",
    "expires_at",
];

const RECEIPT_FIELDS: &[&str] = &[
    "schema",
    "receipt_id",
    "principal_id",
    "recovery_session_id",
    "policy_id",
    "policy_version",
    "trust_domain",
    "new_device_id",
    "proof_summary",
    "outcome",
    "started_at",
    "completed_at",
];

#[tokio::test(flavor = "multi_thread")]
async fn recovery_persistence_survives_state_restart_and_rejects_replays() {
    let persistence: Arc<dyn PersistenceStore> = Arc::new(MemoryPersistenceStore::new());
    let state = shared_recovery_state(persistence.clone());
    let token = dev_token(state.clone()).await;
    let signing = SigningKey::from_bytes(&[71u8; 32]);
    let (principal_id, verification_method) = did_key_principal(&signing);
    let policy = signed_recovery_policy(
        &signing,
        &principal_id,
        &verification_method,
        1,
        None,
        POLICY_FIELDS,
    );

    post_recovery_policy(state.clone(), &token, &policy, StatusCode::CREATED).await;

    let restarted = shared_recovery_state(persistence.clone());
    let receipt = signed_recovery_receipt(
        &signing,
        &principal_id,
        &verification_method,
        policy["policy_id"].as_str().unwrap(),
        1,
        None,
        RECEIPT_FIELDS,
    );
    post_recovery_receipt(restarted.clone(), &token, &receipt, StatusCode::CREATED).await;
    post_recovery_receipt(restarted.clone(), &token, &receipt, StatusCode::CONFLICT).await;

    let duplicate_version = signed_recovery_policy(
        &signing,
        &principal_id,
        &verification_method,
        1,
        None,
        POLICY_FIELDS,
    );
    post_recovery_policy(restarted, &token, &duplicate_version, StatusCode::CONFLICT).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_policy_rejects_tampered_signature_body() {
    let state = shared_recovery_state(Arc::new(MemoryPersistenceStore::new()));
    let token = dev_token(state.clone()).await;
    let signing = SigningKey::from_bytes(&[72u8; 32]);
    let (principal_id, verification_method) = did_key_principal(&signing);
    let mut policy = signed_recovery_policy(
        &signing,
        &principal_id,
        &verification_method,
        1,
        None,
        POLICY_FIELDS,
    );
    policy["trust_domain"] = serde_json::json!("cx:trust_domain:tampered.example");

    let body = post_recovery_policy(state, &token, &policy, StatusCode::UNAUTHORIZED).await;
    assert_eq!(body["error"]["code"], "proof_invalid");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_policy_production_accepts_verified_payload() {
    let mut config = test_config();
    config.development_mode = false;
    let state = shared_recovery_state_with_config(Arc::new(MemoryPersistenceStore::new()), config);
    let token = "prod_recovery_token";
    seed_bearer_session(&state, token).await;
    let signing = SigningKey::from_bytes(&[77u8; 32]);
    let (principal_id, verification_method) = did_key_principal(&signing);
    let policy = signed_recovery_policy(
        &signing,
        &principal_id,
        &verification_method,
        1,
        None,
        POLICY_FIELDS,
    );

    let body = post_recovery_policy(state, token, &policy, StatusCode::CREATED).await;
    assert_eq!(body["ok"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_policy_rejects_missing_signed_field_coverage() {
    let state = shared_recovery_state(Arc::new(MemoryPersistenceStore::new()));
    let token = dev_token(state.clone()).await;
    let signing = SigningKey::from_bytes(&[73u8; 32]);
    let (principal_id, verification_method) = did_key_principal(&signing);
    let reduced_fields: Vec<&str> = POLICY_FIELDS
        .iter()
        .copied()
        .filter(|field| *field != "trust_domain")
        .collect();
    let policy = signed_recovery_policy(
        &signing,
        &principal_id,
        &verification_method,
        1,
        None,
        &reduced_fields,
    );

    let body = post_recovery_policy(state, &token, &policy, StatusCode::UNAUTHORIZED).await;
    assert_eq!(body["error"]["code"], "proof_invalid");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_receipt_rejects_policy_binding_mismatch() {
    let state = shared_recovery_state(Arc::new(MemoryPersistenceStore::new()));
    let token = dev_token(state.clone()).await;
    let signing = SigningKey::from_bytes(&[74u8; 32]);
    let (principal_id, verification_method) = did_key_principal(&signing);
    let policy = signed_recovery_policy(
        &signing,
        &principal_id,
        &verification_method,
        1,
        None,
        POLICY_FIELDS,
    );
    post_recovery_policy(state.clone(), &token, &policy, StatusCode::CREATED).await;

    let receipt = signed_recovery_receipt(
        &signing,
        &principal_id,
        &verification_method,
        &new_prefixed_uuid7("cx:policy:"),
        1,
        None,
        RECEIPT_FIELDS,
    );
    let body = post_recovery_receipt(state, &token, &receipt, StatusCode::CONFLICT).await;
    assert_eq!(body["error"]["code"], "recovery_policy_id_mismatch");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_receipt_rejects_tampered_proof_digest() {
    let state = shared_recovery_state(Arc::new(MemoryPersistenceStore::new()));
    let token = dev_token(state.clone()).await;
    let signing = SigningKey::from_bytes(&[75u8; 32]);
    let (principal_id, verification_method) = did_key_principal(&signing);
    let policy = signed_recovery_policy(
        &signing,
        &principal_id,
        &verification_method,
        1,
        None,
        POLICY_FIELDS,
    );
    post_recovery_policy(state.clone(), &token, &policy, StatusCode::CREATED).await;

    let mut receipt = signed_recovery_receipt(
        &signing,
        &principal_id,
        &verification_method,
        policy["policy_id"].as_str().unwrap(),
        1,
        None,
        RECEIPT_FIELDS,
    );
    receipt["proof_summary"]["proof_digest"] = serde_json::json!(
        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    );

    let body = post_recovery_receipt(state, &token, &receipt, StatusCode::UNAUTHORIZED).await;
    assert_eq!(body["error"]["code"], "proof_invalid");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_policy_rejects_non_monotonic_supersedes_after_restart() {
    let persistence: Arc<dyn PersistenceStore> = Arc::new(MemoryPersistenceStore::new());
    let state = shared_recovery_state(persistence.clone());
    let token = dev_token(state.clone()).await;
    let signing = SigningKey::from_bytes(&[76u8; 32]);
    let (principal_id, verification_method) = did_key_principal(&signing);
    let v1 = signed_recovery_policy(
        &signing,
        &principal_id,
        &verification_method,
        1,
        None,
        POLICY_FIELDS,
    );
    post_recovery_policy(state.clone(), &token, &v1, StatusCode::CREATED).await;

    let restarted = shared_recovery_state(persistence);
    let v2_wrong_supersedes = signed_recovery_policy(
        &signing,
        &principal_id,
        &verification_method,
        2,
        Some(&new_prefixed_uuid7("cx:policy:")),
        POLICY_FIELDS,
    );
    let body = post_recovery_policy(
        restarted,
        &token,
        &v2_wrong_supersedes,
        StatusCode::CONFLICT,
    )
    .await;
    assert_eq!(body["error"]["code"], "recovery_policy_supersedes_invalid");
}

// ── REC-1 read APIs (C-P1) ─────────────────────────────────────────────────

const RECOVERY_TEST_DEVICE: &str = "cx:device:01904100-0000-7000-8000-a11ce0000001";

#[tokio::test(flavor = "multi_thread")]
async fn recovery_policy_get_returns_active_and_history() {
    let state = shared_recovery_state(Arc::new(MemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[91u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    // Authenticate AS the principal so the read APIs (principal-isolated) see it.
    let token =
        dev_token_for_device(state.clone(), &principal_id, RECOVERY_TEST_DEVICE, "Recovery").await;

    let v1 = signed_recovery_policy(&signing, &principal_id, &vm, 1, None, POLICY_FIELDS);
    let body1 = post_recovery_policy(state.clone(), &token, &v1, StatusCode::CREATED).await;
    let v1_id = body1["policy_id"].as_str().unwrap().to_owned();
    let v2 = signed_recovery_policy(&signing, &principal_id, &vm, 2, Some(&v1_id), POLICY_FIELDS);
    post_recovery_policy(state.clone(), &token, &v2, StatusCode::CREATED).await;

    let active = get_recovery(
        state.clone(),
        &token,
        "/api/v1/identity/recovery-policy",
        StatusCode::OK,
    )
    .await;
    assert_eq!(active["active_policy"]["version"], 2);
    assert_eq!(active["active_policy"]["principal_id"], principal_id);

    let history = get_recovery(
        state,
        &token,
        "/api/v1/identity/recovery-policies",
        StatusCode::OK,
    )
    .await;
    let arr = history["policies"].as_array().unwrap();
    assert_eq!(arr.len(), 2, "history: {history}");
    assert_eq!(arr[0]["version"], 2, "newest first");
    assert_eq!(arr[1]["version"], 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_receipts_get_returns_history() {
    let state = shared_recovery_state(Arc::new(MemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[92u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let token =
        dev_token_for_device(state.clone(), &principal_id, RECOVERY_TEST_DEVICE, "Recovery").await;

    let policy = signed_recovery_policy(&signing, &principal_id, &vm, 1, None, POLICY_FIELDS);
    let pbody = post_recovery_policy(state.clone(), &token, &policy, StatusCode::CREATED).await;
    let policy_id = pbody["policy_id"].as_str().unwrap().to_owned();
    let receipt =
        signed_recovery_receipt(&signing, &principal_id, &vm, &policy_id, 1, None, RECEIPT_FIELDS);
    post_recovery_receipt(state.clone(), &token, &receipt, StatusCode::CREATED).await;

    let body = get_recovery(
        state,
        &token,
        "/api/v1/identity/recovery-receipts",
        StatusCode::OK,
    )
    .await;
    let arr = body["receipts"].as_array().unwrap();
    assert_eq!(arr.len(), 1, "receipts: {body}");
    assert_eq!(arr[0]["policy_id"], policy_id);
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_read_enforces_principal_isolation() {
    let state = shared_recovery_state(Arc::new(MemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[93u8; 32]);
    let (principal_id, _vm) = did_key_principal(&signing);
    let token =
        dev_token_for_device(state.clone(), &principal_id, RECOVERY_TEST_DEVICE, "Recovery").await;

    // Querying ANOTHER principal's recovery state is forbidden.
    let body = get_recovery(
        state,
        &token,
        "/api/v1/identity/recovery-policy?principal_id=did:web:someone-else.example",
        StatusCode::FORBIDDEN,
    )
    .await;
    assert_eq!(body["error"]["code"], "recovery_principal_isolation");
}

// ── C-P2 recovery session lifecycle ────────────────────────────────────────

const RECOVERY_TEST_DEVICE_B: &str = "cx:device:01904100-0000-7000-8000-a11ce0000002";

/// Helper: seed an accepted v1 policy for `principal_id` and open a recovery
/// session against it. Returns the session JSON body.
async fn open_recovery_session(
    state: AppState,
    token: &str,
    signing: &SigningKey,
    principal_id: &str,
    vm: &str,
) -> Value {
    let policy = signed_recovery_policy(signing, principal_id, vm, 1, None, POLICY_FIELDS);
    post_recovery_policy(state.clone(), token, &policy, StatusCode::CREATED).await;
    let create_body = serde_json::json!({
        "trust_domain": "cx:trust_domain:soland.local",
        "requesting_device_id": "cx:device:01904100-0000-7000-8000-000000000099",
    });
    post_recovery(
        state,
        token,
        "/api/v1/identity/recovery-sessions",
        &create_body,
        StatusCode::CREATED,
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_session_create_and_get_roundtrip() {
    let state = shared_recovery_state(Arc::new(MemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[101u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let token =
        dev_token_for_device(state.clone(), &principal_id, RECOVERY_TEST_DEVICE, "Recovery").await;

    let session = open_recovery_session(state.clone(), &token, &signing, &principal_id, &vm).await;
    assert_eq!(session["state"], "pending");
    assert_eq!(session["principal_id"], principal_id);
    assert_eq!(session["policy_version"], 1);
    let challenge = session["challenge"].as_str().unwrap();
    assert!(!challenge.is_empty(), "challenge must be issued");
    let session_id = session["recovery_session_id"].as_str().unwrap();
    assert!(session_id.starts_with("cx:recovery_session:"));

    let fetched = get_recovery(
        state,
        &token,
        &format!("/api/v1/identity/recovery-sessions/{session_id}"),
        StatusCode::OK,
    )
    .await;
    assert_eq!(fetched["recovery_session_id"], session_id);
    assert_eq!(fetched["challenge"], challenge);
    assert_eq!(fetched["state"], "pending");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_session_create_requires_active_policy() {
    let state = shared_recovery_state(Arc::new(MemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[102u8; 32]);
    let (principal_id, _vm) = did_key_principal(&signing);
    let token =
        dev_token_for_device(state.clone(), &principal_id, RECOVERY_TEST_DEVICE, "Recovery").await;

    let create_body = serde_json::json!({
        "trust_domain": "cx:trust_domain:soland.local",
        "requesting_device_id": "cx:device:01904100-0000-7000-8000-000000000099",
    });
    let body = post_recovery(
        state,
        &token,
        "/api/v1/identity/recovery-sessions",
        &create_body,
        StatusCode::CONFLICT,
    )
    .await;
    assert_eq!(body["error"]["code"], "recovery_policy_missing");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_session_get_enforces_principal_isolation() {
    let state = shared_recovery_state(Arc::new(MemoryPersistenceStore::new()));
    let signing_a = SigningKey::from_bytes(&[103u8; 32]);
    let (principal_a, vm_a) = did_key_principal(&signing_a);
    let token_a =
        dev_token_for_device(state.clone(), &principal_a, RECOVERY_TEST_DEVICE, "RecoveryA").await;
    let session =
        open_recovery_session(state.clone(), &token_a, &signing_a, &principal_a, &vm_a).await;
    let session_id = session["recovery_session_id"].as_str().unwrap();

    // A different principal must NOT be able to read A's session.
    let signing_b = SigningKey::from_bytes(&[104u8; 32]);
    let (principal_b, _vm_b) = did_key_principal(&signing_b);
    let token_b =
        dev_token_for_device(state.clone(), &principal_b, RECOVERY_TEST_DEVICE_B, "RecoveryB").await;
    let body = get_recovery(
        state,
        &token_b,
        &format!("/api/v1/identity/recovery-sessions/{session_id}"),
        StatusCode::FORBIDDEN,
    )
    .await;
    assert_eq!(body["error"]["code"], "recovery_principal_isolation");
}

/// Build the canonical recovery-proof transcript the server reconstructs, and
/// return a base64url Ed25519 signature over it by `signing`.
fn sign_recovery_proof(signing: &SigningKey, session: &Value) -> String {
    let transcript = serde_json::json!({
        "type": "cx.identity.recovery_proof.v1",
        "kind": "principal_signing",
        "principal_id": session["principal_id"],
        "requesting_device_id": session["requesting_device_id"],
        "trust_domain": session["trust_domain"],
        "policy_id": session["policy_id"],
        "policy_version": session["policy_version"],
        "recovery_session_id": session["recovery_session_id"],
        "challenge": session["challenge"],
        "expires_at": session["expires_at"],
    });
    let bytes = contrix_sdk::canonical::canonical_json_bytes(&transcript).unwrap();
    URL_SAFE_NO_PAD.encode(signing.sign(&bytes).to_bytes())
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_session_principal_signing_proof_verifies() {
    let state = shared_recovery_state(Arc::new(MemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[105u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let token =
        dev_token_for_device(state.clone(), &principal_id, RECOVERY_TEST_DEVICE, "Recovery").await;
    let session = open_recovery_session(state.clone(), &token, &signing, &principal_id, &vm).await;
    let session_id = session["recovery_session_id"].as_str().unwrap().to_owned();
    let challenge = session["challenge"].as_str().unwrap().to_owned();
    let signature = sign_recovery_proof(&signing, &session);

    let proof_body = serde_json::json!({
        "proof": {
            "kind": "principal_signing",
            "challenge": challenge,
            "verification_method": vm,
            "signature": signature,
        },
    });
    let body = post_recovery(
        state.clone(),
        &token,
        &format!("/api/v1/identity/recovery-sessions/{session_id}/proofs"),
        &proof_body,
        StatusCode::OK,
    )
    .await;
    assert_eq!(body["ok"], true);
    assert_eq!(body["state"], "verified", "valid proof advances to verified");
    assert_eq!(body["verification"], "verified");

    // Verified on re-read.
    let fetched = get_recovery(
        state,
        &token,
        &format!("/api/v1/identity/recovery-sessions/{session_id}"),
        StatusCode::OK,
    )
    .await;
    assert_eq!(fetched["state"], "verified");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_session_principal_signing_rejects_bad_signature() {
    let state = shared_recovery_state(Arc::new(MemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[111u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let token =
        dev_token_for_device(state.clone(), &principal_id, RECOVERY_TEST_DEVICE, "Recovery").await;
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
            "signature": signature,
        },
    });
    let body = post_recovery(
        state.clone(),
        &token,
        &format!("/api/v1/identity/recovery-sessions/{session_id}/proofs"),
        &proof_body,
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_eq!(body["error"]["code"], "proof_invalid");

    // Session stays pending after a rejected proof.
    let fetched = get_recovery(
        state,
        &token,
        &format!("/api/v1/identity/recovery-sessions/{session_id}"),
        StatusCode::OK,
    )
    .await;
    assert_eq!(fetched["state"], "pending");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_session_proof_rejects_challenge_mismatch() {
    let state = shared_recovery_state(Arc::new(MemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[106u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let token =
        dev_token_for_device(state.clone(), &principal_id, RECOVERY_TEST_DEVICE, "Recovery").await;
    let session = open_recovery_session(state.clone(), &token, &signing, &principal_id, &vm).await;
    let session_id = session["recovery_session_id"].as_str().unwrap().to_owned();

    let proof_body = serde_json::json!({
        "proof": { "kind": "principal_signing", "challenge": "not-the-real-challenge" },
    });
    let body = post_recovery(
        state,
        &token,
        &format!("/api/v1/identity/recovery-sessions/{session_id}/proofs"),
        &proof_body,
        StatusCode::CONFLICT,
    )
    .await;
    assert_eq!(body["error"]["code"], "recovery_session_challenge_mismatch");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_session_proof_rejects_kind_not_allowed_by_policy() {
    let state = shared_recovery_state(Arc::new(MemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[107u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let token =
        dev_token_for_device(state.clone(), &principal_id, RECOVERY_TEST_DEVICE, "Recovery").await;
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
        &format!("/api/v1/identity/recovery-sessions/{session_id}/proofs"),
        &proof_body,
        StatusCode::CONFLICT,
    )
    .await;
    assert_eq!(body["error"]["code"], "recovery_proof_kind_not_allowed");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_session_complete_rejects_unverified() {
    let state = shared_recovery_state(Arc::new(MemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[108u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let token =
        dev_token_for_device(state.clone(), &principal_id, RECOVERY_TEST_DEVICE, "Recovery").await;
    let session = open_recovery_session(state.clone(), &token, &signing, &principal_id, &vm).await;
    let session_id = session["recovery_session_id"].as_str().unwrap().to_owned();

    let body = post_recovery(
        state,
        &token,
        &format!("/api/v1/identity/recovery-sessions/{session_id}/complete"),
        &serde_json::json!({}),
        StatusCode::CONFLICT,
    )
    .await;
    assert_eq!(body["error"]["code"], "recovery_session_not_verified");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_session_complete_authorizes_device_after_verify() {
    // C-P4: a verified session completes by authorizing the requesting device
    // into inventory (real, auth-consulted) + transitioning to `completed`. The
    // canonical operation-stream emission is the acknowledged `production_gap`.
    let state = shared_recovery_state(Arc::new(MemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[112u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let token =
        dev_token_for_device(state.clone(), &principal_id, RECOVERY_TEST_DEVICE, "Recovery").await;
    let session = open_recovery_session(state.clone(), &token, &signing, &principal_id, &vm).await;
    let session_id = session["recovery_session_id"].as_str().unwrap().to_owned();
    let device_id = session["requesting_device_id"].as_str().unwrap().to_owned();
    let challenge = session["challenge"].as_str().unwrap().to_owned();
    let signature = sign_recovery_proof(&signing, &session);

    post_recovery(
        state.clone(),
        &token,
        &format!("/api/v1/identity/recovery-sessions/{session_id}/proofs"),
        &serde_json::json!({
            "proof": {
                "kind": "principal_signing",
                "challenge": challenge,
                "verification_method": vm,
                "signature": signature,
            },
        }),
        StatusCode::OK,
    )
    .await;

    let body = post_recovery(
        state.clone(),
        &token,
        &format!("/api/v1/identity/recovery-sessions/{session_id}/complete"),
        &serde_json::json!({}),
        StatusCode::OK,
    )
    .await;
    assert_eq!(body["state"], "completed");
    assert_eq!(body["device_id"], device_id);
    assert_eq!(body["authorization_event"]["event_kind"], "cx.device.authorize");
    assert_eq!(
        body["production_gap"],
        "authorization_event_not_yet_in_operation_stream"
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

    // Re-read shows completed; a second complete is rejected (not verified).
    let again = post_recovery(
        state,
        &token,
        &format!("/api/v1/identity/recovery-sessions/{session_id}/complete"),
        &serde_json::json!({}),
        StatusCode::CONFLICT,
    )
    .await;
    assert_eq!(again["error"]["code"], "recovery_session_not_verified");
}

async fn post_recovery(
    state: AppState,
    token: &str,
    path: &str,
    body: &Value,
    expected_status: StatusCode,
) -> Value {
    let mut response = TestClient::post(format!("http://server{path}"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(body)
        .send(&app_from_state(state))
        .await;
    let status = response.status_code.unwrap();
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, expected_status, "response body: {body}");
    body
}

async fn get_recovery(
    state: AppState,
    token: &str,
    path: &str,
    expected_status: StatusCode,
) -> Value {
    let mut response = TestClient::get(format!("http://server{path}"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state))
        .await;
    let status = response.status_code.unwrap();
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, expected_status, "response body: {body}");
    body
}

fn shared_recovery_state(persistence: Arc<dyn PersistenceStore>) -> AppState {
    AppState::new_with_persistence(test_config(), Db { pool: None }, persistence)
}

fn shared_recovery_state_with_config(
    persistence: Arc<dyn PersistenceStore>,
    config: soland::config::AppConfig,
) -> AppState {
    AppState::new_with_persistence(config, Db { pool: None }, persistence)
}

async fn seed_bearer_session(state: &AppState, token: &str) {
    let now = chrono::Utc::now();
    let actor = "did:web:alice.example";
    let device_id = "cx:device:01904100-0000-7000-8000-a11ce0000001";
    state
        .persistence
        .sessions()
        .put(&SessionRecord {
            token_hash: test_session_token_hash(token, &state.config.service_did),
            actor: actor.to_owned(),
            device_id: device_id.to_owned(),
            audience: state.config.service_did.clone(),
            expires_at: now + chrono::Duration::minutes(10),
            created_at: now,
            revoked_at: None,
        })
        .await
        .unwrap();
    state
        .persistence
        .devices()
        .put(&DeviceInventoryRecord {
            actor: actor.to_owned(),
            device_id: device_id.to_owned(),
            display_name: Some("Production Test Device".to_owned()),
            verification_state: "verified".to_owned(),
            payload: serde_json::json!({}),
            created_at: now,
            updated_at: now,
            revoked_at: None,
        })
        .await
        .unwrap();
}

fn test_session_token_hash(token: &str, audience: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(audience.as_bytes());
    hasher.update(b":");
    hasher.update(token.as_bytes());
    format!("sha256:{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

fn did_key_principal(signing: &SigningKey) -> (String, String) {
    let multibase = test_ed25519_multibase_public(signing);
    let principal_id = format!("did:key:{multibase}");
    let verification_method = format!("{principal_id}#{multibase}");
    (principal_id, verification_method)
}

fn signed_recovery_policy(
    signing: &SigningKey,
    principal_id: &str,
    verification_method: &str,
    version: u32,
    supersedes: Option<&str>,
    signed_fields: &[&str],
) -> Value {
    let mut policy = serde_json::json!({
        "schema": "cx.schema.recovery_policy.v1",
        "policy_id": new_prefixed_uuid7("cx:policy:"),
        "principal_id": principal_id,
        "version": version,
        "trust_domain": "cx:trust_domain:soland.local",
        "allowed_proof_kinds": ["principal_signing"],
        "supersedes": supersedes,
        "issued_at": "2026-05-30T00:00:00Z",
        "expires_at": "2026-06-30T00:00:00Z",
        "auth_data": {
            "verification_method": verification_method,
            "signature_algorithm": "EdDSA",
            "signed_fields": signed_fields,
            "signature": ""
        }
    });
    sign_recovery_payload(
        &mut policy,
        "cx.identity.recovery_policy.signature.v1",
        signed_fields,
        signing,
    );
    policy
}

fn signed_recovery_receipt(
    signing: &SigningKey,
    principal_id: &str,
    verification_method: &str,
    policy_id: &str,
    policy_version: u32,
    recovery_session_id: Option<&str>,
    signed_fields: &[&str],
) -> Value {
    let mut receipt = serde_json::json!({
        "schema": "cx.schema.recovery_receipt.v1",
        "receipt_id": new_prefixed_uuid7("cx:receipt:"),
        "principal_id": principal_id,
        "recovery_session_id": recovery_session_id
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| new_prefixed_uuid7("cx:recovery_session:")),
        "policy_id": policy_id,
        "policy_version": policy_version,
        "trust_domain": "cx:trust_domain:soland.local",
        "new_device_id": "cx:device:01904100-0000-7000-8000-000000000042",
        "proof_summary": {
            "kind": "principal_signing",
            "proof_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        },
        "outcome": "completed",
        "started_at": "2026-05-30T00:00:00Z",
        "completed_at": "2026-05-30T00:00:01Z",
        "auth_data": {
            "verification_method": verification_method,
            "signature_algorithm": "EdDSA",
            "signed_fields": signed_fields,
            "signature": ""
        }
    });
    sign_recovery_payload(
        &mut receipt,
        "cx.identity.recovery_receipt.signature.v1",
        signed_fields,
        signing,
    );
    receipt
}

fn sign_recovery_payload(
    payload: &mut Value,
    transcript_type: &str,
    signed_fields: &[&str],
    signing: &SigningKey,
) {
    let mut signed_payload = Map::new();
    for field in signed_fields {
        signed_payload.insert(
            (*field).to_owned(),
            payload.get(*field).cloned().unwrap_or(Value::Null),
        );
    }
    let transcript = serde_json::json!({
        "type": transcript_type,
        "signed_fields": signed_fields,
        "payload": Value::Object(signed_payload),
    });
    let transcript_bytes = contrix_sdk::canonical::canonical_json_bytes(&transcript).unwrap();
    let signature = signing.sign(&transcript_bytes);
    payload["auth_data"]["signature"] =
        serde_json::json!(URL_SAFE_NO_PAD.encode(signature.to_bytes()));
}

async fn post_recovery_policy(
    state: AppState,
    token: &str,
    body: &Value,
    expected_status: StatusCode,
) -> Value {
    let mut response = TestClient::post("http://server/api/v1/identity/recovery-policy")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(body)
        .send(&app_from_state(state))
        .await;
    let status = response.status_code.unwrap();
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, expected_status, "response body: {body}");
    body
}

async fn post_recovery_receipt(
    state: AppState,
    token: &str,
    body: &Value,
    expected_status: StatusCode,
) -> Value {
    let mut response = TestClient::post("http://server/api/v1/identity/recovery-receipt")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(body)
        .send(&app_from_state(state))
        .await;
    let status = response.status_code.unwrap();
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, expected_status, "response body: {body}");
    body
}
