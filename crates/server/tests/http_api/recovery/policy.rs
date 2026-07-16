//! Integration tests — REC-1 recovery policy publication + read APIs.


use std::sync::Arc;

use soland::persistence::{PersistenceStore, SolandMemoryPersistenceStore};

use super::helpers::*;
use crate::common::*;

#[tokio::test(flavor = "multi_thread")]
async fn recovery_persistence_survives_state_restart_and_rejects_replays() {
    let persistence: Arc<dyn PersistenceStore> = Arc::new(SolandMemoryPersistenceStore::new());
    let state = shared_recovery_state(persistence.clone());
    let signing = SigningKey::from_bytes(&[71u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);

    // Authorize a device via the full recovery strand (persists the policy + the
    // device's accepted public key).
    let (policy_id, device_id) =
        authorize_device_via_recovery(&state, &signing, &principal_id, &vm).await;

    // Restart: fresh in-memory state over the same persistence. The device
    // inventory (and policy) survive; the receipt verifies against the persisted
    // device key.
    let restarted = shared_recovery_state(persistence.clone());
    let token = recovery_token_for_principal(restarted.clone(), &principal_id).await;
    let receipt = signed_device_recovery_receipt(
        &recovery_device_key(),
        &principal_id,
        &policy_id,
        1,
        &device_id,
        RECEIPT_FIELDS,
    );
    post_recovery_receipt(restarted.clone(), &token, &receipt, StatusCode::CREATED).await;
    // Replaying the same receipt (same recovery_session_id) is rejected.
    post_recovery_receipt(restarted.clone(), &token, &receipt, StatusCode::CONFLICT).await;

    let duplicate_version =
        signed_recovery_policy(&signing, &principal_id, &vm, 1, None, POLICY_FIELDS);
    post_recovery_policy(restarted, &token, &duplicate_version, StatusCode::CONFLICT).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_policy_rejects_tampered_signature_body() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[72u8; 32]);
    let (principal_id, verification_method) = did_key_principal(&signing);
    let token = recovery_token_for_principal(state.clone(), &principal_id).await;
    let mut policy = signed_recovery_policy(
        &signing,
        &principal_id,
        &verification_method,
        1,
        None,
        POLICY_FIELDS,
    );
    policy["trust_domain"] = serde_json::json!("ak:trust_domain:tampered.example");

    let body = post_recovery_policy(state, &token, &policy, StatusCode::UNAUTHORIZED).await;
    assert_eq!(body["error"]["code"], "proof_invalid");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_policy_production_accepts_verified_payload() {
    let mut config = test_config();
    config.development_mode = false;
    let state =
        shared_recovery_state_with_config(Arc::new(SolandMemoryPersistenceStore::new()), config);
    let token = "prod_recovery_token";
    let signing = SigningKey::from_bytes(&[77u8; 32]);
    let (principal_id, verification_method) = did_key_principal(&signing);
    seed_bearer_session(&state, token, &principal_id).await;
    ingest_fresh_recovery_did_document(&state, &principal_id).await;
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
async fn recovery_policy_accepts_genesis_session_device_signature() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let principal_signing = SigningKey::from_bytes(&[82u8; 32]);
    let device_signing = SigningKey::from_bytes(&[83u8; 32]);
    let (principal_id, _vm) = did_key_principal(&principal_signing);
    let token = "device_signed_policy_token";
    seed_bearer_session_with_device_public_key(
        &state,
        token,
        &principal_id,
        &test_ed25519_multibase_public(&device_signing),
    )
    .await;
    let verification_method = format!("{principal_id}#{RECOVERY_TEST_DEVICE}");
    let policy = signed_recovery_policy(
        &device_signing,
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
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[73u8; 32]);
    let (principal_id, verification_method) = did_key_principal(&signing);
    let token = recovery_token_for_principal(state.clone(), &principal_id).await;
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
async fn recovery_policy_rejects_non_monotonic_supersedes_after_restart() {
    let persistence: Arc<dyn PersistenceStore> = Arc::new(SolandMemoryPersistenceStore::new());
    let state = shared_recovery_state(persistence.clone());
    let signing = SigningKey::from_bytes(&[76u8; 32]);
    let (principal_id, verification_method) = did_key_principal(&signing);
    let token = recovery_token_for_principal(state.clone(), &principal_id).await;
    ingest_fresh_recovery_did_document(&state, &principal_id).await;
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
        Some(&new_prefixed_uuid7("ak:policy:")),
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

#[tokio::test(flavor = "multi_thread")]
async fn recovery_policy_get_returns_null_without_active_policy() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[90u8; 32]);
    let (principal_id, _vm) = did_key_principal(&signing);
    let token = dev_token_for_device(
        state.clone(),
        &principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery",
    )
    .await;

    let body = get_recovery(
        state,
        &token,
        "/_arkret/root/identity/recovery-policy",
        StatusCode::OK,
    )
    .await;
    assert!(body["active_policy"].is_null(), "body: {body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_policy_get_returns_active_and_history() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[91u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    // Authenticate AS the principal so the read APIs (principal-isolated) see it.
    let token = dev_token_for_device(
        state.clone(),
        &principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery",
    )
    .await;

    let v1_id = seed_recovery_policy(&state, &principal_id, &vm, 1, None).await;
    seed_recovery_policy(&state, &principal_id, &vm, 2, Some(&v1_id)).await;

    let active = get_recovery(
        state.clone(),
        &token,
        "/_arkret/root/identity/recovery-policy",
        StatusCode::OK,
    )
    .await;
    assert_eq!(active["active_policy"]["version"], 2);
    assert_eq!(active["active_policy"]["principal_id"], principal_id);

    let history = get_recovery(
        state,
        &token,
        "/_soland/root/identity/recovery-policies",
        StatusCode::OK,
    )
    .await;
    let arr = history["policies"].as_array().unwrap();
    assert_eq!(arr.len(), 2, "history: {history}");
    assert_eq!(arr[0]["version"], 2, "newest first");
    assert_eq!(arr[1]["version"], 1);
}
