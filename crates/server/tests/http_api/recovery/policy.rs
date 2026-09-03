//! Integration tests — REC-1 recovery policy publication + read APIs.

use std::sync::Arc;

use soland_storage::PersistenceStore;

use super::helpers::*;
use crate::common::*;

/// A durable store on a database leased for the calling test. The lease is
/// owned by the store, so a restart fixture that rebuilds `AppState` over the
/// same `Arc` keeps the same rows.
async fn leased_persistence() -> Arc<dyn PersistenceStore> {
    Arc::new(soland_storage_postgres::PgPersistenceStore::leased(
        Arc::new(soland_storage_postgres::test_database::TestDatabase::lease().await),
    ))
}

#[test]
fn recovery_policy_persistence_survives_state_restart_and_rejects_replays() {
    run_on_deep_stack_multi_thread(
        "recovery_policy_persistence_survives_state_restart_and_rejects_replays",
        recovery_policy_persistence_survives_state_restart_and_rejects_replays_body,
    );
}

async fn recovery_policy_persistence_survives_state_restart_and_rejects_replays_body() {
    let persistence = leased_persistence().await;
    let state = shared_recovery_state(persistence.clone()).await;
    let signing = SigningKey::from_bytes(&[71u8; 32]);
    let (principal_id, vm) = did_webvh_principal(&signing);

    seed_recovery_policy(&state, &principal_id, &vm, 1, None).await;

    // Restart over the same persistence and verify that the active policy still
    // participates in monotonic version admission.
    let restarted = shared_recovery_state(persistence.clone()).await;
    let token = recovery_token_for_principal(restarted.clone(), &principal_id).await;

    let duplicate_version =
        signed_recovery_policy(&restarted, &signing, &principal_id, &vm, 1, None);
    post_recovery_policy(
        restarted,
        &token,
        &duplicate_version,
        &signing,
        StatusCode::CONFLICT,
    )
    .await;
}

#[test]
fn recovery_policy_rejects_tampered_signature_body() {
    run_on_deep_stack_multi_thread(
        "recovery_policy_rejects_tampered_signature_body",
        recovery_policy_rejects_tampered_signature_body_body,
    );
}

async fn recovery_policy_rejects_tampered_signature_body_body() {
    let state = shared_recovery_state(leased_persistence().await).await;
    let signing = SigningKey::from_bytes(&[72u8; 32]);
    let (principal_id, verification_method) = did_key_principal(&signing);
    let token = recovery_token_for_principal(state.clone(), &principal_id).await;
    let mut policy = signed_recovery_policy(
        &state,
        &signing,
        &principal_id,
        &verification_method,
        1,
        None,
    );
    policy["trust_domain"] = serde_json::json!("ak:trust_domain:tampered.example");

    let body =
        post_recovery_policy(state, &token, &policy, &signing, StatusCode::UNAUTHORIZED).await;
    assert_eq!(problem_code(&body), "proof_invalid");
}

#[test]
fn recovery_policy_production_accepts_verified_payload() {
    run_on_deep_stack_multi_thread(
        "recovery_policy_production_accepts_verified_payload",
        recovery_policy_production_accepts_verified_payload_body,
    );
}

async fn recovery_policy_production_accepts_verified_payload_body() {
    let mut config = test_config();
    config.development_mode = false;
    let state = shared_recovery_state_with_config(leased_persistence().await, config).await;
    assert!(!state.config().development_mode);
    let token = "prod_recovery_token";
    let signing = SigningKey::from_bytes(&[77u8; 32]);
    let (principal_id, verification_method) = did_webvh_principal(&signing);
    seed_bearer_session(&state, token, &principal_id).await;
    let policy = signed_recovery_policy(
        &state,
        &signing,
        &principal_id,
        &verification_method,
        1,
        None,
    );
    let expected_account_id = fixture_account_id(&state, &principal_id);

    let body = post_recovery_policy(state, token, &policy, &signing, StatusCode::CREATED).await;
    assert_eq!(body["account_id"], serde_json::json!(expected_account_id));
    assert_eq!(body["version"], 1);
}

#[test]
fn recovery_policy_rejects_unregistered_grant_and_mismatched_dpop_holder() {
    run_on_deep_stack_multi_thread(
        "recovery_policy_rejects_unregistered_grant_and_mismatched_dpop_holder",
        recovery_policy_rejects_unregistered_grant_and_mismatched_dpop_holder_body,
    );
}

async fn recovery_policy_rejects_unregistered_grant_and_mismatched_dpop_holder_body() {
    let state = shared_recovery_state(leased_persistence().await).await;
    let signing = SigningKey::from_bytes(&[78u8; 32]);
    let (principal_id, _verification_method) = did_key_principal(&signing);
    let token = verified_dev_token_for_device(
        state.clone(),
        &principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery",
    )
    .await;

    assert_recovery_policy_grant_binding_rejections(state, &token).await;
}

#[test]
fn recovery_policy_accepts_genesis_session_device_signature() {
    run_on_deep_stack_multi_thread(
        "recovery_policy_accepts_genesis_session_device_signature",
        recovery_policy_accepts_genesis_session_device_signature_body,
    );
}

async fn recovery_policy_accepts_genesis_session_device_signature_body() {
    let state = shared_recovery_state(leased_persistence().await).await;
    let did_root = SigningKey::from_bytes(&[82u8; 32]);
    let device_signing = SigningKey::from_bytes(&[83u8; 32]);
    let (principal_id, principal_vm) = did_key_principal(&did_root);
    let token = "device_signed_policy_token";
    seed_bearer_session_with_device_public_key(
        &state,
        token,
        &principal_id,
        &test_ed25519_multibase_public(&device_signing),
    )
    .await;
    let principal_did = principal_vm
        .split_once('#')
        .map(|(controller, _)| controller)
        .expect("principal verification method has a DID controller");
    let verification_method = format!("{principal_did}#{RECOVERY_TEST_DEVICE}");
    let policy = signed_recovery_policy(
        &state,
        &device_signing,
        &principal_id,
        &verification_method,
        1,
        None,
    );
    let expected_account_id = fixture_account_id(&state, &principal_id);

    let body =
        post_recovery_policy(state, token, &policy, &device_signing, StatusCode::CREATED).await;
    assert_eq!(body["account_id"], serde_json::json!(expected_account_id));
    assert_eq!(body["version"], 1);
}

#[test]
fn recovery_policy_rejects_non_monotonic_supersedes_after_restart() {
    run_on_deep_stack_multi_thread(
        "recovery_policy_rejects_non_monotonic_supersedes_after_restart",
        recovery_policy_rejects_non_monotonic_supersedes_after_restart_body,
    );
}

async fn recovery_policy_rejects_non_monotonic_supersedes_after_restart_body() {
    let persistence = leased_persistence().await;
    let state = shared_recovery_state(persistence.clone()).await;
    let signing = SigningKey::from_bytes(&[76u8; 32]);
    let (principal_id, verification_method) = did_webvh_principal(&signing);
    let token = recovery_token_for_principal(state.clone(), &principal_id).await;
    let v1 = signed_recovery_policy(
        &state,
        &signing,
        &principal_id,
        &verification_method,
        1,
        None,
    );
    post_recovery_policy(state.clone(), &token, &v1, &signing, StatusCode::CREATED).await;

    let restarted = shared_recovery_state(persistence).await;
    let v2_wrong_supersedes = signed_recovery_policy(
        &restarted,
        &signing,
        &principal_id,
        &verification_method,
        2,
        Some(&new_prefixed_uuid7("ak:policy:")),
    );
    let body = post_recovery_policy(
        restarted,
        &token,
        &v2_wrong_supersedes,
        &signing,
        StatusCode::CONFLICT,
    )
    .await;
    assert_eq!(problem_code(&body), "recovery_policy_supersedes_invalid");
}

// ── REC-1 read APIs (C-P1) ─────────────────────────────────────────────────

#[test]
fn recovery_policy_get_returns_null_without_active_policy() {
    run_on_deep_stack_multi_thread(
        "recovery_policy_get_returns_null_without_active_policy",
        recovery_policy_get_returns_null_without_active_policy_body,
    );
}

async fn recovery_policy_get_returns_null_without_active_policy_body() {
    let state = shared_recovery_state(leased_persistence().await).await;
    let signing = SigningKey::from_bytes(&[90u8; 32]);
    let (principal_id, _vm) = did_key_principal(&signing);
    let token = verified_dev_token_for_device(
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

#[test]
fn recovery_policy_get_returns_active_and_history() {
    run_on_deep_stack_multi_thread(
        "recovery_policy_get_returns_active_and_history",
        recovery_policy_get_returns_active_and_history_body,
    );
}

async fn recovery_policy_get_returns_active_and_history_body() {
    let state = shared_recovery_state(leased_persistence().await).await;
    let signing = SigningKey::from_bytes(&[91u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    // Authenticate AS the principal so the read APIs (principal-isolated) see it.
    let token = verified_dev_token_for_device(
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
    assert_eq!(
        active["active_policy"]["account_id"],
        serde_json::json!(fixture_account_id(&state, &principal_id))
    );

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
