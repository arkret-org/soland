//! Integration tests — REC-1 recovery policy publication + read APIs.

use std::sync::Arc;

use soland_storage::PersistenceStore;
use soland_storage_memory::SolandMemoryPersistenceStore;

use super::helpers::*;
use crate::common::*;

#[test]
fn recovery_policy_persistence_survives_state_restart_and_rejects_replays() {
    run_on_deep_stack_multi_thread(
        "recovery_policy_persistence_survives_state_restart_and_rejects_replays",
        recovery_policy_persistence_survives_state_restart_and_rejects_replays_body,
    );
}

async fn recovery_policy_persistence_survives_state_restart_and_rejects_replays_body() {
    let persistence: Arc<dyn PersistenceStore> = Arc::new(SolandMemoryPersistenceStore::new());
    let state = shared_recovery_state(persistence.clone()).await;
    let signing = SigningKey::from_bytes(&[71u8; 32]);
    let (principal_id, vm) = did_webvh_principal(&signing);

    seed_recovery_policy(&state, &principal_id, &vm, 1, None).await;

    // Restart over the same persistence and verify that the active policy still
    // participates in monotonic version admission.
    let restarted = shared_recovery_state(persistence.clone()).await;
    let token = recovery_token_for_principal(restarted.clone(), &principal_id).await;

    let duplicate_version =
        signed_recovery_policy(&signing, &principal_id, &vm, 1, None, POLICY_FIELDS);
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
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new())).await;
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

    let body =
        post_recovery_policy(state, &token, &policy, &signing, StatusCode::UNAUTHORIZED).await;
    assert_eq!(body["error"]["code"], "proof_invalid");
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
    let state =
        shared_recovery_state_with_config(Arc::new(SolandMemoryPersistenceStore::new()), config)
            .await;
    let token = "prod_recovery_token";
    let signing = SigningKey::from_bytes(&[77u8; 32]);
    let (principal_id, verification_method) = did_webvh_principal(&signing);
    seed_bearer_session(&state, token, &principal_id).await;
    let policy = signed_recovery_policy(
        &signing,
        &principal_id,
        &verification_method,
        1,
        None,
        POLICY_FIELDS,
    );

    let body = post_recovery_policy(state, token, &policy, &signing, StatusCode::CREATED).await;
    assert_eq!(body["ok"], true);
}

#[test]
fn recovery_policy_accepts_genesis_session_device_signature() {
    run_on_deep_stack_multi_thread(
        "recovery_policy_accepts_genesis_session_device_signature",
        recovery_policy_accepts_genesis_session_device_signature_body,
    );
}

async fn recovery_policy_accepts_genesis_session_device_signature_body() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new())).await;
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
    let principal_full_id = principal_vm
        .split_once('#')
        .map(|(controller, _)| controller)
        .expect("principal verification method has a Full DID controller");
    let verification_method = format!("{principal_full_id}#{RECOVERY_TEST_DEVICE}");
    let policy = signed_recovery_policy(
        &device_signing,
        &principal_id,
        &verification_method,
        1,
        None,
        POLICY_FIELDS,
    );

    let body =
        post_recovery_policy(state, token, &policy, &device_signing, StatusCode::CREATED).await;
    assert_eq!(body["ok"], true);
}

#[test]
fn recovery_policy_rejects_missing_signed_field_coverage() {
    run_on_deep_stack_multi_thread(
        "recovery_policy_rejects_missing_signed_field_coverage",
        recovery_policy_rejects_missing_signed_field_coverage_body,
    );
}

async fn recovery_policy_rejects_missing_signed_field_coverage_body() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new())).await;
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

    let body =
        post_recovery_policy(state, &token, &policy, &signing, StatusCode::BAD_REQUEST).await;
    assert_eq!(body["error"]["code"], "schema_violation");
}

#[test]
fn recovery_policy_rejects_non_monotonic_supersedes_after_restart() {
    run_on_deep_stack_multi_thread(
        "recovery_policy_rejects_non_monotonic_supersedes_after_restart",
        recovery_policy_rejects_non_monotonic_supersedes_after_restart_body,
    );
}

async fn recovery_policy_rejects_non_monotonic_supersedes_after_restart_body() {
    let persistence: Arc<dyn PersistenceStore> = Arc::new(SolandMemoryPersistenceStore::new());
    let state = shared_recovery_state(persistence.clone()).await;
    let signing = SigningKey::from_bytes(&[76u8; 32]);
    let (principal_id, verification_method) = did_webvh_principal(&signing);
    let token = recovery_token_for_principal(state.clone(), &principal_id).await;
    let v1 = signed_recovery_policy(
        &signing,
        &principal_id,
        &verification_method,
        1,
        None,
        POLICY_FIELDS,
    );
    post_recovery_policy(state.clone(), &token, &v1, &signing, StatusCode::CREATED).await;

    let restarted = shared_recovery_state(persistence).await;
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
        &signing,
        StatusCode::CONFLICT,
    )
    .await;
    assert_eq!(body["error"]["code"], "recovery_policy_supersedes_invalid");
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
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new())).await;
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
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new())).await;
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
        active["active_policy"]["principal_id"],
        fixture_actor_core_id(&principal_id).as_str()
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
