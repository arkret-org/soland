//! Integration tests — C-P5 did_recovery backup ↔ active policy binding,
//! plus key-backup delete retirement rules for did_recovery backups.

#![allow(unused_imports)]

use std::sync::Arc;

use soland::persistence::SolandMemoryPersistenceStore;

use super::helpers::*;
use crate::common::*;

#[tokio::test(flavor = "multi_thread")]
async fn did_recovery_backup_rejects_missing_active_recovery_policy() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[120u8; 32]);
    let (principal_id, _vm) = did_key_principal(&signing);
    let token = dev_token_for_device(
        state.clone(),
        &principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery",
    )
    .await;

    let backup_id = "ak:backup:01964137-0000-7000-8000-0000000000c4";
    let policy_id = "ak:policy:01964137-0000-7000-8000-0000000000ee";
    let backup = did_recovery_backup_body(&principal_id, backup_id, policy_id);
    let body = put_key_backup(state, &token, backup_id, &backup, StatusCode::CONFLICT).await;
    assert_eq!(body["error"]["code"], "recovery_policy_mismatch");
}

#[tokio::test(flavor = "multi_thread")]
async fn did_recovery_backup_rejects_recovery_policy_mismatch() {
    // A did_recovery backup whose recovery_policy_ref does not equal the actor's
    // active recovery policy MUST be rejected with recovery_policy_mismatch.
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[121u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let token = dev_token_for_device(
        state.clone(),
        &principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery",
    )
    .await;

    // Seed an active recovery policy (v1) — its policy_id is random, so the
    // backup's fixed wrong policy_id below cannot match it.
    seed_recovery_policy(&state, &principal_id, &vm, 1, None).await;

    let backup_id = "ak:backup:01964137-0000-7000-8000-0000000000c5";
    let wrong_policy = "ak:policy:01964137-0000-7000-8000-0000000000ff";
    let backup = did_recovery_backup_body(&principal_id, backup_id, wrong_policy);
    let body = put_key_backup(state, &token, backup_id, &backup, StatusCode::CONFLICT).await;
    assert_eq!(body["error"]["code"], "recovery_policy_mismatch");
}

#[tokio::test(flavor = "multi_thread")]
async fn did_recovery_backup_rejects_unverified_session_device() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[124u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let _first = dev_token_for_device(
        state.clone(),
        &principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery",
    )
    .await;
    let second = dev_token_for_device(
        state.clone(),
        &principal_id,
        RECOVERY_TEST_DEVICE_B,
        "Recovery Browser",
    )
    .await;

    let policy_id = seed_recovery_policy(&state, &principal_id, &vm, 1, None).await;
    let backup_id = "ak:backup:01964137-0000-7000-8000-0000000000c8";
    let mut backup = did_recovery_backup_body(&principal_id, backup_id, &policy_id);
    backup["auth_data"]["device_id"] = serde_json::json!(RECOVERY_TEST_DEVICE_B);
    backup["auth_data"]["verification_method"] =
        serde_json::json!(format!("{principal_id}#{RECOVERY_TEST_DEVICE_B}"));

    let body = put_key_backup(state, &second, backup_id, &backup, StatusCode::FORBIDDEN).await;
    assert_eq!(body["error"]["code"], "device_not_authorized");
}

#[tokio::test(flavor = "multi_thread")]
async fn key_backup_delete_allows_active_did_recovery_tail_backup() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[122u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let token = dev_token_for_device(
        state.clone(),
        &principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery",
    )
    .await;

    let policy_id = seed_recovery_policy(&state, &principal_id, &vm, 1, None).await;
    let backup_id = "ak:backup:01964137-0000-7000-8000-0000000000c6";
    let backup = did_recovery_backup_body(&principal_id, backup_id, &policy_id);
    put_key_backup(state.clone(), &token, backup_id, &backup, StatusCode::OK).await;

    let body = delete_key_backup(state, &token, &principal_id, backup_id, StatusCode::OK).await;
    assert_eq!(body["deleted"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn key_backup_delete_allows_stale_did_recovery_backup() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[123u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let token = dev_token_for_device(
        state.clone(),
        &principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery",
    )
    .await;

    let v1_policy_id = seed_recovery_policy(&state, &principal_id, &vm, 1, None).await;
    let backup_id = "ak:backup:01964137-0000-7000-8000-0000000000c7";
    let backup = did_recovery_backup_body(&principal_id, backup_id, &v1_policy_id);
    put_key_backup(state.clone(), &token, backup_id, &backup, StatusCode::OK).await;

    seed_recovery_policy(&state, &principal_id, &vm, 2, Some(&v1_policy_id)).await;

    let body = delete_key_backup(state, &token, &principal_id, backup_id, StatusCode::OK).await;
    assert_eq!(body["deleted"], true);
    assert_eq!(body["backup_id"], backup_id);
}
