//! Integration tests — REC-1 recovery receipt verification + read APIs.

use std::sync::Arc;

use soland_storage_memory::SolandMemoryPersistenceStore;

use super::helpers::*;
use crate::common::*;

#[tokio::test(flavor = "multi_thread")]
async fn recovery_receipt_rejects_policy_binding_mismatch() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[74u8; 32]);
    let (principal_id, verification_method) = did_key_principal(&signing);
    let token = recovery_token_for_principal(state.clone(), &principal_id).await;
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
        &new_prefixed_uuid7("ak:policy:"),
        1,
        None,
        RECEIPT_FIELDS,
    );
    let body = post_recovery_receipt(state, &token, &receipt, StatusCode::CONFLICT).await;
    assert_eq!(body["error"]["code"], "recovery_policy_id_mismatch");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_receipt_rejects_tampered_proof_digest() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[75u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let (policy_id, device_id) =
        authorize_device_via_recovery(&state, &signing, &principal_id, &vm).await;
    let token = dev_token(state.clone()).await;

    let mut receipt = signed_device_recovery_receipt(
        &recovery_device_key(),
        &principal_id,
        &policy_id,
        1,
        &device_id,
        RECEIPT_FIELDS,
    );
    // Tamper a signed field (proof_summary) AFTER signing → device signature
    // no longer verifies.
    receipt["proof_summary"]["proof_digest"] = serde_json::json!(
        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    );

    let body = post_recovery_receipt(state, &token, &receipt, StatusCode::UNAUTHORIZED).await;
    assert_eq!(body["error"]["code"], "proof_invalid");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_receipt_rejects_unauthorized_device() {
    // §15 step 7 — a receipt for a device with no accepted ak.device.authorize
    // MUST be rejected (no authorized device key to verify against).
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[79u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let token = recovery_token_for_principal(state.clone(), &principal_id).await;
    // Publish an active policy but NEVER authorize the device.
    let policy = signed_recovery_policy(&signing, &principal_id, &vm, 1, None, POLICY_FIELDS);
    let pbody = post_recovery_policy(state.clone(), &token, &policy, StatusCode::CREATED).await;
    let policy_id = pbody["policy_id"].as_str().unwrap().to_owned();

    let receipt = signed_device_recovery_receipt(
        &recovery_device_key(),
        &principal_id,
        &policy_id,
        1,
        "ak:device:01904100-0000-7000-8000-00000000aaaa",
        RECEIPT_FIELDS,
    );
    let body = post_recovery_receipt(state, &token, &receipt, StatusCode::CONFLICT).await;
    assert_eq!(
        body["error"]["code"],
        "recovery_receipt_device_not_authorized"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_receipt_rejects_revoked_recovered_device() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[80u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let (policy_id, device_id) =
        authorize_device_via_recovery(&state, &signing, &principal_id, &vm).await;
    let mut device = state
        .test_persistence()
        .devices()
        .get(&principal_id, &device_id)
        .await
        .unwrap()
        .expect("authorized recovered device");
    let now = chrono::Utc::now();
    device.revoked_at = Some(now);
    device.updated_at = now;
    state
        .test_persistence()
        .devices()
        .put(&device)
        .await
        .unwrap();
    let token = dev_token(state.clone()).await;

    let receipt = signed_device_recovery_receipt(
        &recovery_device_key(),
        &principal_id,
        &policy_id,
        1,
        &device_id,
        RECEIPT_FIELDS,
    );
    let body = post_recovery_receipt(state, &token, &receipt, StatusCode::CONFLICT).await;
    assert_eq!(
        body["error"]["code"],
        "recovery_receipt_device_not_authorized"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_receipt_requires_backup_classes_unlocked() {
    // device-lifecycle.md §15 step 7: backup_classes_unlocked is a required
    // normative receipt field. Dropping it MUST be rejected.
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[78u8; 32]);
    let (principal_id, verification_method) = did_key_principal(&signing);
    let token = recovery_token_for_principal(state.clone(), &principal_id).await;
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
    receipt
        .as_object_mut()
        .unwrap()
        .remove("backup_classes_unlocked");

    let body = post_recovery_receipt(state, &token, &receipt, StatusCode::BAD_REQUEST).await;
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("backup_classes_unlocked"),
        "expected backup_classes_unlocked error: {body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_receipts_get_returns_history() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[92u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let (policy_id, device_id) =
        authorize_device_via_recovery(&state, &signing, &principal_id, &vm).await;
    let token = dev_token_for_device(
        state.clone(),
        &principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery",
    )
    .await;

    let receipt = signed_device_recovery_receipt(
        &recovery_device_key(),
        &principal_id,
        &policy_id,
        1,
        &device_id,
        RECEIPT_FIELDS,
    );
    post_recovery_receipt(state.clone(), &token, &receipt, StatusCode::CREATED).await;

    let body = get_recovery(
        state,
        &token,
        "/_soland/root/identity/recovery-receipts",
        StatusCode::OK,
    )
    .await;
    let arr = body["receipts"].as_array().unwrap();
    assert_eq!(arr.len(), 1, "receipts: {body}");
    assert_eq!(arr[0]["policy_id"], policy_id);
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_read_enforces_principal_isolation() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[93u8; 32]);
    let (principal_id, _vm) = did_key_principal(&signing);
    let token = dev_token_for_device(
        state.clone(),
        &principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery",
    )
    .await;

    // Querying ANOTHER principal's recovery state is forbidden.
    let body = get_recovery(
        state,
        &token,
        "/_arkret/root/identity/recovery-policy?principal_id=did:web:someone-else.example",
        StatusCode::FORBIDDEN,
    )
    .await;
    assert_eq!(body["error"]["code"], "recovery_principal_isolation");
}
