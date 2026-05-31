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
