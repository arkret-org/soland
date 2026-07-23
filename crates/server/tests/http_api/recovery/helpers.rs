//! Shared helpers and constants for the `recovery` test cluster.
//!
//! Every test submodule under `http_api::recovery::*` reaches these via
//! `use super::helpers::*;`. Shared common-module fixtures arrive through
//! `use crate::common::*;`.

use std::sync::Arc;

use arkret_models_crypto::{
    KeyBackupDeleteDevelopmentProof, KeyBackupDeleteProof, KeysBackupsDeleteRequestBody,
};
use serde_json::{Map, Value};
use soland_storage::{
    CanonicalEventRecord, DeviceInventoryRecord, PersistenceStore, RecoveryPolicyRecord,
    SessionRecord, WebvhDocumentRecord,
};

use crate::common::*;

pub(crate) const POLICY_FIELDS: &[&str] = &[
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

pub(crate) const RECEIPT_FIELDS: &[&str] = &[
    "schema",
    "receipt_id",
    "principal_id",
    "recovery_session_id",
    "policy_id",
    "policy_version",
    "trust_domain",
    "new_device_id",
    "proof_summary",
    "backup_classes_unlocked",
    "welcome_count",
    "outcome",
    "started_at",
    "completed_at",
];

pub(crate) const RECOVERY_TEST_DEVICE: &str = "ak:device:01904100-0000-7000-8000-a11ce0000001";

pub(crate) const RECOVERY_TEST_DEVICE_B: &str = "ak:device:01904100-0000-7000-8000-a11ce0000002";

pub(crate) const AUTH_EVENT_ID: &str = "ak:event:01964137-0000-7000-8000-00000000a111";
pub(crate) const LIST_EVENT_ID: &str = "ak:event:01964137-0000-7000-8000-00000000a222";

/// Helper: seed an accepted v1 policy for `principal_id` and open a recovery
/// session against it. Returns the session JSON body.
pub(crate) async fn open_recovery_session(
    state: AppState,
    token: &str,
    signing: &SigningKey,
    principal_id: &str,
    vm: &str,
) -> Value {
    ingest_fresh_recovery_did_document(&state, principal_id).await;
    seed_recovery_policy(&state, principal_id, vm, 1, None).await;
    ensure_cross_signing(state.clone(), principal_id, vm, signing);
    let create_body = serde_json::json!({
        "principal_id": principal_id,
        "trust_domain": "ak:trust_domain:soland.local",
        "requesting_device_id": "ak:device:01904100-0000-7000-8000-000000000099",
    });
    post_recovery(
        state,
        token,
        "/_arkret/root/identity/recovery-sessions",
        &create_body,
        StatusCode::CREATED,
    )
    .await
}

pub(crate) fn ensure_cross_signing(
    state: AppState,
    principal_id: &str,
    vm: &str,
    signing: &SigningKey,
) {
    let principal = Did::new(principal_id.to_owned()).unwrap();
    if !state.test_has_current_cross_signing(&principal) {
        let ssk = SigningKey::from_bytes(&[231u8; 32]);
        let usk = SigningKey::from_bytes(&[232u8; 32]);
        seed_cross_signing(&state, principal_id, vm, signing, &ssk, &usk);
    }
}

/// Build the canonical recovery-proof transcript the server reconstructs, and
/// return a base64url Ed25519 signature over it by `signing`.
pub(crate) fn sign_recovery_proof(signing: &SigningKey, session: &Value) -> String {
    let model_generation_ref = recovery_model_generation_ref(session);
    let transcript = serde_json::json!({
        "type": "ak.identity.recovery_proof.v1",
        "kind": "principal_signing",
        "principal_id": session["principal_id"],
        "requesting_device_id": session["requesting_device_id"],
        "trust_domain": session["trust_domain"],
        "policy_id": session["policy_id"],
        "policy_version": session["policy_version"],
        "recovery_session_id": session["recovery_session_id"],
        "identity_model": session["identity_model"],
        "model_generation_ref": model_generation_ref,
        "challenge": session["challenge"],
        "created_at": session["created_at"],
        "expires_at": session["expires_at"],
    });
    let bytes = arkret_canonical::canonical_json_bytes(&transcript).unwrap();
    URL_SAFE_NO_PAD.encode(signing.sign(&bytes).to_bytes())
}

pub(crate) fn sign_trusted_recovery_service_proof(
    signing: &SigningKey,
    session: &Value,
    service_id: &str,
    verification_method: &str,
    audience: &str,
    attestation_ref: Option<&str>,
) -> String {
    let model_generation_ref = recovery_model_generation_ref(session);
    let mut proof_body = serde_json::json!({
        "kind": "trusted_recovery_service",
        "challenge": session["challenge"],
        "service_id": service_id,
        "audience": audience,
        "verification_method": verification_method,
        "alg": "EdDSA",
    });
    if let Some(attestation_ref) = attestation_ref {
        proof_body["attestation_ref"] = serde_json::json!(attestation_ref);
    }
    let transcript = serde_json::json!({
        "type": "ak.identity.recovery_proof.v1",
        "kind": "trusted_recovery_service",
        "principal_id": session["principal_id"],
        "requesting_device_id": session["requesting_device_id"],
        "trust_domain": session["trust_domain"],
        "policy_id": session["policy_id"],
        "policy_version": session["policy_version"],
        "recovery_session_id": session["recovery_session_id"],
        "identity_model": session["identity_model"],
        "model_generation_ref": model_generation_ref,
        "challenge": session["challenge"],
        "created_at": session["created_at"],
        "expires_at": session["expires_at"],
        "proof_body": proof_body,
    });
    let bytes = arkret_canonical::canonical_json_bytes(&transcript).unwrap();
    URL_SAFE_NO_PAD.encode(signing.sign(&bytes).to_bytes())
}

fn recovery_model_generation_ref(session: &Value) -> Value {
    match session["identity_model"].as_str() {
        Some("cross_signing") => session["ssk_generation"].clone(),
        Some("enrollment_authority") => session["current_device_generation_ref"].clone(),
        other => panic!("unexpected recovery identity model in fixture: {other:?}"),
    }
}

/// The recovering device's keypair (fixed for tests). Its public key is stored
/// at authorization and used to verify a later recovery_receipt's signature.
pub(crate) fn recovery_device_key() -> SigningKey {
    SigningKey::from_bytes(&[230u8; 32])
}

/// Run a full recovery completion so the requesting device is authorized (its
/// `recovery_device_key()` public key recorded). Returns `(policy_id, device_id)`.
pub(crate) async fn authorize_device_via_recovery(
    state: &AppState,
    signing: &SigningKey,
    principal_id: &str,
    vm: &str,
) -> (String, String) {
    let ssk = SigningKey::from_bytes(&[231u8; 32]);
    let usk = SigningKey::from_bytes(&[232u8; 32]);
    seed_cross_signing(state, principal_id, vm, signing, &ssk, &usk);
    let token = dev_token_for_device(
        state.clone(),
        principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery",
    )
    .await;
    // `verified_session_for` → `open_recovery_session` already publishes the v1
    // policy; read its id from the session rather than double-posting.
    let (session, session_id) =
        verified_session_for(state, &token, signing, principal_id, vm).await;
    let policy_id = session["policy_id"].as_str().unwrap().to_owned();
    let device_id = session["requesting_device_id"].as_str().unwrap().to_owned();
    let complete_body =
        seed_completion_events(state, &session, device_authorize_material(&session, &ssk)).await;
    post_recovery(
        state.clone(),
        &token,
        &format!("/_arkret/root/identity/recovery-sessions/{session_id}/complete"),
        &complete_body,
        StatusCode::OK,
    )
    .await;
    (policy_id, device_id)
}

/// Build a recovery_receipt signed by the authorized device key (§15 step 7).
pub(crate) fn signed_device_recovery_receipt(
    device_key: &SigningKey,
    principal_id: &str,
    policy_id: &str,
    policy_version: u32,
    new_device_id: &str,
    signed_fields: &[&str],
) -> Value {
    let mut receipt = serde_json::json!({
        "schema": "ak.schema.recovery_receipt.v1",
        "receipt_id": new_prefixed_uuid7("ak:receipt:"),
        "principal_id": principal_id,
        "recovery_session_id": new_prefixed_uuid7("ak:recovery_session:"),
        "policy_id": policy_id,
        "policy_version": policy_version,
        "trust_domain": "ak:trust_domain:soland.local",
        "new_device_id": new_device_id,
        "proof_summary": {
            "kind": "principal_signing",
            "proof_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        },
        "backup_classes_unlocked": [],
        "welcome_count": 0,
        "outcome": "completed",
        "started_at": "2026-05-30T00:00:00.000Z",
        "completed_at": "2026-05-30T00:00:01.000Z",
        "auth_data": {
            "verification_method": format!("{principal_id}#{new_device_id}"),
            "signature_algorithm": "EdDSA",
            "signed_fields": signed_fields,
            "signature": ""
        }
    });
    sign_recovery_payload(
        &mut receipt,
        "ak.identity.recovery_receipt.signature.v1",
        signed_fields,
        device_key,
    );
    receipt
}

/// Build a well-formed client `device_authorize` material bound to `session`,
/// with a real `cross_signing_binding` signed by `ssk` over the canonical
/// device-trust input at the session's ssk_generation.
pub(crate) fn device_authorize_material(session: &Value, ssk: &SigningKey) -> Value {
    let principal = session["principal_id"].as_str().unwrap();
    let device = session["requesting_device_id"].as_str().unwrap();
    let generation = session["ssk_generation"].as_u64().unwrap();
    let did = arkret_identifiers::Did::new(principal.to_owned()).unwrap();
    let device_id = arkret_identifiers::DeviceId::new(device.to_owned()).unwrap();
    // The new device's real keypair — its multibase public key is what the
    // server records, and what a later recovery_receipt MUST be signed by.
    let device_public_key = test_ed25519_multibase_public(&recovery_device_key());
    let hpke_key = "z6LSTestRecoveryHpkeKey";
    let algorithms = [
        "ak.hpke_x25519_aead_chacha20poly1305.v1".to_owned(),
        "ak.mls.v1".to_owned(),
    ];
    let input = arkret_crypto::DeviceTrustBinding::canonical_input(
        &did,
        &device_id,
        &device_public_key,
        hpke_key,
        &algorithms,
        generation,
    )
    .unwrap();
    let signature = URL_SAFE_NO_PAD.encode(ssk.sign(&input).to_bytes());
    serde_json::json!({
        "principal_id": principal,
        "device_id": device,
        "device_public_key": device_public_key,
        "hpke_key": hpke_key,
        "algorithms": algorithms,
        "authorized_by": principal,
        // Canonical operation timestamps are seconds-precision UTC.
        "not_before": "2026-05-30T00:00:00.000Z",
        "device_signature": "ZGV2aWNlLXNlbGYtc2lnbmF0dXJlLXBsYWNlaG9sZGVy",
        "recovery_session_id": session["recovery_session_id"],
        "cross_signing_binding": {
            "verification_method": format!("{principal}#CK_self_signing_v1"),
            "alg": "EdDSA",
            "ssk_generation": generation,
            "signature": signature,
        },
    })
}

/// Seed an accepted `ak.cross_signing.publish` (generation 1) into the server's
/// cross-signing registry so `/complete` can verify the device binding against the SSK.
pub(crate) fn seed_cross_signing(
    state: &AppState,
    principal_id: &str,
    vm: &str,
    psk: &SigningKey,
    ssk: &SigningKey,
    usk: &SigningKey,
) {
    let publish = serde_json::json!({
        "principal_id": principal_id,
        "trust_domain": "ak:trust_domain:soland.local",
        "principal_signing_key": {
            "kid": vm, "alg": "EdDSA",
            "public_key": test_ed25519_multibase_public(psk), "key_format": "multibase",
        },
        "self_signing_key": {
            "kid": format!("{principal_id}#CK_self_signing_v1"), "alg": "EdDSA",
            "public_key": test_ed25519_multibase_public(ssk), "key_format": "multibase",
            "binding": { "verification_method": vm, "alg": "EdDSA", "signature": "cGxhY2Vob2xkZXItc2ln" },
        },
        "user_signing_key": {
            "kid": format!("{principal_id}#CK_user_signing_v1"), "alg": "EdDSA",
            "public_key": test_ed25519_multibase_public(usk), "key_format": "multibase",
            "binding": { "verification_method": vm, "alg": "EdDSA", "signature": "cGxhY2Vob2xkZXItc2ln" },
        },
        "expected_previous_generation": 0,
        "generation": 1,
        "issued_at": "2026-05-30T00:00:00.000Z",
    });
    let content: arkret_models_identity::CrossSigningPublish =
        serde_json::from_value(publish).expect("cross-signing publish content");
    state
        .test_record_cross_signing_publish(content)
        .expect("seed cross-signing publish");
}

/// Seed a client-submitted control event into the durable event store (mirrors
/// what `POST /events` persists), so `/complete` can resolve it by id.
pub(crate) async fn seed_control_event(
    state: &AppState,
    event_id: &str,
    kind: &str,
    principal_id: &str,
    payload: Value,
) {
    let envelope = serde_json::json!({ "payload": payload });
    let canonical_bytes = arkret_canonical::canonical_json_bytes(&envelope).unwrap();
    state
        .test_persistence()
        .events()
        .put(CanonicalEventRecord {
            event_id: event_id.to_owned(),
            actor_id: principal_id.to_owned(),
            actor_seq: 1,
            realm_id: None,
            kind: kind.to_owned(),
            schema_id: "ak.schema.event.v1".to_owned(),
            canonical_digest: format!("sha256:{}", "0".repeat(64)),
            canonical_bytes,
            envelope,
            received_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
}

/// Seed both control events (authorize from `device_authorize`, list_update for
/// the session's device) and return `{authorization_event_id, device_list_update_event_id}`
/// for the complete_request body.
pub(crate) async fn seed_completion_events(
    state: &AppState,
    session: &Value,
    device_authorize: Value,
) -> Value {
    let principal = session["principal_id"].as_str().unwrap();
    let device = session["requesting_device_id"].as_str().unwrap();
    seed_control_event(
        state,
        AUTH_EVENT_ID,
        "ak.device.authorize",
        principal,
        device_authorize,
    )
    .await;
    seed_control_event(
        state,
        LIST_EVENT_ID,
        "ak.device.list_update",
        principal,
        serde_json::json!({ "principal_id": principal, "changed": [device] }),
    )
    .await;
    serde_json::json!({
        "authorization_event_id": AUTH_EVENT_ID,
        "device_list_update_event_id": LIST_EVENT_ID,
    })
}

/// Open a session for `signing`, submit a valid principal_signing proof, return
/// the verified session JSON + id. (No cross-signing seed.)
pub(crate) async fn verified_session_for(
    state: &AppState,
    token: &str,
    signing: &SigningKey,
    principal_id: &str,
    vm: &str,
) -> (Value, String) {
    let session = open_recovery_session(state.clone(), token, signing, principal_id, vm).await;
    let session_id = session["recovery_session_id"].as_str().unwrap().to_owned();
    let challenge = session["challenge"].as_str().unwrap().to_owned();
    let signature = sign_recovery_proof(signing, &session);
    post_recovery(
        state.clone(),
        token,
        &format!("/_arkret/root/identity/recovery-sessions/{session_id}/proofs"),
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
    (session, session_id)
}

pub(crate) fn did_recovery_backup_body(
    principal_id: &str,
    backup_id: &str,
    policy_id: &str,
) -> Value {
    serde_json::json!({
        "backup_id": backup_id,
        "actor_id": principal_id,
        "backup_class": "did_recovery",
        "backup_version": "kb_1",
        "created_at": "2026-05-30T00:00:00.000Z",
        "series_id": "ak:backup_series:01964137-0000-7000-8000-0000000000c5",
        "series_seq": 0,
        "recovery_policy_ref": { "policy_id": policy_id, "policy_version": 1 },
        "encryption": {
            "recipient_method": "recovery_public_key",
            "recipient_key_ref": "did:web:alice.example#recovery",
            "aead": {
                "name": "chacha20_poly1305",
                "aead_profile": "ak.aead.chacha20_poly1305.v1",
                "enc": "ZW5jYXBzdWxhdGVka2V5"
            }
        },
        "domain_separation": {
            "hkdf_info": "arkret-key-backup/did_recovery/recovery_policy/v1",
            "subdomain": "recovery_policy",
            "aead_aad": {
                "schema": "ak.schema.key_backup.v1",
                "actor_id": principal_id,
                "device_id": "did:web:alice.example#recovery",
                "backup_class": "did_recovery",
                "backup_version": "kb_1",
                "created_at": "2026-05-30T00:00:00.000Z",
                "item_types": ["recovery_key_share"]
            }
        },
        "contents": [{ "item_type": "recovery_key_share", "secret_id": "test-secret" }],
        "ciphertext": "AAAA",
        "ciphertext_digest":
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "auth_data": {
            "device_id": RECOVERY_TEST_DEVICE,
            "verification_method": format!("{principal_id}#device"),
            "signature_algorithm": "Ed25519",
            "signature": "c2lnbmF0dXJl",
            "ssk_generation": 1,
            "signed_fields": [
                "backup_id",
                "actor_id",
                "backup_class",
                "backup_version",
                "series_id",
                "series_seq",
                "supersedes",
                "encryption",
                "domain_separation",
                "contents",
                "ciphertext_digest",
                "recovery_policy_ref"
            ]
        }
    })
}

pub(crate) async fn put_key_backup(
    state: AppState,
    token: &str,
    backup_id: &str,
    body: &Value,
    expected_status: StatusCode,
) -> Value {
    let mut response = TestClient::put(format!(
        "http://server/_arkret/self/keys/backups/{backup_id}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .json(body)
    .send(&app_from_state(state))
    .await;
    let status = response.status_code.unwrap();
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, expected_status, "response body: {body}");
    body
}

pub(crate) async fn delete_key_backup(
    state: AppState,
    token: &str,
    principal_id: &str,
    backup_id: &str,
    expected_status: StatusCode,
) -> Value {
    let proof = format!("dev-ssk-delete:v1:{principal_id}:{backup_id}");
    let body = KeysBackupsDeleteRequestBody {
        proof: KeyBackupDeleteProof::Development(KeyBackupDeleteDevelopmentProof::new(proof)),
        reason: None,
    };
    let mut response = TestClient::delete(format!(
        "http://server/_arkret/self/keys/backups/{backup_id}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .json(&body)
    .send(&app_from_state(state))
    .await;
    let status = response.status_code.unwrap();
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, expected_status, "response body: {body}");
    body
}

pub(crate) async fn post_recovery(
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

pub(crate) async fn get_recovery(
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

pub(crate) fn shared_recovery_state(persistence: Arc<dyn PersistenceStore>) -> AppState {
    soland_test_support::app_state_with_persistence(test_config(), persistence)
}

pub(crate) fn shared_recovery_state_with_config(
    persistence: Arc<dyn PersistenceStore>,
    config: soland_http::config::AppConfig,
) -> AppState {
    soland_test_support::app_state_with_persistence(config, persistence)
}

pub(crate) async fn seed_recovery_policy(
    state: &AppState,
    principal_id: &str,
    verification_method: &str,
    version: u32,
    supersedes: Option<&str>,
) -> String {
    let policy_id = new_prefixed_uuid7("ak:policy:");
    let issued_at = chrono::DateTime::parse_from_rfc3339("2026-05-30T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let expires_at = chrono::DateTime::parse_from_rfc3339("2026-06-30T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let raw_payload = serde_json::json!({
        "schema": "ak.schema.recovery_policy.v1",
        "policy_id": policy_id,
        "principal_id": principal_id,
        "version": version,
        "trust_domain": "ak:trust_domain:soland.local",
        "allowed_proof_kinds": ["principal_signing"],
        "supersedes": supersedes,
        "issued_at": "2026-05-30T00:00:00.000Z",
        "expires_at": "2026-06-30T00:00:00.000Z",
        "auth_data": {
            "verification_method": verification_method,
            "signature_algorithm": "Ed25519",
            "signed_fields": POLICY_FIELDS,
            "signature": "c2lnbmF0dXJl"
        }
    });
    state
        .test_persistence()
        .recovery_policies()
        .insert(RecoveryPolicyRecord {
            policy_id: policy_id.clone(),
            principal_id: principal_id.to_owned(),
            version,
            trust_domain: "ak:trust_domain:soland.local".to_owned(),
            allowed_proof_kinds: vec!["principal_signing".to_owned()],
            supersedes: supersedes.map(ToOwned::to_owned),
            expires_at: Some(expires_at),
            issued_at,
            raw_payload,
            accepted_at: chrono::Utc::now(),
            verification_method: verification_method.to_owned(),
        })
        .await
        .unwrap();
    policy_id
}

pub(crate) async fn recovery_token_for_principal(state: AppState, principal_id: &str) -> String {
    dev_token_for_device(
        state,
        principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery Test Device",
    )
    .await
}

pub(crate) async fn ingest_fresh_recovery_did_document(state: &AppState, did: &str) {
    let now = chrono::Utc::now();
    let did_document = if let Some(public_key_multibase) = did.strip_prefix("did:key:") {
        let verification_method = format!("{did}#{public_key_multibase}");
        serde_json::json!({
            "id": did,
            "verificationMethod": [{
                "id": verification_method,
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": public_key_multibase,
            }],
            "authentication": [verification_method],
            "assertionMethod": [verification_method],
        })
    } else {
        serde_json::json!({
            "id": did,
            "verificationMethod": [],
        })
    };
    state
        .test_persistence()
        .webvh()
        .put_document(WebvhDocumentRecord {
            did: did.to_owned(),
            did_document,
            key_log_head: Some("sha256:recovery-test-head".to_owned()),
            seq: 1,
            method_evidence: serde_json::json!({ "mode": "test" }),
            fetched_at: now,
            expires_at: now,
            updated_at: now,
        })
        .await
        .unwrap();
}

pub(crate) async fn seed_bearer_session(state: &AppState, token: &str, actor: &str) {
    seed_bearer_session_with_device_payload(state, token, actor, "verified", serde_json::json!({}))
        .await;
}

pub(crate) async fn seed_bearer_session_with_device_public_key(
    state: &AppState,
    token: &str,
    actor: &str,
    device_public_key: &str,
) {
    seed_bearer_session_with_device_payload(
        state,
        token,
        actor,
        "unverified",
        serde_json::json!({ "device_public_key": device_public_key }),
    )
    .await;
}

pub(crate) async fn seed_bearer_session_with_device_payload(
    state: &AppState,
    token: &str,
    actor: &str,
    verification_state: &str,
    device_payload: Value,
) {
    let now = chrono::Utc::now();
    let device_id = RECOVERY_TEST_DEVICE;
    state
        .test_persistence()
        .sessions()
        .put(&SessionRecord {
            token_hash: test_session_credential_hash(token, state.service_id()),
            actor: actor.to_owned(),
            device_id: device_id.to_owned(),
            audience: state.service_id().clone(),
            session_public_key: None,
            agent_session: None,
            expires_at: now + chrono::Duration::minutes(10),
            created_at: now,
            revoked_at: None,
        })
        .await
        .unwrap();
    state
        .test_persistence()
        .devices()
        .put(&DeviceInventoryRecord {
            actor: actor.to_owned(),
            device_id: device_id.to_owned(),
            display_name: Some("Production Test Device".to_owned()),
            verification_state: verification_state.to_owned(),
            payload: device_payload,
            created_at: now,
            updated_at: now,
            revoked_at: None,
        })
        .await
        .unwrap();
}

pub(crate) fn test_session_credential_hash(token: &str, audience: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(audience.as_bytes());
    hasher.update(b":");
    hasher.update(token.as_bytes());
    format!("sha256:{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

pub(crate) fn did_key_principal(signing: &SigningKey) -> (String, String) {
    let multibase = test_ed25519_multibase_public(signing);
    let principal_id = format!("did:key:{multibase}");
    let verification_method = format!("{principal_id}#{multibase}");
    (principal_id, verification_method)
}

pub(crate) fn signed_recovery_policy(
    signing: &SigningKey,
    principal_id: &str,
    verification_method: &str,
    version: u32,
    supersedes: Option<&str>,
    signed_fields: &[&str],
) -> Value {
    let mut policy = serde_json::json!({
        "schema": "ak.schema.recovery_policy.v1",
        "policy_id": new_prefixed_uuid7("ak:policy:"),
        "principal_id": principal_id,
        "version": version,
        "trust_domain": "ak:trust_domain:soland.local",
        "allowed_proof_kinds": ["principal_signing"],
        "supersedes": supersedes,
        "issued_at": "2026-05-30T00:00:00.000Z",
        "expires_at": "2026-06-30T00:00:00.000Z",
        "auth_data": {
            "verification_method": verification_method,
            "signature_algorithm": "Ed25519",
            "signed_fields": signed_fields,
            "signature": ""
        }
    });
    sign_recovery_payload(
        &mut policy,
        "ak.identity.recovery_policy.signature.v1",
        signed_fields,
        signing,
    );
    policy
}

pub(crate) fn signed_recovery_receipt(
    signing: &SigningKey,
    principal_id: &str,
    verification_method: &str,
    policy_id: &str,
    policy_version: u32,
    recovery_session_id: Option<&str>,
    signed_fields: &[&str],
) -> Value {
    let mut receipt = serde_json::json!({
        "schema": "ak.schema.recovery_receipt.v1",
        "receipt_id": new_prefixed_uuid7("ak:receipt:"),
        "principal_id": principal_id,
        "recovery_session_id": recovery_session_id
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| new_prefixed_uuid7("ak:recovery_session:")),
        "policy_id": policy_id,
        "policy_version": policy_version,
        "trust_domain": "ak:trust_domain:soland.local",
        "new_device_id": "ak:device:01904100-0000-7000-8000-000000000042",
        "proof_summary": {
            "kind": "principal_signing",
            "proof_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        },
        "backup_classes_unlocked": [],
        "welcome_count": 0,
        "outcome": "completed",
        "started_at": "2026-05-30T00:00:00.000Z",
        "completed_at": "2026-05-30T00:00:01.000Z",
        "auth_data": {
            "verification_method": verification_method,
            "signature_algorithm": "EdDSA",
            "signed_fields": signed_fields,
            "signature": ""
        }
    });
    sign_recovery_payload(
        &mut receipt,
        "ak.identity.recovery_receipt.signature.v1",
        signed_fields,
        signing,
    );
    receipt
}

pub(crate) fn sign_recovery_payload(
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
    let transcript_bytes = arkret_canonical::canonical_json_bytes(&transcript).unwrap();
    let signature = signing.sign(&transcript_bytes);
    payload["auth_data"]["signature"] =
        serde_json::json!(URL_SAFE_NO_PAD.encode(signature.to_bytes()));
}

pub(crate) async fn post_recovery_policy(
    state: AppState,
    token: &str,
    body: &Value,
    expected_status: StatusCode,
) -> Value {
    if let Some(principal_id) = body.get("principal_id").and_then(Value::as_str) {
        ingest_fresh_recovery_did_document(&state, principal_id).await;
    }
    let mut response = TestClient::post("http://server/_arkret/root/identity/recovery-policy")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(body)
        .send(&app_from_state(state))
        .await;
    let status = response.status_code.unwrap();
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, expected_status, "response body: {body}");
    body
}

pub(crate) async fn post_recovery_receipt(
    state: AppState,
    token: &str,
    body: &Value,
    expected_status: StatusCode,
) -> Value {
    let mut response = TestClient::post("http://server/_soland/root/identity/recovery-receipt")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(body)
        .send(&app_from_state(state))
        .await;
    let status = response.status_code.unwrap();
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, expected_status, "response body: {body}");
    body
}
