//! Integration tests — C-P2..C-P5 recovery session lifecycle + completion.

use std::sync::Arc;

use soland_storage::{
    CanonicalEventRecord, DeviceInventoryRecord, DeviceMessageRecord, RecoveryPolicyRecord,
    RecoverySessionRecord, WebvhLogRecord,
};
use soland_storage_memory::SolandMemoryPersistenceStore;

use super::helpers::*;
use crate::common::*;

const RESET_SOURCE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-c51000000001";

fn cross_signing_reset_event(
    actor: &str,
    device_id: &str,
    event_id: &str,
    actor_seq: u64,
    prev_event_id: &str,
    payload: Value,
    actor_signing_key: &SigningKey,
) -> Value {
    let realm_id = soland_test_support::principal_control_realm_for_did(actor);
    let event = signed_canonical_event(
        event_id,
        "ak.cross_signing.reset",
        actor,
        device_id,
        &realm_id,
        actor_seq,
        vec![prev_event_id],
        payload,
    );
    let mut event: arkret_wire::Event =
        serde_json::from_value(event).expect("reset Event roundtrip");
    event.proofs.clear();
    let verification_method = actor.strip_prefix("did:key:").map_or_else(
        || format!("{actor}#{device_id}"),
        |key| format!("{actor}#{key}"),
    );
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        actor_signing_key.clone(),
        event.actor_id.clone(),
        verification_method.clone(),
    );
    let created_at = event.created_at;
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(created_at),
    )
    .expect("reset Event signing");
    serde_json::to_value(event).expect("reset Event serializes")
}
fn base_reset_payload(principal_id: &str, event_id: &str, proof: Value) -> Value {
    serde_json::json!({
        "principal_id": principal_id,
        "trust_domain": "ak:trust_domain:soland.local",
        "reset_event_id": event_id,
        "previous_generation": 1,
        "new_generation": 2,
        "reset_reason_code": "rotation",
        "proof": proof,
        "issued_at": arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
    })
}

fn sign_reset_payload(payload: &mut Value, signing: &SigningKey) {
    let content: arkret_models_identity::CrossSigningResetPayload =
        serde_json::from_value(payload.clone()).expect("reset content");
    let input = content.reset_signing_input().expect("reset signing input");
    let signature = URL_SAFE_NO_PAD.encode(signing.sign(&input).to_bytes());
    payload["proof"]["signature"] = serde_json::json!(signature);
}

fn sign_device_quorum_reset_payload(payload: &mut Value, signings: &[SigningKey]) {
    let content: arkret_models_identity::CrossSigningResetPayload =
        serde_json::from_value(payload.clone()).expect("reset content");
    let input = content.reset_signing_input().expect("reset signing input");
    for (idx, signing) in signings.iter().enumerate() {
        let signature = URL_SAFE_NO_PAD.encode(signing.sign(&input).to_bytes());
        payload["proof"]["signatures"][idx]["signature"] = serde_json::json!(signature);
    }
}

fn bind_recovery_unlock_commitment(payload: &mut Value) {
    let content: arkret_models_identity::CrossSigningResetPayload =
        serde_json::from_value(payload.clone()).expect("reset content");
    let commitment = content
        .recovery_unlock_commitment()
        .expect("recovery unlock commitment");
    payload["proof"]["unlock_commitment"] = serde_json::json!(commitment);
}

async fn submit_reset_event(state: AppState, token: &str, event: Value) -> Value {
    submit_reset_event_with_status(state, token, event, StatusCode::OK).await
}

async fn submit_reset_event_with_status(
    state: AppState,
    token: &str,
    event: Value,
    expected_status: StatusCode,
) -> Value {
    let mut response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&event)
        .send(&app_from_state(state))
        .await;
    let status = response.status_code.unwrap();
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, expected_status, "response body: {body}");
    body
}

async fn seed_reset_recovery_policy(
    state: &AppState,
    principal_id: &str,
    allowed_kind: &str,
    extra: Value,
) -> String {
    let policy_id = new_prefixed_uuid7("ak:policy:");
    let issued_at = chrono::Utc::now();
    let expires_at = issued_at + chrono::Duration::days(1);
    let mut raw_payload = serde_json::json!({
        "schema": "ak.schema.recovery_policy.v1",
        "policy_id": policy_id.clone(),
        "principal_id": principal_id,
        "version": 1,
        "supersedes": null,
        "trust_domain": "ak:trust_domain:soland.local",
        "allowed_proof_kinds": [allowed_kind],
        "publication_authorization_rules": [{
            "rule_id": allowed_kind,
            "proof_kind": allowed_kind,
            "issuer_role": "identity_recovery",
            "allowed_actions": ["ak.device.reanchor"],
            "issuers": [{
                "verification_method": format!("{principal_id}#reset-policy")
            }],
            "threshold": 1
        }],
        "issued_at": arkret_canonical::format_timestamp_canonical(issued_at),
        "expires_at": arkret_canonical::format_timestamp_canonical(expires_at),
        "auth_data": {
            "verification_method": format!("{principal_id}#reset-policy"),
            "signature_algorithm": "Ed25519",
            "signed_fields": [
                "schema",
                "policy_id",
                "principal_id",
                "version",
                "supersedes",
                "trust_domain",
                "allowed_proof_kinds",
                "publication_authorization_rules",
                "issued_at",
                "expires_at"
            ],
            "signature": "AA"
        }
    });
    if let (Some(target), Some(extra)) = (raw_payload.as_object_mut(), extra.as_object()) {
        for (key, value) in extra {
            target.insert(key.clone(), value.clone());
        }
    }
    state
        .test_persistence()
        .recovery_policies()
        .insert(RecoveryPolicyRecord {
            policy_id: policy_id.clone(),
            principal_id: principal_id.to_owned(),
            version: 1,
            acceptance_basis: fixture_recovery_policy_basis(),
            trust_domain: "ak:trust_domain:soland.local".to_owned(),
            allowed_proof_kinds: vec![allowed_kind.to_owned()],
            supersedes: None,
            expires_at: Some(expires_at),
            issued_at,
            raw_payload,
            accepted_at: chrono::Utc::now(),
            verification_method: format!("{principal_id}#reset-policy"),
        })
        .await
        .unwrap();
    policy_id
}

async fn seed_verified_reset_recovery_session(
    state: &AppState,
    principal_id: &str,
    policy_id: &str,
) -> String {
    let now = chrono::Utc::now();
    let recovery_session_id = new_prefixed_uuid7("ak:recovery_session:");
    let (publication_authority_context, publication_authority_context_digest) =
        fixture_recovery_publication_authority_context(principal_id);
    state
        .test_persistence()
        .recovery_sessions()
        .insert(RecoverySessionRecord {
            recovery_session_id: recovery_session_id.clone(),
            principal_id: principal_id.to_owned(),
            requesting_device_id: RESET_SOURCE_DEVICE.to_owned(),
            trust_domain: "ak:trust_domain:soland.local".to_owned(),
            policy_id: policy_id.to_owned(),
            policy_version: 1,
            identity_model: arkret_models_crypto::RecoveryIdentityModel::CrossSigning,
            ssk_generation: Some(1),
            current_device_generation_ref: None,
            device_generation_status: None,
            registry_head: None,
            accepted_seal_frontier: None,
            policy_payload: serde_json::json!({}),
            publication_authority_context,
            publication_authority_context_digest,
            challenge: "verified-reset-session".to_owned(),
            state: "verified".to_owned(),
            proof_payload: Some(serde_json::json!({
                "proof": { "kind": "principal_signing" }
            })),
            transaction_id: None,
            created_at: now - chrono::Duration::seconds(1),
            updated_at: now,
            expires_at: now + chrono::Duration::minutes(10),
        })
        .await
        .unwrap();
    recovery_session_id
}

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
    assert!(session_id.starts_with("ak:recovery_session:"));

    let fetched = get_recovery(
        state,
        &token,
        &format!("/_arkret/root/identity/recovery-sessions/{session_id}"),
        StatusCode::OK,
    )
    .await;
    assert_eq!(fetched["recovery_session_id"], session_id);
    assert_eq!(fetched["challenge"], challenge);
    assert_eq!(fetched["state"], "pending");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_session_derives_enrollment_authority_model() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let principal_id = "did:webvh:z6mkfixture:recovery.example";
    let authority_id = "did:webvh:z6mkauthority:recovery.example";
    let inception_version = format!("1-{}", "a".repeat(64));
    let inception_digest = format!("sha256:{}", "b".repeat(64));
    let realm_id = soland_test_support::principal_control_realm_for_did(principal_id);
    let create_event_id = "ak:event:01964137-0000-7000-8000-00000000b001";
    let authorize_event_id = "ak:event:01964137-0000-7000-8000-00000000b002";
    let now = chrono::Utc::now();

    state
        .test_persistence()
        .webvh()
        .append_log_event(WebvhLogRecord {
            event_digest: inception_digest.clone(),
            did: principal_id.to_owned(),
            seq: 1,
            operation: serde_json::json!({
                "versionId": inception_version,
                "state": {
                    "id": principal_id,
                    "service": [{
                        "id": format!("{principal_id}#device-enrollment-authority"),
                        "type": "ArkretDeviceEnrollmentAuthority",
                        "serviceEndpoint": authority_id,
                    }],
                },
            }),
            created_at: now,
        })
        .await
        .unwrap();

    let mut bootstrap_records = Vec::new();
    for (event_id, actor_seq, kind, digest_hex, envelope) in [
        (
            create_event_id,
            0,
            "ak.realm.create",
            "c",
            serde_json::json!({
                "event_id": create_event_id,
                "kind": "ak.realm.create",
                "actor_id": principal_id,
                "actor_seq": 0,
                "realm_id": realm_id,
                "prev_refs": [],
                "refs": [{"role": "did_inception", "critical": true}],
                "payload": {"object": {"fields": {"purpose": "principal_control"}}},
            }),
        ),
        (
            authorize_event_id,
            1,
            "ak.device.authorize",
            "d",
            serde_json::json!({
                "event_id": authorize_event_id,
                "kind": "ak.device.authorize",
                "actor_id": principal_id,
                "actor_seq": 1,
                "realm_id": realm_id,
                "prev_refs": [create_event_id],
                "refs": [],
                "payload": {"principal_id": principal_id},
            }),
        ),
    ] {
        let canonical_bytes = arkret_canonical::canonical_json_bytes(&envelope).unwrap();
        bootstrap_records.push(CanonicalEventRecord {
            event_id: event_id.to_owned(),
            actor_id: principal_id.to_owned(),
            actor_seq,
            realm_id: Some(realm_id.clone()),
            kind: kind.to_owned(),
            schema_id: "ak.schema.event_envelope.v1".to_owned(),
            canonical_digest: format!("sha256:{}", digest_hex.repeat(64)),
            canonical_bytes,
            envelope,
            received_at: now,
        });
    }
    state
        .test_persistence()
        .events()
        .put_identity_anchor_batch_atomic(
            bootstrap_records,
            Vec::new(),
            None,
            None,
            None,
            None,
            Vec::new(),
            Vec::new(),
        )
        .await
        .unwrap();

    seed_reset_recovery_policy(
        &state,
        principal_id,
        "principal_signing",
        serde_json::json!({}),
    )
    .await;
    let token = dev_token_for_device(
        state.clone(),
        principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery",
    )
    .await;
    let requesting_device_id = "ak:device:01904100-0000-7000-8000-000000000099";
    let session = post_recovery(
        state.clone(),
        &token,
        "/_arkret/root/identity/recovery-sessions",
        &serde_json::json!({
            "principal_id": principal_id,
            "trust_domain": "ak:trust_domain:soland.local",
            "requesting_device_id": requesting_device_id,
        }),
        StatusCode::CREATED,
    )
    .await;

    assert_eq!(session["identity_model"], "enrollment_authority");
    assert_eq!(
        session["current_device_generation_ref"],
        serde_json::json!(inception_version)
    );
    assert_eq!(session["device_generation_status"], "active");
    assert_eq!(session["registry_head"], inception_digest);
    assert!(session.get("ssk_generation").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_session_create_requires_active_policy() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[102u8; 32]);
    let (principal_id, _) = did_key_principal(&signing);
    let token = dev_token_for_device(
        state.clone(),
        &principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery",
    )
    .await;

    let create_body = serde_json::json!({
        "principal_id": principal_id,
        "trust_domain": "ak:trust_domain:soland.local",
        "requesting_device_id": "ak:device:01904100-0000-7000-8000-000000000099",
    });
    let body = post_recovery(
        state,
        &token,
        "/_arkret/root/identity/recovery-sessions",
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
        &format!("/_arkret/root/identity/recovery-sessions/{session_id}"),
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
        &format!("/_arkret/root/identity/recovery-sessions/{session_id}/proofs"),
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
        &format!("/_arkret/root/identity/recovery-sessions/{session_id}"),
        StatusCode::OK,
    )
    .await;
    assert_eq!(fetched["schema"], "ak.schema.recovery_session.v1");
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
        &format!("/_arkret/root/identity/recovery-sessions/{session_id}/proofs"),
        &proof_body,
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_eq!(body["error"]["code"], "proof_invalid");

    // Session stays pending after a rejected proof.
    let fetched = get_recovery(
        state,
        &token,
        &format!("/_arkret/root/identity/recovery-sessions/{session_id}"),
        StatusCode::OK,
    )
    .await;
    assert_eq!(fetched["state"], "pending");
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_session_recovery_unlock_binds_policy_transcript_and_key() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let principal_signing = SigningKey::from_bytes(&[141u8; 32]);
    let (principal_id, principal_vm) = did_key_principal(&principal_signing);
    let recovery_signing = SigningKey::from_bytes(&[142u8; 32]);
    let recovery_ref = format!("{principal_id}#recovery-proof-0");
    let recovery_public = test_ed25519_multibase_public(&recovery_signing);
    let not_before = arkret_canonical::format_timestamp_canonical(
        chrono::Utc::now() - chrono::Duration::hours(1),
    );
    let expires_at = arkret_canonical::format_timestamp_canonical(
        chrono::Utc::now() + chrono::Duration::days(1),
    );
    let key_agreement_ref = format!("{principal_id}#backup-hpke-0");
    seed_reset_recovery_policy(
        &state,
        &principal_id,
        "recovery_unlock",
        serde_json::json!({
            "recovery_keys": [{
                "verification_method": recovery_ref.clone(),
                "public_key_multibase": recovery_public,
                "key_agreement_ref": key_agreement_ref.clone(),
                "alg": "Ed25519",
                "not_before": not_before,
                "expires_at": expires_at,
            }],
            "recovery_key_agreements": [{
                "key_agreement_ref": key_agreement_ref,
                "alg": "X25519",
                "public_key_multibase": "z6LSr8KVwSrjSa7Bj6KagU93mSi8zQM6VfmmUoTb8xXJFEr7",
                "hpke_suites": ["ak.hpke_x25519_aead_chacha20poly1305.v1"],
                "use": "backup_hpke",
                "not_before": not_before,
                "expires_at": expires_at,
            }],
        }),
    )
    .await;
    ensure_cross_signing(
        state.clone(),
        &principal_id,
        &principal_vm,
        &principal_signing,
    )
    .await;
    let token = dev_token_for_device(
        state.clone(),
        &principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery",
    )
    .await;
    let session = post_recovery(
        state.clone(),
        &token,
        "/_arkret/root/identity/recovery-sessions",
        &serde_json::json!({
            "principal_id": principal_id,
            "trust_domain": "ak:trust_domain:soland.local",
            "requesting_device_id": "ak:device:01904100-0000-7000-8000-000000000141",
        }),
        StatusCode::CREATED,
    )
    .await;
    let session_id = session["recovery_session_id"].as_str().unwrap();

    let mut bad_commitment = recovery_unlock_proof(&recovery_signing, &session, &recovery_ref);
    bad_commitment["proof"]["unlock_commitment"] =
        serde_json::json!(format!("sha256:{}", "00".repeat(32)));
    let rejected = post_recovery(
        state.clone(),
        &token,
        &format!("/_arkret/root/identity/recovery-sessions/{session_id}/proofs"),
        &bad_commitment,
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_eq!(rejected["error"]["code"], "recovery_evidence_unbound");

    let attacker = SigningKey::from_bytes(&[143u8; 32]);
    let bad_signature = recovery_unlock_proof(&attacker, &session, &recovery_ref);
    let rejected = post_recovery(
        state.clone(),
        &token,
        &format!("/_arkret/root/identity/recovery-sessions/{session_id}/proofs"),
        &bad_signature,
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_eq!(rejected["error"]["code"], "proof_invalid");

    let fetched = get_recovery(
        state.clone(),
        &token,
        &format!("/_arkret/root/identity/recovery-sessions/{session_id}"),
        StatusCode::OK,
    )
    .await;
    assert_eq!(fetched["state"], "pending");

    let accepted = post_recovery(
        state,
        &token,
        &format!("/_arkret/root/identity/recovery-sessions/{session_id}/proofs"),
        &recovery_unlock_proof(&recovery_signing, &session, &recovery_ref),
        StatusCode::OK,
    )
    .await;
    assert_eq!(accepted["state"], "verified");
    assert_eq!(accepted["proof_summary"]["kind"], "recovery_unlock");
    assert!(
        accepted["proof_summary"]["proof_digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_session_trusted_recovery_service_proof_verifies_and_audits() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[134u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let service_key = SigningKey::from_bytes(&[135u8; 32]);
    let (service_id, service_vm) = did_key_principal(&service_key);
    seed_reset_recovery_policy(
        &state,
        &principal_id,
        "trusted_recovery_service",
        serde_json::json!({
            "trusted_recovery_services": [{ "service_id": service_id.clone() }]
        }),
    )
    .await;
    ensure_cross_signing(state.clone(), &principal_id, &vm, &signing).await;
    let token = dev_token_for_device(
        state.clone(),
        &principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery",
    )
    .await;
    let create_body = serde_json::json!({
        "principal_id": principal_id.clone(),
        "trust_domain": "ak:trust_domain:soland.local",
        "requesting_device_id": "ak:device:01904100-0000-7000-8000-000000000139",
    });
    let session = post_recovery(
        state.clone(),
        &token,
        "/_arkret/root/identity/recovery-sessions",
        &create_body,
        StatusCode::CREATED,
    )
    .await;
    let session_id = session["recovery_session_id"].as_str().unwrap().to_owned();
    let challenge = session["challenge"].as_str().unwrap().to_owned();
    let audience = state.service_id().clone();
    let signature = sign_trusted_recovery_service_proof(
        &service_key,
        &session,
        &service_id,
        &service_vm,
        &audience,
        None,
    );

    let proof_body = serde_json::json!({
        "proof": {
            "kind": "trusted_recovery_service",
            "challenge": challenge,
            "service_id": service_id.clone(),
            "audience": audience.clone(),
            "verification_method": service_vm.clone(),
            "alg": "EdDSA",
            "signature": signature,
        },
    });
    let body = post_recovery(
        state.clone(),
        &token,
        &format!("/_arkret/root/identity/recovery-sessions/{session_id}/proofs"),
        &proof_body,
        StatusCode::OK,
    )
    .await;
    assert_eq!(body["state"], "verified");
    assert_eq!(body["proof_summary"]["kind"], "trusted_recovery_service");
    assert!(
        body["proof_summary"]["proof_digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );

    let fetched = get_recovery(
        state.clone(),
        &token,
        &format!("/_arkret/root/identity/recovery-sessions/{session_id}"),
        StatusCode::OK,
    )
    .await;
    assert_eq!(fetched["state"], "verified");
    assert_eq!(fetched["proof_summary"], body["proof_summary"]);

    let audit = state
        .test_persistence()
        .audit()
        .list_for_actor(&principal_id)
        .await
        .unwrap();
    let proof_audit = audit
        .iter()
        .find(|entry| {
            entry.get("action").and_then(Value::as_str)
                == Some("ak.root.identity.recovery_session.command.submit_proof")
        })
        .expect("submit_proof audit row");
    assert_eq!(proof_audit["outcome"], "verified");
    assert_eq!(
        proof_audit["payload"]["proof_kind"],
        "trusted_recovery_service"
    );
    assert_eq!(
        proof_audit["payload"]["proof_summary"],
        body["proof_summary"]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_session_trusted_recovery_service_rejects_unlisted_service_and_allows_retry() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[136u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let service_key = SigningKey::from_bytes(&[137u8; 32]);
    let (service_id, service_vm) = did_key_principal(&service_key);
    let attacker_service_key = SigningKey::from_bytes(&[138u8; 32]);
    let (attacker_service_id, attacker_service_vm) = did_key_principal(&attacker_service_key);
    seed_reset_recovery_policy(
        &state,
        &principal_id,
        "trusted_recovery_service",
        serde_json::json!({
            "trusted_recovery_services": [{ "service_id": service_id.clone() }]
        }),
    )
    .await;
    ensure_cross_signing(state.clone(), &principal_id, &vm, &signing).await;
    let token = dev_token_for_device(
        state.clone(),
        &principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery",
    )
    .await;
    let create_body = serde_json::json!({
        "principal_id": principal_id.clone(),
        "trust_domain": "ak:trust_domain:soland.local",
        "requesting_device_id": "ak:device:01904100-0000-7000-8000-000000000140",
    });
    let session = post_recovery(
        state.clone(),
        &token,
        "/_arkret/root/identity/recovery-sessions",
        &create_body,
        StatusCode::CREATED,
    )
    .await;
    let session_id = session["recovery_session_id"].as_str().unwrap().to_owned();
    let challenge = session["challenge"].as_str().unwrap().to_owned();
    let audience = state.service_id().clone();
    let rejected_signature = sign_trusted_recovery_service_proof(
        &attacker_service_key,
        &session,
        &attacker_service_id,
        &attacker_service_vm,
        &audience,
        None,
    );
    let rejected_body = serde_json::json!({
        "proof": {
            "kind": "trusted_recovery_service",
            "challenge": challenge,
            "service_id": attacker_service_id.clone(),
            "audience": audience.clone(),
            "verification_method": attacker_service_vm.clone(),
            "alg": "EdDSA",
            "signature": rejected_signature,
        },
    });
    let body = post_recovery(
        state.clone(),
        &token,
        &format!("/_arkret/root/identity/recovery-sessions/{session_id}/proofs"),
        &rejected_body,
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_eq!(body["error"]["code"], "recovery_proof_authority_invalid");

    let fetched = get_recovery(
        state.clone(),
        &token,
        &format!("/_arkret/root/identity/recovery-sessions/{session_id}"),
        StatusCode::OK,
    )
    .await;
    assert_eq!(fetched["state"], "pending");

    let accepted_signature = sign_trusted_recovery_service_proof(
        &service_key,
        &session,
        &service_id,
        &service_vm,
        state.service_id(),
        None,
    );
    let accepted_audience = state.service_id().clone();
    let accepted_body = serde_json::json!({
        "proof": {
            "kind": "trusted_recovery_service",
            "challenge": session["challenge"],
            "service_id": service_id.clone(),
            "audience": accepted_audience,
            "verification_method": service_vm.clone(),
            "alg": "EdDSA",
            "signature": accepted_signature,
        },
    });
    let body = post_recovery(
        state,
        &token,
        &format!("/_arkret/root/identity/recovery-sessions/{session_id}/proofs"),
        &accepted_body,
        StatusCode::OK,
    )
    .await;
    assert_eq!(body["state"], "verified");
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
        "proof": {
            "kind": "principal_signing",
            "challenge": "not-the-real-challenge",
            "verification_method": vm,
            "alg": "EdDSA",
            "signature": "c2ln"
        },
    });
    let body = post_recovery(
        state,
        &token,
        &format!("/_arkret/root/identity/recovery-sessions/{session_id}/proofs"),
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
        "proof": {
            "kind": "device_quorum",
            "challenge": challenge,
            "threshold": 2,
            "signatures": [
                {
                    "device_id": "ak:device:01904100-0000-7000-8000-000000000071",
                    "verification_method": format!("{principal_id}#device-a"),
                    "alg": "EdDSA",
                    "signature": "c2ln"
                },
                {
                    "device_id": "ak:device:01904100-0000-7000-8000-000000000072",
                    "verification_method": format!("{principal_id}#device-b"),
                    "alg": "EdDSA",
                    "signature": "c2ln"
                }
            ]
        },
    });
    let body = post_recovery(
        state,
        &token,
        &format!("/_arkret/root/identity/recovery-sessions/{session_id}/proofs"),
        &proof_body,
        StatusCode::CONFLICT,
    )
    .await;
    assert_eq!(body["error"]["code"], "recovery_proof_kind_not_allowed");
}

#[tokio::test(flavor = "multi_thread")]
async fn cross_signing_reset_accepts_recovery_unlock_quorum_and_trusted_service_proofs() {
    // recovery_unlock proof.
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[121u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let ssk = SigningKey::from_bytes(&[122u8; 32]);
    let usk = SigningKey::from_bytes(&[123u8; 32]);
    let publish_event_id =
        seed_cross_signing(&state, &principal_id, &vm, &signing, &ssk, &usk).await;
    let recovery_key = SigningKey::from_bytes(&[124u8; 32]);
    let (_recovery_did, recovery_ref) = did_key_principal(&recovery_key);
    let policy_id = seed_reset_recovery_policy(
        &state,
        &principal_id,
        "recovery_unlock",
        serde_json::json!({
            "recovery_unlock": { "recovery_secret_ref": recovery_ref }
        }),
    )
    .await;
    let token = dev_token_for_device(
        state.clone(),
        &principal_id,
        RESET_SOURCE_DEVICE,
        "Reset Source",
    )
    .await;
    let recovery_session_id =
        seed_verified_reset_recovery_session(&state, &principal_id, &policy_id).await;
    let event_id = new_prefixed_uuid7("ak:event:");
    let mut payload = base_reset_payload(
        &principal_id,
        &event_id,
        serde_json::json!({
            "kind": "recovery_unlock",
            "recovery_session_id": recovery_session_id,
            "recovery_secret_ref": recovery_ref,
            "unlock_commitment": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "alg": "EdDSA",
            "signature": "AA"
        }),
    );
    bind_recovery_unlock_commitment(&mut payload);
    sign_reset_payload(&mut payload, &recovery_key);
    let body = submit_reset_event(
        state.clone(),
        &token,
        cross_signing_reset_event(
            &principal_id,
            RESET_SOURCE_DEVICE,
            &event_id,
            2,
            &publish_event_id,
            payload,
            &signing,
        ),
    )
    .await;
    assert_eq!(body["status"], "accepted", "body: {body}");
    assert_eq!(body["accepted"][0], event_id);

    // trusted_recovery_service proof.
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[125u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let ssk = SigningKey::from_bytes(&[126u8; 32]);
    let usk = SigningKey::from_bytes(&[127u8; 32]);
    let publish_event_id =
        seed_cross_signing(&state, &principal_id, &vm, &signing, &ssk, &usk).await;
    let service_key = SigningKey::from_bytes(&[128u8; 32]);
    let (service_id, service_vm) = did_key_principal(&service_key);
    let policy_id = seed_reset_recovery_policy(
        &state,
        &principal_id,
        "trusted_recovery_service",
        serde_json::json!({
            "trusted_recovery_services": [{ "service_id": service_id }]
        }),
    )
    .await;
    let token = dev_token_for_device(
        state.clone(),
        &principal_id,
        RESET_SOURCE_DEVICE,
        "Reset Source",
    )
    .await;
    let recovery_session_id =
        seed_verified_reset_recovery_session(&state, &principal_id, &policy_id).await;
    let event_id = new_prefixed_uuid7("ak:event:");
    let mut payload = base_reset_payload(
        &principal_id,
        &event_id,
        serde_json::json!({
            "kind": "trusted_recovery_service",
            "recovery_session_id": recovery_session_id,
            "service_id": service_id,
            "verification_method": service_vm,
            "alg": "EdDSA",
            "signature": "AA"
        }),
    );
    sign_reset_payload(&mut payload, &service_key);
    let body = submit_reset_event(
        state.clone(),
        &token,
        cross_signing_reset_event(
            &principal_id,
            RESET_SOURCE_DEVICE,
            &event_id,
            2,
            &publish_event_id,
            payload,
            &signing,
        ),
    )
    .await;
    assert_eq!(body["status"], "accepted", "body: {body}");
    assert_eq!(body["accepted"][0], event_id);

    // device_quorum proof.
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[129u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let ssk = SigningKey::from_bytes(&[130u8; 32]);
    let usk = SigningKey::from_bytes(&[131u8; 32]);
    let publish_event_id =
        seed_cross_signing(&state, &principal_id, &vm, &signing, &ssk, &usk).await;
    seed_reset_recovery_policy(
        &state,
        &principal_id,
        "device_quorum",
        serde_json::json!({ "device_quorum": { "k": 2 } }),
    )
    .await;
    let device_a = "ak:device:01904100-0000-7000-8000-c5100000000a";
    let device_b = "ak:device:01904100-0000-7000-8000-c5100000000b";
    let device_a_key = SigningKey::from_bytes(&[132u8; 32]);
    let device_b_key = SigningKey::from_bytes(&[133u8; 32]);
    for (device_id, key) in [(device_a, &device_a_key), (device_b, &device_b_key)] {
        let now = chrono::Utc::now();
        state
            .test_persistence()
            .devices()
            .put(&DeviceInventoryRecord {
                actor: principal_id.clone(),
                device_id: device_id.to_owned(),
                display_name: Some("Quorum Device".to_owned()),
                verification_state: "verified".to_owned(),
                payload: serde_json::json!({
                    "device_public_key": test_ed25519_multibase_public(key)
                }),
                created_at: now,
                updated_at: now,
                revoked_at: None,
            })
            .await
            .unwrap();
    }
    let token = dev_token_for_device(
        state.clone(),
        &principal_id,
        RESET_SOURCE_DEVICE,
        "Reset Source",
    )
    .await;
    let event_id = new_prefixed_uuid7("ak:event:");
    let mut payload = base_reset_payload(
        &principal_id,
        &event_id,
        serde_json::json!({
            "kind": "device_quorum",
            "threshold": 2,
            "signatures": [
                {
                    "device_id": device_a,
                    "verification_method": format!("{principal_id}#{device_a}"),
                    "alg": "EdDSA",
                    "signature": "AA"
                },
                {
                    "device_id": device_b,
                    "verification_method": format!("{principal_id}#{device_b}"),
                    "alg": "EdDSA",
                    "signature": "AA"
                }
            ]
        }),
    );
    sign_device_quorum_reset_payload(&mut payload, &[device_a_key, device_b_key]);
    let body = submit_reset_event(
        state.clone(),
        &token,
        cross_signing_reset_event(
            &principal_id,
            RESET_SOURCE_DEVICE,
            &event_id,
            2,
            &publish_event_id,
            payload,
            &signing,
        ),
    )
    .await;
    assert_eq!(body["status"], "accepted", "body: {body}");
    assert_eq!(body["accepted"][0], event_id);
}

#[tokio::test(flavor = "multi_thread")]
async fn cross_signing_reset_replay_cache_and_queue_purge_cover_publish_window() {
    let state = shared_recovery_state(Arc::new(SolandMemoryPersistenceStore::new()));
    let signing = SigningKey::from_bytes(&[134u8; 32]);
    let (principal_id, vm) = did_key_principal(&signing);
    let ssk = SigningKey::from_bytes(&[135u8; 32]);
    let usk = SigningKey::from_bytes(&[136u8; 32]);
    let publish_event_id =
        seed_cross_signing(&state, &principal_id, &vm, &signing, &ssk, &usk).await;
    let token = dev_token_for_device(
        state.clone(),
        &principal_id,
        RESET_SOURCE_DEVICE,
        "Reset Source",
    )
    .await;

    let target_device = "ak:device:01904100-0000-7000-8000-c5100000000c";
    let now = chrono::Utc::now();
    for (position, kind, content) in [
        (
            1,
            "ak.key.verification.request",
            serde_json::json!({ "transaction_id": "old-verification" }),
        ),
        (
            2,
            "ak.key.verification.request",
            serde_json::json!({ "transaction_id": "new-verification", "new_generation": 2 }),
        ),
        (
            3,
            "ak.message.notify",
            serde_json::json!({ "body": "ordinary queued message" }),
        ),
    ] {
        state
            .test_persistence()
            .device_messages()
            .append(DeviceMessageRecord {
                idempotency_key: format!("reset-purge-{position}"),
                sender: principal_id.clone(),
                recipient: principal_id.clone(),
                device_id: target_device.to_owned(),
                position,
                content: serde_json::json!({
                    "kind": kind,
                    "content": content,
                    "expires_at": arkret_canonical::format_timestamp_canonical(
                        now + chrono::Duration::hours(1)
                    ),
                }),
                created_at: now,
            })
            .await
            .unwrap();
    }

    let event_id = new_prefixed_uuid7("ak:event:");
    let mut payload = base_reset_payload(
        &principal_id,
        &event_id,
        serde_json::json!({
            "kind": "principal_signing",
            "verification_method": vm,
            "alg": "EdDSA",
            "signature": "AA"
        }),
    );
    sign_reset_payload(&mut payload, &signing);
    let body = submit_reset_event(
        state.clone(),
        &token,
        cross_signing_reset_event(
            &principal_id,
            RESET_SOURCE_DEVICE,
            &event_id,
            2,
            &publish_event_id,
            payload,
            &signing,
        ),
    )
    .await;
    assert_eq!(body["status"], "accepted", "body: {body}");

    let queued = state
        .test_persistence()
        .device_messages()
        .list_after(&principal_id, target_device, 0)
        .await
        .unwrap();
    let kinds: Vec<_> = queued
        .iter()
        .filter_map(|message| message.content.get("kind").and_then(Value::as_str))
        .collect();
    assert_eq!(
        kinds,
        vec!["ak.key.verification.request", "ak.message.notify"],
        "queued after reset: {queued:?}"
    );
    assert_eq!(
        queued[0]
            .content
            .pointer("/content/new_generation")
            .and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(
        state
            .test_persistence()
            .device_messages()
            .lost_watermark(&principal_id, target_device)
            .await
            .unwrap(),
        Some(1)
    );

    let replay_event_id = new_prefixed_uuid7("ak:event:");
    let mut replay_payload = base_reset_payload(
        &principal_id,
        &replay_event_id,
        serde_json::json!({
            "kind": "principal_signing",
            "verification_method": vm,
            "alg": "EdDSA",
            "signature": "AA"
        }),
    );
    sign_reset_payload(&mut replay_payload, &signing);
    let replay = submit_reset_event_with_status(
        state,
        &token,
        cross_signing_reset_event(
            &principal_id,
            RESET_SOURCE_DEVICE,
            &replay_event_id,
            3,
            &event_id,
            replay_payload,
            &signing,
        ),
        StatusCode::PRECONDITION_FAILED,
    )
    .await;
    assert_eq!(replay["error"]["message"], "cross_signing_reset_replayed");
}
