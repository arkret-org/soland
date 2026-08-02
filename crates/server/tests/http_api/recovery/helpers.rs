//! Shared helpers and constants for the `recovery` test cluster.
//!
//! Every test submodule under `http_api::recovery::*` reaches these via
//! `use super::helpers::*;`. Shared common-module fixtures arrive through
//! `use crate::common::*;`.

use std::sync::Arc;

use arkret_identifiers::Hash;
use arkret_models_crypto::{
    KeyBackupDeleteProof, KeysBackupsDeleteChallenge, KeysBackupsDeleteRequestBody,
    KeysBackupsIssueDeleteChallengeRequestBody,
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
    "publication_authorization_rules",
    "supersedes",
    "issued_at",
    "expires_at",
];

pub(crate) const RECOVERY_TEST_DEVICE: &str = "ak:device:01904100-0000-7000-8000-a11ce0000001";

pub(crate) const RECOVERY_TEST_DEVICE_B: &str = "ak:device:01904100-0000-7000-8000-a11ce0000002";

fn seed_local_notary_authority(state: &AppState, realm_id: &RealmId, seal: &arkret_wire::Seal) {
    let move_id = seal
        .delta
        .first()
        .cloned()
        .expect("notary fixture Seal covers a Control Move");
    let op = arkret_state::lattice::ordered_log::IssuedOp {
        issuer: Did::new(state.service_id().to_owned()).unwrap(),
        op: arkret_state::lattice::SealedOp::new(
            move_id,
            arkret_wire::LatticeOp {
                op_type: arkret_wire::LatticeOpType::Set,
                tag: None,
                value: Some(serde_json::json!({
                    "kind": "single_did",
                    "did": state.service_id(),
                })),
                from: None,
                to: None,
                reason: None,
                issuer_seq: None,
            },
        ),
    };
    state
        .test_append_sealed_effects(
            realm_id,
            &seal.id,
            &[(arkret_wire::REALM_NOTARY_CELL.parse().unwrap(), op)],
        )
        .unwrap();
}

async fn seed_realm_create_proposal_policy(
    state: &AppState,
    realm_id: &RealmId,
    principal_id: &str,
) -> arkret_wire::EventId {
    if let Some(record) = state
        .test_persistence()
        .events()
        .realm_events_newest_first(realm_id.as_str())
        .await
        .unwrap()
        .into_iter()
        .find(|record| record.kind == arkret_wire::EventKind::REALM_CREATE)
    {
        return arkret_wire::EventId::new(record.event_id).unwrap();
    }
    let event = arkret_wire::Event::new(
        arkret_wire::EventKind::REALM_CREATE,
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        Did::new(principal_id.to_owned()).unwrap(),
        0,
        arkret_identifiers::Hlc::new(format!(
            "{:012x}-0000-a11ce100",
            chrono::Utc::now().timestamp_millis()
        ))
        .unwrap(),
        serde_json::json!({
            "object": {
                "id": realm_id,
            }
        }),
    )
    .unwrap();
    let event_id = event.event_id.clone();
    let canonical_digest = event.event_digest().unwrap();
    let envelope = serde_json::to_value(&event).unwrap();
    state
        .test_persistence()
        .events()
        .put(CanonicalEventRecord {
            event_id: event_id.to_string(),
            actor_id: principal_id.to_owned(),
            actor_seq: 0,
            realm_id: Some(realm_id.to_string()),
            kind: arkret_wire::EventKind::REALM_CREATE.to_owned(),
            schema_id: "ak.schema.event_envelope.v1".to_owned(),
            canonical_digest,
            canonical_bytes: arkret_canonical::canonical_json_bytes(&envelope).unwrap(),
            envelope,
            received_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
    event_id
}

/// Helper: seed an accepted v1 policy for `principal_id` and open a recovery
/// session against it. Returns the session JSON body.
pub(crate) async fn open_recovery_session(
    state: AppState,
    token: &str,
    signing: &SigningKey,
    principal_id: &str,
    vm: &str,
) -> Value {
    ingest_pinned_recovery_did_document(&state, principal_id, vm, signing).await;
    seed_recovery_policy(&state, principal_id, vm, 1, None).await;
    ensure_cross_signing(state.clone(), principal_id, vm, signing).await;
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

pub(crate) async fn ensure_cross_signing(
    state: AppState,
    principal_id: &str,
    vm: &str,
    signing: &SigningKey,
) {
    let principal = Did::new(principal_id.to_owned()).unwrap();
    if !state.test_has_current_cross_signing(&principal) {
        let ssk = SigningKey::from_bytes(&[231u8; 32]);
        let usk = SigningKey::from_bytes(&[232u8; 32]);
        let _ = seed_cross_signing(&state, principal_id, vm, signing, &ssk, &usk).await;
    }
}

/// Build the canonical recovery-proof transcript the server reconstructs, and
/// return a base64url Ed25519 signature over it by `signing`.
pub(crate) fn sign_recovery_proof(signing: &SigningKey, session: &Value) -> String {
    let model_generation_ref = recovery_model_generation_ref(session);
    let transcript = serde_json::json!({
        "schema": "ak.identity.recovery_proof.v1",
        "kind": "principal_signing",
        "principal_id": session["principal_id"],
        "requesting_device_id": session["requesting_device_id"],
        "trust_domain": session["trust_domain"],
        "policy_id": session["policy_id"],
        "policy_version": session["policy_version"],
        "recovery_session_id": session["recovery_session_id"],
        "identity_model": session["identity_model"],
        "model_generation_ref": model_generation_ref,
        "publication_authority_context_digest": session["publication_authority_context_digest"],
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
        "schema": "ak.identity.recovery_proof.v1",
        "kind": "trusted_recovery_service",
        "principal_id": session["principal_id"],
        "requesting_device_id": session["requesting_device_id"],
        "trust_domain": session["trust_domain"],
        "policy_id": session["policy_id"],
        "policy_version": session["policy_version"],
        "recovery_session_id": session["recovery_session_id"],
        "identity_model": session["identity_model"],
        "model_generation_ref": model_generation_ref,
        "publication_authority_context_digest": session["publication_authority_context_digest"],
        "challenge": session["challenge"],
        "created_at": session["created_at"],
        "expires_at": session["expires_at"],
        "proof_body": proof_body,
    });
    let bytes = arkret_canonical::canonical_json_bytes(&transcript).unwrap();
    URL_SAFE_NO_PAD.encode(signing.sign(&bytes).to_bytes())
}

pub(crate) fn recovery_unlock_proof(
    signing: &SigningKey,
    session: &Value,
    recovery_secret_ref: &str,
) -> Value {
    let proof_body = serde_json::json!({
        "kind": "recovery_unlock",
        "challenge": session["challenge"],
        "recovery_secret_ref": recovery_secret_ref,
        "verification_method": recovery_secret_ref,
        "alg": "Ed25519",
    });
    let transcript = serde_json::json!({
        "schema": "ak.identity.recovery_proof.v1",
        "kind": "recovery_unlock",
        "principal_id": session["principal_id"],
        "requesting_device_id": session["requesting_device_id"],
        "trust_domain": session["trust_domain"],
        "policy_id": session["policy_id"],
        "policy_version": session["policy_version"],
        "recovery_session_id": session["recovery_session_id"],
        "identity_model": session["identity_model"],
        "model_generation_ref": recovery_model_generation_ref(session),
        "publication_authority_context_digest": session["publication_authority_context_digest"],
        "challenge": session["challenge"],
        "created_at": session["created_at"],
        "expires_at": session["expires_at"],
        "proof_body": proof_body,
    });
    let bytes = arkret_canonical::canonical_json_bytes(&transcript).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(b"ak.recovery-session-unlock-binding-v1\n");
    hasher.update(recovery_secret_ref.as_bytes());
    hasher.update(&bytes);

    serde_json::json!({
        "proof": {
            "kind": "recovery_unlock",
            "challenge": session["challenge"],
            "recovery_secret_ref": recovery_secret_ref,
            "verification_method": recovery_secret_ref,
            "alg": "Ed25519",
            "unlock_commitment": format!("sha256:{}", hex::encode(hasher.finalize())),
            "signature": URL_SAFE_NO_PAD.encode(signing.sign(&bytes).to_bytes()),
        }
    })
}

fn recovery_model_generation_ref(session: &Value) -> Value {
    match session["identity_model"].as_str() {
        Some("cross_signing") => session["ssk_generation"].clone(),
        Some("enrollment_authority") => session["current_device_generation_ref"].clone(),
        other => panic!("unexpected recovery identity model in fixture: {other:?}"),
    }
}

pub(crate) async fn seed_cross_signing(
    state: &AppState,
    principal_id: &str,
    vm: &str,
    psk: &SigningKey,
    ssk: &SigningKey,
    usk: &SigningKey,
) -> String {
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
        serde_json::from_value(publish.clone()).expect("cross-signing publish content");
    state
        .test_record_cross_signing_publish(content)
        .expect("seed cross-signing publish");

    let realm_id = soland_test_support::principal_control_realm_for_did(principal_id);
    let realm = RealmId::new(realm_id.clone()).unwrap();
    let create_event_id = seed_realm_create_proposal_policy(state, &realm, principal_id).await;
    let event_id = new_prefixed_uuid7("ak:event:");
    let envelope = serde_json::json!({
        "event_id": event_id,
        "actor_id": principal_id,
        "actor_seq": 1,
        "realm_id": realm_id,
        "kind": "ak.cross_signing.publish",
        "prev_refs": [create_event_id],
        "payload": publish,
    });
    let canonical_bytes = arkret_canonical::canonical_json_bytes(&envelope).unwrap();
    let canonical_digest = arkret_canonical::sha256_digest(&canonical_bytes);
    state
        .test_persistence()
        .events()
        .put(CanonicalEventRecord {
            event_id: event_id.clone(),
            actor_id: principal_id.to_owned(),
            actor_seq: 1,
            realm_id: Some(realm_id.clone()),
            kind: "ak.cross_signing.publish".to_owned(),
            schema_id: "ak.schema.cross_signing_publish.v1".to_owned(),
            canonical_digest: canonical_digest.clone(),
            canonical_bytes,
            envelope,
            received_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        [0x61; 32],
        Did::new(principal_id.to_owned()).unwrap(),
        arkret_wire::DidUrl::new(format!("{principal_id}#fixture-notary")).unwrap(),
    );
    let seal = arkret_wire::Seal::sign_single(
        realm,
        Vec::new(),
        vec![Hash::new(canonical_digest).unwrap()],
        Hash::new(arkret_state::EMPTY_STATE_ROOT.to_owned()).unwrap(),
        arkret_identifiers::Hlc::new("019f00000000-0000-a11ce101").unwrap(),
        &signer,
    )
    .unwrap();
    state.test_put_seal(&seal).unwrap();
    seed_local_notary_authority(state, &seal.realm_id, &seal);
    event_id
}

pub(crate) fn fixture_recovery_policy_basis() -> arkret_wire::LeaseBasisRef {
    arkret_wire::LeaseBasisRef::Seal(
        arkret_identifiers::SealId::new(format!("ak:seal:sha256:{}", "b".repeat(64))).unwrap(),
    )
}

pub(crate) fn fixture_recovery_publication_authority_context(
    principal_id: &str,
) -> (
    arkret_models_crypto::RecoveryPublicationAuthorityContext,
    Hash,
) {
    let realm_id = RealmId::new(soland_test_support::principal_control_realm_for_did(
        principal_id,
    ))
    .unwrap();
    let scope_ref = arkret_wire::ScopeRef::Realm { realm_id };
    let authority_set_policy = arkret_wire::AuthoritySetPolicy {
        schema: arkret_wire::SchemaId::AUTHORITY_SET_POLICY_V1.to_owned(),
        authority_set_id: arkret_wire::RECOVERY_CROSS_SIGNING_AUTHORITY_SET_ID.to_owned(),
        policy_kind: arkret_wire::AuthoritySetPolicyKind::PrincipalControl,
        scope_ref: scope_ref.clone(),
        source: arkret_wire::AuthoritySetPolicySource {
            source_kind: arkret_wire::AuthoritySetSourceKind::CrossSigningPublish,
            source_ref: new_prefixed_uuid7("ak:event:"),
            source_digest: Hash::new(format!("sha256:{}", "c".repeat(64))).unwrap(),
            generation_ref: "1".to_owned(),
        },
        authorization_rules: vec![arkret_wire::AuthoritySetAuthorizationRule {
            rule_id: "cross_signing".to_owned(),
            issuer_role: arkret_wire::AuthoritySetIssuerRole::CrossSigningSelfSigning,
            allowed_actions: vec![
                "ak.device.authorize".to_owned(),
                "ak.device.list_update".to_owned(),
            ],
            issuers: vec![arkret_wire::AuthoritySetIssuer {
                verification_method: arkret_wire::DidUrl::new(format!(
                    "{principal_id}#CK_self_signing_v1"
                ))
                .unwrap(),
            }],
            threshold: 1,
        }],
    };
    let authority_set_ref = arkret_wire::AuthoritySetRef {
        authority_set_id: authority_set_policy.authority_set_id.clone(),
        authority_set_digest: authority_set_policy.digest().unwrap(),
    };
    let context = arkret_models_crypto::RecoveryPublicationAuthorityContext {
        identity_model: arkret_models_crypto::RecoveryIdentityModel::CrossSigning,
        basis_ref: fixture_recovery_policy_basis(),
        scope_ref,
        authority_set_ref,
        authority_set_policy,
        allowed_actions: vec![
            arkret_models_crypto::RecoveryPublicationAction::DeviceAuthorize,
            arkret_models_crypto::RecoveryPublicationAction::DeviceListUpdate,
        ],
    };
    let digest = context.digest().unwrap();
    (context, digest)
}

/// Build a schema-conforming DID recovery backup fixture.
pub(crate) fn did_recovery_backup_body(
    principal_id: &str,
    backup_id: &str,
    policy_id: &str,
) -> Value {
    serde_json::json!({
        "backup_id": backup_id,
        "actor_id": principal_id,
        "backup_kind": "did_recovery",
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
                "backup_kind": "did_recovery",
                "backup_version": "kb_1",
                "created_at": "2026-05-30T00:00:00.000Z",
                "item_kinds": ["recovery_key_share"]
            }
        },
        "contents": [{ "item_kind": "recovery_key_share", "secret_id": "test-secret" }],
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
                "backup_kind",
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
    // `key-management.md` §7 makes `Idempotency-Key` mandatory on a key-backup
    // PUT. The key is derived from the backup id so a retry of the same
    // fixture write replays rather than conflicting, which is what these tests
    // exercise — they are about recovery policy, not about idempotency.
    let mut response = TestClient::put(format!(
        "http://server/_arkret/self/keys/backups/{backup_id}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .add_header("idempotency-key", format!("fixture:{backup_id}"), true)
    .json(body)
    .send(&app_from_state(state))
    .await;
    let status = response.status_code.unwrap();
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, expected_status, "response body: {body}");
    body
}

/// Drive the whole §7.8.1 delete protocol: ask for a challenge, sign the
/// canonical delete-intent transcript with the principal's control key, then
/// DELETE.
///
/// It has to be the whole protocol. The previous helper posted a
/// `dev-ssk-delete:v1:{actor}:{backup}` string, which `key-management.md` §7.8
/// judged dead precisely because it carried no server-issued freshness — a
/// helper that skipped the challenge would be testing a path the server no
/// longer has.
pub(crate) async fn delete_key_backup(
    state: AppState,
    token: &str,
    signing: &SigningKey,
    verification_method: &str,
    backup_id: &str,
    expected_status: StatusCode,
) -> Value {
    let request_id = arkret_wire::Base64UrlString::new("dGVzdC1yZXF1ZXN0LWlk")
        .expect("fixture request_id is base64url");
    let challenge =
        issue_key_backup_delete_challenge(state.clone(), token, backup_id, request_id.clone())
            .await;

    let transcript = challenge.delete_intent_transcript(None);
    let canonical =
        arkret_canonical::canonical_json_bytes(&transcript).expect("canonical transcript");
    let payload_digest = challenge
        .delete_intent_digest(None)
        .expect("delete-intent digest");
    let proof = arkret_wire::PayloadProof {
        kind: "detached_jws".to_owned(),
        verification_method: arkret_wire::DidUrl::new(verification_method.to_owned())
            .expect("fixture verification method is a DID URL"),
        alg: "EdDSA".to_owned(),
        payload_digest,
        // Inside the challenge window, which the server checks.
        created_at: challenge.issued_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: arkret_signatures::jws::sign_jws_ed25519(&canonical, signing).expect("sign"),
    };

    let body = KeysBackupsDeleteRequestBody {
        request_id,
        challenge_id: challenge.challenge_id.clone(),
        proof: KeyBackupDeleteProof::PrincipalSigning { proof },
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

pub(crate) async fn issue_key_backup_delete_challenge(
    state: AppState,
    token: &str,
    backup_id: &str,
    request_id: arkret_wire::Base64UrlString,
) -> KeysBackupsDeleteChallenge {
    let mut response = TestClient::post(format!(
        "http://server/_arkret/self/keys/backups/{backup_id}/delete-challenge"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .json(&KeysBackupsIssueDeleteChallengeRequestBody { request_id })
    .send(&app_from_state(state))
    .await;
    let status = response.status_code.unwrap();
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "response body: {body}");
    serde_json::from_value(body).expect("issued challenge decodes")
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
        .send(&app_from_state(state.clone()))
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
        .send(&app_from_state(state.clone()))
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
        "publication_authorization_rules": [{
            "rule_id": "principal_signing",
            "proof_kind": "principal_signing",
            "issuer_role": "identity_recovery",
            "allowed_actions": ["ak.device.reanchor"],
            "issuers": [{"verification_method": verification_method}],
            "threshold": 1
        }],
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
            acceptance_basis: fixture_recovery_policy_basis(),
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
    let verification_method = arkret_wire::DidUrl::new(format!("{principal_id}#{multibase}"))
        .expect("fixture verification method is a DID URL");
    (principal_id, verification_method.as_str().to_owned())
}

pub(crate) fn did_webvh_principal(signing: &SigningKey) -> (String, String) {
    let multibase = test_ed25519_multibase_public(signing);
    let principal_id = format!("did:webvh:{multibase}:recovery.example");
    let verification_method = arkret_wire::DidUrl::new(format!("{principal_id}#recovery"))
        .expect("fixture verification method is a DID URL");
    (principal_id, verification_method.as_str().to_owned())
}

pub(crate) async fn ingest_pinned_recovery_did_document(
    state: &AppState,
    did: &str,
    verification_method: &str,
    signing: &SigningKey,
) {
    let now = chrono::Utc::now();
    let public_key_multibase = test_ed25519_multibase_public(signing);
    let did_document = serde_json::json!({
        "id": did,
        "verificationMethod": [{
            "id": verification_method,
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": public_key_multibase,
        }],
        "authentication": [verification_method],
        "assertionMethod": [verification_method],
    });
    let key_log_head = arkret_canonical::canonical_sha256(&serde_json::json!({
        "did": did,
        "version_id": 1,
        "verification_method": verification_method,
        "public_key_multibase": public_key_multibase,
    }))
    .expect("fixture DID log head hashes");
    state
        .test_persistence()
        .webvh()
        .put_document(WebvhDocumentRecord {
            did: did.to_owned(),
            did_document,
            key_log_head: Some(key_log_head),
            seq: 1,
            method_evidence: serde_json::json!({
                "mode": "test",
                "parameters": {"method": "did:webvh:1.0"}
            }),
            fetched_at: now,
            expires_at: now + chrono::Duration::hours(1),
            updated_at: now,
        })
        .await
        .unwrap();
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
        "publication_authorization_rules": [{
            "rule_id": "principal_signing",
            "proof_kind": "principal_signing",
            "issuer_role": "identity_recovery",
            "allowed_actions": ["ak.device.reanchor"],
            "issuers": [{"verification_method": verification_method}],
            "threshold": 1
        }],
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
    policy: &Value,
    event_signing_key: &SigningKey,
    expected_status: StatusCode,
) -> Value {
    let principal_id = policy["principal_id"]
        .as_str()
        .expect("recovery policy principal_id");
    let verification_method = arkret_wire::DidUrl::new(
        policy["auth_data"]["verification_method"]
            .as_str()
            .expect("recovery policy verification method"),
    )
    .expect("fixture verification method is a DID URL");
    // did-usage-and-verification.md §2.2 — the Event proof method MUST be a
    // `#fragment` DID URL under the principal. The non-`did:key:` fallback
    // reuses the policy's own method, so pin the invariant here instead of
    // letting a bare DID reach the Event.
    let event_verification_method = arkret_wire::DidUrl::new(principal_id.strip_prefix("did:key:").map_or_else(
        || {
            assert!(
                verification_method.starts_with(&format!("{principal_id}#")),
                "fixture verification_method `{verification_method}` must be a DID URL rooted in {principal_id}"
            );
            verification_method.as_str().to_owned()
        },
        |key| format!("{principal_id}#{key}"),
    ))
    .expect("fixture Event verification method is a DID URL");
    ingest_pinned_recovery_did_document(
        &state,
        principal_id,
        event_verification_method.as_str(),
        event_signing_key,
    )
    .await;

    let realm_id = soland_test_support::principal_control_realm_for_did(principal_id);
    let realm = RealmId::new(realm_id.clone()).unwrap();
    seed_realm_create_proposal_policy(&state, &realm, principal_id).await;
    soland_test_support::cba_basis::seed_realm_basis(&state, &realm_id, principal_id, &[]).await;
    let basis = soland_test_support::cba_basis::realm_basis_seal(&realm_id, principal_id, &[]);
    seed_local_notary_authority(&state, &realm, &basis);
    let prior = state
        .test_persistence()
        .events()
        .realm_events_newest_first(&realm_id)
        .await
        .expect("recovery policy Realm events");
    let actor_seq = prior
        .iter()
        .filter(|record| record.actor_id == principal_id)
        .map(|record| record.actor_seq)
        .max()
        .map_or(0, |seq| seq + 1);
    let prev_refs = prior
        .iter()
        .filter(|record| record.actor_id == principal_id && record.actor_seq + 1 == actor_seq)
        .map(|record| arkret_wire::EventId::new(record.event_id.clone()).unwrap())
        .collect();
    let logical = TEST_EVENT_SEQ.fetch_add(1, Ordering::Relaxed) & 0xffff;
    let mut event = arkret_wire::Event::new(
        arkret_wire::EventKind::POLICY_SET,
        arkret_wire::ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        Did::new(principal_id.to_owned()).unwrap(),
        actor_seq,
        arkret_identifiers::Hlc::new(format!(
            "{:012x}-{logical:04x}-a11ce101",
            chrono::Utc::now().timestamp_millis()
        ))
        .unwrap(),
        serde_json::json!({
            "policy_id": policy["policy_id"],
            "value": policy,
        }),
    )
    .unwrap();
    event.prev_refs = prev_refs;
    event.requirements.schema_profile_refs =
        vec![arkret_wire::ProfileRef::new("ak.schema.recovery_policy.v1").unwrap()];
    soland_test_support::cba_basis::apply_registered_cba_plane(
        &mut event,
        &event_verification_method,
        &[],
    );
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        event_signing_key.clone(),
        event.actor_id.clone(),
        event_verification_method.clone(),
    );
    let event_created_at = event.created_at;
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        &event_verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(event_created_at),
    )
    .unwrap();

    let mut lease_response = TestClient::post("http://server/_arkret/self/authorization-leases")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header(
            "Idempotency-Key",
            format!("recovery-policy-lease-{}", event.event_id),
            true,
        )
        .json(&arkret_wire::AuthorizationLeaseIssueRequest {
            events: vec![event.clone()],
            intents: Vec::new(),
        })
        .send(&app_from_state(state.clone()))
        .await;
    let lease_status = lease_response.status_code.unwrap();
    let lease_body: Value = lease_response.take_json().await.unwrap();
    if lease_status != StatusCode::OK {
        assert_eq!(lease_status, expected_status, "response body: {lease_body}");
        return lease_body;
    }
    let lease_outcome: arkret_wire::AuthorizationLeaseIssueOutcome =
        serde_json::from_value(lease_body).expect("authorization lease outcome");
    let receipt_request = arkret_wire::ProposalReceiptIssueRequest {
        event: event.clone(),
        authorization_lease: lease_outcome.authorization_leases[0].clone(),
        cba_proof_bundles: Vec::new(),
    };
    let mut receipt_response =
        TestClient::post("http://server/_arkret/self/control-proposal-receipts")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&receipt_request)
            .send(&app_from_state(state.clone()))
            .await;
    let receipt_status = receipt_response.status_code.unwrap();
    let receipt_body: Value = receipt_response.take_json().await.unwrap();
    if receipt_status != StatusCode::OK {
        assert_eq!(
            receipt_status, expected_status,
            "response body: {receipt_body}"
        );
        return receipt_body;
    }
    let receipt_outcome: arkret_wire::ProposalReceiptIssueOutcome =
        serde_json::from_value(receipt_body).expect("proposal receipt outcome");
    let member_receipt = receipt_outcome.member_receipt;
    let control_proposal_receipt = arkret_wire::ControlProposalReceipt {
        kind: arkret_wire::ControlProposalReceiptKind::ProposalReceipt,
        realm_id: member_receipt.realm_id.clone(),
        proposal_digest: member_receipt.proposal_digest.clone(),
        received_at: member_receipt.received_at,
        decision_due_at: member_receipt.decision_due_at,
        absolute_due_at: member_receipt.absolute_due_at,
        defer_count: 0,
        authority_set_ref: member_receipt.authority_set_ref.clone(),
        member_receipts: vec![member_receipt],
    };
    let request = arkret_models_crypto::RecoveryPolicyPublishRequest {
        event: event.clone(),
        authorization_lease: lease_outcome.authorization_leases[0].clone(),
        cba_proof_bundles: Vec::new(),
        control_proposal_receipt: Some(control_proposal_receipt),
    };
    let mut response = TestClient::post("http://server/_arkret/root/identity/recovery-policy")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&request)
        .send(&app_from_state(state.clone()))
        .await;
    let mut status = response.status_code.unwrap();
    let mut response_body: Value = response.take_json().await.unwrap();

    if expected_status == StatusCode::CREATED {
        assert_eq!(
            status,
            StatusCode::PRECONDITION_FAILED,
            "first publication must wait for Seal coverage: {response_body}"
        );
        assert_eq!(response_body["error"]["code"], "frontier_unavailable");

        let leaves = state
            .test_seal_leaves(&realm)
            .expect("recovery policy Seal frontier");
        assert_eq!(leaves.len(), 1, "fixture recovery frontier must be linear");
        let mut pending = leaves.clone();
        let mut covered = std::collections::BTreeSet::new();
        let mut predecessor_state_root = None;
        while let Some(seal_id) = pending.pop() {
            let seal = state
                .test_seal(&seal_id)
                .expect("recovery policy predecessor lookup")
                .expect("recovery policy predecessor");
            if predecessor_state_root.is_none() {
                predecessor_state_root = Some(seal.state_root.clone());
            }
            covered.extend(seal.delta);
            pending.extend(seal.predecessor_refs);
        }
        let event_digest = Hash::new(event.event_digest().unwrap()).unwrap();
        covered.insert(event_digest.clone());
        let control_root =
            arkret_state::control_event_set_root(&covered).expect("recovery policy control root");
        let seal_signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
            [0x62; 32],
            Did::new(principal_id.to_owned()).unwrap(),
            arkret_wire::DidUrl::new(format!("{principal_id}#recovery-policy-notary")).unwrap(),
        );
        let successor = arkret_wire::Seal::sign_single_kind_with_control_root(
            realm,
            leaves,
            vec![event_digest],
            control_root,
            predecessor_state_root.expect("recovery policy predecessor state root"),
            arkret_identifiers::Hlc::new(format!(
                "{:012x}-{logical:04x}-a11ce102",
                chrono::Utc::now().timestamp_millis()
            ))
            .unwrap(),
            arkret_wire::SealKind::Normal,
            &seal_signer,
        )
        .unwrap();
        state.test_put_seal(&successor).unwrap();

        let mut retry = TestClient::post("http://server/_arkret/root/identity/recovery-policy")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&request)
            .send(&app_from_state(state))
            .await;
        status = retry.status_code.unwrap();
        response_body = retry.take_json().await.unwrap();
    }

    assert_eq!(status, expected_status, "response body: {response_body}");
    response_body
}
