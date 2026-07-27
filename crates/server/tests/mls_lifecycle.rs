//! G3.S1 integration test — exercises the keypackage/welcome HTTP surface
//! end-to-end:
//!
//!   1. upload a KeyPackage,
//!   2. claim it atomically (and assert a second claim returns 409),
//!   3. submit canonical `ak.mls.genesis` and `ak.mls.welcome` events and assert they mirror into
//!      the MLS epoch / Welcome stores,
//!   4. receive the Welcome through the standard durable device-message stream.
//!
//! MLS commits no longer have a dedicated REST surface — clients submit
//! `ak.mls.commit` events via the canonical `POST /_arkret/self/events` pipeline
//! (W1C). The commit-bump path is covered by reducer-level unit tests in
//! `reducer::mls`; we don't re-test it here.
//!
//! The test runs against a fresh in-memory soland (no Pg) using the
//! shared `dev-login` shortcut for bearer issuance — same pattern as
//! `tests/http_api/`.

use std::collections::BTreeMap;

use arkret_identifiers::{Did, TypedTrustDomainId};
use arkret_models_collaboration::events_payloads::MlsWelcomeClaimEnvelope;
use arkret_models_identity::{
    CrossSigningPublish, KeyFormat, PublishedKey, SubordinateSignedKey, SubordinateSignedKeyBinding,
};
use arkret_wire::NonEmptyString;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use ed25519_dalek::{Signer as _, SigningKey};
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use soland_http::config::{AppConfig, ObjectStorageConfig};
use soland_http::service;
use soland_http::state::AppState;
use soland_test_support::AppStateTestExt as _;

fn test_config() -> AppConfig {
    AppConfig {
        object_storage: ObjectStorageConfig::local(std::env::temp_dir().join("soland-mls-blobs")),
        development_mode: true,
        did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: BTreeMap::new(),
        trust_domain: "ak:trust_domain:soland-mls-test.local".to_owned(),
        ..soland_test_support::app_config()
    }
}

fn app_from_state(state: AppState) -> salvo::Service {
    service(state)
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn test_ssk_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[42_u8; 32])
}

fn ed25519_public_multibase(signing: &SigningKey) -> String {
    let mut bytes = Vec::with_capacity(34);
    bytes.extend_from_slice(&[0xed, 0x01]);
    bytes.extend_from_slice(signing.verifying_key().as_bytes());
    format!("z{}", bs58::encode(bytes).into_string())
}

fn sign_b64(signing: &SigningKey, bytes: &[u8]) -> String {
    b64(&signing.sign(bytes).to_bytes())
}

fn sha256_json(value: &Value) -> String {
    let bytes = arkret_canonical::canonical_json_bytes(value)
        .unwrap_or_else(|_| serde_json::to_vec(value).unwrap());
    format!("sha256:{}", hex::encode(Sha256::digest(&bytes)))
}

fn signed_event(
    event_id: &str,
    actor_seq: u64,
    actor: &str,
    device_id: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
) -> Value {
    let now = Utc::now();
    let actor = arkret_identifiers::Did::new(actor.to_owned()).unwrap();
    let verification_method = format!("{}#{device_id}", actor.as_str());
    let mut event = arkret_wire::Event::new_with_id_at(
        arkret_wire::EventId::new(event_id.to_owned()).unwrap(),
        kind,
        arkret_identifiers::RealmId::new(realm_id.to_owned()).unwrap(),
        actor.clone(),
        actor_seq,
        arkret_identifiers::Hlc::new(format!(
            "{:012x}-0000-00000000",
            now.timestamp_millis().max(0) as u64
        ))
        .unwrap(),
        payload,
        now,
    )
    .unwrap();
    let signer = arkret_signatures::Ed25519MoveSigner::from_did_key_seed(
        [21_u8; 32],
        actor,
        verification_method.clone(),
    );
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(now),
    )
    .unwrap();
    serde_json::to_value(event).unwrap()
}

fn set_event_prev_refs(event: &mut Value, prev_refs: &[&str]) {
    let verification_method = event["proofs"][0]["verification_method"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut typed: arkret_wire::Event = serde_json::from_value(event.clone()).unwrap();
    typed.prev_refs = prev_refs
        .iter()
        .map(|event_id| arkret_wire::EventId::new((*event_id).to_owned()).unwrap())
        .collect();
    typed.proofs.clear();
    let signer = arkret_signatures::Ed25519MoveSigner::from_did_key_seed(
        [21_u8; 32],
        typed.actor_id.clone(),
        verification_method.clone(),
    );
    let created_at = typed.created_at;
    arkret_signatures::sign_event(
        &mut typed,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(created_at),
    )
    .unwrap();
    *event = serde_json::to_value(typed).unwrap();
}

fn set_realm_create_effects(event: &mut Value) {
    let verification_method = event["proofs"][0]["verification_method"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut typed: arkret_wire::Event = serde_json::from_value(event.clone()).unwrap();
    typed.effects = arkret_bootstrap::realm_create_effects(&typed).unwrap();
    typed.proofs.clear();
    let signer = arkret_signatures::Ed25519MoveSigner::from_did_key_seed(
        [21_u8; 32],
        typed.actor_id.clone(),
        verification_method.clone(),
    );
    let created_at = typed.created_at;
    arkret_signatures::sign_event(
        &mut typed,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(created_at),
    )
    .unwrap();
    *event = serde_json::to_value(typed).unwrap();
}

async fn dev_token(state: AppState, actor: &str, device_id: &str, display: &str) -> String {
    let login: Value = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&json!({
            "actor": actor,
            "device_id": device_id,
            "display_name": display,
        }))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    login["session_credential"].as_str().unwrap().to_owned()
}

fn cross_signing_publish(principal: &str, generation: u64) -> CrossSigningPublish {
    let principal_id = Did::new(principal.to_owned()).unwrap();
    let self_signing_public_key = ed25519_public_multibase(&test_ssk_signing_key());
    CrossSigningPublish {
        principal_id: principal_id.clone(),
        trust_domain: TypedTrustDomainId::new("ak:trust_domain:soland-mls-test.local").unwrap(),
        principal_signing_key: PublishedKey {
            kid: NonEmptyString::new(format!("{principal}#principal-signing")).unwrap(),
            alg: NonEmptyString::new("EdDSA").unwrap(),
            public_key: NonEmptyString::new("z6MkPrincipalAlice").unwrap(),
            key_format: KeyFormat::Multibase,
        },
        self_signing_key: SubordinateSignedKey {
            kid: NonEmptyString::new(format!("{principal}#self-signing")).unwrap(),
            alg: NonEmptyString::new("EdDSA").unwrap(),
            public_key: NonEmptyString::new(self_signing_public_key).unwrap(),
            key_format: KeyFormat::Multibase,
            binding: SubordinateSignedKeyBinding {
                verification_method: NonEmptyString::new(format!("{principal}#principal-signing"))
                    .unwrap(),
                alg: NonEmptyString::new("EdDSA").unwrap(),
                signature: NonEmptyString::new(format!("psk-sig-ssk-gen-{generation}")).unwrap(),
            },
        },
        user_signing_key: SubordinateSignedKey {
            kid: NonEmptyString::new(format!("{principal}#user-signing")).unwrap(),
            alg: NonEmptyString::new("EdDSA").unwrap(),
            public_key: NonEmptyString::new("z6MkUserAlice").unwrap(),
            key_format: KeyFormat::Multibase,
            binding: SubordinateSignedKeyBinding {
                verification_method: NonEmptyString::new(format!("{principal}#principal-signing"))
                    .unwrap(),
                alg: NonEmptyString::new("EdDSA").unwrap(),
                signature: NonEmptyString::new(format!("psk-sig-usk-gen-{generation}")).unwrap(),
            },
        },
        expected_previous_generation: generation.saturating_sub(1),
        generation: std::num::NonZeroU64::new(generation).unwrap(),
        issued_at: Utc::now(),
    }
}

fn seed_cross_signing_generation(state: &AppState, principal: &str, generation: u64) {
    for current in 1..=generation {
        state
            .test_record_cross_signing_publish(cross_signing_publish(principal, current))
            .unwrap();
    }
}

#[tokio::test]
async fn mls_lifecycle_end_to_end() {
    let state = soland_test_support::app_state(test_config());

    let alice_did = "did:web:alice.example";
    let alice_device = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let alice_token = dev_token(state.clone(), alice_did, alice_device, "Alice").await;
    let event_signing_key = SigningKey::from_bytes(&[21_u8; 32]);
    let mut alice_device_record = state
        .test_persistence()
        .devices()
        .get(alice_did, alice_device)
        .await
        .unwrap()
        .unwrap();
    alice_device_record.payload["device_public_key"] =
        json!(ed25519_public_multibase(&event_signing_key));
    alice_device_record.verification_state = "verified".to_owned();
    state
        .test_persistence()
        .devices()
        .put(&alice_device_record)
        .await
        .unwrap();
    seed_cross_signing_generation(&state, alice_did, 3);
    let realm_id = "ak:realm:01904100-0000-7000-8000-00000000e2ee";

    // ── 1. upload a KeyPackage (W1C: ak.self.keys.keypackages.upload.create) ──
    let keypackage_id = "ak:mls_keypackage:t-01";
    let keypackage_id_mismatch = "ak:mls_keypackage:t-02";
    let uploaded_keypackage_ref = "ak:mls:keypackage:test-01";
    let mismatch_keypackage_ref = "ak:mls:keypackage:test-02";
    let keypackage_bytes = b"opaque-mls-keypackage";
    let mismatch_keypackage_bytes = b"opaque-mls-keypackage-mismatch";
    let keypackage_digest = arkret_canonical::sha256_digest(keypackage_bytes);
    let mismatch_keypackage_digest = arkret_canonical::sha256_digest(mismatch_keypackage_bytes);
    let capabilities = json!(["ak.mls.rfc9420", "ak.mls.profile.full"]);
    let capabilities_digest = sha256_json(&capabilities);
    let mismatch_capabilities = json!(["ak.mls.rfc9420"]);
    let publish_unsigned: arkret_models_crypto::KeyPackagesUploadUnsignedRequest =
        serde_json::from_value(json!({
            "principal_id": alice_did,
            "device_id": alice_device,
            "key_packages": [
                {
                    "keypackage_id": keypackage_id,
                    "keypackage_ref": uploaded_keypackage_ref,
                    "keypackage_digest": keypackage_digest.clone(),
                    "key_package": b64(keypackage_bytes),
                    "cipher_suites": ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
                    "capabilities": capabilities.clone(),
                    "expires_at": "2100-01-01T00:00:00.000Z",
                    "created_at": "2026-05-25T00:00:00.000Z"
                },
                {
                    "keypackage_id": keypackage_id_mismatch,
                    "keypackage_ref": mismatch_keypackage_ref,
                    "keypackage_digest": mismatch_keypackage_digest,
                    "key_package": b64(mismatch_keypackage_bytes),
                    "cipher_suites": ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
                    "capabilities": mismatch_capabilities,
                    "expires_at": "2100-01-01T00:00:00.000Z",
                    "created_at": "2026-05-25T00:00:01.000Z"
                }
            ]
        }))
        .unwrap();
    let publish_signature = arkret_signatures::keypackages::sign_keypackages_upload_request(
        &publish_unsigned,
        &format!("{alice_did}#{alice_device}"),
        &[21_u8; 32],
    )
    .unwrap();
    let publish_body = publish_unsigned.into_signed(publish_signature);
    let device_signature = serde_json::to_value(&publish_body.device_signature).unwrap();
    let publish_resp = TestClient::post("http://server/_arkret/self/keys/keypackages/upload")
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .json(&publish_body)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(publish_resp.status_code, Some(StatusCode::OK));
    let mut publish_resp = publish_resp;
    let publish_json: Value = publish_resp.take_json().await.unwrap();
    assert_eq!(publish_json["accepted"], json!(2));
    assert_eq!(
        publish_json["key_package_refs"],
        json!([uploaded_keypackage_ref, mismatch_keypackage_ref])
    );
    assert!(
        state
            .test_persistence()
            .mls_key_packages()
            .get(keypackage_id)
            .await
            .unwrap()
            .is_some(),
        "publish must mirror into the store"
    );
    let published_row = state
        .test_persistence()
        .mls_key_packages()
        .get(keypackage_id)
        .await
        .unwrap()
        .expect("published KeyPackage row");
    assert_eq!(
        published_row.capabilities,
        vec![
            "ak.mls.rfc9420".to_owned(),
            "ak.mls.profile.full".to_owned()
        ]
    );
    assert_eq!(published_row.capabilities_digest, capabilities_digest);
    assert_eq!(published_row.ssk_generation, Some(3));

    // ── 2a. atomic claim wins (W1C: ak.self.keys.keypackages.command.claim) ───
    let claim_url = "http://server/_arkret/self/keys/keypackages/claim".to_owned();
    let claim_resp = TestClient::post(&claim_url)
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .json(&json!({
            "target_principal_id": alice_did,
            "intended_realm_id": realm_id,
            "requester": alice_did,
            "required_capabilities": ["ak.mls.profile.full"],
            "claim_nonce": b64(b"claim-nonce-01"),
            "expires_at": "2100-01-01T00:00:00.000Z",
            "mls_group_id": "ak:mls_group:abc"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(claim_resp.status_code, Some(StatusCode::OK));
    let mut claim_resp = claim_resp;
    let claim_json: Value = claim_resp.take_json().await.unwrap();
    let claims = claim_json["claims"].as_array().expect("claims array");
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0]["keypackage_ref"], json!(uploaded_keypackage_ref));
    assert_eq!(claims[0]["keypackage_digest"], json!(keypackage_digest));
    assert_eq!(claims[0]["capabilities"], capabilities);
    assert_eq!(claims[0]["capabilities_digest"], json!(capabilities_digest));
    assert_eq!(claims[0]["ssk_generation"], json!(3));
    assert_eq!(claims[0]["device_signature"], device_signature);
    let claim_id = claims[0]["claim_id"].as_str().unwrap().to_owned();
    let claimed_keypackage_ref = claims[0]["keypackage_ref"].as_str().unwrap().to_owned();
    let claimed_keypackage_digest = claims[0]["keypackage_digest"].as_str().unwrap().to_owned();
    let claimed_capabilities_digest = claims[0]["capabilities_digest"]
        .as_str()
        .unwrap()
        .to_owned();

    // ── 2b. a new request cannot re-claim the package for the same group ─
    let same_group_claim_resp = TestClient::post(&claim_url)
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .json(&json!({
            "target_principal_id": alice_did,
            "intended_realm_id": realm_id,
            "requester": alice_did,
            "required_capabilities": ["ak.mls.profile.full"],
            "claim_nonce": b64(b"claim-nonce-same-group"),
            "expires_at": "2100-01-01T00:00:00.000Z",
            "mls_group_id": "ak:mls_group:abc"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(same_group_claim_resp.status_code, Some(StatusCode::OK));
    let mut same_group_claim_resp = same_group_claim_resp;
    let same_group_claim_json: Value = same_group_claim_resp.take_json().await.unwrap();
    assert!(
        same_group_claim_json["claims"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        same_group_claim_json["failures"][0]["reason_code"],
        json!("claim_failed")
    );

    // ── 2c. another group cannot claim the same package ─
    let rejected_claim_resp = TestClient::post(&claim_url)
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .json(&json!({
            "target_principal_id": alice_did,
            "intended_realm_id": realm_id,
            "requester": alice_did,
            "required_capabilities": ["ak.mls.profile.full"],
            "claim_nonce": b64(b"claim-nonce-02"),
            "expires_at": "2100-01-01T00:00:00.000Z",
            "mls_group_id": "ak:mls_group:second"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(rejected_claim_resp.status_code, Some(StatusCode::OK));
    let mut rejected_claim_resp = rejected_claim_resp;
    let rejected_claim_json: Value = rejected_claim_resp.take_json().await.unwrap();
    assert!(rejected_claim_json["claims"].as_array().unwrap().is_empty());
    assert_eq!(
        rejected_claim_json["failures"][0]["reason_code"],
        json!("claim_failed")
    );

    let bob_did = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-b0b0e0000001";
    let bob_token = dev_token(state.clone(), bob_did, bob_device, "Bob").await;
    let group_id = "ak:mls_group:abc";
    let effective_scope = json!({"kind": "realm", "realm_id": realm_id});
    let frontier_ref = "ak:event:01904100-0000-7000-8000-00000000f00d";
    let keypackage_ref = claimed_keypackage_ref;
    let welcome_ref =
        "ak:blob:sha256:8888888888888888888888888888888888888888888888888888888888888888";
    let governance_binding = json!({
        "binding_version": 1,
        "encoding_profile": "cbor-deterministic-rfc8949-v1",
        "realm_id": realm_id,
        "effective_scope": effective_scope.clone(),
        "mls_group_id": group_id,
        "previous_epoch": 0,
        "next_epoch": 0,
        "membership_frontier": [frontier_ref],
        "policy_root": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "capability_root": "sha256:5555555555555555555555555555555555555555555555555555555555555555",
        "discussion_metadata_digest": "sha256:6666666666666666666666666666666666666666666666666666666666666666",
        "binding_profile": soland_domain::kinds::MLS_GOVERNANCE_BINDING_FULL_PROFILE,
        "reducer_profile": soland_domain::kinds::MLS_REDUCER_PROFILE_V1
    });

    // ── 3a. Realm + MLS group genesis enter through canonical events ─
    let mut realm_create = signed_event(
        "ak:event:01904100-0000-7000-8000-00000000e2e0",
        0,
        alice_did,
        alice_device,
        realm_id,
        "ak.realm.create",
        json!({
            "object": {
                "id": realm_id,
                "schema": "ak.schema.realm.v1",
                "title": "MLS lifecycle",
                "created_by": alice_did,
                "trust_domain": "ak:trust_domain:soland-mls-test.local",
                "schema_refs": ["ak.schema.realm.v1"],
                "default_discoverability": "listed",
                "default_join_rule": "invite",
                "history_visibility": "joined",
                "encryption_profile": "mls_rfc9420",
                "security_class": "standard",
                "federation_policy": "restricted",
                "notary_profile": "single_did",
                "digest_algorithm": "sha256",
                "notary": {
                    "kind": "single_did",
                    "did": alice_did,
                    "recovery_members": ["did:web:recovery.example"],
                    "controller_organization": "did:web:organization.primary.example",
                    "recovery_controller_organizations": ["did:web:organization.recovery.example"]
                },
                "created_at": "2026-05-25T00:00:00.000Z"
            }
        }),
    );
    set_realm_create_effects(&mut realm_create);
    let grant_id = "ak:grant:01904100-0000-7000-8000-00000000e2ef";
    let grant_created_at = realm_create["created_at"].as_str().unwrap();
    let mut grant: arkret_models_collaboration::governance::grant_constraint::CapabilityGrant = serde_json::from_value(json!({
        "id": grant_id,
        "schema": "ak.schema.capability.v1",
        "realm_id": realm_id,
        "issuer": alice_did,
        "subject": alice_did,
        "actions": [
            "ak.realm.admin",
            "ak.capability.grant",
            "ak.capability.revoke",
            "ak.realm_key.share"
        ],
        "capability_action_registry_digest": arkret_policy::current_capability_action_registry_digest().unwrap(),
        "resources": [{
            "kind": "realm",
            "realm_id": realm_id,
            "match_scope": "realm_wide"
        }],
        "issued_at": grant_created_at,
        "proofs": []
    }))
    .unwrap();
    let mut grant_proof = arkret_wire::PayloadProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: format!("{alice_did}#{alice_device}"),
        payload_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
            .unwrap(),
        created_at: chrono::DateTime::parse_from_rfc3339(grant_created_at)
            .unwrap()
            .with_timezone(&Utc),
        domain: None,
        audience: None,
        proof_purpose: Some(arkret_wire::PayloadProofPurpose::IssuerAttestation),
        jws: "pending".to_owned(),
    };
    grant_proof.payload_digest = grant.payload_digest().unwrap();
    grant_proof.jws = arkret_signatures::jws::sign_jws_ed25519(
        &grant.canonical_proof_binding_bytes(&grant_proof).unwrap(),
        &event_signing_key,
    )
    .unwrap();
    grant.proofs.push(grant_proof);
    let mut founding_grant = signed_event(
        "ak:event:01904100-0000-7000-8000-00000000e2ef",
        1,
        alice_did,
        alice_device,
        realm_id,
        arkret_wire::events::EventKind::CAPABILITY_GRANT,
        json!({"grant_id": grant_id, "grant": grant}),
    );
    set_event_prev_refs(
        &mut founding_grant,
        &[realm_create["event_id"].as_str().unwrap()],
    );
    let mut create_resp = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .json(&json!({"events": [realm_create, founding_grant]}))
        .send(&app_from_state(state.clone()))
        .await;
    let create_status = create_resp.status_code;
    if create_status != Some(StatusCode::OK) {
        let error: Value = create_resp.take_json().await.unwrap_or(Value::Null);
        panic!("Realm create failed with {create_status:?}: {error}");
    }

    let mut genesis = signed_event(
        "ak:event:01904100-0000-7000-8000-00000000e2e1",
        2,
        alice_did,
        alice_device,
        realm_id,
        "ak.mls.genesis",
        json!({
            "mls_group_id": group_id,
            "effective_scope": effective_scope.clone(),
            "epoch": 0,
            "creator_principal_id": alice_did,
            "creator_device_id": alice_device,
            "cipher_suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            "group_info_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            "ratchet_tree_digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
            "governance_binding": governance_binding,
            "created_at": "2026-05-25T00:00:01.000Z"
        }),
    );
    set_event_prev_refs(
        &mut genesis,
        &["ak:event:01904100-0000-7000-8000-00000000e2ef"],
    );
    let genesis_resp = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .json(&genesis)
        .send(&app_from_state(state.clone()))
        .await;
    let genesis_status = genesis_resp.status_code;
    if genesis_status != Some(StatusCode::OK) {
        let mut genesis_resp = genesis_resp;
        let error: Value = genesis_resp.take_json().await.unwrap_or(Value::Null);
        panic!("MLS Genesis failed with {genesis_status:?}: {error}");
    }
    assert_eq!(
        state
            .test_persistence()
            .mls_commits()
            .get(&effective_scope, group_id)
            .await
            .unwrap()
            .expect("genesis persisted")
            .epoch,
        0
    );

    // ── 3b. Welcome is a durable event and mirrors into the pending queue ─
    let mut claim_envelope = json!({
        "keypackage_ref": keypackage_ref,
        "keypackage_digest": claimed_keypackage_digest,
        "intended_realm_id": realm_id,
        "claim_id": claim_id,
        "requester_did": alice_did,
        "ssk_generation": 3,
        "nonce": b64(b"welcome-claim-nonce-01-128-bit"),
        "welcome_digest": arkret_canonical::sha256_digest(b"opaque-mls-welcome"),
        "created_at": "2026-05-25T00:00:02.000Z",
        "signature": {
            "kid": format!("{alice_did}#self-signing"),
            "alg": "EdDSA",
            "sig": b64(&[0_u8; 64])
        }
    });
    let claim_envelope_model: MlsWelcomeClaimEnvelope =
        serde_json::from_value(claim_envelope.clone()).unwrap();
    let claim_envelope_signature = sign_b64(
        &test_ssk_signing_key(),
        &claim_envelope_model.canonical_signing_bytes().unwrap(),
    );
    claim_envelope["signature"]["sig"] = json!(claim_envelope_signature);

    let mut welcome = signed_event(
        "ak:event:01904100-0000-7000-8000-00000000e2e2",
        3,
        alice_did,
        alice_device,
        realm_id,
        "ak.mls.welcome",
        json!({
            "mls_group_id": group_id,
            "epoch": 1,
            "recipient_principal_id": bob_did,
            "recipient_device_id": bob_device,
            "keypackage_ref": keypackage_ref,
            "keypackage_digest": claimed_keypackage_digest,
            "claim_id": claim_id,
            "claim_ref": {
                "claim_id": claim_id,
                "keypackage_ref": keypackage_ref,
                "keypackage_digest": claimed_keypackage_digest,
                "capabilities_digest": claimed_capabilities_digest,
                "ssk_generation": 3
            },
            "claim_envelope": claim_envelope,
            "welcome_ref": welcome_ref,
            "ciphertext": b64(b"opaque-mls-welcome"),
            "expires_at": "2100-01-01T00:00:00.000Z",
            "commit_ref": "ak:event:01904100-0000-7000-8000-00000000e2e3",
            "governance_binding": governance_binding
        }),
    );
    set_event_prev_refs(
        &mut welcome,
        &["ak:event:01904100-0000-7000-8000-00000000e2e1"],
    );
    let mut welcome_resp = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .json(&welcome)
        .send(&app_from_state(state.clone()))
        .await;
    let welcome_status = welcome_resp.status_code;
    if welcome_status != Some(StatusCode::OK) {
        let error: Value = welcome_resp.take_json().await.unwrap_or(Value::Null);
        panic!("expected welcome status 200, got {welcome_status:?}: {error}");
    }
    assert_eq!(
        state
            .test_persistence()
            .mls_welcomes()
            .snapshot_all()
            .await
            .unwrap()
            .len(),
        1
    );

    // ── 3c. Canonical commit event advances the durable epoch row ─
    let commit_binding = json!({
        "binding_version": 1,
        "encoding_profile": "cbor-deterministic-rfc8949-v1",
        "realm_id": realm_id,
        "effective_scope": effective_scope.clone(),
        "mls_group_id": group_id,
        "previous_epoch": 0,
        "next_epoch": 1,
        "membership_frontier": [frontier_ref],
        "policy_root": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "capability_root": "sha256:5555555555555555555555555555555555555555555555555555555555555555",
        "discussion_metadata_digest": "sha256:6666666666666666666666666666666666666666666666666666666666666666",
        "binding_profile": soland_domain::kinds::MLS_GOVERNANCE_BINDING_FULL_PROFILE,
        "reducer_profile": soland_domain::kinds::MLS_REDUCER_PROFILE_V1
    });
    let mut commit = signed_event(
        "ak:event:01904100-0000-7000-8000-00000000e2e3",
        4,
        alice_did,
        alice_device,
        realm_id,
        "ak.mls.commit",
        json!({
            "mls_group_id": group_id,
            "base_epoch": 0,
            "base_epoch_ref": "ak:event:01904100-0000-7000-8000-00000000e2e1",
            "proposal_refs": [],
            "next_epoch": 1,
            "commit_digest": "sha256:7777777777777777777777777777777777777777777777777777777777777777",
            "governance_binding": commit_binding
        }),
    );
    set_event_prev_refs(
        &mut commit,
        &["ak:event:01904100-0000-7000-8000-00000000e2e2"],
    );
    let commit_resp = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .json(&commit)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(commit_resp.status_code, Some(StatusCode::OK));
    assert_eq!(
        state
            .test_persistence()
            .mls_commits()
            .get(&effective_scope, group_id)
            .await
            .unwrap()
            .expect("commit persisted")
            .epoch,
        1
    );

    // ── 4. Bob sees the Welcome on the standard to-device queue ─
    let device_messages_resp = TestClient::get("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {bob_token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(device_messages_resp.status_code, Some(StatusCode::OK));
    let mut device_messages_resp = device_messages_resp;
    let device_messages_json: Value = device_messages_resp.take_json().await.unwrap();
    let device_messages = device_messages_json["messages"]
        .as_array()
        .expect("device messages array");
    assert_eq!(device_messages.len(), 1, "{device_messages_json}");
    let device_message = &device_messages[0];
    assert_eq!(device_message["kind"], json!("ak.mls.welcome"));
    assert_eq!(device_message["sender_device_id"], json!(alice_device));
    assert_eq!(device_message["recipient_principal_id"], json!(bob_did));
    assert_eq!(device_message["recipient_device_id"], json!(bob_device));
    assert_eq!(
        device_message["expires_at"],
        json!("2100-01-01T00:00:00.000Z")
    );
    assert_eq!(device_message["content"]["mls_group_id"], json!(group_id));
    assert_eq!(device_message["content"]["epoch"], json!(1));
    assert_eq!(
        device_message["content"]["recipient_principal_id"],
        json!(bob_did)
    );
    assert_eq!(
        device_message["content"]["recipient_device_id"],
        json!(bob_device)
    );
    assert_eq!(
        device_message["content"]["ciphertext"],
        json!(URL_SAFE_NO_PAD.encode(b"opaque-mls-welcome"))
    );
    assert_eq!(
        device_message["content"]["governance_binding"],
        governance_binding
    );
    assert_eq!(
        device_message["content"]["claim_ref"]["claim_id"],
        json!(claim_id)
    );
    assert_eq!(
        device_message["content"]["claim_envelope"]["welcome_digest"],
        json!(arkret_canonical::sha256_digest(b"opaque-mls-welcome"))
    );
    assert_eq!(
        device_message["content"]["commit_ref"],
        json!("ak:event:01904100-0000-7000-8000-00000000e2e3")
    );
    assert_eq!(
        device_message["unsigned"]["mls_welcome_id"],
        json!(welcome_ref)
    );

    // ── 5. MLS commits no longer have a dedicated REST surface ──
    // The dedicated `POST /_arkret/self/mls/commits` endpoint was removed in
    // W1C; clients now submit `ak.mls.commit` events via the canonical
    // `POST /_arkret/self/events` pipeline (ak.self.events.command.submit of the registered
    // durable `ak.mls.commit` kind). The reducer-level epoch-bump path is
    // covered by unit tests in `reducer::mls`. We deliberately do not
    // re-exercise it here from the HTTP layer.
}
