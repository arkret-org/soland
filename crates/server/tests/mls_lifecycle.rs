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

use arkret_identifiers::RealmId;
use arkret_models_collaboration::events_payloads::MlsWelcomeClaimEnvelope;
use arkret_wire::{CORE_REDUCER_PROFILE, ProfileId};
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
use soland_test_support::signed_event::{CallerSignedEvent, complete_realm_bootstrap_unit};

fn test_config() -> AppConfig {
    AppConfig {
        object_storage: ObjectStorageConfig::local(std::env::temp_dir().join("soland-mls-blobs")),
        development_mode: true,
        did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: BTreeMap::new(),
        trust_domain: arkret_identifiers::TrustDomainId::new(
            "ak:trust_domain:soland-mls-test.local",
        )
        .unwrap(),
        ..soland_test_support::app_config()
    }
}

fn app_from_state(state: AppState) -> salvo::Service {
    service(state)
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
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

#[expect(
    clippy::too_many_arguments,
    reason = "the helper mirrors the complete self KeyPackage claim transcript"
)]
fn signed_keypackage_claim_request(
    authority_service_id: &str,
    requester: &str,
    requester_device: &str,
    requester_device_authorize_event_id: &str,
    target_principal_id: &str,
    target_device_ids: &[&str],
    intended_realm_id: &str,
    required_capabilities: &[&str],
    claim_random: &[u8],
    expires_at: chrono::DateTime<Utc>,
    mls_group_id: &str,
) -> arkret_models_crypto::KeyPackagesClaimRequestBody {
    assert!(
        claim_random.len() >= 16,
        "self KeyPackage claim request id must carry at least 128 bits"
    );
    let created_at = Utc::now();
    let requester_full = arkret_identifiers::DidFullId::new(requester.to_owned()).unwrap();
    let requester_id = arkret_wire::project_full_id_to_core_id(&requester_full).unwrap();
    let target_full = arkret_identifiers::DidFullId::new(target_principal_id.to_owned()).unwrap();
    let target_principal_id = arkret_wire::project_full_id_to_core_id(&target_full).unwrap();
    let verification_method = format!("{}#{requester_device}", requester_full.as_str());
    let claim_request_id = b64(claim_random);
    let mut body: arkret_models_crypto::KeyPackagesClaimRequestBody =
        serde_json::from_value(json!({
            "claim_request_id": claim_request_id,
            "target_principal_id": target_principal_id,
            "target_device_ids": target_device_ids,
            "intended_realm_id": intended_realm_id,
            "requester": requester_id,
            "claim_purpose": "realm_membership",
            "required_capabilities": required_capabilities,
            "expires_at": arkret_canonical::format_timestamp_canonical(expires_at),
            "mls_group_id": mls_group_id,
            "service_binding": {
                "source_service_id": authority_service_id,
                "destination_service_id": authority_service_id
            },
            "requester_authorization": {
                "kind": "device",
                "verification_method": verification_method,
                "requester_device_id": requester_device,
                "device_authorize_event_id": requester_device_authorize_event_id,
                "signed_at": arkret_canonical::format_timestamp_canonical(created_at),
                "signature": {
                    "kid": verification_method,
                    "signature_algorithm": "Ed25519",
                    "sig": "AA"
                }
            }
        }))
        .expect("typed self KeyPackage claim request");
    let binding = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
        &body.unsigned_request(),
        &body.service_binding,
        &body.requester_authorization,
    )
    .expect("claim authorization transcript");
    let arkret_models_crypto::PeerKeyPackageRequesterAuthorization::Device { signature, .. } =
        &mut body.requester_authorization
    else {
        unreachable!("fixture constructs device authorization")
    };
    signature.sig = arkret_wire::Base64UrlString::new(sign_b64(
        &SigningKey::from_bytes(&[21_u8; 32]),
        &binding,
    ))
    .expect("claim authorization signature");
    assert_eq!(
        body.claim_purpose,
        arkret_models_crypto::PeerKeyPackageClaimPurpose::RealmMembership
    );
    body.validate_shape()
        .expect("fixture KeyPackage claim shape");
    body
}

fn install_routable_member(state: &AppState, realm_id: &str, member: &arkret_wire::DidCoreId) {
    let now = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(Utc::now().timestamp_millis())
        .unwrap();
    state.test_projection().lock().members.insert(
        (realm_id.to_owned(), member.to_string()),
        soland_domain::reducer::SolandMembershipState {
            member: member.to_string(),
            realm_id: realm_id.to_owned(),
            state: "join".to_owned(),
            role: "member".to_owned(),
            delivery_status: Some("routable".to_owned()),
            recipient_service_id: Some(state.service_id().to_owned()),
            recipient_service_resolution: None,
            membership_event_ref: None,
            delivery_binding_frontier: None,
            delivery_binding_expires_at: None,
            invited_at: None,
            joined_at: now,
            updated_at: now,
            reason: None,
        },
    );
}

/// The Realm's accepted Seal frontier — the registered sourcing for a
/// single-leaf Control Move `seal_basis` (`events.rs::events_frontier`).
///
/// This suite bootstraps its Realm through `ak.realm.create` +
/// `ak.capability.grant`, so the Seal every MLS Control Move here cites is the
/// Realm's real accepted governance Seal, read back from the server.
async fn realm_seal_frontier(
    state: AppState,
    token: &str,
    realm_id: &str,
) -> arkret_models_collaboration::event_sync::RealmSealFrontierView {
    for attempt in 0..50 {
        let mut response = TestClient::query("http://server/_arkret/self/seals/frontier")
            .json(&serde_json::json!({"realm_id": realm_id}))
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await;
        let status = response.status_code;
        let body: Value = response.take_json().await.unwrap_or(Value::Null);
        if status == Some(StatusCode::OK) {
            let frontier: arkret_models_collaboration::event_sync::SealFrontierState =
                serde_json::from_value(body).expect("typed Realm Seal frontier");
            return frontier.frontier;
        }
        assert_eq!(
            status,
            Some(StatusCode::SERVICE_UNAVAILABLE),
            "Realm Seal frontier failed with {status:?}: {body}"
        );
        assert!(
            attempt < 49,
            "Realm Seal frontier remained unavailable: {body}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    unreachable!("bounded Realm Seal frontier retry returns or panics")
}

#[expect(
    clippy::too_many_arguments,
    reason = "the fixture mirrors the complete canonical event envelope"
)]
fn signed_event(
    _event_id: &str,
    actor_seq: u64,
    actor: &str,
    device_id: &str,
    realm_id: &str,
    kind: impl AsRef<str>,
    payload: Value,
    seal_basis: Option<arkret_wire::SealBasis>,
) -> Value {
    let now = Utc::now();
    let actor_full_id = arkret_identifiers::DidFullId::new(actor.to_owned()).unwrap();
    let verification_method =
        arkret_wire::DidUrl::new(format!("{}#{device_id}", actor_full_id.as_str()))
            .expect("fixture verification method is a DID URL");
    let mut event = arkret_wire::test_support::raw_event_at(
        kind.as_ref(),
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(realm_id.to_owned()).unwrap(),
        },
        arkret_wire::project_full_id_to_core_id(&actor_full_id).unwrap(),
        soland_test_support::fixture_principal_server_id(),
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
    event.seal_basis = seal_basis;
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        [21_u8; 32],
        actor_full_id,
        verification_method.clone(),
    );
    let mut event = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .expect("fixture envelope finalizes");
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(now),
    )
    .unwrap();
    let event = event.into_event();
    serde_json::to_value(event).unwrap()
}

fn set_event_prev_refs(event: &mut Value, prev_refs: &[&str]) {
    let verification_method = arkret_wire::DidUrl::new(
        event["proofs"][0]["verification_method"]
            .as_str()
            .unwrap()
            .to_owned(),
    )
    .expect("fixture verification method is a DID URL");
    let mut typed: arkret_wire::Event = serde_json::from_value(event.clone()).unwrap();
    typed.prev_refs = prev_refs
        .iter()
        .map(|event_id| arkret_wire::EventId::new((*event_id).to_owned()).unwrap())
        .collect();
    typed.proofs.clear();
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        [21_u8; 32],
        arkret_identity::verification_method_did(verification_method.as_str()).unwrap(),
        verification_method.clone(),
    );
    let created_at = typed.created_at;
    let mut typed = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        typed,
        arkret_canonical::DigestSuite::Sha256,
    )
    .expect("fixture envelope finalizes");
    arkret_signatures::sign_event(
        &mut typed,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(created_at),
    )
    .unwrap();
    let typed = typed.into_event();
    *event = serde_json::to_value(typed).unwrap();
}

async fn dev_token(state: AppState, actor: &str, device_id: &str, display: &str) -> String {
    let actor_core = arkret_wire::project_full_id_to_core_id(
        &arkret_identifiers::DidFullId::new(actor.to_owned()).expect("fixture actor full DID"),
    )
    .expect("fixture actor core id");
    let login: Value = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&json!({
            "actor": actor_core,
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

async fn project_authorized_principal_device(
    state: &AppState,
    principal_full_id: &str,
    device_id: &str,
    signing_key: &SigningKey,
) -> String {
    let principal_full = arkret_identifiers::DidFullId::new(principal_full_id.to_owned()).unwrap();
    let principal_id = arkret_wire::project_full_id_to_core_id(&principal_full).unwrap();
    let principal_server_id =
        arkret_identifiers::DidCoreId::new(state.service_id().to_owned()).unwrap();
    let pcr_realm_id = arkret_identifiers::RealmId::new(
        soland_test_support::fixture_principal_control_realm(principal_full_id),
    )
    .unwrap();
    soland_test_support::cba_basis::seed_realm_genesis_event(
        state,
        pcr_realm_id.as_str(),
        principal_full_id,
    )
    .await;
    let genesis_record = state
        .test_persistence()
        .events()
        .realm_events_newest_first(pcr_realm_id.as_str())
        .await
        .unwrap()
        .into_iter()
        .find(|record| record.kind == arkret_wire::EventKind::RealmCreate.as_str())
        .expect("PCR genesis Event");
    let genesis: arkret_wire::Event = serde_json::from_value(genesis_record.envelope).unwrap();
    let now = Utc::now();
    let mut authorize = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::DeviceAuthorize.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: pcr_realm_id.clone(),
        },
        principal_id.clone(),
        principal_server_id.clone(),
        1,
        arkret_identifiers::Hlc::new("019041000000-0000-00000001".to_owned()).unwrap(),
        json!({
            "principal_id": principal_id,
            "device_id": device_id,
            "device_public_key": ed25519_public_multibase(signing_key),
            "hpke_key": "z6LSTestAuthorizedDeviceHpkeKey",
            "algorithms": ["ak.hpke_x25519_aead_chacha20poly1305.v1", "ak.mls.v1"],
            "authorized_by": principal_id,
            "not_before": "2026-05-25T00:00:00.000Z",
            "authorization_binding_kind": "registration_anchor",
            "device_signature": "c2ln"
        }),
        now,
    )
    .unwrap();
    authorize.prev_refs = vec![genesis.event_id.clone()];
    authorize
        .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    let operation = arkret_event_draft::ProjectedEventOperation::from_accepted_event(
        arkret_identifiers::OperationId::new(arkret_identifiers::new_prefixed_uuid7(
            "ak:operation:",
        ))
        .unwrap(),
        arkret_wire::OperationKind::Create,
        None,
        &authorize,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let authorize_event_id = authorize.event_id.to_string();
    state
        .test_persistence()
        .events()
        .put(soland_test_support::signed_event::canonical_event_record(
            &authorize,
            Some(pcr_realm_id.as_str()),
            now,
        ))
        .await
        .unwrap();
    let authority_key =
        arkret_wire::PrincipalAuthorityKey::new(principal_id.clone(), principal_server_id);
    if state
        .test_persistence()
        .principal_resolutions()
        .by_authority_key(&authority_key)
        .await
        .unwrap()
        .is_none()
    {
        let applied = state
            .test_persistence()
            .principal_resolutions()
            .compare_and_set(
                None,
                soland_storage::PrincipalResolutionRecord {
                    authority_key,
                    pcr_realm_id: pcr_realm_id.clone(),
                    genesis_event: genesis.clone(),
                    current_event: genesis.clone(),
                    projection: arkret_models_identity::PrincipalResolutionProjection {
                        full_id: principal_full,
                        method_history_head: format!("sha256:{}", "1".repeat(64)),
                        version_id: "1-QmMlsLifecycleAuthority".to_owned(),
                        resolution_event_ref: genesis.event_id.to_string(),
                        updated_at: genesis.created_at,
                    },
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            applied,
            soland_storage::PrincipalResolutionCasResult::Applied(_)
        ));
    }
    soland_test_support::project_accepted_operations(state, principal_id.as_str(), &[operation])
        .await;
    authorize_event_id
}

#[test]
fn mls_lifecycle_end_to_end() {
    let joined = std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build MLS lifecycle test runtime")
                .block_on(mls_lifecycle_end_to_end_body());
        })
        .expect("spawn MLS lifecycle test thread")
        .join();
    if let Err(payload) = joined {
        std::panic::resume_unwind(payload);
    }
}

async fn mls_lifecycle_end_to_end_body() {
    let state = soland_test_support::app_state(test_config());
    let _control_seal_coordinator = soland_http::control_seal_coordinator::spawn(state.clone());

    let alice_did = "did:web:alice.example";
    let alice_device = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let alice_token = dev_token(state.clone(), alice_did, alice_device, "Alice").await;
    let alice_core = arkret_wire::project_full_id_to_core_id(
        &arkret_identifiers::DidFullId::new(alice_did).unwrap(),
    )
    .unwrap();
    let event_signing_key = SigningKey::from_bytes(&[21_u8; 32]);
    let alice_device_authorize_event_id =
        project_authorized_principal_device(&state, alice_did, alice_device, &event_signing_key)
            .await;
    let realm_genesis = CallerSignedEvent::realm_genesis(
        alice_did,
        alice_device,
        soland_test_support::cba_basis::realm_genesis_payload(
            &state,
            alice_did,
            "MLS lifecycle",
            "ak:trust_domain:soland-mls-test.local",
            Utc::now(),
        ),
    )
    .build();
    let realm_id_owned = RealmId::from_event_id(&realm_genesis.event_id).to_string();
    let realm_id = realm_id_owned.as_str();
    let group_id_owned = arkret_wire::ScopeRef::Realm {
        realm_id: RealmId::new(realm_id.to_owned()).unwrap(),
    }
    .canonical_mls_group_id()
    .unwrap();
    let group_id = group_id_owned.as_str();
    let realm_bootstrap =
        complete_realm_bootstrap_unit(realm_genesis, alice_did, alice_device, "MLS lifecycle");
    let bootstrap_frontier_event_id = realm_bootstrap
        .last()
        .expect("complete Realm bootstrap")
        .event_id
        .to_string();

    // ── 0. the Realm has to exist before anything cites it ──────────────
    //
    // `peer_claim_policy_authorized`'s `RealmMembership` branch requires both
    // requester and target to be a joined member (or the owner) of
    // `intended_realm_id`. A KeyPackage claim naming a Realm the projection has
    // never seen is not a claim into that Realm, so the bootstrap unit is
    // submitted first rather than after the claim.
    let mut create_resp = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .add_header("content-type", "application/json", true)
        .body(
            arkret_canonical::canonical_json_bytes(&json!({
                "events": realm_bootstrap
                    .iter()
                    .cloned()
                    .map(arkret_wire::EventInitialSubmission::online)
                    .collect::<Vec<_>>()
            }))
            .unwrap(),
        )
        .send(&app_from_state(state.clone()))
        .await;
    let create_status = create_resp.status_code;
    if create_status != Some(StatusCode::OK) {
        let error: Value = create_resp.take_json().await.unwrap_or(Value::Null);
        panic!("Realm create failed with {create_status:?}: {error}");
    }
    install_routable_member(&state, realm_id, &alice_core);

    // ── 1. upload a KeyPackage (W1C: ak.self.keys.keypackages.upload.create) ──
    let alice_mls_identity = arkret_mls::ArkretMlsIdentity::new_human_device(
        alice_core.clone(),
        arkret_wire::DeviceId::new(alice_device.to_owned()).unwrap(),
        // The accepted human-device identity key signs the upload batch and
        // the RFC 9420 LeafNode under the same v1 endpoint authority.
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(event_signing_key.clone()),
    )
    .unwrap();
    let keypackage_record = alice_mls_identity.key_package_record().unwrap();
    let keypackage_id = keypackage_record.keypackage_id.clone();
    let uploaded_keypackage_ref = keypackage_record.keypackage_ref.to_string();
    let capabilities = json!(keypackage_record.capabilities);
    let capabilities_digest = sha256_json(&capabilities);
    let valid_entry =
        arkret_models_crypto::mls_key_package_record_upload_entry(&keypackage_record).unwrap();
    let mut mismatched_capabilities_entry = valid_entry.clone();
    mismatched_capabilities_entry.keypackage_id =
        "keypackage-capability-binding-mismatch".to_owned();
    mismatched_capabilities_entry.capabilities = vec!["ak.content.v1".to_owned()];
    let mismatched_capabilities_id = mismatched_capabilities_entry.keypackage_id.clone();
    let mut noncanonical_capabilities_entry = valid_entry.clone();
    noncanonical_capabilities_entry.keypackage_id =
        "keypackage-capability-order-invalid".to_owned();
    noncanonical_capabilities_entry.capabilities.reverse();
    let noncanonical_capabilities_id = noncanonical_capabilities_entry.keypackage_id.clone();
    let publish_unsigned = arkret_models_crypto::KeyPackagesUploadUnsignedRequest {
        principal_id: alice_core.clone(),
        device_id: Some(arkret_wire::DeviceId::new(alice_device.to_owned()).unwrap()),
        pairwise_verification_method: None,
        intended_realm_id: None,
        agent_verification_method: None,
        agent_key_authorize_event_id: None,
        keypackages: vec![
            valid_entry,
            mismatched_capabilities_entry,
            noncanonical_capabilities_entry,
        ],
        expires_at: None,
        strand_id: None,
        mls_group_id: None,
    };
    let publish_signature = arkret_signatures::keypackages::sign_keypackages_upload_request(
        &publish_unsigned,
        &format!("{alice_did}#{alice_device}"),
        &[21_u8; 32],
    )
    .unwrap();
    let publish_body = publish_unsigned.into_signed(publish_signature);
    let mut publish_resp = TestClient::post("http://server/_arkret/self/keys/keypackages/upload")
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .add_header("content-type", "application/json", true)
        .body(
            arkret_canonical::canonical_json_bytes(&publish_body)
                .expect("canonical key-package upload body"),
        )
        .send(&app_from_state(state.clone()))
        .await;
    let publish_status = publish_resp.status_code;
    let publish_body = publish_resp.take_string().await.unwrap();
    assert_eq!(publish_status, Some(StatusCode::OK), "{publish_body}");
    let publish_json: Value = serde_json::from_str(&publish_body).unwrap();
    assert_eq!(publish_json["accepted"], json!(1));
    assert_eq!(
        publish_json["keypackage_refs"],
        json!([uploaded_keypackage_ref])
    );
    let rejected = publish_json["rejected"]
        .as_array()
        .expect("invalid capability projections must be rejected");
    assert_eq!(rejected.len(), 2);
    assert!(rejected.iter().any(|failure| {
        failure["reason_code"] == json!("keypackage_capabilities_signed_binding_invalid")
    }));
    assert!(
        rejected
            .iter()
            .any(|failure| failure["reason_code"] == json!("capabilities_invalid"))
    );
    assert!(
        state
            .test_persistence()
            .mls_key_packages()
            .get(&keypackage_id)
            .await
            .unwrap()
            .is_some(),
        "publish must mirror into the store"
    );
    for rejected_id in [mismatched_capabilities_id, noncanonical_capabilities_id] {
        assert!(
            state
                .test_persistence()
                .mls_key_packages()
                .get(&rejected_id)
                .await
                .unwrap()
                .is_none(),
            "rejected capability projection must not be persisted"
        );
    }
    let published_row = state
        .test_persistence()
        .mls_key_packages()
        .get(&keypackage_id)
        .await
        .unwrap()
        .expect("published KeyPackage row");
    assert_eq!(
        published_row.capabilities,
        vec!["ak.content.v1".to_owned(), "mimi.content.v1".to_owned()]
    );
    assert_eq!(published_row.capabilities_digest, capabilities_digest);
    assert_eq!(
        published_row.device_authorize_event_id.as_deref(),
        Some(alice_device_authorize_event_id.as_str())
    );

    // ── 2a. atomic claim wins (W1C: ak.self.keys.keypackages.command.claim) ───
    let claim_url = "http://server/_arkret/self/keys/keypackages/claim".to_owned();
    let claim_expires_at = Utc::now() + chrono::Duration::minutes(4);
    let initial_claim = signed_keypackage_claim_request(
        state.service_id(),
        alice_did,
        alice_device,
        &alice_device_authorize_event_id,
        alice_did,
        &[alice_device],
        realm_id,
        &["ak.content.v1"],
        b"claim-nonce-01-unique",
        claim_expires_at,
        group_id,
    );
    let claim_resp = TestClient::post(&claim_url)
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .add_header("content-type", "application/json", true)
        .body(arkret_canonical::canonical_json_bytes(&initial_claim).unwrap())
        .send(&app_from_state(state.clone()))
        .await;
    let mut claim_resp = claim_resp;
    let claim_json: Value = claim_resp.take_json().await.unwrap();
    assert_eq!(
        claim_resp.status_code,
        Some(StatusCode::OK),
        "initial KeyPackage claim failed: {claim_json}"
    );
    let claims = claim_json["claims"].as_array().expect("claims array");
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0]["keypackage_ref"], json!(uploaded_keypackage_ref));
    assert_eq!(claims[0]["capabilities"], capabilities);
    assert!(claims[0].get("keypackage_digest").is_none());
    assert!(claims[0].get("capabilities_digest").is_none());
    assert_eq!(
        claims[0]["device_authorize_event_id"],
        json!(alice_device_authorize_event_id)
    );
    assert!(claims[0].get("endpoint_signature").is_none());
    // ── 2b. a new request cannot re-claim the package for the same group ─
    let same_group_claim = signed_keypackage_claim_request(
        state.service_id(),
        alice_did,
        alice_device,
        &alice_device_authorize_event_id,
        alice_did,
        &[alice_device],
        realm_id,
        &["ak.content.v1"],
        b"claim-nonce-same-group",
        claim_expires_at,
        group_id,
    );
    let same_group_claim_resp = TestClient::post(&claim_url)
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .add_header("content-type", "application/json", true)
        .body(arkret_canonical::canonical_json_bytes(&same_group_claim).unwrap())
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        same_group_claim_resp.status_code,
        Some(StatusCode::BAD_REQUEST)
    );
    let mut same_group_claim_resp = same_group_claim_resp;
    let same_group_claim_json: Value = same_group_claim_resp.take_json().await.unwrap();
    assert_eq!(
        same_group_claim_json["error"]["code"],
        json!("claim_failed")
    );

    let bob_did = "did:web:bob.example";
    let bob_core = arkret_wire::project_full_id_to_core_id(
        &arkret_identifiers::DidFullId::new(bob_did).unwrap(),
    )
    .unwrap();
    let bob_device = "ak:device:01904100-0000-7000-8000-b0b0e0000001";
    let bob_token = dev_token(state.clone(), bob_did, bob_device, "Bob").await;
    project_authorized_principal_device(&state, bob_did, bob_device, &event_signing_key).await;

    // `peer_claim_policy_authorized`'s `RealmMembership` branch requires the
    // claim target to already be a joined Realm member. Realm membership
    // (`ak.member.state`) and MLS group membership are separate: Bob joins the
    // Realm first, and only then can Alice claim his KeyPackage to add him to
    // the MLS group.
    install_routable_member(&state, realm_id, &bob_core);

    let bob_mls_identity = arkret_mls::ArkretMlsIdentity::new_human_device(
        bob_core.clone(),
        arkret_wire::DeviceId::new(bob_device.to_owned()).unwrap(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(event_signing_key.clone()),
    )
    .unwrap();
    let lifecycle_keypackage_record = bob_mls_identity.key_package_record().unwrap();
    let lifecycle_keypackage_id = lifecycle_keypackage_record.keypackage_id.clone();
    let lifecycle_keypackage_ref = lifecycle_keypackage_record.keypackage_ref.to_string();
    let lifecycle_claim_expires_at = Utc::now() + chrono::Duration::minutes(4);
    let lifecycle_capabilities = json!(lifecycle_keypackage_record.capabilities);
    let lifecycle_capabilities_digest = sha256_json(&lifecycle_capabilities);
    let lifecycle_publish_unsigned = arkret_models_crypto::KeyPackagesUploadUnsignedRequest {
        principal_id: bob_core.clone(),
        device_id: Some(arkret_wire::DeviceId::new(bob_device.to_owned()).unwrap()),
        pairwise_verification_method: None,
        intended_realm_id: None,
        agent_verification_method: None,
        agent_key_authorize_event_id: None,
        keypackages: vec![
            arkret_models_crypto::mls_key_package_record_upload_entry(&lifecycle_keypackage_record)
                .unwrap(),
        ],
        expires_at: None,
        strand_id: None,
        mls_group_id: None,
    };
    let lifecycle_publish_signature =
        arkret_signatures::keypackages::sign_keypackages_upload_request(
            &lifecycle_publish_unsigned,
            &format!("{bob_did}#{bob_device}"),
            &[21_u8; 32],
        )
        .unwrap();
    let lifecycle_publish_body =
        lifecycle_publish_unsigned.into_signed(lifecycle_publish_signature);
    let lifecycle_publish_resp =
        TestClient::post("http://server/_arkret/self/keys/keypackages/upload")
            .add_header("authorization", format!("Bearer {bob_token}"), true)
            .add_header("content-type", "application/json", true)
            .body(
                arkret_canonical::canonical_json_bytes(&lifecycle_publish_body)
                    .expect("canonical key-package upload body"),
            )
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(lifecycle_publish_resp.status_code, Some(StatusCode::OK));

    let lifecycle_claim_body = signed_keypackage_claim_request(
        state.service_id(),
        alice_did,
        alice_device,
        &alice_device_authorize_event_id,
        bob_did,
        &[bob_device],
        realm_id,
        &["ak.content.v1"],
        b"lifecycle-claim-nonce-01",
        lifecycle_claim_expires_at,
        group_id,
    );
    let mut lifecycle_claim_resp = TestClient::post(&claim_url)
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .add_header("content-type", "application/json", true)
        .body(arkret_canonical::canonical_json_bytes(&lifecycle_claim_body).unwrap())
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(lifecycle_claim_resp.status_code, Some(StatusCode::OK));
    let lifecycle_claim: Value = lifecycle_claim_resp.take_json().await.unwrap();
    assert_eq!(
        lifecycle_claim["claims"][0]["keypackage_ref"],
        json!(lifecycle_keypackage_ref)
    );
    assert_eq!(
        lifecycle_claim["claims"][0]["capabilities"],
        lifecycle_capabilities
    );
    assert!(
        lifecycle_claim["claims"][0]
            .get("keypackage_digest")
            .is_none()
    );
    assert!(
        lifecycle_claim["claims"][0]
            .get("capabilities_digest")
            .is_none()
    );
    assert_eq!(
        state
            .test_persistence()
            .mls_key_packages()
            .get(&lifecycle_keypackage_id)
            .await
            .unwrap()
            .expect("claimed lifecycle KeyPackage remains durable")
            .claimed_by_mls_group_id
            .as_deref(),
        Some(group_id)
    );
    // `mls_welcome_payload.claim_receipt` is required and is the
    // destination-signed receipt for *this* Welcome's claim — Bob's, from the
    // lifecycle claim below, not Alice's own self-claim above.
    let lifecycle_claim_receipt = lifecycle_claim["claim_receipt"].clone();
    let claim_id = lifecycle_claim["claims"][0]["claim_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let claimed_keypackage_ref = lifecycle_claim["claims"][0]["keypackage_ref"]
        .as_str()
        .unwrap()
        .to_owned();
    let claimed_keypackage_bytes = URL_SAFE_NO_PAD
        .decode(
            lifecycle_claim["claims"][0]["keypackage"]
                .as_str()
                .unwrap()
                .trim_end_matches('='),
        )
        .unwrap();
    let claimed_keypackage_digest = arkret_canonical::sha256_digest(&claimed_keypackage_bytes);
    let claimed_capabilities_digest = sha256_json(&lifecycle_claim["claims"][0]["capabilities"]);
    assert_eq!(claimed_capabilities_digest, lifecycle_capabilities_digest);
    let claimed_device_authorize_event_id =
        lifecycle_claim["claims"][0]["device_authorize_event_id"]
            .as_str()
            .unwrap()
            .to_owned();

    let effective_scope = json!({"kind": "realm", "realm_id": realm_id});
    let keypackage_ref = claimed_keypackage_ref;
    // The bootstrapped Realm now has an accepted governance Seal. Every MLS
    // Control Move below cites it as its independent Event-admission
    // `seal_basis`. The MLS binding carries only the unique security frontier.
    let realm_seal = realm_seal_frontier(state.clone(), &alice_token, realm_id).await;
    let realm_seal_basis = realm_seal.seal_basis();
    let governance_binding = json!({
        "binding_version": 1,
        "encoding_profile": "cbor-deterministic-rfc8949-v1",
        "realm_id": realm_id,
        "effective_scope": effective_scope.clone(),
        "mls_group_id": group_id,
        "previous_epoch": 0,
        "next_epoch": 0,
        "security_frontier_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "content_scheme": "mls_rfc9420",
        "binding_profile": ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
        "reducer_profile": CORE_REDUCER_PROFILE
    });

    let mut genesis = signed_event(
        "ak:event:AV_PzlO4KFPCRZ8atMU31wQSdrwGcjtOZpgIu9c_gs1o",
        8,
        alice_did,
        alice_device,
        realm_id,
        "ak.mls.genesis",
        json!({
            "mls_group_id": group_id,
            "effective_scope": effective_scope.clone(),
            "epoch": 0,
            "cipher_suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            "group_info_ref": "ak:blob:sha256:3333333333333333333333333333333333333333333333333333333333333333",
            "group_info_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            "ratchet_tree_ref": "ak:blob:sha256:4444444444444444444444444444444444444444444444444444444444444444",
            "ratchet_tree_digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
            "governance_binding": governance_binding,
            "created_at": "2026-05-25T00:00:01.000Z"
        }),
        Some(realm_seal_basis.clone()),
    );
    set_event_prev_refs(&mut genesis, &[bootstrap_frontier_event_id.as_str()]);
    let mls_genesis_event_id = genesis["event_id"].as_str().unwrap().to_owned();
    let genesis_resp = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .add_header("content-type", "application/json", true)
        .body(arkret_canonical::canonical_json_bytes(&genesis).unwrap())
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
    let welcome_binding = json!({
        "binding_version": 1,
        "encoding_profile": "cbor-deterministic-rfc8949-v1",
        "realm_id": realm_id,
        "effective_scope": effective_scope.clone(),
        "mls_group_id": group_id,
        "previous_epoch": 0,
        "next_epoch": 1,
        "security_frontier_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "content_scheme": "mls_rfc9420",
        "binding_profile": ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
        "reducer_profile": CORE_REDUCER_PROFILE
    });
    let mut claim_envelope = json!({
        "keypackage_ref": keypackage_ref,
        "keypackage_digest": claimed_keypackage_digest,
        "intended_realm_id": realm_id,
        "claim_id": claim_id,
        "requester_actor_id": alice_core,
        "requester_device_id": alice_device,
        "requester_device_authorize_event_id": alice_device_authorize_event_id,
        "welcome_digest": arkret_canonical::sha256_digest(b"opaque-mls-welcome"),
        "created_at": "2026-05-25T00:00:02.000Z",
        "signature": {
            "kid": format!("{alice_did}#{alice_device}"),
            "signature_algorithm": "Ed25519",
            "sig": b64(&[0_u8; 64])
        }
    });
    let claim_envelope_model: MlsWelcomeClaimEnvelope =
        serde_json::from_value(claim_envelope.clone()).unwrap();
    let claim_receipt_model: arkret_models_crypto::PeerKeyPackageClaimReceipt =
        serde_json::from_value(lifecycle_claim_receipt.clone()).unwrap();
    let claim_envelope_signature = sign_b64(
        &event_signing_key,
        &claim_envelope_model
            .canonical_signing_bytes(&claim_receipt_model)
            .unwrap(),
    );
    claim_envelope["signature"]["sig"] = json!(claim_envelope_signature);

    let mut welcome = signed_event(
        "ak:event:AcRK-D2fBUTneeX_47VmTFFtdaFb9UNQ7_kQE7bDKypP",
        9,
        alice_did,
        alice_device,
        realm_id,
        "ak.mls.welcome",
        json!({
            "mls_group_id": group_id,
            "epoch": 1,
            "recipient_principal_id": bob_core,
            "recipient_device_id": bob_device,
            "keypackage_ref": keypackage_ref,
            "claim_id": claim_id,
            "claim_ref": {
                "claim_id": claim_id,
                "keypackage_ref": keypackage_ref,
                "keypackage_digest": claimed_keypackage_digest,
                "capabilities_digest": claimed_capabilities_digest,
                "device_authorize_event_id": claimed_device_authorize_event_id
            },
            "claim_envelope": claim_envelope,
            "claim_receipt": lifecycle_claim_receipt,
            "ciphertext": b64(b"opaque-mls-welcome"),
            "expires_at": lifecycle_claim_receipt["expires_at"].clone(),
            "commit_ref": "ak:event:AV7r9jE8uOCT8ZEtX3vuk67GOqlz6qBab2XgiJdgkfZr",
            "governance_binding": welcome_binding
        }),
        Some(realm_seal_basis.clone()),
    );
    set_event_prev_refs(&mut welcome, &[mls_genesis_event_id.as_str()]);
    let welcome_event_id = welcome["event_id"].as_str().unwrap().to_owned();
    let mut welcome_resp = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .add_header("content-type", "application/json", true)
        .body(arkret_canonical::canonical_json_bytes(&welcome).unwrap())
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
        "security_frontier_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "content_scheme": "mls_rfc9420",
        "binding_profile": ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
        "reducer_profile": CORE_REDUCER_PROFILE
    });
    let commit_bytes = b"opaque-mls-commit";
    let mut commit = signed_event(
        "ak:event:AV7r9jE8uOCT8ZEtX3vuk67GOqlz6qBab2XgiJdgkfZr",
        10,
        alice_did,
        alice_device,
        realm_id,
        "ak.mls.commit",
        json!({
            "mls_group_id": group_id,
            "base_epoch": 0,
            "base_epoch_ref": mls_genesis_event_id,
            "proposal_refs": [],
            "next_epoch": 1,
            "commit_bytes_b64": b64(commit_bytes),
            "commit_digest": arkret_canonical::sha256_digest(commit_bytes),
            "governance_binding": commit_binding
        }),
        Some(realm_seal_basis),
    );
    set_event_prev_refs(&mut commit, &[welcome_event_id.as_str()]);
    let commit_resp = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .add_header("content-type", "application/json", true)
        .body(arkret_canonical::canonical_json_bytes(&commit).unwrap())
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
    assert_eq!(device_message["recipient_principal_id"], json!(bob_core));
    assert_eq!(device_message["recipient_device_id"], json!(bob_device));
    assert_eq!(
        device_message["expires_at"],
        lifecycle_claim_receipt["expires_at"]
    );
    assert_eq!(device_message["content"]["mls_group_id"], json!(group_id));
    assert_eq!(device_message["content"]["epoch"], json!(1));
    assert_eq!(
        device_message["content"]["recipient_principal_id"],
        json!(bob_core)
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
        welcome_binding
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
        json!("ak:event:AV7r9jE8uOCT8ZEtX3vuk67GOqlz6qBab2XgiJdgkfZr")
    );
    assert_eq!(
        device_message["unsigned"]["mls_welcome_id"],
        json!(welcome_event_id)
    );

    // ── 5. MLS commits no longer have a dedicated REST surface ──
    // The dedicated `POST /_arkret/self/mls/commits` endpoint was removed in
    // W1C; clients now submit `ak.mls.commit` events via the canonical
    // `POST /_arkret/self/events` pipeline (ak.self.events.command.submit of the registered
    // durable `ak.mls.commit` kind). The reducer-level epoch-bump path is
    // covered by unit tests in `reducer::mls`. We deliberately do not
    // re-exercise it here from the HTTP layer.
}
