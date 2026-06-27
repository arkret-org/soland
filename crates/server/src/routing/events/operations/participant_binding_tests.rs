use cokret_sdk::lattice::CellState;
use cokret_sdk::{CellRef, Operation};
use serde_json::{Value, json};

use super::*;
use crate::db::Db;
use crate::routing::interop::participant_binding;

const REALM_ID: &str = "ck:realm:01904100-0000-7000-8000-c0ffeec0ffec";
const CALL_ID: &str = "ck:call:01904100-0000-7000-8000-ca11ca11ca11";
const FOCUS_ID: &str = "ck:focus:cokret-native:green";
const ACTOR_ID: &str = "did:web:alice.example";
const DEVICE_ID: &str = "ck:device:01904100-0000-7000-8000-a11ce0000001";
const ISSUER_KID: &str = "did:web:soland.local#media-2026-06";
const PARTICIPANT_IDENTITY: &str = "ck:rtc_participant:01904100-0000-7000-8000-aaaaaaaaaaaa";

fn test_config() -> crate::config::AppConfig {
    crate::config::AppConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        metrics_bind: "127.0.0.1:0".parse().unwrap(),
        public_base_url: "http://server".to_owned(),
        service_did: "did:web:soland.local".to_owned(),
        tls_cert_path: None,
        tls_key_path: None,
        database_url: None,
        object_storage: crate::config::ObjectStorageConfig::local(
            std::env::temp_dir().join("soland-participant-binding-crypto-test-blobs"),
        ),
        ice: crate::config::IceServersConfig::default(),
        livekit: crate::config::LiveKitConfig::default(),
        cors_allow_origin: None,
        account_authority_url: None,
        oidc_client_id: None,
        development_mode: true,
        session_grant_introspection_url: None,
        session_grant_introspection_bearer: None,
        did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
        embedded_webvh_provider_enabled: false,
        embedded_webvh_registration_bearer: None,
        external_webvh_provider_url: None,
        external_webvh_provider_active: false,
        default_webvh_provider_id: None,
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: std::collections::BTreeMap::new(),
        notary_signing_key_seed: Some([7u8; 32]),
        agent_audit_binding_signing_seed: None,
        use_keystore: false,
        federation_policy: crate::config::FederationPolicy::Mesh,
        federation_peers: Vec::new(),
        federation_outbound_enabled: false,
        admin_default_page_limit: 100,
        admin_max_page_limit: 1000,
        admin_principal_dids: Vec::new(),
        to_device_queue_capacity: 10_000,
        push_bridge_cache_ttl_seconds: 900,
        push_bridge_trusted_service_dids: Vec::new(),
        resumable_upload_dir: std::path::PathBuf::from("./soland-resumable-uploads"),
        resumable_upload_incomplete_ttl_seconds: 86_400,
        seal_compaction_min_age_seconds: 604_800,
        compaction_min_witnesses: 1,
        compaction_preserve_genesis: true,
        compaction_prune_only_singleton_successors: true,
        compaction_prune_walk_interval_seconds: 0,
        compaction_prune_walk_per_realm_limit: 50,
        seed_demo_data: false,
        trust_domain: "ck:trust_domain:soland.local".to_owned(),
        receive_policy_constraints: None,
        sovereign_enclave_enabled: false,
        sovereign_enclave_allowed_outbound_hosts: Vec::new(),
        candidate_join_policy_enabled: false,
        erasure_propagation_window_ms: 604_800_000,
        log_format: crate::config::LogFormat::Plain,
    }
}

/// Install a current-epoch media_service cell anchoring `issuer_kid` under
/// `service_id`.
fn install_media_service_with_service_id(state: &AppState, service_id: &str, issuer_kid: &str) {
    let cell_id = CellRef::new(format!(
        "ck:cell:ck.component.realm.media_service.v1:{REALM_ID}"
    ))
    .unwrap();
    state.projection.lock().unwrap().cells.insert(
        cell_id,
        CellState::Value(json!({
            "media_service": {
                "service_id": service_id,
                "foci": [{
                    "focus_id": FOCUS_ID,
                    "backend": "cokret-native",
                    "issuer_kid": issuer_kid,
                    "connect_url": "wss://media.soland.local/native"
                }]
            }
        })),
    );
}

/// Install a current-epoch media_service cell anchoring `issuer_kid` under
/// the soland self service_id (the cokret-native self-signed deployment).
fn install_media_service(state: &AppState, issuer_kid: &str) {
    install_media_service_with_service_id(state, "did:web:soland.local", issuer_kid);
}

/// Mint a self-signed binding through the shared issuer helper so the bytes
/// are byte-symmetric with the verifier. `media-service-binding.md` §3: the
/// signature covers ONLY the seven authoritative fields; the wire binding
/// additionally carries the unsigned `scheme` / `issuer_kid` / `issued_at`
/// metadata.
fn signed_binding(state: &AppState, expires_at: &str) -> Value {
    let issued_at = "2026-06-15T00:00:00Z";
    // Signed value = the seven authoritative fields only.
    let signed = participant_binding::binding_canonical_value(
        &json!(REALM_ID),
        &json!(CALL_ID),
        &json!(FOCUS_ID),
        &json!(ACTOR_ID),
        &json!(DEVICE_ID),
        &json!(PARTICIPANT_IDENTITY),
        &json!(expires_at),
    );
    let signing_key = state.notary_signing_key();
    let sig = participant_binding::sign_binding(&signed, &signing_key);
    json!({
        "scheme": cokret_sdk::PARTICIPANT_BINDING_SCHEMA,
        "issuer_kid": ISSUER_KID,
        "realm_id": REALM_ID,
        "call_id": CALL_ID,
        "focus_id": FOCUS_ID,
        "actor_id": ACTOR_ID,
        "device_id": DEVICE_ID,
        "participant_identity": PARTICIPANT_IDENTITY,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "sig": sig,
    })
}

fn call_state_op(binding: Value) -> Operation {
    let mut op = Operation::create(
        cokret_sdk::OperationId::new(format!("ck:operation:{}", uuid::Uuid::now_v7())).unwrap(),
        cokret_sdk::RealmId::new(REALM_ID.to_owned()).unwrap(),
        cokret_sdk::events::kinds::CALL_STATE,
        json!({
            "call_id": CALL_ID,
            "state": "active",
            "participants": [{
                "actor_id": ACTOR_ID,
                "device_id": DEVICE_ID,
                "participant_identity": PARTICIPANT_IDENTITY,
                "participant_binding": binding,
            }],
        }),
    );
    // Freeze created_at before the binding expiry so the freshness gate
    // passes for the happy-path fixtures.
    op.created_at = "2026-06-15T00:01:00Z".parse().unwrap();
    op
}

#[test]
fn legal_self_signed_binding_passes_full_crypto_verification() {
    let state = AppState::new(test_config(), Db { pool: None });
    install_media_service(&state, ISSUER_KID);
    let op = call_state_op(signed_binding(&state, "2026-06-15T00:05:00Z"));
    assert!(validate_operation_semantics(&state, std::slice::from_ref(&op)).is_ok());
}

#[test]
fn tampered_tuple_field_is_rejected_participant_binding_invalid() {
    let state = AppState::new(test_config(), Db { pool: None });
    install_media_service(&state, ISSUER_KID);
    let mut binding = signed_binding(&state, "2026-06-15T00:05:00Z");
    // Flip the signed actor_id without re-signing → signature no longer
    // covers these bytes.
    binding["actor_id"] = json!("did:web:mallory.example");
    let mut op = call_state_op(binding);
    // Keep the participant entry consistent with the tampered binding so the
    // mismatch is caught by the signature, not the field cross-check.
    op.payload["participants"][0]["actor_id"] = json!("did:web:mallory.example");
    let err = validate_operation_semantics(&state, std::slice::from_ref(&op)).unwrap_err();
    assert!(
        err.starts_with("participant_binding_invalid"),
        "expected participant_binding_invalid, got {err}"
    );
}

#[test]
fn binding_field_mismatch_with_participant_entry_is_rejected() {
    let state = AppState::new(test_config(), Db { pool: None });
    install_media_service(&state, ISSUER_KID);
    let mut op = call_state_op(signed_binding(&state, "2026-06-15T00:05:00Z"));
    // The participant entry's device_id diverges from the signed binding.
    op.payload["participants"][0]["device_id"] =
        json!("ck:device:01904100-0000-7000-8000-d1ffffffffff");
    let err = validate_operation_semantics(&state, std::slice::from_ref(&op)).unwrap_err();
    assert!(
        err.starts_with("participant_binding_invalid"),
        "expected participant_binding_invalid, got {err}"
    );
}

#[test]
fn issuer_not_anchored_in_current_epoch_is_rejected_token_issuer_unauthorised() {
    let state = AppState::new(test_config(), Db { pool: None });
    // Epoch anchors a different service DID + issuer_kid than the binding
    // carries, so neither the focus issuer_kids set nor the service_id
    // prefix admits `did:web:soland.local#media-2026-06`.
    install_media_service_with_service_id(
        &state,
        "did:web:other.example",
        "did:web:other.example#media-1",
    );
    let op = call_state_op(signed_binding(&state, "2026-06-15T00:05:00Z"));
    let err = validate_operation_semantics(&state, std::slice::from_ref(&op)).unwrap_err();
    assert!(
        err.starts_with("token_issuer_unauthorised"),
        "expected token_issuer_unauthorised, got {err}"
    );
}

#[test]
fn missing_media_service_epoch_is_rejected_token_issuer_unauthorised() {
    let state = AppState::new(test_config(), Db { pool: None });
    // No media_service cell installed at all.
    let op = call_state_op(signed_binding(&state, "2026-06-15T00:05:00Z"));
    let err = validate_operation_semantics(&state, std::slice::from_ref(&op)).unwrap_err();
    assert!(
        err.starts_with("token_issuer_unauthorised"),
        "expected token_issuer_unauthorised, got {err}"
    );
}

#[test]
fn corrupt_signature_is_rejected_participant_binding_invalid() {
    let state = AppState::new(test_config(), Db { pool: None });
    install_media_service(&state, ISSUER_KID);
    let mut binding = signed_binding(&state, "2026-06-15T00:05:00Z");
    binding["sig"] = json!(
        "eddsa-ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
    let op = call_state_op(binding);
    let err = validate_operation_semantics(&state, std::slice::from_ref(&op)).unwrap_err();
    assert!(
        err.starts_with("participant_binding_invalid"),
        "expected participant_binding_invalid, got {err}"
    );
}

#[test]
fn expired_binding_is_rejected_participant_binding_invalid() {
    let state = AppState::new(test_config(), Db { pool: None });
    install_media_service(&state, ISSUER_KID);
    // expires_at is before the event created_at (2026-06-15T00:01:00Z).
    let op = call_state_op(signed_binding(&state, "2026-06-15T00:00:30Z"));
    let err = validate_operation_semantics(&state, std::slice::from_ref(&op)).unwrap_err();
    assert!(
        err.starts_with("participant_binding_invalid"),
        "expected participant_binding_invalid, got {err}"
    );
}

/// `media-service-binding.md` §3 — the signing input is exactly
/// `LABEL || 0x00 || canonical_json(7 authoritative fields)`. Mutating an
/// UNSIGNED metadata field (`issued_at`) MUST NOT break the signature
/// (it is not covered), while the byte layout of the signing input MUST
/// match the spec construction verbatim.
fn signing_input_matches_spec_construction() {
    // Build the canonical signing input the spec fixes and assert the
    // module helper produces the identical bytes.
    let signed = participant_binding::binding_canonical_value(
        &json!(REALM_ID),
        &json!(CALL_ID),
        &json!(FOCUS_ID),
        &json!(ACTOR_ID),
        &json!(DEVICE_ID),
        &json!(PARTICIPANT_IDENTITY),
        &json!("2026-06-15T00:05:00Z"),
    );
    let canonical = participant_binding::binding_canonical_bytes(&signed);
    let actual = participant_binding::binding_signing_input(&canonical);

    let mut expected = Vec::new();
    expected.extend_from_slice(cokret_sdk::PARTICIPANT_BINDING_SCHEMA.as_bytes());
    expected.push(0);
    // canonical-json is key-sorted (alphabetical) over the seven fields only.
    let expected_json = format!(
        "{{\"actor_id\":\"{ACTOR_ID}\",\"call_id\":\"{CALL_ID}\",\
         \"device_id\":\"{DEVICE_ID}\",\"expires_at\":\"2026-06-15T00:05:00Z\",\
         \"focus_id\":\"{FOCUS_ID}\",\"participant_identity\":\"{PARTICIPANT_IDENTITY}\",\
         \"realm_id\":\"{REALM_ID}\"}}"
    );
    expected.extend_from_slice(expected_json.as_bytes());
    assert_eq!(actual, expected, "signing input must match spec §3 layout");
    // The label is the verbatim scheme value, no private domain prefix.
    assert!(actual.starts_with(b"ck.media.participant_binding.v1\0"));
}

#[test]
fn signing_input_layout_and_unsigned_metadata() {
    signing_input_matches_spec_construction();

    // Mutating an unsigned metadata field (`issued_at`) leaves the binding
    // verifiable: the signature only covers the seven authoritative fields.
    let state = AppState::new(test_config(), Db { pool: None });
    install_media_service(&state, ISSUER_KID);
    let mut binding = signed_binding(&state, "2026-06-15T00:05:00Z");
    binding["issued_at"] = json!("2000-01-01T00:00:00Z");
    let op = call_state_op(binding);
    assert!(
        validate_operation_semantics(&state, std::slice::from_ref(&op)).is_ok(),
        "mutating unsigned metadata must not break the binding signature"
    );
}
