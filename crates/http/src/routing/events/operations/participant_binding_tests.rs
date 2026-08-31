use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_identifiers::CellRef;
use arkret_models_collaboration::events_payloads::call::ParticipantBinding;
use arkret_models_collaboration::objects::media::CallMediaParticipantBinding;
use arkret_state::lattice::CellState;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::Signer as _;
use serde_json::{Value, json};
use soland_storage_postgres::Db;

use super::*;

const REALM_ID: &str = "ak:realm:AWBLVNs9HeoGO5lSMOgHAujzyX_u-d_6wfDWF_3lEM2J";
const CALL_ID: &str = "ak:call:Aa5NVuAPR6HTlIsZAgPhBnb3iRqz7fRvyOkiCWbdOaLa";
const FOCUS_ID: &str = "arkret_native_green";
const ACTOR_ID: &str = "ak:did_core:webvh:z6mkalice";
const DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-a11ce0000001";
const ISSUER_KID: &str = "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service#media-2026-06";
const PARTICIPANT_ID: &str = "ak:rtc_participant:01904100-0000-7000-8000-aaaaaaaaaaaa";

fn participant_actor(principal: &str) -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(principal).unwrap(),
        crate::test_event::station_id(),
    ))
}

fn test_config() -> crate::config::AppConfig {
    crate::config::AppConfig {
        object_storage: crate::config::ObjectStorageConfig::local(
            std::env::temp_dir().join("soland-participant-binding-crypto-test-blobs"),
        ),
        development_mode: true,
        did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: std::collections::BTreeMap::new(),
        notary_signing_key_seed: Some([7u8; 32]),
        ..crate::config::AppConfig::test_default()
    }
}

/// Install a current-epoch media_service cell anchoring `issuer_kid` under
/// `service_id`.
fn install_media_service_with_service_id(state: &AppState, service_id: &str, issuer_kid: &str) {
    let cell_id = CellRef::new(arkret_wire::null_subject_cell(
        arkret_wire::CellFamilyId::REALM_MEDIA_SERVICE_V1,
    ))
    .unwrap();
    state
        .test_projection()
        .lock()
        .realm_null_subject_cells
        .insert(
            (REALM_ID.to_owned(), cell_id.as_str().to_owned()),
            CellState::Value(json!({
                "service_id": service_id,
                "foci": [{
                    "focus_id": FOCUS_ID,
                    "backend": "arkret_native",
                    "issuer_kid": issuer_kid,
                    "connect_url": "wss://media.soland.local/native"
                }]
            })),
        );
}

/// Install a current-epoch media_service cell anchoring `issuer_kid` under
/// the soland self service_id (the arkret_native self-signed deployment).
fn install_media_service(state: &AppState, issuer_kid: &str) {
    install_media_service_with_service_id(
        state,
        "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service",
        issuer_kid,
    );
}

/// Mint a self-signed binding through the shared issuer helper so the bytes
/// are byte-symmetric with the verifier. `media-service-binding.md` §3: the
/// signature covers ONLY the seven authoritative fields; the wire binding
/// additionally carries the unsigned `scheme` / `issuer_kid` / `issued_at`
/// metadata.
fn signed_binding(state: &AppState, expires_at: &str) -> Value {
    let issued_at = "2026-06-15T00:00:00.000Z";
    let mut value = json!({
        "scheme": ParticipantBinding::SCHEMA,
        "issuer_kid": ISSUER_KID,
        "realm_id": REALM_ID,
        "call_id": CALL_ID,
        "focus_id": FOCUS_ID,
        "actor_id": participant_actor(ACTOR_ID),
        "device_id": DEVICE_ID,
        "participant_id": PARTICIPANT_ID,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "sig": "",
    });
    let binding: CallMediaParticipantBinding = serde_json::from_value(value.clone()).unwrap();
    let signing_input =
        arkret_signatures::media::participant_binding_signing_input(&binding).unwrap();
    let signing_key = state.notary_signing_key();
    value["sig"] = json!(URL_SAFE_NO_PAD.encode(signing_key.sign(&signing_input).to_bytes()));
    value
}

fn call_state_op(binding: Value) -> Operation {
    let mut op = arkret_event_draft::test_support::raw_projected_operation(
        arkret_identifiers::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
            .unwrap(),
        arkret_identifiers::RealmId::new(REALM_ID.to_owned()).unwrap(),
        arkret_wire::EventKind::CallState.as_str(),
        json!({
            "call_id": CALL_ID,
            "roster_delta": {
                "op": "join",
                "participant": {
                    "actor_id": participant_actor(ACTOR_ID),
                    "device_id": DEVICE_ID,
                    "participant_id": PARTICIPANT_ID,
                    "participant_binding": binding,
                }
            },
        }),
    );
    // Freeze created_at before the binding expiry so the freshness gate
    // passes for the happy-path fixtures.
    op.created_at = "2026-06-15T00:01:00.000Z".parse().unwrap();
    op
}

#[test]
fn legal_self_signed_binding_passes_full_crypto_verification() {
    let state = AppState::new(test_config(), Db { pool: None });
    install_media_service(&state, ISSUER_KID);
    let op = call_state_op(signed_binding(&state, "2026-06-15T00:05:00.000Z"));
    validate_operation_semantics(&state, std::slice::from_ref(&op))
        .expect("valid full-Actor participant binding");
}

#[test]
fn tampered_tuple_field_is_rejected_participant_binding_invalid() {
    let state = AppState::new(test_config(), Db { pool: None });
    install_media_service(&state, ISSUER_KID);
    let mut binding = signed_binding(&state, "2026-06-15T00:05:00.000Z");
    // Flip the signed actor_id without re-signing → signature no longer
    // covers these bytes.
    binding["actor_id"] = json!(participant_actor("ak:did_core:webvh:z6mkmallory"));
    let mut op = call_state_op(binding);
    // Keep the participant entry consistent with the tampered binding so the
    // mismatch is caught by the signature, not the field cross-check.
    op.payload["roster_delta"]["participant"]["actor_id"] =
        json!(participant_actor("ak:did_core:webvh:z6mkmallory"));
    let err = validate_operation_semantics(&state, std::slice::from_ref(&op)).unwrap_err();
    assert!(
        err.starts_with("participant_binding_invalid"),
        "expected participant_binding_invalid, got {err}"
    );
}

#[test]
fn same_principal_at_another_station_does_not_match_participant_binding() {
    let state = AppState::new(test_config(), Db { pool: None });
    install_media_service(&state, ISSUER_KID);
    let mut op = call_state_op(signed_binding(&state, "2026-06-15T00:05:00.000Z"));
    op.payload["roster_delta"]["participant"]["actor_id"] =
        json!(arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(ACTOR_ID).unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        )));
    let error = validate_operation_semantics(&state, &[op]).unwrap_err();
    assert!(error.starts_with("participant_binding_invalid"));
}

#[test]
fn binding_field_mismatch_with_participant_entry_is_rejected() {
    let state = AppState::new(test_config(), Db { pool: None });
    install_media_service(&state, ISSUER_KID);
    let mut op = call_state_op(signed_binding(&state, "2026-06-15T00:05:00.000Z"));
    // The participant entry's device_id diverges from the signed binding.
    op.payload["roster_delta"]["participant"]["device_id"] =
        json!("ak:device:01904100-0000-7000-8000-d1ffffffffff");
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
    // prefix admits
    // `did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service#
    // media-2026-06`.
    install_media_service_with_service_id(
        &state,
        "ak:did_core:webvh:z6mkother",
        "did:webvh:z6mkother:other.example#media-1",
    );
    let op = call_state_op(signed_binding(&state, "2026-06-15T00:05:00.000Z"));
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
    let op = call_state_op(signed_binding(&state, "2026-06-15T00:05:00.000Z"));
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
    let mut binding = signed_binding(&state, "2026-06-15T00:05:00.000Z");
    binding["sig"] = json!(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
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
    // expires_at is before the event created_at (2026-06-15T00:01:00.000Z).
    let op = call_state_op(signed_binding(&state, "2026-06-15T00:00:30.000Z"));
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
    let state = AppState::new(test_config(), Db { pool: None });
    let binding: CallMediaParticipantBinding =
        serde_json::from_value(signed_binding(&state, "2026-06-15T00:05:00.000Z")).unwrap();
    let actual = arkret_signatures::media::participant_binding_signing_input(&binding).unwrap();

    let mut expected = Vec::new();
    expected.extend_from_slice(ParticipantBinding::SCHEMA.as_bytes());
    expected.push(0);
    // canonical-json is key-sorted (alphabetical) over the seven fields only.
    let actor_json = participant_actor(ACTOR_ID).to_string();
    let expected_json = format!(
        "{{\"actor_id\":{actor_json},\"call_id\":\"{CALL_ID}\",\
         \"device_id\":\"{DEVICE_ID}\",\"expires_at\":\"2026-06-15T00:05:00.000Z\",\
         \"focus_id\":\"{FOCUS_ID}\",\"participant_id\":\"{PARTICIPANT_ID}\",\
         \"realm_id\":\"{REALM_ID}\"}}"
    );
    expected.extend_from_slice(expected_json.as_bytes());
    assert_eq!(actual, expected, "signing input must match spec §3 layout");
    // The label is the verbatim scheme value, no private domain prefix.
    assert!(actual.starts_with(b"ak.media.participant_binding.v1\0"));
}

#[test]
fn signing_input_layout_and_unsigned_metadata() {
    signing_input_matches_spec_construction();

    // Mutating an unsigned metadata field (`issued_at`) leaves the binding
    // verifiable: the signature only covers the seven authoritative fields.
    let state = AppState::new(test_config(), Db { pool: None });
    install_media_service(&state, ISSUER_KID);
    let mut binding = signed_binding(&state, "2026-06-15T00:05:00.000Z");
    binding["issued_at"] = json!("2000-01-01T00:00:00.000Z");
    let op = call_state_op(binding);
    assert!(
        validate_operation_semantics(&state, std::slice::from_ref(&op)).is_ok(),
        "mutating unsigned metadata must not break the binding signature"
    );
}
