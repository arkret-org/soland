use super::super::*;
use super::audit::{validate_audit_accessed_payload, validate_strand_watch_audit_pair};
use super::enrollment::validate_device_enrollment_authority_binding;
use super::mls_governance::{
    projected_media_plaintext_service_present, projected_mls_governance_binding_covers_policy_root,
    projected_mls_governance_binding_metadata_digest,
};
use super::payload_shape::{
    validate_conflict_repair_event_payload, validate_event_audience_fields,
    validate_pre_schema_wire_shape, validate_realm_create_policy_constraints,
    validate_space_container_lifecycle_payload,
};

const E2EE_RELAXED_PROFILE: &str = "ak.profile.e2ee_relaxed.v1";
const LOCAL_EVENT_CRITICAL_FEATURES: [&str; 4] = [
    "ak.event_envelope.v1",
    "ak.profile.core_event_store.v1",
    "ak.proof.event_digest.v1",
    arkret_models_collaboration::objects::direct_conversation::DIRECT_CONVERSATION_REALM_ROLE_FEATURE,
];

pub(crate) fn canonical_json_hash(value: &Value) -> Option<String> {
    canonical::canonical_sha256(value).ok()
}

fn event_digest_suite(
    state: &AppState,
    kind: &str,
    realm_id: &str,
    object: &serde_json::Map<String, Value>,
) -> Result<String, EventValidationError> {
    let suite = if kind == arkret_wire::events::EventKind::REALM_CREATE {
        realm_create_digest_algorithm(object)
    } else {
        state
            .projection_application()
            .snapshot()
            .realm_digest_algorithm(realm_id)
    }
    .unwrap_or_else(|| "sha256".to_owned());
    arkret_canonical::digest_suite(&suite)
        .map(|_| suite.clone())
        .map_err(|_| unsupported_digest_algorithm_error(&suite))
}

fn realm_create_digest_algorithm(object: &serde_json::Map<String, Value>) -> Option<String> {
    object
        .get("payload")
        .and_then(|payload| {
            payload
                .get("object")
                .and_then(|object| object.get("digest_algorithm"))
                .or_else(|| payload.get("digest_algorithm"))
        })
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn event_digest_for_suite(bytes: &[u8], suite: &str) -> Result<String, EventValidationError> {
    arkret_canonical::canonical_digest_with_suite(bytes, suite)
        .map_err(|_| unsupported_digest_algorithm_error(suite))
}

fn unsupported_digest_algorithm_error(suite: &str) -> EventValidationError {
    let code = arkret_wire::ErrorCode::UnsupportedDigestAlgorithm;
    event_validation_error(
        error_http_status(code),
        code.as_str(),
        format!("unsupported digest algorithm: {suite}"),
    )
}

fn event_realm_id(object: &serde_json::Map<String, Value>) -> Result<String, EventValidationError> {
    if let Some(realm_id) = event_string_field(object, &["realm_id"]) {
        if RealmId::new(realm_id.clone()).is_err() {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "realm_id must use the ak:realm: typed prefix",
            ));
        }
        return Ok(realm_id.clone());
    }

    Err(event_validation_error(
        StatusCode::BAD_REQUEST,
        "missing_param",
        "realm_id is required",
    ))
}

mod applet;
mod capability_grant_proofs;
mod capability_refs;
mod control_move;
mod envelope_core;
mod features_schema;
mod minimal_metadata_author;
mod proofs;

use applet::*;
pub(in crate::routing::events::event_log) use capability_refs::validate_data_event_capability_refs;
use capability_refs::*;
use control_move::*;
#[cfg(test)]
pub(crate) use envelope_core::validate_event_envelope;
pub(crate) use envelope_core::validate_event_envelope_with_context;
pub(crate) use features_schema::{
    event_requirements_schema_id, validate_event_critical_features,
    validate_event_schema_and_payload, validate_event_time_fields, validate_member_identity_proof,
};
pub(crate) use proofs::validate_event_proofs;

#[cfg(test)]
mod control_move_seal_basis_tests {
    use super::*;

    fn control_move_with_effects(kind: &str) -> serde_json::Map<String, Value> {
        serde_json::json!({
            "kind": kind,
            "effects": [{"cell": "ak:cell:ak.component.test.envelope.v1:x", "op": {"type": "set", "value": 1}}],
        })
        .as_object()
        .unwrap()
        .clone()
    }

    #[test]
    fn realm_history_sharing_policy_is_a_bootstrap_followup() {
        // Regression: inkson's restricted-history bootstrap emits a
        // ak.realm.history_sharing_policy Control Move in the same ordered
        // batch (no Seal exists yet, so it carries no seal_basis). soland
        // MUST accept it as a genesis followup alongside the other realm.*
        // policy moves, else the whole create batch is `status=partial`.
        assert!(is_realm_bootstrap_followup_kind(
            arkret_wire::events::EventKind::REALM_HISTORY_SHARING_POLICY
        ));
        let obj =
            control_move_with_effects(arkret_wire::events::EventKind::REALM_HISTORY_SHARING_POLICY);
        // As a recognized bootstrap followup it passes without seal_basis…
        validate_control_move_seal_basis(&obj, true).unwrap();
        // …but a non-bootstrap effects-bearing Control Move still requires it.
        let err = validate_control_move_seal_basis(&obj, false).unwrap_err();
        assert!(format!("{err:?}").contains("seal_basis.leaves"));
    }
}
