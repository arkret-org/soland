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
const LOCAL_EVENT_CRITICAL_FEATURES: [&str; 3] = [
    "ak.event_envelope.v1",
    "ak.profile.core_event_store.v1",
    "ak.proof.event_digest.v1",
];

pub(crate) fn canonical_json_hash(value: &Value) -> String {
    canonical::canonical_sha256(value).unwrap_or_else(|_| {
        let bytes = serde_json::to_vec(value).unwrap_or_default();
        arkret_sdk::canonical::sha256_digest(&bytes)
    })
}

fn event_digest_suite(
    state: &AppState,
    kind: &str,
    realm_id: &str,
    object: &serde_json::Map<String, Value>,
) -> Result<String, EventValidationError> {
    let suite = if kind == arkret_sdk::events::kinds::REALM_CREATE {
        realm_create_digest_algorithm(object)
    } else {
        state.projection.lock().realm_digest_algorithm(realm_id)
    }
    .unwrap_or_else(|| "sha256".to_owned());
    arkret_sdk::canonical::digest_suite(&suite)
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
    arkret_sdk::canonical::canonical_digest_with_suite(bytes, suite)
        .map_err(|_| unsupported_digest_algorithm_error(suite))
}

fn unsupported_digest_algorithm_error(suite: &str) -> EventValidationError {
    let code = arkret_sdk::ErrorCode::UnsupportedDigestAlgorithm;
    event_validation_error(
        error_http_status(code),
        code.as_str(),
        format!("unsupported digest algorithm: {suite}"),
    )
}

pub(crate) fn preflight_mls_projection_reject(
    proj: &crate::reducer::ProjectionState,
    operation: &Operation,
) -> Option<String> {
    let kind = kinds::canonical_kind_string(operation);
    match kind.as_str() {
        arkret_sdk::events::kinds::MLS_KEYPACKAGE
        | arkret_sdk::events::kinds::MLS_WELCOME
        | arkret_sdk::events::kinds::MLS_GENESIS
        | arkret_sdk::events::kinds::MLS_PROPOSAL
        | arkret_sdk::events::kinds::MLS_COMMIT => {
            let mut snapshot = proj.clone();
            let effect = match kind.as_str() {
                arkret_sdk::events::kinds::MLS_KEYPACKAGE => {
                    match operation.payload.get("action").and_then(Value::as_str) {
                        Some("publish") => {
                            crate::reducer::mls::apply_keypackage_publish(&mut snapshot, operation)
                        }
                        Some("claim") => {
                            crate::reducer::mls::apply_keypackage_claim(&mut snapshot, operation)
                        }
                        Some(other) => crate::reducer::ProjectionEffect::Rejected {
                            reason: format!("mls_keypackage_action_unknown:{other}"),
                        },
                        None => crate::reducer::ProjectionEffect::Rejected {
                            reason: "mls_keypackage_action_missing".to_owned(),
                        },
                    }
                }
                arkret_sdk::events::kinds::MLS_WELCOME => {
                    crate::reducer::mls::apply_welcome_enqueue(&mut snapshot, operation)
                }
                arkret_sdk::events::kinds::MLS_GENESIS => {
                    crate::reducer::mls::apply_group_genesis(&mut snapshot, operation)
                }
                arkret_sdk::events::kinds::MLS_PROPOSAL => {
                    crate::reducer::mls::apply_remove_proposal(&mut snapshot, operation)
                }
                arkret_sdk::events::kinds::MLS_COMMIT => {
                    crate::reducer::mls::apply_commit_epoch(&mut snapshot, operation)
                }
                _ => crate::reducer::ProjectionEffect::Ignored,
            };
            match effect {
                crate::reducer::ProjectionEffect::Rejected { reason } => Some(reason),
                _ => None,
            }
        }
        _ => None,
    }
}

/// P2 — surface the moderation reducer's §5.5.2 fail-closed rejections at
/// ingest, mirroring [`preflight_mls_projection_reject`]. Runs the moderation
/// reducer against a clone of the live projection so the
/// separation-of-duties / overturn↔lift / modify↔new-decision constraints
/// reject the event with the canonical reason_code BEFORE it is committed.
///
/// The clone sees the same already-applied cells as the real apply will —
/// within an ordered submit batch the paired `ck.moderation.decision.lift` /
/// new `ck.moderation.decision` were applied to the live projection by their
/// own earlier `submit_event_value` calls, so the cell already reflects them.
pub(crate) fn preflight_moderation_projection_reject(
    proj: &crate::reducer::ProjectionState,
    operation: &Operation,
    hlc: &crate::hlc::ServerHlc,
) -> Option<String> {
    let kind = kinds::canonical_kind_string(operation);
    let is_moderation = matches!(
        kind.as_str(),
        arkret_sdk::events::kinds::MODERATION_DECISION
            | arkret_sdk::events::kinds::MODERATION_DECISION_LIFT
            | arkret_sdk::events::kinds::MODERATION_APPEAL_SUBMIT
            | arkret_sdk::events::kinds::MODERATION_APPEAL_REVIEW
            | arkret_sdk::events::kinds::MODERATION_APPEAL_DECISION
            | arkret_sdk::events::kinds::MODERATION_APPEAL_CLOSE
    );
    if !is_moderation {
        return None;
    }
    let mut snapshot = proj.clone();
    match snapshot.apply(operation, hlc) {
        crate::reducer::ProjectionEffect::Rejected { reason } => Some(reason),
        _ => None,
    }
}

pub(crate) fn preflight_invite_projection_reject(
    _state: &AppState,
    proj: &crate::reducer::ProjectionState,
    operation: &Operation,
    hlc: &crate::hlc::ServerHlc,
) -> Option<String> {
    let kind = kinds::canonical_kind_string(operation);
    if !matches!(
        kind.as_str(),
        arkret_sdk::events::kinds::INVITE_THIRD_PARTY | arkret_sdk::events::kinds::INVITE_CLAIM
    ) {
        return None;
    }
    let mut snapshot = proj.clone();
    match snapshot.apply(operation, hlc) {
        crate::reducer::ProjectionEffect::Rejected { reason } => Some(reason),
        _ => None,
    }
}

pub(crate) fn preflight_calendar_projection_reject(
    proj: &crate::reducer::ProjectionState,
    operation: &Operation,
    hlc: &crate::hlc::ServerHlc,
) -> Option<String> {
    let kind = kinds::canonical_kind_string(operation);
    if !matches!(
        kind.as_str(),
        arkret_sdk::events::kinds::STRAND_CREATE
            | arkret_sdk::events::kinds::STRAND_UPDATE
            | arkret_sdk::events::kinds::RSVP_SET
    ) {
        return None;
    }
    let mut snapshot = proj.clone();
    match snapshot.apply(operation, hlc) {
        crate::reducer::ProjectionEffect::Rejected { reason } => Some(reason),
        _ => None,
    }
}

pub(crate) fn preflight_capability_projection_reject(
    proj: &crate::reducer::ProjectionState,
    operation: &Operation,
    hlc: &crate::hlc::ServerHlc,
) -> Option<String> {
    let kind = kinds::canonical_kind_string(operation);
    if !matches!(
        kind.as_str(),
        arkret_sdk::events::kinds::CAPABILITY_GRANT
            | arkret_sdk::events::kinds::CAPABILITY_REVOKE
            | arkret_sdk::events::kinds::CAPABILITY_DELEGATE
    ) {
        return None;
    }
    let mut snapshot = proj.clone();
    match snapshot.apply(operation, hlc) {
        crate::reducer::ProjectionEffect::Rejected { reason } => Some(reason),
        _ => None,
    }
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
mod capability_refs;
mod control_move;
mod envelope_core;
mod features_schema;
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
            "effects": [{"cell": "ak:cell:x", "op": {"type": "set", "value": 1}}],
        })
        .as_object()
        .unwrap()
        .clone()
    }

    #[test]
    fn realm_history_sharing_policy_is_a_bootstrap_followup() {
        // Regression: inkson's restricted-history bootstrap emits a
        // ck.realm.history_sharing_policy Control Move in the same ordered
        // batch (no Seal exists yet, so it carries no seal_basis). soland
        // MUST accept it as a genesis followup alongside the other realm.*
        // policy moves, else the whole create batch is `status=partial`.
        assert!(is_realm_bootstrap_followup_kind(
            arkret_sdk::events::kinds::REALM_HISTORY_SHARING_POLICY
        ));
        let obj =
            control_move_with_effects(arkret_sdk::events::kinds::REALM_HISTORY_SHARING_POLICY);
        // As a recognized bootstrap followup it passes without seal_basis…
        validate_control_move_seal_basis(&obj, true).unwrap();
        // …but a non-bootstrap effects-bearing Control Move still requires it.
        let err = validate_control_move_seal_basis(&obj, false).unwrap_err();
        assert!(format!("{err:?}").contains("seal_basis.leaves"));
    }
}
