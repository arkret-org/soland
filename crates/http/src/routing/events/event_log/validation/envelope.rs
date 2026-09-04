use super::super::*;
use super::audit::{validate_audit_accessed_payload, validate_strand_watch_manage_others_levels};
use super::enrollment::validate_device_authorization_binding;
use super::mls_governance::projected_media_plaintext_service_present;
use super::payload_shape::{
    validate_event_audience_fields, validate_pre_schema_wire_shape,
    validate_space_container_lifecycle_payload,
};

const LOCAL_EVENT_CRITICAL_FEATURES: [&str; 4] = [
    arkret_wire::SchemaId::EVENT_V1,
    arkret_wire::ProfileId::CORE_EVENT_STORE_V1,
    arkret_wire::ProofContextId::EVENT_PROOF_V1,
    arkret_models_collaboration::objects::direct_conversation::DIRECT_CONVERSATION_REALM_ROLE_FEATURE,
];

pub(crate) fn canonical_json_hash(value: &Value) -> Option<String> {
    canonical::canonical_sha256(value).ok()
}

pub(super) async fn event_digest_suite(
    state: &AppState,
    kind: &str,
    realm_id: &str,
    _object: &serde_json::Map<String, Value>,
    realm_bootstrap_contexts: &[RealmBootstrapBatchContext],
) -> Result<String, EventValidationError> {
    let suite = if kind == arkret_wire::event_kind_str::REALM_CREATE {
        // The Realm-create bridge is always SHA-256. Its declared suite
        // governs the remaining founding Events and the Genesis Seal.
        "sha256".to_owned()
    } else {
        let projections = state.projections();
        let projected = projections.snapshot().realm_digest_algorithm(realm_id);
        let staged_bootstrap = realm_bootstrap_contexts
            .iter()
            .find(|context| context.realm_id == realm_id)
            .and_then(|context| context.digest_algorithm.clone());
        // A closed Realm bootstrap already carries the signed digest-suite
        // choice in its validated batch context. It has no durable cells yet,
        // so consulting that context must precede the accepted-Seal cache
        // reload. Besides doing needless synchronous storage work, reloading
        // here can wait on the global history-view CAS lock held by another
        // concurrent bootstrap.
        let projected = match projected.or(staged_bootstrap) {
            Some(projected) => Some(projected),
            None => {
                // apply_accepted_seal persists the cell ops before the HTTP
                // projection cache is refreshed. A concurrent next Event may
                // therefore observe the accepted frontier during this narrow
                // cache window. Reload the durable cells once instead of
                // reporting a false dependency_missing for an already
                // materialized Realm.
                let typed_realm_id = arkret_identifiers::RealmId::new(realm_id.to_owned()).ok();
                if let Some(typed_realm_id) = typed_realm_id {
                    let _ = projections.reload_cells_from_store(&typed_realm_id).await;
                    projections.snapshot().realm_digest_algorithm(realm_id)
                } else {
                    None
                }
            }
        };
        projected.ok_or_else(|| {
            event_validation_error(
                StatusCode::CONFLICT,
                arkret_wire::ErrorCode::DEPENDENCY_MISSING,
                "Realm digest-suite cell is not materialized; Event identity cannot be verified",
            )
        })?
    };
    arkret_canonical::digest_suite(&suite)
        .map(|_| suite.clone())
        .map_err(|_| unsupported_digest_algorithm_error(&suite))
}

pub(super) fn event_digest_for_suite(
    bytes: &[u8],
    suite: &str,
) -> Result<String, EventValidationError> {
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
    // Spec zh/models/realm-and-space.md section 2.5.0: `ak.realm.create` is the
    // one kind that MUST NOT carry `realm_id`. The Realm's id is derived from
    // the genesis Event's own `event_id`, so carrying it would put a function
    // of the digest inside the digest preimage — there is no fixed point to
    // solve. Receivers derive it instead, which is also what makes `realm_id`
    // self-certifying against the genesis they were served.
    let is_realm_genesis = event_string_field(object, &["kind"])
        .is_some_and(|kind| kind == arkret_wire::EventKind::RealmCreate.as_str());

    if is_realm_genesis {
        if object.contains_key("realm_id") {
            let mut error = event_validation_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                arkret_wire::ErrorCode::SchemaViolation.as_str(),
                "ak.realm.create MUST omit realm_id; \
                 it is derived from the genesis event_id",
            );
            error.reason_code = Some(arkret_wire::ReasonCode::OBJECT_ID_NOT_EVENT_DERIVED);
            return Err(error);
        }
        return derive_realm_id_from_event_id(object);
    }

    if let Some(realm_id) = event_string_field(object, &["realm_id"]) {
        if RealmId::new(realm_id.clone()).is_err() {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "param_invalid",
                "realm_id must use the ak:realm: typed prefix",
            ));
        }
        return Ok(realm_id.clone());
    }

    Err(event_validation_error(
        StatusCode::BAD_REQUEST,
        "param_missing",
        "realm_id is required",
    ))
}

/// Derive this genesis Event's Realm id from its own signed content.
///
/// Two branches, both pure functions of the signed Event, so the id stays
/// self-certifying either way (spec `zh/models/realm-and-space.md` section
/// 2.5.0): every Realm, including a Principal Control Realm, is
/// `retype(event_id)`.
///
/// This is also the **first-contact check**: because the id is a function of
/// the Event, a receiver that is served a fabricated "Realm S" computes a
/// different id and never reaches the state that would let the forgery in.
fn derive_realm_id_from_event_id(
    object: &serde_json::Map<String, Value>,
) -> Result<String, EventValidationError> {
    let event_id = event_string_field(object, &["event_id"]).ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "param_missing",
            "event_id is required to derive the Realm id",
        )
    })?;
    let event_id = arkret_wire::EventId::new(event_id.clone()).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "param_invalid",
            "event_id must use the ak:event: typed prefix",
        )
    })?;
    Ok(arkret_wire::derive_genesis_realm_id(&event_id).into_string())
}

#[cfg(test)]
mod event_derived_id_tests {
    use super::*;

    #[test]
    fn staged_bootstrap_digest_precedes_durable_reload() {
        let suite = select_event_digest_algorithm(None, Some("sha256".to_owned()), || {
            panic!("a staged bootstrap must not consult durable Realm cells")
        });
        assert_eq!(suite.as_deref(), Some("sha256"));
    }

    #[test]
    fn realm_genesis_uses_the_common_carried_object_id_reason() {
        let object = serde_json::json!({
            "kind": "ak.realm.create",
            "event_id": "ak:event:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
            "realm_id": "ak:realm:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM"
        })
        .as_object()
        .expect("object fixture")
        .clone();
        let error = event_realm_id(&object).expect_err("realm_id is reducer-derived");
        assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(error.code, "schema_violation");
        assert_eq!(
            error.reason_code,
            Some(arkret_wire::ReasonCode::OBJECT_ID_NOT_EVENT_DERIVED)
        );
    }

    #[test]
    fn non_genesis_realm_id_with_reserved_header_bits_is_rejected() {
        let object = serde_json::json!({
            "kind": "ak.message.create",
            "realm_id": "ak:realm:_V1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM"
        })
        .as_object()
        .expect("object fixture")
        .clone();
        let error = event_realm_id(&object).expect_err("reserved header bits must fail closed");
        assert_eq!(error.code, "param_invalid");
    }
}

mod applet;
mod capability_grant;
mod capability_refs;
mod control_move;
mod envelope_core;
mod features_schema;
mod minimal_metadata_author;
mod proofs;
mod realm_authority_root;

use applet::*;
pub(in crate::routing::events::event_log) use capability_refs::validate_data_event_capability_refs;
use capability_refs::*;
use control_move::*;
#[cfg(test)]
pub(crate) use envelope_core::validate_event_envelope;
pub(crate) use envelope_core::validate_event_envelope_with_context;
pub(in crate::routing) use envelope_core::validate_private_invite_envelope;
pub(crate) use features_schema::{
    event_requirements_schema_id, validate_event_critical_features,
    validate_event_schema_and_payload, validate_event_time_fields, validate_member_identity_proof,
};
pub(crate) use proofs::validate_event_proofs;
