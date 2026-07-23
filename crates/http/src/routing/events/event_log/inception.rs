use super::*;
pub(super) use crate::canonical_value_digest;

const DID_INCEPTION_REF_ROLE: &str = "did_inception";
const DID_RECOVERY_ANCHOR_REF_ROLE: &str = "did_recovery_anchor";

pub(super) fn require_object_field(
    object: &serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<(), EventValidationError> {
    match object.get(key) {
        Some(Value::Object(_)) => Ok(()),
        Some(_) => Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "event payload must be a JSON object",
        )),
        None => Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "missing_param",
            "event payload is required",
        )),
    }
}

pub(super) fn event_ref_list(
    object: &serde_json::Map<String, Value>,
    key: &str,
    max_len: usize,
) -> Result<Vec<String>, EventValidationError> {
    let Some(value) = object.get(key) else {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "missing_param",
            "event reference lists are required",
        ));
    };
    let Some(values) = value.as_array() else {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "event reference lists must be arrays",
        ));
    };
    // scalability-constraints.md section 2. `prev_refs` carries reason_code
    // `prev_refs_too_large` (which also covers the MUST-dedup rule); other ref
    // lists carry `refs_too_large`. Both are `schema_violation` reasons.
    let too_large_reason = if key == "prev_refs" {
        "prev_refs_too_large"
    } else {
        "refs_too_large"
    };
    let count_error = if key == "prev_refs" {
        arkret_core::validate_event_prev_ref_count(values.len()).is_err()
    } else {
        arkret_core::validate_event_ref_count(values.len()).is_err()
    };
    if values.len() > max_len || count_error {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            too_large_reason,
            "event reference list exceeds the v1 maximum entry count",
        ));
    }
    let mut seen = std::collections::HashSet::with_capacity(values.len());
    values
        .iter()
        .map(|value| {
            let Some(event_id) = value.as_str() else {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "event references must be strings",
                ));
            };
            if !is_valid_event_id(event_id) {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "event references must use the ak:event: typed prefix",
                ));
            }
            // Entries MUST be deduplicated.
            if !seen.insert(event_id) {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    too_large_reason,
                    "event reference list MUST NOT contain duplicate entries",
                ));
            }
            Ok(event_id.to_owned())
        })
        .collect()
}

pub(super) fn principal_control_genesis_shape(
    object: &serde_json::Map<String, Value>,
    actor_id: &str,
) -> bool {
    object.get("kind").and_then(Value::as_str) == Some(arkret_wire::events::EventKind::REALM_CREATE)
        && object
            .get("payload")
            .and_then(|payload| payload.pointer("/object/fields/purpose"))
            .and_then(Value::as_str)
            == Some("principal_control")
        && object
            .get("payload")
            .and_then(|payload| payload.pointer("/object/created_by"))
            .and_then(Value::as_str)
            == Some(actor_id)
        && object
            .get("payload")
            .and_then(|payload| payload.pointer("/object/id"))
            .and_then(Value::as_str)
            == object.get("realm_id").and_then(Value::as_str)
}

fn anchor_refs(object: &serde_json::Map<String, Value>) -> Vec<(&str, &str, bool)> {
    object
        .get("refs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|reference| {
            let role = reference.get("role")?.as_str()?;
            matches!(role, DID_INCEPTION_REF_ROLE | DID_RECOVERY_ANCHOR_REF_ROLE).then(|| {
                (
                    role,
                    reference
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                    reference
                        .get("critical")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                )
            })
        })
        .collect()
}

pub(super) async fn resolve_event_root_anchor_method(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
    actor_id: &str,
) -> Result<Option<String>, EventValidationError> {
    let refs = anchor_refs(object);
    if refs.is_empty() {
        return Ok(None);
    }
    if refs.len() != 1 || !refs[0].2 {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "root-anchored Event requires exactly one critical DID anchor reference",
        ));
    }

    let (role, anchor_id, _) = refs[0];
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let valid_shape = match role {
        DID_INCEPTION_REF_ROLE => principal_control_genesis_shape(object, actor_id),
        DID_RECOVERY_ANCHOR_REF_ROLE => {
            kind == "ak.device.reanchor"
                && object
                    .get("payload")
                    .and_then(|payload| payload.get("principal_id"))
                    .and_then(Value::as_str)
                    == Some(actor_id)
        }
        _ => false,
    };
    if !valid_shape {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "failed_precondition",
            "identity-root proof is outside the closed PCR genesis and device re-anchor allowlist",
        ));
    }
    if role == DID_RECOVERY_ANCHOR_REF_ROLE
        && object
            .get("payload")
            .and_then(|payload| payload.get("did_version_id"))
            .and_then(Value::as_str)
            != Some(anchor_id)
    {
        return Err(event_validation_error(
            StatusCode::CONFLICT,
            "device_reanchor_entry_not_head",
            "device re-anchor DID anchor reference must equal payload.did_version_id",
        ));
    }
    if !actor_id.starts_with("did:webvh:") {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "failed_precondition",
            "root-anchored Event requires a verifiable did:webvh history",
        ));
    }

    let mut records = state
        .did_application()
        .log_events(actor_id)
        .await
        .map_err(|error| {
            event_validation_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "stale_did_document",
                format!("DID history is unavailable for root-anchor verification: {error}"),
            )
        })?;
    records.sort_by_key(|record| record.seq);
    let log = records
        .iter()
        .map(|record| {
            crate::routing::identity::webvh_validation::WebvhLogEntry::new(record.operation.clone())
        })
        .collect::<Vec<_>>();
    crate::routing::identity::webvh_validation::validate_log_chain(&log).map_err(|error| {
        event_validation_error(
            StatusCode::FORBIDDEN,
            "invalid_proof",
            format!("root-anchor DID history validation failed: {error}"),
        )
    })?;
    crate::routing::identity::webvh_validation::verify_scid_against_did(actor_id, &log[0])
        .map_err(|error| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "invalid_proof",
                format!("root-anchor DID SCID validation failed: {error}"),
            )
        })?;
    crate::routing::identity::webvh_validation::verify_log_subject(actor_id, &log).map_err(
        |error| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "invalid_proof",
                format!("root-anchor DID subject validation failed: {error}"),
            )
        },
    )?;
    crate::routing::identity::webvh_validation::validate_witness_policy_for_log(
        &log,
        now().timestamp(),
    )
    .map_err(|error| {
        event_validation_error(
            StatusCode::FORBIDDEN,
            "invalid_proof",
            format!("root-anchor DID witness validation failed: {error}"),
        )
    })?;
    crate::routing::identity::webvh_validation::validate_rotation_authorization_for_log(&log)
        .map_err(|error| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "invalid_proof",
                format!("root-anchor DID controller validation failed: {error}"),
            )
        })?;

    let referenced = match role {
        DID_INCEPTION_REF_ROLE => log
            .first()
            .filter(|entry| entry.version_id() == Some(anchor_id)),
        DID_RECOVERY_ANCHOR_REF_ROLE => log
            .iter()
            .find(|entry| entry.version_id() == Some(anchor_id)),
        _ => None,
    }
    .ok_or_else(|| {
        event_validation_error(
            StatusCode::FORBIDDEN,
            if role == DID_RECOVERY_ANCHOR_REF_ROLE {
                "device_reanchor_entry_not_head"
            } else {
                "invalid_proof"
            },
            "DID anchor reference does not resolve to the required history entry",
        )
    })?;
    if role == DID_RECOVERY_ANCHOR_REF_ROLE
        && log.last().and_then(|entry| entry.version_id()) != referenced.version_id()
    {
        return Err(event_validation_error(
            StatusCode::CONFLICT,
            "device_reanchor_entry_not_head",
            "device re-anchor DID entry is not the accepted registry head",
        ));
    }
    crate::routing::identity::webvh_validation::validate_active_controller_proof(referenced)
        .map_err(|error| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "invalid_proof",
                format!("referenced DID entry active-controller proof is invalid: {error}"),
            )
        })?;
    let methods =
        crate::routing::identity::webvh_validation::active_update_verification_methods(referenced);
    if methods.len() != 1 {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "invalid_proof",
            "root-anchor DID entry must expose exactly one active update authority",
        ));
    }
    Ok(methods.into_iter().next())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn object(refs: serde_json::Value) -> serde_json::Map<String, Value> {
        json!({ "prev_refs": refs }).as_object().unwrap().clone()
    }

    #[test]
    fn prev_refs_over_max_rejected() {
        let refs: Vec<Value> = (0..(MAX_EVENT_PREV_REFS + 1))
            .map(|i| json!(format!("ak:event:e{i}")))
            .collect();
        let err =
            event_ref_list(&object(json!(refs)), "prev_refs", MAX_EVENT_PREV_REFS).unwrap_err();
        assert_eq!(err.code, "prev_refs_too_large");
    }

    #[test]
    fn duplicate_prev_refs_rejected() {
        let refs = json!(["ak:event:e1", "ak:event:e1"]);
        let err = event_ref_list(&object(refs), "prev_refs", MAX_EVENT_PREV_REFS).unwrap_err();
        assert_eq!(err.code, "prev_refs_too_large");
    }

    #[test]
    fn distinct_prev_refs_within_limit_ok() {
        let refs = json!(["ak:event:e1", "ak:event:e2"]);
        let out = event_ref_list(&object(refs), "prev_refs", MAX_EVENT_PREV_REFS).unwrap();
        assert_eq!(
            out,
            vec!["ak:event:e1".to_owned(), "ak:event:e2".to_owned()]
        );
    }
}
