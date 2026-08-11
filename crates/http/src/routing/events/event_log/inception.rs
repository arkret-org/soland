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
        arkret_wire::event_envelope::validate_event_prev_ref_count(values.len()).is_err()
    } else {
        arkret_wire::event_envelope::validate_event_ref_count(values.len()).is_err()
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
    object.get("kind").and_then(Value::as_str) == Some(arkret_wire::EventKind::RealmCreate.as_str())
        && object
            .get("payload")
            .and_then(|payload| payload.pointer("/object/purpose"))
            .and_then(Value::as_str)
            == Some("principal_control")
        && object.get("actor_id").and_then(Value::as_str) == Some(actor_id)
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
    let actor_core_id = arkret_wire::DidCoreId::new(actor_id.to_owned()).map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            format!("root-anchored Event actor_id must be a core id: {error}"),
        )
    })?;
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
    // Event actor_id and the notary cell are stable core state. did:webvh
    // history lookup uses the full identity from the signed proof's
    // verification method; reconstructing it from either core id is forbidden.
    let principal_full_id = if role == DID_INCEPTION_REF_ROLE {
        let mut matching_full_ids = std::collections::BTreeSet::new();
        for proof in object
            .get("proofs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(verification_method) =
                proof.get("verification_method").and_then(Value::as_str)
            else {
                continue;
            };
            let Some((full_id, _)) = verification_method.rsplit_once('#') else {
                continue;
            };
            let Ok(full_id) = arkret_wire::DidFullId::new(full_id.to_owned()) else {
                continue;
            };
            if arkret_wire::project_full_id_to_core_id(&full_id)
                .is_ok_and(|core_id| core_id == actor_core_id)
            {
                matching_full_ids.insert(full_id);
            }
        }
        if matching_full_ids.len() != 1 {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "invalid_proof",
                "principal-control genesis must have exactly one signed full DID projecting to actor_id",
            ));
        }
        matching_full_ids.pop_first().expect("length checked")
    } else {
        let realm_id = object
            .get("realm_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "missing_param",
                    "root-anchored Event must carry realm_id",
                )
            })?;
        state
            .projections()
            .snapshot()
            .principal_resolution_for_realm(realm_id)
            .and_then(|resolution| resolution.get("full_id"))
            .and_then(Value::as_str)
            .and_then(|full_id| arkret_wire::DidFullId::new(full_id.to_owned()).ok())
            .ok_or_else(|| {
                event_validation_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "stale_did_document",
                    "selected PCR full-id resolution is unavailable",
                )
            })?
    };
    if principal_full_id.method() != "webvh" {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "failed_precondition",
            "root-anchored Event requires a verifiable did:webvh history",
        ));
    }

    let mut records = state
        .dids()
        .log_events(principal_full_id.as_str())
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
    crate::routing::identity::webvh_validation::verify_scid_against_did(
        principal_full_id.as_str(),
        &log[0],
    )
    .map_err(|error| {
        event_validation_error(
            StatusCode::FORBIDDEN,
            "invalid_proof",
            format!("root-anchor DID SCID validation failed: {error}"),
        )
    })?;
    crate::routing::identity::webvh_validation::verify_log_subject(
        principal_full_id.as_str(),
        &log,
    )
    .map_err(|error| {
        event_validation_error(
            StatusCode::FORBIDDEN,
            "invalid_proof",
            format!("root-anchor DID subject validation failed: {error}"),
        )
    })?;
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

    fn event_ref(index: usize) -> String {
        arkret_identifiers::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            arkret_canonical::sha256_bytes(&index.to_be_bytes()),
        )
        .to_string()
    }

    #[test]
    fn prev_refs_over_max_rejected() {
        let refs: Vec<Value> = (0..(MAX_EVENT_PREV_REFS + 1))
            .map(|i| json!(event_ref(i)))
            .collect();
        let err =
            event_ref_list(&object(json!(refs)), "prev_refs", MAX_EVENT_PREV_REFS).unwrap_err();
        assert_eq!(err.code, "prev_refs_too_large");
    }

    #[test]
    fn duplicate_prev_refs_rejected() {
        let duplicate = event_ref(1);
        let refs = json!([duplicate.clone(), duplicate]);
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
