use super::super::*;

/// Wire-shape validators applied on the event ingest path.
///
/// Each maps a [`crate::wire_validators::WireRejection`] to a
/// `schema_violation`-class [`EventValidationError`] carrying the precise
/// reason code.
pub(super) fn validate_pre_schema_wire_shape(
    kind: &str,
    payload: &Value,
) -> Result<(), EventValidationError> {
    if kind == arkret_sdk::events::EventKind::MEMBER_IDENTITY_UPDATE {
        crate::wire_validators::member_identity::validate_member_identity_update_payload(payload)
            .map_err(wire_rejection_to_validation_error)?;
    }
    Ok(())
}

fn wire_rejection_to_validation_error(
    rejection: crate::wire_validators::WireRejection,
) -> EventValidationError {
    event_validation_error(StatusCode::BAD_REQUEST, rejection.reason, rejection.message)
}

pub(super) fn validate_conflict_repair_event_payload(
    payload: &Value,
) -> Result<(), EventValidationError> {
    let Some(object) = payload.as_object() else {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "conflict repair payload must be an object",
        ));
    };
    let cell_id = object
        .get("cell_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "conflict repair payload requires cell_id",
            )
        })?;
    if arkret_sdk::CellRef::new(cell_id.to_owned()).is_err() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "conflict repair cell_id must use canonical ak:cell:ak.component.*.v<n>:<subject> form",
        ));
    }
    let heads = object
        .get("conflict_heads")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "conflict repair payload requires conflict_heads",
            )
        })?;
    if heads.len() < 2
        || heads
            .iter()
            .any(|head| head.as_str().is_none_or(|value| value.trim().is_empty()))
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "conflict repair conflict_heads must contain at least two non-empty strings",
        ));
    }
    if object
        .get("recovery_capability_ref")
        .and_then(Value::as_str)
        .is_none_or(|value| value.trim().is_empty())
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "conflict repair payload requires recovery_capability_ref",
        ));
    }
    if object
        .get("state_witness_ref")
        .or_else(|| object.get("state_witness"))
        .and_then(Value::as_str)
        .is_none_or(|value| value.trim().is_empty())
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "conflict repair payload requires state_witness_ref",
        ));
    }
    if !object.contains_key("winner_value") {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "conflict repair payload requires winner_value",
        ));
    }
    Ok(())
}

pub(super) fn validate_realm_create_policy_constraints(
    kind: &str,
    payload: &Value,
    is_self_principal_pcr_bootstrap_create: bool,
) -> Result<(), EventValidationError> {
    if kind != arkret_sdk::events::EventKind::REALM_CREATE {
        return Ok(());
    }
    let Some(object) = payload.get("object").and_then(Value::as_object) else {
        return Ok(());
    };
    let history_visibility = object
        .get("history_visibility")
        .and_then(Value::as_str)
        .unwrap_or("joined");
    if history_visibility == "restricted"
        && !is_self_principal_pcr_bootstrap_create
        && object
            .get("history_sharing_policy")
            .and_then(Value::as_object)
            .is_none()
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "history_sharing_policy_missing",
            "restricted history_visibility requires an effective history_sharing_policy",
        ));
    }
    Ok(())
}

pub(super) fn validate_space_container_lifecycle_payload(
    payload: &Value,
) -> Result<(), EventValidationError> {
    let Some(object) = payload.as_object() else {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "space lifecycle payload must be an object",
        ));
    };
    let target = object
        .get("space_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "space lifecycle payload requires space_id",
            )
        })?;
    if validate_space_id(target).is_err() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "space lifecycle payload space_id must use ak:space:",
        ));
    }
    if object.get("target_ref").is_some() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "space lifecycle payload must use space_id, not target_ref",
        ));
    }
    Ok(())
}

pub(super) fn validate_event_audience_fields(
    object: &serde_json::Map<String, Value>,
    state: &AppState,
    session: &SessionRecord,
) -> Result<(), EventValidationError> {
    if let Some(audience) = event_string_field(object, &["audience"])
        && audience != state.service_id
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "audience_mismatch",
            "event audience must bind to this service DID",
        ));
    }
    if let Some(domain) = event_string_field(object, &["domain"])
        && domain != state.service_id
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "domain_mismatch",
            "event domain must bind to this service DID",
        ));
    }
    if let Some(device_id) = event_string_field(object, &["device_id"])
        && device_id != session.device_id
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "device_session_mismatch",
            "event device_id must match the bearer session device",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn restricted_realm_create_payload() -> Value {
        json!({
            "object": {
                "history_visibility": "restricted"
            }
        })
    }

    #[test]
    fn ordinary_restricted_realm_still_requires_history_sharing_policy() {
        let error = validate_realm_create_policy_constraints(
            arkret_sdk::events::EventKind::REALM_CREATE,
            &restricted_realm_create_payload(),
            false,
        )
        .expect_err("ordinary restricted Realm must not receive the PCR exception");
        assert_eq!(error.code, "history_sharing_policy_missing");
    }

    #[test]
    fn recognized_self_principal_pcr_does_not_require_a_third_bootstrap_slot() {
        validate_realm_create_policy_constraints(
            arkret_sdk::events::EventKind::REALM_CREATE,
            &restricted_realm_create_payload(),
            true,
        )
        .expect("strict SDK-validated PCR bootstrap is exactly two slots");
    }
}
