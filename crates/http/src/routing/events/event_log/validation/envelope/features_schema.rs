use super::*;

pub(crate) fn validate_event_schema_and_payload(
    _state: &AppState,
    kind: &str,
    _schema_id: &str,
    envelope: &Value,
    object: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    serde_json::from_value::<arkret_wire::Event>(envelope.clone()).map_err(|error| {
        event_validation_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            format!("event envelope violates its typed wire contract: {error}"),
        )
    })?;

    let payload = object.get("payload").ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "param_missing",
            "event payload is required",
        )
    })?;
    // Wire-shape validators that must run before the registered payload
    // schema validator to surface their precise reason codes.
    validate_pre_schema_wire_shape(kind, payload)?;
    if matches!(
        kind,
        arkret_wire::event_kind_str::SPACE_ARCHIVE
            | arkret_wire::event_kind_str::SPACE_RESTORE
            | arkret_wire::event_kind_str::SPACE_TOMBSTONE
    ) {
        return validate_space_container_lifecycle_payload(payload);
    }
    let typed_kind = arkret_wire::EventKind::from(kind);
    arkret_event_draft::validate_event_payload(&typed_kind, payload).map_err(|error| {
        event_validation_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            format!("event payload violates its typed SDK contract: {error}"),
        )
    })?;
    if kind == arkret_wire::EventKind::SchemaDefine.as_str() {
        arkret_schema::validate_schema_definition_payload(payload).map_err(|error| {
            event_validation_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "schema_violation",
                format!("event payload violates its registered validator profile: {error}"),
            )
        })?;
    }
    Ok(())
}
