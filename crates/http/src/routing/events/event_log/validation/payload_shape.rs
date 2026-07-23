use super::super::*;

// Wire-shape validators applied on the event ingest path.
//
// Each maps a [`soland_http::wire_validators::WireRejection`] to a
// `schema_violation`-class [`EventValidationError`] carrying the precise
// reason code.

/// Forbidden-wire-fields registry entry `sidecar_exchange_binding`
/// (spec/v1/artifacts/registry/forbidden-wire-fields.json, zh/models/sidecar.md
/// §7.2.1): the Agent Sidecar exchange binding, exchange control plaintext,
/// and `exchange_id` are legal only inside MLS-encrypted payload/metadata of
/// Sidecar-backing-Circle-scoped events. Any plaintext occurrence on the
/// submitted wire — the key `sidecar_exchange_binding`, the key `exchange_id`,
/// or a string value equal to one of the two Sidecar schema ids — is a
/// hard-reject `schema_violation`. `ak.agent.sidecar.exchange.control` needs
/// no exemption: its outer payload carries only `strand_id` plus an
/// `encrypted_payload` envelope whose ciphertext is an opaque string, so
/// conforming producers never trip this structural scan.
const SIDECAR_FORBIDDEN_WIRE_KEYS: &[&str] = &["sidecar_exchange_binding", "exchange_id"];
const SIDECAR_FORBIDDEN_WIRE_STRING_VALUES: &[&str] = &[
    "ak.schema.agent_sidecar_event_exchange_binding.v1",
    "ak.schema.agent_sidecar_exchange_control.v1",
];

fn scan_sidecar_forbidden_wire_fields(value: &Value) -> Result<(), EventValidationError> {
    match value {
        Value::Object(object) => {
            for (key, nested) in object {
                if SIDECAR_FORBIDDEN_WIRE_KEYS.contains(&key.as_str()) {
                    return Err(sidecar_forbidden_wire_field_error(key));
                }
                scan_sidecar_forbidden_wire_fields(nested)?;
            }
            Ok(())
        }
        Value::Array(values) => {
            for nested in values {
                scan_sidecar_forbidden_wire_fields(nested)?;
            }
            Ok(())
        }
        Value::String(text) => {
            if SIDECAR_FORBIDDEN_WIRE_STRING_VALUES.contains(&text.as_str()) {
                return Err(sidecar_forbidden_wire_field_error(text));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn sidecar_forbidden_wire_field_error(token: &str) -> EventValidationError {
    event_validation_error(
        StatusCode::BAD_REQUEST,
        "schema_violation",
        format!(
            "`{token}` is Sidecar-exchange material and must not appear in plaintext event payloads \
             (forbidden-wire-fields sidecar_exchange_binding)"
        ),
    )
}

pub(super) fn validate_pre_schema_wire_shape(
    kind: &str,
    payload: &Value,
) -> Result<(), EventValidationError> {
    scan_sidecar_forbidden_wire_fields(payload)?;
    if kind == arkret_wire::events::EventKind::MEMBER_IDENTITY_UPDATE {
        soland_http::wire_validators::member_identity::validate_member_identity_update_payload(
            payload,
        )
        .map_err(wire_rejection_to_validation_error)?;
    }
    Ok(())
}

fn wire_rejection_to_validation_error(
    rejection: soland_http::wire_validators::WireRejection,
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
    if arkret_identifiers::CellRef::new(cell_id.to_owned()).is_err() {
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
    if kind != arkret_wire::events::EventKind::REALM_CREATE {
        return Ok(());
    }
    let Some(object) = payload.get("object").and_then(Value::as_object) else {
        return Ok(());
    };
    let history_visibility = object
        .get("history_visibility")
        .and_then(Value::as_str)
        .unwrap_or("joined");
    if object.get("encryption_profile").and_then(Value::as_str) == Some("mls_rfc9420")
        && let Err(reason) = arkret_models_collaboration::governance::history_visibility::validate_history_visibility_content_scheme_values(
            history_visibility,
            object.get("content_scheme").and_then(Value::as_str),
        )
    {
        return Err(event_validation_error(
            StatusCode::PRECONDITION_FAILED,
            "failed_precondition",
            reason,
        ));
    }
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
        && audience != *state.service_id()
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "audience_mismatch",
            "event audience must bind to this service DID",
        ));
    }
    if let Some(domain) = event_string_field(object, &["domain"])
        && domain != *state.service_id()
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
    fn plaintext_sidecar_exchange_binding_key_is_rejected_pre_schema() {
        let payload = json!({
            "message_id": "ak:message:01904100-0000-7000-8000-000000000001",
            "strand_id": "ak:strand:01904100-0000-7000-8000-000000000002",
            "content": {"kind": "ak.content.text", "body": "hello"},
            "metadata": {
                "sidecar_exchange_binding": {
                    "role": "request"
                }
            }
        });
        let error = validate_pre_schema_wire_shape(
            arkret_wire::events::EventKind::MESSAGE_CREATE,
            &payload,
        )
        .expect_err("plaintext metadata must not carry the exchange binding");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.code, "schema_violation");
    }

    #[test]
    fn plaintext_exchange_id_field_is_rejected_pre_schema() {
        let payload = json!({
            "message_id": "ak:message:01904100-0000-7000-8000-000000000001",
            "strand_id": "ak:strand:01904100-0000-7000-8000-000000000002",
            "content": {"kind": "ak.content.text", "body": "hello"},
            "refs": [{"role": "after", "exchange_id": "018f-abc"}]
        });
        let error = validate_pre_schema_wire_shape(
            arkret_wire::events::EventKind::MESSAGE_CREATE,
            &payload,
        )
        .expect_err("plaintext exchange_id must be rejected in any nested position");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.code, "schema_violation");
    }

    #[test]
    fn plaintext_sidecar_schema_id_values_are_rejected_pre_schema() {
        for schema_id in [
            "ak.schema.agent_sidecar_event_exchange_binding.v1",
            "ak.schema.agent_sidecar_exchange_control.v1",
        ] {
            let payload = json!({
                "strand_id": "ak:strand:01904100-0000-7000-8000-000000000002",
                "metadata": {"fields": {"schema": schema_id}}
            });
            let error = validate_pre_schema_wire_shape(
                arkret_wire::events::EventKind::MESSAGE_CREATE,
                &payload,
            )
            .expect_err("Sidecar schema ids must never appear as plaintext wire values");
            assert_eq!(error.status, StatusCode::BAD_REQUEST);
            assert_eq!(error.code, "schema_violation");
        }
    }

    #[test]
    fn ordinary_message_and_exchange_control_outer_payload_pass_the_sidecar_scan() {
        let message = json!({
            "message_id": "ak:message:01904100-0000-7000-8000-000000000001",
            "strand_id": "ak:strand:01904100-0000-7000-8000-000000000002",
            "content": {"kind": "ak.content.text", "body": "hello"},
            "metadata": {"fields": {"jira_status": "open"}}
        });
        validate_pre_schema_wire_shape(arkret_wire::events::EventKind::MESSAGE_CREATE, &message)
            .expect("ordinary messages are unaffected by the sidecar forbidden-wire scan");

        // The exchange control Event's outer payload is only strand_id plus an
        // opaque encrypted envelope; the structural scan must not reject it.
        let control = json!({
            "strand_id": "ak:strand:01904100-0000-7000-8000-000000000002",
            "encrypted_payload": {
                "ciphertext": "b3BhcXVlLW1scy1jaXBoZXJ0ZXh0",
                "content_type": "application/vnd.arkret.mls-ciphertext"
            }
        });
        validate_pre_schema_wire_shape(
            arkret_wire::events::EventKind::AGENT_SIDECAR_EXCHANGE_CONTROL,
            &control,
        )
        .expect("conforming exchange control outer payloads carry no plaintext exchange material");
    }

    #[test]
    fn ordinary_restricted_realm_still_requires_history_sharing_policy() {
        let error = validate_realm_create_policy_constraints(
            arkret_wire::events::EventKind::REALM_CREATE,
            &restricted_realm_create_payload(),
            false,
        )
        .expect_err("ordinary restricted Realm must not receive the PCR exception");
        assert_eq!(error.code, "history_sharing_policy_missing");
    }

    #[test]
    fn recognized_self_principal_pcr_does_not_require_a_third_bootstrap_slot() {
        validate_realm_create_policy_constraints(
            arkret_wire::events::EventKind::REALM_CREATE,
            &restricted_realm_create_payload(),
            true,
        )
        .expect("strict SDK-validated PCR bootstrap is exactly two slots");
    }

    #[test]
    fn mls_world_readable_realm_requires_history_capable_content_scheme() {
        let payload = json!({
            "object": {
                "history_visibility": "world_readable",
                "encryption_profile": "mls_rfc9420"
            }
        });
        let error = validate_realm_create_policy_constraints(
            arkret_wire::events::EventKind::REALM_CREATE,
            &payload,
            false,
        )
        .expect_err("strict MLS content cannot expose pre-join history");
        assert_eq!(error.status, StatusCode::PRECONDITION_FAILED);
        assert_eq!(error.code, "failed_precondition");
        assert_eq!(
            error.message,
            arkret_wire::ReasonCode::HISTORY_VISIBILITY_REQUIRES_HISTORY_CAPABLE_SCHEME
        );
    }
}
