use super::*;

pub(super) fn validate_control_move_seal_basis(
    object: &serde_json::Map<String, Value>,
    allow_realm_bootstrap_followup_without_basis: bool,
) -> Result<(), EventValidationError> {
    let has_effects = object
        .get("effects")
        .and_then(Value::as_array)
        .is_some_and(|effects| !effects.is_empty());
    if object.get("kind").and_then(Value::as_str)
        == Some(arkret_sdk::events::EventKind::REALM_CREATE)
    {
        if object.contains_key("seal_ref")
            || object.contains_key("auth_context")
            || object.contains_key("seal_basis")
        {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "schema_violation",
                "ak.realm.create genesis bootstrap must not carry seal_ref, auth_context, or seal_basis",
            ));
        }
        return Ok(());
    }
    if object.get("kind").and_then(Value::as_str) == Some("ak.device.reanchor") {
        if object.contains_key("seal_ref")
            || object.contains_key("auth_context")
            || object.contains_key("seal_basis")
        {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "schema_violation",
                "ak.device.reanchor must use payload.pre_fence_basis and must not carry Event seal fields",
            ));
        }
        return Ok(());
    }
    if !has_effects {
        return Ok(());
    }
    if allow_realm_bootstrap_followup_without_basis
        && !object.contains_key("seal_ref")
        && !object.contains_key("auth_context")
        && !object.contains_key("seal_basis")
    {
        return Ok(());
    }
    if object.contains_key("seal_ref") || object.contains_key("auth_context") {
        return Ok(());
    }
    let leaves = object
        .get("seal_basis")
        .and_then(Value::as_object)
        .and_then(|basis| basis.get("leaves"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "schema_violation",
                "Control Move with effects requires seal_basis.leaves",
            )
        })?;
    if leaves.is_empty() {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "schema_violation",
            "Control Move seal_basis.leaves must be non-empty",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CbaEffectPlane {
    Data,
    Control,
}

pub(super) const DATA_PLANE_CELL_FAMILIES: &[&str] = &[
    "ak.component.strand.discussion.timeline.v1",
    "ak.component.message.reactions.v1",
    "ak.component.pin.v1",
];

pub(super) fn validate_cba_effect_planes(
    object: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    let Some(effects) = object.get("effects").and_then(Value::as_array) else {
        return Ok(());
    };
    if effects.is_empty() {
        return Ok(());
    }
    let is_data_event = object.contains_key("seal_ref") || object.contains_key("auth_context");
    let is_control_move = object.contains_key("seal_basis");
    if !is_data_event && !is_control_move {
        return Ok(());
    }
    for effect in effects {
        let family = cba_effect_cell_family(effect)?;
        match cba_cell_family_plane(family)? {
            CbaEffectPlane::Control if is_data_event => {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "plane_cross_write",
                    "DataEvent effects[] must not write control-plane cell",
                ));
            }
            CbaEffectPlane::Data if is_control_move => {
                return Err(event_validation_error(
                    StatusCode::PRECONDITION_FAILED,
                    "failed_plane",
                    "Control Move effects[] must not write data-plane cell",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

pub(super) fn cba_effect_cell_family(effect: &Value) -> Result<&str, EventValidationError> {
    let cell = effect.get("cell").and_then(Value::as_str).ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "effects[] entries require cell",
        )
    })?;
    if arkret_sdk::CellRef::new(cell.to_owned()).is_err() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "effects[].cell must use canonical ak:cell:ak.component.*.v<n>:<subject> form",
        ));
    }
    let Some(rest) = cell.strip_prefix("ak:cell:") else {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "effects[].cell must use the ak:cell: typed prefix",
        ));
    };
    let Some((family, subject)) = rest.split_once(':') else {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "effects[].cell must include a cell family and subject",
        ));
    };
    if family.trim().is_empty() || subject.trim().is_empty() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "effects[].cell must include a non-empty cell family and subject",
        ));
    }
    Ok(family)
}

fn cba_cell_family_plane(family: &str) -> Result<CbaEffectPlane, EventValidationError> {
    if DATA_PLANE_CELL_FAMILIES.contains(&family) {
        return Ok(CbaEffectPlane::Data);
    }
    if soland_domain::artifacts::cell_family_bindings()
        .iter()
        .any(|binding| binding.cell_family == family)
    {
        return Ok(CbaEffectPlane::Control);
    }
    Err(event_validation_error(
        StatusCode::BAD_REQUEST,
        "schema_violation",
        format!("effects[].cell references unknown cell family {family}"),
    ))
}

pub(super) fn is_realm_bootstrap_followup_kind(kind: &str) -> bool {
    arkret_sdk::realm::bootstrap::is_realm_bootstrap_followup_kind(kind)
}

pub(super) async fn reject_revoked_actor_device_signature(
    object: &serde_json::Map<String, Value>,
    state: &AppState,
    session: &SessionRecord,
    actor_id: &str,
) -> Result<(), EventValidationError> {
    let proof_devices = object
        .get("proofs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .filter_map(|proof| event_string_field(proof, &["verification_method"]))
        .filter_map(|vm| actor_device_id_from_verification_method(&vm, actor_id))
        .collect::<std::collections::BTreeSet<_>>();

    let mut candidate_devices = proof_devices;
    candidate_devices.insert(session.device_id.clone());
    if let Some(device_id) = event_string_field(object, &["device_id"]) {
        candidate_devices.insert(device_id);
    }

    for device_id in candidate_devices {
        let revoked = state
            .devices_store()
            .get(actor_id, &device_id)
            .await
            .map_err(|error| {
                event_validation_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("device revocation lookup failed: {error}"),
                )
            })?
            .is_some_and(|device| device.revoked_at.is_some());
        if revoked {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "actor_signature_revoked",
                "event proof was signed by a revoked actor device",
            ));
        }
    }
    Ok(())
}

pub(super) fn actor_device_id_from_verification_method(
    verification_method: &str,
    actor_id: &str,
) -> Option<String> {
    verification_method
        .strip_prefix(actor_id)
        .and_then(|suffix| suffix.strip_prefix('#'))
        .map(str::trim)
        .filter(|fragment| !fragment.is_empty())
        .map(|fragment| {
            if fragment.starts_with("ak:device:") {
                fragment.to_owned()
            } else {
                format!("ak:device:{fragment}")
            }
        })
}
