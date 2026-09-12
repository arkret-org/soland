use super::*;

pub(super) fn validate_control_move_seal_basis(
    object: &serde_json::Map<String, Value>,
    allow_realm_bootstrap_followup_without_basis: bool,
) -> Result<(), EventValidationError> {
    if object.get("kind").and_then(Value::as_str)
        == Some(arkret_wire::EventKind::RealmCreate.as_str())
    {
        if object.contains_key("auth_context") || object.contains_key("seal_basis") {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "schema_violation",
                "ak.realm.create genesis bootstrap must not carry auth_context or seal_basis",
            ));
        }
        return Ok(());
    }
    if object.get("kind").and_then(Value::as_str)
        == Some(arkret_wire::event_kind_str::DEVICE_REANCHOR)
    {
        if object.contains_key("auth_context") || object.contains_key("seal_basis") {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "schema_violation",
                "ak.device.reanchor must use payload.pre_fence_seal_frontier and must not carry Event seal fields",
            ));
        }
        return Ok(());
    }
    // This used to short-circuit on an empty producer `effects[]`, which v1
    // never carries — so every conformant Control Move skipped the seal_basis
    // requirement entirely. The gate is the registry's own reducer_input flag:
    // a kind the reducer consumes must be a DataEvent or carry seal_basis
    // (`event-auth-state-resolution.md` §5), and a kind it does not consume has
    // no basis obligation.
    let is_reducer_input = object
        .get("kind")
        .and_then(Value::as_str)
        .map(arkret_wire::EventKind::from)
        .and_then(|kind| kind.descriptor())
        .is_some_and(|descriptor| descriptor.reducer_input);
    if !is_reducer_input {
        return Ok(());
    }
    if allow_realm_bootstrap_followup_without_basis
        && !object.contains_key("auth_context")
        && !object.contains_key("seal_basis")
    {
        return Ok(());
    }
    if object.contains_key("auth_context") {
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
                "Control Move requires seal_basis.leaves",
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

pub(super) fn is_realm_bootstrap_followup_kind(kind: &str) -> bool {
    kind.parse::<arkret_wire::EventKind>()
        .is_ok_and(|kind| arkret_policy::realm_bootstrap::is_realm_bootstrap_followup_kind(&kind))
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

    let directory_actor_id = if arkret_wire::DidCoreId::new(session.actor.clone())
        .is_ok_and(|session_actor_id| session_actor_id.as_str() == actor_id)
    {
        session.actor.as_str()
    } else {
        actor_id
    };
    for device_id in candidate_devices {
        let revoked = state
            .identities()
            .find_device(soland_services::identity::FindDeviceQuery {
                actor_id: directory_actor_id.to_owned(),
                device_id: device_id.clone(),
            })
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
    let (method_controller, fragment) = verification_method.rsplit_once('#')?;
    let method_controller = arkret_wire::Did::new(method_controller.to_owned()).ok()?;
    let method_actor_id = arkret_wire::project_did_to_core_id(&method_controller).ok()?;
    (method_actor_id.as_str() == actor_id)
        .then_some(fragment)
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
