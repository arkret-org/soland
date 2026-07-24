use super::*;

/// Look up which Arkret `realm_id` (if any) the MIMI `room_id` is
/// bound to. Scans the persistence projection event log for the
/// most recent `ak.mimi.room_binding` event whose
/// `payload.mimi_room_id` (or trailing segment of `mimi_room_uri`)
/// matches `room_id`. Returns `None` when no binding has been
/// recorded; callers translate that into a 404/400 rather than
/// silently routing the request at a hard-coded demo Realm.
pub(super) async fn latest_mimi_room_binding(
    state: &AppState,
    room_id: &str,
) -> Option<MimiRoomBindingProjection> {
    let entries = state
        .event_queries()
        .projected_events()
        .await
        .ok()?;
    // Walk in reverse so the most-recently-recorded binding wins.
    for entry in entries.iter().rev() {
        if entry.event_kind != "ak.mimi.room_binding" {
            continue;
        }
        let payload_room = entry
            .payload
            .get("mimi_room_id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| {
                entry
                    .payload
                    .get("mimi_room_uri")
                    .and_then(Value::as_str)
                    .and_then(|uri| uri.rsplit('/').next().map(ToOwned::to_owned))
            });
        let binding = entry.payload.get("binding").unwrap_or(&entry.payload);
        let binding_payload = mimi_room_binding_security_payload(binding);
        let binding_room = binding_payload
            .get("mimi_room_uri")
            .and_then(Value::as_str)
            .and_then(|uri| uri.rsplit('/').next().map(str::to_owned));
        if payload_room.as_deref() == Some(room_id) || binding_room.as_deref() == Some(room_id) {
            let realm_id = entry
                .payload
                .get("binding_scope")
                .and_then(|s| s.get("realm_id"))
                .and_then(Value::as_str)
                .or_else(|| {
                    binding_payload
                        .get("binding_scope")
                        .and_then(|s| s.get("realm_id"))
                        .and_then(Value::as_str)
                })
                .or_else(|| entry.payload.get("realm_id").and_then(Value::as_str))
                .or_else(|| binding_payload.get("realm_id").and_then(Value::as_str))?;
            return Some(MimiRoomBindingProjection {
                event_id: entry.event_id.clone(),
                realm_id: realm_id.to_owned(),
                binding: binding.clone(),
            });
        }
    }
    None
}

pub(super) async fn mimi_bound_realm_id(state: &AppState, room_id: &str) -> Option<String> {
    latest_mimi_room_binding(state, room_id)
        .await
        .map(|binding| binding.realm_id)
}

pub(super) fn enforce_mimi_submit_binding(
    room_binding: &MimiRoomBindingProjection,
    body: &Value,
    message: &Value,
) -> Result<(), AppError> {
    validate_mimi_room_binding_payload(&room_binding.binding)?;
    let binding_payload = mimi_room_binding_security_payload(&room_binding.binding);
    match binding_payload.get("status").and_then(Value::as_str) {
        Some("accepted") => {}
        Some(_) | None => {
            return Err(AppError::invalid_param(
                "MIMI room binding is not writable in its current state",
            )
            .with_wire_code(arkret_wire::ReasonCode::MIMI_ROOM_STATE_INCOMPATIBLE));
        }
    }
    match binding_payload
        .get("local_provider_role")
        .and_then(Value::as_str)
    {
        Some("hub" | "follower") => {}
        Some("observer") => {
            return Err(
                AppError::capability_denied("MIMI observer binding cannot submit writes")
                    .with_wire_code(arkret_wire::ReasonCode::MIMI_OBSERVER_WRITE_FORBIDDEN),
            );
        }
        _ => {
            return Err(
                AppError::invalid_param("MIMI room binding has no writable provider role")
                    .with_wire_code(arkret_wire::ReasonCode::MIMI_ROOM_STATE_INCOMPATIBLE),
            );
        }
    }

    let Some(binding_group_id) = binding_payload
        .get("mls_group_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(());
    };
    let submit_group_id = mimi_submit_mls_group_id(body, message).ok_or_else(|| {
        AppError::invalid_param("MIMI submit_message is missing mls_group_id")
            .with_wire_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISMATCH)
    })?;
    if submit_group_id != binding_group_id {
        return Err(AppError::invalid_param(
            "MIMI submit_message mls_group_id does not match room binding",
        )
        .with_wire_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISMATCH));
    }
    let epoch = mimi_submit_epoch(body, message).ok_or_else(|| {
        AppError::invalid_param("MIMI submit_message is missing MLS epoch")
            .with_wire_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISMATCH)
    })?;
    let governance_binding = mimi_governance_binding_candidate(binding_payload, body, message)
        .ok_or_else(|| {
            AppError::invalid_param("MIMI submit_message lacks governance_binding")
                .with_wire_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISSING)
        })?;
    validate_mimi_submit_governance_binding(
        governance_binding,
        &room_binding.realm_id,
        binding_group_id,
        epoch,
        binding_payload
            .get("policy_root")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty()),
    )?;
    if !mimi_submit_has_covered_seals_cell(binding_payload, body, message, governance_binding) {
        return Err(AppError::invalid_param(
            "MIMI submit_message lacks covered_seals_cell evidence",
        )
        .with_wire_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISSING));
    }
    Ok(())
}

pub(super) fn validate_mimi_room_binding_payload(binding: &Value) -> Result<(), AppError> {
    let payload = mimi_room_binding_security_payload(binding);
    if payload
        .get("hub_provider")
        .and_then(Value::as_str)
        .is_none_or(|value| value.trim().is_empty())
    {
        return Err(
            AppError::invalid_param("MIMI room binding requires hub_provider")
                .with_wire_code(arkret_wire::ReasonCode::MIMI_ROOM_STATE_INCOMPATIBLE),
        );
    }
    match payload.get("local_provider_role").and_then(Value::as_str) {
        Some("hub" | "follower" | "observer") => {}
        _ => {
            return Err(AppError::invalid_param(
                "MIMI room binding requires a known local_provider_role",
            )
            .with_wire_code(arkret_wire::ReasonCode::MIMI_ROOM_STATE_INCOMPATIBLE));
        }
    }
    match payload.get("status").and_then(Value::as_str) {
        Some("proposed" | "accepted" | "revoked" | "migrating") => Ok(()),
        _ => Err(
            AppError::invalid_param("MIMI room binding requires a lifecycle status")
                .with_wire_code(arkret_wire::ReasonCode::MIMI_ROOM_STATE_INCOMPATIBLE),
        ),
    }
}

pub(super) async fn enforce_mimi_room_binding_transition(
    state: &AppState,
    room_id: &str,
    next_binding: &Value,
) -> Result<(), AppError> {
    let next_status = mimi_room_binding_status(next_binding)?;
    let previous = latest_mimi_room_binding(state, room_id).await;
    let previous_status = match previous.as_ref() {
        Some(previous) => Some(mimi_room_binding_status(&previous.binding)?),
        None => None,
    };
    if mimi_room_binding_transition_allowed(previous_status, next_status) {
        return Ok(());
    }
    let detail = previous_status
        .map(|status| format!("from={status};to={next_status}"))
        .unwrap_or_else(|| format!("from=<none>;to={next_status}"));
    Err(
        AppError::invalid_param("MIMI room binding status transition is not allowed")
            .with_wire_code(arkret_wire::ReasonCode::MIMI_ROOM_BINDING_STATUS_TRANSITION_INVALID)
            .with_reason_detail(detail),
    )
}

pub(super) fn mimi_room_binding_status(binding: &Value) -> Result<&str, AppError> {
    let payload = mimi_room_binding_security_payload(binding);
    payload
        .get("status")
        .and_then(Value::as_str)
        .filter(|status| matches!(*status, "proposed" | "accepted" | "revoked" | "migrating"))
        .ok_or_else(|| {
            AppError::invalid_param("MIMI room binding requires a lifecycle status")
                .with_wire_code(arkret_wire::ReasonCode::MIMI_ROOM_STATE_INCOMPATIBLE)
        })
}

pub(super) fn mimi_room_binding_transition_allowed(previous: Option<&str>, next: &str) -> bool {
    matches!(
        (previous, next),
        (None, "proposed" | "accepted")
            | (Some("proposed"), "accepted" | "revoked")
            | (Some("accepted"), "migrating" | "revoked")
            | (Some("migrating"), "accepted" | "revoked")
    )
}

pub(super) fn mimi_room_binding_security_payload(binding: &Value) -> &Value {
    binding
        .get("payload")
        .filter(|payload| payload.is_object())
        .unwrap_or(binding)
}

pub(super) fn mimi_submit_mls_group_id<'a>(body: &'a Value, message: &'a Value) -> Option<&'a str> {
    body.get("mls_group_id")
        .or_else(|| {
            body.get("ciphertext")
                .and_then(|ciphertext| ciphertext.get("mls_group_id"))
        })
        .or_else(|| message.get("mls_group_id"))
        .or_else(|| message.get("group_id"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

pub(super) fn mimi_submit_epoch(body: &Value, message: &Value) -> Option<u64> {
    body.get("epoch")
        .or_else(|| {
            body.get("ciphertext")
                .and_then(|ciphertext| ciphertext.get("epoch"))
        })
        .or_else(|| message.get("epoch"))
        .and_then(Value::as_u64)
}

pub(super) fn mimi_governance_binding_candidate<'a>(
    binding_payload: &'a Value,
    body: &'a Value,
    message: &'a Value,
) -> Option<&'a Value> {
    governance_binding_field(message)
        .or_else(|| {
            body.get("associated_data")
                .and_then(governance_binding_field)
        })
        .or_else(|| body.get("ciphertext").and_then(governance_binding_field))
        .or_else(|| governance_binding_field(body))
        .or_else(|| governance_binding_field(binding_payload))
}

pub(super) fn governance_binding_field(value: &Value) -> Option<&Value> {
    value
        .get("governance_binding")
        .or_else(|| value.get("mls_governance_binding"))
}

pub(super) fn validate_mimi_submit_governance_binding(
    binding: &Value,
    realm_id: &str,
    group_id: &str,
    epoch: u64,
    expected_policy_root: Option<&str>,
) -> Result<(), AppError> {
    let error = |reason: &'static str| {
        AppError::invalid_param("MIMI submit_message governance_binding is not valid")
            .with_wire_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISMATCH)
            .with_reason_detail(reason)
    };
    if binding.get("binding_version").and_then(Value::as_u64) != Some(1) {
        return Err(error("mls_governance_binding_version_invalid"));
    }
    if binding.get("encoding_profile").and_then(Value::as_str)
        != Some("cbor-deterministic-rfc8949-v1")
    {
        return Err(error("mls_governance_binding_encoding_profile_invalid"));
    }
    if binding.get("binding_profile").and_then(Value::as_str)
        != Some(soland_services::operation_semantics::MLS_GOVERNANCE_BINDING_FULL_PROFILE)
    {
        return Err(error("mls_governance_binding_profile_invalid"));
    }
    if binding.get("reducer_profile").and_then(Value::as_str)
        != Some(soland_services::operation_semantics::MLS_REDUCER_PROFILE_V1)
    {
        return Err(error("mls_governance_binding_reducer_profile_invalid"));
    }
    if binding.get("mls_group_id").and_then(Value::as_str) != Some(group_id) {
        return Err(error("mls_governance_binding_group_mismatch"));
    }
    if binding.get("next_epoch").and_then(Value::as_u64) != Some(epoch) {
        return Err(error("mls_governance_binding_next_epoch_mismatch"));
    }
    if binding.get("realm_id").and_then(Value::as_str) != Some(realm_id) {
        return Err(error("mls_governance_binding_realm_mismatch"));
    }
    let Some(scope) = binding.get("effective_scope").and_then(Value::as_object) else {
        return Err(error("mls_governance_binding_scope_missing"));
    };
    if scope.get("realm_id").and_then(Value::as_str) != Some(realm_id) {
        return Err(error("mls_governance_binding_scope_mismatch"));
    }
    match scope.get("kind").and_then(Value::as_str) {
        Some("realm") => {
            if binding.get("circle_id").is_some() {
                return Err(error("mls_governance_binding_scope_mismatch"));
            }
        }
        Some("circle") => {
            let Some(circle_id) = scope.get("circle_id").and_then(Value::as_str) else {
                return Err(error("mls_governance_binding_scope_mismatch"));
            };
            if binding.get("circle_id").and_then(Value::as_str) != Some(circle_id) {
                return Err(error("mls_governance_binding_scope_mismatch"));
            }
        }
        _ => return Err(error("mls_governance_binding_scope_missing")),
    }
    let Some(frontier) = binding.get("membership_frontier").and_then(Value::as_array) else {
        return Err(error("mls_governance_binding_membership_frontier_missing"));
    };
    if frontier.is_empty()
        || frontier
            .iter()
            .any(|value| value.as_str().is_none_or(str::is_empty))
    {
        return Err(error("mls_governance_binding_membership_frontier_missing"));
    }
    let Some(policy_root) = binding
        .get("policy_root")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("sha256:"))
    else {
        return Err(error("mls_governance_binding_policy_root_missing"));
    };
    if let Some(expected_policy_root) = expected_policy_root
        && policy_root != expected_policy_root
    {
        return Err(error("mls_governance_binding_policy_root_mismatch"));
    }
    Ok(())
}

pub(super) fn mimi_submit_has_covered_seals_cell(
    binding_payload: &Value,
    body: &Value,
    message: &Value,
    governance_binding: &Value,
) -> bool {
    let null = Value::Null;
    [
        governance_binding,
        message,
        body.get("associated_data").unwrap_or(&null),
        body.get("ciphertext").unwrap_or(&null),
        body,
        binding_payload,
    ]
    .into_iter()
    .any(|value| {
        value
            .get("covered_seals_cell")
            .or_else(|| value.get("covered_seals"))
            .is_some_and(non_empty_json_value)
    })
}

pub(super) fn non_empty_json_value(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(_) | Value::Number(_) => true,
        Value::String(value) => !value.trim().is_empty(),
        Value::Array(values) => !values.is_empty(),
        Value::Object(object) => !object.is_empty(),
    }
}

/// Emit a `ak.mimi.room_binding` projection event capturing the
/// binding state. Returns the generated event_id so the caller can
/// echo it back to the MIMI client. The binding payload is captured
/// verbatim under `payload.binding` and `mimi_room_id` is hoisted to
/// the top level so [`mimi_bound_realm_id`] can dispatch lookups
/// efficiently.
///
/// Returns `None` when the binding payload declares no Arkret
/// `realm_id` (neither under `binding_scope.realm_id` nor at the top
/// level). The caller is expected to surface that to the client as a
/// 400 rather than implicitly bind the room to some default Realm.
pub(super) async fn emit_mimi_room_binding_event(
    state: &AppState,
    room_id: &str,
    binding: &Value,
) -> Result<Option<String>, AppError> {
    let event_id = ids::generate_event_id();
    let realm_id = binding
        .get("binding_scope")
        .and_then(|s| s.get("realm_id"))
        .and_then(Value::as_str)
        .or_else(|| binding.get("realm_id").and_then(Value::as_str))
        .map(str::to_owned);
    let Some(realm_id) = realm_id else {
        return Ok(None);
    };
    validate_mimi_room_binding_payload(binding)?;
    enforce_mimi_room_binding_transition(state, room_id, binding).await?;
    let mimi_room_uri_value = binding
        .get("mimi_room_uri")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| mimi_room_uri(state, room_id));
    let record = ProjectionEventRecord {
        event_id: event_id.clone(),
        realm_id: realm_id.clone(),
        event_kind: "ak.mimi.room_binding".to_owned(),
        operation_type: "mimi_facade_room_binding".to_owned(),
        operation_id: None,
        sender: None,
        payload: json!({
            "profile": "ak.profile.mimi_interop.v1",
            "mimi_room_uri": mimi_room_uri_value,
            "mimi_room_id": room_id,
            "binding_scope": {
                "realm_id": realm_id,
                "strand_id": binding
                    .get("binding_scope")
                    .and_then(|s| s.get("strand_id"))
                    .cloned()
                    .unwrap_or(Value::Null),
            },
            "binding": binding.clone(),
            "mimi_provenance": {
                "facade": "soland.mimi.v1",
                "mimi_provider_id": mimi_provider_id(state),
                "accepted_at": chrono::Utc::now(),
            },
        }),
        created_at: chrono::Utc::now(),
        received_at: chrono::Utc::now(),
    };
    if let Err(error) =
        crate::routing::events::projection::persist_and_publish_projection_event(state, record)
            .await
    {
        tracing::error!(%error, "mimi: failed to append room_binding to projection_events");
    }
    Ok(Some(event_id))
}

pub(super) fn mimi_room_projection(state: &AppState, room_id: &str, realm_id: &str) -> Value {
    json!({
        "kind": "ak.mimi.room_binding",
        "profile": "ak.profile.mimi_interop.v1",
        "mimi_room_uri": mimi_room_uri(state, room_id),
        "binding_scope": {
            "realm_id": realm_id,
            "channel_id": Value::Null
        },
        "hub_provider": state.service_id().clone(),
        "local_provider_role": "hub",
        "mls_group_id": format!("mls:{}", room_id),
        "policy_root": arkret_canonical::sha256_digest(format!("{realm_id}:{room_id}:policy").as_bytes()),
        "status": "accepted",
        "canonical_truth": "arkret_signed_event_reducer"
    })
}

pub(super) fn unsupported_mimi_draft(body: &Value) -> Option<&'static str> {
    for (field, expected, message) in [
        (
            "protocol_draft",
            "draft-ietf-mimi-protocol-06",
            "unsupported MIMI protocol draft",
        ),
        (
            "content_draft",
            "draft-ietf-mimi-content-08",
            "unsupported MIMI content draft",
        ),
        (
            "room_policy_draft",
            "draft-ietf-mimi-room-policy-03",
            "unsupported MIMI room policy draft",
        ),
        (
            "identifier_draft",
            "draft-kohbrok-mimi-identifiers-01",
            "unsupported MIMI identifier draft",
        ),
    ] {
        let value = body
            .get(field)
            .or_else(|| body.get("mimi").and_then(|mimi| mimi.get(field)))
            .and_then(|value| value.as_str());
        if value.is_some_and(|value| value != expected) {
            return Some(message);
        }
    }
    None
}

pub(super) fn valid_mimi_room_id(room_id: &str) -> bool {
    !room_id.is_empty()
        && room_id.len() <= 256
        && room_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':' | '~'))
}

pub(super) fn valid_mimi_content_type(value: &str) -> bool {
    matches!(
        value,
        "application/mimi-content"
            | "text/plain;charset=utf-8"
            | "text/markdown;variant=GFM-MIMI"
            | "application/vnd.arkret.content+json"
    )
}

