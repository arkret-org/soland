use arkret_wire::{CORE_REDUCER_PROFILE, ProfileId};

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
) -> Result<Option<MimiRoomBindingProjection>, AppError> {
    let entries = state
        .event_queries()
        .projected_events_for_kind(arkret_wire::EventKind::MimiRoomBinding)
        .await
        .map_err(|error| AppError::internal(format!("MIMI binding lookup failed: {error}")))?;
    // Walk in reverse so the most-recently-recorded binding wins.
    for entry in entries.iter().rev() {
        if entry.event_kind != arkret_wire::EventKind::MimiRoomBinding {
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
            let Some(realm_id) = entry
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
                .or_else(|| binding_payload.get("realm_id").and_then(Value::as_str))
            else {
                continue;
            };
            return Ok(Some(MimiRoomBindingProjection {
                event_id: entry.event_id.clone(),
                realm_id: realm_id.to_owned(),
                binding: binding.clone(),
            }));
        }
    }
    Ok(None)
}

pub(super) async fn mimi_bound_realm_id(
    state: &AppState,
    room_id: &str,
) -> Result<Option<String>, AppError> {
    latest_mimi_room_binding(state, room_id)
        .await
        .map(|binding| binding.map(|binding| binding.realm_id))
}

pub(super) fn enforce_mimi_submit_binding(
    room_binding: &MimiRoomBindingProjection,
    body: &MimiSubmitMessageRequestBody,
    message: &Value,
    associated_data: Option<&Value>,
) -> Result<(), AppError> {
    validate_mimi_room_binding_payload(&room_binding.binding)?;
    let binding_payload = mimi_room_binding_security_payload(&room_binding.binding);
    match binding_payload.get("status").and_then(Value::as_str) {
        Some("accepted") => {}
        Some(_) | None => {
            return Err(AppError::param_invalid(
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
                AppError::param_invalid("MIMI room binding has no writable provider role")
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
    let submit_group_id = mimi_submit_mls_group_id(body).ok_or_else(|| {
        AppError::param_invalid("MIMI submit_message is missing mls_group_id")
            .with_wire_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISMATCH)
    })?;
    if submit_group_id != binding_group_id {
        return Err(AppError::param_invalid(
            "MIMI submit_message mls_group_id does not match room binding",
        )
        .with_wire_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISMATCH));
    }
    let epoch = mimi_submit_epoch(body).ok_or_else(|| {
        AppError::param_invalid("MIMI submit_message is missing MLS epoch")
            .with_wire_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISMATCH)
    })?;
    let governance_binding =
        mimi_governance_binding_candidate(binding_payload, message, associated_data).ok_or_else(
            || {
                AppError::param_invalid("MIMI submit_message lacks governance_binding")
                    .with_wire_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISSING)
            },
        )?;
    validate_mimi_submit_governance_binding(
        governance_binding,
        &room_binding.realm_id,
        binding_group_id,
        epoch,
    )?;
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
            AppError::param_invalid("MIMI room binding requires hub_provider")
                .with_wire_code(arkret_wire::ReasonCode::MIMI_ROOM_STATE_INCOMPATIBLE),
        );
    }
    match payload.get("local_provider_role").and_then(Value::as_str) {
        Some("hub" | "follower" | "observer") => {}
        _ => {
            return Err(AppError::param_invalid(
                "MIMI room binding requires a known local_provider_role",
            )
            .with_wire_code(arkret_wire::ReasonCode::MIMI_ROOM_STATE_INCOMPATIBLE));
        }
    }
    match payload.get("status").and_then(Value::as_str) {
        Some("proposed" | "accepted" | "revoked" | "migrating") => Ok(()),
        _ => Err(
            AppError::param_invalid("MIMI room binding requires a lifecycle status")
                .with_wire_code(arkret_wire::ReasonCode::MIMI_ROOM_STATE_INCOMPATIBLE),
        ),
    }
}

pub(super) fn mimi_room_binding_security_payload(binding: &Value) -> &Value {
    binding
        .get("payload")
        .filter(|payload| payload.is_object())
        .unwrap_or(binding)
}

pub(super) fn mimi_submit_mls_group_id(body: &MimiSubmitMessageRequestBody) -> Option<&str> {
    body.mls_group_id
        .as_ref()
        .map(MlsGroupId::as_str)
        .filter(|value| !value.trim().is_empty())
}

pub(super) fn mimi_submit_epoch(body: &MimiSubmitMessageRequestBody) -> Option<u64> {
    body.epoch
}

pub(super) fn mimi_governance_binding_candidate<'a>(
    binding_payload: &'a Value,
    message: &'a Value,
    associated_data: Option<&'a Value>,
) -> Option<&'a Value> {
    governance_binding_field(message)
        .or_else(|| associated_data.and_then(governance_binding_field))
        .or_else(|| governance_binding_field(binding_payload))
}

/// `governance_binding` is the canonical carrier name in every schema that
/// defines the object (`event-payload.schema.json#/$defs/mls_governance_binding`
/// and `mls-governance-proof-bundle.schema.json`); no spec schema defines a
/// field named `mls_governance_binding`.
pub(super) fn governance_binding_field(value: &Value) -> Option<&Value> {
    crate::routing::mls::payload_fields::governance_binding(value)
}

pub(super) fn validate_mimi_submit_governance_binding(
    binding: &Value,
    realm_id: &str,
    group_id: &str,
    epoch: u64,
) -> Result<(), AppError> {
    let error = |reason: &'static str| {
        AppError::param_invalid("MIMI submit_message governance_binding is not valid")
            .with_wire_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISMATCH)
            .with_reason_detail(reason)
    };
    let binding: arkret_models_crypto::MlsGovernanceBindingPayload =
        serde_json::from_value(binding.clone())
            .map_err(|_| error("mls_governance_binding_invalid"))?;
    binding
        .validate()
        .map_err(|_| error("mls_governance_binding_invalid"))?;
    if binding.mls_group_id() != group_id || binding.next_epoch() != epoch {
        return Err(error("mls_governance_binding_generation_mismatch"));
    }
    if binding.realm_id().as_str() != realm_id
        || binding.effective_scope().realm_id().as_str() != realm_id
    {
        return Err(error("mls_governance_binding_scope_mismatch"));
    }
    if binding.binding_profile() != ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1
        || binding.reducer_profile() != CORE_REDUCER_PROFILE
    {
        return Err(error("mls_governance_binding_profile_invalid"));
    }
    Ok(())
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

/// Admit the exact caller-authored room-binding Event carried by a MIMI update.
pub(super) async fn admit_mimi_room_binding_event(
    state: &AppState,
    room_id: &str,
    update_body: &Value,
    binding: &Value,
    submission: Value,
) -> Result<String, AppError> {
    let submission: arkret_wire::EventInitialSubmission = serde_json::from_value(submission)
        .map_err(|error| {
            AppError::param_invalid(format!("MIMI room binding Event is invalid: {error}"))
                .with_wire_code("schema_violation")
        })?;
    let realm_id = binding
        .get("binding_scope")
        .and_then(|s| s.get("realm_id"))
        .and_then(Value::as_str)
        .or_else(|| binding.get("realm_id").and_then(Value::as_str))
        .ok_or_else(|| {
            AppError::param_invalid(
                "room_binding requires `binding_scope.realm_id` or a top-level `realm_id`",
            )
            .with_wire_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISSING)
        })?;
    validate_mimi_room_binding_payload(binding)?;
    let expected_room_uri = mimi_room_uri(state, room_id)?;
    let event = &submission.event;
    let sender_actor_id = update_body
        .get("sender_actor_id")
        .cloned()
        .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value).ok())
        .ok_or_else(|| {
            AppError::param_invalid("room binding update requires sender_actor_id")
                .with_wire_code("mimi_room_binding_event_invalid")
        })?;
    let binding_group_id = binding.get("mls_group_id").and_then(Value::as_str);
    let update_group_id = update_body.get("mls_group_id").and_then(Value::as_str);
    if event.kind != arkret_wire::EventKind::MimiRoomBinding
        || event.realm_id.as_str() != realm_id
        || event.actor_id != sender_actor_id
        || serde_json::to_value(&event.payload).ok().as_ref() != Some(binding)
        || binding.get("mimi_room_uri").and_then(Value::as_str) != Some(expected_room_uri.as_str())
        || binding_group_id.is_none()
        || binding_group_id != update_group_id
    {
        return Err(AppError::param_invalid(
            "room_binding_event does not match the authenticated MIMI room update",
        )
        .with_wire_code("mimi_room_binding_event_invalid"));
    }
    let sender_account = local_mimi_sender_account(&sender_actor_id, &state.service_core_id())?;
    let device_id = event
        .proofs
        .first()
        .and_then(arkret_wire::EventProof::as_producer)
        .and_then(|proof| proof.verification_method.as_str().rsplit_once('#'))
        .map(|(_, fragment)| fragment.to_owned())
        .ok_or_else(|| {
            AppError::param_invalid("MIMI room binding Event requires a DID URL proof key")
                .with_wire_code("invalid_proof")
        })?;
    let now = chrono::Utc::now();
    let session = soland_services::identity::SessionIdentityState {
        account_pk: None,
        token_hash: format!("mimi-room-binding:{}", event.event_id),
        actor: sender_account.principal_id.to_string(),
        device_id,
        audience: sender_account.station_id.to_string(),
        session_public_key: None,
        agent_session: None,
        session_grant: None,
        expires_at: now + chrono::Duration::minutes(5),
        created_at: now,
        revoked_at: None,
    };
    let event_id = event.event_id.to_string();
    crate::routing::events::event_log::submit_initial_event_submission(state, &session, submission)
        .await
        .map_err(|error| {
            crate::routing::events::event_log::submit_one_error_to_app_error(
                "MIMI room binding Event submit failed",
                error.status,
                error.code,
                &error.message,
            )
        })?;
    Ok(event_id)
}

// This local submit path has no accepted foreign-account authority bridge.
// Do not manufacture one from a provider signature or from a bare principal.
fn local_mimi_sender_account(
    actor: &arkret_wire::ActorId,
    local_station: &arkret_wire::DidCoreId,
) -> Result<arkret_wire::AccountId, AppError> {
    actor
        .as_account_id()
        .filter(|account| &account.station_id == local_station)
        .cloned()
        .ok_or_else(|| {
            AppError::capability_denied("MIMI room binding requires a proven local Account sender")
        })
}

#[cfg(test)]
mod local_sender_tests {
    use super::*;

    #[test]
    fn room_binding_never_relabels_a_foreign_or_service_sender_as_a_local_account() {
        let principal = arkret_wire::DidCoreId::new("ak:did_core:web:sender.example").unwrap();
        let station = arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let account = arkret_wire::AccountId::new(principal.clone(), station.clone());
        assert_eq!(
            local_mimi_sender_account(&arkret_wire::ActorId::account(account.clone()), &station)
                .unwrap(),
            account,
        );
        for rejected in [
            arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                principal.clone(),
                arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
            )),
            arkret_wire::ActorId::service(principal),
        ] {
            assert!(local_mimi_sender_account(&rejected, &station).is_err());
        }
    }
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
