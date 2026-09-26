use super::*;

pub(super) fn validate_realm_lifecycle_write_gate(
    state: &AppState,
    operation: &Operation,
    operations: &[Operation],
) -> Result<(), &'static str> {
    let kind = kinds::canonical_kind(operation);
    let realm_id = operation.realm_id.as_str();
    let projection = state.projections().snapshot();
    if projection.realm_is_in_terminal_state(realm_id)
        && !arkret_wire::events::kinds::is_audit_kind(&kind)
    {
        return Err("realm_terminal_state");
    }
    // A new Realm's closed founding batch has no durable projection yet.
    // Its genesis and registered follow-ups use initial facets, while actual
    // archive/freeze cells are always enforced. Batch validation still owns
    // the complete founding shape and authority checks.
    let is_registered_bootstrap_kind = arkret_schema::REALM_BOOTSTRAP_PROFILES
        .iter()
        .flat_map(|profile| profile.ordered_slots)
        .any(|slot| slot.event_kind == kind.as_str());
    let staged_creation = is_registered_bootstrap_kind
        && operations.iter().any(|candidate| {
            kinds::canonical_kind_for_operation(candidate)
                == Some(arkret_wire::EventKind::RealmCreate)
                && candidate.realm_id == operation.realm_id
        });
    let blocked = projection.realm_is_archived(realm_id)
        || projection.realm_is_frozen(realm_id)
        || (!staged_creation && projection.realm_ordinary_writes_blocked(realm_id));
    if blocked && !arkret_wire::events::kinds::realm_write_gate_exempt(&kind, &operation.payload) {
        return Err(arkret_wire::ErrorCode::REALM_FROZEN);
    }
    Ok(())
}

pub(super) async fn validate_circle_create_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    if kinds::canonical_kind_for_operation(operation) != Some(arkret_wire::EventKind::CircleCreate)
    {
        return Ok(());
    }
    if let Some(sidecar_id) = operation
        .payload
        .get("trusted_sidecar_id")
        .and_then(Value::as_str)
    {
        let Some(actor) = policy_operation_sender(operation) else {
            return Err("sidecar_create_denied");
        };
        if !sidecar_circle_object_shape_is_constrained(operation, actor, sidecar_id) {
            return Err("sidecar_create_denied");
        }
        let realm_id = operation.realm_id.as_str();
        if policy_realm_member_joined(state, realm_id, actor)
            || crate::authz::actor_may(
                state,
                realm_id,
                actor,
                &[arkret_wire::CapabilityActionId::SELF_AGENT_SIDECAR_COMMAND_ENSURE_V1],
                realm_id,
                operation.created_at,
            )
            .await?
        {
            return Ok(());
        }
        return Err("sidecar_create_denied");
    }
    if operation
        .payload
        .pointer("/object/display/short_name")
        .and_then(Value::as_str)
        .is_some_and(|short_name| short_name.starts_with("SC-"))
        || operation
            .payload
            .pointer("/object/title")
            .and_then(Value::as_str)
            == Some("Agent Sidecar Scope")
    {
        return Err("sidecar_create_denied");
    }
    let Some(actor) = policy_operation_sender(operation) else {
        return Ok(());
    };
    let realm_id = operation.realm_id.as_str();
    if crate::authz::actor_may(
        state,
        realm_id,
        actor,
        &[arkret_wire::CapabilityActionId::CIRCLE_CREATE],
        realm_id,
        operation.created_at,
    )
    .await?
    {
        return Ok(());
    }
    Err("missing_capability")
}

pub(super) async fn validate_circle_management_policy(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let Some(kind) = kinds::canonical_kind_for_operation(operation) else {
        return Ok(());
    };
    if kind == arkret_wire::EventKind::CircleMemberState
        && operation.payload.get("membership").and_then(Value::as_str) == Some("join")
        && let Some(target) = operation
            .payload
            .get("member_id")
            .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value.clone()).ok())
        && !policy_realm_member_joined(state, operation.realm_id.as_str(), &target)
    {
        return Err("circle_member_must_be_realm_member");
    }
    let (action, reason) = match kind {
        arkret_wire::EventKind::CircleUpdate
        | arkret_wire::EventKind::CircleArchive
        | arkret_wire::EventKind::CircleRestore
        | arkret_wire::EventKind::CircleTombstone => (
            arkret_wire::CapabilityActionId::CIRCLE_MANAGE,
            "circle_manage_capability_required",
        ),
        arkret_wire::EventKind::CircleMemberState
            if circle_member_manage_required(state, operation) =>
        {
            (
                arkret_wire::CapabilityActionId::CIRCLE_MEMBER_MANAGE,
                "circle_member_manage_capability_required",
            )
        }
        _ => return Ok(()),
    };
    let Some(actor) = policy_operation_sender(operation) else {
        return Ok(());
    };
    let Some(circle_id) = operation_circle_id(operation) else {
        return Ok(());
    };
    if state
        .projections()
        .snapshot()
        .circle(circle_id)
        .is_some_and(|circle| {
            circle.title == "Agent Sidecar Scope"
                || circle
                    .display
                    .pointer("/short_name")
                    .and_then(Value::as_str)
                    .is_some_and(|short_name| short_name.starts_with("SC-"))
        })
    {
        return Err("sidecar_create_denied");
    }
    let realm_id = operation.realm_id.as_str();
    if crate::authz::actor_may(
        state,
        realm_id,
        actor,
        &[action],
        circle_id,
        operation.created_at,
    )
    .await?
    {
        return Ok(());
    }
    Err(reason)
}

/// Policy-layer acting-principal accessor.
///
/// The executing principal is an accepted envelope fact. Payload `actor_id`
/// fields name targets and must never participate in authorization.
pub(super) fn policy_operation_sender(operation: &Operation) -> Option<&arkret_wire::ActorId> {
    Some(&operation.context.sender)
}

pub(super) fn operation_circle_id(operation: &Operation) -> Option<&str> {
    operation
        .payload
        .get("circle_id")
        .and_then(Value::as_str)
        .or_else(|| operation.payload.get("target_ref").and_then(Value::as_str))
        .or_else(|| {
            operation
                .payload
                .get("object")
                .and_then(|object| object.get("id"))
                .and_then(Value::as_str)
        })
}

pub(super) fn circle_member_manage_required(state: &AppState, operation: &Operation) -> bool {
    let Some(actor) = policy_operation_sender(operation) else {
        return false;
    };
    let Some(target) = operation
        .payload
        .get("member_id")
        .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value.clone()).ok())
    else {
        return false;
    };
    let membership = operation
        .payload
        .get("membership")
        .and_then(Value::as_str)
        .unwrap_or("join");
    match membership {
        "invite" | "ban" => true,
        "join" if target == *actor => {
            let Some(circle_id) = operation_circle_id(operation) else {
                return false;
            };
            {
                let projection = state.projections().snapshot();
                {
                    projection
                        .circle(circle_id)
                        .map(|circle| circle.join_rule != "public")
                }
            }
            .unwrap_or(false)
        }
        _ => target != *actor,
    }
}

pub(super) fn policy_realm_member_joined(
    state: &AppState,
    realm_id: &str,
    actor: &arkret_wire::ActorId,
) -> bool {
    {
        let projection = state.projections().snapshot();
        {
            projection
                .member(realm_id, &actor.to_string())
                .map(|membership| membership.state == "join")
        }
    }
    .unwrap_or(false)
}

pub(super) fn sidecar_circle_object_shape_is_constrained(
    _operation: &Operation,
    _actor: &arkret_wire::ActorId,
    _sidecar_id: &str,
) -> bool {
    false
}
