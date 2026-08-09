use super::*;

pub(super) fn realm_frozen_operation_exempt(kind: &arkret_wire::EventKind) -> bool {
    arkret_wire::events::kinds::is_audit_kind(kind)
        || matches!(
            kind,
            arkret_wire::EventKind::RealmArchive
                | arkret_wire::EventKind::RealmFreeze
                | arkret_wire::EventKind::RealmTombstone
                | arkret_wire::EventKind::RealmDestroy
        )
}

pub(super) fn validate_realm_lifecycle_write_gate(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let kind = kinds::canonical_kind(operation);
    let realm_id = operation.realm_id.as_str();
    let projection = state.projections().snapshot();
    if projection.realm_is_in_terminal_state(realm_id)
        && !arkret_wire::events::kinds::is_audit_kind(&kind)
    {
        return Err("realm_terminal_state");
    }
    if projection.realm_is_frozen_at(realm_id, chrono::Utc::now())
        && !realm_frozen_operation_exempt(&kind)
    {
        return Err(arkret_wire::ErrorCode::REALM_FROZEN);
    }
    Ok(())
}

/// `morph.md` §4.1 S3 — the actor MUST hold the high-tier
/// `ak.morph.schema_migrate` capability at the event frontier. The effective
/// Realm-owner aggregate is also a registered source for this Event kind.
/// The opt-in profile gate and CAS are enforced by the state-aware preflight;
/// this check is the capability conjunct only.
pub(super) async fn validate_morph_schema_migrate_authz(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let Some(actor) = policy_operation_sender(operation) else {
        return Err("capability_denied");
    };
    let realm_id = operation.realm_id.as_str();
    if state
        .projections()
        .snapshot()
        .actor_holds_effective_realm_owner(realm_id, actor, operation.created_at)
    {
        return Ok(());
    }
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    if state
        .authorization()
        .check(soland_services::authorization::AuthorizationCheck {
            actor,
            action: arkret_wire::EventKind::MorphSchemaMigrate.as_str(),
            resource: realm_id,
            realm_id,
            owner: owner.as_deref(),
            members: &members,
            resource_facets: &[],
        })
        .allowed
    {
        return Ok(());
    }
    Err("capability_denied")
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
        let (owner, members) = realm_owner_and_members(state, realm_id).await;
        let verdict =
            state
                .authorization()
                .check(soland_services::authorization::AuthorizationCheck {
                    actor,
                    action: arkret_wire::CapabilityActionId::SELF_AGENT_SIDECAR_COMMAND_ENSURE,
                    resource: realm_id,
                    realm_id,
                    owner: owner.as_deref(),
                    members: &members,
                    resource_facets: &[],
                });
        if verdict.allowed
            || members.iter().any(|member| member == actor)
            || policy_realm_member_joined(state, realm_id, actor)
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
    if state
        .projections()
        .snapshot()
        .actor_holds_effective_realm_owner(realm_id, actor, operation.created_at)
    {
        return Ok(());
    }
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    if state
        .authorization()
        .check(soland_services::authorization::AuthorizationCheck {
            actor,
            action: arkret_wire::CapabilityActionId::CIRCLE_CREATE,
            resource: realm_id,
            realm_id,
            owner: owner.as_deref(),
            members: &members,
            resource_facets: &[],
        })
        .allowed
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
    let (action, reason) = match kind {
        arkret_wire::EventKind::CircleUpdate
        | arkret_wire::EventKind::CircleArchive
        | arkret_wire::EventKind::CircleRestore
        | arkret_wire::EventKind::CircleTombstone => {
            ("ak.circle.manage", "circle_manage_capability_required")
        }
        arkret_wire::EventKind::CircleMemberState
            if circle_member_manage_required(state, operation) =>
        {
            (
                "ak.circle.member.manage",
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
    if state
        .projections()
        .snapshot()
        .actor_holds_effective_realm_owner(realm_id, actor, operation.created_at)
    {
        return Ok(());
    }
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    if state
        .authorization()
        .check(soland_services::authorization::AuthorizationCheck {
            actor,
            action,
            resource: circle_id,
            realm_id,
            owner: owner.as_deref(),
            members: &members,
            resource_facets: &[],
        })
        .allowed
    {
        return Ok(());
    }
    Err(reason)
}

/// Policy-layer acting-principal accessor.
///
/// The executing principal is an accepted envelope fact. Payload `actor_id`
/// fields name targets and must never participate in authorization.
pub(super) fn policy_operation_sender(operation: &Operation) -> Option<&str> {
    Some(operation.context.sender.as_str())
}

pub(super) fn operation_circle_id(operation: &Operation) -> Option<&str> {
    operation
        .payload
        .get("circle_id")
        .and_then(Value::as_str)
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
    let Some(target) = operation.payload.get("actor_id").and_then(Value::as_str) else {
        return false;
    };
    let membership = operation
        .payload
        .get("membership")
        .and_then(Value::as_str)
        .unwrap_or("join");
    match membership {
        "invite" | "ban" => true,
        "join" if target == actor => {
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
        _ => target != actor,
    }
}

pub(super) fn policy_realm_member_joined(state: &AppState, realm_id: &str, actor: &str) -> bool {
    {
        let projection = state.projections().snapshot();
        {
            projection
                .member(realm_id, actor)
                .map(|membership| membership.state == "join")
        }
    }
    .unwrap_or(false)
}

pub(super) fn sidecar_circle_object_shape_is_constrained(
    _operation: &Operation,
    _actor: &str,
    _sidecar_id: &str,
) -> bool {
    false
}
