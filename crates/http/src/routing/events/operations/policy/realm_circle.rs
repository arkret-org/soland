use arkret_models_collaboration::agent_operations::AgentLifecycleState;

use super::*;

pub(super) fn realm_frozen_operation_exempt(kind: &str) -> bool {
    arkret_wire::events::kinds::is_audit_kind(kind)
        || matches!(
            kind,
            arkret_wire::EventKind::REALM_ARCHIVE
                | arkret_wire::EventKind::REALM_FREEZE
                | arkret_wire::EventKind::REALM_TOMBSTONE
                | arkret_wire::EventKind::REALM_DESTROY
        )
}

pub(super) fn validate_realm_lifecycle_write_gate(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let kind = kinds::canonical_kind_string(operation);
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
/// `ak.morph.schema_migrate` capability at the event frontier. Missing
/// capability yields `capability_denied`. Realm ownership does not substitute
/// for the grant. The opt-in profile gate and CAS are enforced by the
/// state-aware preflight; this check is the capability conjunct only.
pub(super) async fn validate_morph_schema_migrate_authz(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let Some(actor) = policy_operation_sender(operation) else {
        return Err("capability_denied");
    };
    let realm_id = operation.realm_id.as_str();
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    if state
        .authorization()
        .check(soland_services::authorization::AuthorizationCheck {
            actor,
            action: arkret_wire::EventKind::MORPH_SCHEMA_MIGRATE,
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
    if kinds::canonical_kind_for_operation(operation) != Some(arkret_wire::EventKind::CIRCLE_CREATE)
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
        arkret_wire::EventKind::CIRCLE_UPDATE
        | arkret_wire::EventKind::CIRCLE_ARCHIVE
        | arkret_wire::EventKind::CIRCLE_RESTORE
        | arkret_wire::EventKind::CIRCLE_TOMBSTONE => {
            ("ak.circle.manage", "circle_manage_capability_required")
        }
        arkret_wire::EventKind::CIRCLE_MEMBER_STATE
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

pub(super) async fn sidecar_member_state_shape_is_constrained(
    state: &AppState,
    operation: &Operation,
    controller: &str,
    circle_id: &str,
) -> bool {
    if kinds::canonical_kind_for_operation(operation)
        != Some(arkret_wire::EventKind::CIRCLE_MEMBER_STATE)
    {
        return false;
    }
    if operation.payload.get("membership").and_then(Value::as_str) != Some("join") {
        return false;
    }
    let Some(target) = operation.payload.get("actor_id").and_then(Value::as_str) else {
        return false;
    };
    let realm_id = operation.realm_id.as_str();
    {
        let projection = state.projections().snapshot();
        let Some(circle) = projection.circle(circle_id) else {
            return false;
        };
        if circle.realm_id != realm_id
            || circle.profile_ref.is_some()
            || circle.title != "Agent Sidecar Scope"
            || circle.created_by != controller
            || !circle
                .display
                .pointer("/short_name")
                .and_then(Value::as_str)
                .is_some_and(|short_name| short_name.starts_with("SC-"))
        {
            return false;
        }
    }
    if !policy_realm_member_joined(state, realm_id, target) {
        return false;
    }
    if target == controller {
        return true;
    }
    let Ok(records) = state
        .agent_pairings()
        .agents_for_controller(controller)
        .await
    else {
        return false;
    };
    let record_matches = records.iter().any(|record| {
        record.id == target
            && record.controller_id == controller
            && record.state == AgentLifecycleState::Active
    });
    if !record_matches {
        return false;
    }
    let projection = state.projections().snapshot();
    !matches!(
        projection.agent_lifecycles.get(target),
        Some(
            arkret_models_collaboration::agent_operations::AgentLifecycleState::Paused
                | arkret_models_collaboration::agent_operations::AgentLifecycleState::Deactivated
        )
    ) && projection.agent_has_authorized_key(target)
}

/// Policy-layer acting-principal accessor.
///
/// Unlike [`Operation::actor`], which probes `actor_id` before `sender`, the
/// policy layer must resolve the *executing* principal. For membership events
/// (e.g. arkret_wire::EventKind::CIRCLE_MEMBER_STATE) the `actor_id` field names the
/// *target* member, not the executor, so preferring it would let a forged verdict pass its own
/// authorization gate. This accessor therefore resolves the executor as
/// `sender` → `actor_id` → `created_by`, matching the historical soland
/// contract.
pub(super) fn policy_operation_sender(operation: &Operation) -> Option<&str> {
    operation
        .payload
        .get("sender")
        .or_else(|| operation.payload.get("actor_id"))
        .or_else(|| operation.payload.get("created_by"))
        // Full-object create payloads keep the executor on the object.
        .or_else(|| {
            operation
                .payload
                .get("object")
                .and_then(|object| object.get("created_by"))
        })
        .and_then(Value::as_str)
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
    operation: &Operation,
    actor: &str,
    sidecar_id: &str,
) -> bool {
    if kinds::canonical_kind_for_operation(operation) != Some(arkret_wire::EventKind::CIRCLE_CREATE)
    {
        return false;
    }
    let payload = &operation.payload;
    let Some(object) = payload.get("object").and_then(Value::as_object) else {
        return false;
    };
    let realm_id = operation.realm_id.as_str();
    if object.get("realm_id").and_then(Value::as_str) != Some(realm_id) {
        return false;
    }
    if object.get("created_by").and_then(Value::as_str) != Some(actor) {
        return false;
    }
    if object.get("profile_ref").is_some() {
        return false;
    }
    if object.get("directory_visibility").and_then(Value::as_str) != Some("members") {
        return false;
    }
    if object.get("join_rule").and_then(Value::as_str) != Some("invite") {
        return false;
    }
    if object.get("history_visibility").and_then(Value::as_str) != Some("restricted") {
        return false;
    }
    // Sidecars are never a plaintext escape hatch. The reserved aggregate is
    // stricter than an ordinary Circle: both floors and the profile are fixed
    // to MLS E2EE even when the parent principal-control Realm permits
    // plaintext. `ensure` may only return after this exact shape is projected,
    // which lets clients select the encrypted composer without a downgrade.
    if object
        .get("content_encryption_floor")
        .and_then(Value::as_str)
        != Some("e2ee_required")
        || object
            .get("metadata_encryption_floor")
            .and_then(Value::as_str)
            != Some("e2ee_required")
        || object.get("encryption_profile").and_then(Value::as_str) != Some("mls_rfc9420")
    {
        return false;
    }
    let expected_short_name =
        arkret_wire::constants::agent_sidecar_backing_circle_short_name(sidecar_id);
    object.get("title").and_then(Value::as_str) == Some("Agent Sidecar Scope")
        && object.get("summary").is_none()
        && object
            .get("display")
            .and_then(|display| display.get("short_name"))
            .and_then(Value::as_str)
            == Some(expected_short_name.as_str())
        && object
            .get("display")
            .and_then(|display| display.pointer("/symbol/glyph"))
            .and_then(Value::as_str)
            == Some("lock")
}
