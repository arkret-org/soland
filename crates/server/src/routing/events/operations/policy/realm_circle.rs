use super::*;

pub(super) fn realm_frozen_operation_exempt(kind: &str) -> bool {
    arkret_sdk::events::kinds::is_audit_kind(kind)
        || matches!(
            kind,
            arkret_sdk::events::EventKind::REALM_ARCHIVE
                | arkret_sdk::events::EventKind::REALM_FREEZE
                | arkret_sdk::events::EventKind::REALM_TOMBSTONE
                | arkret_sdk::events::EventKind::REALM_DESTROY
        )
}

pub(super) fn validate_realm_lifecycle_write_gate(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let kind = kinds::canonical_kind_string(operation);
    let realm_id = operation.realm_id.as_str();
    let projection = state.projection.lock();
    if projection.realm_is_in_terminal_state(realm_id)
        && !arkret_sdk::events::kinds::is_audit_kind(&kind)
    {
        return Err("realm_terminal_state");
    }
    if projection.realm_is_frozen_at(realm_id, chrono::Utc::now())
        && !realm_frozen_operation_exempt(&kind)
    {
        return Err(arkret_sdk::ErrorCode::REALM_FROZEN);
    }
    Ok(())
}

/// `morph.md` §4.1 S3 — the actor MUST hold the high-tier
/// `ak.morph.schema_migrate` capability at the event frontier. Missing
/// capability yields `capability_denied`. Realm owners are implicitly
/// authorized (mirrors the other Realm-object capability gates). The opt-in
/// profile gate and CAS are enforced by the state-aware preflight; this check
/// is the capability conjunct only.
pub(super) async fn validate_morph_schema_migrate_authz(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let Some(actor) = policy_operation_sender(operation) else {
        return Err("capability_denied");
    };
    let realm_id = operation.realm_id.as_str();
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    if owner.as_deref() == Some(actor) {
        return Ok(());
    }
    if state
        .authz
        .check(
            actor,
            arkret_sdk::events::EventKind::MORPH_SCHEMA_MIGRATE,
            realm_id,
            realm_id,
            owner.as_deref(),
            &members,
            &[],
        )
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
    if kinds::canonical_kind_for_operation(operation)
        != Some(arkret_sdk::events::EventKind::CIRCLE_CREATE)
    {
        return Ok(());
    }
    if payload_asserts_agent_sidecar_ensure(&operation.payload) {
        let Some(actor) = policy_operation_sender(operation) else {
            return Err("sidecar_create_denied");
        };
        if !sidecar_circle_create_shape_is_constrained(&operation.payload, operation, actor) {
            return Err("sidecar_create_denied");
        }
        let realm_id = operation.realm_id.as_str();
        let (owner, members) = realm_owner_and_members(state, realm_id).await;
        let verdict = state.authz.check(
            actor,
            arkret_sdk::CapabilityActionId::SELF_AGENT_SIDECAR_THREAD_COMMAND_ENSURE,
            realm_id,
            realm_id,
            owner.as_deref(),
            &members,
            &[],
        );
        if verdict.allowed
            || members.iter().any(|member| member == actor)
            || policy_realm_member_joined(state, realm_id, actor)
        {
            return Ok(());
        }
        return Err("sidecar_create_denied");
    }
    let Some(actor) = policy_operation_sender(operation) else {
        return Ok(());
    };
    let realm_id = operation.realm_id.as_str();
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    if state
        .authz
        .check(
            actor,
            arkret_sdk::CapabilityActionId::CIRCLE_CREATE,
            realm_id,
            realm_id,
            owner.as_deref(),
            &members,
            &[],
        )
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
        arkret_sdk::events::EventKind::CIRCLE_UPDATE
        | arkret_sdk::events::EventKind::CIRCLE_ARCHIVE
        | arkret_sdk::events::EventKind::CIRCLE_RESTORE
        | arkret_sdk::events::EventKind::CIRCLE_TOMBSTONE => {
            ("ak.circle.manage", "circle_manage_capability_required")
        }
        arkret_sdk::events::EventKind::CIRCLE_MEMBER_STATE
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
    let realm_id = operation.realm_id.as_str();
    let (owner, members) = realm_owner_and_members(state, realm_id).await;
    if state
        .authz
        .check(
            actor,
            action,
            circle_id,
            realm_id,
            owner.as_deref(),
            &members,
            &[],
        )
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
    if operation.payload.get("membership").and_then(Value::as_str) != Some("join") {
        return false;
    }
    let Some(target) = operation.payload.get("actor_id").and_then(Value::as_str) else {
        return false;
    };
    let realm_id = operation.realm_id.as_str();
    {
        let projection = state.projection.lock();
        let Some(circle) = projection.circle(circle_id) else {
            return false;
        };
        if circle.realm_id != realm_id
            || circle.profile_ref.as_deref() != Some(arkret_sdk::PROFILE_AGENT_SIDECAR_THREAD)
            || circle.created_by != controller
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
        .persistence
        .agents()
        .list_for_controller(controller)
        .await
    else {
        return false;
    };
    let record_matches = records.iter().any(|record| {
        record.id == target && record.controller_id == controller && record.state == "active"
    });
    if !record_matches {
        return false;
    }
    let projection = state.projection.lock();
    !matches!(
        projection.agent_lifecycles.get(target),
        Some(
            arkret_sdk::AgentLifecycleState::Paused | arkret_sdk::AgentLifecycleState::Deactivated
        )
    ) && projection.agent_has_authorized_key(target)
}

/// Policy-layer acting-principal accessor.
///
/// Unlike [`Operation::actor`], which probes `actor_id` before `sender`, the
/// policy layer must resolve the *executing* principal. For membership events
/// (e.g. arkret_sdk::events::EventKind::CIRCLE_MEMBER_STATE) the `actor_id` field names the
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
                let projection = state.projection.lock();
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
        let projection = state.projection.lock();
        {
            projection
                .member(realm_id, actor)
                .map(|membership| membership.state == "join")
        }
    }
    .unwrap_or(false)
}

pub(super) fn payload_asserts_agent_sidecar_ensure(payload: &Value) -> bool {
    let profile_matches = payload.get("profile").and_then(Value::as_str).or_else(|| {
        payload
            .get("object")
            .and_then(|object| object.get("profile_ref"))
            .and_then(Value::as_str)
    }) == Some(arkret_sdk::PROFILE_AGENT_SIDECAR_THREAD);
    if !profile_matches {
        return false;
    }
    if payload
        .get("sidecar_ensure_capability_verified")
        .and_then(Value::as_bool)
        == Some(true)
    {
        return true;
    }
    payload
        .get("actor_capability")
        .and_then(Value::as_object)
        .is_some_and(|cap| {
            cap.get("action").and_then(Value::as_str)
                == Some(arkret_sdk::CapabilityActionId::SELF_AGENT_SIDECAR_THREAD_COMMAND_ENSURE)
                && cap.get("allowed").and_then(Value::as_bool) == Some(true)
        })
}

pub(super) fn sidecar_circle_create_shape_is_constrained(
    payload: &Value,
    operation: &Operation,
    actor: &str,
) -> bool {
    let Some(object) = payload.get("object").and_then(Value::as_object) else {
        return false;
    };
    let realm_id = operation.realm_id.as_str();
    let controller = payload
        .get("controller_id")
        .and_then(Value::as_str)
        .unwrap_or(actor);
    if controller != actor {
        return false;
    }
    if object.get("realm_id").and_then(Value::as_str) != Some(realm_id) {
        return false;
    }
    if object.get("created_by").and_then(Value::as_str) != Some(actor) {
        return false;
    }
    if object.get("profile_ref").and_then(Value::as_str)
        != Some(arkret_sdk::PROFILE_AGENT_SIDECAR_THREAD)
    {
        return false;
    }
    if object.get("directory_visibility").and_then(Value::as_str) != Some("members") {
        return false;
    }
    if object.get("join_rule").and_then(Value::as_str) != Some("invite") {
        return false;
    }
    if object.get("history_visibility").and_then(Value::as_str) != Some("joined") {
        return false;
    }
    let expected_key = arkret_sdk::agent_sidecar_circle_key(realm_id, actor);
    if payload
        .get("controller_agent_circle_key")
        .and_then(Value::as_str)
        != Some(expected_key.as_str())
    {
        return false;
    }
    let expected_short_name = arkret_sdk::agent_sidecar_short_name(&expected_key);
    object.get("title").and_then(Value::as_str) == Some(expected_short_name.as_str())
        && object
            .get("display")
            .and_then(|display| display.get("short_name"))
            .and_then(Value::as_str)
            == Some(expected_short_name.as_str())
}
