use super::*;

// ── CKP-0016 — agent participation ceiling (admission validate + projection write) ──

pub(super) fn ap_uuid_part(typed_id: &str) -> &str {
    typed_id.rsplit(':').next().unwrap_or(typed_id)
}

pub(super) fn ap_bool(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// Extract the agent_participation ceiling a realm-policy / circle / strand
/// operation carries, plus the parent scope_key chain to validate
/// tighten-only against. Returns `(scope_kind, scope_key, child_ceiling,
/// parent_scope_keys)` or None when the operation carries no ceiling.
pub(super) fn agent_participation_ceiling_change(
    operation: &Operation,
) -> Option<(
    &'static str,
    String,
    cokret_sdk::models::AgentParticipation,
    Vec<String>,
)> {
    use cokret_sdk::models::AgentParticipation;
    let payload = &operation.payload;
    let realm_uuid = ap_uuid_part(operation.realm_id.as_str()).to_owned();
    let find = |native: bool| -> Option<Value> {
        let base = payload
            .get("agent_participation")
            .or_else(|| {
                payload
                    .get("patch")
                    .and_then(|p| p.get("agent_participation"))
            })
            .or_else(|| {
                payload
                    .get("state")
                    .and_then(|p| p.get("agent_participation"))
            })
            .or_else(|| {
                payload
                    .get("object")
                    .and_then(|p| p.get("agent_participation"))
            })?;
        if native {
            base.get("native_agent").cloned()
        } else {
            Some(base.clone())
        }
    };
    let to_part = |value: &Value| AgentParticipation {
        reply: ap_bool(value, "reply"),
        accept_third_party_mention: ap_bool(value, "accept_third_party_mention"),
        act_on_behalf: ap_bool(value, "act_on_behalf"),
    };
    let id_of = |key: &str| -> Option<String> {
        payload
            .get(key)
            .and_then(Value::as_str)
            .or_else(|| {
                payload
                    .get("patch")
                    .and_then(|p| p.get(key))
                    .and_then(Value::as_str)
            })
            .or_else(|| {
                payload
                    .get("object")
                    .and_then(|p| p.get("id"))
                    .and_then(Value::as_str)
            })
            .map(ToOwned::to_owned)
    };
    match kinds::canonical_kind_for_operation(operation) {
        Some(cokret_sdk::events::kinds::REALM_POLICY_COMPONENTS) => {
            let value = find(true)?;
            Some((
                "realm",
                format!("realm:{realm_uuid}"),
                to_part(&value),
                Vec::new(),
            ))
        }
        Some(cokret_sdk::events::kinds::CIRCLE_CREATE)
        | Some(cokret_sdk::events::kinds::CIRCLE_UPDATE) => {
            let value = find(false)?;
            let circle_uuid = ap_uuid_part(&id_of("circle_id")?).to_owned();
            Some((
                "circle",
                format!("circle:{realm_uuid}:{circle_uuid}"),
                to_part(&value),
                vec![format!("realm:{realm_uuid}")],
            ))
        }
        Some(cokret_sdk::events::kinds::STRAND_CREATE)
        | Some(cokret_sdk::events::kinds::STRAND_UPDATE) => {
            let value = find(false)?;
            let strand_uuid = ap_uuid_part(&id_of("strand_id")?).to_owned();
            Some((
                "strand",
                format!("strand:{realm_uuid}:{strand_uuid}"),
                to_part(&value),
                vec![format!("realm:{realm_uuid}")],
            ))
        }
        _ => None,
    }
}

/// Admission gate (CKP-0016 §3 invariant 1): an inner-scope
/// `agent_participation` ceiling MUST NOT widen its parent ceiling. The
/// parent ceiling is the deployment default (`ALL` in dev) intersected
/// with any persisted parent-scope ceiling rows.
pub(super) fn agent_participation_parent_scope_keys(
    state: &AppState,
    operation: &Operation,
    scope_kind: &str,
    fallback_parent_keys: Vec<String>,
) -> Vec<String> {
    if scope_kind != "strand" {
        return fallback_parent_keys;
    }
    let realm_uuid = ap_uuid_part(operation.realm_id.as_str()).to_owned();
    let mut parent_keys = vec![format!("realm:{realm_uuid}")];
    let scope_circle_id = operation
        .payload
        .pointer("/object/scope_circle_id")
        .or_else(|| operation.payload.get("scope_circle_id"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            let strand_id = operation
                .payload
                .get("strand_id")
                .and_then(Value::as_str)
                .or_else(|| {
                    operation
                        .payload
                        .get("object")
                        .and_then(|object| object.get("id"))
                        .and_then(Value::as_str)
                })?;
            {
                let projection = state.projection.lock();
                projection.strand_scope_circle_id(strand_id)
            }
        });
    if let Some(circle_id) = scope_circle_id {
        parent_keys.push(crate::routing::agent_participation::circle_scope_key(
            operation.realm_id.as_str(),
            &circle_id,
        ));
    }
    parent_keys
}

/// Admission gate (CKP-0016): an inner-scope `agent_participation` ceiling
/// must not widen its parent ceiling.
pub async fn validate_agent_participation_ceiling(
    state: &AppState,
    operations: &[Operation],
) -> Result<(), &'static str> {
    use cokret_sdk::models::{AgentParticipation, validate_agent_participation_tightens};
    for operation in operations {
        let Some((scope_kind, _scope_key, child, parent_keys)) =
            agent_participation_ceiling_change(operation)
        else {
            continue;
        };
        let parent_keys =
            agent_participation_parent_scope_keys(state, operation, scope_kind, parent_keys);
        let mut parent = AgentParticipation::ALL;
        if !parent_keys.is_empty() {
            let rows = state
                .persistence
                .agent_participation()
                .ceilings_for_scope_keys(&parent_keys)
                .await
                .unwrap_or_default();
            for row in &rows {
                parent = parent.intersect(AgentParticipation {
                    reply: ap_bool(row, "reply"),
                    accept_third_party_mention: ap_bool(row, "accept_third_party_mention"),
                    act_on_behalf: ap_bool(row, "act_on_behalf"),
                });
            }
        }
        if validate_agent_participation_tightens(parent, child).is_err() {
            return Err("agent_participation_ceiling_widen");
        }
    }
    Ok(())
}

/// The `agent_participation_ceiling` row to UPSERT after an event with a
/// ceiling change is accepted (projection write), or None.
pub(crate) fn agent_participation_ceiling_record(operation: &Operation) -> Option<Value> {
    let (scope_kind, scope_key, child, _parents) = agent_participation_ceiling_change(operation)?;
    Some(serde_json::json!({
        "scope_kind": scope_kind,
        "scope_key": scope_key,
        "realm_id": operation.realm_id.as_str(),
        "reply": child.reply,
        "accept_third_party_mention": child.accept_third_party_mention,
        "act_on_behalf": child.act_on_behalf,
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AgentParticipationMode {
    Reply,
    ActOnBehalf,
}

impl AgentParticipationMode {
    fn rejection_reason(self) -> &'static str {
        match self {
            Self::Reply => "agent_reply_not_permitted",
            Self::ActOnBehalf => "agent_act_on_behalf_not_permitted",
        }
    }
}

fn ap_effective_for_mode(
    mode: AgentParticipationMode,
    effective: cokret_sdk::models::AgentParticipation,
) -> bool {
    match mode {
        AgentParticipationMode::Reply => effective.reply,
        AgentParticipationMode::ActOnBehalf => effective.act_on_behalf,
    }
}

pub(super) async fn native_agent_exists(
    state: &AppState,
    principal_id: &str,
) -> Result<bool, &'static str> {
    state
        .persistence
        .agents()
        .get(principal_id)
        .await
        .map(|record| record.is_some())
        .map_err(|_| "agent_principal_lookup_unavailable")
}

pub(super) async fn agent_lifecycle_rejection_reason(
    state: &AppState,
    agent_principal_id: &str,
) -> Result<Option<&'static str>, &'static str> {
    let record_state = state
        .persistence
        .agents()
        .get(agent_principal_id)
        .await
        .map_err(|_| "agent_principal_lookup_unavailable")?
        .and_then(|record| {
            record
                .get("state")
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
    match record_state.as_deref() {
        Some("paused") => return Ok(Some("agent_paused")),
        Some("deactivated") => return Ok(Some("agent_deactivated")),
        _ => {}
    }

    let projected = {
        let projection = state.projection.lock();
        projection.agent_lifecycles.get(agent_principal_id).copied()
    };
    Ok(match projected {
        Some(cokret_sdk::AgentLifecycleState::Paused) => Some("agent_paused"),
        Some(cokret_sdk::AgentLifecycleState::Deactivated) => Some("agent_deactivated"),
        _ => None,
    })
}

pub(super) fn agent_participation_action(operation: &Operation) -> Option<&str> {
    kinds::canonical_kind_for_operation(operation)
}

pub(super) fn validate_agent_act_on_behalf_authorization_ref(
    state: &AppState,
    operation: &Operation,
    agent_principal_id: &str,
) -> Result<String, &'static str> {
    let authorization_ref = operation
        .payload
        .get("authorization_ref")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or("agent_act_on_behalf_authorization_ref_missing")?;
    if !authorization_ref.starts_with("ck:grant:") {
        return Err("agent_act_on_behalf_authorization_ref_invalid");
    }
    let Some(action) = agent_participation_action(operation) else {
        return Err("agent_act_on_behalf_authorization_action_unsupported");
    };
    let resource = operation
        .object_id
        .as_deref()
        .unwrap_or_else(|| operation.realm_id.as_str());
    let grants = state
        .authz
        .grants_for_subject(agent_principal_id, operation.realm_id.as_str());
    let Some(grant) = grants
        .iter()
        .find(|grant| grant.grant_id == authorization_ref)
    else {
        return Err("agent_act_on_behalf_authorization_ref_inactive");
    };
    let action_allowed = grant.actions.iter().any(|candidate| candidate == action);
    let resource_expr = {
        let projection = state.projection.lock();
        Some(projection.authz_resource_expr(operation.realm_id.as_str(), resource))
    }
    .unwrap_or_else(|| resource.to_owned());
    if !action_allowed || !crate::authz::resource_matches(&grant.resource, &resource_expr) {
        return Err("agent_act_on_behalf_authorization_ref_scope");
    }
    Ok(authorization_ref.to_owned())
}

pub(super) fn agent_action_target_matches(target: &Value, operation: &Operation) -> bool {
    if target
        .get("operation_id")
        .and_then(Value::as_str)
        .is_some_and(|operation_id| operation_id == operation.operation_id.as_str())
    {
        return true;
    }
    match target.get("kind").and_then(Value::as_str) {
        Some("realm") => target
            .get("realm_id")
            .and_then(Value::as_str)
            .is_some_and(|realm_id| realm_id == operation.realm_id.as_str()),
        Some("strand") => {
            let Some(target_ref) = target.get("ref").and_then(Value::as_str) else {
                return false;
            };
            operation
                .payload
                .get("strand_id")
                .or_else(|| operation.payload.get("thread_id"))
                .and_then(Value::as_str)
                .is_some_and(|strand_id| strand_id == target_ref)
        }
        Some("message") | Some("object") => {
            let Some(target_ref) = target.get("ref").and_then(Value::as_str) else {
                return false;
            };
            operation.object_id.as_deref() == Some(target_ref)
                || operation
                    .payload
                    .get("message_id")
                    .and_then(Value::as_str)
                    .is_some_and(|message_id| message_id == target_ref)
        }
        _ => false,
    }
}

pub(super) fn validate_agent_act_on_behalf_approval(
    state: &AppState,
    operation: &Operation,
    agent_principal_id: &str,
    authorization_ref: &str,
) -> Result<(), &'static str> {
    let request_id = operation
        .payload
        .get("approval_request_id")
        .or_else(|| operation.payload.get("request_id"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or("agent_act_on_behalf_approval_request_id_missing")?;
    let approval_nonce = operation
        .payload
        .get("approval_nonce")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or("agent_act_on_behalf_approval_nonce_missing")?;
    let action = agent_participation_action(operation)
        .ok_or("agent_act_on_behalf_approval_action_unsupported")?;
    let projection = state.projection.lock();
    let request = projection
        .agent_action_requests
        .get(request_id)
        .ok_or("agent_act_on_behalf_approval_request_missing")?;
    if request.status != crate::reducer::AgentActionRequestStatus::Approved {
        return Err("agent_act_on_behalf_approval_request_not_approved");
    }
    if request.agent_principal_id != agent_principal_id {
        return Err("agent_act_on_behalf_approval_agent_mismatch");
    }
    let approval = request
        .approval
        .as_ref()
        .ok_or("agent_act_on_behalf_approval_missing")?;
    if approval.approval_nonce != approval_nonce {
        return Err("agent_act_on_behalf_approval_nonce_mismatch");
    }
    if approval.expires_at <= chrono::Utc::now() {
        return Err("agent_act_on_behalf_approval_expired");
    }
    if approval.proposed_action != action {
        return Err("agent_act_on_behalf_approval_action_mismatch");
    }
    if !agent_action_target_matches(&approval.target, operation) {
        return Err("agent_act_on_behalf_approval_target_mismatch");
    }
    let payload_digest = cokret_sdk::canonical::canonical_sha256(&operation.payload)
        .map_err(|_| "agent_act_on_behalf_approval_payload_digest_invalid")?;
    if approval.approved_payload_digest != payload_digest {
        return Err("agent_act_on_behalf_approval_payload_digest_mismatch");
    }
    let expires_at = approval.expires_at;
    drop(projection);
    if !state.remember_agent_approval_nonce(
        agent_principal_id,
        authorization_ref,
        request_id,
        approval_nonce,
        expires_at,
    ) {
        return Err(cokret_sdk::error::REASON_APPROVAL_NONCE_REUSED);
    }
    Ok(())
}

pub(super) fn operation_agent_context(operation: &Operation) -> Option<&Value> {
    operation
        .payload
        .get("agent_context")
        .or_else(|| {
            operation
                .payload
                .get("provenance")
                .and_then(|provenance| provenance.get("agent_context"))
        })
        .filter(|value| !value.is_null())
}

pub(super) fn agent_context_string<'a>(
    context: &'a Value,
    field: &str,
    missing_reason: &'static str,
) -> Result<&'a str, &'static str> {
    let object = context.as_object().ok_or("agent_context_invalid")?;
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(missing_reason)
}

pub(super) fn agent_context_agent_id(operation: &Operation) -> Option<&str> {
    operation_agent_context(operation).and_then(|context| {
        context
            .as_object()
            .and_then(|object| object.get("agent_id"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    })
}

pub(super) fn operation_agent_provenance(operation: &Operation) -> Option<&Value> {
    operation
        .payload
        .get("provenance")
        .or_else(|| operation.payload.get("agent_provenance"))
        .filter(|value| value.is_object())
}

pub(super) fn operation_provenance_agent_id(operation: &Operation) -> Option<&str> {
    operation_agent_provenance(operation).and_then(|provenance| {
        provenance
            .get("agent_id")
            .or_else(|| provenance.get("executed_by"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    })
}

pub(super) fn operation_executed_by(operation: &Operation) -> Option<&str> {
    operation
        .payload
        .get("executed_by")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            operation_agent_provenance(operation).and_then(|provenance| {
                provenance
                    .get("executed_by")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
            })
        })
}

pub(super) fn operation_provenance_marks_agent(operation: &Operation) -> bool {
    let Some(provenance) = operation_agent_provenance(operation) else {
        return false;
    };
    provenance
        .get("actor_kind")
        .and_then(Value::as_str)
        .is_some_and(|value| value == "agent")
        || provenance
            .get("kind")
            .and_then(Value::as_str)
            .is_some_and(|value| value == "agent")
        || operation_provenance_agent_id(operation).is_some()
}

async fn operation_agent_write_context(
    state: &AppState,
    operation: &Operation,
) -> Result<Option<(String, AgentParticipationMode)>, &'static str> {
    if let Some(executed_by) = operation_executed_by(operation)
        && (agent_context_agent_id(operation) == Some(executed_by)
            || operation_provenance_marks_agent(operation)
            || native_agent_exists(state, executed_by).await?)
    {
        return Ok(Some((
            executed_by.to_owned(),
            AgentParticipationMode::ActOnBehalf,
        )));
    }
    if let Some(agent_id) = agent_context_agent_id(operation) {
        let mode = if operation_executed_by(operation).is_some() {
            AgentParticipationMode::ActOnBehalf
        } else {
            AgentParticipationMode::Reply
        };
        return Ok(Some((agent_id.to_owned(), mode)));
    }
    if operation_provenance_marks_agent(operation)
        && let Some(agent_id) = operation_provenance_agent_id(operation)
            .map(ToOwned::to_owned)
            .or_else(|| operation.actor().map(|did| did.to_string()))
    {
        let mode = if operation_executed_by(operation).is_some() {
            AgentParticipationMode::ActOnBehalf
        } else {
            AgentParticipationMode::Reply
        };
        return Ok(Some((agent_id, mode)));
    }
    if let Some(sender) = policy_operation_sender(operation)
        && native_agent_exists(state, sender).await?
    {
        return Ok(Some((sender.to_owned(), AgentParticipationMode::Reply)));
    }
    Ok(None)
}

pub(super) fn validate_agent_context_authorization_ref(
    state: &AppState,
    operation: &Operation,
    agent_principal_id: &str,
    authorization_ref: &str,
) -> Result<(), &'static str> {
    if !authorization_ref.starts_with("ck:grant:") {
        return Err("agent_context_authorization_ref_invalid");
    }
    let Some(action) = agent_participation_action(operation) else {
        return Err("agent_context_authorization_action_unsupported");
    };
    let resource = operation
        .object_id
        .as_deref()
        .unwrap_or_else(|| operation.realm_id.as_str());
    let grants = state
        .authz
        .grants_for_subject(agent_principal_id, operation.realm_id.as_str());
    let Some(grant) = grants
        .iter()
        .find(|grant| grant.grant_id == authorization_ref)
    else {
        return Err("agent_context_authorization_ref_inactive");
    };
    let action_allowed = grant.actions.iter().any(|candidate| candidate == action);
    let resource_expr = {
        let projection = state.projection.lock();
        Some(projection.authz_resource_expr(operation.realm_id.as_str(), resource))
    }
    .unwrap_or_else(|| resource.to_owned());
    if !action_allowed || !crate::authz::resource_matches(&grant.resource, &resource_expr) {
        return Err("agent_context_authorization_ref_scope");
    }
    Ok(())
}

pub(super) fn validate_agent_context(
    state: &AppState,
    operation: &Operation,
    agent_principal_id: &str,
    envelope_authorization_ref: Option<&str>,
) -> Result<(), &'static str> {
    let context = operation_agent_context(operation).ok_or("agent_context_missing")?;
    let agent_id = agent_context_string(context, "agent_id", "agent_context_agent_id_missing")?;
    if agent_id != agent_principal_id {
        return Err("agent_context_agent_mismatch");
    }
    agent_context_string(
        context,
        "operator_or_controller",
        "agent_context_operator_or_controller_missing",
    )?;
    agent_context_string(
        context,
        "execution_purpose",
        "agent_context_execution_purpose_missing",
    )?;
    let context_authorization_ref = agent_context_string(
        context,
        "authorization_ref",
        "agent_context_authorization_ref_missing",
    )?;
    validate_agent_context_authorization_ref(
        state,
        operation,
        agent_principal_id,
        context_authorization_ref,
    )?;
    if let Some(envelope_authorization_ref) = envelope_authorization_ref
        && context_authorization_ref != envelope_authorization_ref
    {
        return Err("agent_context_authorization_ref_mismatch");
    }
    Ok(())
}

/// CKP-0016 §5.2 / CKP-0008 §4.10 + architecture §7 enforcement
/// (soland-native): every agent-originated Event carries auditable
/// `agent_context`. Reply-as-agent uses the `reply` bit; act-on-behalf uses
/// envelope-derived `executed_by`, requires a referenced active grant, and
/// uses the `act_on_behalf` bit. Non-agent actors fall through to standard
/// authz.
pub async fn validate_agent_reply_participation(
    state: &AppState,
    operations: &[Operation],
) -> Result<(), &'static str> {
    for operation in operations {
        let Some((agent_principal_id, mode)) =
            operation_agent_write_context(state, operation).await?
        else {
            continue;
        };
        if let Some(reason) = agent_lifecycle_rejection_reason(state, &agent_principal_id).await? {
            return Err(reason);
        }
        let authorization_ref = if mode == AgentParticipationMode::ActOnBehalf {
            Some(validate_agent_act_on_behalf_authorization_ref(
                state,
                operation,
                &agent_principal_id,
            )?)
        } else {
            None
        };
        validate_agent_context(
            state,
            operation,
            &agent_principal_id,
            authorization_ref.as_deref(),
        )?;
        let strand_id = operation
            .payload
            .get("strand_id")
            .and_then(Value::as_str)
            .or_else(|| operation.payload.get("thread_id").and_then(Value::as_str));
        let Some(scope_keys) = crate::routing::agent_participation::scope_keys_for_message(
            state,
            operation.realm_id.as_str(),
            strand_id,
        ) else {
            return Err(mode.rejection_reason());
        };
        let Some(resolved) =
            crate::routing::agent_participation::resolve_agent_participation_for_scope_keys(
                state,
                &agent_principal_id,
                &scope_keys,
            )
            .await
        else {
            return Err(mode.rejection_reason());
        };
        if !ap_effective_for_mode(mode, resolved.effective) {
            return Err(mode.rejection_reason());
        }
        if let Some(authorization_ref) = authorization_ref {
            validate_agent_act_on_behalf_approval(
                state,
                operation,
                &agent_principal_id,
                &authorization_ref,
            )?;
        }
    }
    Ok(())
}
