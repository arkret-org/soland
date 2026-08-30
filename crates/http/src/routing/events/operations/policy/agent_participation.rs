use arkret_models_collaboration::governance::agent_participation::ParticipationBits;

use super::*;

// ── AKP-0016 — agent participation ceiling (admission validate + projection write) ──

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
    arkret_models_collaboration::governance::agent_participation::ParticipationBits,
    Vec<String>,
)> {
    use arkret_models_collaboration::governance::agent_participation::ParticipationBits;
    let payload = &operation.payload;
    let realm_id = operation.realm_id.as_str();
    let find = || -> Option<Value> {
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
        base.get("native_agent").cloned()
    };
    let to_part = |value: &Value| ParticipationBits {
        reply_message: ap_bool(value, "reply_message"),
        reaction_add: ap_bool(value, "reaction_add"),
        reaction_remove: ap_bool(value, "reaction_remove"),
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
        Some(arkret_wire::EventKind::RealmPolicyBundle) => {
            let value = find()?;
            Some((
                "realm",
                crate::routing::agent_participation::realm_scope_key(realm_id),
                to_part(&value),
                Vec::new(),
            ))
        }
        Some(arkret_wire::EventKind::CircleCreate) | Some(arkret_wire::EventKind::CircleUpdate) => {
            let value = find()?;
            let circle_id = id_of("circle_id")?;
            Some((
                "circle",
                crate::routing::agent_participation::circle_scope_key(realm_id, &circle_id),
                to_part(&value),
                vec![crate::routing::agent_participation::realm_scope_key(
                    realm_id,
                )],
            ))
        }
        Some(arkret_wire::EventKind::StrandCreate) | Some(arkret_wire::EventKind::StrandUpdate) => {
            let value = find()?;
            let strand_id = id_of("strand_id")?;
            Some((
                "strand",
                crate::routing::agent_participation::strand_scope_key(realm_id, &strand_id),
                to_part(&value),
                vec![crate::routing::agent_participation::realm_scope_key(
                    realm_id,
                )],
            ))
        }
        _ => None,
    }
}

/// Admission gate (AKP-0016 §3 invariant 1): an inner-scope
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
    let mut parent_keys = vec![crate::routing::agent_participation::realm_scope_key(
        operation.realm_id.as_str(),
    )];
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
                let projection = state.projections().snapshot();
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

/// Admission gate (AKP-0016): an inner-scope `agent_participation` ceiling
/// must not widen its parent ceiling.
pub async fn validate_agent_participation_ceiling(
    state: &AppState,
    operations: &[Operation],
) -> Result<(), &'static str> {
    use arkret_models_collaboration::governance::agent_participation::{
        ParticipationBits, validate_agent_participation_tightens,
    };
    for operation in operations {
        let Some((scope_kind, _scope_key, child, parent_keys)) =
            agent_participation_ceiling_change(operation)
        else {
            continue;
        };
        let parent_keys =
            agent_participation_parent_scope_keys(state, operation, scope_kind, parent_keys);
        let mut parent = ParticipationBits::ALL;
        if !parent_keys.is_empty() {
            let rows = state
                .agent_participations()
                .ceilings(&parent_keys)
                .await
                .unwrap_or_default();
            for row in &rows {
                parent = parent.intersect(ParticipationBits {
                    reply_message: ap_bool(row, "reply_message"),
                    reaction_add: ap_bool(row, "reaction_add"),
                    reaction_remove: ap_bool(row, "reaction_remove"),
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
        "reply_message": child.reply_message,
        "reaction_add": child.reaction_add,
        "reaction_remove": child.reaction_remove,
        "accept_third_party_mention": child.accept_third_party_mention,
        "act_on_behalf": child.act_on_behalf,
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AgentParticipationMode {
    ReplyMessage,
    ReactionAdd,
    ReactionRemove,
    ActOnBehalf,
}

impl AgentParticipationMode {
    fn rejection_reason(self) -> &'static str {
        match self {
            Self::ReplyMessage => "agent_reply_not_permitted",
            Self::ReactionAdd => "agent_reaction_add_not_permitted",
            Self::ReactionRemove => "agent_reaction_remove_not_permitted",
            Self::ActOnBehalf => "agent_act_on_behalf_not_permitted",
        }
    }
}

fn autonomous_participation_mode(
    operation: &Operation,
) -> Result<AgentParticipationMode, &'static str> {
    match agent_participation_action(operation) {
        Some(arkret_wire::EventKind::MessageCreate) => Ok(AgentParticipationMode::ReplyMessage),
        Some(arkret_wire::EventKind::ReactionAdd) => Ok(AgentParticipationMode::ReactionAdd),
        Some(arkret_wire::EventKind::ReactionRemove) => Ok(AgentParticipationMode::ReactionRemove),
        _ => Err("agent_participation_action_unknown"),
    }
}

fn ap_effective_for_mode(mode: AgentParticipationMode, effective: ParticipationBits) -> bool {
    match mode {
        AgentParticipationMode::ReplyMessage => effective.reply_message,
        AgentParticipationMode::ReactionAdd => effective.reaction_add,
        AgentParticipationMode::ReactionRemove => effective.reaction_remove,
        AgentParticipationMode::ActOnBehalf => effective.act_on_behalf,
    }
}

pub(super) async fn native_agent_exists(
    state: &AppState,
    principal_id: &str,
) -> Result<bool, &'static str> {
    state
        .agent_pairings()
        .agent(principal_id)
        .await
        .map(|record| record.is_some())
        .map_err(|_| "agent_principal_lookup_unavailable")
}

pub(super) async fn agent_lifecycle_rejection_reason(
    state: &AppState,
    agent_id: &str,
) -> Result<Option<&'static str>, &'static str> {
    let record_state = state
        .agent_pairings()
        .agent(agent_id)
        .await
        .map_err(|_| "agent_principal_lookup_unavailable")?
        .map(|record| record.state);
    match record_state {
        Some(arkret_models_collaboration::agent_operations::AgentLifecycleState::Paused) => {
            return Ok(Some("agent_paused"));
        }
        Some(arkret_models_collaboration::agent_operations::AgentLifecycleState::Deactivated) => {
            return Ok(Some("agent_deactivated"));
        }
        _ => {}
    }

    let projected = {
        let projection = state.projections().snapshot();
        projection.agent_lifecycles.get(agent_id).copied()
    };
    Ok(match projected {
        Some(arkret_models_collaboration::agent_operations::AgentLifecycleState::Paused) => {
            Some("agent_paused")
        }
        Some(arkret_models_collaboration::agent_operations::AgentLifecycleState::Deactivated) => {
            Some("agent_deactivated")
        }
        _ => None,
    })
}

pub(super) fn agent_participation_action(operation: &Operation) -> Option<arkret_wire::EventKind> {
    kinds::canonical_kind_for_operation(operation)
}

pub(super) fn validate_agent_act_on_behalf_authorization_ref(
    state: &AppState,
    operation: &Operation,
    agent_id: &str,
) -> Result<String, &'static str> {
    let authorization_ref = operation
        .payload
        .get("authorization_ref")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or("agent_act_on_behalf_authorization_ref_missing")?;
    if !authorization_ref.starts_with("ak:grant:") {
        return Err("agent_act_on_behalf_authorization_ref_invalid");
    }
    let Some(action) = agent_participation_action(operation) else {
        return Err("agent_act_on_behalf_authorization_action_unsupported");
    };
    let resource = operation
        .object_id
        .as_deref()
        .unwrap_or_else(|| operation.realm_id.as_str());
    let agent = arkret_wire::ActorId::hosted_principal(
        arkret_wire::DidCoreId::new(agent_id.to_owned())
            .map_err(|_| "agent_act_on_behalf_actor_id_invalid")?,
        operation.context.sender.route_service_id().clone(),
    );
    let grants = state
        .authorization()
        .grants_for_subject(&agent, operation.realm_id.as_str());
    let Some(grant) = grants
        .iter()
        .find(|grant| grant.grant_id == authorization_ref)
    else {
        return Err("agent_act_on_behalf_authorization_ref_inactive");
    };
    let action_allowed = grant
        .actions
        .iter()
        .any(|candidate| candidate == action.as_str());
    let resource_expr = {
        let projection = state.projections().snapshot();
        Some(projection.authz_resource_expr(operation.realm_id.as_str(), resource))
    }
    .unwrap_or_else(|| resource.to_owned());
    if !action_allowed || !crate::authz::resource_matches(&grant.resource, &resource_expr) {
        return Err("agent_act_on_behalf_authorization_ref_scope");
    }
    Ok(authorization_ref.to_owned())
}

pub(super) fn validate_agent_act_on_behalf_approval(
    state: &AppState,
    operation: &Operation,
    agent_id: &str,
    authorization_ref: &str,
) -> Result<ValidatedAgentApprovalNonce, &'static str> {
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
    let approval = state.projections().validate_agent_action_approval(
        operation,
        agent_id,
        request_id,
        approval_nonce,
        action.as_str(),
        chrono::Utc::now(),
    )?;
    Ok(ValidatedAgentApprovalNonce {
        agent_id: agent_id.to_owned(),
        authorization_ref: authorization_ref.to_owned(),
        request_id: request_id.to_owned(),
        approval_nonce: approval_nonce.to_owned(),
        expires_at: approval.expires_at,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ValidatedAgentApprovalNonce {
    pub agent_id: String,
    pub authorization_ref: String,
    pub request_id: String,
    pub approval_nonce: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
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
        .context
        .executed_by
        .as_ref()
        .map(|actor| actor.signing_principal_id().as_str())
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
    let actor_id = Some(operation.context.sender.to_string());
    let executed_by = operation_executed_by(operation);
    let authorization_ref = operation.context.authorization_ref.as_deref();
    if let (Some(actor_id), Some(executed_by), Some(authorization_ref)) =
        (actor_id.as_deref(), executed_by, authorization_ref)
    {
        let managed = state
            .agent_pairings()
            .agent(actor_id)
            .await
            .map_err(|_| "agent_principal_lookup_unavailable")?
            .is_some_and(|record| {
                arkret_wire::DidCoreId::new(record.controller_id.clone())
                    .or_else(|_| {
                        arkret_wire::Did::new(record.controller_id.clone())
                            .and_then(|did| arkret_wire::project_did_to_core_id(&did))
                    })
                    .is_ok_and(|controller_id| controller_id.as_str() == executed_by)
                    && record.principal_control_realm_id == operation.realm_id.as_str()
                    && record.controller_authorization_ref.as_str() == authorization_ref
            });
        if managed {
            return Ok(None);
        }
    }
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
            autonomous_participation_mode(operation)?
        };
        return Ok(Some((agent_id.to_owned(), mode)));
    }
    if operation_provenance_marks_agent(operation)
        && let Some(agent_id) = operation_provenance_agent_id(operation)
            .map(ToOwned::to_owned)
            .or_else(|| Some(operation.context.sender.to_string()))
    {
        let mode = if operation_executed_by(operation).is_some() {
            AgentParticipationMode::ActOnBehalf
        } else {
            autonomous_participation_mode(operation)?
        };
        return Ok(Some((agent_id, mode)));
    }
    if let Some(sender) = policy_operation_sender(operation)
        && native_agent_exists(state, sender.signing_principal_id().as_str()).await?
    {
        return Ok(Some((
            sender.signing_principal_id().to_string(),
            autonomous_participation_mode(operation)?,
        )));
    }
    Ok(None)
}

pub(super) fn validate_agent_context_authorization_ref(
    state: &AppState,
    operation: &Operation,
    agent_id: &str,
    authorization_ref: &str,
) -> Result<(), &'static str> {
    // A two-principal Direct Conversation is itself an explicit invitation to
    // exchange messages. Bind reply authority to that canonical Realm/binding
    // instead of requiring a second capability grant that the materialization
    // protocol does not emit for the peer.
    if authorization_ref == operation.realm_id.as_str()
        && agent_participation_action(operation) == Some(arkret_wire::EventKind::MessageCreate)
    {
        let binding = super::governance::active_direct_conversation_binding_for_realm(
            state,
            operation.realm_id.as_str(),
        )
        .ok_or("agent_context_authorization_ref_inactive")?;
        let strand_id = operation
            .payload
            .get("strand_id")
            .and_then(Value::as_str)
            .ok_or("agent_context_authorization_ref_scope")?;
        if binding
            .participants_unordered
            .iter()
            .any(|participant| participant == agent_id)
            && binding.main_strand_id == strand_id
        {
            return Ok(());
        }
        return Err("agent_context_authorization_ref_scope");
    }
    if !authorization_ref.starts_with("ak:grant:") {
        return Err("agent_context_authorization_ref_invalid");
    }
    let Some(action) = agent_participation_action(operation) else {
        return Err("agent_context_authorization_action_unsupported");
    };
    let resource = operation
        .object_id
        .as_deref()
        .unwrap_or_else(|| operation.realm_id.as_str());
    let agent = arkret_wire::ActorId::hosted_principal(
        arkret_wire::DidCoreId::new(agent_id.to_owned())
            .map_err(|_| "agent_context_actor_id_invalid")?,
        operation.context.sender.route_service_id().clone(),
    );
    let grants = state
        .authorization()
        .grants_for_subject(&agent, operation.realm_id.as_str());
    let Some(grant) = grants
        .iter()
        .find(|grant| grant.grant_id == authorization_ref)
    else {
        return Err("agent_context_authorization_ref_inactive");
    };
    let action_allowed = grant
        .actions
        .iter()
        .any(|candidate| candidate == action.as_str());
    let resource_expr = {
        let projection = state.projections().snapshot();
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
    expected_agent_id: &str,
    envelope_authorization_ref: Option<&str>,
) -> Result<(), &'static str> {
    let context = operation_agent_context(operation).ok_or("agent_context_missing")?;
    let agent_id = agent_context_string(context, "agent_id", "agent_context_agent_id_missing")?;
    if agent_id != expected_agent_id {
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
        agent_id,
        context_authorization_ref,
    )?;
    if let Some(envelope_authorization_ref) = envelope_authorization_ref
        && context_authorization_ref != envelope_authorization_ref
    {
        return Err("agent_context_authorization_ref_mismatch");
    }
    Ok(())
}

/// AKP-0016 §5.2 / AKP-0008 §4.10 + architecture §7 enforcement
/// (soland-native): every agent-originated Event carries auditable
/// `agent_context`. Reply-as-agent uses the `reply` bit; act-on-behalf uses
/// envelope-derived `executed_by`, requires a referenced active grant, and
/// uses the `act_on_behalf` bit. Non-agent actors fall through to standard
/// authz.
pub async fn validate_agent_reply_participation(
    state: &AppState,
    operations: &[Operation],
) -> Result<Vec<ValidatedAgentApprovalNonce>, &'static str> {
    let mut approvals = Vec::new();
    for operation in operations {
        let Some((agent_id, mode)) = operation_agent_write_context(state, operation).await? else {
            continue;
        };
        if let Some(reason) = agent_lifecycle_rejection_reason(state, &agent_id).await? {
            return Err(reason);
        }
        let authorization_ref = if mode == AgentParticipationMode::ActOnBehalf {
            Some(validate_agent_act_on_behalf_authorization_ref(
                state, operation, &agent_id,
            )?)
        } else {
            None
        };
        validate_agent_context(state, operation, &agent_id, authorization_ref.as_deref())?;
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
                &agent_id,
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
            approvals.push(validate_agent_act_on_behalf_approval(
                state,
                operation,
                &agent_id,
                &authorization_ref,
            )?);
        }
    }
    Ok(approvals)
}
