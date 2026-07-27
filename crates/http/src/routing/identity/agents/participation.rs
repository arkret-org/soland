use salvo::oapi::endpoint;

use super::*;

pub(super) fn participation_scope_kind(scope: &AgentParticipationScope) -> &'static str {
    match scope {
        AgentParticipationScope::Realm { .. } => "realm",
        AgentParticipationScope::Circle { .. } => "circle",
        AgentParticipationScope::Strand { .. } => "strand",
    }
}

pub(super) fn participation_from_value(row: &Value) -> AgentParticipation {
    AgentParticipation {
        reply: row.get("reply").and_then(Value::as_bool).unwrap_or(false),
        accept_third_party_mention: row
            .get("accept_third_party_mention")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        act_on_behalf: row
            .get("act_on_behalf")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    }
}

/// Effective ceiling for a scope = fold(deployment ⊇ Realm ⊇ Circle ⊇
/// Strand). Reads the `agent_participation_ceiling` projection for the
/// enclosing scope_key chain and intersects each row over the deployment
/// default; a scope with no ceiling rows inherits the deployment default
/// (AKP-0010 §4.4, fail-closed by intersection).
pub(super) async fn resolve_effective_ceiling(
    state: &AppState,
    scope: &AgentParticipationScope,
) -> AgentParticipation {
    crate::routing::agent_participation::resolve_effective_ceiling(state, scope).await
}

pub(super) fn agent_participation_failed_precondition(reason: &'static str) -> AppError {
    AppError::new(ErrorCode::FailedPrecondition, reason)
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_wire_code(reason)
}

#[endpoint(
    operation_id = "ak.self.agent.participation.resource.replace",
    summary = "Replace an agent's participation policy",
    tags("agent_participation")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.participation.resource.replace"))]
pub(super) async fn set_agent_participation(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentParticipationReplaceRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentParticipationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    let record = require_agent_controller(state, &session, &agent_id).await?;
    crate::routing::identity::managed_agent_pcr::validate_agent_controller_binding(
        state,
        &record,
        chrono::Utc::now(),
    )
    .await?;
    let body = body.into_inner();
    let governance_ceiling = resolve_effective_ceiling(state, &body.scope).await;
    let ceiling = effective_participation(
        governance_ceiling,
        agent_requested_participation_ceiling(&record),
    );
    validate_selection_within_ceiling(ceiling, body.selection).map_err(|_| {
        agent_participation_failed_precondition(
            arkret_wire::ReasonCode::AGENT_PARTICIPATION_EXCEEDS_CEILING,
        )
    })?;
    let effective = effective_participation(ceiling, body.selection);
    let scope_value = serde_json::to_value(&body.scope).unwrap_or(Value::Null);
    let selection_value = serde_json::to_value(body.selection).unwrap_or(Value::Null);
    let ceiling_value = serde_json::to_value(ceiling).unwrap_or(Value::Null);
    let effective_value = serde_json::to_value(effective).unwrap_or(Value::Null);
    // Persist the controller selection (ak.agent.participation.v1).
    state
        .agent_participations()
        .store_selection(json!({
            "agent_id": agent_id,
            "scope_kind": participation_scope_kind(&body.scope),
            "scope_key": body.scope.scope_key(),
            "realm_id": body.scope.realm_id().as_str(),
            "scope": scope_value.clone(),
            "reply": body.selection.reply,
            "accept_third_party_mention": body.selection.accept_third_party_mention,
            "act_on_behalf": body.selection.act_on_behalf,
        }))
        .await
        .map_err(|err| AppError::internal(format!("participation persist failed: {err}")))?;
    append_audit_log(
        state,
        Some(&session.actor),
        "ak.self.agent.participation.resource.replace",
        json!({
            "agent_id": agent_id,
            "controller_id": session.actor.clone(),
            "scope": scope_value,
            "scope_key": body.scope.scope_key(),
            "selection": selection_value,
            "ceiling": ceiling_value,
            "effective": effective_value,
        }),
        "accepted",
    )
    .await;
    // Capability materialization is controller-authored durable history.
    // Inkson submits the matching signed `ak.capability.{grant,revoke}` Event
    // after this aggregate has resolved and persisted the effective selection.
    // Soland must never impersonate the controller, including in development.
    json_ok(AgentParticipationOutcome {
        ok: true,
        agent_id,
        entries: vec![AgentParticipationEntry {
            scope: body.scope,
            selection: body.selection,
            ceiling,
            effective,
        }],
    })
}

pub(super) fn normalize_sidecar_exposure_ack(
    value: Option<Value>,
    controller_id: &str,
) -> Result<Option<Value>, AppError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let ack: AgentSidecarExposureAck = serde_json::from_value(value)
        .map_err(|err| AppError::invalid_param(format!("sidecar_exposure_ack invalid: {err}")))?;
    if ack.acknowledged_by.as_str() != controller_id {
        return Err(AppError::capability_denied(
            "sidecar_exposure_ack.acknowledged_by must match the controller session",
        ));
    }
    if ack.sidecar_refs.is_empty() {
        return Err(AppError::invalid_param(
            "sidecar_exposure_ack.sidecar_refs must be non-empty when present",
        ));
    }
    if ack.sidecar_refs.len() > 128 {
        return Err(AppError::invalid_param(
            "sidecar_exposure_ack.sidecar_refs exceeds the 128 item limit",
        ));
    }
    let mut refs = std::collections::BTreeSet::new();
    for sidecar_ref in &ack.sidecar_refs {
        if sidecar_ref.trim().is_empty() {
            return Err(AppError::invalid_param(
                "sidecar_exposure_ack.sidecar_refs must not contain empty refs",
            ));
        }
        if !refs.insert(sidecar_ref.as_str()) {
            return Err(AppError::invalid_param(
                "sidecar_exposure_ack.sidecar_refs must be unique",
            ));
        }
    }
    serde_json::to_value(ack)
        .map(Some)
        .map_err(|err| AppError::internal(format!("sidecar_exposure_ack serialize failed: {err}")))
}

#[endpoint(
    operation_id = "ak.self.agent.participation.resource.get",
    summary = "Get an agent's participation policy",
    tags("agent_participation")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.participation.resource.get"))]
pub(super) async fn get_agent_participation(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentParticipationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    let record = require_agent_controller(state, &session, &agent_id).await?;
    crate::routing::identity::managed_agent_pcr::validate_agent_controller_binding(
        state,
        &record,
        chrono::Utc::now(),
    )
    .await?;
    let selections = state
        .agent_participations()
        .selections(&agent_id)
        .await
        .map_err(|err| AppError::internal(format!("participation read failed: {err}")))?;
    let mut entries = Vec::with_capacity(selections.len());
    for row in &selections {
        let Some(scope_value) = row.get("scope") else {
            continue;
        };
        let Ok(scope) = serde_json::from_value::<AgentParticipationScope>(scope_value.clone())
        else {
            continue;
        };
        let selection = participation_from_value(row);
        let governance_ceiling = resolve_effective_ceiling(state, &scope).await;
        let ceiling = effective_participation(
            governance_ceiling,
            agent_requested_participation_ceiling(&record),
        );
        let effective = effective_participation(ceiling, selection);
        entries.push(AgentParticipationEntry {
            scope,
            selection,
            ceiling,
            effective,
        });
    }
    json_ok(AgentParticipationOutcome {
        ok: true,
        agent_id,
        entries,
    })
}
