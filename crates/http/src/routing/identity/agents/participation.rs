use salvo::oapi::endpoint;

use super::*;

pub(super) fn participation_scope_kind(scope: &ParticipationScope) -> &'static str {
    match scope {
        ParticipationScope::Realm { .. } => "realm",
        ParticipationScope::Circle { .. } => "circle",
        ParticipationScope::Strand { .. } => "strand",
    }
}

pub(super) fn participation_from_value(row: &Value) -> ParticipationBits {
    ParticipationBits {
        reply_message: row
            .get("reply_message")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        reaction_add: row
            .get("reaction_add")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        reaction_remove: row
            .get("reaction_remove")
            .and_then(Value::as_bool)
            .unwrap_or(false),
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
    body: JsonBody<ParticipationReplaceRequestBody>,
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
    let scope_value = serde_json::to_value(&body.target_scope).unwrap_or(Value::Null);
    let scope_key = body.target_scope.scope_key();
    let accepted_version = body
        .expected_version
        .checked_add(1)
        .filter(|version| *version <= i64::MAX as u64)
        .ok_or_else(|| AppError::invalid_param("expected_version exceeds supported range"))?;
    let selection_value = serde_json::to_value(body.selection).unwrap_or(Value::Null);
    if !state
        .agent_participations()
        .compare_and_swap_selection(
            json!({
                "agent_id": agent_id,
                "scope_kind": participation_scope_kind(&body.target_scope),
                "scope_key": scope_key,
                "realm_id": body.target_scope.realm_id().as_str(),
                "scope": scope_value.clone(),
                "version": accepted_version,
                "reply_message": body.selection.reply_message,
                "reaction_add": body.selection.reaction_add,
                "reaction_remove": body.selection.reaction_remove,
                "accept_third_party_mention": body.selection.accept_third_party_mention,
                "act_on_behalf": body.selection.act_on_behalf,
            }),
            body.expected_version,
        )
        .await
        .map_err(|err| AppError::internal(format!("participation persist failed: {err}")))?
    {
        return Err(agent_participation_failed_precondition("cas_conflict"));
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "ak.self.agent.participation.resource.replace",
        json!({
            "agent_id": agent_id,
            "controller_id": session.actor.clone(),
            "scope": scope_value,
            "scope_key": scope_key,
            "selection": selection_value,
            "accepted_version": accepted_version,
        }),
        "accepted",
    )
    .await;
    json_ok(load_agent_participation_outcome(state, &agent_id).await?)
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
    json_ok(load_agent_participation_outcome(state, &agent_id).await?)
}

async fn load_agent_participation_outcome(
    state: &AppState,
    agent_id: &str,
) -> Result<AgentParticipationOutcome, AppError> {
    let selections = state
        .agent_participations()
        .selections(agent_id)
        .await
        .map_err(|err| AppError::internal(format!("participation read failed: {err}")))?;
    let mut entries = Vec::with_capacity(selections.len());
    for row in &selections {
        let Some(scope_value) = row.get("scope") else {
            continue;
        };
        let Ok(scope) = serde_json::from_value::<ParticipationScope>(scope_value.clone()) else {
            continue;
        };
        let selection = participation_from_value(row);
        let version = row.get("version").and_then(Value::as_u64).unwrap_or(0);
        if version == 0 {
            continue;
        }
        entries.push(AgentParticipationEntry {
            scope,
            selection,
            version,
        });
    }
    Ok(AgentParticipationOutcome {
        ok: true,
        agent_id: agent_id.to_owned(),
        entries,
    })
}
