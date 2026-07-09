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
/// (CKP-0010 §4.4, fail-closed by intersection).
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
    operation_id = "ck.self.agent.participation.resource.replace",
    tags("agents"),
    summary = "Set an agent's participation selection for a scope (controller-self only)",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.participation.resource.replace"))]
pub(super) async fn set_agent_participation(
    aa: AuthArgs,
    agent_principal_id: PathParam<String>,
    body: JsonBody<AgentParticipationSetReqBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentParticipationResBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_principal_id.into_inner();
    require_agent_controller(state, &session, &agent_id).await?;
    let body = body.into_inner();
    let ceiling = resolve_effective_ceiling(state, &body.scope).await;
    validate_selection_within_ceiling(ceiling, body.selection).map_err(|_| {
        agent_participation_failed_precondition(
            cokret_sdk::error::REASON_AGENT_PARTICIPATION_EXCEEDS_CEILING,
        )
    })?;
    let effective = effective_participation(ceiling, body.selection);
    let scope_value = serde_json::to_value(&body.scope).unwrap_or(Value::Null);
    let selection_value = serde_json::to_value(body.selection).unwrap_or(Value::Null);
    let ceiling_value = serde_json::to_value(ceiling).unwrap_or(Value::Null);
    let effective_value = serde_json::to_value(effective).unwrap_or(Value::Null);
    // Persist the controller selection (ck.agent.participation.v1).
    state
        .persistence
        .agent_participation()
        .put_selection(json!({
            "agent_principal_id": agent_id,
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
        "ck.self.agent.participation.resource.replace",
        json!({
            "agent_principal_id": agent_id,
            "controller_principal_id": session.actor.clone(),
            "scope": scope_value,
            "scope_key": body.scope.scope_key(),
            "selection": selection_value,
            "ceiling": ceiling_value,
            "effective": effective_value,
        }),
        "accepted",
    )
    .await;
    // CKP-0016 §5.2 / CKP-0008 §4.9 (dev option B) — materialise the effective
    // participation decision into a durable capability grant. effective reply
    // ⇒ `ck.capability.grant` (ck.message.create + ck.reaction.add over the
    // scope resource); otherwise `ck.capability.revoke` (idempotent). The
    // grant id is deterministic per (agent, scope_key) so set/unset/set
    // converge on a single cell. Production submits these from inkson.
    if state.config.development_mode {
        let realm = ensure_self_realm(state, &session).await?;
        let grant_id = participation_grant_id(&agent_id, &body.scope.scope_key());
        if effective.reply {
            let resource = participation_scope_resource(&body.scope);
            materialize_capability_grant(state, &session, &realm, &agent_id, resource, &grant_id)
                .await?;
        } else {
            revoke_capability_grant(state, &session, &realm, &grant_id).await?;
        }
    }
    json_ok(AgentParticipationResBody {
        ok: true,
        agent_principal_id: agent_id,
        entries: vec![AgentParticipationEntry {
            scope: body.scope,
            selection: body.selection,
            ceiling,
            effective,
        }],
    })
}

/// Deterministic capability grant id for a materialised participation
/// selection, keyed by (agent_principal_id, scope_key) so toggling the
/// selection converges on one grant cell (CKP-0016 §5.2).
pub(super) fn participation_grant_id(agent_principal_id: &str, scope_key: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"ak:grant:agent_participation:v1:");
    hasher.update(agent_principal_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(scope_key.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // Force UUIDv7 version + RFC-9562 variant so the id matches the
    // ck:grant:<uuidv7> wire pattern.
    bytes[6] = (bytes[6] & 0x0F) | 0x70;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    let g = |slice: &[u8]| slice.iter().map(|b| format!("{b:02x}")).collect::<String>();
    format!(
        "ak:grant:{}-{}-{}-{}-{}",
        g(&bytes[0..4]),
        g(&bytes[4..6]),
        g(&bytes[6..8]),
        g(&bytes[8..10]),
        g(&bytes[10..16]),
    )
}

/// Map a participation scope to a capability `resource-selector` object. The
/// grant authorizes the agent over the scope's realm (Realm scope) or the
/// specific strand (Strand scope); a Circle scope narrows to the circle id.
pub(super) fn participation_scope_resource(scope: &AgentParticipationScope) -> Value {
    match scope {
        AgentParticipationScope::Realm { realm_id } => {
            json!({ "kind": "realm", "realm_id": realm_id.as_str() })
        }
        AgentParticipationScope::Circle {
            realm_id,
            circle_id,
        } => {
            json!({ "kind": "circle", "realm_id": realm_id.as_str(), "circle_id": circle_id.as_str() })
        }
        AgentParticipationScope::Strand {
            realm_id,
            strand_id,
        } => {
            json!({ "kind": "strand", "realm_id": realm_id.as_str(), "strand_id": strand_id.as_str() })
        }
    }
}

pub(super) fn is_capability_grant_id(grant_id: &str) -> bool {
    grant_id.starts_with("ak:grant:")
}

pub(super) fn normalize_sidecar_exposure_ack(
    value: Option<Value>,
    controller_did: &str,
) -> Result<Option<Value>, AppError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let ack: AgentSidecarExposureAck = serde_json::from_value(value)
        .map_err(|err| AppError::invalid_param(format!("sidecar_exposure_ack invalid: {err}")))?;
    if ack.acknowledged_by.as_str() != controller_did {
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
    operation_id = "ck.self.agent.participation.resource.get",
    tags("agents"),
    summary = "Get an agent's resolved participation policy (controller-self only)",
    status_codes(200, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.participation.resource.get"))]
pub(super) async fn get_agent_participation(
    aa: AuthArgs,
    agent_principal_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentParticipationResBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_principal_id.into_inner();
    require_agent_controller(state, &session, &agent_id).await?;
    let selections = state
        .persistence
        .agent_participation()
        .list_selections(&agent_id)
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
        let ceiling = resolve_effective_ceiling(state, &scope).await;
        let effective = effective_participation(ceiling, selection);
        entries.push(AgentParticipationEntry {
            scope,
            selection,
            ceiling,
            effective,
        });
    }
    json_ok(AgentParticipationResBody {
        ok: true,
        agent_principal_id: agent_id,
        entries,
    })
}
