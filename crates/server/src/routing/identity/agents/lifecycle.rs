use super::*;

#[endpoint(
    operation_id = "ak.self.agent.command.provision",
    tags("agents"),
    summary = "Provision a personal agent (DID + pairing request)",
    status_codes(201, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.command.provision"))]
pub(super) async fn provision_agent(
    aa: AuthArgs,
    body: JsonBody<AgentProvisionRequestBody>,
    depot: &mut Depot,
    res: &mut Response,
    req: &mut Request,
) -> JsonResult<AgentProvisionOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    // Spec `agent_provision_request_body` carries no controller_id —
    // the controller is ALWAYS the authenticated principal.
    let controller_id = session.actor.clone();
    let display_name = body
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let agent_slug = body.slug.trim().to_owned();
    let now_utc = chrono::Utc::now();
    validate_agent_slug(&agent_slug)
        .map_err(|err| AppError::invalid_param(format!("slug is invalid: {err}")))?;
    let existing = state
        .persistence
        .agents()
        .list_for_controller(&controller_id)
        .await
        .map_err(|err| AppError::internal(format!("agent slug conflict check failed: {err}")))?;
    let mut existing = existing;
    for record in existing.iter_mut() {
        *record = lazily_expire_pairing(state, &session, record.clone()).await;
    }
    if existing.iter().any(|record| {
        record.get("agent_slug").and_then(Value::as_str) == Some(agent_slug.as_str())
            && agent_record_reserves_selector_slug(record, &now_utc)
    }) {
        return Err(AppError::invalid_param(
            "slug is already bound to an active or open agent for this controller",
        ));
    }
    let agent_id = generate_agent_principal_did(&state.config.service_id);
    let timestamp = now_utc.to_rfc3339_opts(SecondsFormat::Millis, true);
    let pairing_request_id = format!("agent_pairing_request:{}", uuid::Uuid::now_v7());
    let pairing_code = generate_pairing_code();
    let pairing_ttl_ms = body
        .pairing_ttl_ms
        .unwrap_or(15 * 60 * 1000)
        .min(24 * 60 * 60 * 1000);
    let expires_at = now_utc + chrono::Duration::milliseconds(pairing_ttl_ms as i64);
    let requested_scope = body
        .requested_scope
        .map(|scope| serde_json::to_value(scope).unwrap_or(Value::Null))
        .unwrap_or(Value::Null);
    if !state.config.development_mode {
        return Err(AppError::unsupported_feature(
            "production agent provisioning requires protocol-valid delegated fan-out",
        )
        .with_wire_code("agent_provision_fanout_unavailable"));
    }
    // Persist the agent_principal row so list/get/lifecycle + grant/session
    // paths have a real principal to operate on (AKP-0008). Per the spec
    // agent lifecycle the agent starts `pending_runtime_key`; the gate
    // `ak.gate.account.command.pair_agent_key` flips it to `active` once the
    // runtime key is authorized.
    // AKP-0008 D1: development can materialize the agent's identity sub-events
    // with dev proofs. Production fails closed above until the delegated
    // fan-out has a protocol-valid authorization_ref + detached-JWS path.
    let realm = ensure_self_realm(state, &session).await?;
    let (profile_event, accountability_event, grant_ids) = fanout_provision_subevents(
        state,
        &session,
        &realm,
        &agent_id,
        display_name.as_deref(),
        &requested_scope,
    )
    .await?;
    let provision_event_refs = json!({
        "agent_profile_event_id": profile_event,
        "accountability_grant_event_id": accountability_event,
        "initial_capability_grant_ids": grant_ids,
    });
    let self_realm_id = Some(realm);
    state
        .persistence
        .agents()
        .put(json!({
            "agent_id": agent_id,
            "controller_id": controller_id,
            "display_name": display_name,
            "agent_slug": agent_slug.clone(),
            "requested_scope": requested_scope,
            "accountability": body.accountability,
            "state": "pending_runtime_key",
            "self_realm_id": self_realm_id,
            "provision_event_refs": provision_event_refs,
            "pairing_request_id": pairing_request_id,
            "pairing_code": pairing_code,
            "pairing_expires_at": expires_at.to_rfc3339_opts(SecondsFormat::Millis, true),
            "created_at": timestamp,
            "updated_at": timestamp,
        }))
        .await
        .map_err(|err| AppError::internal(format!("agent persist failed: {err}")))?;
    append_audit_log(
        state,
        Some(&session.actor),
        "ak.self.agent.command.provision",
        json!({
            "agent_id": agent_id,
            "controller_id": controller_id,
            "display_name": display_name,
            "slug": agent_slug,
            "pairing_request_id": pairing_request_id,
        }),
        "accepted",
    )
    .await;
    res.status_code(StatusCode::CREATED);
    let agent_principal_did = arkret_sdk::Did::new(agent_id).map_err(|err| {
        AppError::internal(format!("generated agent principal DID invalid: {err}"))
    })?;
    json_ok(AgentProvisionOutcome {
        agent_id: agent_principal_did,
        pairing_request_id,
        pairing_code: Some(pairing_code),
        expires_at,
    })
}

/// `ak.self.agent.command.renew_pairing` — re-open pairing on an agent whose
/// runtime key was never authorized instead of burning the principal and
/// provisioning a replacement. Security invariant: pairing HANDLES are
/// one-time (the fresh `pairing_request_id` + `pairing_code` replace the old
/// tuple, which becomes permanently unresolvable through the same
/// anti-enumeration lookup), the PRINCIPAL is not.
#[endpoint(
    operation_id = "ak.self.agent.command.renew_pairing",
    tags("agents"),
    summary = "Re-open pairing on a never-activated personal agent",
    status_codes(200, 400, 401, 403, 404, 412, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.command.renew_pairing"))]
pub(super) async fn renew_agent_pairing(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentRenewPairingRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentProvisionOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    let body = body.into_inner();
    let record = require_agent_controller(state, &session, &agent_id).await?;
    // Lazy-expire first so a stale pending record renews through the same
    // path (grants already revoked) as an observed-expired one.
    let record = lazily_expire_pairing(state, &session, record).await;
    match record.get("state").and_then(Value::as_str) {
        Some("pending_runtime_key" | "pairing_expired") => {}
        Some("deactivated") => {
            return Err(pairing_failed_precondition(
                "agent is deactivated; deactivation is terminal",
            )
            .with_reason_detail("agent_deactivated"));
        }
        _ => {
            return Err(pairing_failed_precondition(
                "agent already has an authorized runtime key; rotate the key instead of renewing pairing",
            ));
        }
    }
    if !state.config.development_mode {
        return Err(AppError::unsupported_feature(
            "production agent pairing renewal requires protocol-valid delegated fan-out",
        )
        .with_wire_code("agent_provision_fanout_unavailable"));
    }
    let now_utc = chrono::Utc::now();
    // `pairing_expired` does not reserve the slug, so a replacement agent may
    // have claimed it since. Renewing would then produce two open agents with
    // the same selector slug for one controller — reject like provision does.
    let agent_slug = record
        .get("agent_slug")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if !agent_slug.is_empty() {
        let siblings = state
            .persistence
            .agents()
            .list_for_controller(&session.actor)
            .await
            .map_err(|err| AppError::internal(format!("agent slug conflict check failed: {err}")))?;
        if siblings.iter().any(|sibling| {
            sibling.get("agent_id").and_then(Value::as_str) != Some(agent_id.as_str())
                && sibling.get("agent_slug").and_then(Value::as_str) == Some(agent_slug.as_str())
                && agent_record_reserves_selector_slug(sibling, &now_utc)
        }) {
            return Err(pairing_failed_precondition(
                "slug is already bound to an active or open agent for this controller",
            ));
        }
    }
    // Re-issue the pending grants the expiry cleanup revoked. A still-open
    // pairing keeps its live grants; only re-fan-out when none remain.
    let realm = ensure_self_realm(state, &session).await?;
    let live_grant_ids = {
        let proj = state.projection.lock();
        proj.grant_ids_for_subject(&agent_id)
    };
    let grant_ids = if live_grant_ids.is_empty() {
        let requested_scope = record
            .get("requested_scope")
            .cloned()
            .unwrap_or(Value::Null);
        fanout_renewal_grants(state, &session, &realm, &agent_id, &requested_scope).await?
    } else {
        live_grant_ids
    };
    let pairing_request_id = format!("agent_pairing_request:{}", uuid::Uuid::now_v7());
    let pairing_code = generate_pairing_code();
    let pairing_ttl_ms = body
        .pairing_ttl_ms
        .unwrap_or(15 * 60 * 1000)
        .min(24 * 60 * 60 * 1000);
    let expires_at = now_utc + chrono::Duration::milliseconds(pairing_ttl_ms as i64);
    let timestamp = now_utc.to_rfc3339_opts(SecondsFormat::Millis, true);
    let mut record = record;
    {
        let obj = record
            .as_object_mut()
            .ok_or_else(|| AppError::internal("agent record is not an object"))?;
        obj.insert("state".to_owned(), json!("pending_runtime_key"));
        obj.insert(
            "pairing_request_id".to_owned(),
            json!(pairing_request_id.clone()),
        );
        obj.insert("pairing_code".to_owned(), json!(pairing_code.clone()));
        obj.insert(
            "pairing_expires_at".to_owned(),
            json!(expires_at.to_rfc3339_opts(SecondsFormat::Millis, true)),
        );
        // A runtime-key request submitted against the dead handle must not
        // survive into the renewed pairing.
        obj.insert("approval_request_id".to_owned(), Value::Null);
        obj.insert("runtime_key_request".to_owned(), Value::Null);
        obj.insert("approval_requested_at".to_owned(), Value::Null);
        obj.insert("updated_at".to_owned(), json!(timestamp));
        if let Some(refs) = obj
            .get_mut("provision_event_refs")
            .and_then(Value::as_object_mut)
        {
            refs.insert("initial_capability_grant_ids".to_owned(), json!(grant_ids));
        }
    }
    state
        .persistence
        .agents()
        .put(record)
        .await
        .map_err(|err| AppError::internal(format!("agent persist failed: {err}")))?;
    append_audit_log(
        state,
        Some(&session.actor),
        "ak.self.agent.command.renew_pairing",
        json!({
            "agent_id": agent_id,
            "controller_id": session.actor,
            "slug": agent_slug,
            "pairing_request_id": pairing_request_id,
        }),
        "accepted",
    )
    .await;
    let agent_principal_did = arkret_sdk::Did::new(agent_id)
        .map_err(|err| AppError::internal(format!("persisted agent DID invalid: {err}")))?;
    json_ok(AgentProvisionOutcome {
        agent_id: agent_principal_did,
        pairing_request_id,
        pairing_code: Some(pairing_code),
        expires_at,
    })
}

#[endpoint(
    operation_id = "ak.self.agent.query.list",
    tags("agents"),
    summary = "List personal agents owned by the authenticated controller",
    status_codes(200, 401, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.query.list"))]
pub(super) async fn list_agents(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let records = state
        .persistence
        .agents()
        .list_for_controller(&session.actor)
        .await
        .map_err(|err| AppError::internal(format!("agent list failed: {err}")))?;
    // AKP-0008 §4.3.2 — lazily expire any agent past its pairing window
    // before projecting, so list reflects `pairing_expired` and the pending
    // grants are revoked on first observation.
    let mut agents = Vec::with_capacity(records.len());
    for record in records {
        let record = lazily_expire_pairing(state, &session, record).await;
        agents.push(agent_projection_from_record(&record));
    }
    // spec `agent_list` = `{agents: [agent_projection], next_cursor?, has_more}`.
    json_ok(AgentList {
        agents,
        next_cursor: None,
        has_more: false,
    })
}

#[endpoint(
    operation_id = "ak.self.agent.resource.get",
    tags("agents"),
    summary = "Get a personal agent by id (controller-self only)",
    status_codes(200, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.resource.get"))]
pub(super) async fn get_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    validate_agent_id(&agent_id)?;
    let record = state
        .persistence
        .agents()
        .get(&agent_id)
        .await
        .map_err(|err| AppError::internal(format!("agent get failed: {err}")))?
        .ok_or_else(|| AppError::not_found("agent not found"))?;
    // Controller-self only: hide others' agents behind 404 to avoid enumeration.
    if record.get("controller_id").and_then(Value::as_str) != Some(session.actor.as_str()) {
        return Err(AppError::not_found("agent not found"));
    }
    let record = lazily_expire_pairing(state, &session, record).await;
    let mut view = agent_view_from_record(&record);
    // Surface the agent's effective capability grants from the authz
    // projection so the controller UI can list and revoke them; the
    // persisted record itself never carries grants.
    view.grants = state
        .authz
        .grants_for_subject_all_realms(&agent_id)
        .into_iter()
        .filter_map(|grant| serde_json::to_value(grant).ok())
        .collect();
    json_ok(view)
}

/// AKP-0008 §4.3.2 — lazily expire a `pending_runtime_key` agent whose
/// pairing window has elapsed. On first observation past `pairing_expires_at`
/// the agent flips to `pairing_expired` and (dev option B) the pending
/// `effective_after_first_authorized_key` grants are auto-revoked. Returns
/// the record with the (possibly) updated `state`. No-op for any other
/// state. The controller `session` authors the revoke fan-out.
pub(super) async fn lazily_expire_pairing(
    state: &AppState,
    session: &SessionRecord,
    mut record: Value,
) -> Value {
    if record.get("state").and_then(Value::as_str) != Some("pending_runtime_key") {
        return record;
    }
    let expired = record
        .get("pairing_expires_at")
        .and_then(Value::as_str)
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|expires| chrono::Utc::now() > expires.with_timezone(&chrono::Utc))
        .unwrap_or(false);
    if !expired {
        return record;
    }
    let Some(agent_id) = record
        .get("agent_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
    else {
        return record;
    };
    let changed_at = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let _ = state
        .persistence
        .agents()
        .set_state(&agent_id, "pairing_expired", &changed_at)
        .await;
    if state.config.development_mode
        && let Ok(realm) = ensure_self_realm(state, session).await
    {
        let grant_ids = {
            let proj = state.projection.lock();
            Some(proj.grant_ids_for_subject(&agent_id))
        }
        .unwrap_or_default();
        let _ = submit_revoke_agent_grants(state, session, &realm, &grant_ids).await;
    }
    if let Some(obj) = record.as_object_mut() {
        obj.insert(
            "state".to_owned(),
            Value::String("pairing_expired".to_owned()),
        );
    }
    record
}

pub(super) async fn lifecycle_transition(
    state: &AppState,
    aa: &AuthArgs,
    req: &Request,
    agent_id: String,
    new_state: AgentLifecycleState,
    event_kind: &str,
    reason: Option<String>,
    sidecar_exposure_ack: Option<Value>,
) -> Result<AgentLifecycleOutcome, AppError> {
    let session = aa.authenticated_session(state, req).await?;
    let record = require_agent_controller(state, &session, &agent_id).await?;
    let sidecar_exposure_ack =
        normalize_sidecar_exposure_ack(sidecar_exposure_ack, &session.actor)?;
    let status_changed_at = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    // Read the current persisted state so the durable transition carries the
    // accurate `previous_status` (resume comes from `paused`, etc.).
    let previous_status = record
        .get("state")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "active".to_owned());
    // AKP-0008 §4.11 (dev option B): drive the FSM reducer with the durable
    // `ak.self.agent.{pause,resume,deactivate}` event authored by the
    // controller, and on deactivate fan-out the revocation chain
    // (`ak.agent.key.revoke` + `ak.capability.revoke` for every grant the
    // agent holds). Production submits the lifecycle event from inkson.
    if state.config.development_mode {
        let realm = ensure_self_realm(state, &session).await?;
        submit_durable_agent_lifecycle(
            state,
            &session,
            &realm,
            &agent_id,
            event_kind,
            &previous_status,
            reason.as_deref(),
            sidecar_exposure_ack.as_ref(),
        )
        .await?;
        if event_kind == "ak.self.agent.deactivate" {
            let (key_ids, grant_ids) = {
                let proj = state.projection.lock();
                Some({
                    (
                        proj.authorized_key_ids_for(&agent_id),
                        proj.grant_ids_for_subject(&agent_id),
                    )
                })
            }
            .unwrap_or_default();
            submit_revoke_agent_keys(state, &session, &realm, &agent_id, &key_ids).await?;
            submit_revoke_agent_grants(state, &session, &realm, &grant_ids).await?;
        }
    } else {
        let mut payload = json!({
            "agent_id": agent_id,
            "controller_id": session.actor.clone(),
            "transition": match event_kind {
                "ak.self.agent.pause" => "pause",
                "ak.self.agent.resume" => "resume",
                "ak.self.agent.deactivate" => "deactivate",
                _ => new_state.as_wire_str(),
            },
            "previous_status": previous_status,
            "status_changed_at": status_changed_at.clone(),
        });
        // pause / resume carry the spec-required `freshness_frontier`;
        // deactivate carries none (SPEC-SOL-003 resolution).
        if event_kind != "ak.self.agent.deactivate" {
            payload.as_object_mut().expect("payload object").insert(
                "freshness_frontier".to_owned(),
                json!({ "captured_at": status_changed_at.clone() }),
            );
        }
        if let Some(reason) = reason.as_ref() {
            payload
                .as_object_mut()
                .expect("payload object")
                .insert("reason".to_owned(), Value::String(reason.clone()));
        }
        if event_kind == "ak.self.agent.resume"
            && let Some(ack) = sidecar_exposure_ack
        {
            payload
                .as_object_mut()
                .expect("payload object")
                .insert("sidecar_exposure_ack".to_owned(), ack);
        }
        append_audit_log(state, Some(&session.actor), event_kind, payload, "accepted").await;
    }
    // Persist the lifecycle state transition on the agent_principal row so
    // list/get reflect the new status (the durable event drives the reducer
    // FSM; this row is the read-side projection consumed by the HTTP API).
    let _ = state
        .persistence
        .agents()
        .set_state(&agent_id, new_state.as_wire_str(), &status_changed_at)
        .await;
    // spec `agent_lifecycle_state` = `operation_status_outcome` =
    // `{ok: true, status}` (status is the post-transition `agent_status`).
    Ok(AgentLifecycleOutcome {
        ok: true,
        status: new_state,
    })
}

#[endpoint(
    operation_id = "ak.self.agent.command.pause",
    tags("agents"),
    summary = "Pause a personal agent",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.command.pause"))]
pub(super) async fn pause_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentPauseRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentLifecycleOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    json_ok(
        lifecycle_transition(
            state,
            &aa,
            req,
            agent_id.into_inner(),
            AgentLifecycleState::Paused,
            "ak.self.agent.pause",
            body.reason,
            None,
        )
        .await?,
    )
}

#[endpoint(
    operation_id = "ak.self.agent.command.resume",
    tags("agents"),
    summary = "Resume a paused personal agent",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.command.resume"))]
pub(super) async fn resume_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentResumeRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentLifecycleOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    json_ok(
        lifecycle_transition(
            state,
            &aa,
            req,
            agent_id.into_inner(),
            AgentLifecycleState::Active,
            "ak.self.agent.resume",
            None,
            body.sidecar_exposure_ack,
        )
        .await?,
    )
}

#[endpoint(
    operation_id = "ak.self.agent.command.deactivate",
    tags("agents"),
    summary = "Deactivate a personal agent (terminal lifecycle state)",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.command.deactivate"))]
pub(super) async fn deactivate_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentDeactivateRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentLifecycleOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    json_ok(
        lifecycle_transition(
            state,
            &aa,
            req,
            agent_id.into_inner(),
            AgentLifecycleState::Deactivated,
            "ak.self.agent.deactivate",
            body.reason,
            None,
        )
        .await?,
    )
}

#[endpoint(
    operation_id = "ak.self.agent.command.rotate_key",
    tags("agents"),
    summary = "Rotate the agent runtime key (revoke + authorize chain)",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.command.rotate_key"))]
pub(super) async fn rotate_agent_key(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentRotateKeyRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentRotateKeyOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    require_agent_controller(state, &session, &agent_id).await?;
    let body = body.into_inner();
    let _replacement_kid = body
        .replacement_key
        .get("kid")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::invalid_param("replacement_key.kid is required"))?;
    Err(AppError::unsupported_feature(
        "agent key rotation requires a durable revoke + authorize event chain and is not available",
    ))
}

#[endpoint(
    operation_id = "ak.self.agent.grant.command.attach",
    tags("agents"),
    summary = "Attach a capability grant to an agent",
    status_codes(201, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.grant.command.attach"))]
pub(super) async fn attach_agent_grant(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentGrantAttachRequestBody>,
    depot: &mut Depot,
    res: &mut Response,
    req: &mut Request,
) -> JsonResult<AgentGrantAttachOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    require_agent_controller(state, &session, &agent_id).await?;
    let body = body.into_inner();
    // spec `agent_grant_attach_request_body` = `{grant: object}`.
    if !body.grant.is_object() {
        return Err(AppError::invalid_param("grant must be an object"));
    }
    // spec `agent_grant_attach_outcome.grant_id` MUST be a `ak:grant:<uuidv7>`.
    let grant_id_str = ids::generate_grant_id();
    let grant_id = GrantId::new(grant_id_str.clone())
        .map_err(|err| AppError::internal(format!("generated grant id invalid: {err}")))?;
    // AKP-0008 §4.11 (dev option B): write the real `ak.capability.grant`
    // authored by the controller. Production submits this from inkson.
    if state.config.development_mode {
        let realm = ensure_self_realm(state, &session).await?;
        attach_agent_grant_event(
            state,
            &session,
            &realm,
            &agent_id,
            &grant_id_str,
            &body.grant,
        )
        .await?;
    } else {
        append_audit_log(
            state,
            Some(&session.actor),
            "ak.self.agent.grant.command.attach",
            json!({
                "agent_id": agent_id,
                "grant_id": grant_id,
                "grant": body.grant,
            }),
            "accepted",
        )
        .await;
    }
    res.status_code(StatusCode::CREATED);
    // spec `agent_grant_attach_outcome` = `{ok, grant_id}`.
    json_ok(AgentGrantAttachOutcome { ok: true, grant_id })
}

#[endpoint(
    operation_id = "ak.self.agent.grant.resource.delete",
    tags("agents"),
    summary = "Detach (revoke) a capability grant from an agent",
    status_codes(200, 400, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.grant.resource.delete"))]
pub(super) async fn detach_agent_grant(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    grant_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentGrantDetachOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    let grant_id = grant_id.into_inner();
    require_agent_controller(state, &session, &agent_id).await?;
    if !grant_id.starts_with("ak:accountability_grant:") && !grant_id.starts_with("ak:grant:") {
        return Err(AppError::invalid_param(
            "grant_id must be a ak:accountability_grant:<uuidv7> or ak:grant:<uuidv7> typed id",
        ));
    }
    let revoked_at = now();
    append_audit_log(
        state,
        Some(&session.actor),
        "ak.self.agent.grant.resource.delete",
        json!({
            "agent_id": agent_id,
            "grant_id": grant_id,
        }),
        "accepted",
    )
    .await;
    // AKP-0008 §4.11 (dev option B): detach of a capability grant MUST emit
    // the real revoke event so the authz projection and cache converge. An
    // accountability-grant detach is a separate governance object, so it stays
    // audit-only here until that cell family is introduced.
    if state.config.development_mode && is_capability_grant_id(&grant_id) {
        let realm = ensure_self_realm(state, &session).await?;
        revoke_capability_grant(state, &session, &realm, &grant_id).await?;
    }
    // spec `agent_grant_detach_outcome` = `{ok, revoked_at}`.
    json_ok(AgentGrantDetachOutcome {
        ok: true,
        revoked_at,
    })
}
