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
    // Spec `agent_provision_request_body` carries no controller_did —
    // the controller is ALWAYS the authenticated principal.
    let controller_did = session.actor.clone();
    let display_name = body
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let agent_slug = body
        .agent_slug
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let now_utc = chrono::Utc::now();
    if let Some(slug) = agent_slug.as_deref() {
        validate_agent_slug(slug)
            .map_err(|err| AppError::invalid_param(format!("agent_slug is invalid: {err}")))?;
        let existing = state
            .persistence
            .agents()
            .list_for_controller(&controller_did)
            .await
            .map_err(|err| {
                AppError::internal(format!("agent slug conflict check failed: {err}"))
            })?;
        let mut existing = existing;
        for record in existing.iter_mut() {
            *record = lazily_expire_pairing(state, &session, record.clone()).await;
        }
        if existing.iter().any(|record| {
            record.get("agent_slug").and_then(Value::as_str) == Some(slug)
                && agent_record_reserves_selector_slug(record, &now_utc)
        }) {
            return Err(AppError::invalid_param(
                "agent_slug is already bound to an active or open agent for this controller",
            ));
        }
    }
    // The agent's actor DID is server-generated (the spec body carries no
    // client-supplied agent_id). did:webvh-only red line: derive it on the
    // deployment service host with a self-certifying SCID, never did:web.
    let agent_id = {
        let host = crate::config::did_host_from_service_did(&state.config.service_did)
            .unwrap_or_else(|| "soland.local".to_owned());
        let controller_slug = session.actor.replace([':', '/', '.'], "-");
        let skeleton = serde_json::json!({
            "scid": "{SCID}",
            "host": host,
            "path": format!("webvh:agent-actor:{controller_slug}"),
        });
        let scid =
            crate::routing::identity::webvh_validation::derive_webvh_scid_from_skeleton(&skeleton)
                .unwrap_or_else(|_| controller_slug.clone());
        format!("did:webvh:{scid}:{host}:webvh:agent-actor:{controller_slug}")
    };
    let agent_principal_id = generate_agent_principal_did(&state.config.service_did);
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
    // paths have a real principal to operate on (CKP-0008). Per the spec
    // agent lifecycle the agent starts `pending_runtime_key`; the gate
    // `ck.gate.account.command.pair_agent_key` flips it to `active` once the
    // runtime key is authorized.
    // CKP-0008 D1: development can materialize the agent's identity sub-events
    // with dev proofs. Production fails closed above until the delegated
    // fan-out has a protocol-valid authorization_ref + detached-JWS path.
    let realm = ensure_self_realm(state, &session).await?;
    let (profile_event, accountability_event, grant_ids) = fanout_provision_subevents(
        state,
        &session,
        &realm,
        &agent_principal_id,
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
            "agent_principal_id": agent_principal_id,
            "controller_did": controller_did,
            "agent_id": agent_id,
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
            "agent_principal_id": agent_principal_id,
            "controller_did": controller_did,
            "agent_id": agent_id,
            "display_name": display_name,
            "agent_slug": agent_slug,
            "pairing_request_id": pairing_request_id,
        }),
        "accepted",
    )
    .await;
    res.status_code(StatusCode::CREATED);
    let agent_principal_did = arkret_sdk::Did::new(agent_principal_id).map_err(|err| {
        AppError::internal(format!("generated agent principal DID invalid: {err}"))
    })?;
    json_ok(AgentProvisionOutcome {
        agent_principal_id: agent_principal_did,
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
    // CKP-0008 §4.3.2 — lazily expire any agent past its pairing window
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

/// Spec §11 adapter registry ids. `supported_protocols` returned by
/// discover MUST be a subset of this set; a registered endpoint that
/// declares a protocol outside the registry is dropped from the
/// discover projection rather than surfaced verbatim.
pub(super) const AGENT_ADAPTER_REGISTRY_IDS: [&str; 4] =
    ["a2a", "acp", "mcp_bridge", "http_custom"];

#[endpoint(
    operation_id = "ak.self.agent.protocol.query.discover",
    tags("agents"),
    summary = "Discover an agent runtime's declared external protocol endpoints",
    status_codes(200, 400, 401, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.protocol.query.discover"))]
pub(super) async fn discover_agent_endpoint(
    aa: AuthArgs,
    body: JsonBody<AgentProtocolDiscoverRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentProtocolDiscoverOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    // Any authenticated principal may probe the public agent endpoint
    // registry; the discover surface returns only the projection of an
    // accepted `ck.agent.endpoint` event (no controller-private fields).
    let _session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let agent_id = body.agent_id.as_str().to_owned();
    let snapshot = {
        let proj = state.projection.lock();
        proj.agents.get(&agent_id).cloned()
    };
    let Some(projection) = snapshot else {
        // Fail closed: an agent with no accepted `ck.agent.endpoint`
        // cannot be discovered (spec §12 `discovery_failed`).
        return Err(
            AppError::not_found("agent endpoint not registered").with_wire_code("discovery_failed")
        );
    };
    // Constrain to the §11 adapter registry so callers can rely on the
    // returned ids being valid adapter selectors.
    let supported_protocols: Vec<String> = projection
        .supported_protocols
        .iter()
        .filter(|p| AGENT_ADAPTER_REGISTRY_IDS.contains(&p.as_str()))
        .cloned()
        .collect();
    json_ok(AgentProtocolDiscoverOutcome {
        agent_id: body.agent_id,
        supported_protocols,
        agent_card_url: projection.agent_card_url,
        metadata_url: projection.metadata_url,
        endpoint_url: projection.endpoint_url,
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
    agent_principal_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_principal_id.into_inner();
    validate_agent_principal_id(&agent_id)?;
    let record = state
        .persistence
        .agents()
        .get(&agent_id)
        .await
        .map_err(|err| AppError::internal(format!("agent get failed: {err}")))?
        .ok_or_else(|| AppError::not_found("agent not found"))?;
    // Controller-self only: hide others' agents behind 404 to avoid enumeration.
    if record.get("controller_did").and_then(Value::as_str) != Some(session.actor.as_str()) {
        return Err(AppError::not_found("agent not found"));
    }
    let record = lazily_expire_pairing(state, &session, record).await;
    json_ok(agent_view_from_record(&record))
}

/// CKP-0008 §4.3.2 — lazily expire a `pending_runtime_key` agent whose
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
    let Some(agent_principal_id) = record
        .get("agent_principal_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
    else {
        return record;
    };
    let changed_at = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let _ = state
        .persistence
        .agents()
        .set_state(&agent_principal_id, "pairing_expired", &changed_at)
        .await;
    if state.config.development_mode
        && let Ok(realm) = ensure_self_realm(state, session).await
    {
        let grant_ids = {
            let proj = state.projection.lock();
            Some(proj.grant_ids_for_subject(&agent_principal_id))
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
    // CKP-0008 §4.11 (dev option B): drive the FSM reducer with the durable
    // `ck.self.agent.{pause,resume,deactivate}` event authored by the
    // controller, and on deactivate fan-out the revocation chain
    // (`ck.agent.key.revoke` + `ck.capability.revoke` for every grant the
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
            "agent_principal_id": agent_id,
            "controller_principal_id": session.actor.clone(),
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
    agent_principal_id: PathParam<String>,
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
            agent_principal_id.into_inner(),
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
    agent_principal_id: PathParam<String>,
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
            agent_principal_id.into_inner(),
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
    agent_principal_id: PathParam<String>,
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
            agent_principal_id.into_inner(),
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
    agent_principal_id: PathParam<String>,
    body: JsonBody<AgentRotateKeyRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentRotateKeyOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_principal_id.into_inner();
    require_agent_controller(state, &session, &agent_id).await?;
    let body = body.into_inner();
    // spec `agent_rotate_key_request_body` = `{replacement_key, proof_of_possession}`.
    let replacement_kid = body
        .replacement_key
        .get("kid")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::invalid_param("replacement_key.kid is required"))?;
    append_audit_log(
        state,
        Some(&session.actor),
        "ak.self.agent.command.rotate_key",
        json!({
            "agent_principal_id": agent_id,
            "replacement_key": body.replacement_key,
        }),
        "accepted",
    )
    .await;
    let _ = replacement_kid;
    // spec `agent_rotate_key_outcome` = `{ok, authorized_event_ref}`. The
    // authorized event id pins the new key authorization (P2-impl: emit the
    // real ak.agent.key.revoke + ak.agent.key.authorize chain under it and
    // invalidate session-grants bound to the revoked key).
    let authorized_event_ref = EventId::new(ids::generate_event_id())
        .map_err(|err| AppError::internal(format!("generated event id invalid: {err}")))?;
    json_ok(AgentRotateKeyOutcome {
        ok: true,
        authorized_event_ref,
    })
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
    agent_principal_id: PathParam<String>,
    body: JsonBody<AgentGrantAttachRequestBody>,
    depot: &mut Depot,
    res: &mut Response,
    req: &mut Request,
) -> JsonResult<AgentGrantAttachOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_principal_id.into_inner();
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
    // CKP-0008 §4.11 (dev option B): write the real `ck.capability.grant`
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
                "agent_principal_id": agent_id,
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
    agent_principal_id: PathParam<String>,
    grant_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentGrantDetachOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_principal_id.into_inner();
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
            "agent_principal_id": agent_id,
            "grant_id": grant_id,
        }),
        "accepted",
    )
    .await;
    // CKP-0008 §4.11 (dev option B): detach of a capability grant MUST emit
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
