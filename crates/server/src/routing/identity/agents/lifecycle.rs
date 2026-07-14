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
    let avatar_blob_ref = body.avatar_blob_ref.map(|value| value.to_string());
    let now_utc = chrono::Utc::now();
    validate_agent_slug(&agent_slug)
        .map_err(|err| AppError::invalid_param(format!("slug is invalid: {err}")))?;
    let requested_scope = serde_json::to_value(&body.requested_scope)
        .map_err(|error| AppError::invalid_param(format!("requested_scope is invalid: {error}")))?;
    let active_recovery_policy = state
        .persistence
        .recovery_policies()
        .get_active_for_principal(&controller_id)
        .await
        .map_err(|error| {
            AppError::internal(format!("controller recovery policy lookup failed: {error}"))
        })?;
    if active_recovery_policy.is_none() {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "controller must accept a recovery policy before provisioning a managed Agent",
        )
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_reason_code("recovery_policy_required"));
    }
    let controller_realm = require_controller_principal_control_realm(state, &session).await?;
    let existing = state
        .persistence
        .agents()
        .list_for_controller(&controller_id)
        .await
        .map_err(|err| AppError::internal(format!("agent slug conflict check failed: {err}")))?;
    let mut existing = existing;
    for record in existing.iter_mut() {
        *record = lazily_expire_pairing(state, record.clone()).await?;
    }
    if existing.iter().any(|record| {
        record.agent_slug.as_deref() == Some(agent_slug.as_str())
            && agent_record_reserves_selector_slug(record, &now_utc)
    }) {
        return Err(AppError::invalid_param(
            "slug is already bound to an active or open agent for this controller",
        ));
    }
    let agent_id = generate_agent_principal_did(&state.config.service_id);
    let principal_control_realm_id =
        crate::routing::identity::managed_agent_pcr::allocate_principal_control_realm_id()?;
    let controller_authorization_ref =
        crate::routing::identity::managed_agent_pcr::controller_authorization_ref(&agent_id);
    let pairing_request_id = format!("agent_pairing_request:{}", uuid::Uuid::now_v7());
    let pairing_code = generate_pairing_code();
    let pairing_ttl_ms = body
        .pairing_ttl_ms
        .unwrap_or(15 * 60 * 1000)
        .min(24 * 60 * 60 * 1000);
    let expires_at = now_utc + chrono::Duration::milliseconds(pairing_ttl_ms as i64);
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
    let (accountability_event, selector_event) =
        fanout_provision_subevents(state, &session, &controller_realm, &agent_id, &agent_slug)
            .await?;
    let provision_event_refs = json!({
        "accountability_grant_event_id": accountability_event,
        "selector_claim_event_id": selector_event,
    });
    crate::routing::identity::managed_agent_pcr::persist_managed_agent_did_binding(
        state,
        &agent_id,
        &controller_id,
        &principal_control_realm_id,
        &controller_authorization_ref,
    )
    .await?;
    let controller_account = state
        .persistence
        .accounts()
        .get(&session.actor)
        .await
        .map_err(|error| AppError::internal(format!("controller account lookup failed: {error}")))?
        .ok_or_else(|| AppError::internal("controller account is missing"))?;
    let mut principal = AgentPrincipalRecord::new(
        agent_id.clone(),
        controller_id.clone(),
        principal_control_realm_id.as_str().to_owned(),
        controller_authorization_ref.clone(),
        "pending_runtime_key".to_owned(),
        now_utc,
    );
    principal.controller_account_id =
        Some(ids::typed_uuid_part_expect_internal(&controller_account.id));
    principal.recipient_service_id = Some(state.config.service_id.clone());
    principal.display_name = display_name.clone();
    principal.agent_slug = Some(agent_slug.clone());
    principal.avatar_blob_ref = avatar_blob_ref.clone();
    principal.requested_scope = Some(requested_scope);
    principal.accountability = (!body.accountability.is_null()).then_some(body.accountability);
    principal.provision_event_refs = Some(provision_event_refs);
    principal.pairing_request_id = Some(pairing_request_id.clone());
    principal.pairing_code = Some(pairing_code.clone());
    principal.pairing_expires_at = Some(expires_at);
    state
        .persistence
        .agents()
        .put(principal)
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
            "avatar_blob_ref": avatar_blob_ref,
            "pairing_request_id": pairing_request_id,
            "principal_control_realm_id": principal_control_realm_id,
            "controller_authorization_ref": controller_authorization_ref,
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
        principal_control_realm_id,
        controller_authorization_ref,
        pcr_recovery: AgentProvisionPcrRecovery::default(),
        pairing_request_id,
        pairing_code: Some(pairing_code),
        expires_at,
    })
}

/// `ak.self.agent.command.renew_pairing` — re-open pairing in place on any
/// non-terminal agent (key-management.md §3.6.1). Two branches share the
/// one-time-handle invariant (the fresh `pairing_request_id` + `pairing_code`
/// replace the old tuple, which becomes permanently unresolvable through the
/// same anti-enumeration lookup; the PRINCIPAL is not one-time):
///
/// - Bootstrap re-open (`pending_runtime_key` / `pairing_expired`): status returns to
///   `pending_runtime_key` without changing Realm grants.
/// - Runtime replacement (`active` / `paused`): zero-downtime key replacement. Agent status,
///   existing keys, sessions, and grants all stay untouched; completing the new pairing supersedes
///   every old active key (reason=`superseded_by_repairing`) in the pair transaction.
///
/// Only `deactivated` rejects (deactivation is terminal).
#[endpoint(
    operation_id = "ak.self.agent.command.renew_pairing",
    tags("agents"),
    summary = "Re-open pairing on a non-terminal personal agent",
    status_codes(200, 400, 401, 403, 404, 412, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.command.renew_pairing"))]
pub(super) async fn renew_agent_pairing(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentRenewPairingRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentRenewPairingOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    let body = body.into_inner();
    let record = require_agent_controller(state, &session, &agent_id).await?;
    // Lazy-expire first so a stale pending record renews through the same
    // state path as an observed-expired one.
    let record = lazily_expire_pairing(state, record).await?;
    let bootstrap_reopen = match record.state.as_str() {
        "pending_runtime_key" | "pairing_expired" => true,
        "active" | "paused" => false,
        "deactivated" => {
            return Err(pairing_failed_precondition(
                "agent is deactivated; deactivation is terminal",
            )
            .with_reason_detail("agent_deactivated"));
        }
        _ => {
            return Err(pairing_failed_precondition(
                "agent state does not permit pairing renewal",
            ));
        }
    };
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
    let agent_slug = record.agent_slug.clone().unwrap_or_default();
    if !agent_slug.is_empty() {
        let siblings = state
            .persistence
            .agents()
            .list_for_controller(&session.actor)
            .await
            .map_err(|err| {
                AppError::internal(format!("agent slug conflict check failed: {err}"))
            })?;
        if siblings.iter().any(|sibling| {
            sibling.id != agent_id
                && sibling.agent_slug.as_deref() == Some(agent_slug.as_str())
                && agent_record_reserves_selector_slug(sibling, &now_utc)
        }) {
            return Err(pairing_failed_precondition(
                "slug is already bound to an active or open agent for this controller",
            ));
        }
    }
    let pairing_request_id = format!("agent_pairing_request:{}", uuid::Uuid::now_v7());
    let pairing_code = generate_pairing_code();
    let pairing_ttl_ms = body
        .pairing_ttl_ms
        .unwrap_or(15 * 60 * 1000)
        .min(24 * 60 * 60 * 1000);
    let expires_at = now_utc + chrono::Duration::milliseconds(pairing_ttl_ms as i64);
    let terminal_notification = account_notification_context(&record);
    let mut record = record;
    if bootstrap_reopen {
        record.state = "pending_runtime_key".to_owned();
        record.state_changed_at = Some(now_utc);
    }
    // Runtime replacement is not a state transition: active/paused stay
    // as-is while the fresh handle is open.
    record.pairing_request_id = Some(pairing_request_id.clone());
    record.pairing_code = Some(pairing_code.clone());
    record.pairing_expires_at = Some(expires_at);
    // A runtime-key request submitted against the dead handle must not
    // survive into the renewed pairing.
    record.approval_request_id = None;
    record.runtime_key_request = None;
    record.approval_requested_at = None;
    record.runtime_key_binding_digest = None;
    record.runtime_public_key_digest = None;
    record.runtime_attestation_digest = None;
    record.approval_notification_id = None;
    record.updated_at = now_utc;
    state
        .persistence
        .agents()
        .put(record.clone())
        .await
        .map_err(|err| AppError::internal(format!("agent persist failed: {err}")))?;
    if let Some(context) = terminal_notification {
        persist_terminal_account_notification(state, context, "renewed").await?;
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "ak.self.agent.command.renew_pairing",
        json!({
            "agent_id": agent_id,
            "controller_id": session.actor,
            "slug": agent_slug,
            "pairing_request_id": pairing_request_id,
            "mode": if bootstrap_reopen { "bootstrap_reopen" } else { "runtime_replacement" },
        }),
        "accepted",
    )
    .await;
    let agent_principal_did = arkret_sdk::Did::new(agent_id)
        .map_err(|err| AppError::internal(format!("persisted agent DID invalid: {err}")))?;
    let principal_control_realm_id = RealmId::new(record.principal_control_realm_id.clone())
        .map_err(|error| AppError::internal(format!("persisted Agent PCR invalid: {error}")))?;
    let controller_authorization_ref = record.controller_authorization_ref.clone();
    let pcr_recovery =
        crate::routing::identity::managed_agent_pcr::project_agent_pcr_recovery(state, &record)
            .await?;
    json_ok(AgentRenewPairingOutcome {
        agent_id: agent_principal_did,
        principal_control_realm_id,
        controller_authorization_ref,
        pcr_recovery,
        pairing_mode: if bootstrap_reopen {
            AgentPairingMode::Bootstrap
        } else {
            AgentPairingMode::Replacement
        },
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
    // Lazily expire any agent past its pairing window before projecting, so
    // list reflects `pairing_expired` without changing Realm grants.
    let mut agents = Vec::with_capacity(records.len());
    for record in records {
        let record = reconcile_accepted_agent_authorization(state, record).await?;
        let record = lazily_expire_pairing(state, record).await?;
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
    summary = "Get a personal agent by id (controller or policy-authorized service)",
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
    let service_authorized = agent_projection_service_authorized(state, req);
    let session = if service_authorized {
        None
    } else {
        Some(aa.authenticated_session(state, req).await?)
    };
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
    if let Some(session) = session.as_ref() {
        if record.controller_id != session.actor {
            return Err(AppError::not_found("agent not found"));
        }
    }
    let record = reconcile_accepted_agent_authorization(state, record).await?;
    let record = lazily_expire_pairing(state, record).await?;
    let mut view = agent_view_from_record(state, &record).await?;
    if service_authorized {
        if let Some(key_state) = view.key_state.as_mut() {
            key_state.pairing_code = None;
        }
    }
    // Surface the agent's effective capability grants from the authz
    // projection so the controller UI can list and revoke them; the
    // persisted record itself never carries grants.
    view.grants = state
        .authz
        .grants_for_subject_all_realms(&agent_id)
        .into_iter()
        .filter_map(|grant| {
            Some(GrantSnapshot {
                grant_id: GrantId::new(grant.grant_id).ok()?,
                status: Some("active".to_owned()),
                grant_digest: None,
                expires_at: grant.expires_at,
            })
        })
        .collect();
    json_ok(view)
}

/// Lazily expire a `pending_runtime_key` agent whose pairing window has
/// elapsed. Pairing state is independent from Realm grants, so expiry never
/// creates, revokes, or rewrites a grant.
pub(super) async fn lazily_expire_pairing(
    state: &AppState,
    mut record: AgentPrincipalRecord,
) -> Result<AgentPrincipalRecord, AppError> {
    if !agent_pairing_handle_is_open(&record) {
        return Ok(record);
    }
    let expired = record
        .pairing_expires_at
        .map(|expires| chrono::Utc::now() > expires)
        .unwrap_or(false);
    if !expired {
        return Ok(record);
    }
    let agent_id = record.id.clone();
    let bootstrap_expired = record.state == "pending_runtime_key";
    let terminal_notification = account_notification_context(&record);
    let now = chrono::Utc::now();
    if bootstrap_expired {
        record.state = "pairing_expired".to_owned();
        record.state_changed_at = Some(now);
    }
    record.approval_request_id = None;
    record.runtime_key_request = None;
    record.approval_requested_at = None;
    record.runtime_key_binding_digest = None;
    record.runtime_public_key_digest = None;
    record.runtime_attestation_digest = None;
    record.approval_notification_id = None;
    record.updated_at = now;
    state
        .persistence
        .agents()
        .put(record.clone())
        .await
        .map_err(|error| {
            AppError::internal(format!("failed to persist expired Agent pairing: {error}"))
        })?;
    if let Some(context) = terminal_notification
        && let Err(error) = persist_terminal_account_notification(state, context, "expired").await
    {
        tracing::error!(message = %error.message, agent_id, "failed to persist expired Agent approval notification");
    }
    Ok(record)
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
    let terminal_notification = (event_kind == "ak.self.agent.deactivate")
        .then(|| account_notification_context(&record))
        .flatten();
    let sidecar_exposure_ack =
        normalize_sidecar_exposure_ack(sidecar_exposure_ack, &session.actor)?;
    // AKP-0008 D1: the durable lifecycle event and its fan-out only exist on
    // the development fan-out path. Production MUST fail closed instead of
    // mutating the read-side row without a durable transition (a deactivate
    // that flips the projection but revokes nothing is worse than an error).
    if !state.config.development_mode {
        return Err(AppError::unsupported_feature(
            "production agent lifecycle transitions require protocol-valid delegated fan-out",
        )
        .with_wire_code("agent_lifecycle_fanout_unavailable"));
    }
    // Resume re-disclosure (key-management.md §3.6.1): sidecar circles the
    // controller created while the agent was paused re-enter the agent's
    // eligibility set on resume, so the controller MUST explicitly
    // re-acknowledge them; silent resume is forbidden.
    if event_kind == "ak.self.agent.resume" {
        let paused_at = Some(record.updated_at);
        let new_sidecar_ids = controller_sidecar_circles_since(state, &session.actor, paused_at);
        if !new_sidecar_ids.is_empty() {
            let acked: std::collections::BTreeSet<String> = sidecar_exposure_ack
                .as_ref()
                .and_then(|ack| ack.get("sidecar_refs"))
                .and_then(Value::as_array)
                .map(|refs| {
                    refs.iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            let missing: Vec<&String> = new_sidecar_ids
                .iter()
                .filter(|circle_id| !acked.contains(*circle_id))
                .collect();
            if !missing.is_empty() {
                return Err(AppError::new(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "resume requires explicit sidecar exposure acknowledgement for {} sidecar circle(s) created while paused",
                        missing.len()
                    ),
                )
                .with_status(salvo::http::StatusCode::PRECONDITION_FAILED)
                .with_reason_code("sidecar_exposure_ack_required"));
            }
        }
    }
    let status_changed_at = chrono::Utc::now();
    // Read the current persisted state so the durable transition carries the
    // accurate `previous_status` (resume comes from `paused`, etc.).
    let previous_status = record.state.clone();
    // AKP-0008 §4.11 (dev option B): drive the FSM reducer with the durable
    // `ak.self.agent.{pause,resume,deactivate}` event authored as the Agent
    // and executed/signed by its controller, and on deactivate fan-out the revocation chain
    // (`ak.agent.key.revoke` + `ak.capability.revoke` for every grant the
    // agent holds). Production fails closed above.
    let realm = record.principal_control_realm_id.clone();
    let authorization_ref = record.controller_authorization_ref.clone();
    submit_durable_agent_lifecycle(
        state,
        &session,
        &realm,
        &agent_id,
        &authorization_ref,
        event_kind,
        &previous_status,
        reason.as_deref(),
        sidecar_exposure_ack.as_ref(),
    )
    .await?;
    if event_kind == "ak.self.agent.deactivate" {
        let (key_ids, grant_locations) = {
            let proj = state.projection.lock();
            (
                proj.authorized_key_ids_for(&agent_id),
                proj.unrevoked_grant_locations_for_subject(&agent_id),
            )
        };
        submit_revoke_agent_keys(
            state,
            &session,
            &realm,
            &agent_id,
            &authorization_ref,
            &key_ids,
            None,
        )
        .await?;
        submit_revoke_agent_grants(state, &session, &grant_locations).await?;
    }
    // Persist the lifecycle state transition on the agent_principal row so
    // list/get reflect the new status (the durable event drives the reducer
    // FSM; this row is the read-side projection consumed by the HTTP API).
    let mut updated_record = record;
    updated_record.state = new_state.as_wire_str().to_owned();
    updated_record.state_changed_at = Some(status_changed_at);
    updated_record.updated_at = status_changed_at;
    if event_kind == "ak.self.agent.deactivate" {
        updated_record.approval_request_id = None;
        updated_record.runtime_key_request = None;
        updated_record.approval_requested_at = None;
        updated_record.runtime_key_binding_digest = None;
        updated_record.runtime_public_key_digest = None;
        updated_record.runtime_attestation_digest = None;
        updated_record.approval_notification_id = None;
    }
    state
        .persistence
        .agents()
        .put(updated_record)
        .await
        .map_err(|error| AppError::internal(format!("agent lifecycle persist failed: {error}")))?;
    if let Some(context) = terminal_notification {
        persist_terminal_account_notification(state, context, "deactivated").await?;
    }
    // spec `agent_lifecycle_state` = `operation_status_outcome` =
    // `{ok: true, status}` (status is the post-transition `agent_status`).
    Ok(AgentLifecycleOutcome {
        ok: true,
        status: new_state,
    })
}

/// Active sidecar Circles owned by `controller` created strictly after
/// `since`. `since=None` (missing/unparsable pause timestamp) fails closed by
/// treating every sidecar circle as new, forcing an explicit ack.
fn controller_sidecar_circles_since(
    state: &AppState,
    controller: &str,
    since: Option<chrono::DateTime<chrono::Utc>>,
) -> Vec<String> {
    let projection = state.projection.lock();
    projection
        .circles
        .values()
        .filter(|circle| {
            circle.created_by == controller
                && circle.directory_visibility == "members"
                && circle.state == crate::reducer::CircleLifecycleState::Active
                && circle.title
                    == super::sidecar::sidecar_short_name(
                        &super::sidecar::controller_agent_circle_key(&circle.realm_id, controller),
                    )
                && since.is_none_or(|since| circle.created_at > since)
        })
        .map(|circle| circle.circle_id.clone())
        .collect()
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
    let record = require_agent_controller(state, &session, &agent_id).await?;
    let body = body.into_inner();
    let grant_constraints = body
        .grant
        .constraints
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            AppError::internal(format!("grant constraint encoding failed: {error}"))
        })?;
    if !agent_grant_within_requested_scope(
        &record,
        &body.grant.actions,
        &body.grant.resources,
        &grant_constraints,
    ) {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "grant exceeds the immutable Agent requested_scope ceiling",
        )
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_wire_code("agent_grant_exceeds_requested_scope"));
    }
    if !state.config.development_mode {
        return Err(AppError::unsupported_feature(
            "production Agent grant attachment requires protocol-valid Event authoring",
        )
        .with_wire_code("agent_grant_fanout_unavailable"));
    }
    let grant_id = body.grant.id.clone();
    attach_agent_grant_event(state, &session, &agent_id, &body.grant).await?;
    append_audit_log(
        state,
        Some(&session.actor),
        "ak.self.agent.grant.command.attach",
        json!({
            "agent_id": agent_id,
            "grant_id": grant_id,
            "realm_id": body.grant.realm_id,
        }),
        "accepted",
    )
    .await;
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
    let typed_grant_id = GrantId::new(grant_id.clone())
        .map_err(|error| AppError::invalid_param(format!("grant_id is invalid: {error}")))?;
    if !state.config.development_mode {
        return Err(AppError::unsupported_feature(
            "production Agent grant detachment requires protocol-valid Event authoring",
        )
        .with_wire_code("agent_grant_fanout_unavailable"));
    }
    let locations = {
        let projection = state.projection.lock();
        projection
            .grant_locations_for_subject(&agent_id)
            .into_iter()
            .filter(|(candidate, _)| candidate == typed_grant_id.as_str())
            .collect::<Vec<_>>()
    };
    let [(matched_grant_id, realm_id)] = locations.as_slice() else {
        return Err(AppError::not_found("Agent capability grant not found"));
    };
    revoke_capability_grant(state, &session, realm_id, matched_grant_id).await?;
    let revoked_at = now();
    append_audit_log(
        state,
        Some(&session.actor),
        "ak.self.agent.grant.resource.delete",
        json!({
            "agent_id": agent_id,
            "grant_id": typed_grant_id,
            "realm_id": realm_id,
        }),
        "accepted",
    )
    .await;
    // spec `agent_grant_detach_outcome` = `{ok, revoked_at}`.
    json_ok(AgentGrantDetachOutcome {
        ok: true,
        revoked_at,
    })
}
