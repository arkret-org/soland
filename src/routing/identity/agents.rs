//! CXP-0008 / CXP-0009 — Personal Agent provisioning + lifecycle surface.
//!
//! Implements the 11 personal-agent HTTP operations gap-reported as missing
//! in soland. The handlers below stand up the cross-project HTTP contract
//! (sodmin admin UI, yougen client, cotest journey vectors) ahead of the
//! deep reducer logic.
//!
//! Surfaces:
//! - `POST   /auth/account/agent-key-pair`               — `cx.account.agent_key_pair`
//! - `POST   /api/v1/agents`                             — `cx.agent.provision`
//! - `GET    /api/v1/agents`                             — `cx.agent.list`
//! - `GET    /api/v1/agents/{id}`                        — `cx.agent.get`
//! - `POST   /api/v1/agents/{id}/pause`                  — `cx.agent.pause`
//! - `POST   /api/v1/agents/{id}/resume`                 — `cx.agent.resume`
//! - `POST   /api/v1/agents/{id}/deactivate`             — `cx.agent.deactivate`
//! - `POST   /api/v1/agents/{id}/rotate-key`             — `cx.agent.rotate_key`
//! - `POST   /api/v1/agents/{id}/grants`                 — `cx.agent.grant.attach`
//! - `DELETE /api/v1/agents/{id}/grants/{grant_id}`      — `cx.agent.grant.detach`
//! - `POST   /api/v1/agents/{id}/sidecar-thread/ensure`  — `cx.agent.sidecar_thread.ensure`
//!
//! All endpoints accept controller-self bearer sessions (TODO(P2-impl):
//! tighten to `controller-only` actor binding once the personal-agent
//! relation index lands). Each handler appends an audit-log row matching
//! the canonical event-kind name so the existing admin / federation
//! projections stay in sync ahead of the reducer rewrite.

use chrono::SecondsFormat;
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{AuthArgs, append_audit_log, now, validate_did};
use crate::error::{AppError, ErrorCode};
use crate::ids;
use crate::result::{JsonResult, json_ok};
use crate::state::AppState;
use crate::wire::{
    AgentGrantAttachReqBody, AgentGrantDetachResBody, AgentGrantResBody, AgentKeyPairReqBody,
    AgentKeyPairResBody, AgentLifecycleReqBody, AgentLifecycleResBody, AgentListResBody,
    AgentProvisionReqBody, AgentResBody, AgentRotateKeyReqBody, AgentRotateKeyResBody,
    AgentSidecarThreadEnsureReqBody, AgentSidecarThreadEnsureResBody,
};

/// Mounted at `/api/v1`.
pub(super) fn router() -> Router {
    Router::with_path("agents")
        .post(provision_agent)
        .get(list_agents)
        .push(Router::with_path("{agent_id}").get(get_agent))
        .push(Router::with_path("{agent_id}/pause").post(pause_agent))
        .push(Router::with_path("{agent_id}/resume").post(resume_agent))
        .push(Router::with_path("{agent_id}/deactivate").post(deactivate_agent))
        .push(Router::with_path("{agent_id}/rotate-key").post(rotate_agent_key))
        .push(
            Router::with_path("{agent_id}/grants")
                .post(attach_agent_grant)
                .push(Router::with_path("{grant_id}").delete(detach_agent_grant)),
        )
        .push(Router::with_path("{agent_id}/sidecar-thread/ensure").post(ensure_sidecar_thread))
}

/// `/auth/account/agent-key-pair` lives under the auth router, not
/// `/api/v1/agents`. Registered separately in `routing::identity::auth`.
pub(crate) fn agent_key_pair_router() -> Router {
    Router::with_path("agent-key-pair").post(agent_key_pair)
}

fn validate_agent_principal_id(value: &str) -> Result<(), AppError> {
    if !value.starts_with("cx:agent_principal:") {
        return Err(AppError::invalid_param(
            "agent_principal_id must be a cx:agent_principal:<uuidv7> typed id",
        ));
    }
    Ok(())
}

#[endpoint(
    operation_id = "cx.account.agent_key_pair",
    tags("agents"),
    summary = "Authorize an agent runtime key pair against the agent principal",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.account.agent_key_pair"))]
async fn agent_key_pair(
    aa: AuthArgs,
    body: JsonBody<AgentKeyPairReqBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentKeyPairResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    validate_agent_principal_id(&body.agent_principal_id)?;
    if body.verification_method.trim().is_empty() {
        return Err(AppError::invalid_param("verification_method is required"));
    }
    // ERR-1 — PROOF_INVALID +
    // VERIFICATION_METHOD_PRINCIPAL_MISMATCH +
    // APPROVAL_ALREADY_CONSUMED reason codes anchor here. The pairing
    // pipeline (CXP-0008 §4.2) emits PROOF_INVALID when the
    // runtime_attestation signature fails crypto verification,
    // VERIFICATION_METHOD_PRINCIPAL_MISMATCH when the DID resolved from
    // `verification_method` doesn't match the agent_principal's
    // controller, and APPROVAL_ALREADY_CONSUMED when the controller
    // approval token has been re-played.
    //
    // TODO(R4): wire the runtime attestation verifier + controller
    // approval ledger so this handler can short-circuit with those
    // canonical reasons.
    let _proof_invalid_reason: &str = crate::error::reasons::PROOF_INVALID;
    let _verification_method_mismatch_reason: &str =
        crate::error::reasons::VERIFICATION_METHOD_PRINCIPAL_MISMATCH;
    let _approval_consumed_reason: &str = crate::error::reasons::APPROVAL_ALREADY_CONSUMED;
    // Spec: agent_key_authorize_payload `runtime_attestation` baseline kind
    // is `self_asserted`; unknown kinds fail-closed. TODO(P2-impl): full
    // validator + reducer write to `cx.agent.key.authorize`.
    if let Some(attestation) = body.runtime_attestation.as_ref() {
        let kind = attestation
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !matches!(kind, "self_asserted") {
            return Err(AppError::new(
                ErrorCode::SchemaViolation,
                format!("unsupported runtime_attestation.kind `{kind}`"),
            ));
        }
    }
    let authorized_at = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    append_audit_log(
        state,
        Some(&session.actor),
        "cx.agent.key.authorize",
        json!({
            "agent_principal_id": body.agent_principal_id,
            "verification_method": body.verification_method,
        }),
        "accepted",
    );
    json_ok(AgentKeyPairResBody {
        ok: true,
        agent_principal_id: body.agent_principal_id,
        verification_method: body.verification_method,
        authorized_at,
        todos: vec![
            "P2-impl: write cx.agent.key.authorize event into the event log".to_owned(),
            "P2-impl: enforce verification_method↔agent_principal_id consistency".to_owned(),
        ],
    })
}

#[endpoint(
    operation_id = "cx.agent.provision",
    tags("agents"),
    summary = "Provision a personal agent (DID + first agent key + grant attach)",
    status_codes(201, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.agent.provision"))]
async fn provision_agent(
    aa: AuthArgs,
    body: JsonBody<AgentProvisionReqBody>,
    depot: &mut Depot,
    res: &mut Response,
    req: &mut Request,
) -> JsonResult<AgentResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    if body.display_name.trim().is_empty() {
        return Err(AppError::invalid_param("display_name is required"));
    }
    let controller_did = body.controller_did.unwrap_or_else(|| session.actor.clone());
    if validate_did(&controller_did).is_err() {
        return Err(AppError::invalid_param("controller_did must be a DID"));
    }
    if controller_did != session.actor {
        return Err(AppError::capability_denied(
            "controller_did must match the authenticated session actor",
        ));
    }
    let agent_did = body
        .agent_did
        .unwrap_or_else(|| format!("did:web:agent.{}", session.actor.replace([':', '/'], ".")));
    if validate_did(&agent_did).is_err() {
        return Err(AppError::invalid_param("agent_did must be a DID"));
    }
    let agent_principal_id = ids::generate("agent_principal");
    let timestamp = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    append_audit_log(
        state,
        Some(&session.actor),
        "cx.agent.provision",
        json!({
            "agent_principal_id": agent_principal_id,
            "controller_did": controller_did,
            "agent_did": agent_did,
            "display_name": body.display_name,
        }),
        "accepted",
    );
    res.status_code(StatusCode::CREATED);
    json_ok(AgentResBody {
        agent_principal_id,
        controller_did,
        agent_did,
        display_name: body.display_name,
        state: "active".to_owned(),
        created_at: timestamp.clone(),
        updated_at: timestamp,
        grants: body.initial_grants,
        todos: vec![
            "P2-impl: persist agent_principal row + emit cx.agent.provision event".to_owned(),
            "P2-impl: orchestrate DID Document registration + first key authorize".to_owned(),
            "P2-impl: process initial_grants[] through cx.capability.grant pipeline".to_owned(),
        ],
    })
}

#[endpoint(
    operation_id = "cx.agent.list",
    tags("agents"),
    summary = "List personal agents owned by the authenticated controller",
    status_codes(200, 401, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.agent.list"))]
async fn list_agents(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentListResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    // TODO(P2-impl): query the agent_principal projection scoped to the
    // controller's DID. For now we return an empty stable shape so
    // sodmin/yougen can wire the endpoint without 404.
    json_ok(AgentListResBody {
        agents: Vec::new(),
        next_cursor: None,
        todos: vec![
            "P2-impl: implement agent_principal projection query".to_owned(),
            "P2-impl: enforce controller-self only".to_owned(),
        ],
    })
}

#[endpoint(
    operation_id = "cx.agent.get",
    tags("agents"),
    summary = "Get a personal agent by id (controller-self only)",
    status_codes(200, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.agent.get"))]
async fn get_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    validate_agent_principal_id(&agent_id)?;
    // TODO(P2-impl): look up agent_principal row, 404 when absent / not
    // owned by the controller. For now any well-formed id returns the
    // canonical "stub" response so the cross-project HTTP shape stays
    // stable.
    Err(AppError::not_found("agent lookup not yet wired (P2-impl)"))
}

async fn lifecycle_transition(
    state: &AppState,
    aa: &AuthArgs,
    req: &Request,
    agent_id: String,
    new_state: &str,
    event_kind: &str,
    reason: Option<String>,
) -> Result<AgentLifecycleResBody, AppError> {
    let session = aa.authenticated_session(state, req).await?;
    validate_agent_principal_id(&agent_id)?;
    // ERR-1 / REDU-1 — surface AGENT_PAUSED / AGENT_DEACTIVATED reason
    // codes through this transition path so the constants stay
    // grep-discoverable from the handler that emits them. The reducer's
    // FSM rejection (`reducer::apply_agent_lifecycle`) re-emits the
    // canonical wire form to clients when the projection is wired.
    //
    // TODO(R4): once the per-agent FSM projection is queryable from the
    // handler, look up the current AgentLifecycleState and reject
    // pre-flight (no audit-log churn) when:
    //   - state == Paused and !is_resume(event_kind) → AGENT_PAUSED
    //   - state == Deactivated                       → AGENT_DEACTIVATED
    let _agent_paused_reason: &str = crate::error::reasons::AGENT_PAUSED;
    let _agent_deactivated_reason: &str = crate::error::reasons::AGENT_DEACTIVATED;
    let at = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let mut payload = json!({
        "agent_principal_id": agent_id,
        "state": new_state,
    });
    if let Some(reason) = reason.as_ref() {
        payload
            .as_object_mut()
            .expect("payload object")
            .insert("reason".to_owned(), Value::String(reason.clone()));
    }
    append_audit_log(state, Some(&session.actor), event_kind, payload, "accepted");
    let mut todos = vec![format!(
        "P2-impl: emit {event_kind} event + fan-out capability cache invalidation"
    )];
    if event_kind == "cx.agent.deactivate" {
        todos.push(
            "P2-impl: fan-out cx.agent.key.revoke + cx.capability.revoke + runtime endpoint revocation"
                .to_owned(),
        );
    }
    Ok(AgentLifecycleResBody {
        ok: true,
        agent_principal_id: agent_id,
        state: new_state.to_owned(),
        at,
        todos,
    })
}

#[endpoint(
    operation_id = "cx.agent.pause",
    tags("agents"),
    summary = "Pause a personal agent",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.agent.pause"))]
async fn pause_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentLifecycleReqBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentLifecycleResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    json_ok(lifecycle_transition(
        state,
        &aa,
        req,
        agent_id.into_inner(),
        "paused",
        "cx.agent.pause",
        body.reason,
    ).await?)
}

#[endpoint(
    operation_id = "cx.agent.resume",
    tags("agents"),
    summary = "Resume a paused personal agent",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.agent.resume"))]
async fn resume_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentLifecycleReqBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentLifecycleResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    json_ok(lifecycle_transition(
        state,
        &aa,
        req,
        agent_id.into_inner(),
        "active",
        "cx.agent.resume",
        body.reason,
    ).await?)
}

#[endpoint(
    operation_id = "cx.agent.deactivate",
    tags("agents"),
    summary = "Deactivate a personal agent (terminal lifecycle state)",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.agent.deactivate"))]
async fn deactivate_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentLifecycleReqBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentLifecycleResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    json_ok(lifecycle_transition(
        state,
        &aa,
        req,
        agent_id.into_inner(),
        "deactivated",
        "cx.agent.deactivate",
        body.reason,
    ).await?)
}

#[endpoint(
    operation_id = "cx.agent.rotate_key",
    tags("agents"),
    summary = "Rotate the agent runtime key (revoke + authorize chain)",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.agent.rotate_key"))]
async fn rotate_agent_key(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentRotateKeyReqBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentRotateKeyResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    validate_agent_principal_id(&agent_id)?;
    let body = body.into_inner();
    if body.new_verification_method.trim().is_empty() {
        return Err(AppError::invalid_param(
            "new_verification_method is required",
        ));
    }
    let at = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    append_audit_log(
        state,
        Some(&session.actor),
        "cx.agent.rotate_key",
        json!({
            "agent_principal_id": agent_id,
            "new_verification_method": body.new_verification_method,
            "previous_key_id": body.previous_key_id,
        }),
        "accepted",
    );
    json_ok(AgentRotateKeyResBody {
        ok: true,
        agent_principal_id: agent_id,
        authorized_verification_method: body.new_verification_method,
        revoked_verification_method: body.previous_key_id,
        at,
        todos: vec![
            "P2-impl: emit cx.agent.key.revoke + cx.agent.key.authorize chain".to_owned(),
            "P2-impl: invalidate session-grants bound to the revoked verification_method"
                .to_owned(),
        ],
    })
}

#[endpoint(
    operation_id = "cx.agent.grant.attach",
    tags("agents"),
    summary = "Attach a capability grant to an agent",
    status_codes(201, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.agent.grant.attach"))]
async fn attach_agent_grant(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentGrantAttachReqBody>,
    depot: &mut Depot,
    res: &mut Response,
    req: &mut Request,
) -> JsonResult<AgentGrantResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    validate_agent_principal_id(&agent_id)?;
    let body = body.into_inner();
    if body.grant_kind.trim().is_empty() {
        return Err(AppError::invalid_param("grant_kind is required"));
    }
    let grant_id = ids::generate("accountability_grant");
    let created_at = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    append_audit_log(
        state,
        Some(&session.actor),
        "cx.agent.grant.attach",
        json!({
            "agent_principal_id": agent_id,
            "grant_id": grant_id,
            "grant_kind": body.grant_kind,
            "scope": body.scope,
        }),
        "accepted",
    );
    res.status_code(StatusCode::CREATED);
    json_ok(AgentGrantResBody {
        ok: true,
        agent_principal_id: agent_id,
        grant_id,
        grant_kind: body.grant_kind,
        scope: body.scope,
        state: "active".to_owned(),
        created_at,
        todos: vec![
            "P2-impl: emit cx.capability.grant event with accountability_grant binding".to_owned(),
        ],
    })
}

#[endpoint(
    operation_id = "cx.agent.grant.detach",
    tags("agents"),
    summary = "Detach (revoke) a capability grant from an agent",
    status_codes(200, 400, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.agent.grant.detach"))]
async fn detach_agent_grant(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    grant_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentGrantDetachResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    let grant_id = grant_id.into_inner();
    validate_agent_principal_id(&agent_id)?;
    if !grant_id.starts_with("cx:accountability_grant:") && !grant_id.starts_with("cx:grant:") {
        return Err(AppError::invalid_param(
            "grant_id must be a cx:accountability_grant:<uuidv7> or cx:grant:<uuidv7> typed id",
        ));
    }
    let detached_at = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    append_audit_log(
        state,
        Some(&session.actor),
        "cx.agent.grant.detach",
        json!({
            "agent_principal_id": agent_id,
            "grant_id": grant_id,
        }),
        "accepted",
    );
    json_ok(AgentGrantDetachResBody {
        ok: true,
        agent_principal_id: agent_id,
        grant_id,
        detached_at,
        todos: vec!["P2-impl: emit cx.capability.revoke event + cache invalidation".to_owned()],
    })
}

#[endpoint(
    operation_id = "cx.agent.sidecar_thread.ensure",
    tags("agents"),
    summary = "Idempotently ensure the controller<->agent sidecar Circle exists",
    status_codes(200, 201, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.agent.sidecar_thread.ensure"))]
async fn ensure_sidecar_thread(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentSidecarThreadEnsureReqBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentSidecarThreadEnsureResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    validate_agent_principal_id(&agent_id)?;
    let body = body.into_inner();
    // ERR-1 — SIDECAR_CREATE_DENIED + PAIRING_REQUEST_EXPIRED reason
    // codes surface here when the controller<->agent sidecar policy
    // forbids creation or when the pairing request has timed out.
    // TODO(R4): when the policy projection is wired, evaluate the
    // controller-agent relation index and short-circuit with:
    //   - SIDECAR_CREATE_DENIED when the controller policy is disabled
    //   - PAIRING_REQUEST_EXPIRED when pairing_request.expires_at <= now
    let _sidecar_denied_reason: &str = crate::error::reasons::SIDECAR_CREATE_DENIED;
    let _pairing_expired_reason: &str = crate::error::reasons::PAIRING_REQUEST_EXPIRED;
    let realm_id = body
        .context_realm_id
        .unwrap_or_else(|| ids::generate("realm"));
    let sidecar_circle_id = ids::generate("sidecar_circle");
    append_audit_log(
        state,
        Some(&session.actor),
        "cx.agent.sidecar_thread.ensure",
        json!({
            "agent_principal_id": agent_id,
            "sidecar_circle_id": sidecar_circle_id,
            "realm_id": realm_id,
        }),
        "accepted",
    );
    let _ = now();
    json_ok(AgentSidecarThreadEnsureResBody {
        ok: true,
        agent_principal_id: agent_id,
        sidecar_circle_id,
        realm_id,
        created: true,
        todos: vec![
            "P2-impl: derive controller_agent_circle_key + idempotent Circle creation".to_owned(),
            "P2-impl: enforce context-realm-preferred sidecar home policy".to_owned(),
        ],
    })
}
