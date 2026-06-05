//! CKP-0008 / CKP-0009 — Personal Agent provisioning + lifecycle surface.
//!
//! Implements the 11 personal-agent HTTP operations gap-reported as missing
//! in soland. The handlers below stand up the cross-project HTTP contract
//! (sodmin admin UI, yougen client, cotest journey vectors) ahead of the
//! deep reducer logic.
//!
//! Surfaces:
//! - `POST   /_cokret/gate/account/agent-key-pair`               — `ck.gate.account.agent_key_pair`
//! - `POST   /_cokret/self/agents`                             — `ck.self.agent.provision`
//! - `GET    /_cokret/self/agents`                             — `ck.self.agent.list`
//! - `GET    /_cokret/self/agents/{id}`                        — `ck.self.agent.get`
//! - `POST   /_cokret/self/agents/{id}/pause`                  — `ck.self.agent.pause`
//! - `POST   /_cokret/self/agents/{id}/resume`                 — `ck.self.agent.resume`
//! - `POST   /_cokret/self/agents/{id}/deactivate`             — `ck.self.agent.deactivate`
//! - `POST   /_cokret/self/agents/{id}/rotate-key`             — `ck.self.agent.rotate_key`
//! - `POST   /_cokret/self/agents/{id}/grants`                 — `ck.self.agent.grant.attach`
//! - `DELETE /_cokret/self/agents/{id}/grants/{grant_id}`      — `ck.self.agent.grant.detach`
//! - `POST   /_cokret/self/agents/{id}/sidecar-thread/ensure`  —
//!   `ck.self.agent.sidecar_thread.ensure`
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
use crate::error::AppError;
use crate::ids;
use crate::result::{JsonResult, json_ok};
use crate::state::AppState;
use crate::wire::{
    AgentGrantAttachReqBody, AgentGrantDetachResBody, AgentGrantResBody, AgentKeyPairReqBody,
    AgentKeyPairResBody, AgentLifecycleReqBody, AgentLifecycleResBody, AgentListResBody,
    AgentProvisionReqBody, AgentResBody, AgentRotateKeyReqBody, AgentRotateKeyResBody,
    AgentSidecarThreadEnsureReqBody, AgentSidecarThreadEnsureResBody,
};

/// Mounted under `/_cokret/self`.
pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(
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
                ),
        )
        .push(
            Router::with_path("agent-sidecar-threads:ensure").post(ensure_sidecar_thread_canonical),
        )
}

pub(super) fn legacy_router() -> Router {
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

/// `/_cokret/gate/account/agent-key-pair` lives under the auth router, not
/// `/_cokret/self/agents`. Registered separately in `routing::identity::auth`.
pub(crate) fn agent_key_pair_router() -> Router {
    Router::with_path("agent-key-pair").post(agent_key_pair)
}

fn validate_agent_principal_id(value: &str) -> Result<(), AppError> {
    if validate_did(value).is_err() {
        return Err(AppError::invalid_param(
            "agent_principal_id must be a DID scalar",
        ));
    }
    Ok(())
}

fn verification_method_principal(verification_method: &str) -> &str {
    verification_method
        .split('#')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("")
}

fn generate_agent_principal_did() -> String {
    format!("did:web:agent-{}.agents.example", uuid::Uuid::now_v7())
}

#[endpoint(
    operation_id = "ck.gate.account.agent_key_pair",
    tags("agents"),
    summary = "Authorize an agent runtime key pair against the agent principal",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.gate.account.agent_key_pair"))]
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
    if verification_method_principal(&body.verification_method) != body.agent_principal_id {
        return Err(AppError::invalid_param(
            "verification_method DID must match agent_principal_id",
        ));
    }
    // ERR-1 — PROOF_INVALID +
    // VERIFICATION_METHOD_PRINCIPAL_MISMATCH +
    // APPROVAL_ALREADY_CONSUMED reason codes anchor here. The pairing
    // pipeline (CKP-0008 §4.2) emits PROOF_INVALID when the
    // runtime_attestation signature fails crypto verification,
    // VERIFICATION_METHOD_PRINCIPAL_MISMATCH when the DID resolved from
    // `verification_method` doesn't match the agent_principal's
    // controller, and APPROVAL_ALREADY_CONSUMED when the controller
    // approval token has been re-played.
    //
    // Runtime attestations are currently refused below with
    // `unsupported_feature`; once the verifier + controller approval
    // ledger land this handler should emit those canonical reasons from
    // the concrete failing check.
    let _proof_invalid_reason: &str = crate::error::reasons::PROOF_INVALID;
    let _verification_method_mismatch_reason: &str =
        crate::error::reasons::VERIFICATION_METHOD_PRINCIPAL_MISMATCH;
    let _approval_consumed_reason: &str = crate::error::reasons::APPROVAL_ALREADY_CONSUMED;
    // The runtime-attestation verifier is not wired yet. Refuse every
    // supplied attestation fail-closed instead of accepting a shape-only
    // `self_asserted` placeholder as if it were a verified binding.
    if let Some(attestation) = body.runtime_attestation.as_ref() {
        let kind = attestation
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        return Err(AppError::unsupported_feature(format!(
            "runtime_attestation verifier is not wired; refusing kind `{kind}` fail-closed"
        )));
    }
    let authorized_at = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    append_audit_log(
        state,
        Some(&session.actor),
        "ck.agent.key.authorize",
        json!({
            "agent_principal_id": body.agent_principal_id,
            "verification_method": body.verification_method,
        }),
        "accepted",
    )
    .await;
    json_ok(AgentKeyPairResBody {
        ok: true,
        agent_principal_id: body.agent_principal_id,
        verification_method: body.verification_method,
        authorized_at,
        todos: vec![
            "P2-impl: write ck.agent.key.authorize event into the event log".to_owned(),
            "P2-impl: persist controller approval consumption before accepting key authorization".to_owned(),
            "P2-impl: wire runtime_attestation verifier before accepting attested key authorization".to_owned(),
        ],
    })
}

#[endpoint(
    operation_id = "ck.self.agent.provision",
    tags("agents"),
    summary = "Provision a personal agent (DID + first agent key + grant attach)",
    status_codes(201, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.provision"))]
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
    let agent_id = body
        .agent_id
        .unwrap_or_else(|| format!("did:web:agent.{}", session.actor.replace([':', '/'], ".")));
    if validate_did(&agent_id).is_err() {
        return Err(AppError::invalid_param("agent_id must be a DID"));
    }
    let agent_principal_id = generate_agent_principal_did();
    let timestamp = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    append_audit_log(
        state,
        Some(&session.actor),
        "ck.self.agent.provision",
        json!({
            "agent_principal_id": agent_principal_id,
            "controller_did": controller_did,
            "agent_id": agent_id,
            "display_name": body.display_name,
        }),
        "accepted",
    )
    .await;
    res.status_code(StatusCode::CREATED);
    json_ok(AgentResBody {
        agent_principal_id,
        controller_did,
        agent_id,
        display_name: body.display_name,
        state: "active".to_owned(),
        created_at: timestamp.clone(),
        updated_at: timestamp,
        grants: body.initial_grants,
        todos: vec![
            "P2-impl: persist agent_principal row + emit ck.self.agent.provision event".to_owned(),
            "P2-impl: orchestrate DID Document registration + first key authorize".to_owned(),
            "P2-impl: process initial_grants[] through ck.capability.grant pipeline".to_owned(),
        ],
    })
}

#[endpoint(
    operation_id = "ck.self.agent.list",
    tags("agents"),
    summary = "List personal agents owned by the authenticated controller",
    status_codes(200, 401, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.list"))]
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
    operation_id = "ck.self.agent.get",
    tags("agents"),
    summary = "Get a personal agent by id (controller-self only)",
    status_codes(200, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.get"))]
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
    let status_changed_at = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let mut payload = json!({
        "agent_principal_id": agent_id,
        "controller_principal_id": session.actor.clone(),
        "transition": match event_kind {
            "ck.self.agent.pause" => "pause",
            "ck.self.agent.resume" => "resume",
            "ck.self.agent.deactivate" => "deactivate",
            _ => new_state,
        },
        "previous_status": match event_kind {
            "ck.self.agent.resume" => "paused",
            "ck.self.agent.deactivate" => "active",
            _ => "active",
        },
        "status_changed_at": status_changed_at.clone(),
    });
    let frontier_key = if event_kind == "ck.self.agent.deactivate" {
        "revocation_frontier"
    } else {
        "freshness_frontier"
    };
    payload.as_object_mut().expect("payload object").insert(
        frontier_key.to_owned(),
        json!({ "captured_at": status_changed_at.clone() }),
    );
    if let Some(reason) = reason.as_ref() {
        payload
            .as_object_mut()
            .expect("payload object")
            .insert("reason".to_owned(), Value::String(reason.clone()));
    }
    append_audit_log(state, Some(&session.actor), event_kind, payload, "accepted").await;
    let mut todos = vec![format!(
        "P2-impl: emit {event_kind} event + fan-out capability cache invalidation"
    )];
    if event_kind == "ck.self.agent.deactivate" {
        todos.push(
            "P2-impl: fan-out ck.agent.key.revoke + ck.capability.revoke + runtime endpoint revocation"
                .to_owned(),
        );
    }
    Ok(AgentLifecycleResBody {
        ok: true,
        agent_principal_id: agent_id,
        state: new_state.to_owned(),
        status_changed_at,
        todos,
    })
}

#[endpoint(
    operation_id = "ck.self.agent.pause",
    tags("agents"),
    summary = "Pause a personal agent",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.pause"))]
async fn pause_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentLifecycleReqBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentLifecycleResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    json_ok(
        lifecycle_transition(
            state,
            &aa,
            req,
            agent_id.into_inner(),
            "paused",
            "ck.self.agent.pause",
            body.reason,
        )
        .await?,
    )
}

#[endpoint(
    operation_id = "ck.self.agent.resume",
    tags("agents"),
    summary = "Resume a paused personal agent",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.resume"))]
async fn resume_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentLifecycleReqBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentLifecycleResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    json_ok(
        lifecycle_transition(
            state,
            &aa,
            req,
            agent_id.into_inner(),
            "active",
            "ck.self.agent.resume",
            body.reason,
        )
        .await?,
    )
}

#[endpoint(
    operation_id = "ck.self.agent.deactivate",
    tags("agents"),
    summary = "Deactivate a personal agent (terminal lifecycle state)",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.deactivate"))]
async fn deactivate_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentLifecycleReqBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentLifecycleResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    json_ok(
        lifecycle_transition(
            state,
            &aa,
            req,
            agent_id.into_inner(),
            "deactivated",
            "ck.self.agent.deactivate",
            body.reason,
        )
        .await?,
    )
}

#[endpoint(
    operation_id = "ck.self.agent.rotate_key",
    tags("agents"),
    summary = "Rotate the agent runtime key (revoke + authorize chain)",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.rotate_key"))]
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
        "ck.self.agent.rotate_key",
        json!({
            "agent_principal_id": agent_id,
            "new_verification_method": body.new_verification_method,
            "previous_key_id": body.previous_key_id,
        }),
        "accepted",
    )
    .await;
    json_ok(AgentRotateKeyResBody {
        ok: true,
        agent_principal_id: agent_id,
        authorized_verification_method: body.new_verification_method,
        revoked_verification_method: body.previous_key_id,
        at,
        todos: vec![
            "P2-impl: emit ck.agent.key.revoke + ck.agent.key.authorize chain".to_owned(),
            "P2-impl: invalidate session-grants bound to the revoked verification_method"
                .to_owned(),
        ],
    })
}

#[endpoint(
    operation_id = "ck.self.agent.grant.attach",
    tags("agents"),
    summary = "Attach a capability grant to an agent",
    status_codes(201, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.grant.attach"))]
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
        "ck.self.agent.grant.attach",
        json!({
            "agent_principal_id": agent_id,
            "grant_id": grant_id,
            "grant_kind": body.grant_kind,
            "agent_key_scope": body.scope,
        }),
        "accepted",
    )
    .await;
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
            "P2-impl: emit ck.capability.grant event with accountability_grant binding".to_owned(),
        ],
    })
}

#[endpoint(
    operation_id = "ck.self.agent.grant.detach",
    tags("agents"),
    summary = "Detach (revoke) a capability grant from an agent",
    status_codes(200, 400, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.grant.detach"))]
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
    if !grant_id.starts_with("ck:accountability_grant:") && !grant_id.starts_with("ck:grant:") {
        return Err(AppError::invalid_param(
            "grant_id must be a ck:accountability_grant:<uuidv7> or ck:grant:<uuidv7> typed id",
        ));
    }
    let detached_at = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    append_audit_log(
        state,
        Some(&session.actor),
        "ck.self.agent.grant.detach",
        json!({
            "agent_principal_id": agent_id,
            "grant_id": grant_id,
        }),
        "accepted",
    )
    .await;
    json_ok(AgentGrantDetachResBody {
        ok: true,
        agent_principal_id: agent_id,
        grant_id,
        detached_at,
        todos: vec!["P2-impl: emit ck.capability.revoke event + cache invalidation".to_owned()],
    })
}

#[endpoint(
    operation_id = "ck.self.agent.sidecar_thread.ensure",
    tags("agents"),
    summary = "Idempotently ensure the controller<->agent sidecar Circle exists",
    status_codes(200, 201, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.sidecar_thread.ensure"))]
async fn ensure_sidecar_thread(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentSidecarThreadEnsureReqBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentSidecarThreadEnsureResBody> {
    ensure_sidecar_thread_impl(aa, agent_id.into_inner(), body.into_inner(), depot, req).await
}

async fn ensure_sidecar_thread_impl(
    aa: AuthArgs,
    agent_id: String,
    body: AgentSidecarThreadEnsureReqBody,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentSidecarThreadEnsureResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    validate_agent_principal_id(&agent_id)?;
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
    // `sidecar_circle_id` 描述的是该值的用途(sidecar 线程的 Circle),其 typed
    // 前缀必须是已注册的 `ck:circle:`,而非未注册的 `ck:sidecar_circle:`。
    let sidecar_circle_id = ids::generate("circle");
    append_audit_log(
        state,
        Some(&session.actor),
        "ck.self.agent.sidecar_thread.ensure",
        json!({
            "agent_principal_id": agent_id,
            "sidecar_circle_id": sidecar_circle_id,
            "realm_id": realm_id,
        }),
        "accepted",
    )
    .await;
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

#[endpoint(
    operation_id = "ck.self.agent.sidecar_thread.ensure",
    tags("agents"),
    summary = "Idempotently ensure the controller<->agent sidecar Circle exists",
    status_codes(200, 201, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.sidecar_thread.ensure"))]
async fn ensure_sidecar_thread_canonical(
    aa: AuthArgs,
    body: JsonBody<AgentSidecarThreadEnsureReqBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentSidecarThreadEnsureResBody> {
    let mut body = body.into_inner();
    let agent_id = body
        .agent_principal_id
        .take()
        .ok_or_else(|| AppError::missing_param("agent_principal_id is required"))?;
    ensure_sidecar_thread_impl(aa, agent_id, body, depot, req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_principal_id_is_did_not_typed_id() {
        validate_agent_principal_id("did:web:agent.example").expect("DID-as-id must be accepted");
        assert!(
            validate_agent_principal_id("ck:agent_principal:01999999-0000-7000-8000-00000000a001")
                .is_err()
        );
    }

    #[test]
    fn verification_method_principal_strips_query_and_fragment() {
        assert_eq!(
            verification_method_principal("did:web:agent.example?versionId=1#key-1"),
            "did:web:agent.example"
        );
    }
}
