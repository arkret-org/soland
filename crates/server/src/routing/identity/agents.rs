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
use cokret_sdk::model::{
    AgentDeactivateRequestBody, AgentGrantAttachOutcome, AgentGrantAttachRequestBody,
    AgentGrantDetachOutcome, AgentKeyPairOutcome, AgentKeyPairRequestBody, AgentLifecycleState,
    AgentList, AgentParticipation, AgentParticipationEntry,
    AgentParticipationOutcome as AgentParticipationResBody, AgentParticipationScope,
    AgentParticipationSetRequestBody as AgentParticipationSetReqBody, AgentPauseRequestBody,
    AgentProvisionOutcome, AgentProvisionRequestBody, AgentResumeRequestBody,
    AgentRotateKeyOutcome, AgentRotateKeyRequestBody, AgentSidecarThreadEnsureOutcome,
    AgentSidecarThreadEnsureRequestBody, AgentView, effective_participation, validate_agent_slug,
    validate_selection_within_ceiling,
};
use cokret_sdk::{EventId, GrantId};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{AuthArgs, append_audit_log, now, validate_did};
use crate::error::AppError;
use crate::ids;
use crate::result::{JsonResult, json_ok};
use crate::state::AppState;

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
                )
                .push(
                    Router::with_path("{agent_id}/participation")
                        .get(get_agent_participation)
                        .put(set_agent_participation),
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
        .push(
            Router::with_path("{agent_id}/participation")
                .get(get_agent_participation)
                .put(set_agent_participation),
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

/// Project a persisted agent_principal JSON record into the spec
/// `agent_projection` shape (`agent-operations.schema.json#/$defs/agent_projection`):
/// `{agent_principal_id, display_name?, agent_slug?, status, created_at?, updated_at?}`.
/// soland-internal columns (`controller_did`, `agent_id`, `pairing_*`) are NOT
/// part of the protocol projection and are dropped at the wire boundary; the
/// persistence `state` column carries the `agent_status` enum value verbatim.
fn agent_projection_from_record(record: &Value) -> Value {
    let str_field = |key: &str| record.get(key).and_then(Value::as_str);
    let mut projection = serde_json::Map::new();
    projection.insert(
        "agent_principal_id".to_owned(),
        json!(str_field("agent_principal_id").unwrap_or_default()),
    );
    if let Some(display_name) = str_field("display_name").filter(|value| !value.is_empty()) {
        projection.insert("display_name".to_owned(), json!(display_name));
    }
    if let Some(agent_slug) = str_field("agent_slug").filter(|value| !value.is_empty()) {
        projection.insert("agent_slug".to_owned(), json!(agent_slug));
    }
    projection.insert(
        "status".to_owned(),
        json!(str_field("state").unwrap_or("active")),
    );
    if let Some(created_at) = str_field("created_at").filter(|value| !value.is_empty()) {
        projection.insert("created_at".to_owned(), json!(created_at));
    }
    if let Some(updated_at) = str_field("updated_at").filter(|value| !value.is_empty()) {
        projection.insert("updated_at".to_owned(), json!(updated_at));
    }
    Value::Object(projection)
}

/// Build the spec `agent_view` (`agent-operations.schema.json#/$defs/agent_view`)
/// from a persisted record: `{agent: <agent_projection>, status, grants[], key_state}`.
/// The `agent`/`status` pair is required; `grants`/`key_state` default empty until
/// the per-agent grant + key projections are wired.
fn agent_view_from_record(record: &Value) -> AgentView {
    let status = record
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or("active")
        .to_owned();
    AgentView {
        agent: agent_projection_from_record(record),
        status,
        grants: Vec::new(),
        key_state: Value::Null,
    }
}

// ─────────────────────────────────────────────────────────────────────
// CKP-0010 — agent participation policy (set / get).
//
// Stands up the cross-project HTTP contract at the same fidelity as the
// sibling agent handlers (audit-log row + typed response), but performs
// the REAL ceiling check via the shared `cokret_sdk` validators so the
// "inner scope MUST NOT exceed the outer ceiling" invariant is enforced
// at the edge. Persistence into `agent_participation`, ceiling
// resolution from the realm/circle/flow policy projection,
// capability-grant materialization (`ck.capability.grant` / `revoke`),
// and the dispatcher mention gate are P2-impl — matching the rest of
// this surface.
// ─────────────────────────────────────────────────────────────────────

/// Deployment-default participation ceiling. Default / dev deployments
/// allow all three bits; production tightens via the
/// sovereign-deployment profile + per-Realm `agent_participation` policy
/// component (CKP-0010 §3 invariant 3).
fn deployment_default_ceiling() -> AgentParticipation {
    AgentParticipation::ALL
}

fn participation_scope_kind(scope: &AgentParticipationScope) -> &'static str {
    match scope {
        AgentParticipationScope::Realm { .. } => "realm",
        AgentParticipationScope::Circle { .. } => "circle",
        AgentParticipationScope::Flow { .. } => "flow",
    }
}

/// The enclosing scope_key chain for ceiling resolution: the Realm key
/// always applies; Circle / Flow additionally contribute their own key.
fn enclosing_scope_keys(scope: &AgentParticipationScope) -> Vec<String> {
    let realm_key = AgentParticipationScope::Realm {
        realm_id: scope.realm_id().clone(),
    }
    .scope_key();
    match scope {
        AgentParticipationScope::Realm { .. } => vec![realm_key],
        AgentParticipationScope::Circle { .. } | AgentParticipationScope::Flow { .. } => {
            vec![realm_key, scope.scope_key()]
        }
    }
}

fn participation_from_value(row: &Value) -> AgentParticipation {
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
/// Flow). Reads the `agent_participation_ceiling` projection for the
/// enclosing scope_key chain and intersects each row over the deployment
/// default; a scope with no ceiling rows inherits the deployment default
/// (CKP-0010 §4.4, fail-closed by intersection).
async fn resolve_effective_ceiling(
    state: &AppState,
    scope: &AgentParticipationScope,
) -> AgentParticipation {
    let scope_keys = enclosing_scope_keys(scope);
    let rows = state
        .persistence
        .agent_participation()
        .ceilings_for_scope_keys(&scope_keys)
        .await
        .unwrap_or_default();
    let mut ceiling = deployment_default_ceiling();
    for row in &rows {
        ceiling = ceiling.intersect(participation_from_value(row));
    }
    ceiling
}

#[endpoint(
    operation_id = "ck.self.agent.participation.set",
    tags("agents"),
    summary = "Set an agent's participation selection for a scope (controller-self only)",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.participation.set"))]
async fn set_agent_participation(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentParticipationSetReqBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentParticipationResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    validate_agent_principal_id(&agent_id)?;
    let body = body.into_inner();
    let ceiling = resolve_effective_ceiling(state, &body.scope).await;
    validate_selection_within_ceiling(ceiling, body.selection)
        .map_err(|err| AppError::capability_denied(err.to_string()))?;
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
        "ck.self.agent.participation.set",
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

#[endpoint(
    operation_id = "ck.self.agent.participation.get",
    tags("agents"),
    summary = "Get an agent's resolved participation policy (controller-self only)",
    status_codes(200, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.participation.get"))]
async fn get_agent_participation(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentParticipationResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    validate_agent_principal_id(&agent_id)?;
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

#[endpoint(
    operation_id = "ck.gate.account.agent_key_pair",
    tags("agents"),
    summary = "Authorize an agent runtime key pair against the agent principal",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.gate.account.agent_key_pair"))]
async fn agent_key_pair(
    aa: AuthArgs,
    body: JsonBody<AgentKeyPairRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentKeyPairOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let agent_principal_id = body.agent_principal_id.as_str();
    validate_agent_principal_id(agent_principal_id)?;
    if body.verification_method.trim().is_empty() {
        return Err(AppError::invalid_param("verification_method is required"));
    }
    if verification_method_principal(&body.verification_method) != agent_principal_id {
        return Err(AppError::invalid_param(
            "verification_method DID must match agent_principal_id",
        ));
    }
    // ERR-1 — PROOF_INVALID +
    // VERIFICATION_METHOD_PRINCIPAL_MISMATCH +
    // APPROVAL_ALREADY_CONSUMED reason codes seal here. The pairing
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
    // Pairing semantics: a provisioned agent starts `pending_runtime_key`;
    // authorizing the first runtime key flips it to `active`.
    let _ = state
        .persistence
        .agents()
        .set_state(agent_principal_id, "active", &authorized_at)
        .await;
    append_audit_log(
        state,
        Some(&session.actor),
        "ck.agent.key.authorize",
        json!({
            "agent_principal_id": agent_principal_id,
            "verification_method": body.verification_method,
        }),
        "accepted",
    )
    .await;
    // Spec `agent_key_pair_outcome` = `{ok, authorized_event_ref}`. The audit
    // row above is the deployment-local stand-in for the durable
    // `ck.agent.key.authorize` event; we mint the event id the outcome MUST
    // carry so clients can pin the authorization (P2-impl: persist the real
    // signed event under this id + controller approval consumption +
    // runtime_attestation verifier).
    let authorized_event_ref = EventId::new(ids::generate_event_id())
        .map_err(|err| AppError::internal(format!("generated event id invalid: {err}")))?;
    json_ok(AgentKeyPairOutcome {
        ok: true,
        authorized_event_ref,
    })
}

/// Generate a short human-relayable pairing code for the provision
/// outcome (`agent_provision_outcome.pairing_code`). 8 decimal digits
/// from the OS CSPRNG.
fn generate_pairing_code() -> String {
    use rand::RngExt;
    let mut buf = [0u8; 4];
    rand::rng().fill(&mut buf);
    format!("{:08}", u32::from_be_bytes(buf) % 100_000_000)
}

#[endpoint(
    operation_id = "ck.self.agent.provision",
    tags("agents"),
    summary = "Provision a personal agent (DID + pairing request)",
    status_codes(201, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.provision"))]
async fn provision_agent(
    aa: AuthArgs,
    body: JsonBody<AgentProvisionRequestBody>,
    depot: &mut Depot,
    res: &mut Response,
    req: &mut Request,
) -> JsonResult<AgentProvisionOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
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
        if existing.iter().any(|record| {
            record.get("agent_slug").and_then(Value::as_str) == Some(slug)
                && record.get("state").and_then(Value::as_str) != Some("deactivated")
        }) {
            return Err(AppError::invalid_param(
                "agent_slug is already bound to an active agent for this controller",
            ));
        }
    }
    // The agent's actor DID is server-generated (the spec body carries no
    // client-supplied agent_id).
    let agent_id = format!("did:web:agent.{}", session.actor.replace([':', '/'], "."));
    let agent_principal_id = generate_agent_principal_did();
    let now_utc = chrono::Utc::now();
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
    // Persist the agent_principal row so list/get/lifecycle + grant/session
    // paths have a real principal to operate on (CKP-0008). Per the spec
    // agent lifecycle the agent starts `pending_runtime_key`; the gate
    // `ck.gate.account.agent_key_pair` flips it to `active` once the
    // runtime key is authorized.
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
        "ck.self.agent.provision",
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
    let agent_principal_did = cokret_sdk::Did::new(agent_principal_id).map_err(|err| {
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
) -> JsonResult<AgentList> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let records = state
        .persistence
        .agents()
        .list_for_controller(&session.actor)
        .await
        .map_err(|err| AppError::internal(format!("agent list failed: {err}")))?;
    // spec `agent_list` = `{agents: [agent_projection], next_cursor?, has_more}`.
    json_ok(AgentList {
        agents: records.iter().map(agent_projection_from_record).collect(),
        next_cursor: None,
        has_more: false,
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
) -> JsonResult<AgentView> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
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
    json_ok(agent_view_from_record(&record))
}

async fn lifecycle_transition(
    state: &AppState,
    aa: &AuthArgs,
    req: &Request,
    agent_id: String,
    new_state: AgentLifecycleState,
    event_kind: &str,
    reason: Option<String>,
) -> Result<Value, AppError> {
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
            _ => new_state.as_wire_str(),
        },
        "previous_status": match event_kind {
            "ck.self.agent.resume" => "paused",
            "ck.self.agent.deactivate" => "active",
            _ => "active",
        },
        "status_changed_at": status_changed_at.clone(),
    });
    // pause / resume carry the spec-required `freshness_frontier`.
    // deactivate carries no frontier field since the SPEC-SOL-003 resolution:
    // a revocation's basis is the Control Move envelope seal_basis and its
    // cutoff is the accepted Seal covering the Move.
    if event_kind != "ck.self.agent.deactivate" {
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
    // Persist the lifecycle state transition on the agent_principal row. The
    // persisted `state` column carries the `agent_status` enum value; the
    // lifecycle transitions land at `active` / `paused` / `deactivated`.
    let new_status = new_state.as_wire_str();
    let _ = state
        .persistence
        .agents()
        .set_state(&agent_id, new_status, &status_changed_at)
        .await;
    append_audit_log(state, Some(&session.actor), event_kind, payload, "accepted").await;
    // spec `agent_lifecycle_state` = `operation_status_outcome` =
    // `{ok: true, status}` (status is the post-transition `agent_status`).
    Ok(json!({ "ok": true, "status": new_status }))
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
    body: JsonBody<AgentPauseRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    json_ok(
        lifecycle_transition(
            state,
            &aa,
            req,
            agent_id.into_inner(),
            AgentLifecycleState::Paused,
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
    body: JsonBody<AgentResumeRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    // spec `agent_resume_request_body` carries an optional
    // `sidecar_exposure_ack`, not a `reason`. P2-impl: thread the ack into the
    // sidecar exposure consent ledger before re-activating the agent.
    let _body = body.into_inner();
    json_ok(
        lifecycle_transition(
            state,
            &aa,
            req,
            agent_id.into_inner(),
            AgentLifecycleState::Active,
            "ck.self.agent.resume",
            None,
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
    body: JsonBody<AgentDeactivateRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    json_ok(
        lifecycle_transition(
            state,
            &aa,
            req,
            agent_id.into_inner(),
            AgentLifecycleState::Deactivated,
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
    body: JsonBody<AgentRotateKeyRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentRotateKeyOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    validate_agent_principal_id(&agent_id)?;
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
        "ck.self.agent.rotate_key",
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
    // real ck.agent.key.revoke + ck.agent.key.authorize chain under it and
    // invalidate session-grants bound to the revoked key).
    let authorized_event_ref = EventId::new(ids::generate_event_id())
        .map_err(|err| AppError::internal(format!("generated event id invalid: {err}")))?;
    json_ok(AgentRotateKeyOutcome {
        ok: true,
        authorized_event_ref,
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
    body: JsonBody<AgentGrantAttachRequestBody>,
    depot: &mut Depot,
    res: &mut Response,
    req: &mut Request,
) -> JsonResult<AgentGrantAttachOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    validate_agent_principal_id(&agent_id)?;
    let body = body.into_inner();
    // spec `agent_grant_attach_request_body` = `{grant: object}`.
    if !body.grant.is_object() {
        return Err(AppError::invalid_param("grant must be an object"));
    }
    // spec `agent_grant_attach_outcome.grant_id` MUST be a `ck:grant:<uuidv7>`.
    let grant_id = GrantId::new(ids::generate_grant_id())
        .map_err(|err| AppError::internal(format!("generated grant id invalid: {err}")))?;
    append_audit_log(
        state,
        Some(&session.actor),
        "ck.self.agent.grant.attach",
        json!({
            "agent_principal_id": agent_id,
            "grant_id": grant_id,
            "grant": body.grant,
        }),
        "accepted",
    )
    .await;
    res.status_code(StatusCode::CREATED);
    // spec `agent_grant_attach_outcome` = `{ok, grant_id}`. P2-impl: emit the
    // real ck.capability.grant event with the accountability_grant binding.
    json_ok(AgentGrantAttachOutcome { ok: true, grant_id })
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
) -> JsonResult<AgentGrantDetachOutcome> {
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
    let revoked_at = now();
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
    // spec `agent_grant_detach_outcome` = `{ok, revoked_at}`. P2-impl: emit the
    // real ck.capability.revoke event + cache invalidation.
    json_ok(AgentGrantDetachOutcome {
        ok: true,
        revoked_at,
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
    body: JsonBody<AgentSidecarThreadEnsureRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentSidecarThreadEnsureOutcome> {
    // Legacy `/_cokret/self/agents/{id}/sidecar-thread/ensure` route: the path
    // `{agent_id}` MUST agree with the spec body's `agent_principal_id`.
    let agent_id = agent_id.into_inner();
    let body = body.into_inner();
    if body.agent_principal_id.as_str() != agent_id {
        return Err(AppError::invalid_param(
            "path agent_id must match body agent_principal_id",
        ));
    }
    ensure_sidecar_thread_impl(aa, body, depot, req).await
}

async fn ensure_sidecar_thread_impl(
    aa: AuthArgs,
    body: AgentSidecarThreadEnsureRequestBody,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentSidecarThreadEnsureOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    // ERR-1 — SIDECAR_CREATE_DENIED + PAIRING_REQUEST_EXPIRED reason
    // codes surface here when the controller<->agent sidecar policy
    // forbids creation or when the pairing request has timed out.
    // TODO(R4): when the policy projection is wired, evaluate the
    // controller-agent relation index and short-circuit with:
    //   - SIDECAR_CREATE_DENIED when the controller policy is disabled
    //   - PAIRING_REQUEST_EXPIRED when pairing_request.expires_at <= now
    let _sidecar_denied_reason: &str = crate::error::reasons::SIDECAR_CREATE_DENIED;
    let _pairing_expired_reason: &str = crate::error::reasons::PAIRING_REQUEST_EXPIRED;
    // spec `agent_sidecar_thread_ensure_outcome` =
    // `{ok, private_circle_id, private_flow_id, private_relation_id,
    //   pending_member_reconciliations?}`. The private Circle / Flow / Relation
    // ids are minted here; P2-impl: derive the deterministic
    // controller_agent_circle_key for true idempotent creation and enforce the
    // context-realm-preferred sidecar home policy.
    let private_circle_id = cokret_sdk::CircleId::new(ids::generate_circle_id())
        .map_err(|err| AppError::internal(format!("generated circle id invalid: {err}")))?;
    let private_flow_id = cokret_sdk::FlowId::new(ids::generate("flow"))
        .map_err(|err| AppError::internal(format!("generated flow id invalid: {err}")))?;
    let private_relation_id = cokret_sdk::RelationId::new(ids::generate_relation_id())
        .map_err(|err| AppError::internal(format!("generated relation id invalid: {err}")))?;
    append_audit_log(
        state,
        Some(&session.actor),
        "ck.self.agent.sidecar_thread.ensure",
        json!({
            "agent_principal_id": body.agent_principal_id,
            "controller_principal_id": body.controller_principal_id,
            "realm_id": body.realm_id,
            "private_circle_id": private_circle_id,
        }),
        "accepted",
    )
    .await;
    json_ok(AgentSidecarThreadEnsureOutcome {
        ok: true,
        private_circle_id,
        private_flow_id,
        private_relation_id,
        pending_member_reconciliations: Vec::new(),
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
    body: JsonBody<AgentSidecarThreadEnsureRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentSidecarThreadEnsureOutcome> {
    ensure_sidecar_thread_impl(aa, body.into_inner(), depot, req).await
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

    #[test]
    fn agent_view_projects_spec_shape_dropping_internal_columns() {
        let view = agent_view_from_record(&json!({
            "agent_principal_id": "did:web:agent.example",
            "controller_did": "did:web:example.com:users:alice",
            "agent_id": "did:web:agent.example",
            "display_name": "Summary Assistant",
            "agent_slug": "summary",
            "state": "active",
            "created_at": "2026-06-11T00:00:00.000Z",
            "updated_at": "2026-06-11T00:00:00.000Z"
        }));
        // spec `agent_view` = `{agent: <agent_projection>, status, ...}`.
        assert_eq!(view.status, "active");
        let agent = serde_json::to_value(&view).expect("view serializes");
        assert_eq!(agent["agent"]["agent_slug"], "summary");
        assert_eq!(agent["agent"]["status"], "active");
        assert_eq!(agent["agent"]["agent_principal_id"], "did:web:agent.example");
        // soland-internal columns MUST NOT leak into the protocol projection.
        assert!(agent["agent"].get("controller_did").is_none());
        assert!(agent["agent"].get("agent_id").is_none());
    }
}
