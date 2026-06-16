//! CKP-0008 / CKP-0009 — Personal Agent provisioning + lifecycle surface.
//!
//! Implements the 11 personal-agent HTTP operations gap-reported as missing
//! in soland. The handlers below stand up the cross-project HTTP contract
//! (sodmin admin UI, yougen client, cotest journey vectors) ahead of the
//! deep reducer logic.
//!
//! Surfaces:
//! - `POST   /_cokret/gate/account/agent-key-pair`               —
//!   `ck.gate.account.command.pair_agent_key`
//! - `POST   /_cokret/self/agents`                             — `ck.self.agent.command.provision`
//! - `GET    /_cokret/self/agents`                             — `ck.self.agent.query.list`
//! - `GET    /_cokret/self/agents/{id}`                        — `ck.self.agent.resource.get`
//! - `POST   /_cokret/self/agents/{id}/pause`                  — `ck.self.agent.command.pause`
//! - `POST   /_cokret/self/agents/{id}/resume`                 — `ck.self.agent.command.resume`
//! - `POST   /_cokret/self/agents/{id}/deactivate`             — `ck.self.agent.command.deactivate`
//! - `POST   /_cokret/self/agents/{id}/rotate-key`             — `ck.self.agent.command.rotate_key`
//! - `POST   /_cokret/self/agents/{id}/grants`                 —
//!   `ck.self.agent.grant.command.attach`
//! - `DELETE /_cokret/self/agents/{id}/grants/{grant_id}`      —
//!   `ck.self.agent.grant.resource.delete`
//! - `POST   /_cokret/self/agent-sidecar-threads:ensure`       —
//!   `ck.self.agent.sidecar_thread.command.ensure`
//!
//! All endpoints accept controller-self bearer sessions (TODO(P2-impl):
//! tighten to `controller-only` actor binding once the personal-agent
//! relation index lands). Each handler appends an audit-log row matching
//! the canonical event-kind name so the existing admin / federation
//! projections stay in sync ahead of the reducer rewrite.

use chrono::SecondsFormat;
use cokret_sdk::models::{
    AgentDeactivateRequestBody, AgentGrantAttachOutcome, AgentGrantAttachRequestBody,
    AgentGrantDetachOutcome, AgentKeyPairOutcome, AgentKeyPairRequestBody, AgentLifecycleOutcome,
    AgentLifecycleState, AgentList, AgentParticipation, AgentParticipationEntry,
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
use crate::state::{AppState, SessionRecord};

mod dev_fanout;
use dev_fanout::{
    attach_agent_grant_event, ensure_self_realm, fanout_provision_subevents,
    materialize_capability_grant, revoke_capability_grant, submit_durable_agent_lifecycle,
    submit_durable_key_authorize, submit_revoke_agent_grants, submit_revoke_agent_keys,
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

/// `/_cokret/gate/account/agent-key-pair` lives under the auth router, not
/// `/_cokret/self/agents`. Registered separately in `routing::identity::auth`.
pub(crate) fn agent_key_pair_router() -> Router {
    Router::with_path("agent-key-pair").post(agent_key_pair)
}

/// CKP-0008 (dev option B) — synthesize a controller-authored
/// `SessionRecord` so the server-side fan-out can author durable sub-events
/// as the controller (`actor_id == session.actor`). Only used under
/// `development_mode`; the resulting session is never persisted or returned.
fn controller_dev_session(controller_did: &str, state: &AppState) -> SessionRecord {
    SessionRecord {
        token_hash: format!("agent-dev-fanout:{controller_did}"),
        actor: controller_did.to_owned(),
        device_id: "agent-dev-fanout".to_owned(),
        audience: state.config.service_did.clone(),
        session_public_key: None,
        expires_at: now() + chrono::Duration::minutes(5),
        created_at: now(),
        revoked_at: None,
    }
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
// resolution from the realm/circle/strand policy projection,
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
        AgentParticipationScope::Strand { .. } => "strand",
    }
}

/// The enclosing scope_key chain for ceiling resolution: the Realm key
/// always applies; Circle / Strand additionally contribute their own key.
fn enclosing_scope_keys(scope: &AgentParticipationScope) -> Vec<String> {
    let realm_key = AgentParticipationScope::Realm {
        realm_id: scope.realm_id().clone(),
    }
    .scope_key();
    match scope {
        AgentParticipationScope::Realm { .. } => vec![realm_key],
        AgentParticipationScope::Circle { .. } | AgentParticipationScope::Strand { .. } => {
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
/// Strand). Reads the `agent_participation_ceiling` projection for the
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
    operation_id = "ck.self.agent.participation.resource.replace",
    tags("agents"),
    summary = "Set an agent's participation selection for a scope (controller-self only)",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.participation.resource.replace"))]
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
    // converge on a single cell. Production submits these from yougen.
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
fn participation_grant_id(agent_principal_id: &str, scope_key: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"ck:grant:agent_participation:v1:");
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
        "ck:grant:{}-{}-{}-{}-{}",
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
fn participation_scope_resource(scope: &AgentParticipationScope) -> Value {
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

#[endpoint(
    operation_id = "ck.self.agent.participation.resource.get",
    tags("agents"),
    summary = "Get an agent's resolved participation policy (controller-self only)",
    status_codes(200, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.participation.resource.get"))]
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
    operation_id = "ck.gate.account.command.pair_agent_key",
    tags("agents"),
    summary = "Authorize an agent runtime key pair against the agent principal",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.gate.account.command.pair_agent_key"))]
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
    // CKP-0008 §4.5 / D3 (dev option B): submit the durable
    // `ck.agent.key.authorize` event authored by the controller so the
    // reducer projects the agent-key state and clears the agent's pending
    // `effective_after_first_authorized_key` grants. Production submits this
    // from coauth/yougen and never enters this branch.
    let authorized_event_ref = if state.config.development_mode {
        let controller_did = state
            .persistence
            .agents()
            .get(agent_principal_id)
            .await
            .ok()
            .flatten()
            .and_then(|record| {
                record
                    .get("controller_did")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .unwrap_or_else(|| session.actor.clone());
        let controller_session = controller_dev_session(&controller_did, state);
        let realm = ensure_self_realm(state, &controller_session).await?;
        let key_id = dev_fanout::default_agent_key_id(agent_principal_id);
        let event_id = submit_durable_key_authorize(
            state,
            &controller_session,
            &realm,
            agent_principal_id,
            &body.verification_method,
            &key_id,
        )
        .await?;
        EventId::new(event_id)
            .map_err(|err| AppError::internal(format!("authorize event id invalid: {err}")))?
    } else {
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
        // Production option A: the durable event is submitted by coauth /
        // yougen; soland mints the pin id the outcome MUST carry.
        EventId::new(ids::generate_event_id())
            .map_err(|err| AppError::internal(format!("generated event id invalid: {err}")))?
    };
    // Pairing semantics: a provisioned agent starts `pending_runtime_key`;
    // flip to `active` ONLY after the durable key authorization has been
    // accepted (a failed submit above propagates via `?` and MUST NOT leave
    // the agent flipped to active).
    let _ = state
        .persistence
        .agents()
        .set_state(agent_principal_id, "active", &authorized_at)
        .await;
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
    operation_id = "ck.self.agent.command.provision",
    tags("agents"),
    summary = "Provision a personal agent (DID + pairing request)",
    status_codes(201, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.command.provision"))]
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
    // `ck.gate.account.command.pair_agent_key` flips it to `active` once the
    // runtime key is authorized.
    // CKP-0008 D1 (dev option B): provision the agent's identity sub-events
    // into the controller's self realm. `ensure_self_realm` is idempotent and
    // the three sub-events (profile / accountability / initial capability
    // grant) are authored by the controller. Production (option A) submits
    // these from yougen and never enters this branch.
    let mut self_realm_id: Option<String> = None;
    let mut provision_event_refs = json!({});
    if state.config.development_mode {
        let realm = ensure_self_realm(state, &session).await?;
        let (profile_event, accountability_event, grant_id) = fanout_provision_subevents(
            state,
            &session,
            &realm,
            &agent_principal_id,
            display_name.as_deref(),
            &requested_scope,
        )
        .await?;
        provision_event_refs = json!({
            "agent_profile_event_id": profile_event,
            "accountability_grant_event_id": accountability_event,
            "initial_capability_grant_ids": [grant_id],
        });
        self_realm_id = Some(realm);
    }
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
        "ck.self.agent.command.provision",
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
    operation_id = "ck.self.agent.query.list",
    tags("agents"),
    summary = "List personal agents owned by the authenticated controller",
    status_codes(200, 401, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.query.list"))]
async fn list_agents(aa: AuthArgs, depot: &mut Depot, req: &mut Request) -> JsonResult<AgentList> {
    let state = depot.obtain::<AppState>().expect("state injected");
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

#[endpoint(
    operation_id = "ck.self.agent.resource.get",
    tags("agents"),
    summary = "Get a personal agent by id (controller-self only)",
    status_codes(200, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.resource.get"))]
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
    let record = lazily_expire_pairing(state, &session, record).await;
    json_ok(agent_view_from_record(&record))
}

/// CKP-0008 §4.3.2 — lazily expire a `pending_runtime_key` agent whose
/// pairing window has elapsed. On first observation past `pairing_expires_at`
/// the agent flips to `pairing_expired` and (dev option B) the pending
/// `effective_after_first_authorized_key` grants are auto-revoked. Returns
/// the record with the (possibly) updated `state`. No-op for any other
/// state. The controller `session` authors the revoke fan-out.
async fn lazily_expire_pairing(
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
    if state.config.development_mode {
        if let Ok(realm) = ensure_self_realm(state, session).await {
            let grant_ids = state
                .projection
                .lock()
                .ok()
                .map(|proj| proj.grant_ids_for_subject(&agent_principal_id))
                .unwrap_or_default();
            let _ = submit_revoke_agent_grants(state, session, &realm, &grant_ids).await;
        }
    }
    if let Some(obj) = record.as_object_mut() {
        obj.insert(
            "state".to_owned(),
            Value::String("pairing_expired".to_owned()),
        );
    }
    record
}

async fn lifecycle_transition(
    state: &AppState,
    aa: &AuthArgs,
    req: &Request,
    agent_id: String,
    new_state: AgentLifecycleState,
    event_kind: &str,
    reason: Option<String>,
) -> Result<AgentLifecycleOutcome, AppError> {
    let session = aa.authenticated_session(state, req).await?;
    validate_agent_principal_id(&agent_id)?;
    let status_changed_at = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    // Read the current persisted state so the durable transition carries the
    // accurate `previous_status` (resume comes from `paused`, etc.).
    let previous_status = state
        .persistence
        .agents()
        .get(&agent_id)
        .await
        .ok()
        .flatten()
        .and_then(|record| {
            record
                .get("state")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| "active".to_owned());
    // CKP-0008 §4.11 (dev option B): drive the FSM reducer with the durable
    // `ck.self.agent.{pause,resume,deactivate}` event authored by the
    // controller, and on deactivate fan-out the revocation chain
    // (`ck.agent.key.revoke` + `ck.capability.revoke` for every grant the
    // agent holds). Production submits the lifecycle event from yougen.
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
        )
        .await?;
        if event_kind == "ck.self.agent.deactivate" {
            let (key_ids, grant_ids) = state
                .projection
                .lock()
                .ok()
                .map(|proj| {
                    (
                        proj.authorized_key_ids_for(&agent_id),
                        proj.grant_ids_for_subject(&agent_id),
                    )
                })
                .unwrap_or_default();
            submit_revoke_agent_keys(state, &session, &realm, &agent_id, &key_ids).await?;
            submit_revoke_agent_grants(state, &session, &realm, &grant_ids).await?;
        }
    } else {
        let mut payload = json!({
            "agent_principal_id": agent_id,
            "controller_principal_id": session.actor.clone(),
            "transition": match event_kind {
                "ck.self.agent.pause" => "pause",
                "ck.self.agent.resume" => "resume",
                "ck.self.agent.deactivate" => "deactivate",
                _ => new_state.as_wire_str(),
            },
            "previous_status": previous_status,
            "status_changed_at": status_changed_at.clone(),
        });
        // pause / resume carry the spec-required `freshness_frontier`;
        // deactivate carries none (SPEC-SOL-003 resolution).
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
    operation_id = "ck.self.agent.command.pause",
    tags("agents"),
    summary = "Pause a personal agent",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.command.pause"))]
async fn pause_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentPauseRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentLifecycleOutcome> {
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
    operation_id = "ck.self.agent.command.resume",
    tags("agents"),
    summary = "Resume a paused personal agent",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.command.resume"))]
async fn resume_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentResumeRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentLifecycleOutcome> {
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
    operation_id = "ck.self.agent.command.deactivate",
    tags("agents"),
    summary = "Deactivate a personal agent (terminal lifecycle state)",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.command.deactivate"))]
async fn deactivate_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentDeactivateRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentLifecycleOutcome> {
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
    operation_id = "ck.self.agent.command.rotate_key",
    tags("agents"),
    summary = "Rotate the agent runtime key (revoke + authorize chain)",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.command.rotate_key"))]
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
        "ck.self.agent.command.rotate_key",
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
    operation_id = "ck.self.agent.grant.command.attach",
    tags("agents"),
    summary = "Attach a capability grant to an agent",
    status_codes(201, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.grant.command.attach"))]
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
    let grant_id_str = ids::generate_grant_id();
    let grant_id = GrantId::new(grant_id_str.clone())
        .map_err(|err| AppError::internal(format!("generated grant id invalid: {err}")))?;
    // CKP-0008 §4.11 (dev option B): write the real `ck.capability.grant`
    // authored by the controller. Production submits this from yougen.
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
            "ck.self.agent.grant.command.attach",
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
    operation_id = "ck.self.agent.grant.resource.delete",
    tags("agents"),
    summary = "Detach (revoke) a capability grant from an agent",
    status_codes(200, 400, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.grant.resource.delete"))]
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
        "ck.self.agent.grant.resource.delete",
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

async fn ensure_sidecar_thread_impl(
    aa: AuthArgs,
    body: AgentSidecarThreadEnsureRequestBody,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentSidecarThreadEnsureOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    // spec `agent_sidecar_thread_ensure_outcome` =
    // `{ok, private_circle_id, private_strand_id, private_relation_id,
    //   pending_member_reconciliations?}`. The private Circle / Strand / Relation
    // ids are minted here; P2-impl: derive the deterministic
    // controller_agent_circle_key for true idempotent creation and enforce the
    // context-realm-preferred sidecar home policy.
    let private_circle_id = cokret_sdk::CircleId::new(ids::generate_circle_id())
        .map_err(|err| AppError::internal(format!("generated circle id invalid: {err}")))?;
    let private_strand_id = cokret_sdk::StrandId::new(ids::generate("strand"))
        .map_err(|err| AppError::internal(format!("generated strand id invalid: {err}")))?;
    let private_relation_id = cokret_sdk::RelationId::new(ids::generate_relation_id())
        .map_err(|err| AppError::internal(format!("generated relation id invalid: {err}")))?;
    append_audit_log(
        state,
        Some(&session.actor),
        "ck.self.agent.sidecar_thread.command.ensure",
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
        private_strand_id,
        private_relation_id,
        pending_member_reconciliations: Vec::new(),
    })
}

#[endpoint(
    operation_id = "ck.self.agent.sidecar_thread.command.ensure",
    tags("agents"),
    summary = "Idempotently ensure the controller<->agent sidecar Circle exists",
    status_codes(200, 201, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.sidecar_thread.command.ensure"))]
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
        assert_eq!(
            agent["agent"]["agent_principal_id"],
            "did:web:agent.example"
        );
        // soland-internal columns MUST NOT leak into the protocol projection.
        assert!(agent["agent"].get("controller_did").is_none());
        assert!(agent["agent"].get("agent_id").is_none());
    }
}
