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
//! Controller operations enforce the persisted `agent_principals.controller_did`
//! binding before they mutate state or emit fan-out. Each handler appends an
//! audit-log row matching the canonical event-kind name so the existing admin /
//! federation projections stay in sync ahead of the reducer rewrite.

use std::collections::BTreeSet;

use chrono::SecondsFormat;
use cokret_sdk::models::{
    AgentDeactivateRequestBody, AgentGrantAttachOutcome, AgentGrantAttachRequestBody,
    AgentGrantDetachOutcome, AgentKeyPairOutcome, AgentKeyPairRequestBody, AgentLifecycleOutcome,
    AgentLifecycleState, AgentList, AgentParticipation, AgentParticipationEntry,
    AgentParticipationOutcome as AgentParticipationResBody, AgentParticipationScope,
    AgentParticipationSetRequestBody as AgentParticipationSetReqBody, AgentPauseRequestBody,
    AgentProtocolDiscoverOutcome, AgentProtocolDiscoverRequestBody, AgentProvisionOutcome,
    AgentProvisionRequestBody, AgentResumeRequestBody, AgentRotateKeyOutcome,
    AgentRotateKeyRequestBody, AgentSidecarContextRef, AgentSidecarExposureAck,
    AgentSidecarThreadEnsureOutcome, AgentSidecarThreadEnsureRequestBody, AgentView,
    effective_participation, validate_agent_slug, validate_selection_within_ceiling,
};
use cokret_sdk::{
    CircleId, Did, EventId, GrantId, Operation, OperationId, RealmId, RelationId, StrandId,
};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{AuthArgs, append_audit_log, now, validate_did};
use crate::error::{AppError, ErrorCode};
use crate::ids;
use crate::result::{JsonResult, json_ok};
use crate::routing::accept_local_operations;
use crate::routing::events::event_log::submit_event_value;
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
                .push(Router::with_path("discover").post(discover_agent_endpoint))
                .push(Router::with_path("{agent_principal_id}").get(get_agent))
                .push(Router::with_path("{agent_principal_id}/pause").post(pause_agent))
                .push(Router::with_path("{agent_principal_id}/resume").post(resume_agent))
                .push(Router::with_path("{agent_principal_id}/deactivate").post(deactivate_agent))
                .push(Router::with_path("{agent_principal_id}/rotate-key").post(rotate_agent_key))
                .push(
                    Router::with_path("{agent_principal_id}/grants")
                        .post(attach_agent_grant)
                        .push(Router::with_path("{grant_id}").delete(detach_agent_grant)),
                )
                .push(
                    Router::with_path("{agent_principal_id}/participation")
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
        agent_session: None,
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

fn ensure_agent_record_controller(
    record: &Value,
    agent_principal_id: &str,
    session: &SessionRecord,
) -> Result<(), AppError> {
    if record.get("agent_principal_id").and_then(Value::as_str) != Some(agent_principal_id) {
        return Err(AppError::capability_denied(
            "agent principal record does not match the requested principal",
        ));
    }
    let Some(controller_did) = record
        .get("controller_did")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    else {
        return Err(AppError::capability_denied(
            "agent principal has no controller binding",
        ));
    };
    if controller_did != session.actor.as_str() {
        return Err(AppError::capability_denied(
            "agent principal is not controlled by the authenticated session",
        ));
    }
    Ok(())
}

async fn require_agent_controller(
    state: &AppState,
    session: &SessionRecord,
    agent_principal_id: &str,
) -> Result<Value, AppError> {
    validate_agent_principal_id(agent_principal_id)?;
    let record = state
        .persistence
        .agents()
        .get(agent_principal_id)
        .await
        .map_err(|err| AppError::internal(format!("agent controller lookup failed: {err}")))?
        .ok_or_else(|| AppError::capability_denied("agent principal has no controller binding"))?;
    ensure_agent_record_controller(&record, agent_principal_id, session)?;
    Ok(record)
}

fn ensure_sidecar_controller_request(
    body: &AgentSidecarThreadEnsureRequestBody,
    session: &SessionRecord,
) -> Result<(), AppError> {
    if body.controller_principal_id.as_str() != session.actor.as_str() {
        return Err(sidecar_create_denied(
            "sidecar controller_principal_id must match the authenticated session",
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

/// Mint a `did:webvh` principal DID for a server-provisioned agent.
///
/// did:webvh-only red line: agent principals MUST NOT use `did:web` (no
/// key-log history). The DID host is the deployment's real service host
/// (derived from the configured `service_did`), never a `.agents.example`
/// placeholder. The SCID is a self-certifying multihash derived from a
/// per-agent genesis skeleton so the identifier is bound to its inception
/// material rather than being an opaque random string.
fn generate_agent_principal_did(service_did: &str) -> String {
    let host = crate::config::did_host_from_service_did(service_did)
        .unwrap_or_else(|| "soland.local".to_owned());
    let agent_uuid = uuid::Uuid::now_v7();
    // Genesis skeleton: the SCID is the multihash of this canonical structure
    // with the SCID field left as the placeholder, matching the did:webvh SCID
    // derivation used elsewhere in soland.
    let skeleton = serde_json::json!({
        "scid": "{SCID}",
        "host": host,
        "path": format!("webvh:agent:{agent_uuid}"),
    });
    let scid =
        crate::routing::identity::webvh_validation::derive_webvh_scid_from_skeleton(&skeleton)
            .unwrap_or_else(|_| agent_uuid.simple().to_string());
    format!("did:webvh:{scid}:{host}:webvh:agent:{agent_uuid}")
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

fn participation_scope_kind(scope: &AgentParticipationScope) -> &'static str {
    match scope {
        AgentParticipationScope::Realm { .. } => "realm",
        AgentParticipationScope::Circle { .. } => "circle",
        AgentParticipationScope::Strand { .. } => "strand",
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
    crate::routing::agent_participation::resolve_effective_ceiling(state, scope).await
}

fn agent_participation_failed_precondition(reason: &'static str) -> AppError {
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
async fn set_agent_participation(
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

fn is_capability_grant_id(grant_id: &str) -> bool {
    grant_id.starts_with("ck:grant:")
}

fn normalize_sidecar_exposure_ack(
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
async fn get_agent_participation(
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
    let state = depot.get_typed::<AppState>().expect("state injected");
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
    let agent_record = require_agent_controller(state, &session, agent_principal_id).await?;
    ensure_pairing_request_open(&agent_record)?;
    let runtime_public_key_digest = runtime_public_key_digest(&body.public_key)?;
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
    // CKP-0008 §4.5 / D3: the runtime key may become active only after a
    // reducer-visible `ck.agent.key.authorize` event exists. Development mode
    // still materializes the event with the local dev-proof path; production
    // requires yougen/coauth to provide a controller-signed durable event and
    // soland submits + rechecks it here.
    let event_id = if state.config.development_mode {
        let controller_session = controller_dev_session(&session.actor, state);
        let realm = ensure_self_realm(state, &controller_session).await?;
        let key_id = dev_fanout::default_agent_key_id(agent_principal_id);
        submit_durable_key_authorize(
            state,
            &controller_session,
            &realm,
            agent_principal_id,
            &body.verification_method,
            &key_id,
        )
        .await?
    } else {
        submit_production_key_authorize_event(
            state,
            &session,
            &body.authorize_event,
            &agent_record,
            agent_principal_id,
            &body.verification_method,
            &runtime_public_key_digest,
        )
        .await?
    };
    let authorized_event_ref = EventId::new(event_id)
        .map_err(|err| AppError::internal(format!("authorize event id invalid: {err}")))?;
    // Pairing semantics: a provisioned agent starts `pending_runtime_key`;
    // flip to `active` ONLY after the durable key authorization has been
    // accepted (a failed submit above propagates via `?` and MUST NOT leave
    // the agent flipped to active).
    let updated = state
        .persistence
        .agents()
        .set_state(agent_principal_id, "active", &authorized_at)
        .await
        .map_err(|err| AppError::internal(format!("agent state activation failed: {err}")))?;
    if !updated {
        return Err(AppError::internal(
            "agent state activation failed: agent principal disappeared",
        ));
    }
    json_ok(AgentKeyPairOutcome {
        ok: true,
        authorized_event_ref,
    })
}

async fn submit_production_key_authorize_event(
    state: &AppState,
    session: &SessionRecord,
    envelope: &Value,
    agent_record: &Value,
    agent_principal_id: &str,
    verification_method: &str,
    runtime_public_key_digest: &str,
) -> Result<String, AppError> {
    ensure_key_authorize_event_matches_request(
        envelope,
        &session.actor,
        agent_record,
        agent_principal_id,
        verification_method,
        runtime_public_key_digest,
        &state.config.service_did,
    )?;
    let outcome = submit_event_value(state, session, envelope.clone())
        .await
        .map_err(|error| {
            AppError::invalid_param(format!(
                "ck.agent.key.authorize submit failed: {}",
                error.message
            ))
            .with_status(error.status)
            .with_wire_code(error.code)
        })?;
    Ok(outcome.event_id)
}

fn ensure_key_authorize_event_matches_request(
    envelope: &Value,
    controller: &str,
    agent_record: &Value,
    agent_principal_id: &str,
    verification_method: &str,
    runtime_public_key_digest: &str,
    service_did: &str,
) -> Result<(), AppError> {
    if envelope.get("kind").and_then(Value::as_str) != Some("ck.agent.key.authorize") {
        return Err(AppError::invalid_param(
            "authorize_event.kind must be ck.agent.key.authorize",
        ));
    }
    if envelope.get("actor_id").and_then(Value::as_str) != Some(controller) {
        return Err(AppError::capability_denied(
            "authorize_event.actor_id must match the authenticated controller",
        ));
    }
    let payload = envelope
        .get("payload")
        .ok_or_else(|| AppError::invalid_param("authorize_event.payload is required"))?;
    if payload.get("agent_principal_id").and_then(Value::as_str) != Some(agent_principal_id) {
        return Err(AppError::invalid_param(
            "authorize_event.payload.agent_principal_id must match the pairing request",
        ));
    }
    if payload.get("verification_method").and_then(Value::as_str) != Some(verification_method) {
        return Err(AppError::invalid_param(
            "authorize_event.payload.verification_method must match the pairing request",
        ));
    }
    if payload
        .get("accountable_principal_id")
        .and_then(Value::as_str)
        != Some(controller)
    {
        return Err(AppError::capability_denied(
            "authorize_event.payload.accountable_principal_id must match the authenticated controller",
        ));
    }
    ensure_authorize_event_scope_matches_requested(agent_record, payload)?;
    let audience = payload
        .get("audience")
        .and_then(Value::as_array)
        .ok_or_else(|| AppError::invalid_param("authorize_event.payload.audience is required"))?;
    if !audience
        .iter()
        .any(|value| value.as_str() == Some(service_did))
    {
        return Err(AppError::invalid_param(
            "authorize_event.payload.audience must include this principal server",
        ));
    }
    let expires_at = payload
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .ok_or_else(|| {
            AppError::invalid_param("authorize_event.payload.expires_at must be rfc3339")
        })?;
    if expires_at.with_timezone(&chrono::Utc) <= chrono::Utc::now() {
        return Err(pairing_failed_precondition(
            "authorize_event payload has expired",
        ));
    }
    if payload.get("public_key_digest").and_then(Value::as_str) != Some(runtime_public_key_digest) {
        return Err(AppError::invalid_param(
            "authorize_event.payload.public_key_digest must bind the runtime public_key",
        ));
    }
    let expected_digest = pairing_request_binding_digest(
        agent_record,
        controller,
        agent_principal_id,
        verification_method,
        runtime_public_key_digest,
        service_did,
    )?;
    if payload
        .get("approval_evidence")
        .and_then(|value| value.get("request_canonical_digest"))
        .and_then(Value::as_str)
        != Some(expected_digest.as_str())
    {
        return Err(AppError::invalid_param(
            "authorize_event.payload.approval_evidence.request_canonical_digest must bind the pairing request",
        ));
    }
    Ok(())
}

fn ensure_pairing_request_open(agent_record: &Value) -> Result<(), AppError> {
    match agent_record.get("state").and_then(Value::as_str) {
        Some("pending_runtime_key") => {}
        Some("pairing_expired") => {
            return Err(pairing_failed_precondition("pairing request has expired"));
        }
        Some("active") => {
            return Err(pairing_failed_precondition(
                "agent runtime key is already active",
            ));
        }
        Some("paused" | "deactivated") => {
            return Err(pairing_failed_precondition(
                "agent is not accepting runtime key pairing",
            ));
        }
        _ => {
            return Err(pairing_failed_precondition(
                "agent pairing state is not pending_runtime_key",
            ));
        }
    }
    let expires_at = pairing_record_timestamp(agent_record, "pairing_expires_at")?;
    if expires_at <= chrono::Utc::now() {
        return Err(pairing_failed_precondition("pairing request has expired"));
    }
    Ok(())
}

fn pairing_failed_precondition(reason: &'static str) -> AppError {
    AppError::new(ErrorCode::FailedPrecondition, reason)
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_reason_detail(reason)
}

fn pairing_record_string<'a>(record: &'a Value, key: &str) -> Result<&'a str, AppError> {
    record
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            pairing_failed_precondition("agent pairing metadata is incomplete")
                .with_reason_detail(format!("missing {key}"))
        })
}

fn pairing_record_timestamp(
    record: &Value,
    key: &str,
) -> Result<chrono::DateTime<chrono::Utc>, AppError> {
    let value = pairing_record_string(record, key)?;
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
        .map_err(|_| AppError::invalid_param(format!("agent pairing metadata {key} is invalid")))
}

fn runtime_public_key_digest(public_key: &Value) -> Result<String, AppError> {
    if public_key.is_null() {
        return Err(AppError::missing_param("public_key is required"));
    }
    cokret_sdk::canonical::canonical_sha256(public_key).map_err(|error| {
        AppError::invalid_param(format!("public_key is not canonicalizable: {error}"))
    })
}

fn ensure_authorize_event_scope_matches_requested(
    agent_record: &Value,
    payload: &Value,
) -> Result<(), AppError> {
    let scope = payload.get("agent_key_scope").ok_or_else(|| {
        AppError::invalid_param("authorize_event.payload.agent_key_scope is required")
    })?;
    let actions = scope
        .get("actions")
        .and_then(Value::as_array)
        .filter(|actions| !actions.is_empty())
        .ok_or_else(|| {
            AppError::invalid_param("authorize_event.payload.agent_key_scope.actions is required")
        })?;
    if actions
        .iter()
        .any(|action| action.as_str().is_none_or(str::is_empty))
    {
        return Err(AppError::invalid_param(
            "authorize_event.payload.agent_key_scope.actions must be non-empty strings",
        ));
    }
    if let Some(expected) = agent_record
        .get("requested_scope")
        .filter(|value| !value.is_null())
        && scope != expected
    {
        return Err(AppError::invalid_param(
            "authorize_event.payload.agent_key_scope must match the provisioned requested_scope",
        ));
    }
    Ok(())
}

fn pairing_request_binding_digest(
    agent_record: &Value,
    controller: &str,
    agent_principal_id: &str,
    verification_method: &str,
    runtime_public_key_digest: &str,
    service_did: &str,
) -> Result<String, AppError> {
    let pairing_request_id = pairing_record_string(agent_record, "pairing_request_id")?;
    let pairing_code = pairing_record_string(agent_record, "pairing_code")?;
    let expires_at = pairing_record_string(agent_record, "pairing_expires_at")?;
    let binding = json!({
        "kind": "ck.agent.key_pairing_request_binding.v1",
        "operation_id": "ck.gate.account.command.pair_agent_key",
        "controller_principal_id": controller,
        "agent_principal_id": agent_principal_id,
        "verification_method": verification_method,
        "runtime_public_key_digest": runtime_public_key_digest,
        "pairing_request_id": pairing_request_id,
        "pairing_code": pairing_code,
        "expires_at": expires_at,
        "audience": service_did,
    });
    cokret_sdk::canonical::canonical_sha256(&binding).map_err(|error| {
        AppError::internal(format!(
            "pairing binding digest canonicalization failed: {error}"
        ))
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
        let (profile_event, accountability_event, grant_ids) = fanout_provision_subevents(
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
            "initial_capability_grant_ids": grant_ids,
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
const AGENT_ADAPTER_REGISTRY_IDS: [&str; 4] = ["a2a", "acp", "mcp_bridge", "http_custom"];

#[endpoint(
    operation_id = "ck.self.agent.protocol.query.discover",
    tags("agents"),
    summary = "Discover an agent runtime's declared external protocol endpoints",
    status_codes(200, 400, 401, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.protocol.query.discover"))]
async fn discover_agent_endpoint(
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
    operation_id = "ck.self.agent.resource.get",
    tags("agents"),
    summary = "Get a personal agent by id (controller-self only)",
    status_codes(200, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.resource.get"))]
async fn get_agent(
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

async fn lifecycle_transition(
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
            sidecar_exposure_ack.as_ref(),
        )
        .await?;
        if event_kind == "ck.self.agent.deactivate" {
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
        if event_kind == "ck.self.agent.resume"
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
    operation_id = "ck.self.agent.command.pause",
    tags("agents"),
    summary = "Pause a personal agent",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.agent.command.pause"))]
async fn pause_agent(
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
            "ck.self.agent.pause",
            body.reason,
            None,
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
            "ck.self.agent.resume",
            None,
            body.sidecar_exposure_ack,
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
            "ck.self.agent.deactivate",
            body.reason,
            None,
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

const SIDECAR_CREATE_DENIED: &str = "sidecar_create_denied";
const ADDRESSED_AGENT_NOT_ELIGIBLE: &str = "addressed_agent_not_eligible";
const CONTROLLER_IN_ADDRESSED_AGENTS: &str = "controller_in_addressed_agents";

fn sidecar_create_denied(message: impl Into<String>) -> AppError {
    AppError::capability_denied(message).with_wire_code(SIDECAR_CREATE_DENIED)
}

fn sidecar_failed_precondition(reason: &'static str, message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::FailedPrecondition, message.into())
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_wire_code(reason)
}

fn sidecar_reducer_reject_to_app_error(reason: &'static str) -> AppError {
    AppError::new(
        ErrorCode::FailedPrecondition,
        format!("agent sidecar reducer rejected: {reason}"),
    )
    .with_status(StatusCode::PRECONDITION_FAILED)
    .with_wire_code(reason)
}

async fn authorize_sidecar_ensure(
    state: &AppState,
    controller: &str,
    realm_id: &str,
) -> Result<(), AppError> {
    let owner = state
        .persistence
        .realm_meta()
        .get(realm_id)
        .await
        .ok()
        .flatten()
        .map(|meta| meta.owner);
    let members = realm_members_for_authz(state, realm_id);
    let verdict = state.authz.check(
        controller,
        cokret_sdk::CAP_ACTION_AGENT_SIDECAR_THREAD_ENSURE,
        realm_id,
        realm_id,
        owner.as_deref(),
        &members,
        &[],
    );
    if verdict.allowed {
        return Ok(());
    }
    if matches!(
        verdict.reason.as_str(),
        "explicit_deny" | "quarantine" | "require_review" | "constraints_not_satisfied"
    ) {
        return Err(sidecar_create_denied(
            "ck.self.agent.sidecar_thread.command.ensure denied by policy",
        ));
    }
    if realm_member_joined(state, realm_id, controller) {
        return Ok(());
    }
    Err(sidecar_create_denied(
        "ck.self.agent.sidecar_thread.command.ensure requires a Realm member controller",
    ))
}

fn realm_members_for_authz(state: &AppState, realm_id: &str) -> Vec<String> {
    {
        let realms = state.realms.lock();
        {
            RealmId::new(realm_id.to_owned())
                .ok()
                .and_then(|id| realms.get(&id).cloned())
        }
    }
    .map(|realm| {
        realm
            .members
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    })
    .unwrap_or_default()
}

fn realm_member_joined(state: &AppState, realm_id: &str, actor: &str) -> bool {
    let in_realm_directory = {
        let realms = state.realms.lock();
        {
            RealmId::new(realm_id.to_owned())
                .ok()
                .and_then(|id| realms.get(&id).cloned())
        }
    }
    .and_then(|realm| {
        Did::new(actor.to_owned())
            .ok()
            .map(|did| realm.members.contains(&did))
    })
    .unwrap_or(false);
    if in_realm_directory {
        return true;
    }
    {
        let projection = state.projection.lock();
        {
            projection
                .member(realm_id, actor)
                .map(|membership| membership.state == "join")
        }
    }
    .unwrap_or(false)
}

fn normalize_sidecar_context_ref(context_ref: &AgentSidecarContextRef) -> Result<Value, AppError> {
    let has_strand = context_ref.strand_id.is_some();
    let has_relation = context_ref.relation_id.is_some();
    if has_relation
        && (has_strand || context_ref.message_id.is_some() || context_ref.track_name.is_some())
    {
        return Err(AppError::invalid_param(
            "context_ref with relation_id must not include strand_id, message_id, or track_name",
        ));
    }
    if !has_relation && !has_strand {
        return Err(AppError::invalid_param(
            "context_ref must include either strand_id or relation_id",
        ));
    }
    if context_ref.message_id.is_some() && !has_strand {
        return Err(AppError::invalid_param(
            "context_ref.message_id requires strand_id",
        ));
    }
    serde_json::to_value(context_ref)
        .map_err(|err| AppError::internal(format!("context_ref serialization failed: {err}")))
}

fn sidecar_context_target_ref(context_ref: &AgentSidecarContextRef) -> String {
    if let Some(relation_id) = &context_ref.relation_id {
        return relation_id.to_string();
    }
    if let Some(message_id) = &context_ref.message_id {
        return message_id.to_string();
    }
    context_ref
        .strand_id
        .as_ref()
        .expect("context_ref validated")
        .to_string()
}

fn validate_sidecar_context_projection(
    state: &AppState,
    context_ref: &AgentSidecarContextRef,
) -> Result<(), AppError> {
    let projection = state.projection.lock();
    let realm_id = context_ref.realm_id.as_str();
    if let Some(relation_id) = &context_ref.relation_id {
        let relation = projection
            .relations
            .get(relation_id.as_str())
            .ok_or_else(|| AppError::not_found("context_ref.relation_id not found"))?;
        if relation.realm_id != realm_id {
            return Err(sidecar_failed_precondition(
                "context_ref_realm_mismatch",
                "context_ref.relation_id belongs to another Realm",
            ));
        }
        if relation.state != "active" {
            return Err(sidecar_failed_precondition(
                "relation_not_active",
                "context_ref.relation_id is not active",
            ));
        }
        return Ok(());
    }
    let Some(strand_id) = &context_ref.strand_id else {
        return Err(AppError::invalid_param(
            "context_ref must include strand_id or relation_id",
        ));
    };
    let strand = projection
        .strands
        .get(strand_id.as_str())
        .ok_or_else(|| AppError::not_found("context_ref.strand_id not found"))?;
    if strand.realm_id != realm_id {
        return Err(sidecar_failed_precondition(
            "context_ref_realm_mismatch",
            "context_ref.strand_id belongs to another Realm",
        ));
    }
    if let Some(message_id) = &context_ref.message_id {
        let message = projection
            .messages
            .get(message_id.as_str())
            .ok_or_else(|| AppError::not_found("context_ref.message_id not found"))?;
        if message.realm_id != realm_id || message.thread_id != strand_id.as_str() {
            return Err(sidecar_failed_precondition(
                "context_ref_realm_mismatch",
                "context_ref.message_id does not belong to the referenced Strand",
            ));
        }
    }
    Ok(())
}

fn normalize_addressed_agents(
    controller: &str,
    body: &AgentSidecarThreadEnsureRequestBody,
) -> Result<Vec<String>, AppError> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for agent in &body.addressed_agent_principal_ids {
        let agent = agent.as_str().trim();
        if agent == controller {
            return Err(sidecar_failed_precondition(
                CONTROLLER_IN_ADDRESSED_AGENTS,
                "addressed_agent_principal_ids must not contain the controller",
            ));
        }
        if seen.insert(agent.to_owned()) {
            out.push(agent.to_owned());
        }
    }
    Ok(out)
}

async fn eligible_sidecar_agents(
    state: &AppState,
    realm_id: &str,
    controller: &str,
    addressed_agents: &[String],
) -> Result<Vec<String>, AppError> {
    let records = state
        .persistence
        .agents()
        .list_for_controller(controller)
        .await
        .map_err(|err| AppError::internal(format!("agent list failed: {err}")))?;
    let mut eligible = BTreeSet::new();
    for record in records {
        if let Some(agent_id) = record.get("agent_principal_id").and_then(Value::as_str)
            && agent_record_is_sidecar_eligible(state, realm_id, controller, &record)
        {
            eligible.insert(agent_id.to_owned());
        }
    }
    for addressed in addressed_agents {
        if !eligible.contains(addressed) {
            return Err(sidecar_failed_precondition(
                ADDRESSED_AGENT_NOT_ELIGIBLE,
                "addressed agent is not eligible for this sidecar Realm",
            ));
        }
    }
    Ok(eligible.into_iter().collect())
}

fn agent_record_is_sidecar_eligible(
    state: &AppState,
    realm_id: &str,
    controller: &str,
    record: &Value,
) -> bool {
    let Some(agent_id) = record.get("agent_principal_id").and_then(Value::as_str) else {
        return false;
    };
    if record.get("controller_did").and_then(Value::as_str) != Some(controller) {
        return false;
    }
    if record
        .get("state")
        .and_then(Value::as_str)
        .is_some_and(|state| state != "active")
    {
        return false;
    }
    if !realm_member_joined(state, realm_id, agent_id) {
        return false;
    }
    let projection = state.projection.lock();
    !matches!(
        projection.agent_lifecycles.get(agent_id),
        Some(AgentLifecycleState::Paused | AgentLifecycleState::Deactivated)
    ) && projection.agent_has_authorized_key(agent_id)
}

fn controller_agent_circle_key(realm_id: &str, controller: &str) -> String {
    cokret_sdk::agent_sidecar_circle_key(realm_id, controller)
}

fn sidecar_short_name(controller_agent_circle_key: &str) -> String {
    cokret_sdk::agent_sidecar_short_name(controller_agent_circle_key)
}

fn find_sidecar_circle(
    state: &AppState,
    realm_id: &str,
    controller: &str,
    short_name: &str,
) -> Option<CircleId> {
    let projection = state.projection.lock();
    projection
        .circles
        .values()
        .find(|circle| {
            circle.realm_id == realm_id
                && circle.created_by == controller
                && circle.title == short_name
                && circle.directory_visibility == "members"
                && circle.state == crate::reducer::CircleLifecycleState::Active
        })
        .and_then(|circle| CircleId::new(circle.circle_id.clone()).ok())
}

fn sidecar_actor_capability(circle_id: Option<&str>) -> Value {
    let mut value = json!({
        "action": cokret_sdk::CAP_ACTION_AGENT_SIDECAR_THREAD_ENSURE,
        "allowed": true,
    });
    if let Some(circle_id) = circle_id
        && let Some(object) = value.as_object_mut()
    {
        object.insert("circle_id".to_owned(), Value::String(circle_id.to_owned()));
    }
    value
}

fn new_sidecar_operation(
    realm_id: &RealmId,
    kind: &'static str,
    payload: Value,
) -> Result<Operation, AppError> {
    let operation_id = OperationId::new(ids::generate_operation_id())
        .map_err(|err| AppError::internal(format!("generated operation id invalid: {err}")))?;
    Ok(Operation::create(
        operation_id,
        realm_id.clone(),
        kind,
        payload,
    ))
}

async fn ensure_sidecar_circle(
    state: &AppState,
    controller: &str,
    realm_id: &RealmId,
    controller_agent_circle_key: &str,
    short_name: &str,
) -> Result<CircleId, AppError> {
    if let Some(circle_id) = find_sidecar_circle(state, realm_id.as_str(), controller, short_name) {
        return Ok(circle_id);
    }
    let circle_id = CircleId::new(ids::generate_circle_id())
        .map_err(|err| AppError::internal(format!("generated circle id invalid: {err}")))?;
    let object = json!({
        "id": circle_id,
        "realm_id": realm_id,
        "title": short_name,
        "summary": "Controller-private AI sidecar scope",
        "display": {
            "short_name": short_name,
        },
        "directory_visibility": "members",
        "join_rule": "invite",
        "history_visibility": "joined",
        "content_encryption_floor": "e2ee_required",
        "metadata_encryption_floor": "e2ee_required",
        "encryption_profile": "mls_rfc9420",
        "created_by": controller,
        "sidecar_profile": cokret_sdk::PROFILE_AGENT_SIDECAR_THREAD,
        "controller_principal_id": controller,
        "controller_agent_circle_key": controller_agent_circle_key,
    });
    let payload = json!({
        "object": object,
        "sender": controller,
        "profile": cokret_sdk::PROFILE_AGENT_SIDECAR_THREAD,
        "sidecar_ensure_capability_verified": true,
        "actor_capability": sidecar_actor_capability(None),
    });
    let operation =
        new_sidecar_operation(realm_id, cokret_sdk::events::kinds::CIRCLE_CREATE, payload)?;
    accept_local_operations(state, controller, std::slice::from_ref(&operation))
        .await
        .map_err(sidecar_reducer_reject_to_app_error)?;
    find_sidecar_circle(state, realm_id.as_str(), controller, short_name)
        .ok_or_else(|| AppError::internal("sidecar Circle accepted but not projected"))
}

fn circle_has_member(state: &AppState, circle_id: &str, actor: &str) -> bool {
    {
        let projection = state.projection.lock();
        {
            projection
                .circles
                .get(circle_id)
                .map(|circle| circle.members.contains(actor))
        }
    }
    .unwrap_or(false)
}

async fn ensure_sidecar_member(
    state: &AppState,
    controller: &str,
    realm_id: &RealmId,
    circle_id: &CircleId,
    actor: &str,
) -> Result<(), AppError> {
    if circle_has_member(state, circle_id.as_str(), actor) {
        return Ok(());
    }
    let payload = json!({
        "circle_id": circle_id,
        "actor": actor,
        "actor_id": actor,
        "membership": "join",
        "sender": controller,
        "manage_capability_verified": true,
        "profile": cokret_sdk::PROFILE_AGENT_SIDECAR_THREAD,
        "sidecar_ensure_capability_verified": true,
        "actor_capability": {
            "action": "ck.circle.member.manage",
            "circle_id": circle_id,
            "allowed": true,
        },
    });
    let operation = new_sidecar_operation(
        realm_id,
        cokret_sdk::events::kinds::CIRCLE_MEMBER_STATE,
        payload,
    )?;
    accept_local_operations(state, controller, std::slice::from_ref(&operation))
        .await
        .map_err(sidecar_reducer_reject_to_app_error)
}

fn find_sidecar_strand(
    state: &AppState,
    realm_id: &str,
    controller: &str,
    circle_id: &str,
    normalized_context_ref_digest: &str,
) -> Option<StrandId> {
    let projection = state.projection.lock();
    projection
        .strands
        .values()
        .find(|strand| {
            strand.realm_id == realm_id
                && strand.scope_circle_id.as_deref() == Some(circle_id)
                && strand.fields.get("sidecar_profile").and_then(Value::as_str)
                    == Some(cokret_sdk::PROFILE_AGENT_SIDECAR_THREAD)
                && strand
                    .fields
                    .get("controller_principal_id")
                    .and_then(Value::as_str)
                    == Some(controller)
                && strand
                    .fields
                    .get("normalized_context_ref_digest")
                    .and_then(Value::as_str)
                    == Some(normalized_context_ref_digest)
        })
        .and_then(|strand| StrandId::new(strand.strand_id.clone()).ok())
}

async fn ensure_sidecar_strand(
    state: &AppState,
    controller: &str,
    realm_id: &RealmId,
    circle_id: &CircleId,
    normalized_context_ref: &Value,
    normalized_context_ref_digest: &str,
) -> Result<StrandId, AppError> {
    if let Some(strand_id) = find_sidecar_strand(
        state,
        realm_id.as_str(),
        controller,
        circle_id.as_str(),
        normalized_context_ref_digest,
    ) {
        return Ok(strand_id);
    }
    let strand_id = StrandId::new(ids::generate("strand"))
        .map_err(|err| AppError::internal(format!("generated strand id invalid: {err}")))?;
    let object = json!({
        "id": strand_id,
        "realm_id": realm_id,
        "metadata": {
            "title": "AI sidecar",
            "summary": "Controller-private AI sidecar thread",
            "fields": {
                "sidecar_profile": cokret_sdk::PROFILE_AGENT_SIDECAR_THREAD,
                "controller_principal_id": controller,
                "normalized_context_ref": normalized_context_ref,
                "normalized_context_ref_digest": normalized_context_ref_digest,
            },
        },
        "scope_circle_id": circle_id,
        "created_by": controller,
    });
    let payload = json!({
        "object": object,
        "sender": controller,
        "profile": cokret_sdk::PROFILE_AGENT_SIDECAR_THREAD,
        "sidecar_ensure_capability_verified": true,
        "actor_capability": sidecar_actor_capability(Some(circle_id.as_str())),
    });
    let operation =
        new_sidecar_operation(realm_id, cokret_sdk::events::kinds::STRAND_CREATE, payload)?;
    accept_local_operations(state, controller, std::slice::from_ref(&operation))
        .await
        .map_err(sidecar_reducer_reject_to_app_error)?;
    find_sidecar_strand(
        state,
        realm_id.as_str(),
        controller,
        circle_id.as_str(),
        normalized_context_ref_digest,
    )
    .ok_or_else(|| AppError::internal("sidecar Strand accepted but not projected"))
}

fn find_sidecar_relation(
    state: &AppState,
    realm_id: &str,
    circle_id: &str,
    private_strand_id: &str,
    target_ref: &str,
) -> Option<RelationId> {
    let projection = state.projection.lock();
    projection
        .relations
        .values()
        .find(|relation| {
            relation.realm_id == realm_id
                && relation.relation_kind == "agent_sidecar_of"
                && relation.scope_circle_id.as_deref() == Some(circle_id)
                && relation.from_ref.as_deref() == Some(private_strand_id)
                && relation.to_ref.as_deref() == Some(target_ref)
                && relation.state == "active"
        })
        .and_then(|relation| RelationId::new(relation.relation_id.clone()).ok())
}

async fn ensure_sidecar_relation(
    state: &AppState,
    controller: &str,
    realm_id: &RealmId,
    circle_id: &CircleId,
    private_strand_id: &StrandId,
    target_ref: &str,
    normalized_context_ref_digest: &str,
    track_name: Option<&str>,
) -> Result<RelationId, AppError> {
    if let Some(relation_id) = find_sidecar_relation(
        state,
        realm_id.as_str(),
        circle_id.as_str(),
        private_strand_id.as_str(),
        target_ref,
    ) {
        return Ok(relation_id);
    }
    let relation_id = RelationId::new(ids::generate_relation_id())
        .map_err(|err| AppError::internal(format!("generated relation id invalid: {err}")))?;
    let mut fields = json!({
        "sidecar_profile": cokret_sdk::PROFILE_AGENT_SIDECAR_THREAD,
        "controller_principal_id": controller,
        "normalized_context_ref_digest": normalized_context_ref_digest,
    });
    if let Some(track_name) = track_name
        && let Some(object) = fields.as_object_mut()
    {
        object.insert(
            "context_track_name".to_owned(),
            Value::String(track_name.to_owned()),
        );
    }
    let payload = json!({
        "relation_id": relation_id,
        "relation_kind": "agent_sidecar_of",
        "from_ref": private_strand_id,
        "to_ref": target_ref,
        "scope_circle_id": circle_id,
        "fields": fields,
        "sender": controller,
        "profile": cokret_sdk::PROFILE_AGENT_SIDECAR_THREAD,
        "sidecar_ensure_capability_verified": true,
        "actor_capability": sidecar_actor_capability(Some(circle_id.as_str())),
    });
    let operation = new_sidecar_operation(
        realm_id,
        cokret_sdk::events::kinds::RELATION_CREATE,
        payload,
    )?;
    accept_local_operations(state, controller, std::slice::from_ref(&operation))
        .await
        .map_err(sidecar_reducer_reject_to_app_error)?;
    find_sidecar_relation(
        state,
        realm_id.as_str(),
        circle_id.as_str(),
        private_strand_id.as_str(),
        target_ref,
    )
    .ok_or_else(|| AppError::internal("sidecar Relation accepted but not projected"))
}

async fn ensure_sidecar_thread_impl(
    aa: AuthArgs,
    body: AgentSidecarThreadEnsureRequestBody,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentSidecarThreadEnsureOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    ensure_sidecar_controller_request(&body, &session)?;
    let controller = body.controller_principal_id.as_str();
    let realm_id = body.context_ref.realm_id.clone();
    authorize_sidecar_ensure(state, controller, realm_id.as_str()).await?;
    let normalized_context_ref = normalize_sidecar_context_ref(&body.context_ref)?;
    validate_sidecar_context_projection(state, &body.context_ref)?;
    let normalized_context_ref_digest =
        cokret_sdk::canonical::canonical_sha256(&normalized_context_ref)
            .map_err(|err| AppError::internal(format!("context_ref digest failed: {err}")))?;
    let target_ref = sidecar_context_target_ref(&body.context_ref);
    let addressed_agents = normalize_addressed_agents(controller, &body)?;
    let eligible_agents =
        eligible_sidecar_agents(state, realm_id.as_str(), controller, &addressed_agents).await?;
    let controller_agent_circle_key = controller_agent_circle_key(realm_id.as_str(), controller);
    let short_name = sidecar_short_name(&controller_agent_circle_key);
    let private_circle_id = ensure_sidecar_circle(
        state,
        controller,
        &realm_id,
        &controller_agent_circle_key,
        &short_name,
    )
    .await?;
    ensure_sidecar_member(state, controller, &realm_id, &private_circle_id, controller).await?;
    for agent in &eligible_agents {
        ensure_sidecar_member(state, controller, &realm_id, &private_circle_id, agent).await?;
    }
    let private_strand_id = ensure_sidecar_strand(
        state,
        controller,
        &realm_id,
        &private_circle_id,
        &normalized_context_ref,
        &normalized_context_ref_digest,
    )
    .await?;
    let private_relation_id = ensure_sidecar_relation(
        state,
        controller,
        &realm_id,
        &private_circle_id,
        &private_strand_id,
        &target_ref,
        &normalized_context_ref_digest,
        body.context_ref.track_name.as_deref(),
    )
    .await?;
    append_audit_log(
        state,
        Some(&session.actor),
        "ck.self.agent.sidecar_thread.command.ensure",
        json!({
            "controller_principal_id": body.controller_principal_id,
            "addressed_agent_principal_ids": addressed_agents,
            "context_ref": normalized_context_ref,
            "normalized_context_ref_digest": normalized_context_ref_digest,
            "private_circle_id": private_circle_id,
            "private_strand_id": private_strand_id,
            "private_relation_id": private_relation_id,
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

    fn test_session(actor: &str) -> SessionRecord {
        SessionRecord {
            token_hash: format!("test-session:{actor}"),
            actor: actor.to_owned(),
            device_id: "test-device".to_owned(),
            audience: "did:web:soland.test".to_owned(),
            session_public_key: None,
            agent_session: None,
            expires_at: now() + chrono::Duration::minutes(5),
            created_at: now(),
            revoked_at: None,
        }
    }

    fn agent_record(agent_principal_id: &str, controller_did: &str) -> Value {
        json!({
            "agent_principal_id": agent_principal_id,
            "controller_did": controller_did,
            "agent_id": agent_principal_id,
            "display_name": "Test Agent",
            "state": "active",
        })
    }

    fn pending_pairing_record(
        agent_principal_id: &str,
        controller_did: &str,
        requested_scope: Value,
        pairing_code: &str,
        pairing_expires_at: &str,
    ) -> Value {
        json!({
            "agent_principal_id": agent_principal_id,
            "controller_did": controller_did,
            "agent_id": agent_principal_id,
            "display_name": "Test Agent",
            "state": "pending_runtime_key",
            "requested_scope": requested_scope,
            "pairing_request_id": "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
            "pairing_code": pairing_code,
            "pairing_expires_at": pairing_expires_at,
        })
    }

    fn requested_agent_scope() -> Value {
        json!({
            "actions": [
                "ck.self.events.stream.subscribe",
                "ck.self.events.query.scan",
                "ck.self.events.command.submit",
                "ck.event.read",
                "ck.message.create"
            ],
            "resources": [{ "kind": "service", "service_did": "did:web:soland.local" }]
        })
    }

    fn key_authorize_envelope(
        record: &Value,
        controller: &str,
        agent_principal_id: &str,
        verification_method: &str,
        public_key_digest: &str,
        service_did: &str,
        scope: Value,
    ) -> Value {
        let request_canonical_digest = pairing_request_binding_digest(
            record,
            controller,
            agent_principal_id,
            verification_method,
            public_key_digest,
            service_did,
        )
        .expect("pairing binding digest");
        json!({
            "kind": "ck.agent.key.authorize",
            "actor_id": controller,
            "payload": {
                "agent_principal_id": agent_principal_id,
                "key_id": "ck:agent_key:01999999000070008000000000000001",
                "verification_method": verification_method,
                "public_key_digest": public_key_digest,
                "accountable_principal_id": controller,
                "agent_key_scope": scope,
                "audience": [service_did],
                "issued_at": "2026-07-06T00:00:00Z",
                "expires_at": "2999-01-01T00:00:00Z",
                "approval_evidence": {
                    "kind": "approval_event",
                    "ref": "ck:event:01999999-0000-7000-8000-000000000001",
                    "request_canonical_digest": request_canonical_digest,
                    "approved_by": controller,
                },
            },
        })
    }

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
    fn detach_revoke_only_targets_capability_grants() {
        assert!(is_capability_grant_id(
            "ck:grant:01999999-0000-7000-8000-000000000001"
        ));
        assert!(!is_capability_grant_id(
            "ck:accountability_grant:01999999-0000-7000-8000-000000000001"
        ));
    }

    #[test]
    fn agent_view_projects_spec_shape_dropping_internal_columns() {
        let view = agent_view_from_record(&json!({
            "agent_principal_id": "did:webvh:agent.example",
            "controller_did": "did:webvh:example.com:users:alice",
            "agent_id": "did:webvh:agent.example",
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
            "did:webvh:agent.example"
        );
        // soland-internal columns MUST NOT leak into the protocol projection.
        assert!(agent["agent"].get("controller_did").is_none());
        assert!(agent["agent"].get("agent_id").is_none());
    }

    #[test]
    fn resume_sidecar_exposure_ack_is_validated_and_normalized() {
        let ack = normalize_sidecar_exposure_ack(
            Some(json!({
                "acknowledged_at": "2026-06-18T12:00:00Z",
                "acknowledged_by": "did:web:controller.example",
                "sidecar_refs": [
                    "ck:circle:01964137-0000-7000-8000-000000000020",
                    "ck:strand:01964137-0000-7000-8000-000000000021"
                ]
            })),
            "did:web:controller.example",
        )
        .expect("valid sidecar exposure ack should normalize")
        .expect("ack should be present");

        assert_eq!(ack["acknowledged_by"], "did:web:controller.example");
        assert_eq!(ack["sidecar_refs"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn resume_sidecar_exposure_ack_rejects_wrong_controller() {
        let err = normalize_sidecar_exposure_ack(
            Some(json!({
                "acknowledged_at": "2026-06-18T12:00:00Z",
                "acknowledged_by": "did:web:other.example",
                "sidecar_refs": ["ck:circle:01964137-0000-7000-8000-000000000020"]
            })),
            "did:web:controller.example",
        )
        .expect_err("ack by another controller must reject");

        assert_eq!(err.wire_code(), "capability_denied");
    }

    #[test]
    fn controller_binding_accepts_agent_controller() {
        let session = test_session("did:web:controller.example");
        let record = agent_record("did:web:agent.example", "did:web:controller.example");

        ensure_agent_record_controller(&record, "did:web:agent.example", &session)
            .expect("controller session must operate its agent");
    }

    #[test]
    fn controller_binding_rejects_non_controller() {
        let session = test_session("did:web:mallory.example");
        let record = agent_record("did:web:agent.example", "did:web:controller.example");

        let err = ensure_agent_record_controller(&record, "did:web:agent.example", &session)
            .expect_err("non-controller session must be rejected");

        assert_eq!(err.wire_code(), "capability_denied");
    }

    #[test]
    fn key_authorize_event_binds_pairing_transcript_and_scope() {
        let controller = "did:web:controller.example";
        let agent = "did:web:agent.example";
        let verification_method = "did:web:agent.example#runtime-key-1";
        let service_did = "did:web:soland.local";
        let public_key_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let scope = requested_agent_scope();
        let record = pending_pairing_record(
            agent,
            controller,
            scope.clone(),
            "12345678",
            "2999-01-01T00:00:00Z",
        );
        let envelope = key_authorize_envelope(
            &record,
            controller,
            agent,
            verification_method,
            public_key_digest,
            service_did,
            scope,
        );

        ensure_pairing_request_open(&record).expect("pending pairing should be open");
        ensure_key_authorize_event_matches_request(
            &envelope,
            controller,
            &record,
            agent,
            verification_method,
            public_key_digest,
            service_did,
        )
        .expect("matching authorize_event should pass");
    }

    #[test]
    fn key_authorize_event_rejects_wrong_pairing_code_digest() {
        let controller = "did:web:controller.example";
        let agent = "did:web:agent.example";
        let verification_method = "did:web:agent.example#runtime-key-1";
        let service_did = "did:web:soland.local";
        let public_key_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let scope = requested_agent_scope();
        let record = pending_pairing_record(
            agent,
            controller,
            scope.clone(),
            "12345678",
            "2999-01-01T00:00:00Z",
        );
        let mut mismatched_record = record.clone();
        mismatched_record["pairing_code"] = json!("87654321");
        let envelope = key_authorize_envelope(
            &record,
            controller,
            agent,
            verification_method,
            public_key_digest,
            service_did,
            scope,
        );

        let err = ensure_key_authorize_event_matches_request(
            &envelope,
            controller,
            &mismatched_record,
            agent,
            verification_method,
            public_key_digest,
            service_did,
        )
        .expect_err("wrong pairing code must change the expected digest");

        assert_eq!(err.wire_code(), "invalid_param");
        assert!(err.message.contains("request_canonical_digest"));
    }

    #[test]
    fn key_authorize_event_rejects_expired_pairing() {
        let record = pending_pairing_record(
            "did:web:agent.example",
            "did:web:controller.example",
            requested_agent_scope(),
            "12345678",
            "2000-01-01T00:00:00Z",
        );

        let err = ensure_pairing_request_open(&record)
            .expect_err("expired pairing request must fail closed");

        assert_eq!(err.wire_code(), "failed_precondition");
        assert_eq!(
            err.reason_detail.as_deref(),
            Some("pairing request has expired")
        );
    }

    #[test]
    fn key_authorize_event_rejects_scope_mismatch() {
        let controller = "did:web:controller.example";
        let agent = "did:web:agent.example";
        let verification_method = "did:web:agent.example#runtime-key-1";
        let service_did = "did:web:soland.local";
        let public_key_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let expected_scope = requested_agent_scope();
        let record = pending_pairing_record(
            agent,
            controller,
            expected_scope,
            "12345678",
            "2999-01-01T00:00:00Z",
        );
        let weaker_scope = json!({
            "actions": ["ck.self.events.stream.subscribe"],
            "resources": [{ "kind": "service", "service_did": service_did }]
        });
        let envelope = key_authorize_envelope(
            &record,
            controller,
            agent,
            verification_method,
            public_key_digest,
            service_did,
            weaker_scope,
        );

        let err = ensure_key_authorize_event_matches_request(
            &envelope,
            controller,
            &record,
            agent,
            verification_method,
            public_key_digest,
            service_did,
        )
        .expect_err("agent_key_scope must match provisioned requested_scope");

        assert_eq!(err.wire_code(), "invalid_param");
        assert!(err.message.contains("agent_key_scope"));
    }

    #[test]
    fn key_authorize_event_rejects_wrong_runtime_public_key_digest() {
        let controller = "did:web:controller.example";
        let agent = "did:web:agent.example";
        let verification_method = "did:web:agent.example#runtime-key-1";
        let service_did = "did:web:soland.local";
        let public_key_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let scope = requested_agent_scope();
        let record = pending_pairing_record(
            agent,
            controller,
            scope.clone(),
            "12345678",
            "2999-01-01T00:00:00Z",
        );
        let envelope = key_authorize_envelope(
            &record,
            controller,
            agent,
            verification_method,
            public_key_digest,
            service_did,
            scope,
        );

        let err = ensure_key_authorize_event_matches_request(
            &envelope,
            controller,
            &record,
            agent,
            verification_method,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            service_did,
        )
        .expect_err("authorize_event public key digest must bind request public_key");

        assert_eq!(err.wire_code(), "invalid_param");
        assert!(err.message.contains("public_key_digest"));
    }

    #[test]
    fn sidecar_request_rejects_body_controller_mismatch() {
        let session = test_session("did:web:controller.example");
        let body = AgentSidecarThreadEnsureRequestBody {
            controller_principal_id: Did::new("did:web:mallory.example").expect("controller did"),
            addressed_agent_principal_ids: Vec::new(),
            context_ref: AgentSidecarContextRef::strand(
                RealmId::new("ck:realm:0196419b-0000-7000-8000-000000000001").expect("realm id"),
                StrandId::new("ck:strand:0196419b-0000-7000-8000-000000000002").expect("strand id"),
            ),
        };

        let err = ensure_sidecar_controller_request(&body, &session)
            .expect_err("sidecar body controller must match session actor");

        assert_eq!(err.wire_code(), SIDECAR_CREATE_DENIED);
    }

    #[test]
    fn sidecar_context_ref_requires_strand_or_relation() {
        let context_ref = AgentSidecarContextRef {
            realm_id: RealmId::new("ck:realm:01964137-0000-7000-8000-000000000030").unwrap(),
            strand_id: None,
            track_name: None,
            message_id: None,
            relation_id: None,
        };
        let err = normalize_sidecar_context_ref(&context_ref)
            .expect_err("context_ref without a target must reject");
        assert_eq!(err.wire_code(), "invalid_param");
    }

    #[test]
    fn sidecar_addressed_agents_rejects_controller() {
        let controller = Did::new("did:web:example.com:users:alice").unwrap();
        let body = AgentSidecarThreadEnsureRequestBody {
            controller_principal_id: controller.clone(),
            addressed_agent_principal_ids: vec![controller.clone()],
            context_ref: AgentSidecarContextRef::strand(
                RealmId::new("ck:realm:01964137-0000-7000-8000-000000000030").unwrap(),
                StrandId::new("ck:strand:01964137-0000-7000-8000-000000000031").unwrap(),
            ),
        };
        let err = normalize_addressed_agents(controller.as_str(), &body)
            .expect_err("controller must not be addressable as an agent");
        assert_eq!(err.wire_code(), CONTROLLER_IN_ADDRESSED_AGENTS);
    }
}
