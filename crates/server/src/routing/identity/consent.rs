//! Holder-private consent cell routes.
//!
//! This is the G3.S4 minimal reducer surface for
//! `ck.component.consent.grant.v1`: the in-process projection stores one
//! OR-set-like cell per `(holder_did, peer_did, scope)`, and contact
//! requests consult that projection before opening or accepting a request.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use cokret_sdk::{
    ConsentCellList, ConsentCellView, ConsentRequestRequestBody, ConsentState,
    ConsentUpdateRequestBody, Did, EventId, Operation,
};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{AuthArgs, append_audit_log, now, query_param, sha256_hex, validate_did};
use crate::error::AppError;
use crate::routing::identity::device_messages::{
    ACCOUNT_DATA_UPDATE_TYPE, fanout_actor_private_update,
};
use crate::state::{
    AccountDataRecord, AppState, ConsentCellKey, ConsentCellRecord, ConsentGrantDot,
    ProjectionEventRecord,
};
use crate::{JsonResult, ids, json_ok};

const ACCOUNT_DATA_TYPE_INVITE_QUARANTINE: &str = "ck.account.invite_quarantine";
const INVITE_QUARANTINE_ORIGIN_DEVICE: &str = "server:consent_revoke";

pub(super) fn router() -> Router {
    Router::with_path("consent")
        .push(Router::with_path("cells").get(list_consent_cells))
        .push(Router::with_path("cells/{holder_did}").get(get_consent_cell))
        .push(Router::with_path("cells/{holder_did}/grant").post(grant_consent_cell))
        .push(Router::with_path("cells/{holder_did}/revoke").post(revoke_consent_cell))
        .push(Router::with_path("request").post(request_consent_cell))
}

pub(crate) async fn project_consent_operation(state: &AppState, operation: &Operation) {
    let kind = crate::kinds::canonical_kind_string(operation);
    let projected = match kind.as_str() {
        "ck.consent.grant" => project_consent_grant_operation(state, operation).await,
        "ck.consent.revoke" => project_consent_revoke_operation(state, operation).await,
        _ => return,
    };
    if let Err(error) = projected {
        tracing::warn!(
            %error,
            operation_id = %operation.operation_id,
            kind = %kind,
            "accepted consent event could not be projected into consent cells"
        );
    }
}

async fn project_consent_grant_operation(
    state: &AppState,
    operation: &Operation,
) -> Result<(), AppError> {
    let holder = consent_holder(operation)?;
    let peer = consent_peer(&operation.payload)?;
    validate_holder_update(&holder, &holder, &peer)?;
    let scope = consent_scope(&operation.payload)?;
    let consent_id = consent_id(&operation.payload)?;
    let expires_at = consent_expires_at(&operation.payload)?;
    let dot = consent_grant_dot(operation, &consent_id);
    let previous = consent_cell_snapshot(state, &holder, &peer, &scope);
    let updated = grant_cell_with_dot(
        state,
        &holder,
        &peer,
        &scope,
        dot,
        Some(consent_cell_id_for_consent_id(&consent_id)),
        expires_at,
        operation.created_at,
    );
    persist_consent_cell(state, &updated, previous).await
}

async fn project_consent_revoke_operation(
    state: &AppState,
    operation: &Operation,
) -> Result<(), AppError> {
    let holder = consent_holder(operation)?;
    let consent_id = consent_id(&operation.payload)?;
    let (peer, scope) = consent_revoke_target(state, &holder, &operation.payload, &consent_id)?;
    validate_holder_update(&holder, &holder, &peer)?;
    let observed_dots = observed_dots(&operation.payload)?;
    let revoked_at = consent_revoked_at(&operation.payload)?.unwrap_or(operation.created_at);
    let mutations =
        revoke_cells_with_observed_dots(state, &holder, &peer, &scope, &observed_dots, revoked_at);
    for mutation in &mutations {
        persist_consent_cell(state, &mutation.updated, mutation.previous.clone()).await?;
    }
    emit_consent_revoke_invalidation(state, &holder, &peer, &scope, revoked_at, &mutations).await;
    Ok(())
}

#[endpoint(
    operation_id = "ck.self.consent.query.list",
    tags("consent"),
    summary = "List consent cells visible to the authenticated holder"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.consent.query.list"))]
async fn list_consent_cells(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ConsentCellList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let now = now();
    let mut cells = state
        .consent_cells
        .lock()
        .values()
        .filter(|cell| cell.holder == session.actor || cell.peer == session.actor)
        .map(|cell| consent_response(cell, now))
        .collect::<Result<Vec<_>, _>>()?;
    cells.sort_by(|a, b| {
        a.holder_did
            .cmp(&b.holder_did)
            .then_with(|| a.peer_did.cmp(&b.peer_did))
            .then_with(|| a.consent_scope.cmp(&b.consent_scope))
    });
    json_ok(ConsentCellList { ok: true, cells })
}

#[endpoint(
    operation_id = "ck.self.consent.resource.get",
    tags("consent"),
    summary = "Read one holder-private consent cell",
    status_codes(200, 400, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.consent.resource.get"))]
async fn get_consent_cell(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    holder_did: PathParam<String>,
) -> JsonResult<ConsentCellView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let holder = holder_did.into_inner();
    if validate_did(&holder).is_err() {
        return Err(AppError::invalid_param("invalid holder DID"));
    }
    let peer =
        query_param(req, "peer").ok_or_else(|| AppError::missing_param("peer is required"))?;
    if validate_did(&peer).is_err() {
        return Err(AppError::invalid_param("invalid peer DID"));
    }
    authorize_reader(&session.actor, &holder, &peer)?;
    // Accept both `consent_scope` (canonical) and the shorter `scope` alias so
    // holder-private reads stay addressable from either query convention.
    let scope_param = query_param(req, "consent_scope").or_else(|| query_param(req, "scope"));
    let scope = normalize_scope(scope_param.as_deref())?;
    let key = ConsentCellKey {
        holder,
        peer,
        scope,
    };
    let cell = state
        .consent_cells
        .lock()
        .get(&key)
        .cloned()
        .ok_or_else(|| AppError::not_found("consent cell not found"))?;
    json_ok(consent_response(&cell, now())?)
}

#[endpoint(
    operation_id = "ck.self.consent.command.grant",
    tags("consent"),
    summary = "Grant scoped consent to a peer DID",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.consent.command.grant"))]
async fn grant_consent_cell(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    holder_did: PathParam<String>,
    body: JsonBody<ConsentUpdateRequestBody>,
) -> JsonResult<ConsentCellView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let holder = holder_did.into_inner();
    let body = body.into_inner();
    validate_holder_update(&session.actor, &holder, body.peer_did.as_str())?;
    let scope = normalize_scope(body.consent_scope.as_deref())?;
    let previous = consent_cell_snapshot(state, &holder, body.peer_did.as_str(), &scope);
    let updated = grant_cell(
        state,
        &holder,
        body.peer_did.as_str(),
        &scope,
        body.expires_at,
        now(),
    );
    persist_consent_cell(state, &updated, previous).await?;
    append_audit_log(
        state,
        Some(&holder),
        "consent.grant",
        json!({
            "holder_did": holder,
            "peer_did": body.peer_did,
            "consent_scope": scope,
            "expires_at": body.expires_at,
        }),
        "accepted",
    )
    .await;
    json_ok(consent_response(&updated, now())?)
}

#[endpoint(
    operation_id = "ck.self.consent.command.revoke",
    tags("consent"),
    summary = "Revoke scoped consent from a peer DID",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.consent.command.revoke"))]
async fn revoke_consent_cell(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    holder_did: PathParam<String>,
    body: JsonBody<ConsentUpdateRequestBody>,
) -> JsonResult<ConsentCellView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let holder = holder_did.into_inner();
    let body = body.into_inner();
    validate_holder_update(&session.actor, &holder, body.peer_did.as_str())?;
    let scope = normalize_scope(body.consent_scope.as_deref())?;
    let revoked_at = now();
    let mutations = revoke_cells(state, &holder, body.peer_did.as_str(), &scope, revoked_at);
    let updated = mutations
        .iter()
        .find(|mutation| mutation.updated.scope == scope)
        .map(|mutation| mutation.updated.clone())
        .unwrap_or_else(|| empty_cell(&holder, body.peer_did.as_str(), &scope, revoked_at));
    for mutation in &mutations {
        persist_consent_cell(state, &mutation.updated, mutation.previous.clone()).await?;
    }
    emit_consent_revoke_invalidation(
        state,
        &holder,
        body.peer_did.as_str(),
        &scope,
        revoked_at,
        &mutations,
    )
    .await;
    append_audit_log(
        state,
        Some(&holder),
        "consent.revoke",
        json!({
            "holder_did": holder,
            "peer_did": body.peer_did,
            "consent_scope": scope,
            "observed_dots": updated.revoked_dots.iter().cloned().collect::<Vec<_>>(),
        }),
        "accepted",
    )
    .await;
    json_ok(consent_response(&updated, now())?)
}

#[endpoint(
    operation_id = "ck.self.consent.command.request",
    tags("consent"),
    summary = "Open a scoped consent request",
    status_codes(200, 201, 400, 401, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.consent.command.request"))]
async fn request_consent_cell(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
    body: JsonBody<ConsentRequestRequestBody>,
) -> JsonResult<ConsentCellView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let peer = match body.peer_did {
        Some(peer) => peer,
        None => Did::new(session.actor.clone())
            .map_err(|e| AppError::invalid_param(format!("peer_did: {e}")))?,
    };
    if peer.as_str() != session.actor {
        return Err(AppError::capability_denied(
            "consent request peer must match authenticated actor",
        ));
    }
    let holder_account = state
        .persistence
        .accounts()
        .get(body.holder_did.as_str())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if holder_account.is_none() {
        return Err(AppError::not_found("holder account not found"));
    }
    let scope = normalize_scope(body.consent_scope.as_deref())?;
    let previous = consent_cell_snapshot(state, body.holder_did.as_str(), peer.as_str(), &scope);
    let cell = record_pending_request(
        state,
        body.holder_did.as_str(),
        peer.as_str(),
        &scope,
        now(),
    );
    persist_consent_cell(state, &cell, previous).await?;
    res.status_code(StatusCode::CREATED);
    json_ok(consent_response(&cell, now())?)
}

pub(super) fn normalize_scope(input: Option<&str>) -> Result<String, AppError> {
    let raw = input.unwrap_or("direct_message").trim();
    if raw.is_empty() {
        return Ok("direct_message".to_owned());
    }
    let normalized = raw.to_ascii_lowercase();
    match normalized.as_str() {
        "invite" => Ok("invite".to_owned()),
        "message" | "direct_message" | "messaging" | "dm" => Ok("direct_message".to_owned()),
        "call" | "voice_call" => Ok("voice_call".to_owned()),
        "video_call" => Ok("video_call".to_owned()),
        "presence" => Ok("presence".to_owned()),
        "any" => Ok("any".to_owned()),
        _ => Err(AppError::invalid_param(
            "scope must be invite, direct_message, voice_call, video_call, presence, or any",
        )),
    }
}

pub(super) fn consent_cell_snapshot(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
) -> Option<ConsentCellRecord> {
    state
        .consent_cells
        .lock()
        .get(&consent_key(holder, peer, scope))
        .cloned()
}

/// Write-through a single mutated consent cell to durable storage.
///
/// Callers update the in-memory working projection before reaching this async
/// boundary. On durable write failure, this helper rolls back the matching
/// in-memory mutation before surfacing the request failure.
pub(super) async fn persist_consent_cell(
    state: &AppState,
    record: &ConsentCellRecord,
    previous: Option<ConsentCellRecord>,
) -> Result<(), AppError> {
    if let Err(error) = state.persistence.consent_cells().put(record).await {
        let restored = restore_consent_cell_after_persist_failure(state, record, previous);
        tracing::error!(
            %error,
            holder = %record.holder,
            peer = %record.peer,
            scope = %record.scope,
            restored,
            "failed to persist consent cell to durable storage"
        );
        return Err(AppError::internal(format!(
            "failed to persist consent cell: {error}"
        )));
    }
    Ok(())
}

fn restore_consent_cell_after_persist_failure(
    state: &AppState,
    record: &ConsentCellRecord,
    previous: Option<ConsentCellRecord>,
) -> bool {
    let key = consent_key(&record.holder, &record.peer, &record.scope);
    let mut cells = state.consent_cells.lock();
    if !cells.get(&key).is_some_and(|current| current == record) {
        return false;
    }
    match previous {
        Some(previous) => {
            cells.insert(key, previous);
        }
        None => {
            cells.remove(&key);
        }
    }
    true
}

pub(super) fn record_pending_request(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
    requested_at: DateTime<Utc>,
) -> ConsentCellRecord {
    record_pending_request_with_cell_id(state, holder, peer, scope, requested_at, None)
}

fn record_pending_request_with_cell_id(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
    requested_at: DateTime<Utc>,
    cell_id: Option<String>,
) -> ConsentCellRecord {
    let key = consent_key(holder, peer, scope);
    let mut cells = state.consent_cells.lock();
    let cell = cells
        .entry(key)
        .or_insert_with(|| empty_cell(holder, peer, scope, requested_at));
    if let Some(cell_id) = cell_id {
        cell.cell_id = cell_id;
    }
    cell.requested_at = Some(requested_at);
    cell.updated_at = requested_at;
    cell.clone()
}

pub(crate) fn has_active_consent_for_scope(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
    at: DateTime<Utc>,
) -> bool {
    let scope = normalize_scope(Some(scope)).unwrap_or_else(|_| scope.to_owned());
    let cells = state.consent_cells.lock();
    let exact_key = consent_key(holder, peer, &scope);
    let any_key = consent_key(holder, peer, "any");
    [exact_key, any_key].iter().any(|key| {
        cells
            .get(key)
            .is_some_and(|cell| effective_state(cell, at) == "granted")
    })
}

pub(crate) async fn materialize_mimi_consent_request(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
) -> Result<(String, ConsentCellRecord), AppError> {
    validate_did(holder).map_err(|_| AppError::invalid_param("invalid holder DID"))?;
    validate_did(peer).map_err(|_| AppError::invalid_param("invalid peer DID"))?;
    let scope = normalize_scope(Some(scope))?;
    let requested_at = now();
    let previous = consent_cell_snapshot(state, holder, peer, &scope);
    let consent_id = ids::generate("consent");
    let cell = record_pending_request_with_cell_id(
        state,
        holder,
        peer,
        &scope,
        requested_at,
        Some(consent_cell_id_for_consent_id(&consent_id)),
    );
    persist_consent_cell(state, &cell, previous).await?;
    Ok((consent_id, cell))
}

pub(crate) async fn materialize_mimi_consent_update(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
    granted: bool,
) -> Result<(ConsentCellRecord, Option<String>), AppError> {
    validate_did(holder).map_err(|_| AppError::invalid_param("invalid holder DID"))?;
    validate_did(peer).map_err(|_| AppError::invalid_param("invalid peer DID"))?;
    let scope = normalize_scope(Some(scope))?;
    let updated_at = now();
    let previous = consent_cell_snapshot(state, holder, peer, &scope);
    let (cell, event_ref) = if granted {
        let (event_ref, cell) =
            grant_contact_managed_consent(state, holder, peer, &scope, updated_at);
        (cell, Some(event_ref))
    } else {
        (revoke_cell(state, holder, peer, &scope, updated_at), None)
    };
    persist_consent_cell(state, &cell, previous).await?;
    Ok((cell, event_ref))
}

pub(crate) async fn materialize_mimi_consent_update_by_id(
    state: &AppState,
    consent_id: &str,
    actor_id: &str,
    granted: bool,
) -> Result<Option<(ConsentCellRecord, Option<String>)>, AppError> {
    validate_did(actor_id).map_err(|_| AppError::invalid_param("invalid actor DID"))?;
    let existing = state
        .consent_cells
        .lock()
        .values()
        .find(|cell| {
            cell.cell_id == consent_id || cell.cell_id == consent_cell_id_for_consent_id(consent_id)
        })
        .cloned();
    let Some(existing) = existing else {
        return Ok(None);
    };
    if existing.holder != actor_id {
        return Err(AppError::capability_denied(
            "MIMI consent update actor must be the holder of the consent cell",
        ));
    }
    materialize_mimi_consent_update(
        state,
        &existing.holder,
        &existing.peer,
        &existing.scope,
        granted,
    )
    .await
    .map(Some)
}

/// Spec `sync/invite-addressing.md` §2 — verify a `consent_grant`
/// introduction evidence. The `consent_grant_ref` (and optional
/// `consent_id`) MUST resolve to an **active** grant dot in `subject`'s
/// (the invitee's) consent cell with `peer == inviter` and
/// `consent_scope ∈ {invite, any}`, unrevoked and unexpired. Returns
/// `true` only when such a dot exists. On any mismatch the caller MUST
/// downgrade the delivery to the low-trust `explicit_address` path.
pub(crate) fn has_active_consent_grant_evidence(
    state: &AppState,
    subject: &str,
    inviter: &str,
    consent_grant_ref: &str,
    consent_id: Option<&str>,
    at: DateTime<Utc>,
) -> bool {
    let grant_ref = consent_grant_ref.trim();
    if grant_ref.is_empty() {
        return false;
    }
    let expected_cell_id = consent_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(consent_cell_id_for_consent_id);
    let cells = state.consent_cells.lock();
    cells.values().any(|cell| {
        if cell.holder != subject || cell.peer != inviter {
            return false;
        }
        if !matches!(cell.scope.as_str(), "invite" | "any") {
            return false;
        }
        if let Some(expected) = &expected_cell_id
            && &cell.cell_id != expected
        {
            return false;
        }
        active_grant_dots(cell, at)
            .iter()
            .any(|dot| grant_dot_matches_ref(dot, grant_ref))
    })
}

/// A consent grant dot is minted as `{event_id}:{actor_seq}`,
/// `{actor}#{actor_seq}` or `{consent_id}#{operation_id}` (see
/// `consent_grant_dot`). The `consent_grant_ref` carried in the
/// introduction evidence is the originating **event id**; match it against
/// the dot's event-id segment as well as the whole dot string.
fn grant_dot_matches_ref(dot: &str, grant_ref: &str) -> bool {
    if dot == grant_ref {
        return true;
    }
    event_ref_for_dot(dot).is_some_and(|event_ref| event_ref == grant_ref)
}

/// Extract the canonical `ck:event:<uuid>` event ref encoded in a grant
/// dot, if any. Only the `{event_id}:{actor_seq}` mint form (and a bare
/// `ck:event:<uuid>` dot) carries a real event id; the `{actor}#{seq}` and
/// `{consent_id}#{op}` forms encode a DID / consent-cell id in their head
/// segment, not an event ref, so they yield `None`.
///
/// `EventId` values are themselves `:`-delimited (`ck:event:<uuid>`), so we
/// strip only the trailing `:<actor_seq>` segment rather than splitting on
/// the first `:`. The result is validated through `EventId::new` so callers
/// can rely on it being a well-formed event ref.
pub(crate) fn event_ref_for_dot(dot: &str) -> Option<&str> {
    if dot.contains('#') {
        // `{actor}#{seq}` / `{consent_id}#{op}` — head is not an event id.
        return None;
    }
    // A bare event-id dot, or the `{event_id}:{actor_seq}` mint form.
    let candidate = match dot.rsplit_once(':') {
        // Trailing segment is the numeric `actor_seq`; the prefix is the id.
        Some((prefix, seq)) if seq.chars().all(|c| c.is_ascii_digit()) && !seq.is_empty() => prefix,
        _ => dot,
    };
    cokret_sdk::EventId::new(candidate).ok().map(|_| candidate)
}

/// Spec invite-addressing.md §2 / contact-operations.schema.json — resolve
/// the event ref of an **active** `invite`/`any` consent grant the `holder`
/// gave the `peer`. Used by the contact-list projection to populate
/// `invite_consent_grant_ref`: the holder hands this ref to `peer` as
/// `consent_grant` introduction evidence so the peer's server can verify it
/// via [`has_active_consent_grant_evidence`] without a locator URL.
///
/// Returns the first active dot (deterministic `BTreeMap` order) whose dot
/// string carries a resolvable `ck:event:<uuid>` event ref; dots minted in
/// the non-event `{actor}#{seq}` / `{consent_id}#{op}` forms are skipped.
pub(crate) fn active_invite_consent_grant_ref(
    state: &AppState,
    holder: &str,
    peer: &str,
    at: DateTime<Utc>,
) -> Option<String> {
    let cells = state.consent_cells.lock();
    for scope in ["invite", "any"] {
        if let Some(cell) = cells.get(&consent_key(holder, peer, scope)) {
            for dot in active_grant_dots(cell, at) {
                if let Some(event_ref) = event_ref_for_dot(&dot) {
                    return Some(event_ref.to_owned());
                }
            }
        }
    }
    None
}

/// Spec `contact-and-direct-conversation.md` §3 — a contact accept (and the
/// requester-side grant a contact request opens) MUST write a real
/// target/requester-controlled `ck.consent.grant` whose **event ref** is
/// referenced from `consent_grant_refs[]` / `requester_consent_refs[]`.
///
/// The minted grant dot therefore uses the event-bearing
/// `{event_id}:{actor_seq}` form (same shape `consent_grant_operation`
/// projection mints), so [`event_ref_for_dot`] resolves a canonical
/// `ck:event:<uuid>` ref and the contact-list projection can populate
/// `invite_consent_grant_ref` with it. The returned `EventId` string is the
/// grant event ref the caller records in the fact's `*_consent_refs[]`.
///
/// Only contact-managed grants are routed through this event-minting helper;
/// the standalone `POST .../consent/cells/{holder}/grant` REST endpoint keeps
/// minting opaque `ck:consent:<uuid>` dots via [`grant_cell`], so its existing
/// behavior (and tests) are untouched.
/// Returns `(event_ref, mutated_cell)`. The caller MUST write `mutated_cell`
/// through to durable storage at its async boundary via [`persist_consent_cell`].
pub(crate) fn grant_contact_managed_consent(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
    granted_at: DateTime<Utc>,
) -> (String, ConsentCellRecord) {
    let scope = normalize_scope(Some(scope)).unwrap_or_else(|_| scope.to_owned());
    let event_id = ids::generate_event_id();
    // actor_seq is a per-actor monotonic counter on the originating event;
    // contact-managed grants are minted server-side without a real event log
    // seq, so we pin seq=0. `event_ref_for_dot` strips the trailing numeric
    // segment and recovers `event_id` regardless of the seq value.
    let dot = format!("{event_id}:0");
    let updated = grant_cell_with_dot(state, holder, peer, &scope, dot, None, None, granted_at);
    (event_id, updated)
}

pub(crate) fn project_contact_managed_consent_ref(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
    grant_event_ref: &str,
    granted_at: DateTime<Utc>,
) -> Result<ConsentCellRecord, AppError> {
    let scope = normalize_scope(Some(scope)).unwrap_or_else(|_| scope.to_owned());
    let event_ref = EventId::new(grant_event_ref.to_owned())
        .map_err(|error| AppError::invalid_param(format!("invalid consent_grant_ref: {error}")))?;
    let dot = format!("{}:0", event_ref.as_str());
    Ok(grant_cell_with_dot(
        state, holder, peer, &scope, dot, None, None, granted_at,
    ))
}

pub(crate) struct ConsentCellMutation {
    pub previous: Option<ConsentCellRecord>,
    pub updated: ConsentCellRecord,
}

/// Spec contact-and-direct-conversation.md §3 — `ck.self.contact.command.tombstone`
/// MUST enumerate and revoke the holder's contact-managed active grant
/// dots toward `peer`. When `scopes` is empty, default to every scope the
/// holder currently grants `peer` (the recommended `revoke_scopes` default).
///
/// Returns `(revoked_dot_refs, complete)`. `complete` is `false` when a
/// cell carried no enumerable active dots yet was non-empty — the caller
/// MUST then report a partial / fail-closed tombstone rather than a full
/// one. Revoking contact-managed dots only; non-contact-managed consent
/// (e.g. standalone org invite grants) is left untouched unless the caller
/// performs a separate full peer revoke.
/// Returns `(revoked_dot_refs, complete, mutated_cells)`. The caller MUST
/// write every cell in `mutated_cells` through to durable storage at its async
/// boundary via [`persist_consent_cell`].
pub(crate) fn revoke_contact_managed_consent(
    state: &AppState,
    holder: &str,
    peer: &str,
    scopes: &[String],
    revoked_at: DateTime<Utc>,
) -> (Vec<String>, bool, Vec<ConsentCellMutation>) {
    // Resolve the target scope set: explicit `revoke_scopes` (normalized)
    // or every scope the holder currently has a cell for toward `peer`.
    let target_scopes: Vec<String> = if scopes.is_empty() {
        let cells = state.consent_cells.lock();
        cells
            .values()
            .filter(|cell| cell.holder == holder && cell.peer == peer)
            .map(|cell| cell.scope.clone())
            .collect()
    } else {
        let mut normalized = Vec::new();
        for scope in scopes {
            if let Ok(scope) = normalize_scope(Some(scope))
                && !normalized.contains(&scope)
            {
                normalized.push(scope);
            }
        }
        normalized
    };

    let mut revoked_refs = Vec::new();
    let mut complete = true;
    let mut mutated = Vec::new();
    for scope in target_scopes {
        let active_before = {
            let cells = state.consent_cells.lock();
            cells
                .get(&consent_key(holder, peer, &scope))
                .map(|cell| active_grant_dots(cell, revoked_at))
                .unwrap_or_default()
        };
        if active_before.is_empty() {
            continue;
        }
        let previous = consent_cell_snapshot(state, holder, peer, &scope);
        let updated = revoke_cell(state, holder, peer, &scope, revoked_at);
        // Confirm every previously-active dot is now revoked; otherwise the
        // enumeration was incomplete and we MUST flag partial.
        for dot in &active_before {
            if updated.revoked_dots.contains(dot) {
                revoked_refs.push(dot.clone());
            } else {
                complete = false;
            }
        }
        mutated.push(ConsentCellMutation { previous, updated });
    }
    (revoked_refs, complete, mutated)
}

pub(super) async fn auto_revoke_requester_side_contact_consent(
    state: &AppState,
    requester: &str,
    target: &str,
    scopes: &[String],
    revoked_at: DateTime<Utc>,
    reason: &str,
    contact_event_ref: Option<&str>,
) -> Result<(Vec<String>, bool), AppError> {
    let requester_exists = state
        .persistence
        .accounts()
        .get(requester)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .is_some();
    if !requester_exists {
        return Ok((Vec::new(), true));
    }

    let normalized_scopes = scopes
        .iter()
        .filter_map(|scope| normalize_scope(Some(scope)).ok())
        .collect::<Vec<_>>();
    let revoke_scopes = if normalized_scopes.is_empty() {
        scopes.to_vec()
    } else {
        normalized_scopes.clone()
    };
    let (revoked_dots, complete, mutated_cells) =
        revoke_contact_managed_consent(state, requester, target, &revoke_scopes, revoked_at);
    for mutation in &mutated_cells {
        persist_consent_cell(state, &mutation.updated, mutation.previous.clone()).await?;
    }
    if !mutated_cells.is_empty() {
        let invalidation_scope = if revoke_scopes.len() == 1 {
            revoke_scopes[0].as_str()
        } else {
            "any"
        };
        emit_consent_revoke_invalidation(
            state,
            requester,
            target,
            invalidation_scope,
            revoked_at,
            &mutated_cells,
        )
        .await;
    }
    if !revoked_dots.is_empty() || !complete {
        append_audit_log(
            state,
            Some(requester),
            "consent.requester_side.auto_revoke",
            json!({
                "requester": requester,
                "target": target,
                "scopes": revoke_scopes,
                "reason": reason,
                "contact_event_ref": contact_event_ref,
                "revoked_dots": revoked_dots.clone(),
                "partial_revoke": !complete,
                "revoked_at": revoked_at,
            }),
            if complete { "accepted" } else { "partial" },
        )
        .await;
    }
    Ok((revoked_dots, complete))
}

fn grant_cell(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
    expires_at: Option<DateTime<Utc>>,
    granted_at: DateTime<Utc>,
) -> ConsentCellRecord {
    grant_cell_with_dot(
        state,
        holder,
        peer,
        scope,
        ids::generate("consent"),
        None,
        expires_at,
        granted_at,
    )
}

#[allow(clippy::too_many_arguments)]
fn grant_cell_with_dot(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
    dot: String,
    cell_id: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    granted_at: DateTime<Utc>,
) -> ConsentCellRecord {
    let key = consent_key(holder, peer, scope);
    let mut cells = state.consent_cells.lock();
    let cell = cells
        .entry(key)
        .or_insert_with(|| empty_cell(holder, peer, scope, granted_at));
    if let Some(cell_id) = cell_id {
        cell.cell_id = cell_id;
    }
    cell.grant_dots.insert(
        dot.clone(),
        ConsentGrantDot {
            dot,
            expires_at,
            granted_at,
        },
    );
    cell.revoked_at = None;
    cell.updated_at = granted_at;
    cell.clone()
}

fn revoke_cells(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
    revoked_at: DateTime<Utc>,
) -> Vec<ConsentCellMutation> {
    revoke_cells_inner(state, holder, peer, scope, None, revoked_at)
}

fn revoke_cells_with_observed_dots(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
    observed_dots: &[String],
    revoked_at: DateTime<Utc>,
) -> Vec<ConsentCellMutation> {
    revoke_cells_inner(state, holder, peer, scope, Some(observed_dots), revoked_at)
}

fn revoke_cells_inner(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
    observed_dots: Option<&[String]>,
    revoked_at: DateTime<Utc>,
) -> Vec<ConsentCellMutation> {
    revoke_target_scopes(scope)
        .into_iter()
        .map(|target_scope| {
            let previous = consent_cell_snapshot(state, holder, peer, &target_scope);
            let dots = if scope == "any" && target_scope != "any" {
                grant_dots_for_cell(state, holder, peer, &target_scope)
            } else {
                observed_dots
                    .map(|dots| dots.to_vec())
                    .unwrap_or_else(|| grant_dots_for_cell(state, holder, peer, &target_scope))
            };
            let mut updated =
                revoke_cell_with_dots(state, holder, peer, &target_scope, &dots, revoked_at);
            if scope == "any" && target_scope != "any" {
                updated = mark_cell_superseded_by_any_revoke(
                    state,
                    holder,
                    peer,
                    &target_scope,
                    revoked_at,
                );
            }
            ConsentCellMutation { previous, updated }
        })
        .collect()
}

fn revoke_target_scopes(scope: &str) -> Vec<String> {
    if scope == "any" {
        std::iter::once("any")
            .chain(CONSENT_ACTION_SCOPE_CASCADE.iter().copied())
            .map(ToOwned::to_owned)
            .collect()
    } else {
        vec![scope.to_owned()]
    }
}

fn grant_dots_for_cell(state: &AppState, holder: &str, peer: &str, scope: &str) -> Vec<String> {
    state
        .consent_cells
        .lock()
        .get(&consent_key(holder, peer, scope))
        .map(|cell| cell.grant_dots.keys().cloned().collect())
        .unwrap_or_default()
}

fn mark_cell_superseded_by_any_revoke(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
    revoked_at: DateTime<Utc>,
) -> ConsentCellRecord {
    let key = consent_key(holder, peer, scope);
    let mut cells = state.consent_cells.lock();
    let cell = cells
        .entry(key)
        .or_insert_with(|| empty_cell(holder, peer, scope, revoked_at));
    cell.revoked_dots
        .insert(SUPERSEDED_BY_ANY_REVOKE.to_owned());
    cell.revoked_at = Some(revoked_at);
    cell.updated_at = revoked_at;
    cell.clone()
}

fn revoke_cell(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
    revoked_at: DateTime<Utc>,
) -> ConsentCellRecord {
    let observed_dots = {
        let key = consent_key(holder, peer, scope);
        state
            .consent_cells
            .lock()
            .get(&key)
            .map(|cell| cell.grant_dots.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default()
    };
    revoke_cell_with_dots(state, holder, peer, scope, &observed_dots, revoked_at)
}

fn revoke_cell_with_dots(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
    observed_dots: &[String],
    revoked_at: DateTime<Utc>,
) -> ConsentCellRecord {
    let key = consent_key(holder, peer, scope);
    let mut cells = state.consent_cells.lock();
    let cell = cells
        .entry(key)
        .or_insert_with(|| empty_cell(holder, peer, scope, revoked_at));
    for dot in observed_dots {
        cell.revoked_dots.insert(dot.clone());
    }
    cell.revoked_at = Some(revoked_at);
    cell.updated_at = revoked_at;
    cell.clone()
}

fn validate_holder_update(session_actor: &str, holder: &str, peer: &str) -> Result<(), AppError> {
    if validate_did(holder).is_err() {
        return Err(AppError::invalid_param("invalid holder DID"));
    }
    if validate_did(peer).is_err() {
        return Err(AppError::invalid_param("invalid peer DID"));
    }
    if session_actor != holder {
        return Err(AppError::capability_denied(
            "only the holder DID may update a consent cell",
        ));
    }
    if peer == holder {
        return Err(AppError::invalid_param(
            "peer DID must differ from holder DID",
        ));
    }
    Ok(())
}

fn authorize_reader(session_actor: &str, holder: &str, peer: &str) -> Result<(), AppError> {
    if session_actor == holder || session_actor == peer {
        Ok(())
    } else {
        Err(AppError::capability_denied(
            "consent cell is visible only to holder or peer",
        ))
    }
}

fn empty_cell(
    holder: &str,
    peer: &str,
    scope: &str,
    updated_at: DateTime<Utc>,
) -> ConsentCellRecord {
    ConsentCellRecord {
        holder: holder.to_owned(),
        peer: peer.to_owned(),
        scope: scope.to_owned(),
        cell_id: consent_cell_id(holder, peer, scope),
        requested_at: None,
        grant_dots: std::collections::BTreeMap::new(),
        revoked_dots: std::collections::BTreeSet::new(),
        revoked_at: None,
        updated_at,
    }
}

fn consent_key(holder: &str, peer: &str, scope: &str) -> ConsentCellKey {
    ConsentCellKey {
        holder: holder.to_owned(),
        peer: peer.to_owned(),
        scope: scope.to_owned(),
    }
}

fn consent_cell_id(holder: &str, peer: &str, scope: &str) -> String {
    let digest = sha256_hex(format!("{holder}\0{peer}\0{scope}").as_bytes());
    format!("ak:cell:ck.component.consent.grant.v1:{}", &digest[..32])
}

fn consent_cell_id_for_consent_id(consent_id: &str) -> String {
    if consent_id.starts_with("ak:cell:") {
        consent_id.to_owned()
    } else {
        format!("ak:cell:ck.component.consent.grant.v1:{consent_id}")
    }
}

fn consent_id(payload: &Value) -> Result<String, AppError> {
    first_payload_string(payload, &["consent_id", "cell_subject", "cell_id"])
        .ok_or_else(|| AppError::missing_param("consent_id is required"))
}

fn consent_holder(operation: &Operation) -> Result<String, AppError> {
    let sender = operation
        .payload
        .get("sender")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::missing_param("event sender is required"))?;
    let holder = first_payload_string(
        &operation.payload,
        &["holder_did", "holder", "consenter", "issuer"],
    )
    .unwrap_or_else(|| sender.to_owned());
    if holder != sender {
        return Err(AppError::capability_denied(
            "consent holder must match event sender",
        ));
    }
    Ok(holder)
}

fn consent_peer(payload: &Value) -> Result<String, AppError> {
    first_payload_string(
        payload,
        &["peer", "peer_did", "grantee_did", "target_did", "target"],
    )
    .or_else(|| {
        payload
            .get("tag")
            .and_then(Value::as_object)
            .and_then(|tag| {
                tag.get("peer")
                    .or_else(|| tag.get("peer_did"))
                    .and_then(Value::as_str)
            })
            .map(ToOwned::to_owned)
    })
    .ok_or_else(|| AppError::missing_param("peer is required"))
}

fn consent_scope(payload: &Value) -> Result<String, AppError> {
    let scope = first_payload_string(payload, &["consent_scope", "scope"]).or_else(|| {
        payload
            .get("tag")
            .and_then(Value::as_object)
            .and_then(|tag| {
                tag.get("scope")
                    .or_else(|| tag.get("consent_scope"))
                    .and_then(Value::as_str)
            })
            .map(ToOwned::to_owned)
    });
    normalize_scope(scope.as_deref())
}

fn consent_revoke_target(
    state: &AppState,
    holder: &str,
    payload: &Value,
    consent_id: &str,
) -> Result<(String, String), AppError> {
    if let (Ok(peer), Ok(scope)) = (consent_peer(payload), consent_scope(payload)) {
        return Ok((peer, scope));
    }
    let cell_id = consent_cell_id_for_consent_id(consent_id);
    state
        .consent_cells
        .lock()
        .values()
        .find(|cell| cell.holder == holder && cell.cell_id == cell_id)
        .map(|cell| (cell.peer.clone(), cell.scope.clone()))
        .ok_or_else(|| {
            AppError::missing_param("revoke requires peer/scope or an existing consent_id cell")
        })
}

fn consent_expires_at(payload: &Value) -> Result<Option<DateTime<Utc>>, AppError> {
    optional_timestamp(payload, &["expires_at"])
}

fn consent_revoked_at(payload: &Value) -> Result<Option<DateTime<Utc>>, AppError> {
    optional_timestamp(payload, &["revoked_at"])
}

fn optional_timestamp(payload: &Value, keys: &[&str]) -> Result<Option<DateTime<Utc>>, AppError> {
    let Some(value) = keys
        .iter()
        .find_map(|key| payload.get(*key).and_then(Value::as_str))
    else {
        return Ok(None);
    };
    DateTime::parse_from_rfc3339(value)
        .map(|value| Some(value.with_timezone(&Utc)))
        .map_err(|_| AppError::invalid_param("timestamp must be RFC3339"))
}

fn first_payload_string(payload: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| payload.get(*key).and_then(Value::as_str))
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn consent_grant_dot(operation: &Operation, consent_id: &str) -> String {
    match (
        operation.payload.get("event_id").and_then(Value::as_str),
        operation.payload.get("actor_seq").and_then(Value::as_u64),
    ) {
        (Some(event_id), Some(actor_seq)) => format!("{event_id}:{actor_seq}"),
        _ => match (
            operation.payload.get("sender").and_then(Value::as_str),
            operation.payload.get("actor_seq").and_then(Value::as_u64),
        ) {
            (Some(actor), Some(actor_seq)) => format!("{actor}#{actor_seq}"),
            _ => format!("{consent_id}#{}", operation.operation_id),
        },
    }
}

fn observed_dots(payload: &Value) -> Result<Vec<String>, AppError> {
    let observed = payload
        .get("observed_dots")
        .and_then(Value::as_array)
        .ok_or_else(|| AppError::missing_param("observed_dots is required"))?;
    let dots = observed
        .iter()
        .filter_map(observed_dot_string)
        .collect::<Vec<_>>();
    if dots.is_empty() {
        return Err(AppError::invalid_param("observed_dots must not be empty"));
    }
    Ok(dots)
}

fn observed_dot_string(value: &Value) -> Option<String> {
    if let Some(dot) = value.as_str() {
        return Some(dot.to_owned());
    }
    let object = value.as_object()?;
    if let (Some(actor), Some(actor_seq)) = (
        object.get("actor_id").and_then(Value::as_str),
        object.get("actor_seq").and_then(Value::as_u64),
    ) {
        return Some(format!("{actor}#{actor_seq}"));
    }
    if let (Some(event_id), Some(actor_seq)) = (
        object.get("event_id").and_then(Value::as_str),
        object.get("actor_seq").and_then(Value::as_u64),
    ) {
        return Some(format!("{event_id}:{actor_seq}"));
    }
    None
}

fn consent_response(
    cell: &ConsentCellRecord,
    at: DateTime<Utc>,
) -> Result<ConsentCellView, AppError> {
    let active_grant_dots = active_grant_dots(cell, at);
    Ok(ConsentCellView {
        ok: true,
        cell_id: cell.cell_id.clone(),
        holder_did: Did::new(cell.holder.clone())
            .map_err(|e| AppError::internal(format!("stored consent holder_did: {e}")))?,
        peer_did: Did::new(cell.peer.clone())
            .map_err(|e| AppError::internal(format!("stored consent peer_did: {e}")))?,
        consent_scope: normalize_scope(Some(&cell.scope))?,
        state: consent_response_state(cell, at),
        expires_at: response_expires_at(cell),
        requested_at: cell.requested_at,
        updated_at: cell.updated_at,
        active_grant_dots,
        grant_dots: cell
            .grant_dots
            .values()
            .map(|grant| grant.dot.clone())
            .collect(),
        revoked_dots: cell.revoked_dots.iter().cloned().collect(),
    })
}

fn consent_response_state(cell: &ConsentCellRecord, at: DateTime<Utc>) -> ConsentState {
    match effective_state(cell, at) {
        "granted" => ConsentState::Active,
        "revoked" => ConsentState::Revoked,
        _ => ConsentState::Pending,
    }
}

fn active_grant_dots(cell: &ConsentCellRecord, at: DateTime<Utc>) -> Vec<String> {
    cell.grant_dots
        .iter()
        .filter(|(dot, grant)| {
            !cell.revoked_dots.contains(*dot)
                && grant.expires_at.is_none_or(|expires_at| expires_at > at)
        })
        .map(|(_, grant)| grant.dot.clone())
        .collect()
}

fn response_expires_at(cell: &ConsentCellRecord) -> Option<DateTime<Utc>> {
    cell.grant_dots
        .values()
        .max_by_key(|grant| grant.granted_at)
        .and_then(|grant| grant.expires_at)
}

fn effective_state(cell: &ConsentCellRecord, at: DateTime<Utc>) -> &'static str {
    let mut has_unrevoked = false;
    let mut has_expired_unrevoked = false;
    for (dot, grant) in &cell.grant_dots {
        if cell.revoked_dots.contains(dot) {
            continue;
        }
        has_unrevoked = true;
        if grant.expires_at.is_some_and(|expires_at| expires_at <= at) {
            has_expired_unrevoked = true;
        } else {
            return "granted";
        }
    }
    if has_unrevoked && has_expired_unrevoked {
        return "expired";
    }
    if let Some(revoked_at) = cell.revoked_at {
        let request_reopened_after_revoke = cell
            .requested_at
            .is_some_and(|requested_at| requested_at > revoked_at);
        if !request_reopened_after_revoke {
            return "revoked";
        }
    }
    "pending"
}

pub(super) async fn emit_consent_revoke_invalidation(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
    revoked_at: DateTime<Utc>,
    mutations: &[ConsentCellMutation],
) {
    let invalidated_action_scopes = revoke_target_scopes(scope);
    let target_peer_service_dids =
        consent_invalidation_peer_service_dids(state, holder, peer).await;
    let invalidated_quarantine_entries =
        match invalidate_quarantined_invites_for_revoke(state, holder, peer, scope, revoked_at)
            .await
        {
            Ok(count) => count,
            Err(error) => {
                tracing::warn!(
                    %error,
                    holder,
                    peer,
                    scope,
                    "failed to invalidate invite quarantine entries for consent revoke"
                );
                0
            }
        };
    let invalidated_channels = ConsentRevokeInvalidationChannel::ALL
        .iter()
        .map(|channel| channel.as_str())
        .collect::<Vec<_>>();
    let mutated_cells = mutations
        .iter()
        .map(|mutation| {
            json!({
                "cell_id": &mutation.updated.cell_id,
                "consent_scope": &mutation.updated.scope,
                "revoked_dots": mutation.updated.revoked_dots.iter().cloned().collect::<Vec<_>>(),
                "revoked_at": mutation.updated.revoked_at.as_ref().map(|value| value.to_rfc3339()),
            })
        })
        .collect::<Vec<_>>();
    let payload = json!({
        "schema": "ck.vector.consent.cache_invalidation.v1",
        "holder_did": holder,
        "peer_did": peer,
        "consent_scope": scope,
        "invalidated_action_scopes": invalidated_action_scopes,
        "invalidated_cache_scopes": CONSENT_SCOPE_CASCADE,
        "invalidated_channels": invalidated_channels,
        "target_peer_service_dids": target_peer_service_dids,
        "local_quarantine_entries_invalidated": invalidated_quarantine_entries,
        "eager_invalidation": true,
        "scope_cascade_marker": if scope == "any" {
            Some(SUPERSEDED_BY_ANY_REVOKE)
        } else {
            None
        },
        "mutated_cells": mutated_cells,
        "revoked_at": revoked_at.to_rfc3339(),
    });
    crate::routing::events::projection::append_projection_event(
        state,
        ProjectionEventRecord {
            event_id: ids::generate_event_id(),
            realm_id: super::recovery::principal_control_realm_for_did(holder),
            event_kind: "ck.vector.consent.cache_invalidation.v1".to_owned(),
            operation_type: "consent_revoke_cache_invalidation".to_owned(),
            operation_id: None,
            sender: Some(holder.to_owned()),
            payload: payload.clone(),
            created_at: revoked_at,
            received_at: now(),
        },
    )
    .await;
    append_audit_log(
        state,
        Some(holder),
        "consent.revoke.cache_invalidation",
        payload,
        "accepted",
    )
    .await;
}

// ────────────────────────────────────────────────────────────────────────
// scope=any cascade.
// ────────────────────────────────────────────────────────────────────────

async fn consent_invalidation_peer_service_dids(
    state: &AppState,
    holder: &str,
    peer: &str,
) -> Vec<String> {
    let mut services = BTreeSet::new();
    for actor in [holder, peer] {
        let records = match state.persistence.contacts().list_for_actor(actor).await {
            Ok(records) => records,
            Err(error) => {
                tracing::warn!(
                    %error,
                    actor,
                    holder,
                    peer,
                    "failed to list contacts for consent invalidation target discovery"
                );
                continue;
            }
        };
        for record in records {
            let same_pair = (record.requester == holder && record.target == peer)
                || (record.requester == peer && record.target == holder);
            if !same_pair {
                continue;
            }
            if let Some(service_did) = record
                .peer_service_did
                .as_deref()
                .filter(|value| *value != state.config.service_did)
            {
                services.insert(service_did.to_owned());
            }
        }
    }
    services.into_iter().collect()
}

async fn invalidate_quarantined_invites_for_revoke(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
    revoked_at: DateTime<Utc>,
) -> Result<usize, AppError> {
    if !matches!(scope, "invite" | "any") {
        return Ok(0);
    }
    let account_data = state.persistence.account_data();
    let Some(existing) = account_data
        .get(holder, ACCOUNT_DATA_TYPE_INVITE_QUARANTINE)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    else {
        return Ok(0);
    };
    let Some(entries) = existing.payload.get("entries").and_then(Value::as_array) else {
        return Ok(0);
    };
    let mut removed = 0usize;
    let retained = entries
        .iter()
        .filter(|entry| {
            let should_remove = quarantine_entry_matches_consent_revoke(entry, peer);
            if should_remove {
                removed += 1;
            }
            !should_remove
        })
        .cloned()
        .collect::<Vec<_>>();
    if removed == 0 {
        return Ok(0);
    }

    let mut object = existing.payload.as_object().cloned().unwrap_or_default();
    object.insert(
        "schema".to_owned(),
        Value::String("ck.account.invite_quarantine.v1".to_owned()),
    );
    object.insert("entries".to_owned(), Value::Array(retained));
    object.insert("updated_at".to_owned(), json!(revoked_at));
    object.insert(
        "last_invalidation".to_owned(),
        json!({
            "reason": "consent_revoke",
            "peer_did": peer,
            "consent_scope": scope,
            "revoked_at": revoked_at,
            "removed_entries": removed,
        }),
    );
    let record = AccountDataRecord {
        actor: holder.to_owned(),
        data_type: ACCOUNT_DATA_TYPE_INVITE_QUARANTINE.to_owned(),
        payload: Value::Object(object),
        updated_at: revoked_at,
    };
    account_data
        .put(&record)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    fanout_actor_private_update(
        state,
        holder,
        INVITE_QUARANTINE_ORIGIN_DEVICE,
        ACCOUNT_DATA_UPDATE_TYPE,
        json!({
            "operation": "put",
            "data_type": ACCOUNT_DATA_TYPE_INVITE_QUARANTINE,
            "content": record.payload.clone(),
            "updated_at": record.updated_at,
        }),
    )
    .await;
    append_audit_log(
        state,
        Some(holder),
        "consent.revoke.invite_quarantine_invalidation",
        json!({
            "holder_did": holder,
            "peer_did": peer,
            "consent_scope": scope,
            "removed_entries": removed,
            "revoked_at": revoked_at,
        }),
        "accepted",
    )
    .await;
    Ok(removed)
}

fn quarantine_entry_matches_consent_revoke(entry: &Value, peer: &str) -> bool {
    let pending = entry
        .get("status")
        .and_then(Value::as_str)
        .is_none_or(|status| status == "pending_review");
    let invite_scope = entry
        .get("consent_scope")
        .and_then(Value::as_str)
        .is_none_or(|scope| scope == "invite");
    let peer_matches = entry
        .get("source_peer_did")
        .or_else(|| entry.get("inviter"))
        .and_then(Value::as_str)
        == Some(peer);
    pending && invite_scope && peer_matches
}

/// Concrete action scopes covered by `consent_scope=any`.
pub const CONSENT_ACTION_SCOPE_CASCADE: &[&str] = &[
    "invite",
    "direct_message",
    "voice_call",
    "video_call",
    "presence",
];

/// Spec T17 — downstream cache scopes that a `scope=any` revoke MUST invalidate.
/// The full list is open-ended in spec; soland tracks the five that gate
/// cross-service routing today.
pub const CONSENT_SCOPE_CASCADE: &[&str] = &[
    "directory_reachability",
    "mimi_consent",
    "push_contact_psi",
    "invite_gate",
    "in_flight_invite",
];

/// Spec T17 — when a consent revoke is issued with `scope=any`, the
/// projection MUST mark every cascaded child scope with this marker so
/// consumers can distinguish "explicitly revoked" from "swept by an
/// any-revoke".
pub const SUPERSEDED_BY_ANY_REVOKE: &str = "superseded_by_any_revoke";

/// Spec T17 — five cache-invalidation channels that an `any`-revoke MUST
/// broadcast to cross-service consumers (teabay / floria / coauth).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsentRevokeInvalidationChannel {
    DirectoryReachability,
    MimiConsent,
    PushContactPsi,
    InviteGate,
    InFlightInvite,
}

impl ConsentRevokeInvalidationChannel {
    pub const ALL: &'static [Self] = &[
        Self::DirectoryReachability,
        Self::MimiConsent,
        Self::PushContactPsi,
        Self::InviteGate,
        Self::InFlightInvite,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::DirectoryReachability => "directory_reachability",
            Self::MimiConsent => "mimi_consent",
            Self::PushContactPsi => "push_contact_psi",
            Self::InviteGate => "invite_gate",
            Self::InFlightInvite => "in_flight_invite",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::str::FromStr;

    use soland_data::Db;

    use super::*;
    use crate::config::{
        AppConfig, IceServersConfig, LiveKitConfig, LogFormat, ObjectStorageConfig,
    };

    #[test]
    fn consent_revoke_cascade_table_stable() {
        // Sanity — 5 channels, 5 cascade scopes.
        assert_eq!(ConsentRevokeInvalidationChannel::ALL.len(), 5);
        assert_eq!(CONSENT_SCOPE_CASCADE.len(), 5);
    }

    fn test_config() -> AppConfig {
        AppConfig {
            public_base_url: "http://test".to_owned(),
            service_did: "did:web:test.local".to_owned(),
            object_storage: ObjectStorageConfig::local(std::env::temp_dir()),
            development_mode: true,
            did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
            jws_replay_window_seconds: 0,
            jws_replay_window_per_family: std::collections::BTreeMap::new(),
            seal_compaction_min_age_seconds: 0,
            compaction_min_witnesses: 0,
            compaction_preserve_genesis: false,
            compaction_prune_only_singleton_successors: false,
            ..AppConfig::test_default()
        }
    }

    /// Spec contact-and-direct-conversation.md §3 / invite-addressing.md §2 —
    /// the contact-managed grant minted by `grant_contact_managed_consent`
    /// MUST carry a resolvable `ck:event:<uuid>` ref so the holder's contact
    /// row surfaces it (`active_invite_consent_grant_ref`) AND the peer's
    /// server accepts it back as `consent_grant` evidence
    /// (`has_active_consent_grant_evidence`). This pins both directions to the
    /// same `{event_id}:{seq}` dot form.
    #[test]
    fn contact_managed_invite_grant_round_trips_as_consent_evidence() {
        let state = AppState::new(test_config(), Db { pool: None });
        let bob = "did:web:cm-bob.example"; // consent-cell holder
        let alice = "did:web:cm-alice.example"; // peer / inviter
        let now = Utc::now();

        // bob grants alice an `invite`-scope contact-managed consent.
        let (grant_ref, _cell) = grant_contact_managed_consent(&state, bob, alice, "invite", now);
        assert!(
            grant_ref.starts_with("ak:event:"),
            "grant ref is a canonical event id: {grant_ref}"
        );

        // The contact-list projection (holder=bob, peer=alice) surfaces it.
        let surfaced = active_invite_consent_grant_ref(&state, bob, alice, now)
            .expect("active invite grant ref is surfaced");
        assert_eq!(surfaced, grant_ref);

        // The dot helpers agree with the new `{event_id}:{seq}` form.
        let dot = format!("{grant_ref}:0");
        assert_eq!(event_ref_for_dot(&dot), Some(grant_ref.as_str()));
        assert!(grant_dot_matches_ref(&dot, &grant_ref));

        // alice's server accepts the ref as `consent_grant` evidence:
        // subject=bob gave inviter=alice an active invite grant.
        assert!(
            has_active_consent_grant_evidence(&state, bob, alice, &grant_ref, None, now),
            "the surfaced ref verifies as active consent_grant evidence"
        );
        // A bogus ref does not verify.
        assert!(!has_active_consent_grant_evidence(
            &state,
            bob,
            alice,
            "ak:event:00000000-0000-7000-8000-000000000000",
            None,
            now
        ));
    }

    /// Durable round-trip: a contact-managed grant written through to the
    /// persistence store must re-hydrate into a fresh `AppState`'s consent-cell
    /// map as an *active* grant (`has_active_consent_for_scope == true`). This
    /// is the M3 boot path — restart re-inflates consent from durable storage.
    #[tokio::test]
    async fn consent_grant_persists_and_rehydrates_as_active() {
        let state = AppState::new(test_config(), Db { pool: None });
        let bob = "did:web:rh-bob.example"; // holder
        let alice = "did:web:rh-alice.example"; // peer
        let now = Utc::now();

        // Grant + write-through, mirroring the routing call sites.
        let previous = consent_cell_snapshot(&state, bob, alice, "message");
        let (_grant_ref, cell) = grant_contact_managed_consent(&state, bob, alice, "message", now);
        persist_consent_cell(&state, &cell, previous).await.unwrap();

        // Persistence holds the cell.
        let snapshot = state
            .persistence
            .consent_cells()
            .snapshot_all()
            .await
            .unwrap();
        assert_eq!(snapshot.len(), 1, "one cell persisted");

        // A fresh AppState that shares the same persistence store re-hydrates
        // the cell from durable storage and sees it as active.
        let fresh = AppState::new_with_persistence(
            test_config(),
            Db { pool: None },
            state.persistence.clone(),
        );
        fresh.hydrate().await.unwrap();
        assert!(
            has_active_consent_for_scope(&fresh, bob, alice, "message", now),
            "re-hydrated consent grant is active after boot"
        );
    }
}
