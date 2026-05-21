//! Holder-private consent cell routes.
//!
//! This is the G3.S4 minimal reducer surface for
//! `cx.component.consent.grant.v1`: the in-process projection stores one
//! OR-set-like cell per `(holder_did, peer_did, scope)`, and contact
//! requests consult that projection before opening or accepting a request.

use chrono::{DateTime, Utc};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{AuthArgs, append_audit_log, now, query_param, sha256_hex, validate_did};
use crate::error::AppError;
use crate::ids;
use crate::state::{AppState, ConsentCellKey, ConsentCellRecord, ConsentGrantDot, ContactRecord};
use crate::{JsonResult, json_ok};

pub(super) fn router() -> Router {
    Router::with_path("consent")
        .push(Router::with_path("cells").get(list_consent_cells))
        .push(Router::with_path("cells/{holder_did}").get(get_consent_cell))
        .push(Router::with_path("cells/{holder_did}/grant").post(grant_consent_cell))
        .push(Router::with_path("cells/{holder_did}/revoke").post(revoke_consent_cell))
        .push(Router::with_path("request").post(request_consent_cell))
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ConsentCellResponse {
    pub ok: bool,
    pub cell_id: String,
    pub holder_did: String,
    pub peer_did: String,
    pub scope: String,
    pub state: String,
    pub valid_until: Option<DateTime<Utc>>,
    pub requested_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    pub active_grant_dots: Vec<String>,
    pub grant_dots: Vec<String>,
    pub revoked_dots: Vec<String>,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ConsentCellsResponse {
    pub ok: bool,
    pub cells: Vec<ConsentCellResponse>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct ConsentRequestBody {
    pub holder_did: String,
    #[serde(default)]
    pub peer_did: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct ConsentUpdateBody {
    pub peer_did: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub valid_until: Option<DateTime<Utc>>,
}

#[endpoint(
    operation_id = "cx.consent.cells.list",
    tags("consent"),
    summary = "List consent cells visible to the authenticated holder"
)]
async fn list_consent_cells(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ConsentCellsResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let now = now();
    let mut cells = state
        .consent_cells
        .lock()
        .expect("consent_cells lock")
        .values()
        .filter(|cell| cell.holder == session.actor || cell.peer == session.actor)
        .map(|cell| consent_response(cell, now))
        .collect::<Vec<_>>();
    cells.sort_by(|a, b| {
        a.holder_did
            .cmp(&b.holder_did)
            .then_with(|| a.peer_did.cmp(&b.peer_did))
            .then_with(|| a.scope.cmp(&b.scope))
    });
    json_ok(ConsentCellsResponse { ok: true, cells })
}

#[endpoint(
    operation_id = "cx.consent.cells.get",
    tags("consent"),
    summary = "Read one holder-private consent cell",
    status_codes(200, 400, 401, 403, 404, 500)
)]
async fn get_consent_cell(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    holder_did: PathParam<String>,
) -> JsonResult<ConsentCellResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
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
    let scope = normalize_scope(query_param(req, "scope").as_deref())?;
    let key = ConsentCellKey {
        holder,
        peer,
        scope,
    };
    let cell = state
        .consent_cells
        .lock()
        .expect("consent_cells lock")
        .get(&key)
        .cloned()
        .ok_or_else(|| AppError::not_found("consent cell not found"))?;
    json_ok(consent_response(&cell, now()))
}

#[endpoint(
    operation_id = "cx.consent.cells.grant",
    tags("consent"),
    summary = "Grant scoped consent to a peer DID",
    status_codes(200, 400, 401, 403, 500)
)]
async fn grant_consent_cell(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    holder_did: PathParam<String>,
    body: JsonBody<ConsentUpdateBody>,
) -> JsonResult<ConsentCellResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let holder = holder_did.into_inner();
    let body = body.into_inner();
    validate_holder_update(&session.actor, &holder, &body.peer_did)?;
    let scope = normalize_scope(body.scope.as_deref())?;
    let updated = grant_cell(
        state,
        &holder,
        &body.peer_did,
        &scope,
        body.valid_until,
        now(),
    );
    let contact_status = if effective_state(&updated, now()) == "granted" {
        "accepted"
    } else {
        "pending"
    };
    upsert_contact_status(state, &body.peer_did, &holder, &scope, contact_status)?;
    append_audit_log(
        state,
        Some(&holder),
        "consent.grant",
        json!({
            "holder_did": holder,
            "peer_did": body.peer_did,
            "scope": scope,
            "valid_until": body.valid_until,
        }),
        "accepted",
    );
    json_ok(consent_response(&updated, now()))
}

#[endpoint(
    operation_id = "cx.consent.cells.revoke",
    tags("consent"),
    summary = "Revoke scoped consent from a peer DID",
    status_codes(200, 400, 401, 403, 500)
)]
async fn revoke_consent_cell(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    holder_did: PathParam<String>,
    body: JsonBody<ConsentUpdateBody>,
) -> JsonResult<ConsentCellResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let holder = holder_did.into_inner();
    let body = body.into_inner();
    validate_holder_update(&session.actor, &holder, &body.peer_did)?;
    let scope = normalize_scope(body.scope.as_deref())?;
    let updated = revoke_cell(state, &holder, &body.peer_did, &scope, now());
    upsert_contact_status(state, &body.peer_did, &holder, &scope, "pending")?;
    append_audit_log(
        state,
        Some(&holder),
        "consent.revoke",
        json!({
            "holder_did": holder,
            "peer_did": body.peer_did,
            "scope": scope,
            "observed_dots": updated.revoked_dots.iter().cloned().collect::<Vec<_>>(),
        }),
        "accepted",
    );
    json_ok(consent_response(&updated, now()))
}

#[endpoint(
    operation_id = "cx.consent.request",
    tags("consent"),
    summary = "Open a scoped consent request",
    status_codes(200, 201, 400, 401, 404, 500)
)]
async fn request_consent_cell(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
    body: JsonBody<ConsentRequestBody>,
) -> JsonResult<ConsentCellResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    if validate_did(&body.holder_did).is_err() {
        return Err(AppError::invalid_param("invalid holder DID"));
    }
    let peer = body.peer_did.unwrap_or_else(|| session.actor.clone());
    if peer != session.actor {
        return Err(AppError::capability_denied(
            "consent request peer must match authenticated actor",
        ));
    }
    let holder_account = state
        .persistence
        .accounts()
        .get(&body.holder_did)
        .map_err(|error| AppError::internal(error.to_string()))?;
    if holder_account.is_none() {
        return Err(AppError::not_found("holder account not found"));
    }
    let scope = normalize_scope(body.scope.as_deref())?;
    let cell = record_pending_request(state, &body.holder_did, &peer, &scope, now());
    res.status_code(StatusCode::CREATED);
    json_ok(consent_response(&cell, now()))
}

pub(super) fn normalize_scope(input: Option<&str>) -> Result<String, AppError> {
    let raw = input.unwrap_or("message").trim();
    if raw.is_empty() {
        return Ok("message".to_owned());
    }
    let normalized = raw.to_ascii_lowercase();
    if matches!(normalized.as_str(), "invite" | "message" | "call") {
        Ok(normalized)
    } else {
        Err(AppError::invalid_param(
            "scope must be invite, message, or call",
        ))
    }
}

pub(super) fn record_pending_request(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
    requested_at: DateTime<Utc>,
) -> ConsentCellRecord {
    let key = consent_key(holder, peer, scope);
    let mut cells = state.consent_cells.lock().expect("consent_cells lock");
    let cell = cells
        .entry(key)
        .or_insert_with(|| empty_cell(holder, peer, scope, requested_at));
    cell.requested_at = Some(requested_at);
    cell.updated_at = requested_at;
    cell.clone()
}

pub(super) fn has_active_consent_for_scope(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
    at: DateTime<Utc>,
) -> bool {
    let key = consent_key(holder, peer, scope);
    state
        .consent_cells
        .lock()
        .expect("consent_cells lock")
        .get(&key)
        .is_some_and(|cell| effective_state(cell, at) == "granted")
}

fn grant_cell(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
    valid_until: Option<DateTime<Utc>>,
    granted_at: DateTime<Utc>,
) -> ConsentCellRecord {
    let key = consent_key(holder, peer, scope);
    let mut cells = state.consent_cells.lock().expect("consent_cells lock");
    let cell = cells
        .entry(key)
        .or_insert_with(|| empty_cell(holder, peer, scope, granted_at));
    let dot = ids::generate("consent");
    cell.grant_dots.insert(
        dot.clone(),
        ConsentGrantDot {
            dot,
            valid_until,
            granted_at,
        },
    );
    cell.revoked_at = None;
    cell.updated_at = granted_at;
    cell.clone()
}

fn revoke_cell(
    state: &AppState,
    holder: &str,
    peer: &str,
    scope: &str,
    revoked_at: DateTime<Utc>,
) -> ConsentCellRecord {
    let key = consent_key(holder, peer, scope);
    let mut cells = state.consent_cells.lock().expect("consent_cells lock");
    let cell = cells
        .entry(key)
        .or_insert_with(|| empty_cell(holder, peer, scope, revoked_at));
    for dot in cell.grant_dots.keys() {
        cell.revoked_dots.insert(dot.clone());
    }
    cell.revoked_at = Some(revoked_at);
    cell.updated_at = revoked_at;
    cell.clone()
}

fn upsert_contact_status(
    state: &AppState,
    requester: &str,
    target: &str,
    scope: &str,
    status: &str,
) -> Result<(), AppError> {
    let store = state.persistence.contacts();
    let mut contact = store
        .get_scoped(requester, target, scope)
        .map_err(|error| AppError::internal(error.to_string()))?
        .unwrap_or_else(|| ContactRecord {
            requester: requester.to_owned(),
            target: target.to_owned(),
            scope: scope.to_owned(),
            status: status.to_owned(),
            created_at: now(),
            updated_at: now(),
        });
    contact.status = status.to_owned();
    contact.updated_at = now();
    store
        .put(&contact)
        .map_err(|error| AppError::internal(error.to_string()))
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
    format!("cx:cell:cx.component.consent.grant.v1:{}", &digest[..32])
}

fn consent_response(cell: &ConsentCellRecord, at: DateTime<Utc>) -> ConsentCellResponse {
    let active_grant_dots = active_grant_dots(cell, at);
    ConsentCellResponse {
        ok: true,
        cell_id: cell.cell_id.clone(),
        holder_did: cell.holder.clone(),
        peer_did: cell.peer.clone(),
        scope: cell.scope.clone(),
        state: effective_state(cell, at).to_owned(),
        valid_until: response_valid_until(cell),
        requested_at: cell.requested_at,
        updated_at: cell.updated_at,
        active_grant_dots,
        grant_dots: cell
            .grant_dots
            .values()
            .map(|grant| grant.dot.clone())
            .collect(),
        revoked_dots: cell.revoked_dots.iter().cloned().collect(),
    }
}

fn active_grant_dots(cell: &ConsentCellRecord, at: DateTime<Utc>) -> Vec<String> {
    cell.grant_dots
        .iter()
        .filter(|(dot, grant)| {
            !cell.revoked_dots.contains(*dot)
                && grant.valid_until.is_none_or(|valid_until| valid_until > at)
        })
        .map(|(_, grant)| grant.dot.clone())
        .collect()
}

fn response_valid_until(cell: &ConsentCellRecord) -> Option<DateTime<Utc>> {
    cell.grant_dots
        .values()
        .max_by_key(|grant| grant.granted_at)
        .and_then(|grant| grant.valid_until)
}

fn effective_state(cell: &ConsentCellRecord, at: DateTime<Utc>) -> &'static str {
    let mut has_unrevoked = false;
    let mut has_expired_unrevoked = false;
    for (dot, grant) in &cell.grant_dots {
        if cell.revoked_dots.contains(dot) {
            continue;
        }
        has_unrevoked = true;
        if grant
            .valid_until
            .is_some_and(|valid_until| valid_until <= at)
        {
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
