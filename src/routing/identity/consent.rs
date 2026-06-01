//! Holder-private consent cell routes.
//!
//! This is the G3.S4 minimal reducer surface for
//! `cx.component.consent.grant.v1`: the in-process projection stores one
//! OR-set-like cell per `(holder_did, peer_did, scope)`, and contact
//! requests consult that projection before opening or accepting a request.

use chrono::{DateTime, Utc};
use contrix_sdk::Operation;
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

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
    pub expires_at: Option<DateTime<Utc>>,
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
    pub expires_at: Option<DateTime<Utc>>,
}

pub(crate) async fn project_consent_operation(state: &AppState, operation: &Operation) {
    let kind = crate::kinds::canonical_kind_string(operation);
    let projected = match kind.as_str() {
        "cx.consent.grant" => project_consent_grant_operation(state, operation).await,
        "cx.consent.revoke" => project_consent_revoke_operation(state, operation).await,
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
    let contact_status = if effective_state(&updated, operation.created_at) == "granted" {
        "accepted"
    } else {
        "pending"
    };
    upsert_contact_status_at(
        state,
        &peer,
        &holder,
        &scope,
        contact_status,
        operation.created_at,
    )
    .await
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
    revoke_cell_with_dots(state, &holder, &peer, &scope, &observed_dots, revoked_at);
    upsert_contact_status_at(state, &peer, &holder, &scope, "pending", revoked_at).await
}

#[endpoint(
    operation_id = "cx.consent.cells.list",
    tags("consent"),
    summary = "List consent cells visible to the authenticated holder"
)]
#[tracing::instrument(skip_all, fields(op = "cx.consent.cells.list"))]
async fn list_consent_cells(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ConsentCellsResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
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
#[tracing::instrument(skip_all, fields(op = "cx.consent.cells.get"))]
async fn get_consent_cell(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    holder_did: PathParam<String>,
) -> JsonResult<ConsentCellResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
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
#[tracing::instrument(skip_all, fields(op = "cx.consent.cells.grant"))]
async fn grant_consent_cell(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    holder_did: PathParam<String>,
    body: JsonBody<ConsentUpdateBody>,
) -> JsonResult<ConsentCellResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let holder = holder_did.into_inner();
    let body = body.into_inner();
    validate_holder_update(&session.actor, &holder, &body.peer_did)?;
    let scope = normalize_scope(body.scope.as_deref())?;
    let updated = grant_cell(
        state,
        &holder,
        &body.peer_did,
        &scope,
        body.expires_at,
        now(),
    );
    let contact_status = if effective_state(&updated, now()) == "granted" {
        "accepted"
    } else {
        "pending"
    };
    upsert_contact_status(state, &body.peer_did, &holder, &scope, contact_status).await?;
    append_audit_log(
        state,
        Some(&holder),
        "consent.grant",
        json!({
            "holder_did": holder,
            "peer_did": body.peer_did,
            "scope": scope,
            "expires_at": body.expires_at,
        }),
        "accepted",
    )
    .await;
    json_ok(consent_response(&updated, now()))
}

#[endpoint(
    operation_id = "cx.consent.cells.revoke",
    tags("consent"),
    summary = "Revoke scoped consent from a peer DID",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.consent.cells.revoke"))]
async fn revoke_consent_cell(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    holder_did: PathParam<String>,
    body: JsonBody<ConsentUpdateBody>,
) -> JsonResult<ConsentCellResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let holder = holder_did.into_inner();
    let body = body.into_inner();
    validate_holder_update(&session.actor, &holder, &body.peer_did)?;
    let scope = normalize_scope(body.scope.as_deref())?;
    let updated = revoke_cell(state, &holder, &body.peer_did, &scope, now());
    upsert_contact_status(state, &body.peer_did, &holder, &scope, "pending").await?;
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
    )
    .await;
    json_ok(consent_response(&updated, now()))
}

#[endpoint(
    operation_id = "cx.consent.request",
    tags("consent"),
    summary = "Open a scoped consent request",
    status_codes(200, 201, 400, 401, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.consent.request"))]
async fn request_consent_cell(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
    body: JsonBody<ConsentRequestBody>,
) -> JsonResult<ConsentCellResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
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
        .await
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
    match normalized.as_str() {
        "invite" => Ok("invite".to_owned()),
        "message" | "direct_message" | "messaging" | "dm" => Ok("message".to_owned()),
        "call" | "voice_call" | "video_call" => Ok("call".to_owned()),
        "presence" => Ok("presence".to_owned()),
        "any" => Ok("any".to_owned()),
        _ => Err(AppError::invalid_param(
            "scope must be invite, message, call, presence, or any",
        )),
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
    let cells = state.consent_cells.lock().expect("consent_cells lock");
    let exact_key = consent_key(holder, peer, scope);
    let any_key = consent_key(holder, peer, "any");
    [exact_key, any_key].iter().any(|key| {
        cells
            .get(key)
            .is_some_and(|cell| effective_state(cell, at) == "granted")
    })
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
    let mut cells = state.consent_cells.lock().expect("consent_cells lock");
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
            .expect("consent_cells lock")
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
    let mut cells = state.consent_cells.lock().expect("consent_cells lock");
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

async fn upsert_contact_status(
    state: &AppState,
    requester: &str,
    target: &str,
    scope: &str,
    status: &str,
) -> Result<(), AppError> {
    upsert_contact_status_at(state, requester, target, scope, status, now()).await
}

async fn upsert_contact_status_at(
    state: &AppState,
    requester: &str,
    target: &str,
    scope: &str,
    status: &str,
    updated_at: DateTime<Utc>,
) -> Result<(), AppError> {
    let store = state.persistence.contacts();
    let mut contact = store
        .get_scoped(requester, target, scope)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .unwrap_or_else(|| ContactRecord {
            requester: requester.to_owned(),
            target: target.to_owned(),
            scope: scope.to_owned(),
            status: status.to_owned(),
            created_at: updated_at,
            updated_at,
        });
    contact.status = status.to_owned();
    contact.updated_at = updated_at;
    store
        .put(&contact)
        .await
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

fn consent_cell_id_for_consent_id(consent_id: &str) -> String {
    if consent_id.starts_with("cx:cell:") {
        consent_id.to_owned()
    } else {
        format!("cx:cell:cx.component.consent.grant.v1:{consent_id}")
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
        .expect("consent_cells lock")
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

fn consent_response(cell: &ConsentCellRecord, at: DateTime<Utc>) -> ConsentCellResponse {
    let active_grant_dots = active_grant_dots(cell, at);
    ConsentCellResponse {
        ok: true,
        cell_id: cell.cell_id.clone(),
        holder_did: cell.holder.clone(),
        peer_did: cell.peer.clone(),
        scope: cell.scope.clone(),
        state: effective_state(cell, at).to_owned(),
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
