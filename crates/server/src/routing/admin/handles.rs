//! Operator handle-management admin surface (Wave 3 / T6.2 §2).
//!
//! Endpoints (product-local operator surface, `org.cokret.soland.*` op IDs):
//!
//! - `GET  /_soland/admin/handles` — paginated list of handle rows.
//! - `GET  /_soland/admin/handles/{id}` — single handle row.
//! - `GET  /_soland/admin/handles/{id}/audit` — handle audit trail from the shared audit table.
//! - `POST /_soland/admin/handles/{id}/revoke` — operator-level handle revocation (releases the
//!   durable account binding + records the audit trail).
//! - `POST /_soland/admin/handles/{id}/reassign` — operator-level re-bind of a handle to a new
//!   subject DID.
//!
//! Authoritative data source: the durable `accounts` table. Each account
//! row carries a bare `localpart`; the canonical handle is `@<localpart>`.
//! The handle id surfaced to operators is the account's `localpart` (stable
//! and URL-safe). The local handle-claim evidence cache
//! ([`crate::state::MemberIdentityRegistry`]) enriches rows with
//! issuer / binding-state metadata when present. Wire shapes mirror sodmin's
//! `HandleRecord` / `HandleAuditEvent` / `HandleReassignRequest` DTOs
//! (`sodmin/src/types/handles.rs`).
//!
//! The collection list (`GET /_soland/admin/handles`) is also reachable via
//! the generic `/_soland/admin/{resource}` snapshot — both share
//! [`admin_handle_items`].

use std::collections::BTreeMap;

use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{AuthArgs, append_audit_log, require_admin_principal};
use crate::error::AppError;
use crate::state::{AppState, HandleClaimEvidenceRecord};
use crate::{JsonResult, json_ok};

/// One handle row. Mirrors sodmin's `HandleRecord` DTO.
#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub(super) struct AdminHandleRecord {
    pub id: String,
    pub canonical_uri: String,
    pub aliases: Vec<String>,
    pub issuer_did: Option<String>,
    pub subject_id: Option<String>,
    pub assigned_at: Option<String>,
    pub expires_at: Option<String>,
    pub last_reassignment_at: Option<String>,
    pub status: Option<String>,
}

/// One audit event for a handle. Mirrors sodmin's `HandleAuditEvent` DTO.
#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub(super) struct AdminHandleAuditEvent {
    pub id: String,
    pub action: String,
    pub actor_id: Option<String>,
    pub timestamp: Option<String>,
    pub reason: Option<String>,
    pub previous_subject_id: Option<String>,
    pub new_subject_id: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub(super) struct AdminHandleListOutcome {
    pub data: Vec<AdminHandleRecord>,
    pub total: u64,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub(super) struct AdminHandleAuditListOutcome {
    pub data: Vec<AdminHandleAuditEvent>,
    pub total: u64,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub(super) struct AdminHandleReassignBody {
    pub new_subject_id: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub(super) struct AdminHandleRevokeBody {
    #[serde(default)]
    pub reason: Option<String>,
}

pub(super) fn router() -> Router {
    Router::with_path("handles").get(list_handles).push(
        Router::with_path("{handle_id}")
            .get(get_handle)
            .push(Router::with_path("audit").get(get_handle_audit))
            .push(Router::with_path("revoke").post(revoke_handle))
            .push(Router::with_path("reassign").post(reassign_handle)),
    )
}

/// Build the full handle row set off the durable accounts table, enriched
/// with local handle-claim evidence. Shared with the generic admin
/// collection snapshot (`/_soland/admin/handles`).
pub(super) async fn admin_handle_items(state: &AppState) -> Vec<AdminHandleRecord> {
    // Index handle-claim evidence by subject DID so account rows can pick
    // up issuer / binding-state metadata when a directory-issued claim is
    // cached locally.
    let claims = state.member_identity_registry().snapshot_handle_claims();
    let claims_by_subject: BTreeMap<String, Vec<HandleClaimEvidenceRecord>> = claims;

    let accounts = state
        .persistence
        .accounts()
        .list()
        .await
        .unwrap_or_default();

    accounts
        .into_iter()
        .filter(|account| !account.localpart.is_empty())
        .map(|account| {
            let evidence = claims_by_subject.get(&account.did);
            let primary_claim = evidence.and_then(|records| records.first());
            let status = match primary_claim {
                Some(record) if record.revoked => "revoked".to_owned(),
                Some(record) => record.binding_state.clone(),
                None => "active".to_owned(),
            };
            AdminHandleRecord {
                id: account.localpart.clone(),
                canonical_uri: format!("ck:handle:{}", account.handle()),
                aliases: vec![account.handle()],
                issuer_did: primary_claim
                    .and_then(|record| record.issuer_service_did.clone())
                    .or_else(|| Some(state.config.service_did.clone())),
                subject_id: Some(account.did.clone()),
                assigned_at: Some(account.created_at.to_rfc3339()),
                expires_at: primary_claim
                    .and_then(|record| record.expires_at.map(|ts| ts.to_rfc3339())),
                last_reassignment_at: None,
                status: Some(status),
            }
        })
        .collect()
}

/// Resolve a single handle row by its operator id (the account localpart).
async fn handle_record_by_id(
    state: &AppState,
    handle_id: &str,
) -> Result<AdminHandleRecord, AppError> {
    admin_handle_items(state)
        .await
        .into_iter()
        .find(|record| record.id == handle_id)
        .ok_or_else(|| AppError::not_found("handle not found"))
}

#[endpoint(
    operation_id = "org.cokret.soland.admin.handles.list",
    tags("admin", "handles"),
    summary = "List operator handle rows",
    status_codes(200, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.admin.handles.list"))]
async fn list_handles(
    aa: AuthArgs,
    page: QueryParam<u64, false>,
    per_page: QueryParam<u64, false>,
    search: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminHandleListOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let _ = require_admin_principal(state, session)?;

    let page = page.into_inner().unwrap_or(1).max(1);
    let per_page = per_page.into_inner().unwrap_or(50).clamp(1, 500);
    let search = search.into_inner().unwrap_or_default();
    let needle = search.trim().to_lowercase();

    let mut rows = admin_handle_items(state).await;
    if !needle.is_empty() {
        rows.retain(|row| {
            row.id.to_lowercase().contains(&needle)
                || row.canonical_uri.to_lowercase().contains(&needle)
                || row
                    .subject_id
                    .as_deref()
                    .is_some_and(|did| did.to_lowercase().contains(&needle))
                || row
                    .aliases
                    .iter()
                    .any(|alias| alias.to_lowercase().contains(&needle))
        });
    }
    rows.sort_by(|a, b| a.id.cmp(&b.id));

    let total = rows.len() as u64;
    let start = ((page - 1) * per_page) as usize;
    let window: Vec<AdminHandleRecord> = rows
        .into_iter()
        .skip(start)
        .take(per_page as usize)
        .collect();
    let has_more = (start as u64) + (window.len() as u64) < total;
    let next_cursor = has_more.then(|| (page + 1).to_string());

    json_ok(AdminHandleListOutcome {
        data: window,
        total,
        next_cursor,
    })
}

#[endpoint(
    operation_id = "org.cokret.soland.admin.handles.get",
    tags("admin", "handles"),
    summary = "Read a single operator handle row",
    status_codes(200, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.admin.handles.get"))]
async fn get_handle(
    aa: AuthArgs,
    handle_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminHandleRecord> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let _ = require_admin_principal(state, session)?;
    json_ok(handle_record_by_id(state, &handle_id.into_inner()).await?)
}

#[endpoint(
    operation_id = "org.cokret.soland.admin.handles.audit",
    tags("admin", "handles"),
    summary = "Read the audit trail for a handle",
    status_codes(200, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.admin.handles.audit"))]
async fn get_handle_audit(
    aa: AuthArgs,
    handle_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminHandleAuditListOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let _ = require_admin_principal(state, session)?;
    let handle_id = handle_id.into_inner();
    // Confirm the handle exists so the operator gets a clean 404 rather
    // than an empty list for a non-existent handle.
    let record = handle_record_by_id(state, &handle_id).await?;
    let handle_at = record.aliases.first().cloned().unwrap_or_default();

    let entries = state
        .persistence
        .audit()
        .snapshot_all()
        .await
        .unwrap_or_default();
    let mut data: Vec<AdminHandleAuditEvent> = entries
        .into_iter()
        .filter(|entry| audit_entry_mentions_handle(entry, &handle_id, &handle_at))
        .map(audit_entry_to_handle_event)
        .collect();
    data.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    let total = data.len() as u64;

    json_ok(AdminHandleAuditListOutcome {
        data,
        total,
        next_cursor: None,
    })
}

/// True when an audit entry references the handle by its localpart id or by
/// its `@<localpart>` form. Handle-related actions are matched both on the
/// action verb and on a payload mention so re-keyed actions still surface.
fn audit_entry_mentions_handle(entry: &Value, handle_id: &str, handle_at: &str) -> bool {
    let action = entry.get("action").and_then(Value::as_str).unwrap_or("");
    if !action.contains("handle") {
        return false;
    }
    let serialized = entry.to_string();
    serialized.contains(handle_id) || (!handle_at.is_empty() && serialized.contains(handle_at))
}

fn audit_entry_to_handle_event(entry: Value) -> AdminHandleAuditEvent {
    let payload = entry.get("payload");
    AdminHandleAuditEvent {
        id: entry
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_default(),
        action: entry
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or("handle")
            .to_owned(),
        actor_id: entry
            .get("actor")
            .or_else(|| entry.get("actor_id"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        timestamp: entry
            .get("created_at")
            .or_else(|| entry.get("timestamp"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        reason: payload
            .and_then(|value| value.get("reason"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        previous_subject_id: payload
            .and_then(|value| value.get("previous_subject_id"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        new_subject_id: payload
            .and_then(|value| value.get("new_subject_id"))
            .and_then(Value::as_str)
            .map(str::to_owned),
    }
}

#[endpoint(
    operation_id = "org.cokret.soland.admin.handles.revoke",
    tags("admin", "handles"),
    summary = "Operator-level handle revocation",
    status_codes(200, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.admin.handles.revoke"))]
async fn revoke_handle(
    aa: AuthArgs,
    handle_id: PathParam<String>,
    body: JsonBody<AdminHandleRevokeBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminHandleRecord> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    let handle_id = handle_id.into_inner();
    let reason = body.into_inner().reason;

    let record = handle_record_by_id(state, &handle_id).await?;
    let subject_did = record
        .subject_id
        .clone()
        .ok_or_else(|| AppError::not_found("handle has no bound subject"))?;

    // Operator revocation releases the durable account binding: clear the
    // localpart so the handle is no longer claimed, and record the release
    // in the post-release grace ledger like the self-service path does.
    let accounts = state.persistence.accounts();
    let mut account = accounts
        .get(&subject_did)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("account not found"))?;
    let released = account.localpart.clone();
    account.localpart = String::new();
    accounts
        .put(&account)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    crate::routing::identity::account::record_handle_release(state, &released);

    append_audit_log(
        state,
        Some(&session.actor),
        "admin.handle.revoke",
        json!({
            "handle_id": handle_id,
            "handle": format!("@{released}"),
            "previous_subject_id": subject_did,
            "reason": reason,
        }),
        "accepted",
    )
    .await;

    let mut revoked = record;
    revoked.status = Some("revoked".to_owned());
    json_ok(revoked)
}

#[endpoint(
    operation_id = "org.cokret.soland.admin.handles.reassign",
    tags("admin", "handles"),
    summary = "Operator-level handle re-bind to a new subject DID",
    status_codes(200, 400, 401, 403, 404, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.admin.handles.reassign"))]
async fn reassign_handle(
    aa: AuthArgs,
    handle_id: PathParam<String>,
    body: JsonBody<AdminHandleReassignBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminHandleRecord> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    let handle_id = handle_id.into_inner();
    let body = body.into_inner();
    let new_subject_id = body.new_subject_id.trim().to_owned();
    if new_subject_id.is_empty() {
        return Err(AppError::invalid_param("new_subject_id is required"));
    }

    let record = handle_record_by_id(state, &handle_id).await?;
    let previous_subject_id = record.subject_id.clone();

    let accounts = state.persistence.accounts();
    // The localpart that backs this handle is the operator id itself.
    let localpart = record
        .aliases
        .first()
        .map(|alias| alias.trim_start_matches('@').to_owned())
        .unwrap_or_else(|| handle_id.clone());

    // Target account must exist before we re-bind onto it.
    let mut target = accounts
        .get(&new_subject_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("target subject account not found"))?;

    // Detach the handle from its current holder, if a different account
    // still carries the localpart.
    if let Some(previous) = previous_subject_id.as_deref() {
        if previous != new_subject_id {
            if let Some(mut prior) = accounts
                .get(previous)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
            {
                if prior.localpart == localpart {
                    prior.localpart = String::new();
                    accounts
                        .put(&prior)
                        .await
                        .map_err(|error| AppError::internal(error.to_string()))?;
                }
            }
        }
    }

    target.localpart = localpart.clone();
    accounts
        .put(&target)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;

    let now = super::now();
    append_audit_log(
        state,
        Some(&session.actor),
        "admin.handle.reassign",
        json!({
            "handle_id": handle_id,
            "handle": format!("@{localpart}"),
            "previous_subject_id": previous_subject_id,
            "new_subject_id": new_subject_id,
            "reason": body.reason,
        }),
        "accepted",
    )
    .await;

    let mut reassigned = record;
    reassigned.subject_id = Some(new_subject_id);
    reassigned.last_reassignment_at = Some(now.to_rfc3339());
    reassigned.status = Some("active".to_owned());
    json_ok(reassigned)
}
