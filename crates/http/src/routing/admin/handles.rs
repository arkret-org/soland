//! Operator handle-management admin surface (Wave 3 / T6.2 §2).
//!
//! Endpoints (product-local operator surface, `org.arkret.soland.*` op IDs):
//!
//! - `GET  /_soland/admin/handles` — paginated list of handle rows.
//! - `GET  /_soland/admin/handles/{id}` — single handle row.
//! - `GET  /_soland/admin/handles/{id}/audit` — handle audit trail from the shared audit table.
//! - `POST /_soland/admin/handles/{id}/revoke` — operator-level handle revocation (releases the
//!   durable account binding + records the audit trail).
//! - `POST /_soland/admin/handles/{id}/reassign` — operator-level re-bind of a handle to a new
//!   subject DID.
//!
//! Authoritative data source: the durable `account_localparts` table. Each row
//! carries a bare `localpart`; the canonical handle is `@<localpart>`. The
//! handle id surfaced to operators is the localpart (stable and URL-safe).
//! The local handle-claim evidence cache
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
use serde_json::{Value, json};
use soland_contracts::admin::handles::{
    AdminHandleAuditEvent, AdminHandleAuditListOutcome, AdminHandleListOutcome,
    AdminHandleReassignBody, AdminHandleRecord, AdminHandleRevokeBody,
};
use soland_http::error::AppError;

use super::{AuthArgs, append_audit_log, require_admin_principal};
use crate::state::{AppState, HandleClaimEvidenceRecord};

const DESTRUCTIVE_REASON_MAX_CHARS: usize = 512;
use crate::{JsonResult, json_ok};

fn validate_destructive_reason(reason: &str) -> Result<String, AppError> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(AppError::param_invalid("reason is required"));
    }
    if reason.chars().count() > DESTRUCTIVE_REASON_MAX_CHARS {
        return Err(AppError::param_invalid(
            "reason must not exceed 512 characters",
        ));
    }
    if reason.chars().any(char::is_control) {
        return Err(AppError::param_invalid("reason must be a single line"));
    }

    let lower = reason.to_ascii_lowercase();
    const SENSITIVE_MARKERS: &[&str] = &[
        "-----begin private key",
        "authorization:",
        "bearer ey",
        "password=",
        "secret=",
        "token=",
    ];
    if SENSITIVE_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
    {
        return Err(AppError::param_invalid(
            "reason must not contain credentials or secrets",
        ));
    }
    Ok(reason.to_owned())
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
    let claims = state.handle_claims_snapshot();
    let claims_by_subject: BTreeMap<String, Vec<HandleClaimEvidenceRecord>> = claims;

    let accounts = state.identities().accounts().await.unwrap_or_default();

    let mut rows = Vec::new();
    for account in accounts {
        let localparts = state
            .identities()
            .account_localparts(account.principal_id.as_str())
            .await
            .unwrap_or_default();
        for localpart in localparts {
            let evidence = claims_by_subject.get(account.principal_id.as_str());
            let primary_claim = evidence.and_then(|records| records.first());
            let status = match primary_claim {
                Some(record) if record.revoked => "revoked".to_owned(),
                Some(record) => record.binding_state.clone(),
                None => "active".to_owned(),
            };
            let handle = format!("@{}", localpart.localpart);
            rows.push(AdminHandleRecord {
                id: localpart.localpart.clone(),
                canonical_uri: format!("ak:handle:{handle}"),
                aliases: vec![handle],
                issuer_did: primary_claim
                    .and_then(|record| record.issuer_service_id.clone())
                    .or_else(|| Some(state.service_id().clone())),
                subject_id: Some(account.principal_id.to_string()),
                assigned_at: Some(arkret_canonical::format_timestamp_canonical(
                    localpart.created_at,
                )),
                expires_at: primary_claim.and_then(|record| {
                    record
                        .expires_at
                        .map(arkret_canonical::format_timestamp_canonical)
                }),
                last_reassignment_at: None,
                status: Some(status),
            });
        }
    }
    rows
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

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.admin.handles.list",
    tags("soland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.handles.list"))]
async fn list_handles(
    aa: AuthArgs,
    page: QueryParam<u64, false>,
    per_page: QueryParam<u64, false>,
    search: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminHandleListOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
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

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.admin.handles.get",
    tags("soland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.handles.get"))]
async fn get_handle(
    aa: AuthArgs,
    handle_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminHandleRecord> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let _ = require_admin_principal(state, session)?;
    json_ok(handle_record_by_id(state, &handle_id.into_inner()).await?)
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.admin.handles.audit",
    tags("soland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.handles.audit"))]
async fn get_handle_audit(
    aa: AuthArgs,
    handle_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminHandleAuditListOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let _ = require_admin_principal(state, session)?;
    let handle_id = handle_id.into_inner();
    // Confirm the handle exists so the operator gets a clean 404 rather
    // than an empty list for a non-existent handle.
    let record = handle_record_by_id(state, &handle_id).await?;
    let handle_at = record.aliases.first().cloned().unwrap_or_default();

    let entries = state.governance().audit_entries().await.unwrap_or_default();
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

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.admin.handles.revoke",
    tags("soland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.handles.revoke"))]
async fn revoke_handle(
    aa: AuthArgs,
    handle_id: PathParam<String>,
    body: JsonBody<AdminHandleRevokeBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminHandleRecord> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    let handle_id = handle_id.into_inner();
    let reason = body.into_inner().reason;

    let record = handle_record_by_id(state, &handle_id).await?;
    let subject_did = record
        .subject_id
        .clone()
        .ok_or_else(|| AppError::not_found("handle has no bound subject"))?;

    // Operator revocation releases the durable account-localpart binding and
    // records the release in the post-release grace ledger.
    let released = handle_id.clone();
    state
        .identities()
        .remove_localpart(&subject_did, &released)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    crate::routing::identity::account::record_handle_release(state, &released)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;

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

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.admin.handles.reassign",
    tags("soland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.handles.reassign"))]
async fn reassign_handle(
    aa: AuthArgs,
    handle_id: PathParam<String>,
    body: JsonBody<AdminHandleReassignBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminHandleRecord> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    let handle_id = handle_id.into_inner();
    let body = body.into_inner();
    let new_subject_id = body.new_subject_id.trim().to_owned();
    if new_subject_id.is_empty() {
        return Err(AppError::param_invalid("new_subject_id is required"));
    }
    let reason = validate_destructive_reason(&body.reason)?;

    let record = handle_record_by_id(state, &handle_id).await?;
    let previous_subject_id = record.subject_id.clone();

    // The localpart that backs this handle is the operator id itself.
    let localpart = record
        .aliases
        .first()
        .map(|alias| alias.trim_start_matches('@').to_owned())
        .unwrap_or_else(|| handle_id.clone());

    // Target account must exist before we re-bind onto it.
    let target = state
        .identities()
        .account(&new_subject_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("target subject account not found"))?;

    // Detach the handle from its current holder, if a different account
    // still carries the localpart.
    if let Some(previous) = previous_subject_id.as_deref()
        && previous != new_subject_id
    {
        state
            .identities()
            .remove_localpart(previous, &localpart)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
    }

    state
        .identities()
        .add_localpart(target.principal_id.as_str(), &localpart, true)
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
            "reason": reason,
        }),
        "accepted",
    )
    .await;

    let mut reassigned = record;
    reassigned.subject_id = Some(new_subject_id);
    reassigned.last_reassignment_at = Some(arkret_canonical::format_timestamp_canonical(now));
    reassigned.status = Some("active".to_owned());
    json_ok(reassigned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destructive_reason_policy_rejects_secrets_and_multiline_text() {
        assert!(validate_destructive_reason("SEC-1234 forced reassignment").is_ok());
        assert!(validate_destructive_reason("first\nsecond").is_err());
        assert!(validate_destructive_reason("password=hunter2").is_err());
        assert!(validate_destructive_reason(&"x".repeat(513)).is_err());
    }

    #[test]
    fn destructive_reason_policy_trims_and_blocks_all_credential_markers() {
        assert_eq!(
            validate_destructive_reason("  incident INC-42  ").unwrap(),
            "incident INC-42"
        );
        assert!(validate_destructive_reason("authorization: Bearer abc").is_err());
        assert!(validate_destructive_reason("BEARER eyJhbGciOi").is_err());
        assert!(validate_destructive_reason("secret=rotation-key").is_err());
        assert!(validate_destructive_reason("token=opaque-value").is_err());
        assert!(validate_destructive_reason("-----BEGIN PRIVATE KEY-----").is_err());
        assert!(validate_destructive_reason("\t").is_err());
    }
}
