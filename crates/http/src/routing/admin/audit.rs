//! Audit-log surface.
//!
//! Two disjoint mounts (no double-mounting; SOL-NAME-02):
//!
//! - Operator queries ([`ops_router`], mounted inside the `RequireAdmin` gated `/_soland/admin/*`
//!   branch): `GET audit/events`, `GET audit/erasure-receipts`.
//!
//! `append_audit_log` — internal helper used everywhere a side-effect needs
//! to be recorded (auth, Realm lifecycle, message send, federation, etc.).
//!
//! All persistence access is mediated by `GovernanceService`.

use salvo::oapi::extract::QueryParam;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};
use soland_http::util::query_param;

use super::{now, realm_has_member};
use crate::ids;
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct AuditErasureReceiptsOutcome {
    receipts: Vec<AuditErasureReceiptItem>,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct AuditErasureReceiptItem {
    receipt_id: Option<String>,
    issuer: Option<String>,
    subject_kind: Option<String>,
    subject_ref: Option<String>,
    outcome: String,
    storage_boundary: Option<String>,
    scope_realm_id: Option<String>,
    fanout_status: String,
    recorded_at: String,
    payload: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct AuditEventsOutcome {
    events: Vec<Value>,
    next_cursor: Option<String>,
}

/// Operator audit queries, mounted inside the admin-gated
/// `/_soland/admin/*` branch.
pub(super) fn ops_router() -> Router {
    Router::new()
        // D14 — production typed audit query at the collection root.
        .push(Router::with_path("audit").get(super::queries::admin_query_audit))
        .push(Router::with_path("audit/events").get(audit_events))
        .push(Router::with_path("audit/erasure-receipts").get(audit_erasure_receipts))
}

/// Spec `realm-and-space.md` §2.5.2 — exposes the
/// `ak.audit.erasure_receipt` projection so verifiers / auditors can
/// query the local receipt list, including the canonical `fanout_status`.
/// Advertised via
/// `/_arkret/describe.erasure_receipts_endpoint`.
///
/// The endpoint is authentication-gated; reading the receipt list does
/// not leak any post-erasure payload (the projection holds canonical
/// receipt envelopes — issuer / subject / outcome / scope — which are
/// the auditable surface by design).
#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.audit.erasure_receipts.list",
    tags("soland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.audit.erasure_receipts.list"))]
async fn audit_erasure_receipts(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AuditErasureReceiptsOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    // Authenticate the session so the endpoint isn't usable
    // unauthenticated; we don't restrict cross-actor reads because the
    // receipt list is the auditable surface (see method doc above).
    let _session = aa.authenticated_session(state, req).await?;
    let receipts: Vec<AuditErasureReceiptItem> = {
        let proj = state.projections().snapshot();
        proj.erasure_receipts
            .iter()
            .map(|r| AuditErasureReceiptItem {
                receipt_id: r.receipt_id.clone(),
                issuer: r.issuer.clone(),
                subject_kind: r.subject_kind.clone(),
                subject_ref: r.subject_ref.clone(),
                outcome: r.outcome.clone(),
                storage_boundary: r.storage_boundary.clone(),
                scope_realm_id: r.scope_realm_id.clone(),
                fanout_status: r.fanout_status.clone(),
                recorded_at: arkret_canonical::format_timestamp_canonical(r.recorded_at),
                payload: r.payload.clone(),
            })
            .collect()
    };
    json_ok(AuditErasureReceiptsOutcome { receipts })
}

#[salvo::oapi::endpoint(operation_id = "org.arkret.soland.audit.events", tags("soland_admin"))]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.audit.events"))]
async fn audit_events(
    aa: AuthArgs,
    actor: QueryParam<String, false>,
    limit: QueryParam<usize, false>,
    cursor: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AuditEventsOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id_filter = query_param(req, "realm_id");
    let kind_filter = query_param(req, "kind");
    let limit = limit.into_inner().unwrap_or(100).clamp(1, 500);
    let cursor = query_param(req, "cursor").or_else(|| cursor.into_inner());
    let mut events = if let Some(realm_id) = realm_id_filter.as_deref() {
        if !realm_has_member(state, realm_id, &session.actor).await {
            return Err(AppError::not_found("audit realm not found"));
        }
        state
            .governance()
            .audit_entries()
            .await
            .map_err(|error| {
                tracing::error!(%error, "failed to read audit log");
                AppError::internal("audit store unavailable")
            })?
            .into_iter()
            .filter(|event| audit_event_matches_realm(event, realm_id))
            .collect()
    } else {
        let actor = query_param(req, "actor")
            .or_else(|| actor.into_inner())
            .unwrap_or_else(|| session.actor.clone());
        if actor != session.actor {
            return Err(AppError::capability_denied(
                "audit queries are limited to the authenticated actor",
            ));
        }
        state
            .governance()
            .audit_entries_for_actor(&actor)
            .await
            .map_err(|error| {
                tracing::error!(%error, "failed to read audit log");
                AppError::internal("audit store unavailable")
            })?
    };
    if let Some(kind) = kind_filter.as_deref() {
        events.retain(|event| audit_event_matches_kind(event, kind));
    }
    let start = cursor
        .as_deref()
        .and_then(|cursor| {
            events
                .iter()
                .position(|event| event["audit_id"].as_str() == Some(cursor))
                .map(|index| index + 1)
        })
        .unwrap_or(0);
    if start > 0 {
        events.drain(..start);
    }
    let has_more = events.len() > limit;
    if has_more {
        events.truncate(limit);
    }
    let next_cursor = has_more
        .then(|| {
            events
                .last()
                .and_then(|event| event["audit_id"].as_str())
                .map(ToOwned::to_owned)
        })
        .flatten();
    json_ok(AuditEventsOutcome {
        events,
        next_cursor,
    })
}

fn audit_event_matches_realm(event: &Value, realm_id: &str) -> bool {
    [event.pointer("/payload/realm_id"), event.get("realm_id")]
        .into_iter()
        .flatten()
        .any(|value| value.as_str() == Some(realm_id))
}

fn audit_event_matches_kind(event: &Value, kind: &str) -> bool {
    [
        event.get("action"),
        event.get("kind"),
        event.pointer("/payload/kind"),
        event.pointer("/payload/type"),
    ]
    .into_iter()
    .flatten()
    .any(|value| value.as_str() == Some(kind))
}

pub async fn append_audit_log(
    state: &AppState,
    actor: Option<&str>,
    action: &str,
    payload: Value,
    outcome: &str,
) {
    let device_id = payload
        .get("device_id")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned);
    let realm_id = payload
        .get("realm_id")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned);
    let operation_id = payload
        .get("operation_id")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned);
    let entry = json!({
        "audit_id": ids::generate("audit"),
        "request_id": ids::generate_request_id(),
        "actor": actor,
        "device_id": device_id,
        "realm_id": realm_id,
        "operation_id": operation_id,
        "action": action,
        "payload": payload.clone(),
        "outcome": outcome,
        "created_at": now(),
    });
    if let Err(error) = state
        .governance()
        .append_audit_entry(soland_services::governance::AppendAuditEntryCommand { entry })
        .await
    {
        // Spec: C.3.7 — every audit-append failure MUST surface to
        // operators. We escalate to ERROR (was previously implicit
        // here) and bump the `soland_audit_append_failures_total`
        // metric so on-call can alert on durable-audit drops without
        // tailing the trace stream.
        tracing::error!(%error, action, outcome, "failed to append audit log entry");
        crate::metrics::record_audit_append_failure();
    }
}
