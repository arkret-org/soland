//! Audit-log surface.
//!
//! - `GET /api/v1/audit/events` — actor-scoped audit query (cursor-paginated). Auth-restricted to
//!   the authenticated actor (no cross-actor reads).
//! - `append_audit_log` — internal helper used everywhere a side-effect needs to be recorded (auth,
//!   space lifecycle, message send, federation, etc.).
//!
//! Both back onto `state.persistence.audit()`.

use salvo::oapi::extract::{JsonBody, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::now;
use crate::error::AppError;
use crate::ids;
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("audit/events").get(audit_events))
        .push(Router::with_path("audit/user-action").post(post_user_action))
}

/// Client-side telemetry sink.
///
/// `POST /api/v1/audit/user-action` accepts a batched user-action audit
/// envelope shape (`actor`, `action`, `outcome`, `note?`, `recorded_at`)
/// — the same shape that sodmin emits internally and that yougen posts
/// via `ContrixApi::post_audit_user_action`.
///
/// The endpoint is authenticated; the posted `actor` MUST match the
/// session actor (no cross-actor writes). The audit entry is appended
/// via `append_audit_log` so it shows up in the same `audit/events`
/// query a sodmin operator already runs.
#[endpoint(
    operation_id = "cx.extension.soland.audit.user_action",
    tags("audit"),
    summary = "Append a client-side user-action audit entry"
)]
async fn post_user_action(
    aa: AuthArgs,
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    let actor = body
        .get("actor")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    if actor.is_empty() {
        return Err(AppError::invalid_param("actor is required"));
    }
    if actor != session.actor {
        return Err(AppError::capability_denied(
            "audit posts are limited to the authenticated actor",
        ));
    }
    let action = body
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    if action.is_empty() {
        return Err(AppError::invalid_param("action is required"));
    }
    let outcome = body.get("outcome").and_then(|v| v.as_str()).unwrap_or("ok");
    let note = body
        .get("note")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);
    let target = json!({
        "kind": "user_action",
        "note": note,
        "recorded_at": body.get("recorded_at").cloned().unwrap_or(Value::Null),
    });
    append_audit_log(state, Some(&actor), &action, target, outcome);
    json_ok(json!({"ok": true}))
}

#[endpoint(
    operation_id = "cx.extension.soland.audit.events",
    tags("audit"),
    summary = "Actor-scoped audit query (cursor-paginated; actor MUST match session)"
)]
async fn audit_events(
    aa: AuthArgs,
    actor: QueryParam<String, false>,
    limit: QueryParam<usize, false>,
    cursor: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let actor = actor.into_inner().unwrap_or_else(|| session.actor.clone());
    if actor != session.actor {
        return Err(AppError::capability_denied(
            "audit queries are limited to the authenticated actor",
        ));
    }
    let limit = limit.into_inner().unwrap_or(100).clamp(1, 500);
    let cursor = cursor.into_inner();
    let mut events = state
        .persistence
        .audit()
        .list_for_actor(&actor)
        .map_err(|error| {
            tracing::error!(%error, "failed to read audit log");
            AppError::internal("audit store unavailable")
        })?;
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
    json_ok(json!({
        "events": events,
        "next_cursor": next_cursor,
    }))
}

pub fn append_audit_log(
    state: &AppState,
    actor: Option<&str>,
    action: &str,
    payload: Value,
    outcome: &str,
) {
    // Audit entry envelope follows the spec convention from
    // `identity/account-lifecycle.md` §8 and `models/flow-and-message.md`
    // §watch_audit_read, which both refer to the action-specific body of an
    // audit event as `payload`. soland historically labelled this column
    // `target`; the JSON output now exposes it as `payload` (the
    // spec-aligned name) while retaining a copy under `target` for in-process
    // consumers that have not yet migrated.
    let device_id = payload
        .get("device_id")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned);
    let space_id = payload
        .get("space_id")
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
        "space_id": space_id,
        "operation_id": operation_id,
        "action": action,
        "payload": payload.clone(),
        // `target` is a legacy alias preserved for in-tree readers; new
        // consumers MUST use `payload`. Remove once internal callers migrate.
        "target": payload,
        "outcome": outcome,
        "created_at": now(),
    });
    if let Err(error) = state.persistence.audit().append(entry) {
        tracing::error!(%error, "failed to append audit log entry");
    }
}
