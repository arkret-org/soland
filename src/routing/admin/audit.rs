//! Audit-log surface.
//!
//! - `GET /api/v1/audit/events` — actor-scoped audit query (cursor-paginated). Auth-restricted to
//!   the authenticated actor (no cross-actor reads).
//! - `append_audit_log` — internal helper used everywhere a side-effect needs to be recorded (auth,
//!   space lifecycle, message send, federation, etc.).
//!
//! Both back onto `state.persistence.audit()` (see Tier 0 in `_todos.md`).

use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{auth_or_render, now, query_param, render_error};
use crate::ids;
use crate::state::AppState;

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("audit/events").get(audit_events))
        .push(Router::with_path("audit/user-action").post(post_user_action))
}

/// Sprint Q1 第十四增量 (P1): client-side telemetry sink.
///
/// `POST /api/v1/audit/user-action` accepts a batched user-action audit
/// envelope shape (`actor`, `action`, `outcome`, `note?`, `recorded_at`)
/// — the same shape that sodmin emits internally and that yougen
/// already speculatively posts via `ContrixApi::post_audit_user_action`.
/// Until this route landed yougen treated the 404 as
/// `AuditPostError::NotWired` and locally re-buffered every entry;
/// shipping the route turns the buffered pipeline into a real telemetry
/// channel.
///
/// The endpoint is authenticated; the posted `actor` MUST match the
/// session actor (no cross-actor writes). The audit entry is appended
/// via `append_audit_log` so it shows up in the same `audit/events`
/// query a sodmin operator already runs.
#[endpoint]
async fn post_user_action(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<Value>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid user-action audit body",
            );
            return;
        }
    };
    let actor = body
        .get("actor")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    if actor.is_empty() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "actor is required",
        );
        return;
    }
    if actor != session.actor {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "audit posts are limited to the authenticated actor",
        );
        return;
    }
    let action = body
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    if action.is_empty() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "action is required",
        );
        return;
    }
    let outcome = body
        .get("outcome")
        .and_then(|v| v.as_str())
        .unwrap_or("ok");
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
    res.render(Json(json!({"ok": true})));
}

#[endpoint]
async fn audit_events(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let actor = query_param(req, "actor").unwrap_or_else(|| session.actor.clone());
    if actor != session.actor {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "audit queries are limited to the authenticated actor",
        );
        return;
    }
    let limit = query_param(req, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100)
        .clamp(1, 500);
    let cursor = query_param(req, "cursor");
    let mut events = match state.persistence.audit().list_for_actor(&actor) {
        Ok(events) => events,
        Err(error) => {
            tracing::error!(%error, "failed to read audit log");
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "audit store unavailable",
            );
            return;
        }
    };
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
    res.render(Json(json!({
        "events": events,
        "next_cursor": next_cursor,
    })));
}

pub fn append_audit_log(
    state: &AppState,
    actor: Option<&str>,
    action: &str,
    target: Value,
    outcome: &str,
) {
    let device_id = target
        .get("device_id")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned);
    let space_id = target
        .get("space_id")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned);
    let operation_id = target
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
        "target": target,
        "outcome": outcome,
        "created_at": now(),
    });
    if let Err(error) = state.persistence.audit().append(entry) {
        tracing::error!(%error, "failed to append audit log entry");
    }
}
