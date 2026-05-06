//! Audit-log surface.
//!
//! - `GET /api/v1/audit/events` — actor-scoped audit query (cursor-paginated).
//!   Auth-restricted to the authenticated actor (no cross-actor reads).
//! - `append_audit_log` — internal helper used everywhere a side-effect needs
//!   to be recorded (auth, space lifecycle, message send, federation, etc.).
//!
//! Both back onto the in-memory `state.audit_log` lock today; F2 in
//! `_todos.md` covers durable persistence.

use salvo::{http::StatusCode, prelude::*};
use serde_json::{Value, json};

use crate::{ids, state::AppState};

use super::{auth_or_render, now, query_param, render_error};

#[endpoint]
pub async fn audit_events(depot: &mut Depot, req: &mut Request, res: &mut Response) {
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
    let mut events = state
        .audit_log
        .lock()
        .expect("audit log lock")
        .iter()
        .filter(|event| event["actor"].as_str() == Some(actor.as_str()))
        .cloned()
        .collect::<Vec<_>>();
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
    let commit_id = target
        .get("commit_id")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned);
    state.audit_log.lock().expect("audit log lock").push(json!({
        "audit_id": ids::generate("audit"),
        "request_id": ids::generate_request_id(),
        "actor": actor,
        "device_id": device_id,
        "space_id": space_id,
        "operation_id": operation_id,
        "commit_id": commit_id,
        "action": action,
        "target": target,
        "outcome": outcome,
        "created_at": now(),
    }));
}
