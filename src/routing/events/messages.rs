//! `POST /api/v1/messages/send` — soland-specific simplified send-message
//! surface that records a single `cx.message.create` projection event
//! without the full Event Envelope ceremony.
//!
//! Spec note: the canonical write path is `POST /api/v1/events` (signed
//! Event Envelope). `/messages/send` is a deployment-local convenience
//! that admin tooling, clients, and tests use to push a message without
//! constructing the Envelope themselves. It still goes through the
//! projection layer and is governed by Space membership + plaintext
//! visibility policy.

use chrono::Utc;
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{
    auth_or_render, flow_id_from_space_id, message_id_from_event_id, render_error,
    space_allows_plaintext_service, space_has_member, validate_space_id,
};
use crate::state::{AppState, MessageRecord};
use crate::{ids, kinds};

pub(super) fn router() -> Router {
    Router::with_path("messages/send").post(messages_send)
}

#[endpoint]
async fn messages_send(depot: &mut Depot, req: &mut Request, res: &mut Response) {
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
                "invalid message send request",
            );
            return;
        }
    };
    let Some(space_id) = body.get("space_id").and_then(Value::as_str) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "space_id is required",
        );
        return;
    };
    if validate_space_id(space_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    }
    if !space_has_member(state, space_id, &session.actor) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "actor is not a joined member of the space",
        );
        return;
    }
    let encrypted = body.get("encrypted").and_then(Value::as_bool).unwrap_or(false);
    let Some(content) = body.get("content") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "content is required",
        );
        return;
    };
    if !encrypted && !space_allows_plaintext_service(state, space_id) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "policy_violation",
            "space policy denies plaintext writes from this service",
        );
        return;
    }
    if encrypted {
        let scheme = content.get("scheme").and_then(Value::as_str);
        let ciphertext = content.get("ciphertext").and_then(Value::as_str);
        if scheme.is_none() || ciphertext.map(str::is_empty).unwrap_or(true) {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "encrypted content must carry a non-empty scheme + ciphertext envelope",
            );
            return;
        }
    } else {
        // Plaintext body MUST have either `body` (legacy) or canonical
        // `blocks: []` content blocks; reject obviously-broken submissions
        // before they sneak into the projection.
        let has_body = content.get("body").and_then(Value::as_str).is_some();
        let has_blocks = content
            .get("blocks")
            .and_then(Value::as_array)
            .map(|blocks| {
                !blocks.is_empty()
                    && blocks.iter().all(|block| {
                        block
                            .get("kind")
                            .and_then(Value::as_str)
                            .is_some_and(|kind| matches!(kind, "text" | "code"))
                    })
            })
            .unwrap_or(false);
        if !has_body && !has_blocks {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "plaintext content must include either `body` or a non-empty `blocks[]` array of text/code blocks",
            );
            return;
        }
    }

    let event_id = ids::generate_event_id();
    let flow_id = flow_id_from_space_id(space_id);
    let thread_id = body
        .get("thread_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| flow_id.clone());
    let now = Utc::now();
    let record = MessageRecord {
        event_id: event_id.clone(),
        space_id: space_id.to_owned(),
        sender: session.actor.clone(),
        thread_id: thread_id.clone(),
        content: content.clone(),
        encrypted,
        created_at: now,
    };
    if let Err(error) = state.persistence.messages().put(&record) {
        render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &format!("message store unavailable: {error}"),
        );
        return;
    }

    res.render(Json(json!({
        "event_id": event_id,
        "kind": kinds::CX_MESSAGE_CREATE,
        "message_id": message_id_from_event_id(&event_id),
        "flow_id": flow_id,
        "thread_id": thread_id,
        "space_id": space_id,
        "sender": session.actor.clone(),
        "encrypted": encrypted,
        "created_at": now,
    })));
}
