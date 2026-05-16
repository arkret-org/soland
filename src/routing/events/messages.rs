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

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::operations::{
    validate_content_blocks, validate_encrypted_payload_envelope, validate_mentions,
};
use super::{
    flow_id_from_space_id, message_id_from_event_id, space_allows_plaintext_service,
    space_has_member, validate_space_id,
};
use crate::error::{AppError, ErrorCode};
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::{AppState, MessageRecord};
use crate::{ids, kinds};

fn encode_send_cursor(
    space_id: &str,
    positions: &std::collections::BTreeMap<String, i64>,
    issued_ms: i64,
) -> String {
    let cursor = json!({
        "schema": "cx.schema.cursor.v1",
        "version": 1,
        "kind": "message_send",
        "space_id": space_id,
        "issued_at_ms": issued_ms,
        "positions": {
            "spaces": positions,
            "to_device": 0,
        }
    });
    let bytes = contrix_sdk::canonical::canonical_json_bytes(&cursor)
        .unwrap_or_else(|_| cursor.to_string().into_bytes());
    format!("cx:cursor:{}", URL_SAFE_NO_PAD.encode(bytes))
}

pub(super) fn router() -> Router {
    Router::with_path("messages/send").post(messages_send)
}

#[endpoint(
    operation_id = "cx.messages.send",
    tags("messages"),
    summary = "Soland-local simplified send-message surface (mirrors into projection_events)"
)]
async fn messages_send(
    aa: AuthArgs,
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    let space_id = body
        .get("space_id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::missing_param("space_id is required"))?;
    if validate_space_id(space_id).is_err() {
        return Err(AppError::invalid_param("invalid space_id"));
    }
    if !space_has_member(state, space_id, &session.actor) {
        return Err(AppError::capability_denied(
            "actor is not a joined member of the space",
        ));
    }
    let encrypted = body.get("encrypted").and_then(Value::as_bool).unwrap_or(false);
    let content = body
        .get("content")
        .ok_or_else(|| AppError::missing_param("content is required"))?;
    if !encrypted && !space_allows_plaintext_service(state, space_id) {
        return Err(AppError::capability_denied(
            "space policy denies plaintext writes from this service",
        ));
    }
    if encrypted {
        if let Err(message) = validate_encrypted_payload_envelope(content) {
            return Err(AppError::new(ErrorCode::SchemaViolation, message));
        }
    } else {
        let has_body = content.get("body").and_then(Value::as_str).is_some();
        let has_blocks = content
            .get("blocks")
            .and_then(Value::as_array)
            .is_some_and(|blocks| !blocks.is_empty());
        if !has_body && !has_blocks {
            return Err(AppError::new(
                ErrorCode::SchemaViolation,
                "plaintext content must include either `body` or a non-empty `blocks[]` array",
            ));
        }
        if let Err(message) = validate_content_blocks(content) {
            return Err(AppError::new(ErrorCode::SchemaViolation, message));
        }
        if let Err(message) = validate_mentions(content) {
            return Err(AppError::invalid_param(message));
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
    state
        .persistence
        .messages()
        .put(&record)
        .map_err(|error| AppError::internal(format!("message store unavailable: {error}")))?;
    let projection_record = crate::state::ProjectionEventRecord {
        event_id: event_id.clone(),
        space_id: space_id.to_owned(),
        event_kind: kinds::CX_MESSAGE_CREATE.to_owned(),
        operation_type: "event".to_owned(),
        operation_id: Some(format!(
            "cx:operation:{}",
            event_id.strip_prefix("cx:event:").unwrap_or(&event_id)
        )),
        sender: Some(session.actor.clone()),
        payload: json!({
            "thread_id": thread_id.clone(),
            "content": content.clone(),
            "encrypted": encrypted,
        }),
        created_at: now,
    };
    if let Err(error) = state.persistence.projection_events().append(projection_record) {
        tracing::error!(%error, "failed to mirror message into projection_events");
    }

    let event_suffix = event_id.strip_prefix("cx:event:").unwrap_or(&event_id);
    let operation_id = format!("cx:operation:{event_suffix}");
    let mut positions = std::collections::BTreeMap::new();
    positions.insert(space_id.to_owned(), now.timestamp_micros());
    let sync_token = encode_send_cursor(space_id, &positions, now.timestamp_millis());

    json_ok(json!({
        "event_id": event_id,
        "operation_id": operation_id,
        "kind": kinds::CX_MESSAGE_CREATE,
        "message_id": message_id_from_event_id(&event_id),
        "flow_id": flow_id,
        "thread_id": thread_id,
        "space_id": space_id,
        "sender": session.actor.clone(),
        "encrypted": encrypted,
        "created_at": now,
        "sync_token": sync_token,
    }))
}
