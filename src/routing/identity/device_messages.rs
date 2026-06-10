//! To-device message transport.
//!
//! Surfaces:
//! - `POST /_cokret/self/device_messages` — send to-device messages, idempotent on `(actor,
//!   idempotency_key)` so duplicate retries return 200 without re-queueing. The idempotency key is
//!   supplied via the `Idempotency-Key` request header.
//! - `GET /_cokret/self/device_messages` — pull pending to-device messages for the bound
//!   session/device. Uses the `ck:cursor:` `to_device_position` from
//!   `parse_and_validate_sync_cursor` so a duplicate sync cannot prematurely ack a delivery (this
//!   is what the README calls out as the cursor-acked eviction guarantee).

use std::collections::BTreeMap;

use salvo::oapi::extract::{JsonBody, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{
    SyncCursorError, now, parse_and_validate_sync_cursor, sync_token_for_client_sync,
    validate_device_message_payload,
};
use crate::error::{AppError, ErrorCode};
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::{AppState, DeviceMessageRecord, SessionRecord};
use crate::wire::{
    DeviceMessageEnvelope, DeviceMessagesGetOutcome, DeviceMessagesPutOutcome,
    DeviceMessagesPutRequestBody, sync_token,
};

pub(crate) const ACCOUNT_DATA_UPDATE_TYPE: &str = "ck.account_data.update";
pub(crate) const BLOCKLIST_UPDATE_TYPE: &str = "ck.account.blocklist.update";
pub(crate) const READ_MARKER_UPDATE_TYPE: &str = "ck.read_cursor.update";
pub(crate) const NOTIFICATION_READ_MARKER_UPDATE_TYPE: &str = "ck.notification.read_cursor.update";

pub(super) fn protocol_router() -> Router {
    Router::new().push(
        Router::with_path("device_messages")
            .post(send_device_messages)
            .get(get_device_messages),
    )
}

pub(super) fn legacy_router() -> Router {
    Router::new()
        .push(
            Router::with_path("device_messages/describe")
                .get(super::describe::device_messages_describe),
        )
        .push(
            Router::with_path("device_messages")
                .post(send_device_messages)
                .get(get_device_messages),
        )
}

#[endpoint(
    operation_id = "ck.self.device_messages.put",
    tags("device_messages"),
    summary = "Send to-device messages (idempotent on Idempotency-Key + sender actor)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.device_messages.put"))]
async fn send_device_messages(
    aa: AuthArgs,
    body: JsonBody<DeviceMessagesPutRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DeviceMessagesPutOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let idempotency_key = req
        .headers()
        .get("Idempotency-Key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned())
        .unwrap_or_else(sync_token);
    let body = body.into_inner();
    for (recipient, devices) in &body.messages {
        for (device_id, content) in devices {
            let content_value = json!({
                "kind": content.kind.clone(),
                "content": content.content.clone(),
                "expires_at": content.expires_at,
            });
            if let Err(message) = validate_device_message_payload(&content_value) {
                return Err(AppError::invalid_param(message));
            }
            let _ = device_id;
        }
        let _ = recipient;
    }
    let device_messages = state.persistence.device_messages();
    let registered = device_messages
        .try_register_txn(format!("{}:{idempotency_key}", session.actor))
        .await
        .unwrap_or(false);
    if !registered {
        return json_ok(DeviceMessagesPutOutcome {
            ok: true,
            delivered: BTreeMap::new(),
            unknown_devices: BTreeMap::new(),
        });
    }
    let mut delivered = BTreeMap::new();
    for (recipient, devices) in body.messages {
        let mut delivered_devices = Vec::new();
        for (device_id, content) in devices {
            let created_at = now();
            let position = state.next_to_device_position();
            let mut content = serde_json::to_value(&content)
                .map_err(|error| AppError::internal(error.to_string()))?;
            if let Some(object) = content.as_object_mut() {
                object.insert("sender_device_id".to_owned(), json!(session.device_id));
            }
            if let Err(error) = device_messages
                .append(DeviceMessageRecord {
                    idempotency_key: idempotency_key.clone(),
                    sender: session.actor.clone(),
                    recipient: recipient.to_string(),
                    device_id: device_id.to_string(),
                    position,
                    content,
                    created_at,
                })
                .await
            {
                tracing::error!(%error, "failed to append device message");
            }
            delivered_devices.push(device_id.to_string());
        }
        delivered.insert(recipient.to_string(), json!(delivered_devices));
    }
    json_ok(DeviceMessagesPutOutcome {
        ok: true,
        delivered,
        unknown_devices: BTreeMap::new(),
    })
}

pub(crate) async fn fanout_actor_private_update(
    state: &AppState,
    actor: &str,
    origin_device_id: &str,
    event_type: &str,
    content: Value,
) -> usize {
    let devices = state
        .persistence
        .devices()
        .list_for_actor(actor)
        .await
        .unwrap_or_default();
    let mut delivered = 0;
    for device in devices {
        if device.revoked_at.is_some() || device.device_id == origin_device_id {
            continue;
        }
        let created_at = now();
        let position = state.next_to_device_position();
        let idempotency_key = format!("{event_type}:{actor}:{origin_device_id}:{position}");
        let envelope = json!({
            "type": event_type,
            "sender_device_id": origin_device_id,
            "content": content.clone(),
            "created_at": created_at,
        });
        match state
            .persistence
            .device_messages()
            .append(DeviceMessageRecord {
                idempotency_key,
                sender: actor.to_owned(),
                recipient: actor.to_owned(),
                device_id: device.device_id,
                position,
                content: envelope,
                created_at,
            })
            .await
        {
            Ok(()) => delivered += 1,
            Err(error) => tracing::error!(%error, actor, "failed to fan out actor-private update"),
        }
    }
    delivered
}

#[endpoint(
    operation_id = "ck.self.device_messages.get",
    tags("device_messages"),
    summary = "Pull pending to-device messages for the bound session/device"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.device_messages.get"))]
async fn get_device_messages(
    aa: AuthArgs,
    from: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DeviceMessagesGetOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let cursor = from.into_inner();
    let ack_position = match cursor {
        Some(cursor) => match parse_and_validate_sync_cursor(
            &cursor,
            state,
            Some(&session),
            None,
            chrono::Utc::now().timestamp_millis(),
        )
        .await
        {
            Ok(cursor) => {
                // Presenting a valid cursor proves the client persisted it;
                // strictly-older handle rows for this stream are superseded.
                // Best-effort.
                if let Some(presented_issued_at_ms) = cursor.issued_at_ms {
                    let _ = state
                        .persistence
                        .sync_cursors()
                        .prune_stream_superseded(
                            &session.actor,
                            &session.device_id,
                            &crate::routing::events::sync::sync_filter_digest(None),
                            presented_issued_at_ms,
                        )
                        .await;
                }
                cursor.to_device_position
            }
            Err(SyncCursorError::Expired) => {
                return Err(AppError::new(
                    ErrorCode::CursorExpired,
                    "cursor has expired",
                ));
            }
            Err(SyncCursorError::Invalid(message)) => {
                return Err(AppError::invalid_param(message));
            }
            Err(SyncCursorError::Mismatch(message)) => {
                return Err(AppError::new(ErrorCode::CursorIntegrityInvalid, message));
            }
            Err(SyncCursorError::Integrity(message)) => {
                return Err(AppError::new(ErrorCode::CursorIntegrityInvalid, message));
            }
            Err(SyncCursorError::Revoked) => {
                return Err(AppError::new(
                    ErrorCode::CursorRevoked,
                    "cursor authority has been revoked",
                ));
            }
        },
        None => 0,
    };
    let _ = state
        .persistence
        .device_messages()
        .ack(&session.actor, &session.device_id, ack_position)
        .await;
    let queued = state
        .persistence
        .device_messages()
        .list_after(&session.actor, &session.device_id, ack_position)
        .await
        .unwrap_or_default();
    let messages = device_message_envelopes_after(&queued);
    let to_device_position = queued
        .iter()
        .map(|message| message.position)
        .max()
        .unwrap_or(ack_position);
    json_ok(DeviceMessagesGetOutcome {
        messages,
        next_cursor: Some(
            sync_token_for_client_sync(
                state,
                Some(&session),
                None,
                BTreeMap::new(),
                to_device_position,
            )
            .await,
        ),
        has_more: false,
        limited: false,
    })
}

pub async fn prune_acked_device_messages(
    state: &AppState,
    session: &SessionRecord,
    ack_position: i64,
) {
    let _ = state
        .persistence
        .device_messages()
        .ack(&session.actor, &session.device_id, ack_position)
        .await;
}

pub fn device_message_events_after(messages: &[DeviceMessageRecord]) -> Vec<Value> {
    messages
        .iter()
        .map(|message| {
            json!({
                "idempotency_key": message.idempotency_key,
                "sender": message.sender,
                "recipient": message.recipient,
                "device_id": message.device_id,
                "position": message.position,
                "content": message.content,
                "created_at": message.created_at,
            })
        })
        .collect()
}

fn device_message_envelopes_after(messages: &[DeviceMessageRecord]) -> Vec<DeviceMessageEnvelope> {
    messages
        .iter()
        .filter_map(device_message_envelope_from_record)
        .collect()
}

fn device_message_envelope_from_record(
    message: &DeviceMessageRecord,
) -> Option<DeviceMessageEnvelope> {
    let kind = message
        .content
        .get("kind")
        .or_else(|| message.content.get("type"))
        .and_then(Value::as_str)?
        .to_owned();
    let content = message
        .content
        .get("content")
        .cloned()
        .unwrap_or(Value::Null);
    let expires_at = message
        .content
        .get("expires_at")
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .unwrap_or_else(|| message.created_at + chrono::Duration::hours(1));
    Some(DeviceMessageEnvelope {
        kind,
        sender_principal_id: cokret_sdk::Did::new(message.sender.clone()).ok()?,
        sender_device_id: cokret_sdk::DeviceId::new(
            message
                .content
                .get("sender_device_id")
                .and_then(Value::as_str)
                .unwrap_or("ck:device:00000000-0000-7000-8000-000000000000")
                .to_owned(),
        )
        .ok()?,
        recipient_principal_id: cokret_sdk::Did::new(message.recipient.clone()).ok()?,
        recipient_device_id: cokret_sdk::DeviceId::new(message.device_id.clone()).ok()?,
        sent_at: message.created_at,
        expires_at,
        content,
        device_proof: message.content.get("device_proof").cloned(),
        unsigned: message.content.get("unsigned").cloned(),
    })
}
