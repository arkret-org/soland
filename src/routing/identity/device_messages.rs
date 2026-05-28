//! To-device message transport.
//!
//! Surfaces:
//! - `POST /api/v1/device_messages` — send to-device messages, idempotent on `(actor,
//!   idempotency_key)` so duplicate retries return 200 without re-queueing. The idempotency key is
//!   supplied via the `Idempotency-Key` request header.
//! - `GET /api/v1/device_messages` — pull pending to-device messages for the bound session/device.
//!   Uses the `cx:cursor:` `to_device_position` from `parse_and_validate_sync_cursor` so a
//!   duplicate sync cannot prematurely ack a delivery (this is what the README calls out as the
//!   cursor-acked eviction guarantee).

use std::collections::BTreeMap;

use salvo::oapi::extract::{JsonBody, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{
    SyncCursorError, now, parse_and_validate_sync_cursor, sync_token_for_client_sync,
    validate_device_message_payload, validate_did,
};
use crate::error::{AppError, ErrorCode};
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::{AppState, DeviceMessageRecord, SessionRecord};
use crate::wire::{
    DeviceMessagesReceiveResBody, DeviceMessagesSendReqBody, DeviceMessagesSendResBody, sync_token,
};

pub(crate) const ACCOUNT_DATA_UPDATE_TYPE: &str = "cx.account_data.update";
pub(crate) const BLOCKLIST_UPDATE_TYPE: &str = "cx.account.blocklist.update";
pub(crate) const READ_MARKER_UPDATE_TYPE: &str = "cx.read_cursor.update";
pub(crate) const NOTIFICATION_READ_MARKER_UPDATE_TYPE: &str = "cx.notification.read_cursor.update";

pub(super) fn router() -> Router {
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
    operation_id = "cx.device_messages.put",
    tags("device_messages"),
    summary = "Send to-device messages (idempotent on Idempotency-Key + sender actor)"
)]
#[tracing::instrument(skip_all, fields(op = "cx.device_messages.put"))]
async fn send_device_messages(
    aa: AuthArgs,
    body: JsonBody<DeviceMessagesSendReqBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DeviceMessagesSendResBody> {
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
        if validate_did(recipient).is_err() {
            return Err(AppError::invalid_param("invalid device message recipient"));
        }
        for (device_id, content) in devices {
            if device_id.trim().is_empty() {
                return Err(AppError::invalid_param("invalid device_id"));
            }
            if let Err(message) = validate_device_message_payload(content) {
                return Err(AppError::invalid_param(message));
            }
        }
    }
    let device_messages = state.persistence.device_messages();
    let registered = device_messages
        .try_register_txn(format!("{}:{idempotency_key}", session.actor))
        .await
        .unwrap_or(false);
    if !registered {
        return json_ok(DeviceMessagesSendResBody {
            ok: true,
            delivered: json!({}),
            unknown_devices: json!({}),
        });
    }
    let mut delivered = serde_json::Map::new();
    for (recipient, devices) in body.messages {
        let mut delivered_devices = Vec::new();
        for (device_id, content) in devices {
            let created_at = now();
            let position = state.next_to_device_position();
            if let Err(error) = device_messages
                .append(DeviceMessageRecord {
                    idempotency_key: idempotency_key.clone(),
                    sender: session.actor.clone(),
                    recipient: recipient.clone(),
                    device_id: device_id.clone(),
                    position,
                    content,
                    created_at,
                })
                .await
            {
                tracing::error!(%error, "failed to append device message");
            }
            delivered_devices.push(device_id);
        }
        delivered.insert(recipient, json!(delivered_devices));
    }
    json_ok(DeviceMessagesSendResBody {
        ok: true,
        delivered: json!(delivered),
        unknown_devices: json!({}),
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
    operation_id = "cx.device_messages.get",
    tags("device_messages"),
    summary = "Pull pending to-device messages for the bound session/device"
)]
#[tracing::instrument(skip_all, fields(op = "cx.device_messages.get"))]
async fn get_device_messages(
    aa: AuthArgs,
    from: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DeviceMessagesReceiveResBody> {
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
        ) {
            Ok(cursor) => cursor.to_device_position,
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
    let events = device_message_events_after(&queued);
    let to_device_position = events
        .iter()
        .filter_map(|event| event.get("position").and_then(|position| position.as_i64()))
        .max()
        .unwrap_or(ack_position);
    json_ok(DeviceMessagesReceiveResBody {
        events,
        next_cursor: Some(sync_token_for_client_sync(
            state,
            Some(&session),
            None,
            BTreeMap::new(),
            to_device_position,
        )),
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
