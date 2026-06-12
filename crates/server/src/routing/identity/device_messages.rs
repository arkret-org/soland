//! To-device message transport.
//!
//! Surfaces:
//! - `POST /_cokret/self/device_messages` — send to-device messages, idempotent on `(actor,
//!   idempotency_key)` so duplicate retries return 200 without re-queueing. The idempotency key is
//!   supplied via the `Idempotency-Key` request header.
//! - `GET /_cokret/self/device_messages` — pull pending to-device messages for the bound
//!   session/device. A `from` cursor is read-only pagination state; it never prunes the queue.
//! - `POST /_cokret/self/device_messages/ack` — consume a bearer ack token and prune the messages
//!   covered by that delivery batch.

use std::collections::{BTreeMap, BTreeSet};

use salvo::oapi::extract::{JsonBody, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{
    SyncCursorError, now, parse_and_validate_sync_cursor, sync_token_for_client_sync,
    validate_device_message_target,
};
use crate::error::{AppError, ErrorCode};
use crate::ids;
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::{AppState, DeviceInventoryRecord, DeviceMessageRecord};
use crate::wire::{
    DeviceMessageEnvelope, DeviceMessagesAckOutcome, DeviceMessagesAckRequestBody,
    DeviceMessagesGetOutcome, DeviceMessagesPutOutcome, DeviceMessagesPutRequestBody,
};

pub(crate) const ACCOUNT_DATA_UPDATE_TYPE: &str = "ck.account_data.update";
pub(crate) const BLOCKLIST_UPDATE_TYPE: &str = "ck.account.blocklist.update";
pub(crate) const READ_MARKER_UPDATE_TYPE: &str = "ck.read_cursor.update";
pub(crate) const NOTIFICATION_READ_MARKER_UPDATE_TYPE: &str = "ck.notification.read_cursor.update";
pub(crate) const TO_DEVICE_PAGE_LIMIT: usize = 1000;

pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(
            Router::with_path("device_messages")
                .post(send_device_messages)
                .get(get_device_messages),
        )
        .push(Router::with_path("device_messages/ack").post(ack_device_messages))
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
        .push(Router::with_path("device_messages/ack").post(ack_device_messages))
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
        .unwrap_or_else(ids::generate_request_id);
    let body = body.into_inner();
    let sender_device = state
        .persistence
        .devices()
        .get(&session.actor, &session.device_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let sender_verified = device_is_active_verified(sender_device.as_ref());
    let mut deliverable_targets = BTreeSet::new();
    let mut unknown_devices = BTreeMap::new();
    for devices in body.messages.values() {
        for target in devices.values() {
            if let Err(message) = validate_device_message_target(target) {
                return Err(AppError::invalid_param(message));
            }
        }
    }
    let devices_store = state.persistence.devices();
    for (recipient, devices) in &body.messages {
        for (device_id, target) in devices {
            let recipient = recipient.to_string();
            let device_id = device_id.to_string();
            let same_principal = recipient == session.actor;
            let verification_bootstrap = target.kind.starts_with("ck.key.verification.");
            let secret_message = target.kind.starts_with("ck.secret.");
            let target_record = devices_store
                .get(&recipient, &device_id)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            let target_active = device_is_active(target_record.as_ref());
            let target_verified = device_is_active_verified(target_record.as_ref());

            if !sender_verified && !(same_principal && target_verified && verification_bootstrap) {
                return Err(AppError::capability_denied(
                    "fresh device sessions may only send verification bootstrap to authorized same-principal devices",
                )
                .with_wire_code("fresh_device_scope_violation"));
            }
            if secret_message && !(sender_verified && target_verified) {
                return Err(AppError::capability_denied(
                    "secret to-device messages require authorized sender and recipient devices",
                )
                .with_wire_code("device_not_authorized"));
            }
            if !target_active
                || (!target_verified
                    && !(sender_verified && same_principal && verification_bootstrap))
            {
                note_unknown_device(&mut unknown_devices, &recipient, &device_id);
                continue;
            }
            deliverable_targets.insert((recipient, device_id));
        }
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
            let recipient_key = recipient.to_string();
            let device_key = device_id.to_string();
            if !deliverable_targets.contains(&(recipient_key.clone(), device_key.clone())) {
                continue;
            }
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
                    recipient: recipient_key.clone(),
                    device_id: device_key.clone(),
                    position,
                    content,
                    created_at,
                })
                .await
            {
                tracing::error!(%error, "failed to append device message");
            }
            delivered_devices.push(device_key);
        }
        if !delivered_devices.is_empty() {
            delivered.insert(recipient.to_string(), json!(delivered_devices));
        }
    }
    json_ok(DeviceMessagesPutOutcome {
        ok: true,
        delivered,
        unknown_devices,
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
    limit: QueryParam<u32, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DeviceMessagesGetOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let cursor = from.into_inner();
    let cursor_position = match cursor {
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
    let page_limit = match limit.into_inner() {
        Some(0) => return Err(AppError::invalid_param("limit must be greater than zero")),
        Some(limit) => (limit as usize).min(TO_DEVICE_PAGE_LIMIT),
        None => TO_DEVICE_PAGE_LIMIT,
    };
    let queued = state
        .persistence
        .device_messages()
        .list_after(&session.actor, &session.device_id, cursor_position)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let has_more = queued.len() > page_limit;
    let page = queued.into_iter().take(page_limit).collect::<Vec<_>>();
    let messages = device_message_envelopes_after(&page);
    let to_device_position = page
        .iter()
        .map(|message| message.position)
        .max()
        .unwrap_or(cursor_position);
    let ack_token = if page.is_empty() {
        None
    } else {
        state
            .persistence
            .device_messages()
            .issue_ack_token(&session.actor, &session.device_id, to_device_position)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
    };
    let next_cursor = if page.is_empty() {
        None
    } else {
        Some(
            sync_token_for_client_sync(
                state,
                Some(&session),
                None,
                BTreeMap::new(),
                to_device_position,
            )
            .await,
        )
    };
    json_ok(DeviceMessagesGetOutcome {
        messages,
        ack_token,
        next_cursor,
        has_more,
        limited: has_more,
        lost: false,
    })
}

#[endpoint(
    operation_id = "ck.self.device_messages.ack",
    tags("device_messages"),
    summary = "Acknowledge a delivered to-device batch by bearer token"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.device_messages.ack"))]
async fn ack_device_messages(
    aa: AuthArgs,
    body: JsonBody<DeviceMessagesAckRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DeviceMessagesAckOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let ack_token = body.ack_token.trim();
    if ack_token.is_empty() {
        return Err(AppError::invalid_param("invalid_ack_token"));
    }
    let Some(pruned_count) = state
        .persistence
        .device_messages()
        .ack_with_token(&session.actor, &session.device_id, ack_token)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    else {
        return Err(AppError::invalid_param("invalid_ack_token"));
    };
    json_ok(DeviceMessagesAckOutcome {
        ok: true,
        pruned_count: Some(pruned_count as u64),
    })
}

pub(crate) fn device_message_envelopes_after(
    messages: &[DeviceMessageRecord],
) -> Vec<DeviceMessageEnvelope> {
    messages
        .iter()
        .filter_map(device_message_envelope_from_record)
        .collect()
}

fn device_is_active(record: Option<&DeviceInventoryRecord>) -> bool {
    record.is_some_and(|record| record.revoked_at.is_none())
}

fn device_is_active_verified(record: Option<&DeviceInventoryRecord>) -> bool {
    record.is_some_and(|record| {
        record.revoked_at.is_none() && record.verification_state == "verified"
    })
}

fn note_unknown_device(
    unknown_devices: &mut BTreeMap<String, Value>,
    recipient: &str,
    device_id: &str,
) {
    let entry = unknown_devices
        .entry(recipient.to_owned())
        .or_insert_with(|| json!([]));
    if let Some(devices) = entry.as_array_mut() {
        devices.push(json!(device_id));
    } else {
        *entry = json!([device_id]);
    }
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
                .and_then(Value::as_str)?
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
