//! To-device message transport.
//!
//! Surfaces:
//! - `PUT /api/v1/device_messages/{txn_id}` — send to-device messages,
//!   idempotent on `(actor, txn_id)` so duplicate retries return 200 without
//!   re-queueing
//! - `GET /api/v1/device_messages` — pull pending to-device messages for the
//!   bound session/device. Uses the `cx:cursor:` `to_device_position` from
//!   `parse_and_validate_sync_cursor` so a duplicate sync cannot prematurely
//!   ack a delivery (this is what the README calls out as the cursor-acked
//!   eviction guarantee).

use std::collections::{BTreeMap, VecDeque};

use salvo::{http::StatusCode, prelude::*};
use serde_json::{Value, json};

use crate::{
    state::{AppState, DeviceMessageRecord, SessionRecord},
    wire::{
        DeviceMessagesReceiveResponse, DeviceMessagesSendRequest, DeviceMessagesSendResponse,
        sync_token,
    },
};

use super::{
    SyncCursorError, auth_or_render, now, parse_and_validate_sync_cursor, query_param,
    render_error, sync_token_for_client_sync, validate_device_id, validate_device_message_payload,
    validate_did,
};

#[endpoint]
pub async fn put_device_messages(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let txn_id = req.param::<String>("txn_id").unwrap_or_else(sync_token);
    let body = match req.parse_json::<DeviceMessagesSendRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid device messages request",
            );
            return;
        }
    };
    for (recipient, devices) in &body.messages {
        if validate_did(recipient).is_err() {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "invalid device message recipient",
            );
            return;
        }
        for (device_id, content) in devices {
            if validate_device_id(device_id).is_err() {
                render_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "invalid device_id",
                );
                return;
            }
            if let Err(message) = validate_device_message_payload(content) {
                render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
                return;
            }
        }
    }
    {
        let mut txns = state
            .device_message_txns
            .lock()
            .expect("device message txn lock");
        if !txns.insert(format!("{}:{txn_id}", session.actor)) {
            res.render(Json(DeviceMessagesSendResponse {
                ok: true,
                delivered: json!({}),
                unknown_devices: json!({}),
            }));
            return;
        }
    }
    let mut delivered = serde_json::Map::new();
    let mut queue = state.device_messages.lock().expect("device message lock");
    for (recipient, devices) in body.messages {
        let mut delivered_devices = Vec::new();
        for (device_id, content) in devices {
            let created_at = now();
            queue.push_back(DeviceMessageRecord {
                txn_id: txn_id.clone(),
                sender: session.actor.clone(),
                recipient: recipient.clone(),
                device_id: device_id.clone(),
                position: created_at.timestamp_micros(),
                content,
                created_at,
            });
            delivered_devices.push(device_id);
        }
        delivered.insert(recipient, json!(delivered_devices));
    }
    res.render(Json(DeviceMessagesSendResponse {
        ok: true,
        delivered: json!(delivered),
        unknown_devices: json!({}),
    }));
}

#[endpoint]
pub async fn get_device_messages(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let ack_position = match query_param(req, "ack").or_else(|| query_param(req, "since")) {
        Some(cursor) => match parse_and_validate_sync_cursor(
            &cursor,
            state,
            Some(&session),
            None,
            None,
            None,
            &[],
            chrono::Utc::now().timestamp_millis(),
        ) {
            Ok(cursor) => cursor.to_device_position,
            Err(SyncCursorError::Expired) => {
                render_error(
                    res,
                    StatusCode::UNAUTHORIZED,
                    "sync_token_expired",
                    "sync token has expired",
                );
                return;
            }
            Err(SyncCursorError::Invalid(message)) => {
                render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
                return;
            }
            Err(SyncCursorError::Mismatch(message)) => {
                render_error(res, StatusCode::BAD_REQUEST, "sync_token_mismatch", message);
                return;
            }
        },
        None => 0,
    };
    let mut queue = state.device_messages.lock().expect("device message lock");
    prune_acked_device_messages(&mut queue, &session, ack_position);
    let events = device_message_events_after(&queue, &session, ack_position);
    let to_device_position = events
        .iter()
        .filter_map(|event| event.get("position").and_then(|position| position.as_i64()))
        .max()
        .unwrap_or(ack_position);
    res.render(Json(DeviceMessagesReceiveResponse {
        events,
        next_batch: Some(sync_token_for_client_sync(
            state,
            Some(&session),
            None,
            None,
            None,
            &[],
            BTreeMap::new(),
            to_device_position,
        )),
        limited: false,
    }));
}

pub fn prune_acked_device_messages(
    queue: &mut VecDeque<DeviceMessageRecord>,
    session: &SessionRecord,
    ack_position: i64,
) {
    if ack_position <= 0 {
        return;
    }
    queue.retain(|message| {
        !(message.recipient == session.actor
            && message.device_id == session.device_id
            && message.position <= ack_position)
    });
}

pub fn device_message_events_after(
    queue: &VecDeque<DeviceMessageRecord>,
    session: &SessionRecord,
    ack_position: i64,
) -> Vec<Value> {
    queue
        .iter()
        .filter(|message| {
            message.recipient == session.actor
                && message.device_id == session.device_id
                && message.position > ack_position
        })
        .map(|message| {
            json!({
                "txn_id": message.txn_id,
                "sender": message.sender,
                "recipient": message.recipient,
                "device_id": message.device_id,
                "position": message.position,
                "content": message.content,
                "created_at": message.created_at
            })
        })
        .collect()
}
