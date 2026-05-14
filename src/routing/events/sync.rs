//! Client sync + snapshot handlers + the cursor-helper machinery they share
//! with events and device-message modules.
//!
//! Surfaces for the current sync/event wire layout:
//! - `GET  /api/v1/sync/describe`
//! - `POST /api/v1/sync`                    — `cx.sync.account` (account-aggregate sync: timeline,
//!   presence, typing, to_device). Renamed from `cx.sync.client_sync` — path unchanged.
//! - `POST /api/v1/sync/typing`             — `cx.sync.typing` (transient ephemeral)
//! - `GET  /api/v1/events/subscribe`        — `cx.events.subscribe` (replaces `cx.sync.subscribe` /
//!   `/api/v1/sync/subscribe`). Multi-space / multi-actor stream; frame `kind` field replaces
//!   `type`.
//! - `GET  /api/v1/events`                  — `cx.events.query` (replaces `cx.events.list` +
//!   `cx.sync.backfill` via `direction=forward|backward`).
//! - `GET  /api/v1/sync/backfill/gap`       — `cx.sync.backfill_gap` (deployment-local; not in
//!   spec)
//! - `GET  /api/v1/sync/snapshot-head`
//! - `GET  /api/v1/sync/snapshot-chunk`
//!
//! `SyncCursor`, `SyncCursorError`, `parse_and_validate_sync_cursor`,
//! `decode_sync_cursor_value`, `sync_token_for_client_sync`, `sync_filter_hash`,
//! `bound_cursor`, `bound_cursor_with_positions`, `normalized_strings` are all
//! `pub` because sibling routing modules reuse them. They
//! live here because the cursor lifecycle is anchored to `client_sync`.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use chrono::{Duration as ChronoDuration, SecondsFormat};
use contrix_sdk::SpaceId;
use futures_util::stream::StreamExt;
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::json;
use tokio::sync::broadcast::error::RecvError;

use super::{
    auth_or_render, authenticated_session, backfill_gap_events, default_discussion_track,
    device_message_events_after, flow_id_from_space_id, flow_projection_for_space,
    is_space_deleted, now, parse_snapshot_ref, projected_event_page, projection_event_json,
    prune_acked_device_messages, prune_expired_typing, query_param, render_error, sha256_hex,
    snapshot_bundle_for_space, space_has_member, space_id_accessible, space_visible_to,
    sync_timeline_message_json, truncate_gap_events, typing_ephemeral_for_space, validate_did,
    validate_space_id,
};
use crate::reducer::ProjectionState;
use crate::state::{AppState, PresenceRecord, SessionRecord, TypingRecord};
use crate::wire::{
    BackfillResponse, ClientSyncRequest, ClientSyncResponse, SetTypingRequest, SetTypingResponse,
    SnapshotHeadResponse, SyncDescribeResponse, sync_token,
};

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("sync/describe").get(sync_describe))
        .push(Router::with_path("sync").post(client_sync))
        .push(Router::with_path("sync/typing").post(set_typing))
        .push(Router::with_path("sync/backfill/gap").get(sync_gap_backfill))
        .push(Router::with_path("sync/snapshot-head").get(snapshot_head))
        .push(Router::with_path("sync/snapshot-chunk").get(snapshot_chunk))
}

#[endpoint]
async fn sync_describe(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    res.render(Json(SyncDescribeResponse {
        service_did: state.config.service_did.clone(),
        supported_sync_profiles: vec![
            "initial".to_owned(),
            "incremental".to_owned(),
            "board".to_owned(),
            "chat".to_owned(),
            "topic".to_owned(),
        ],
        limits: json!({"max_spaces": 50, "max_timeline_events": 100}),
        frontier: json!({"storage": state.db.mode(), "generated_at": now()}),
    }));
}

#[endpoint]
async fn client_sync(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match req.parse_json::<ClientSyncRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid sync request",
            );
            return;
        }
    };
    let session = authenticated_session(state, req).ok();
    let since_cursor = if let Some(since) = body.since.as_deref() {
        match parse_and_validate_sync_cursor(
            since,
            state,
            session.as_ref(),
            body.profile.as_deref(),
            body.filter.as_ref(),
            body.renderer.as_deref(),
            &body.facets,
            chrono::Utc::now().timestamp_millis(),
        ) {
            Ok(cursor) => cursor,
            Err(SyncCursorError::Expired) => {
                render_error(
                    res,
                    StatusCode::GONE,
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
        }
    } else {
        SyncCursor::default()
    };
    if let Some(presence) = body.set_presence.as_deref()
        && !matches!(presence, "online" | "offline" | "unavailable")
    {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "set_presence must be online, offline, or unavailable",
        );
        return;
    }
    if let Some(profile) = body.profile.as_deref()
        && !matches!(
            profile,
            "initial" | "incremental" | "board" | "chat" | "topic"
        )
    {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "profile must be initial, incremental, board, chat, or topic",
        );
        return;
    }
    if let Some(renderer) = body.renderer.as_deref()
        && !is_supported_view_renderer(renderer)
    {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "renderer must be collection, timeline, graph, document, or composite",
        );
        return;
    }

    if let Some(presence) = body.set_presence.as_deref() {
        let Some(session) = session.as_ref() else {
            render_error(
                res,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "set_presence requires authentication",
            );
            return;
        };
        if let Err(error) = state.persistence.presence().put(PresenceRecord {
            actor: session.actor.clone(),
            status: presence.to_owned(),
            updated_at: chrono::Utc::now(),
        }) {
            tracing::error!(%error, "failed to persist presence");
        }
    }
    prune_expired_typing(state);
    let visible_spaces: Vec<_> = {
        let spaces = state.spaces.lock().expect("spaces lock");
        spaces
            .search(Default::default())
            .into_iter()
            .filter(|space| space_visible_to(state, space, session.as_ref()))
            .map(|space| {
                (
                    space.space_id.to_string(),
                    space.name.clone(),
                    space.description.clone(),
                    space.tags.clone(),
                    space.category.clone(),
                )
            })
            .collect()
    };
    let projection = state.projection.lock().expect("projection lock");
    let mut sync_spaces = std::collections::BTreeMap::new();
    let mut positions = BTreeMap::new();
    for (space_id, title, summary, tags, category) in visible_spaces {
        let flow = flow_projection_for_space(state, &space_id, &title, summary.as_deref());
        let flow_state_after = flow.clone();
        let flow_list_item = flow.clone();
        let title_text = title.clone();
        let summary_text = summary.clone();
        let tags_value = tags.clone();
        let category_value = category.clone();
        let since_position = since_cursor
            .positions
            .get(&space_id)
            .copied()
            .unwrap_or_default();
        let (timeline_events, space_position) =
            timeline_events_for_space(state, &projection, &space_id, since_position);
        positions.insert(space_id.clone(), space_position);
        sync_spaces.insert(
            space_id.clone(),
            json!({
                "summary": {
                    "flow": flow,
                    "title": title_text,
                    "summary": summary_text,
                    "tags": tags_value,
                    "category": category_value,
                },
                "flows": [flow_list_item],
                "timeline": {"events": timeline_events, "limited": false},
                "state": [],
                "state_after": {"events": [flow_state_after]},
                "ephemeral": typing_ephemeral_for_space(state, &space_id, session.as_ref()),
                "unread": {"notification_count": 0, "highlight_count": 0}
            }),
        );
    }

    let mut to_device_position = since_cursor.to_device_position;
    let to_device = session
        .as_ref()
        .map(|session| {
            prune_acked_device_messages(state, session, since_cursor.to_device_position);
            let queued = state
                .persistence
                .device_messages()
                .list_after(
                    &session.actor,
                    &session.device_id,
                    since_cursor.to_device_position,
                )
                .unwrap_or_default();
            let events = device_message_events_after(&queued);
            if let Some(max_position) = events
                .iter()
                .filter_map(|event| event.get("position").and_then(|position| position.as_i64()))
                .max()
            {
                to_device_position = max_position;
            }
            events
        })
        .unwrap_or_default();

    res.render(Json(ClientSyncResponse {
        next_batch: sync_token_for_client_sync(
            state,
            session.as_ref(),
            body.profile.as_deref(),
            body.filter.as_ref(),
            body.renderer.as_deref(),
            &body.facets,
            positions,
            to_device_position,
        ),
        spaces: sync_spaces,
        to_device,
        account_data: Vec::new(),
        device_lists: json!({"changed": [], "left": []}),
    }));
}

fn timeline_events_for_space(
    state: &AppState,
    projection: &ProjectionState,
    space_id: &str,
    since_position: i64,
) -> (Vec<serde_json::Value>, i64) {
    let mut seen = BTreeSet::new();
    let mut newest_position = since_position;
    let mut timeline_entries = Vec::new();

    for message in projection.messages_for_space(space_id) {
        let position = message.created_at.timestamp_micros();
        newest_position = newest_position.max(position);
        if position <= since_position || !seen.insert(message.event_id.clone()) {
            continue;
        }
        timeline_entries.push((position, sync_timeline_message_json(message)));
    }

    for message in state
        .persistence
        .messages()
        .list_for_space(space_id, 100)
        .unwrap_or_default()
    {
        let position = message.created_at.timestamp_micros();
        newest_position = newest_position.max(position);
        if position <= since_position || !seen.insert(message.event_id.clone()) {
            continue;
        }
        timeline_entries.push((position, sync_timeline_message_record_json(&message)));
    }

    timeline_entries.sort_by(|left, right| left.0.cmp(&right.0));
    (
        timeline_entries
            .into_iter()
            .map(|(_, event)| event)
            .collect(),
        newest_position,
    )
}

fn sync_timeline_message_record_json(message: &crate::state::MessageRecord) -> serde_json::Value {
    let flow_id = if message.thread_id.starts_with("cx:flow:") {
        message.thread_id.clone()
    } else {
        flow_id_from_space_id(&message.space_id)
    };
    let track_id = message.thread_id.clone();
    json!({
        "kind": "cx.message.create",
        "event_id": message.event_id,
        "message_id": super::message_id_from_event_id(&message.event_id),
        "flow_id": flow_id,
        "space_id": message.space_id,
        "track": default_discussion_track(&flow_id, &track_id),
        "thread_id": message.thread_id,
        "sender": message.sender,
        "content": message.content,
        "encrypted": message.encrypted,
        "decryption_state": if message.encrypted { "opaque" } else { "cleartext" },
        "created_at": message.created_at,
    })
}

fn is_supported_view_renderer(renderer: &str) -> bool {
    matches!(
        renderer,
        "collection" | "timeline" | "graph" | "document" | "composite"
    )
}

#[derive(Debug, Default)]
pub struct SyncCursor {
    pub positions: BTreeMap<String, i64>,
    pub to_device_position: i64,
}

#[derive(Debug)]
pub enum SyncCursorError {
    Invalid(&'static str),
    Mismatch(&'static str),
    Expired,
}

pub fn sync_token_for_client_sync(
    state: &AppState,
    session: Option<&SessionRecord>,
    profile: Option<&str>,
    filter: Option<&serde_json::Value>,
    renderer: Option<&str>,
    facets: &[String],
    spaces_positions: BTreeMap<String, i64>,
    to_device_position: i64,
) -> String {
    let issued_at = chrono::Utc::now();
    let expires_at = issued_at + ChronoDuration::hours(1);
    let principal_id = session
        .map(|session| session.actor.clone())
        .unwrap_or_else(|| "anonymous".to_owned());
    let device_id = session
        .map(|session| session.device_id.clone())
        .unwrap_or_else(|| "anonymous".to_owned());
    let device_positions = BTreeMap::from([(device_id.clone(), issued_at.timestamp_micros())]);
    let profile = profile.unwrap_or("incremental");
    let cursor = json!({
        "v": "1",
        "purpose": "stream",
        "t": issued_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "x": expires_at.timestamp_millis(),
        "_profile": profile,
        "principal_id": principal_id,
        "device_id": device_id,
        "service_id": state.config.service_did.clone(),
        "renderer": renderer,
        "facets": facets,
        "_filter_hash": sync_filter_hash(profile, filter, renderer, facets),
        "_positions": {
            "spaces": spaces_positions,
            "devices": device_positions,
            "to_device": to_device_position
        }
    });
    let bytes = contrix_sdk::canonical::canonical_json_bytes(&cursor)
        .unwrap_or_else(|_| cursor.to_string().into_bytes());
    format!("cx:cursor:{}", URL_SAFE_NO_PAD.encode(bytes))
}

pub fn parse_and_validate_sync_cursor(
    token: &str,
    state: &AppState,
    session: Option<&SessionRecord>,
    profile: Option<&str>,
    filter: Option<&serde_json::Value>,
    renderer: Option<&str>,
    facets: &[String],
    now_ms: i64,
) -> Result<SyncCursor, SyncCursorError> {
    let value = decode_sync_cursor_value(token)?;
    if value
        .get("v")
        .and_then(|v| v.as_str())
        .is_none_or(|v| v != "1")
        || value
            .get("purpose")
            .and_then(|purpose| purpose.as_str())
            .is_none_or(|purpose| purpose != "stream")
    {
        return Err(SyncCursorError::Invalid("since must be a v1 sync cursor"));
    }
    if value
        .get("x")
        .and_then(|expires_at| expires_at.as_i64())
        .is_some_and(|expires_at| expires_at <= now_ms)
    {
        return Err(SyncCursorError::Expired);
    }
    let expected_principal = session
        .map(|session| session.actor.as_str())
        .unwrap_or("anonymous");
    let expected_device = session
        .map(|session| session.device_id.as_str())
        .unwrap_or("anonymous");
    if value
        .get("principal_id")
        .and_then(|principal| principal.as_str())
        .is_some_and(|principal| principal != expected_principal)
    {
        return Err(SyncCursorError::Mismatch(
            "sync token principal does not match request actor",
        ));
    }
    if value
        .get("device_id")
        .and_then(|device| device.as_str())
        .is_some_and(|device| device != expected_device)
    {
        return Err(SyncCursorError::Mismatch(
            "sync token device does not match request device",
        ));
    }
    if value
        .get("service_id")
        .and_then(|service| service.as_str())
        .is_some_and(|service| service != state.config.service_did)
    {
        return Err(SyncCursorError::Mismatch(
            "sync token service does not match this service DID",
        ));
    }
    let expected_filter_hash =
        sync_filter_hash(profile.unwrap_or("incremental"), filter, renderer, facets);
    if value
        .get("_filter_hash")
        .and_then(|filter_hash| filter_hash.as_str())
        .is_some_and(|filter_hash| filter_hash != expected_filter_hash)
    {
        return Err(SyncCursorError::Mismatch(
            "sync token filter hash does not match request filter",
        ));
    }
    let positions_value = value.get("_positions").ok_or(SyncCursorError::Invalid(
        "since cursor must contain _positions",
    ))?;
    let positions = positions_value
        .get("spaces")
        .and_then(|spaces| spaces.as_object())
        .ok_or(SyncCursorError::Invalid(
            "since cursor must contain _positions.spaces",
        ))?
        .iter()
        .filter_map(|(space_id, position)| {
            position
                .as_i64()
                .map(|position| (space_id.clone(), position))
        })
        .collect();
    let to_device_position = positions_value
        .get("to_device")
        .and_then(|position| position.as_i64())
        .unwrap_or_default();
    Ok(SyncCursor {
        positions,
        to_device_position,
    })
}

pub fn decode_sync_cursor_value(token: &str) -> Result<serde_json::Value, SyncCursorError> {
    let Some(encoded) = token.strip_prefix("cx:cursor:") else {
        return Err(SyncCursorError::Invalid(
            "since must use a cx:cursor sync token",
        ));
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| SyncCursorError::Invalid("since cursor must be valid base64url"))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| SyncCursorError::Invalid("since cursor must contain JSON"))
}

pub fn sync_filter_hash(
    profile: &str,
    filter: Option<&serde_json::Value>,
    renderer: Option<&str>,
    facets: &[String],
) -> String {
    let empty_filter = json!({});
    let binding = json!({
        "profile": profile,
        "filter": filter.unwrap_or(&empty_filter),
        "renderer": renderer,
        "facets": normalized_strings(facets),
    });
    contrix_sdk::canonical::canonical_sha256(&binding)
        .unwrap_or_else(|_| format!("sha256:{}", sha256_hex(binding.to_string().as_bytes())))
}

pub fn bound_cursor(profile: &str, binding: serde_json::Value) -> String {
    bound_cursor_with_positions(profile, binding, json!({}))
}

pub fn bound_cursor_with_positions(
    profile: &str,
    binding: serde_json::Value,
    positions: serde_json::Value,
) -> String {
    let now = chrono::Utc::now();
    let expires_at = now + ChronoDuration::days(7);
    let filter_hash = contrix_sdk::canonical::canonical_sha256(&binding)
        .unwrap_or_else(|_| format!("sha256:{}", sha256_hex(binding.to_string().as_bytes())));
    let cursor = json!({
        "v": "1",
        "purpose": "stream",
        "t": now.to_rfc3339_opts(SecondsFormat::Millis, true),
        "x": expires_at.timestamp_millis(),
        "_profile": profile,
        "_filter_hash": filter_hash,
        "_binding": binding,
        "_positions": positions
    });
    let bytes = contrix_sdk::canonical::canonical_json_bytes(&cursor)
        .unwrap_or_else(|_| cursor.to_string().into_bytes());
    format!("cx:cursor:{}", URL_SAFE_NO_PAD.encode(bytes))
}

pub fn normalized_strings(values: &[String]) -> Vec<String> {
    let mut values = values.to_vec();
    values.sort();
    values.dedup();
    values
}

#[endpoint]
async fn set_typing(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<SetTypingRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid typing request",
            );
            return;
        }
    };
    if validate_space_id(&body.space_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    }
    if !space_has_member(state, &body.space_id, &session.actor) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "actor is not a joined member of the space",
        );
        return;
    }

    let expires_at = if body.typing {
        let timeout_ms = body.timeout_ms.unwrap_or(30_000).clamp(1_000, 120_000);
        let now = chrono::Utc::now();
        let expires_at = now + chrono::Duration::milliseconds(timeout_ms as i64);
        if let Err(error) = state.persistence.typing().put(TypingRecord {
            actor: session.actor.clone(),
            space_id: body.space_id.clone(),
            scope_id: body.scope_id.clone(),
            expires_at,
            updated_at: now,
        }) {
            tracing::error!(%error, "failed to persist typing");
        }
        Some(expires_at)
    } else {
        let _ = state
            .persistence
            .typing()
            .remove(&session.actor, &body.space_id);
        None
    };

    res.render(Json(SetTypingResponse {
        ok: true,
        space_id: body.space_id,
        actor: session.actor,
        typing: body.typing,
        expires_at,
    }));
}

/// `cx.events.subscribe` at `GET /api/v1/events/subscribe`. NDJSON
/// streaming: each line is one frame, frame `kind` is one of
/// `event` / `catchup_complete` / `heartbeat` / `dropped`.
///
/// Selector: repeated `spaces[]` query args (multi-value). The legacy
/// singular `space_id` parameter is not supported.
///
/// Lifecycle:
///   1. Validate inputs (spaces, accessibility).
///   2. Subscribe to the live event broadcast BEFORE serving history so no events are missed in the
///      history-vs-live window.
///   3. Build an async stream that yields: a) historical event frames (if `include_history=true`,
///      default true) b) one `catchup_complete` frame c) live event frames as broadcast
///      notifications arrive d) periodic `heartbeat` frames every 30s of idle e) `dropped` frames
///      when broadcast lag is detected
///   4. Stream terminates when:
///      - `max_duration_ms` query param elapsed (default 60_000 ms)
///      - client disconnects (drops the response stream)
///      - the broadcast channel is closed (server shutdown)
#[endpoint]
pub(super) async fn events_subscribe(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected").clone();
    // Repeated `spaces=` query args (multi-value).
    let spaces = super::query_param_all(req, "spaces");
    if spaces.is_empty() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "spaces is required",
        );
        return;
    }
    for space in &spaces {
        if validate_space_id(space).is_err() {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_param",
                &format!("invalid space: {space}"),
            );
            return;
        }
    }
    let session = authenticated_session(&state, req).ok();
    let mut accessible_spaces: Vec<String> = Vec::with_capacity(spaces.len());
    for space in spaces {
        if space_id_accessible(&state, &space, session.as_ref()) {
            accessible_spaces.push(space);
        }
    }
    if accessible_spaces.is_empty() {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
        return;
    }
    let limit = query_param(req, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100)
        .min(100);
    // Cursor parameter uses `from`; the legacy `cursor` param is not supported.
    let cursor = query_param(req, "from");
    let include_history = query_param(req, "include_history")
        .as_deref()
        .map(|value| matches!(value, "true" | "1" | "yes"))
        .unwrap_or(true);
    // Cap how long the stream stays open. Default 60s; tests
    // typically pass `max_duration_ms=500` to bound assertion latency.
    // Production clients reconnect after the close (HTTP/1.1 long-poll
    // pattern) or use SSE EventSource auto-reconnect.
    let max_duration_ms = query_param(req, "max_duration_ms")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(60_000)
        .min(600_000);
    // Heartbeat interval. Default 15s; min 100ms (for tests).
    let heartbeat_ms = query_param(req, "heartbeat_ms")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(15_000)
        .max(100);

    // Subscribe to live notifications BEFORE serving history so we don't
    // miss events that land between history-end and subscribe-start.
    let mut rx = state.event_broadcast.subscribe();

    // Pre-build history frames synchronously (same logic as the old unary
    // handler). The async stream yields these first, then transitions to
    // live events.
    let mut history_frames: Vec<serde_json::Value> = Vec::new();
    let mut seq: u64 = 0;
    let mut last_cursor: Option<String> = None;

    if include_history {
        for space_id in &accessible_spaces {
            match projected_event_page(&state, space_id, cursor.as_deref(), limit) {
                Ok(Some(page)) => {
                    for event in page.items {
                        seq += 1;
                        let event_cursor = event.event_id.clone();
                        last_cursor = Some(event_cursor.clone());
                        history_frames.push(json!({
                            "kind": "event",
                            "seq": seq,
                            "cursor": event_cursor,
                            "payload": projection_event_json(&event)
                        }));
                    }
                    if let Some(next) = page.next_cursor {
                        last_cursor = Some(next);
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    if error.to_string().contains("invalid_cursor") && accessible_spaces.len() == 1
                    {
                        render_error(
                            res,
                            StatusCode::BAD_REQUEST,
                            "invalid_cursor",
                            "cursor not found",
                        );
                        return;
                    }
                }
            }
        }
    }

    let catchup_cursor = last_cursor.unwrap_or_else(sync_token);
    let space_filter: BTreeSet<String> = accessible_spaces.iter().cloned().collect();
    let stream_deadline = tokio::time::Instant::now() + Duration::from_millis(max_duration_ms);

    // The async stream — yields one NDJSON line (Bytes) per frame.
    let body_stream = async_stream::stream! {
        // 1. Historical frames.
        for frame in &history_frames {
            yield Ok::<Bytes, std::io::Error>(ndjson_line(frame));
        }
        let mut live_seq = seq;

        // 2. catchup_complete signals end of historical buffer.
        let catchup = json!({
            "kind": "catchup_complete",
            "cursor": catchup_cursor,
        });
        yield Ok(ndjson_line(&catchup));

        // 3. Live loop: tokio::select on broadcast recv + heartbeat tick + deadline.
        let mut heartbeat = tokio::time::interval(Duration::from_millis(heartbeat_ms));
        // Skip first immediate tick — interval fires once at construction.
        heartbeat.tick().await;
        loop {
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(stream_deadline) => {
                    // Final heartbeat then close.
                    let close_frame = json!({
                        "kind": "heartbeat",
                        "ts": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                        "stream_closing": true,
                    });
                    yield Ok(ndjson_line(&close_frame));
                    break;
                }
                recv = rx.recv() => {
                    match recv {
                        Ok(notification) => {
                            if !space_filter.contains(&notification.space_id) {
                                continue;
                            }
                            // Dispatch on notification.kind to
                            // produce the right NDJSON frame shape.
                            use crate::state::EventNotificationKind;
                            let frame = match notification.kind {
                                EventNotificationKind::Event { cursor, event_payload } => {
                                    live_seq += 1;
                                    json!({
                                        "kind": "event",
                                        "seq": live_seq,
                                        "cursor": cursor,
                                        "payload": event_payload,
                                    })
                                }
                                EventNotificationKind::EpochRotation { previous_epoch, new_epoch } => {
                                    json!({
                                        "kind": "epoch_rotation",
                                        "space_id": notification.space_id,
                                        "previous_epoch": previous_epoch,
                                        "new_epoch": new_epoch,
                                    })
                                }
                                EventNotificationKind::Frontier { state_root, anchor_id } => {
                                    json!({
                                        "kind": "frontier",
                                        "space_id": notification.space_id,
                                        "state_root": state_root,
                                        "anchor_id": anchor_id,
                                    })
                                }
                                EventNotificationKind::ResyncRequired { reason } => {
                                    json!({
                                        "kind": "resync_required",
                                        "space_id": notification.space_id,
                                        "reason": reason,
                                    })
                                }
                                EventNotificationKind::Unauthorized { reason } => {
                                    json!({
                                        "kind": "unauthorized",
                                        "space_id": notification.space_id,
                                        "reason": reason,
                                    })
                                }
                            };
                            yield Ok(ndjson_line(&frame));
                        }
                        Err(RecvError::Lagged(skipped)) => {
                            // Broadcast capacity exceeded — emit `dropped`
                            // so the client knows to resync from a fresh
                            // /events?direction=backward query.
                            let frame = json!({
                                "kind": "dropped",
                                "skipped": skipped,
                                "reason": "broadcast_lagged",
                            });
                            yield Ok(ndjson_line(&frame));
                        }
                        Err(RecvError::Closed) => {
                            // Server shutdown / channel dropped.
                            break;
                        }
                    }
                }
                _ = heartbeat.tick() => {
                    let frame = json!({
                        "kind": "heartbeat",
                        "ts": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    });
                    yield Ok(ndjson_line(&frame));
                }
            }
        }
    };

    let _ = res.add_header("content-type", "application/x-ndjson", true);
    res.stream(body_stream.boxed());
}

/// Serialize a JSON frame to a length-prefixed
/// NDJSON line. Each line ends with `\n` per the NDJSON / JSON-Lines
/// convention so streaming clients can split-on-newline incrementally
/// without parsing the whole buffer.
fn ndjson_line(value: &serde_json::Value) -> Bytes {
    let mut s = serde_json::to_string(value).unwrap_or_else(|_| "{}".to_owned());
    s.push('\n');
    Bytes::from(s)
}

/// `cx.events.query` at `GET /api/v1/events`.
/// Reads from the projection layer so callers writing through
/// `POST /api/v1/events` see their messages here.
///
/// Selector: `spaces[]` ∪ `actors[]` repeated query args (multi-value).
/// Multi-space queries call `projected_event_page` per space and merge sorted
/// by HLC; the result paginates as a single stream.
/// `actors[]`-only queries dispatch to the durable Event-store reader.
///
/// Range: `from?` + `until?` + `direction`.
/// `direction=backward` reverses the merged stream so callers can paginate
/// older events with the same `next_cursor` semantics.
#[endpoint]
pub(super) async fn events_query(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    // Collect all `spaces=` and `actors=` repeated args.
    let spaces = super::query_param_all(req, "spaces");
    let actors = super::query_param_all(req, "actors");
    if spaces.is_empty() && actors.is_empty() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "events.query requires at least one of spaces[] / actors[]",
        );
        return;
    }
    for space in &spaces {
        if validate_space_id(space).is_err() {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_param",
                &format!("invalid space: {space}"),
            );
            return;
        }
    }
    for actor in &actors {
        if validate_did(actor).is_err() {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_param",
                &format!("invalid actor: {actor}"),
            );
            return;
        }
    }
    // Dispatch: if no spaces (actor-scoped query), forward to the durable
    // Event-store reader in routing/events.rs which builds an actor-keyed
    // `frontier.actors` map. The projection-aware path below is space-keyed.
    if spaces.is_empty() {
        super::events_query_durable_scope_impl(depot, req, res).await;
        return;
    }
    let session = authenticated_session(state, req).ok();
    let mut accessible_spaces: Vec<String> = Vec::with_capacity(spaces.len());
    for space in spaces {
        if space_id_accessible(state, &space, session.as_ref()) {
            accessible_spaces.push(space);
        }
    }
    if accessible_spaces.is_empty() {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
        return;
    }
    let limit = query_param(req, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100)
        .min(100);
    // `from` is the cursor parameter; `direction = forward | backward`.
    // The legacy `cursor` parameter is not supported.
    let cursor = query_param(req, "from");
    let direction = query_param(req, "direction").unwrap_or_else(|| "forward".to_owned());
    if direction != "forward" && direction != "backward" {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "direction must be 'forward' or 'backward'",
        );
        return;
    }
    let backward = direction == "backward";

    // Single-space fast path preserves the original `BackfillResponse` shape
    // for soland's existing test surface (cx.sync.backfill behavior).
    if accessible_spaces.len() == 1 {
        let space_id = &accessible_spaces[0];
        match projected_event_page(state, space_id, cursor.as_deref(), limit) {
            Ok(Some(page)) => {
                let mut events: Vec<_> = page.items.iter().map(projection_event_json).collect();
                if backward {
                    events.reverse();
                }
                res.render(Json(BackfillResponse {
                    events,
                    prev_cursor: cursor.clone(),
                    prev_batch: cursor,
                    next_cursor: page.next_cursor.or_else(|| Some(sync_token())),
                    limited: page.has_more,
                }));
                return;
            }
            Ok(None) => {}
            Err(error) => {
                if error.to_string().contains("invalid_cursor") {
                    render_error(
                        res,
                        StatusCode::BAD_REQUEST,
                        "invalid_cursor",
                        "cursor not found",
                    );
                    return;
                }
                render_error(
                    res,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "projection_error",
                    &error.to_string(),
                );
                return;
            }
        }
        res.render(Json(BackfillResponse {
            events: Vec::new(),
            prev_cursor: cursor.clone(),
            prev_batch: cursor,
            next_cursor: Some(sync_token()),
            limited: false,
        }));
        return;
    }

    // Multi-space merge path: call `projected_event_page` per space, merge
    // by `received_at`, then paginate. `next_cursor` is the last-event id of
    // the merged page (consistent with single-space cursor semantics).
    let mut merged: Vec<serde_json::Value> = Vec::new();
    let mut any_has_more = false;
    for space_id in &accessible_spaces {
        // Each per-space call uses `limit` so the merge floor is bounded
        // by `accessible_spaces.len() * limit`.
        match projected_event_page(state, space_id, cursor.as_deref(), limit) {
            Ok(Some(page)) => {
                if page.has_more {
                    any_has_more = true;
                }
                merged.extend(page.items.iter().map(projection_event_json));
            }
            Ok(None) => {}
            Err(error) => {
                if error.to_string().contains("invalid_cursor") {
                    render_error(
                        res,
                        StatusCode::BAD_REQUEST,
                        "invalid_cursor",
                        "cursor not found",
                    );
                    return;
                }
                // Other errors on one space don't fail the whole multi-space
                // query — carry on with what we have.
                continue;
            }
        }
    }
    // Sort by `created_at` (string-comparable RFC3339), tie-break by
    // `event_id` for determinism.
    merged.sort_by(|left, right| {
        let left_ts = left["created_at"].as_str().unwrap_or("");
        let right_ts = right["created_at"].as_str().unwrap_or("");
        left_ts
            .cmp(right_ts)
            .then_with(|| left["event_id"].as_str().cmp(&right["event_id"].as_str()))
    });
    if backward {
        merged.reverse();
    }
    let mut page_events = merged.into_iter().take(limit + 1).collect::<Vec<_>>();
    let limited = page_events.len() > limit || any_has_more;
    if page_events.len() > limit {
        page_events.truncate(limit);
    }
    let next_cursor = limited
        .then(|| {
            page_events
                .last()
                .and_then(|event| event["event_id"].as_str().map(ToOwned::to_owned))
        })
        .flatten()
        .or_else(|| Some(sync_token()));
    res.render(Json(BackfillResponse {
        events: page_events,
        prev_cursor: cursor.clone(),
        prev_batch: cursor,
        next_cursor,
        limited,
    }));
}

#[endpoint]
async fn sync_gap_backfill(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(space_id) = query_param(req, "space_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "space_id is required",
        );
        return;
    };
    if validate_space_id(&space_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    }
    let session = authenticated_session(state, req).ok();
    if !space_id_accessible(state, &space_id, session.as_ref()) {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
        return;
    }
    let limit = query_param(req, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100)
        .clamp(1, 500);
    let from_cursor = query_param(req, "from_cursor")
        .or_else(|| query_param(req, "from"))
        .or_else(|| query_param(req, "prev_batch"))
        .or_else(|| query_param(req, "cursor"));
    let to_cursor = query_param(req, "to_cursor")
        .or_else(|| query_param(req, "to"))
        .or_else(|| query_param(req, "next_batch"));

    // Resolve sync `cx:cursor:` tokens to reducer event cursors. The
    // sync token's `_positions` map encodes per-Space `timestamp_micros`
    // checkpoints; we translate that into the last `event_id` at or
    // before the checkpoint so backfill can resume from there. Plain
    // event-id cursors flow through unchanged.
    let from_cursor = match resolve_sync_cursor_to_event_id(state, &space_id, from_cursor) {
        Ok(cursor) => cursor,
        Err(message) => {
            render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
            return;
        }
    };
    let to_cursor = match resolve_sync_cursor_to_event_id(state, &space_id, to_cursor) {
        Ok(cursor) => cursor,
        Err(message) => {
            render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
            return;
        }
    };

    let (events, next_cursor, limited) =
        match backfill_gap_events(state, &space_id, from_cursor.as_deref(), limit) {
            Ok(result) => result,
            Err(error) => {
                if error.to_string().contains("invalid_cursor") {
                    render_error(
                        res,
                        StatusCode::BAD_REQUEST,
                        "invalid_cursor",
                        "cursor not found",
                    );
                    return;
                }
                render_error(
                    res,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "backfill_error",
                    &error.to_string(),
                );
                return;
            }
        };
    let (events, gap_complete) = truncate_gap_events(events, to_cursor.as_deref());
    let next_cursor = if gap_complete {
        to_cursor.clone()
    } else {
        next_cursor
    };
    res.render(Json(json!({
        "events": events,
        "from_cursor": from_cursor.clone(),
        "to_cursor": to_cursor.clone(),
        "prev_batch": from_cursor.clone(),
        "next_cursor": next_cursor,
        "limited": limited && !gap_complete,
        "gap_complete": gap_complete || !limited,
        "production_gap": "durable_sync_position_validation",
    })));
}

#[endpoint]
async fn snapshot_head(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(space_id) = query_param(req, "space_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "space_id is required",
        );
        return;
    };
    if validate_space_id(&space_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    }
    if is_space_deleted(state, &space_id) {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
        return;
    }
    let Ok(space_id_value) = SpaceId::new(space_id.clone()) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    };
    let spaces = state.spaces.lock().expect("spaces lock");
    if spaces.get(&space_id_value).is_none() {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
        return;
    }
    drop(spaces);
    let Some(bundle) = snapshot_bundle_for_space(state, &space_id) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
        return;
    };
    let service_did = state.config.service_did.clone();
    let signature_payload = format!(
        "{}:{}:{}",
        bundle.snapshot_ref, bundle.state_hash, service_did
    );
    res.render(Json(SnapshotHeadResponse {
        snapshot_ref: bundle.snapshot_ref,
        state_hash: bundle.state_hash,
        manifest: bundle.manifest,
        chunks: vec![bundle.chunk_descriptor],
        frontier: bundle.frontier,
        signature: json!({
            "kid": format!("{service_did}#snapshot-dev"),
            "alg": "sha256-dev",
            "sig": sha256_hex(signature_payload.as_bytes())
        }),
    }));
}

#[endpoint]
async fn snapshot_chunk(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(snapshot_ref) = query_param(req, "snapshot_ref") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "snapshot_ref is required",
        );
        return;
    };
    let chunk_id = query_param(req, "chunk_id").unwrap_or_else(|| "0".to_owned());
    if chunk_id != "0" {
        render_error(
            res,
            StatusCode::NOT_FOUND,
            "not_found",
            "snapshot chunk not found",
        );
        return;
    }
    let Some((space_id, expected_hash)) = parse_snapshot_ref(&snapshot_ref) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid snapshot_ref",
        );
        return;
    };
    if is_space_deleted(state, &space_id) {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
        return;
    }
    let Some(bundle) = snapshot_bundle_for_space(state, &space_id) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
        return;
    };
    if bundle.snapshot_ref != snapshot_ref || bundle.state_hash != expected_hash {
        render_error(
            res,
            StatusCode::CONFLICT,
            "snapshot_stale",
            "snapshot_ref no longer matches the current snapshot frontier",
        );
        return;
    }

    // TODO(P1 snapshot): replace the single JSON chunk with deterministic
    // multi-chunk Merkle output and signed generator proofs.
    res.render(Json(json!({
        "snapshot_ref": snapshot_ref,
        "chunk_id": chunk_id,
        "media_type": "application/json",
        "encoding": "base64url",
        "digest": bundle.state_hash,
        "verified": format!("sha256:{}", sha256_hex(&bundle.chunk_bytes)) == bundle.state_hash,
        "bytes_base64": URL_SAFE_NO_PAD.encode(&bundle.chunk_bytes),
    })));
}
