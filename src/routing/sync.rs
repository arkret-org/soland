//! Client sync + snapshot handlers + the cursor-helper machinery they share
//! with the index module.
//!
//! Surfaces:
//! - `GET  /api/v1/sync/describe`
//! - `POST /api/v1/sync`                    — full client_sync (timeline, presence, typing, to_device)
//! - `POST /api/v1/sync/typing`             — set_typing (transient ephemeral)
//! - `GET  /api/v1/sync/subscribe`          — long-poll subscribe
//! - `GET  /api/v1/sync/backfill`
//! - `GET  /api/v1/sync/backfill/gap`
//! - `GET  /api/v1/sync/snapshot-head`
//! - `GET  /api/v1/sync/snapshot-chunk`
//!
//! `SyncCursor`, `SyncCursorError`, `parse_and_validate_sync_cursor`,
//! `decode_sync_cursor_value`, `sync_token_for_client_sync`, `sync_filter_hash`,
//! `bound_cursor`, `bound_cursor_with_positions`, `normalized_strings` are all
//! `pub` because the index module + device_messages module reuse them. They
//! live here because the cursor lifecycle is anchored to `client_sync`.
//!
//! Stream-S in `_todos.md` covers the still-open work: `cx:cursor:` ↔ reducer
//! event-seq mapping (S1, `handlers.rs:7623` TODO), deterministic
//! snapshot-chunk sharding (S2), history-visibility unification (B-03 / S3),
//! `cx:space:` prefix audit (M-15 / S4), and `$ME` / `*` substitution
//! formalization (M-16 / S5).

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use contrix_sdk::SpaceId;
use salvo::{http::StatusCode, prelude::*};
use serde_json::json;

use crate::{
    state::{AppState, PresenceRecord, SessionRecord, TypingRecord},
    wire::{
        BackfillResponse, ClientSyncRequest, ClientSyncResponse, SetTypingRequest,
        SetTypingResponse, SnapshotHeadResponse, SyncDescribeResponse, sync_token,
    },
};

use super::{
    auth_or_render, authenticated_session, backfill_gap_events,
    device_message_events_after, flow_projection_for_space, is_space_deleted,
    is_supported_view_renderer, now, operation_is_visible, parse_snapshot_ref,
    projected_event_page, projection_event_from_operation, projection_event_json,
    prune_acked_device_messages, prune_expired_typing, query_param,
    redaction_targets_from_operations, render_error, sha256_hex, snapshot_bundle_for_space,
    space_has_member, space_id_accessible, space_visible_to, sync_timeline_message_json,
    truncate_gap_events, typing_ephemeral_for_space, validate_no_removed_legacy_contracts,
    validate_space_id,
};

#[endpoint]
pub async fn sync_describe(depot: &mut Depot, res: &mut Response) {
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
pub async fn client_sync(depot: &mut Depot, req: &mut Request, res: &mut Response) {
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
    if let Some(filter) = body.filter.as_ref()
        && let Err(message) = validate_no_removed_legacy_contracts(filter)
    {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
        return;
    }
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
            "renderer must be collection, conversation, graph, queue, list, kanban, table, calendar, or timeline",
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
        let messages = projection.messages_for_space(&space_id);
        let space_position = messages
            .iter()
            .map(|message| message.created_at.timestamp_micros())
            .max()
            .unwrap_or(since_position);
        let timeline_events: Vec<_> = projection
            .messages_for_space(&space_id)
            .into_iter()
            .filter(|message| message.created_at.timestamp_micros() > since_position)
            .map(sync_timeline_message_json)
            .collect();
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
    let expires_at = issued_at + chrono::Duration::hours(1);
    let principal_id = session
        .map(|session| session.actor.clone())
        .unwrap_or_else(|| "anonymous".to_owned());
    let device_id = session
        .map(|session| session.device_id.clone())
        .unwrap_or_else(|| "anonymous".to_owned());
    let device_positions = BTreeMap::from([(device_id.clone(), issued_at.timestamp_micros())]);
    let profile = profile.unwrap_or("incremental");
    let cursor = json!({
        "schema": "cx.schema.cursor.v1",
        "version": 1,
        "profile": profile,
        "principal_id": principal_id,
        "device_id": device_id,
        "service_id": state.config.service_did.clone(),
        "renderer": renderer,
        "facets": facets,
        "filter_hash": sync_filter_hash(profile, filter, renderer, facets),
        "issued_at": issued_at,
        "issued_at_ms": issued_at.timestamp_millis(),
        "expires_at": expires_at,
        "expires_at_ms": expires_at.timestamp_millis(),
        "positions": {
            "spaces": spaces_positions,
            "devices": device_positions,
            "to_device": to_device_position,
            "repo": null
        }
    });
    format!("cx:cursor:{}", URL_SAFE_NO_PAD.encode(cursor.to_string()))
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
        .get("schema")
        .and_then(|schema| schema.as_str())
        .is_none_or(|schema| schema != "cx.schema.cursor.v1")
        || value
            .get("version")
            .and_then(|version| version.as_u64())
            .is_none_or(|version| version != 1)
    {
        return Err(SyncCursorError::Invalid("since must be a v1 sync cursor"));
    }
    if value
        .get("expires_at_ms")
        .and_then(|expires_at_ms| expires_at_ms.as_i64())
        .is_some_and(|expires_at_ms| expires_at_ms <= now_ms)
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
        .get("filter_hash")
        .and_then(|filter_hash| filter_hash.as_str())
        .is_some_and(|filter_hash| filter_hash != expected_filter_hash)
    {
        return Err(SyncCursorError::Mismatch(
            "sync token filter hash does not match request filter",
        ));
    }
    let positions_value = value.get("positions").ok_or(SyncCursorError::Invalid(
        "since cursor must contain positions",
    ))?;
    let positions = positions_value
        .get("spaces")
        .and_then(|spaces| spaces.as_object())
        .ok_or(SyncCursorError::Invalid(
            "since cursor must contain positions.spaces",
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
    bound_cursor_with_positions(profile, binding, json!({"repo": null}))
}

pub fn bound_cursor_with_positions(
    profile: &str,
    binding: serde_json::Value,
    positions: serde_json::Value,
) -> String {
    let now = chrono::Utc::now();
    let filter_hash = contrix_sdk::canonical::canonical_sha256(&binding)
        .unwrap_or_else(|_| format!("sha256:{}", sha256_hex(binding.to_string().as_bytes())));
    let cursor = json!({
        "schema": "cx.schema.cursor.v1",
        "version": 1,
        "profile": profile,
        "filter_hash": filter_hash,
        "issued_at": now,
        "issued_at_ms": now.timestamp_millis(),
        "positions": positions
    });
    format!("cx:cursor:{}", URL_SAFE_NO_PAD.encode(cursor.to_string()))
}

pub fn normalized_strings(values: &[String]) -> Vec<String> {
    let mut values = values.to_vec();
    values.sort();
    values.dedup();
    values
}

#[endpoint]
pub async fn set_typing(depot: &mut Depot, req: &mut Request, res: &mut Response) {
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

#[endpoint]
pub async fn sync_subscribe(depot: &mut Depot, req: &mut Request, res: &mut Response) {
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
        .min(100);
    let cursor = query_param(req, "cursor");
    match projected_event_page(state, &space_id, cursor.as_deref(), limit) {
        Ok(Some(page)) => {
            let frames: Vec<_> = page
                .items
                .into_iter()
                .enumerate()
                .map(|(index, event)| {
                    let cursor = event.event_id.clone();
                    json!({
                        "type": "event",
                        "seq": index + 1,
                        "cursor": cursor,
                        "payload": projection_event_json(&event)
                    })
                })
                .collect();
            res.render(Json(json!({
                "frames": frames,
                "next_cursor": page.next_cursor.or_else(|| Some(sync_token())),
                "has_more": page.has_more
            })));
        }
        Ok(None) => match state
            .repo
            .sync_space_operations(&space_id, cursor.as_deref(), limit)
        {
            Ok(page) => {
                let mut seq = 0usize;
                let frames: Vec<_> = page
                    .items
                    .into_iter()
                    .map(|operation| {
                        seq += 1;
                        let projected = projection_event_from_operation(&operation, None);
                        let cursor = projected
                            .operation_id
                            .clone()
                            .unwrap_or_else(|| projected.event_id.clone());
                        json!({
                            "type": "event",
                            "seq": seq,
                            "cursor": cursor,
                            "payload": projection_event_json(&projected)
                        })
                    })
                    .collect();
                res.render(Json(json!({
                    "frames": frames,
                    "next_cursor": page.next_cursor.or_else(|| Some(sync_token())),
                    "has_more": page.has_more
                })));
            }
            Err(error) => render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "repo_error",
                &error.to_string(),
            ),
        },
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
        }
    }
}

#[endpoint]
pub async fn sync_backfill(depot: &mut Depot, req: &mut Request, res: &mut Response) {
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
        .min(100);
    let cursor = query_param(req, "cursor");
    match projected_event_page(state, &space_id, cursor.as_deref(), limit) {
        Ok(Some(page)) => {
            let events = page.items.iter().map(projection_event_json).collect();
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
    let page = match state
        .repo
        .sync_space_operations(&space_id, cursor.as_deref(), limit)
    {
        Ok(page) => page,
        Err(error) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "repo_error",
                &error.to_string(),
            );
            return;
        }
    };
    let redacted = redaction_targets_from_operations(&page.items);
    let events: Vec<_> = page
        .items
        .into_iter()
        .filter(|operation| operation_is_visible(operation, &redacted))
        .map(|operation| projection_event_json(&projection_event_from_operation(&operation, None)))
        .collect();
    res.render(Json(BackfillResponse {
        events,
        prev_cursor: cursor.clone(),
        prev_batch: cursor,
        next_cursor: page.next_cursor.or_else(|| Some(sync_token())),
        limited: page.has_more,
    }));
}

#[endpoint]
pub async fn sync_gap_backfill(depot: &mut Depot, req: &mut Request, res: &mut Response) {
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

    // TODO(P0 sync): map durable cx:cursor space positions to reducer event
    // cursors. This first contract accepts the event/operation cursors returned
    // by sync/backfill and sync/subscribe.
    if from_cursor
        .as_deref()
        .is_some_and(|cursor| cursor.starts_with("cx:cursor:"))
        || to_cursor
            .as_deref()
            .is_some_and(|cursor| cursor.starts_with("cx:cursor:"))
    {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "gap backfill currently expects event cursors, not sync tokens",
        );
        return;
    }

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
pub async fn snapshot_head(depot: &mut Depot, req: &mut Request, res: &mut Response) {
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
pub async fn snapshot_chunk(depot: &mut Depot, req: &mut Request, res: &mut Response) {
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
