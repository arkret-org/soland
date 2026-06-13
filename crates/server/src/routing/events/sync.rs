//! Account aggregate + snapshot handlers + the cursor-helper machinery they share
//! with events and device-message modules.
//!
//! Surfaces for the current sync/event wire layout:
//! - `GET  /_cokret/self/account/describe`
//! - `GET  /_cokret/self/account/subscribe`       — `ck.self.account.stream.subscribe`
//!   (account-aggregate NDJSON: timeline, presence, typing, to_device).
//! - `POST /_cokret/self/ephemeral`               — `ck.self.ephemeral.command.send` (broadcast
//!   ephemeral)
//! - `GET  /_cokret/self/events/subscribe`        — `ck.self.events.stream.subscribe`. Multi-Realm
//!   / multi-actor stream; frame `kind` field replaces `type`.
//! - `GET  /_cokret/self/events`                  — `ck.self.events.query.scan` (replaces
//!   `ck.events.list` + `ck.sync.backfill` via `direction=forward|backward`).
//! - `GET  /_cokret/self/sync/backfill/gap`       — `ck.sync.backfill_gap` (deployment-local; not
//!   in spec)
//! - `GET  /_cokret/self/snapshot/head`
//! - `GET  /_soland/self/sync/snapshot-chunk`
//!
//! `SyncCursor`, `SyncCursorError`, `parse_and_validate_sync_cursor`,
//! `decode_sync_cursor_value`, `sync_token_for_client_sync`, `sync_filter_digest`,
//! are `pub` because sibling routing modules reuse them. They
//! live here because the cursor lifecycle is sealed to account subscribe.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use chrono::{DateTime, Duration as ChronoDuration, SecondsFormat, Utc};
use cokret_sdk::http::EventsQueryOutcome;
use cokret_sdk::lattice::CellState;
use cokret_sdk::{EphemeralSubmitOutcome, PresenceStatus, RealmId};
use futures_util::stream::StreamExt;
use salvo::http::{StatusCode, header};
use salvo::prelude::*;
use serde_json::{Value, json};
use tokio::sync::broadcast::error::RecvError;

use super::projection::{
    actor_erased_in_realm, retention_tombstone_for_event, tombstone_timeline_event_for_retention,
    tombstone_timeline_event_value,
};
use super::{
    TO_DEVICE_PAGE_LIMIT, augment_timeline_message_json, authenticated_session,
    backfill_gap_events, default_discussion_track, device_message_envelopes_after,
    flow_id_from_realm_id, flow_projection_for_realm, is_realm_deleted, now, parse_snapshot_ref,
    projected_event_page, projection_event_json, prune_expired_typing, query_param,
    realm_discoverability, realm_event_visible_to_session, realm_has_member,
    realm_history_visibility, realm_id_accessible, realm_visible_to, render_error, sha256_hex,
    snapshot_bundle_for_realm, snapshot_manifest_for_realm,
    sync_timeline_message_json_with_projection, truncate_gap_events, typing_ephemeral_for_realm,
    validate_did,
};
use crate::ids;
use crate::persistence::SyncCursorRecord;
use crate::reducer::ProjectionState;
use crate::state::{
    AppState, HandleClaimDigestInput, HandleClaimEvidenceRecord, PresenceRecord,
    ProjectionEventRecord, RealmDirectoryEntry, RealmMetaRecord, SessionRecord, TypingRecord,
};
use crate::wire::{EventsQueryPostRequestBody, SyncDescription, SyncRequestBody};

const TIMELINE_POSITION_SUBTICKS: i64 = 1024;
const PERSONAL_BLOCKLIST_DATA_TYPES: &[&str] = &["ck.account.blocklist", "ck.account.blocklist.v1"];
const PRESENCE_ONLINE_TTL_SECONDS: i64 = 3;
const HANDLE_CLAIMS_INLINE_MAX_BYTES: usize = 8 * 1024;

pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(Router::with_path("account/describe").get(account_describe))
        .push(Router::with_path("account/subscribe").get(account_subscribe))
        .push(Router::with_path("account/cursor/revoke").post(account_cursor_revoke))
        .push(Router::with_path("ephemeral").post(submit_ephemeral))
        .push(Router::with_path("snapshot/head").get(snapshot_head))
}

pub(super) fn legacy_router() -> Router {
    Router::new()
        .push(Router::with_path("account/describe").get(account_describe))
        .push(Router::with_path("account/subscribe").get(account_subscribe))
        .push(Router::with_path("account/cursor/revoke").post(account_cursor_revoke))
        .push(Router::with_path("ephemeral").post(submit_ephemeral))
        .push(Router::with_path("sync/backfill/gap").get(sync_gap_backfill))
        // Product-face dev snapshot head: serves the deployment-local dev
        // bundle descriptor. The protocol `ck.self.snapshot.query.manifest_head` (manifest
        // contract) is NOT implemented and fails closed on `/_cokret/`.
        .push(Router::with_path("sync/snapshot-head").get(snapshot_head_dev))
        .push(Router::with_path("sync/snapshot-chunk").get(snapshot_chunk))
}

fn scope_selector_to_realm_id(value: &str) -> Result<String, crate::error::AppError> {
    if RealmId::new(value.to_owned()).is_ok() {
        return Ok(value.to_owned());
    }
    Err(crate::error::AppError::invalid_param("invalid realm_id"))
}

fn normalize_scope_selectors(values: Vec<String>) -> Result<Vec<String>, crate::error::AppError> {
    values
        .into_iter()
        .map(|value| scope_selector_to_realm_id(&value))
        .collect()
}

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "account_describe"))]
async fn account_describe(depot: &mut Depot) -> crate::result::JsonResult<SyncDescription> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let supported_sync_profiles = vec![
        "initial".to_owned(),
        "incremental".to_owned(),
        "board".to_owned(),
        "chat".to_owned(),
        "topic".to_owned(),
        "offline_queue_flush".to_owned(),
        "backfill_gap".to_owned(),
        "bottom_cell_repair".to_owned(),
    ];
    let service_did = validate_did(&state.config.service_did).map_err(|_| {
        crate::error::AppError::internal("configured service_did is not a valid DID")
    })?;
    crate::result::json_ok(SyncDescription {
        service_did,
        supported_sync_profiles,
        limits: json!({
            "max_realms": 50,
            "max_timeline_events": 100,
            "offline_flush_endpoint": "/_cokret/self/events",
            "backfill_endpoint": "/_cokret/self/sync/backfill/gap",
            "bottom_repair_endpoint": "/_soland/admin/realms/{realm_id}/bottom/{cell_id}/repair"
        }),
        // SDK `SyncDescription.frontier` is an opaque cursor string; hand out
        // the current sync token so callers can seed `after` from describe.
        frontier: Some(sync_token_for_state(state).await),
    })
}

/// Default long-poll window for incremental `account/subscribe` requests
/// that find the delta empty after building the initial snapshot. Clients
/// can override with `max_wait_ms=<N>`; `max_wait_ms=0` opts out and
/// preserves the immediate-return behavior expected by older tests.
const ACCOUNT_SUBSCRIBE_DEFAULT_WAIT_MS: u64 = 25_000;
/// Hard ceiling on the long-poll window. Matches `events_subscribe`'s
/// `max_duration_ms` cap so an idle stream cannot live forever and tie up
/// connection slots.
const ACCOUNT_SUBSCRIBE_MAX_WAIT_MS: u64 = 60_000;
/// Default reconnect guard advertised on subscribe terminal control frames.
const SUBSCRIBE_RECONNECT_AFTER_MS: u64 = 10_000;
/// SOL-02-005 — debounce window for `account_subscribe` long-poll wakeups.
/// When a broadcast notification passes the visibility filter, further
/// notifications arriving within this window are drained and coalesced so a
/// burst of N broadcasts triggers ONE snapshot rebuild instead of N. Keeps
/// the read-amplification of busy Realms bounded at the cost of up to this
/// much extra delivery latency per long-poll turn.
const SUBSCRIBE_REBUILD_DEBOUNCE_MS: u64 = 150;
/// Maximum lifetime of an issued sync cursor (mirrors the 1h TTL minted by
/// [`sync_token_for_client_sync`]). A revocation record is retained for at
/// least this long so a leaked cursor cannot outlive its revocation.
const CURSOR_MAX_TTL_SECONDS: i64 = 3600;

#[endpoint(
    operation_id = "ck.self.account.stream.subscribe",
    tags("sync"),
    summary = "Account-aggregate subscribe stream (timeline / presence / typing / to_device)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.account.stream.subscribe"))]
async fn account_subscribe(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected").clone();
    let body = account_subscribe_query(req);
    let max_wait_ms = parse_max_wait_ms(req);
    let session = authenticated_session(&state, req).await.ok();
    let filter_value = sync_filter_value(body.filter.as_ref());
    let subscribe_scope_key = account_subscribe_scope_key(req, session.as_ref(), &body);
    if reject_subscribe_reconnect(&state, &subscribe_scope_key, res) {
        return;
    }
    let after_cursor = if let Some(after) = body.after.as_deref() {
        match parse_and_validate_sync_cursor(
            after,
            &state,
            session.as_ref(),
            filter_value.as_ref(),
            chrono::Utc::now().timestamp_millis(),
        )
        .await
        {
            Ok(cursor) => cursor,
            Err(SyncCursorError::Expired) => {
                crate::error::render_error_code(
                    crate::error::ErrorCode::CursorExpired,
                    res,
                    "cursor has expired",
                );
                return;
            }
            Err(SyncCursorError::Invalid(message)) => {
                crate::error::render_error_code(
                    crate::error::ErrorCode::InvalidParam,
                    res,
                    message,
                );
                return;
            }
            Err(SyncCursorError::Mismatch(message)) | Err(SyncCursorError::Integrity(message)) => {
                crate::error::render_error_code(
                    crate::error::ErrorCode::CursorIntegrityInvalid,
                    res,
                    message,
                );
                return;
            }
            Err(SyncCursorError::Revoked) => {
                crate::error::render_error_code(
                    crate::error::ErrorCode::CursorRevoked,
                    res,
                    "cursor authority has been revoked",
                );
                return;
            }
        }
    } else {
        SyncCursor::default()
    };
    // Forward-progress cleanup: presenting a valid cursor proves the client
    // persisted it, so every strictly-older handle row for this stream is
    // superseded and can go. Keeps the durable table at ~2 rows per active
    // (principal, device, filter) stream. Best-effort.
    if let (Some(session), Some(presented_issued_at_ms)) =
        (session.as_ref(), after_cursor.issued_at_ms)
    {
        let _ = state
            .persistence
            .sync_cursors()
            .prune_stream_superseded(
                &session.actor,
                &session.device_id,
                &sync_filter_digest(filter_value.as_ref()),
                presented_issued_at_ms,
            )
            .await;
    }
    if let Some(presence) = body.set_presence.as_ref() {
        let Some(session) = session.as_ref() else {
            crate::error::render_error_code(
                crate::error::ErrorCode::Unauthenticated,
                res,
                "set_presence requires authentication",
            );
            return;
        };
        if let Err(error) = state
            .persistence
            .presence()
            .put(PresenceRecord {
                actor: session.actor.clone(),
                status: presence_status_wire(presence).to_owned(),
                updated_at: chrono::Utc::now(),
            })
            .await
        {
            tracing::error!(%error, "failed to persist presence");
        }
    }
    prune_expired_typing(&state).await;

    // Subscribe to broadcast BEFORE building the initial snapshot so an
    // event landing between snapshot-build and long-poll subscribe is not
    // missed.
    let mut rx = state.event_broadcast.subscribe();
    let mut response = build_sync_snapshot(&state, session.as_ref(), &body, &after_cursor).await;
    let mut control_frame: Option<Value> = None;

    // Long-poll only when the client supplied an `after` cursor (true
    // incremental sync) AND the snapshot is delta-empty. Full sync always
    // returns immediately because the client needs the baseline. A
    // `max_wait_ms=0` opt-out preserves the legacy immediate-return
    // behavior for tests / clients that handle their own polling cadence.
    if body.after.is_some() && max_wait_ms > 0 && delta_is_empty(&response) {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(max_wait_ms);
        loop {
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(deadline) => break,
                recv = rx.recv() => {
                    match recv {
                        Ok(notification) => {
                            // Filter on realms visible to the current session.
                            // For non-event notifications (epoch/frontier/etc.)
                            // we still rebuild so the client picks up control
                            // state on its next delta if it surfaces there.
                            if !realm_id_accessible(&state, &notification.realm_id, session.as_ref()).await {
                                continue;
                            }
                            // SOL-02-005 debounce: drain notifications that
                            // arrive within the coalescing window (bounded by
                            // the long-poll deadline) so a broadcast burst
                            // rebuilds the snapshot once. Coalesced
                            // notifications need no individual handling — the
                            // rebuilt snapshot covers everything visible.
                            let mut lagged_during_drain = false;
                            let drain_until = (tokio::time::Instant::now()
                                + Duration::from_millis(SUBSCRIBE_REBUILD_DEBOUNCE_MS))
                            .min(deadline);
                            loop {
                                tokio::select! {
                                    biased;
                                    _ = tokio::time::sleep_until(drain_until) => break,
                                    more = rx.recv() => match more {
                                        Ok(_) => {}
                                        Err(RecvError::Lagged(_)) => {
                                            lagged_during_drain = true;
                                            break;
                                        }
                                        Err(RecvError::Closed) => break,
                                    }
                                }
                            }
                            response = build_sync_snapshot(&state, session.as_ref(), &body, &after_cursor).await;
                            if !delta_is_empty(&response) {
                                break;
                            }
                            if lagged_during_drain {
                                // Same terminal handling as the direct
                                // `Lagged` arm below: gate reconnect and
                                // close with a control frame.
                                arm_subscribe_reconnect(&state, &subscribe_scope_key, SUBSCRIBE_RECONNECT_AFTER_MS);
                                control_frame = Some(account_reconnect_control_frame(
                                    body.after.as_deref(),
                                    "broadcast_lagged",
                                    SUBSCRIBE_RECONNECT_AFTER_MS,
                                ));
                                break;
                            }
                        }
                        Err(RecvError::Lagged(_)) => {
                            // We lost some notifications; rebuild and let the
                            // delta speak for itself. If the rebuilt delta is
                            // still empty, close with a terminal control frame
                            // and gate immediate reconnect for the same scope.
                            response = build_sync_snapshot(&state, session.as_ref(), &body, &after_cursor).await;
                            if !delta_is_empty(&response) {
                                break;
                            }
                            arm_subscribe_reconnect(&state, &subscribe_scope_key, SUBSCRIBE_RECONNECT_AFTER_MS);
                            control_frame = Some(account_reconnect_control_frame(
                                body.after.as_deref(),
                                "broadcast_lagged",
                                SUBSCRIBE_RECONNECT_AFTER_MS,
                            ));
                            break;
                        }
                        Err(RecvError::Closed) => break,
                    }
                }
            }
        }
    }

    let frames = if let Some(control_frame) = control_frame {
        vec![ndjson_line(&control_frame)]
    } else {
        let cursor = response.cursor.clone();
        let mut frames = vec![ndjson_line(&account_delta_frame(response))];
        if body.catchup.unwrap_or(false) {
            frames.push(ndjson_line(&json!({
                "kind": "catchup_complete",
                "cursor": cursor,
            })));
        }
        frames
    };

    let body_stream = async_stream::stream! {
        for frame in frames {
            yield Ok::<Bytes, std::io::Error>(frame);
        }
    };
    let _ = res.add_header("content-type", "application/x-ndjson", true);
    res.stream(body_stream.boxed());
}

/// `POST /_cokret/self/account/cursor/revoke` — `ck.self.account.command.revoke_cursor`.
///
/// High-assurance optional endpoint: record a previously issued cursor
/// authority in the revocation set until its maximum TTL would have elapsed.
/// A revoked cursor thereafter returns `cursor_revoked` from
/// [`parse_and_validate_sync_cursor`] and never advances to-device ack,
/// account-subscribe resume position, wait-for barrier state, or dropped
/// recovery state. `revoke_scope` controls breadth (`this_cursor` default,
/// `same_device`, `same_session`).
#[endpoint(
    operation_id = "ck.self.account.command.revoke_cursor",
    tags("sync"),
    summary = "Revoke a previously issued cursor authority",
    status_codes(200, 400, 401, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.account.command.revoke_cursor"))]
async fn account_cursor_revoke(
    aa: crate::routing::system::extract::AuthArgs,
    body: salvo::oapi::extract::JsonBody<cokret_sdk::AccountCursorRevokeRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<cokret_sdk::AccountCursorRevokeOutcome> {
    use crate::error::AppError;
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();

    let cursor = body.cursor.trim();
    if !cursor.starts_with("ck:cursor:") || cursor.len() <= "ck:cursor:".len() {
        return Err(AppError::invalid_param("cursor must be a ck:cursor token"));
    }
    let reason_code = body.reason_code.trim();
    if reason_code.is_empty() {
        return Err(AppError::invalid_param("reason_code is required"));
    }
    let scope = body.revoke_scope;
    let scope_value = match scope {
        cokret_sdk::CursorRevokeScope::ThisCursor => "this_cursor",
        cokret_sdk::CursorRevokeScope::SameDevice => "same_device",
        cokret_sdk::CursorRevokeScope::SameSession => "same_session",
    };

    let revoked_at = now();
    let expires_at = revoked_at + ChronoDuration::seconds(CURSOR_MAX_TTL_SECONDS);
    let device_id = if matches!(scope, cokret_sdk::CursorRevokeScope::ThisCursor) {
        None
    } else {
        Some(session.device_id.clone())
    };
    let record = crate::state::CursorRevocation {
        cursor_digest: sha256_hex(cursor.as_bytes()),
        principal_id: session.actor.clone(),
        device_id,
        scope: scope_value.to_owned(),
        reason_code: reason_code.to_owned(),
        revoked_at,
        expires_at,
    };
    // Durable first (fail-closed): a revocation that is only cached in
    // memory would silently un-revoke on the next restart, which defeats
    // the high-assurance purpose of this endpoint. Only after the ledger
    // write succeeds do we update the in-memory cache that
    // `cursor_authority_revoked` consults.
    state
        .persistence
        .sync_cursors()
        .record_revocation(&record)
        .await
        .map_err(|error| {
            AppError::internal(format!("failed to persist cursor revocation: {error}"))
        })?;
    {
        let now_ms = revoked_at.timestamp_millis();
        let mut revocations = state
            .sync_cursor_revocations
            .lock()
            .expect("sync cursor revocations lock");
        revocations.retain(|entry| entry.expires_at.timestamp_millis() > now_ms);
        revocations.push(record);
    }

    crate::json_ok(cokret_sdk::AccountCursorRevokeOutcome {
        revoked: true,
        expires_at,
        revoke_scope_effective: Some(scope),
    })
}

/// Returns `true` when `token` (or the authenticated session it is bound to)
/// has an active revocation recorded by [`account_cursor_revoke`]. Prunes
/// entries past their GC horizon as a side effect.
fn cursor_authority_revoked(
    state: &AppState,
    token: &str,
    session: Option<&SessionRecord>,
    now_ms: i64,
) -> bool {
    let mut revocations = state
        .sync_cursor_revocations
        .lock()
        .expect("sync cursor revocations lock");
    revocations.retain(|entry| entry.expires_at.timestamp_millis() > now_ms);
    if revocations.is_empty() {
        return false;
    }
    let digest = sha256_hex(token.as_bytes());
    revocations.iter().any(|entry| match entry.scope.as_str() {
        "this_cursor" => entry.cursor_digest == digest,
        // soland's stateful cursor binds (principal, device); `same_session`
        // is enforced at the same granularity as `same_device`.
        "same_device" | "same_session" => session.is_some_and(|session| {
            entry.principal_id == session.actor
                && entry.device_id.as_deref() == Some(session.device_id.as_str())
        }),
        _ => false,
    })
}

fn parse_max_wait_ms(req: &mut Request) -> u64 {
    query_param(req, "max_wait_ms")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(ACCOUNT_SUBSCRIBE_DEFAULT_WAIT_MS)
        .min(ACCOUNT_SUBSCRIBE_MAX_WAIT_MS)
}

/// A snapshot is "delta-empty" when an incremental sync would carry no
/// new realm state, no membership departure, no queued device messages,
/// and no presence ticks. `account_data` is intentionally excluded — it
/// is always emitted in full for authenticated sessions today, so it
/// would defeat long-poll entirely.
fn delta_is_empty(response: &cokret_sdk::model::SyncOutcome) -> bool {
    response.realms.is_empty()
        && response.left_realms.is_empty()
        && response.to_device.is_empty()
        && response.to_device_lost != Some(true)
        && response.presence.is_empty()
}

fn account_subscribe_query(req: &mut Request) -> SyncRequestBody {
    SyncRequestBody {
        after: query_param(req, "after"),
        catchup: query_param(req, "catchup").and_then(|value| value.parse::<bool>().ok()),
        filter: query_param(req, "filter").and_then(|value| serde_json::from_str(&value).ok()),
        set_presence: query_param(req, "set_presence").and_then(|value| match value.as_str() {
            "online" => Some(PresenceStatus::Online),
            "offline" => Some(PresenceStatus::Offline),
            "unavailable" => Some(PresenceStatus::Unavailable),
            _ => None,
        }),
        subscriptions: None,
        wait_for: None,
    }
}

fn sync_filter_value(filter: Option<&cokret_sdk::SyncFilter>) -> Option<Value> {
    filter.and_then(|filter| serde_json::to_value(filter).ok())
}

fn presence_status_wire(status: &PresenceStatus) -> &'static str {
    match status {
        PresenceStatus::Online => "online",
        PresenceStatus::Offline => "offline",
        PresenceStatus::Unavailable => "unavailable",
    }
}

fn account_delta_frame(response: cokret_sdk::model::SyncOutcome) -> Value {
    let mut to_device = json!({"messages": response.to_device});
    if let Some(object) = to_device.as_object_mut() {
        if let Some(ack_token) = response.to_device_ack_token {
            object.insert("ack_token".to_owned(), json!(ack_token));
        }
        if response.to_device_limited {
            object.insert("limited".to_owned(), json!(true));
        }
        if let Some(next_cursor) = response.to_device_next_cursor {
            object.insert("next_cursor".to_owned(), json!(next_cursor));
        }
        if let Some(lost) = response.to_device_lost {
            object.insert("lost".to_owned(), json!(lost));
        }
    }
    json!({
        "kind": "delta",
        "cursor": response.cursor,
        "realms": response.realms,
        "to_device": to_device,
        "device_lists": response.device_lists,
        "account_data": {"events": response.account_data},
        "presence": {"events": response.presence},
        "notifications": response.notifications,
        "partial": response.partial,
    })
}

fn account_reconnect_control_frame(
    after: Option<&str>,
    reason: impl Into<String>,
    reconnect_after_ms: u64,
) -> Value {
    let reason = reason.into();
    match after {
        Some(cursor) if !cursor.is_empty() => json!({
            "kind": "dropped",
            "cursor": cursor,
            "reason": reason,
            "reconnect_after_ms": reconnect_after_ms,
        }),
        _ => json!({
            "kind": "resync_required",
            "reason": reason,
            "reconnect_after_ms": reconnect_after_ms,
        }),
    }
}

fn account_subscribe_scope_key(
    req: &Request,
    session: Option<&SessionRecord>,
    body: &SyncRequestBody,
) -> String {
    let filter_value = sync_filter_value(body.filter.as_ref());
    format!(
        "ck.self.account.stream.subscribe|{}|filter={}",
        subscribe_subject(req, session),
        sync_filter_digest(filter_value.as_ref())
    )
}

fn roster_member_actor_id(member: &Value) -> Option<String> {
    member
        .get("actor_id")
        .or_else(|| member.get("actor"))
        .or_else(|| member.get("did"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|actor| !actor.is_empty())
        .map(ToOwned::to_owned)
}

async fn presence_events_for_actors(state: &AppState, actors: BTreeSet<String>) -> Vec<Value> {
    let mut events = Vec::new();
    for actor in actors {
        if let Ok(Some(record)) = state.persistence.presence().get(&actor).await {
            events.push(presence_sync_event_json(record));
        }
    }
    events
}

fn presence_sync_event_json(record: PresenceRecord) -> Value {
    let is_stale_online = record.status == "online"
        && now().signed_duration_since(record.updated_at)
            > ChronoDuration::seconds(PRESENCE_ONLINE_TTL_SECONDS);
    let status = if is_stale_online {
        "offline".to_owned()
    } else {
        record.status.clone()
    };
    let mut event = json!({
        "user_id": record.actor,
        "actor_id": record.actor,
        "presence": status,
        "status": status,
        "updated_at": record.updated_at,
    });
    if is_stale_online && let Some(object) = event.as_object_mut() {
        object.insert("last_active".to_owned(), json!(record.updated_at));
    }
    event
}

/// Build one snapshot of the account-aggregate sync response for the next
/// `ck.self.account.stream.subscribe` delta frame.
async fn build_sync_snapshot(
    state: &AppState,
    session: Option<&SessionRecord>,
    body: &SyncRequestBody,
    after_cursor: &SyncCursor,
) -> cokret_sdk::model::SyncOutcome {
    let filter_value = sync_filter_value(body.filter.as_ref());
    // SYNC-MEM-1 + ROST-SOL-1..3 (cokret-spec @ b56cab1) — `members[]` is
    // the per-Realm roster v2 projection from
    // `account-subscribe-frame.schema.json#/$defs/member_roster_entry`. Each
    // row carries `{actor_id, membership, subject_id?, identity_event_ids?,
    // member_display_state_digest?, identity_events?, handle_claim_digests?,
    // handle_claims?, handle_claims_limited?}` — `handle` / display name MUST
    // NOT appear here. Identity is resolved by following
    // `identity_event_ids[]` into the separately delivered
    // `ck.member.identity.update` event log; servers that lack the events for
    // the client SHOULD inline them via `identity_events[]` (gated on
    // `subject_id` disclosure).
    let candidate_realms: Vec<RealmDirectoryEntry> = {
        let realms = state.realms.lock().expect("realms lock");
        realms
            .search(Default::default())
            .into_iter()
            .cloned()
            .collect()
    };
    let mut visible_realms: Vec<(String, String, Option<String>, _, Option<String>, _)> =
        Vec::new();
    for realm_entry in &candidate_realms {
        if realm_visible_to(state, realm_entry, session).await {
            let members = roster_members_for_realm(state, realm_entry, session, body);
            visible_realms.push((
                realm_entry.realm_id.to_string(),
                realm_entry.title.clone(),
                realm_entry.description.clone(),
                realm_entry.tags.clone(),
                realm_entry.category.clone(),
                members,
            ));
        }
    }
    // Compute "left after last cursor" so incremental syncs can prune
    // client-side caches without forcing a full account baseline.
    // On full sync (no `after` cursor -> empty `after_cursor.positions`)
    // there is nothing to compare against; the client already treats
    // omission from `realms` as authoritative there.
    let visible_realm_ids: BTreeSet<&str> =
        visible_realms.iter().map(|(id, ..)| id.as_str()).collect();
    let left_realms: Vec<String> = if body.after.is_some() {
        after_cursor
            .positions
            .keys()
            .filter(|id| !visible_realm_ids.contains(id.as_str()))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    drop(visible_realm_ids);

    let mut presence_actors = BTreeSet::new();
    for (_, _, _, _, _, members) in &visible_realms {
        for member in members {
            if let Some(actor) = roster_member_actor_id(member) {
                presence_actors.insert(actor);
            }
        }
    }
    let presence = if body.after.is_none() {
        presence_events_for_actors(state, presence_actors).await
    } else {
        Vec::new()
    };

    // Clone the projection so the per-Realm loop below can `.await` async
    // visibility/timeline helpers without holding the (non-Send) lock guard
    // across a suspension point.
    let projection = state.projection.lock().expect("projection lock").clone();
    let mut sync_realms = std::collections::BTreeMap::new();
    let mut timeline_positions = BTreeMap::new();
    let mut account_positions = BTreeMap::new();
    let is_incremental = body.after.is_some();
    for (realm_id, title, summary, tags, category, members) in visible_realms {
        let flow = flow_projection_for_realm(state, &realm_id, &title, summary.as_deref()).await;
        let flow_state_after = flow.clone();
        let flow_list_item = flow.clone();
        let summary_members = members.clone();
        let meta = state
            .persistence
            .realm_meta()
            .get(&realm_id)
            .await
            .ok()
            .flatten();
        let history_visibility = meta
            .as_ref()
            .map(|record| record.history_visibility.clone())
            .unwrap_or_else(|| "shared".to_owned());
        let encryption_profile = meta
            .as_ref()
            .and_then(|record| record.encryption_profile.clone())
            .unwrap_or_else(|| "none".to_owned());
        let known_timeline_to_cursor = after_cursor.positions.contains_key(&realm_id);
        let known_account_to_cursor = after_cursor.account_positions.contains_key(&realm_id);
        let after_timeline_position = after_cursor
            .positions
            .get(&realm_id)
            .copied()
            .unwrap_or_default();
        let after_account_position = after_cursor
            .account_positions
            .get(&realm_id)
            .copied()
            .unwrap_or_default();
        let (timeline_events, timeline_position) = timeline_events_for_realm(
            state,
            &projection,
            &realm_id,
            after_timeline_position,
            session,
        )
        .await;
        let account_position = account_realm_projection_position(meta.as_ref(), &realm_id);
        timeline_positions.insert(realm_id.clone(), timeline_position);
        account_positions.insert(realm_id.clone(), account_position);
        let account_projection_changed = if known_account_to_cursor {
            account_position != after_account_position
        } else {
            account_position > after_timeline_position
        };
        // Incremental sync skips realms whose visible account-aggregate
        // projection is unchanged. This drops the always-full
        // `summary`/`flows`/`state_after`/`members` baseline from idle polls
        // while still minting a cursor that advances internal frontiers.
        //
        // Timeline and account projection positions are separate cursor
        // vectors. Visible timeline events drive `positions.realms`; Realm /
        // Flow metadata drives `positions.account_realms`. Keeping them
        // separate prevents a metadata-only position from masking a later
        // visible timeline event, and lets hidden timeline advancement move
        // the cursor without emitting an empty Realm projection.
        //
        // Caveats: membership changes that don't bump a projection position
        // (e.g. raw `ck.realm.member.update` events) will not propagate through
        // an incremental sync until either (a) a new timeline event arrives,
        // or (b) the client issues a full sync (no `after`). This is a known
        // limitation — see follow-up TODO to add per-realm activity tracking
        // off `event_broadcast`.
        if is_incremental
            && known_timeline_to_cursor
            && timeline_events.is_empty()
            && !account_projection_changed
        {
            continue;
        }
        let bottom_cells = bottom_cells_for_realm(&projection, &realm_id);
        let seal_view = seal_view_for_realm(&bottom_cells);
        let ephemeral = typing_ephemeral_for_realm(state, &realm_id, session).await;
        sync_realms.insert(
            realm_id.clone(),
            json!({
                "summary": {
                    "flow": flow,
                    "title": title,
                    "summary": summary,
                    "tags": tags,
                    "category": category,
                    "members": summary_members,
                    // SYNC-MEM-2/4 — mirror `members_limited` so the two
                    // `members` views stay byte-equal.
                    "members_limited": false,
                    "history_visibility": history_visibility.clone(),
                    "encryption_profile": encryption_profile.clone(),
                },
                "history_visibility": history_visibility,
                "encryption_profile": encryption_profile,
                "members": members,
                // SYNC-MEM-2 (cokret-spec @ 7157ee8) — `members_limited`
                // is always `false` until lazy-load truncation lands; the
                // spec requires the flag to be present so clients can tell
                // a small roster from a truncated one.
                "members_limited": false,
                "flows": [flow_list_item],
                "timeline": {"events": timeline_events, "limited": false},
                "state": [],
                "state_after": {"events": [flow_state_after]},
                "bottom_cells": bottom_cells,
                "seal_view": seal_view,
                "ephemeral": ephemeral,
                "unread": {"notification_count": 0, "highlight_count": 0}
            }),
        );
    }
    drop(projection);

    let mut to_device_position = after_cursor.to_device_position;
    let mut to_device_ack_token = None;
    let mut to_device_limited = false;
    let mut to_device_next_cursor = None;
    let to_device = if let Some(session) = session {
        let queued = state
            .persistence
            .device_messages()
            .list_after(&session.actor, &session.device_id, 0)
            .await
            .unwrap_or_default();
        to_device_limited = queued.len() > TO_DEVICE_PAGE_LIMIT;
        let page = queued
            .into_iter()
            .take(TO_DEVICE_PAGE_LIMIT)
            .collect::<Vec<_>>();
        let events = device_message_envelopes_after(&page)
            .into_iter()
            .filter_map(|message| serde_json::to_value(message).ok())
            .collect::<Vec<_>>();
        if let Some(max_position) = page.iter().map(|message| message.position).max() {
            to_device_position = max_position;
            to_device_ack_token = state
                .persistence
                .device_messages()
                .issue_ack_token(&session.actor, &session.device_id, to_device_position)
                .await
                .ok()
                .flatten();
            if to_device_limited {
                to_device_next_cursor = Some(
                    sync_token_for_client_sync(
                        state,
                        Some(session),
                        filter_value.as_ref(),
                        BTreeMap::new(),
                        BTreeMap::new(),
                        to_device_position,
                    )
                    .await,
                );
            }
        }
        events
    } else {
        Vec::new()
    };

    // Actor-private account data: hydrate every `(actor, data_type)` row
    // owned by the authenticated session so the client can join e.g.
    // `ck.contacts.realm.<realm_id>` Realm remarks against the public
    // Realm title during render. Spec: discovery/client-preferences.md
    // §2 (storage model) / §3.7 (Realm remarks).
    let account_data = if let Some(session) = session {
        state
            .persistence
            .account_data()
            .list_for_actor(&session.actor)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|record| {
                json!({
                    "data_type": record.data_type,
                    "content": record.payload,
                    "updated_at": record.updated_at,
                })
            })
            .collect()
    } else {
        Vec::new()
    };

    cokret_sdk::model::SyncOutcome {
        cursor: sync_token_for_client_sync(
            state,
            session,
            filter_value.as_ref(),
            timeline_positions,
            account_positions,
            to_device_position,
        )
        .await,
        realms: sync_realms,
        left_realms,
        to_device,
        to_device_ack_token,
        to_device_limited,
        to_device_next_cursor,
        to_device_lost: None,
        device_lists: json!({"changed": [], "left": []}),
        account_data,
        presence,
        notifications: serde_json::Value::Null,
        partial: false,
    }
}

/// SYNC-MEM-1..4 + ROST-SOL-1..3 (cokret-spec @ b56cab1) — build the
/// per-Realm `members[]` roster v2 projection from the in-memory
/// `RealmDirectoryEntry` plus the MemberIdentity registry.
///
/// Schema source:
/// `account-subscribe-frame.schema.json#/$defs/member_roster_entry`. Each
/// row carries `{actor_id, membership, subject_id?, identity_event_ids?,
/// member_display_state_digest?, identity_events?, handle_claim_digests?,
/// handle_claims?, handle_claims_limited?}`. The retired R3 shape
/// `{did, handle_uri?}` is gone and the R3.1 roster digest field is renamed
/// to `member_display_state_digest` (R3.2). `handle` / display
/// name MUST NOT appear here; handle strings may only ride inside signed
/// `handle_claims[]`.
///
/// R3.2 dependentRequired (ROST-SOL-2): the disclosure-gated fields
/// (`subject_id` plus its companions `identity_events` / `handle_claim_digests`
/// / `handle_claims` / `handle_claims_limited`) MUST be omitted together
/// unless `subject_id` is disclosed by Realm policy. Clients resolve
/// identity by following `identity_event_ids[]` into the separately
/// delivered `ck.member.identity.update` event log; SYNC-MEM-3 inlines the
/// original envelopes only when `subject_id` is disclosed.
///
/// MIU-SOL-4: the effective set is multi-valued (no last-writer-wins); ALL
/// effective `identity_event_ids[]` are listed.
fn roster_members_for_realm(
    state: &AppState,
    realm_entry: &crate::state::RealmDirectoryEntry,
    session: Option<&SessionRecord>,
    body: &SyncRequestBody,
) -> Vec<Value> {
    let registry = state.member_identity_registry();
    let context = RosterDisclosureContext::new(state, realm_entry, session, body);
    realm_entry
        .members
        .iter()
        .map(|did| {
            let did_str = did.as_str();
            let mut entry = serde_json::Map::new();
            entry.insert("actor_id".to_owned(), json!(did_str));
            // Wire-side membership state. We do not currently project
            // invite/knock distinct from join in `RealmDirectoryEntry`; the
            // structured FSM lives in `ProjectionState::members` and
            // bare-`members` set here represents "join" rows.
            entry.insert("membership".to_owned(), json!("join"));
            if let Some(snapshot) =
                registry.snapshot_for_actor(realm_entry.realm_id.as_str(), did_str)
            {
                if !snapshot.identity_event_ids.is_empty() {
                    entry.insert(
                        "identity_event_ids".to_owned(),
                        json!(snapshot.identity_event_ids),
                    );
                }
                // ROST-SOL-1 — roster digest field rename to
                // `member_display_state_digest`. NOT disclosure-gated.
                if let Some(digest) = snapshot.member_display_state_digest {
                    entry.insert("member_display_state_digest".to_owned(), json!(digest));
                }
                // ROST-SOL-2 — `subject_id` is disclosed only when Realm
                // policy authorizes the caller to learn the principal /
                // holder DID. When disclosed, the gated companion fields MAY
                // be populated; otherwise they MUST all be omitted (the SDK
                // `MemberRosterEntry::validate` dependentRequired rule).
                if subject_disclosed_to_caller(&context, did_str)
                    && let Some(subject_id) = snapshot.subject_id.as_deref()
                {
                    entry.insert("subject_id".to_owned(), json!(subject_id));
                    // SYNC-MEM-3 — inline original Event envelopes (gated on
                    // subject disclosure per ROST-SOL-2). The reducer stores
                    // the events as received; we do NOT rewrite projection
                    // on egress.
                    if !snapshot.identity_events.is_empty() {
                        entry.insert(
                            "identity_events".to_owned(),
                            json!(snapshot.identity_events),
                        );
                    }
                    let visible_claims: Vec<HandleClaimEvidenceRecord> = registry
                        .handle_claims_for_subject(subject_id)
                        .into_iter()
                        .filter(|claim| handle_claim_visible_to_caller(&context, claim))
                        .collect();
                    if !visible_claims.is_empty() {
                        let digest_inputs: Vec<HandleClaimDigestInput> = visible_claims
                            .iter()
                            .map(|claim| HandleClaimDigestInput {
                                claim_digest: claim.digest.clone(),
                                binding_state: claim.binding_state.clone(),
                                expires_at: claim.expires_at.map(|expires_at| {
                                    expires_at.to_rfc3339_opts(SecondsFormat::Millis, true)
                                }),
                            })
                            .collect();
                        if let Some(digest) = crate::state::display_state_digest(
                            realm_entry.realm_id.as_str(),
                            did_str,
                            &snapshot.effective_entries,
                            &digest_inputs,
                        ) {
                            entry.insert("member_display_state_digest".to_owned(), json!(digest));
                        }
                        entry.insert(
                            "handle_claim_digests".to_owned(),
                            json!(
                                visible_claims
                                    .iter()
                                    .map(|claim| claim.digest.clone())
                                    .collect::<Vec<_>>()
                            ),
                        );
                        let (claims, limited) = inline_handle_claims(&visible_claims);
                        if !claims.is_empty() {
                            entry.insert("handle_claims".to_owned(), json!(claims));
                        }
                        if limited {
                            entry.insert("handle_claims_limited".to_owned(), json!(true));
                        }
                    }
                }
            }
            Value::Object(entry)
        })
        .collect()
}

struct RosterDisclosureContext<'a> {
    service_did: &'a str,
    realm_public: bool,
    realm_members: &'a BTreeSet<cokret_sdk::Did>,
    caller: Option<&'a str>,
    audience: String,
    now: DateTime<Utc>,
}

impl<'a> RosterDisclosureContext<'a> {
    fn new(
        state: &'a AppState,
        realm_entry: &'a RealmDirectoryEntry,
        session: Option<&'a SessionRecord>,
        body: &SyncRequestBody,
    ) -> Self {
        Self {
            service_did: &state.config.service_did,
            realm_public: realm_entry.public,
            realm_members: &realm_entry.members,
            caller: session.map(|session| session.actor.as_str()),
            audience: roster_handle_claim_audience(state, session, body),
            now: now(),
        }
    }

    fn caller_is_realm_member(&self) -> bool {
        self.caller.is_some_and(|caller| {
            cokret_sdk::Did::new(caller.to_owned())
                .ok()
                .is_some_and(|did| self.realm_members.contains(&did))
        })
    }
}

fn roster_handle_claim_audience(
    state: &AppState,
    session: Option<&SessionRecord>,
    body: &SyncRequestBody,
) -> String {
    let filter_value = sync_filter_value(body.filter.as_ref());
    filter_value
        .as_ref()
        .and_then(|filter| filter.get("handle_claim_audience"))
        .or_else(|| {
            filter_value
                .as_ref()
                .and_then(|filter| filter.get("audience"))
        })
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| session.map(|session| session.audience.clone()))
        .unwrap_or_else(|| state.config.service_did.clone())
}

/// ROST-SOL-2/3 — subject and companion fields disclose only when the Realm
/// policy admits the caller. Public Realms can reveal public evidence; private
/// Realms require the caller to be a member. A caller may always see their own
/// subject binding.
fn subject_disclosed_to_caller(context: &RosterDisclosureContext<'_>, actor_id: &str) -> bool {
    context.caller == Some(actor_id) || context.realm_public || context.caller_is_realm_member()
}

fn handle_claim_visible_to_caller(
    context: &RosterDisclosureContext<'_>,
    claim: &HandleClaimEvidenceRecord,
) -> bool {
    if !trusted_handle_claim_issuer(context, claim) {
        return false;
    }
    if claim.revoked || claim.binding_state != "verified" {
        return false;
    }
    if claim
        .expires_at
        .is_some_and(|expires_at| expires_at <= context.now)
    {
        return false;
    }
    if claim
        .audience
        .as_deref()
        .is_some_and(|audience| audience != context.audience)
    {
        return false;
    }
    match claim.visibility.as_deref().unwrap_or("restricted") {
        "public" => subject_disclosed_to_caller(context, &claim.subject_id),
        "members" | "restricted" => {
            context.caller == Some(claim.subject_id.as_str()) || context.caller_is_realm_member()
        }
        _ => false,
    }
}

fn trusted_handle_claim_issuer(
    context: &RosterDisclosureContext<'_>,
    claim: &HandleClaimEvidenceRecord,
) -> bool {
    claim.issuer == context.service_did
        || claim.issuer_service_did.as_deref() == Some(context.service_did)
}

fn inline_handle_claims(claims: &[HandleClaimEvidenceRecord]) -> (Vec<Value>, bool) {
    let mut used = 0usize;
    let mut out = Vec::new();
    let mut limited = false;
    for claim in claims {
        let Ok(bytes) = serde_json::to_vec(&claim.envelope) else {
            limited = true;
            continue;
        };
        if used + bytes.len() > HANDLE_CLAIMS_INLINE_MAX_BYTES {
            limited = true;
            continue;
        }
        used += bytes.len();
        out.push(claim.envelope.clone());
    }
    (out, limited)
}

async fn timeline_events_for_realm(
    state: &AppState,
    projection: &ProjectionState,
    realm_id: &str,
    after_position: i64,
    session: Option<&SessionRecord>,
) -> (Vec<serde_json::Value>, i64) {
    let mut seen = BTreeSet::new();
    let mut newest_position = after_position;
    let mut timeline_entries = Vec::new();

    for message in projection.messages_for_realm(realm_id) {
        let position = timeline_event_position(state, &message.event_id, message.created_at).await;
        newest_position = newest_position.max(position);
        if position <= after_position || !seen.insert(message.event_id.clone()) {
            continue;
        }
        if !realm_event_visible_to_session_with_projection(
            state,
            projection,
            realm_id,
            message.created_at,
            Some(&message.sender),
            session,
        )
        .await
        {
            continue;
        }
        if !circle_scope_visible_to_session(
            projection,
            message_scope_circle_id(&message.content),
            session,
            Some(&message.sender),
        ) {
            continue;
        }
        let mut event = sync_timeline_message_json_with_projection(message, projection);
        if let Some(tombstone) = retention_tombstone_for_event(state, &message.event_id) {
            tombstone_timeline_event_for_retention(&mut event, &tombstone);
        }
        timeline_entries.push((position, event));
    }

    for message in state
        .persistence
        .messages()
        .list_for_realm(realm_id, 100)
        .await
        .unwrap_or_default()
    {
        let position = timeline_event_position(state, &message.event_id, message.created_at).await;
        newest_position = newest_position.max(position);
        if position <= after_position || !seen.insert(message.event_id.clone()) {
            continue;
        }
        if !realm_event_visible_to_session_with_projection(
            state,
            projection,
            realm_id,
            message.created_at,
            Some(&message.sender),
            session,
        )
        .await
        {
            continue;
        }
        if !circle_scope_visible_to_session(
            projection,
            message_scope_circle_id(&message.content),
            session,
            Some(&message.sender),
        ) {
            continue;
        }
        let mut event = sync_timeline_message_record_json_with_projection(&message, projection);
        if let Some(tombstone) = retention_tombstone_for_event(state, &message.event_id) {
            tombstone_timeline_event_for_retention(&mut event, &tombstone);
        }
        timeline_entries.push((position, event));
    }

    timeline_entries.sort_by_key(|left| left.0);
    (
        timeline_entries
            .into_iter()
            .map(|(_, event)| event)
            .collect(),
        newest_position,
    )
}

fn account_realm_projection_position(meta: Option<&RealmMetaRecord>, realm_id: &str) -> i64 {
    meta.map(|record| timestamp_position_with_tie_breaker(record.updated_at, realm_id))
        .unwrap_or_default()
}

async fn timeline_event_position(
    state: &AppState,
    event_id: &str,
    created_at: DateTime<Utc>,
) -> i64 {
    let timestamp = state
        .persistence
        .events()
        .get(event_id)
        .await
        .ok()
        .flatten()
        .map(|record| record.received_at)
        .unwrap_or(created_at);
    timestamp_position_with_tie_breaker(timestamp, event_id)
}

fn timestamp_position_with_tie_breaker(timestamp: DateTime<Utc>, event_id: &str) -> i64 {
    timestamp
        .timestamp_micros()
        .saturating_mul(TIMELINE_POSITION_SUBTICKS)
        .saturating_add(timeline_event_tie_breaker(event_id))
}

fn timeline_event_tie_breaker(event_id: &str) -> i64 {
    ids::typed_uuid_part(event_id)
        .map(|uuid| ((uuid.as_u128() >> 64) & 0x03ff) as i64)
        .unwrap_or_default()
}

async fn realm_event_visible_to_session_with_projection(
    state: &AppState,
    projection: &ProjectionState,
    realm_id: &str,
    event_created_at: DateTime<Utc>,
    sender: Option<&str>,
    session: Option<&SessionRecord>,
) -> bool {
    if sender.is_some_and(|sender| session.is_some_and(|session| session.actor == sender)) {
        return true;
    }
    if personal_blocklist_blocks_sender_for_session(state, session, sender).await {
        return false;
    }
    match realm_history_visibility(state, realm_id).await.as_str() {
        "world_readable" => true,
        "shared" => {
            if realm_discoverability(state, realm_id).await == "public" {
                return true;
            }
            match session {
                Some(session) => realm_has_member(state, realm_id, &session.actor).await,
                None => false,
            }
        }
        "joined" | "invited" => {
            let Some(session) = session else {
                return false;
            };
            let mut joined_at = projection
                .member(realm_id, &session.actor)
                .filter(|member| member.state == "join")
                .map(|member| member.joined_at);
            if joined_at.is_none() {
                let meta = state
                    .persistence
                    .realm_meta()
                    .get(realm_id)
                    .await
                    .ok()
                    .flatten();
                if let Some(meta) = meta {
                    if meta.owner == session.actor {
                        joined_at = Some(meta.created_at);
                    }
                }
            }
            joined_at.is_some_and(|joined_at| event_created_at >= joined_at)
        }
        _ => false,
    }
}

fn bottom_cells_for_realm(projection: &ProjectionState, realm_id: &str) -> Vec<Value> {
    projection
        .cells
        .iter()
        .filter_map(|(cell, state)| {
            let CellState::Bottom(bottom) = state else {
                return None;
            };
            let cell_id = cell.as_str();
            if !cell_id.contains(realm_id) {
                return None;
            }
            Some(json!({
                "realm_id": realm_id,
                "cell_id": cell_id,
                "state": "bottom",
                "bottom": bottom,
            }))
        })
        .collect()
}

fn seal_view_for_realm(bottom_cells: &[Value]) -> Value {
    let cells = bottom_cells
        .iter()
        .filter_map(|entry| {
            let cell_id = entry.get("cell_id").and_then(Value::as_str)?;
            let bottom = entry.get("bottom")?;
            let status = match bottom.get("kind").and_then(Value::as_str) {
                Some("Conflict") | Some("conflict") => "expose",
                _ => "reject",
            };
            let heads = bottom_heads_for_sync(bottom);
            Some((
                cell_id.to_owned(),
                json!({
                    "bottom": status,
                    "heads": heads,
                    "diagnostic": bottom,
                }),
            ))
        })
        .collect::<serde_json::Map<_, _>>();
    json!({
        "frontier": [],
        "leaves": [],
        "state_root": Value::Null,
        "cells": cells,
    })
}

fn bottom_heads_for_sync(bottom: &Value) -> Vec<Value> {
    if let Some(heads) = bottom.get("heads").and_then(Value::as_array)
        && !heads.is_empty()
    {
        return heads
            .iter()
            .filter_map(|head| {
                if let Some(object) = head.as_object() {
                    let move_id = object
                        .get("move_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if move_id.is_empty() {
                        return None;
                    }
                    return Some(json!({
                        "move_id": move_id,
                        "value": object.get("value").cloned().unwrap_or(Value::Null),
                    }));
                }
                let move_id = head.as_str()?;
                Some(json!({"move_id": move_id, "value": Value::Null}))
            })
            .collect();
    }
    bottom
        .get("move_ids")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|move_id| move_id.as_str())
        .map(|move_id| json!({"move_id": move_id, "value": Value::Null}))
        .collect()
}

async fn projection_record_visible_to_session(
    state: &AppState,
    event: &ProjectionEventRecord,
    session: Option<&SessionRecord>,
) -> bool {
    realm_event_visible_to_session(
        state,
        &event.realm_id,
        event.created_at,
        event.sender.as_deref(),
        session,
    )
    .await
        && !personal_blocklist_blocks_sender_for_session(state, session, event.sender.as_deref())
            .await
}

async fn projection_event_value_visible_to_session(
    state: &AppState,
    event: &Value,
    session: Option<&SessionRecord>,
) -> bool {
    let Some(realm_id) = event.get("realm_id").and_then(Value::as_str) else {
        return false;
    };
    let Some(created_at) = event
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(|value| {
            DateTime::parse_from_rfc3339(value)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
        })
    else {
        return false;
    };
    let sender = event.get("sender").and_then(Value::as_str);
    realm_event_visible_to_session(state, realm_id, created_at, sender, session).await
        && !personal_blocklist_blocks_sender_for_session(state, session, sender).await
}

async fn canonical_event_visible_to_personal_blocklist(
    state: &AppState,
    record: &crate::state::CanonicalEventRecord,
    session: &SessionRecord,
) -> bool {
    !personal_blocklist_blocks_sender_for_session(state, Some(session), Some(&record.actor_id))
        .await
}

async fn personal_blocklist_blocks_sender_for_session(
    state: &AppState,
    session: Option<&SessionRecord>,
    sender: Option<&str>,
) -> bool {
    let (Some(session), Some(sender)) = (session, sender) else {
        return false;
    };
    if sender == session.actor {
        return false;
    }
    for data_type in PERSONAL_BLOCKLIST_DATA_TYPES.iter() {
        let blocked = state
            .persistence
            .account_data()
            .get(&session.actor, data_type)
            .await
            .ok()
            .flatten()
            .is_some_and(|record| blocklist_payload_blocks_sender(&record.payload, sender));
        if blocked {
            return true;
        }
    }
    false
}

fn blocklist_payload_blocks_sender(payload: &Value, sender: &str) -> bool {
    if let Some(entries) = payload.get("entries").and_then(Value::as_array) {
        return entries
            .iter()
            .any(|entry| blocklist_entry_blocks_sender(entry, sender));
    }
    if let Some(entries) = payload.get("blocked").and_then(Value::as_array) {
        return entries
            .iter()
            .any(|entry| blocklist_entry_blocks_sender(entry, sender));
    }
    blocklist_entry_blocks_sender(payload, sender)
}

fn blocklist_entry_blocks_sender(entry: &Value, sender: &str) -> bool {
    match entry {
        Value::String(_) => blocklist_value_is_sender(entry, sender),
        Value::Object(object) => {
            let mode = object
                .get("mode")
                .or_else(|| object.get("kind"))
                .or_else(|| object.get("action"))
                .or_else(|| object.get("status"))
                .and_then(Value::as_str)
                .unwrap_or("block");
            if matches!(mode, "allow" | "unblock" | "removed" | "deleted") {
                return false;
            }
            object
                .get("target")
                .or_else(|| object.get("did"))
                .or_else(|| object.get("actor"))
                .is_some_and(|target| blocklist_entry_target_matches_sender(target, sender))
        }
        _ => false,
    }
}

fn blocklist_entry_target_matches_sender(target: &Value, sender: &str) -> bool {
    match target {
        Value::String(_) => blocklist_value_is_sender(target, sender),
        Value::Object(object) => object
            .get("did")
            .or_else(|| object.get("actor"))
            .or_else(|| object.get("id"))
            .is_some_and(|value| blocklist_value_is_sender(value, sender)),
        _ => false,
    }
}

fn blocklist_value_is_sender(value: &Value, sender: &str) -> bool {
    value.as_str().is_some_and(|value| value == sender)
}

fn message_scope_circle_id(content: &Value) -> Option<&str> {
    content
        .get("scope_circle_id")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("ck:circle:"))
}

fn circle_scope_visible_to_session(
    projection: &ProjectionState,
    scope_circle_id: Option<&str>,
    session: Option<&SessionRecord>,
    sender: Option<&str>,
) -> bool {
    let Some(scope_circle_id) = scope_circle_id else {
        return true;
    };
    if sender.is_some_and(|sender| session.is_some_and(|session| session.actor == sender)) {
        return true;
    }
    let Some(session) = session else {
        return false;
    };
    projection.circle_scope_visible_to_actor(scope_circle_id, &session.actor)
}

fn add_scope_circle_metadata(event: &mut serde_json::Value, content: &serde_json::Value) {
    let Some(scope_circle_id) = message_scope_circle_id(content) else {
        return;
    };
    let Some(object) = event.as_object_mut() else {
        return;
    };
    object.insert(
        "scope_circle_id".to_owned(),
        serde_json::Value::String(scope_circle_id.to_owned()),
    );
    object.insert(
        "effective_scope".to_owned(),
        serde_json::Value::String(scope_circle_id.to_owned()),
    );
}

fn sync_timeline_message_record_json(message: &crate::state::MessageRecord) -> serde_json::Value {
    // flow_id is always derived from realm_id (one flow per Realm for
    // the message timeline) — thread_id is the discussion *track* within
    // that flow, NOT the flow itself. The legacy top-level `branch` object
    // was removed in revision 0a5ab85 (see cokret-spec
    // `artifacts/registry/forbidden-wire-fields.json` entry "branch"); the
    // `track_name` is the concrete v1 wire field.
    let flow_id = flow_id_from_realm_id(&message.realm_id);
    let track_id = message.thread_id.clone();
    let mut event = json!({
        "kind": "ck.message.create",
        "event_id": message.event_id,
        "message_id": super::message_id_from_event_id(&message.event_id),
        "flow_id": flow_id,
        "realm_id": message.realm_id,
        "track_name": default_discussion_track(&flow_id, &track_id),
        "thread_id": message.thread_id,
        "sender": message.sender,
        "content": message.content,
        "encrypted": message.encrypted,
        "decryption_state": if message.encrypted { "opaque" } else { "plaintext" },
        "created_at": message.created_at,
    });
    add_scope_circle_metadata(&mut event, &message.content);
    event
}

fn sync_timeline_message_record_json_with_projection(
    message: &crate::state::MessageRecord,
    projection: &ProjectionState,
) -> serde_json::Value {
    let mut event = sync_timeline_message_record_json(message);
    if actor_erased_in_realm(projection, &message.sender, &message.realm_id) {
        tombstone_timeline_event_value(&mut event);
    }
    augment_timeline_message_json(event, &message.event_id, &message.content, projection)
}

#[derive(Debug, Default)]
pub struct SyncCursor {
    /// Visible timeline frontier per Realm.
    pub positions: BTreeMap<String, i64>,
    /// Account aggregate projection frontier per Realm. This is a
    /// server-internal cursor vector carried inside the opaque handle binding;
    /// it is intentionally separate from `positions.realms` so metadata-only
    /// deltas cannot mask later visible timeline events.
    pub account_positions: BTreeMap<String, i64>,
    pub to_device_position: i64,
    /// `ctx.issued_at_ms` from the stateful handle. Used for forward-progress
    /// pruning of older handles after a client proves it persisted a cursor.
    /// Per-Realm account projection freshness lives in `account_positions`,
    /// not here.
    pub issued_at_ms: Option<i64>,
}

#[derive(Debug)]
pub enum SyncCursorError {
    Invalid(&'static str),
    Mismatch(&'static str),
    Integrity(&'static str),
    Expired,
    /// The cursor authority was revoked via `ck.self.account.command.revoke_cursor`.
    /// Surfaced as `cursor_revoked`; MUST be raised before any server-side
    /// state advancement (to-device ack, account-subscribe resume, wait-for
    /// barrier release, dropped/resync recovery).
    Revoked,
}

pub async fn sync_token_for_client_sync(
    state: &AppState,
    session: Option<&SessionRecord>,
    filter: Option<&serde_json::Value>,
    realms_positions: BTreeMap<String, i64>,
    account_realms_positions: BTreeMap<String, i64>,
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
    let filter_digest = sync_filter_digest(filter);
    let issued_at_ms = issued_at.timestamp_millis();
    let expires_at_ms = expires_at.timestamp_millis();
    let positions = json!({
        "realms": realms_positions,
        "account_realms": account_realms_positions,
        "devices": device_positions,
        "to_device": to_device_position
    });
    // Deterministic handle: HMAC over the binding content (positions
    // included, per-mint `devices` wall-clock stamp excluded), so an
    // unchanged frontier re-mints the SAME handle and the upsert only
    // refreshes the row's expiry instead of growing the table.
    let binding = stream_cursor_handle_binding(
        &principal_id,
        &device_id,
        &state.config.service_did,
        &filter_digest,
        &realms_positions,
        &account_realms_positions,
        to_device_position,
    );
    let handle = derive_cursor_handle(&state.sync_cursor_hmac_key, &binding);
    upsert_sync_cursor_record(
        state,
        SyncCursorRecord {
            handle: handle.clone(),
            principal_id: Some(principal_id),
            device_id: Some(device_id),
            service_id: state.config.service_did.clone(),
            filter_digest: Some(filter_digest),
            purpose: "stream".to_owned(),
            positions: Some(positions),
            target: None,
            issued_at_ms,
            expires_at_ms,
        },
    )
    .await;
    let cursor = json!({
        "v": "1",
        "purpose": "stream",
        "t": issued_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "x": expires_at_ms,
        "h": handle
    });
    encode_sync_cursor_value(cursor)
}

pub(crate) async fn sync_token_for_state(state: &AppState) -> String {
    sync_token_for_state_positions(state, BTreeMap::new()).await
}

async fn sync_token_for_realm_position(state: &AppState, realm_id: &str, position: i64) -> String {
    sync_token_for_state_positions(state, BTreeMap::from([(realm_id.to_owned(), position)])).await
}

async fn sync_token_for_state_positions(
    state: &AppState,
    realms_positions: BTreeMap<String, i64>,
) -> String {
    let issued_at = chrono::Utc::now();
    let expires_at = issued_at + ChronoDuration::hours(1);
    let issued_at_ms = issued_at.timestamp_millis();
    let expires_at_ms = expires_at.timestamp_millis();
    let binding = service_cursor_handle_binding(&state.config.service_did, &realms_positions);
    let handle = derive_cursor_handle(&state.sync_cursor_hmac_key, &binding);
    upsert_sync_cursor_record(
        state,
        SyncCursorRecord {
            handle: handle.clone(),
            principal_id: None,
            device_id: None,
            service_id: state.config.service_did.clone(),
            filter_digest: None,
            purpose: "stream".to_owned(),
            positions: Some(json!({
                "realms": realms_positions,
                "account_realms": {},
                "devices": {},
                "to_device": 0
            })),
            target: None,
            issued_at_ms,
            expires_at_ms,
        },
    )
    .await;
    encode_sync_cursor_value(json!({
            "v": "1",
            "purpose": "stream",
            "t": issued_at.to_rfc3339_opts(SecondsFormat::Millis, true),
            "x": expires_at_ms,
            "h": handle
    }))
}

pub(super) fn encode_sync_cursor_value(cursor: Value) -> String {
    let bytes = cokret_sdk::canonical::canonical_json_bytes(&cursor)
        .unwrap_or_else(|_| cursor.to_string().into_bytes());
    format!("ck:cursor:{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// Deterministic, unguessable stateful cursor handle.
///
/// `handle = base64url( HMAC-SHA256(cursor_key, canonical_binding)[..16] )`.
///
/// Keyed (HMAC, not a bare hash): a bare hash of the binding inputs — all of
/// which a caller knows (its own/another device id, the realm positions) —
/// would be forgeable, letting an attacker mint a victim device's handle and
/// advance its `to_device` ack to prune undelivered Welcomes. The server-secret
/// `cursor_key` makes the handle unguessable while keeping it deterministic, so
/// identical bindings (same positions) map to the same handle (no per-poll
/// churn, no new row). 16 bytes → 128 bits → ≥22 base64url chars, satisfying
/// `cursor.schema.json` `h`.
fn derive_cursor_handle(cursor_key: &[u8], canonical_binding: &[u8]) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256>>::new_from_slice(cursor_key).expect("HMAC accepts any key length");
    mac.update(canonical_binding);
    let tag = mac.finalize().into_bytes();
    URL_SAFE_NO_PAD.encode(&tag[..16])
}

/// Canonical byte string a STREAM cursor handle is derived from.
///
/// Excludes the per-mint `positions.devices` timestamp (it is a wall-clock
/// stamp, not a content position; including it would defeat determinism — see
/// `_cursor_todos.md` C1). Includes every field the integrity check binds, so a
/// cross-binding handle never collides.
fn stream_cursor_handle_binding(
    principal_id: &str,
    device_id: &str,
    service_id: &str,
    filter_digest: &str,
    realms_positions: &BTreeMap<String, i64>,
    account_realms_positions: &BTreeMap<String, i64>,
    to_device_position: i64,
) -> Vec<u8> {
    let binding = json!({
        "principal_id": principal_id,
        "device_id": device_id,
        "service_id": service_id,
        "filter_digest": filter_digest,
        "purpose": "stream",
        "realms": realms_positions,
        "account_realms": account_realms_positions,
        "to_device": to_device_position,
    });
    cokret_sdk::canonical::canonical_json_bytes(&binding)
        .unwrap_or_else(|_| binding.to_string().into_bytes())
}

/// Canonical byte string the GENERIC service-level cursor handle is derived
/// from (`sync_token_for_state`: empty positions, no session binding). Shaped
/// differently from [`stream_cursor_handle_binding`] so the two namespaces
/// can never collide.
fn service_cursor_handle_binding(
    service_id: &str,
    realms_positions: &BTreeMap<String, i64>,
) -> Vec<u8> {
    let binding = json!({
        "kind": "generic",
        "purpose": "stream",
        "service_id": service_id,
        "realms": realms_positions,
        "account_realms": {},
        "to_device": 0,
    });
    cokret_sdk::canonical::canonical_json_bytes(&binding)
        .unwrap_or_else(|_| binding.to_string().into_bytes())
}

/// How often the durable sync-cursor handle table is swept for expired rows.
/// Stream cursors live 1h, so a 15-minute cadence keeps the table within a
/// small constant factor of the active-stream count without measurable load
/// (one indexed DELETE per pass).
const SYNC_CURSOR_TTL_SWEEP_INTERVAL: Duration = Duration::from_secs(900);

/// Spawn the periodic TTL sweep for the durable sync-cursor handle table.
///
/// Forward-progress pruning (on cursor presentation) already caps per-stream
/// rows; this sweep is the backstop that clears rows whose client never came
/// back, replacing the old lookup-time-only lazy deletion that let
/// superseded handles accumulate until restart.
pub fn spawn_sync_cursor_ttl_sweeper(
    state: AppState,
) -> std::sync::Arc<tokio::task::JoinHandle<()>> {
    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SYNC_CURSOR_TTL_SWEEP_INTERVAL);
        // Skip the immediate first tick so we don't fire mid-boot.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let now_ms = chrono::Utc::now().timestamp_millis();
            match state.persistence.sync_cursors().prune_expired(now_ms).await {
                Ok(0) => {}
                Ok(pruned) => tracing::debug!(
                    worker = "sync_cursor_ttl_sweep",
                    pruned,
                    "expired sync cursor handles pruned"
                ),
                Err(error) => tracing::warn!(
                    worker = "sync_cursor_ttl_sweep",
                    %error,
                    "sync cursor TTL sweep failed"
                ),
            }
        }
    });
    std::sync::Arc::new(task)
}

/// Persist (or expiry-refresh) the handle row behind a freshly-minted cursor.
///
/// A failed write is downgraded to a warning rather than failing the sync
/// response: the client still gets its data, and if the row never lands the
/// next `after=` presentation fails handle lookup and the client recovers
/// through the spec's full-resync path (client-sync.md §12.3).
async fn upsert_sync_cursor_record(state: &AppState, record: SyncCursorRecord) {
    if let Err(error) = state.persistence.sync_cursors().upsert(&record).await {
        tracing::warn!(%error, handle = %record.handle, "sync cursor handle upsert failed");
    }
}

async fn stored_sync_cursor_by_handle(
    state: &AppState,
    handle: &str,
) -> Result<Value, SyncCursorError> {
    let record = state
        .persistence
        .sync_cursors()
        .get(handle)
        .await
        .map_err(|error| {
            tracing::warn!(%error, handle, "sync cursor handle lookup failed");
            SyncCursorError::Integrity("sync cursor handle lookup failed")
        })?
        .ok_or(SyncCursorError::Integrity("sync cursor handle is unknown"))?;
    Ok(stored_value_from_sync_cursor_record(record))
}

/// Rebuild the legacy in-memory `{ctx, positions, target?, expires_at_ms}`
/// stored shape from a persisted row, so the validation code downstream of
/// the lookup is byte-compatible with the pre-durability behavior (generic
/// rows reconstruct a ctx WITHOUT `principal_id`/`device_id`, which
/// `parse_and_validate_sync_cursor` rejects by construction).
fn stored_value_from_sync_cursor_record(record: SyncCursorRecord) -> Value {
    let mut ctx = serde_json::Map::new();
    if let Some(principal_id) = record.principal_id {
        ctx.insert("principal_id".to_owned(), Value::String(principal_id));
    }
    if let Some(device_id) = record.device_id {
        ctx.insert("device_id".to_owned(), Value::String(device_id));
    }
    ctx.insert("service_id".to_owned(), Value::String(record.service_id));
    if let Some(filter_digest) = record.filter_digest {
        ctx.insert("filter_digest".to_owned(), Value::String(filter_digest));
    }
    ctx.insert("issued_at_ms".to_owned(), json!(record.issued_at_ms));
    let mut stored = json!({
        "ctx": Value::Object(ctx),
        "expires_at_ms": record.expires_at_ms,
    });
    if let Some(positions) = record.positions {
        stored["positions"] = positions;
    }
    if let Some(target) = record.target {
        stored["target"] = target;
    }
    stored
}

fn has_inline_cursor_body_marker(value: &Value) -> bool {
    value.get("_mac").is_some()
        || value.get("_sig").is_some()
        || value.get("positions").is_some()
        || value.get("scope").is_some()
        || value.get("s").is_some()
        || value.get("d").is_some()
        || value.get("target").is_some()
        || value.get("issuer_kid").is_some()
}

fn cursor_position_map(
    positions_value: &Value,
    key: &'static str,
    missing_error: Option<&'static str>,
) -> Result<BTreeMap<String, i64>, SyncCursorError> {
    let Some(map) = positions_value.get(key).and_then(Value::as_object) else {
        return match missing_error {
            Some(message) => Err(SyncCursorError::Integrity(message)),
            None => Ok(BTreeMap::new()),
        };
    };
    Ok(map
        .iter()
        .filter_map(|(realm_id, position)| {
            position
                .as_i64()
                .map(|position| (realm_id.clone(), position))
        })
        .collect())
}

pub async fn parse_and_validate_sync_cursor(
    token: &str,
    state: &AppState,
    session: Option<&SessionRecord>,
    filter: Option<&serde_json::Value>,
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
        return Err(SyncCursorError::Invalid(
            "after must be a v1 account cursor",
        ));
    }
    // Revocation is checked before TTL / integrity so a revoked authority
    // always surfaces `cursor_revoked` and never advances server-side state
    // (to-device ack, subscribe resume, wait-for barrier, dropped recovery).
    // `this_cursor` matches the exact token by digest; `same_device` /
    // `same_session` match the authenticated session's (principal, device),
    // which the cursor is bound to and re-verified against below.
    if cursor_authority_revoked(state, token, session, now_ms) {
        return Err(SyncCursorError::Revoked);
    }
    let Some(expires_at) = value.get("x").and_then(|expires_at| expires_at.as_i64()) else {
        return Err(SyncCursorError::Invalid("after cursor must contain x"));
    };
    if expires_at <= now_ms {
        return Err(SyncCursorError::Expired);
    }
    if has_inline_cursor_body_marker(&value)
        || value.get("_ctx").is_some()
        || value.get("_positions").is_some()
    {
        return Err(SyncCursorError::Integrity(
            "core cursor must use stateful handle form",
        ));
    };
    let Some(handle) = value.get("h").and_then(|h| h.as_str()) else {
        return Err(SyncCursorError::Integrity("after cursor must contain h"));
    };
    if validate_cursor_handle(handle).is_err() {
        return Err(SyncCursorError::Invalid("invalid cursor handle"));
    }
    let stored = stored_sync_cursor_by_handle(state, handle).await?;
    if stored
        .get("expires_at_ms")
        .and_then(|expires_at| expires_at.as_i64())
        .is_none_or(|expires_at| expires_at <= now_ms)
    {
        let _ = state.persistence.sync_cursors().delete(handle).await;
        return Err(SyncCursorError::Integrity("sync cursor handle has expired"));
    }
    let ctx = stored
        .get("ctx")
        .and_then(|ctx| ctx.as_object())
        .ok_or(SyncCursorError::Integrity("cursor handle is missing ctx"))?;
    let expected_principal = session
        .map(|session| session.actor.as_str())
        .unwrap_or("anonymous");
    let expected_device = session
        .map(|session| session.device_id.as_str())
        .unwrap_or("anonymous");
    if ctx
        .get("principal_id")
        .and_then(|principal| principal.as_str())
        .is_none_or(|principal| principal != expected_principal)
    {
        return Err(SyncCursorError::Mismatch(
            "cursor principal does not match request actor",
        ));
    }
    if ctx
        .get("device_id")
        .and_then(|device| device.as_str())
        .is_none_or(|device| device != expected_device)
    {
        return Err(SyncCursorError::Mismatch(
            "cursor device does not match request device",
        ));
    }
    if ctx
        .get("service_id")
        .and_then(|service| service.as_str())
        .is_none_or(|service| service != state.config.service_did)
    {
        return Err(SyncCursorError::Mismatch(
            "cursor service does not match this service DID",
        ));
    }
    let expected_filter_digest = sync_filter_digest(filter);
    if ctx
        .get("filter_digest")
        .and_then(|filter_digest| filter_digest.as_str())
        .is_none_or(|filter_digest| filter_digest != expected_filter_digest)
    {
        return Err(SyncCursorError::Mismatch(
            "cursor filter digest does not match request filter",
        ));
    }
    let positions_value = stored.get("positions").ok_or(SyncCursorError::Integrity(
        "cursor handle is missing positions",
    ))?;
    let positions = cursor_position_map(
        positions_value,
        "realms",
        Some("cursor handle is missing positions.realms"),
    )?;
    let account_positions = cursor_position_map(positions_value, "account_realms", None)?;
    let to_device_position = positions_value
        .get("to_device")
        .and_then(|position| position.as_i64())
        .unwrap_or_default();
    let issued_at_ms = ctx.get("issued_at_ms").and_then(|value| value.as_i64());
    Ok(SyncCursor {
        positions,
        account_positions,
        to_device_position,
        issued_at_ms,
    })
}

pub fn decode_sync_cursor_value(token: &str) -> Result<serde_json::Value, SyncCursorError> {
    let Some(encoded) = token.strip_prefix("ck:cursor:") else {
        return Err(SyncCursorError::Invalid(
            "after must use a ck:cursor account token",
        ));
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| SyncCursorError::Invalid("after cursor must be valid base64url"))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| SyncCursorError::Invalid("after cursor must contain JSON"))
}

/// Translate an optional client cursor to a backfill (event-id) cursor.
///
/// - `None` → `None` (start from the beginning).
/// - Plain string that does NOT start with `ck:cursor:` → pass through unchanged; the caller
///   already speaks the projection's `event_id` cursor.
/// - `ck:cursor:...` → decode the structured cursor, look up the handle's stored position for
///   `realm_id` (a `timestamp_micros` checkpoint), then walk the Realm's projected events and
///   persisted messages to find the most recent event at-or-before that checkpoint and return its
///   `event_id`. When no event sits at-or-before the checkpoint, return `None` so backfill streams
///   from the start of the Realm.
pub async fn resolve_sync_cursor_to_event_id(
    state: &AppState,
    realm_id: &str,
    cursor: Option<String>,
) -> Result<Option<String>, &'static str> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    if !cursor.starts_with("ck:cursor:") {
        return Ok(Some(cursor));
    }
    let value = decode_sync_cursor_value(&cursor)
        .map_err(|_| "sync cursor is not a valid ck:cursor token")?;
    if has_inline_cursor_body_marker(&value)
        || value.get("_ctx").is_some()
        || value.get("_positions").is_some()
    {
        return Err("sync cursor integrity invalid");
    }
    let Some(handle) = value.get("h").and_then(Value::as_str) else {
        return Err("sync cursor is missing stateful handle");
    };
    let stored = stored_sync_cursor_by_handle(state, handle)
        .await
        .map_err(|_| "sync cursor handle is unknown")?;
    let checkpoint = stored
        .get("positions")
        .and_then(|positions| positions.get("realms"))
        .and_then(|realms| realms.get(realm_id))
        .and_then(|position| position.as_i64());
    let Some(checkpoint) = checkpoint else {
        return Ok(None);
    };

    let mut newest_event_id: Option<(i64, String)> = None;
    // Snapshot the (event_id, created_at) pairs out from under the projection
    // lock before the async position lookups (guard is not Send).
    let projected_messages: Vec<(String, DateTime<Utc>)> = {
        let projection = state.projection.lock().expect("projection lock");
        projection
            .messages_for_realm(realm_id)
            .into_iter()
            .map(|message| (message.event_id.clone(), message.created_at))
            .collect()
    };
    for (event_id, created_at) in projected_messages {
        let position = timeline_event_position(state, &event_id, created_at).await;
        if position <= checkpoint {
            match &newest_event_id {
                Some((existing_pos, _)) if *existing_pos >= position => {}
                _ => newest_event_id = Some((position, event_id.clone())),
            }
        }
    }
    for message in state
        .persistence
        .messages()
        .list_for_realm(realm_id, 1000)
        .await
        .unwrap_or_default()
    {
        let position = timeline_event_position(state, &message.event_id, message.created_at).await;
        if position <= checkpoint {
            match &newest_event_id {
                Some((existing_pos, _)) if *existing_pos >= position => {}
                _ => newest_event_id = Some((position, message.event_id.clone())),
            }
        }
    }
    Ok(newest_event_id.map(|(_, event_id)| event_id))
}

pub fn sync_filter_digest(filter: Option<&serde_json::Value>) -> String {
    let empty_filter = json!({});
    let binding = json!({
        "filter": filter.unwrap_or(&empty_filter),
    });
    cokret_sdk::canonical::canonical_sha256(&binding)
        .unwrap_or_else(|_| cokret_sdk::canonical::sha256_digest(binding.to_string().as_bytes()))
}

#[endpoint(
    operation_id = "ck.self.ephemeral.command.send",
    tags("sync"),
    summary = "Send a broadcast ephemeral signal"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.ephemeral.command.send"))]
async fn submit_ephemeral(
    aa: crate::routing::system::extract::AuthArgs,
    body: salvo::oapi::extract::JsonBody<cokret_sdk::EphemeralEnvelope>,
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<EphemeralSubmitOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let envelope = body.into_inner();

    validate_ephemeral_envelope(&envelope)?;

    let realm_id = envelope.realm_id.clone();
    let realm_id_str = realm_id.as_str();
    let actor_id = envelope.actor_id.to_string();
    if actor_id != session.actor {
        return Err(crate::error::AppError::capability_denied(
            "ephemeral actor_id must match the bearer session actor",
        ));
    }
    if !realm_has_member(state, realm_id_str, &session.actor).await {
        return Err(crate::error::AppError::capability_denied(
            "actor is not a joined member of the realm",
        ));
    }

    match envelope.kind.as_str() {
        "ck.typing" => {
            persist_ephemeral_typing(state, &session.actor, realm_id_str, &envelope).await
        }
        "ck.presence" => persist_ephemeral_presence(state, &session.actor, &envelope).await,
        "ck.receipt.read" => admit_ephemeral_read_receipt(state, realm_id_str, &envelope).await?,
        "ck.call.signal" => {}
        _ => {
            return Err(crate::error::AppError::invalid_param(
                "unsupported ephemeral kind",
            ));
        }
    }

    crate::result::json_ok(EphemeralSubmitOutcome {
        accepted: true,
        kind: envelope.kind,
        realm_id,
        dispatched_to: None,
        server_received_at: Some(chrono::Utc::now()),
    })
}

fn validate_ephemeral_envelope(
    envelope: &cokret_sdk::EphemeralEnvelope,
) -> Result<(), crate::error::AppError> {
    if !matches!(
        envelope.kind.as_str(),
        "ck.call.signal" | "ck.presence" | "ck.typing" | "ck.receipt.read"
    ) {
        return Err(crate::error::AppError::invalid_param(
            "unsupported ephemeral kind",
        ));
    }
    let window_ms = envelope
        .expires_at
        .signed_duration_since(envelope.sent_at)
        .num_milliseconds();
    if window_ms <= 0 || (window_ms as u64) > cokret_sdk::EPHEMERAL_ABSOLUTE_HARD_CEILING_MS as u64
    {
        return Err(crate::error::AppError::invalid_param(
            "ephemeral expires_at must be after sent_at and within the hard TTL ceiling",
        ));
    }
    if envelope.expires_at <= chrono::Utc::now() {
        return Err(crate::error::AppError::invalid_param(
            "ephemeral signal is already expired",
        ));
    }
    Ok(())
}

async fn persist_ephemeral_typing(
    state: &AppState,
    actor: &str,
    realm_id: &str,
    envelope: &cokret_sdk::EphemeralEnvelope,
) {
    let typing = envelope
        .payload
        .get("typing")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    if typing {
        let scope_id = envelope
            .payload
            .get("scope_id")
            .or_else(|| envelope.payload.get("flow_id"))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(ToOwned::to_owned);
        if let Err(error) = state
            .persistence
            .typing()
            .put(TypingRecord {
                actor: actor.to_owned(),
                realm_id: realm_id.to_owned(),
                scope_id,
                expires_at: envelope.expires_at,
                updated_at: chrono::Utc::now(),
            })
            .await
        {
            tracing::error!(%error, "failed to persist ephemeral typing");
        }
    } else {
        let _ = state.persistence.typing().remove(actor, realm_id).await;
    }
}

async fn persist_ephemeral_presence(
    state: &AppState,
    actor: &str,
    envelope: &cokret_sdk::EphemeralEnvelope,
) {
    let status = envelope
        .payload
        .get("status")
        .or_else(|| envelope.payload.get("state"))
        .and_then(Value::as_str)
        .unwrap_or("online")
        .to_owned();
    if let Err(error) = state
        .persistence
        .presence()
        .put(PresenceRecord {
            actor: actor.to_owned(),
            status,
            updated_at: chrono::Utc::now(),
        })
        .await
    {
        tracing::error!(%error, "failed to persist ephemeral presence");
    }
}

async fn admit_ephemeral_read_receipt(
    state: &AppState,
    realm_id: &str,
    envelope: &cokret_sdk::EphemeralEnvelope,
) -> Result<(), crate::error::AppError> {
    if envelope
        .payload
        .get("event_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .is_none()
    {
        return Err(crate::error::AppError::invalid_param(
            "ck.receipt.read payload requires event_id",
        ));
    }

    let (disclosure, _visibility, _scope_overrides_allowed) =
        super::event_log::effective_read_receipt_policy_for_realm(state, realm_id)
            .await
            .unwrap_or_else(|| ("optional".to_owned(), "members".to_owned(), true));
    if disclosure == "disabled" {
        return Err(crate::error::AppError::new(
            crate::error::ErrorCode::PolicyViolation,
            format!(
                "Realm '{realm_id}' read_receipt_policy.disclosure=disabled; ck.receipt.read dropped"
            ),
        )
        .with_status(StatusCode::FORBIDDEN));
    }
    Ok(())
}

/// `ck.self.events.stream.subscribe` at `GET /_cokret/self/events/subscribe`. NDJSON
/// streaming: each line is one frame, frame `kind` is one of
/// `event` / `catchup_complete` / `heartbeat` / `dropped`.
///
/// Selector: repeated `realms[]` query args (multi-value).
///
/// Lifecycle:
///   1. Validate inputs (realms, accessibility).
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
#[tracing::instrument(skip_all, fields(op = "events_subscribe"))]
pub(super) async fn events_subscribe(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected").clone();
    let realms = super::query_param_all(req, "realms");
    if realms.is_empty() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "realms is required",
        );
        return;
    }
    let realms = match normalize_scope_selectors(realms) {
        Ok(realms) => realms,
        Err(error) => {
            let message = error.to_string();
            render_error(res, StatusCode::BAD_REQUEST, "invalid_param", &message);
            return;
        }
    };
    let session = authenticated_session(&state, req).await.ok();
    let mut accessible_realms: Vec<String> = Vec::with_capacity(realms.len());
    for realm in realms {
        if realm_id_accessible(&state, &realm, session.as_ref()).await {
            accessible_realms.push(realm);
        }
    }
    if accessible_realms.is_empty() {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
        return;
    }
    let limit = query_param(req, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100)
        .min(100);
    let cursor = query_param(req, "after");
    let include_history = query_param(req, "include_history")
        .as_deref()
        .map(|value| matches!(value, "true" | "1" | "yes"))
        .unwrap_or(true);
    let subscribe_scope_key = events_subscribe_scope_key(req, session.as_ref(), &accessible_realms);
    if reject_subscribe_reconnect(&state, &subscribe_scope_key, res) {
        return;
    }
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
        for realm_id in &accessible_realms {
            match projected_event_page(&state, realm_id, cursor.as_deref(), limit).await {
                Ok(Some(page)) => {
                    for event in page.items {
                        if !projection_record_visible_to_session(&state, &event, session.as_ref())
                            .await
                        {
                            continue;
                        }
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
                    if error.to_string().contains("invalid_cursor") && accessible_realms.len() == 1
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

    let catchup_cursor = match last_cursor {
        Some(cursor) => cursor,
        None => sync_token_for_state(&state).await,
    };
    let realm_filter: BTreeSet<String> = accessible_realms.iter().cloned().collect();
    let stream_deadline = tokio::time::Instant::now() + Duration::from_millis(max_duration_ms);
    let session_for_stream = session.clone();
    let subscribe_scope_key_for_stream = subscribe_scope_key.clone();

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
                            if !realm_filter.contains(&notification.realm_id) {
                                continue;
                            }
                            // Dispatch on notification.kind to
                            // produce the right NDJSON frame shape.
                            use crate::state::EventNotificationKind;
                            let mut terminal = false;
                            let frame = match notification.kind {
                                EventNotificationKind::Event { cursor, event_payload } => {
                                    if !projection_event_value_visible_to_session(
                                        &state,
                                        &event_payload,
                                        session_for_stream.as_ref(),
                                    ).await {
                                        continue;
                                    }
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
                                        "realm_id": notification.realm_id,
                                        "previous_epoch": previous_epoch,
                                        "new_epoch": new_epoch,
                                    })
                                }
                                EventNotificationKind::Frontier { state_root, seal_id } => {
                                    json!({
                                        "kind": "frontier",
                                        "realm_id": notification.realm_id,
                                        "state_root": state_root,
                                        "seal_id": seal_id,
                                    })
                                }
                                EventNotificationKind::ResyncRequired { reason, reconnect_after_ms } => {
                                    let reconnect_after_ms =
                                        reconnect_after_ms
                                            .filter(|value| *value > 0)
                                            .unwrap_or(SUBSCRIBE_RECONNECT_AFTER_MS);
                                    arm_subscribe_reconnect(
                                        &state,
                                        &subscribe_scope_key_for_stream,
                                        reconnect_after_ms,
                                    );
                                    terminal = true;
                                    json!({
                                        "kind": "resync_required",
                                        "realm_id": notification.realm_id,
                                        "reason": reason,
                                        "reconnect_after_ms": reconnect_after_ms,
                                    })
                                }
                                EventNotificationKind::Unauthorized { reason } => {
                                    json!({
                                        "kind": "unauthorized",
                                        "realm_id": notification.realm_id,
                                        "reason": reason,
                                    })
                                }
                            };
                            yield Ok(ndjson_line(&frame));
                            if terminal {
                                break;
                            }
                        }
                        Err(RecvError::Lagged(skipped)) => {
                            // Round 4 (B1.5) — broadcast capacity exceeded.
                            // The typed EventsSubscribeFrameBody requires a
                            // resume cursor on Dropped; if we don't have a
                            // valid cursor (the broadcast lag dropped state
                            // we'd need to mint one) the SDK rule downgrades
                            // to ResyncRequired. We always carry the
                            // catchup_cursor we already have, so Dropped is
                            // safe here.
                            let cursor_str = catchup_cursor.clone();
                            // Use the typed-id form (ck:cursor:<base64url>),
                            // not the cursor::Cursor struct.
                            let cursor_typed =
                                cokret_sdk::identifiers::Cursor::new(cursor_str.clone()).ok();
                            arm_subscribe_reconnect(
                                &state,
                                &subscribe_scope_key_for_stream,
                                SUBSCRIBE_RECONNECT_AFTER_MS,
                            );
                            let body = dropped_or_resync(
                                cursor_typed,
                                format!("broadcast_lagged skipped={skipped}"),
                                Some(SUBSCRIBE_RECONNECT_AFTER_MS),
                            );
                            // Emit the typed frame body fields at the top
                            // level (matches the SDK `kind`-tagged shape).
                            let body_json = serde_json::to_value(&body)
                                .unwrap_or_else(|_| json!({"kind": "resync_required"}));
                            let mut frame = body_json;
                            if let Some(obj) = frame.as_object_mut() {
                                obj.insert(
                                    "skipped".to_owned(),
                                    Value::Number(serde_json::Number::from(skipped)),
                                );
                            }
                            yield Ok(ndjson_line(&frame));
                            break;
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

fn subscribe_subject(req: &Request, session: Option<&SessionRecord>) -> String {
    match session {
        Some(session) => format!("session:{}:{}", session.actor, session.device_id),
        None => format!("remote:{}", req.remote_addr()),
    }
}

fn events_subscribe_scope_key(
    req: &Request,
    session: Option<&SessionRecord>,
    accessible_realms: &[String],
) -> String {
    let realms = accessible_realms
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "ck.self.events.stream.subscribe|{}|realms={realms}",
        subscribe_subject(req, session)
    )
}

fn reject_subscribe_reconnect(
    state: &AppState,
    subscribe_scope_key: &str,
    res: &mut Response,
) -> bool {
    let retry_after_ms = state
        .subscribe_reconnect_gate
        .lock()
        .expect("subscribe reconnect gate lock")
        .retry_after_ms(subscribe_scope_key, Utc::now());
    if let Some(retry_after_ms) = retry_after_ms {
        render_subscribe_rate_limited(res, retry_after_ms);
        return true;
    }
    false
}

fn arm_subscribe_reconnect(state: &AppState, subscribe_scope_key: &str, reconnect_after_ms: u64) {
    state
        .subscribe_reconnect_gate
        .lock()
        .expect("subscribe reconnect gate lock")
        .arm(
            subscribe_scope_key.to_owned(),
            Utc::now(),
            reconnect_after_ms,
        );
}

fn render_subscribe_rate_limited(res: &mut Response, retry_after_ms: u64) {
    let retry_after_seconds = retry_after_ms.div_ceil(1000).max(1);
    res.status_code(StatusCode::TOO_MANY_REQUESTS);
    res.headers_mut()
        .insert(header::RETRY_AFTER, retry_after_seconds.into());
    res.render(Json(
        cokret_sdk::ErrorEnvelope::new(
            "rate_limited",
            "Subscribe reconnect window is still active.",
        )
        .with_request_id(ids::generate_request_id())
        .with_retry_after_ms(Some(retry_after_ms)),
    ));
}

#[derive(Clone, Debug)]
struct EventsQueryParts {
    realms: Vec<String>,
    actors: Vec<String>,
    after: Option<String>,
    before: Option<String>,
    order: String,
    limit: usize,
}

fn validate_events_query_order(order: &str) -> Result<(), crate::error::AppError> {
    match order {
        "default" | "ascending" | "descending" => Ok(()),
        _ => Err(crate::error::AppError::invalid_param(
            "order must be default, ascending, or descending",
        )),
    }
}

fn events_query_direction(parts: &EventsQueryParts) -> bool {
    parts.order == "descending"
        || (parts.order == "default" && parts.before.is_some() && parts.after.is_none())
}

fn events_query_cursor_and_stop(
    parts: &EventsQueryParts,
) -> (Option<String>, Option<String>, bool) {
    let backward = events_query_direction(parts);
    let cursor = if backward {
        parts.before.clone().or_else(|| parts.after.clone())
    } else {
        parts.after.clone()
    };
    let stop = if backward {
        parts.after.clone()
    } else {
        parts.before.clone()
    };
    (cursor, stop, backward)
}

fn truncate_before_stop_cursor(mut events: Vec<Value>, stop_cursor: Option<&str>) -> Vec<Value> {
    let Some(stop_cursor) = stop_cursor else {
        return events;
    };
    if let Some(index) = events.iter().position(|event| {
        event
            .get("event_id")
            .and_then(Value::as_str)
            .is_some_and(|event_id| event_id == stop_cursor)
    }) {
        events.truncate(index);
    }
    events
}

/// `ck.self.events.query.scan` at `GET /_cokret/self/events`.
/// Reads from the projection layer so callers writing through
/// `POST /_cokret/self/events` see their messages here.
///
/// Selector: `realms[]` plus optional `actors[]` repeated query args.
/// Multi-Realm queries call `projected_event_page` per Realm and merge sorted
/// by HLC; the result paginates as a single stream.
/// `actors[]`-only queries dispatch to the durable Event-store reader.
///
/// Range: `from?` + `until?` + `direction`.
/// `direction=backward` reverses the merged stream so callers can paginate
/// older events with the same `next_cursor` semantics.
#[endpoint(
    operation_id = "ck.self.events.query.scan",
    tags("events"),
    summary = "Projection-aware events query (single- or multi-Realm merge; backward / forward direction)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.events.query.scan"))]
pub(super) async fn events_query(
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<serde_json::Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let limit = query_param(req, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100)
        .clamp(1, 100);
    let parts = EventsQueryParts {
        realms: super::query_param_all(req, "realms"),
        actors: super::query_param_all(req, "actors"),
        after: query_param(req, "after"),
        before: query_param(req, "before"),
        order: query_param(req, "order").unwrap_or_else(|| "default".to_owned()),
        limit,
    };
    events_query_impl(state, req, parts).await
}

#[endpoint(
    operation_id = "ck.self.events.query.scan_body",
    tags("events"),
    summary = "Body-based projection-aware events query for large selectors"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.events.query.scan_body"))]
pub(super) async fn events_query_post(
    body: salvo::oapi::extract::JsonBody<EventsQueryPostRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<serde_json::Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    let parts = EventsQueryParts {
        realms: body
            .realms
            .into_iter()
            .map(|realm| realm.into_string())
            .collect(),
        actors: body
            .actors
            .into_iter()
            .map(|actor| actor.into_string())
            .collect(),
        after: body.after.map(|cursor| cursor.into_string()),
        before: body.before.map(|cursor| cursor.into_string()),
        order: body.order.unwrap_or_else(|| "default".to_owned()),
        limit: body
            .limit
            .map(|limit| limit as usize)
            .unwrap_or(100)
            .clamp(1, 100),
    };
    events_query_impl(state, req, parts).await
}

async fn events_query_impl(
    state: &AppState,
    req: &Request,
    parts: EventsQueryParts,
) -> crate::result::JsonResult<serde_json::Value> {
    validate_events_query_order(&parts.order)?;
    if parts.realms.is_empty() && parts.actors.is_empty() {
        return Err(crate::error::AppError::missing_param(
            "events.query requires at least one of realms[] / actors[]",
        ));
    }
    let realms = normalize_scope_selectors(parts.realms.clone())?;
    for actor in &parts.actors {
        if validate_did(actor).is_err() {
            return Err(crate::error::AppError::invalid_param(format!(
                "invalid actor: {actor}"
            )));
        }
    }
    // Dispatch: if no Realms (actor-scoped query), forward to the durable
    // Event-store reader in routing/events.rs which builds an actor-keyed
    // `frontier.actors` map. The projection-aware path below is Realm-keyed.
    if realms.is_empty() {
        let session =
            authenticated_session(state, req)
                .await
                .map_err(|(status, code, message)| {
                    crate::error::AppError::invalid_param(message)
                        .with_status(status)
                        .with_wire_code(code)
                })?;
        let response = durable_events_query_from_parts(state, &session, &parts).await;
        return crate::result::json_ok(serde_json::to_value(response).unwrap_or(json!({})));
    }
    let session = authenticated_session(state, req).await.ok();
    let mut accessible_realms: Vec<String> = Vec::with_capacity(realms.len());
    for realm in realms {
        if realm_id_accessible(state, &realm, session.as_ref()).await {
            accessible_realms.push(realm);
        }
    }
    if accessible_realms.is_empty() {
        return Err(crate::error::AppError::not_found("not found"));
    }
    let limit = parts.limit;
    let (cursor, stop_cursor, backward) = events_query_cursor_and_stop(&parts);

    // Single-Realm fast path preserves the original `SolandBackfillOutcome` shape
    // for soland's existing test surface (ck.sync.backfill behavior).
    if accessible_realms.len() == 1 {
        let realm_id = &accessible_realms[0];
        match projected_event_page(state, realm_id, cursor.as_deref(), limit).await {
            Ok(Some(page)) => {
                let mut events: Vec<Value> = Vec::new();
                let mut last_visible_position = None;
                for event in &page.items {
                    if projection_record_visible_to_session(state, event, session.as_ref()).await {
                        last_visible_position = Some(
                            timeline_event_position(state, &event.event_id, event.created_at).await,
                        );
                        events.push(projection_event_json(event));
                    }
                }
                if backward {
                    events.reverse();
                }
                let events = truncate_before_stop_cursor(events, stop_cursor.as_deref());
                let terminal_cursor = match last_visible_position {
                    Some(position) => {
                        Some(sync_token_for_realm_position(state, realm_id, position).await)
                    }
                    None => Some(sync_token_for_state(state).await),
                };
                let events = full_events_from_projection_json(state, &events).await;
                return crate::result::json_ok(
                    serde_json::to_value(EventsQueryOutcome {
                        events,
                        snapshot_bootstrap: None,
                        prev_cursor: cursor.clone(),
                        next_cursor: match page.next_cursor {
                            Some(next_cursor) => Some(next_cursor),
                            None => terminal_cursor,
                        },
                        has_more: page.has_more,
                        range_completeness: Value::Null,
                    })
                    .unwrap_or(json!({})),
                );
            }
            Ok(None) => {}
            Err(error) => {
                if error.to_string().contains("invalid_cursor") {
                    return Err(crate::error::AppError::invalid_param("cursor not found")
                        .with_wire_code("invalid_cursor"));
                }
                return Err(crate::error::AppError::internal(error.to_string()));
            }
        }
        return crate::result::json_ok(
            serde_json::to_value(EventsQueryOutcome {
                events: Vec::new(),
                snapshot_bootstrap: None,
                prev_cursor: cursor.clone(),
                next_cursor: Some(sync_token_for_state(state).await),
                has_more: false,
                range_completeness: Value::Null,
            })
            .unwrap_or(json!({})),
        );
    }

    // Multi-Realm merge path: call `projected_event_page` per Realm, merge
    // by `received_at`, then paginate.
    let mut merged: Vec<serde_json::Value> = Vec::new();
    let mut any_has_more = false;
    for realm_id in &accessible_realms {
        match projected_event_page(state, realm_id, cursor.as_deref(), limit).await {
            Ok(Some(page)) => {
                if page.has_more {
                    any_has_more = true;
                }
                for event in &page.items {
                    if projection_record_visible_to_session(state, event, session.as_ref()).await {
                        merged.push(projection_event_json(event));
                    }
                }
            }
            Ok(None) => {}
            Err(error) => {
                if error.to_string().contains("invalid_cursor") {
                    return Err(crate::error::AppError::invalid_param("cursor not found")
                        .with_wire_code("invalid_cursor"));
                }
                continue;
            }
        }
    }
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
    let merged = truncate_before_stop_cursor(merged, stop_cursor.as_deref());
    let mut page_events = merged.into_iter().take(limit + 1).collect::<Vec<_>>();
    let limited = page_events.len() > limit || any_has_more;
    if page_events.len() > limit {
        page_events.truncate(limit);
    }
    let next_cursor = match limited
        .then(|| {
            page_events
                .last()
                .and_then(|event| event["event_id"].as_str().map(ToOwned::to_owned))
        })
        .flatten()
    {
        Some(next_cursor) => Some(next_cursor),
        None => Some(sync_token_for_state(state).await),
    };
    let events = full_events_from_projection_json(state, &page_events).await;
    crate::result::json_ok(
        serde_json::to_value(EventsQueryOutcome {
            events,
            snapshot_bootstrap: None,
            prev_cursor: cursor.clone(),
            next_cursor,
            has_more: limited,
            range_completeness: Value::Null,
        })
        .unwrap_or(json!({})),
    )
}

/// Enrich visible projection rows to full spec `Event` envelopes by fetching
/// each event's canonical record from the durable Event store, so the
/// Realm-scoped `ck.self.events.query` path returns the spec
/// `EventsQueryOutcome { events: Vec<Event> }` shape uniformly with the
/// actor-scoped durable reader (SOL-05-003). Rows whose canonical record is
/// absent (e.g. fully redacted / tombstoned) are dropped. Visibility and
/// pagination are already applied to `projection_rows` by the caller.
async fn full_events_from_projection_json(
    state: &AppState,
    projection_rows: &[Value],
) -> Vec<cokret_sdk::Event> {
    let mut events = Vec::with_capacity(projection_rows.len());
    for row in projection_rows {
        let Some(event_id) = row.get("event_id").and_then(Value::as_str) else {
            continue;
        };
        if let Ok(Some(record)) = state.persistence.events().get(event_id).await
            && let Ok(event) = super::event_log::sdk_event_for_state(state, &record)
        {
            events.push(event);
        }
    }
    events
}

async fn durable_events_query_from_parts(
    state: &AppState,
    session: &SessionRecord,
    parts: &EventsQueryParts,
) -> EventsQueryOutcome {
    let actors_set: BTreeSet<&str> = parts.actors.iter().map(String::as_str).collect();
    let realms_set: BTreeSet<&str> = parts.realms.iter().map(String::as_str).collect();
    let all_records = state
        .persistence
        .events()
        .snapshot_all()
        .await
        .unwrap_or_default();
    let mut records = Vec::new();
    for record in all_records {
        let actor_match = actors_set.contains(record.actor_id.as_str());
        let realm_match = record
            .realm_id
            .as_deref()
            .is_some_and(|realm| realms_set.contains(realm));
        if !(actor_match || realm_match) {
            continue;
        }
        if !super::event_log::event_visible_to_session(state, &record, session).await {
            continue;
        }
        if !canonical_event_visible_to_personal_blocklist(state, &record, session).await {
            continue;
        }
        records.push(record);
    }
    records.sort_by(|left, right| {
        left.received_at
            .cmp(&right.received_at)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    let (cursor, stop_cursor, backward) = events_query_cursor_and_stop(parts);
    if backward {
        records.reverse();
    }
    let start = cursor
        .as_deref()
        .and_then(|cursor| records.iter().position(|record| record.event_id == cursor))
        .map(|index| index + 1)
        .unwrap_or(0);
    let mut page = records
        .into_iter()
        .skip(start)
        .take(parts.limit + 1)
        .collect::<Vec<_>>();
    if let Some(stop_cursor) = stop_cursor.as_deref()
        && let Some(index) = page
            .iter()
            .position(|record| record.event_id == stop_cursor)
    {
        page.truncate(index);
    }
    let has_more = page.len() > parts.limit;
    if has_more {
        page.truncate(parts.limit);
    }
    let next_cursor = has_more
        .then(|| page.last().map(|record| record.event_id.clone()))
        .flatten();
    let events = page
        .iter()
        .filter_map(|record| super::event_log::sdk_event_for_state(state, record).ok())
        .collect();
    EventsQueryOutcome {
        events,
        snapshot_bootstrap: None,
        next_cursor,
        prev_cursor: None,
        has_more,
        range_completeness: Value::Null,
    }
}

#[endpoint(
    operation_id = "org.cokret.soland.sync.backfill_gap",
    tags("sync"),
    summary = "Backfill the gap between two cursors (deployment-local; not in spec)"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.sync.backfill_gap"))]
async fn sync_gap_backfill(
    realm_id: salvo::oapi::extract::QueryParam<String, true>,
    limit: salvo::oapi::extract::QueryParam<usize, false>,
    _from_cursor: salvo::oapi::extract::QueryParam<String, false>,
    _to_cursor: salvo::oapi::extract::QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<serde_json::Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let realm_id = scope_selector_to_realm_id(&realm_id.into_inner())?;
    let session = authenticated_session(state, req).await.ok();
    if !realm_id_accessible(state, &realm_id, session.as_ref()).await {
        return Err(crate::error::AppError::not_found("not found"));
    }
    let limit = limit.into_inner().unwrap_or(100).clamp(1, 500);
    let from_cursor = query_param(req, "from_cursor");
    let to_cursor = query_param(req, "to_cursor");

    // Resolve sync `ck:cursor:` tokens to reducer event cursors.
    let from_cursor = resolve_sync_cursor_to_event_id(state, &realm_id, from_cursor)
        .await
        .map_err(crate::error::AppError::invalid_param)?;
    let to_cursor = resolve_sync_cursor_to_event_id(state, &realm_id, to_cursor)
        .await
        .map_err(crate::error::AppError::invalid_param)?;

    let (events, next_cursor, limited) =
        backfill_gap_events(state, &realm_id, from_cursor.as_deref(), limit)
            .await
            .map_err(|error| {
                if error.to_string().contains("invalid_cursor") {
                    crate::error::AppError::invalid_param("cursor not found")
                        .with_wire_code("invalid_cursor")
                } else {
                    crate::error::AppError::internal(error.to_string())
                }
            })?;
    let mut filtered_events = Vec::new();
    for event in events {
        if projection_event_value_visible_to_session(state, &event, session.as_ref()).await {
            filtered_events.push(event);
        }
    }
    let events = filtered_events;
    let (events, gap_complete) = truncate_gap_events(events, to_cursor.as_deref());
    let next_cursor = if gap_complete {
        to_cursor.clone()
    } else {
        next_cursor
    };
    crate::result::json_ok(json!({
        "events": events,
        "from_cursor": from_cursor.clone(),
        "to_cursor": to_cursor.clone(),
        "prev_cursor": from_cursor.clone(),
        "next_cursor": next_cursor,
        "limited": limited && !gap_complete,
        "gap_complete": gap_complete || !limited,
        "production_gap": "durable_sync_position_validation",
    }))
}

#[endpoint(
    operation_id = "ck.self.snapshot.query.manifest_head",
    tags("sync"),
    summary = "Read the signed snapshot-v1 manifest head for a Realm"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.snapshot.query.manifest_head"))]
async fn snapshot_head(
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<serde_json::Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let realm_id = query_param(req, "realm_id")
        .ok_or_else(|| crate::error::AppError::missing_param("realm_id is required"))?;
    let realm_id = scope_selector_to_realm_id(&realm_id)?;
    let session = authenticated_session(state, req)
        .await
        .map_err(|(status, code, message)| {
            crate::error::AppError::invalid_param(message)
                .with_status(status)
                .with_wire_code(code)
        })?;
    if is_realm_deleted(state, &realm_id).await
        || !realm_id_accessible(state, &realm_id, Some(&session)).await
    {
        return Err(crate::error::AppError::not_found("not found"));
    }
    let manifest = snapshot_manifest_for_realm(state, &realm_id)
        .await
        .map_err(|error| {
            if error.code == crate::error::ErrorCode::NotFound {
                error
            } else if error.code == crate::error::ErrorCode::InternalError {
                error
            } else {
                crate::error::AppError::new(
                    crate::error::ErrorCode::SnapshotUnavailable,
                    error.message,
                )
            }
        })?;
    let value = serde_json::to_value(manifest)
        .map_err(|error| crate::error::AppError::internal(error.to_string()))?;
    crate::result::json_ok(value)
}

/// Deployment-local dev snapshot head (`/_soland/self/sync/snapshot-head`).
/// Serves the dev bundle descriptor (chunk plan + merkle root + dev digest)
/// that pairs with `org.cokret.soland.sync.snapshot_chunk`. This is NOT the
/// protocol `ck.self.snapshot.query.manifest_head` manifest contract.
#[endpoint(
    operation_id = "org.cokret.soland.sync.snapshot_head",
    tags("sync"),
    summary = "Read the deployment-local dev snapshot head (chunk plan + merkle root)"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.sync.snapshot_head"))]
async fn snapshot_head_dev(
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<serde_json::Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let realm_id = query_param(req, "realm_id")
        .ok_or_else(|| crate::error::AppError::missing_param("realm_id is required"))?;
    let realm_id = scope_selector_to_realm_id(&realm_id)?;
    if is_realm_deleted(state, &realm_id).await {
        return Err(crate::error::AppError::not_found("not found"));
    }
    let realm_id_value = RealmId::new(realm_id.clone())
        .map_err(|_| crate::error::AppError::invalid_param("invalid realm_id"))?;
    {
        let realms = state.realms.lock().expect("realms lock");
        if realms.get(&realm_id_value).is_none() {
            return Err(crate::error::AppError::not_found("not found"));
        }
    }
    let bundle = snapshot_bundle_for_realm(state, &realm_id)
        .await
        .ok_or_else(|| crate::error::AppError::not_found("not found"))?;
    // chunks[] is the per-chunk descriptor (id + size + digest) — receivers
    // fetch each chunk via `/sync/snapshot-chunk?chunk_id=N` and check it
    // against `merkle_root` using the chunk's `audit_path`.
    let chunk_descriptors: Vec<serde_json::Value> = bundle
        .chunks
        .iter()
        .map(|c| {
            json!({
                "chunk_id": c.chunk_id,
                "media_type": "application/json",
                "digest": c.digest.as_str(),
                "size": c.bytes.len(),
            })
        })
        .collect();
    let merkle_root = bundle.tree.root().as_str().to_owned();
    let service_did = state.config.service_did.clone();
    let digest_payload = format!("{}:{}:{}", bundle.id, bundle.state_digest, service_did);
    crate::result::json_ok(json!({
        "id": bundle.id,
        "state_digest": bundle.state_digest,
        "chunks": chunk_descriptors,
        "frontier": bundle.frontier,
        // Dev integrity digest over (id, state_digest, service
        // DID). Deliberately NOT named `signature`: the spec forbids
        // fabricating snapshot manifest signatures.
        "dev_digest": {
            "kid": format!("{service_did}#snapshot-dev"),
            "alg": "sha256-dev",
            "digest": sha256_hex(digest_payload.as_bytes())
        },
        "merkle_root": merkle_root,
        "chunk_count": bundle.chunk_count,
        "chunk_bytes": bundle.chunk_bytes,
        "total_bytes": bundle.total_bytes,
        "generator_proof": bundle.generator_proof,
    }))
}

#[endpoint(
    operation_id = "org.cokret.soland.sync.snapshot_chunk",
    tags("sync"),
    summary = "Read one chunk of a snapshot-v1 bundle (with audit_path proving merkle membership)"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.sync.snapshot_chunk"))]
async fn snapshot_chunk(
    snapshot_ref: salvo::oapi::extract::QueryParam<String, true>,
    chunk_id: salvo::oapi::extract::QueryParam<u32, false>,
    depot: &mut Depot,
) -> crate::result::JsonResult<serde_json::Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let snapshot_ref = snapshot_ref.into_inner();
    let chunk_id = chunk_id.into_inner().unwrap_or(0);
    let (realm_id, expected_hash) = parse_snapshot_ref(&snapshot_ref)
        .ok_or_else(|| crate::error::AppError::invalid_param("invalid snapshot_ref"))?;
    if is_realm_deleted(state, &realm_id).await {
        return Err(crate::error::AppError::not_found("not found"));
    }
    let bundle = snapshot_bundle_for_realm(state, &realm_id)
        .await
        .ok_or_else(|| crate::error::AppError::not_found("not found"))?;
    if bundle.id != snapshot_ref || bundle.state_digest != expected_hash {
        return Err(crate::error::AppError::new(
            crate::error::ErrorCode::StaleFrontier,
            "snapshot_ref no longer matches the current snapshot frontier",
        ));
    }
    // Snapshot v1: chunks[N] is the SDK-canonical SnapshotChunk @
    // chunk_id=N. Out-of-range `chunk_id` returns 404.
    let tree_size = bundle.tree.tree_size();
    let chunk = bundle
        .chunks
        .get(chunk_id as usize)
        .ok_or_else(|| crate::error::AppError::not_found("snapshot chunk not found"))?;
    let audit_path = bundle
        .tree
        .audit_path(chunk_id as usize)
        .unwrap_or_default()
        .into_iter()
        .map(|h| h.as_str().to_owned())
        .collect::<Vec<_>>();
    crate::result::json_ok(json!({
        "snapshot_ref": snapshot_ref,
        "chunk_id": chunk_id,
        "media_type": "application/json",
        "encoding": "base64url",
        "digest": chunk.digest.as_str(),
        "verified": cokret_sdk::canonical::sha256_digest(&chunk.bytes) == chunk.digest.as_str(),
        "bytes_base64": URL_SAFE_NO_PAD.encode(&chunk.bytes),
        "audit_path": audit_path,
        "tree_size": tree_size,
        "merkle_root": bundle.tree.root().as_str(),
    }))
}

#[cfg(test)]
#[path = "sync_tests.rs"]
mod tests;

// ════════════════════════════════════════════════════════════════════════
// EventsSubscribe NDJSON typed frames + cursor handle entropy (spec B1.5/T03).
// ════════════════════════════════════════════════════════════════════════

/// Spec B1.5 — when an implementation would emit a `Dropped` frame but
/// cannot supply a resume cursor, the wire-breaking rule downgrades to
/// `ResyncRequired`. Callers use [`dropped_or_resync`] to construct the
/// correct frame body from an optional cursor.
///
/// Note: the cursor type expected by `EventsSubscribeFrameBody::Dropped`
/// is the typed-id `cokret_identifiers::Cursor` (`ck:cursor:<base64url>`),
/// NOT the `cokret_sdk::Cursor` struct produced by `cursor::Cursor::new()`.
/// The typed-id is exposed as `cokret_sdk::identifiers::Cursor`.
pub fn dropped_or_resync(
    cursor: Option<cokret_sdk::identifiers::Cursor>,
    reason: impl Into<String>,
    reconnect_after_ms: Option<u64>,
) -> cokret_sdk::EventsSubscribeFrameBody {
    let reason = reason.into();
    match cursor {
        Some(cursor) => cokret_sdk::EventsSubscribeFrameBody::Dropped {
            cursor,
            reason,
            reconnect_after_ms,
        },
        None => cokret_sdk::EventsSubscribeFrameBody::ResyncRequired {
            reason,
            reconnect_after_ms,
        },
    }
}

/// Spec T03 — minimum length of a base64url cursor handle to supply
/// ≥128-bit entropy. Spec tightened `h.minLength` from 16 → 22.
pub const CURSOR_HANDLE_MIN_LENGTH: usize = 22;

/// Validate an inbound cursor handle (post-base64url-decode is callers'
/// responsibility). Spec T03 — rejects shorter than 22 chars.
pub fn validate_cursor_handle(handle: &str) -> Result<(), (crate::error::ErrorCode, &'static str)> {
    if handle.len() < CURSOR_HANDLE_MIN_LENGTH {
        return Err((
            crate::error::ErrorCode::CursorIntegrityInvalid,
            "cursor handle MUST be at least 22 base64url characters \
             (≥128-bit entropy); spec tightening",
        ));
    }
    if !handle
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
    {
        return Err((
            crate::error::ErrorCode::CursorIntegrityInvalid,
            "cursor handle MUST be base64url (no padding)",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod cursor_frame_tests {
    use super::*;

    #[test]
    fn dropped_without_cursor_downgrades_to_resync() {
        let body = dropped_or_resync(None, "broadcast_lag", Some(10_000));
        assert!(matches!(
            body,
            cokret_sdk::EventsSubscribeFrameBody::ResyncRequired { .. }
        ));
        let cursor = cokret_sdk::identifiers::Cursor::new("ck:cursor:resume").unwrap();
        let body = dropped_or_resync(Some(cursor), "broadcast_lag", Some(10_000));
        assert!(matches!(
            body,
            cokret_sdk::EventsSubscribeFrameBody::Dropped {
                reconnect_after_ms: Some(10_000),
                ..
            }
        ));
    }

    #[test]
    fn cursor_handle_minimum_length_enforced() {
        // 22-char handle should pass.
        let ok = "a".repeat(22);
        validate_cursor_handle(&ok).unwrap();
        // 21-char handle must fail.
        let bad = "a".repeat(21);
        let err = validate_cursor_handle(&bad).unwrap_err();
        assert_eq!(err.0, crate::error::ErrorCode::CursorIntegrityInvalid);
    }
}
