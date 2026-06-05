//! Account aggregate + snapshot handlers + the cursor-helper machinery they share
//! with events and device-message modules.
//!
//! Surfaces for the current sync/event wire layout:
//! - `GET  /_cokret/self/account/describe`
//! - `GET  /_cokret/self/account/subscribe`       — `ck.self.account.subscribe` (account-aggregate
//!   NDJSON: timeline, presence, typing, to_device).
//! - `POST /_cokret/self/ephemeral`               — `ck.self.ephemeral.send` (broadcast ephemeral)
//! - `GET  /_cokret/self/events/subscribe`        — `ck.self.events.subscribe`. Multi-Realm /
//!   multi-actor stream; frame `kind` field replaces `type`.
//! - `GET  /_cokret/self/events`                  — `ck.self.events.query` (replaces
//!   `ck.events.list` + `ck.sync.backfill` via `direction=forward|backward`).
//! - `GET  /_cokret/self/sync/backfill/gap`       — `ck.sync.backfill_gap` (deployment-local; not
//!   in spec)
//! - `GET  /_cokret/self/snapshot/head`
//! - `GET  /_soland/self/sync/snapshot-chunk`
//!
//! `SyncCursor`, `SyncCursorError`, `parse_and_validate_sync_cursor`,
//! `decode_sync_cursor_value`, `sync_token_for_client_sync`, `sync_filter_digest`,
//! are `pub` because sibling routing modules reuse them. They
//! live here because the cursor lifecycle is anchored to account subscribe.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use chrono::{DateTime, Duration as ChronoDuration, SecondsFormat, Utc};
use cokret_sdk::lattice::CellState;
use cokret_sdk::{EphemeralSubmitResBody, RealmId};
use ed25519_dalek::{Signature, Signer as _, Verifier as _};
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
    augment_timeline_message_json, authenticated_session, backfill_gap_events,
    default_discussion_track, device_message_events_after, flow_id_from_realm_id,
    flow_projection_for_realm, is_realm_deleted, now, parse_snapshot_ref, projected_event_page,
    projection_event_json, prune_acked_device_messages, prune_expired_typing, query_param,
    realm_discoverability, realm_event_visible_to_session, realm_has_member,
    realm_history_visibility, realm_id_accessible, realm_visible_to, render_error, sha256_hex,
    snapshot_bundle_for_realm, sync_timeline_message_json_with_projection, truncate_gap_events,
    typing_ephemeral_for_realm, validate_did,
};
use crate::ids;
use crate::reducer::ProjectionState;
use crate::state::{
    AppState, HandleClaimDigestInput, HandleClaimEvidenceRecord, PresenceRecord,
    ProjectionEventRecord, RealmDirectoryEntry, SessionRecord, TypingRecord,
};
use crate::wire::{
    AccountDescribeResBody, BackfillResBody, ClientSyncRequest, EventsQueryPostRequest,
    SnapshotHeadResponse,
};

const TIMELINE_POSITION_SUBTICKS: i64 = 1024;
const PERSONAL_BLOCKLIST_DATA_TYPES: &[&str] = &["ck.account.blocklist", "ck.account.blocklist.v1"];
const PRESENCE_ONLINE_TTL_SECONDS: i64 = 3;
const HANDLE_CLAIMS_INLINE_MAX_BYTES: usize = 8 * 1024;

#[cfg(test)]
static TEST_STATELESS_CURSOR_PROFILE_DECLARED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

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
        .push(Router::with_path("snapshot/head").get(snapshot_head))
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
async fn account_describe(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let mut supported_sync_profiles = vec![
        "initial".to_owned(),
        "incremental".to_owned(),
        "board".to_owned(),
        "chat".to_owned(),
        "topic".to_owned(),
        "offline_queue_flush".to_owned(),
        "backfill_gap".to_owned(),
        "bottom_cell_repair".to_owned(),
    ];
    if is_stateless_cursor_profile_declared(state) {
        supported_sync_profiles.push("ck.profile.stateless_cursor.v1".to_owned());
    }
    res.render(Json(AccountDescribeResBody {
        service_did: state.config.service_did.clone(),
        supported_sync_profiles,
        limits: json!({
            "max_realms": 50,
            "max_timeline_events": 100,
            "offline_flush_endpoint": "/_cokret/self/events",
            "backfill_endpoint": "/_cokret/self/sync/backfill/gap",
            "bottom_repair_endpoint": "/_soland/admin/realms/{realm_id}/bottom/{cell_id}/repair"
        }),
        frontier: json!({"storage": state.db.mode(), "generated_at": now()}),
    }));
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
/// Maximum lifetime of an issued sync cursor (mirrors the 1h TTL minted by
/// [`sync_token_for_client_sync`]). A revocation record is retained for at
/// least this long so a leaked cursor cannot outlive its revocation.
const CURSOR_MAX_TTL_SECONDS: i64 = 3600;

#[endpoint(
    operation_id = "ck.self.account.subscribe",
    tags("sync"),
    summary = "Account-aggregate subscribe stream (timeline / presence / typing / to_device)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.account.subscribe"))]
async fn account_subscribe(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected").clone();
    let body = account_subscribe_query(req);
    let max_wait_ms = parse_max_wait_ms(req);
    let session = authenticated_session(&state, req).await.ok();
    let subscribe_scope_key = account_subscribe_scope_key(req, session.as_ref(), &body);
    if reject_subscribe_reconnect(&state, &subscribe_scope_key, res) {
        return;
    }
    let after_cursor = if let Some(after) = body.after.as_deref() {
        match parse_and_validate_sync_cursor(
            after,
            &state,
            session.as_ref(),
            body.filter.as_ref(),
            chrono::Utc::now().timestamp_millis(),
        ) {
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
    if let Some(presence) = body.set_presence.as_deref()
        && !matches!(presence, "online" | "offline" | "unavailable")
    {
        crate::error::render_error_code(
            crate::error::ErrorCode::InvalidParam,
            res,
            "set_presence must be online, offline, or unavailable",
        );
        return;
    }

    if let Some(presence) = body.set_presence.as_deref() {
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
                status: presence.to_owned(),
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
                            response = build_sync_snapshot(&state, session.as_ref(), &body, &after_cursor).await;
                            if !delta_is_empty(&response) {
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

/// `POST /_cokret/self/account/cursor/revoke` — `ck.self.account.cursor_revoke`.
///
/// High-assurance optional endpoint: record a previously issued cursor
/// authority in the revocation set until its maximum TTL would have elapsed.
/// A revoked cursor thereafter returns `cursor_revoked` from
/// [`parse_and_validate_sync_cursor`] and never advances to-device ack,
/// account-subscribe resume position, wait-for barrier state, or dropped
/// recovery state. `revoke_scope` controls breadth (`this_cursor` default,
/// `same_device`, `same_session`).
#[endpoint(
    operation_id = "ck.self.account.cursor_revoke",
    tags("sync"),
    summary = "Revoke a previously issued cursor authority",
    status_codes(200, 400, 401, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.account.cursor_revoke"))]
async fn account_cursor_revoke(
    aa: crate::routing::system::extract::AuthArgs,
    body: salvo::oapi::extract::JsonBody<crate::wire::CursorRevokeRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<crate::wire::CursorRevokeResponse> {
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
    let scope = body.revoke_scope.as_deref().unwrap_or("this_cursor");
    if !matches!(scope, "this_cursor" | "same_device" | "same_session") {
        return Err(AppError::invalid_param(
            "revoke_scope must be this_cursor, same_device, or same_session",
        ));
    }

    let revoked_at = now();
    let expires_at = revoked_at + ChronoDuration::seconds(CURSOR_MAX_TTL_SECONDS);
    let device_id = if scope == "this_cursor" {
        None
    } else {
        Some(session.device_id.clone())
    };
    let record = crate::state::CursorRevocation {
        cursor_digest: sha256_hex(cursor.as_bytes()),
        principal_id: session.actor.clone(),
        device_id,
        scope: scope.to_owned(),
        reason_code: reason_code.to_owned(),
        revoked_at,
        expires_at,
    };
    {
        let now_ms = revoked_at.timestamp_millis();
        let mut revocations = state
            .sync_cursor_revocations
            .lock()
            .expect("sync cursor revocations lock");
        revocations.retain(|entry| entry.expires_at.timestamp_millis() > now_ms);
        revocations.push(record);
    }

    crate::json_ok(crate::wire::CursorRevokeResponse {
        revoked: true,
        expires_at: expires_at.to_rfc3339_opts(SecondsFormat::Millis, true),
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
fn delta_is_empty(response: &cokret_sdk::model::SyncResBody) -> bool {
    response.realms.is_empty()
        && response.left_realms.is_empty()
        && response.to_device.is_empty()
        && response.presence.is_empty()
}

fn account_subscribe_query(req: &mut Request) -> ClientSyncRequest {
    ClientSyncRequest {
        after: query_param(req, "after"),
        catchup: query_param(req, "catchup").and_then(|value| value.parse::<bool>().ok()),
        filter: query_param(req, "filter").and_then(|value| serde_json::from_str(&value).ok()),
        set_presence: query_param(req, "set_presence"),
    }
}

fn account_delta_frame(response: cokret_sdk::model::SyncResBody) -> Value {
    json!({
        "kind": "delta",
        "cursor": response.cursor,
        "realms": response.realms,
        "to_device": {"messages": response.to_device},
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
    body: &ClientSyncRequest,
) -> String {
    format!(
        "ck.self.account.subscribe|{}|filter={}",
        subscribe_subject(req, session),
        sync_filter_digest(body.filter.as_ref())
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
/// `ck.self.account.subscribe` delta frame.
async fn build_sync_snapshot(
    state: &AppState,
    session: Option<&SessionRecord>,
    body: &ClientSyncRequest,
    after_cursor: &SyncCursor,
) -> cokret_sdk::model::SyncResBody {
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
    for space in &candidate_realms {
        if realm_visible_to(state, space, session).await {
            let members = roster_members_for_realm(state, space, session, body);
            visible_realms.push((
                space.realm_id.to_string(),
                space.name.clone(),
                space.description.clone(),
                space.tags.clone(),
                space.category.clone(),
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
    let mut positions = BTreeMap::new();
    let is_incremental = body.after.is_some();
    let cursor_issued_at = after_cursor
        .issued_at_ms
        .and_then(chrono::DateTime::<Utc>::from_timestamp_millis);
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
        let known_to_cursor = after_cursor.positions.contains_key(&realm_id);
        let after_position = after_cursor
            .positions
            .get(&realm_id)
            .copied()
            .unwrap_or_default();
        let (timeline_events, space_position) =
            timeline_events_for_realm(state, &projection, &realm_id, after_position, session).await;
        positions.insert(realm_id.clone(), space_position);
        // Incremental sync skips realms whose timeline position is
        // unchanged AND whose meta `updated_at` is at-or-before the
        // cursor's `issued_at`. This drops the always-full
        // `summary`/`flows`/`state_after`/`members` baseline from idle
        // polls — the realm stays in the client's local projection.
        //
        // Caveats: membership changes that don't bump `realm_meta.updated_at`
        // (e.g. raw `ck.realm.member.update` events) will not propagate
        // through an incremental sync until either (a) a new timeline
        // event arrives, or (b) the client issues a full sync (no
        // `after`). This is a known limitation — see follow-up TODO to
        // add per-realm activity tracking off `event_broadcast`.
        if is_incremental
            && known_to_cursor
            && timeline_events.is_empty()
            && space_position == after_position
        {
            let meta_changed = meta
                .as_ref()
                .zip(cursor_issued_at.as_ref())
                .is_some_and(|(record, issued_at)| record.updated_at > *issued_at);
            if !meta_changed {
                continue;
            }
        }
        let bottom_cells = bottom_cells_for_realm(&projection, &realm_id);
        let anchor_view = anchor_view_for_realm(&bottom_cells);
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
                "anchor_view": anchor_view,
                "ephemeral": ephemeral,
                "unread": {"notification_count": 0, "highlight_count": 0}
            }),
        );
    }
    drop(projection);

    let mut to_device_position = after_cursor.to_device_position;
    let to_device = if let Some(session) = session {
        prune_acked_device_messages(state, session, after_cursor.to_device_position).await;
        let queued = state
            .persistence
            .device_messages()
            .list_after(
                &session.actor,
                &session.device_id,
                after_cursor.to_device_position,
            )
            .await
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
    } else {
        Vec::new()
    };

    // Actor-private account data: hydrate every `(actor, data_type)` row
    // owned by the authenticated session so the client can join e.g.
    // `ck.contacts.space.<realm_id>` Space remarks against the public
    // Space `title` during render. Spec: discovery/client-preferences.md
    // §2 (storage model) / §3.7 (Space remarks).
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

    cokret_sdk::model::SyncResBody {
        cursor: sync_token_for_client_sync(
            state,
            session,
            body.filter.as_ref(),
            positions,
            to_device_position,
        ),
        realms: sync_realms,
        left_realms,
        to_device,
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
    space: &crate::state::RealmDirectoryEntry,
    session: Option<&SessionRecord>,
    body: &ClientSyncRequest,
) -> Vec<Value> {
    let registry = state.member_identity_registry();
    let context = RosterDisclosureContext::new(state, space, session, body);
    space
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
            if let Some(snapshot) = registry.snapshot_for_actor(space.realm_id.as_str(), did_str) {
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
                            space.realm_id.as_str(),
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
        space: &'a RealmDirectoryEntry,
        session: Option<&'a SessionRecord>,
        body: &ClientSyncRequest,
    ) -> Self {
        Self {
            service_did: &state.config.service_did,
            realm_public: space.public,
            realm_members: &space.members,
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
    body: &ClientSyncRequest,
) -> String {
    body.filter
        .as_ref()
        .and_then(|filter| filter.get("handle_claim_audience"))
        .or_else(|| {
            body.filter
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

fn anchor_view_for_realm(bottom_cells: &[Value]) -> Value {
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
        "decryption_state": if message.encrypted { "opaque" } else { "cleartext" },
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
    pub positions: BTreeMap<String, i64>,
    pub to_device_position: i64,
    /// `ctx.issued_at_ms` from the stateful handle. Used by
    /// `build_sync_snapshot` to skip unchanged realms on incremental sync —
    /// any realm whose meta `updated_at` is at or before this point AND
    /// whose timeline position is unchanged is "delta-empty" and omitted.
    pub issued_at_ms: Option<i64>,
}

#[derive(Debug)]
pub enum SyncCursorError {
    Invalid(&'static str),
    Mismatch(&'static str),
    Integrity(&'static str),
    Expired,
    /// The cursor authority was revoked via `ck.self.account.cursor_revoke`.
    /// Surfaced as `cursor_revoked`; MUST be raised before any server-side
    /// state advancement (to-device ack, account-subscribe resume, wait-for
    /// barrier release, dropped/resync recovery).
    Revoked,
}

pub fn sync_token_for_client_sync(
    state: &AppState,
    session: Option<&SessionRecord>,
    filter: Option<&serde_json::Value>,
    realms_positions: BTreeMap<String, i64>,
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
        "devices": device_positions,
        "to_device": to_device_position
    });
    if is_stateless_cursor_profile_declared(state) {
        let cursor = json!({
            "v": "1",
            "purpose": "stream",
            "t": issued_at.to_rfc3339_opts(SecondsFormat::Millis, true),
            "x": expires_at_ms,
            "issuer_kid": stateless_cursor_issuer_kid(state),
            "target": {
                "principal_id": principal_id,
                "device_id": device_id,
                "service_id": state.config.service_did.clone()
            },
            "scope": {
                "filter_digest": filter_digest
            },
            "positions": positions,
            "issued_at_ms": issued_at_ms
        });
        let signed = sign_stateless_sync_cursor(state, cursor)
            .expect("stateless sync cursor must be signable");
        return encode_sync_cursor_value(signed);
    }
    let ctx = json!({
        "principal_id": principal_id,
        "device_id": device_id,
        "service_id": state.config.service_did.clone(),
        "filter_digest": filter_digest,
        "issued_at_ms": issued_at_ms
    });
    let handle = store_sync_cursor_handle(
        state,
        json!({
            "ctx": ctx,
            "positions": positions,
            "expires_at_ms": expires_at_ms
        }),
    );
    let cursor = json!({
        "v": "1",
        "purpose": "stream",
        "t": issued_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "x": expires_at_ms,
        "h": handle
    });
    encode_sync_cursor_value(cursor)
}

pub(crate) fn sync_token_for_state(state: &AppState) -> String {
    let issued_at = chrono::Utc::now();
    let expires_at = issued_at + ChronoDuration::hours(1);
    let expires_at_ms = expires_at.timestamp_millis();
    let handle = store_sync_cursor_handle(
        state,
        json!({
            "ctx": {
                "kind": "generic",
                "service_id": state.config.service_did.clone(),
                "issued_at_ms": issued_at.timestamp_millis()
            },
            "positions": {
                "realms": {},
                "devices": {},
                "to_device": 0
            },
            "expires_at_ms": expires_at_ms
        }),
    );
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

fn store_sync_cursor_handle(state: &AppState, stored: Value) -> String {
    loop {
        let handle = cokret_sdk::cursor::generate_cursor_handle()
            .unwrap_or_else(|error| fallback_sync_cursor_handle(&error));
        let mut handles = state
            .sync_cursor_handles
            .lock()
            .expect("sync cursor handles lock");
        if !handles.contains_key(&handle) {
            handles.insert(handle.clone(), stored.clone());
            return handle;
        }
    }
}

fn fallback_sync_cursor_handle(error: &cokret_sdk::Error) -> String {
    let seed = format!(
        "soland-sync-cursor-fallback:{}:{:?}",
        Utc::now().timestamp_nanos_opt().unwrap_or_default(),
        std::thread::current().id()
    );
    let digest = sha256_hex(seed.as_bytes());
    tracing::error!(%error, "cursor handle RNG unavailable; using deterministic emergency handle");
    format!("fallback{}", &digest[..54])
}

fn stored_sync_cursor_by_handle(state: &AppState, handle: &str) -> Result<Value, SyncCursorError> {
    state
        .sync_cursor_handles
        .lock()
        .expect("sync cursor handles lock")
        .get(handle)
        .cloned()
        .ok_or(SyncCursorError::Integrity("sync cursor handle is unknown"))
}

/// CURSOR-1 — is `ck.profile.stateless_cursor.v1` declared by this
/// deployment? Toggled by the `SOLAND_PROFILE_STATELESS_CURSOR` env var
/// (mirrors the gating pattern used by `accountable_principals.strict_reject.v1`
/// in `routing/events/operations.rs`). Default: stateful-only.
fn is_stateless_cursor_profile_declared(_state: &AppState) -> bool {
    #[cfg(test)]
    if TEST_STATELESS_CURSOR_PROFILE_DECLARED.load(std::sync::atomic::Ordering::SeqCst) {
        return true;
    }

    matches!(
        std::env::var("SOLAND_PROFILE_STATELESS_CURSOR").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes")
    )
}

fn has_stateless_cursor_marker(value: &Value) -> bool {
    value.get("_mac").is_some()
        || value.get("_sig").is_some()
        || value.get("positions").is_some()
        || value.get("scope").is_some()
        || value.get("s").is_some()
        || value.get("d").is_some()
        || value.get("target").is_some()
        || value.get("issuer_kid").is_some()
}

fn stateless_cursor_issuer_kid(state: &AppState) -> String {
    format!("{}#anchorer-key", state.config.service_did)
}

fn stateless_cursor_canonical_body(cursor: &Value) -> Result<Vec<u8>, SyncCursorError> {
    let mut body = cursor.clone();
    let Some(object) = body.as_object_mut() else {
        return Err(SyncCursorError::Invalid(
            "stateless cursor body must be a JSON object",
        ));
    };
    object.remove("_sig");
    object.remove("_mac");
    cokret_sdk::canonical::canonical_json_bytes(&body)
        .map_err(|_| SyncCursorError::Integrity("stateless cursor canonical body is invalid"))
}

fn sign_stateless_sync_cursor(
    state: &AppState,
    mut cursor: Value,
) -> Result<Value, SyncCursorError> {
    let issuer_kid = stateless_cursor_issuer_kid(state);
    {
        let Some(object) = cursor.as_object_mut() else {
            return Err(SyncCursorError::Invalid(
                "stateless cursor body must be a JSON object",
            ));
        };
        object.insert("issuer_kid".to_owned(), Value::String(issuer_kid));
        object.remove("_sig");
        object.remove("_mac");
    }
    let canonical_body = stateless_cursor_canonical_body(&cursor)?;
    let signature = state.anchorer_signing_key().sign(&canonical_body);
    let Some(object) = cursor.as_object_mut() else {
        return Err(SyncCursorError::Invalid(
            "stateless cursor body must be a JSON object",
        ));
    };
    object.insert(
        "_sig".to_owned(),
        json!({
            "alg": "Ed25519",
            "sig": URL_SAFE_NO_PAD.encode(signature.to_bytes())
        }),
    );
    Ok(cursor)
}

fn stateless_cursor_signature(cursor: &Value) -> Result<Signature, SyncCursorError> {
    let sig_b64 = match cursor.get("_sig") {
        Some(Value::String(sig)) => sig.as_str(),
        Some(Value::Object(sig)) => {
            let alg = sig
                .get("alg")
                .and_then(Value::as_str)
                .ok_or(SyncCursorError::Integrity(
                    "stateless cursor signature missing alg",
                ))?;
            if !matches!(alg, "Ed25519" | "EdDSA") {
                return Err(SyncCursorError::Integrity(
                    "stateless cursor signature alg is unsupported",
                ));
            }
            sig.get("sig")
                .or_else(|| sig.get("signature"))
                .or_else(|| sig.get("signature_b64"))
                .and_then(Value::as_str)
                .ok_or(SyncCursorError::Integrity(
                    "stateless cursor signature missing sig",
                ))?
        }
        Some(_) => {
            return Err(SyncCursorError::Integrity(
                "stateless cursor _sig must be a signature string or object",
            ));
        }
        None => {
            return Err(SyncCursorError::Integrity(
                "stateless cursor missing _sig integrity tag",
            ));
        }
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(sig_b64.as_bytes())
        .map_err(|_| SyncCursorError::Integrity("stateless cursor signature is not base64url"))?;
    Signature::from_slice(&bytes)
        .map_err(|_| SyncCursorError::Integrity("stateless cursor signature is invalid length"))
}

fn verify_stateless_sync_cursor_signature(
    cursor: &Value,
    state: &AppState,
) -> Result<(), SyncCursorError> {
    let issuer_kid =
        cursor
            .get("issuer_kid")
            .and_then(Value::as_str)
            .ok_or(SyncCursorError::Integrity(
                "stateless cursor missing issuer_kid binding",
            ))?;
    let expected_issuer_kid = stateless_cursor_issuer_kid(state);
    if issuer_kid != expected_issuer_kid {
        return Err(SyncCursorError::Integrity(
            "stateless cursor issuer_kid is not this service issuer",
        ));
    }

    let signature = stateless_cursor_signature(cursor).inspect_err(|_error| {
        crate::metrics::record_digest_mismatch("cursor_canonical_digest");
    })?;
    let canonical_body = stateless_cursor_canonical_body(cursor).inspect_err(|_error| {
        crate::metrics::record_digest_mismatch("cursor_canonical_digest");
    })?;
    state
        .anchorer_signing_key()
        .verifying_key()
        .verify(&canonical_body, &signature)
        .map_err(|_| {
            crate::metrics::record_digest_mismatch("cursor_canonical_digest");
            SyncCursorError::Integrity("stateless cursor signature verification failed")
        })
}

fn sync_cursor_from_stateless_value(
    value: &Value,
    state: &AppState,
    session: Option<&SessionRecord>,
    filter: Option<&serde_json::Value>,
) -> Result<SyncCursor, SyncCursorError> {
    let target =
        value
            .get("target")
            .and_then(Value::as_object)
            .ok_or(SyncCursorError::Integrity(
                "stateless cursor missing target binding",
            ))?;
    let expected_principal = session
        .map(|session| session.actor.as_str())
        .unwrap_or("anonymous");
    let expected_device = session
        .map(|session| session.device_id.as_str())
        .unwrap_or("anonymous");
    if target
        .get("principal_id")
        .and_then(Value::as_str)
        .is_none_or(|principal| principal != expected_principal)
    {
        return Err(SyncCursorError::Mismatch(
            "cursor principal does not match request actor",
        ));
    }
    if target
        .get("device_id")
        .and_then(Value::as_str)
        .is_none_or(|device| device != expected_device)
    {
        return Err(SyncCursorError::Mismatch(
            "cursor device does not match request device",
        ));
    }
    if target
        .get("service_id")
        .and_then(Value::as_str)
        .is_none_or(|service| service != state.config.service_did)
    {
        return Err(SyncCursorError::Mismatch(
            "cursor service does not match this service DID",
        ));
    }

    let scope = value
        .get("scope")
        .and_then(Value::as_object)
        .ok_or(SyncCursorError::Integrity(
            "stateless cursor missing scope binding",
        ))?;
    let expected_filter_digest = sync_filter_digest(filter);
    if scope
        .get("filter_digest")
        .and_then(Value::as_str)
        .is_none_or(|filter_digest| filter_digest != expected_filter_digest)
    {
        return Err(SyncCursorError::Mismatch(
            "cursor filter digest does not match request filter",
        ));
    }

    let positions_value = value.get("positions").ok_or(SyncCursorError::Integrity(
        "stateless cursor missing positions",
    ))?;
    let positions = positions_value
        .get("realms")
        .and_then(Value::as_object)
        .ok_or(SyncCursorError::Integrity(
            "stateless cursor missing positions.realms",
        ))?
        .iter()
        .filter_map(|(realm_id, position)| {
            position
                .as_i64()
                .map(|position| (realm_id.clone(), position))
        })
        .collect();
    let to_device_position = positions_value
        .get("to_device")
        .and_then(Value::as_i64)
        .unwrap_or_default();
    let issued_at_ms = value
        .get("issued_at_ms")
        .and_then(Value::as_i64)
        .or_else(|| {
            value
                .get("t")
                .and_then(Value::as_str)
                .and_then(|issued_at| DateTime::parse_from_rfc3339(issued_at).ok())
                .map(|issued_at| issued_at.timestamp_millis())
        });

    Ok(SyncCursor {
        positions,
        to_device_position,
        issued_at_ms,
    })
}

pub fn parse_and_validate_sync_cursor(
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
    // CURSOR-1 (R3 spec-sync 2026-05-27, cokret-spec b47ff6ec) —
    // core schema rejects stateless body fields unless the server
    // declares `ck.profile.stateless_cursor.v1`. Stateless body markers
    // per `_before_todos.md §0.14`: `_mac`, `_sig`, `s`, `d`, `target`,
    // `issuer_kid`. Also keeps the existing `_ctx` / `_positions`
    // rejects which are soland-specific stateful-only fields.
    let stateless_cursor_declared = is_stateless_cursor_profile_declared(state);
    let has_stateless_marker = has_stateless_cursor_marker(&value);
    if has_stateless_marker && !stateless_cursor_declared {
        return Err(SyncCursorError::Integrity(
            "core cursor must use stateful handle form (stateless body \
             requires ck.profile.stateless_cursor.v1)",
        ));
    }
    if value.get("_ctx").is_some() || value.get("_positions").is_some() {
        return Err(SyncCursorError::Integrity(
            "core cursor must use stateful handle form",
        ));
    };
    if stateless_cursor_declared && has_stateless_marker {
        verify_stateless_sync_cursor_signature(&value, state)?;
        if value.get("h").is_none() {
            return sync_cursor_from_stateless_value(&value, state, session, filter);
        }
    }
    let Some(handle) = value.get("h").and_then(|h| h.as_str()) else {
        return Err(SyncCursorError::Integrity("after cursor must contain h"));
    };
    if validate_cursor_handle(handle).is_err() {
        return Err(SyncCursorError::Invalid("invalid cursor handle"));
    }
    let stored = stored_sync_cursor_by_handle(state, handle)?;
    if stored
        .get("expires_at_ms")
        .and_then(|expires_at| expires_at.as_i64())
        .is_none_or(|expires_at| expires_at <= now_ms)
    {
        state
            .sync_cursor_handles
            .lock()
            .expect("sync cursor handles lock")
            .remove(handle);
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
    let positions = positions_value
        .get("realms")
        .and_then(|realms| realms.as_object())
        .ok_or(SyncCursorError::Integrity(
            "cursor handle is missing positions.realms",
        ))?
        .iter()
        .filter_map(|(realm_id, position)| {
            position
                .as_i64()
                .map(|position| (realm_id.clone(), position))
        })
        .collect();
    let to_device_position = positions_value
        .get("to_device")
        .and_then(|position| position.as_i64())
        .unwrap_or_default();
    let issued_at_ms = ctx.get("issued_at_ms").and_then(|value| value.as_i64());
    Ok(SyncCursor {
        positions,
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
///   `realm_id` (a `timestamp_micros` checkpoint), then walk the space's projected events and
///   persisted messages to find the most recent event at-or-before that checkpoint and return its
///   `event_id`. When no event sits at-or-before the checkpoint, return `None` so backfill streams
///   from the start of the space.
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
    let has_stateless_marker = has_stateless_cursor_marker(&value);
    if has_stateless_marker {
        if !is_stateless_cursor_profile_declared(state) {
            return Err("sync cursor integrity invalid");
        }
        verify_stateless_sync_cursor_signature(&value, state)
            .map_err(|_| "sync cursor integrity invalid")?;
    }
    let checkpoint = if let Some(handle) = value.get("h").and_then(Value::as_str) {
        let stored = stored_sync_cursor_by_handle(state, handle)
            .map_err(|_| "sync cursor handle is unknown")?;
        stored
            .get("positions")
            .and_then(|positions| positions.get("realms"))
            .and_then(|realms| realms.get(realm_id))
            .and_then(|position| position.as_i64())
    } else if has_stateless_marker {
        value
            .get("positions")
            .and_then(|positions| positions.get("realms"))
            .and_then(|realms| realms.get(realm_id))
            .and_then(|position| position.as_i64())
    } else {
        return Err("sync cursor is missing stateful handle");
    };
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
        .unwrap_or_else(|_| format!("sha256:{}", sha256_hex(binding.to_string().as_bytes())))
}

#[endpoint(
    operation_id = "ck.self.ephemeral.send",
    tags("sync"),
    summary = "Send a broadcast ephemeral signal"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.ephemeral.send"))]
async fn submit_ephemeral(
    aa: crate::routing::system::extract::AuthArgs,
    body: salvo::oapi::extract::JsonBody<cokret_sdk::EphemeralEnvelope>,
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<EphemeralSubmitResBody> {
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

    crate::result::json_ok(EphemeralSubmitResBody {
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

/// `ck.self.events.subscribe` at `GET /_cokret/self/events/subscribe`. NDJSON
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

    let catchup_cursor = last_cursor.unwrap_or_else(|| sync_token_for_state(&state));
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
                                EventNotificationKind::Frontier { state_root, anchor_id } => {
                                    json!({
                                        "kind": "frontier",
                                        "realm_id": notification.realm_id,
                                        "state_root": state_root,
                                        "anchor_id": anchor_id,
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
        "ck.self.events.subscribe|{}|realms={realms}",
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

/// `ck.self.events.query` at `GET /_cokret/self/events`.
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
    operation_id = "ck.self.events.query",
    tags("events"),
    summary = "Projection-aware events query (single- or multi-Realm merge; backward / forward direction)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.events.query"))]
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
    operation_id = "ck.self.events.query_post",
    tags("events"),
    summary = "Body-based projection-aware events query for large selectors"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.events.query_post"))]
pub(super) async fn events_query_post(
    body: salvo::oapi::extract::JsonBody<EventsQueryPostRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<serde_json::Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    let parts = EventsQueryParts {
        realms: body.realms,
        actors: body.actors,
        after: body.after,
        before: body.before,
        order: body.order.unwrap_or_else(|| "default".to_owned()),
        limit: body.limit.unwrap_or(100).clamp(1, 100),
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

    // Single-Realm fast path preserves the original `BackfillResBody` shape
    // for soland's existing test surface (ck.sync.backfill behavior).
    if accessible_realms.len() == 1 {
        let realm_id = &accessible_realms[0];
        match projected_event_page(state, realm_id, cursor.as_deref(), limit).await {
            Ok(Some(page)) => {
                let mut events: Vec<Value> = Vec::new();
                for event in &page.items {
                    if projection_record_visible_to_session(state, event, session.as_ref()).await {
                        events.push(projection_event_json(event));
                    }
                }
                if backward {
                    events.reverse();
                }
                let events = truncate_before_stop_cursor(events, stop_cursor.as_deref());
                return crate::result::json_ok(
                    serde_json::to_value(BackfillResBody {
                        events,
                        prev_cursor: cursor.clone(),
                        next_cursor: page
                            .next_cursor
                            .or_else(|| Some(sync_token_for_state(state))),
                        limited: page.has_more,
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
            serde_json::to_value(BackfillResBody {
                events: Vec::new(),
                prev_cursor: cursor.clone(),
                next_cursor: Some(sync_token_for_state(state)),
                limited: false,
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
    let next_cursor = limited
        .then(|| {
            page_events
                .last()
                .and_then(|event| event["event_id"].as_str().map(ToOwned::to_owned))
        })
        .flatten()
        .or_else(|| Some(sync_token_for_state(state)));
    crate::result::json_ok(
        serde_json::to_value(BackfillResBody {
            events: page_events,
            prev_cursor: cursor.clone(),
            next_cursor,
            limited,
        })
        .unwrap_or(json!({})),
    )
}

async fn durable_events_query_from_parts(
    state: &AppState,
    session: &SessionRecord,
    parts: &EventsQueryParts,
) -> crate::wire::EventsPageResponse {
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
    let frontier = super::event_log::events_frontier_json(&page);
    let events = page
        .iter()
        .map(|record| super::event_log::event_read_response_for_state(state, record))
        .collect();
    crate::wire::EventsPageResponse {
        events,
        next_cursor,
        frontier,
    }
}

#[endpoint(
    operation_id = "ck.extension.soland.sync.backfill_gap",
    tags("sync"),
    summary = "Backfill the gap between two cursors (deployment-local; not in spec)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.sync.backfill_gap"))]
async fn sync_gap_backfill(
    realm_id: salvo::oapi::extract::QueryParam<String, true>,
    limit: salvo::oapi::extract::QueryParam<usize, false>,
    from_cursor: salvo::oapi::extract::QueryParam<String, false>,
    to_cursor: salvo::oapi::extract::QueryParam<String, false>,
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
    let from_cursor = from_cursor.into_inner();
    let to_cursor = to_cursor.into_inner();

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
    operation_id = "ck.self.snapshot.head",
    tags("sync"),
    summary = "Read the snapshot-v1 head (manifest + chunk descriptors + merkle_root) for a Realm"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.snapshot.head"))]
async fn snapshot_head(
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<SnapshotHeadResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    // Spec-canonical query param is `realm_id`.
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
    // Snapshot v1: the manifest already lists per-chunk digests, so
    // `chunks[]` becomes the per-chunk descriptor (id + size + digest)
    // — receivers fetch each chunk via `/sync/snapshot-chunk?chunk_id=N`
    // and check it against `merkle_root` using the chunk's `audit_path`.
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
    let generator_proof_value = bundle.generator_proof.clone();
    let service_did = state.config.service_did.clone();
    let signature_payload = format!(
        "{}:{}:{}",
        bundle.snapshot_ref, bundle.state_digest, service_did
    );
    crate::result::json_ok(SnapshotHeadResponse {
        snapshot_ref: bundle.snapshot_ref,
        state_digest: bundle.state_digest,
        manifest: bundle.manifest,
        chunks: chunk_descriptors,
        frontier: bundle.frontier,
        signature: json!({
            "kid": format!("{service_did}#snapshot-dev"),
            "alg": "sha256-dev",
            "sig": sha256_hex(signature_payload.as_bytes())
        }),
        merkle_root,
        chunk_count: bundle.chunk_count,
        chunk_bytes: bundle.chunk_bytes,
        total_bytes: bundle.total_bytes,
        generator_proof: generator_proof_value,
    })
}

#[endpoint(
    operation_id = "ck.extension.soland.sync.snapshot_chunk",
    tags("sync"),
    summary = "Read one chunk of a snapshot-v1 bundle (with audit_path proving merkle membership)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.sync.snapshot_chunk"))]
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
    if bundle.snapshot_ref != snapshot_ref || bundle.state_digest != expected_hash {
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
        "verified": format!("sha256:{}", sha256_hex(&chunk.bytes)) == chunk.digest.as_str(),
        "bytes_base64": URL_SAFE_NO_PAD.encode(&chunk.bytes),
        "audit_path": audit_path,
        "tree_size": tree_size,
        "merkle_root": bundle.tree.root().as_str(),
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use super::*;

    #[test]
    fn timeline_position_disambiguates_same_second_events() {
        let created_at = DateTime::parse_from_rfc3339("2026-05-22T16:18:24Z")
            .unwrap()
            .with_timezone(&Utc);
        let realm_create = timestamp_position_with_tie_breaker(
            created_at,
            "ck:event:019e507b-16b2-719a-84fd-a9319ab43a36",
        );
        let welcome_message = timestamp_position_with_tie_breaker(
            created_at,
            "ck:event:019e507b-1857-73b7-9579-a00706bf0af4",
        );

        assert_ne!(realm_create, welcome_message);
        assert!(welcome_message > realm_create);
    }

    #[test]
    fn presence_sync_event_marks_stale_online_offline() {
        let record = PresenceRecord {
            actor: "did:web:alice.example".to_owned(),
            status: "online".to_owned(),
            updated_at: now() - ChronoDuration::seconds(PRESENCE_ONLINE_TTL_SECONDS + 1),
        };

        let event = presence_sync_event_json(record);

        assert_eq!(event["user_id"], "did:web:alice.example");
        assert_eq!(event["presence"], "offline");
        assert_eq!(event["status"], "offline");
        assert!(event.get("last_active").is_some());
    }

    fn test_config() -> crate::config::AppConfig {
        crate::config::AppConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            metrics_bind: "127.0.0.1:0".parse().unwrap(),
            public_base_url: "http://server".to_owned(),
            service_did: "did:web:soland.local".to_owned(),
            tls_cert_path: None,
            tls_key_path: None,
            database_url: None,
            object_storage: crate::config::ObjectStorageConfig::local(
                std::env::temp_dir().join("soland-sync-cursor-test-blobs"),
            ),
            cors_allow_origin: None,
            auth_server_url: None,
            development_mode: true,
            oauth_introspection_url: None,
            oauth_introspection_bearer: None,
            session_grant_introspection_url: None,
            session_grant_introspection_bearer: None,
            did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
            embedded_webvh_provider_enabled: false,
            embedded_webvh_registration_bearer: None,
            external_webvh_provider_url: None,
            external_webvh_provider_active: false,
            default_webvh_provider_id: None,
            jws_replay_window_seconds: 0,
            jws_replay_window_per_family: BTreeMap::new(),
            anchorer_signing_key_seed: Some([9u8; 32]),
            agent_audit_binding_signing_seed: None,
            use_keystore: false,
            federation_policy: crate::config::FederationPolicy::Mesh,
            federation_peers: Vec::new(),
            federation_outbound_enabled: false,
            admin_default_page_limit: 100,
            admin_max_page_limit: 1000,
            admin_principal_dids: Vec::new(),
            push_bridge_cache_ttl_seconds: 900,
            push_bridge_trusted_service_dids: Vec::new(),
            compaction_min_anchor_age_seconds: 604_800,
            compaction_min_witnesses: 1,
            compaction_preserve_genesis: true,
            compaction_prune_only_singleton_successors: true,
            compaction_prune_walk_interval_seconds: 0,
            compaction_prune_walk_per_realm_limit: 50,
            seed_demo_data: true,
            trust_domain: "ck:trust_domain:soland.local".to_owned(),
            sovereign_enclave_enabled: false,
            sovereign_enclave_allowed_outbound_hosts: Vec::new(),
            erasure_propagation_window_ms: 604_800_000,
            log_format: crate::config::LogFormat::Plain,
        }
    }

    fn test_state() -> AppState {
        AppState::new(test_config(), crate::db::Db { pool: None })
    }

    const ROSTER_REALM: &str = "ck:realm:01904100-0000-7000-8000-00000000a001";
    const ROSTER_ACTOR: &str = "did:web:alice.example";
    const ROSTER_SUBJECT: &str = "did:web:alice-principal.example";
    const ROSTER_CALLER: &str = "did:web:bob.example";

    fn roster_body(audience: &str) -> ClientSyncRequest {
        ClientSyncRequest {
            after: None,
            catchup: None,
            filter: Some(json!({ "audience": audience })),
            set_presence: None,
        }
    }

    fn roster_session(state: &AppState, actor: &str) -> SessionRecord {
        SessionRecord {
            token_hash: "token".to_owned(),
            actor: actor.to_owned(),
            device_id: "device-1".to_owned(),
            audience: state.config.service_did.clone(),
            expires_at: now() + ChronoDuration::hours(1),
            created_at: now(),
            revoked_at: None,
        }
    }

    fn roster_realm(public: bool, include_caller: bool) -> RealmDirectoryEntry {
        let mut entry = RealmDirectoryEntry::new(
            RealmId::new(ROSTER_REALM.to_owned()).unwrap(),
            "Roster evidence",
        );
        entry.public = public;
        entry
            .members
            .insert(cokret_sdk::Did::new(ROSTER_ACTOR.to_owned()).unwrap());
        if include_caller {
            entry
                .members
                .insert(cokret_sdk::Did::new(ROSTER_CALLER.to_owned()).unwrap());
        }
        entry
    }

    fn insert_member_identity_subject(state: &AppState) {
        use crate::state::{MemberIdentityEventRecord, MemberIdentitySubjectKey};
        let identity_payload = json!({
            "member_identity": {
                "subject_id": ROSTER_SUBJECT,
                "display_profile": { "display_name": "Alice" }
            }
        });
        let payload_digest = cokret_sdk::canonical::sha256_digest(
            cokret_sdk::canonical::canonical_json_bytes(&identity_payload).unwrap(),
        );
        state
            .member_identity
            .lock()
            .expect("member_identity lock")
            .insert(MemberIdentityEventRecord {
                event_id: "ck:operation:roster-identity-1".to_owned(),
                subject: MemberIdentitySubjectKey {
                    realm_id: ROSTER_REALM.to_owned(),
                    actor_id: ROSTER_ACTOR.to_owned(),
                    segment: "member_identity".to_owned(),
                },
                payload_digest,
                replaces: Vec::new(),
                raw_event: json!({
                    "operation_id": "ck:operation:roster-identity-1",
                    "event_kind": crate::kinds::CK_MEMBER_IDENTITY_UPDATE,
                    "realm_id": ROSTER_REALM,
                    "created_at": now(),
                    "payload": {
                        "realm_id": ROSTER_REALM,
                        "actor_id": ROSTER_ACTOR,
                        "segment": "member_identity",
                        "identity_payload": identity_payload,
                    }
                }),
            });
    }

    fn handle_claim(
        state: &AppState,
        issuer: &str,
        audience: &str,
        expires_at: DateTime<Utc>,
        binding_state: &str,
        extra: Option<Value>,
    ) -> Value {
        let mut claim = json!({
            "schema": "ck.schema.handle_claim.v1",
            "handle": "alice:soland.local",
            "subject": ROSTER_SUBJECT,
            "issuer": issuer,
            "issuer_service_did": issuer,
            "binding_state": binding_state,
            "claim_kind": "handle_binding",
            "visibility": "public",
            "audience": audience,
            "created_at": (now() - ChronoDuration::minutes(1)).to_rfc3339_opts(SecondsFormat::Millis, true),
            "expires_at": expires_at.to_rfc3339_opts(SecondsFormat::Millis, true),
            "proofs": [{
                "kind": "detached_jws",
                "alg": "EdDSA",
                "verification_method": format!("{issuer}#directory-handle-claim"),
                "payload_digest": "sha256:unsigned-payload",
                "jws": "detached"
            }]
        });
        if let Some(extra) = extra
            && let Some(object) = claim.as_object_mut()
        {
            object.insert("claims".to_owned(), extra);
        }
        // Keep tests honest: use the configured service DID unless a test is
        // intentionally exercising issuer trust rejection.
        if issuer == state.config.service_did {
            claim["issuer_service_did"] = json!(state.config.service_did);
        }
        claim
    }

    fn cache_claim(state: &AppState, claim: Value) -> String {
        state
            .member_identity
            .lock()
            .expect("member_identity lock")
            .upsert_handle_claim_envelope(claim)
            .expect("claim cached")
    }

    fn roster_row(
        state: &AppState,
        realm: &RealmDirectoryEntry,
        session: Option<&SessionRecord>,
    ) -> Value {
        let body = roster_body(&state.config.service_did);
        roster_members_for_realm(state, realm, session, &body)
            .into_iter()
            .find(|row| row["actor_id"] == ROSTER_ACTOR)
            .expect("actor row")
    }

    fn canonical_value_digest(value: &Value) -> String {
        cokret_sdk::canonical::sha256_digest(
            cokret_sdk::canonical::canonical_json_bytes(value).unwrap(),
        )
    }

    #[test]
    fn roster_discloses_handle_claim_for_visible_trusted_issuer() {
        let state = test_state();
        insert_member_identity_subject(&state);
        let claim = handle_claim(
            &state,
            &state.config.service_did,
            &state.config.service_did,
            now() + ChronoDuration::hours(1),
            "verified",
            None,
        );
        let digest = cache_claim(&state, claim);
        let realm = roster_realm(false, true);
        let session = roster_session(&state, ROSTER_CALLER);

        let row = roster_row(&state, &realm, Some(&session));

        assert_eq!(row["subject_id"], ROSTER_SUBJECT);
        assert_eq!(row["handle_claim_digests"], json!([digest]));
        assert_eq!(
            canonical_value_digest(&row["handle_claims"][0]),
            row["handle_claim_digests"][0].as_str().unwrap()
        );
        assert!(row.get("handle_claims_limited").is_none());
    }

    #[test]
    fn roster_hides_handle_claim_from_untrusted_issuer() {
        let state = test_state();
        insert_member_identity_subject(&state);
        cache_claim(
            &state,
            handle_claim(
                &state,
                "did:web:evil.example",
                &state.config.service_did,
                now() + ChronoDuration::hours(1),
                "verified",
                None,
            ),
        );
        let realm = roster_realm(false, true);
        let session = roster_session(&state, ROSTER_CALLER);

        let row = roster_row(&state, &realm, Some(&session));

        assert_eq!(row["subject_id"], ROSTER_SUBJECT);
        assert!(row.get("handle_claim_digests").is_none());
        assert!(row.get("handle_claims").is_none());
    }

    #[test]
    fn roster_hides_expired_handle_claim() {
        let state = test_state();
        insert_member_identity_subject(&state);
        cache_claim(
            &state,
            handle_claim(
                &state,
                &state.config.service_did,
                &state.config.service_did,
                now() - ChronoDuration::seconds(1),
                "verified",
                None,
            ),
        );
        let realm = roster_realm(false, true);
        let session = roster_session(&state, ROSTER_CALLER);

        let row = roster_row(&state, &realm, Some(&session));

        assert_eq!(row["subject_id"], ROSTER_SUBJECT);
        assert!(row.get("handle_claim_digests").is_none());
    }

    #[test]
    fn roster_hides_revoked_handle_claim() {
        let state = test_state();
        insert_member_identity_subject(&state);
        cache_claim(
            &state,
            handle_claim(
                &state,
                &state.config.service_did,
                &state.config.service_did,
                now() + ChronoDuration::hours(1),
                "revoked",
                None,
            ),
        );
        let realm = roster_realm(false, true);
        let session = roster_session(&state, ROSTER_CALLER);

        let row = roster_row(&state, &realm, Some(&session));

        assert_eq!(row["subject_id"], ROSTER_SUBJECT);
        assert!(row.get("handle_claim_digests").is_none());
    }

    #[test]
    fn roster_disclosure_depends_on_realm_policy() {
        let state = test_state();
        insert_member_identity_subject(&state);
        let digest = cache_claim(
            &state,
            handle_claim(
                &state,
                &state.config.service_did,
                &state.config.service_did,
                now() + ChronoDuration::hours(1),
                "verified",
                None,
            ),
        );

        let private_realm = roster_realm(false, false);
        let private_row = roster_row(&state, &private_realm, None);
        assert!(private_row.get("subject_id").is_none());
        assert!(private_row.get("handle_claim_digests").is_none());
        assert!(private_row.get("handle_claims").is_none());

        let public_realm = roster_realm(true, false);
        let public_row = roster_row(&state, &public_realm, None);
        assert_eq!(public_row["subject_id"], ROSTER_SUBJECT);
        assert_eq!(public_row["handle_claim_digests"], json!([digest]));
    }

    #[test]
    fn roster_limits_large_inline_handle_claim_payloads() {
        let state = test_state();
        insert_member_identity_subject(&state);
        let claim = handle_claim(
            &state,
            &state.config.service_did,
            &state.config.service_did,
            now() + ChronoDuration::hours(1),
            "verified",
            Some(json!([{"blob": "x".repeat(HANDLE_CLAIMS_INLINE_MAX_BYTES + 1)}])),
        );
        let digest = cache_claim(&state, claim);
        let realm = roster_realm(false, true);
        let session = roster_session(&state, ROSTER_CALLER);

        let row = roster_row(&state, &realm, Some(&session));

        assert_eq!(row["subject_id"], ROSTER_SUBJECT);
        assert_eq!(row["handle_claim_digests"], json!([digest]));
        assert!(row.get("handle_claims").is_none());
        assert_eq!(row["handle_claims_limited"], true);
    }

    struct StatelessCursorProfileGuard {
        _guard: MutexGuard<'static, ()>,
    }

    impl Drop for StatelessCursorProfileGuard {
        fn drop(&mut self) {
            TEST_STATELESS_CURSOR_PROFILE_DECLARED
                .store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn stateless_cursor_profile_guard() -> StatelessCursorProfileGuard {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let guard = LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("stateless cursor test lock");
        TEST_STATELESS_CURSOR_PROFILE_DECLARED.store(true, std::sync::atomic::Ordering::SeqCst);
        StatelessCursorProfileGuard { _guard: guard }
    }

    fn issued_stateless_cursor(state: &AppState) -> Value {
        let token = sync_token_for_client_sync(
            state,
            None,
            None,
            BTreeMap::from([("ck:realm:stateless-cursor-test".to_owned(), 7)]),
            12,
        );
        decode_sync_cursor_value(&token).expect("issued cursor decodes")
    }

    fn assert_integrity_error(error: SyncCursorError) {
        match error {
            SyncCursorError::Integrity(_) => {}
            other => panic!("expected cursor integrity error, got {other:?}"),
        }
    }

    #[test]
    fn stateless_cursor_issuance_signs_and_verifies_current_service_cursor() {
        let _profile = stateless_cursor_profile_guard();
        let state = test_state();
        let cursor = issued_stateless_cursor(&state);

        assert_eq!(cursor["issuer_kid"], "did:web:soland.local#anchorer-key");
        assert!(cursor.get("_sig").is_some());
        assert!(cursor.get("h").is_none());

        let token = encode_sync_cursor_value(cursor);
        let parsed = parse_and_validate_sync_cursor(
            &token,
            &state,
            None,
            None,
            chrono::Utc::now().timestamp_millis(),
        )
        .expect("signed stateless cursor must verify");

        assert_eq!(
            parsed.positions.get("ck:realm:stateless-cursor-test"),
            Some(&7)
        );
        assert_eq!(parsed.to_device_position, 12);
        assert!(parsed.issued_at_ms.is_some());
    }

    #[test]
    fn stateless_cursor_rejects_body_tamper() {
        let _profile = stateless_cursor_profile_guard();
        let state = test_state();
        let mut cursor = issued_stateless_cursor(&state);
        cursor["positions"]["to_device"] = json!(99);

        let token = encode_sync_cursor_value(cursor);
        let error = parse_and_validate_sync_cursor(
            &token,
            &state,
            None,
            None,
            chrono::Utc::now().timestamp_millis(),
        )
        .expect_err("tampered cursor body must fail verification");

        assert_integrity_error(error);
    }

    #[test]
    fn stateless_cursor_rejects_issuer_kid_tamper() {
        let _profile = stateless_cursor_profile_guard();
        let state = test_state();
        let mut cursor = issued_stateless_cursor(&state);
        cursor["issuer_kid"] = json!("did:web:other.example#anchorer-key");

        let token = encode_sync_cursor_value(cursor);
        let error = parse_and_validate_sync_cursor(
            &token,
            &state,
            None,
            None,
            chrono::Utc::now().timestamp_millis(),
        )
        .expect_err("tampered issuer kid must fail verification");

        assert_integrity_error(error);
    }

    #[test]
    fn stateless_cursor_rejects_missing_signature() {
        let _profile = stateless_cursor_profile_guard();
        let state = test_state();
        let mut cursor = issued_stateless_cursor(&state);
        cursor.as_object_mut().unwrap().remove("_sig");

        let token = encode_sync_cursor_value(cursor);
        let error = parse_and_validate_sync_cursor(
            &token,
            &state,
            None,
            None,
            chrono::Utc::now().timestamp_millis(),
        )
        .expect_err("unsigned stateless cursor must fail verification");

        assert_integrity_error(error);
    }

    #[test]
    fn revoked_cursor_returns_revoked_error() {
        let state = test_state();
        let token = sync_token_for_client_sync(
            &state,
            None,
            None,
            BTreeMap::from([("ck:realm:revoke-test".to_owned(), 3)]),
            5,
        );
        let now_ms = chrono::Utc::now().timestamp_millis();
        parse_and_validate_sync_cursor(&token, &state, None, None, now_ms)
            .expect("freshly issued cursor validates");

        state
            .sync_cursor_revocations
            .lock()
            .unwrap()
            .push(crate::state::CursorRevocation {
                cursor_digest: sha256_hex(token.as_bytes()),
                principal_id: "did:web:alice.example".to_owned(),
                device_id: None,
                scope: "this_cursor".to_owned(),
                reason_code: "compromised".to_owned(),
                revoked_at: now(),
                expires_at: now() + ChronoDuration::seconds(CURSOR_MAX_TTL_SECONDS),
            });

        let error = parse_and_validate_sync_cursor(&token, &state, None, None, now_ms)
            .expect_err("revoked cursor must fail validation");
        assert!(
            matches!(error, SyncCursorError::Revoked),
            "expected Revoked, got {error:?}"
        );
    }

    #[test]
    fn expired_revocation_entry_is_pruned_and_does_not_block() {
        let state = test_state();
        let token = sync_token_for_client_sync(
            &state,
            None,
            None,
            BTreeMap::from([("ck:realm:revoke-gc".to_owned(), 1)]),
            0,
        );
        let now_ms = chrono::Utc::now().timestamp_millis();
        state
            .sync_cursor_revocations
            .lock()
            .unwrap()
            .push(crate::state::CursorRevocation {
                cursor_digest: sha256_hex(token.as_bytes()),
                principal_id: "did:web:alice.example".to_owned(),
                device_id: None,
                scope: "this_cursor".to_owned(),
                reason_code: "stale".to_owned(),
                revoked_at: now() - ChronoDuration::seconds(2 * CURSOR_MAX_TTL_SECONDS),
                expires_at: now() - ChronoDuration::seconds(CURSOR_MAX_TTL_SECONDS),
            });

        parse_and_validate_sync_cursor(&token, &state, None, None, now_ms)
            .expect("expired revocation entry must be pruned, not block a valid cursor");
        assert!(
            state.sync_cursor_revocations.lock().unwrap().is_empty(),
            "expired revocation entry should have been pruned"
        );
    }

    #[test]
    fn stateless_cursor_rejects_expired_signed_cursor() {
        let _profile = stateless_cursor_profile_guard();
        let state = test_state();
        let now_ms = chrono::Utc::now().timestamp_millis();
        let issued_at = chrono::Utc::now() - ChronoDuration::hours(2);
        let cursor = sign_stateless_sync_cursor(
            &state,
            json!({
                "v": "1",
                "purpose": "stream",
                "t": issued_at.to_rfc3339_opts(SecondsFormat::Millis, true),
                "x": now_ms - 1,
                "issuer_kid": stateless_cursor_issuer_kid(&state),
                "target": {
                    "principal_id": "anonymous",
                    "device_id": "anonymous",
                    "service_id": state.config.service_did.clone()
                },
                "scope": {
                    "filter_digest": sync_filter_digest(None)
                },
                "positions": {
                    "realms": {},
                    "devices": {},
                    "to_device": 0
                },
                "issued_at_ms": issued_at.timestamp_millis()
            }),
        )
        .expect("expired fixture signs");

        let token = encode_sync_cursor_value(cursor);
        let error = parse_and_validate_sync_cursor(&token, &state, None, None, now_ms)
            .expect_err("expired signed stateless cursor must fail");

        assert!(matches!(error, SyncCursorError::Expired));
    }
}

// ════════════════════════════════════════════════════════════════════════
// EventsSubscribe NDJSON typed frames + cursor handle entropy (spec B1.5/T03).
// ════════════════════════════════════════════════════════════════════════

/// Spec B1.5 — wrap a typed `EventsSubscribeFrameBody` in the envelope
/// shape soland emits on the wire (kept distinct from the SDK body type so
/// the per-frame `seq` / `realm_id` envelope can evolve independently of
/// the SDK's `kind`-tagged body).
///
/// The envelope serialises a flattened body via `#[serde(flatten)]` so
/// downstream consumers see exactly the SDK `EventsSubscribeFrameBody`
/// fields plus the wrapper's `seq` / `realm_id` / `cursor` fields at the
/// top level.
#[allow(dead_code)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SubscribeFrameEnvelope {
    /// Monotonic per-connection sequence (matches the legacy `seq` field).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// Originating Realm (for fan-out frames). Optional; absent on
    /// `heartbeat`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<String>,
    /// Cursor for the frame, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(flatten)]
    pub body: cokret_sdk::EventsSubscribeFrameBody,
}

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
