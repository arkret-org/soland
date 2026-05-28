//! Account aggregate + snapshot handlers + the cursor-helper machinery they share
//! with events and device-message modules.
//!
//! Surfaces for the current sync/event wire layout:
//! - `GET  /api/v1/account/describe`
//! - `GET  /api/v1/account/subscribe`       — `cx.account.subscribe` (account-aggregate NDJSON:
//!   timeline, presence, typing, to_device).
//! - `POST /api/v1/ephemeral`               — `cx.ephemeral.send` (broadcast ephemeral)
//! - `GET  /api/v1/events/subscribe`        — `cx.events.subscribe`. Multi-space / multi-actor
//!   stream; frame `kind` field replaces `type`.
//! - `GET  /api/v1/events`                  — `cx.events.query` (replaces `cx.events.list` +
//!   `cx.sync.backfill` via `direction=forward|backward`).
//! - `GET  /api/v1/sync/backfill/gap`       — `cx.sync.backfill_gap` (deployment-local; not in
//!   spec)
//! - `GET  /api/v1/snapshot/head`
//! - `GET  /api/v1/sync/snapshot-chunk`
//!
//! `SyncCursor`, `SyncCursorError`, `parse_and_validate_sync_cursor`,
//! `decode_sync_cursor_value`, `sync_token_for_client_sync`, `sync_filter_hash`,
//! are `pub` because sibling routing modules reuse them. They
//! live here because the cursor lifecycle is anchored to account subscribe.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use chrono::{DateTime, Duration as ChronoDuration, SecondsFormat, Utc};
use contrix_sdk::lattice::CellState;
use contrix_sdk::{EphemeralSubmitResBody, RealmId};
use futures_util::stream::StreamExt;
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Value, json};
use tokio::sync::broadcast::error::RecvError;

use super::projection::{
    actor_erased_in_space, retention_tombstone_for_event, tombstone_timeline_event_for_retention,
    tombstone_timeline_event_value,
};
use super::{
    augment_timeline_message_json, authenticated_session, backfill_gap_events,
    default_discussion_track, device_message_events_after, flow_id_from_space_id,
    flow_projection_for_space, is_realm_deleted, now, parse_snapshot_ref, projected_event_page,
    projection_event_json, prune_acked_device_messages, prune_expired_typing, query_param,
    realm_discoverability, realm_event_visible_to_session, realm_has_member,
    realm_history_visibility, realm_id_accessible, realm_visible_to, render_error, sha256_hex,
    snapshot_bundle_for_space, sync_timeline_message_json_with_projection, truncate_gap_events,
    typing_ephemeral_for_space, validate_did,
};
use crate::ids;
use crate::reducer::ProjectionState;
use crate::state::{
    AppState, PresenceRecord, ProjectionEventRecord, RealmDirectoryEntry, SessionRecord,
    TypingRecord,
};
use crate::wire::{
    AccountDescribeResBody, BackfillResBody, ClientSyncRequest, EventsQueryPostRequest,
    SnapshotHeadResponse,
};

const TIMELINE_POSITION_SUBTICKS: i64 = 1024;
const PERSONAL_BLOCKLIST_DATA_TYPES: &[&str] = &["cx.account.blocklist", "cx.account.blocklist.v1"];

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("account/describe").get(account_describe))
        .push(Router::with_path("account/subscribe").get(account_subscribe))
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
    res.render(Json(AccountDescribeResBody {
        service_did: state.config.service_did.clone(),
        supported_sync_profiles: vec![
            "initial".to_owned(),
            "incremental".to_owned(),
            "board".to_owned(),
            "chat".to_owned(),
            "topic".to_owned(),
            "offline_queue_flush".to_owned(),
            "backfill_gap".to_owned(),
            "bottom_cell_repair".to_owned(),
        ],
        limits: json!({
            "max_spaces": 50,
            "max_timeline_events": 100,
            "offline_flush_endpoint": "/api/v1/events",
            "backfill_endpoint": "/api/v1/sync/backfill/gap",
            "bottom_repair_endpoint": "/api/admin/v1/spaces/{space_id}/bottom/{cell_id}/repair"
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

#[endpoint(
    operation_id = "cx.account.subscribe",
    tags("sync"),
    summary = "Account-aggregate subscribe stream (timeline / presence / typing / to_device)"
)]
#[tracing::instrument(skip_all, fields(op = "cx.account.subscribe"))]
async fn account_subscribe(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected").clone();
    let body = account_subscribe_query(req);
    let max_wait_ms = parse_max_wait_ms(req);
    let session = authenticated_session(&state, req).await.ok();
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
        if let Err(error) = state.persistence.presence().put(PresenceRecord {
            actor: session.actor.clone(),
            status: presence.to_owned(),
            updated_at: chrono::Utc::now(),
        }).await {
            tracing::error!(%error, "failed to persist presence");
        }
    }
    prune_expired_typing(&state);

    // Subscribe to broadcast BEFORE building the initial snapshot so an
    // event landing between snapshot-build and long-poll subscribe is not
    // missed.
    let mut rx = state.event_broadcast.subscribe();
    let mut response = build_sync_snapshot(&state, session.as_ref(), &body, &after_cursor).await;

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
                            if !realm_id_accessible(&state, &notification.space_id, session.as_ref()).await {
                                continue;
                            }
                            response = build_sync_snapshot(&state, session.as_ref(), &body, &after_cursor).await;
                            if !delta_is_empty(&response) {
                                break;
                            }
                        }
                        Err(RecvError::Lagged(_)) => {
                            // We lost some notifications; rebuild and let the
                            // delta speak for itself.
                            response = build_sync_snapshot(&state, session.as_ref(), &body, &after_cursor).await;
                            if !delta_is_empty(&response) {
                                break;
                            }
                        }
                        Err(RecvError::Closed) => break,
                    }
                }
            }
        }
    }

    let cursor = response.cursor.clone();
    let mut frames = vec![ndjson_line(&account_delta_frame(response))];
    if body.catchup.unwrap_or(false) {
        frames.push(ndjson_line(&json!({
            "kind": "catchup_complete",
            "cursor": cursor,
        })));
    }

    let body_stream = async_stream::stream! {
        for frame in frames {
            yield Ok::<Bytes, std::io::Error>(frame);
        }
    };
    let _ = res.add_header("content-type", "application/x-ndjson", true);
    res.stream(body_stream.boxed());
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
fn delta_is_empty(response: &contrix_sdk::model::SyncResBody) -> bool {
    response.spaces.is_empty()
        && response.left_spaces.is_empty()
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

fn account_delta_frame(response: contrix_sdk::model::SyncResBody) -> Value {
    json!({
        "kind": "delta",
        "cursor": response.cursor,
        "realms": response.spaces,
        "to_device": {"messages": response.to_device},
        "device_lists": response.device_lists,
        "account_data": {"events": response.account_data},
        "presence": {"events": response.presence},
        "notifications": response.notifications,
        "partial": response.partial,
    })
}

/// Build one snapshot of the account-aggregate sync response for the next
/// `cx.account.subscribe` delta frame.
async fn build_sync_snapshot(
    state: &AppState,
    session: Option<&SessionRecord>,
    body: &ClientSyncRequest,
    after_cursor: &SyncCursor,
) -> contrix_sdk::model::SyncResBody {
    // SYNC-MEM-1 + ROST-SOL-1..3 (contrix-spec @ b56cab1) — `members[]` is
    // the per-Realm roster v2 projection from
    // `account-subscribe-frame.schema.json#/$defs/member_roster_entry`. Each
    // row carries `{actor_id, membership, subject_id?, identity_event_ids?,
    // member_display_state_digest?, identity_events?, handle_claim_digests?,
    // handle_claims?, handle_claims_limited?}` — `handle` / display name MUST
    // NOT appear here. Identity is resolved by following
    // `identity_event_ids[]` into the separately delivered
    // `cx.member.identity.update` event log; servers that lack the events for
    // the client SHOULD inline them via `identity_events[]` (gated on
    // `subject_id` disclosure).
    let candidate_spaces: Vec<RealmDirectoryEntry> = {
        let spaces = state.realms.lock().expect("spaces lock");
        spaces.search(Default::default()).into_iter().cloned().collect()
    };
    let mut visible_spaces: Vec<(String, String, Option<String>, _, Option<String>, _)> =
        Vec::new();
    for space in &candidate_spaces {
        if realm_visible_to(state, space, session).await {
            let members = roster_members_for_realm(state, space);
            visible_spaces.push((
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
    // omission from `spaces` as authoritative there.
    let visible_space_ids: BTreeSet<&str> = visible_spaces
        .iter()
        .map(|(id, _, _, _, _, _)| id.as_str())
        .collect();
    let left_spaces: Vec<String> = if body.after.is_some() {
        after_cursor
            .positions
            .keys()
            .filter(|id| !visible_space_ids.contains(id.as_str()))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    drop(visible_space_ids);

    // Clone the projection so the per-space loop below can `.await` async
    // visibility/timeline helpers without holding the (non-Send) lock guard
    // across a suspension point.
    let projection = state.projection.lock().expect("projection lock").clone();
    let mut sync_spaces = std::collections::BTreeMap::new();
    let mut positions = BTreeMap::new();
    let is_incremental = body.after.is_some();
    let cursor_issued_at = after_cursor
        .issued_at_ms
        .and_then(chrono::DateTime::<Utc>::from_timestamp_millis);
    for (space_id, title, summary, tags, category, members) in visible_spaces {
        let flow = flow_projection_for_space(state, &space_id, &title, summary.as_deref()).await;
        let flow_state_after = flow.clone();
        let flow_list_item = flow.clone();
        let summary_members = members.clone();
        let meta = state.persistence.realm_meta().get(&space_id).await.ok().flatten();
        let history_visibility = meta
            .as_ref()
            .map(|record| record.history_visibility.clone())
            .unwrap_or_else(|| "shared".to_owned());
        let encryption_profile = meta
            .as_ref()
            .and_then(|record| record.encryption_profile.clone())
            .unwrap_or_else(|| "none".to_owned());
        let known_to_cursor = after_cursor.positions.contains_key(&space_id);
        let after_position = after_cursor
            .positions
            .get(&space_id)
            .copied()
            .unwrap_or_default();
        let (timeline_events, space_position) =
            timeline_events_for_space(state, &projection, &space_id, after_position, session).await;
        positions.insert(space_id.clone(), space_position);
        // Incremental sync skips realms whose timeline position is
        // unchanged AND whose meta `updated_at` is at-or-before the
        // cursor's `issued_at`. This drops the always-full
        // `summary`/`flows`/`state_after`/`members` baseline from idle
        // polls — the realm stays in the client's local projection.
        //
        // Caveats: membership changes that don't bump `realm_meta.updated_at`
        // (e.g. raw `cx.realm.member.update` events) will not propagate
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
        let bottom_cells = bottom_cells_for_space(&projection, &space_id);
        let anchor_view = anchor_view_for_space(&bottom_cells);
        let ephemeral = typing_ephemeral_for_space(state, &space_id, session).await;
        sync_spaces.insert(
            space_id.clone(),
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
                // SYNC-MEM-2 (contrix-spec @ 7157ee8) — `members_limited`
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
        prune_acked_device_messages(state, session, after_cursor.to_device_position);
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
    // `cx.contacts.space.<space_id>` Space remarks against the public
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

    contrix_sdk::model::SyncResBody {
        cursor: sync_token_for_client_sync(
            state,
            session,
            body.filter.as_ref(),
            positions,
            to_device_position,
        ),
        spaces: sync_spaces,
        left_spaces,
        to_device,
        device_lists: json!({"changed": [], "left": []}),
        account_data,
        presence: Vec::new(),
        notifications: serde_json::Value::Null,
        partial: false,
    }
}

/// SYNC-MEM-1..4 + ROST-SOL-1..3 (contrix-spec @ b56cab1) — build the
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
/// delivered `cx.member.identity.update` event log; SYNC-MEM-3 inlines the
/// original envelopes only when `subject_id` is disclosed.
///
/// MIU-SOL-4: the effective set is multi-valued (no last-writer-wins); ALL
/// effective `identity_event_ids[]` are listed.
fn roster_members_for_realm(
    state: &AppState,
    space: &crate::state::RealmDirectoryEntry,
) -> Vec<Value> {
    let registry = state.member_identity_registry();
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
            if let Some(snapshot) =
                registry.snapshot_for_actor(space.realm_id.as_str(), did_str)
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
                    entry.insert(
                        "member_display_state_digest".to_owned(),
                        json!(digest),
                    );
                }
                // ROST-SOL-2 — `subject_id` is disclosed only when Realm
                // policy authorizes the caller to learn the principal /
                // holder DID. When disclosed, the gated companion fields MAY
                // be populated; otherwise they MUST all be omitted (the SDK
                // `MemberRosterEntry::validate` dependentRequired rule).
                if subject_disclosed_to_caller(state, space, did_str)
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
                    // ROST-SOL-3 — populate real handle-claim evidence from
                    // the local handle-claim cache once it lands.
                    // TODO(R3.2.1): select the context-visible claim subset,
                    // compute `contrix::identity::claim_digest` into
                    // `handle_claim_digests[]`, inline the signed
                    // `handle_claims[]` (size-bounded, setting
                    // `handle_claims_limited=true` on truncation). For now we
                    // disclose `subject_id` only; the gated claim fields stay
                    // omitted, which the dependentRequired rule permits.
                }
            }
            Value::Object(entry)
        })
        .collect()
}

/// ROST-SOL-2 (R3.2) — decide whether the current Realm discloses the
/// `subject_id` (principal / holder DID) of `actor_id` to the caller.
///
/// TODO(R3.2.1): wire the real Realm disclosure policy (issuer trust /
/// audience scope / intent). For now soland fails closed — `subject_id`
/// and every gated companion field are omitted until the disclosure-policy
/// engine is wired, so principal/holder DIDs never leak across disclosure
/// boundaries. This is a per-Realm policy hook, not a per-handle one; the
/// handle-claim evidence remains gated separately (ROST-SOL-3).
fn subject_disclosed_to_caller(
    _state: &AppState,
    _space: &crate::state::RealmDirectoryEntry,
    _actor_id: &str,
) -> bool {
    false
}

async fn timeline_events_for_space(
    state: &AppState,
    projection: &ProjectionState,
    space_id: &str,
    after_position: i64,
    session: Option<&SessionRecord>,
) -> (Vec<serde_json::Value>, i64) {
    let mut seen = BTreeSet::new();
    let mut newest_position = after_position;
    let mut timeline_entries = Vec::new();

    for message in projection.messages_for_space(space_id) {
        let position = timeline_event_position(state, &message.event_id, message.created_at).await;
        newest_position = newest_position.max(position);
        if position <= after_position || !seen.insert(message.event_id.clone()) {
            continue;
        }
        if !realm_event_visible_to_session_with_projection(
            state,
            projection,
            space_id,
            message.created_at,
            Some(&message.sender),
            session,
        ).await {
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
        .list_for_space(space_id, 100).await
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
            space_id,
            message.created_at,
            Some(&message.sender),
            session,
        ).await {
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

async fn timeline_event_position(state: &AppState, event_id: &str, created_at: DateTime<Utc>) -> i64 {
    let timestamp = state
        .persistence
        .events()
        .get(event_id).await
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
    space_id: &str,
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
    match realm_history_visibility(state, space_id).await.as_str() {
        "world_readable" => true,
        "shared" => {
            if realm_discoverability(state, space_id).await == "public" {
                return true;
            }
            match session {
                Some(session) => realm_has_member(state, space_id, &session.actor).await,
                None => false,
            }
        }
        "joined" | "invited" => {
            let Some(session) = session else {
                return false;
            };
            let mut joined_at = projection
                .member(space_id, &session.actor)
                .filter(|member| member.state == "join")
                .map(|member| member.joined_at);
            if joined_at.is_none() {
                let meta = state
                    .persistence
                    .realm_meta()
                    .get(space_id)
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

fn bottom_cells_for_space(projection: &ProjectionState, space_id: &str) -> Vec<Value> {
    projection
        .cells
        .iter()
        .filter_map(|(cell, state)| {
            let CellState::Bottom(bottom) = state else {
                return None;
            };
            let cell_id = cell.as_str();
            if !cell_id.contains(space_id) {
                return None;
            }
            Some(json!({
                "space_id": space_id,
                "cell_id": cell_id,
                "state": "bottom",
                "bottom": bottom,
            }))
        })
        .collect()
}

fn anchor_view_for_space(bottom_cells: &[Value]) -> Value {
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
        &event.space_id,
        event.created_at,
        event.sender.as_deref(),
        session,
    ).await && !personal_blocklist_blocks_sender_for_session(state, session, event.sender.as_deref()).await
}

async fn projection_event_value_visible_to_session(
    state: &AppState,
    event: &Value,
    session: Option<&SessionRecord>,
) -> bool {
    let Some(space_id) = event.get("space_id").and_then(Value::as_str) else {
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
    realm_event_visible_to_session(state, space_id, created_at, sender, session).await
        && !personal_blocklist_blocks_sender_for_session(state, session, sender).await
}

async fn canonical_event_visible_to_personal_blocklist(
    state: &AppState,
    record: &crate::state::CanonicalEventRecord,
    session: &SessionRecord,
) -> bool {
    !personal_blocklist_blocks_sender_for_session(state, Some(session), Some(&record.actor_id)).await
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
                .get("kind")
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

fn sync_timeline_message_record_json(message: &crate::state::MessageRecord) -> serde_json::Value {
    // flow_id is always derived from space_id (one flow per space for
    // the message timeline) — thread_id is the discussion *track* within
    // that flow, NOT the flow itself. The legacy top-level `branch` object
    // was removed in revision 0a5ab85 (see contrix-spec
    // `artifacts/registry/forbidden-wire-fields.json` entry "branch"); the
    // `track` field is the v1 replacement.
    let flow_id = flow_id_from_space_id(&message.space_id);
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

fn sync_timeline_message_record_json_with_projection(
    message: &crate::state::MessageRecord,
    projection: &ProjectionState,
) -> serde_json::Value {
    let mut event = sync_timeline_message_record_json(message);
    if actor_erased_in_space(projection, &message.sender, &message.space_id) {
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
}

pub fn sync_token_for_client_sync(
    state: &AppState,
    session: Option<&SessionRecord>,
    filter: Option<&serde_json::Value>,
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
    let filter_hash = sync_filter_hash(filter);
    let issued_at_ms = issued_at.timestamp_millis();
    let expires_at_ms = expires_at.timestamp_millis();
    let positions = json!({
        "spaces": spaces_positions,
        "devices": device_positions,
        "to_device": to_device_position
    });
    let ctx = json!({
        "principal_id": principal_id,
        "device_id": device_id,
        "service_id": state.config.service_did.clone(),
        "filter_hash": filter_hash,
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
                "spaces": {},
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
    let bytes = contrix_sdk::canonical::canonical_json_bytes(&cursor)
        .unwrap_or_else(|_| cursor.to_string().into_bytes());
    format!("cx:cursor:{}", URL_SAFE_NO_PAD.encode(bytes))
}

fn store_sync_cursor_handle(state: &AppState, stored: Value) -> String {
    loop {
        let handle = contrix_sdk::cursor::generate_cursor_handle();
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

fn stored_sync_cursor_by_handle(state: &AppState, handle: &str) -> Result<Value, SyncCursorError> {
    state
        .sync_cursor_handles
        .lock()
        .expect("sync cursor handles lock")
        .get(handle)
        .cloned()
        .ok_or(SyncCursorError::Integrity("sync cursor handle is unknown"))
}

/// CURSOR-1 — is `cx.profile.stateless_cursor.v1` declared by this
/// deployment? Toggled by the `SOLAND_PROFILE_STATELESS_CURSOR` env var
/// (mirrors the gating pattern used by `accountable_to.strict_reject.v1`
/// in `routing/events/operations.rs`). Default: stateful-only.
fn is_stateless_cursor_profile_declared(_state: &AppState) -> bool {
    matches!(
        std::env::var("SOLAND_PROFILE_STATELESS_CURSOR").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes")
    )
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
    let Some(expires_at) = value.get("x").and_then(|expires_at| expires_at.as_i64()) else {
        return Err(SyncCursorError::Invalid("after cursor must contain x"));
    };
    if expires_at <= now_ms {
        return Err(SyncCursorError::Expired);
    }
    // CURSOR-1 (R3 spec-sync 2026-05-27, contrix-spec b47ff6ec) —
    // core schema rejects stateless body fields unless the server
    // declares `cx.profile.stateless_cursor.v1`. Stateless body markers
    // per `_before_todos.md §0.14`: `_mac`, `_sig`, `s`, `d`, `target`,
    // `issuer_kid`. Also keeps the existing `_ctx` / `_positions`
    // rejects which are soland-specific stateful-only fields.
    let stateless_cursor_declared = is_stateless_cursor_profile_declared(state);
    let has_stateless_marker = value.get("_mac").is_some()
        || value.get("_sig").is_some()
        || value.get("s").is_some()
        || value.get("d").is_some()
        || value.get("target").is_some()
        || value.get("issuer_kid").is_some();
    if has_stateless_marker && !stateless_cursor_declared {
        return Err(SyncCursorError::Integrity(
            "core cursor must use stateful handle form (stateless body \
             requires cx.profile.stateless_cursor.v1)",
        ));
    }
    if value.get("_ctx").is_some() || value.get("_positions").is_some() {
        return Err(SyncCursorError::Integrity(
            "core cursor must use stateful handle form",
        ));
    };
    if stateless_cursor_declared && has_stateless_marker {
        // CURSOR-1 — stateless cursor path. Integrity binding check:
        // the cursor MUST carry both `_sig` (or `_mac`) and `issuer_kid`
        // so the receiver can resolve the issuer's verification key and
        // verify the integrity tag. Absence of either fails with
        // `cursor_integrity_invalid`.
        // TODO(R4): cryptographic verification of `_sig` against the
        // `issuer_kid`-resolved verification key over canonical-JSON
        // bytes of the stateless cursor body. Until then we only
        // enforce the wire-shape contract.
        if value.get("issuer_kid").and_then(Value::as_str).is_none() {
            return Err(SyncCursorError::Integrity(
                "stateless cursor missing issuer_kid binding",
            ));
        }
        if value.get("_sig").is_none() && value.get("_mac").is_none() {
            return Err(SyncCursorError::Integrity(
                "stateless cursor missing _sig / _mac integrity tag",
            ));
        }
    }
    let Some(handle) = value.get("h").and_then(|h| h.as_str()) else {
        return Err(SyncCursorError::Integrity("after cursor must contain h"));
    };
    if crate::round23::validate_cursor_handle(handle).is_err() {
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
    let expected_filter_hash = sync_filter_hash(filter);
    if ctx
        .get("filter_hash")
        .and_then(|filter_hash| filter_hash.as_str())
        .is_none_or(|filter_hash| filter_hash != expected_filter_hash)
    {
        return Err(SyncCursorError::Mismatch(
            "cursor filter hash does not match request filter",
        ));
    }
    let positions_value = stored.get("positions").ok_or(SyncCursorError::Integrity(
        "cursor handle is missing positions",
    ))?;
    let positions = positions_value
        .get("spaces")
        .and_then(|spaces| spaces.as_object())
        .ok_or(SyncCursorError::Integrity(
            "cursor handle is missing positions.spaces",
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
    let issued_at_ms = ctx
        .get("issued_at_ms")
        .and_then(|value| value.as_i64());
    Ok(SyncCursor {
        positions,
        to_device_position,
        issued_at_ms,
    })
}

pub fn decode_sync_cursor_value(token: &str) -> Result<serde_json::Value, SyncCursorError> {
    let Some(encoded) = token.strip_prefix("cx:cursor:") else {
        return Err(SyncCursorError::Invalid(
            "after must use a cx:cursor account token",
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
/// - Plain string that does NOT start with `cx:cursor:` → pass through
///   unchanged; the caller already speaks the projection's `event_id` cursor.
/// - `cx:cursor:...` → decode the structured cursor, look up
///   the handle's stored position for `space_id` (a `timestamp_micros`
///   checkpoint), then walk
///   the space's projected events and persisted messages to find the most
///   recent event at-or-before that checkpoint and return its
///   `event_id`. When no event sits at-or-before the checkpoint, return
///   `None` so backfill streams from the start of the space.
pub async fn resolve_sync_cursor_to_event_id(
    state: &AppState,
    space_id: &str,
    cursor: Option<String>,
) -> Result<Option<String>, &'static str> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    if !cursor.starts_with("cx:cursor:") {
        return Ok(Some(cursor));
    }
    let value = decode_sync_cursor_value(&cursor)
        .map_err(|_| "sync cursor is not a valid cx:cursor token")?;
    let handle = value
        .get("h")
        .and_then(Value::as_str)
        .ok_or("sync cursor is missing stateful handle")?;
    let stored =
        stored_sync_cursor_by_handle(state, handle).map_err(|_| "sync cursor handle is unknown")?;
    let checkpoint = stored
        .get("positions")
        .and_then(|positions| positions.get("spaces"))
        .and_then(|spaces| spaces.get(space_id))
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
            .messages_for_space(space_id)
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
        .list_for_space(space_id, 1000).await
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

pub fn sync_filter_hash(filter: Option<&serde_json::Value>) -> String {
    let empty_filter = json!({});
    let binding = json!({
        "filter": filter.unwrap_or(&empty_filter),
    });
    contrix_sdk::canonical::canonical_sha256(&binding)
        .unwrap_or_else(|_| format!("sha256:{}", sha256_hex(binding.to_string().as_bytes())))
}

#[endpoint(
    operation_id = "cx.ephemeral.send",
    tags("sync"),
    summary = "Send a broadcast ephemeral signal"
)]
#[tracing::instrument(skip_all, fields(op = "cx.ephemeral.send"))]
async fn submit_ephemeral(
    aa: crate::routing::system::extract::AuthArgs,
    body: salvo::oapi::extract::JsonBody<contrix_sdk::EphemeralEnvelope>,
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
        "cx.typing" => {
            persist_ephemeral_typing(state, &session.actor, realm_id_str, &envelope).await
        }
        "cx.presence" => persist_ephemeral_presence(state, &session.actor, &envelope).await,
        "cx.receipt.read" => admit_ephemeral_read_receipt(state, realm_id_str, &envelope).await?,
        "cx.call.signal" => {}
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
    envelope: &contrix_sdk::EphemeralEnvelope,
) -> Result<(), crate::error::AppError> {
    if !matches!(
        envelope.kind.as_str(),
        "cx.call.signal" | "cx.presence" | "cx.typing" | "cx.receipt.read"
    ) {
        return Err(crate::error::AppError::invalid_param(
            "unsupported ephemeral kind",
        ));
    }
    let window_ms = envelope
        .expires_at
        .signed_duration_since(envelope.sent_at)
        .num_milliseconds();
    if window_ms <= 0 || (window_ms as u64) > contrix_sdk::EPHEMERAL_ABSOLUTE_HARD_CEILING_MS as u64
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
    envelope: &contrix_sdk::EphemeralEnvelope,
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
        if let Err(error) = state.persistence.typing().put(TypingRecord {
            actor: actor.to_owned(),
            space_id: realm_id.to_owned(),
            scope_id,
            expires_at: envelope.expires_at,
            updated_at: chrono::Utc::now(),
        }).await {
            tracing::error!(%error, "failed to persist ephemeral typing");
        }
    } else {
        let _ = state.persistence.typing().remove(actor, realm_id).await;
    }
}

async fn persist_ephemeral_presence(
    state: &AppState,
    actor: &str,
    envelope: &contrix_sdk::EphemeralEnvelope,
) {
    let status = envelope
        .payload
        .get("status")
        .or_else(|| envelope.payload.get("state"))
        .and_then(Value::as_str)
        .unwrap_or("online")
        .to_owned();
    if let Err(error) = state.persistence.presence().put(PresenceRecord {
        actor: actor.to_owned(),
        status,
        updated_at: chrono::Utc::now(),
    }).await {
        tracing::error!(%error, "failed to persist ephemeral presence");
    }
}

async fn admit_ephemeral_read_receipt(
    state: &AppState,
    realm_id: &str,
    envelope: &contrix_sdk::EphemeralEnvelope,
) -> Result<(), crate::error::AppError> {
    if envelope
        .payload
        .get("event_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .is_none()
    {
        return Err(crate::error::AppError::invalid_param(
            "cx.receipt.read payload requires event_id",
        ));
    }

    let (disclosure, _visibility, _scope_overrides_allowed) =
        super::event_log::effective_read_receipt_policy_for_space(state, realm_id)
            .await.unwrap_or_else(|| ("optional".to_owned(), "members".to_owned(), true));
    if disclosure == "disabled" {
        return Err(crate::error::AppError::new(
            crate::error::ErrorCode::PolicyViolation,
            format!(
                "Realm '{realm_id}' read_receipt_policy.disclosure=disabled; cx.receipt.read dropped"
            ),
        )
        .with_status(StatusCode::FORBIDDEN));
    }
    Ok(())
}

/// `cx.events.subscribe` at `GET /api/v1/events/subscribe`. NDJSON
/// streaming: each line is one frame, frame `kind` is one of
/// `event` / `catchup_complete` / `heartbeat` / `dropped`.
///
/// Selector: repeated `spaces[]` query args (multi-value).
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
#[tracing::instrument(skip_all, fields(op = "events_subscribe"))]
pub(super) async fn events_subscribe(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected").clone();
    // Spec-canonical param is `realms=` (cx.events.subscribe). Legacy
    // `spaces=` is accepted as an alias through the Realm/Space rename
    // window so older clients don't break.
    let mut spaces = super::query_param_all(req, "realms");
    spaces.extend(super::query_param_all(req, "spaces"));
    if spaces.is_empty() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "realms is required",
        );
        return;
    }
    let spaces = match normalize_scope_selectors(spaces) {
        Ok(spaces) => spaces,
        Err(error) => {
            let message = error.to_string();
            render_error(res, StatusCode::BAD_REQUEST, "invalid_param", &message);
            return;
        }
    };
    let session = authenticated_session(&state, req).await.ok();
    let mut accessible_spaces: Vec<String> = Vec::with_capacity(spaces.len());
    for space in spaces {
        if realm_id_accessible(&state, &space, session.as_ref()).await {
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
            match projected_event_page(&state, space_id, cursor.as_deref(), limit).await {
                Ok(Some(page)) => {
                    for event in page.items {
                        if !projection_record_visible_to_session(&state, &event, session.as_ref()).await {
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

    let catchup_cursor = last_cursor.unwrap_or_else(|| sync_token_for_state(&state));
    let space_filter: BTreeSet<String> = accessible_spaces.iter().cloned().collect();
    let stream_deadline = tokio::time::Instant::now() + Duration::from_millis(max_duration_ms);
    let session_for_stream = session.clone();

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
                            // Round 4 (B1.5) — broadcast capacity exceeded.
                            // The typed EventsSubscribeFrameBody requires a
                            // resume cursor on Dropped; if we don't have a
                            // valid cursor (the broadcast lag dropped state
                            // we'd need to mint one) the SDK rule downgrades
                            // to ResyncRequired. We always carry the
                            // catchup_cursor we already have, so Dropped is
                            // safe here.
                            let cursor_str = catchup_cursor.clone();
                            // Use the typed-id form (cx:cursor:<base64url>),
                            // not the cursor::Cursor struct.
                            let cursor_typed =
                                contrix_sdk::identifiers::Cursor::new(cursor_str.clone()).ok();
                            let body = crate::round4::dropped_or_resync(
                                cursor_typed,
                                format!("broadcast_lagged skipped={skipped}"),
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
#[endpoint(
    operation_id = "cx.events.query",
    tags("events"),
    summary = "Projection-aware events query (single- or multi-space merge; backward / forward direction)"
)]
#[tracing::instrument(skip_all, fields(op = "cx.events.query"))]
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
    operation_id = "cx.events.query_post",
    tags("events"),
    summary = "Body-based projection-aware events query for large selectors"
)]
#[tracing::instrument(skip_all, fields(op = "cx.events.query_post"))]
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
    let spaces = normalize_scope_selectors(parts.realms.clone())?;
    for actor in &parts.actors {
        if validate_did(actor).is_err() {
            return Err(crate::error::AppError::invalid_param(format!(
                "invalid actor: {actor}"
            )));
        }
    }
    // Dispatch: if no spaces (actor-scoped query), forward to the durable
    // Event-store reader in routing/events.rs which builds an actor-keyed
    // `frontier.actors` map. The projection-aware path below is space-keyed.
    if spaces.is_empty() {
        let session = authenticated_session(state, req).await.map_err(|(status, code, message)| {
            crate::error::AppError::invalid_param(message)
                .with_status(status)
                .with_wire_code(code)
        })?;
        let response = durable_events_query_from_parts(state, &session, &parts).await;
        return crate::result::json_ok(serde_json::to_value(response).unwrap_or(json!({})));
    }
    let session = authenticated_session(state, req).await.ok();
    let mut accessible_spaces: Vec<String> = Vec::with_capacity(spaces.len());
    for space in spaces {
        if realm_id_accessible(state, &space, session.as_ref()).await {
            accessible_spaces.push(space);
        }
    }
    if accessible_spaces.is_empty() {
        return Err(crate::error::AppError::not_found("not found"));
    }
    let limit = parts.limit;
    let (cursor, stop_cursor, backward) = events_query_cursor_and_stop(&parts);

    // Single-space fast path preserves the original `BackfillResBody` shape
    // for soland's existing test surface (cx.sync.backfill behavior).
    if accessible_spaces.len() == 1 {
        let space_id = &accessible_spaces[0];
        match projected_event_page(state, space_id, cursor.as_deref(), limit).await {
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

    // Multi-space merge path: call `projected_event_page` per space, merge
    // by `received_at`, then paginate.
    let mut merged: Vec<serde_json::Value> = Vec::new();
    let mut any_has_more = false;
    for space_id in &accessible_spaces {
        match projected_event_page(state, space_id, cursor.as_deref(), limit).await {
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
    let spaces_set: BTreeSet<&str> = parts.realms.iter().map(String::as_str).collect();
    let all_records = state
        .persistence
        .events()
        .snapshot_all()
        .await
        .unwrap_or_default();
    let mut records = Vec::new();
    for record in all_records {
        let actor_match = actors_set.contains(record.actor_id.as_str());
        let space_match = record
            .space_id
            .as_deref()
            .is_some_and(|s| spaces_set.contains(s));
        if !(actor_match || space_match) {
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
    operation_id = "cx.extension.soland.sync.backfill_gap",
    tags("sync"),
    summary = "Backfill the gap between two cursors (deployment-local; not in spec)"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.sync.backfill_gap"))]
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

    // Resolve sync `cx:cursor:` tokens to reducer event cursors.
    let from_cursor = resolve_sync_cursor_to_event_id(state, &realm_id, from_cursor)
        .await.map_err(crate::error::AppError::invalid_param)?;
    let to_cursor = resolve_sync_cursor_to_event_id(state, &realm_id, to_cursor)
        .await.map_err(crate::error::AppError::invalid_param)?;

    let (events, next_cursor, limited) =
        backfill_gap_events(state, &realm_id, from_cursor.as_deref(), limit).await.map_err(|error| {
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
    operation_id = "cx.snapshot.head",
    tags("sync"),
    summary = "Read the snapshot-v2 head (manifest + chunk descriptors + merkle_root) for a Realm"
)]
#[tracing::instrument(skip_all, fields(op = "cx.snapshot.head"))]
async fn snapshot_head(
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<SnapshotHeadResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    // Spec-canonical query param is `realm_id`.
    let space_id = query_param(req, "realm_id")
        .ok_or_else(|| crate::error::AppError::missing_param("realm_id is required"))?;
    let space_id = scope_selector_to_realm_id(&space_id)?;
    if is_realm_deleted(state, &space_id).await {
        return Err(crate::error::AppError::not_found("not found"));
    }
    let space_id_value = RealmId::new(space_id.clone())
        .map_err(|_| crate::error::AppError::invalid_param("invalid realm_id"))?;
    {
        let spaces = state.realms.lock().expect("spaces lock");
        if spaces.get(&space_id_value).is_none() {
            return Err(crate::error::AppError::not_found("not found"));
        }
    }
    let bundle = snapshot_bundle_for_space(state, &space_id)
        .await.ok_or_else(|| crate::error::AppError::not_found("not found"))?;
    // Snapshot v2: the manifest already lists per-chunk digests, so
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
    operation_id = "cx.extension.soland.sync.snapshot_chunk",
    tags("sync"),
    summary = "Read one chunk of a snapshot-v2 bundle (with audit_path proving merkle membership)"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.sync.snapshot_chunk"))]
async fn snapshot_chunk(
    snapshot_ref: salvo::oapi::extract::QueryParam<String, true>,
    chunk_id: salvo::oapi::extract::QueryParam<u32, false>,
    depot: &mut Depot,
) -> crate::result::JsonResult<serde_json::Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let snapshot_ref = snapshot_ref.into_inner();
    let chunk_id = chunk_id.into_inner().unwrap_or(0);
    let (space_id, expected_hash) = parse_snapshot_ref(&snapshot_ref)
        .ok_or_else(|| crate::error::AppError::invalid_param("invalid snapshot_ref"))?;
    if is_realm_deleted(state, &space_id).await {
        return Err(crate::error::AppError::not_found("not found"));
    }
    let bundle = snapshot_bundle_for_space(state, &space_id)
        .await.ok_or_else(|| crate::error::AppError::not_found("not found"))?;
    if bundle.snapshot_ref != snapshot_ref || bundle.state_digest != expected_hash {
        return Err(crate::error::AppError::new(
            crate::error::ErrorCode::StaleFrontier,
            "snapshot_ref no longer matches the current snapshot frontier",
        ));
    }
    // Snapshot v2: chunks[N] is the SDK-canonical SnapshotChunk @
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
    use super::*;

    #[test]
    fn timeline_position_disambiguates_same_second_events() {
        let created_at = DateTime::parse_from_rfc3339("2026-05-22T16:18:24Z")
            .unwrap()
            .with_timezone(&Utc);
        let realm_create = timestamp_position_with_tie_breaker(
            created_at,
            "cx:event:019e507b-16b2-719a-84fd-a9319ab43a36",
        );
        let welcome_message = timestamp_position_with_tie_breaker(
            created_at,
            "cx:event:019e507b-1857-73b7-9579-a00706bf0af4",
        );

        assert_ne!(realm_create, welcome_message);
        assert!(welcome_message > realm_create);
    }
}
