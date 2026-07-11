//! Account-aggregate describe + subscribe long-poll stream
//! (`ak.self.account.stream.subscribe`): the timeline / presence / typing /
//! to_device NDJSON delta machinery and its auth-material gate.

use super::*;
use crate::routing::spaces::space::{
    presence_activity_detail_visible_to_session, presence_visible_to_session,
};

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "account_describe"))]
pub(super) async fn account_describe(
    depot: &mut Depot,
) -> crate::result::JsonResult<SyncDescription> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let supported_sync_profiles = vec![
        "initial".to_owned(),
        "incremental".to_owned(),
        "board".to_owned(),
        "chat".to_owned(),
        "topic".to_owned(),
        "offline_queue_flush".to_owned(),
        "bottom_cell_repair".to_owned(),
    ];
    let service_id = validate_did(&state.config.service_id).map_err(|_| {
        crate::error::AppError::internal("configured service_id is not a valid DID")
    })?;
    crate::result::json_ok(SyncDescription {
        service_id,
        supported_sync_profiles,
        limits: json!({
            "max_realms": 50,
            "max_timeline_events": 100,
            "offline_flush_endpoint": "/_arkret/self/events",
            "bottom_repair_endpoint": "/_soland/admin/realms/{realm_id}/bottom/{cell_id}/repair"
        }),
        // SDK `SyncDescription.frontier` is an opaque cursor string; hand out
        // the current sync token so callers can seed `after` from describe.
        frontier: Some(serde_json::Value::String(sync_token_for_state(state).await)),
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
/// SOL-02-005 — debounce window for `account_subscribe` long-poll wakeups.
/// When a broadcast notification passes the visibility filter, further
/// notifications arriving within this window are drained and coalesced so a
/// burst of N broadcasts triggers ONE snapshot rebuild instead of N. Keeps
/// the read-amplification of busy Realms bounded at the cost of up to this
/// much extra delivery latency per long-poll turn.
const SUBSCRIBE_REBUILD_DEBOUNCE_MS: u64 = 150;
/// Pure predicate: do the `Authorization` header value and/or query string
/// carry authentication material? Split out from the `Request` so the
/// degrade-vs-propagate decision is unit-testable without a live request.
///
/// Mirrors the positions `authenticated_session` inspects: a `Bearer` header,
/// or a token smuggled into the query string (which it rejects outright).
pub(crate) fn auth_material_present(authorization: Option<&str>, query: Option<&str>) -> bool {
    let header_bearer = authorization
        .is_some_and(|value| value.starts_with("Bearer ") || value.starts_with("bearer "));
    let query_token = query.is_some_and(|query| {
        query.contains("access_token=") || query.contains("auth=") || query.contains("token=")
    });
    header_bearer || query_token
}

/// True when the request carries authentication material in any position the
/// auth layer inspects. The subscribe handlers use this to tell a genuinely
/// anonymous client (no material at all) apart from one presenting a bad /
/// expired credential.
pub(crate) fn request_presents_auth_material(req: &Request) -> bool {
    let authorization = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    auth_material_present(authorization, req.uri().query())
}

/// Resolve the optional session for subscribe surfaces that allow anonymous
/// public-Realm reads.
///
/// A request presenting bad auth material must surface its auth error instead
/// of degrading to anonymous, because sync cursors are principal-bound.
pub(crate) async fn subscribe_session_or_render(
    state: &AppState,
    req: &Request,
    res: &mut Response,
) -> Option<Option<SessionRecord>> {
    match authenticated_session(state, req).await {
        Ok(session) => Some(Some(session)),
        Err((status, code, message)) => {
            if request_presents_auth_material(req) {
                render_error(res, status, code, message);
                None
            } else {
                Some(None)
            }
        }
    }
}

/// Resolve the required session for account subscribe long-poll.
///
/// client-sync.md requires `Authorization` on this surface. Fail closed on
/// every auth error so clients observe the real 401/auth wire code instead of
/// replaying as anonymous.
pub(crate) async fn account_subscribe_session_or_render(
    state: &AppState,
    req: &Request,
    res: &mut Response,
) -> Option<SessionRecord> {
    match authenticated_session(state, req).await {
        Ok(session) => Some(session),
        Err((status, code, message)) => {
            render_error(res, status, code, message);
            None
        }
    }
}

#[endpoint(
    operation_id = "ak.self.account.stream.subscribe",
    tags("sync"),
    summary = "Account-aggregate subscribe stream (timeline / presence / typing / to_device)"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.account.stream.subscribe"))]
pub(super) async fn account_subscribe(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot
        .get_typed::<AppState>()
        .expect("state injected")
        .clone();
    let body = account_subscribe_query(req);
    let max_wait_ms = parse_max_wait_ms(req);
    let session = match account_subscribe_session_or_render(&state, req, res).await {
        Some(session) => session,
        None => return,
    };
    let filter_value = sync_filter_value(body.filter.as_ref());
    let subscribe_scope_key = account_subscribe_scope_key(req, Some(&session), &body);
    if reject_subscribe_reconnect(&state, &subscribe_scope_key, res) {
        return;
    }
    let after_cursor = if let Some(after) = body.after.as_deref() {
        match parse_and_validate_sync_cursor(
            after,
            &state,
            Some(&session),
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
    if let Some(presented_issued_at_ms) = after_cursor.issued_at_ms {
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
    // client-sync.md: the account subscribe surface is read-only.
    // Presence intent (`set_presence`) is NOT a subscribe parameter —
    // clients broadcast `ak.presence` through
    // `POST /_arkret/self/ephemeral`; any `set_presence` query value is
    // ignored here so establishing or replaying a subscription never
    // triggers a server-side mutation.
    prune_expired_typing(&state).await;

    // Subscribe to broadcast BEFORE building the initial snapshot so an
    // event landing between snapshot-build and long-poll subscribe is not
    // missed.
    let mut rx = state.event_broadcast.subscribe();
    let mut response =
        build_sync_snapshot(&state, Some(&session), &body, &after_cursor, false).await;
    let mut control_frame: Option<Value> = None;

    // Long-poll only when the client supplied an `after` cursor (true
    // incremental sync) AND the snapshot is delta-empty. Full sync always
    // returns immediately because the client needs the baseline. A
    // `max_wait_ms=0` opt-out preserves the immediate-return
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
                            if !account_subscribe_notification_should_wake(
                                &state,
                                &notification,
                                Some(&session),
                                &after_cursor,
                            )
                            .await
                            {
                                continue;
                            }
                            // SOL-02-005 debounce: drain notifications that
                            // arrive within the coalescing window (bounded by
                            // the long-poll deadline) so a broadcast burst
                            // rebuilds the snapshot once. Coalesced
                            // notifications need no individual handling — the
                            // rebuilt snapshot covers everything visible.
                            let mut lagged_during_drain = false;
                            let mut include_presence_delta =
                                account_subscribe_notification_is_presence(&notification);
                            let drain_until = (tokio::time::Instant::now()
                                + Duration::from_millis(SUBSCRIBE_REBUILD_DEBOUNCE_MS))
                            .min(deadline);
                            loop {
                                tokio::select! {
                                    biased;
                                    _ = tokio::time::sleep_until(drain_until) => break,
                                    more = rx.recv() => match more {
                                        Ok(more) => {
                                            include_presence_delta |=
                                                account_subscribe_notification_is_presence(&more);
                                        }
                                        Err(RecvError::Lagged(_)) => {
                                            lagged_during_drain = true;
                                            include_presence_delta = true;
                                            break;
                                        }
                                        Err(RecvError::Closed) => break,
                                    }
                                }
                            }
                            response = build_sync_snapshot(
                                &state,
                                Some(&session),
                                &body,
                                &after_cursor,
                                include_presence_delta,
                            )
                            .await;
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
                            response = build_sync_snapshot(
                                &state,
                                Some(&session),
                                &body,
                                &after_cursor,
                                true,
                            )
                            .await;
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

    if account_subscribe_prefers_json(req) {
        if let Some(control_frame) = control_frame {
            res.render(Json(control_frame));
        } else {
            res.render(Json(response));
        }
        return;
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

fn account_subscribe_prefers_json(req: &Request) -> bool {
    req.headers()
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|accept| accept_contains_media_type(accept, "application/json"))
}

fn accept_contains_media_type(accept: &str, media_type: &str) -> bool {
    accept.split(',').any(|part| {
        part.split(';')
            .next()
            .map(str::trim)
            .is_some_and(|value| value.eq_ignore_ascii_case(media_type))
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
fn delta_is_empty(response: &arkret_sdk::models::SyncOutcome) -> bool {
    response.realms.is_empty()
        && response.left_realms.is_empty()
        && response.to_device.is_empty()
        && response.to_device_lost != Some(true)
        && response.presence.is_empty()
        && notifications_delta_is_empty(&response.notifications)
}

fn account_subscribe_notification_is_presence(
    notification: &crate::state::EventNotification,
) -> bool {
    matches!(
        &notification.kind,
        crate::state::EventNotificationKind::Ephemeral { kind } if kind == "ak.presence"
    )
}

async fn account_subscribe_notification_should_wake(
    state: &AppState,
    notification: &crate::state::EventNotification,
    session: Option<&SessionRecord>,
    after_cursor: &SyncCursor,
) -> bool {
    if realm_id_accessible(state, &notification.realm_id, session).await {
        return true;
    }
    let (invite_notifications, _) =
        pending_invite_notification_delta(state, session, after_cursor, true).await;
    invite_notifications.iter().any(|invite| {
        invite
            .get("realm_id")
            .and_then(Value::as_str)
            .is_some_and(|realm_id| realm_id == notification.realm_id)
    })
}

fn notifications_delta_is_empty(value: &Value) -> bool {
    if value.is_null() {
        return true;
    }
    if let Some(events) = value.get("events").and_then(Value::as_array) {
        return events.is_empty();
    }
    if let Some(items) = value.get("items").and_then(Value::as_array) {
        return items.is_empty();
    }
    value.as_array().is_some_and(Vec::is_empty)
}

fn account_subscribe_query(req: &mut Request) -> SyncRequestBody {
    SyncRequestBody {
        after: query_param(req, "after"),
        catchup: query_param(req, "catchup").and_then(|value| value.parse::<bool>().ok()),
        filter: query_param(req, "filter").and_then(|value| serde_json::from_str(&value).ok()),
        subscriptions: None,
        wait_for: None,
    }
}

pub(crate) fn sync_filter_value(filter: Option<&arkret_sdk::SyncFilter>) -> Option<Value> {
    filter.and_then(|filter| serde_json::to_value(filter).ok())
}

fn account_delta_frame(response: arkret_sdk::models::SyncOutcome) -> Value {
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
        "ak.self.account.stream.subscribe|{}|filter={}",
        subscribe_subject(req, session),
        sync_filter_digest(filter_value.as_ref())
    )
}

pub(crate) fn roster_member_actor_id(member: &Value) -> Option<String> {
    member
        .get("actor_id")
        .or_else(|| member.get("actor"))
        .or_else(|| member.get("did"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|actor| !actor.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) async fn presence_events_for_actors(
    state: &AppState,
    actors: BTreeSet<String>,
    session: Option<&SessionRecord>,
) -> Vec<Value> {
    let mut events = Vec::new();
    for actor in actors {
        if !presence_visible_to_session(state, &actor, session).await {
            continue;
        }
        let records = state
            .persistence
            .presence()
            .list_for_actor(&actor)
            .await
            .unwrap_or_default();
        if let Some(aggregated) = aggregate_presence_records(&records, now()) {
            let reveal_activity_detail =
                presence_activity_detail_visible_to_session(state, &actor, session).await;
            events.push(presence_sync_event_json(
                &actor,
                &aggregated,
                reveal_activity_detail,
            ));
        }
    }
    events
}

/// One actor's presence after merging their per-device broadcasts
/// (profiles-presence.md §3.3 multi-device aggregation).
#[derive(Clone, Debug)]
pub(crate) struct AggregatedPresence {
    pub status: String,
    pub status_message: Option<String>,
    pub last_active_at: Option<String>,
    pub updated_at: DateTime<Utc>,
    /// Every device row has lapsed — the actor projects as `offline`
    /// with the coarse stale-activity bucket appended.
    pub all_expired: bool,
}

/// Deterministic multi-device merge: unexpired rows aggregate by the
/// `dnd > online > idle` priority; no unexpired row at all projects as
/// `offline`. `status_message` / `last_active_at` come from the most
/// recently updated unexpired row carrying a value.
pub(crate) fn aggregate_presence_records(
    records: &[PresenceRecord],
    now: DateTime<Utc>,
) -> Option<AggregatedPresence> {
    let newest_updated_at = records.iter().map(|record| record.updated_at).max()?;
    let live: Vec<&PresenceRecord> = records
        .iter()
        .filter(|record| !presence_record_expired(record, now))
        .collect();
    if live.is_empty() {
        return Some(AggregatedPresence {
            status: "offline".to_owned(),
            status_message: None,
            last_active_at: None,
            updated_at: newest_updated_at,
            all_expired: true,
        });
    }
    let status = arkret_sdk::aggregate_presence_states(
        live.iter()
            .filter_map(|record| arkret_sdk::PresenceStatus::parse_wire(&record.status)),
    );
    let mut by_recency: Vec<&&PresenceRecord> = live.iter().collect();
    by_recency.sort_by_key(|record| std::cmp::Reverse(record.updated_at));
    let status_message = by_recency
        .iter()
        .find_map(|record| record.status_message.clone().filter(|m| !m.is_empty()));
    let last_active_at = by_recency
        .iter()
        .find_map(|record| record.last_active_at.clone());
    Some(AggregatedPresence {
        status: status.as_wire().to_owned(),
        status_message,
        last_active_at,
        updated_at: by_recency
            .first()
            .map(|record| record.updated_at)
            .unwrap_or(newest_updated_at),
        all_expired: false,
    })
}

fn presence_record_expired(record: &PresenceRecord, now: DateTime<Utc>) -> bool {
    if let Some(expires_at) = record.expires_at
        && expires_at <= now
    {
        return true;
    }
    // Stale-online decay back-stop: an `online` row that stopped being
    // refreshed lapses even when its envelope TTL was generous.
    record.status == "online"
        && now.signed_duration_since(record.updated_at)
            > ChronoDuration::seconds(PRESENCE_ONLINE_TTL_SECONDS)
}

pub(crate) fn presence_sync_event_json(
    actor: &str,
    aggregated: &AggregatedPresence,
    reveal_activity_detail: bool,
) -> Value {
    let downgraded =
        !reveal_activity_detail && matches!(aggregated.status.as_str(), "dnd" | "idle");
    let status = if downgraded {
        "offline".to_owned()
    } else {
        aggregated.status.clone()
    };
    let mut event = json!({
        "user_id": actor,
        "actor_id": actor,
        "presence": status,
        "status": status,
        "updated_at": aggregated.updated_at,
    });
    let Some(object) = event.as_object_mut() else {
        return event;
    };
    if downgraded {
        // §3.4: for observers outside the visibility set `dnd` / `idle`
        // degrade to `offline`; leaking a fresh status message or
        // activity bucket alongside would reopen the same side channel.
        return event;
    }
    if aggregated.all_expired {
        object.insert(
            "last_active_at".to_owned(),
            json!(presence_last_active_bucket_interval(aggregated.updated_at)),
        );
        return event;
    }
    if let Some(status_message) = aggregated.status_message.as_ref() {
        object.insert("status_message".to_owned(), json!(status_message));
    }
    if reveal_activity_detail && let Some(last_active_at) = aggregated.last_active_at.as_ref() {
        object.insert("last_active_at".to_owned(), json!(last_active_at));
    }
    event
}

fn presence_last_active_bucket_interval(updated_at: DateTime<Utc>) -> String {
    const LAST_ACTIVE_BUCKET_SECONDS: i64 = 60 * 60;
    let bucket_start_seconds = updated_at
        .timestamp()
        .div_euclid(LAST_ACTIVE_BUCKET_SECONDS)
        * LAST_ACTIVE_BUCKET_SECONDS;
    let bucket_start =
        DateTime::<Utc>::from_timestamp(bucket_start_seconds, 0).unwrap_or(updated_at);
    format!(
        "{}/PT1H",
        bucket_start.to_rfc3339_opts(SecondsFormat::Secs, true)
    )
}
