//! Account-aggregate describe + subscribe long-poll stream
//! (`ck.self.account.stream.subscribe`): the timeline / presence / typing /
//! to_device NDJSON delta machinery and its auth-material gate.

use super::*;
use crate::routing::spaces::space::{
    PresenceVisibilityPolicy, presence_activity_detail_visible_to_session,
    presence_visibility_for_actor, presence_visible_to_session,
};

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "account_describe"))]
pub(super) async fn account_describe(
    depot: &mut Depot,
) -> crate::result::JsonResult<SyncDescription> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let supported_sync_profiles = vec![
        "initial".to_owned(),
        "incremental".to_owned(),
        "board".to_owned(),
        "chat".to_owned(),
        "topic".to_owned(),
        "offline_queue_flush".to_owned(),
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

/// Resolve the optional session for a subscribe long-poll **without masking a
/// failed authentication as anonymous**.
///
/// Subscribe MAY run anonymously, but ONLY when the client presents no auth
/// material at all. A request that DOES present a bearer which then fails
/// authentication MUST NOT be silently downgraded to an anonymous session: the
/// sync cursor is bound to the minting principal, so an anonymous replay of a
/// principal-bound cursor surfaces as `cursor_integrity_invalid` ("cursor
/// principal does not match request actor"). The client's sync engine treats
/// that as "reset the cursor and retry" rather than "refresh the session", so a
/// merely-expired bearer sends it into a non-recovering anonymous loop instead
/// of re-authenticating. Fail closed: render the real 401 — preserving the
/// `auth_expired` wire code the client keys its refresh on — and signal the
/// handler to stop.
///
/// Returns `Some(session_opt)` to continue (anonymous when the inner option is
/// `None`), or `None` when an auth error was already rendered to `res`.
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

#[endpoint(
    operation_id = "ck.self.account.stream.subscribe",
    tags("sync"),
    summary = "Account-aggregate subscribe stream (timeline / presence / typing / to_device)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.account.stream.subscribe"))]
pub(super) async fn account_subscribe(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected").clone();
    let body = account_subscribe_query(req);
    let max_wait_ms = parse_max_wait_ms(req);
    let session = match subscribe_session_or_render(&state, req, res).await {
        Some(session) => session,
        None => return,
    };
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
        if presence_visibility_for_actor(&state, &session.actor).await
            == PresenceVisibilityPolicy::Nobody
        {
            if let Err(error) = state.persistence.presence().delete(&session.actor).await {
                tracing::error!(%error, "failed to clear hidden presence");
            }
        } else if let Err(error) = state
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
fn delta_is_empty(response: &cokret_sdk::models::SyncOutcome) -> bool {
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

pub(crate) fn sync_filter_value(filter: Option<&cokret_sdk::SyncFilter>) -> Option<Value> {
    filter.and_then(|filter| serde_json::to_value(filter).ok())
}

fn presence_status_wire(status: &PresenceStatus) -> &'static str {
    match status {
        PresenceStatus::Online => "online",
        PresenceStatus::Offline => "offline",
        PresenceStatus::Unavailable => "unavailable",
    }
}

fn account_delta_frame(response: cokret_sdk::models::SyncOutcome) -> Value {
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
        if let Ok(Some(record)) = state.persistence.presence().get(&actor).await {
            let reveal_activity_detail =
                presence_activity_detail_visible_to_session(state, &actor, session).await;
            events.push(presence_sync_event_json(record, reveal_activity_detail));
        }
    }
    events
}

pub(crate) fn presence_sync_event_json(
    record: PresenceRecord,
    reveal_activity_detail: bool,
) -> Value {
    let is_stale_online = record.status == "online"
        && now().signed_duration_since(record.updated_at)
            > ChronoDuration::seconds(PRESENCE_ONLINE_TTL_SECONDS);
    let status = if is_stale_online {
        "offline".to_owned()
    } else {
        presence_status_for_observer(&record.status, reveal_activity_detail)
    };
    let mut event = json!({
        "user_id": record.actor,
        "actor_id": record.actor,
        "presence": status,
        "status": status,
        "updated_at": record.updated_at,
    });
    if is_stale_online && let Some(object) = event.as_object_mut() {
        object.insert(
            "last_active_at".to_owned(),
            json!(presence_last_active_bucket_interval(record.updated_at)),
        );
    }
    event
}

fn presence_status_for_observer(status: &str, reveal_activity_detail: bool) -> String {
    if !reveal_activity_detail && matches!(status, "dnd" | "idle") {
        return "offline".to_owned();
    }
    status.to_owned()
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
