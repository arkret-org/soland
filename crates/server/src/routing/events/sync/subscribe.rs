//! Account-aggregate describe + long-lived subscribe stream
//! (`ak.self.account.stream.subscribe`): the timeline / presence / typing /
//! to_device NDJSON delta machinery and its auth-material gate.

use super::*;
use crate::routing::spaces::space::presence_visible_to_session;

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "account_describe"))]
pub(super) async fn account_describe(
    depot: &mut Depot,
) -> soland_http::result::JsonResult<arkret_sdk::ServiceDescribe> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    soland_http::result::json_ok(crate::routing::system::describe::build_server_description(
        state,
    ))
}

/// Bounded account long-poll window. An incremental request with no visible
/// changes waits for a durable/broadcast wake-up and completes after 30s with
/// a projection-neutral frontier. The client then reconnects from that cursor.
const ACCOUNT_SUBSCRIBE_DEFAULT_WAIT_MS: u64 = 30_000;
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
    let query_token = query.is_some_and(arkret_sdk::contains_query_auth_material);
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
                soland_http::error::render_error_code(
                    soland_http::error::ErrorCode::CursorExpired,
                    res,
                    "cursor has expired",
                );
                return;
            }
            Err(SyncCursorError::Invalid(message)) => {
                soland_http::error::render_error_code(
                    soland_http::error::ErrorCode::InvalidParam,
                    res,
                    message,
                );
                return;
            }
            Err(SyncCursorError::Mismatch(message)) | Err(SyncCursorError::Integrity(message)) => {
                soland_http::error::render_error_code(
                    soland_http::error::ErrorCode::CursorIntegrityInvalid,
                    res,
                    message,
                );
                return;
            }
            Err(SyncCursorError::Revoked) => {
                soland_http::error::render_error_code(
                    soland_http::error::ErrorCode::CursorRevoked,
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
            .sync_application()
            .prune_superseded_cursors(
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
    let response = build_sync_snapshot(&state, Some(&session), &body, &after_cursor, false).await;
    let initial_cursor = response.cursor.clone();
    let initial_has_delta = body.after.is_none() || !delta_is_empty(&response);
    let body_stream = async_stream::stream! {
        if initial_has_delta {
            yield Ok::<Bytes, std::io::Error>(ndjson_line(&response));
            if body.catchup.unwrap_or(false) {
                yield Ok::<Bytes, std::io::Error>(ndjson_line(&account_catchup_complete_frame(
                    initial_cursor.clone(),
                )));
            }
            return;
        }

        let current_cursor = after_cursor;
        let current_cursor_token = body.after.clone();
        let deadline = tokio::time::Instant::now()
            + Duration::from_millis(ACCOUNT_SUBSCRIBE_DEFAULT_WAIT_MS);

        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    // Re-read durable projections at timeout. Broadcast is only
                    // a latency hint, so a lost wake-up must not hide data.
                    let final_snapshot = build_sync_snapshot(
                        &state,
                        Some(&session),
                        &body,
                        &current_cursor,
                        false,
                    ).await;
                    let final_cursor = final_snapshot.cursor.clone();
                    if delta_is_empty(&final_snapshot) {
                        yield Ok::<Bytes, std::io::Error>(ndjson_line(
                            &account_frontier_frame(final_cursor.clone()),
                        ));
                    } else {
                        yield Ok::<Bytes, std::io::Error>(ndjson_line(&final_snapshot));
                    }
                    if body.catchup.unwrap_or(false) {
                        yield Ok::<Bytes, std::io::Error>(ndjson_line(
                            &account_catchup_complete_frame(final_cursor),
                        ));
                    }
                    break;
                }
                recv = rx.recv() => match recv {
                    Ok(notification) => {
                        if !account_subscribe_notification_should_wake(
                            &state,
                            &notification,
                            Some(&session),
                        ).await {
                            continue;
                        }
                        let mut include_presence_delta =
                            account_subscribe_notification_is_presence(&notification);
                        let drain_until = tokio::time::Instant::now()
                            + Duration::from_millis(SUBSCRIBE_REBUILD_DEBOUNCE_MS);
                        let mut lagged = false;
                        loop {
                            tokio::select! {
                                _ = tokio::time::sleep_until(drain_until) => break,
                                more = rx.recv() => match more {
                                    Ok(more) => include_presence_delta |=
                                        account_subscribe_notification_is_presence(&more),
                                    Err(RecvError::Lagged(_)) => {
                                        lagged = true;
                                        break;
                                    }
                                    Err(RecvError::Closed) => break,
                                }
                            }
                        }
                        if lagged {
                            arm_subscribe_reconnect(
                                &state,
                                &subscribe_scope_key,
                                SUBSCRIBE_RECONNECT_AFTER_MS,
                            );
                            yield Ok::<Bytes, std::io::Error>(ndjson_line(
                                &account_reconnect_control_frame(
                                    current_cursor_token.as_deref(),
                                    "broadcast_lagged",
                                    SUBSCRIBE_RECONNECT_AFTER_MS,
                                ),
                            ));
                            break;
                        }
                        let delta = build_sync_snapshot(
                            &state,
                            Some(&session),
                            &body,
                            &current_cursor,
                            include_presence_delta,
                        ).await;
                        if delta_is_empty(&delta) {
                            continue;
                        }
                        let delta_cursor = delta.cursor.clone();
                        yield Ok::<Bytes, std::io::Error>(ndjson_line(&delta));
                        if body.catchup.unwrap_or(false) {
                            yield Ok::<Bytes, std::io::Error>(ndjson_line(
                                &account_catchup_complete_frame(delta_cursor),
                            ));
                        }
                        break;
                    }
                    Err(RecvError::Lagged(_)) => {
                        arm_subscribe_reconnect(
                            &state,
                            &subscribe_scope_key,
                            SUBSCRIBE_RECONNECT_AFTER_MS,
                        );
                        yield Ok::<Bytes, std::io::Error>(ndjson_line(
                            &account_reconnect_control_frame(
                                current_cursor_token.as_deref(),
                                "broadcast_lagged",
                                SUBSCRIBE_RECONNECT_AFTER_MS,
                            ),
                        ));
                        break;
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        }
    };
    let _ = res.add_header("content-type", "application/x-ndjson", true);
    res.stream(body_stream.boxed());
}

fn account_frontier_frame(cursor: Option<String>) -> arkret_sdk::AccountSubscribeFrame {
    arkret_sdk::AccountSubscribeFrame {
        kind: arkret_sdk::AccountSubscribeFrameKind::Frontier,
        cursor,
        realms: None,
        to_device: None,
        device_lists: None,
        account_data: None,
        presence: None,
        notifications: None,
        partial: None,
        priority: None,
        reconnect_after_ms: None,
    }
}

fn account_catchup_complete_frame(cursor: Option<String>) -> arkret_sdk::AccountSubscribeFrame {
    arkret_sdk::AccountSubscribeFrame {
        kind: arkret_sdk::AccountSubscribeFrameKind::CatchupComplete,
        cursor,
        realms: None,
        to_device: None,
        device_lists: None,
        account_data: None,
        presence: None,
        notifications: None,
        partial: None,
        priority: None,
        reconnect_after_ms: None,
    }
}

/// A snapshot is "delta-empty" when an incremental sync would carry no
/// new realm state, no membership departure, no queued device messages,
/// and no presence ticks. `account_data` is intentionally excluded — it
/// is always emitted in full for authenticated sessions today, so it
/// would defeat long-poll entirely.
fn delta_is_empty(response: &arkret_sdk::AccountSubscribeFrame) -> bool {
    response
        .realms
        .as_ref()
        .is_none_or(|realms| realms.entries.is_empty())
        && response
            .to_device
            .as_ref()
            .is_none_or(|to_device| to_device.messages.is_empty() && to_device.lost != Some(true))
        && response
            .presence
            .as_ref()
            .is_none_or(|presence| presence.events.is_empty())
        && response
            .notifications
            .as_ref()
            .is_none_or(|notifications| notifications.items.is_empty())
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
) -> bool {
    if let crate::state::EventNotificationKind::Account {
        account_id,
        recipient_service_id,
    } = &notification.kind
    {
        let Some(session) = session else {
            return false;
        };
        if recipient_service_id != &state.service_id {
            return false;
        }
        return state
            .accounts_store()
            .get(&session.actor)
            .await
            .ok()
            .flatten()
            .is_some_and(|account| account.id == *account_id);
    }
    if realm_id_accessible(state, &notification.realm_id, session).await {
        return true;
    }
    false
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

fn account_reconnect_control_frame(
    after: Option<&str>,
    _reason: impl Into<String>,
    reconnect_after_ms: u64,
) -> arkret_sdk::AccountSubscribeFrame {
    let (kind, cursor) = match after {
        Some(cursor) if !cursor.is_empty() => (
            arkret_sdk::AccountSubscribeFrameKind::Dropped,
            Some(cursor.to_owned()),
        ),
        _ => (arkret_sdk::AccountSubscribeFrameKind::ResyncRequired, None),
    };
    arkret_sdk::AccountSubscribeFrame {
        kind,
        cursor,
        realms: None,
        to_device: None,
        device_lists: None,
        account_data: None,
        presence: None,
        notifications: None,
        partial: None,
        priority: None,
        reconnect_after_ms: Some(reconnect_after_ms),
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
) -> Vec<arkret_sdk::EphemeralEnvelope> {
    let now = Utc::now();
    let mut events = Vec::new();
    for actor in actors {
        if !presence_visible_to_session(state, &actor, session).await {
            continue;
        }
        events.extend(
            state
                .presence_store()
                .list_for_actor(&actor)
                .await
                .unwrap_or_default()
                .into_iter()
                .filter(|record| !presence_record_expired(record, now))
                .map(|record| record.envelope),
        );
    }
    events.sort_by_key(|event| {
        (
            event.actor_id.clone(),
            event.device_id.clone(),
            event.sent_at,
        )
    });
    events
}

/// One actor's presence after merging their per-device broadcasts
/// (profiles-presence.md §3.3 multi-device aggregation).
#[derive(Clone, Debug)]
pub(crate) struct AggregatedPresence {
    pub status: String,
    pub updated_at: DateTime<Utc>,
}

/// Deterministic multi-device merge: unexpired rows aggregate by the
/// `dnd > online > idle` priority; no unexpired row at all projects as
/// `offline`.
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
            updated_at: newest_updated_at,
        });
    }
    let status = arkret_sdk::aggregate_presence_states(
        live.iter()
            .filter_map(|record| arkret_sdk::PresenceStatus::parse_wire(&record.status)),
    );
    let mut by_recency: Vec<&&PresenceRecord> = live.iter().collect();
    by_recency.sort_by_key(|record| std::cmp::Reverse(record.updated_at));
    Some(AggregatedPresence {
        status: status.as_wire().to_owned(),
        updated_at: by_recency
            .first()
            .map(|record| record.updated_at)
            .unwrap_or(newest_updated_at),
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
