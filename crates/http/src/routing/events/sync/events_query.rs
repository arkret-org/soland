//! Multi-Realm / multi-actor event stream (`ak.self.events.stream.subscribe.v1`),
//! projection-aware events read (`ak.self.events.read.scan.v1`),
//! signed snapshot-manifest head, plus the NDJSON framing and reconnect-gate
//! helpers shared by both subscribe surfaces.

use super::*;

/// Bounded catch-up page size, shared by the NDJSON surface and the WebSocket
/// events channel so both bindings truncate at the same point.
pub(crate) const EVENTS_CATCHUP_LIMIT: usize = 100;
const EVENTS_SUBSCRIBE_DEFAULT_WAIT_MS: u64 = 30_000;

/// `ak.self.events.stream.subscribe.v1` at `GET /_arkret/self/events/subscribe`. NDJSON
/// streaming: each line is one frame, frame `kind` is one of
/// `event` / `catchup_complete` / `heartbeat` / `dropped`.
///
/// Selector: repeated `realms[]` query args (multi-value).
///
/// Lifecycle:
///   1. Validate inputs (realms, accessibility).
///   2. Subscribe to the live event broadcast BEFORE serving history so no events are missed in the
///      history-vs-live window.
///   3. Build an async stream that yields: a) bounded replay frames when `catchup=true` b) one
///      `catchup_complete` frame after replay data, or after a `frontier` baseline when the replay
///      is empty c) live event frames as broadcast notifications arrive d) periodic `heartbeat`
///      frames every 30s of idle e) a terminal `resync_required` frame when subscription-wide
///      broadcast lag is detected
///   4. Stream terminates when:
///      - `max_duration_ms` query param elapsed (default 30_000 ms)
///      - client disconnects (drops the response stream)
///      - the broadcast channel is closed (server shutdown)
#[handler]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.events.subscribe"))]
pub(crate) async fn events_subscribe(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot
        .get_typed::<AppState>()
        .expect("state injected")
        .clone();
    let realms = super::super::query_param_all(req, "realms");
    if realms.is_empty() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "param_missing",
            "realms is required",
        );
        return;
    }
    let realms = match normalize_scope_selectors(realms) {
        Ok(realms) => realms,
        Err(error) => {
            let message = error.to_string();
            render_error(res, StatusCode::BAD_REQUEST, "param_invalid", &message);
            return;
        }
    };
    let session = match subscribe_session_or_render(&state, req, res).await {
        Some(session) => session,
        None => return,
    };
    if let Some(session) = session.as_ref()
        && let Err(error) = super::super::require_agent_session_scope(
            session,
            arkret_wire::ServiceOperationId::SELF_EVENTS_STREAM_SUBSCRIBE_V1,
        )
    {
        render_error(res, error.http_status(), error.wire_code(), &error.message);
        return;
    }
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
    let after_token = query_param(req, "after");
    let catchup = match query_param(req, "catchup") {
        None => false,
        Some(value) => match value.parse::<bool>() {
            Ok(catchup) => catchup,
            Err(_) => {
                render_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    "param_invalid",
                    "catchup must be a boolean",
                );
                return;
            }
        },
    };
    // Every cursor this stream hands out is an opaque `ak:cursor:` token (NOT a
    // raw `event_id`): the typed `EventsSubscribeFrame.cursor` is
    // `Option<identifiers::Cursor>`, which rejects anything without the
    // `ak:cursor:` prefix, so a frame carrying a bare `event_id` fails to parse
    // client-side and the client never advances its resume position. We mint
    // tokens with `sync_token_for_events_query` and accept them back through
    // `parse_and_validate_events_query_cursor`; both are bound to the SAME
    // realm-scope `filter_digest` so a token we issue round-trips as a valid
    // `after`.
    let filter_digest = events_subscribe_filter_digest(&accessible_realms);
    let resume_event_id = match &after_token {
        Some(after) => {
            match parse_and_validate_events_query_cursor(
                after,
                &state,
                session.as_ref(),
                &filter_digest,
                chrono::Utc::now().timestamp_millis(),
            )
            .await
            {
                Ok(cursor) => Some(cursor.event_id),
                Err(error) => {
                    let mapped = events_query_cursor_error(error);
                    soland_http::error::render_error_code(mapped.code, res, &mapped.message);
                    return;
                }
            }
        }
        None => None,
    };
    let subscribe_scope_key = events_subscribe_scope_key(req, session.as_ref(), &accessible_realms);
    if reject_subscribe_reconnect(&state, &subscribe_scope_key, res) {
        return;
    }
    // Cap how long the stream stays open. Default 30s so clients whose HTTP
    // runtime exposes the NDJSON body only when the response closes (notably
    // browser/WASM fetch adapters) still observe bounded live latency. Tests
    // typically pass `max_duration_ms=500` to bound assertion latency.
    // Production clients reconnect after the close (HTTP/1.1 long-poll
    // pattern) or use SSE EventSource auto-reconnect.
    let max_duration_ms = query_param(req, "max_duration_ms")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(EVENTS_SUBSCRIBE_DEFAULT_WAIT_MS)
        .min(600_000);
    // Heartbeat interval. Default 15s; min 100ms (for tests).
    let heartbeat_ms = query_param(req, "heartbeat_ms")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(15_000)
        .max(100);

    // Subscribe to live notifications BEFORE serving history so we don't
    // miss events that land between history-end and subscribe-start.
    let mut rx = state.subscribe_event_notifications();

    let realm_filter = accessible_realms.iter().cloned().collect::<BTreeSet<_>>();
    let replay_upper_bound = if catchup {
        match resume_event_id.as_deref() {
            Some(cursor) => {
                match projected_event_replay_upper_bound(&state, &realm_filter, cursor).await {
                    Ok(upper_bound) => upper_bound,
                    Err(error) if error.to_string().contains("invalid_cursor") => {
                        render_error(
                            res,
                            StatusCode::BAD_REQUEST,
                            "invalid_cursor",
                            "cursor not found",
                        );
                        return;
                    }
                    Err(error) => {
                        tracing::warn!(%error, "failed to capture events catch-up upper bound");
                        render_error(
                            res,
                            StatusCode::SERVICE_UNAVAILABLE,
                            "temporarily_unavailable",
                            "event replay is unavailable",
                        );
                        return;
                    }
                }
            }
            // Unlike account initial sync, a cursorless Realm subscribe is a
            // live tail. Durable history bootstrap uses events.read.scan.
            None => None,
        }
    } else {
        None
    };
    let stream_deadline = tokio::time::Instant::now() + Duration::from_millis(max_duration_ms);
    let session_for_stream = session.clone();
    let subscribe_scope_key_for_stream = subscribe_scope_key.clone();
    let filter_digest_for_stream = filter_digest.clone();

    // The async stream — yields one NDJSON line (Bytes) per frame.
    let body_stream = async_stream::stream! {
        let mut replayed_event_ids = BTreeSet::new();
        let mut replay_cursor = None;

        // 1. Replay incrementally through the upper bound captured after the
        // live receiver was installed. Queued notifications for replayed ids
        // are discarded below, creating one replay-to-live boundary.
        if let Some(upper_bound) = replay_upper_bound.as_deref() {
            let page = projected_event_page_for_realms_through(
                &state,
                &realm_filter,
                resume_event_id.as_deref(),
                Some(upper_bound),
                EVENTS_CATCHUP_LIMIT,
            )
            .await;
            let page = match page {
                Ok(Some(page)) => page,
                Ok(None) => return,
                Err(error) => {
                    tracing::warn!(%error, "events catch-up replay failed after stream start");
                    let frame = json!({"kind": "resync_required"});
                    yield Ok::<Bytes, std::io::Error>(ndjson_line(&frame));
                    return;
                }
            };
            let has_more = page.has_more;
            for event in page.items {
                if !projection_record_visible_to_session(
                    &state,
                    &event,
                    session_for_stream.as_ref(),
                )
                .await
                {
                    continue;
                }
                replayed_event_ids.insert(event.event_id.clone());
                let projected = projection_event_json(&event);
                let Some(event_envelope) = full_event_from_projection_json(&state, &projected).await else {
                    tracing::warn!(event_id = %event.event_id, "events catch-up could not materialize a canonical event envelope");
                    let frame = json!({"kind": "resync_required"});
                    yield Ok(ndjson_line(&frame));
                    return;
                };
                let cursor = sync_token_for_events_query(
                    &state,
                    session_for_stream.as_ref(),
                    &filter_digest_for_stream,
                    &event.event_id,
                )
                .await;
                replay_cursor = Some(cursor.clone());
                let Some(frame) = events_event_frame(&event.realm_id, &cursor, &event_envelope) else {
                    yield Ok(ndjson_line(&json!({"kind": "resync_required"})));
                    return;
                };
                yield Ok(ndjson_line(&frame));
            }
            if has_more {
                let frame = json!({"kind": "resync_required"});
                yield Ok(ndjson_line(&frame));
                return;
            }
        }

        // 2. An empty bounded catch-up still needs an explicit baseline so
        // clients can distinguish "caught up, no delta" from a truncated
        // response. Reuse the validated resume cursor: `frontier` is
        // projection-neutral but establishes the baseline required before
        // `catchup_complete`.
        if catchup && replay_cursor.is_none()
            && let Some(cursor) = after_token.as_ref()
        {
            let frontier = json!({
                "kind": "frontier",
                "cursor": cursor,
            });
            yield Ok(ndjson_line(&frontier));
            replay_cursor = Some(cursor.clone());
        }

        // Completion follows either replay data or the empty-replay frontier.
        if let Some(cursor) = replay_cursor.as_ref() {
            let catchup_complete = json!({
                "kind": "catchup_complete",
                "cursor": cursor,
            });
            yield Ok(ndjson_line(&catchup_complete));
        }

        let mut active_realms = realm_filter.clone();

        // 3. Live loop: tokio::select on broadcast recv + heartbeat tick + deadline.
        let mut heartbeat = tokio::time::interval(Duration::from_millis(heartbeat_ms));
        // Skip first immediate tick — interval fires once at construction.
        heartbeat.tick().await;
        loop {
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(stream_deadline) => {
                    // Final heartbeat then close.
                    let close_frame = json!({"kind": "heartbeat"});
                    yield Ok(ndjson_line(&close_frame));
                    break;
                }
                recv = rx.recv() => {
                    match recv {
                        Ok(notification) => {
                            if !active_realms.contains(&notification.realm_id) {
                                continue;
                            }
                            let realm_id = notification.realm_id.clone();
                            // Dispatch on notification.kind to
                            // produce the right NDJSON frame shape.
                            use crate::state::EventNotificationKind;
                            let mut terminal = false;
                            let frame = match notification.kind {
                                EventNotificationKind::Event { cursor, event_payload } => {
                                    if replayed_event_ids.contains(&cursor) {
                                        continue;
                                    }
                                    if !projection_event_value_visible_to_session(
                                        &state,
                                        &event_payload,
                                        session_for_stream.as_ref(),
                                    ).await {
                                        continue;
                                    }
                                    // The broadcast carries the raw `event_id`;
                                    // mint the opaque `ak:cursor:` resume token
                                    // the typed frame requires.
                                    let live_cursor = sync_token_for_events_query(
                                        &state,
                                        session_for_stream.as_ref(),
                                        &filter_digest_for_stream,
                                        &cursor,
                                    ).await;
                                    let Some(event_envelope) = full_event_from_projection_json(
                                        &state,
                                        &event_payload,
                                    ).await else {
                                        tracing::warn!(event_id = %cursor, "live event could not materialize a canonical event envelope");
                                        active_realms.remove(&realm_id);
                                        terminal = active_realms.is_empty();
                                        let frame = json!({
                                            "kind": "resync_required",
                                            "realm_id": realm_id,
                                        });
                                        yield Ok(ndjson_line(&frame));
                                        if terminal {
                                            break;
                                        }
                                        continue;
                                    };
                                    let Some(frame) = events_event_frame(&realm_id, &live_cursor, &event_envelope) else {
                                        continue;
                                    };
                                    serde_json::to_value(frame).unwrap_or_else(|_| json!({"kind": "resync_required"}))
                                }
                                EventNotificationKind::EpochRotation { previous_epoch: _, new_epoch } => {
                                    serde_json::to_value(events_epoch_rotation_frame(&realm_id, new_epoch))
                                        .unwrap_or_else(|_| json!({"kind": "resync_required"}))
                                }
                                EventNotificationKind::Frontier { .. } => continue,
                                EventNotificationKind::ResyncRequired { .. } => {
                                    active_realms.remove(&realm_id);
                                    terminal = active_realms.is_empty();
                                    json!({
                                        "kind": "resync_required",
                                        "realm_id": realm_id,
                                    })
                                }
                                EventNotificationKind::Unauthorized { reason: _ } => {
                                    active_realms.remove(&realm_id);
                                    terminal = active_realms.is_empty();
                                    json!({
                                        "kind": "unauthorized",
                                        "realm_id": realm_id,
                                    })
                                }
                                // A Signal is not a durable Event: this stream
                                // must never surface one.
                                EventNotificationKind::Signal { .. } => {
                                    continue;
                                }
                                EventNotificationKind::Account { .. } => continue,
                            };
                            yield Ok(ndjson_line(&frame));
                            if terminal {
                                break;
                            }
                        }
                        Err(RecvError::Lagged(_)) => {
                            // Round 4 (B1.5) — broadcast capacity exceeded.
                            // The typed EventsSubscribeFrame requires a
                            // resume cursor on Dropped; if we don't have a
                            // valid cursor, the SDK rule downgrades to
                            // ResyncRequired instead of emitting cursorless Dropped.
                            arm_subscribe_reconnect(
                                &state,
                                &subscribe_scope_key_for_stream,
                                SUBSCRIBE_RECONNECT_AFTER_MS,
                            );
                            let body_json = json!({
                                "kind": "resync_required",
                                "reconnect_after_ms": SUBSCRIBE_RECONNECT_AFTER_MS,
                            });
                            yield Ok(ndjson_line(&body_json));
                            break;
                        }
                        Err(RecvError::Closed) => {
                            // Server shutdown / channel dropped.
                            break;
                        }
                    }
                }
                _ = heartbeat.tick() => {
                    let frame = json!({"kind": "heartbeat"});
                    yield Ok(ndjson_line(&frame));
                }
            }
        }
    };

    let _ = res.add_header("content-type", "application/x-ndjson", true);
    res.stream(body_stream.boxed());
}

fn events_event_frame(
    realm_id: &str,
    cursor: &str,
    event: &arkret_wire::Event,
) -> Option<EventsSubscribeFrame> {
    Some(EventsSubscribeFrame::Event {
        realm_id: RealmId::new(realm_id.to_owned()).ok()?,
        cursor: Cursor::new(cursor.to_owned()).ok()?,
        payload: Box::new(event.clone()),
    })
}

fn events_epoch_rotation_frame(realm_id: &str, new_epoch: Value) -> EventsSubscribeFrame {
    EventsSubscribeFrame::EpochRotation {
        realm_id: RealmId::new(realm_id.to_owned()).expect("stored realm id is validated"),
        payload: arkret_models_collaboration::http_bodies::EpochRotationPayload {
            new_epoch: u32::try_from(new_epoch.as_u64().expect("stored epoch is unsigned"))
                .expect("stored epoch fits u32"),
        },
    }
}

/// Serialize a JSON frame to a length-prefixed
/// NDJSON line. Each line ends with `\n` per the NDJSON / JSON-Lines
/// convention so streaming clients can split-on-newline incrementally
/// without parsing the whole buffer.
pub(crate) fn ndjson_line(value: &impl serde::Serialize) -> Bytes {
    let mut s = serde_json::to_string(value).unwrap_or_else(|_| "{}".to_owned());
    s.push('\n');
    Bytes::from(s)
}

pub(crate) fn subscribe_subject(req: &Request, session: Option<&SessionIdentityState>) -> String {
    match session {
        Some(session) => format!("session:{}:{}", session.actor, session.device_id),
        None => format!("remote:{}", req.remote_addr()),
    }
}

/// Scope `filter_digest` the realm subscribe stream binds its cursors to.
///
/// Resume cursors minted by `sync_token_for_events_query` are bound to this
/// digest, and `parse_and_validate_events_query_cursor` rejects a token whose
/// digest does not match — so a cursor issued for one realm-set cannot be
/// replayed against another (`cursor_integrity_invalid`). Distinct from the
/// account stream's filter (different `operation_id`), keeping the two streams'
/// cursors non-interchangeable per `encoding.md` §8.3.1.
pub(crate) fn events_subscribe_filter_digest(accessible_realms: &[String]) -> String {
    let realms = accessible_realms
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    sync_filter_digest(Some(&json!({
        "operation_id": arkret_wire::ServiceOperationId::SELF_EVENTS_STREAM_SUBSCRIBE_V1,
        "realms": realms,
    })))
}

fn events_subscribe_scope_key(
    req: &Request,
    session: Option<&SessionIdentityState>,
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
        "ak.self.events.stream.subscribe.v1|{}|realms={realms}",
        subscribe_subject(req, session)
    )
}

pub(crate) fn reject_subscribe_reconnect(
    state: &AppState,
    subscribe_scope_key: &str,
    res: &mut Response,
) -> bool {
    let retry_after_ms = state
        .sync()
        .subscribe_retry_after_ms(subscribe_scope_key, Utc::now());
    if let Some(retry_after_ms) = retry_after_ms {
        render_subscribe_rate_limited(res, retry_after_ms);
        return true;
    }
    false
}

pub(crate) fn arm_subscribe_reconnect(
    state: &AppState,
    subscribe_scope_key: &str,
    reconnect_after_ms: u64,
) {
    state.sync().arm_subscribe_reconnect(
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
    crate::error::render_problem_envelope(
        res,
        StatusCode::TOO_MANY_REQUESTS,
        arkret_wire::problem_details::ErrorEnvelope::new(
            "rate_limited",
            "Subscribe reconnect window is still active.",
        )
        .with_request_id(ids::generate_request_id())
        .with_retry_after_ms(Some(retry_after_ms)),
    );
}

#[derive(Clone, Debug)]
struct EventsQueryParts {
    realms: Vec<String>,
    actors: Vec<String>,
    after: Option<String>,
    before: Option<String>,
    order: String,
    limit: usize,
    filters: Option<Value>,
    include_completeness: bool,
}

fn validate_events_query_order(order: &str) -> Result<(), soland_http::error::AppError> {
    match order {
        "default" | "ascending" | "descending" => Ok(()),
        _ => Err(soland_http::error::AppError::param_invalid(
            "order must be default, ascending, or descending",
        )),
    }
}

fn reject_events_query_filter_digest_pseudo_fields(
    filters: Option<&Value>,
) -> Result<(), soland_http::error::AppError> {
    if filters.is_some_and(value_contains_filter_digest_pseudo_field) {
        return Err(soland_http::error::AppError::param_invalid(
            "filters must not contain cursor filter_digest fields",
        ));
    }
    Ok(())
}

fn value_contains_filter_digest_pseudo_field(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            object.contains_key("_filter_digest")
                || object.contains_key("filter_digest")
                || object
                    .values()
                    .any(value_contains_filter_digest_pseudo_field)
        }
        Value::Array(values) => values.iter().any(value_contains_filter_digest_pseudo_field),
        _ => false,
    }
}

fn events_query_scope_digest(
    realms: &[String],
    actors: &[String],
    filters: Option<&Value>,
    order: &str,
) -> String {
    let realms = realms
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let actors = actors
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let binding = json!({
        "operation_id": arkret_wire::ServiceOperationId::SELF_EVENTS_READ_SCAN_V1,
        "realms": realms,
        "actors": actors,
        "filters": filters.cloned().unwrap_or_else(|| json!({})),
        "order": order,
    });
    sync_filter_digest(Some(&binding))
}

fn events_query_cursor_error(error: SyncCursorError) -> soland_http::error::AppError {
    match error {
        SyncCursorError::Expired => soland_http::error::AppError::new(
            soland_http::error::ErrorCode::CursorExpired,
            "cursor has expired",
        ),
        // encoding.md §8.3 closed set: syntax/schema failures pin the top-level
        // `param_invalid` code with reason `invalid_cursor`.
        SyncCursorError::Invalid(message) => soland_http::error::AppError::param_invalid(message)
            .with_reason_code(arkret_wire::ReasonCode::INVALID_CURSOR),
        SyncCursorError::Mismatch(message) | SyncCursorError::Integrity(message) => {
            soland_http::error::AppError::new(
                soland_http::error::ErrorCode::CursorIntegrityInvalid,
                message,
            )
        }
        SyncCursorError::Revoked => soland_http::error::AppError::new(
            soland_http::error::ErrorCode::CursorRevoked,
            "cursor authority has been revoked",
        ),
    }
}

async fn events_query_cursor_target(
    state: &AppState,
    session: Option<&SessionIdentityState>,
    filter_digest: &str,
    cursor: Option<&str>,
) -> Result<Option<String>, soland_http::error::AppError> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    parse_and_validate_events_query_cursor(
        cursor,
        state,
        session,
        filter_digest,
        chrono::Utc::now().timestamp_millis(),
    )
    .await
    .map(|cursor| Some(cursor.event_id))
    .map_err(events_query_cursor_error)
}

fn events_query_direction(parts: &EventsQueryParts) -> bool {
    parts.order == "descending"
        || (parts.order == "default" && (parts.before.is_some() || parts.after.is_none()))
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

#[endpoint(operation_id = "ak.self.events.read.scan")]
#[tracing::instrument(skip_all, fields(op = "ak.self.events.read.scan.v1"))]
pub(crate) async fn events_read_body(
    body: salvo::oapi::extract::JsonBody<EventsQueryPostRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> soland_http::result::JsonResult<EventsQueryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    let parts = EventsQueryParts {
        realms: body
            .realm_ids
            .into_iter()
            .map(|realm| realm.into_string())
            .collect(),
        actors: body
            .actor_ids
            .into_iter()
            .map(|actor| actor.to_string())
            .collect(),
        after: body.after.map(|cursor| cursor.into_string()),
        before: body.before.map(|cursor| cursor.into_string()),
        order: body.order.unwrap_or_else(|| "default".to_owned()),
        limit: body
            .limit
            .map(|limit| limit as usize)
            .unwrap_or(100)
            .clamp(1, 100),
        filters: body
            .filters
            .map(|filters| Value::Object(filters.into_iter().collect())),
        include_completeness: body.include_completeness.unwrap_or(false),
    };
    events_query_impl(state, req, parts).await
}

async fn events_query_impl(
    state: &AppState,
    req: &Request,
    parts: EventsQueryParts,
) -> soland_http::result::JsonResult<EventsQueryOutcome> {
    validate_events_query_order(&parts.order)?;
    reject_events_query_filter_digest_pseudo_fields(parts.filters.as_ref())?;
    if parts.realms.is_empty() && parts.actors.is_empty() {
        return Err(soland_http::error::AppError::param_missing(
            "events.read requires at least one of realms[] / actors[]",
        ));
    }
    let realms = normalize_scope_selectors(parts.realms.clone())?;
    for actor in &parts.actors {
        if arkret_wire::DidCoreId::new(actor.clone()).is_err() {
            return Err(soland_http::error::AppError::param_invalid(format!(
                "invalid actor: {actor}"
            )));
        }
    }
    let session = if realms.is_empty() {
        Some(
            authenticated_session(state, req)
                .await
                .map_err(|(status, code, message)| {
                    soland_http::error::AppError::param_invalid(message)
                        .with_status(status)
                        .with_wire_code(code)
                })?,
        )
    } else {
        // Anonymous scan is allowed (public realms), but a presented-yet-invalid
        // bearer must surface its 401 rather than degrade to anonymous — see
        // `subscribe_session_or_render` for the cursor-masking rationale.
        match authenticated_session(state, req).await {
            Ok(session) => Some(session),
            Err((status, code, message)) => {
                if request_presents_auth_material(req) {
                    return Err(soland_http::error::AppError::param_invalid(message)
                        .with_status(status)
                        .with_wire_code(code));
                }
                None
            }
        }
    };
    if let Some(session) = session.as_ref() {
        super::super::require_agent_session_scope(
            session,
            arkret_wire::ServiceOperationId::SELF_EVENTS_READ_SCAN_V1,
        )?;
    }
    let filter_digest =
        events_query_scope_digest(&realms, &parts.actors, parts.filters.as_ref(), &parts.order);
    let (cursor_token, stop_cursor_token, backward) = events_query_cursor_and_stop(&parts);
    let cursor = events_query_cursor_target(
        state,
        session.as_ref(),
        &filter_digest,
        cursor_token.as_deref(),
    )
    .await?;
    let stop_cursor = events_query_cursor_target(
        state,
        session.as_ref(),
        &filter_digest,
        stop_cursor_token.as_deref(),
    )
    .await?;
    // Dispatch: if no Realms (actor-scoped query), forward to the durable
    // Event-store reader in routing/events.rs which builds an actor-keyed
    // `frontier.actors` map. The projection-aware path below is Realm-keyed.
    if realms.is_empty() {
        let response = durable_events_query_from_parts(
            state,
            session.as_ref().expect("actor query requires session"),
            &parts,
            cursor.as_deref(),
            stop_cursor.as_deref(),
            backward,
            &filter_digest,
            cursor_token.clone(),
        )
        .await?;
        return soland_http::result::json_ok(response);
    }
    let range_completeness =
        range_completeness_for_query(state, session.as_ref(), &parts, &realms).await?;
    let mut accessible_realms: Vec<String> = Vec::with_capacity(realms.len());
    let mut managed_agent_control_realms: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    for realm in realms {
        if let Some(session) = session.as_ref()
            && crate::routing::identity::managed_agent_pcr::controller_manages_agent_pcr(
                state,
                &session.actor,
                &realm,
            )
            .await?
        {
            managed_agent_control_realms.insert(realm.clone());
            accessible_realms.push(realm);
            continue;
        }
        if realm_id_accessible(state, &realm, session.as_ref()).await {
            accessible_realms.push(realm);
            continue;
        }
    }
    if accessible_realms.is_empty() {
        return Err(soland_http::error::AppError::not_found("not found"));
    }
    let limit = parts.limit;

    // Single-Realm fast path: paginate + apply visibility over the projection
    // store, then enrich the final page to typed EventReadRow values. Ordinary
    // rows carry their complete canonical Event; redacted slots carry only the
    // closed projection view and its durable digest commitment.
    if accessible_realms.len() == 1 {
        let realm_id = &accessible_realms[0];
        let managed_agent_control = managed_agent_control_realms.contains(realm_id);
        let realm_ids = std::collections::BTreeSet::from([realm_id.clone()]);
        match projected_event_page_for_realms_in_direction(
            state,
            &realm_ids,
            cursor.as_deref(),
            limit,
            backward,
        )
        .await
        {
            Ok(Some(page)) => {
                let mut events: Vec<Value> = Vec::new();
                let mut last_visible_event_id = None;
                for event in &page.items {
                    if events_query_event_visible(
                        state,
                        event,
                        session.as_ref(),
                        managed_agent_control,
                    )
                    .await
                    {
                        last_visible_event_id = Some(event.event_id.clone());
                        events.push(projection_event_json(event));
                    }
                }
                let events = truncate_before_stop_cursor(events, stop_cursor.as_deref());
                let first_visible_event_id =
                    events.first().and_then(|event| event["event_id"].as_str());
                let directional_continuation = page
                    .next_cursor
                    .as_deref()
                    .or(last_visible_event_id.as_deref());
                let older_event_id = backward.then_some(page.next_cursor.as_deref()).flatten();
                let newer_event_id = if backward {
                    first_visible_event_id
                } else {
                    directional_continuation
                };
                let prev_cursor = match older_event_id {
                    Some(event_id) => Some(
                        sync_token_for_events_query(
                            state,
                            session.as_ref(),
                            &filter_digest,
                            event_id,
                        )
                        .await,
                    ),
                    None => None,
                };
                let next_cursor = match newer_event_id {
                    Some(event_id) => Some(
                        sync_token_for_events_query(
                            state,
                            session.as_ref(),
                            &filter_digest,
                            event_id,
                        )
                        .await,
                    ),
                    None => None,
                };
                let events = full_events_from_projection_json(state, &events).await?;
                return soland_http::result::json_ok(EventsQueryOutcome {
                    events,
                    snapshot_bootstrap: None,
                    prev_cursor: if backward {
                        prev_cursor
                    } else {
                        cursor_token.clone()
                    },
                    next_cursor,
                    has_more: if backward {
                        page.has_more
                    } else {
                        cursor_token.is_some()
                    },
                    range_completeness: range_completeness.clone(),
                });
            }
            Ok(None) => {}
            Err(error) => {
                if error.to_string().contains("invalid_cursor") {
                    return Err(
                        soland_http::error::AppError::param_invalid("cursor not found")
                            .with_wire_code("invalid_cursor"),
                    );
                }
                return Err(soland_http::error::AppError::internal(error.to_string()));
            }
        }
        return soland_http::result::json_ok(EventsQueryOutcome {
            events: Vec::new(),
            snapshot_bootstrap: None,
            prev_cursor: cursor_token.clone(),
            next_cursor: None,
            has_more: false,
            range_completeness,
        });
    }

    // The cursor names one position in the globally ordered union. Splitting
    // this read per Realm would make that cursor absent from every other Realm.
    let realm_ids = accessible_realms.iter().cloned().collect();
    let page = projected_event_page_for_realms_in_direction(
        state,
        &realm_ids,
        cursor.as_deref(),
        limit,
        backward,
    )
    .await
    .map_err(|error| {
        if error.to_string().contains("invalid_cursor") {
            soland_http::error::AppError::param_invalid("cursor not found")
                .with_wire_code("invalid_cursor")
        } else {
            soland_http::error::AppError::internal(error.to_string())
        }
    })?;
    let Some(page) = page else {
        return soland_http::result::json_ok(EventsQueryOutcome {
            events: Vec::new(),
            snapshot_bootstrap: None,
            prev_cursor: cursor_token,
            next_cursor: None,
            has_more: false,
            range_completeness,
        });
    };
    let mut page_events = Vec::new();
    for event in &page.items {
        let managed_agent_control = managed_agent_control_realms.contains(&event.realm_id);
        if events_query_event_visible(state, event, session.as_ref(), managed_agent_control).await {
            page_events.push(projection_event_json(event));
        }
    }
    let page_events = truncate_before_stop_cursor(page_events, stop_cursor.as_deref());
    let directional_continuation = page.next_cursor.as_deref().or_else(|| {
        page_events
            .last()
            .and_then(|event| event["event_id"].as_str())
    });
    let first_visible_event_id = page_events
        .first()
        .and_then(|event| event["event_id"].as_str());
    let older_event_id = backward.then_some(page.next_cursor.as_deref()).flatten();
    let newer_event_id = if backward {
        first_visible_event_id
    } else {
        directional_continuation
    };
    let prev_cursor = match older_event_id {
        Some(event_id) => Some(
            sync_token_for_events_query(state, session.as_ref(), &filter_digest, event_id).await,
        ),
        None => None,
    };
    let next_cursor = match newer_event_id {
        Some(event_id) => Some(
            sync_token_for_events_query(state, session.as_ref(), &filter_digest, event_id).await,
        ),
        None => None,
    };
    let events = full_events_from_projection_json(state, &page_events).await?;
    soland_http::result::json_ok(EventsQueryOutcome {
        events,
        snapshot_bootstrap: None,
        prev_cursor: if backward {
            prev_cursor
        } else {
            cursor_token.clone()
        },
        next_cursor,
        has_more: if backward {
            page.has_more
        } else {
            cursor_token.is_some()
        },
        range_completeness,
    })
}

async fn range_completeness_for_query(
    state: &AppState,
    session: Option<&SessionIdentityState>,
    parts: &EventsQueryParts,
    realms: &[String],
) -> Result<
    Option<arkret_models_collaboration::http_bodies::EventsRangeCompleteness>,
    soland_http::error::AppError,
> {
    use arkret_models_collaboration::sync_frames::snapshot::{
        RangeCompletenessAttestation, RangeCompletenessAttestationEventRange,
        RangeCompletenessAttestationEventRangeFromFrontier,
        RangeCompletenessAttestationEventRangeToFrontier,
        RangeCompletenessAttestationWitnessAttestation,
        RangeCompletenessAttestationWitnessAttestationWitnessesItem,
    };
    use arkret_signatures::{Ed25519PayloadSigner, SignEventOptions, sign_event};
    use arkret_wire::{Hash, PayloadProofPurpose, PayloadSigner, proof_kind};

    if !parts.include_completeness
        || realms.len() != 1
        || !parts.actors.is_empty()
        || parts.filters.is_some()
    {
        return Ok(None);
    }
    let Some(session) = session else {
        return Ok(None);
    };
    let realm_id = RealmId::new(realms[0].clone())
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    let actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)?;
    if !state
        .projections()
        .snapshot()
        .realm_is_principal_control_for_actor(realm_id.as_str(), &actor.to_string())
    {
        return Ok(None);
    }

    let records = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    let mut accepted_events = records
        .iter()
        .filter(|record| record.realm_id.as_deref() == Some(realm_id.as_str()))
        .map(|record| super::super::event_log::sdk_event_for_state(state, record))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    accepted_events.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| left.event_id.as_str().cmp(right.event_id.as_str()))
    });
    if accepted_events.len() < 2 {
        return Ok(None);
    }
    let (from_frontier, to_frontier) =
        arkret_state::full_realm_range_frontiers(&accepted_events)
            .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    let range_events = arkret_state::full_realm_range_events(&accepted_events)
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    let actor_seq_ranges = arkret_state::range_completeness_actor_seq_ranges(&range_events)
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    if actor_seq_ranges.is_empty() {
        return Ok(None);
    }
    let digest_suite = state.projections().realm_digest_suite(realm_id.as_str());
    let (root, covered_event_ids) =
        arkret_state::range_completeness_root_with_suite(&range_events, digest_suite)
            .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;

    let issuer = state.service_resolution_commitment().did.clone();
    let issuer_actor = arkret_wire::project_did_to_core_id(&issuer)
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    let verification_method =
        arkret_wire::DidUrl::new(format!("{issuer}#notary-key")).map_err(|error| {
            soland_http::error::AppError::internal(format!(
                "service notary verification method is invalid: {error}"
            ))
        })?;
    let observed_at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    // The attestation is a service-signed object, not an Event: it gets its own
    // minted id rather than one retyped from a fabricated `ak:event:` value.
    let attestation_id = ids::generate("attestation");
    let signer = Ed25519PayloadSigner::new(
        state.notary_signing_key().as_ref().clone(),
        issuer.clone(),
        verification_method.clone(),
    );
    let mut payload = RangeCompletenessAttestation {
        attestation_id,
        schema: arkret_wire::SchemaId::RANGE_COMPLETENESS_ATTESTATION_V1.to_owned(),
        issuer_id: issuer_actor.clone(),
        issuer_role: "events_api".to_owned(),
        realm_id: realm_id.clone(),
        event_range: RangeCompletenessAttestationEventRange {
            from_frontier: RangeCompletenessAttestationEventRangeFromFrontier {
                realm_frontier: from_frontier,
                extra: BTreeMap::new(),
            },
            to_frontier: RangeCompletenessAttestationEventRangeToFrontier {
                realm_frontier: to_frontier.clone(),
                extra: BTreeMap::new(),
            },
            actor_seq_ranges,
        },
        root,
        count: covered_event_ids.len() as u64,
        observed_at,
        witness_attestation: RangeCompletenessAttestationWitnessAttestation {
            witnesses: vec![
                RangeCompletenessAttestationWitnessAttestationWitnessesItem {
                    witness_id: issuer_actor.clone(),
                    verification_method: verification_method.clone(),
                    controlling_organization_id: issuer_actor.clone(),
                    attested_at: Some(observed_at),
                    extra: BTreeMap::new(),
                },
            ],
        },
        proofs: Vec::new(),
    };
    let mut unsigned_payload = serde_json::to_value(&payload)
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    unsigned_payload
        .as_object_mut()
        .expect("typed completeness payload serializes as an object")
        .remove("proofs");
    let canonical_payload = arkret_canonical::canonical_json_bytes(&unsigned_payload)
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    let unsigned_proof = arkret_wire::UnsignedPayloadProof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        verification_method: verification_method.clone(),
        payload_digest: Hash::new(arkret_canonical::canonical::sha256_digest(
            &canonical_payload,
        ))
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?,
        created_at: observed_at,
        domain: None,
        audience: None,
        proof_purpose: Some(PayloadProofPurpose::IssuerAttestation),
    };
    let proof_binding = payload
        .proof_signing_bytes(&unsigned_proof)
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    let signature = signer
        .sign_payload(&proof_binding)
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    let payload_proof = unsigned_proof
        .finalize(signature.jws)
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    payload.proofs.push(payload_proof);

    let actor_seq = accepted_events
        .iter()
        .filter(|event| event.actor_id == arkret_wire::ActorId::service(issuer_actor.clone()))
        .map(|event| event.actor_seq)
        .max()
        .map_or(0, |sequence| sequence.saturating_add(1));
    let attestation_hlc = arkret_identifiers::Hlc::new(state.hlc().now())
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    let mut attestation_event = arkret_event_draft::TypedEventDraft::<
        arkret_wire::event_spec::AttestationRangeCompleteness,
    >::new(
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        arkret_wire::ActorId::service(issuer_actor.clone()),
        payload,
    )
    .map(|draft| draft.with_prev_refs(to_frontier))
    .and_then(|draft| {
        draft.author_with_digest_suite(actor_seq, attestation_hlc, observed_at, digest_suite)
    })
    .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    let event_id = attestation_event.event_id().clone();
    sign_event(
        &mut attestation_event,
        &signer,
        &verification_method,
        SignEventOptions::new().with_created_at(observed_at),
    )
    .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    Ok(Some(
        arkret_models_collaboration::http_bodies::EventsRangeCompleteness {
            attestation_refs: vec![event_id],
            attestations: vec![attestation_event.into_event()],
        },
    ))
}

/// Per-event visibility for `events.read`. Organization Recovery holders use
/// the dedicated archive surface and never gain timeline scan authority here.
async fn events_query_event_visible(
    state: &AppState,
    event: &soland_services::events::ProjectedEvent,
    session: Option<&soland_services::identity::SessionIdentityState>,
    managed_agent_control: bool,
) -> bool {
    if managed_agent_control {
        return true;
    }
    projection_record_visible_to_session(state, event, session).await
}

/// Enrich visible projection rows to the spec's closed `EventReadRow` union.
/// Canonical rows return the complete signed Event. Redacted Message rows keep
/// their timeline slot as a `RedactedEventView`, binding the durable Event id
/// and digest without mutating or masquerading as the signed Event envelope.
/// Visibility and pagination are already applied to `projection_rows` by the
/// caller. Every selected projection row must resolve to its canonical Event;
/// returning a shorter successful page would hide an accepted Event while the
/// cursor advances past it.
async fn full_events_from_projection_json(
    state: &AppState,
    projection_rows: &[Value],
) -> Result<Vec<arkret_models_collaboration::http_bodies::EventReadRow>, soland_http::error::AppError>
{
    let mut events = Vec::with_capacity(projection_rows.len());
    for row in projection_rows {
        events.push(event_read_row_from_projection_json(state, row).await?);
    }
    Ok(events)
}

async fn event_read_row_from_projection_json(
    state: &AppState,
    row: &Value,
) -> Result<arkret_models_collaboration::http_bodies::EventReadRow, soland_http::error::AppError> {
    use arkret_models_collaboration::http_bodies::{
        EventReadRow, EventRedactionReason, HiddenEventField, HiddenEventFields, RedactedEventView,
        RedactedEventViewKind, ReducerInputFalse,
    };

    let event_id = row.get("event_id").and_then(Value::as_str).ok_or_else(|| {
        soland_http::error::AppError::internal(
            "projected Event row is missing its canonical event_id",
        )
    })?;
    let record = state
        .event_queries()
        .canonical_event(event_id)
        .await
        .map_err(|error| {
            soland_http::error::AppError::internal(format!(
                "canonical Event lookup failed for projected row {event_id}: {error}"
            ))
        })?
        .ok_or_else(|| {
            soland_http::error::AppError::internal(format!(
                "projected Event row {event_id} has no canonical Event record"
            ))
        })?;
    let event = super::super::event_log::sdk_event_for_state(state, &record).map_err(|error| {
        soland_http::error::AppError::internal(format!(
            "canonical Event materialization failed for projected row {event_id}: {error}"
        ))
    })?;
    if !projection_row_is_redacted_message_tombstone(row) {
        return Ok(event.into());
    }
    let hidden_fields = HiddenEventFields::new(
        ["payload", "proofs", "unsigned"]
            .into_iter()
            .map(|field| HiddenEventField::new(field).expect("static hidden Event field"))
            .collect(),
    )
    .expect("static hidden Event fields are unique");
    Ok(EventReadRow::Redacted(RedactedEventView {
        view_kind: RedactedEventViewKind::RedactedEventView,
        event_id: event.event_id,
        kind: event.kind,
        realm_id: event.realm_id,
        created_at: Some(event.created_at),
        payload_digest: None,
        redaction_reason: EventRedactionReason::Redacted,
        hidden_fields,
        inclusion_proof: None,
        reducer_input: ReducerInputFalse,
    }))
}

/// Materialize the full Event envelope required by an `event` subscribe
/// frame. Projection rows are useful for visibility filtering and pagination,
/// but are not wire Event envelopes (`event_kind` vs `kind`, no actor_seq,
/// prev_refs, proofs, ...). A redacted projection has no valid full Event
/// representation, so it is omitted from this Event-only stream rather than
/// mutating its canonical payload while retaining stale proofs and Event id.
pub(crate) async fn full_event_from_projection_json(
    state: &AppState,
    row: &Value,
) -> Option<arkret_wire::Event> {
    if projection_row_is_redacted_message_tombstone(row) {
        return None;
    }
    let event_id = row.get("event_id").and_then(Value::as_str)?;
    if let Ok(Some(record)) = state.event_queries().canonical_event(event_id).await
        && let Ok(event) = super::super::event_log::sdk_event_for_state(state, &record)
    {
        return Some(event);
    }
    None
}

fn projection_row_is_redacted_message_tombstone(row: &Value) -> bool {
    row.get("event_kind")
        .and_then(Value::as_str)
        .is_some_and(|kind| {
            matches!(
                kind,
                arkret_wire::event_kind_str::MESSAGE_CREATE
                    | arkret_wire::event_kind_str::MESSAGE_REVISE
            )
        })
        && row.get("payload").is_some_and(|payload| {
            payload.get("redacted").and_then(Value::as_bool) == Some(true)
                || payload.get("state").and_then(Value::as_str) == Some("redacted")
        })
}

#[cfg(test)]
mod tests {
    use soland_services::events::AcceptedEvent;

    use super::*;

    const TEST_REALM: &str = "ak:realm:ATdMSXE70ijF1u9M9PvT4WFuWRgKpqVf-tiHDAD-_stf";
    const TEST_ACTOR: &str = "did:web:alice.example";
    const TEST_ACTOR_CORE: &str = "ak:did_core:web:alice.example";

    fn test_state() -> AppState {
        let mut config = crate::config::AppConfig::test_default();
        config.seed_demo_data = false;
        AppState::new(config, soland_storage_postgres::Db { pool: None })
    }

    #[test]
    fn events_query_default_direction_matches_boundary_contract() {
        let mut parts = EventsQueryParts {
            realms: vec![TEST_REALM.to_owned()],
            actors: Vec::new(),
            after: None,
            before: None,
            order: "default".to_owned(),
            limit: 100,
            filters: None,
            include_completeness: false,
        };
        assert!(events_query_direction(&parts));

        parts.after = Some("ak:cursor:newer".to_owned());
        assert!(!events_query_direction(&parts));

        parts.before = Some("ak:cursor:older".to_owned());
        assert!(events_query_direction(&parts));
    }

    #[tokio::test]
    async fn projection_enrichment_fails_when_canonical_event_is_missing() {
        let state = test_state();
        let error = full_events_from_projection_json(
            &state,
            &[json!({
                "event_id": "ak:event:AQsHmGu_9sPOyJ4aG8VlWQBp8wGGhdC-BjfAaXqrIbk-",
                "event_kind": arkret_wire::EventKind::MessageCreate.as_str(),
                "payload": {}
            })],
        )
        .await
        .expect_err("a projection row without its canonical Event must fail the page");

        assert_eq!(error.code, soland_http::error::ErrorCode::InternalError);
        assert!(error.message.contains("has no canonical Event record"));
    }

    async fn append_query_test_event(state: &AppState, realm_id: &str, second: u32) -> String {
        let canonical_bytes = format!("{{\"second\":{second}}}").into_bytes();
        let digest =
            arkret_canonical::digest_bytes(arkret_canonical::DigestSuite::Sha256, &canonical_bytes);
        let event_id =
            arkret_identifiers::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, digest)
                .to_string();
        let received_at =
            DateTime::parse_from_rfc3339(&format!("2026-08-26T01:00:{second:02}.000Z"))
                .unwrap()
                .with_timezone(&Utc);
        state
            .event_queries()
            .store_canonical_event(AcceptedEvent {
                event_id: event_id.clone(),
                actor_id: TEST_ACTOR_CORE.to_owned(),
                actor_seq: u64::from(second),
                realm_id: Some(realm_id.to_owned()),
                kind: arkret_wire::EventKind::MessageCreate.to_string(),
                schema_id: "ak.schema.event.v1".to_owned(),
                digest_suite: arkret_canonical::DigestSuite::Sha256,
                canonical_digest: arkret_canonical::digest(
                    arkret_canonical::DigestSuite::Sha256,
                    &canonical_bytes,
                ),
                canonical_bytes,
                envelope: json!({}),
                received_at,
            })
            .await
            .unwrap();
        crate::routing::events::projection::append_projection_event(
            state,
            soland_services::events::ProjectedEvent {
                event_id: event_id.clone(),
                realm_id: realm_id.to_owned(),
                event_kind: arkret_wire::EventKind::MessageCreate,
                operation_kind: "event".to_owned(),
                operation_id: None,
                sender: Some(TEST_ACTOR_CORE.to_owned()),
                payload: json!({}),
                created_at: received_at,
                received_at,
            },
        )
        .await
        .unwrap();
        event_id
    }

    #[tokio::test]
    async fn multi_realm_cursor_resumes_the_globally_ordered_union() {
        let state = test_state();
        let realms = BTreeSet::from(["realm-a".to_owned(), "realm-b".to_owned()]);
        let mut event_ids = Vec::new();
        for (realm, second) in [
            ("realm-a", 1),
            ("realm-b", 2),
            ("realm-a", 3),
            ("realm-b", 4),
        ] {
            event_ids.push(append_query_test_event(&state, realm, second).await);
        }

        let first = projected_event_page_for_realms_in_direction(&state, &realms, None, 2, false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            first
                .items
                .iter()
                .map(|event| event.event_id.as_str())
                .collect::<Vec<_>>(),
            [event_ids[0].as_str(), event_ids[1].as_str()]
        );
        let second = projected_event_page_for_realms_in_direction(
            &state,
            &realms,
            first.next_cursor.as_deref(),
            2,
            false,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            second
                .items
                .iter()
                .map(|event| event.event_id.as_str())
                .collect::<Vec<_>>(),
            [event_ids[2].as_str(), event_ids[3].as_str()]
        );
    }

    #[tokio::test]
    async fn before_cursor_reads_older_events_in_descending_order() {
        let state = test_state();
        let realms = BTreeSet::from(["realm-a".to_owned(), "realm-b".to_owned()]);
        let mut event_ids = Vec::new();
        for (realm, second) in [
            ("realm-a", 1),
            ("realm-b", 2),
            ("realm-a", 3),
            ("realm-b", 4),
        ] {
            event_ids.push(append_query_test_event(&state, realm, second).await);
        }

        let page = projected_event_page_for_realms_in_direction(
            &state,
            &realms,
            Some(event_ids[3].as_str()),
            2,
            true,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            page.items
                .iter()
                .map(|event| event.event_id.as_str())
                .collect::<Vec<_>>(),
            [event_ids[2].as_str(), event_ids[1].as_str()]
        );
        assert!(page.has_more);
        assert_eq!(page.next_cursor.as_deref(), Some(event_ids[1].as_str()));
    }

    #[test]
    fn events_subscribe_default_wait_is_30_seconds() {
        assert_eq!(EVENTS_SUBSCRIBE_DEFAULT_WAIT_MS, 30_000);
    }

    #[tokio::test]
    async fn sidecar_recovery_query_retains_the_complete_digestible_event_envelope() {
        let state = test_state();
        let created_at = DateTime::parse_from_rfc3339("2026-07-29T10:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc);
        let sidecar_id = "ak:sidecar:AQYqC06461HNyfIIzUY8eXmafXvmC9i29nNObXCIbj0-";
        let mut event = crate::test_event::raw_event_at(
            arkret_wire::EventKind::SidecarContextAttach.as_str(),
            arkret_wire::ScopeRef::Sidecar {
                realm_id: RealmId::new(TEST_REALM.to_owned()).unwrap(),
                sidecar_id: arkret_identifiers::SidecarId::new(sidecar_id.to_owned()).unwrap(),
            },
            crate::test_actor_id_str(TEST_ACTOR),
            41,
            arkret_identifiers::Hlc::new("01970e589d21-0041-a13f9c2e").unwrap(),
            json!({
                "sidecar_id": sidecar_id,
                "source_context_ref": {
                    "kind": "strand",
                    "strand_id": "ak:strand:AWc6STOZP9GTGlkpfVSYBsWGd0eNukyDV6phslEwPfMB"
                },
                "version": 1
            }),
            created_at,
        )
        .unwrap();
        crate::test_event::attach_fixture_producer_proof(
            &mut event,
            arkret_wire::DidUrl::new(format!("{TEST_ACTOR}#device-key")).unwrap(),
        );
        let expected_digest = event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        let event_envelope = serde_json::to_value(&event).unwrap();
        assert_eq!(event_envelope["scope_ref"]["kind"], json!("sidecar"));
        put_durable_event(
            &state,
            event.event_id.as_str(),
            arkret_wire::EventKind::SidecarContextAttach.as_str(),
            event_envelope,
            created_at,
        )
        .await;
        let stored = state
            .event_queries()
            .canonical_event(event.event_id.as_str())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.envelope["scope_ref"]["kind"], json!("sidecar"));
        let direct = crate::routing::events::event_log::sdk_event_for_state(&state, &stored)
            .expect("full envelope");
        assert_eq!(direct.scope_ref, event.scope_ref);
        let row = soland_services::events::ProjectedEvent {
            event_id: event.event_id.to_string(),
            realm_id: TEST_REALM.to_owned(),
            event_kind: arkret_wire::EventKind::SidecarContextAttach,
            operation_kind: "event".to_owned(),
            operation_id: Some("ak:operation:01904100-0000-7000-8000-00000000aa43".to_owned()),
            sender: Some(TEST_ACTOR.to_owned()),
            payload: serde_json::to_value(&event.payload).unwrap(),
            created_at,
            received_at: created_at,
        };
        let enriched = full_events_from_projection_json(&state, &[projection_event_json(&row)])
            .await
            .expect("projection row resolves to its canonical Event");
        assert_eq!(enriched.len(), 1);
        let enriched = enriched[0].event().expect("complete Event read row");
        assert_eq!(enriched.event_id, event.event_id);
        assert_eq!(enriched.scope_ref, event.scope_ref);
        assert_eq!(enriched.payload, event.payload);
        assert_eq!(
            enriched
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
            expected_digest
        );
    }

    #[tokio::test]
    async fn canonical_event_read_preserves_absent_hlc_and_digest() {
        let state = test_state();
        let created_at = DateTime::parse_from_rfc3339("2026-08-09T01:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut event = crate::test_event::raw_event_at(
            arkret_wire::EventKind::ContactRequested.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: RealmId::new(TEST_REALM.to_owned()).unwrap(),
            },
            crate::test_actor_id_str(TEST_ACTOR),
            2,
            arkret_identifiers::Hlc::new("019041000000-0000-a13f9c2e").unwrap(),
            json!({"contact_id": "ak:contact:no-hlc"}),
            created_at,
        )
        .unwrap();
        event.hlc = None;
        crate::test_event::attach_fixture_producer_proof(
            &mut event,
            arkret_wire::DidUrl::new(format!("{TEST_ACTOR}#device-key")).unwrap(),
        );
        event.event_id = event
            .derive_event_id_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        let expected_digest = event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        let envelope = serde_json::to_value(&event).unwrap();
        assert!(envelope.get("hlc").is_none());
        put_durable_event(
            &state,
            event.event_id.as_str(),
            arkret_wire::EventKind::ContactRequested.as_str(),
            envelope,
            created_at,
        )
        .await;

        let stored = state
            .event_queries()
            .canonical_event(event.event_id.as_str())
            .await
            .unwrap()
            .unwrap();
        let reconstructed =
            crate::routing::events::event_log::sdk_event_for_state(&state, &stored).unwrap();
        assert!(reconstructed.hlc.is_none());
        assert_eq!(
            reconstructed
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
            expected_digest
        );
        assert_eq!(
            reconstructed
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
            stored.canonical_digest
        );
    }

    fn operation_at(
        operation_id: &str,
        kind: impl AsRef<str>,
        payload: Value,
        created_at: DateTime<Utc>,
    ) -> arkret_event_draft::ProjectedEventOperation {
        let mut operation = arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(operation_id.to_owned()).unwrap(),
            RealmId::new(TEST_REALM.to_owned()).unwrap(),
            kind.as_ref(),
            payload,
        );
        operation.created_at = created_at;
        operation
    }

    async fn put_durable_event(
        state: &AppState,
        event_id: &str,
        kind: &str,
        envelope: Value,
        created_at: DateTime<Utc>,
    ) {
        let event: arkret_wire::Event =
            serde_json::from_value(envelope.clone()).expect("durable fixture is a typed Event");
        let canonical_bytes = crate::routing::events::event_log::event_canonical_bytes(&envelope)
            .expect("durable fixture has a canonical digest payload");
        let canonical_digest = event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .expect("durable fixture digest");
        let actor_id = envelope
            .get("actor_id")
            .and_then(Value::as_str)
            .unwrap_or(TEST_ACTOR)
            .to_owned();
        let actor_seq = envelope
            .get("actor_seq")
            .and_then(Value::as_u64)
            .unwrap_or(1);
        let realm_id = envelope
            .get("realm_id")
            .and_then(Value::as_str)
            .unwrap_or(TEST_REALM)
            .to_owned();
        state
            .event_queries()
            .store_canonical_event(AcceptedEvent {
                event_id: event_id.to_owned(),
                actor_id,
                actor_seq,
                realm_id: Some(realm_id),
                kind: kind.to_owned(),
                schema_id: "ak.schema.event.v1".to_owned(),
                digest_suite: arkret_canonical::DigestSuite::Sha256,
                canonical_digest,
                canonical_bytes,
                envelope,
                received_at: created_at,
            })
            .await
            .expect("durable event stored");
    }

    #[tokio::test]
    async fn events_query_returns_closed_redacted_views_without_canonical_plaintext() {
        let state = test_state();
        let created_at = DateTime::parse_from_rfc3339("2026-07-06T10:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc);
        let revised_at = created_at + chrono::Duration::seconds(30);
        let redacted_at = created_at + chrono::Duration::minutes(1);
        let strand_id = strand_id_from_realm_id(TEST_REALM).expect("canonical fixture RealmId");
        let realm_id = RealmId::new(TEST_REALM.to_owned()).unwrap();
        let actor_did = arkret_identifiers::Did::new(TEST_ACTOR.to_owned()).unwrap();
        let mut message_event = crate::test_event::raw_event_at(
            arkret_wire::EventKind::MessageCreate.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            crate::test_actor_id(&actor_did),
            1,
            arkret_identifiers::Hlc::new("019041000000-0000-00000000").unwrap(),
            json!({
                "strand_id": strand_id,
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "secret that must not leak"}
            }),
            created_at,
        )
        .unwrap();
        crate::test_event::attach_fixture_producer_proof(
            &mut message_event,
            arkret_wire::DidUrl::new(format!("{TEST_ACTOR}#device-key")).unwrap(),
        );
        let message_event_id = message_event.event_id.to_string();
        let message_id = arkret_identifiers::MessageId::from_event_id(&message_event.event_id);
        let mut revise_event = crate::test_event::raw_event_at(
            arkret_wire::EventKind::MessageRevise.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            crate::test_actor_id(&actor_did),
            2,
            arkret_identifiers::Hlc::new("019041000000-0001-00000000").unwrap(),
            json!({
                "message_id": message_id,
                "strand_id": strand_id,
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "revised secret that must not leak"}
            }),
            revised_at,
        )
        .unwrap();
        crate::test_event::attach_fixture_producer_proof(
            &mut revise_event,
            arkret_wire::DidUrl::new(format!("{TEST_ACTOR}#device-key")).unwrap(),
        );
        let revise_event_id = revise_event.event_id.to_string();
        let mut redaction_event = crate::test_event::raw_event_at(
            arkret_wire::EventKind::MessageRedact.as_str(),
            arkret_wire::ScopeRef::Realm { realm_id },
            crate::test_actor_id(&actor_did),
            3,
            arkret_identifiers::Hlc::new("019041000000-0002-00000000").unwrap(),
            json!({
                "message_id": message_id,
                "reason": "test redaction"
            }),
            redacted_at,
        )
        .unwrap();
        crate::test_event::attach_fixture_producer_proof(
            &mut redaction_event,
            arkret_wire::DidUrl::new(format!("{TEST_ACTOR}#device-key")).unwrap(),
        );
        let redaction_event_id = redaction_event.event_id.to_string();
        let plaintext_payload = json!({
            "event_id": message_event_id,
            "message_id": message_id,
            "realm_id": TEST_REALM,
            "strand_id": strand_id,
            "track_name": "discussion",
            "sender": TEST_ACTOR_CORE,
            "content": {"kind": "ak.content.text", "body": "secret that must not leak"}
        });
        let revised_payload = json!({
            "event_id": revise_event_id,
            "message_id": message_id,
            "realm_id": TEST_REALM,
            "strand_id": strand_id,
            "track_name": "discussion",
            "sender": TEST_ACTOR_CORE,
            "content": {"kind": "ak.content.text", "body": "revised secret that must not leak"}
        });
        let message = operation_at(
            "ak:operation:01904100-0000-7000-8000-00000000aa41",
            arkret_wire::EventKind::MessageCreate,
            plaintext_payload.clone(),
            created_at,
        );
        let revise = operation_at(
            "ak:operation:01904100-0000-7000-8000-00000000aa43",
            arkret_wire::EventKind::MessageRevise,
            revised_payload.clone(),
            revised_at,
        );
        let redaction = operation_at(
            "ak:operation:01904100-0000-7000-8000-00000000aa42",
            arkret_wire::EventKind::MessageRedact,
            json!({
                "event_id": redaction_event_id,
                "message_id": message_id,
                "reason": "test redaction",
                "sender": TEST_ACTOR_CORE
            }),
            redacted_at,
        );
        put_durable_event(
            &state,
            message_event_id.as_str(),
            arkret_wire::EventKind::MessageCreate.as_str(),
            serde_json::to_value(&message_event).unwrap(),
            created_at,
        )
        .await;
        put_durable_event(
            &state,
            revise_event_id.as_str(),
            arkret_wire::EventKind::MessageRevise.as_str(),
            serde_json::to_value(&revise_event).unwrap(),
            revised_at,
        )
        .await;
        put_durable_event(
            &state,
            redaction_event_id.as_str(),
            arkret_wire::EventKind::MessageRedact.as_str(),
            serde_json::to_value(&redaction_event).unwrap(),
            redacted_at,
        )
        .await;
        crate::routing::events::projection::project_accepted_operations(
            &state,
            TEST_ACTOR,
            &[message, revise, redaction],
        )
        .await;

        let page = projected_event_page_for_realms_in_direction(
            &state,
            &BTreeSet::from([TEST_REALM.to_owned()]),
            None,
            100,
            false,
        )
        .await
        .expect("projected page")
        .expect("projected events");
        let rows = page
            .items
            .iter()
            .map(projection_event_json)
            .collect::<Vec<_>>();
        let message_row = rows
            .iter()
            .find(|row| row["event_id"] == message_event_id)
            .expect("message row retained as tombstone");
        assert_eq!(message_row["payload"]["redacted"], json!(true));
        let revise_row = rows
            .iter()
            .find(|row| row["event_id"] == revise_event_id)
            .expect("revision row retained as tombstone");
        assert_eq!(revise_row["payload"]["redacted"], json!(true));

        let events = full_events_from_projection_json(&state, &rows)
            .await
            .expect("projection rows resolve to canonical Events");
        let redacted = events
            .iter()
            .filter_map(|row| match row {
                arkret_models_collaboration::http_bodies::EventReadRow::Redacted(view) => {
                    Some(view)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let message = redacted
            .iter()
            .find(|view| view.event_id.as_str() == message_event_id)
            .expect("message Event slot retained as a closed redacted view");
        assert_eq!(
            message.redaction_reason,
            arkret_models_collaboration::http_bodies::EventRedactionReason::Redacted
        );
        assert_eq!(
            message.event_digest().as_str(),
            message_event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap()
        );
        assert!(
            !serde_json::to_string(message)
                .unwrap()
                .contains("secret that must not leak")
        );
        let revise = redacted
            .iter()
            .find(|view| view.event_id.as_str() == revise_event_id)
            .expect("revision Event slot retained as a closed redacted view");
        assert!(
            !serde_json::to_string(revise)
                .unwrap()
                .contains("revised secret")
        );
        assert!(
            events
                .iter()
                .filter_map(|row| row.event())
                .all(|event| event.event_id.as_str() != redaction_event_id)
        );
    }
}

async fn durable_events_query_from_parts(
    state: &AppState,
    session: &SessionIdentityState,
    parts: &EventsQueryParts,
    cursor: Option<&str>,
    stop_cursor: Option<&str>,
    backward: bool,
    filter_digest: &str,
    cursor_token: Option<String>,
) -> Result<EventsQueryOutcome, soland_http::error::AppError> {
    let actors_set: BTreeSet<&str> = parts.actors.iter().map(String::as_str).collect();
    let realms_set: BTreeSet<&str> = parts.realms.iter().map(String::as_str).collect();
    let all_records = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| {
            soland_http::error::AppError::internal(format!("canonical Event scan failed: {error}"))
        })?;
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
        if !super::super::event_log::event_visible_to_session(state, &record, session).await {
            continue;
        }
        super::super::event_log::sdk_event_for_state(state, &record).map_err(|error| {
            soland_http::error::AppError::internal(format!(
                "canonical Event materialization failed for actor-scoped row {} ({}): {error}",
                record.event_id, record.kind
            ))
        })?;
        // Personal blocklists are encrypted actor-private presentation state.
        // They must not remove accepted Operations from the canonical query;
        // clients apply the holder's filter after sync.
        records.push(record);
    }
    records.sort_by(|left, right| {
        left.received_at
            .cmp(&right.received_at)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    if backward {
        records.reverse();
    }
    let start = cursor
        .and_then(|cursor| records.iter().position(|record| record.event_id == cursor))
        .map(|index| index + 1)
        .unwrap_or(0);
    let mut page = records
        .into_iter()
        .skip(start)
        .take(parts.limit + 1)
        .collect::<Vec<_>>();
    if let Some(stop_cursor) = stop_cursor
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
    let first_cursor = match page.first() {
        Some(record) => Some(
            sync_token_for_events_query(state, Some(session), filter_digest, &record.event_id)
                .await,
        ),
        None => None,
    };
    let last_cursor = match page.last() {
        Some(record) => Some(
            sync_token_for_events_query(state, Some(session), filter_digest, &record.event_id)
                .await,
        ),
        None => None,
    };
    let events = page
        .iter()
        .map(|record| {
            super::super::event_log::sdk_event_for_state(state, record).map_err(|error| {
                soland_http::error::AppError::internal(format!(
                    "canonical Event materialization failed for actor-scoped row {} ({}): {error}",
                    record.event_id, record.kind
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(EventsQueryOutcome {
        events,
        snapshot_bootstrap: None,
        next_cursor: if backward {
            first_cursor
        } else {
            last_cursor.clone()
        },
        prev_cursor: if backward {
            has_more.then_some(last_cursor).flatten()
        } else {
            cursor_token.clone()
        },
        has_more: if backward {
            has_more
        } else {
            cursor_token.is_some()
        },
        range_completeness: None,
    })
}

#[endpoint(operation_id = "ak.self.snapshot.read.manifest_head")]
#[tracing::instrument(skip_all, fields(op = "ak.self.snapshot.read.manifest_head.v1"))]
pub(super) async fn snapshot_head(
    depot: &mut Depot,
    req: &mut Request,
) -> soland_http::result::JsonResult<arkret_state::SnapshotManifest> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let realm_id = query_param(req, "realm_id")
        .ok_or_else(|| soland_http::error::AppError::param_missing("realm_id is required"))?;
    let realm_id = scope_selector_to_realm_id(&realm_id)?;
    let session = authenticated_session(state, req)
        .await
        .map_err(|(status, code, message)| {
            soland_http::error::AppError::param_invalid(message)
                .with_status(status)
                .with_wire_code(code)
        })?;
    if is_realm_deleted(state, &realm_id).await
        || !realm_id_accessible(state, &realm_id, Some(&session)).await
    {
        return Err(soland_http::error::AppError::not_found("not found"));
    }
    let manifest = snapshot_manifest_for_realm(state, &realm_id)
        .await
        .map_err(|error| {
            if matches!(
                error.code,
                soland_http::error::ErrorCode::NotFound
                    | soland_http::error::ErrorCode::InternalError
            ) {
                error
            } else {
                soland_http::error::AppError::new(
                    soland_http::error::ErrorCode::SnapshotUnavailable,
                    error.message,
                )
            }
        })?;
    soland_http::result::json_ok(manifest)
}
