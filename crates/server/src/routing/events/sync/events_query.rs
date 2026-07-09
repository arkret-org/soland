//! Multi-Realm / multi-actor event stream (`ck.self.events.stream.subscribe`),
//! projection-aware events query (`ck.self.events.query.scan` + body form),
//! signed snapshot-manifest head, plus the NDJSON framing and reconnect-gate
//! helpers shared by both subscribe surfaces.

use super::*;

/// `ck.self.events.stream.subscribe` at `GET /_arkret/self/events/subscribe`. NDJSON
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
    let session = match subscribe_session_or_render(&state, req, res).await {
        Some(session) => session,
        None => return,
    };
    if let Some(session) = session.as_ref() {
        if let Err(error) = super::super::require_agent_session_scope(
            session,
            super::super::AGENT_SCOPE_EVENTS_STREAM_SUBSCRIBE,
        ) {
            render_error(res, error.http_status(), error.wire_code(), &error.message);
            return;
        }
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
    let limit = query_param(req, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100)
        .min(100);
    let after_token = query_param(req, "after");
    let include_history = query_param(req, "include_history")
        .as_deref()
        .map(|value| matches!(value, "true" | "1" | "yes"))
        .unwrap_or(true);
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
                    crate::error::render_error_code(mapped.code, res, &mapped.message);
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
    // The raw `event_id` of the last history event served. The resume cursor is
    // minted from it once, below — history event frames carry no per-event
    // cursor (the typed frame's `cursor` is optional, and the single
    // `catchup_complete` token is what the client resumes from), which also
    // avoids one cursor-record upsert per history event.
    let mut last_event_id: Option<String> = None;

    if include_history {
        for realm_id in &accessible_realms {
            match projected_event_page(&state, realm_id, resume_event_id.as_deref(), limit).await {
                Ok(Some(page)) => {
                    for event in page.items {
                        if !projection_record_visible_to_session(&state, &event, session.as_ref())
                            .await
                        {
                            continue;
                        }
                        seq += 1;
                        last_event_id = Some(event.event_id.clone());
                        history_frames.push(json!({
                            "kind": "event",
                            "seq": seq,
                            "payload": projection_event_json(&event)
                        }));
                    }
                    if let Some(next) = page.next_cursor {
                        last_event_id = Some(next);
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

    let catchup_cursor = match last_event_id {
        Some(event_id) => {
            sync_token_for_events_query(&state, session.as_ref(), &filter_digest, &event_id).await
        }
        // No new history event to anchor the catchup cursor to. On a resume poll
        // (`after=<cursor>`, `include_history=false`) the history loop is skipped
        // entirely, so this branch is the steady state of an idle realm. We MUST
        // echo back the client's already-validated, principal-bound `after`
        // cursor here: minting a `sync_token_for_state` token instead stamps
        // `principal_id = None`, and the client's next poll resubmitting it is
        // rejected by `parse_and_validate_events_query_cursor` with
        // `cursor_integrity_invalid` ("cursor principal does not match request
        // actor") — an oscillating error on every idle poll. Only fall back to
        // the service-state token on a fresh subscribe that carried no `after`.
        None => match after_token.clone() {
            Some(after) => after,
            None => sync_token_for_state(&state).await,
        },
    };
    let realm_filter: BTreeSet<String> = accessible_realms.iter().cloned().collect();
    let stream_deadline = tokio::time::Instant::now() + Duration::from_millis(max_duration_ms);
    let session_for_stream = session.clone();
    let subscribe_scope_key_for_stream = subscribe_scope_key.clone();
    let filter_digest_for_stream = filter_digest.clone();

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
                                    // The broadcast carries the raw `event_id`;
                                    // mint the opaque `ak:cursor:` resume token
                                    // the typed frame requires.
                                    let live_cursor = sync_token_for_events_query(
                                        &state,
                                        session_for_stream.as_ref(),
                                        &filter_digest_for_stream,
                                        &cursor,
                                    ).await;
                                    json!({
                                        "kind": "event",
                                        "seq": live_seq,
                                        "cursor": live_cursor,
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
                                EventNotificationKind::Ephemeral { .. } => {
                                    continue;
                                }
                            };
                            yield Ok(ndjson_line(&frame));
                            if terminal {
                                break;
                            }
                        }
                        Err(RecvError::Lagged(skipped)) => {
                            // Round 4 (B1.5) — broadcast capacity exceeded.
                            // The typed EventsSubscribeFrame requires a
                            // resume cursor on Dropped; if we don't have a
                            // valid cursor (the broadcast lag dropped state
                            // we'd need to mint one) the SDK rule downgrades
                            // to ResyncRequired. We always carry the
                            // catchup_cursor we already have, so Dropped is
                            // safe here.
                            let cursor_str = catchup_cursor.clone();
                            // Use the typed-id form (ak:cursor:<base64url>),
                            // not the cursor::Cursor struct.
                            let cursor_typed =
                                arkret_sdk::identifiers::Cursor::new(cursor_str.clone()).ok();
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
                            // Emit the flat frame fields at the top level.
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
pub(crate) fn ndjson_line(value: &serde_json::Value) -> Bytes {
    let mut s = serde_json::to_string(value).unwrap_or_else(|_| "{}".to_owned());
    s.push('\n');
    Bytes::from(s)
}

pub(crate) fn subscribe_subject(req: &Request, session: Option<&SessionRecord>) -> String {
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
fn events_subscribe_filter_digest(accessible_realms: &[String]) -> String {
    let realms = accessible_realms
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    sync_filter_digest(Some(&json!({
        "operation_id": "ck.self.events.stream.subscribe",
        "realms": realms,
    })))
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

pub(crate) fn reject_subscribe_reconnect(
    state: &AppState,
    subscribe_scope_key: &str,
    res: &mut Response,
) -> bool {
    let retry_after_ms = state
        .subscribe_reconnect_gate
        .lock()
        .retry_after_ms(subscribe_scope_key, Utc::now());
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
    state.subscribe_reconnect_gate.lock().arm(
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
        arkret_sdk::ErrorEnvelope::new(
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
    filters: Option<Value>,
}

fn validate_events_query_order(order: &str) -> Result<(), crate::error::AppError> {
    match order {
        "default" | "ascending" | "descending" => Ok(()),
        _ => Err(crate::error::AppError::invalid_param(
            "order must be default, ascending, or descending",
        )),
    }
}

fn events_query_filters_param(req: &Request) -> Result<Option<Value>, crate::error::AppError> {
    query_param(req, "filters")
        .map(|value| {
            serde_json::from_str(&value)
                .map_err(|_| crate::error::AppError::invalid_param("filters must be a JSON value"))
        })
        .transpose()
}

fn reject_events_query_filter_digest_pseudo_fields(
    filters: Option<&Value>,
) -> Result<(), crate::error::AppError> {
    if filters.is_some_and(value_contains_filter_digest_pseudo_field) {
        return Err(crate::error::AppError::invalid_param(
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

fn reject_events_query_filter_digest_query_params(
    req: &Request,
) -> Result<(), crate::error::AppError> {
    if query_param(req, "_filter_digest").is_some() || query_param(req, "filter_digest").is_some() {
        return Err(crate::error::AppError::invalid_param(
            "cursor filter_digest is server-derived",
        ));
    }
    Ok(())
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
        "operation_id": "ck.self.events.query.scan",
        "realms": realms,
        "actors": actors,
        "filters": filters.cloned().unwrap_or_else(|| json!({})),
        "order": order,
    });
    sync_filter_digest(Some(&binding))
}

fn events_query_cursor_error(error: SyncCursorError) -> crate::error::AppError {
    match error {
        SyncCursorError::Expired => crate::error::AppError::new(
            crate::error::ErrorCode::CursorExpired,
            "cursor has expired",
        ),
        SyncCursorError::Invalid(message) => crate::error::AppError::invalid_param(message),
        SyncCursorError::Mismatch(message) | SyncCursorError::Integrity(message) => {
            crate::error::AppError::new(crate::error::ErrorCode::CursorIntegrityInvalid, message)
        }
        SyncCursorError::Revoked => crate::error::AppError::new(
            crate::error::ErrorCode::CursorRevoked,
            "cursor authority has been revoked",
        ),
    }
}

async fn events_query_cursor_target(
    state: &AppState,
    session: Option<&SessionRecord>,
    filter_digest: &str,
    cursor: Option<&str>,
) -> Result<Option<String>, crate::error::AppError> {
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

/// `ck.self.events.query.scan` at `GET /_arkret/self/events`.
/// Reads from the projection layer so callers writing through
/// `POST /_arkret/self/events` see their messages here.
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
pub(crate) async fn events_query(
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<EventsQueryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    reject_events_query_filter_digest_query_params(req)?;
    let filters = events_query_filters_param(req)?;
    let limit = query_param(req, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100)
        .clamp(1, 100);
    let parts = EventsQueryParts {
        realms: super::super::query_param_all(req, "realms"),
        actors: super::super::query_param_all(req, "actors"),
        after: query_param(req, "after"),
        before: query_param(req, "before"),
        order: query_param(req, "order").unwrap_or_else(|| "default".to_owned()),
        limit,
        filters,
    };
    events_query_impl(state, req, parts).await
}

#[endpoint(
    operation_id = "ck.self.events.query.scan_body",
    tags("events"),
    summary = "Body-based projection-aware events query for large selectors"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.events.query.scan_body"))]
pub(crate) async fn events_query_post(
    body: salvo::oapi::extract::JsonBody<EventsQueryPostRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<EventsQueryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
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
        filters: body.filters,
    };
    events_query_impl(state, req, parts).await
}

async fn events_query_impl(
    state: &AppState,
    req: &Request,
    parts: EventsQueryParts,
) -> crate::result::JsonResult<EventsQueryOutcome> {
    validate_events_query_order(&parts.order)?;
    reject_events_query_filter_digest_pseudo_fields(parts.filters.as_ref())?;
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
    let session = if realms.is_empty() {
        Some(
            authenticated_session(state, req)
                .await
                .map_err(|(status, code, message)| {
                    crate::error::AppError::invalid_param(message)
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
                    return Err(crate::error::AppError::invalid_param(message)
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
            super::super::AGENT_SCOPE_EVENTS_QUERY_SCAN,
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
        .await;
        return crate::result::json_ok(response);
    }
    let mut accessible_realms: Vec<String> = Vec::with_capacity(realms.len());
    // encryption-and-audit.md §2.10.8 — realms the caller may scan ONLY as a
    // recovery recipient (non-member). Per-event visibility for these realms is
    // restricted to the caller's own RRK-targeted `ck.realm_key.share` events.
    let mut recovery_only_realms: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    for realm in realms {
        if realm_id_accessible(state, &realm, session.as_ref()).await {
            accessible_realms.push(realm);
            continue;
        }
        // Not a member — admit for recovery-grade read iff the caller is a
        // current recovery recipient of this realm.
        if let Some(session) = session.as_ref()
            && crate::routing::spaces::space::realm_recovery_recipient_principal(
                state,
                &realm,
                &session.actor,
            )
            .await
        {
            recovery_only_realms.insert(realm.clone());
            accessible_realms.push(realm);
        }
    }
    if accessible_realms.is_empty() {
        return Err(crate::error::AppError::not_found("not found"));
    }
    let limit = parts.limit;

    // Single-Realm fast path: paginate + apply visibility over the projection
    // store, then enrich the final page to full Event envelopes
    // (`full_events_from_projection_json`) so the response is the spec
    // `EventsQueryOutcome { events: Vec<Event> }` shape, uniform with the
    // actor-scoped durable reader (SOL-05-003).
    if accessible_realms.len() == 1 {
        let realm_id = &accessible_realms[0];
        let recovery_only = recovery_only_realms.contains(realm_id);
        match projected_event_page(state, realm_id, cursor.as_deref(), limit).await {
            Ok(Some(page)) => {
                let mut events: Vec<Value> = Vec::new();
                let mut last_visible_event_id = None;
                for event in &page.items {
                    if events_query_event_visible(state, event, session.as_ref(), recovery_only)
                        .await
                    {
                        last_visible_event_id = Some(event.event_id.clone());
                        events.push(projection_event_json(event));
                    }
                }
                if backward {
                    events.reverse();
                }
                let events = truncate_before_stop_cursor(events, stop_cursor.as_deref());
                let next_event_id = page
                    .next_cursor
                    .as_deref()
                    .or(last_visible_event_id.as_deref());
                let next_cursor = match next_event_id {
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
                let events = full_events_from_projection_json(state, &events).await;
                return crate::result::json_ok(EventsQueryOutcome {
                    events,
                    snapshot_bootstrap: None,
                    prev_cursor: cursor_token.clone(),
                    next_cursor,
                    has_more: page.has_more,
                    range_completeness: Value::Null,
                });
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
        return crate::result::json_ok(EventsQueryOutcome {
            events: Vec::new(),
            snapshot_bootstrap: None,
            prev_cursor: cursor_token.clone(),
            next_cursor: None,
            has_more: false,
            range_completeness: Value::Null,
        });
    }

    // Multi-Realm merge path: call `projected_event_page` per Realm, merge
    // by `received_at`, then paginate.
    let mut merged: Vec<serde_json::Value> = Vec::new();
    let mut any_has_more = false;
    for realm_id in &accessible_realms {
        let recovery_only = recovery_only_realms.contains(realm_id);
        match projected_event_page(state, realm_id, cursor.as_deref(), limit).await {
            Ok(Some(page)) => {
                if page.has_more {
                    any_has_more = true;
                }
                for event in &page.items {
                    if events_query_event_visible(state, event, session.as_ref(), recovery_only)
                        .await
                    {
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
    let next_cursor = match page_events
        .last()
        .and_then(|event| event["event_id"].as_str())
    {
        Some(event_id) => Some(
            sync_token_for_events_query(state, session.as_ref(), &filter_digest, event_id).await,
        ),
        None => None,
    };
    let events = full_events_from_projection_json(state, &page_events).await;
    crate::result::json_ok(EventsQueryOutcome {
        events,
        snapshot_bootstrap: None,
        prev_cursor: cursor_token.clone(),
        next_cursor,
        has_more: limited,
        range_completeness: Value::Null,
    })
}

/// Per-event visibility for `events.query`. For ordinary (member) realm access
/// this delegates to [`projection_record_visible_to_session`]. For a realm the
/// caller reached ONLY via the recovery-recipient gate
/// (`recovery_only == true`, encryption-and-audit.md §2.10.8), visibility is
/// narrowed to the caller's own RRK-targeted `ck.realm_key.share` events — the
/// recovery org reads exactly the opaque ciphertext it can HPKE-open and nothing
/// else from the realm timeline.
async fn events_query_event_visible(
    state: &AppState,
    event: &crate::state::ProjectionEventRecord,
    session: Option<&crate::state::SessionRecord>,
    recovery_only: bool,
) -> bool {
    if recovery_only {
        let Some(session) = session else {
            return false;
        };
        let recipient = event
            .payload
            .get("recipient_principal_id")
            .and_then(Value::as_str);
        return crate::routing::spaces::space::realm_recovery_event_visible(
            &event.event_kind,
            recipient,
            &session.actor,
        );
    }
    projection_record_visible_to_session(state, event, session).await
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
) -> Vec<arkret_sdk::Event> {
    let mut events = Vec::with_capacity(projection_rows.len());
    for row in projection_rows {
        let Some(event_id) = row.get("event_id").and_then(Value::as_str) else {
            continue;
        };
        if projection_row_is_redacted_message_tombstone(row) {
            if let Some(event) = projection_only_event_from_row(state, row) {
                events.push(event);
            }
            continue;
        }
        if let Ok(Some(record)) = state.persistence.events().get(event_id).await
            && let Ok(event) = super::super::event_log::sdk_event_for_state(state, &record)
        {
            events.push(event);
            continue;
        }
        if let Some(event) = projection_only_event_from_row(state, row) {
            events.push(event);
        }
    }
    events
}

fn projection_row_is_redacted_message_tombstone(row: &Value) -> bool {
    matches!(
        row.get("event_kind").and_then(Value::as_str),
        Some(arkret_sdk::events::kinds::MESSAGE_CREATE | arkret_sdk::events::kinds::MESSAGE_REVISE)
    ) && row.get("payload").is_some_and(|payload| {
        payload.get("redacted").and_then(Value::as_bool) == Some(true)
            || payload.get("state").and_then(Value::as_str) == Some("redacted")
    })
}

fn projection_only_event_from_row(state: &AppState, row: &Value) -> Option<arkret_sdk::Event> {
    let event_id = row.get("event_id").and_then(Value::as_str)?;
    let realm_id = row.get("realm_id").and_then(Value::as_str)?;
    let kind = row.get("event_kind").and_then(Value::as_str)?;
    let created_at = row
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))?;
    let sender = row.get("sender").and_then(Value::as_str);
    let actor_id = sender
        .filter(|value| validate_did(value).is_ok())
        .unwrap_or(state.config.service_did.as_str());
    let millis = created_at.timestamp_millis().max(0);
    let hlc = format!("{millis:012x}-0000-00000000");
    let event = json!({
        "event_id": event_id,
        "kind": kind,
        "realm_id": realm_id,
        "actor_id": actor_id,
        "actor_seq": 0,
        "created_at": created_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "hlc": hlc,
        "prev_refs": [],
        "payload": row.get("payload").cloned().unwrap_or_else(|| json!({})),
        "unsigned": {
            "projection_only": true,
            "operation_type": row.get("operation_type").cloned().unwrap_or(Value::Null),
            "operation_id": row.get("operation_id").cloned().unwrap_or(Value::Null),
            "sender": row.get("sender").cloned().unwrap_or(Value::Null),
        },
        "proofs": [],
    });
    serde_json::from_value(event).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::CanonicalEventRecord;

    const TEST_REALM: &str = "ak:realm:01904100-0000-7000-8000-00000000aa01";
    const TEST_ACTOR: &str = "did:web:alice.example";
    const TEST_MESSAGE_EVENT: &str = "ak:event:01904100-0000-7000-8000-00000000aa11";
    const TEST_REVISE_EVENT: &str = "ak:event:01904100-0000-7000-8000-00000000aa12";
    const TEST_MESSAGE_ID: &str = "ak:message:01904100-0000-7000-8000-00000000aa21";
    const TEST_REDACTION_EVENT: &str = "ak:event:01904100-0000-7000-8000-00000000aa31";

    fn test_state() -> AppState {
        let mut config = crate::config::AppConfig::test_default();
        config.seed_demo_data = false;
        AppState::new(config, soland_data::Db { pool: None })
    }

    fn operation_at(
        operation_id: &str,
        kind: &str,
        payload: Value,
        created_at: DateTime<Utc>,
    ) -> arkret_sdk::Operation {
        let mut operation = arkret_sdk::Operation::create(
            arkret_sdk::OperationId::new(operation_id.to_owned()).unwrap(),
            RealmId::new(TEST_REALM.to_owned()).unwrap(),
            kind,
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
        let canonical_bytes = serde_json::to_vec(&envelope).unwrap();
        state
            .persistence
            .events()
            .put(CanonicalEventRecord {
                event_id: event_id.to_owned(),
                actor_id: TEST_ACTOR.to_owned(),
                actor_seq: 1,
                realm_id: Some(TEST_REALM.to_owned()),
                kind: kind.to_owned(),
                schema_id: "ck.schema.event.v1".to_owned(),
                canonical_digest: format!("sha256:test-{}", event_id.rsplit(':').next().unwrap()),
                canonical_bytes,
                envelope,
                received_at: created_at,
            })
            .await
            .expect("durable event stored");
    }

    #[tokio::test]
    async fn events_query_enrich_keeps_redaction_tombstone_over_durable_plaintext() {
        let state = test_state();
        let created_at = DateTime::parse_from_rfc3339("2026-07-06T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let revised_at = created_at + chrono::Duration::seconds(30);
        let redacted_at = created_at + chrono::Duration::minutes(1);
        let strand_id = strand_id_from_realm_id(TEST_REALM);
        let plaintext_payload = json!({
            "event_id": TEST_MESSAGE_EVENT,
            "message_id": TEST_MESSAGE_ID,
            "realm_id": TEST_REALM,
            "strand_id": strand_id,
            "track_name": "discussion",
            "sender": TEST_ACTOR,
            "content": {"kind": "ck.content.text", "body": "secret that must not leak"}
        });
        let revised_payload = json!({
            "event_id": TEST_REVISE_EVENT,
            "target_ref": TEST_MESSAGE_ID,
            "realm_id": TEST_REALM,
            "strand_id": strand_id,
            "track_name": "discussion",
            "sender": TEST_ACTOR,
            "content": {"kind": "ck.content.text", "body": "revised secret that must not leak"}
        });
        let message = operation_at(
            "ak:operation:01904100-0000-7000-8000-00000000aa41",
            arkret_sdk::events::kinds::MESSAGE_CREATE,
            plaintext_payload.clone(),
            created_at,
        );
        let revise = operation_at(
            "ak:operation:01904100-0000-7000-8000-00000000aa43",
            arkret_sdk::events::kinds::MESSAGE_REVISE,
            revised_payload.clone(),
            revised_at,
        );
        let redaction = operation_at(
            "ak:operation:01904100-0000-7000-8000-00000000aa42",
            arkret_sdk::events::kinds::MESSAGE_REDACT,
            json!({
                "event_id": TEST_REDACTION_EVENT,
                "message_id": TEST_MESSAGE_ID,
                "reason": "test redaction",
                "sender": TEST_ACTOR
            }),
            redacted_at,
        );
        crate::routing::events::projection::project_accepted_operations(
            &state,
            TEST_ACTOR,
            &[message, revise, redaction],
        )
        .await;
        put_durable_event(
            &state,
            TEST_MESSAGE_EVENT,
            arkret_sdk::events::kinds::MESSAGE_CREATE,
            json!({
                "event_id": TEST_MESSAGE_EVENT,
                "kind": arkret_sdk::events::kinds::MESSAGE_CREATE,
                "realm_id": TEST_REALM,
                "actor_id": TEST_ACTOR,
                "actor_seq": 1,
                "created_at": created_at,
                "hlc": "019041000000-0000-00000000",
                "prev_refs": [],
                "payload": plaintext_payload,
                "proofs": []
            }),
            created_at,
        )
        .await;
        put_durable_event(
            &state,
            TEST_REVISE_EVENT,
            arkret_sdk::events::kinds::MESSAGE_REVISE,
            json!({
                "event_id": TEST_REVISE_EVENT,
                "kind": arkret_sdk::events::kinds::MESSAGE_REVISE,
                "realm_id": TEST_REALM,
                "actor_id": TEST_ACTOR,
                "actor_seq": 2,
                "created_at": revised_at,
                "hlc": "019041000000-0001-00000000",
                "prev_refs": [TEST_MESSAGE_EVENT],
                "payload": revised_payload,
                "proofs": []
            }),
            revised_at,
        )
        .await;

        let page = projected_event_page(&state, TEST_REALM, None, 100)
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
            .find(|row| row["event_id"] == TEST_MESSAGE_EVENT)
            .expect("message row retained as tombstone");
        assert_eq!(message_row["payload"]["redacted"], json!(true));
        let revise_row = rows
            .iter()
            .find(|row| row["event_id"] == TEST_REVISE_EVENT)
            .expect("revision row retained as tombstone");
        assert_eq!(revise_row["payload"]["redacted"], json!(true));

        let events = full_events_from_projection_json(&state, &rows).await;
        let message_event = events
            .iter()
            .find(|event| event.event_id.as_str() == TEST_MESSAGE_EVENT)
            .expect("message event returned");
        assert_eq!(message_event.payload["redacted"], json!(true));
        assert_eq!(
            message_event.payload["content"]["body"],
            json!("[redacted]")
        );
        assert!(
            !serde_json::to_string(&message_event.payload)
                .unwrap()
                .contains("secret that must not leak")
        );
        let revise_event = events
            .iter()
            .find(|event| event.event_id.as_str() == TEST_REVISE_EVENT)
            .expect("revision event returned");
        assert_eq!(revise_event.payload["redacted"], json!(true));
        assert_eq!(revise_event.payload["content"]["body"], json!("[redacted]"));
        assert!(
            !serde_json::to_string(&revise_event.payload)
                .unwrap()
                .contains("revised secret that must not leak")
        );
    }
}

async fn durable_events_query_from_parts(
    state: &AppState,
    session: &SessionRecord,
    parts: &EventsQueryParts,
    cursor: Option<&str>,
    stop_cursor: Option<&str>,
    backward: bool,
    filter_digest: &str,
    cursor_token: Option<String>,
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
        if !super::super::event_log::event_visible_to_session(state, &record, session).await {
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
    let next_cursor = match page.last() {
        Some(record) => Some(
            sync_token_for_events_query(state, Some(session), filter_digest, &record.event_id)
                .await,
        ),
        None => None,
    };
    let events = page
        .iter()
        .filter_map(|record| super::super::event_log::sdk_event_for_state(state, record).ok())
        .collect();
    EventsQueryOutcome {
        events,
        snapshot_bootstrap: None,
        next_cursor,
        prev_cursor: cursor_token,
        has_more,
        range_completeness: Value::Null,
    }
}

#[endpoint(
    operation_id = "ck.self.snapshot.query.manifest_head",
    tags("sync"),
    summary = "Read the signed snapshot-v1 manifest head for a Realm"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.snapshot.query.manifest_head"))]
pub(super) async fn snapshot_head(
    depot: &mut Depot,
    req: &mut Request,
) -> crate::result::JsonResult<arkret_sdk::SnapshotManifest> {
    let state = depot.get_typed::<AppState>().expect("state injected");
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
            if matches!(
                error.code,
                crate::error::ErrorCode::NotFound | crate::error::ErrorCode::InternalError
            ) {
                error
            } else {
                crate::error::AppError::new(
                    crate::error::ErrorCode::SnapshotUnavailable,
                    error.message,
                )
            }
        })?;
    crate::result::json_ok(manifest)
}
