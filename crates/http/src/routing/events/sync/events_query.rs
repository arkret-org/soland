//! Multi-Realm / multi-actor event stream (`ak.self.events.stream.subscribe.v1`),
//! canonical durable events read (`ak.self.events.read.scan.v1`),
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
/// Selectors: repeated `realm_ids` and percent-encoded JCS `actor_ids` values.
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
    let realms = super::super::query_param_all(req, "realm_ids");
    let actors = super::super::query_param_all(req, "actor_ids");
    if req.uri().query().is_some_and(|query| {
        query.split('&').any(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            matches!(name, "realm_ids" | "actor_ids") && value.is_empty()
        })
    }) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "param_invalid",
            "selectors must not contain empty values",
        );
        return;
    }
    if realms.is_empty() && actors.is_empty() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "param_missing",
            "realm_ids or actor_ids is required",
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
    let actor_filter = match canonical_actor_selectors(&actors) {
        Ok(actors) => actors,
        Err(error) => {
            render_error(res, error.http_status(), error.wire_code(), &error.message);
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
    if realms.is_empty()
        && let Err(error) =
            authorize_actor_only_selectors(&state, session.as_ref(), &actor_filter).await
    {
        render_error(res, error.http_status(), error.wire_code(), &error.message);
        return;
    }
    let requested_realms = realms.clone();
    let realms = if realms.is_empty() {
        state
            .realm_directory()
            .snapshot()
            .entries_iter()
            .map(|(realm_id, _)| realm_id.to_string())
            .collect()
    } else {
        realms
    };
    let mut accessible_realms: Vec<String> = Vec::with_capacity(realms.len());
    for realm in realms {
        if realm_id_accessible(&state, &realm, session.as_ref()).await {
            accessible_realms.push(realm);
        }
    }
    let actor_only = requested_realms.is_empty();
    if accessible_realms.is_empty() && !actor_only {
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
    let filter_digest = events_subscribe_filter_digest(&requested_realms, &actor_filter);
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
    let subscribe_scope_key = events_subscribe_scope_key(req, session.as_ref(), &filter_digest);
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

    let actor_replay = if actor_only && catchup {
        match actor_subscription_replay(&state, &actor_filter, resume_event_id.as_deref()).await {
            Ok(replay) => replay,
            Err(error) => {
                render_error(res, error.http_status(), error.wire_code(), &error.message);
                return;
            }
        }
    } else {
        None
    };

    let realm_filter = accessible_realms.iter().cloned().collect::<BTreeSet<_>>();
    let replay_upper_bound = if catchup && !actor_only {
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
    let stream_deadline = tokio::time::Instant::now()
        + events_subscribe_wait(session.as_ref(), Utc::now(), max_duration_ms);
    let session_for_stream = session.clone();
    let grant_for_stream = soland_http::util::dpop_token(req).map(str::to_owned);
    let subscribe_scope_key_for_stream = subscribe_scope_key.clone();
    let filter_digest_for_stream = filter_digest.clone();

    // The async stream — yields one NDJSON line (Bytes) per frame.
    let body_stream = async_stream::stream! {
        let mut replayed_event_ids = BTreeSet::new();
        let mut replay_cursor = None;

        if !events_stream_authorized(&state, session_for_stream.as_ref(), grant_for_stream.as_deref(), actor_only, &actor_filter).await {
            yield Ok::<Bytes, std::io::Error>(ndjson_line(&json!({"kind": "unauthorized"})));
            return;
        }

        if let Some((events, has_more)) = actor_replay {
            if has_more {
                yield Ok::<Bytes, std::io::Error>(ndjson_line(&json!({"kind": "resync_required"})));
                return;
            }
            for event in events {
                let cursor = sync_token_for_events_query(&state, session_for_stream.as_ref(),
                    &filter_digest_for_stream, event.event_id.as_str()).await;
                replayed_event_ids.insert(event.event_id.to_string());
                replay_cursor = Some(cursor.clone());
                let Some(frame) = events_event_frame(event.realm_id.as_str(), &cursor, &event) else {
                    yield Ok(ndjson_line(&json!({"kind": "resync_required"})));
                    return;
                };
                if !events_stream_authorized(&state, session_for_stream.as_ref(), grant_for_stream.as_deref(), actor_only, &actor_filter).await {
                    yield Ok(ndjson_line(&json!({"kind": "unauthorized"})));
                    return;
                }
                yield Ok(ndjson_line(&frame));
            }
        }

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
                if !actor_filter.is_empty() && !actor_filter.contains(&event_envelope.actor_id.to_string()) {
                    continue;
                }
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
                if !events_stream_authorized(&state, session_for_stream.as_ref(), grant_for_stream.as_deref(), actor_only, &actor_filter).await {
                    yield Ok(ndjson_line(&json!({"kind": "unauthorized"})));
                    return;
                }
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
            if !events_stream_authorized(&state, session_for_stream.as_ref(), grant_for_stream.as_deref(), actor_only, &actor_filter).await {
                yield Ok(ndjson_line(&json!({"kind": "unauthorized"})));
                return;
            }
            let frontier = json!({
                "kind": "frontier",
                "cursor": cursor,
            });
            yield Ok(ndjson_line(&frontier));
            replay_cursor = Some(cursor.clone());
        }

        // Completion follows either replay data or the empty-replay frontier.
        if let Some(cursor) = replay_cursor.as_ref() {
            if !events_stream_authorized(&state, session_for_stream.as_ref(), grant_for_stream.as_deref(), actor_only, &actor_filter).await {
                yield Ok(ndjson_line(&json!({"kind": "unauthorized"})));
                return;
            }
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
                    let expired = session_for_stream.as_ref().is_some_and(|session| session.expires_at <= Utc::now());
                    let close_frame = json!({"kind": if expired { "unauthorized" } else { "heartbeat" }});
                    yield Ok(ndjson_line(&close_frame));
                    break;
                }
                recv = rx.recv() => {
                    match recv {
                        Ok(notification) => {
                            if !active_realms.contains(&notification.realm_id)
                                && !(actor_only && matches!(&notification.kind, crate::state::EventNotificationKind::Event { .. }))
                            {
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
                                    if !actor_only && !projection_event_value_visible_to_session(
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
                                    if !actor_filter.is_empty() && !actor_filter.contains(&event_envelope.actor_id.to_string()) {
                                        continue;
                                    }
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
                            if !events_stream_authorized(&state, session_for_stream.as_ref(), grant_for_stream.as_deref(), actor_only, &actor_filter).await {
                                yield Ok(ndjson_line(&json!({"kind": "unauthorized"})));
                                return;
                            }
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
                    if !events_stream_authorized(&state, session_for_stream.as_ref(), grant_for_stream.as_deref(), actor_only, &actor_filter).await {
                        yield Ok(ndjson_line(&json!({"kind": "unauthorized"})));
                        return;
                    }
                    let frame = json!({"kind": "heartbeat"});
                    yield Ok(ndjson_line(&frame));
                }
            }
        }
    };

    let _ = res.add_header("content-type", "application/x-ndjson", true);
    res.stream(body_stream.boxed());
}

fn events_subscribe_wait(
    session: Option<&SessionIdentityState>,
    at: DateTime<Utc>,
    max_duration_ms: u64,
) -> Duration {
    let requested = Duration::from_millis(max_duration_ms);
    session.map_or(requested, |session| {
        requested.min((session.expires_at - at).to_std().unwrap_or_default())
    })
}

async fn events_stream_authorized(
    state: &AppState,
    session: Option<&SessionIdentityState>,
    grant_jwt: Option<&str>,
    actor_only: bool,
    actors: &BTreeSet<String>,
) -> bool {
    let Some(session) = session else {
        return !actor_only;
    };
    let at = Utc::now();
    if session.expires_at <= at {
        return false;
    }
    let deadline =
        tokio::time::Instant::now() + (session.expires_at - at).to_std().unwrap_or_default();
    let authorization = async {
        crate::routing::identity::auth::revalidate_stream_session(state, session, grant_jwt)
            .await
            .map_err(|_| ())?;
        if actor_only {
            authorize_actor_only_selectors(state, Some(session), actors)
                .await
                .map_err(|_| ())?;
        }
        Ok::<(), ()>(())
    };
    matches!(
        tokio::time::timeout_at(deadline, authorization).await,
        Ok(Ok(()))
    ) && session.expires_at > Utc::now()
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

/// Serialize a JSON frame to a canonical NDJSON line. Each line ends with `\n`
/// per the NDJSON / JSON-Lines
/// convention so streaming clients can split-on-newline incrementally
/// without parsing the whole buffer.
pub(crate) fn ndjson_line(value: &impl serde::Serialize) -> Bytes {
    let mut bytes = arkret_canonical::canonical_json_bytes(value)
        .expect("account and Event stream frames must be canonically serializable");
    bytes.push(b'\n');
    Bytes::from(bytes)
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
pub(crate) fn events_subscribe_filter_digest(
    accessible_realms: &[String],
    actors: &BTreeSet<String>,
) -> String {
    let realms = accessible_realms
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    sync_filter_digest(Some(&json!({
        "operation_id": arkret_wire::ServiceOperationId::SELF_EVENTS_STREAM_SUBSCRIBE_V1,
        "realm_ids": realms,
        "actor_ids": actors.iter().map(|actor| serde_json::from_str::<arkret_wire::ActorId>(actor)
            .expect("actor selector was validated before cursor binding")).collect::<Vec<_>>(),
    })))
}

fn events_subscribe_scope_key(
    req: &Request,
    session: Option<&SessionIdentityState>,
    filter_digest: &str,
) -> String {
    format!(
        "ak.self.events.stream.subscribe.v1|{}|filter={filter_digest}",
        subscribe_subject(req, session)
    )
}

pub(crate) fn canonical_actor_selectors(
    actors: &[String],
) -> Result<BTreeSet<String>, soland_http::error::AppError> {
    if actors.len() > 256 {
        return Err(soland_http::error::AppError::param_invalid(
            "actor_ids exceeds 256 entries",
        ));
    }
    let mut selectors = BTreeSet::new();
    for encoded in actors {
        let actor: arkret_wire::ActorId = serde_json::from_str(encoded).map_err(|_| {
            soland_http::error::AppError::param_invalid(
                "actor_ids requires canonical JCS ActorId objects",
            )
        })?;
        actor
            .validate()
            .map_err(|error| soland_http::error::AppError::param_invalid(error.to_string()))?;
        if actor.to_string() != *encoded || !selectors.insert(encoded.clone()) {
            return Err(soland_http::error::AppError::param_invalid(
                "actor_ids must be canonical and unique",
            ));
        }
    }
    Ok(selectors)
}

pub(crate) async fn authorize_actor_only_selectors(
    state: &AppState,
    session: Option<&SessionIdentityState>,
    actors: &BTreeSet<String>,
) -> Result<(), soland_http::error::AppError> {
    use soland_http::error::AppError;
    let unauthorized = || {
        crate::app_error!(
            CapabilityDenied,
            "actor-only selectors require an exact holder-owned ActorId",
        )
        .with_wire_code("unauthorized")
    };
    let session = session.ok_or_else(unauthorized)?;
    let account_id =
        crate::routing::identity::auth_grant_dpop::authenticated_session_account_id(state, session)
            .await?;
    let account = state
        .identities()
        .account(&account_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let account_pk = account.map(|account| account.pk);
    let holder_actor = arkret_wire::ActorId::account(account_id).to_string();
    for selector in actors {
        if *selector == holder_actor {
            continue;
        }
        let actor: arkret_wire::ActorId =
            serde_json::from_str(selector).map_err(|_| unauthorized())?;
        let arkret_wire::ActorId::Account {
            account_id:
                arkret_wire::AccountId {
                    principal_id,
                    station_id,
                },
        } = actor
        else {
            return Err(unauthorized());
        };
        let agent = state
            .agent_pairings()
            .agent(principal_id.as_str())
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            .ok_or_else(unauthorized)?;
        if account_pk.is_none()
            || agent.controller_account_pk != account_pk
            || agent.recipient_id.as_deref() != Some(station_id.as_str())
            || agent.state
                != arkret_models_collaboration::agent_operations::AgentLifecycleState::Active
        {
            return Err(unauthorized());
        }
        crate::routing::identity::agent_pcr::validate_agent_controller_binding(
            state,
            &agent,
            Utc::now(),
        )
        .await
        .map_err(|_| unauthorized())?;
    }
    Ok(())
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
        SyncCursorError::Expired => crate::app_error!(CursorExpired, "cursor has expired",),
        // encoding.md §8.3 closed set: syntax/schema failures pin the top-level
        // `param_invalid` code with reason `invalid_cursor`.
        SyncCursorError::Invalid(message) => soland_http::error::AppError::param_invalid(message)
            .with_reason_code(arkret_wire::ReasonCode::INVALID_CURSOR),
        SyncCursorError::Mismatch(message) | SyncCursorError::Integrity(message) => {
            crate::app_error!(CursorIntegrityInvalid, message,)
        }
        SyncCursorError::Revoked => {
            crate::app_error!(CursorRevoked, "cursor authority has been revoked",)
        }
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
    let actor_filter = canonical_actor_selectors(&parts.actors)?;
    let session = if realms.is_empty() {
        Some(
            authenticated_session(state, req)
                .await
                .map_err(|(_status, code, message)| {
                    let typed = soland_http::error::ErrorCode::from_wire(code)
                        .unwrap_or(soland_http::error::ErrorCode::Unauthenticated);
                    soland_http::error::AppError::from_rejection(typed, message)
                })?,
        )
    } else {
        // Anonymous scan is allowed (public realms), but a presented-yet-invalid
        // bearer must surface its 401 rather than degrade to anonymous — see
        // `subscribe_session_or_render` for the cursor-masking rationale.
        match authenticated_session(state, req).await {
            Ok(session) => Some(session),
            Err((_status, code, message)) => {
                if request_presents_auth_material(req) {
                    let typed = soland_http::error::ErrorCode::from_wire(code)
                        .unwrap_or(soland_http::error::ErrorCode::Unauthenticated);
                    return Err(soland_http::error::AppError::from_rejection(typed, message));
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
    if realms.is_empty() {
        authorize_actor_only_selectors(state, session.as_ref(), &actor_filter).await?;
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
        )
        .await?;
        return soland_http::result::json_ok(response);
    }
    let mut accessible_realms: Vec<String> = Vec::with_capacity(realms.len());
    let mut agent_control_realms: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    for realm in realms {
        if let Some(session) = session.as_ref()
            && crate::routing::identity::agent_pcr::controller_manages_agent_pcr(
                state,
                &session.actor,
                &realm,
            )
            .await?
        {
            agent_control_realms.insert(realm.clone());
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
    // A projection row is published only after its immutable canonical Event.
    // Read the dependent index first: reading canonical Events first lets a
    // concurrent accepted append appear only in the later index snapshot and
    // falsely look like corruption. Genuine orphan/mismatched rows still fail
    // below; candidates continue to come exclusively from canonical Events.
    let mut indexed_rows = Vec::new();
    for realm in &accessible_realms {
        let rows = state
            .event_queries()
            .projected_events_for_realm(realm)
            .await
            .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
        indexed_rows.extend(rows.into_iter().map(|row| (realm.clone(), row)));
    }
    let records = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    let by_id: BTreeMap<_, _> = records
        .iter()
        .map(|record| (record.event_id.as_str(), record))
        .collect();
    let realm_set: BTreeSet<_> = accessible_realms.iter().cloned().collect();
    for (realm, row) in indexed_rows {
        let record = by_id.get(row.event_id.as_str()).ok_or_else(|| {
            soland_http::error::AppError::internal("projection row has no canonical Event")
        })?;
        if super::super::event_log::canonical_realm_id_for_record(record).as_deref()
            != Some(realm.as_str())
            || record.kind != row.event_kind.as_str()
        {
            return Err(soland_http::error::AppError::internal(
                "projection index differs from canonical Event",
            ));
        }
    }
    let mut candidates = Vec::new();
    let mut views = Vec::new();
    for record in &records {
        let Some(realm) = super::super::event_log::canonical_realm_id_for_record(record) else {
            continue;
        };
        if !realm_set.contains(&realm) {
            continue;
        }
        let actor = canonical_record_actor_key(record)?;
        let event = super::super::event_log::canonical_event_for_read(record)
            .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
        if record.event_id != event.event_id.as_str()
            || record.kind != event.kind.as_str()
            || record.actor_seq != event.actor_seq
        {
            return Err(soland_http::error::AppError::internal(
                "canonical Event index differs from signed envelope",
            ));
        }
        // These transient views are derived from EVERY accepted Event, not from
        // persisted projection row presence. They are never emitted as Events.
        let view = ProjectedEvent {
            event_id: record.event_id.clone(),
            realm_id: realm.clone(),
            event_kind: event.kind.clone(),
            operation_kind: String::new(),
            operation_id: None,
            sender: Some(actor.clone()),
            payload: serde_json::to_value(&event.payload)
                .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?,
            created_at: event.created_at,
            received_at: record.received_at,
        };
        views.push(view.clone());
        if !actor_filter.is_empty() && !actor_filter.contains(&actor) {
            continue;
        }
        let managed = agent_control_realms.contains(&realm);
        if !managed {
            if !projection_record_visible_to_session(state, &view, session.as_ref()).await {
                continue;
            }
            if let arkret_wire::ScopeRef::Sidecar { sidecar_id, .. } = &event.scope_ref {
                let projection = state.projections().snapshot();
                let holder = session.as_ref().and_then(|session| {
                    crate::routing::identity::session_actor::session_actor_from_credential(
                        state, session,
                    )
                    .ok()
                });
                if !projection
                    .sidecars
                    .get(sidecar_id.as_str())
                    .is_some_and(|sidecar| {
                        holder.as_ref().is_some_and(|actor| {
                            actor.as_account_id() == Some(&sidecar.controller_account_id)
                        })
                    })
                {
                    continue;
                }
            }
            let circle = super::super::event_log::effective_scope_for_envelope(&record.envelope)
                .filter(|scope| scope.starts_with("ak:circle:"));
            if !circle_scope_visible_to_session(
                state,
                &state.projections().snapshot(),
                circle.as_deref(),
                record.received_at,
                session.as_ref(),
                Some(&actor),
            ) {
                continue;
            }
        }
        candidates.push((record, event, view));
    }
    let roots = candidates
        .iter()
        .map(|(record, ..)| record.event_id.clone())
        .collect();
    let depths = soland_services::events::canonical_event_depths(&records, &roots)
        .map_err(soland_http::error::AppError::internal)?;
    candidates.sort_by(|(left, le, _), (right, re, _)| {
        depths[&left.event_id]
            .cmp(&depths[&right.event_id])
            .then_with(|| le.hlc.is_none().cmp(&re.hlc.is_none()))
            .then_with(|| le.hlc.cmp(&re.hlc))
            .then_with(|| left.actor_id.cmp(&right.actor_id))
            .then_with(|| left.actor_seq.cmp(&right.actor_seq))
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    let after = if backward {
        stop_cursor.as_deref()
    } else {
        cursor.as_deref()
    };
    let before = if parts.before.is_some() {
        if backward {
            cursor.as_deref()
        } else {
            stop_cursor.as_deref()
        }
    } else {
        None
    };
    let ids: Vec<_> = candidates
        .iter()
        .map(|(record, ..)| record.event_id.as_str())
        .collect();
    let (indices, has_more) = canonical_query_page(&ids, after, before, backward, parts.limit)?;
    let mut page_rows = Vec::new();
    {
        use soland_services::projection::tombstone::*;
        let projection = state.projections().snapshot();
        let redactions = message_redactions_from_events(&views, &projection);
        for index in &indices {
            let (record, _, view) = &candidates[*index];
            let mut view = view.clone();
            tombstone_projection_event_for_erased_actor(&projection, &mut view);
            tombstone_projection_event_for_message_redaction(&projection, &redactions, &mut view);
            if let Some(tombstone) =
                super::super::projection::retention_tombstone_for_event(state, &record.event_id)
            {
                tombstone_projection_event_for_retention(&mut view, &tombstone);
            }
            page_rows.push(projection_event_json(&view));
        }
    }
    // Materialize all rows before issuing any successful continuation token.
    let events = full_events_from_projection_json(state, &page_rows).await?;
    let older = indices.iter().min().map(|index| ids[*index]);
    let newer = indices.iter().max().map(|index| ids[*index]).or(after);
    let prev_cursor = if has_more {
        match older.or(after) {
            Some(id) => {
                Some(sync_token_for_events_query(state, session.as_ref(), &filter_digest, id).await)
            }
            None => None,
        }
    } else {
        None
    };
    let next_cursor = match newer {
        Some(id) => {
            Some(sync_token_for_events_query(state, session.as_ref(), &filter_digest, id).await)
        }
        None => None,
    };
    soland_http::result::json_ok(EventsQueryOutcome {
        events,
        snapshot_bootstrap: None,
        prev_cursor,
        next_cursor,
        has_more,
    })
}

/// Bounds are absolute canonical positions; order controls presentation only.
fn canonical_query_page(
    ids: &[&str],
    after: Option<&str>,
    before: Option<&str>,
    backward: bool,
    limit: usize,
) -> Result<(Vec<usize>, bool), soland_http::error::AppError> {
    let position = |id: &str| {
        ids.iter().position(|value| *value == id).ok_or_else(|| {
            soland_http::error::AppError::param_invalid("cursor position unavailable")
                .with_reason_code(arkret_wire::ReasonCode::INVALID_CURSOR)
        })
    };
    let start = after
        .map(position)
        .transpose()?
        .map_or(0, |index| index + 1);
    let end = before.map(position).transpose()?.unwrap_or(ids.len());
    if end < start {
        return Err(
            soland_http::error::AppError::param_invalid("cursor bounds are reversed")
                .with_reason_code(arkret_wire::ReasonCode::INVALID_CURSOR),
        );
    }
    let indices: Vec<_> = if backward {
        (start..end).rev().take(limit).collect()
    } else {
        (start..end).take(limit).collect()
    };
    let has_more = indices
        .iter()
        .min()
        .map_or(after.is_some() && start > 1, |index| *index > 0);
    Ok((indices, has_more))
}
#[cfg(test)]

async fn projection_matches_actor_selectors(
    state: &AppState,
    event: &soland_services::events::ProjectedEvent,
    actors: &BTreeSet<String>,
) -> Result<bool, soland_http::error::AppError> {
    if actors.is_empty() {
        return Ok(true);
    }
    let record = state
        .event_queries()
        .canonical_event(&event.event_id)
        .await
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?
        .ok_or_else(|| {
            soland_http::error::AppError::internal("actor filter requires the canonical Event")
        })?;
    Ok(actors.contains(&canonical_record_actor_key(&record)?))
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
    use arkret_models_collaboration::http_bodies::EventRedactionReason;

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
    let event = super::super::event_log::canonical_event_for_read(&record).map_err(|error| {
        soland_http::error::AppError::internal(format!(
            "canonical Event materialization failed for projected row {event_id}: {error}"
        ))
    })?;
    let retained = row["payload"]["retention_tombstone"].as_bool() == Some(true);
    let erased = row["sender"].as_str()
        == Some(soland_services::projection::tombstone::ERASED_USER_PLACEHOLDER);
    if !projection_row_is_redacted_message_tombstone(row) && !retained && !erased {
        return Ok(event.into());
    }
    Ok(super::super::event_log::redacted_event_read_row(
        event,
        if retained {
            EventRedactionReason::RetentionPruned
        } else if erased {
            EventRedactionReason::PolicyHidden
        } else {
            EventRedactionReason::Redacted
        },
    ))
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

    #[test]
    fn ndjson_frames_are_byte_for_byte_canonical_json() {
        let line = ndjson_line(&json!({
            "z": 1,
            "a": {"second": true, "first": false},
        }));
        assert_eq!(line.last(), Some(&b'\n'));
        assert_eq!(
            &line[..line.len() - 1],
            arkret_canonical::canonical_json_bytes(&json!({
                "z": 1,
                "a": {"second": true, "first": false},
            }))
            .unwrap()
        );
    }

    #[test]
    fn canonical_page_bounds_are_independent_of_presentation_direction() {
        let ids = ["a", "b", "c", "d"];
        assert_eq!(
            canonical_query_page(&ids, None, None, true, 2).unwrap(),
            (vec![3, 2], true)
        );
        assert_eq!(
            canonical_query_page(&ids, Some("b"), None, true, 2).unwrap(),
            (vec![3, 2], true)
        );
        assert_eq!(
            canonical_query_page(&ids, None, Some("d"), true, 2).unwrap(),
            (vec![2, 1], true)
        );
        assert_eq!(
            canonical_query_page(&ids, Some("a"), Some("d"), false, 1).unwrap(),
            (vec![1], true)
        );
        assert_eq!(
            canonical_query_page(&ids, Some("d"), None, false, 2).unwrap(),
            (vec![], true)
        );
        assert!(canonical_query_page(&ids, Some("missing"), None, false, 2).is_err());
        assert!(canonical_query_page(&ids, Some("d"), Some("b"), true, 2).is_err());
    }

    fn test_state() -> AppState {
        let mut config = crate::config::AppConfig::test_default();
        config.seed_demo_data = false;
        AppState::new(config, soland_storage_postgres::Db { pool: None })
    }

    fn selector_at(station: &str) -> arkret_wire::ActorId {
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(TEST_ACTOR_CORE).unwrap(),
            arkret_wire::DidCoreId::new(station).unwrap(),
        ))
    }

    #[test]
    fn actor_selectors_require_unique_canonical_full_identity() {
        let first = selector_at("ak:did_core:web:station-a.example").to_string();
        let second = selector_at("ak:did_core:web:station-b.example").to_string();
        assert_eq!(
            canonical_actor_selectors(&[first.clone(), second])
                .unwrap()
                .len(),
            2
        );
        assert!(canonical_actor_selectors(&[TEST_ACTOR_CORE.to_owned()]).is_err());
        assert!(canonical_actor_selectors(&[first.clone(), first.clone()]).is_err());
        assert!(canonical_actor_selectors(&[format!(" {first}")]).is_err());
        let mut legacy =
            serde_json::to_value(selector_at("ak:did_core:web:station-a.example")).unwrap();
        legacy["principal_id"] = json!(TEST_ACTOR_CORE);
        assert!(canonical_actor_selectors(&[legacy.to_string()]).is_err());
        assert!(canonical_actor_selectors(&vec![first; 257]).is_err());
    }

    #[test]
    fn subscribe_cursor_scope_binds_station_and_normalizes_selector_order() {
        let first = selector_at("ak:did_core:web:station-a.example").to_string();
        let second = selector_at("ak:did_core:web:station-b.example").to_string();
        let realms = vec![TEST_REALM.to_owned()];
        assert_ne!(
            events_subscribe_filter_digest(&realms, &BTreeSet::from([first.clone()])),
            events_subscribe_filter_digest(&realms, &BTreeSet::from([second.clone()])),
        );
        assert_eq!(
            events_subscribe_filter_digest(
                &realms,
                &BTreeSet::from([first.clone(), second.clone()])
            ),
            events_subscribe_filter_digest(&realms, &BTreeSet::from([second, first])),
        );
    }

    #[tokio::test]
    async fn actor_only_selector_requires_authenticated_exact_holder() {
        let error = authorize_actor_only_selectors(
            &test_state(),
            None,
            &BTreeSet::from([selector_at("ak:did_core:web:station-a.example").to_string()]),
        )
        .await
        .unwrap_err();
        assert_eq!(error.wire_code(), "unauthorized");
    }

    fn stream_test_state() -> AppState {
        AppState::new(
            crate::config::AppConfig {
                development_mode: true,
                seed_demo_data: false,
                ..crate::config::AppConfig::test_default()
            },
            soland_storage_postgres::Db { pool: None },
        )
    }

    async fn stream_test_session(state: &AppState) -> SessionIdentityState {
        let account_id = arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(TEST_ACTOR_CORE).unwrap(),
            state.service_core_id(),
        );
        state
            .identities()
            .save_account(soland_services::identity::AccountProfileState {
                // The store assigns the primary key.
                pk: soland_storage::AccountPk(0),
                principal_id: account_id.principal_id.clone(),
                account_id: account_id.clone(),
                localpart: "alice".to_owned(),
                display_name: None,
                bio: None,
                avatar_blob_ref: None,
                created_at: Utc::now(),
            })
            .await
            .unwrap();
        let account_pk = state
            .identities()
            .account(&account_id)
            .await
            .expect("account lookup")
            .expect("account was just saved")
            .pk;
        let session = SessionIdentityState {
            token_hash: crate::routing::identity::auth::session_credential_hash(
                "stream-test",
                state.service_id(),
            ),
            account_pk: Some(account_pk),
            actor: TEST_ACTOR_CORE.to_owned(),
            device_id: "ak:device:0196419b-0000-7000-8000-000000000001".to_owned(),
            audience: state.service_id().clone(),
            session_public_key: None,
            agent_session: None,
            session_grant: None,
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            created_at: Utc::now(),
            revoked_at: None,
        };
        state
            .identities()
            .save_device(soland_services::identity::SaveDeviceCommand {
                actor_id: session.actor.clone(),
                device_id: session.device_id.clone(),
                display_name: None,
                device: soland_services::identity::DeviceIdentity {
                    actor_id: session.actor.clone(),
                    device_id: session.device_id.clone(),
                    display_name: None,
                    verification_state: "verified".to_owned(),
                    payload: json!({"device_id": session.device_id}),
                    created_at: session.created_at,
                    updated_at: session.created_at,
                    revoked_at: None,
                },
            })
            .await
            .unwrap();
        state
            .sessions()
            .create_session(session.clone())
            .await
            .unwrap();
        session
    }

    async fn stream_test_response(state: &AppState, after: Option<&str>) -> Response {
        let actor = selector_at(state.service_id()).to_string();
        let mut url = url::Url::parse("http://server/").unwrap();
        url.query_pairs_mut()
            .extend_pairs([("actor_ids", actor.as_str()), ("max_duration_ms", "60000")]);
        if let Some(after) = after {
            url.query_pairs_mut()
                .extend_pairs([("catchup", "true"), ("after", after)]);
        }
        let router = salvo::Router::new()
            .hoop(salvo::affix_state::inject(state.clone()))
            .get(events_subscribe);
        salvo::test::TestClient::get(url.as_str())
            .add_header("authorization", "Bearer stream-test", true)
            .send(&salvo::Service::new(router))
            .await
    }

    async fn next_stream_test_frame(response: &mut Response) -> Value {
        let frame = response.body.next().await.unwrap().unwrap();
        serde_json::from_slice(&frame.into_data().unwrap()).unwrap()
    }

    #[tokio::test]
    async fn events_stream_closes_at_original_session_expiry() {
        let state = stream_test_state();
        let mut session = stream_test_session(&state).await;
        session.expires_at = Utc::now() + chrono::Duration::seconds(1);
        state
            .sessions()
            .create_session(session.clone())
            .await
            .unwrap();
        assert_eq!(
            events_subscribe_wait(Some(&session), session.expires_at, 60_000),
            Duration::ZERO
        );
        let mut response = stream_test_response(&state, None).await;
        let frame = tokio::time::timeout(
            Duration::from_secs(3),
            next_stream_test_frame(&mut response),
        )
        .await
        .expect("session expiry must close an idle stream before its requested duration");
        assert_eq!(frame["kind"], "unauthorized", "{frame}");
        assert!(
            Utc::now() >= session.expires_at,
            "a current session must not be rejected before expiry",
        );
        assert!(response.body.next().await.is_none());
    }

    #[tokio::test]
    async fn actor_catchup_stops_when_session_is_revoked_between_frames() {
        let state = stream_test_state();
        let session = stream_test_session(&state).await;
        let actor = selector_at(state.service_id());
        let created_at = Utc::now() - chrono::Duration::minutes(1);
        let mut ids = Vec::new();
        for index in 0..3 {
            let mut event = arkret_wire::test_support::raw_event_for_actor_at(
                arkret_wire::EventKind::ProfileUpdate.as_str(),
                arkret_wire::ScopeRef::Realm {
                    realm_id: RealmId::new(TEST_REALM).unwrap(),
                },
                actor.clone(),
                index as u64 + 1,
                arkret_wire::Hlc::new(format!("019f00000000-000{index}-00000001")).unwrap(),
                json!({"display_name": format!("profile {index}")}),
                created_at + chrono::Duration::seconds(index),
            )
            .unwrap();
            crate::test_event::attach_fixture_producer_proof(
                &mut event,
                arkret_wire::DidUrl::new(format!("{TEST_ACTOR}#device-key")).unwrap(),
            );
            put_durable_event(
                &state,
                event.event_id.as_str(),
                event.kind.as_str(),
                serde_json::to_value(&event).unwrap(),
                event.created_at,
            )
            .await;
            ids.push(event.event_id.to_string());
        }
        let digest = events_subscribe_filter_digest(&[], &BTreeSet::from([actor.to_string()]));
        let after = sync_token_for_events_query(&state, Some(&session), &digest, &ids[0]).await;
        let mut response = stream_test_response(&state, Some(&after)).await;
        let first = next_stream_test_frame(&mut response).await;
        assert_eq!(first["kind"], "event", "{first}");
        assert_eq!(first["payload"]["event_id"], ids[1]);
        state
            .sessions()
            .revoke_session(&session.token_hash, Utc::now())
            .await
            .unwrap();
        let next = next_stream_test_frame(&mut response).await;
        assert_eq!(
            next["kind"], "unauthorized",
            "revoked catch-up must not expose the next event: {next}"
        );
        assert!(response.body.next().await.is_none());
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
        assert!(
            projection_matches_actor_selectors(
                &state,
                &row,
                &BTreeSet::from([event.actor_id.to_string()])
            )
            .await
            .unwrap()
        );
        let wrong_station = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            event.actor_id.signing_principal_id().clone(),
            arkret_wire::DidCoreId::new("ak:did_core:web:wrong-station.example").unwrap(),
        ));
        assert!(
            !projection_matches_actor_selectors(
                &state,
                &row,
                &BTreeSet::from([wrong_station.to_string()])
            )
            .await
            .unwrap()
        );
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
        let actor_id = event.actor_id.to_string();
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
    async fn actor_catchup_reads_canonical_control_history_without_projection_rows() {
        let state = test_state();
        let first_actor = selector_at("ak:did_core:web:station-a.example");
        let other_actor = selector_at("ak:did_core:web:station-b.example");
        let created_at: DateTime<Utc> = "2026-08-31T00:00:00.000Z".parse().unwrap();
        let mut ids = Vec::new();
        for (index, actor) in [first_actor.clone(), other_actor, first_actor.clone()]
            .into_iter()
            .enumerate()
        {
            let mut event = arkret_wire::test_support::raw_event_for_actor_at(
                arkret_wire::EventKind::ProfileUpdate.as_str(),
                arkret_wire::ScopeRef::Realm {
                    realm_id: RealmId::new(TEST_REALM).unwrap(),
                },
                actor,
                index as u64 + 1,
                arkret_wire::Hlc::new(format!("019f00000000-000{index}-00000001")).unwrap(),
                json!({"display_name": format!("profile {index}")}),
                created_at + chrono::Duration::seconds(index as i64),
            )
            .unwrap();
            crate::test_event::attach_fixture_producer_proof(
                &mut event,
                arkret_wire::DidUrl::new(format!("{TEST_ACTOR}#device-key")).unwrap(),
            );
            put_durable_event(
                &state,
                event.event_id.as_str(),
                event.kind.as_str(),
                serde_json::to_value(&event).unwrap(),
                created_at + chrono::Duration::seconds(index as i64),
            )
            .await;
            ids.push(event.event_id.to_string());
        }
        let actors = BTreeSet::from([first_actor.to_string()]);
        let (events, has_more) = actor_subscription_replay(&state, &actors, Some(&ids[0]))
            .await
            .unwrap()
            .unwrap();
        assert!(!has_more);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id.as_str(), ids[2]);
        assert_eq!(events[0].actor_id, first_actor);
        assert!(
            actor_subscription_replay(&state, &actors, Some(&ids[1]))
                .await
                .is_err()
        );
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

        let page = crate::routing::events::projection::projected_event_page_for_realms_through(
            &state,
            &BTreeSet::from([TEST_REALM.to_owned()]),
            None,
            None,
            100,
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

fn canonical_record_actor_key(
    record: &soland_services::events::AcceptedEvent,
) -> Result<String, soland_http::error::AppError> {
    let actor: arkret_wire::ActorId = serde_json::from_value(
        record
            .envelope
            .get("actor_id")
            .cloned()
            .unwrap_or(Value::Null),
    )
    .map_err(|error| {
        soland_http::error::AppError::internal(format!("canonical Event actor is invalid: {error}"))
    })?;
    let key = actor.to_string();
    if key != record.actor_id {
        return Err(soland_http::error::AppError::internal(
            "canonical Event actor index differs from its signed identity",
        ));
    }
    Ok(key)
}

async fn canonical_events_for_actor_selectors(
    state: &AppState,
    actors: &BTreeSet<String>,
) -> Result<Vec<soland_services::events::AcceptedEvent>, soland_http::error::AppError> {
    let all_records = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| {
            soland_http::error::AppError::internal(format!("canonical Event scan failed: {error}"))
        })?;
    let roots = all_records
        .iter()
        .filter(|record| actors.contains(&record.actor_id))
        .map(|record| record.event_id.clone())
        .collect();
    let depths = soland_services::events::canonical_event_depths(&all_records, &roots)
        .map_err(soland_http::error::AppError::internal)?;
    let mut records = Vec::new();
    for record in all_records {
        if !actors.contains(&record.actor_id) {
            continue;
        }
        let event = super::super::event_log::canonical_event_for_read(&record)?;
        records.push((record, event.hlc));
    }
    records.sort_by(|(left, lh), (right, rh)| {
        depths[&left.event_id]
            .cmp(&depths[&right.event_id])
            .then_with(|| lh.is_none().cmp(&rh.is_none()))
            .then_with(|| lh.cmp(rh))
            .then_with(|| left.actor_id.cmp(&right.actor_id))
            .then_with(|| left.actor_seq.cmp(&right.actor_seq))
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    Ok(records.into_iter().map(|(record, _)| record).collect())
}

/// Capture durable actor history after the live receiver is installed. This
/// snapshot is shared by HTTP and WebSocket; no projection row is required.
pub(crate) async fn actor_subscription_replay(
    state: &AppState,
    actors: &BTreeSet<String>,
    after: Option<&str>,
) -> Result<Option<(Vec<arkret_wire::Event>, bool)>, soland_http::error::AppError> {
    let Some(after) = after else {
        return Ok(None);
    };
    let records = canonical_events_for_actor_selectors(state, actors).await?;
    let start = records
        .iter()
        .position(|record| record.event_id == after)
        .ok_or_else(|| {
            soland_http::error::AppError::param_invalid("actor replay cursor is unavailable")
                .with_reason_code(arkret_wire::ReasonCode::INVALID_CURSOR)
        })?
        + 1;
    let has_more = records.len().saturating_sub(start) > EVENTS_CATCHUP_LIMIT;
    let events = records
        .iter()
        .skip(start)
        .take(EVENTS_CATCHUP_LIMIT)
        .map(|record| super::super::event_log::sdk_event_for_state(state, record))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some((events, has_more)))
}

async fn durable_events_query_from_parts(
    state: &AppState,
    session: &SessionIdentityState,
    parts: &EventsQueryParts,
    cursor: Option<&str>,
    stop_cursor: Option<&str>,
    backward: bool,
    filter_digest: &str,
) -> Result<EventsQueryOutcome, soland_http::error::AppError> {
    let actors_set = parts.actors.iter().cloned().collect();
    // Exact holder/Agent authority was checked before this call.
    // Personal blocklists are presentation state, not canonical-log filters.
    let records = canonical_events_for_actor_selectors(state, &actors_set).await?;
    let after = if backward { stop_cursor } else { cursor };
    let before = if parts.before.is_some() {
        if backward { cursor } else { stop_cursor }
    } else {
        None
    };
    let ids: Vec<_> = records
        .iter()
        .map(|record| record.event_id.as_str())
        .collect();
    let (indices, has_more) = canonical_query_page(&ids, after, before, backward, parts.limit)?;
    let page: Vec<_> = indices.iter().map(|index| &records[*index]).collect();
    let mut events = Vec::with_capacity(page.len());
    for record in &page {
        events.push(super::super::event_log::canonical_event_read_row(state, record).await?);
    }
    let older = indices.iter().min().map(|index| ids[*index]);
    let newer = indices.iter().max().map(|index| ids[*index]).or(after);
    let prev_cursor = if has_more {
        match older.or(after) {
            Some(id) => {
                Some(sync_token_for_events_query(state, Some(session), filter_digest, id).await)
            }
            None => None,
        }
    } else {
        None
    };
    let next_cursor = match newer {
        Some(id) => {
            Some(sync_token_for_events_query(state, Some(session), filter_digest, id).await)
        }
        None => None,
    };
    Ok(EventsQueryOutcome {
        events,
        snapshot_bootstrap: None,
        next_cursor,
        prev_cursor,
        has_more,
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
        .map_err(|(_status, code, message)| {
            let typed = soland_http::error::ErrorCode::from_wire(code)
                .unwrap_or(soland_http::error::ErrorCode::Unauthenticated);
            soland_http::error::AppError::from_rejection(typed, message)
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
                crate::app_error!(SnapshotUnavailable, error.message,)
            }
        })?;
    soland_http::result::json_ok(manifest)
}
