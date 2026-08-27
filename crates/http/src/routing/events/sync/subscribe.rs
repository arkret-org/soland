//! Account-aggregate describe + long-lived subscribe stream
//! (`ak.self.account.stream.subscribe`): the timeline / account-data /
//! to_device NDJSON delta machinery and its auth-material gate.

use super::*;

#[endpoint(operation_id = "ak.self.account.read.describe")]
#[tracing::instrument(skip_all, fields(op = "ak.self.account.read.describe"))]
pub(super) async fn account_describe(
    depot: &mut Depot,
) -> soland_http::result::JsonResult<arkret_models_discovery::ServiceDescribe> {
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
    let query_token = query.is_some_and(arkret_wire::contains_query_auth_material);
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
) -> Option<Option<SessionIdentityState>> {
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
) -> Option<SessionIdentityState> {
    match authenticated_session(state, req).await {
        Ok(session) => Some(session),
        Err((status, code, message)) => {
            render_error(res, status, code, message);
            None
        }
    }
}

#[handler]
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
    let wait_for_event_id =
        if let Ok(wait_for) = depot.get_typed::<soland_http::openapi_routes::WaitForSyncToken>() {
            match parse_and_validate_barrier_cursor(
                &wait_for.0,
                &state,
                &session,
                chrono::Utc::now().timestamp_millis(),
            )
            .await
            {
                Ok(event_id) => Some(event_id),
                Err(error) => {
                    render_account_cursor_error(res, error, true);
                    return;
                }
            }
        } else {
            None
        };
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
                // encoding.md §8.3 closed set: syntax/schema failures pin the
                // top-level `param_invalid` code with reason `invalid_cursor`.
                soland_http::error::render_error_with_reason_code(
                    res,
                    soland_http::error::error_http_status(
                        soland_http::error::ErrorCode::ParamInvalid,
                    ),
                    soland_http::error::ErrorCode::ParamInvalid.as_str(),
                    message,
                    arkret_wire::ReasonCode::INVALID_CURSOR,
                    None,
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
            .sync()
            .prune_superseded_cursors(
                &session.actor,
                &session.device_id,
                &sync_filter_digest(filter_value.as_ref()),
                presented_issued_at_ms,
            )
            .await;
    }
    // client-sync.md: the account subscribe surface is read-only. Transient
    // state is not carried here at all in v1 — presence, typing, receipts and
    // call signalling are encrypted Signals on `ak.self.signal.*`, so no
    // `set_presence`-style subscribe parameter exists and establishing or
    // replaying a subscription never triggers a server-side mutation.

    // Subscribe to broadcast BEFORE checking the barrier/building the initial snapshot so an
    // event landing between snapshot-build and long-poll subscribe is not
    // missed.
    let mut rx = state.subscribe_event_notifications();
    if let Some(event_id) = wait_for_event_id.as_deref() {
        if !wait_for_account_projection_barrier(&state, &mut rx, event_id).await {
            let current = build_sync_snapshot(&state, Some(&session), &body, &after_cursor).await;
            let envelope = arkret_wire::problem_details::ErrorEnvelope::new(
                "temporarily_unavailable",
                "account projection did not reach the requested barrier before timeout",
            )
            .with_request_id(arkret_identifiers::new_prefixed_uuid7("ak:request:"))
            .with_detail(
                "frontier",
                current.cursor.map(Value::String).unwrap_or(Value::Null),
            );
            crate::error::render_problem_envelope(res, StatusCode::SERVICE_UNAVAILABLE, envelope);
            return;
        }
        res.headers_mut().insert(
            salvo::http::header::HeaderName::from_static("x-arkret-wait-for-satisfied"),
            salvo::http::HeaderValue::from_static("true"),
        );
    }
    let response = build_sync_snapshot(&state, Some(&session), &body, &after_cursor).await;
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
                        let drain_until = tokio::time::Instant::now()
                            + Duration::from_millis(SUBSCRIBE_REBUILD_DEBOUNCE_MS);
                        let mut lagged = false;
                        loop {
                            tokio::select! {
                                _ = tokio::time::sleep_until(drain_until) => break,
                                more = rx.recv() => match more {
                                    Ok(_) => {}
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

pub(crate) fn account_frontier_frame(
    cursor: Option<String>,
) -> arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame {
    arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame {
        kind: arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrameKind::Frontier,
        cursor,
        realms: None,
        to_device: None,
        device_lists: None,
        account_data: None,
        notifications: None,
        agent_signer_evidence_bundle: None,
        partial: None,
        priority: None,
        reconnect_after_ms: None,
    }
}

pub(crate) fn account_catchup_complete_frame(
    cursor: Option<String>,
) -> arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame {
    arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame {
        kind: arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrameKind::CatchupComplete,
        cursor,
        realms: None,
        to_device: None,
        device_lists: None,
        account_data: None,
        notifications: None,
        agent_signer_evidence_bundle: None,
        partial: None,
        priority: None,
        reconnect_after_ms: None,
    }
}

/// A snapshot is "delta-empty" when an incremental sync would carry no
/// new realm state, no membership departure, no queued device messages,
/// and no queued notifications. `account_data` is intentionally excluded — it
/// is always emitted in full for authenticated sessions today, so it
/// would defeat long-poll entirely.
pub(crate) fn delta_is_empty(
    response: &arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame,
) -> bool {
    response
        .realms
        .as_ref()
        .is_none_or(|realms| realms.entries.is_empty())
        && response
            .to_device
            .as_ref()
            .is_none_or(|to_device| to_device.messages.is_empty() && to_device.lost != Some(true))
        && response
            .notifications
            .as_ref()
            .is_none_or(|notifications| notifications.items.is_empty())
}

pub(crate) async fn account_subscribe_notification_should_wake(
    state: &AppState,
    notification: &crate::state::EventNotification,
    session: Option<&SessionIdentityState>,
) -> bool {
    if let crate::state::EventNotificationKind::Account {
        account_id,
        recipient_service_id,
    } = &notification.kind
    {
        let Some(session) = session else {
            return false;
        };
        if recipient_service_id != state.service_id() {
            return false;
        }
        return state
            .identities()
            .account(&session.actor)
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
    }
}

pub(crate) async fn wait_for_account_projection_barrier(
    state: &AppState,
    rx: &mut tokio::sync::broadcast::Receiver<crate::state::EventNotification>,
    event_id: &str,
) -> bool {
    let deadline =
        tokio::time::Instant::now() + Duration::from_millis(ACCOUNT_SUBSCRIBE_DEFAULT_WAIT_MS);
    loop {
        match state.event_queries().projected_event(event_id).await {
            Ok(Some(_)) => return true,
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, event_id, "account barrier projection lookup failed");
            }
        }
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => return false,
            notification = rx.recv() => match notification {
                Ok(_) | Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => return false,
            }
        }
    }
}

fn render_account_cursor_error(res: &mut Response, error: SyncCursorError, barrier: bool) {
    let context = if barrier {
        "X-Arkret-Wait-For"
    } else {
        "after"
    };
    match error {
        SyncCursorError::Expired => soland_http::error::render_error_code(
            soland_http::error::ErrorCode::CursorExpired,
            res,
            &format!("{context} cursor has expired"),
        ),
        // encoding.md §8.3 closed set: syntax/schema failures pin the top-level
        // `param_invalid` code with reason `invalid_cursor`.
        SyncCursorError::Invalid(message) => soland_http::error::render_error_with_reason_code(
            res,
            soland_http::error::error_http_status(soland_http::error::ErrorCode::ParamInvalid),
            soland_http::error::ErrorCode::ParamInvalid.as_str(),
            message,
            arkret_wire::ReasonCode::INVALID_CURSOR,
            None,
        ),
        SyncCursorError::Mismatch(message) | SyncCursorError::Integrity(message) => {
            soland_http::error::render_error_code(
                soland_http::error::ErrorCode::CursorIntegrityInvalid,
                res,
                message,
            )
        }
        SyncCursorError::Revoked => soland_http::error::render_error_code(
            soland_http::error::ErrorCode::CursorRevoked,
            res,
            &format!("{context} cursor authority has been revoked"),
        ),
    }
}

pub(crate) fn sync_filter_value(
    filter: Option<&arkret_models_collaboration::sync_frames::client_sync::SyncFilter>,
) -> Option<Value> {
    filter.and_then(|filter| serde_json::to_value(filter).ok())
}

fn account_reconnect_control_frame(
    after: Option<&str>,
    _reason: impl Into<String>,
    reconnect_after_ms: u64,
) -> arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame {
    let (kind, cursor) = match after {
        Some(cursor) if !cursor.is_empty() => (
            arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrameKind::Dropped,
            Some(cursor.to_owned()),
        ),
        _ => (arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrameKind::ResyncRequired, None),
    };
    arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame {
        kind,
        cursor,
        realms: None,
        to_device: None,
        device_lists: None,
        account_data: None,
        notifications: None,
        agent_signer_evidence_bundle: None,
        partial: None,
        priority: None,
        reconnect_after_ms: Some(reconnect_after_ms),
    }
}

fn account_subscribe_scope_key(
    req: &Request,
    session: Option<&SessionIdentityState>,
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
