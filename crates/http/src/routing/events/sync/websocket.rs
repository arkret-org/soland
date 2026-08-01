//! `ak.profile.binding.websocket.v1` endpoint (`zh/sync/websocket-binding.md`).
//!
//! One physical socket at `GET /_arkret/ws` multiplexes the three covered
//! stream operations as logical channels. Everything protocol-shaped —
//! the frames, the `challenge_dpop_session_v1` proof, the channel state
//! machine, the close-code table — comes from the SDK; this module owns only
//! the service-side wiring: Origin admission, the durable challenge record,
//! grant introspection, channel authorization and the per-channel producers.
//!
//! The producers deliberately reuse the same authorization / projection /
//! cursor helpers the canonical HTTP handlers compose. There is no second
//! Signal admission path and no second cursor minting path here; only the
//! frame pacing differs, because a WebSocket channel is long-lived where the
//! HTTP surface is a bounded long poll.
//!
//! **This endpoint is not advertised.** `ServiceDescribe.supported_bindings`
//! stays `http_json` + `tus` until `ak.suite.binding.websocket.v1` runs green
//! against a live peer (§10, and the S7-3a gate in the task spec). Serving it
//! unadvertised is exactly what that suite needs to run.

use std::collections::BTreeSet;

use arkret_models_collaboration::sync_frames::websocket_binding::{
    WebSocketChannelControlPayload, WebSocketClientFrame, WebSocketClosedReason,
    WebSocketConnectionLimits, WebSocketDataPayload, WebSocketOpenParameters, WebSocketServerFrame,
};
use arkret_models_collaboration::sync_frames::websocket_session::{
    WebSocketConnectionState, WebSocketFrameCodec, WebSocketOpenAdmission, WebSocketRejection,
};
use arkret_signatures::websocket_auth::{
    WebSocketAuthVerificationRequest, verify_websocket_auth_proof,
};
use arkret_wire::websocket_binding::{
    WEBSOCKET_AUTHENTICATION_DEADLINE_MS, WEBSOCKET_REPLAY_LEDGER_RETENTION_SECONDS,
    WEBSOCKET_SUBPROTOCOL, WebSocketChallengeRecord, WebSocketCloseCode, WebSocketOperationId,
    WebSocketTransportError, canonical_http_origin, validate_websocket_base_url,
};
use arkret_wire::{ErrorCode as WireErrorCode, ServiceOperationId};
use salvo::websocket::{Message, WebSocket, WebSocketUpgrade};
use soland_services::sync::{WebsocketChallengeState, WebsocketReplayState};
use tokio::sync::mpsc;

use super::*;

/// Limits this deployment advertises in `welcome`. `max_frame_bytes` matches
/// the descriptor §2 shows; the pending ceilings are what §7 requires the
/// service to bound independently per connection and per channel.
const WS_MAX_FRAME_BYTES: u32 = 262_144;
const WS_MAX_CHANNELS: u32 = 16;
const WS_MAX_CONNECTION_PENDING_BYTES: u64 = 4 * 1024 * 1024;
const WS_MAX_CHANNEL_PENDING_BYTES: u64 = 1024 * 1024;
const WS_MAX_CONNECTION_PENDING_FRAMES: u32 = 512;
const WS_MAX_CHANNEL_PENDING_FRAMES: u32 = 128;
const WS_HEARTBEAT_INTERVAL_MS: u32 = 30_000;
/// Poll cadence of the Signal channel, matching the HTTP Signal rail.
const WS_SIGNAL_POLL_MS: u64 = 250;
/// Debounce for account rebuilds, matching the HTTP long-poll handler.
const WS_ACCOUNT_DEBOUNCE_MS: u64 = 150;
/// Path segment under `/_arkret`.
pub(crate) const WS_PATH_SEGMENT: &str = "ws";

fn connection_limits() -> WebSocketConnectionLimits {
    WebSocketConnectionLimits {
        max_frame_bytes: WS_MAX_FRAME_BYTES,
        max_channels: WS_MAX_CHANNELS,
        max_connection_pending_bytes: WS_MAX_CONNECTION_PENDING_BYTES,
        max_channel_pending_bytes: WS_MAX_CHANNEL_PENDING_BYTES,
        max_connection_pending_frames: WS_MAX_CONNECTION_PENDING_FRAMES,
        max_channel_pending_frames: WS_MAX_CHANNEL_PENDING_FRAMES,
        heartbeat_interval_ms: WS_HEARTBEAT_INTERVAL_MS,
    }
}

/// The canonical `wss` discovery `base_url` this deployment would advertise,
/// or `None` when the configured public base URL cannot produce one.
///
/// A deployment served over plain HTTP has no canonical form (§2 fixes the
/// scheme to `wss`), so it simply has no WebSocket binding.
pub(crate) fn websocket_base_url(state: &AppState) -> Option<String> {
    let public = state.config().public_base_url.trim_end_matches('/');
    let authority = public
        .strip_prefix("https://")
        .or_else(|| public.strip_prefix("wss://"))?;
    let candidate = format!("wss://{authority}/_arkret/{WS_PATH_SEGMENT}");
    validate_websocket_base_url(&candidate).ok()?;
    Some(candidate)
}

/// The exact origins §3 admits. A wildcard CORS configuration is deliberately
/// **not** an allow-list: this profile has no origin-less bypass, so a
/// deployment that has not named its browser origins accepts no WebSocket.
fn allowed_origins(state: &AppState) -> BTreeSet<String> {
    state
        .config()
        .cors_allow_origin
        .as_deref()
        .into_iter()
        .flat_map(|value| value.split(','))
        .filter_map(|origin| canonical_http_origin(origin.trim()).ok())
        .collect()
}

/// §3 step 2–3: exactly one syntactically valid `Origin`, canonicalised, and
/// exactly a member of the allow-list.
fn admitted_origin(state: &AppState, req: &Request) -> Option<String> {
    let mut values = req.headers().get_all(salvo::http::header::ORIGIN).iter();
    let origin = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let canonical = canonical_http_origin(origin).ok()?;
    allowed_origins(state)
        .contains(&canonical)
        .then_some(canonical)
}

/// A 192-bit opaque id. §3.1 requires at least 128 bits of entropy in both
/// `connection_id` and `nonce`; the base64url form is 32 characters, inside the
/// frame schema's 22..128 window.
fn random_opaque_id() -> String {
    let mut bytes = [0_u8; 24];
    rand::fill(&mut bytes);
    arkret_canonical::base64url_encode(bytes)
}

/// `GET /_arkret/ws` — the WebSocket binding endpoint.
#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.profile.binding.websocket.v1"))]
pub(crate) async fn websocket_subscribe(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot
        .get_typed::<AppState>()
        .expect("state injected")
        .clone();
    let Some(base_url) = websocket_base_url(&state) else {
        render_error(
            res,
            StatusCode::NOT_FOUND,
            "not_found",
            "this deployment publishes no WebSocket binding",
        );
        return;
    };
    let Some(origin) = admitted_origin(&state, req) else {
        // §3 — a missing, duplicated, `null` or unlisted Origin is refused
        // before the upgrade; there is no native bypass.
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "origin is not admitted for the WebSocket binding",
        );
        return;
    };

    let upgrade = WebSocketUpgrade::new()
        .protocols(&[WEBSOCKET_SUBPROTOCOL])
        .max_message_size(WS_MAX_FRAME_BYTES as usize);
    if let Err(error) = upgrade
        .upgrade(req, res, move |socket| async move {
            serve_connection(state, base_url, origin, socket).await;
        })
        .await
    {
        tracing::debug!(%error, "WebSocket upgrade failed");
    }
}

/// One frame queued for the writer, with the fairness class §7 requires.
struct OutboundFrame {
    frame: WebSocketServerFrame,
    /// Signal frames may be dropped under pressure; durable frames may not.
    droppable: bool,
}

#[derive(Clone)]
struct ChannelSender {
    durable: mpsc::Sender<OutboundFrame>,
    signal: mpsc::Sender<OutboundFrame>,
}

impl ChannelSender {
    async fn send_durable(&self, frame: WebSocketServerFrame) -> bool {
        self.durable
            .send(OutboundFrame {
                frame,
                droppable: false,
            })
            .await
            .is_ok()
    }

    /// §7 — at the Signal queue limit the Signal is dropped rather than
    /// evicting a durable account / events frame.
    fn try_send_signal(&self, frame: WebSocketServerFrame) -> bool {
        self.signal
            .try_send(OutboundFrame {
                frame,
                droppable: true,
            })
            .is_ok()
    }
}

async fn serve_connection(
    state: AppState,
    base_url: String,
    origin: String,
    mut socket: WebSocket,
) {
    let codec = WebSocketFrameCodec::new(WS_MAX_FRAME_BYTES, None);
    let connection_id = random_opaque_id();
    let nonce = random_opaque_id();
    let issued_at = chrono::Utc::now();
    let expires_at =
        issued_at + chrono::Duration::milliseconds(WEBSOCKET_AUTHENTICATION_DEADLINE_MS as i64);
    let retain_until =
        expires_at + chrono::Duration::seconds(WEBSOCKET_REPLAY_LEDGER_RETENTION_SECONDS as i64);

    // §3.1 — the challenge record is written atomically BEFORE the frame goes
    // out, so a proof can never race ahead of the state it is bound to.
    if state
        .sync()
        .websocket_auth()
        .prepare_challenge(&WebsocketChallengeState {
            connection_id: connection_id.clone(),
            nonce: nonce.clone(),
            canonical_origin: origin.clone(),
            canonical_base_url: base_url.clone(),
            issued_at,
            expires_at,
            consumed: false,
            retain_until,
        })
        .await
        .is_err()
    {
        close_with(&mut socket, WebSocketCloseCode::InternalError, "challenge").await;
        return;
    }

    let challenge = WebSocketServerFrame::Challenge {
        connection_id: connection_id.clone(),
        nonce: nonce.clone(),
        expires_at,
    };
    if !send_frame(&mut socket, &codec, &challenge).await {
        return;
    }

    let session = match authenticate(
        &state,
        &mut socket,
        &codec,
        &connection_id,
        &nonce,
        &origin,
        &base_url,
    )
    .await
    {
        Some(session) => session,
        None => return,
    };

    let limits = connection_limits();
    let mut connection = WebSocketConnectionState::new(connection_id.clone(), limits);
    connection.authenticated();
    let welcome =
        match WebSocketServerFrame::welcome(connection_id.clone(), limits, session.expires_at) {
            Ok(welcome) => welcome,
            Err(_) => {
                close_with(&mut socket, WebSocketCloseCode::InternalError, "welcome").await;
                return;
            }
        };
    if !send_frame(&mut socket, &codec, &welcome).await {
        return;
    }

    run_multiplex(state, socket, codec, connection, session).await;
}

/// §3 / §3.1 — read the single `authenticate` frame inside the deadline and
/// decide it against the stored challenge and the presented grant.
async fn authenticate(
    state: &AppState,
    socket: &mut WebSocket,
    codec: &WebSocketFrameCodec,
    connection_id: &str,
    nonce: &str,
    origin: &str,
    base_url: &str,
) -> Option<SessionRecord> {
    let deadline = tokio::time::Duration::from_millis(WEBSOCKET_AUTHENTICATION_DEADLINE_MS);
    let Ok(Some(Ok(message))) = tokio::time::timeout(deadline, socket.recv()).await else {
        close_with(socket, WebSocketCloseCode::PolicyViolation, "auth").await;
        return None;
    };
    let Some(bytes) = text_payload(&message) else {
        close_with(socket, WebSocketCloseCode::ProtocolError, "frame").await;
        return None;
    };
    let frame = match codec.decode_client_frame(bytes) {
        Ok(frame) => frame,
        Err(rejection) => {
            close_rejection(socket, &rejection).await;
            return None;
        }
    };
    let WebSocketClientFrame::Authenticate {
        connection_id: presented_connection_id,
        session_grant,
        dpop_proof,
    } = &frame
    else {
        close_with(socket, WebSocketCloseCode::ProtocolError, "state").await;
        return None;
    };
    if frame.validate().is_err() {
        close_with(socket, WebSocketCloseCode::ProtocolError, "frame").await;
        return None;
    }

    // The grant is introspected fresh: a WebSocket outlives a request, so a
    // cached "active" answer is not an acceptable basis for a long-lived
    // authorization.
    let Ok(grant) = crate::routing::identity::auth_grant_dpop::introspect_session_grant_cached(
        state,
        session_grant,
        true,
    )
    .await
    else {
        close_with(socket, WebSocketCloseCode::PolicyViolation, "grant").await;
        return None;
    };
    let Some(cnf_jkt) = grant.cnf_jkt.clone().filter(|jkt| !jkt.is_empty()) else {
        close_with(socket, WebSocketCloseCode::PolicyViolation, "grant").await;
        return None;
    };

    let Ok(Some(challenge)) = state
        .sync()
        .websocket_auth()
        .challenge(connection_id, nonce)
        .await
    else {
        close_with(socket, WebSocketCloseCode::PolicyViolation, "challenge").await;
        return None;
    };
    let record = WebSocketChallengeRecord {
        connection_id: challenge.connection_id.clone(),
        nonce: challenge.nonce.clone(),
        canonical_origin: challenge.canonical_origin.clone(),
        canonical_base_url: challenge.canonical_base_url.clone(),
        issued_at: challenge.issued_at,
        expires_at: challenge.expires_at,
        consumed: challenge.consumed,
    };
    let verified = match verify_websocket_auth_proof(&WebSocketAuthVerificationRequest {
        compact_jws: dpop_proof,
        connection_id: presented_connection_id,
        session_grant,
        socket_origin: origin,
        challenge: &record,
        grant_cnf_jkt: &cnf_jkt,
        // `jti` only becomes known once the proof parses, so the ledger check
        // is the atomic `consume_challenge` below rather than a pre-read.
        replay_ledger_hit: false,
        now: chrono::Utc::now(),
    }) {
        Ok(verified) => verified,
        Err(error) => {
            tracing::debug!(%error, "WebSocket authenticate rejected");
            close_with(socket, WebSocketCloseCode::PolicyViolation, "proof").await;
            return None;
        }
    };
    if record.canonical_base_url != base_url {
        close_with(socket, WebSocketCloseCode::PolicyViolation, "target").await;
        return None;
    }

    // §3.1 — consume the challenge and write `(cnf.jkt, jti, context)` in one
    // atomic step. A `false` here is a replay, not an error.
    let consumed = state
        .sync()
        .websocket_auth()
        .consume_challenge(
            connection_id,
            nonce,
            &WebsocketReplayState {
                cnf_jkt: verified.replay_ledger_key.cnf_jkt.clone(),
                jti: verified.replay_ledger_key.jti.clone(),
                proof_context: verified.replay_ledger_key.context.clone(),
                consumed_at: chrono::Utc::now(),
                retain_until: chrono::Utc::now()
                    + chrono::Duration::seconds(WEBSOCKET_REPLAY_LEDGER_RETENTION_SECONDS as i64),
            },
        )
        .await
        .unwrap_or(false);
    if !consumed {
        // §3.1 keeps both records for at least the retention window precisely
        // so this distinction survives: a present ledger key is a replay, an
        // absent one is an unknown / already-expired challenge.
        let replayed = state
            .sync()
            .websocket_auth()
            .replay_ledger_contains(
                &verified.replay_ledger_key.cnf_jkt,
                &verified.replay_ledger_key.jti,
                &verified.replay_ledger_key.context,
            )
            .await
            .unwrap_or(false);
        tracing::debug!(
            replayed,
            "WebSocket authenticate did not consume its challenge"
        );
        close_with(socket, WebSocketCloseCode::PolicyViolation, "replay").await;
        return None;
    }

    let Ok((device_id, agent_session)) =
        crate::routing::identity::auth_grant_dpop::grant_session_binding(&grant)
    else {
        close_with(socket, WebSocketCloseCode::PolicyViolation, "grant").await;
        return None;
    };
    Some(
        crate::routing::identity::auth_grant_dpop::session_from_verified_grant(
            state,
            session_grant,
            grant,
            device_id,
            agent_session,
        ),
    )
}

/// §4–§7 — the multiplexed read / write loop.
async fn run_multiplex(
    state: AppState,
    socket: WebSocket,
    codec: WebSocketFrameCodec,
    mut connection: WebSocketConnectionState,
    session: SessionRecord,
) {
    use futures_util::{SinkExt, StreamExt};

    let (mut sink, mut stream) = socket.split();
    let (durable_tx, mut durable_rx) =
        mpsc::channel::<OutboundFrame>(WS_MAX_CONNECTION_PENDING_FRAMES as usize);
    let (signal_tx, mut signal_rx) =
        mpsc::channel::<OutboundFrame>(WS_MAX_CHANNEL_PENDING_FRAMES as usize);
    let sender = ChannelSender {
        durable: durable_tx,
        signal: signal_tx,
    };
    let mut producers: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    let mut heartbeat = tokio::time::interval(tokio::time::Duration::from_millis(
        WS_HEARTBEAT_INTERVAL_MS as u64,
    ));
    heartbeat.tick().await;
    let mut close_code: Option<WebSocketCloseCode> = None;

    loop {
        tokio::select! {
            // §7 — durable account / events traffic is drained before Signal,
            // so a Signal burst can never starve cursor progress.
            biased;
            Some(outbound) = durable_rx.recv() => {
                if !write_frame(&mut sink, &codec, &outbound.frame).await {
                    break;
                }
            }
            Some(outbound) = signal_rx.recv() => {
                debug_assert!(outbound.droppable);
                if !write_frame(&mut sink, &codec, &outbound.frame).await {
                    break;
                }
            }
            _ = heartbeat.tick() => {
                let ping = WebSocketServerFrame::Ping {
                    ping_id: random_opaque_id(),
                    sent_at: chrono::Utc::now(),
                };
                if !write_frame(&mut sink, &codec, &ping).await {
                    break;
                }
            }
            incoming = stream.next() => {
                let Some(Ok(message)) = incoming else {
                    break;
                };
                if message.is_close() {
                    break;
                }
                if message.is_ping() || message.is_pong() {
                    continue;
                }
                let Some(bytes) = text_payload(&message) else {
                    close_code = Some(WebSocketCloseCode::ProtocolError);
                    break;
                };
                let frame = match codec.decode_client_frame(bytes) {
                    Ok(frame) => frame,
                    Err(rejection) => {
                        close_code = rejection.close_code;
                        break;
                    }
                };
                match handle_client_frame(
                    &state,
                    &session,
                    &mut connection,
                    &sender,
                    &mut producers,
                    frame,
                )
                .await
                {
                    Ok(()) => {}
                    Err(rejection) => {
                        if let Some(code) = rejection.close_code {
                            close_code = Some(code);
                            break;
                        }
                        // Channel-scoped: `error` then `closed`, connection open.
                        if let Some(channel_id) = rejection.channel_id.clone() {
                            let error = WebSocketServerFrame::channel_error(
                                channel_id.clone(),
                                rejection.error.clone(),
                            );
                            if !write_frame(&mut sink, &codec, &error).await {
                                break;
                            }
                            let closed = WebSocketServerFrame::Closed {
                                channel_id: channel_id.clone(),
                                reason: WebSocketClosedReason::Error,
                            };
                            if !write_frame(&mut sink, &codec, &closed).await {
                                break;
                            }
                            connection.close_channel(&channel_id);
                        }
                    }
                }
            }
            else => break,
        }
    }

    for producer in producers {
        producer.abort();
    }
    connection.closed();
    let code = close_code.unwrap_or(WebSocketCloseCode::Normal);
    let _ = sink.send(Message::close_with(code.as_u16(), "")).await;
}

async fn handle_client_frame(
    state: &AppState,
    session: &SessionRecord,
    connection: &mut WebSocketConnectionState,
    sender: &ChannelSender,
    producers: &mut Vec<tokio::task::JoinHandle<()>>,
    frame: WebSocketClientFrame,
) -> Result<(), WebSocketRejection> {
    match &frame {
        WebSocketClientFrame::Pong { .. } => Ok(()),
        WebSocketClientFrame::Authenticate { .. } => Err(protocol_rejection(
            "a second authenticate is not part of the connection lifecycle",
        )),
        WebSocketClientFrame::Close { channel_id, .. } => {
            connection.close_channel(channel_id);
            let closed = WebSocketServerFrame::Closed {
                channel_id: channel_id.clone(),
                reason: WebSocketClosedReason::ClientRequest,
            };
            sender.send_durable(closed).await;
            Ok(())
        }
        WebSocketClientFrame::Open {
            channel_id,
            operation_id,
            ..
        } => {
            let parameters = frame
                .open_parameters()
                .map_err(|error| channel_rejection(channel_id, &error.to_string()))?;
            // §5 — operation authorization is re-run per channel: an
            // authenticated connection is not an authorized subscription.
            if let Err(error) =
                super::super::require_agent_session_scope(session, operation_scope(*operation_id))
            {
                return Err(channel_rejection(channel_id, &error.message));
            }
            match connection
                .admit_open(&frame)
                .map_err(|error| channel_rejection(channel_id, &error.to_string()))?
            {
                WebSocketOpenAdmission::Opened {
                    channel_id,
                    operation,
                } => {
                    let opened = WebSocketServerFrame::Opened {
                        channel_id: channel_id.clone(),
                        operation_id: operation,
                    };
                    sender.send_durable(opened).await;
                    producers.push(spawn_producer(
                        state.clone(),
                        session.clone(),
                        sender.clone(),
                        channel_id,
                        parameters,
                    ));
                    Ok(())
                }
                WebSocketOpenAdmission::Conflict(rejection)
                | WebSocketOpenAdmission::RateLimited(rejection) => Err(rejection),
            }
        }
    }
}

fn operation_scope(operation: WebSocketOperationId) -> &'static str {
    match operation {
        WebSocketOperationId::AccountStreamSubscribe => {
            ServiceOperationId::SELF_ACCOUNT_STREAM_SUBSCRIBE
        }
        WebSocketOperationId::EventsStreamSubscribe => {
            ServiceOperationId::SELF_EVENTS_STREAM_SUBSCRIBE
        }
        WebSocketOperationId::SignalStreamSubscribe => {
            ServiceOperationId::SELF_SIGNAL_STREAM_SUBSCRIBE
        }
    }
}

fn spawn_producer(
    state: AppState,
    session: SessionRecord,
    sender: ChannelSender,
    channel_id: String,
    parameters: WebSocketOpenParameters,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        match parameters {
            WebSocketOpenParameters::Account(parameters) => {
                run_account_channel(state, session, sender, channel_id, parameters).await;
            }
            WebSocketOpenParameters::Events(parameters) => {
                run_events_channel(state, session, sender, channel_id, parameters).await;
            }
            WebSocketOpenParameters::Signal => {
                run_signal_channel(state, session, sender, channel_id).await;
            }
        }
    })
}

/// Account channel: the same snapshot / cursor machinery the HTTP long poll
/// composes, emitted continuously instead of once per request.
async fn run_account_channel(
    state: AppState,
    session: SessionRecord,
    sender: ChannelSender,
    channel_id: String,
    parameters:
        arkret_models_collaboration::sync_frames::websocket_binding::WebSocketAccountOpenParameters,
) {
    let body = SyncRequestBody {
        after: parameters
            .after
            .as_ref()
            .map(|cursor| cursor.as_str().to_owned()),
        catchup: parameters.catchup,
        filter: None,
        subscriptions: None,
    };
    let filter_value = sync_filter_value(body.filter.as_ref());
    let mut cursor = match body.after.as_deref() {
        Some(after) => {
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
                Err(_) => {
                    // §6.1 — an unusable resume point is a channel-level
                    // reconnect signal, never a connection failure.
                    let payload = WebSocketChannelControlPayload::Account(Box::new(
                        account_resync_required_frame(),
                    ));
                    if let Ok(frame) =
                        WebSocketServerFrame::channel_control(channel_id.clone(), &payload)
                    {
                        sender.send_durable(frame).await;
                    }
                    return;
                }
            }
        }
        None => SyncCursor::default(),
    };
    let mut notifications = state.subscribe_event_notifications();

    loop {
        let snapshot = build_sync_snapshot(&state, Some(&session), &body, &cursor).await;
        if delta_is_empty(&snapshot) {
            let payload = WebSocketChannelControlPayload::Account(Box::new(
                account_frontier_frame(snapshot.cursor.clone()),
            ));
            if !emit(
                &sender,
                WebSocketServerFrame::channel_control(channel_id.clone(), &payload),
            )
            .await
            {
                return;
            }
        } else {
            let payload = WebSocketDataPayload::Account(Box::new(snapshot.clone()));
            if !emit(
                &sender,
                WebSocketServerFrame::data(channel_id.clone(), &payload),
            )
            .await
            {
                return;
            }
            if body.catchup.unwrap_or(false) {
                let payload = WebSocketChannelControlPayload::Account(Box::new(
                    account_catchup_complete_frame(snapshot.cursor.clone()),
                ));
                if !emit(
                    &sender,
                    WebSocketServerFrame::channel_control(channel_id.clone(), &payload),
                )
                .await
                {
                    return;
                }
            }
            if let Some(next) = snapshot.cursor.as_deref()
                && let Ok(parsed) = parse_and_validate_sync_cursor(
                    next,
                    &state,
                    Some(&session),
                    filter_value.as_ref(),
                    chrono::Utc::now().timestamp_millis(),
                )
                .await
            {
                cursor = parsed;
            }
        }

        // Wait for a visible change, then debounce a burst into one rebuild.
        loop {
            match notifications.recv().await {
                Ok(notification) => {
                    if account_subscribe_notification_should_wake(
                        &state,
                        &notification,
                        Some(&session),
                    )
                    .await
                    {
                        break;
                    }
                }
                Err(RecvError::Lagged(_)) => break,
                Err(RecvError::Closed) => return,
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(WS_ACCOUNT_DEBOUNCE_MS)).await;
    }
}

/// Events channel: live tail over the same broadcast + visibility filter the
/// HTTP surface uses. Catch-up replay stays on `events.query.scan`, exactly as
/// the HTTP binding leaves it.
async fn run_events_channel(
    state: AppState,
    session: SessionRecord,
    sender: ChannelSender,
    channel_id: String,
    parameters:
        arkret_models_collaboration::sync_frames::websocket_binding::WebSocketEventsOpenParameters,
) {
    let mut accessible: Vec<String> = Vec::new();
    for realm in parameters.realms.into_iter().flatten() {
        let realm = realm.as_str().to_owned();
        if realm_id_accessible(&state, &realm, Some(&session)).await {
            accessible.push(realm);
        }
    }
    if accessible.is_empty() {
        let payload = WebSocketChannelControlPayload::Events(Box::new(events_unauthorized_frame()));
        if let Ok(frame) = WebSocketServerFrame::channel_control(channel_id.clone(), &payload) {
            sender.send_durable(frame).await;
        }
        return;
    }
    let realm_filter: BTreeSet<String> = accessible.iter().cloned().collect();
    let filter_digest = events_subscribe_filter_digest(&accessible);
    let mut notifications = state.subscribe_event_notifications();

    loop {
        let notification = match notifications.recv().await {
            Ok(notification) => notification,
            Err(RecvError::Lagged(_)) => {
                let payload = WebSocketChannelControlPayload::Events(Box::new(
                    events_resync_required_frame(),
                ));
                if let Ok(frame) =
                    WebSocketServerFrame::channel_control(channel_id.clone(), &payload)
                {
                    sender.send_durable(frame).await;
                }
                return;
            }
            Err(RecvError::Closed) => return,
        };
        if !realm_filter.contains(&notification.realm_id) {
            continue;
        }
        let crate::state::EventNotificationKind::Event {
            cursor,
            event_payload,
        } = notification.kind
        else {
            continue;
        };
        if !projection_event_value_visible_to_session(&state, &event_payload, Some(&session)).await
        {
            continue;
        }
        let live_cursor =
            sync_token_for_events_query(&state, Some(&session), &filter_digest, &cursor).await;
        let Some(envelope) = full_event_from_projection_json(&state, &event_payload).await else {
            let payload =
                WebSocketChannelControlPayload::Events(Box::new(events_resync_required_frame()));
            if let Ok(frame) = WebSocketServerFrame::channel_control(channel_id.clone(), &payload) {
                sender.send_durable(frame).await;
            }
            return;
        };
        let Ok(frame) = serde_json::from_value(json!({
            "kind": "event",
            "realm_id": notification.realm_id,
            "cursor": live_cursor,
            "payload": envelope,
        })) else {
            continue;
        };
        let payload = WebSocketDataPayload::Events(Box::new(frame));
        if !emit(
            &sender,
            WebSocketServerFrame::data(channel_id.clone(), &payload),
        )
        .await
        {
            return;
        }
    }
}

/// Signal channel: §6.2 — live fanout only. No cursor, no catch-up, no ack.
async fn run_signal_channel(
    state: AppState,
    session: SessionRecord,
    sender: ChannelSender,
    channel_id: String,
) {
    let mut poll = tokio::time::interval(tokio::time::Duration::from_millis(WS_SIGNAL_POLL_MS));
    loop {
        poll.tick().await;
        for envelope in super::signal::pending_signals_for_subscriber(&state, &session).await {
            let payload = WebSocketDataPayload::Signal(Box::new(
                arkret_wire::SignalStreamFrame::signal(envelope),
            ));
            let Ok(frame) = WebSocketServerFrame::data(channel_id.clone(), &payload) else {
                continue;
            };
            if !sender.try_send_signal(frame) {
                // §7 — the Signal queue is full: drop it and tell the channel
                // to reconnect. A durable frame is never evicted to make room.
                let drain = WebSocketChannelControlPayload::Signal(Box::new(
                    arkret_wire::SignalStreamFrame::Drain {
                        reconnect_after_ms: Some(SUBSCRIBE_RECONNECT_AFTER_MS),
                        reason: None,
                    },
                ));
                if let Ok(frame) = WebSocketServerFrame::channel_control(channel_id.clone(), &drain)
                {
                    sender.send_durable(frame).await;
                }
                return;
            }
        }
    }
}

/// Queue one built frame, treating a build failure the same as a closed
/// queue: the channel stops rather than emitting something unvalidated.
async fn emit(sender: &ChannelSender, frame: arkret_wire::Result<WebSocketServerFrame>) -> bool {
    match frame {
        Ok(frame) => sender.send_durable(frame).await,
        Err(_) => false,
    }
}

fn account_resync_required_frame()
-> arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame {
    use arkret_models_collaboration::sync_frames::account_subscribe::{
        AccountSubscribeFrame, AccountSubscribeFrameKind,
    };
    AccountSubscribeFrame {
        kind: AccountSubscribeFrameKind::ResyncRequired,
        cursor: None,
        realms: None,
        to_device: None,
        device_lists: None,
        account_data: None,
        notifications: None,
        agent_signer_evidence_bundle: None,
        partial: None,
        priority: None,
        reconnect_after_ms: Some(SUBSCRIBE_RECONNECT_AFTER_MS),
    }
}

fn events_frame(
    kind: arkret_models_collaboration::http_bodies::EventsSubscribeFrameKind,
) -> arkret_models_collaboration::http_bodies::EventsSubscribeFrame {
    arkret_models_collaboration::http_bodies::EventsSubscribeFrame {
        kind,
        realm_id: None,
        cursor: None,
        payload: None,
        reconnect_after_ms: Some(SUBSCRIBE_RECONNECT_AFTER_MS),
    }
}

fn events_resync_required_frame() -> arkret_models_collaboration::http_bodies::EventsSubscribeFrame
{
    events_frame(arkret_models_collaboration::http_bodies::EventsSubscribeFrameKind::ResyncRequired)
}

fn events_unauthorized_frame() -> arkret_models_collaboration::http_bodies::EventsSubscribeFrame {
    events_frame(arkret_models_collaboration::http_bodies::EventsSubscribeFrameKind::Unauthorized)
}

fn protocol_rejection(message: &str) -> WebSocketRejection {
    WebSocketRejection {
        close_code: Some(WebSocketCloseCode::ProtocolError),
        channel_id: None,
        error: WebSocketTransportError::new(WireErrorCode::InvalidParam, message),
    }
}

fn channel_rejection(channel_id: &str, message: &str) -> WebSocketRejection {
    WebSocketRejection {
        close_code: None,
        channel_id: Some(channel_id.to_owned()),
        error: WebSocketTransportError::new(WireErrorCode::InvalidParam, message),
    }
}

/// §4 — only a text message carries a frame; a binary message is refused.
fn text_payload(message: &Message) -> Option<&[u8]> {
    message.is_text().then(|| message.as_bytes())
}

async fn send_frame(
    socket: &mut WebSocket,
    codec: &WebSocketFrameCodec,
    frame: &WebSocketServerFrame,
) -> bool {
    match codec.encode(frame) {
        Ok(encoded) => socket.send(Message::text(encoded)).await.is_ok(),
        Err(_) => false,
    }
}

async fn write_frame<S>(
    sink: &mut S,
    codec: &WebSocketFrameCodec,
    frame: &WebSocketServerFrame,
) -> bool
where
    S: futures_util::SinkExt<Message> + Unpin,
{
    match codec.encode(frame) {
        Ok(encoded) => sink.send(Message::text(encoded)).await.is_ok(),
        Err(_) => false,
    }
}

async fn close_with(socket: &mut WebSocket, code: WebSocketCloseCode, reason: &str) {
    // §8.1 — a reason string never carries a grant, proof, nonce, DID or
    // cursor; these are one-word audit tags.
    let _ = socket
        .send(Message::close_with(code.as_u16(), reason))
        .await;
}

async fn close_rejection(socket: &mut WebSocket, rejection: &WebSocketRejection) {
    let code = rejection
        .close_code
        .unwrap_or(WebSocketCloseCode::ProtocolError);
    close_with(socket, code, "frame").await;
}
