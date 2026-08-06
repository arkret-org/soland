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
//! The discovery descriptor is produced from the SDK's closed
//! `WebSocketBindingDescriptor` and is advertised only for deployments with a
//! canonical public `https` origin and at least one explicit browser Origin.
//! The production path is covered by a live rustls peer test before this
//! module adds the descriptor to ServiceDescribe (§10).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{LazyLock, Mutex as StdMutex};

use arkret_identifiers::Cursor;
use arkret_models_collaboration::http_bodies::{EventsSubscribeFrame, EventsSubscribeFrameKind};
use arkret_models_collaboration::sync_frames::websocket_binding::{
    WebSocketChannelControlPayload, WebSocketClientFrame, WebSocketClosedReason,
    WebSocketConnectionControlPayload, WebSocketConnectionLimits, WebSocketDataPayload,
    WebSocketOpenParameters, WebSocketReauthReason, WebSocketServerFrame,
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
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

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
const WS_MAX_CONNECTIONS_PER_ACTOR_DEVICE: u32 = 4;
const WS_MAX_INBOUND_FRAMES_PER_SECOND: u32 = 256;
const WS_MAX_INBOUND_BYTES_PER_SECOND: u64 = 1024 * 1024;
const WS_IDLE_TIMEOUT_MS: u64 = 90_000;
const WS_MAX_LIFETIME_MS: u64 = 60 * 60 * 1_000;
const WS_WRITE_TIMEOUT_MS: u64 = 10_000;
const WS_DURABLE_PENDING_TIMEOUT_MS: u64 = 10_000;
#[cfg(not(test))]
const WS_HEARTBEAT_INTERVAL_MS: u32 = 30_000;
/// Keep the live socket test bounded while exercising the same timer path.
#[cfg(test)]
const WS_HEARTBEAT_INTERVAL_MS: u32 = 1_000;
/// Open the five-second reauthentication window one minute before the current
/// grant expires. A shorter-lived grant enters the window immediately.
const WS_REAUTH_LEAD_MS: i64 = 60_000;
const WS_DRAIN_REASON: &str = "service_restart";
/// Poll cadence of the Signal channel, matching the HTTP Signal rail.
const WS_SIGNAL_POLL_MS: u64 = 250;
/// Debounce for account rebuilds, matching the HTTP long-poll handler.
const WS_ACCOUNT_DEBOUNCE_MS: u64 = 150;
/// Path segment under `/_arkret`.
pub(crate) const WS_PATH_SEGMENT: &str = "ws";

static CONNECTION_COUNTS: LazyLock<StdMutex<BTreeMap<(String, String), u32>>> =
    LazyLock::new(|| StdMutex::new(BTreeMap::new()));

struct ConnectionLease {
    key: (String, String),
}

impl ConnectionLease {
    fn acquire(session: &SessionRecord) -> Option<Self> {
        let key = (session.actor.clone(), session.device_id.clone());
        let mut counts = CONNECTION_COUNTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = counts.entry(key.clone()).or_default();
        if *count >= WS_MAX_CONNECTIONS_PER_ACTOR_DEVICE {
            return None;
        }
        *count += 1;
        Some(Self { key })
    }
}

impl Drop for ConnectionLease {
    fn drop(&mut self) {
        let mut counts = CONNECTION_COUNTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = counts.get_mut(&self.key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.key);
            }
        }
    }
}

struct AuthenticatedSession {
    record: SessionRecord,
    grant: String,
}

struct InboundRateWindow {
    started_at: tokio::time::Instant,
    frames: u32,
    bytes: u64,
}

impl InboundRateWindow {
    fn new() -> Self {
        Self {
            started_at: tokio::time::Instant::now(),
            frames: 0,
            bytes: 0,
        }
    }

    fn admit(&mut self, bytes: usize) -> bool {
        if self.started_at.elapsed() >= tokio::time::Duration::from_secs(1) {
            self.started_at = tokio::time::Instant::now();
            self.frames = 0;
            self.bytes = 0;
        }
        self.frames = self.frames.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes as u64);
        self.frames <= WS_MAX_INBOUND_FRAMES_PER_SECOND
            && self.bytes <= WS_MAX_INBOUND_BYTES_PER_SECOND
    }
}

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
    let public = reqwest::Url::parse(&state.config().public_base_url).ok()?;
    if public.scheme() != "https"
        || !public.username().is_empty()
        || public.password().is_some()
        || public.path() != "/"
        || public.query().is_some()
        || public.fragment().is_some()
    {
        return None;
    }
    let origin = public.origin().ascii_serialization();
    let authority = origin.strip_prefix("https://")?;
    let candidate = format!("wss://{authority}/_arkret/{WS_PATH_SEGMENT}");
    validate_websocket_base_url(&candidate).ok()?;
    Some(candidate)
}

/// Add the closed §2 descriptor and its required profile claim when this
/// deployment can actually admit a browser peer. A TLS origin with no explicit
/// Origin allow-list is intentionally not advertised: every conforming client
/// would otherwise discover an endpoint that must reject it.
pub(crate) fn advertise_websocket_binding(
    state: &AppState,
    description: &mut arkret_models_discovery::ServiceDescribe,
) {
    if allowed_origins(state).is_empty() {
        return;
    }
    let Some(base_url) = websocket_base_url(state) else {
        return;
    };
    let descriptor = arkret_models_discovery::websocket_binding::WebSocketBindingDescriptor::new(
        base_url,
        WS_MAX_FRAME_BYTES,
        WS_MAX_CHANNELS,
    );
    let Ok(binding) = descriptor.to_supported_binding() else {
        return;
    };
    description.supported_bindings.push(binding);
    if !description
        .supported_profiles
        .iter()
        .any(|profile| profile == arkret_wire::ProfileId::BINDING_WEBSOCKET_V1)
    {
        description
            .supported_profiles
            .push(arkret_wire::ProfileId::BINDING_WEBSOCKET_V1.to_owned());
    }
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

/// §2/§3: this endpoint is not a generic WebSocket. The upgrade proceeds only
/// when the client offered the registered Arkret subprotocol, because Salvo's
/// RFC 6455 default is otherwise to upgrade successfully without selecting one.
fn requests_arkret_subprotocol(req: &Request) -> bool {
    req.headers()
        .get_all(salvo::http::header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|protocol| protocol.trim() == WEBSOCKET_SUBPROTOCOL)
}

/// §3 step 1: the Upgrade must arrive on the TLS listener and its single
/// `Host` value must identify the configured public service origin. The
/// connection-derived Salvo scheme is used deliberately; an untrusted
/// `X-Forwarded-Proto` header cannot turn a plaintext request into TLS.
fn request_matches_public_service_origin(state: &AppState, req: &Request) -> bool {
    if req.scheme() != &salvo::http::uri::Scheme::HTTPS {
        return false;
    }

    let mut hosts = req.headers().get_all(salvo::http::header::HOST).iter();
    let Some(host) = hosts.next().and_then(|value| value.to_str().ok()) else {
        return false;
    };
    if hosts.next().is_some() || host.is_empty() {
        return false;
    }

    let Ok(request_url) = reqwest::Url::parse(&format!("https://{host}/")) else {
        return false;
    };
    let Ok(public_url) = reqwest::Url::parse(&state.config().public_base_url) else {
        return false;
    };
    request_url.username().is_empty()
        && request_url.password().is_none()
        && request_url.path() == "/"
        && request_url.query().is_none()
        && request_url.fragment().is_none()
        && public_url.scheme() == "https"
        && request_url.origin().ascii_serialization() == public_url.origin().ascii_serialization()
}

/// A 192-bit opaque id. §3.1 requires at least 128 bits of entropy in both
/// `connection_id` and `nonce`; the base64url form is 32 characters, inside the
/// frame schema's 22..128 window.
fn random_opaque_id() -> String {
    let mut bytes = [0_u8; 24];
    rand::fill(&mut bytes);
    arkret_canonical::base64url_encode(bytes)
}

fn deadline_at(deadline: chrono::DateTime<chrono::Utc>) -> tokio::time::Instant {
    let remaining = deadline
        .signed_duration_since(chrono::Utc::now())
        .to_std()
        .unwrap_or_default();
    tokio::time::Instant::now() + remaining
}

async fn sleep_until_opt(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// `GET /_arkret/ws` — the WebSocket binding endpoint.
#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.profile.binding.websocket.v1"))]
pub(crate) async fn websocket_subscribe(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot
        .get_typed::<AppState>()
        .expect("state injected")
        .clone();
    if let Some(drain) = state.current_connection_drain() {
        res.headers_mut().insert(
            salvo::http::header::RETRY_AFTER,
            salvo::http::HeaderValue::from_static("5"),
        );
        render_error(
            res,
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
            if drain.deadline <= chrono::Utc::now() {
                "the service is stopping"
            } else {
                "the service is draining"
            },
        );
        return;
    }
    let Some(base_url) = websocket_base_url(&state) else {
        render_error(
            res,
            StatusCode::NOT_FOUND,
            "not_found",
            "this deployment publishes no WebSocket binding",
        );
        return;
    };
    if !request_matches_public_service_origin(&state, req) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "WebSocket upgrade does not match the public TLS service origin",
        );
        return;
    }
    if !requests_arkret_subprotocol(req) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "the Arkret WebSocket subprotocol was not offered",
        );
        return;
    }
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
    encoded: String,
    /// Signal frames may be dropped under pressure; durable frames may not.
    droppable: bool,
    /// Pending frame/byte permits are released only after the writer removes
    /// this frame from the queue (or the queue is dropped).
    _permits: PendingPermits,
}

struct PendingPermits {
    _connection_frame: OwnedSemaphorePermit,
    _connection_bytes: OwnedSemaphorePermit,
    _channel_frame: Option<OwnedSemaphorePermit>,
    _channel_bytes: Option<OwnedSemaphorePermit>,
}

#[derive(Clone)]
struct PendingQuota {
    frames: std::sync::Arc<Semaphore>,
    bytes: std::sync::Arc<Semaphore>,
}

impl PendingQuota {
    fn new(max_frames: u32, max_bytes: u64) -> Self {
        Self {
            frames: std::sync::Arc::new(Semaphore::new(max_frames as usize)),
            bytes: std::sync::Arc::new(Semaphore::new(max_bytes as usize)),
        }
    }
}

#[derive(Clone)]
struct ChannelSender {
    durable: mpsc::Sender<OutboundFrame>,
    signal: mpsc::Sender<OutboundFrame>,
    codec: WebSocketFrameCodec,
    connection_quota: PendingQuota,
    channel_quota: Option<PendingQuota>,
}

impl ChannelSender {
    fn for_channel(&self) -> Self {
        Self {
            durable: self.durable.clone(),
            signal: self.signal.clone(),
            codec: self.codec,
            connection_quota: self.connection_quota.clone(),
            channel_quota: Some(PendingQuota::new(
                WS_MAX_CHANNEL_PENDING_FRAMES,
                WS_MAX_CHANNEL_PENDING_BYTES,
            )),
        }
    }

    async fn send_durable(&self, frame: WebSocketServerFrame) -> bool {
        let Ok(encoded) = self.codec.encode(&frame) else {
            return false;
        };
        tokio::time::timeout(
            tokio::time::Duration::from_millis(WS_DURABLE_PENDING_TIMEOUT_MS),
            async {
                let Some(permits) = self.acquire_permits(encoded.len()).await else {
                    return false;
                };
                self.durable
                    .send(OutboundFrame {
                        encoded,
                        droppable: false,
                        _permits: permits,
                    })
                    .await
                    .is_ok()
            },
        )
        .await
        .unwrap_or(false)
    }

    /// §7 — at the Signal queue limit the Signal is dropped rather than
    /// evicting a durable account / events frame.
    fn try_send_signal(&self, frame: WebSocketServerFrame) -> bool {
        let Ok(encoded) = self.codec.encode(&frame) else {
            return false;
        };
        let Some(permits) = self.try_acquire_permits(encoded.len()) else {
            return false;
        };
        self.signal
            .try_send(OutboundFrame {
                encoded,
                droppable: true,
                _permits: permits,
            })
            .is_ok()
    }

    async fn acquire_permits(&self, encoded_bytes: usize) -> Option<PendingPermits> {
        let bytes = u32::try_from(encoded_bytes).ok()?;
        let connection_frame = self
            .connection_quota
            .frames
            .clone()
            .acquire_owned()
            .await
            .ok()?;
        let connection_bytes = self
            .connection_quota
            .bytes
            .clone()
            .acquire_many_owned(bytes)
            .await
            .ok()?;
        let (channel_frame, channel_bytes) = match &self.channel_quota {
            Some(quota) => (
                Some(quota.frames.clone().acquire_owned().await.ok()?),
                Some(quota.bytes.clone().acquire_many_owned(bytes).await.ok()?),
            ),
            None => (None, None),
        };
        Some(PendingPermits {
            _connection_frame: connection_frame,
            _connection_bytes: connection_bytes,
            _channel_frame: channel_frame,
            _channel_bytes: channel_bytes,
        })
    }

    fn try_acquire_permits(&self, encoded_bytes: usize) -> Option<PendingPermits> {
        let bytes = u32::try_from(encoded_bytes).ok()?;
        let connection_frame = self
            .connection_quota
            .frames
            .clone()
            .try_acquire_owned()
            .ok()?;
        let connection_bytes = self
            .connection_quota
            .bytes
            .clone()
            .try_acquire_many_owned(bytes)
            .ok()?;
        let (channel_frame, channel_bytes) = match &self.channel_quota {
            Some(quota) => (
                Some(quota.frames.clone().try_acquire_owned().ok()?),
                Some(quota.bytes.clone().try_acquire_many_owned(bytes).ok()?),
            ),
            None => (None, None),
        };
        Some(PendingPermits {
            _connection_frame: connection_frame,
            _connection_bytes: connection_bytes,
            _channel_frame: channel_frame,
            _channel_bytes: channel_bytes,
        })
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
    // DPoP `iat` is an integer NumericDate. Anchor the private challenge
    // window to the same precision so a proof minted during this wall-clock
    // second is not incorrectly considered earlier than the challenge.
    let issued_at = chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0)
        .expect("the current timestamp is representable");
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

    let authenticated = match authenticate(
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
    let session = authenticated.record;
    let Some(_connection_lease) = ConnectionLease::acquire(&session) else {
        close_with(&mut socket, WebSocketCloseCode::PolicyViolation, "limit").await;
        return;
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

    run_multiplex(
        state,
        socket,
        codec,
        connection,
        session,
        authenticated.grant,
        connection_id,
        origin,
        base_url,
    )
    .await;
}

/// §3 — read the single `authenticate` frame inside the deadline and decide it.
async fn authenticate(
    state: &AppState,
    socket: &mut WebSocket,
    codec: &WebSocketFrameCodec,
    connection_id: &str,
    nonce: &str,
    origin: &str,
    base_url: &str,
) -> Option<AuthenticatedSession> {
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
    if !matches!(frame, WebSocketClientFrame::Authenticate { .. }) {
        close_with(socket, WebSocketCloseCode::ProtocolError, "state").await;
        return None;
    }
    match verify_authenticate(state, &frame, connection_id, nonce, origin, base_url).await {
        Ok(session) => {
            let WebSocketClientFrame::Authenticate { session_grant, .. } = frame else {
                unreachable!("the frame kind was checked above")
            };
            Some(AuthenticatedSession {
                record: session,
                grant: session_grant,
            })
        }
        Err(reason) => {
            close_with(socket, WebSocketCloseCode::PolicyViolation, reason).await;
            None
        }
    }
}

/// §3.1 — decide one `authenticate` frame against the stored challenge and the
/// presented grant. Shared by the initial handshake and by reauth (§3): the
/// only difference is which challenge record the nonce selects. The `Err` is
/// the one-word audit tag §8.1 allows in a close reason.
async fn verify_authenticate(
    state: &AppState,
    frame: &WebSocketClientFrame,
    connection_id: &str,
    nonce: &str,
    origin: &str,
    base_url: &str,
) -> std::result::Result<SessionRecord, &'static str> {
    let WebSocketClientFrame::Authenticate {
        connection_id: presented_connection_id,
        session_grant,
        dpop_proof,
    } = frame
    else {
        return Err("state");
    };
    if frame.validate().is_err() {
        return Err("frame");
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
        return Err("grant");
    };
    if grant.audience.as_str() != state.service_id() || grant.expires_at <= chrono::Utc::now() {
        return Err("grant");
    }
    let Some(cnf_jkt) = grant.cnf_jkt.clone().filter(|jkt| !jkt.is_empty()) else {
        return Err("grant");
    };

    let Ok(Some(challenge)) = state
        .sync()
        .websocket_auth()
        .challenge(connection_id, nonce)
        .await
    else {
        return Err("challenge");
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
            return Err("proof");
        }
    };
    if record.canonical_base_url != base_url {
        return Err("target");
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
        return Err("replay");
    }

    let Ok((device_id, agent_session)) =
        crate::routing::identity::auth_grant_dpop::grant_session_binding(&grant)
    else {
        return Err("grant");
    };
    Ok(
        crate::routing::identity::auth_grant_dpop::session_from_verified_grant(
            state,
            session_grant,
            grant,
            device_id,
            agent_session,
        ),
    )
}

/// Mint a fresh challenge record for this connection and return its nonce.
/// §3 — a reauth establishes a new challenge record; nothing about the old one
/// (nonce, proof, `ath`) may be reused.
async fn prepare_reauth_challenge(
    state: &AppState,
    connection_id: &str,
    origin: &str,
    base_url: &str,
) -> Option<(String, chrono::DateTime<chrono::Utc>)> {
    let nonce = random_opaque_id();
    let issued_at = chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0)
        .expect("the current timestamp is representable");
    let expires_at =
        issued_at + chrono::Duration::milliseconds(WEBSOCKET_AUTHENTICATION_DEADLINE_MS as i64);
    let retain_until =
        expires_at + chrono::Duration::seconds(WEBSOCKET_REPLAY_LEDGER_RETENTION_SECONDS as i64);
    state
        .sync()
        .websocket_auth()
        .prepare_challenge(&WebsocketChallengeState {
            connection_id: connection_id.to_owned(),
            nonce: nonce.clone(),
            canonical_origin: origin.to_owned(),
            canonical_base_url: base_url.to_owned(),
            issued_at,
            expires_at,
            consumed: false,
            retain_until,
        })
        .await
        .ok()?;
    Some((nonce, expires_at))
}

/// §4–§7 — the multiplexed read / write loop.
#[allow(clippy::too_many_arguments)]
async fn run_multiplex(
    state: AppState,
    socket: WebSocket,
    codec: WebSocketFrameCodec,
    mut connection: WebSocketConnectionState,
    mut session: SessionRecord,
    mut session_grant: String,
    connection_id: String,
    origin: String,
    base_url: String,
) {
    use futures_util::StreamExt;

    let (mut sink, mut stream) = socket.split();
    let (durable_tx, mut durable_rx) =
        mpsc::channel::<OutboundFrame>(WS_MAX_CONNECTION_PENDING_FRAMES as usize);
    let (signal_tx, mut signal_rx) =
        mpsc::channel::<OutboundFrame>(WS_MAX_CHANNEL_PENDING_FRAMES as usize);
    let sender = ChannelSender {
        durable: durable_tx,
        signal: signal_tx,
        codec,
        connection_quota: PendingQuota::new(
            WS_MAX_CONNECTION_PENDING_FRAMES,
            WS_MAX_CONNECTION_PENDING_BYTES,
        ),
        channel_quota: None,
    };
    let (producer_exit_tx, mut producer_exit_rx) = mpsc::unbounded_channel::<ProducerExit>();
    let mut producers: std::collections::BTreeMap<String, tokio::task::JoinHandle<()>> =
        std::collections::BTreeMap::new();
    let mut heartbeat = tokio::time::interval(tokio::time::Duration::from_millis(
        WS_HEARTBEAT_INTERVAL_MS as u64,
    ));
    heartbeat.tick().await;
    let mut close_code: Option<WebSocketCloseCode> = None;

    // §3 — the reauth window opens ahead of grant expiry, and the old
    // authorization is hard-stopped at that expiry whether or not the client
    // took the window. Both are absolute instants, so a slow reauth cannot
    // extend the authorization it is replacing.
    let mut reauth_at =
        deadline_at(session.expires_at - chrono::Duration::milliseconds(WS_REAUTH_LEAD_MS));
    let mut authorization_expires_at = deadline_at(session.expires_at);
    let mut pending_reauth: Option<String> = None;
    let mut reauth_deadline: Option<tokio::time::Instant> = None;
    // §8 — a service drain; latched, so a connection that survives to here
    // after the signal still observes it on the first poll.
    let mut drain = state.subscribe_connection_drain();
    let mut drain_deadline: Option<tokio::time::Instant> = None;
    let initial_drain = *drain.borrow_and_update();
    if let Some(notice) = initial_drain {
        let payload = WebSocketConnectionControlPayload::Drain {
            reconnect_after_ms: notice.reconnect_after_ms,
            deadline: notice.deadline,
            reason: Some(WS_DRAIN_REASON.to_owned()),
        };
        let Ok(frame) = WebSocketServerFrame::connection_control(&payload) else {
            return;
        };
        if !write_frame(&mut sink, &codec, &frame).await {
            return;
        }
        connection.draining();
        drain_deadline = Some(deadline_at(notice.deadline));
    }
    let mut idle_deadline =
        tokio::time::Instant::now() + tokio::time::Duration::from_millis(WS_IDLE_TIMEOUT_MS);
    let lifetime_deadline =
        tokio::time::Instant::now() + tokio::time::Duration::from_millis(WS_MAX_LIFETIME_MS);
    let mut inbound_rate = InboundRateWindow::new();

    loop {
        tokio::select! {
            // §7 — Tokio's fair selection plus independent queues/permits
            // prevents Signal traffic from evicting or starving durable
            // account/events traffic. Timers and inbound auth remain fair too.
            Some(outbound) = durable_rx.recv() => {
                if timed_send(&mut sink, Message::text(outbound.encoded)).await.is_err() {
                    break;
                }
            }
            Some(outbound) = signal_rx.recv() => {
                debug_assert!(outbound.droppable);
                if timed_send(&mut sink, Message::text(outbound.encoded)).await.is_err() {
                    break;
                }
            }
            Some(exit) = producer_exit_rx.recv() => {
                producers.remove(&exit.channel_id);
                if connection.operation_for(&exit.channel_id).is_some() {
                    connection.close_channel(&exit.channel_id);
                    let closed = WebSocketServerFrame::Closed {
                        channel_id: exit.channel_id,
                        reason: exit.reason,
                    };
                    if !write_frame(&mut sink, &codec, &closed).await {
                        break;
                    }
                }
            }
            _ = tokio::time::sleep_until(authorization_expires_at) => {
                // §3 — the old authorization may not serve past the original
                // grant expiry, reauth pending or not.
                close_code = Some(WebSocketCloseCode::PolicyViolation);
                break;
            }
            _ = tokio::time::sleep_until(idle_deadline) => {
                close_code = Some(WebSocketCloseCode::Normal);
                break;
            }
            _ = tokio::time::sleep_until(lifetime_deadline) => {
                close_code = Some(WebSocketCloseCode::Normal);
                break;
            }
            _ = sleep_until_opt(drain_deadline), if drain_deadline.is_some() => {
                // §8.1 — drain sent and the deadline reached: the service stops.
                close_code = Some(WebSocketCloseCode::GoingAway);
                break;
            }
            _ = sleep_until_opt(reauth_deadline), if reauth_deadline.is_some() => {
                // §3 — the fresh challenge has its own five-second deadline;
                // waiting until the old grant expires would keep serving an
                // authorization after the mandated reauth attempt timed out.
                close_code = Some(WebSocketCloseCode::PolicyViolation);
                break;
            }
            _ = drain.changed() => {
                let Some(notice) = *drain.borrow_and_update() else {
                    continue;
                };
                if drain_deadline.is_some() {
                    continue;
                }
                let payload = WebSocketConnectionControlPayload::Drain {
                    reconnect_after_ms: notice.reconnect_after_ms,
                    deadline: notice.deadline,
                    reason: Some(WS_DRAIN_REASON.to_owned()),
                };
                let Ok(frame) = WebSocketServerFrame::connection_control(&payload) else {
                    close_code = Some(WebSocketCloseCode::InternalError);
                    break;
                };
                if !write_frame(&mut sink, &codec, &frame).await {
                    break;
                }
                // Refuses new channels while existing durable channels keep
                // running until the deadline (§8).
                connection.draining();
                drain_deadline = Some(deadline_at(notice.deadline));
            }
            _ = tokio::time::sleep_until(reauth_at), if pending_reauth.is_none() => {
                let Some((nonce, expires_at)) =
                    prepare_reauth_challenge(&state, &connection_id, &origin, &base_url).await
                else {
                    close_code = Some(WebSocketCloseCode::InternalError);
                    break;
                };
                let frame = WebSocketServerFrame::ReauthRequired {
                    connection_id: connection_id.clone(),
                    nonce: nonce.clone(),
                    expires_at,
                    reason: WebSocketReauthReason::GrantExpiring,
                };
                if !write_frame(&mut sink, &codec, &frame).await {
                    break;
                }
                connection.reauth_required();
                pending_reauth = Some(nonce);
                reauth_deadline = Some(deadline_at(expires_at));
            }
            _ = heartbeat.tick() => {
                // A long-lived connection must observe grant revocation, not
                // merely the expiry captured during its initial upgrade.
                let verification = tokio::time::timeout_at(
                    authorization_expires_at,
                    crate::routing::identity::auth_grant_dpop::introspect_session_grant_cached(
                        &state,
                        &session_grant,
                        true,
                    ),
                )
                .await;
                let Ok(Ok(grant)) = verification else {
                    close_code = Some(WebSocketCloseCode::PolicyViolation);
                    break;
                };
                let Ok((device_id, _)) =
                    crate::routing::identity::auth_grant_dpop::grant_session_binding(&grant)
                else {
                    close_code = Some(WebSocketCloseCode::PolicyViolation);
                    break;
                };
                if grant.subject.as_str() != session.actor
                    || device_id != session.device_id
                    || grant.audience.as_str() != session.audience
                    || grant.expires_at <= chrono::Utc::now()
                {
                    close_code = Some(WebSocketCloseCode::PolicyViolation);
                    break;
                }
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
                idle_deadline = tokio::time::Instant::now()
                    + tokio::time::Duration::from_millis(WS_IDLE_TIMEOUT_MS);
                if !inbound_rate.admit(message.as_bytes().len()) {
                    close_code = Some(WebSocketCloseCode::PolicyViolation);
                    break;
                }
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
                if matches!(frame, WebSocketClientFrame::Authenticate { .. }) {
                    // §3 — an `authenticate` is admissible exactly once more,
                    // and only against the challenge `reauth_required` minted.
                    let Some(nonce) = pending_reauth.take() else {
                        close_code = Some(WebSocketCloseCode::ProtocolError);
                        break;
                    };
                    let verification_deadline = reauth_deadline
                        .unwrap_or(authorization_expires_at)
                        .min(authorization_expires_at);
                    let refreshed_grant = match &frame {
                        WebSocketClientFrame::Authenticate { session_grant, .. } => {
                            session_grant.clone()
                        }
                        _ => unreachable!("the frame kind was checked above"),
                    };
                    match tokio::time::timeout_at(
                        verification_deadline,
                        verify_authenticate(
                            &state,
                            &frame,
                            &connection_id,
                            &nonce,
                            &origin,
                            &base_url,
                        ),
                    )
                    .await
                    {
                        Ok(Ok(refreshed)) => {
                            if refreshed.actor != session.actor
                                || refreshed.device_id != session.device_id
                                || refreshed.audience != session.audience
                                || connection.open_channel_ids().into_iter().any(|channel_id| {
                                    connection.operation_for(channel_id).is_some_and(|operation| {
                                        super::super::require_agent_session_scope(
                                            &refreshed,
                                            operation_scope(operation),
                                        )
                                        .is_err()
                                    })
                                })
                            {
                                close_code = Some(WebSocketCloseCode::PolicyViolation);
                                break;
                            }
                            connection.reauthenticated();
                            authorization_expires_at = deadline_at(refreshed.expires_at);
                            reauth_at = deadline_at(
                                refreshed.expires_at
                                    - chrono::Duration::milliseconds(WS_REAUTH_LEAD_MS),
                            );
                            session = refreshed;
                            session_grant = refreshed_grant;
                            reauth_deadline = None;
                        }
                        Ok(Err(reason)) => {
                            tracing::debug!(reason, "WebSocket reauth rejected");
                            close_code = Some(WebSocketCloseCode::PolicyViolation);
                            break;
                        }
                        Err(_) => {
                            close_code = Some(WebSocketCloseCode::PolicyViolation);
                            break;
                        }
                    }
                    continue;
                }
                match handle_client_frame(
                    &state,
                    &session,
                    &mut connection,
                    &sender,
                    &mut producers,
                    &producer_exit_tx,
                    frame,
                )
                .await
                {
                    Ok(frames) => {
                        let mut write_failed = false;
                        for frame in frames {
                            if !write_frame(&mut sink, &codec, &frame).await {
                                close_code = Some(WebSocketCloseCode::InternalError);
                                write_failed = true;
                                break;
                            }
                        }
                        if write_failed {
                            break;
                        }
                    }
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

    for (_, producer) in producers {
        producer.abort();
    }
    connection.closed();
    let code = close_code.unwrap_or(WebSocketCloseCode::Normal);
    let _ = timed_send(&mut sink, Message::close_with(code.as_u16(), "")).await;
}

async fn handle_client_frame(
    state: &AppState,
    session: &SessionRecord,
    connection: &mut WebSocketConnectionState,
    sender: &ChannelSender,
    producers: &mut std::collections::BTreeMap<String, tokio::task::JoinHandle<()>>,
    producer_exit_tx: &mpsc::UnboundedSender<ProducerExit>,
    frame: WebSocketClientFrame,
) -> Result<Vec<WebSocketServerFrame>, WebSocketRejection> {
    match &frame {
        WebSocketClientFrame::Pong { .. } => Ok(Vec::new()),
        WebSocketClientFrame::Authenticate { .. } => Err(protocol_rejection(
            "a second authenticate is not part of the connection lifecycle",
        )),
        WebSocketClientFrame::Close { channel_id, .. } => {
            connection.close_channel(channel_id);
            if let Some(producer) = producers.remove(channel_id) {
                producer.abort();
            }
            Ok(vec![WebSocketServerFrame::Closed {
                channel_id: channel_id.clone(),
                reason: WebSocketClosedReason::ClientRequest,
            }])
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
                    let producer = spawn_producer(
                        state.clone(),
                        session.clone(),
                        sender.for_channel(),
                        channel_id.clone(),
                        parameters,
                        producer_exit_tx.clone(),
                    );
                    producers.insert(channel_id, producer);
                    Ok(vec![opened])
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

struct ProducerExit {
    channel_id: String,
    reason: WebSocketClosedReason,
}

fn spawn_producer(
    state: AppState,
    session: SessionRecord,
    sender: ChannelSender,
    channel_id: String,
    parameters: WebSocketOpenParameters,
    producer_exit_tx: mpsc::UnboundedSender<ProducerExit>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let reason = match parameters {
            WebSocketOpenParameters::Account(parameters) => {
                run_account_channel(state, session, sender, channel_id.clone(), parameters).await
            }
            WebSocketOpenParameters::Events(parameters) => {
                run_events_channel(state, session, sender, channel_id.clone(), parameters).await
            }
            WebSocketOpenParameters::Signal => {
                run_signal_channel(state, session, sender, channel_id.clone()).await
            }
        };
        let _ = producer_exit_tx.send(ProducerExit { channel_id, reason });
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
) -> WebSocketClosedReason {
    let wait_for = parameters
        .wait_for
        .as_ref()
        .map(|cursor| cursor.as_str().to_owned());
    let body = SyncRequestBody {
        after: parameters
            .after
            .as_ref()
            .map(|cursor| cursor.as_str().to_owned()),
        catchup: parameters.catchup,
        filter: parameters.filter.map(websocket_account_filter),
        subscriptions: None,
    };
    let filter_value = sync_filter_value(body.filter.as_ref());
    let mut notifications = state.subscribe_event_notifications();
    if let Some(wait_for) = wait_for {
        let event_id = match parse_and_validate_barrier_cursor(
            &wait_for,
            &state,
            &session,
            chrono::Utc::now().timestamp_millis(),
        )
        .await
        {
            Ok(event_id) => event_id,
            Err(_) => {
                let payload = WebSocketChannelControlPayload::Account(Box::new(
                    account_resync_required_frame(),
                ));
                if let Ok(frame) =
                    WebSocketServerFrame::channel_control(channel_id.clone(), &payload)
                {
                    sender.send_durable(frame).await;
                }
                return WebSocketClosedReason::Error;
            }
        };
        if !wait_for_account_projection_barrier(&state, &mut notifications, &event_id).await {
            let payload =
                WebSocketChannelControlPayload::Account(Box::new(account_resync_required_frame()));
            if let Ok(frame) = WebSocketServerFrame::channel_control(channel_id.clone(), &payload) {
                sender.send_durable(frame).await;
            }
            return WebSocketClosedReason::Error;
        }
    }
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
                    return WebSocketClosedReason::Error;
                }
            }
        }
        None => SyncCursor::default(),
    };
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
                return WebSocketClosedReason::Error;
            }
        } else {
            let payload = WebSocketDataPayload::Account(Box::new(snapshot.clone()));
            if !emit(
                &sender,
                WebSocketServerFrame::data(channel_id.clone(), &payload),
            )
            .await
            {
                return WebSocketClosedReason::Error;
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
                    return WebSocketClosedReason::Error;
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
                Err(RecvError::Closed) => return WebSocketClosedReason::Completed,
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(WS_ACCOUNT_DEBOUNCE_MS)).await;
    }
}

fn websocket_account_filter(
    filter: arkret_models_collaboration::sync_frames::websocket_binding::WebSocketAccountFilter,
) -> arkret_models_collaboration::sync_frames::client_sync::SyncFilter {
    arkret_models_collaboration::sync_frames::client_sync::SyncFilter {
        realms: filter.realms.unwrap_or_default(),
        timeline_limit: filter.timeline_limit,
        lazy_load_members: filter.lazy_load_members.unwrap_or(false),
        include_redundant_members: filter.include_redundant_members.unwrap_or(false),
        event_types: filter.event_kinds.unwrap_or_default(),
        not_event_types: filter.not_event_kinds.unwrap_or_default(),
        extra: BTreeMap::new(),
    }
}

/// Events channel: bounded catch-up replay followed by a live tail, over the
/// same cursor / visibility / replay helpers the canonical NDJSON surface
/// composes (§6.1 — the catch-up, `dropped` and filter-digest rules are the
/// HTTP binding's rules). A cursorless `catchup=true` stays a live tail on both
/// bindings: durable history bootstrap is `events.read.scan`.
async fn run_events_channel(
    state: AppState,
    session: SessionRecord,
    sender: ChannelSender,
    channel_id: String,
    parameters:
        arkret_models_collaboration::sync_frames::websocket_binding::WebSocketEventsOpenParameters,
) -> WebSocketClosedReason {
    let actor_filter = parameters
        .actors
        .into_iter()
        .flatten()
        .map(|actor| actor.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    let mut accessible: Vec<String> = Vec::new();
    let requested_realms = match parameters.realms.filter(|realms| !realms.is_empty()) {
        Some(realms) => realms,
        None => state
            .realm_directory()
            .snapshot()
            .entries_iter()
            .map(|(realm_id, _)| realm_id.clone())
            .collect(),
    };
    for realm in requested_realms {
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
        return WebSocketClosedReason::Unauthorized;
    }
    let realm_filter: BTreeSet<String> = accessible.iter().cloned().collect();
    let filter_digest = websocket_events_filter_digest(&accessible, &actor_filter);

    // The live receiver is installed BEFORE replay so nothing can land in the
    // history-vs-live window; ids seen during replay are then discarded from
    // the queued notifications, producing one replay-to-live boundary.
    let mut notifications = state.subscribe_event_notifications();

    let after_token = parameters
        .after
        .as_ref()
        .map(|cursor| cursor.as_str().to_owned());
    let catchup = parameters.catchup.unwrap_or(false);
    let resume_event_id = match after_token.as_deref() {
        Some(after) => {
            match parse_and_validate_events_query_cursor(
                after,
                &state,
                Some(&session),
                &filter_digest,
                chrono::Utc::now().timestamp_millis(),
            )
            .await
            {
                Ok(cursor) => Some(cursor.event_id),
                // §6.1 — an unusable resume point is a channel-level reconnect
                // signal, never a connection failure.
                Err(_) => return events_resync(&sender, &channel_id).await,
            }
        }
        None => None,
    };

    let replay_upper_bound = match (catchup, resume_event_id.as_deref()) {
        (true, Some(cursor)) => {
            match projected_event_replay_upper_bound(&state, &realm_filter, cursor).await {
                Ok(upper_bound) => upper_bound,
                Err(error) => {
                    tracing::warn!(%error, "WebSocket events catch-up upper bound failed");
                    return events_resync(&sender, &channel_id).await;
                }
            }
        }
        _ => None,
    };

    let mut replayed_event_ids: BTreeSet<String> = BTreeSet::new();
    let mut replay_cursor: Option<String> = None;
    if let Some(upper_bound) = replay_upper_bound.as_deref() {
        let page = projected_event_page_for_realms_through(
            &state,
            &realm_filter,
            resume_event_id.as_deref(),
            Some(upper_bound),
            EVENTS_CATCHUP_LIMIT,
        )
        .await;
        let Ok(Some(page)) = page else {
            tracing::warn!("WebSocket events catch-up replay failed after channel open");
            return events_resync(&sender, &channel_id).await;
        };
        let has_more = page.has_more;
        if has_more {
            // A bounded catch-up is atomic from the peer's perspective: do
            // not emit a partial prefix and then tell it to restart.
            return events_resync(&sender, &channel_id).await;
        }
        for event in page.items {
            if !projection_record_visible_to_session(&state, &event, Some(&session)).await {
                continue;
            }
            let projected = projection_event_json(&event);
            let Some(envelope) = full_event_from_projection_json(&state, &projected).await else {
                tracing::warn!(
                    event_id = %event.event_id,
                    "WebSocket events catch-up could not materialize a canonical event envelope"
                );
                return events_resync(&sender, &channel_id).await;
            };
            if !actor_filter.is_empty() && !actor_filter.contains(envelope.actor_id.as_str()) {
                continue;
            }
            let cursor = sync_token_for_events_query(
                &state,
                Some(&session),
                &filter_digest,
                &event.event_id,
            )
            .await;
            replayed_event_ids.insert(event.event_id.clone());
            if !emit_events_event(&sender, &channel_id, &event.realm_id, &cursor, &envelope).await {
                return WebSocketClosedReason::Error;
            }
            replay_cursor = Some(cursor);
        }
    }

    // An empty bounded catch-up still needs an explicit baseline so clients can
    // tell "caught up, no delta" from a truncated reply. `frontier` reuses the
    // already-validated resume cursor.
    if catchup
        && replay_cursor.is_none()
        && let Some(cursor) = after_token.as_ref()
    {
        let frontier = events_frame_with_cursor(EventsSubscribeFrameKind::Frontier, cursor);
        if !emit_events_control(&sender, &channel_id, frontier).await {
            return WebSocketClosedReason::Error;
        }
        replay_cursor = Some(cursor.clone());
    }
    if let Some(cursor) = replay_cursor.as_ref() {
        let complete = events_frame_with_cursor(EventsSubscribeFrameKind::CatchupComplete, cursor);
        if !emit_events_control(&sender, &channel_id, complete).await {
            return WebSocketClosedReason::Error;
        }
    }

    let mut active_realms = realm_filter;
    loop {
        let notification = match notifications.recv().await {
            Ok(notification) => notification,
            Err(RecvError::Lagged(_)) => return events_resync(&sender, &channel_id).await,
            Err(RecvError::Closed) => return WebSocketClosedReason::Completed,
        };
        if !active_realms.contains(&notification.realm_id) {
            continue;
        }
        let realm_id = notification.realm_id.clone();
        match notification.kind {
            crate::state::EventNotificationKind::Event {
                cursor,
                event_payload,
            } => {
                if replayed_event_ids.contains(&cursor) {
                    continue;
                }
                if !projection_event_value_visible_to_session(
                    &state,
                    &event_payload,
                    Some(&session),
                )
                .await
                {
                    continue;
                }
                let live_cursor =
                    sync_token_for_events_query(&state, Some(&session), &filter_digest, &cursor)
                        .await;
                let Some(envelope) = full_event_from_projection_json(&state, &event_payload).await
                else {
                    tracing::warn!(event_id = %cursor, "live event could not materialize a canonical event envelope");
                    if retire_events_realm(
                        &sender,
                        &channel_id,
                        EventsSubscribeFrameKind::ResyncRequired,
                        realm_id,
                        &mut active_realms,
                    )
                    .await
                    {
                        return WebSocketClosedReason::Error;
                    }
                    continue;
                };
                if !actor_filter.is_empty() && !actor_filter.contains(envelope.actor_id.as_str()) {
                    continue;
                }
                if !emit_events_event(&sender, &channel_id, &realm_id, &live_cursor, &envelope)
                    .await
                {
                    return WebSocketClosedReason::Error;
                }
            }
            crate::state::EventNotificationKind::EpochRotation {
                previous_epoch: _,
                new_epoch,
            } => {
                let Ok(frame) = serde_json::from_value(json!({
                    "kind": "epoch_rotation",
                    "realm_id": realm_id,
                    "payload": {
                        "new_epoch": new_epoch,
                    },
                })) else {
                    continue;
                };
                if !emit_events_control(&sender, &channel_id, frame).await {
                    return WebSocketClosedReason::Error;
                }
            }
            crate::state::EventNotificationKind::ResyncRequired { .. } => {
                if retire_events_realm(
                    &sender,
                    &channel_id,
                    EventsSubscribeFrameKind::ResyncRequired,
                    realm_id,
                    &mut active_realms,
                )
                .await
                {
                    return WebSocketClosedReason::Error;
                }
            }
            crate::state::EventNotificationKind::Unauthorized { .. } => {
                if retire_events_realm(
                    &sender,
                    &channel_id,
                    EventsSubscribeFrameKind::Unauthorized,
                    realm_id,
                    &mut active_realms,
                )
                .await
                {
                    return WebSocketClosedReason::Unauthorized;
                }
            }
            // A Frontier carries no cursor this stream can hand out, a Signal
            // is not a durable Event, and an Account notification belongs to
            // the account channel.
            crate::state::EventNotificationKind::Frontier { .. }
            | crate::state::EventNotificationKind::Signal { .. }
            | crate::state::EventNotificationKind::Account { .. } => continue,
        }
    }
}

fn websocket_events_filter_digest(
    accessible_realms: &[String],
    actors: &BTreeSet<String>,
) -> String {
    if actors.is_empty() {
        return events_subscribe_filter_digest(accessible_realms);
    }
    let realms = accessible_realms
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    sync_filter_digest(Some(&json!({
        "operation_id": "ak.self.events.stream.subscribe",
        "realms": realms,
        "actors": actors,
    })))
}

/// Emit one events `data` frame; `false` means the channel is finished.
async fn emit_events_event(
    sender: &ChannelSender,
    channel_id: &str,
    realm_id: &str,
    cursor: &str,
    envelope: &arkret_wire::Event,
) -> bool {
    let Ok(frame) = serde_json::from_value(json!({
        "kind": "event",
        "realm_id": realm_id,
        "cursor": cursor,
        "payload": envelope,
    })) else {
        return false;
    };
    let payload = WebSocketDataPayload::Events(Box::new(frame));
    emit(
        sender,
        WebSocketServerFrame::data(channel_id.to_owned(), &payload),
    )
    .await
}

async fn emit_events_control(
    sender: &ChannelSender,
    channel_id: &str,
    frame: EventsSubscribeFrame,
) -> bool {
    let payload = WebSocketChannelControlPayload::Events(Box::new(frame));
    emit(
        sender,
        WebSocketServerFrame::channel_control(channel_id.to_owned(), &payload),
    )
    .await
}

/// §6.1 isolation: one Realm losing visibility retires only that selector.
/// Returns `true` when the channel itself is finished — either the frame could
/// not be queued, or nothing is left to watch.
async fn retire_events_realm(
    sender: &ChannelSender,
    channel_id: &str,
    kind: EventsSubscribeFrameKind,
    realm_id: String,
    active_realms: &mut BTreeSet<String>,
) -> bool {
    active_realms.remove(&realm_id);
    let mut frame = events_frame(kind);
    frame.realm_id = RealmId::new(realm_id).ok();
    let delivered = emit_events_control(sender, channel_id, frame).await;
    !delivered || active_realms.is_empty()
}

/// Terminal channel-level `resync_required`: the client reopens from its last
/// durable cursor, or bootstraps through `events.read.scan`.
async fn events_resync(sender: &ChannelSender, channel_id: &str) -> WebSocketClosedReason {
    let payload = WebSocketChannelControlPayload::Events(Box::new(events_resync_required_frame()));
    if let Ok(frame) = WebSocketServerFrame::channel_control(channel_id.to_owned(), &payload) {
        sender.send_durable(frame).await;
    }
    WebSocketClosedReason::Error
}

#[cfg(test)]
mod tests {
    use salvo::http::HeaderValue;
    use soland_storage_postgres::Db;

    use super::*;

    fn state(public_base_url: &str, cors_allow_origin: Option<&str>) -> AppState {
        let mut config = crate::config::AppConfig::test_default();
        config.public_base_url = public_base_url.to_owned();
        config.cors_allow_origin = cors_allow_origin.map(ToOwned::to_owned);
        AppState::new(config, Db { pool: None })
    }

    fn secure_request(host: &str, origin: &str) -> Request {
        let mut req = Request::new();
        *req.scheme_mut() = salvo::http::uri::Scheme::HTTPS;
        req.headers_mut().insert(
            salvo::http::header::HOST,
            host.parse::<HeaderValue>().expect("host header"),
        );
        req.headers_mut().insert(
            salvo::http::header::ORIGIN,
            origin.parse::<HeaderValue>().expect("origin header"),
        );
        req.headers_mut().insert(
            salvo::http::header::SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static(WEBSOCKET_SUBPROTOCOL),
        );
        req
    }

    #[test]
    fn websocket_base_url_requires_a_canonical_https_service_origin() {
        assert_eq!(
            websocket_base_url(&state("https://server.example/", None)).as_deref(),
            Some("wss://server.example/_arkret/ws")
        );
        assert_eq!(
            websocket_base_url(&state("http://server.example/", None)),
            None
        );
    }

    #[test]
    fn upgrade_admission_binds_tls_host_and_browser_origin_independently() {
        let state = state(
            "https://server.example/",
            Some("https://client.example, https://admin.example:8443"),
        );
        let req = secure_request("server.example", "https://client.example");
        assert!(request_matches_public_service_origin(&state, &req));
        assert_eq!(
            admitted_origin(&state, &req).as_deref(),
            Some("https://client.example")
        );

        let plaintext = Request::new();
        assert!(!request_matches_public_service_origin(&state, &plaintext));
        let wrong_host = secure_request("other.example", "https://client.example");
        assert!(!request_matches_public_service_origin(&state, &wrong_host));
        let wrong_origin = secure_request("server.example", "https://other.example");
        assert_eq!(admitted_origin(&state, &wrong_origin), None);
    }

    #[test]
    fn duplicate_host_or_origin_headers_are_rejected() {
        let state = state("https://server.example/", Some("https://client.example"));
        let mut duplicate_host = secure_request("server.example", "https://client.example");
        duplicate_host.headers_mut().append(
            salvo::http::header::HOST,
            HeaderValue::from_static("server.example"),
        );
        assert!(!request_matches_public_service_origin(
            &state,
            &duplicate_host
        ));

        let mut duplicate_origin = secure_request("server.example", "https://client.example");
        duplicate_origin.headers_mut().append(
            salvo::http::header::ORIGIN,
            HeaderValue::from_static("https://client.example"),
        );
        assert_eq!(admitted_origin(&state, &duplicate_origin), None);
    }

    #[test]
    fn arkret_subprotocol_must_be_explicitly_offered() {
        let mut req = secure_request("server.example", "https://client.example");
        assert!(requests_arkret_subprotocol(&req));
        req.headers_mut().insert(
            salvo::http::header::SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static("other.v1"),
        );
        assert!(!requests_arkret_subprotocol(&req));
        req.headers_mut().insert(
            salvo::http::header::SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static("other.v1, arkret.v1"),
        );
        assert!(requests_arkret_subprotocol(&req));
    }

    fn test_ping() -> WebSocketServerFrame {
        WebSocketServerFrame::Ping {
            ping_id: random_opaque_id(),
            sent_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn pending_permits_block_durable_frames_and_drop_signal_frames() {
        let (durable_tx, mut durable_rx) = mpsc::channel(2);
        let (signal_tx, _signal_rx) = mpsc::channel(2);
        let sender = ChannelSender {
            durable: durable_tx,
            signal: signal_tx,
            codec: WebSocketFrameCodec::new(WS_MAX_FRAME_BYTES, None),
            connection_quota: PendingQuota::new(1, 4_096),
            channel_quota: None,
        };

        assert!(sender.send_durable(test_ping()).await);
        assert!(
            !sender.try_send_signal(test_ping()),
            "a Signal must be dropped instead of consuming a full durable window"
        );

        let blocked_sender = sender.clone();
        let blocked = tokio::spawn(async move { blocked_sender.send_durable(test_ping()).await });
        tokio::task::yield_now().await;
        assert!(
            !blocked.is_finished(),
            "a second durable frame must wait for pending capacity"
        );

        drop(durable_rx.recv().await.expect("first pending frame"));
        assert!(blocked.await.expect("durable sender task"));
        assert!(durable_rx.recv().await.is_some());
    }

    #[tokio::test]
    async fn connection_drain_is_latched_and_cannot_be_extended() {
        let state = state("https://server.example/", None);
        let mut receiver = state.subscribe_connection_drain();
        state.begin_connection_drain(std::time::Duration::from_secs(1));
        receiver.changed().await.expect("drain published");
        let first = receiver.borrow_and_update().expect("drain notice");

        state.begin_connection_drain(std::time::Duration::from_secs(60));
        assert_eq!(*receiver.borrow(), Some(first));
    }

    #[test]
    fn inbound_rate_window_enforces_both_frame_and_byte_ceilings() {
        let mut frames = InboundRateWindow::new();
        for _ in 0..WS_MAX_INBOUND_FRAMES_PER_SECOND {
            assert!(frames.admit(1));
        }
        assert!(!frames.admit(1));

        let mut bytes = InboundRateWindow::new();
        assert!(bytes.admit(WS_MAX_INBOUND_BYTES_PER_SECOND as usize));
        assert!(!bytes.admit(1));
    }

    #[test]
    fn account_filter_maps_every_websocket_selector_to_http_semantics() {
        let realm = RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000099".to_owned())
            .expect("realm id");
        let filter = websocket_account_filter(
            arkret_models_collaboration::sync_frames::websocket_binding::WebSocketAccountFilter {
                realms: Some(vec![realm.clone()]),
                timeline_limit: Some(42),
                lazy_load_members: Some(true),
                include_redundant_members: Some(true),
                event_kinds: Some(vec!["ak.message.create".to_owned()]),
                not_event_kinds: Some(vec!["ak.message.redact".to_owned()]),
            },
        );
        assert_eq!(filter.realms, vec![realm]);
        assert_eq!(filter.timeline_limit, Some(42));
        assert!(filter.lazy_load_members);
        assert!(filter.include_redundant_members);
        assert_eq!(filter.event_types, ["ak.message.create"]);
        assert_eq!(filter.not_event_types, ["ak.message.redact"]);
        assert!(filter.extra.is_empty());
    }

    #[test]
    fn actor_device_connection_count_is_bounded_and_released() {
        let session = SessionRecord {
            token_hash: "lease-test".to_owned(),
            actor: "did:example:websocket-lease-test".to_owned(),
            device_id: "device-websocket-lease-test".to_owned(),
            audience: "did:example:service".to_owned(),
            session_public_key: None,
            agent_session: None,
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            created_at: chrono::Utc::now(),
            revoked_at: None,
        };
        let mut leases = Vec::new();
        for _ in 0..WS_MAX_CONNECTIONS_PER_ACTOR_DEVICE {
            leases.push(ConnectionLease::acquire(&session).expect("within limit"));
        }
        assert!(ConnectionLease::acquire(&session).is_none());
        leases.pop();
        assert!(ConnectionLease::acquire(&session).is_some());
    }
}

#[cfg(test)]
mod live_tests;

/// Signal channel: §6.2 — live fanout only. No cursor, no catch-up, no ack.
async fn run_signal_channel(
    state: AppState,
    session: SessionRecord,
    sender: ChannelSender,
    channel_id: String,
) -> WebSocketClosedReason {
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
                return WebSocketClosedReason::Drain;
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

/// A terminal control frame: the channel stops, so it carries the reconnect
/// guard the client must honour before reopening.
fn events_frame(kind: EventsSubscribeFrameKind) -> EventsSubscribeFrame {
    EventsSubscribeFrame {
        kind,
        realm_id: None,
        cursor: None,
        payload: None,
        reconnect_after_ms: Some(SUBSCRIBE_RECONNECT_AFTER_MS),
    }
}

/// A cursor-bearing catch-up control frame (`frontier` / `catchup_complete`).
/// The channel continues, so there is no reconnect hint.
fn events_frame_with_cursor(kind: EventsSubscribeFrameKind, cursor: &str) -> EventsSubscribeFrame {
    EventsSubscribeFrame {
        kind,
        realm_id: None,
        cursor: Cursor::new(cursor.to_owned()).ok(),
        payload: None,
        reconnect_after_ms: None,
    }
}

fn events_resync_required_frame() -> EventsSubscribeFrame {
    events_frame(EventsSubscribeFrameKind::ResyncRequired)
}

fn events_unauthorized_frame() -> EventsSubscribeFrame {
    events_frame(EventsSubscribeFrameKind::Unauthorized)
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
        Ok(encoded) => timed_send(socket, Message::text(encoded)).await.is_ok(),
        Err(_) => false,
    }
}

async fn timed_send<S>(sink: &mut S, message: Message) -> Result<(), ()>
where
    S: futures_util::SinkExt<Message> + Unpin,
{
    match tokio::time::timeout(
        tokio::time::Duration::from_millis(WS_WRITE_TIMEOUT_MS),
        sink.send(message),
    )
    .await
    {
        Ok(Ok(())) => Ok(()),
        _ => Err(()),
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
        Ok(encoded) => timed_send(sink, Message::text(encoded)).await.is_ok(),
        Err(_) => false,
    }
}

async fn close_with(socket: &mut WebSocket, code: WebSocketCloseCode, reason: &str) {
    // §8.1 — a reason string never carries a grant, proof, nonce, DID or
    // cursor; these are one-word audit tags.
    let _ = timed_send(socket, Message::close_with(code.as_u16(), reason)).await;
}

async fn close_rejection(socket: &mut WebSocket, rejection: &WebSocketRejection) {
    let code = rejection
        .close_code
        .unwrap_or(WebSocketCloseCode::ProtocolError);
    close_with(socket, code, "frame").await;
}
