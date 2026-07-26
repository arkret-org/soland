//! RTC media handlers.
//!
//! Surfaces:
//! - `POST /_arkret/self/rtc/ice-config` (TURN / STUN list)
//! - `POST /_arkret/self/rtc/token` (media token exchange, AKP-0010)
//!
//! These are the only spec-registered media surfaces. Both are stateless with
//! respect to any ephemeral signaling session: the media token issuer reads the
//! independent durable focus, moderation, and per-leg mute-override cells; ICE
//! config is a transport-layer
//! discovery surface bound to the authenticated `(actor, device)`. STUN/TURN
//! URLs, credential TTLs, and the optional TURN shared secret are
//! operator-configurable via `AppConfig::ice`.

use std::collections::BTreeSet;

use arkret_event_draft::Operation;
use arkret_identifiers::{CellRef, DeviceId, Did, Hash, OperationId, RealmId};
use arkret_models_collaboration::objects::media::{
    MediaIceConfigOutcome, MediaIceConfigRequestBody, MediaIceConfigSignature,
    MediaIceCredentialType, MediaIceMode, MediaIceServer, MediaIceSignatureAlgorithm,
    MediaIceSignatureInput,
};
use arkret_wire::{DidUrl, XExtensionMap};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::Signer as _;
use salvo::http::HeaderValue;
use salvo::oapi::endpoint;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_http::error::{AppError, ErrorCode};
use soland_http::result::{JsonResult, json_ok};
use soland_services::events::CanonicalEventRecord;
use soland_services::identity::SessionIdentityState as SessionRecord;

use super::{now, realm_has_member, sha256_hex, validate_device_id, validate_did};
use crate::ids;
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::{
    CallMediaParticipantBinding, CallMediaServiceSignature, CallMediaTokenExchangeOutcome,
    CallMediaTokenExchangeRequestBody,
};

/// Spec-canonical RTC media surface. Mounted under the `self` trust segment by
/// `interop::router()` so the only spec-registered media paths resolve at
/// `/_arkret/self/rtc/ice-config` and `/_arkret/self/rtc/token` (see
/// `contract-catalog.json` / the OpenAPI binding). Ephemeral call signaling is
/// the spec-registered `/_arkret/self/ephemeral` `ak.call.signal` relay (see
/// `routing::events::sync::ephemeral`); the durable call model is the composite
/// call-cell lattice. The legacy soland-internal `/_soland/self/webrtc/*`
/// session stack has been removed — token/ICE authz and focus/ban now read the
/// independent durable cells directly.
pub(super) fn protocol_router() -> Router {
    Router::new()
        // Spec-canonical signed ICE config (`/_arkret/self/rtc/ice-config`).
        .push(Router::with_path("rtc/ice-config").post(arkret_ice_config))
        // AKP-0010 — media token exchange (`/_arkret/self/rtc/token`).
        .push(Router::with_path("rtc/token").post(arkret_rtc_token))
}

#[derive(Clone, Debug)]
struct IceConfigRequestContext {
    pub realm_id: RealmId,
    pub call_id: String,
    pub actor_id: Did,
    pub device_id: DeviceId,
    pub force_turn: bool,
}

#[endpoint(
    operation_id = "ak.self.media.query.ice_config",
    summary = "Get media ICE configuration",
    tags("media")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.media.query.ice_config"))]
async fn arkret_ice_config(
    aa: AuthArgs,
    body: JsonBody<MediaIceConfigRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonResult<MediaIceConfigOutcome> {
    set_ice_config_cache_headers(res);
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    issue_ice_config(
        state,
        &session,
        IceConfigRequestContext {
            realm_id: body.realm_id,
            call_id: body.call_id,
            actor_id: body.actor_id,
            device_id: body.device_id,
            force_turn: matches!(body.mode, MediaIceMode::Turn),
        },
    )
    .await
}

async fn issue_ice_config(
    state: &AppState,
    session: &SessionRecord,
    body: IceConfigRequestContext,
) -> JsonResult<MediaIceConfigOutcome> {
    let realm_id = body.realm_id.as_str();
    let call_id = body.call_id.as_str();
    if call_id.is_empty() {
        return Err(AppError::missing_param("call_id is required"));
    }
    let actor_id = body.actor_id.as_str();
    let device_id = body.device_id.as_str();

    if !is_valid_webrtc_session_id(call_id) {
        return Err(AppError::invalid_param("invalid call_id"));
    }
    if validate_did(actor_id).is_err() || actor_id != session.actor {
        return Err(AppError::invalid_param(
            "actor_id must match the authenticated actor",
        ));
    }
    if validate_device_id(device_id).is_err() || device_id != session.device_id {
        return Err(AppError::invalid_param(
            "device_id must match the authenticated device",
        ));
    }
    // `webrtc-signaling.md` §4 — ICE config is a transport-layer discovery
    // surface bound to the authenticated `(actor, device)`. It precedes the
    // `ak.call.state` roster (a caller fetches TURN/STUN before it has
    // committed its participant row, and the callee fetches it while the call
    // is still ringing), so call existence MUST NOT be enforced here. The only
    // authorization gate is realm membership; the per-call ban gate lives on
    // the media token issuer, not on ICE discovery.
    if !realm_has_member(state, realm_id, actor_id).await {
        return Err(AppError::capability_denied(
            "actor is not a joined member of the realm",
        ));
    }

    let issued_at = now();
    let ttl_seconds: u32 = state.config().ice.ttl_seconds;
    // `webrtc-signaling.md` §4.2 — `refresh_lead_seconds` MUST be strictly less
    // than `ttl_seconds`; a server MUST NOT issue `lead >= ttl` or the client
    // would judge the credential stale at issuance and storm refresh. The env
    // value is operator-configurable, so clamp it at the signing point: cap to
    // `ttl_seconds - 1` and keep the schema floor (>= 10) when `ttl` is large
    // enough to admit it.
    let refresh_lead_seconds: u32 =
        clamp_refresh_lead_seconds(state.config().ice.refresh_lead_seconds, ttl_seconds);
    let expires_at = issued_at + Duration::seconds(i64::from(ttl_seconds));
    // `webrtc-signaling.md` §4.1 — coarse-grained bucket the TURN pseudonym
    // is derived against. v1 fixes `bucket_seconds = 300`; `issued_at_bucket
    // = floor(issued_at / bucket_seconds) * bucket_seconds`. Refreshes inside
    // the same bucket land on the same pseudonym (§4.2 active-leg reuse),
    // while crossing into the next bucket rotates it.
    let bucket_seconds: u32 = ICE_PSEUDONYM_BUCKET_SECONDS;
    let issued_at_bucket = floor_to_bucket(issued_at, bucket_seconds);
    let force_turn = body.force_turn;
    // `webrtc-signaling.md` §4.1 — REST-style (draft-uberti) TURN credential.
    // username = `<expiry-unix>:<pairwise-pseudonym>`; the pseudonym keeps the
    // existing private-key-derived `ak_pseudonym_call_<16hex>` form (does not
    // leak identity), and `<expiry-unix>` is the credential's own expiry so
    // coturn enforces TTL on its side.
    let pseudonym = pairwise_turn_username(
        state,
        realm_id,
        call_id,
        actor_id,
        device_id,
        issued_at_bucket,
    );
    let turn_username = format!("{}:{}", expires_at.timestamp(), pseudonym);
    // credential = base64( HMAC-SHA256(turn_shared_secret, username) ) — the
    // HMAC is taken over the full REST-style username (SHA256, never SHA1).
    let turn_credential = turn_rest_credential(state, &turn_username);
    let turn_server = MediaIceServer {
        urls: state.config().ice.turn_urls.clone(),
        username: Some(turn_username.clone()),
        credential: Some(turn_credential),
        credential_type: Some(MediaIceCredentialType::Password),
    };
    let mut ice_servers = vec![MediaIceServer {
        urls: state.config().ice.stun_urls.clone(),
        username: None,
        credential: None,
        credential_type: None,
    }];
    ice_servers.push(turn_server.clone());
    if force_turn {
        ice_servers = vec![turn_server.clone()];
    }
    let mut response = MediaIceConfigOutcome {
        realm_id: body.realm_id,
        call_id: call_id.to_owned(),
        actor_id: body.actor_id,
        device_id: body.device_id,
        ice_servers,
        ttl_seconds,
        refresh_lead_seconds,
        issued_at,
        issued_at_bucket,
        bucket_seconds,
        expires_at: Some(expires_at),
        force_turn,
        constraints: None,
        next_retry_at: None,
        signature: MediaIceConfigSignature {
            kid: format!("{}#notary-key", state.service_id()),
            alg: MediaIceSignatureAlgorithm::EdDsa,
            signature_input: MediaIceSignatureInput::IceConfigV1,
            payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))
                .map_err(|error| AppError::internal(format!("ICE config digest: {error}")))?,
            sig: String::new(),
        },
        extensions: XExtensionMap::default(),
    };
    sign_ice_config_outcome(state, &mut response)?;
    json_ok(response)
}

fn set_ice_config_cache_headers(res: &mut Response) {
    res.headers_mut().insert(
        "cache-control",
        HeaderValue::from_static("private, no-store"),
    );
    res.headers_mut()
        .insert("pragma", HeaderValue::from_static("no-cache"));
}

/// `webrtc-signaling.md` §4.1 — v1 fixes the TURN pseudonym bucket at 300s.
const ICE_PSEUDONYM_BUCKET_SECONDS: u32 = 300;

/// Schema-aligned floor for `refresh_lead_seconds`
/// (`ice-config-response.schema.json`: `minimum: 10`).
const ICE_REFRESH_LEAD_FLOOR_SECONDS: u32 = 10;

/// `webrtc-signaling.md` §4.2 — server-side guarantee that
/// `refresh_lead_seconds < ttl_seconds`. The operator-configured lead is
/// clamped at issuance so the response always satisfies the MUST: the lead is
/// capped to `ttl_seconds - 1`. When `ttl_seconds` is large enough that the
/// schema floor (10s) still leaves `floor < ttl`, the result is also held at or
/// above that floor; for very small `ttl` the cap to `ttl - 1` wins so the
/// strict-inequality invariant holds even below the floor.
fn clamp_refresh_lead_seconds(configured: u32, ttl_seconds: u32) -> u32 {
    let ceiling = ttl_seconds.saturating_sub(1);
    let clamped = configured.min(ceiling);
    if ttl_seconds > ICE_REFRESH_LEAD_FLOOR_SECONDS {
        clamped.max(ICE_REFRESH_LEAD_FLOOR_SECONDS)
    } else {
        clamped
    }
}

/// `floor(timestamp / bucket_seconds) * bucket_seconds` as a UTC timestamp.
fn floor_to_bucket(timestamp: DateTime<Utc>, bucket_seconds: u32) -> DateTime<Utc> {
    let bucket = i64::from(bucket_seconds).max(1);
    let floored = timestamp.timestamp().div_euclid(bucket) * bucket;
    DateTime::<Utc>::from_timestamp(floored, 0).unwrap_or(timestamp)
}

/// Per-call pairwise TURN pseudonym (`webrtc-signaling.md` §4.1). The
/// identity segment is `ak_pseudonym_call_<16-hex>` and MUST NOT leak the
/// principal DID / handle / a stable cross-call id to the TURN operator.
///
/// Freshness (§4.1 lines 204/213): the pseudonym is HMAC-derived under the
/// media-service private key (the notary signing seed) — *not* a plain hash
/// of stable ids — bound to `(realm_id, call_id, actor_id, device_id,
/// issued_at_bucket)` plus a fresh per-bucket `nonce` derived from the same
/// secret. Because the secret is private to this media service, the result is
/// unlinkable to the TURN operator yet stable across refreshes within one
/// bucket (§4.2 active-leg reuse) and rotates when the bucket advances.
fn pairwise_turn_username(
    state: &AppState,
    realm_id: &str,
    call_id: &str,
    actor_id: &str,
    device_id: &str,
    issued_at_bucket: DateTime<Utc>,
) -> String {
    let secret = state.notary_signing_key().to_bytes();
    let bucket = issued_at_bucket.timestamp();
    // Fresh per-(call,actor,device,bucket) nonce, derived from the private
    // media-service secret so it is not recomputable off stable ids alone and
    // not a deterministic function of the public identifiers.
    let nonce_material = format!(
        "soland-turn-pseudonym-nonce-v1\0{realm_id}\0{call_id}\0{actor_id}\0{device_id}\0{bucket}"
    );
    let nonce = hmac_sha256(&secret, nonce_material.as_bytes());
    let pseudonym_input = json!({
        "realm_id": realm_id,
        "call_id": call_id,
        "actor_id": actor_id,
        "device_id": device_id,
        "issued_at_bucket": bucket,
        "nonce": URL_SAFE_NO_PAD.encode(nonce),
    });
    let pseudonym_bytes = arkret_canonical::canonical_json_bytes(&pseudonym_input)
        .unwrap_or_else(|_| pseudonym_input.to_string().into_bytes());
    let tag = hmac_sha256(&secret, &pseudonym_bytes);
    format!("ak_pseudonym_call_{}", hex::encode(&tag[..8]))
}

/// `webrtc-signaling.md` §4.1 — REST-style (draft-uberti) TURN credential:
/// `credential = base64( HMAC-SHA256(turn_shared_secret, username) )`. The
/// HMAC is over the full `<expiry-unix>:<pseudonym>` username and uses SHA256
/// (never the legacy SHA1). The credential is standard base64 (with padding),
/// matching what an external coturn expects.
///
/// `turn_shared_secret` comes from `state.config().ice.turn_shared_secret`
/// (`SOLAND_TURN_SHARED_SECRET`, W1). When unset, a deployment-stable fallback
/// key is derived from the notary signing seed so credentials stay
/// self-consistent across issue/refresh within this deployment; production
/// deployments fronting an external coturn MUST set `SOLAND_TURN_SHARED_SECRET`
/// to the same secret coturn is configured with.
fn turn_rest_credential(state: &AppState, username: &str) -> String {
    let configured = state.config().ice.turn_shared_secret.as_deref();
    let fallback;
    let secret: &[u8] = match configured {
        Some(secret) => secret.as_bytes(),
        None => {
            fallback = hmac_sha256(
                &state.notary_signing_key().to_bytes(),
                b"soland-turn-shared-secret-fallback-v1",
            );
            &fallback
        }
    };
    base64::engine::general_purpose::STANDARD.encode(hmac_sha256(secret, username.as_bytes()))
}

/// Sign the typed SDK response using its single protocol-owned canonical
/// payload and domain-separated transcript implementation.
fn sign_ice_config_outcome(
    state: &AppState,
    outcome: &mut MediaIceConfigOutcome,
) -> Result<(), AppError> {
    let payload_bytes = outcome
        .canonical_signature_payload()
        .map_err(|error| AppError::internal(format!("ICE config canonicalize: {error}")))?;
    let payload_digest = arkret_canonical::sha256_digest(&payload_bytes);
    let signing_input = outcome
        .signature_input()
        .map_err(|error| AppError::internal(format!("ICE config transcript: {error}")))?;
    let signature = state.notary_signing_key().sign(&signing_input);
    outcome.signature.payload_digest = Hash::new(payload_digest)
        .map_err(|error| AppError::internal(format!("ICE config digest: {error}")))?;
    outcome.signature.sig = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    Ok(())
}

// ── AKP-0010 (R3 spec-sync 2026-05-27, arkret-spec b47ff6ec) — media
// token exchange. Issues a backend_token + ParticipantBinding for a
// caller that already has a committed `ak.component.call.focus.v1` value.
//
// Wire-level checks implemented here:
//   - `focus_id` must equal the call's committed session_focus → `focus_mismatch` (MEDIA-2,
//     REDU-3).
//   - Focus selection is oldest-membership-wins; until the session_focus cell is wired through the
//     reducer, the handler derives the focus from the call participants and their latest
//     `foci_preferred[]` signal.
//   - Token TTL ≤ `MEDIA_TOKEN_TTL_MAX_SECS` (600s); default `MEDIA_TOKEN_TTL_SHOULD_SECS` (300s)
//     (MEDIA-1).
//   - `service_signature.kid` / `participant_binding.issuer_kid` resolves to the current
//     `ak.realm.media_service.service_id` epoch → `token_issuer_unauthorised` (MEDIA-1).
const REALM_MEDIA_SERVICE_CELL_FAMILY: &str = "ak.component.realm.media_service.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MediaProviderKind {
    ArkretNative,
    LiveKit,
    Mediasoup,
}

impl MediaProviderKind {
    fn parse(value: &str) -> Result<Self, AppError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "arkret-native" => Ok(Self::ArkretNative),
            "livekit" => Ok(Self::LiveKit),
            "mediasoup" => Ok(Self::Mediasoup),
            _ => Err(AppError::new(
                ErrorCode::InvalidParam,
                format!("unknown media focus provider `{value}`"),
            )
            .with_wire_code(arkret_wire::ReasonCode::UNKNOWN_FOCUS_TYPE)),
        }
    }

    fn as_wire(self) -> &'static str {
        match self {
            Self::ArkretNative => "arkret-native",
            Self::LiveKit => "livekit",
            Self::Mediasoup => "mediasoup",
        }
    }

    fn token_prefix(self) -> &'static str {
        match self {
            Self::ArkretNative => "arkret-native",
            Self::LiveKit => "livekit",
            Self::Mediasoup => "mediasoup",
        }
    }
}

#[derive(Clone, Debug)]
struct MediaProviderConfig {
    provider: MediaProviderKind,
    focus_id: String,
    issuer_kid: String,
    audience: String,
    ttl_seconds: u64,
    connect_url: Option<String>,
}

#[derive(Clone, Debug)]
struct MediaServiceEpoch {
    service_id: String,
    issuer_kids: BTreeSet<String>,
    foci: Vec<MediaProviderConfig>,
}

impl MediaServiceEpoch {
    fn focus(&self, focus_id: &str) -> Option<&MediaProviderConfig> {
        self.foci.iter().find(|focus| focus.focus_id == focus_id)
    }

    fn focus_ids(&self) -> Vec<String> {
        self.foci
            .iter()
            .map(|focus| focus.focus_id.clone())
            .collect()
    }
}

struct MediaTokenIssueRequestBody<'a> {
    focus: &'a MediaProviderConfig,
    realm_id: &'a str,
    call_id: &'a str,
    actor_id: &'a str,
    device_id: &'a str,
    participant_identity: &'a str,
    /// Publish intent derived from the request `desired_media` (LiveKit
    /// `video.canPublishSources`). `(audio, video, screen)`.
    desired_media: (bool, bool, bool),
    /// Whether the caller carries `ak.call.screen_share` (gates the
    /// `screen_share` publish source per `bindings/livekit.md` §5).
    allow_screen_share: bool,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

struct IssuedMediaToken {
    backend_token: String,
    connect_url: Option<String>,
}

/// Per-provider signing material handed to a [`MediaTokenIssuer`]. The
/// ed25519 notary key signs the `arkret-native` / `mediasoup` envelopes;
/// LiveKit needs the deployment's API Key/Secret to emit a real LiveKit
/// JWT (`bindings/livekit.md` §2).
struct MediaTokenSigningContext<'a> {
    notary_signing_key: &'a ed25519_dalek::SigningKey,
    livekit: &'a crate::config::LiveKitConfig,
}

trait MediaTokenIssuer {
    fn issue(
        &self,
        request: &MediaTokenIssueRequestBody<'_>,
        ctx: &MediaTokenSigningContext<'_>,
    ) -> Result<IssuedMediaToken, AppError>;
}

struct ArkretNativeMediaIssuer;
struct LiveKitMediaIssuer;
struct MediasoupMediaIssuer;

impl MediaTokenIssuer for ArkretNativeMediaIssuer {
    fn issue(
        &self,
        request: &MediaTokenIssueRequestBody<'_>,
        ctx: &MediaTokenSigningContext<'_>,
    ) -> Result<IssuedMediaToken, AppError> {
        Ok(issue_signed_backend_token(
            MediaProviderKind::ArkretNative,
            request,
            ctx.notary_signing_key,
        ))
    }
}

impl MediaTokenIssuer for LiveKitMediaIssuer {
    fn issue(
        &self,
        request: &MediaTokenIssueRequestBody<'_>,
        ctx: &MediaTokenSigningContext<'_>,
    ) -> Result<IssuedMediaToken, AppError> {
        issue_livekit_backend_token(request, ctx.livekit)
    }
}

impl MediaTokenIssuer for MediasoupMediaIssuer {
    fn issue(
        &self,
        request: &MediaTokenIssueRequestBody<'_>,
        ctx: &MediaTokenSigningContext<'_>,
    ) -> Result<IssuedMediaToken, AppError> {
        Ok(issue_signed_backend_token(
            MediaProviderKind::Mediasoup,
            request,
            ctx.notary_signing_key,
        ))
    }
}

async fn handle_rtc_token(
    state: &AppState,
    session: &SessionRecord,
    body: CallMediaTokenExchangeRequestBody,
) -> JsonResult<CallMediaTokenExchangeOutcome> {
    use soland_http::error::ErrorCode;

    // The request body is the SDK typed shape: `realm_id`/`call_id`/`actor_id`/
    // `device_id` arrive already validated as the corresponding scalar id types,
    // and the response binding carries the same typed ids — so the wire outcome
    // reuses `arkret_models_collaboration::objects::media::CallMediaTokenExchangeOutcome` directly
    // instead of a stringly soland mirror.
    let realm_id = body.realm_id.clone();
    if !is_valid_webrtc_session_id(body.call_id.as_str()) {
        return Err(AppError::invalid_param("invalid call_id"));
    }
    let call_id = body.call_id.clone();
    if body.actor_id.as_str() != session.actor {
        return Err(AppError::invalid_param(
            "actor_id must match the authenticated actor",
        ));
    }
    let actor_id = body.actor_id.clone();
    if body.device_id.as_str() != session.device_id {
        return Err(AppError::invalid_param(
            "device_id must match the authenticated device",
        ));
    }
    let device_id = body.device_id.clone();
    if body.focus_id.trim().is_empty() {
        return Err(AppError::invalid_param("focus_id is required"));
    }
    // Authz (`media-service-binding.md` §6 commit ordering) — the token issuer does NOT
    // depend on any ephemeral signaling session. Per `media-service-binding.md`
    // the client redeems the media token BEFORE it joins the durable
    // `ak.component.call.roster.v1` OR-Set (the initiator may exchange a token
    // when no call cell exists yet), so a roster-membership
    // / session-not-found gate would be wrong. Authorization is the conjunction
    // of: (1) realm membership, (2) the `ak.call.join` capability, (3) not under
    // an actor-wide ban in the durable call moderation OR-Set.
    //
    // (1) realm member.
    if !realm_has_member(state, body.realm_id.as_str(), body.actor_id.as_str()).await {
        return Err(AppError::capability_denied(
            "actor is not a joined member of the realm",
        ));
    }
    // (2) `media-service-binding.md` §6 — token exchange is gated on the
    // `ak.call.join` capability, not merely realm membership. §6 defines no
    // dedicated error code, so we surface the generic `capability_denied` (403).
    if !actor_has_call_capability(
        state,
        body.realm_id.as_str(),
        body.actor_id.as_str(),
        CAP_CALL_JOIN,
    )
    .await
    {
        return Err(AppError::capability_denied(
            "actor does not hold the ak.call.join capability for this realm",
        ));
    }

    // Read the independent durable media-policy cells once. They MAY all be
    // absent when a brand-new call initiator redeems a token before writing its
    // first `ak.call.state` event. Absent cells mean no committed focus or ban.
    let call_cells = CallMediaCells::load(
        state,
        body.call_id.as_str(),
        body.actor_id.as_str(),
        body.device_id.as_str(),
    )
    .await?;

    // (3) `webrtc-signaling.md` §3a — a banned actor MUST NOT re-issue a join
    // token for this call's lifetime. The ban set is the durable
    // call moderation effective OR-Set; an absent cell carries
    // no bans (everyone passes).
    if call_cells.actor_is_banned(body.actor_id.as_str()) {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "actor was removed from the call (ban) and cannot re-issue a join token",
        )
        .with_status(StatusCode::FORBIDDEN)
        .with_wire_code(arkret_wire::ReasonCode::CALL_PARTICIPANT_REMOVED));
    }
    let media_epoch = media_service_epoch_for_realm(state, body.realm_id.as_str())?;

    // MEDIA-2 — focus selection. A committed
    // `ak.component.call.focus.v1` value wins when present and `focus_id`
    // MUST match it (`focus_mismatch`). Absent a committed focus, the issuer
    // admits the requested `focus_id` as long as it is a legal focus within the
    // realm media_service epoch (oldest-membership-wins reduces to "any epoch
    // focus" once the ephemeral foci_preferred[] session is gone; the durable
    // committed focus remains the binding decision).
    let session_focus = session_focus_for_call(&call_cells, &media_epoch, body.focus_id.as_str())?;
    if body.focus_id != session_focus {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            format!(
                "focus_id `{}` does not match committed session_focus `{}`",
                body.focus_id, session_focus
            ),
        )
        .with_wire_code(arkret_wire::ReasonCode::FOCUS_MISMATCH));
    }
    let focus = media_epoch.focus(&session_focus).ok_or_else(|| {
        focus_unavailable_error("selected focus is not present in media_service epoch")
    })?;
    if !media_epoch.issuer_kids.contains(&focus.issuer_kid)
        || !issuer_kid_belongs_to_service(&focus.issuer_kid, &media_epoch.service_id)
    {
        return Err(token_issuer_unauthorised(format!(
            "issuer_kid `{}` is not sealed to media_service service_id `{}`",
            focus.issuer_kid, media_epoch.service_id
        )));
    }
    // MEDIA-1 — token TTL defaults to 300s and is capped at the spec ceiling
    // even if the realm focus advertises a larger backend TTL.
    let ttl_secs = focus
        .ttl_seconds
        .clamp(1, arkret_wire::constants::MEDIA_TOKEN_TTL_MAX_SECS);
    let issued_at = now();
    let expires_at = issued_at + Duration::seconds(ttl_secs as i64);

    // `media-service-binding.md` §3 — participant_identity is an SFU-local
    // handle that MUST NOT be a deterministic function of the public principal
    // tuple. Mint a fresh random `ak:rtc_participant:<uuidv7>` per token
    // exchange so the SFU cannot be linked back to (realm, call, actor, device)
    // by recomputing the id, and the wire form matches the schema pattern
    // `^ak:rtc_participant:<uuidv7>$`.
    let participant_identity = arkret_identifiers::new_prefixed_uuid7("ak:rtc_participant:");
    let signing_key = state.notary_signing_key();
    // `bindings/livekit.md` §2/§5 — publish grants are derived from the
    // caller's `desired_media`. Absent the field we default to audio+video
    // (no screen): screen capture is an opt-in source gated by
    // `ak.call.screen_share`. Durable moderator mute overrides are applied
    // here so every backend token is minted with the narrowed send permission.
    let mut desired_media = body
        .desired_media
        .as_ref()
        .map(|media| {
            (
                media.audio.unwrap_or(true),
                media.video.unwrap_or(true),
                media.screen.unwrap_or(false),
            )
        })
        .unwrap_or((true, true, false));
    let (audio_muted, video_muted) =
        call_cells.participant_mute_override(body.actor_id.as_str(), body.device_id.as_str());
    if audio_muted {
        desired_media.0 = false;
    }
    if video_muted {
        desired_media.1 = false;
    }
    // `bindings/livekit.md` §5 — the `screen_share` publish source is gated by
    // a real `ak.call.screen_share` capability, not merely the presence of any
    // `capability_refs`. Resolve it against the projected grants so an actor
    // without the capability never receives a screen-share publish grant.
    let allow_screen_share = actor_has_call_capability(
        state,
        body.realm_id.as_str(),
        body.actor_id.as_str(),
        CAP_CALL_SCREEN_SHARE,
    )
    .await;
    let issue_request = MediaTokenIssueRequestBody {
        focus,
        realm_id: body.realm_id.as_str(),
        call_id: body.call_id.as_str(),
        actor_id: body.actor_id.as_str(),
        device_id: body.device_id.as_str(),
        participant_identity: &participant_identity,
        desired_media,
        allow_screen_share,
        issued_at,
        expires_at,
    };
    let signing_ctx = MediaTokenSigningContext {
        notary_signing_key: &signing_key,
        livekit: &state.config().livekit,
    };
    let issued_token =
        media_token_issuer_for(focus.provider).issue(&issue_request, &signing_ctx)?;

    let issuer_kid = DidUrl::new(focus.issuer_kid.clone()).map_err(|error| {
        token_issuer_unauthorised(format!(
            "media focus issuer_kid is not a verification-method DID URL: {error}"
        ))
    })?;
    // `media-service-binding.md` §3 — the signature covers ONLY the seven
    // authoritative fields `(actor_id, call_id, device_id, expires_at, focus_id,
    // participant_identity, realm_id)`. The self-describing `scheme` /
    // `issuer_kid` / `issued_at` are unsigned wire metadata and MUST NOT enter
    // the signing input. Timestamps are serialized verbatim to RFC3339 strings
    // matching the wire binding so the verifier reconstructs identical bytes.
    let signed_binding = super::participant_binding::binding_canonical_value(
        &json!(body.realm_id),
        &json!(body.call_id),
        &json!(body.focus_id),
        &json!(body.actor_id),
        &json!(body.device_id),
        &json!(participant_identity),
        &json!(expires_at),
    );
    // The binding `sig` is produced through the shared
    // `participant_binding` helper so the issue side and the
    // operation-admission verify side share one canonical-bytes +
    // signing-input definition (`media-service-binding.md` §3 / §7).
    let signing_input = super::participant_binding::binding_signing_input(
        &super::participant_binding::binding_canonical_bytes(&signed_binding),
    );
    let sig = super::participant_binding::sign_binding(&signed_binding, &signing_key);

    // `media-service-binding.md` §3 — the detached service signature is a typed
    // `{kid, sig}` object over the **same** `signing_input` (same label + same
    // seven-field tuple), committing the issuer identity of the whole token
    // exchange response. `kid` is the realm media-service anchor (the focus
    // issuer_kid); `sig` is the base64url detached Ed25519 signature.
    let service_sig = signing_key.sign(&signing_input);
    let service_signature = CallMediaServiceSignature {
        kid: issuer_kid.clone(),
        sig: URL_SAFE_NO_PAD.encode(service_sig.to_bytes()),
    };

    let participant_binding = CallMediaParticipantBinding {
        scheme: arkret_wire::constants::PARTICIPANT_BINDING_SCHEMA.to_owned(),
        sig,
        issuer_kid,
        realm_id,
        call_id,
        focus_id: body.focus_id.clone(),
        actor_id,
        device_id,
        participant_identity: participant_identity.clone(),
        issued_at,
        expires_at,
    };

    // Spec `CallMediaTokenExchangeOutcome` requires `connect_url`; a focus
    // that does not declare one cannot be exchanged into a usable media
    // session, so fail closed instead of returning a partial outcome.
    let connect_url = issued_token
        .connect_url
        .ok_or_else(|| focus_unavailable_error("selected focus does not declare a connect_url"))?;

    json_ok(CallMediaTokenExchangeOutcome {
        focus_id: body.focus_id,
        backend_type: focus.provider.as_wire().to_owned(),
        connect_url,
        backend_token: issued_token.backend_token,
        participant_identity,
        participant_binding,
        expires_at,
        service_signature,
    })
}

/// MEDIA-2 focus selection against `ak.component.call.focus.v1`.
///
/// - A committed `session_focus` is the binding decision: it is returned verbatim provided it is
///   still a legal focus within the current realm media_service epoch (the caller compares it
///   against the request `focus_id` and surfaces `focus_mismatch` on a disagreement).
/// - Absent a committed focus (a brand-new call whose focus cell is still bottom), the issuer
///   admits the `requested_focus_id` as long as it names a legal focus in the epoch. This replaces
///   the old ephemeral oldest-membership-wins derivation that read `foci_preferred[]` off a
///   signaling session: the durable committed focus is the source of truth, and until it is
///   committed any epoch-legal focus the caller asks for is acceptable (the first committer's focus
///   then pins it for everyone via the cell's write-once `session_focus`).
fn session_focus_for_call(
    call_cells: &CallMediaCells,
    media_epoch: &MediaServiceEpoch,
    requested_focus_id: &str,
) -> Result<String, AppError> {
    if let Some(focus) = call_cells.session_focus() {
        if media_epoch.focus(focus).is_some() {
            return Ok(focus.to_owned());
        }
        return Err(focus_unavailable_error(
            "committed session_focus is not present in current media_service epoch",
        ));
    }

    let requested = requested_focus_id.trim();
    if !requested.is_empty() && media_epoch.focus(requested).is_some() {
        return Ok(requested.to_owned());
    }
    // No committed focus and the request did not name a legal epoch focus: fall
    // back to a deterministic default so the issuer can still mint a token for a
    // well-formed epoch (the mismatch against `requested_focus_id` is then
    // surfaced as `focus_mismatch` by the caller).
    if let Some(focus_id) = media_epoch.focus_ids().into_iter().next() {
        return Ok(focus_id);
    }
    Err(focus_unavailable_error(
        "realm media_service epoch has no available foci",
    ))
}

/// Read-only view of the independent durable focus, moderation and per-leg
/// mute cells consumed by the media token issuer.
struct CallMediaCells {
    focus: Option<Value>,
    moderation: Option<Value>,
    mute_override: Option<Value>,
}

impl CallMediaCells {
    async fn load(
        state: &AppState,
        call_id: &str,
        actor_id: &str,
        device_id: &str,
    ) -> Result<Self, AppError> {
        let focus_cell = call_cell_ref("ak.component.call.focus.v1", &[call_id])?;
        let moderation_cell = call_cell_ref("ak.component.call.moderation.v1", &[call_id])?;
        let mute_cell = call_cell_ref(
            "ak.component.call.mute_override.v1",
            &[call_id, actor_id, device_id],
        )?;
        Ok(Self {
            focus: load_call_cell(state, call_id, focus_cell).await?,
            moderation: load_call_cell(state, call_id, moderation_cell).await?,
            mute_override: load_call_cell(state, call_id, mute_cell).await?,
        })
    }

    /// The committed `ak.component.call.focus.v1` value, if any.
    fn session_focus(&self) -> Option<&str> {
        self.focus
            .as_ref()?
            .get("session_focus")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|focus| !focus.is_empty())
    }

    /// Whether `actor_id` is under an actor-wide ban in the moderation
    /// effective OR-Set. A ban value omits `device_id`.
    /// An absent cell carries no bans.
    fn actor_is_banned(&self, actor_id: &str) -> bool {
        let Some(rows) = self.moderation.as_ref().and_then(Value::as_array) else {
            return false;
        };
        rows.iter().any(|entry| {
            if entry.get("removed").and_then(Value::as_bool) == Some(true) {
                return false;
            }
            let row = entry.get("value").unwrap_or(&Value::Null);
            row.get("action").and_then(Value::as_str) == Some("ban")
                && row.get("actor_id").and_then(Value::as_str) == Some(actor_id)
        })
    }

    /// Current moderator mute override for this call leg. Duplicate malformed
    /// rows fail closed: any matching `*_muted=true` removes that publish
    /// permission from the issued backend token.
    fn participant_mute_override(&self, actor_id: &str, device_id: &str) -> (bool, bool) {
        let Some(value) = self.mute_override.as_ref() else {
            return (false, false);
        };
        if value.get("status").and_then(Value::as_str) != Some("active")
            || value.get("actor_id").and_then(Value::as_str) != Some(actor_id)
            || value.get("device_id").and_then(Value::as_str) != Some(device_id)
        {
            return (false, false);
        }
        (
            value
                .get("audio_muted")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            value
                .get("video_muted")
                .and_then(Value::as_bool)
                .unwrap_or(true),
        )
    }
}

fn call_cell_ref(family: &str, subject_parts: &[&str]) -> Result<CellRef, AppError> {
    let subject = if subject_parts.len() == 1 {
        subject_parts[0].to_owned()
    } else {
        arkret_wire::composite_subject(subject_parts)
            .map_err(|error| AppError::internal(format!("invalid call cell subject: {error}")))?
    };
    CellRef::new(format!("ak:cell:{family}:{subject}"))
        .map_err(|error| AppError::internal(format!("invalid call cell id: {error}")))
}

async fn load_call_cell(
    state: &AppState,
    call_id: &str,
    cell_id: CellRef,
) -> Result<Option<Value>, AppError> {
    let cached = {
        let projection = state.projections().snapshot();
        projection.cell_value(&cell_id).cloned()
    };
    match call_state_from_event_log(state, call_id, &cell_id).await? {
        Some(value) => {
            state.projections().cache_cell(cell_id, value.clone());
            Ok(Some(value))
        }
        None => Ok(cached),
    }
}

async fn call_state_from_event_log(
    state: &AppState,
    call_id: &str,
    cell_id: &CellRef,
) -> Result<Option<Value>, AppError> {
    let mut records = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| AppError::internal(format!("events store unavailable: {error}")))?
        .into_iter()
        .filter(|record| {
            record.kind == arkret_wire::events::EventKind::CALL_STATE
                && record_call_id(record) == Some(call_id)
        })
        .collect::<Vec<_>>();
    if records.is_empty() {
        return Ok(None);
    }
    records.sort_by(|left, right| {
        left.received_at
            .cmp(&right.received_at)
            .then_with(|| left.actor_seq.cmp(&right.actor_seq))
            .then_with(|| left.event_id.cmp(&right.event_id))
    });

    let mut operations = Vec::new();
    for record in &records {
        let Some(operation) = call_state_operation_from_record(record)? else {
            continue;
        };
        operations.push(operation);
    }
    Ok(state
        .projections()
        .project_call_state_cell(&operations, cell_id))
}

fn record_call_id(record: &CanonicalEventRecord) -> Option<&str> {
    record
        .envelope
        .get("payload")
        .and_then(|payload| payload.get("call_id"))
        .and_then(Value::as_str)
}

fn call_state_operation_from_record(
    record: &CanonicalEventRecord,
) -> Result<Option<Operation>, AppError> {
    let Some(realm_id) = crate::routing::events::event_log::canonical_realm_id_for_record(record)
    else {
        return Ok(None);
    };
    let realm_id = RealmId::new(realm_id).map_err(|error| AppError::internal(error.to_string()))?;
    let Some(suffix) = record.event_id.strip_prefix("ak:event:") else {
        return Ok(None);
    };
    let operation_id = OperationId::new(format!("ak:operation:{suffix}"))
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut payload = record
        .envelope
        .get("payload")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if let Some(object) = payload.as_object_mut() {
        if let Some(effects) = record.envelope.get("effects") {
            object.insert("effects".to_owned(), effects.clone());
        }
        if let Some(seal_ref) = record.envelope.get("seal_ref") {
            object.insert("seal_ref".to_owned(), seal_ref.clone());
        }
        object.insert(
            "accepted_event_id".to_owned(),
            Value::String(record.event_id.clone()),
        );
    }
    let mut operation = Operation::create(
        operation_id,
        realm_id,
        arkret_wire::events::EventKind::CALL_STATE,
        payload,
    );
    operation.canonical_event_digest = Some(record.canonical_digest.clone());
    operation.created_at = record
        .envelope
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
        .unwrap_or(record.received_at);
    Ok(Some(operation))
}

fn media_service_epoch_for_realm(
    state: &AppState,
    realm_id: &str,
) -> Result<MediaServiceEpoch, AppError> {
    let cell_id = arkret_identifiers::CellRef::new(format!(
        "ak:cell:{REALM_MEDIA_SERVICE_CELL_FAMILY}:{realm_id}"
    ))
    .map_err(|error| AppError::internal(format!("invalid media_service cell id: {error}")))?;
    let value = {
        let projection = state.projections().snapshot();
        projection.cell_value(&cell_id).cloned()
    }
    .ok_or_else(|| {
        token_issuer_unauthorised(format!(
            "realm `{realm_id}` has no projected ak.realm.media_service epoch"
        ))
    })?;
    parse_media_service_epoch(realm_id, &value)
}

fn parse_media_service_epoch(realm_id: &str, value: &Value) -> Result<MediaServiceEpoch, AppError> {
    let service_id = value
        .get("service_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let foci_value = normalized_media_foci(value)?;
    let mut foci = Vec::new();
    for focus_value in foci_value {
        let focus_id = required_json_string(&focus_value, "focus_id")?;
        let provider = focus_value
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::invalid_param("media focus type is required"))
            .and_then(MediaProviderKind::parse)?;
        let issuer_kid = focus_value
            .get("issuer_kid")
            .or_else(|| value.get("issuer_kid"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                token_issuer_unauthorised("media focus issuer_kid is required".to_owned())
            })?
            .to_owned();
        let audience = focus_value
            .get("audience")
            .or_else(|| value.get("audience"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("arkret:media:{realm_id}:{focus_id}"));
        let ttl_seconds = focus_value
            .get("ttl_seconds")
            .or_else(|| value.get("ttl_seconds"))
            .and_then(Value::as_u64)
            .unwrap_or(arkret_wire::constants::MEDIA_TOKEN_TTL_SHOULD_SECS);
        let connect_url = focus_value
            .get("connect_url")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        foci.push(MediaProviderConfig {
            provider,
            focus_id,
            issuer_kid,
            audience,
            ttl_seconds,
            connect_url,
        });
    }
    if foci.is_empty() {
        return Err(focus_unavailable_error(
            "realm media_service epoch has no foci",
        ));
    }
    let service_id = service_id
        .or_else(|| {
            foci.first()
                .and_then(|focus| service_id_from_issuer_kid(&focus.issuer_kid))
        })
        .ok_or_else(|| {
            token_issuer_unauthorised("media_service service_id is required".to_owned())
        })?;
    let issuer_kids = foci
        .iter()
        .map(|focus| focus.issuer_kid.clone())
        .collect::<BTreeSet<_>>();
    Ok(MediaServiceEpoch {
        service_id,
        issuer_kids,
        foci,
    })
}

fn normalized_media_foci(config: &Value) -> Result<Vec<Value>, AppError> {
    if let Some(foci) = config.get("foci").and_then(Value::as_array) {
        return Ok(foci.clone());
    }
    Err(focus_unavailable_error(
        "realm media_service epoch must contain foci[]",
    ))
}

fn media_token_issuer_for(provider: MediaProviderKind) -> Box<dyn MediaTokenIssuer> {
    match provider {
        MediaProviderKind::ArkretNative => Box::new(ArkretNativeMediaIssuer),
        MediaProviderKind::LiveKit => Box::new(LiveKitMediaIssuer),
        MediaProviderKind::Mediasoup => Box::new(MediasoupMediaIssuer),
    }
}

fn issue_signed_backend_token(
    provider: MediaProviderKind,
    request: &MediaTokenIssueRequestBody<'_>,
    signing_key: &ed25519_dalek::SigningKey,
) -> IssuedMediaToken {
    let nonce = ids::generate("media_token");
    let (audio, video, screen) = token_media_permissions(request);
    let token_payload = json!({
        "iss": request.focus.issuer_kid,
        "aud": request.focus.audience,
        "provider": provider.as_wire(),
        "realm_id": request.realm_id,
        "call_id": request.call_id,
        "focus_id": request.focus.focus_id,
        "actor_id": request.actor_id,
        "device_id": request.device_id,
        "participant_identity": request.participant_identity,
        "iat": request.issued_at,
        "exp": request.expires_at,
        "media": {
            "audio": audio,
            "video": video,
            "screen": screen,
        },
        "nonce": nonce,
    });
    let token_bytes = arkret_canonical::canonical_json_bytes(&token_payload)
        .unwrap_or_else(|_| token_payload.to_string().into_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(&token_bytes);
    let signing_input = format!(
        "soland-media-backend-token-v1\0{}\0{}",
        provider.as_wire(),
        payload_b64
    );
    let sig = signing_key.sign(signing_input.as_bytes());
    IssuedMediaToken {
        backend_token: format!(
            "{}.{}.{}",
            provider.token_prefix(),
            payload_b64,
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        ),
        connect_url: request.focus.connect_url.clone(),
    }
}

fn token_media_permissions(request: &MediaTokenIssueRequestBody<'_>) -> (bool, bool, bool) {
    let (audio, video, screen) = request.desired_media;
    (audio, video, screen && request.allow_screen_share)
}

/// LiveKit backend token (`bindings/livekit.md` §2). Emits a **standard
/// LiveKit JWT** — `base64url(header).base64url(payload).base64url(sig)`
/// with header `{"alg":"HS256","typ":"JWT"}` and signature
/// `HMAC-SHA256(API Secret, header.payload)` — so a real LiveKit
/// deployment validates it.
///
/// The deployment LiveKit API Key/Secret come from
/// [`crate::config::LiveKitConfig`]; the focus-declared `issuer_kid` is the
/// LiveKit API Key (§2 `iss` mapping) and MUST equal the configured key, or
/// issuance fails closed. v1 carries a single API Key/Secret pair; mapping
/// multiple LiveKit deployments by `issuer_kid` is follow-up work.
fn issue_livekit_backend_token(
    request: &MediaTokenIssueRequestBody<'_>,
    livekit: &crate::config::LiveKitConfig,
) -> Result<IssuedMediaToken, AppError> {
    let api_key = livekit.api_key.as_deref().filter(|key| !key.is_empty());
    let api_secret = livekit
        .api_secret
        .as_deref()
        .filter(|secret| !secret.is_empty());
    let (Some(api_key), Some(api_secret)) = (api_key, api_secret) else {
        return Err(focus_unavailable_error(
            "livekit focus selected but SOLAND_LIVEKIT_API_KEY / SOLAND_LIVEKIT_API_SECRET are not configured",
        ));
    };
    // §2 `iss` = LiveKit API Key; the focus issuer_kid MUST name the same
    // deployment. Mismatch fails closed rather than signing with a key the
    // LiveKit cluster will reject.
    if request.focus.issuer_kid != api_key {
        return Err(token_issuer_unauthorised(format!(
            "livekit focus issuer_kid `{}` does not match configured LiveKit API Key",
            request.focus.issuer_kid
        )));
    }

    let (audio, video, screen) = token_media_permissions(request);
    let mut can_publish_sources = Vec::new();
    if audio {
        can_publish_sources.push("microphone");
    }
    if video {
        can_publish_sources.push("camera");
    }
    if screen {
        can_publish_sources.push("screen_share");
    }
    let can_publish = !can_publish_sources.is_empty();
    // LiveKit room name MUST NOT leak the raw Realm/call id into LiveKit logs.
    // Derive a stable opaque backend room handle from the full media tuple.
    let room_material = format!(
        "{}\0{}\0{}",
        request.realm_id, request.call_id, request.focus.focus_id
    );
    let room = format!("ak_call_{}", &sha256_hex(room_material.as_bytes())[..16]);
    // LiveKit JWT registered claims (`iat`/`nbf`/`exp`) are NumericDate —
    // seconds since the Unix epoch — not RFC3339 strings.
    let iat = request.issued_at.timestamp();
    let nbf = iat;
    let exp = request.expires_at.timestamp();
    let token_payload = json!({
        "iss": api_key,
        "sub": request.participant_identity,
        // §2: `name` MUST NOT carry actor identity; participant_identity is
        // already a pairwise pseudonym, so reuse it as the display label.
        "name": request.participant_identity,
        "nbf": nbf,
        "iat": iat,
        "exp": exp,
        "video": {
            "room": room,
            "roomJoin": true,
            "canPublish": can_publish,
            "canPublishSources": can_publish_sources,
            "canSubscribe": true,
            "hidden": false,
            "recorder": false,
        },
    });

    let header = json!({"alg": "HS256", "typ": "JWT"});
    let header_b64 = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header).unwrap_or_else(|_| header.to_string().into_bytes()));
    let payload_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&token_payload)
            .unwrap_or_else(|_| token_payload.to_string().into_bytes()),
    );
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature_b64 =
        URL_SAFE_NO_PAD.encode(hmac_sha256(api_secret.as_bytes(), signing_input.as_bytes()));
    Ok(IssuedMediaToken {
        backend_token: format!("{signing_input}.{signature_b64}"),
        connect_url: request.focus.connect_url.clone(),
    })
}

/// HMAC-SHA256 over `data` keyed by `key`. Used to sign the LiveKit JWT
/// (`bindings/livekit.md` §2) with the deployment API Secret.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(key)
        .expect("HMAC accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn required_json_string(value: &Value, field: &str) -> Result<String, AppError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| AppError::invalid_param(format!("{field} is required")))
}

fn service_id_from_issuer_kid(issuer_kid: &str) -> Option<String> {
    issuer_kid
        .split_once('#')
        .map(|(service_id, _)| service_id)
        .filter(|service_id| !service_id.trim().is_empty())
        .map(ToOwned::to_owned)
}

fn issuer_kid_belongs_to_service(issuer_kid: &str, service_id: &str) -> bool {
    issuer_kid
        .strip_prefix(service_id)
        .is_some_and(|rest| rest.starts_with('#'))
}

fn token_issuer_unauthorised(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::FailedPrecondition, message)
        .with_wire_code(arkret_wire::ReasonCode::TOKEN_ISSUER_UNAUTHORISED)
}

fn focus_unavailable_error(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::FailedPrecondition, message)
        .with_wire_code(arkret_wire::ReasonCode::FOCUS_UNAVAILABLE_FOR_CLIENT)
}

#[endpoint(
    operation_id = "ak.self.call.media.exchange.issue_token",
    summary = "Exchange a call media token",
    tags("media")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.call.media.exchange.issue_token"))]
async fn arkret_rtc_token(
    aa: AuthArgs,
    body: JsonBody<CallMediaTokenExchangeRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CallMediaTokenExchangeOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    handle_rtc_token(state, &session, body.into_inner()).await
}

#[cfg(test)]
#[expect(
    clippy::items_after_test_module,
    reason = "media-token tests stay adjacent to the private token helpers"
)]
mod tests {
    use super::*;

    #[test]
    fn participant_mute_override_reads_the_per_leg_cas_cell() {
        let cell = CallMediaCells {
            focus: None,
            moderation: None,
            mute_override: Some(json!({
                "status": "active",
                "actor_id": "did:web:alice.example",
                "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                "audio_muted": true,
                "video_muted": false,
                "changed_by": "did:web:mod.example",
                "changed_at": "2026-06-16T00:00:01.000Z"
            })),
        };

        assert_eq!(
            cell.participant_mute_override(
                "did:web:alice.example",
                "ak:device:01904100-0000-7000-8000-000000000001",
            ),
            (true, false)
        );
    }

    #[test]
    fn removed_moderation_dot_does_not_remain_an_effective_ban() {
        let cell = CallMediaCells {
            focus: None,
            moderation: Some(json!([
                {
                    "tag": "ak:event:01904100-0000-7000-8000-e00000000001",
                    "value": {
                        "actor_id": "did:web:bob.example",
                        "action": "ban"
                    },
                    "removed": true
                },
                {
                    "tag": "ak:event:01904100-0000-7000-8000-e00000000002",
                    "value": {
                        "actor_id": "did:web:carol.example",
                        "action": "ban"
                    }
                }
            ])),
            mute_override: None,
        };

        assert!(!cell.actor_is_banned("did:web:bob.example"));
        assert!(cell.actor_is_banned("did:web:carol.example"));
    }

    #[test]
    fn token_media_permissions_gate_screen_after_mute_adjustment() {
        let focus = MediaProviderConfig {
            provider: MediaProviderKind::ArkretNative,
            focus_id: "ak:focus:arkret-native:test".to_owned(),
            issuer_kid: "did:web:media.example#key-1".to_owned(),
            audience: "media".to_owned(),
            ttl_seconds: 300,
            connect_url: Some("https://media.example".to_owned()),
        };
        let issued_at = Utc::now();
        let request = MediaTokenIssueRequestBody {
            focus: &focus,
            realm_id: "ak:realm:01904100-0000-7000-8000-cfc039892063",
            call_id: "ak:call:01904100-0000-7000-8000-c0000000000c",
            actor_id: "did:web:alice.example",
            device_id: "ak:device:01904100-0000-7000-8000-000000000001",
            participant_identity: "ak:rtc_participant:01904100-0000-7000-8000-000000000009",
            desired_media: (false, true, true),
            allow_screen_share: false,
            issued_at,
            expires_at: issued_at + Duration::seconds(300),
        };

        assert_eq!(token_media_permissions(&request), (false, true, false));
    }

    #[test]
    fn media_provider_kind_rejects_legacy_alias() {
        assert!(MediaProviderKind::parse("arkret_native").is_err());
    }

    #[test]
    fn media_epoch_accepts_spec_focus_id_without_private_prefix() {
        let epoch = parse_media_service_epoch(
            "ak:realm:01904100-0000-7000-8000-cfc039892063",
            &json!({
                "service_id": "did:web:media.example",
                "foci": [{
                    "focus_id": "fra-1",
                    "type": "livekit",
                    "issuer_kid": "did:web:media.example#key-1",
                    "connect_url": "wss://media.example"
                }]
            }),
        )
        .expect("spec focus ids are not required to use a private prefix");

        assert_eq!(epoch.foci[0].focus_id, "fra-1");
    }
}

// `webrtc-signaling.md` §3 — canonical capability actions. The registry is
// the truth source; the spec body and this server MUST use the `ak.`-prefixed
// forms and MUST NOT accept the bare `call.*` names.
const CAP_CALL_JOIN: &str = "ak.call.join";
const CAP_CALL_SCREEN_SHARE: &str = "ak.call.screen_share";

/// Resolve the (owner, members) authorization principals for a realm so the
/// shared [`SolandAuthzEngine`] default rules (owner ⇒ all actions; explicit
/// grants override) evaluate consistently with the rest of the server. Mirrors
/// `events::operations::realm_owner_and_members` / `circles::circle_authz_principals`.
async fn call_authz_principals(state: &AppState, realm_id: &str) -> (Option<String>, Vec<String>) {
    let owner = state
        .realms()
        .realm_metadata(realm_id)
        .await
        .ok()
        .flatten()
        .map(|meta| meta.owner);
    let members = {
        let realms = state.realm_directory().snapshot();
        Some({
            arkret_identifiers::RealmId::new(realm_id.to_owned())
                .ok()
                .and_then(|id| realms.get(&id))
                .map(|realm| realm.members.iter().map(ToString::to_string).collect())
                .unwrap_or_default()
        })
    }
    .unwrap_or_default();
    (owner, members)
}

/// Whether `actor` holds `action` in `realm_id` per the projected capability
/// grants (`ak.component.capability.grant.v1`) and the engine default rules.
/// The realm itself is the capability resource scope (call capabilities are
/// realm-scoped in §3; a call is not a separate grant resource in v1).
pub(crate) async fn actor_has_call_capability(
    state: &AppState,
    realm_id: &str,
    actor: &str,
    action: &str,
) -> bool {
    let (owner, members) = call_authz_principals(state, realm_id).await;
    state
        .authorization()
        .check(soland_services::authorization::AuthorizationCheck {
            actor,
            action,
            resource: realm_id,
            realm_id,
            owner: owner.as_deref(),
            members: &members,
            resource_facets: &[],
        })
        .allowed
}

fn is_valid_webrtc_session_id(value: &str) -> bool {
    // v1 wire ID: `ak:call:<uuidv7-36-char-lowercase-hex>` (RFC 9562 v7,
    // version=7, variant ∈ {8,9,a,b}) — per
    // `arkret-spec/v1/artifacts/registry/id-kind-registry.json` the WebRTC
    // call surface uses `ak:call:`.
    let Some(rest) = value.strip_prefix("ak:call:") else {
        return false;
    };
    let Ok(parsed) = uuid::Uuid::parse_str(rest) else {
        return false;
    };
    parsed.get_version_num() == 7
}
