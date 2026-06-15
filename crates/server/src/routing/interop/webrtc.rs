//! RTC media handlers.
//!
//! Surfaces:
//! - `POST /_cokret/self/rtc/ice-config` (TURN / STUN list)
//! - `POST /_cokret/self/rtc/token` (media token exchange, CKP-0010)
//!
//! Sessions are persisted through `state.persistence.webrtc()`. STUN/TURN
//! URLs, credential TTLs, and the optional TURN shared secret are
//! operator-configurable via `AppConfig::ice`. Durable Pg backing and the
//! spec rule (no DID in TURN username / push payload) are future work.

use std::collections::BTreeSet;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use cokret_sdk::{DeviceId, Did, MediaIceConfigRequestBody, MediaIceMode, RealmId};
use ed25519_dalek::Signer as _;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::Serialize;
use serde_json::{Value, json};

use super::{now, realm_has_member, sha256_hex, validate_device_id, validate_did};
use crate::error::{AppError, ErrorCode};
use crate::ids;
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::{
    AppState, SessionRecord, WebRtcRemovedParticipant, WebRtcSessionRecord, WebRtcSignalRecord,
};
use crate::wire::{
    CallMediaParticipantBinding, CallMediaTokenExchangeOutcome, CallMediaTokenExchangeRequestBody,
};

/// RTC / WebRTC surface. Mounted under the `self` trust segment by
/// `interop::router()` so the spec-canonical media paths resolve at
/// `/_cokret/self/rtc/ice-config` and `/_cokret/self/rtc/token`.
pub(super) fn protocol_router() -> Router {
    Router::new()
        // Spec-canonical signed ICE config (`/_cokret/self/rtc/ice-config`).
        .push(Router::with_path("rtc/ice-config").post(cokret_ice_config))
        // CKP-0010 — media token exchange (`/_cokret/self/rtc/token`).
        .push(Router::with_path("rtc/token").post(cokret_rtc_token))
        // Ephemeral WebRTC signaling face (`webrtc-signaling.md`): session
        // create / close, append+list signals.
        .push(
            Router::with_path("webrtc/sessions")
                .post(create_webrtc_session)
                .push(
                    Router::with_path("{session_id}")
                        .delete(delete_webrtc_session)
                        .push(
                            Router::with_path("signals")
                                .get(list_webrtc_signals)
                                .post(append_webrtc_signal),
                        ),
                ),
        )
        // Call-scoped ICE config + recording control
        // (`webrtc-signaling.md` §4, `call-state.md` §5).
        .push(
            Router::with_path("calls")
                .push(Router::with_path("ice-config").post(calls_ice_config))
                .push(
                    Router::with_path("{call_id}/ice-config/refresh")
                        .post(calls_ice_config_refresh),
                )
                .push(Router::with_path("{call_id}/recording/start").post(calls_recording_start)),
        )
}

#[derive(Clone, Debug)]
struct IceConfigRequestContext {
    pub realm_id: RealmId,
    pub call_id: String,
    pub actor_id: Did,
    pub device_id: DeviceId,
    pub force_turn: bool,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct IceServerDescriptor {
    pub urls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize)]
struct UnsignedIceConfigOutcome {
    pub realm_id: RealmId,
    pub call_id: String,
    pub actor_id: Did,
    pub device_id: DeviceId,
    pub ice_servers: Vec<IceServerDescriptor>,
    pub turn_servers: Vec<IceServerDescriptor>,
    pub ttl_seconds: u32,
    pub refresh_lead_seconds: u32,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub force_turn: bool,
    pub pairwise_pseudonym: String,
    pub refreshed: bool,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct IceConfigSignature {
    pub alg: String,
    pub kid: String,
    pub payload_digest: String,
    pub sig: String,
    pub signature_input: String,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct SolandIceConfigOutcome {
    pub realm_id: RealmId,
    pub call_id: String,
    pub actor_id: Did,
    pub device_id: DeviceId,
    pub ice_servers: Vec<IceServerDescriptor>,
    pub turn_servers: Vec<IceServerDescriptor>,
    pub ttl_seconds: u32,
    pub refresh_lead_seconds: u32,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub force_turn: bool,
    pub pairwise_pseudonym: String,
    pub refreshed: bool,
    pub signature: IceConfigSignature,
}

impl SolandIceConfigOutcome {
    fn signed(
        state: &AppState,
        unsigned: UnsignedIceConfigOutcome,
    ) -> Result<SolandIceConfigOutcome, AppError> {
        let payload_digest = ice_config_payload_digest(&unsigned);
        let sig = ice_config_signature(state, &unsigned);
        Ok(SolandIceConfigOutcome {
            realm_id: unsigned.realm_id,
            call_id: unsigned.call_id,
            actor_id: unsigned.actor_id,
            device_id: unsigned.device_id,
            ice_servers: unsigned.ice_servers,
            turn_servers: unsigned.turn_servers,
            ttl_seconds: unsigned.ttl_seconds,
            refresh_lead_seconds: unsigned.refresh_lead_seconds,
            issued_at: unsigned.issued_at,
            expires_at: unsigned.expires_at,
            force_turn: unsigned.force_turn,
            pairwise_pseudonym: unsigned.pairwise_pseudonym,
            refreshed: unsigned.refreshed,
            signature: IceConfigSignature {
                alg: "EdDSA".to_owned(),
                kid: format!("{}#media-ice", state.config.service_did),
                payload_digest,
                sig,
                signature_input: "soland-media-ice-config-v1".to_owned(),
            },
        })
    }
}

#[endpoint(
    operation_id = "ck.self.media.query.ice_config",
    tags("media"),
    summary = "Issue signed ICE config"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.media.query.ice_config"))]
async fn cokret_ice_config(
    aa: AuthArgs,
    body: JsonBody<MediaIceConfigRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SolandIceConfigOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
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
        None,
        false,
    )
    .await
}

async fn issue_ice_config(
    state: &AppState,
    session: &SessionRecord,
    body: IceConfigRequestContext,
    path_call_id: Option<String>,
    refresh: bool,
) -> JsonResult<SolandIceConfigOutcome> {
    let realm_id = body.realm_id.as_str();
    let call_id = path_call_id
        .as_deref()
        .or(Some(body.call_id.as_str()))
        .filter(|call_id| !call_id.is_empty())
        .ok_or_else(|| AppError::missing_param("call_id is required"))?;
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
    if !realm_has_member(state, realm_id, actor_id).await {
        return Err(AppError::capability_denied(
            "actor is not a joined member of the realm",
        ));
    }
    if let Some(record) = state.persistence.webrtc().get(call_id).await.ok().flatten() {
        if record.realm_id != realm_id {
            return Err(AppError::invalid_param(
                "call_id does not belong to the requested realm",
            ));
        }
        if !record.participants.contains(actor_id) {
            return Err(AppError::capability_denied(
                "actor is not a participant of the call",
            ));
        }
    } else if refresh {
        return Err(AppError::not_found("call session not found"));
    }

    let issued_at = now();
    let ttl_seconds: u32 = state.config.ice.ttl_seconds;
    let refresh_lead_seconds: u32 = state.config.ice.refresh_lead_seconds;
    let expires_at = issued_at + Duration::seconds(i64::from(ttl_seconds));
    let force_turn = body.force_turn;
    let turn_username = pairwise_turn_username(state, realm_id, call_id, actor_id, device_id);
    let turn_credential = turn_credential(
        state, realm_id, call_id, actor_id, device_id, &issued_at, refresh,
    );
    let turn_server = IceServerDescriptor {
        urls: state.config.ice.turn_urls.clone(),
        username: Some(turn_username.clone()),
        credential: Some(turn_credential),
        credential_type: Some("password".to_owned()),
        expires_at: Some(expires_at),
    };
    let mut ice_servers = vec![IceServerDescriptor {
        urls: state.config.ice.stun_urls.clone(),
        username: None,
        credential: None,
        credential_type: None,
        expires_at: None,
    }];
    ice_servers.push(turn_server.clone());
    if force_turn {
        ice_servers = vec![turn_server.clone()];
    }
    let response = UnsignedIceConfigOutcome {
        realm_id: body.realm_id,
        call_id: call_id.to_owned(),
        actor_id: body.actor_id,
        device_id: body.device_id,
        ice_servers,
        turn_servers: vec![turn_server],
        ttl_seconds,
        refresh_lead_seconds,
        issued_at,
        expires_at,
        force_turn,
        pairwise_pseudonym: turn_username,
        refreshed: refresh,
    };
    json_ok(SolandIceConfigOutcome::signed(state, response)?)
}

fn pairwise_turn_username(
    state: &AppState,
    realm_id: &str,
    call_id: &str,
    actor_id: &str,
    device_id: &str,
) -> String {
    let material = format!(
        "soland-turn-user-v1\0{}\0{realm_id}\0{call_id}\0{actor_id}\0{device_id}",
        state.config.service_did
    );
    format!("ck-turn-{}", &sha256_hex(material.as_bytes())[..24])
}

fn turn_credential(
    state: &AppState,
    realm_id: &str,
    call_id: &str,
    actor_id: &str,
    device_id: &str,
    issued_at: &chrono::DateTime<chrono::Utc>,
    refresh: bool,
) -> String {
    let mut material = format!(
        "soland-turn-credential-v1\0{}\0{realm_id}\0{call_id}\0{actor_id}\0{device_id}\0{}\0{refresh}",
        state.config.service_did,
        issued_at.to_rfc3339()
    );
    // When a TURN shared secret is configured, fold it into the credential
    // material so derived credentials cannot be recomputed without it. When
    // unset, material is unchanged and existing credential assertions hold.
    if let Some(secret) = state.config.ice.turn_shared_secret.as_deref() {
        material.push('\0');
        material.push_str(secret);
    }
    URL_SAFE_NO_PAD.encode(sha256_hex(material.as_bytes()))
}

fn ice_config_payload_digest<T: Serialize>(payload: &T) -> String {
    let bytes = cokret_sdk::canonical::canonical_json_bytes(payload)
        .unwrap_or_else(|_| serde_json::to_vec(payload).unwrap_or_default());
    cokret_sdk::canonical::sha256_digest(&bytes)
}

fn ice_config_signature<T: Serialize>(state: &AppState, payload: &T) -> String {
    let payload = cokret_sdk::canonical::canonical_json_bytes(payload)
        .unwrap_or_else(|_| serde_json::to_vec(payload).unwrap_or_default());
    let mut signing_input = Vec::with_capacity(
        b"soland-media-ice-config-v1".len() + state.config.service_did.len() + payload.len() + 2,
    );
    signing_input.extend_from_slice(b"soland-media-ice-config-v1");
    signing_input.push(0);
    signing_input.extend_from_slice(state.config.service_did.as_bytes());
    signing_input.push(0);
    signing_input.extend_from_slice(&payload);
    let signature = state.notary_signing_key().sign(&signing_input);
    format!(
        "eddsa-ed25519:{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

// ── CKP-0010 (R3 spec-sync 2026-05-27, cokret-spec b47ff6ec) — media
// token exchange. Issues a backend_token + ParticipantBinding for a
// caller that already has a committed `ck.call.state.session_focus`.
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
//     `ck.realm.media_service.service_id` epoch → `token_issuer_unauthorised` (MEDIA-1).
const REALM_MEDIA_SERVICE_CELL_FAMILY: &str = "ck.component.realm.media_service.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MediaProviderKind {
    CokretNative,
    LiveKit,
    Mediasoup,
}

impl MediaProviderKind {
    fn parse(value: &str) -> Result<Self, AppError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "cokret-native" | "cokret_native" => Ok(Self::CokretNative),
            "livekit" => Ok(Self::LiveKit),
            "mediasoup" => Ok(Self::Mediasoup),
            _ => Err(AppError::new(
                ErrorCode::UnknownFocusType,
                format!("unknown media focus provider `{value}`"),
            )),
        }
    }

    fn as_wire(self) -> &'static str {
        match self {
            Self::CokretNative => "cokret-native",
            Self::LiveKit => "livekit",
            Self::Mediasoup => "mediasoup",
        }
    }

    fn token_prefix(self) -> &'static str {
        match self {
            Self::CokretNative => "cokret-native",
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
    e2ee_key_source: Option<String>,
}

#[derive(Clone, Debug)]
struct MediaServiceEpoch {
    service_id: String,
    issuer_kids: BTreeSet<String>,
    foci: Vec<MediaProviderConfig>,
    e2ee_key_sources_allowed: BTreeSet<String>,
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
    /// Whether the caller carries `ck.call.screen_share` (gates the
    /// `screen_share` publish source per `bindings/livekit.md` §5).
    allow_screen_share: bool,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

struct IssuedMediaToken {
    backend_token: String,
    connect_url: Option<String>,
}

trait MediaTokenIssuer {
    fn issue(
        &self,
        request: &MediaTokenIssueRequestBody<'_>,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> IssuedMediaToken;
}

struct CokretNativeMediaIssuer;
struct LiveKitMediaIssuer;
struct MediasoupMediaIssuer;

impl MediaTokenIssuer for CokretNativeMediaIssuer {
    fn issue(
        &self,
        request: &MediaTokenIssueRequestBody<'_>,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> IssuedMediaToken {
        issue_signed_backend_token(MediaProviderKind::CokretNative, request, signing_key)
    }
}

impl MediaTokenIssuer for LiveKitMediaIssuer {
    fn issue(
        &self,
        request: &MediaTokenIssueRequestBody<'_>,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> IssuedMediaToken {
        issue_livekit_backend_token(request, signing_key)
    }
}

impl MediaTokenIssuer for MediasoupMediaIssuer {
    fn issue(
        &self,
        request: &MediaTokenIssueRequestBody<'_>,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> IssuedMediaToken {
        issue_signed_backend_token(MediaProviderKind::Mediasoup, request, signing_key)
    }
}

async fn handle_rtc_token(
    state: &AppState,
    session: &SessionRecord,
    body: CallMediaTokenExchangeRequestBody,
) -> JsonResult<CallMediaTokenExchangeOutcome> {
    use crate::error::ErrorCode;

    // The request body is the SDK typed shape: `realm_id`/`call_id`/`actor_id`/
    // `device_id` arrive already validated as the corresponding scalar id types,
    // and the response binding carries the same typed ids — so the wire outcome
    // reuses `cokret_sdk::CallMediaTokenExchangeOutcome` directly instead of a
    // stringly soland mirror.
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
    if !realm_has_member(state, body.realm_id.as_str(), body.actor_id.as_str()).await {
        return Err(AppError::capability_denied(
            "actor is not a joined member of the realm",
        ));
    }

    let webrtc = state
        .persistence
        .webrtc()
        .get(body.call_id.as_str())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("call session not found"))?;
    if webrtc.realm_id != body.realm_id.as_str() {
        return Err(AppError::invalid_param(
            "call_id does not belong to the requested realm",
        ));
    }
    if !webrtc.participants.contains(body.actor_id.as_str()) {
        return Err(
            AppError::capability_denied("actor is not a participant of the call")
                .with_wire_code(crate::error::reasons::PARTICIPANT_IDENTITY_UNRECOGNISED),
        );
    }
    // `webrtc-signaling.md` §3a — a banned actor MUST NOT re-issue a join token
    // for this call's lifetime. The token issuer gates on the actor-wide ban set
    // projected into `removed_participants[]`.
    if actor_is_banned(&webrtc.removed_participants, body.actor_id.as_str()) {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "actor was removed from the call (ban) and cannot re-issue a join token",
        )
        .with_status(StatusCode::FORBIDDEN)
        .with_wire_code(crate::error::reasons::CALL_PARTICIPANT_REMOVED));
    }
    let media_epoch = media_service_epoch_for_realm(state, body.realm_id.as_str())?;

    // MEDIA-2 — focus selection (oldest-membership-wins). A committed
    // `ck.call.state.session_focus` projection wins when present; otherwise we
    // derive from call members ordered by realm membership age and the latest
    // per-member `foci_preferred[]` signal in the call.
    let session_focus = session_focus_for_call(state, &webrtc, &media_epoch)?;
    if body.focus_id != session_focus {
        return Err(AppError::new(
            ErrorCode::FocusMismatch,
            format!(
                "focus_id `{}` does not match committed session_focus `{}`",
                body.focus_id, session_focus
            ),
        ));
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
    if let Some(e2ee_key_source) = &focus.e2ee_key_source
        && !media_epoch.e2ee_key_sources_allowed.is_empty()
        && !media_epoch
            .e2ee_key_sources_allowed
            .contains(e2ee_key_source)
    {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            format!("e2ee_key_source `{e2ee_key_source}` is not authorized by media_service epoch"),
        )
        .with_wire_code(crate::error::reasons::E2EE_KEY_SOURCE_UNAUTHORISED));
    }

    // MEDIA-1 — token TTL defaults to 300s and is capped at the spec ceiling
    // even if the realm focus advertises a larger backend TTL.
    let ttl_secs = focus
        .ttl_seconds
        .clamp(1, cokret_sdk::MEDIA_TOKEN_TTL_MAX_SECS);
    let issued_at = now();
    let expires_at = issued_at + Duration::seconds(ttl_secs as i64);

    let participant_identity = format!(
        "ck:rtc_participant:{}",
        &sha256_hex(
            format!(
                "participant\0{}\0{}\0{}\0{}",
                body.realm_id, body.call_id, body.actor_id, body.device_id
            )
            .as_bytes()
        )[..32]
    );
    let signing_key = state.notary_signing_key();
    // `bindings/livekit.md` §2/§5 — publish grants are derived from the
    // caller's `desired_media`. Absent the field we default to audio+video
    // (no screen): screen capture is an opt-in source gated by
    // `ck.call.screen_share`.
    let desired_media = body
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
    let allow_screen_share = !body.capability_refs.is_empty() || state.config.development_mode;
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
    let issued_token = media_token_issuer_for(focus.provider).issue(&issue_request, &signing_key);

    let issuer_kid = focus.issuer_kid.clone();
    let binding_payload = json!({
        "scheme": cokret_sdk::PARTICIPANT_BINDING_SCHEMA,
        "issuer_kid": issuer_kid.clone(),
        "realm_id": body.realm_id,
        "call_id": body.call_id,
        "focus_id": body.focus_id,
        "actor_id": body.actor_id,
        "device_id": body.device_id,
        "participant_identity": participant_identity,
        "expires_at": expires_at,
    });
    let binding_bytes = cokret_sdk::canonical::canonical_json_bytes(&binding_payload)
        .unwrap_or_else(|_| binding_payload.to_string().into_bytes());
    let mut signing_input =
        Vec::with_capacity(b"soland-media-participant-binding-v1".len() + binding_bytes.len() + 1);
    signing_input.extend_from_slice(b"soland-media-participant-binding-v1");
    signing_input.push(0);
    signing_input.extend_from_slice(&binding_bytes);
    let binding_sig = signing_key.sign(&signing_input);
    let sig = format!(
        "eddsa-ed25519:{}",
        URL_SAFE_NO_PAD.encode(binding_sig.to_bytes())
    );

    let mut service_input = Vec::with_capacity(64 + binding_bytes.len());
    service_input.extend_from_slice(b"soland-media-token-response-v1");
    service_input.push(0);
    service_input.extend_from_slice(&binding_bytes);
    let service_sig = signing_key.sign(&service_input);
    let service_signature = format!(
        "{}:eddsa-ed25519:{}",
        issuer_kid,
        URL_SAFE_NO_PAD.encode(service_sig.to_bytes())
    );

    let participant_binding = CallMediaParticipantBinding {
        scheme: cokret_sdk::PARTICIPANT_BINDING_SCHEMA.to_owned(),
        sig,
        issuer_kid,
        realm_id,
        call_id,
        focus_id: body.focus_id.clone(),
        actor_id,
        device_id,
        participant_identity: participant_identity.clone(),
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

/// MEDIA-2 oldest-membership-wins focus selection.
fn session_focus_for_call(
    state: &AppState,
    webrtc: &WebRtcSessionRecord,
    media_epoch: &MediaServiceEpoch,
) -> Result<String, AppError> {
    let (committed_focus, mut member_order) = {
        let projection = state
            .projection
            .lock()
            .map_err(|error| AppError::internal(format!("projection lock: {error}")))?;
        let committed_focus = projection
            .call_session_focus
            .get(&webrtc.session_id)
            .cloned();
        let member_order = webrtc
            .participants
            .iter()
            .map(|actor| {
                let joined_at = projection
                    .member(&webrtc.realm_id, actor)
                    .map(|member| member.joined_at)
                    .unwrap_or_else(|| {
                        if actor == &webrtc.created_by {
                            webrtc.created_at
                        } else {
                            webrtc.created_at + Duration::milliseconds(1)
                        }
                    });
                (actor.clone(), joined_at)
            })
            .collect::<Vec<_>>();
        (committed_focus, member_order)
    };
    if let Some(focus) = committed_focus {
        if media_epoch.focus(&focus).is_some() {
            return Ok(focus);
        }
        return Err(focus_unavailable_error(
            "committed session_focus is not present in current media_service epoch",
        ));
    }

    member_order.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
    let default_focus_ids = media_epoch.focus_ids();
    if let Some((actor, _)) = member_order.into_iter().next() {
        let preferences = focus_preferences_for_member(webrtc, &actor);
        if preferences.is_empty() {
            if let Some(focus_id) = default_focus_ids.first() {
                return Ok(focus_id.clone());
            }
        } else {
            for focus_id in preferences {
                if media_epoch.focus(&focus_id).is_some() {
                    return Ok(focus_id);
                }
            }
            return Err(focus_unavailable_error(format!(
                "no media_service focus intersects foci_preferred[] for {actor}"
            )));
        }
    }
    Err(focus_unavailable_error(
        "realm media_service epoch has no available foci",
    ))
}

fn media_service_epoch_for_realm(
    state: &AppState,
    realm_id: &str,
) -> Result<MediaServiceEpoch, AppError> {
    let cell_id = cokret_sdk::CellRef::new(format!(
        "ck:cell:{REALM_MEDIA_SERVICE_CELL_FAMILY}:{realm_id}"
    ))
    .map_err(|error| AppError::internal(format!("invalid media_service cell id: {error}")))?;
    let value = {
        let projection = state
            .projection
            .lock()
            .map_err(|error| AppError::internal(format!("projection lock: {error}")))?;
        projection.cell_value(&cell_id).cloned()
    }
    .ok_or_else(|| {
        token_issuer_unauthorised(format!(
            "realm `{realm_id}` has no projected ck.realm.media_service epoch"
        ))
    })?;
    parse_media_service_epoch(realm_id, &value)
}

fn parse_media_service_epoch(realm_id: &str, value: &Value) -> Result<MediaServiceEpoch, AppError> {
    let config = value.get("media_service").unwrap_or(value);
    let service_id = config
        .get("service_id")
        .or_else(|| config.get("service_did"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let foci_value = normalized_media_foci(realm_id, config)?;
    let mut foci = Vec::new();
    for focus_value in foci_value {
        let focus_id = required_json_string(&focus_value, "focus_id")?;
        if !focus_id.starts_with("ck:focus:") {
            return Err(AppError::invalid_param(
                "media focus_id must start with ck:focus:",
            ));
        }
        let provider = focus_value
            .get("type")
            .or_else(|| focus_value.get("backend"))
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::invalid_param("media focus backend/type is required"))
            .and_then(MediaProviderKind::parse)?;
        let issuer_kid = focus_value
            .get("issuer_kid")
            .or_else(|| config.get("issuer_kid"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                token_issuer_unauthorised("media focus issuer_kid is required".to_owned())
            })?
            .to_owned();
        let audience = focus_value
            .get("audience")
            .or_else(|| config.get("audience"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("cokret:media:{realm_id}:{focus_id}"));
        let ttl_seconds = focus_value
            .get("ttl_seconds")
            .or_else(|| focus_value.get("token_ttl_seconds"))
            .or_else(|| config.get("ttl_seconds"))
            .and_then(Value::as_u64)
            .unwrap_or(cokret_sdk::MEDIA_TOKEN_TTL_SHOULD_SECS);
        let connect_url = focus_value
            .get("connect_url")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let e2ee_key_source = focus_value
            .get("e2ee_key_source")
            .or_else(|| config.get("e2ee_key_source"))
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
            e2ee_key_source,
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
    let e2ee_key_sources_allowed = config
        .get("e2ee_key_sources_allowed")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();
    Ok(MediaServiceEpoch {
        service_id,
        issuer_kids,
        foci,
        e2ee_key_sources_allowed,
    })
}

fn normalized_media_foci(realm_id: &str, config: &Value) -> Result<Vec<Value>, AppError> {
    let _ = realm_id;
    if let Some(foci) = config.get("foci").and_then(Value::as_array) {
        return Ok(foci.clone());
    }
    Err(focus_unavailable_error(
        "realm media_service epoch must contain foci[]",
    ))
}

fn focus_preferences_for_member(webrtc: &WebRtcSessionRecord, actor: &str) -> Vec<String> {
    for signal in webrtc.signals.iter().rev() {
        if signal.sender != actor {
            continue;
        }
        if let Some(preferences) = signal
            .payload
            .get("foci_preferred")
            .and_then(Value::as_array)
        {
            let values = preferences
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>();
            if !values.is_empty() {
                return values;
            }
        }
        if let Some(focus_id) = signal
            .payload
            .get("focus_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return vec![focus_id.to_owned()];
        }
    }
    Vec::new()
}

fn media_token_issuer_for(provider: MediaProviderKind) -> Box<dyn MediaTokenIssuer> {
    match provider {
        MediaProviderKind::CokretNative => Box::new(CokretNativeMediaIssuer),
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
        "e2ee_key_source": request.focus.e2ee_key_source,
        "iat": request.issued_at,
        "exp": request.expires_at,
        "nonce": nonce,
    });
    let token_bytes = cokret_sdk::canonical::canonical_json_bytes(&token_payload)
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

/// LiveKit backend token (`bindings/livekit.md` §2). Emits a LiveKit JWT
/// (`HS256`-shaped header + LiveKit `video` grant claims) signed with the
/// service notary key. We keep the `livekit.<payload>.<sig>` wire envelope so
/// the soland test harness can decode the claims, while populating the
/// LiveKit-standard claim names (`video.room` / `canPublish` /
/// `canPublishSources` / `canSubscribe` / `exp` / `sub` / `iss`).
fn issue_livekit_backend_token(
    request: &MediaTokenIssueRequestBody<'_>,
    signing_key: &ed25519_dalek::SigningKey,
) -> IssuedMediaToken {
    let nonce = ids::generate("media_token");
    let (audio, video, screen) = request.desired_media;
    let mut can_publish_sources = Vec::new();
    if audio {
        can_publish_sources.push("microphone");
    }
    if video {
        can_publish_sources.push("camera");
    }
    if screen && request.allow_screen_share {
        can_publish_sources.push("screen_share");
    }
    let can_publish = !can_publish_sources.is_empty();
    // LiveKit room name MUST NOT leak the raw Realm/call id into LiveKit logs
    // (§2): derive a stable opaque `ck_call_<short-hash>` from the call_id.
    let room = format!("ck_call_{}", &sha256_hex(request.call_id.as_bytes())[..16]);
    let token_payload = json!({
        "iss": request.focus.issuer_kid,
        "sub": request.participant_identity,
        "aud": request.focus.audience,
        "provider": MediaProviderKind::LiveKit.as_wire(),
        "realm_id": request.realm_id,
        "call_id": request.call_id,
        "focus_id": request.focus.focus_id,
        "actor_id": request.actor_id,
        "device_id": request.device_id,
        "participant_identity": request.participant_identity,
        "e2ee_key_source": request.focus.e2ee_key_source,
        "nbf": request.issued_at,
        "iat": request.issued_at,
        "exp": request.expires_at,
        "nonce": nonce,
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
    let token_bytes = cokret_sdk::canonical::canonical_json_bytes(&token_payload)
        .unwrap_or_else(|_| token_payload.to_string().into_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(&token_bytes);
    let signing_input = format!(
        "soland-media-backend-token-v1\0{}\0{}",
        MediaProviderKind::LiveKit.as_wire(),
        payload_b64
    );
    let sig = signing_key.sign(signing_input.as_bytes());
    IssuedMediaToken {
        backend_token: format!(
            "{}.{}.{}",
            MediaProviderKind::LiveKit.token_prefix(),
            payload_b64,
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        ),
        connect_url: request.focus.connect_url.clone(),
    }
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
    issuer_kid == service_id
        || issuer_kid
            .strip_prefix(service_id)
            .is_some_and(|rest| rest.starts_with('#'))
}

fn token_issuer_unauthorised(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::TokenIssuerUnauthorised, message)
        .with_wire_code(crate::error::reasons::TOKEN_ISSUER_UNAUTHORISED)
}

fn focus_unavailable_error(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::FailedPrecondition, message)
        .with_wire_code(crate::error::reasons::FOCUS_UNAVAILABLE_FOR_CLIENT)
}

#[endpoint(
    operation_id = "ck.self.call.media.exchange.issue_token",
    tags("media", "calls"),
    summary = "Exchange a session-focus for a backend media token + participant_binding (CKP-0010)",
    status_codes(200, 400, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.call.media.exchange.issue_token"))]
async fn cokret_rtc_token(
    aa: AuthArgs,
    body: JsonBody<CallMediaTokenExchangeRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CallMediaTokenExchangeOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    handle_rtc_token(state, &session, body.into_inner()).await
}

// ── Ephemeral WebRTC signaling face (`webrtc-signaling.md`) ──────────────
//
// These surfaces back the `ck.call.signal` ephemeral channel and the
// `ck.call.state` lifecycle for one-to-one / SFU calls. Sessions and their
// signal log live in `state.persistence.webrtc()`; the call lifecycle state
// (`ringing` → `connecting` → `active` → `ended`) is derived from the most
// recent meaningful signal so `GET .../signals` and the append response can
// surface a `call_state` consistent with `call-state.md` §4.2.

#[derive(Clone, Debug, serde::Deserialize, salvo::oapi::ToSchema)]
struct CreateWebRtcSessionRequestBody {
    realm_id: RealmId,
    #[serde(default)]
    participants: Vec<Did>,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    recording_policy: Option<String>,
    #[serde(default)]
    ttl_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct WebRtcSessionOutcome {
    session_id: String,
    realm_id: String,
    created_by: String,
    participants: Vec<String>,
    mode: String,
    recording_policy: String,
    call_state: String,
    next_cursor: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, serde::Deserialize, salvo::oapi::ToSchema)]
struct AppendSignalRequestBody {
    message_type: String,
    #[serde(default)]
    payload: Value,
    #[serde(default)]
    proofs: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct AppendSignalOutcome {
    seq: u64,
    next_cursor: String,
    call_state: String,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct SignalEventView {
    seq: u64,
    #[serde(rename = "type")]
    message_type: String,
    sender: String,
    payload: Value,
    proofs: Vec<Value>,
    created_at: DateTime<Utc>,
    call_state_after: String,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct ListSignalsOutcome {
    events: Vec<SignalEventView>,
    next_cursor: String,
    call_state: String,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct RecordingStartOutcome {
    ok: bool,
    call_id: String,
    recording_policy: String,
    recording_started_by: String,
    recording_blob_ref: String,
    recording_id: String,
    recording_start_event_id: String,
    recording_state: String,
}

#[derive(Clone, Debug, serde::Deserialize, salvo::oapi::ToSchema)]
struct RecordingStartRequestBody {
    realm_id: RealmId,
    #[serde(default)]
    recording_agent: Option<String>,
    #[serde(default)]
    recording_artifact_url: Option<String>,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct DeleteSessionOutcome {
    ok: bool,
    session_id: String,
}

const CALL_STATE_RINGING: &str = "ringing";
const CALL_STATE_CONNECTING: &str = "connecting";
const CALL_STATE_ACTIVE: &str = "active";
const CALL_STATE_ENDED: &str = "ended";
const CALL_STATE_MISSED: &str = "missed";
const CALL_STATE_CANCELLED: &str = "cancelled";

/// Valid `payload.signal_type` values per `webrtc-signaling.md` §5.
fn is_known_signal_type(message_type: &str) -> bool {
    matches!(
        message_type,
        "invite"
            | "offer"
            | "answer"
            | "candidate"
            | "reject"
            | "hangup"
            | "renegotiate"
            | "mute_state"
            | "media_state"
            | "speaking"
            | "focus_join"
            | "focus_leave"
            | "moderation"
            | "error"
            | "ack"
    )
}

/// Derive the call lifecycle `state` (`call-state.md` §4.2) from the ordered
/// signal log. Lifecycle-bearing signals advance the FSM; ephemeral status
/// signals (candidate / speaking / mute_state / focus_*) leave it untouched.
fn derive_call_state(signals: &[WebRtcSignalRecord]) -> String {
    let mut state = CALL_STATE_RINGING;
    for signal in signals {
        state = call_state_after_signal(state, &signal.message_type, &signal.payload);
    }
    state.to_owned()
}

fn call_state_after_signal(current: &str, message_type: &str, payload: &Value) -> &'static str {
    // Terminal states absorb everything (`call-state.md` §4.2 终态吸收).
    if matches!(
        current,
        CALL_STATE_ENDED | CALL_STATE_MISSED | CALL_STATE_CANCELLED | "failed"
    ) {
        return match current {
            CALL_STATE_MISSED => CALL_STATE_MISSED,
            CALL_STATE_CANCELLED => CALL_STATE_CANCELLED,
            "failed" => "failed",
            _ => CALL_STATE_ENDED,
        };
    }
    match message_type {
        "invite" | "offer" | "renegotiate" => CALL_STATE_CONNECTING,
        "answer" => CALL_STATE_ACTIVE,
        "hangup" => CALL_STATE_ENDED,
        // `webrtc-signaling.md` §3a — `moderation{action=end_for_all}` MUST be
        // immediately followed by writing `ck.call.state.state = ended`; the
        // signal append path projects that terminal transition here. kick / ban
        // remove a participant but leave the call lifecycle running.
        "moderation" => {
            if moderation_action(payload) == Some("end_for_all") {
                CALL_STATE_ENDED
            } else {
                current_non_terminal(current)
            }
        }
        "reject" => {
            if current == CALL_STATE_RINGING {
                CALL_STATE_MISSED
            } else {
                CALL_STATE_ENDED
            }
        }
        "error" => "failed",
        _ => current_non_terminal(current),
    }
}

fn current_non_terminal(current: &str) -> &'static str {
    match current {
        CALL_STATE_RINGING => CALL_STATE_RINGING,
        CALL_STATE_CONNECTING => CALL_STATE_CONNECTING,
        _ => CALL_STATE_ACTIVE,
    }
}

/// Extract `data.action` (or top-level `action`) from a `moderation` payload.
fn moderation_action(payload: &Value) -> Option<&str> {
    payload
        .get("data")
        .and_then(|data| data.get("action"))
        .or_else(|| payload.get("action"))
        .and_then(Value::as_str)
}

/// Project `ck.call.state.removed_participants[]` from the ordered signal log
/// (`webrtc-signaling.md` §3a). Each `moderation{action=kick|ban}` frame
/// contributes a `{ actor_id, device_id?, action, removed_at }` row; `ban`
/// omits `device_id` to mark an actor-wide removal.
fn derive_removed_participants(signals: &[WebRtcSignalRecord]) -> Vec<WebRtcRemovedParticipant> {
    let mut removed = Vec::new();
    for signal in signals {
        if signal.message_type != "moderation" {
            continue;
        }
        let data = signal.payload.get("data").unwrap_or(&signal.payload);
        let action = moderation_action(&signal.payload).unwrap_or("");
        if action != "kick" && action != "ban" {
            continue;
        }
        let Some(actor_id) = data
            .get("target_actor_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        // `ban` is actor-wide (drop device_id); `kick` pins a single leg.
        let device_id = if action == "ban" {
            None
        } else {
            data.get("target_device_id")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        };
        removed.push(WebRtcRemovedParticipant {
            actor_id: actor_id.to_owned(),
            device_id,
            action: action.to_owned(),
            removed_at: signal.created_at,
        });
    }
    removed
}

/// Whether `actor_id` is under an actor-wide `ban` in the removed set
/// (`webrtc-signaling.md` §3a). Token issuance MUST refuse banned actors.
fn actor_is_banned(removed: &[WebRtcRemovedParticipant], actor_id: &str) -> bool {
    removed
        .iter()
        .any(|row| row.action == "ban" && row.actor_id == actor_id)
}

fn session_outcome(record: &WebRtcSessionRecord) -> WebRtcSessionOutcome {
    WebRtcSessionOutcome {
        session_id: record.session_id.clone(),
        realm_id: record.realm_id.clone(),
        created_by: record.created_by.clone(),
        participants: record.participants.iter().cloned().collect(),
        mode: record.mode.clone(),
        recording_policy: record.recording_policy.clone(),
        call_state: derive_call_state(&record.signals),
        next_cursor: record.next_seq.saturating_sub(1).to_string(),
        created_at: record.created_at,
        expires_at: record.expires_at,
    }
}

#[endpoint(
    operation_id = "ck.self.webrtc.session.create",
    tags("media", "calls"),
    summary = "Create an ephemeral WebRTC signaling session",
    status_codes(200, 400, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.webrtc.session.create"))]
async fn create_webrtc_session(
    aa: AuthArgs,
    body: JsonBody<CreateWebRtcSessionRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<WebRtcSessionOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let realm_id = body.realm_id.as_str().to_owned();
    if !realm_has_member(state, &realm_id, &session.actor).await {
        return Err(AppError::capability_denied(
            "actor is not a joined member of the realm",
        ));
    }

    let mode = match body.mode.as_deref() {
        None => "p2p".to_owned(),
        Some(value @ ("p2p" | "mesh" | "sfu" | "mcu")) => value.to_owned(),
        Some(_) => return Err(AppError::invalid_param("mode must be p2p/mesh/sfu/mcu")),
    };
    let recording_policy = match body.recording_policy.as_deref() {
        None => "none".to_owned(),
        Some(value @ ("none" | "allow" | "required")) => value.to_owned(),
        Some(_) => {
            return Err(AppError::invalid_param(
                "recording_policy must be none/allow/required",
            ));
        }
    };

    // The creator is always a participant; explicit `participants` extend the
    // set so 1:1 callers can pre-register the callee.
    let mut participants = BTreeSet::new();
    participants.insert(session.actor.clone());
    for participant in &body.participants {
        participants.insert(participant.as_str().to_owned());
    }

    let issued_at = now();
    let ttl_ms = body.ttl_ms.unwrap_or(60_000).clamp(1_000, 86_400_000);
    let expires_at = issued_at + Duration::milliseconds(ttl_ms as i64);
    let record = WebRtcSessionRecord {
        session_id: ids::generate("call"),
        realm_id,
        created_by: session.actor.clone(),
        participants,
        mode,
        recording_policy,
        recording_started_by: None,
        recording_blob_ref: None,
        removed_participants: Vec::new(),
        expires_at,
        created_at: issued_at,
        next_seq: 1,
        signals: Vec::new(),
    };
    state
        .persistence
        .webrtc()
        .put(record.clone())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(session_outcome(&record))
}

#[endpoint(
    operation_id = "ck.self.webrtc.session.close",
    tags("media", "calls"),
    summary = "Close an ephemeral WebRTC signaling session",
    status_codes(200, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.webrtc.session.close"))]
async fn delete_webrtc_session(
    aa: AuthArgs,
    session_id: salvo::oapi::extract::PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DeleteSessionOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let auth = aa.authenticated_session(state, req).await?;
    let session_id = session_id.into_inner();
    let record = load_session_for_participant(state, &session_id, &auth.actor).await?;
    state
        .persistence
        .webrtc()
        .delete(&record.session_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(DeleteSessionOutcome {
        ok: true,
        session_id,
    })
}

#[endpoint(
    operation_id = "ck.self.webrtc.signal.append",
    tags("media", "calls"),
    summary = "Append a signaling frame to a WebRTC session",
    status_codes(200, 400, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.webrtc.signal.append"))]
async fn append_webrtc_signal(
    aa: AuthArgs,
    session_id: salvo::oapi::extract::PathParam<String>,
    body: JsonBody<AppendSignalRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AppendSignalOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let auth = aa.authenticated_session(state, req).await?;
    let session_id = session_id.into_inner();
    let body = body.into_inner();
    if !is_known_signal_type(&body.message_type) {
        return Err(AppError::invalid_param(format!(
            "unknown signal message_type `{}`",
            body.message_type
        )));
    }
    // §2.2 / §5 — every `ck.call.signal` MUST be signed by the sending
    // device. Reject frames without a device proof before they enter the log.
    if body.proofs.is_empty() {
        return Err(AppError::invalid_param(
            "signaling frame requires at least one device proof",
        ));
    }
    let record = load_session_for_participant(state, &session_id, &auth.actor).await?;
    if matches!(
        derive_call_state(&record.signals).as_str(),
        CALL_STATE_ENDED | CALL_STATE_MISSED | CALL_STATE_CANCELLED | "failed"
    ) {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "call is in a terminal state and cannot accept further signals",
        )
        .with_wire_code("call_state_terminal"));
    }

    let sender = auth.actor.clone();
    let message_type = body.message_type.clone();
    let payload = body.payload.clone();
    let proofs = body.proofs.clone();
    let created_at = now();
    let appended = state
        .persistence
        .webrtc()
        .append_signal(
            &record.session_id,
            &auth.actor,
            Box::new(move |seq| WebRtcSignalRecord {
                seq,
                sender,
                message_type,
                payload,
                proofs,
                created_at,
            }),
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;

    // Re-read so the derived call_state reflects the freshly appended frame.
    let mut refreshed = state
        .persistence
        .webrtc()
        .get(&record.session_id)
        .await
        .ok()
        .flatten()
        .unwrap_or(record);

    // `webrtc-signaling.md` §3a — project the kick / ban moderation log into the
    // durable `ck.call.state.removed_participants[]` materialization so the
    // token issuer can gate re-issue on the ban set. Re-derive from the full
    // signal log and persist when the projection changed.
    let projected_removed = derive_removed_participants(&refreshed.signals);
    if projected_removed.len() != refreshed.removed_participants.len() {
        refreshed.removed_participants = projected_removed;
        let _ = state.persistence.webrtc().put(refreshed.clone()).await;
    }

    json_ok(AppendSignalOutcome {
        seq: appended.seq,
        // Cursor is the highest committed seq; clients pass it back as
        // `?since=` to fetch only newer frames.
        next_cursor: appended.seq.to_string(),
        call_state: derive_call_state(&refreshed.signals),
    })
}

#[endpoint(
    operation_id = "ck.self.webrtc.signal.list",
    tags("media", "calls"),
    summary = "List signaling frames since a cursor",
    status_codes(200, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.webrtc.signal.list"))]
async fn list_webrtc_signals(
    aa: AuthArgs,
    session_id: salvo::oapi::extract::PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ListSignalsOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let auth = aa.authenticated_session(state, req).await?;
    let session_id = session_id.into_inner();
    let since = crate::routing::system::util::query_param(req, "since")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let record = load_session_for_participant(state, &session_id, &auth.actor).await?;

    let mut events = Vec::new();
    let mut running_state = CALL_STATE_RINGING;
    for signal in &record.signals {
        running_state =
            call_state_after_signal(running_state, &signal.message_type, &signal.payload);
        if signal.seq <= since {
            continue;
        }
        events.push(SignalEventView {
            seq: signal.seq,
            message_type: signal.message_type.clone(),
            sender: signal.sender.clone(),
            payload: signal.payload.clone(),
            proofs: signal.proofs.clone(),
            created_at: signal.created_at,
            call_state_after: running_state.to_owned(),
        });
    }
    json_ok(ListSignalsOutcome {
        events,
        // Highest committed seq (0 when the log is empty).
        next_cursor: record.next_seq.saturating_sub(1).to_string(),
        call_state: derive_call_state(&record.signals),
    })
}

/// Load a session and assert the caller is one of its participants.
async fn load_session_for_participant(
    state: &AppState,
    session_id: &str,
    actor: &str,
) -> Result<WebRtcSessionRecord, AppError> {
    if !is_valid_webrtc_session_id(session_id) {
        return Err(AppError::not_found("call session not found"));
    }
    let record = state
        .persistence
        .webrtc()
        .get(session_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("call session not found"))?;
    if !record.participants.contains(actor) {
        return Err(AppError::capability_denied(
            "actor is not a participant of the call",
        ));
    }
    Ok(record)
}

#[derive(Clone, Debug, serde::Deserialize, salvo::oapi::ToSchema)]
struct CallIceConfigRequestBody {
    realm_id: RealmId,
    call_id: String,
    actor_id: Did,
    device_id: DeviceId,
    #[serde(default)]
    mode: Option<MediaIceMode>,
}

#[derive(Clone, Debug, serde::Deserialize, salvo::oapi::ToSchema)]
struct CallIceConfigRefreshRequestBody {
    realm_id: RealmId,
    actor_id: Did,
    device_id: DeviceId,
    #[serde(default)]
    mode: Option<MediaIceMode>,
}

#[endpoint(
    operation_id = "ck.self.call.ice_config.issue",
    tags("media", "calls"),
    summary = "Issue a signed ICE config for a call",
    status_codes(200, 400, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.call.ice_config.issue"))]
async fn calls_ice_config(
    aa: AuthArgs,
    body: JsonBody<CallIceConfigRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SolandIceConfigOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
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
            force_turn: matches!(body.mode, Some(MediaIceMode::Turn)),
        },
        None,
        false,
    )
    .await
}

#[endpoint(
    operation_id = "ck.self.call.ice_config.refresh",
    tags("media", "calls"),
    summary = "Refresh in-call ICE/TURN credentials",
    status_codes(200, 400, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.call.ice_config.refresh"))]
async fn calls_ice_config_refresh(
    aa: AuthArgs,
    call_id: salvo::oapi::extract::PathParam<String>,
    body: JsonBody<CallIceConfigRefreshRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SolandIceConfigOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let call_id = call_id.into_inner();
    issue_ice_config(
        state,
        &session,
        IceConfigRequestContext {
            realm_id: body.realm_id,
            call_id: call_id.clone(),
            actor_id: body.actor_id,
            device_id: body.device_id,
            force_turn: matches!(body.mode, Some(MediaIceMode::Turn)),
        },
        Some(call_id),
        true,
    )
    .await
}

#[endpoint(
    operation_id = "ck.self.call.recording.start",
    tags("media", "calls"),
    summary = "Start a call recording (gated by recording_policy)",
    status_codes(200, 400, 401, 403, 404, 412, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.call.recording.start"))]
async fn calls_recording_start(
    aa: AuthArgs,
    call_id: salvo::oapi::extract::PathParam<String>,
    body: JsonBody<RecordingStartRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RecordingStartOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let auth = aa.authenticated_session(state, req).await?;
    let call_id = call_id.into_inner();
    let body = body.into_inner();
    let mut record = load_session_for_participant(state, &call_id, &auth.actor).await?;
    if record.realm_id != body.realm_id.as_str() {
        return Err(AppError::invalid_param(
            "call_id does not belong to the requested realm",
        ));
    }

    // `webrtc-signaling.md` §3 / `call-state.md` §5 — Realm members do not
    // implicitly hold `ck.call.record`; the per-call `recording_policy` gates
    // whether a recording may start at all.
    if record.recording_policy == "none" {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "call recording_policy forbids recording",
        )
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_wire_code("recording_policy_violation"));
    }

    // `call-state.md` §5 — backend-generated recording artifacts MUST flow
    // through the Cokret blob pipeline. A caller that hands us a raw backend
    // recording URL is bypassing that pipeline and MUST be rejected.
    if body.recording_artifact_url.is_some() {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "recording artifact must be uploaded via the Cokret blob pipeline, not a backend URL",
        )
        .with_wire_code("recording_artifact_pipeline_bypassed"));
    }

    // Mint the recording artifact reference inside the Cokret blob namespace.
    // `recording_id` is the stable opaque lifecycle handle (§5) and the
    // artifact lands as an encrypted blob keyed by its content digest.
    let recording_id = ids::generate("recording");
    let recording_start_event_id = ids::generate_event_id();
    let digest_material = format!(
        "soland-rtc-recording-artifact-v1\0{}\0{}\0{}\0{}",
        record.realm_id, record.session_id, recording_id, recording_start_event_id
    );
    let recording_blob_ref = format!("ck:blob:sha256:{}", sha256_hex(digest_material.as_bytes()));
    let recording_sha = recording_blob_ref
        .trim_start_matches("ck:blob:sha256:")
        .to_owned();
    let now_ts = now();
    let blob_record = crate::state::BlobRecord {
        sha256: recording_sha.clone(),
        size_bytes: 0,
        storage_backend: "cokret-recording-pipeline".to_owned(),
        storage_key: format!("recordings/{}/{recording_id}", record.session_id),
        media_type: "application/vnd.cokret.rtc-recording".to_owned(),
        filename: None,
        realm_id: Some(record.realm_id.clone()),
        encryption: Some(json!({
            "scheme": "ck-rtc-recording-key/v1",
            "recording_id": recording_id.clone(),
            "recording_start_event_id": recording_start_event_id.clone(),
            "recording_agent": body.recording_agent.clone(),
        })),
        uploaded_by: auth.actor.clone(),
        created_at: now_ts,
    };
    state
        .persistence
        .blobs()
        .put(&recording_blob_ref, &blob_record)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;

    record.recording_started_by = Some(auth.actor.clone());
    record.recording_blob_ref = Some(recording_blob_ref.clone());
    state
        .persistence
        .webrtc()
        .put(record.clone())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;

    json_ok(RecordingStartOutcome {
        ok: true,
        call_id,
        recording_policy: record.recording_policy.clone(),
        recording_started_by: auth.actor,
        recording_blob_ref,
        recording_id,
        recording_start_event_id,
        recording_state: "recording".to_owned(),
    })
}

fn is_valid_webrtc_session_id(value: &str) -> bool {
    // v1 wire ID: `ck:call:<uuidv7-36-char-lowercase-hex>` (RFC 9562 v7,
    // version=7, variant ∈ {8,9,a,b}) — per
    // `cokret-spec/v1/artifacts/registry/id-kind-registry.json` the WebRTC
    // call surface uses `ck:call:`.
    let Some(rest) = value.strip_prefix("ck:call:") else {
        return false;
    };
    let Ok(parsed) = uuid::Uuid::parse_str(rest) else {
        return false;
    };
    parsed.get_version_num() == 7
}
