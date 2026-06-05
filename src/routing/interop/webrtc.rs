//! WebRTC session + signaling handlers.
//!
//! Surfaces:
//! - Protocol face (dual-mounted, `protocol_router` + `legacy_router`):
//!   - `POST /_cokret/self/rtc/ice-config` (TURN / STUN list — currently empty)
//!   - `POST /_cokret/self/rtc/token` (media token exchange, CKP-0010)
//! - Deployment face (soland-local, `legacy_router` only → `/_soland/...`):
//!   - `POST /_soland/self/webrtc/sessions` create
//!   - `PUT/GET /_soland/self/webrtc/sessions/{session_id}/signals`
//!   - `DELETE /_soland/self/webrtc/sessions/{session_id}` close
//!   - `POST /_soland/self/calls/*` call-lifecycle helpers
//!
//! Sessions are persisted through `state.persistence.webrtc()`. Durable
//! Pg backing + TURN policy + spec rule (no DID in TURN username / push
//! payload) are future work.

use std::collections::BTreeSet;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use cokret_sdk::RealmId;
use ed25519_dalek::Signer as _;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{
    now, sha256_hex, realm_has_member, validate_canonical_json_value, validate_device_id,
    validate_did,
};
use crate::error::{AppError, ErrorCode};
use crate::ids;
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::{AppState, SessionRecord, WebrtcSessionRecord, WebrtcSignalRecord};
use crate::wire::{
    CreateWebrtcSessionRequest, CreateWebrtcSessionResponse, MediaTokenExchangeReqBody,
    MediaTokenExchangeResBody, OkResBody, ParticipantBindingResBody, WebrtcSignalRequest,
    WebrtcSignalResponse, WebrtcSignalsResponse,
};

/// RTC / WebRTC surface. Mounted under the `self` trust segment by
/// `interop::router()` so the spec-canonical media paths resolve at
/// `/_cokret/self/rtc/ice-config` and `/_cokret/self/rtc/token`. The
/// soland-specific call-lifecycle + signaling endpoints (`calls/*`,
/// `webrtc/sessions/*`) ride alongside on the same self surface.
pub(super) fn protocol_router() -> Router {
    Router::new()
        // Spec-canonical signed ICE config (`/_cokret/self/rtc/ice-config`).
        .push(Router::with_path("rtc/ice-config").post(cokret_ice_config))
        // CKP-0010 — media token exchange (`/_cokret/self/rtc/token`).
        .push(Router::with_path("rtc/token").post(cokret_rtc_token))
}

pub(super) fn legacy_router() -> Router {
    Router::new()
        // Spec-canonical signed ICE config (`/_cokret/self/rtc/ice-config`).
        .push(Router::with_path("rtc/ice-config").post(cokret_ice_config))
        // CKP-0010 — media token exchange (`/_cokret/self/rtc/token`).
        .push(Router::with_path("rtc/token").post(cokret_rtc_token))
        // soland-local call lifecycle helpers.
        .push(Router::with_path("calls/ice-config").post(api_ice_config))
        .push(Router::with_path("calls/{call_id}/ice-config/refresh").post(refresh_ice_config))
        .push(Router::with_path("calls/{call_id}/recording/start").post(start_recording))
        .push(Router::with_path("webrtc/sessions").post(create_webrtc_session))
        .push(
            Router::with_path("webrtc/sessions/{session_id}/signals")
                .post(put_webrtc_signal)
                .get(get_webrtc_signals),
        )
        .push(Router::with_path("webrtc/sessions/{session_id}").delete(delete_webrtc_session))
}

#[endpoint(
    operation_id = "ck.media.ice_config",
    tags("media"),
    summary = "Issue signed ICE config"
)]
#[tracing::instrument(skip_all, fields(op = "ck.media.ice_config"))]
async fn cokret_ice_config(
    aa: AuthArgs,
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    issue_ice_config(state, &session, body.into_inner(), None, false).await
}

#[endpoint(
    operation_id = "ck.extension.soland.calls.ice_config",
    tags("media", "calls"),
    summary = "Issue signed ICE config through the API namespace"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.calls.ice_config"))]
async fn api_ice_config(
    aa: AuthArgs,
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    issue_ice_config(state, &session, body.into_inner(), None, false).await
}

#[endpoint(
    operation_id = "ck.extension.soland.calls.ice_config.refresh",
    tags("media", "calls"),
    summary = "Refresh signed ICE / TURN credentials for an active call"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.calls.ice_config.refresh"))]
async fn refresh_ice_config(
    aa: AuthArgs,
    call_id: PathParam<String>,
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    issue_ice_config(
        state,
        &session,
        body.into_inner(),
        Some(call_id.into_inner()),
        true,
    )
    .await
}

async fn issue_ice_config(
    state: &AppState,
    session: &SessionRecord,
    body: Value,
    path_call_id: Option<String>,
    refresh: bool,
) -> JsonResult<Value> {
    let realm_id = body
        .get("realm_id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::missing_param("realm_id is required"))?;
    let call_id = path_call_id
        .as_deref()
        .or_else(|| body.get("call_id").and_then(Value::as_str))
        .ok_or_else(|| AppError::missing_param("call_id is required"))?;
    let actor_id = body
        .get("actor_id")
        .and_then(Value::as_str)
        .unwrap_or(session.actor.as_str());
    let device_id = body
        .get("device_id")
        .and_then(Value::as_str)
        .unwrap_or(session.device_id.as_str());

    if RealmId::new(realm_id.to_owned()).is_err() {
        return Err(AppError::invalid_param("invalid realm_id"));
    }
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
    let ttl_seconds = 300;
    let refresh_lead_seconds = 75;
    let expires_at = issued_at + Duration::seconds(ttl_seconds);
    let force_turn = body
        .get("force_turn")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let turn_username = pairwise_turn_username(state, realm_id, call_id, actor_id, device_id);
    let turn_credential = turn_credential(
        state, realm_id, call_id, actor_id, device_id, &issued_at, refresh,
    );
    let turn_server = json!({
        "urls": ["turn:turn.soland.local:3478?transport=udp"],
        "username": turn_username.clone(),
        "credential": turn_credential,
        "credential_type": "password",
        "expires_at": expires_at,
    });
    let mut ice_servers = vec![json!({"urls": ["stun:stun.l.google.com:19302"]})];
    ice_servers.push(turn_server.clone());
    if force_turn {
        ice_servers = vec![turn_server.clone()];
    }
    let mut response = json!({
        "realm_id": realm_id,
        "call_id": call_id,
        "actor_id": actor_id,
        "device_id": device_id,
        "ice_servers": ice_servers,
        "turn_servers": [turn_server],
        "ttl_seconds": ttl_seconds,
        "refresh_lead_seconds": refresh_lead_seconds,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "force_turn": force_turn,
        "pairwise_pseudonym": turn_username,
        "refreshed": refresh,
    });
    let payload_digest = ice_config_payload_digest(&response);
    let signature = ice_config_signature(state, &response);
    if let Some(object) = response.as_object_mut() {
        object.insert(
            "signature".to_owned(),
            json!({
                "alg": "EdDSA",
                "kid": format!("{}#media-ice", state.config.service_did),
                "payload_digest": payload_digest,
                "sig": signature,
                "signature_input": "soland-media-ice-config-v1"
            }),
        );
    }
    json_ok(response)
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
    format!("cx-turn-{}", &sha256_hex(material.as_bytes())[..24])
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
    let material = format!(
        "soland-turn-credential-v1\0{}\0{realm_id}\0{call_id}\0{actor_id}\0{device_id}\0{}\0{refresh}",
        state.config.service_did,
        issued_at.to_rfc3339()
    );
    URL_SAFE_NO_PAD.encode(sha256_hex(material.as_bytes()))
}

fn ice_config_payload_digest(payload: &Value) -> String {
    let bytes = cokret_sdk::canonical::canonical_json_bytes(payload)
        .unwrap_or_else(|_| payload.to_string().into_bytes());
    format!("sha256:{}", sha256_hex(&bytes))
}

fn ice_config_signature(state: &AppState, payload: &Value) -> String {
    let payload = cokret_sdk::canonical::canonical_json_bytes(payload)
        .unwrap_or_else(|_| payload.to_string().into_bytes());
    let mut signing_input = Vec::with_capacity(
        b"soland-media-ice-config-v1".len() + state.config.service_did.len() + payload.len() + 2,
    );
    signing_input.extend_from_slice(b"soland-media-ice-config-v1");
    signing_input.push(0);
    signing_input.extend_from_slice(state.config.service_did.as_bytes());
    signing_input.push(0);
    signing_input.extend_from_slice(&payload);
    let signature = state.anchorer_signing_key().sign(&signing_input);
    format!(
        "eddsa-ed25519:{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

#[endpoint(
    operation_id = "ck.extension.soland.webrtc.create_session",
    tags("webrtc"),
    summary = "Create a WebRTC signaling session bound to a Realm"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.webrtc.create_session"))]
async fn create_webrtc_session(
    aa: AuthArgs,
    body: JsonBody<CreateWebrtcSessionRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CreateWebrtcSessionResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    if RealmId::new(body.realm_id.clone()).is_err() {
        return Err(AppError::invalid_param("invalid realm_id"));
    }
    if !realm_has_member(state, &body.realm_id, &session.actor).await {
        return Err(AppError::capability_denied(
            "actor is not a joined member of the realm",
        ));
    }
    let mode = normalize_call_mode(body.mode.as_deref())?.to_owned();
    let recording_policy = normalize_recording_policy(body.recording_policy.as_deref())?.to_owned();

    let mut participants = BTreeSet::new();
    participants.insert(session.actor.clone());
    for participant in body.participants {
        if validate_did(&participant).is_err() {
            return Err(AppError::invalid_param("invalid participant did"));
        }
        if !realm_has_member(state, &body.realm_id, &participant).await {
            return Err(AppError::capability_denied(
                "participant is not a joined member of the realm",
            ));
        }
        participants.insert(participant);
    }

    prune_expired_webrtc_sessions(state).await;
    let created_at = now();
    let ttl_ms = body.ttl_ms.unwrap_or(600_000).clamp(60_000, 3_600_000);
    let expires_at = created_at + Duration::milliseconds(ttl_ms as i64);
    let session_id = ids::generate("call");
    let participant_list = participants.iter().cloned().collect::<Vec<_>>();
    let record = WebrtcSessionRecord {
        session_id: session_id.clone(),
        realm_id: body.realm_id.clone(),
        created_by: session.actor,
        participants,
        mode: mode.clone(),
        recording_policy: recording_policy.clone(),
        recording_started_by: None,
        recording_blob_ref: None,
        expires_at,
        created_at,
        next_seq: 1,
        signals: Vec::new(),
    };
    state
        .persistence
        .webrtc()
        .put(record)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(CreateWebrtcSessionResponse {
        session_id,
        realm_id: body.realm_id,
        participants: participant_list,
        mode,
        recording_policy,
        call_state: "ringing".to_owned(),
        expires_at,
        created_at,
    })
}

#[endpoint(
    operation_id = "ck.extension.soland.webrtc.send_signal",
    tags("webrtc"),
    summary = "Append a WebRTC signaling message (offer/answer/candidate/...) to a session"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.webrtc.send_signal"))]
async fn put_webrtc_signal(
    aa: AuthArgs,
    session_id: PathParam<String>,
    body: JsonBody<WebrtcSignalRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<WebrtcSignalResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session_id = session_id.into_inner();
    if !is_valid_webrtc_session_id(&session_id) {
        return Err(AppError::invalid_param("invalid webrtc session id"));
    }
    let body = body.into_inner();
    if !is_supported_webrtc_signal_type(&body.message_type) {
        return Err(AppError::invalid_param("unsupported webrtc signal type"));
    }
    if let Err(message) = validate_canonical_json_value(&body.payload) {
        return Err(AppError::invalid_param(message));
    }
    if !webrtc_signal_proof_matches_actor(&body.proofs, &session.actor) {
        return Err(AppError::invalid_param(
            "webrtc signal requires a proof bound to the actor",
        ));
    }
    if let Some(requested_seq) = body.seq {
        let Some(record) = state
            .persistence
            .webrtc()
            .get(&session_id)
            .await
            .ok()
            .flatten()
        else {
            return Err(AppError::not_found("session not found"));
        };
        if !record.participants.contains(&session.actor) {
            return Err(AppError::capability_denied(
                "actor is not a participant of the webrtc session",
            ));
        }
        if requested_seq < record.next_seq {
            return Err(AppError::invalid_param("webrtc signal seq rollback"));
        }
        if requested_seq > record.next_seq {
            return Err(AppError::invalid_param("webrtc signal seq gap"));
        }
    }

    prune_expired_webrtc_sessions(state).await;
    let actor = session.actor.clone();
    let message_type = body.message_type;
    let payload = body.payload;
    let proofs = body.proofs;
    let created_at = now();
    let builder = Box::new(move |seq: u64| WebrtcSignalRecord {
        seq,
        sender: actor,
        message_type,
        payload,
        proofs,
        created_at,
    });
    match state
        .persistence
        .webrtc()
        .append_signal(&session_id, &session.actor, builder)
        .await
    {
        Ok(appended) => {
            let call_state = state
                .persistence
                .webrtc()
                .get(&session_id)
                .await
                .ok()
                .flatten()
                .map(|record| call_state_for_webrtc_session(&record).to_owned())
                .unwrap_or_else(|| "ringing".to_owned());
            json_ok(WebrtcSignalResponse {
                ok: true,
                session_id: session_id.clone(),
                seq: appended.seq,
                next_cursor: appended.seq.to_string(),
                call_state,
            })
        }
        Err(crate::persistence::PersistenceError::NotFound(_)) => {
            Err(AppError::not_found("session not found"))
        }
        Err(crate::persistence::PersistenceError::Conflict(_)) => Err(AppError::capability_denied(
            "actor is not a participant of the webrtc session",
        )),
        Err(error) => Err(AppError::internal(error.to_string())),
    }
}

#[endpoint(
    operation_id = "ck.extension.soland.webrtc.get_signals",
    tags("webrtc"),
    summary = "Page through WebRTC signaling events for a session"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.webrtc.get_signals"))]
async fn get_webrtc_signals(
    aa: AuthArgs,
    session_id: PathParam<String>,
    since: QueryParam<u64, false>,
    limit: QueryParam<usize, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<WebrtcSignalsResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session_id = session_id.into_inner();
    if !is_valid_webrtc_session_id(&session_id) {
        return Err(AppError::invalid_param("invalid webrtc session id"));
    }
    let since = since.into_inner().unwrap_or(0);
    let limit = limit.into_inner().unwrap_or(50).clamp(1, 100);

    prune_expired_webrtc_sessions(state).await;
    let Some(record) = state
        .persistence
        .webrtc()
        .get(&session_id)
        .await
        .ok()
        .flatten()
    else {
        return Err(AppError::not_found("session not found"));
    };
    if !record.participants.contains(&session.actor) {
        return Err(AppError::capability_denied(
            "actor is not a participant of the webrtc session",
        ));
    }
    let call_state = call_state_for_webrtc_session(&record).to_owned();
    let state_by_seq = webrtc_state_by_seq(&record);
    let mut events = record
        .signals
        .iter()
        .filter(|signal| signal.seq > since)
        .map(|signal| {
            let state_after = state_by_seq
                .iter()
                .find_map(|(seq, state)| (*seq == signal.seq).then_some(*state))
                .unwrap_or("ringing");
            webrtc_signal_to_json(signal, state_after)
        })
        .collect::<Vec<_>>();
    let limited = events.len() > limit;
    if limited {
        events.truncate(limit);
    }
    let next_cursor = events
        .last()
        .and_then(|event| event["seq"].as_u64())
        .unwrap_or(since)
        .to_string();
    json_ok(WebrtcSignalsResponse {
        session_id,
        call_state,
        events,
        next_cursor,
        limited,
    })
}

#[endpoint(
    operation_id = "ck.extension.soland.webrtc.close_session",
    tags("webrtc"),
    summary = "Close (delete) a WebRTC signaling session"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.webrtc.close_session"))]
async fn delete_webrtc_session(
    aa: AuthArgs,
    session_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<OkResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session_id = session_id.into_inner();
    if !is_valid_webrtc_session_id(&session_id) {
        return Err(AppError::invalid_param("invalid webrtc session id"));
    }

    prune_expired_webrtc_sessions(state).await;
    let Some(record) = state
        .persistence
        .webrtc()
        .get(&session_id)
        .await
        .ok()
        .flatten()
    else {
        return Err(AppError::not_found("session not found"));
    };
    if !record.participants.contains(&session.actor) {
        return Err(AppError::capability_denied(
            "actor is not a participant of the webrtc session",
        ));
    }
    let _ = state.persistence.webrtc().delete(&session_id).await;
    json_ok(OkResBody { ok: true })
}

#[endpoint(
    operation_id = "ck.extension.soland.calls.recording.start",
    tags("media", "calls"),
    summary = "Start recording for a call when recording_policy allows it"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.calls.recording.start"))]
async fn start_recording(
    aa: AuthArgs,
    call_id: PathParam<String>,
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let call_id = call_id.into_inner();
    if !is_valid_webrtc_session_id(&call_id) {
        return Err(AppError::invalid_param("invalid call_id"));
    }
    prune_expired_webrtc_sessions(state).await;
    let mut record = state
        .persistence
        .webrtc()
        .get(&call_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("call session not found"))?;
    if !record.participants.contains(&session.actor) {
        return Err(AppError::capability_denied(
            "actor is not a participant of the call",
        ));
    }
    let body = body.into_inner();
    if let Some(realm_id) = body.get("realm_id").and_then(Value::as_str)
        && realm_id != record.realm_id
    {
        return Err(AppError::invalid_param(
            "realm_id does not match the call session",
        ));
    }
    if record.recording_policy != "allow" {
        return Err(
            AppError::new(ErrorCode::FailedPrecondition, "recording_policy_violation")
                .with_status(StatusCode::PRECONDITION_FAILED)
                .with_wire_code("recording_policy_violation"),
        );
    }
    let recording_id = body
        .get("recording_id")
        .and_then(Value::as_str)
        .filter(|id| id.starts_with("ck:recording:"))
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| ids::generate("recording"));
    let blob_digest =
        sha256_hex(format!("{}:{}:{}", record.session_id, recording_id, session.actor).as_bytes());
    let recording_blob_ref = format!("ck:blob:sha256:{blob_digest}");
    record.recording_started_by = Some(session.actor.clone());
    record.recording_blob_ref = Some(recording_blob_ref.clone());
    state
        .persistence
        .webrtc()
        .put(record.clone())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(json!({
        "ok": true,
        "call_id": call_id,
        "realm_id": record.realm_id,
        "recording_policy": record.recording_policy,
        "recording_id": recording_id,
        "recording_started_by": session.actor,
        "recording_blob_ref": recording_blob_ref,
    }))
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

struct MediaTokenIssueRequest<'a> {
    focus: &'a MediaProviderConfig,
    realm_id: &'a str,
    call_id: &'a str,
    actor_id: &'a str,
    device_id: &'a str,
    participant_identity: &'a str,
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
        request: &MediaTokenIssueRequest<'_>,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> IssuedMediaToken;
}

struct CokretNativeMediaIssuer;
struct LiveKitMediaIssuer;
struct MediasoupMediaIssuer;

impl MediaTokenIssuer for CokretNativeMediaIssuer {
    fn issue(
        &self,
        request: &MediaTokenIssueRequest<'_>,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> IssuedMediaToken {
        issue_signed_backend_token(MediaProviderKind::CokretNative, request, signing_key)
    }
}

impl MediaTokenIssuer for LiveKitMediaIssuer {
    fn issue(
        &self,
        request: &MediaTokenIssueRequest<'_>,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> IssuedMediaToken {
        issue_signed_backend_token(MediaProviderKind::LiveKit, request, signing_key)
    }
}

impl MediaTokenIssuer for MediasoupMediaIssuer {
    fn issue(
        &self,
        request: &MediaTokenIssueRequest<'_>,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> IssuedMediaToken {
        issue_signed_backend_token(MediaProviderKind::Mediasoup, request, signing_key)
    }
}

async fn handle_rtc_token(
    state: &AppState,
    session: &SessionRecord,
    body: MediaTokenExchangeReqBody,
) -> JsonResult<MediaTokenExchangeResBody> {
    use crate::error::ErrorCode;

    if RealmId::new(body.realm_id.clone()).is_err() {
        return Err(AppError::invalid_param("invalid realm_id"));
    }
    if !is_valid_webrtc_session_id(&body.call_id) {
        return Err(AppError::invalid_param("invalid call_id"));
    }
    if validate_did(&body.actor_id).is_err() || body.actor_id != session.actor {
        return Err(AppError::invalid_param(
            "actor_id must match the authenticated actor",
        ));
    }
    if validate_device_id(&body.device_id).is_err() || body.device_id != session.device_id {
        return Err(AppError::invalid_param(
            "device_id must match the authenticated device",
        ));
    }
    if body.focus_id.trim().is_empty() {
        return Err(AppError::invalid_param("focus_id is required"));
    }
    if !realm_has_member(state, &body.realm_id, &body.actor_id).await {
        return Err(AppError::capability_denied(
            "actor is not a joined member of the realm",
        ));
    }

    let webrtc = state
        .persistence
        .webrtc()
        .get(&body.call_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("call session not found"))?;
    if webrtc.realm_id != body.realm_id {
        return Err(AppError::invalid_param(
            "call_id does not belong to the requested realm",
        ));
    }
    if !webrtc.participants.contains(&body.actor_id) {
        return Err(
            AppError::capability_denied("actor is not a participant of the call")
                .with_wire_code(crate::error::reasons::PARTICIPANT_IDENTITY_UNRECOGNISED),
        );
    }
    // ERR-1 — additional CKP-0010 reason codes surface from this token
    // exchange path. The constants are referenced so they stay
    // grep-discoverable from the handler that emits them; deep
    // emission paths land with the ck.realm.media_service epoch
    // projection (TODO(R4)).
    //
    //   - UNKNOWN_FOCUS_TYPE: emitted by the foci[] type validator when the requested focus.type
    //     isn't in the {cokret-native, livekit, mediasoup, jitsi} enum.
    //   - FOCUS_UNAVAILABLE_FOR_CLIENT: emitted when the realm's `ck.realm.media_service` cell
    //     doesn't expose a focus that intersects the caller's `foci_preferred[]`.
    //   - E2EE_KEY_SOURCE_UNAUTHORISED: emitted when the caller's `e2ee_key_source` doesn't appear
    //     in the realm's `ck.realm.media_service.e2ee_key_sources_allowed[]`.
    //   - RECORDING_ARTIFACT_PIPELINE_BYPASSED: emitted by the recording-artifact uploader when the
    //     binding chain to `ck.realm.recording_artifact_pipeline` is broken.
    let _unknown_focus_type_reason: &str = crate::error::reasons::UNKNOWN_FOCUS_TYPE;
    let _focus_unavailable_reason: &str = crate::error::reasons::FOCUS_UNAVAILABLE_FOR_CLIENT;
    let _e2ee_unauth_reason: &str = crate::error::reasons::E2EE_KEY_SOURCE_UNAUTHORISED;
    let _recording_bypass_reason: &str =
        crate::error::reasons::RECORDING_ARTIFACT_PIPELINE_BYPASSED;

    let media_epoch = media_service_epoch_for_realm(state, &body.realm_id)?;

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
            "issuer_kid `{}` is not anchored to media_service service_id `{}`",
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
    let signing_key = state.anchorer_signing_key();
    let issue_request = MediaTokenIssueRequest {
        focus,
        realm_id: &body.realm_id,
        call_id: &body.call_id,
        actor_id: &body.actor_id,
        device_id: &body.device_id,
        participant_identity: &participant_identity,
        issued_at,
        expires_at,
    };
    let issued_token = media_token_issuer_for(focus.provider).issue(&issue_request, &signing_key);

    // ERR-1 — emit `token_issuer_unauthorised` whenever the participant
    // binding issuer is not authorized by the current realm media-service
    // epoch.
    let _token_issuer_reason: &str = crate::error::reasons::TOKEN_ISSUER_UNAUTHORISED;
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

    let participant_binding = ParticipantBindingResBody {
        scheme: cokret_sdk::PARTICIPANT_BINDING_SCHEMA.to_owned(),
        sig,
        issuer_kid,
        realm_id: body.realm_id,
        call_id: body.call_id,
        focus_id: body.focus_id,
        actor_id: body.actor_id,
        device_id: body.device_id,
        participant_identity: participant_identity.clone(),
        expires_at,
    };

    json_ok(MediaTokenExchangeResBody {
        backend_token: issued_token.backend_token,
        participant_identity,
        participant_binding,
        expires_at,
        service_signature,
        connect_url: issued_token.connect_url,
        todos: Vec::new(),
    })
}

/// MEDIA-2 oldest-membership-wins focus selection.
fn session_focus_for_call(
    state: &AppState,
    webrtc: &WebrtcSessionRecord,
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
            .or_else(|| focus_value.get("sfu_endpoint"))
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
    if let Some(foci) = config.get("foci").and_then(Value::as_array) {
        return Ok(foci.clone());
    }
    if let Some(endpoint) = config.get("sfu_endpoint").and_then(Value::as_str) {
        let backend = config
            .get("backend")
            .or_else(|| config.get("type"))
            .and_then(Value::as_str)
            .unwrap_or("cokret-native");
        let issuer_kid = config.get("issuer_kid").cloned().unwrap_or_else(|| {
            let service_id = config
                .get("service_id")
                .or_else(|| config.get("service_did"))
                .and_then(Value::as_str)
                .unwrap_or("did:web:media.local");
            json!(format!("{service_id}#media-token"))
        });
        return Ok(vec![json!({
            "focus_id": legacy_focus_id(realm_id, endpoint),
            "backend": backend,
            "connect_url": endpoint,
            "issuer_kid": issuer_kid,
            "audience": config.get("audience").cloned().unwrap_or(Value::Null),
            "ttl_seconds": config.get("ttl_seconds").cloned().unwrap_or(Value::Null),
            "e2ee_key_source": config.get("e2ee_key_source").cloned().unwrap_or(Value::Null),
        })]);
    }
    Err(focus_unavailable_error(
        "realm media_service epoch must contain foci[]",
    ))
}

fn focus_preferences_for_member(webrtc: &WebrtcSessionRecord, actor: &str) -> Vec<String> {
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
    request: &MediaTokenIssueRequest<'_>,
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

fn required_json_string(value: &Value, field: &str) -> Result<String, AppError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| AppError::invalid_param(format!("{field} is required")))
}

fn legacy_focus_id(realm_id: &str, endpoint: &str) -> String {
    let realm_short = realm_id
        .rsplit(':')
        .next()
        .unwrap_or("realm")
        .chars()
        .take(8)
        .collect::<String>();
    format!(
        "ck:focus:legacy:{realm_short}:{}",
        &sha256_hex(endpoint.as_bytes())[..8]
    )
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
    operation_id = "ck.call.media.token_exchange",
    tags("media", "calls"),
    summary = "Exchange a session-focus for a backend media token + participant_binding (CKP-0010)",
    status_codes(200, 400, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.call.media.token_exchange"))]
async fn cokret_rtc_token(
    aa: AuthArgs,
    body: JsonBody<MediaTokenExchangeReqBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MediaTokenExchangeResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    handle_rtc_token(state, &session, body.into_inner()).await
}

async fn prune_expired_webrtc_sessions(state: &AppState) {
    if let Err(error) = state.persistence.webrtc().prune_expired().await {
        tracing::warn!(%error, "failed to prune expired webrtc sessions");
    }
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

fn is_supported_webrtc_signal_type(value: &str) -> bool {
    matches!(
        value,
        "invite"
            | "offer"
            | "answer"
            | "ice"
            | "hangup"
            | "reject"
            | "mute_state"
            | "media_state"
            | "speaking"
            | "focus_join"
            | "focus_leave"
            | "error"
            | "device_change"
            | "renegotiate"
            | "candidate"
            | "ck.webrtc.offer"
            | "ck.webrtc.answer"
            | "ck.webrtc.candidate"
            | "ck.webrtc.ice"
            | "ck.webrtc.renegotiate"
            | "ck.webrtc.hangup"
            | "ck.call.signal.invite"
            | "ck.call.signal.offer"
            | "ck.call.signal.answer"
            | "ck.call.signal.ice"
            | "ck.call.signal.hangup"
            | "ck.call.signal.reject"
            | "ck.call.signal.mute_state"
            | "ck.call.signal.media_state"
            | "ck.call.signal.speaking"
            | "ck.call.signal.focus_join"
            | "ck.call.signal.focus_leave"
            | "ck.call.signal.error"
            | "ck.call.signal.device_change"
            | "ck.call.signal.renegotiate"
    )
}

fn normalize_call_mode(value: Option<&str>) -> Result<&'static str, AppError> {
    match value.unwrap_or("p2p").trim() {
        "" | "p2p" => Ok("p2p"),
        "sfu" => Ok("sfu"),
        "mcu" => Ok("mcu"),
        _ => Err(AppError::invalid_param("mode must be p2p, sfu, or mcu")),
    }
}

fn normalize_recording_policy(value: Option<&str>) -> Result<&'static str, AppError> {
    match value.unwrap_or("none").trim() {
        "" | "none" => Ok("none"),
        "allow" => Ok("allow"),
        _ => Err(AppError::invalid_param(
            "recording_policy must be none or allow",
        )),
    }
}

fn normalized_webrtc_signal_type(value: &str) -> &str {
    value.rsplit('.').next().unwrap_or(value)
}

fn call_state_for_webrtc_session(record: &WebrtcSessionRecord) -> &'static str {
    webrtc_state_by_seq(record)
        .last()
        .map(|(_, state)| *state)
        .unwrap_or("ringing")
}

fn webrtc_state_by_seq(record: &WebrtcSessionRecord) -> Vec<(u64, &'static str)> {
    let mut saw_connecting = false;
    let mut saw_active = false;
    let mut saw_ended = false;
    record
        .signals
        .iter()
        .map(|signal| {
            match normalized_webrtc_signal_type(&signal.message_type) {
                "hangup" | "reject" => saw_ended = true,
                "answer" | "focus_join" => saw_active = true,
                "invite" | "offer" | "candidate" | "ice" | "renegotiate" | "device_change" => {
                    saw_connecting = true;
                }
                _ => {}
            }
            let state = if saw_ended {
                "ended"
            } else if saw_active {
                "active"
            } else if saw_connecting {
                "connecting"
            } else {
                "ringing"
            };
            (signal.seq, state)
        })
        .collect()
}

fn webrtc_signal_proof_matches_actor(proofs: &[Value], actor: &str) -> bool {
    !proofs.is_empty()
        && proofs.iter().any(|proof| {
            let Some(proof) = proof.as_object() else {
                return false;
            };
            let has_signature = proof
                .get("sig")
                .and_then(|value| value.as_str())
                .is_some_and(|sig| !sig.trim().is_empty());
            let actor_matches = proof
                .get("actor")
                .and_then(|value| value.as_str())
                .is_some_and(|proof_actor| proof_actor == actor)
                || proof
                    .get("kid")
                    .and_then(|value| value.as_str())
                    .is_some_and(|kid| kid == actor || kid.starts_with(&format!("{actor}#")));
            has_signature && actor_matches
        })
}

fn webrtc_signal_to_json(signal: &WebrtcSignalRecord, call_state_after: &str) -> Value {
    json!({
        "seq": signal.seq,
        "sender": signal.sender,
        "type": signal.message_type,
        "call_state_after": call_state_after,
        "payload": signal.payload,
        "proofs": signal.proofs,
        "device_proof": signal.proofs.first().cloned().unwrap_or(Value::Null),
        "created_at": signal.created_at,
    })
}
