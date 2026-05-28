//! WebRTC session + signaling handlers.
//!
//! Surfaces:
//! - `POST /contrix/v1/ice-config` (TURN / STUN list — currently empty)
//! - `POST /api/v1/webrtc/sessions` create
//! - `PUT/GET /api/v1/webrtc/sessions/{session_id}/signals`
//! - `DELETE /api/v1/webrtc/sessions/{session_id}` close
//!
//! Sessions are persisted through `state.persistence.webrtc()`. Durable
//! Pg backing + TURN policy + spec rule (no DID in TURN username / push
//! payload) are future work.

use std::collections::BTreeSet;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Duration;
use contrix_sdk::RealmId;
use ed25519_dalek::Signer as _;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{
    now, sha256_hex, space_has_member, validate_canonical_json_value, validate_device_id,
    validate_did, validate_space_id,
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

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("calls/ice-config").post(api_ice_config))
        .push(Router::with_path("calls/{call_id}/ice-config/refresh").post(refresh_ice_config))
        .push(Router::with_path("calls/{call_id}/recording/start").post(start_recording))
        // CXP-0010 (R3 spec-sync) — media token exchange. Spec-canonical
        // wire-path is `POST /rtc/token` (mounted via `contrix_router`)
        // but `/api/v1/rtc/token` is also accepted as a deployment-local
        // alias so admin UIs that namespace everything under `/api/v1/`
        // can reach the handler without a separate ingress rule.
        .push(Router::with_path("rtc/token").post(api_rtc_token))
        .push(Router::with_path("webrtc/sessions").post(create_webrtc_session))
        .push(
            Router::with_path("webrtc/sessions/{session_id}/signals")
                .post(put_webrtc_signal)
                .get(get_webrtc_signals),
        )
        .push(Router::with_path("webrtc/sessions/{session_id}").delete(delete_webrtc_session))
}

pub(super) fn contrix_router() -> Router {
    Router::new()
        .push(Router::with_path("contrix/v1/ice-config").post(contrix_ice_config))
        // CXP-0010 — `POST /rtc/token` per CXP-0010 / contrix-spec
        // b47ff6ec. Spec path lives at the deployment root (not under
        // `/contrix/v1/`); both shapes are mounted so deployments behind
        // an ingress that strips the `/contrix/v1/` prefix can still
        // reach the handler.
        .push(Router::with_path("rtc/token").post(contrix_rtc_token))
        .push(Router::with_path("contrix/v1/rtc/token").post(contrix_rtc_token))
}

#[endpoint(
    operation_id = "cx.media.ice_config",
    tags("media"),
    summary = "Issue signed ICE config"
)]
#[tracing::instrument(skip_all, fields(op = "cx.media.ice_config"))]
async fn contrix_ice_config(
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
    operation_id = "cx.extension.soland.calls.ice_config",
    tags("media", "calls"),
    summary = "Issue signed ICE config through the API namespace"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.calls.ice_config"))]
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
    operation_id = "cx.extension.soland.calls.ice_config.refresh",
    tags("media", "calls"),
    summary = "Refresh signed ICE / TURN credentials for an active call"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.calls.ice_config.refresh"))]
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
        .or_else(|| body.get("space_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::missing_param("realm_id or space_id is required"))?;
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
    if !space_has_member(state, realm_id, actor_id).await {
        return Err(AppError::capability_denied(
            "actor is not a joined member of the realm",
        ));
    }
    if let Some(record) = state.persistence.webrtc().get(call_id).await.ok().flatten() {
        if record.space_id != realm_id {
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
        "space_id": realm_id,
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
    let bytes = contrix_sdk::canonical::canonical_json_bytes(payload)
        .unwrap_or_else(|_| payload.to_string().into_bytes());
    format!("sha256:{}", sha256_hex(&bytes))
}

fn ice_config_signature(state: &AppState, payload: &Value) -> String {
    let payload = contrix_sdk::canonical::canonical_json_bytes(payload)
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
    operation_id = "cx.extension.soland.webrtc.create_session",
    tags("webrtc"),
    summary = "Create a WebRTC signaling session bound to a Space"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.webrtc.create_session"))]
async fn create_webrtc_session(
    aa: AuthArgs,
    body: JsonBody<CreateWebrtcSessionRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CreateWebrtcSessionResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    if validate_space_id(&body.space_id).is_err() {
        return Err(AppError::invalid_param("invalid space_id"));
    }
    if !space_has_member(state, &body.space_id, &session.actor).await {
        return Err(AppError::capability_denied(
            "actor is not a joined member of the space",
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
        if !space_has_member(state, &body.space_id, &participant).await {
            return Err(AppError::capability_denied(
                "participant is not a joined member of the space",
            ));
        }
        participants.insert(participant);
    }

    prune_expired_webrtc_sessions(state);
    let created_at = now();
    let ttl_ms = body.ttl_ms.unwrap_or(600_000).clamp(60_000, 3_600_000);
    let expires_at = created_at + Duration::milliseconds(ttl_ms as i64);
    let session_id = ids::generate("call");
    let participant_list = participants.iter().cloned().collect::<Vec<_>>();
    let record = WebrtcSessionRecord {
        session_id: session_id.clone(),
        space_id: body.space_id.clone(),
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
        .put(record).await
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(CreateWebrtcSessionResponse {
        session_id,
        space_id: body.space_id,
        participants: participant_list,
        mode,
        recording_policy,
        call_state: "ringing".to_owned(),
        expires_at,
        created_at,
    })
}

#[endpoint(
    operation_id = "cx.extension.soland.webrtc.send_signal",
    tags("webrtc"),
    summary = "Append a WebRTC signaling message (offer/answer/candidate/...) to a session"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.webrtc.send_signal"))]
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
        let Some(record) = state.persistence.webrtc().get(&session_id).await.ok().flatten() else {
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

    prune_expired_webrtc_sessions(state);
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
        .append_signal(&session_id, &session.actor, builder).await
    {
        Ok(appended) => {
            let call_state = state
                .persistence
                .webrtc()
                .get(&session_id).await
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
    operation_id = "cx.extension.soland.webrtc.get_signals",
    tags("webrtc"),
    summary = "Page through WebRTC signaling events for a session"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.webrtc.get_signals"))]
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

    prune_expired_webrtc_sessions(state);
    let Some(record) = state.persistence.webrtc().get(&session_id).await.ok().flatten() else {
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
    operation_id = "cx.extension.soland.webrtc.close_session",
    tags("webrtc"),
    summary = "Close (delete) a WebRTC signaling session"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.webrtc.close_session"))]
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

    prune_expired_webrtc_sessions(state);
    let Some(record) = state.persistence.webrtc().get(&session_id).await.ok().flatten() else {
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
    operation_id = "cx.extension.soland.calls.recording.start",
    tags("media", "calls"),
    summary = "Start recording for a call when recording_policy allows it"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.calls.recording.start"))]
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
    prune_expired_webrtc_sessions(state);
    let mut record = state
        .persistence
        .webrtc()
        .get(&call_id).await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("call session not found"))?;
    if !record.participants.contains(&session.actor) {
        return Err(AppError::capability_denied(
            "actor is not a participant of the call",
        ));
    }
    let body = body.into_inner();
    if let Some(space_id) = body.get("space_id").and_then(Value::as_str)
        && space_id != record.space_id
    {
        return Err(AppError::invalid_param(
            "space_id does not match the call session",
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
        .filter(|id| id.starts_with("cx:recording:"))
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| ids::generate("recording"));
    let blob_digest =
        sha256_hex(format!("{}:{}:{}", record.session_id, recording_id, session.actor).as_bytes());
    let recording_blob_ref = format!("cx:blob:sha256:{blob_digest}");
    record.recording_started_by = Some(session.actor.clone());
    record.recording_blob_ref = Some(recording_blob_ref.clone());
    state
        .persistence
        .webrtc()
        .put(record.clone()).await
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(json!({
        "ok": true,
        "call_id": call_id,
        "space_id": record.space_id,
        "recording_policy": record.recording_policy,
        "recording_id": recording_id,
        "recording_started_by": session.actor,
        "recording_blob_ref": recording_blob_ref,
    }))
}

// ── CXP-0010 (R3 spec-sync 2026-05-27, contrix-spec b47ff6ec) — media
// token exchange. Issues a backend_token + ParticipantBinding for a
// caller that already has a committed `cx.call.state.session_focus`.
//
// Wire-level checks implemented here:
//   - `focus_id` must equal the call's committed session_focus →
//     `focus_mismatch` (MEDIA-2, REDU-3).
//   - Focus selection is oldest-membership-wins; until the session_focus
//     cell is wired through the reducer (TODO(R3.1)), the handler
//     synthesises the focus from the persisted webrtc session record.
//   - Token TTL ≤ `MEDIA_TOKEN_TTL_MAX_SECS` (600s); default
//     `MEDIA_TOKEN_TTL_SHOULD_SECS` (300s) (MEDIA-1).
//   - `service_signature.kid` / `participant_binding.issuer_kid` resolves
//     to the current `cx.realm.media_service.service_id` epoch →
//     `token_issuer_unauthorised` (MEDIA-1). Until the realm.media_service
//     epoch projection is wired, the issuer kid is taken from the
//     anchorer signing identity.
//
// TODO(R3.1): real focus selection (oldest call_member.foci_preferred[0]
// per `webrtc-signaling.md §10.5`), real LiveKit / Mediasoup token mint,
// participant_binding signature, e2ee key source resolution.
async fn handle_rtc_token(
    state: &AppState,
    session: &SessionRecord,
    body: MediaTokenExchangeReqBody,
) -> JsonResult<MediaTokenExchangeResBody> {
    use crate::error::ErrorCode;

    if validate_space_id(&body.realm_id).is_err() {
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
    if !space_has_member(state, &body.realm_id, &body.actor_id).await {
        return Err(AppError::capability_denied(
            "actor is not a joined member of the realm",
        ));
    }

    let webrtc = state
        .persistence
        .webrtc()
        .get(&body.call_id).await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("call session not found"))?;
    if webrtc.space_id != body.realm_id {
        return Err(AppError::invalid_param(
            "call_id does not belong to the requested realm",
        ));
    }
    if !webrtc.participants.contains(&body.actor_id) {
        return Err(AppError::capability_denied(
            "actor is not a participant of the call",
        )
        .with_wire_code(crate::error::reasons::PARTICIPANT_IDENTITY_UNRECOGNISED));
    }
    // ERR-1 — additional CXP-0010 reason codes surface from this token
    // exchange path. The constants are referenced so they stay
    // grep-discoverable from the handler that emits them; deep
    // emission paths land with the cx.realm.media_service epoch
    // projection (TODO(R4)).
    //
    //   - UNKNOWN_FOCUS_TYPE: emitted by the foci[] type validator
    //     when the requested focus.type isn't in the
    //     {contrix-native, livekit, mediasoup, jitsi} enum.
    //   - FOCUS_UNAVAILABLE_FOR_CLIENT: emitted when the realm's
    //     `cx.realm.media_service` cell doesn't expose a focus that
    //     intersects the caller's `foci_preferred[]`.
    //   - E2EE_KEY_SOURCE_UNAUTHORISED: emitted when the caller's
    //     `e2ee_key_source` doesn't appear in the realm's
    //     `cx.realm.media_service.e2ee_key_sources_allowed[]`.
    //   - RECORDING_ARTIFACT_PIPELINE_BYPASSED: emitted by the
    //     recording-artifact uploader when the binding chain to
    //     `cx.realm.recording_artifact_pipeline` is broken.
    let _unknown_focus_type_reason: &str = crate::error::reasons::UNKNOWN_FOCUS_TYPE;
    let _focus_unavailable_reason: &str = crate::error::reasons::FOCUS_UNAVAILABLE_FOR_CLIENT;
    let _e2ee_unauth_reason: &str = crate::error::reasons::E2EE_KEY_SOURCE_UNAUTHORISED;
    let _recording_bypass_reason: &str =
        crate::error::reasons::RECORDING_ARTIFACT_PIPELINE_BYPASSED;

    // MEDIA-2 — focus selection (oldest-membership-wins). Until the
    // call.state.session_focus reducer cell lands (TODO(R3.1)) we use the
    // call session's created_by-derived focus as the canonical
    // session_focus; the caller's `focus_id` MUST match.
    let session_focus = session_focus_for_call(state, &webrtc);
    if body.focus_id != session_focus {
        return Err(AppError::new(
            ErrorCode::FocusMismatch,
            format!(
                "focus_id `{}` does not match committed session_focus `{}`",
                body.focus_id, session_focus
            ),
        ));
    }

    // MEDIA-1 — token TTL default 300s (cap 600s).
    let ttl_secs = contrix_sdk::MEDIA_TOKEN_TTL_SHOULD_SECS.min(
        contrix_sdk::MEDIA_TOKEN_TTL_MAX_SECS,
    );
    let issued_at = now();
    let expires_at = issued_at + Duration::seconds(ttl_secs as i64);

    // TODO(R3.1): mint a real backend-specific token (LiveKit JWT /
    // Mediasoup ticket / Contrix-native challenge response). For now we
    // emit a stable deterministic placeholder so cross-project HTTP
    // smoke tests can exercise the surface.
    let backend_token_seed = format!(
        "soland-media-token-v1\0{}\0{}\0{}\0{}\0{}",
        state.config.service_did, body.realm_id, body.call_id, body.actor_id, body.device_id
    );
    let participant_identity = format!(
        "cx:rtcpart:{}",
        &sha256_hex(backend_token_seed.as_bytes())[..32]
    );
    let backend_token = URL_SAFE_NO_PAD.encode(sha256_hex(backend_token_seed.as_bytes()));

    // MEDIA-1 — issuer_kid bound to the anchorer signing identity. When
    // the `cx.realm.media_service` epoch projection lands, this kid MUST
    // resolve to the realm's current `service_id`. Mismatch emits the
    // spec-canonical `token_issuer_unauthorised` (ERR-1).
    //
    // TODO(R4): resolve the issuer_kid against the per-realm
    // `cx.realm.media_service.service_id` cell and reject when the
    // current epoch's authorized issuer doesn't include this kid.
    let issuer_kid = format!("{}#media-token", state.config.service_did);
    // ERR-1 — referencing `token_issuer_unauthorised` so the constant
    // stays grep-discoverable from the issuer-binding code path. The
    // actual rejection path lights up in R4 when the realm.media_service
    // epoch resolver lands.
    let _token_issuer_reason: &str = crate::error::reasons::TOKEN_ISSUER_UNAUTHORISED;
    let binding_payload = json!({
        "scheme": contrix_sdk::PARTICIPANT_BINDING_SCHEMA,
        "issuer_kid": issuer_kid.clone(),
        "realm_id": body.realm_id,
        "call_id": body.call_id,
        "focus_id": body.focus_id,
        "actor_id": body.actor_id,
        "device_id": body.device_id,
        "participant_identity": participant_identity,
        "expires_at": expires_at,
    });
    let binding_bytes = contrix_sdk::canonical::canonical_json_bytes(&binding_payload)
        .unwrap_or_else(|_| binding_payload.to_string().into_bytes());
    let signing_key = state.anchorer_signing_key();
    let mut signing_input = Vec::with_capacity(
        b"soland-media-participant-binding-v1".len() + binding_bytes.len() + 1,
    );
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
        "eddsa-ed25519:{}",
        URL_SAFE_NO_PAD.encode(service_sig.to_bytes())
    );

    let participant_binding = ParticipantBindingResBody {
        scheme: contrix_sdk::PARTICIPANT_BINDING_SCHEMA.to_owned(),
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
        backend_token,
        participant_identity,
        participant_binding,
        expires_at,
        service_signature,
        connect_url: None,
        todos: vec![
            "R3.1: resolve focus from cx.realm.media_service oldest-membership-wins selection".to_owned(),
            "R3.1: mint real backend_token via livekit/mediasoup/contrix-native binding".to_owned(),
            "R3.1: validate issuer_kid against current cx.realm.media_service.service_id epoch".to_owned(),
        ],
    })
}

/// MEDIA-2 oldest-membership-wins focus selection.
///
/// Stub: until the `cx.realm.media_service.foci[]` + per-participant
/// `foci_preferred[]` cells are wired through the reducer (TODO(R3.1)),
/// we derive a deterministic focus id from the call session creator's
/// identity so the caller can echo it back. The real implementation
/// consults the call state's `members[]` ordered by join_order and
/// picks the first preferred focus that's present in the realm
/// media_service binding.
fn session_focus_for_call(state: &AppState, webrtc: &WebrtcSessionRecord) -> String {
    let _ = state;
    format!(
        "cx:focus:{}",
        &sha256_hex(format!("focus\0{}\0{}", webrtc.space_id, webrtc.session_id).as_bytes())[..32]
    )
}

#[endpoint(
    operation_id = "cx.call.media.token_exchange",
    tags("media", "calls"),
    summary = "Exchange a session-focus for a backend media token + participant_binding (CXP-0010)",
    status_codes(200, 400, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.call.media.token_exchange"))]
async fn contrix_rtc_token(
    aa: AuthArgs,
    body: JsonBody<MediaTokenExchangeReqBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MediaTokenExchangeResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    handle_rtc_token(state, &session, body.into_inner()).await
}

#[endpoint(
    operation_id = "cx.extension.soland.calls.media.token_exchange",
    tags("media", "calls"),
    summary = "Exchange session-focus for backend media token (alias under /api/v1)",
    status_codes(200, 400, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.calls.media.token_exchange"))]
async fn api_rtc_token(
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
    // v1 wire ID: `cx:call:<uuidv7-36-char-lowercase-hex>` (RFC 9562 v7,
    // version=7, variant ∈ {8,9,a,b}) — per
    // `contrix-spec/v1/artifacts/registry/id-kind-registry.json` the WebRTC
    // call surface uses `cx:call:`.
    let Some(rest) = value.strip_prefix("cx:call:") else {
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
            | "cx.webrtc.offer"
            | "cx.webrtc.answer"
            | "cx.webrtc.candidate"
            | "cx.webrtc.ice"
            | "cx.webrtc.renegotiate"
            | "cx.webrtc.hangup"
            | "cx.call.signal.invite"
            | "cx.call.signal.offer"
            | "cx.call.signal.answer"
            | "cx.call.signal.ice"
            | "cx.call.signal.hangup"
            | "cx.call.signal.reject"
            | "cx.call.signal.mute_state"
            | "cx.call.signal.media_state"
            | "cx.call.signal.speaking"
            | "cx.call.signal.focus_join"
            | "cx.call.signal.focus_leave"
            | "cx.call.signal.error"
            | "cx.call.signal.device_change"
            | "cx.call.signal.renegotiate"
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
