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
use crate::error::AppError;
use crate::ids;
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::{AppState, WebrtcSessionRecord, WebrtcSignalRecord};
use crate::wire::{
    CreateWebrtcSessionRequest, CreateWebrtcSessionResponse, OkResBody, WebrtcSignalRequest,
    WebrtcSignalResponse, WebrtcSignalsResponse,
};

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("webrtc/sessions").post(create_webrtc_session))
        .push(
            Router::with_path("webrtc/sessions/{session_id}/signals")
                .post(put_webrtc_signal)
                .get(get_webrtc_signals),
        )
        .push(Router::with_path("webrtc/sessions/{session_id}").delete(delete_webrtc_session))
}

pub(super) fn contrix_router() -> Router {
    Router::with_path("contrix/v1/ice-config").post(ice_config)
}

#[endpoint(
    operation_id = "cx.media.ice_config",
    tags("media"),
    summary = "Issue signed ICE config"
)]
#[tracing::instrument(skip_all, fields(op = "cx.media.ice_config"))]
async fn ice_config(
    aa: AuthArgs,
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    let realm_id = body
        .get("realm_id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::missing_param("realm_id is required"))?;
    let call_id = body
        .get("call_id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::missing_param("call_id is required"))?;
    let actor_id = body
        .get("actor_id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::missing_param("actor_id is required"))?;
    let device_id = body
        .get("device_id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::missing_param("device_id is required"))?;

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
    if !space_has_member(state, realm_id, actor_id) {
        return Err(AppError::capability_denied(
            "actor is not a joined member of the realm",
        ));
    }

    let issued_at = now();
    let ttl_seconds = 300;
    let refresh_lead_seconds = 75;
    let expires_at = issued_at + Duration::seconds(ttl_seconds);
    let mut response = json!({
        "realm_id": realm_id,
        "call_id": call_id,
        "actor_id": actor_id,
        "device_id": device_id,
        "ice_servers": [{"urls": ["stun:stun.l.google.com:19302"]}],
        "ttl_seconds": ttl_seconds,
        "refresh_lead_seconds": refresh_lead_seconds,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "force_turn": false,
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
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    if validate_space_id(&body.space_id).is_err() {
        return Err(AppError::invalid_param("invalid space_id"));
    }
    if !space_has_member(state, &body.space_id, &session.actor) {
        return Err(AppError::capability_denied(
            "actor is not a joined member of the space",
        ));
    }

    let mut participants = BTreeSet::new();
    participants.insert(session.actor.clone());
    for participant in body.participants {
        if validate_did(&participant).is_err() {
            return Err(AppError::invalid_param("invalid participant did"));
        }
        if !space_has_member(state, &body.space_id, &participant) {
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
        expires_at,
        created_at,
        next_seq: 1,
        signals: Vec::new(),
    };
    state
        .persistence
        .webrtc()
        .put(record)
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(CreateWebrtcSessionResponse {
        session_id,
        space_id: body.space_id,
        participants: participant_list,
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
    let session = aa.authenticated_session(state, req)?;
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
        let Some(record) = state.persistence.webrtc().get(&session_id).ok().flatten() else {
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
        .append_signal(&session_id, &session.actor, builder)
    {
        Ok(appended) => json_ok(WebrtcSignalResponse {
            ok: true,
            session_id: session_id.clone(),
            seq: appended.seq,
            next_cursor: appended.seq.to_string(),
        }),
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
    let session = aa.authenticated_session(state, req)?;
    let session_id = session_id.into_inner();
    if !is_valid_webrtc_session_id(&session_id) {
        return Err(AppError::invalid_param("invalid webrtc session id"));
    }
    let since = since.into_inner().unwrap_or(0);
    let limit = limit.into_inner().unwrap_or(50).clamp(1, 100);

    prune_expired_webrtc_sessions(state);
    let Some(record) = state.persistence.webrtc().get(&session_id).ok().flatten() else {
        return Err(AppError::not_found("session not found"));
    };
    if !record.participants.contains(&session.actor) {
        return Err(AppError::capability_denied(
            "actor is not a participant of the webrtc session",
        ));
    }
    let mut events = record
        .signals
        .iter()
        .filter(|signal| signal.seq > since)
        .map(webrtc_signal_to_json)
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
    let session = aa.authenticated_session(state, req)?;
    let session_id = session_id.into_inner();
    if !is_valid_webrtc_session_id(&session_id) {
        return Err(AppError::invalid_param("invalid webrtc session id"));
    }

    prune_expired_webrtc_sessions(state);
    let Some(record) = state.persistence.webrtc().get(&session_id).ok().flatten() else {
        return Err(AppError::not_found("session not found"));
    };
    if !record.participants.contains(&session.actor) {
        return Err(AppError::capability_denied(
            "actor is not a participant of the webrtc session",
        ));
    }
    let _ = state.persistence.webrtc().delete(&session_id);
    json_ok(OkResBody { ok: true })
}

fn prune_expired_webrtc_sessions(state: &AppState) {
    if let Err(error) = state.persistence.webrtc().prune_expired() {
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
        "offer"
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

fn webrtc_signal_to_json(signal: &WebrtcSignalRecord) -> Value {
    json!({
        "seq": signal.seq,
        "sender": signal.sender,
        "type": signal.message_type,
        "payload": signal.payload,
        "proofs": signal.proofs,
        "device_proof": signal.proofs.first().cloned().unwrap_or(Value::Null),
        "created_at": signal.created_at,
    })
}
