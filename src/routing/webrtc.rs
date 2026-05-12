//! WebRTC session + signaling handlers.
//!
//! Surfaces:
//! - `POST /api/v1/contrix/v1/ice-config` (TURN / STUN list — currently empty)
//! - `POST /api/v1/webrtc/sessions` create
//! - `PUT/GET /api/v1/webrtc/sessions/{session_id}/signals`
//! - `DELETE /api/v1/webrtc/sessions/{session_id}` close
//!
//! Sessions are persisted through `state.persistence.webrtc()`. Tier 6-P-4
//! covers the durable Pg backing + TURN policy + spec B-14 (no DID in TURN
//! username / push payload).

use std::collections::BTreeSet;

use chrono::Duration;
use salvo::{http::StatusCode, prelude::*};
use serde_json::{Value, json};

use crate::{
    ids,
    state::{AppState, WebrtcSessionRecord, WebrtcSignalRecord},
    wire::{
        CreateWebrtcSessionRequest, CreateWebrtcSessionResponse, OkResponse, WebrtcSignalRequest,
        WebrtcSignalResponse, WebrtcSignalsResponse,
    },
};

use super::{
    auth_or_render, now, query_param, render_error, space_has_member,
    validate_canonical_json_value, validate_did, validate_space_id,
};

#[endpoint]
pub async fn ice_config(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    res.render(Json(json!({
        "service_did": state.config.service_did.clone(),
        "ttl_seconds": 300,
        "ice_servers": [],
        "issued_at": now(),
    })));
}

#[endpoint]
pub async fn create_webrtc_session(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<CreateWebrtcSessionRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid webrtc session request",
            );
            return;
        }
    };
    if validate_space_id(&body.space_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    }
    if !space_has_member(state, &body.space_id, &session.actor) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "actor is not a joined member of the space",
        );
        return;
    }

    let mut participants = BTreeSet::new();
    participants.insert(session.actor.clone());
    for participant in body.participants {
        if validate_did(&participant).is_err() {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "invalid participant did",
            );
            return;
        }
        if !space_has_member(state, &body.space_id, &participant) {
            render_error(
                res,
                StatusCode::FORBIDDEN,
                "capability_denied",
                "participant is not a joined member of the space",
            );
            return;
        }
        participants.insert(participant);
    }

    prune_expired_webrtc_sessions(state);
    let created_at = now();
    let ttl_ms = body.ttl_ms.unwrap_or(600_000).clamp(60_000, 3_600_000);
    let expires_at = created_at + Duration::milliseconds(ttl_ms as i64);
    let session_id = ids::generate("webrtc");
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
    if let Err(error) = state.persistence.webrtc().put(record) {
        tracing::error!(%error, "failed to persist webrtc session");
        render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "persistence_error",
            "webrtc session store unavailable",
        );
        return;
    }
    res.render(Json(CreateWebrtcSessionResponse {
        session_id,
        space_id: body.space_id,
        participants: participant_list,
        expires_at,
        created_at,
    }));
}

#[endpoint]
pub async fn put_webrtc_signal(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(session_id) = req.param::<String>("session_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "missing webrtc session id",
        );
        return;
    };
    if !is_valid_webrtc_session_id(&session_id) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid webrtc session id",
        );
        return;
    }
    let body = match req.parse_json::<WebrtcSignalRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid webrtc signal request",
            );
            return;
        }
    };
    if !is_supported_webrtc_signal_type(&body.message_type) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "unsupported webrtc signal type",
        );
        return;
    }
    if let Err(message) = validate_canonical_json_value(&body.payload) {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
        return;
    }
    if !webrtc_signal_proof_matches_actor(&body.proofs, &session.actor) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "webrtc signal requires a proof bound to the actor",
        );
        return;
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
        Ok(appended) => res.render(Json(WebrtcSignalResponse {
            ok: true,
            session_id: session_id.clone(),
            seq: appended.seq,
            next_cursor: appended.seq.to_string(),
        })),
        Err(crate::persistence::PersistenceError::NotFound(_)) => {
            render_error(res, StatusCode::NOT_FOUND, "not_found", "session not found");
        }
        Err(crate::persistence::PersistenceError::Conflict(_)) => {
            render_error(
                res,
                StatusCode::FORBIDDEN,
                "capability_denied",
                "actor is not a participant of the webrtc session",
            );
        }
        Err(error) => {
            tracing::error!(%error, "failed to append webrtc signal");
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "persistence_error",
                "webrtc signal store unavailable",
            );
        }
    }
}

#[endpoint]
pub async fn get_webrtc_signals(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(session_id) = req.param::<String>("session_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "missing webrtc session id",
        );
        return;
    };
    if !is_valid_webrtc_session_id(&session_id) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid webrtc session id",
        );
        return;
    }
    let since = query_param(req, "since")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let limit = query_param(req, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(50)
        .clamp(1, 100);

    prune_expired_webrtc_sessions(state);
    let Some(record) = state.persistence.webrtc().get(&session_id).ok().flatten() else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "session not found");
        return;
    };
    if !record.participants.contains(&session.actor) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "actor is not a participant of the webrtc session",
        );
        return;
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
    res.render(Json(WebrtcSignalsResponse {
        session_id,
        events,
        next_cursor,
        limited,
    }));
}

#[endpoint]
pub async fn delete_webrtc_session(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(session_id) = req.param::<String>("session_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "missing webrtc session id",
        );
        return;
    };
    if !is_valid_webrtc_session_id(&session_id) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid webrtc session id",
        );
        return;
    }

    prune_expired_webrtc_sessions(state);
    let Some(record) = state.persistence.webrtc().get(&session_id).ok().flatten() else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "session not found");
        return;
    };
    if !record.participants.contains(&session.actor) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "actor is not a participant of the webrtc session",
        );
        return;
    }
    let _ = state.persistence.webrtc().delete(&session_id);
    res.render(Json(OkResponse { ok: true }));
}

fn prune_expired_webrtc_sessions(state: &AppState) {
    if let Err(error) = state.persistence.webrtc().prune_expired() {
        tracing::warn!(%error, "failed to prune expired webrtc sessions");
    }
}

fn is_valid_webrtc_session_id(value: &str) -> bool {
    // v1 wire ID: `cx:<kind>:<uuidv7-36-char-lowercase-hex>`
    // (RFC 9562 v7, version=7, variant ∈ {8,9,a,b}). See
    // contrix-spec/spec/v1/zh/conformance/encoding.md §4.
    let Some(rest) = value.strip_prefix("cx:webrtc:") else {
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
            | "candidate"
            | "ice"
            | "renegotiate"
            | "hangup"
            | "cx.webrtc.offer"
            | "cx.webrtc.answer"
            | "cx.webrtc.candidate"
            | "cx.webrtc.ice"
            | "cx.webrtc.renegotiate"
            | "cx.webrtc.hangup"
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
        "created_at": signal.created_at,
    })
}
