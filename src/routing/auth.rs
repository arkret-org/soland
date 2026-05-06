//! Auth + session handlers and the session-validation helpers they rely on.
//!
//! Surfaces:
//! - `POST /api/v1/auth/dev-login` — dev-mode bearer issue
//! - `POST /api/v1/auth/session-grant/exchange` — coauth bridge (scaffold; see
//!   the `TODO(session-grant-exchange)` annotation below and Stream-F-9 in
//!   `_todos.md`)
//! - `POST /api/v1/auth/logout` — revoke the bearer + the bound device
//!
//! Internal helpers exported for the rest of `crate::routing`:
//! - `auth_or_render` — the standard "extract session or 401" wrapper used by
//!   nearly every protected handler
//! - `authenticated_session` — the underlying session-lookup pipeline
//! - `is_device_revoked` / `revoke_device_record` — device-revocation gates
//!   (also used by `keys_query` to mask revoked devices and by other auth
//!   adjacent paths)
//! - `session_token_hash` / `token_for` — token derivation primitives

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Duration;
use salvo::oapi::extract::JsonBody;
use salvo::{http::StatusCode, prelude::*};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    JsonResult,
    error::AppError,
    ids, json_ok,
    state::{AppState, DeviceInventoryRecord, SessionRecord},
    wire::{
        DevLoginRequest, DevLoginResponse, LogoutResponse, SessionGrantExchangeRequest,
    },
};

use super::{
    append_audit_log, bearer_token, device_inventory_to_json, now, render_error,
    validate_device_id, validate_did,
};

#[endpoint(
    operation_id = "cx.auth.dev_login",
    tags("auth"),
    summary = "Development bearer-token login",
)]
pub async fn dev_login(
    depot: &mut Depot,
    body: JsonBody<DevLoginRequest>,
) -> JsonResult<DevLoginResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    if !state.config.development_mode {
        return Err(AppError::not_found("endpoint not available"));
    }
    let body = body.into_inner();
    if validate_did(&body.actor).is_err() || validate_device_id(&body.device_id).is_err() {
        return Err(AppError::invalid_param(
            "actor must be a DID and device_id is required",
        ));
    }
    let account = state
        .persistence
        .accounts()
        .get(&body.actor)
        .map_err(|error| AppError::internal(error.to_string()))?;
    if account.is_none() {
        return Err(AppError::not_found("account is not registered"));
    }

    let expires_at = now() + Duration::hours(12);
    let token = token_for(&body.actor, &body.device_id, expires_at.timestamp_millis());
    let token_hash = session_token_hash(&token, &state.config.service_did);
    let session = SessionRecord {
        token_hash,
        actor: body.actor.clone(),
        device_id: body.device_id.clone(),
        audience: state.config.service_did.clone(),
        expires_at,
        created_at: now(),
        revoked_at: None,
    };
    state
        .persistence
        .sessions()
        .put(&session)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let seen_at = now();
    let device_payload = json!({
        "device_id": body.device_id.clone(),
        "display_name": body.display_name.clone(),
        "verification": "unverified",
        "last_seen_at": seen_at
    });
    let device = DeviceInventoryRecord {
        actor: body.actor.clone(),
        device_id: body.device_id.clone(),
        display_name: body.display_name.clone(),
        verification_state: "unverified".to_owned(),
        payload: device_payload,
        created_at: seen_at,
        updated_at: seen_at,
        revoked_at: None,
    };
    state
        .persistence
        .devices()
        .put(&device)
        .map_err(|error| AppError::internal(error.to_string()))?;
    state
        .sessions
        .lock()
        .expect("sessions lock")
        .insert(session.token_hash.clone(), session.clone());
    state
        .devices
        .lock()
        .expect("devices lock")
        .entry(body.actor.clone())
        .or_default()
        .insert(body.device_id.clone(), device_inventory_to_json(&device));
    append_audit_log(
        state,
        Some(&body.actor),
        "auth.dev_login",
        json!({"device_id": body.device_id.clone()}),
        "accepted",
    );

    json_ok(DevLoginResponse {
        access_token: token,
        token_type: "Bearer".to_owned(),
        actor: body.actor,
        device_id: body.device_id,
        expires_at,
    })
}

#[endpoint(
    operation_id = "cx.auth.exchange_session_grant",
    tags("auth"),
    summary = "Exchange a coauth session-grant for a principal-server bearer session",
)]
pub async fn exchange_session_grant(
    depot: &mut Depot,
    body: JsonBody<SessionGrantExchangeRequest>,
) -> JsonResult<DevLoginResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    if body.grant_jwt.trim().is_empty()
        || validate_did(&body.principal_did).is_err()
        || validate_device_id(&body.device_id).is_err()
    {
        return Err(AppError::invalid_param(
            "grant_jwt, principal_did, and device_id are required",
        ));
    }
    let account = state
        .persistence
        .accounts()
        .get(&body.principal_did)
        .map_err(|error| AppError::internal(error.to_string()))?;
    if account.is_none() {
        return Err(AppError::not_found("account is not registered"));
    }

    // TODO(session-grant-exchange): replace this local bridge with real coauth
    // session-grant introspection, audience checks, and session-public-key
    // proof verification before minting a principal-server bearer session.
    let expires_at = now() + Duration::hours(12);
    let token = token_for(
        &body.principal_did,
        &body.device_id,
        expires_at.timestamp_millis(),
    );
    let token_hash = session_token_hash(&token, &state.config.service_did);
    let session = SessionRecord {
        token_hash,
        actor: body.principal_did.clone(),
        device_id: body.device_id.clone(),
        audience: state.config.service_did.clone(),
        expires_at,
        created_at: now(),
        revoked_at: None,
    };
    state
        .persistence
        .sessions()
        .put(&session)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let seen_at = now();
    let device_payload = json!({
        "device_id": body.device_id.clone(),
        "display_name": body.display_name.clone(),
        "verification": "unverified",
        "last_seen_at": seen_at,
        "session_grant_bridge": true,
    });
    let device = DeviceInventoryRecord {
        actor: body.principal_did.clone(),
        device_id: body.device_id.clone(),
        display_name: body.display_name.clone(),
        verification_state: "unverified".to_owned(),
        payload: device_payload,
        created_at: seen_at,
        updated_at: seen_at,
        revoked_at: None,
    };
    state
        .persistence
        .devices()
        .put(&device)
        .map_err(|error| AppError::internal(error.to_string()))?;
    state
        .sessions
        .lock()
        .expect("sessions lock")
        .insert(session.token_hash.clone(), session.clone());
    state
        .devices
        .lock()
        .expect("devices lock")
        .entry(body.principal_did.clone())
        .or_default()
        .insert(body.device_id.clone(), device_inventory_to_json(&device));
    append_audit_log(
        state,
        Some(&body.principal_did),
        "auth.session_grant_exchange",
        json!({
            "device_id": body.device_id.clone(),
            "grant_bridge": true,
        }),
        "accepted",
    );

    json_ok(DevLoginResponse {
        access_token: token,
        token_type: "Bearer".to_owned(),
        actor: body.principal_did,
        device_id: body.device_id,
        expires_at,
    })
}

#[endpoint(
    operation_id = "cx.auth.logout",
    tags("auth"),
    summary = "Revoke the current bearer session and bound device",
)]
pub async fn logout(
    aa: super::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<LogoutResponse> {
    let _ = &aa; // header presence registered with the OpenAPI doc
    let state = depot.obtain::<AppState>().expect("state injected");
    let token = bearer_token(req)
        .map(str::to_owned)
        .ok_or_else(|| AppError::unauthenticated("missing bearer token"))?;
    let token_hash = session_token_hash(&token, &state.config.service_did);
    let revoked_session = match state
        .persistence
        .sessions()
        .get(&token_hash)
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        Some(mut session) if session.revoked_at.is_none() => {
            session.revoked_at = Some(now());
            state
                .persistence
                .sessions()
                .put(&session)
                .map_err(|error| AppError::internal(error.to_string()))?;
            state
                .sessions
                .lock()
                .expect("sessions lock")
                .insert(token_hash.clone(), session.clone());
            Some(session)
        }
        _ => None,
    };
    let revoked = revoked_session.is_some();
    if let Some(session) = revoked_session {
        revoke_device_record(state, &session.actor, &session.device_id)
            .map_err(AppError::internal)?;
        append_audit_log(
            state,
            Some(&session.actor),
            "auth.logout",
            json!({"device_id": session.device_id, "revoked_at": session.revoked_at}),
            "accepted",
        );
        let mut queue = state.device_messages.lock().expect("device message lock");
        queue.retain(|message| {
            !(message.recipient == session.actor && message.device_id == session.device_id)
        });
    }
    json_ok(LogoutResponse { ok: true, revoked })
}

// ── Session validation pipeline ─────────────────────────────────────────────

/// Standard "extract authenticated session or render 401" wrapper used by
/// nearly every protected handler. Returns `None` after rendering an error.
pub fn auth_or_render(
    state: &AppState,
    req: &Request,
    res: &mut Response,
) -> Option<SessionRecord> {
    match authenticated_session(state, req) {
        Ok(session) => Some(session),
        Err((status, code, message)) => {
            render_error(res, status, code, message);
            None
        }
    }
}

/// Look up the bearer-bound session and validate every gate (audience match,
/// not revoked, device not revoked, not expired, no auth material in query
/// strings). Returns the structured rejection on failure.
pub fn authenticated_session(
    state: &AppState,
    req: &Request,
) -> Result<SessionRecord, (StatusCode, &'static str, &'static str)> {
    if req.uri().query().is_some_and(|query| {
        query.contains("access_token=") || query.contains("auth=") || query.contains("token=")
    }) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "auth material in query strings is not allowed",
        ));
    }
    let token = bearer_token(req).ok_or((
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
        "missing bearer token",
    ))?;
    let token_hash = session_token_hash(token, &state.config.service_did);
    let session = state
        .persistence
        .sessions()
        .get(&token_hash)
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "persistence_error",
                "session store unavailable",
            )
        })?
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "invalid bearer token",
        ))?;
    if session.audience != state.config.service_did {
        return Err((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "session audience does not match this service",
        ));
    }
    if session.revoked_at.is_some() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "session revoked",
        ));
    }
    if is_device_revoked(state, &session.actor, &session.device_id) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "device revoked",
        ));
    }
    if session.expires_at <= now() {
        return Err((StatusCode::UNAUTHORIZED, "auth_expired", "session expired"));
    }
    Ok(session)
}

/// Persist + cache that the device is revoked. Used by `logout` and by the
/// device-management handlers in mod.rs.
pub fn revoke_device_record(
    state: &AppState,
    actor: &str,
    device_id: &str,
) -> Result<(), String> {
    let revoked_at = now();
    let mut record = match state.persistence.devices().get(actor, device_id) {
        Ok(record) => record,
        Err(error) => {
            return Err(error.to_string());
        }
    }
    .or_else(|| {
        state
            .devices
            .lock()
            .expect("devices lock")
            .get(actor)
            .and_then(|devices| {
                devices.get(device_id).and_then(|json| {
                    Some(DeviceInventoryRecord {
                        actor: actor.to_owned(),
                        device_id: device_id.to_owned(),
                        display_name: json
                            .get("display_name")
                            .and_then(Value::as_str)
                            .map(ToString::to_string),
                        verification_state: json
                            .get("verification")
                            .and_then(Value::as_str)
                            .unwrap_or("unverified")
                            .to_owned(),
                        payload: json
                            .get("payload")
                            .cloned()
                            .unwrap_or_else(|| json!({"device_id": device_id})),
                        created_at: revoked_at,
                        updated_at: revoked_at,
                        revoked_at: Some(revoked_at),
                    })
                })
            })
    })
    .unwrap_or_else(|| DeviceInventoryRecord {
        actor: actor.to_owned(),
        device_id: device_id.to_owned(),
        display_name: None,
        verification_state: "unverified".to_owned(),
        payload: json!({"device_id": device_id}),
        created_at: revoked_at,
        updated_at: revoked_at,
        revoked_at: Some(revoked_at),
    });
    record.revoked_at = Some(revoked_at);
    record.updated_at = revoked_at;
    state
        .persistence
        .devices()
        .put(&record)
        .map_err(|error| error.to_string())?;
    state
        .devices
        .lock()
        .expect("devices lock")
        .entry(actor.to_owned())
        .or_default()
        .insert(device_id.to_owned(), device_inventory_to_json(&record));
    Ok(())
}

/// Returns true if the in-memory or persistent device record has a
/// `revoked_at` timestamp, or if the device cannot be located at all.
pub fn is_device_revoked(state: &AppState, actor: &str, device_id: &str) -> bool {
    if let Some(actor_devices) = state.devices.lock().expect("devices lock").get(actor) {
        if let Some(device) = actor_devices.get(device_id) {
            return !device.get("revoked_at").is_none_or(Value::is_null);
        }
    }
    match state.persistence.devices().get(actor, device_id) {
        Ok(Some(record)) => record.revoked_at.is_some(),
        Ok(None) => match state.persistence.devices().list_for_actor(actor) {
            Ok(devices) => !devices.iter().any(|record| record.device_id == device_id),
            Err(_) => true,
        },
        Err(_) => true,
    }
}

// ── Token derivation ────────────────────────────────────────────────────────

/// Derive a single-use bearer token. The token is opaque to the client; what
/// the server stores is its `session_token_hash`.
pub fn token_for(actor: &str, device_id: &str, expires_ms: i64) -> String {
    let nonce = ids::generate("session");
    let mut hasher = Sha256::new();
    hasher.update(actor.as_bytes());
    hasher.update(b":");
    hasher.update(device_id.as_bytes());
    hasher.update(b":");
    hasher.update(expires_ms.to_string().as_bytes());
    hasher.update(b":");
    hasher.update(nonce.as_bytes());
    hasher.update(b":soland-dev-session");
    format!("sx_{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

/// Service-DID bound hash of a bearer token, used as the persistence key so
/// cross-service tokens can never collide.
pub fn session_token_hash(token: &str, audience: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(audience.as_bytes());
    hasher.update(b":");
    hasher.update(token.as_bytes());
    format!("sha256:{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
}
