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
use chrono::{DateTime, Duration, Utc};
use salvo::oapi::extract::JsonBody;
use salvo::{http::StatusCode, prelude::*};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    JsonResult,
    error::{AppError, ErrorCode},
    ids, json_ok,
    state::{AppState, DeviceInventoryRecord, SessionRecord},
    wire::{
        DevLoginRequest, DevLoginResponse, LogoutResponse, SessionGrantExchangeRequest,
        SessionGrantIntrospectionProof,
    },
};

use super::{append_audit_log, bearer_token, now, render_error, validate_device_id, validate_did};

const PRINCIPAL_SESSION_BIND_SCOPE: &str = "urn:contrix:principal-server:session.bind";

pub(super) fn router() -> Router {
    Router::with_path("auth")
        .push(Router::with_path("bridge/describe").get(super::describe::auth_bridge_describe))
        .push(Router::with_path("dev-login").post(dev_login))
        .push(Router::with_path("session-grant/exchange").post(exchange_session_grant))
        .push(Router::with_path("logout").post(logout))
}

#[endpoint(
    operation_id = "cx.auth.dev_login",
    tags("auth"),
    summary = "Development bearer-token login"
)]
async fn dev_login(
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
    summary = "Exchange a coauth session-grant for a principal-server bearer session"
)]
async fn exchange_session_grant(
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

    let grant = validate_session_grant_binding(
        state,
        SessionGrantValidationInput {
            grant_jwt: body.grant_jwt.as_str(),
            principal_did: body.principal_did.as_str(),
            device_id: body.device_id.as_str(),
            proof: body.introspection_proof.as_ref(),
        },
    )
    .await?;
    let expires_at = grant
        .as_ref()
        .map(|grant| grant.expires_at)
        .unwrap_or_else(|| now() + Duration::hours(12));
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
    append_audit_log(
        state,
        Some(&body.principal_did),
        "auth.session_grant_exchange",
        json!({
            "device_id": body.device_id.clone(),
            "grant_bridge": true,
            "coauth_introspection": grant.is_some(),
            "one_time_use_consumed": grant.as_ref().map(|grant| grant.one_time_use_consumed).unwrap_or(false),
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

#[derive(Debug, Serialize)]
struct SessionGrantIntrospectionRequest<'a> {
    grant_jwt: &'a str,
    audience: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<&'a SessionGrantIntrospectionProof>,
}

#[derive(Debug, Deserialize)]
struct SessionGrantIntrospectionResponse {
    active: bool,
    status: String,
    #[allow(dead_code)]
    proof_required: bool,
    one_time_use_consumed: bool,
    grant: Option<SessionGrantIntrospectionGrant>,
}

#[derive(Debug, Deserialize)]
struct SessionGrantIntrospectionGrant {
    subject: String,
    device_id: Option<String>,
    audience: String,
    scopes: Vec<String>,
    expires_at: DateTime<Utc>,
}

#[derive(Debug)]
pub(crate) struct SessionGrantValidationInput<'a> {
    pub grant_jwt: &'a str,
    pub principal_did: &'a str,
    pub device_id: &'a str,
    pub proof: Option<&'a SessionGrantIntrospectionProof>,
}

#[derive(Debug)]
pub(crate) struct ValidatedSessionGrant {
    pub expires_at: DateTime<Utc>,
    pub one_time_use_consumed: bool,
}

pub(crate) async fn validate_session_grant_binding(
    state: &AppState,
    input: SessionGrantValidationInput<'_>,
) -> Result<Option<ValidatedSessionGrant>, AppError> {
    let Some(introspection_url) = state.config.session_grant_introspection_url.as_deref() else {
        if state.config.development_mode {
            return Ok(None);
        }
        return Err(AppError::unsupported_feature(
            "session grant exchange requires SOLAND_SESSION_GRANT_INTROSPECTION_URL outside development mode",
        ));
    };
    let bearer = state
        .config
        .session_grant_introspection_bearer
        .as_deref()
        .ok_or_else(|| {
            AppError::unsupported_feature(
                "session grant exchange requires SOLAND_SESSION_GRANT_INTROSPECTION_BEARER",
            )
        })?;
    let request = SessionGrantIntrospectionRequest {
        grant_jwt: input.grant_jwt,
        audience: state.config.service_did.as_str(),
        proof: input.proof,
    };
    let response = reqwest::Client::new()
        .post(introspection_url)
        .bearer_auth(bearer)
        .json(&request)
        .send()
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::TemporarilyUnavailable,
                format!("session grant introspection request failed: {error}"),
            )
        })?;
    if !response.status().is_success() {
        return Err(AppError::capability_denied(format!(
            "session grant introspection was rejected by coauth: {}",
            response.status()
        )));
    }
    let response = response
        .json::<SessionGrantIntrospectionResponse>()
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::TemporarilyUnavailable,
                format!("invalid session grant introspection response: {error}"),
            )
        })?;
    if !response.active || response.status != "active" {
        return Err(AppError::capability_denied(format!(
            "session grant is not active: {}",
            response.status
        )));
    }
    let grant = response.grant.ok_or_else(|| {
        AppError::capability_denied("session grant introspection omitted grant metadata")
    })?;
    if grant.audience != state.config.service_did {
        return Err(AppError::capability_denied(
            "session grant audience does not match this principal server",
        ));
    }
    if grant.subject != input.principal_did {
        return Err(AppError::capability_denied(
            "session grant subject does not match principal_did",
        ));
    }
    if let Some(device_id) = grant.device_id.as_deref()
        && device_id != input.device_id
    {
        return Err(AppError::capability_denied(
            "session grant device does not match device_id",
        ));
    }
    if !grant
        .scopes
        .iter()
        .any(|scope| scope == PRINCIPAL_SESSION_BIND_SCOPE)
    {
        return Err(AppError::capability_denied(
            "session grant is missing principal-server session.bind scope",
        ));
    }
    if grant.expires_at <= now() {
        return Err(AppError::unauthenticated("session grant has expired"));
    }

    Ok(Some(ValidatedSessionGrant {
        expires_at: grant.expires_at,
        one_time_use_consumed: response.one_time_use_consumed,
    }))
}

#[endpoint(
    operation_id = "cx.auth.logout",
    tags("auth"),
    summary = "Revoke the current bearer session and bound device"
)]
async fn logout(
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
        let _ = state
            .persistence
            .device_messages()
            .purge(&session.actor, &session.device_id);
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

/// Persist that the device is revoked. Used by `logout` and by the
/// device-management handlers in mod.rs.
pub fn revoke_device_record(state: &AppState, actor: &str, device_id: &str) -> Result<(), String> {
    let revoked_at = now();
    let mut record = state
        .persistence
        .devices()
        .get(actor, device_id)
        .map_err(|error| error.to_string())?
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
    Ok(())
}

/// Returns true if the persistent device record has a `revoked_at` timestamp,
/// or if the device cannot be located at all.
pub fn is_device_revoked(state: &AppState, actor: &str, device_id: &str) -> bool {
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
