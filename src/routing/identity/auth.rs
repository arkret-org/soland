//! Auth + session handlers and the session-validation helpers they rely on.
//!
//! Surfaces:
//! - `POST /api/v1/auth/dev-login` — dev-mode bearer issue
//! - direct OAuth bearer authentication — Matrix/Palpo-style validation through
//!   coauth `/oauth2/introspect`
//! - `POST /api/v1/auth/session-grant/exchange` — legacy coauth session-grant bridge
//! - `POST /api/v1/auth/logout` — revoke the bearer + the bound device
//!
//! Internal helpers exported for the rest of `crate::routing`:
//! - `auth_or_render` — the standard "extract session or 401" wrapper used by nearly every
//!   protected handler
//! - `authenticated_session` — the underlying session-lookup pipeline
//! - `is_device_revoked` / `revoke_device_record` — device-revocation gates (also used by
//!   `keys_query` to mask revoked devices and by other auth adjacent paths)
//! - `session_token_hash` / `token_for` — token derivation primitives

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use salvo::http::StatusCode;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    append_audit_log, bearer_token, handle_for_did, is_valid_handle, normalize_handle, now,
    render_error, validate_device_id, validate_did,
};
use crate::error::{AppError, ErrorCode};
use crate::state::{AccountRecord, AppState, DeviceInventoryRecord, SessionRecord};
use crate::wire::{
    DevLoginRequest, DevLoginResponse, LogoutResponse, SessionGrantExchangeRequest,
    SessionGrantIntrospectionProof,
};
use crate::{JsonResult, ids, json_ok};

const PRINCIPAL_SESSION_BIND_SCOPE: &str = "urn:contrix:principal-server:session.bind";
const OAUTH_INTROSPECTION_TOKEN_TYPE_HINT: &str = "access_token";

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

#[derive(Debug, Serialize)]
struct OAuthIntrospectionRequest<'a> {
    token: &'a str,
    token_type_hint: &'static str,
}

#[derive(Debug)]
struct OAuthIntrospectionSession {
    actor: String,
    device_id: String,
    display_name: Option<String>,
    expires_at: DateTime<Utc>,
    raw_device_id: Option<String>,
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

/// Look up the bearer-bound session and validate every gate. Development
/// sessions are resolved from soland's local session store. In production,
/// when `SOLAND_OAUTH_INTROSPECTION_URL` is configured, unknown local bearer
/// tokens are treated as coauth OAuth access tokens and verified through the
/// Matrix/Palpo-style introspection path.
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
    let session = state.persistence.sessions().get(&token_hash).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "persistence_error",
            "session store unavailable",
        )
    })?;
    let Some(session) = session else {
        return authenticated_oauth_session(state, token, token_hash);
    };
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

fn authenticated_oauth_session(
    state: &AppState,
    token: &str,
    token_hash: String,
) -> Result<SessionRecord, (StatusCode, &'static str, &'static str)> {
    let Some(introspection_url) = state.config.oauth_introspection_url.as_deref() else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "invalid bearer token",
        ));
    };
    let Some(introspection_bearer) = state.config.oauth_introspection_bearer.as_deref() else {
        tracing::error!(
            "SOLAND_OAUTH_INTROSPECTION_URL is configured without SOLAND_OAUTH_INTROSPECTION_BEARER"
        );
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "auth_misconfigured",
            "OAuth introspection bearer is not configured",
        ));
    };

    let value = request_oauth_introspection(introspection_url, introspection_bearer, token)?;
    let oauth = parse_oauth_introspection(&value, token)?;
    ensure_oauth_account(state, &oauth)?;
    ensure_oauth_device(state, &oauth)?;

    Ok(SessionRecord {
        token_hash,
        actor: oauth.actor,
        device_id: oauth.device_id,
        audience: state.config.service_did.clone(),
        expires_at: oauth.expires_at,
        created_at: now(),
        revoked_at: None,
    })
}

fn request_oauth_introspection(
    introspection_url: &str,
    introspection_bearer: &str,
    token: &str,
) -> Result<Value, (StatusCode, &'static str, &'static str)> {
    let introspection_url = introspection_url.to_owned();
    let introspection_bearer = introspection_bearer.to_owned();
    let token = token.to_owned();
    std::thread::spawn(move || {
        let request = OAuthIntrospectionRequest {
            token: token.as_str(),
            token_type_hint: OAUTH_INTROSPECTION_TOKEN_TYPE_HINT,
        };
        let response = reqwest::blocking::Client::new()
            .post(introspection_url)
            .bearer_auth(introspection_bearer)
            .form(&request)
            .timeout(std::time::Duration::from_secs(3))
            .send()
            .map_err(|error| {
                tracing::warn!(%error, "OAuth introspection request failed");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "auth_unavailable",
                    "OAuth introspection service unavailable",
                )
            })?;
        if !response.status().is_success() {
            tracing::warn!(
                status = response.status().as_u16(),
                "OAuth introspection rejected the service bearer"
            );
            return Err((
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                "invalid bearer token",
            ));
        }
        response.json::<Value>().map_err(|error| {
            tracing::warn!(%error, "OAuth introspection returned invalid JSON");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "auth_unavailable",
                "OAuth introspection response was invalid",
            )
        })
    })
    .join()
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "auth_unavailable",
            "OAuth introspection worker failed",
        )
    })?
}

fn parse_oauth_introspection(
    value: &Value,
    token: &str,
) -> Result<OAuthIntrospectionSession, (StatusCode, &'static str, &'static str)> {
    if !value
        .get("active")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "inactive bearer token",
        ));
    }
    if !scope_contains(value.get("scope"), PRINCIPAL_SESSION_BIND_SCOPE) {
        return Err((
            StatusCode::FORBIDDEN,
            "capability_denied",
            "missing principal-server session.bind scope",
        ));
    }

    let actor = string_field(value, "org.contrix.principal_did")
        .or_else(|| string_field(value, "sub").filter(|did| validate_did(did).is_ok()))
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "OAuth introspection response did not include a principal DID",
        ))?;
    if validate_did(actor).is_err() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "OAuth introspection response included an invalid principal DID",
        ));
    }

    let raw_device_id = string_field(value, "org.contrix.device_id")
        .or_else(|| string_field(value, "device_id"))
        .map(str::to_owned);
    let device_id = raw_device_id
        .as_deref()
        .filter(|device_id| validate_device_id(device_id).is_ok())
        .map(str::to_owned)
        .unwrap_or_else(|| derived_oauth_device_id(value, token));
    let expires_at = oauth_expiry(value);
    if expires_at <= now() {
        return Err((StatusCode::UNAUTHORIZED, "auth_expired", "session expired"));
    }

    Ok(OAuthIntrospectionSession {
        actor: actor.to_owned(),
        device_id,
        display_name: string_field(value, "username").map(str::to_owned),
        expires_at,
        raw_device_id,
    })
}

fn ensure_oauth_account(
    state: &AppState,
    oauth: &OAuthIntrospectionSession,
) -> Result<(), (StatusCode, &'static str, &'static str)> {
    let accounts = state.persistence.accounts();
    if accounts
        .get(&oauth.actor)
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "persistence_error",
                "account store unavailable",
            )
        })?
        .is_some()
    {
        return Ok(());
    }

    let mut handle = oauth
        .display_name
        .as_deref()
        .and_then(sanitized_handle)
        .unwrap_or_else(|| handle_for_did(&oauth.actor));
    let existing = accounts.list().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "persistence_error",
            "account store unavailable",
        )
    })?;
    if existing
        .iter()
        .any(|account| account.handle == handle && account.did != oauth.actor)
    {
        handle = format!("@oauth-{}", short_hex(oauth.actor.as_bytes(), 16));
    }
    let account = AccountRecord {
        did: oauth.actor.clone(),
        handle,
        display_name: oauth.display_name.clone(),
        created_at: now(),
    };
    accounts.put(&account).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "persistence_error",
            "account store unavailable",
        )
    })?;
    append_audit_log(
        state,
        Some(&oauth.actor),
        "auth.oauth_account_autoprovision",
        json!({"handle": account.handle}),
        "accepted",
    );
    Ok(())
}

fn ensure_oauth_device(
    state: &AppState,
    oauth: &OAuthIntrospectionSession,
) -> Result<(), (StatusCode, &'static str, &'static str)> {
    let devices = state.persistence.devices();
    match devices.get(&oauth.actor, &oauth.device_id).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "persistence_error",
            "device store unavailable",
        )
    })? {
        Some(record) if record.revoked_at.is_some() => {
            return Err((
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                "device revoked",
            ));
        }
        Some(_) => return Ok(()),
        None => {}
    }

    let seen_at = now();
    let device = DeviceInventoryRecord {
        actor: oauth.actor.clone(),
        device_id: oauth.device_id.clone(),
        display_name: oauth.display_name.clone(),
        verification_state: "unverified".to_owned(),
        payload: json!({
            "device_id": oauth.device_id.clone(),
            "display_name": oauth.display_name.clone(),
            "verification": "unverified",
            "oauth_introspection": true,
            "raw_device_id": oauth.raw_device_id.clone(),
            "last_seen_at": seen_at,
        }),
        created_at: seen_at,
        updated_at: seen_at,
        revoked_at: None,
    };
    devices.put(&device).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "persistence_error",
            "device store unavailable",
        )
    })
}

fn string_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn scope_contains(value: Option<&Value>, expected: &str) -> bool {
    match value {
        Some(Value::String(scope)) => scope.split_whitespace().any(|scope| scope == expected),
        Some(Value::Array(scopes)) => scopes
            .iter()
            .filter_map(Value::as_str)
            .any(|scope| scope == expected),
        _ => false,
    }
}

fn oauth_expiry(value: &Value) -> DateTime<Utc> {
    if let Some(exp) = value.get("exp").and_then(parse_oauth_datetime) {
        return exp;
    }
    if let Some(seconds) = value.get("expires_in").and_then(Value::as_i64) {
        return now() + Duration::seconds(seconds.max(0));
    }
    now() + Duration::minutes(5)
}

fn parse_oauth_datetime(value: &Value) -> Option<DateTime<Utc>> {
    if let Some(seconds) = value.as_i64() {
        return DateTime::<Utc>::from_timestamp(seconds, 0);
    }
    let text = value.as_str()?.trim();
    if let Ok(seconds) = text.parse::<i64>() {
        return DateTime::<Utc>::from_timestamp(seconds, 0);
    }
    DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn sanitized_handle(value: &str) -> Option<String> {
    let tail = value
        .trim()
        .trim_start_matches('@')
        .to_ascii_lowercase()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_owned();
    if tail.is_empty() {
        return None;
    }
    let handle = normalize_handle(&tail);
    is_valid_handle(&handle).then_some(handle)
}

fn derived_oauth_device_id(value: &Value, token: &str) -> String {
    let seed = string_field(value, "org.contrix.session_id")
        .or_else(|| string_field(value, "jti"))
        .or_else(|| string_field(value, "sub"))
        .unwrap_or(token);
    let digest = format!("{:x}", Sha256::digest(seed.as_bytes()));
    format!(
        "cx:device:{}-{}-7{}-8{}-{}",
        &digest[0..8],
        &digest[8..12],
        &digest[12..15],
        &digest[15..18],
        &digest[18..30]
    )
}

fn short_hex(bytes: &[u8], len: usize) -> String {
    let digest = Sha256::digest(bytes);
    format!("{digest:x}").chars().take(len).collect()
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
