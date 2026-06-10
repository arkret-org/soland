//! Auth + session handlers and the session-validation helpers they rely on.
//!
//! Surfaces:
//! - `POST /_soland/gate/auth/dev-login` — dev-mode bearer issue
//! - direct OAuth bearer authentication — Matrix/Palpo-style validation through coauth
//!   `/oauth/introspect`
//! - `POST /_cokret/gate/account/session-grants` — legacy coauth session-grant bridge
//! - `POST /_soland/gate/auth/logout` — revoke the bearer + the bound device
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
    append_audit_log, bearer_token, handle_for_did, is_valid_handle, normalize_handle,
    normalize_localpart, now, render_error, validate_device_id, validate_did,
};
use crate::error::{AppError, ErrorCode};
use crate::state::{AccountRecord, AppState, DeviceInventoryRecord, SessionRecord};
use crate::wire::{
    DevLoginOutcome, DevLoginRequestBody, LogoutOutcome, SessionGrantExchangeRequestBody,
    SessionGrantIntrospectionProof,
};
use crate::{JsonResult, ids, json_ok};

const PRINCIPAL_SESSION_BIND_SCOPE: &str = "urn:cokret:principal-server:session.bind";
const OAUTH_INTROSPECTION_TOKEN_TYPE_HINT: &str = "access_token";

pub(super) fn router() -> Router {
    legacy_router()
}

pub(super) fn protocol_account_router() -> Router {
    Router::with_path("account")
        .push(Router::with_path("session-grants").post(exchange_session_grant))
}

pub(super) fn legacy_router() -> Router {
    Router::with_path("auth")
        .push(Router::with_path("bridge/describe").get(super::describe::auth_bridge_describe))
        .push(Router::with_path("dev-login").post(dev_login))
        .push(Router::with_path("session-grant/exchange").post(exchange_session_grant))
        .push(Router::with_path("logout").post(logout))
}

fn account_new_session_error(state: &AppState, actor: &str) -> Option<AppError> {
    account_new_session_tuple(state, actor).map(|(status, code, message)| {
        AppError::capability_denied(message)
            .with_status(status)
            .with_wire_code(code)
    })
}

fn account_new_session_tuple(
    state: &AppState,
    actor: &str,
) -> Option<(StatusCode, &'static str, &'static str)> {
    match state.account_lifecycle_state(actor).as_str() {
        "locked" => Some((StatusCode::FORBIDDEN, "account_locked", "account is locked")),
        "suspended" => Some((
            StatusCode::FORBIDDEN,
            "account_suspended",
            "account is suspended",
        )),
        "deactivated" => Some((
            StatusCode::FORBIDDEN,
            "account_deactivated",
            "account has been deactivated",
        )),
        "erased" => Some((
            StatusCode::FORBIDDEN,
            "account_erased",
            "account has been erased",
        )),
        _ => None,
    }
}

/// Spec: A.3 — auth handlers consult the in-memory failed-login counter
/// before doing any other work. The lockout response is 403
/// `account_locked` with a wire body that doesn't reveal which credential
/// failed, only that the actor is currently locked.
fn account_lockout_error(state: &AppState, actor: &str) -> Option<AppError> {
    let until = state.account_lockout_active_until(actor)?;
    let until_wire = until.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    Some(
        AppError::capability_denied(format!(
            "account temporarily locked due to repeated failed auth attempts; \
             retry after {until_wire}"
        ))
        .with_status(StatusCode::FORBIDDEN)
        .with_wire_code("account_locked"),
    )
}

/// Record a failed auth attempt against the actor and emit a single audit
/// row + warn-level tracing breadcrumb. Called from every auth-failure
/// branch in the dev-login / session-grant exchange paths.
pub(super) async fn record_failed_login_attempt(state: &AppState, actor: &str, surface: &str) {
    let record = state.record_failed_login(actor);
    let locked_until = record
        .locked_until
        .map(|until| until.to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
    append_audit_log(
        state,
        Some(actor),
        "auth.failed_attempt",
        json!({
            "surface": surface,
            "attempts": record.attempts,
            "locked_until": locked_until,
        }),
        "denied",
    )
    .await;
    if record.locked_until.is_some() {
        tracing::warn!(
            actor,
            attempts = record.attempts,
            locked_until = ?record.locked_until,
            surface,
            "account locked after repeated failed auth attempts"
        );
    }
}

fn account_existing_session_error(
    state: &AppState,
    actor: &str,
) -> Option<(StatusCode, &'static str, &'static str)> {
    // Spec: C.3.8 — 401 means "not authenticated"; 403 means
    // "authenticated, policy denies". A session-bearing request whose
    // backing account is `locked` / `deactivated` carries a valid
    // bearer (so the request IS authenticated); the lifecycle gate is
    // a policy denial and MUST surface as 403.
    //
    // `erased` is the exception kept at 401: erasure invalidates the
    // bearer itself, so the spec calls for a re-auth signal rather
    // than a policy-denial signal (matches identity/account-lifecycle.md
    // §3 "subsequent authenticated requests return 401 `account_erased`").
    match state.account_lifecycle_state(actor).as_str() {
        "locked" => Some((StatusCode::FORBIDDEN, "account_locked", "account is locked")),
        "deactivated" => Some((
            StatusCode::FORBIDDEN,
            "account_deactivated",
            "account has been deactivated",
        )),
        "erased" => Some((
            StatusCode::UNAUTHORIZED,
            "account_erased",
            "account has been erased",
        )),
        _ => None,
    }
}

#[endpoint(
    operation_id = "org.cokret.soland.auth.dev_login",
    tags("auth"),
    summary = "Development bearer-token login"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.auth.dev_login"))]
async fn dev_login(
    depot: &mut Depot,
    body: JsonBody<DevLoginRequestBody>,
) -> JsonResult<DevLoginOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    if !state.config.development_mode {
        return Err(AppError::not_found("endpoint not available"));
    }
    let body = body.into_inner();
    if validate_did(&body.actor).is_err() || body.device_id.trim().is_empty() {
        return Err(AppError::invalid_param(
            "actor must be a DID and device_id is required",
        ));
    }
    crate::routing::extensions::sovereign::validate_sovereign_did_registration(state, &body.actor)?;
    // Spec: A.3 — auth handlers consult the in-memory failed-login
    // counter before doing anything else. An actor that crossed the
    // threshold gets a 403 `account_locked` until the lockout window
    // expires, without revealing whether the credential would otherwise
    // have been valid.
    if let Some(error) = account_lockout_error(state, &body.actor) {
        return Err(error);
    }
    let account = state
        .persistence
        .accounts()
        .get(&body.actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if let Some(error) = account_new_session_error(state, &body.actor) {
        return Err(error);
    }
    if account.is_none() {
        let synthetic_handle = handle_for_did(&body.actor);
        let synthetic_display = body
            .display_name
            .clone()
            .unwrap_or_else(|| synthetic_handle.trim_start_matches('@').to_owned());
        let record = AccountRecord {
            id: crate::ids::generate_account_id(),
            did: body.actor.clone(),
            localpart: normalize_localpart(&synthetic_handle),
            display_name: Some(synthetic_display),
            bio: None,
            avatar_url: None,
            created_at: now(),
        };
        state
            .persistence
            .accounts()
            .put(&record)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        append_audit_log(
            state,
            Some(&body.actor),
            "account.register",
            json!({"handle": record.handle(), "via": "dev_login"}),
            "accepted",
        )
        .await;
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
        .await
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
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    append_audit_log(
        state,
        Some(&body.actor),
        "auth.dev_login",
        json!({"device_id": body.device_id.clone()}),
        "accepted",
    )
    .await;
    state.clear_failed_login(&body.actor);

    json_ok(DevLoginOutcome {
        access_token: token,
        token_type: "Bearer".to_owned(),
        actor: body.actor,
        device_id: body.device_id,
        expires_at,
    })
}

#[endpoint(
    operation_id = "org.cokret.soland.auth.exchange_session_grant",
    tags("auth"),
    summary = "Exchange a coauth session-grant for a principal-server bearer session"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.auth.exchange_session_grant"))]
async fn exchange_session_grant(
    depot: &mut Depot,
    body: JsonBody<SessionGrantExchangeRequestBody>,
) -> JsonResult<DevLoginOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    if body.grant_jwt.trim().is_empty()
        || validate_did(&body.principal_id).is_err()
        || validate_device_id(&body.device_id).is_err()
    {
        return Err(AppError::invalid_param(
            "grant_jwt, principal_id, and device_id are required",
        ));
    }
    if let Some(error) = account_lockout_error(state, &body.principal_id) {
        return Err(error);
    }
    let account = state
        .persistence
        .accounts()
        .get(&body.principal_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if account.is_none() {
        return Err(AppError::not_found("account is not registered"));
    }
    if let Some(error) = account_new_session_error(state, &body.principal_id) {
        return Err(error);
    }

    let grant = match validate_session_grant_binding(
        state,
        SessionGrantValidationInput {
            grant_jwt: body.grant_jwt.as_str(),
            principal_id: body.principal_id.as_str(),
            device_id: body.device_id.as_str(),
            proof: body.introspection_proof.as_ref(),
        },
    )
    .await
    {
        Ok(grant) => grant,
        Err(error) => {
            // Spec: A.3 — session-grant validation failures count toward
            // the rolling lockout window. Account is locked after 5
            // failures in 15 min; clearing happens on the success
            // path below.
            record_failed_login_attempt(state, &body.principal_id, "session_grant_exchange").await;
            return Err(error);
        }
    };
    let expires_at = grant
        .as_ref()
        .map(|grant| grant.expires_at)
        .unwrap_or_else(|| now() + Duration::hours(12));
    let token = token_for(
        &body.principal_id,
        &body.device_id,
        expires_at.timestamp_millis(),
    );
    let token_hash = session_token_hash(&token, &state.config.service_did);
    let session = SessionRecord {
        token_hash,
        actor: body.principal_id.clone(),
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
        .await
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
        actor: body.principal_id.clone(),
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
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    append_audit_log(
        state,
        Some(&body.principal_id),
        "auth.session_grant_exchange",
        json!({
            "device_id": body.device_id.clone(),
            "grant_bridge": true,
            "coauth_introspection": grant.is_some(),
            "one_time_use_consumed": grant.as_ref().map(|grant| grant.one_time_use_consumed).unwrap_or(false),
        }),
        "accepted",
    )
    .await;
    state.clear_failed_login(&body.principal_id);

    json_ok(DevLoginOutcome {
        access_token: token,
        token_type: "Bearer".to_owned(),
        actor: body.principal_id,
        device_id: body.device_id,
        expires_at,
    })
}

#[derive(Debug, Serialize)]
struct SessionGrantIntrospectionRequestBody<'a> {
    grant_jwt: &'a str,
    audience: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<&'a SessionGrantIntrospectionProof>,
}

#[derive(Debug, Deserialize)]
struct SessionGrantIntrospectionOutcome {
    active: bool,
    status: String,
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
struct OAuthIntrospectionRequestBody<'a> {
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
    pub principal_id: &'a str,
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
    let request = SessionGrantIntrospectionRequestBody {
        grant_jwt: input.grant_jwt,
        audience: state.config.service_did.as_str(),
        proof: input.proof,
    };
    // SOL-03-002: pin validated IPs into the client to close the DNS-rebinding
    // TOCTOU window between the egress check and the connection.
    let (introspection_url, client) =
        crate::security::validate_http_url_for_egress_with_pinned_client(
            introspection_url,
            "session grant introspection",
            state.config.development_mode,
            std::time::Duration::from_secs(10),
        )
        .map_err(AppError::capability_denied)?;
    let response = client
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
        .json::<SessionGrantIntrospectionOutcome>()
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
    if grant.subject != input.principal_id {
        return Err(AppError::capability_denied(
            "session grant subject does not match principal_id",
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
    operation_id = "org.cokret.soland.auth.logout",
    tags("auth"),
    summary = "Revoke the current bearer session and bound device"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.auth.logout"))]
async fn logout(
    aa: super::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<LogoutOutcome> {
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
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        Some(mut session) if session.revoked_at.is_none() => {
            session.revoked_at = Some(now());
            state
                .persistence
                .sessions()
                .put(&session)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            Some(session)
        }
        _ => None,
    };
    let revoked = revoked_session.is_some();
    if let Some(session) = revoked_session {
        revoke_device_record(state, &session.actor, &session.device_id)
            .await
            .map_err(AppError::internal)?;
        append_audit_log(
            state,
            Some(&session.actor),
            "auth.logout",
            json!({"device_id": session.device_id, "revoked_at": session.revoked_at}),
            "accepted",
        )
        .await;
        let _ = state
            .persistence
            .device_messages()
            .purge(&session.actor, &session.device_id)
            .await;
    }
    json_ok(LogoutOutcome { ok: true, revoked })
}

// ── Session validation pipeline ─────────────────────────────────────────────

/// Standard "extract authenticated session or render 401" wrapper used by
/// nearly every protected handler. Returns `None` after rendering an error.
pub async fn auth_or_render(
    state: &AppState,
    req: &Request,
    res: &mut Response,
) -> Option<SessionRecord> {
    match authenticated_session(state, req).await {
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
pub async fn authenticated_session(
    state: &AppState,
    req: &Request,
) -> Result<SessionRecord, (StatusCode, &'static str, &'static str)> {
    if let Some(query) = req.uri().query()
        && (query.contains("access_token=") || query.contains("auth=") || query.contains("token="))
    {
        // Spec: A.3 — auth material MUST NOT appear in query strings.
        // We log a truncated preview of the offending token so on-call
        // can correlate without persisting the full bearer in tracing
        // backends. The preview is at most 8 chars of the matched
        // `<param>=<token>` value; we never log the full token.
        let preview = query_string_token_preview(query);
        tracing::warn!(
            token_preview = %preview,
            "auth material in query strings rejected (token preview only, full value redacted)"
        );
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
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "session store unavailable",
            )
        })?;
    let Some(session) = session else {
        return authenticated_oauth_session(state, token, token_hash).await;
    };
    if session.audience != state.config.service_did {
        return Err((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "session audience does not match this service",
        ));
    }
    if let Some(error) = account_existing_session_error(state, &session.actor) {
        return Err(error);
    }
    if session.revoked_at.is_some() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "session revoked",
        ));
    }
    if is_device_revoked(state, &session.actor, &session.device_id).await {
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

/// Extract a short, redaction-safe preview of any auth-material parameter
/// (`access_token=`, `auth=`, or `token=`) found in `query`. Returns at most
/// the first 8 characters of the parameter value, followed by `…` if the
/// value was longer. Used by the query-string rejection path so tracing
/// backends can correlate an offending request without persisting the
/// full token.
fn query_string_token_preview(query: &str) -> String {
    const PREFIXES: &[&str] = &["access_token=", "auth=", "token="];
    for pair in query.split('&') {
        for prefix in PREFIXES {
            if let Some(value) = pair.strip_prefix(prefix) {
                let preview: String = value.chars().take(8).collect();
                if value.chars().nth(8).is_some() {
                    return format!("{preview}…");
                }
                return preview;
            }
        }
    }
    String::new()
}

async fn authenticated_oauth_session(
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

    let value = request_oauth_introspection(
        introspection_url,
        introspection_bearer,
        token,
        state.config.development_mode,
    )?;
    let oauth = parse_oauth_introspection(&value, token)?;
    ensure_oauth_account(state, &oauth).await?;
    if let Some(error) = account_new_session_tuple(state, &oauth.actor) {
        return Err(error);
    }
    ensure_oauth_device(state, &oauth).await?;

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

// OAuth introspection timing-attack mitigation (Spec: A.3).
//
// The introspection call is the dominant signal that distinguishes a known
// vs unknown bearer token from the caller's perspective. We wrap each call
// in:
//   1. A fixed timeout (`OAUTH_INTROSPECTION_TIMEOUT`) so success/failure both bound at the same
//      upper edge.
//   2. A constant-time floor: we always wait at least `OAUTH_INTROSPECTION_MIN_LATENCY` before
//      returning, with a small random jitter on top so the floor itself is not observable as a
//      sharp edge.
//
// The work is dispatched onto the current tokio runtime (the auth path is
// reached from `async fn` handlers; this function is sync only because
// `Salvo` extractors give us a sync bridge), gated behind
// `block_in_place` so a slow upstream cannot starve the runtime.
const OAUTH_INTROSPECTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const OAUTH_INTROSPECTION_MIN_LATENCY: std::time::Duration = std::time::Duration::from_millis(40);
const OAUTH_INTROSPECTION_JITTER_MAX: std::time::Duration = std::time::Duration::from_millis(20);

fn request_oauth_introspection(
    introspection_url: &str,
    introspection_bearer: &str,
    token: &str,
    development_mode: bool,
) -> Result<Value, (StatusCode, &'static str, &'static str)> {
    let introspection_url = introspection_url.to_owned();
    let introspection_bearer = introspection_bearer.to_owned();
    let token = token.to_owned();

    let runtime_handle = match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle,
        Err(_) => {
            // Not on a tokio runtime — should only happen in unit tests
            // that bypass the salvo runtime. Fall back to the legacy
            // blocking client; the timing-leak window is irrelevant
            // outside the request-serving runtime.
            return legacy_blocking_introspection(
                &introspection_url,
                &introspection_bearer,
                &token,
                development_mode,
            );
        }
    };

    tokio::task::block_in_place(|| {
        runtime_handle.block_on(async move {
            let started = tokio::time::Instant::now();
            let jitter_micros = jitter_micros(OAUTH_INTROSPECTION_JITTER_MAX);
            let result = perform_oauth_introspection(
                &introspection_url,
                &introspection_bearer,
                &token,
                development_mode,
            )
            .await;
            // Constant-time floor: regardless of whether the upstream
            // returned 200, 401, or timed out, sleep until at least
            // `min_latency + jitter` has elapsed. This collapses the
            // observable timing distribution between "token unknown to
            // soland" (fast 401), "token known to coauth, active"
            // (slow round-trip), and "token known to coauth, inactive"
            // (slow round-trip) into a single floor.
            let floor =
                OAUTH_INTROSPECTION_MIN_LATENCY + std::time::Duration::from_micros(jitter_micros);
            let elapsed = started.elapsed();
            if elapsed < floor {
                tokio::time::sleep(floor - elapsed).await;
            }
            result
        })
    })
}

async fn perform_oauth_introspection(
    introspection_url: &str,
    introspection_bearer: &str,
    token: &str,
    development_mode: bool,
) -> Result<Value, (StatusCode, &'static str, &'static str)> {
    let request = OAuthIntrospectionRequestBody {
        token,
        token_type_hint: OAUTH_INTROSPECTION_TOKEN_TYPE_HINT,
    };
    // SOL-03-002: pin validated IPs into the client to close the DNS-rebinding
    // TOCTOU window between the egress check and the connection.
    let (introspection_url, client) =
        crate::security::validate_http_url_for_egress_with_pinned_client(
            introspection_url,
            "OAuth introspection",
            development_mode,
            OAUTH_INTROSPECTION_TIMEOUT,
        )
        .map_err(|error| {
            tracing::warn!(%error, "OAuth introspection denied by egress policy");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "auth_unavailable",
                "OAuth introspection service unavailable",
            )
        })?;
    let fut = client
        .post(introspection_url)
        .bearer_auth(introspection_bearer)
        .form(&request)
        .send();
    let response = match tokio::time::timeout(OAUTH_INTROSPECTION_TIMEOUT, fut).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            tracing::warn!(%error, "OAuth introspection request failed");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "auth_unavailable",
                "OAuth introspection service unavailable",
            ));
        }
        Err(_) => {
            tracing::warn!("OAuth introspection request timed out");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "auth_unavailable",
                "OAuth introspection service unavailable",
            ));
        }
    };
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
    let parse_fut = response.json::<Value>();
    match tokio::time::timeout(OAUTH_INTROSPECTION_TIMEOUT, parse_fut).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => {
            tracing::warn!(%error, "OAuth introspection returned invalid JSON");
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "auth_unavailable",
                "OAuth introspection response was invalid",
            ))
        }
        Err(_) => {
            tracing::warn!("OAuth introspection JSON decode timed out");
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "auth_unavailable",
                "OAuth introspection response was invalid",
            ))
        }
    }
}

fn legacy_blocking_introspection(
    introspection_url: &str,
    introspection_bearer: &str,
    token: &str,
    development_mode: bool,
) -> Result<Value, (StatusCode, &'static str, &'static str)> {
    let request = OAuthIntrospectionRequestBody {
        token,
        token_type_hint: OAUTH_INTROSPECTION_TOKEN_TYPE_HINT,
    };
    // SOL-03-002: pin validated IPs into the (blocking) client to close the
    // DNS-rebinding TOCTOU window, matching the async path. (This legacy
    // blocking path is only reachable outside the request-serving runtime; see
    // SOL-08-002/SOL-99-002 for its planned removal.)
    let (introspection_url, client) =
        crate::security::validate_http_url_for_egress_with_pinned_blocking_client(
            introspection_url,
            "OAuth introspection",
            development_mode,
            OAUTH_INTROSPECTION_TIMEOUT,
        )
        .map_err(|error| {
            tracing::warn!(%error, "OAuth introspection denied by egress policy");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "auth_unavailable",
                "OAuth introspection service unavailable",
            )
        })?;
    let response = client
            .post(introspection_url)
            .bearer_auth(introspection_bearer)
            .form(&request)
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
}

/// Sample a small jitter in microseconds for the introspection constant-time
/// floor. We pull from `rand::OsRng` rather than a fast PRNG so the floor
/// itself is not predictable from an external observer.
fn jitter_micros(max: std::time::Duration) -> u64 {
    use rand::RngCore;
    let max_micros = max.as_micros().min(u128::from(u64::MAX)) as u64;
    if max_micros == 0 {
        return 0;
    }
    let mut buf = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    u64::from_le_bytes(buf) % max_micros
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

    let actor = string_field(value, "org.cokret.principal_did")
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

    let raw_device_id = string_field(value, "org.cokret.device_id")
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

async fn ensure_oauth_account(
    state: &AppState,
    oauth: &OAuthIntrospectionSession,
) -> Result<(), (StatusCode, &'static str, &'static str)> {
    let accounts = state.persistence.accounts();
    if accounts
        .get(&oauth.actor)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "account store unavailable",
            )
        })?
        .is_some()
    {
        return Ok(());
    }

    let mut localpart = normalize_localpart(
        &oauth
            .display_name
            .as_deref()
            .and_then(sanitized_handle)
            .unwrap_or_else(|| handle_for_did(&oauth.actor)),
    );
    let existing = accounts.list().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "account store unavailable",
        )
    })?;
    if existing
        .iter()
        .any(|account| account.localpart == localpart && account.did != oauth.actor)
    {
        localpart = format!("oauth-{}", short_hex(oauth.actor.as_bytes(), 16));
    }
    let account = AccountRecord {
        id: crate::ids::generate_account_id(),
        did: oauth.actor.clone(),
        localpart,
        display_name: oauth.display_name.clone(),
        bio: None,
        avatar_url: None,
        created_at: now(),
    };
    accounts.put(&account).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "account store unavailable",
        )
    })?;
    append_audit_log(
        state,
        Some(&oauth.actor),
        "auth.oauth_account_autoprovision",
        json!({"handle": account.handle()}),
        "accepted",
    )
    .await;
    Ok(())
}

async fn ensure_oauth_device(
    state: &AppState,
    oauth: &OAuthIntrospectionSession,
) -> Result<(), (StatusCode, &'static str, &'static str)> {
    let devices = state.persistence.devices();
    match devices
        .get(&oauth.actor, &oauth.device_id)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
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
    devices.put(&device).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
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
    let seed = string_field(value, "org.cokret.session_id")
        .or_else(|| string_field(value, "jti"))
        .or_else(|| string_field(value, "sub"))
        .unwrap_or(token);
    let digest = format!("{:x}", Sha256::digest(seed.as_bytes()));
    format!(
        "ck:device:{}-{}-7{}-8{}-{}",
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

/// Revoke every active bearer session for an actor.
pub async fn revoke_sessions_for_actor(state: &AppState, actor: &str) -> Result<usize, String> {
    let revoked_at = now();
    let sessions = state
        .persistence
        .sessions()
        .snapshot_all()
        .await
        .map_err(|error| error.to_string())?;
    let mut count = 0usize;
    for mut session in sessions
        .into_iter()
        .filter(|session| session.actor == actor && session.revoked_at.is_none())
    {
        session.revoked_at = Some(revoked_at);
        state
            .persistence
            .sessions()
            .put(&session)
            .await
            .map_err(|error| error.to_string())?;
        count += 1;
    }
    Ok(count)
}

/// Revoke every active device record for an actor.
pub async fn revoke_devices_for_actor(state: &AppState, actor: &str) -> Result<usize, String> {
    let revoked_at = now();
    let devices = state
        .persistence
        .devices()
        .list()
        .await
        .map_err(|error| error.to_string())?;
    let mut count = 0usize;
    for mut device in devices
        .into_iter()
        .filter(|device| device.actor == actor && device.revoked_at.is_none())
    {
        device.revoked_at = Some(revoked_at);
        device.updated_at = revoked_at;
        state
            .persistence
            .devices()
            .put(&device)
            .await
            .map_err(|error| error.to_string())?;
        count += 1;
    }
    Ok(count)
}

/// Persist that the device is revoked. Used by `logout` and by the
/// device-management handlers in mod.rs.
pub async fn revoke_device_record(
    state: &AppState,
    actor: &str,
    device_id: &str,
) -> Result<(), String> {
    let revoked_at = now();
    let mut record = state
        .persistence
        .devices()
        .get(actor, device_id)
        .await
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
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

/// Returns true if the persistent device record has a `revoked_at` timestamp,
/// or if the device cannot be located at all.
pub async fn is_device_revoked(state: &AppState, actor: &str, device_id: &str) -> bool {
    match state.persistence.devices().get(actor, device_id).await {
        Ok(Some(record)) => record.revoked_at.is_some(),
        Ok(None) => match state.persistence.devices().list_for_actor(actor).await {
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
