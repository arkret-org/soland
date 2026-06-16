//! Auth + session handlers and the session-validation helpers they rely on.
//!
//! Surfaces:
//! - `POST /_soland/gate/auth/dev-login` — dev-mode bearer issue
//! - direct OAuth bearer authentication — Matrix/Palpo-style validation through coauth
//!   `/oauth/introspect`
//! - `POST /_cokret/gate/account/session-grants` — coauth session-grant bridge
//! - `POST /_cokret/gate/account/session-grants/revoke` — spec
//!   `ck.gate.account.command.revoke_session`
//! - `POST /_cokret/gate/account/logout` — spec `ck.gate.account.command.logout`: revoke the bearer
//!   + the bound device session record + queued to-device
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
use cokret_sdk::{
    AccountDevicePairOutcome, AccountDevicePairRequestBody, DeviceId, EventId,
    SessionRevokeOutcome, SessionRevokeRequestBody,
};
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
    DevLoginRequestBody, LogoutOutcome, SessionGrantExchangeRequestBody,
    SessionGrantIntrospectOutcome, SessionGrantIntrospectRequestBody, SessionGrantIntrospectStatus,
    SessionGrantIntrospectionProof, SessionLoginOutcome,
};
use crate::{JsonResult, ids, json_ok};

const PRINCIPAL_SESSION_BIND_SCOPE: &str = "urn:cokret:principal-server:session.bind";
const OAUTH_INTROSPECTION_TOKEN_TYPE_HINT: &str = "access_token";

/// Lifetime (minutes) of an access bearer minted from a session-grant exchange.
/// The bearer is a SHORT access token; the (longer, minutes-to-hours) session
/// grant is the refresh credential the client re-exchanges for fresh bearers.
/// Capped so a long grant never yields a long-lived bearer; never extended past
/// the grant's own expiry.
const SHORT_BEARER_TTL_MINUTES: i64 = 15;

/// Expiry for an access bearer minted from a session-grant exchange: `now +
/// SHORT_BEARER_TTL`, but never beyond the grant's own expiry. Keeps bearers
/// short regardless of grant length, and never mints a bearer that outlives the
/// refresh credential backing it.
fn capped_bearer_expiry(grant_expires_at: DateTime<Utc>, now: DateTime<Utc>) -> DateTime<Utc> {
    grant_expires_at.min(now + Duration::minutes(SHORT_BEARER_TTL_MINUTES))
}

pub(super) fn router() -> Router {
    local_router()
}

pub(super) fn protocol_account_router() -> Router {
    Router::with_path("account")
        .push(
            Router::with_path("session-grants")
            .post(exchange_session_grant)
            // Spec `account_auth` surface group: `ck.gate.account.command.revoke_session`
            // binds to `POST /_cokret/gate/account/session-grants/revoke`.
                .push(Router::with_path("revoke").post(session_revoke)),
        )
        // Spec `ck.gate.account.command.logout` — Principal Server device
        // logout (account-lifecycle §4.1): revoke this session's bearer, mark
        // its local device session record revoked, drop the device's queued
        // to-device. Canonical `/_cokret/gate/account/logout`; deployment
        // gateways route this longer prefix to soland even though `/_cokret/gate/`
        // otherwise goes to the Auth Server.
        .push(Router::with_path("logout").post(logout))
        .push(Router::with_path("device-pair").post(account_device_pair))
}

pub(super) fn local_router() -> Router {
    // Device logout is the spec op `ck.gate.account.command.logout`, served at
    // the canonical `/_cokret/gate/account/logout` (see `protocol_account_router`).
    // Deployment gateways route that longer prefix to soland (the Principal
    // Server) even though `/_cokret/gate/` otherwise goes to the Auth Server, so
    // no `/_soland/gate/auth/logout` product alias is needed.
    Router::with_path("auth")
        .push(Router::with_path("bridge/describe").get(super::describe::auth_bridge_describe))
        .push(Router::with_path("dev-login").post(dev_login))
        .push(Router::with_path("session-grant/exchange").post(exchange_session_grant))
}

#[endpoint(
    operation_id = "ck.gate.account.command.pair_device",
    tags("auth"),
    summary = "Pair a new device with approval from the authenticated existing device",
    status_codes(200, 400, 401, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.gate.account.command.pair_device"))]
async fn account_device_pair(
    aa: super::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<AccountDevicePairRequestBody>,
) -> JsonResult<AccountDevicePairOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    json_ok(authorize_account_device_pair(state, &session, body.into_inner()).await?)
}

async fn authorize_account_device_pair(
    state: &AppState,
    session: &SessionRecord,
    body: AccountDevicePairRequestBody,
) -> Result<AccountDevicePairOutcome, AppError> {
    ensure_authorizing_device_verified(state, session).await?;
    let pairing_code = body.pairing_code.trim();
    if pairing_code.is_empty() {
        return Err(AppError::missing_param("pairing_code is required"));
    }
    if !is_base64url_non_empty(body.challenge_signature.trim()) {
        return Err(AppError::invalid_param(
            "challenge_signature must be non-empty base64url",
        ));
    }
    let device_id = device_id_from_pair_pubkey(&body.new_device_pubkey)?;
    if device_id == session.device_id {
        return Err(AppError::conflict(
            "new device id must differ from the authorizing session device",
        )
        .with_wire_code("cannot_pair_current_device"));
    }
    if let Some(existing) = state
        .persistence
        .devices()
        .get(&session.actor, &device_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        && existing.revoked_at.is_none()
        && existing.verification_state == "verified"
    {
        return Err(AppError::conflict("device is already authorized")
            .with_wire_code("device_already_authorized"));
    }

    let authorized_event_ref = ids::generate_event_id();
    let authorized_at = now();
    let display_name = body
        .display_name
        .as_deref()
        .or_else(|| {
            body.device_metadata
                .get("display_name")
                .and_then(Value::as_str)
        })
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let device = DeviceInventoryRecord {
        actor: session.actor.clone(),
        device_id: device_id.clone(),
        display_name: display_name.clone(),
        verification_state: "verified".to_owned(),
        payload: json!({
            "authorization": {
                "event_kind": "ck.device.authorize",
                "authorized_event_ref": authorized_event_ref.clone(),
                "authorized_by_device_id": session.device_id.clone(),
                "authorized_at": authorized_at,
                "pairing_code": pairing_code,
                "challenge_signature": body.challenge_signature,
                "new_device_pubkey": body.new_device_pubkey,
                "device_metadata": body.device_metadata,
            }
        }),
        created_at: authorized_at,
        updated_at: authorized_at,
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
        Some(&session.actor),
        "account.device_pair",
        json!({
            "device_id": session.device_id.clone(),
            "new_device_id": device_id,
            "authorized_event_ref": authorized_event_ref.clone(),
        }),
        "accepted",
    )
    .await;

    let device_id =
        DeviceId::new(device.device_id).map_err(|error| AppError::internal(error.to_string()))?;
    let authorized_event_ref = EventId::new(authorized_event_ref)
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(AccountDevicePairOutcome {
        device_id,
        authorized_event_ref,
        device_grant: json!({
            "status": "active",
            "authorized_by_device_id": session.device_id.clone(),
            "authorized_at": authorized_at,
            "display_name": display_name,
        }),
        key_backup_hint: json!({}),
    })
}

fn initial_session_device_verification_state<'a>(
    existing_devices: &'a [DeviceInventoryRecord],
    device_id: &str,
) -> &'a str {
    if existing_devices.is_empty()
        || existing_devices
            .iter()
            .any(|device| device.device_id == device_id && device.verification_state == "verified")
    {
        "verified"
    } else {
        "unverified"
    }
}

fn validated_session_device_public_key(value: Option<&str>) -> Result<Option<String>, AppError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    crate::routing::identity::cross_signing::decode_ed25519_key(value, "multibase").map_err(
        |error| {
            AppError::invalid_param(format!(
                "device_public_key must be an Ed25519 multibase key: {error}"
            ))
        },
    )?;
    Ok(Some(value.to_owned()))
}

async fn ensure_authorizing_device_verified(
    state: &AppState,
    session: &SessionRecord,
) -> Result<(), AppError> {
    let device = state
        .persistence
        .devices()
        .get(&session.actor, &session.device_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| {
            AppError::capability_denied("authorizing device is not registered")
                .with_wire_code("device_not_authorized")
        })?;
    if device.revoked_at.is_some() || device.verification_state != "verified" {
        return Err(
            AppError::capability_denied("authorizing device is not verified")
                .with_wire_code("device_not_authorized"),
        );
    }
    Ok(())
}

fn device_id_from_pair_pubkey(new_device_pubkey: &Value) -> Result<String, AppError> {
    let object = new_device_pubkey
        .as_object()
        .ok_or_else(|| AppError::invalid_param("new_device_pubkey must be an object"))?;
    for required in ["kid", "alg"] {
        let value = object
            .get(required)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                AppError::missing_param(format!("new_device_pubkey.{required} is required"))
            })?;
        let _ = value;
    }
    let public_key = object
        .get("public_key")
        .or_else(|| object.get("key"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::missing_param("new_device_pubkey.public_key is required"))?;
    if !is_base64url_non_empty(public_key) {
        return Err(AppError::invalid_param(
            "new_device_pubkey.public_key must be base64url",
        ));
    }
    let kid = object
        .get("kid")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    DeviceId::new(kid.to_owned())
        .map(|device_id| device_id.to_string())
        .map_err(|_| AppError::invalid_param("new_device_pubkey.kid must be a ck:device id"))
}

fn is_base64url_non_empty(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn account_new_session_error(state: &AppState, actor: &str) -> Option<AppError> {
    account_new_session_tuple(state, actor).map(|(status, code, reason_detail, message)| {
        AppError::capability_denied(message)
            .with_status(status)
            .with_wire_code(code)
            .with_reason_detail(reason_detail)
    })
}

/// Lifecycle gate for new session issuance. Wire codes come from the spec
/// error-code-registry: `locked` / `suspended` deny by account policy →
/// `policy_denied` (403); `deactivated` / `erased` hit the
/// account-lifecycle.md §7.1 write barrier → `failed_precondition` with
/// reason `principal_deactivated`. The pre-rename lifecycle word is kept in
/// `error.details.reason_detail` for operators.
fn account_new_session_tuple(
    state: &AppState,
    actor: &str,
) -> Option<(StatusCode, &'static str, &'static str, &'static str)> {
    match state.account_lifecycle_state(actor).as_str() {
        "locked" => Some((
            StatusCode::FORBIDDEN,
            "policy_denied",
            "account_status=locked",
            "account is locked",
        )),
        "suspended" => Some((
            StatusCode::FORBIDDEN,
            "policy_denied",
            "account_status=suspended",
            "account is suspended",
        )),
        "deactivated" => Some((
            StatusCode::CONFLICT,
            "failed_precondition",
            "principal_deactivated (account_status=deactivated)",
            "account has been deactivated",
        )),
        "erased" => Some((
            StatusCode::CONFLICT,
            "failed_precondition",
            "principal_deactivated (account_status=erased)",
            "account has been erased",
        )),
        _ => None,
    }
}

/// Spec: A.3 — auth handlers consult the in-memory failed-login counter
/// before doing any other work. The lockout response is 403
/// `policy_denied` (registry code; lifecycle detail travels in
/// `error.details.reason_detail`) with a wire body that doesn't reveal
/// which credential failed, only that the actor is currently locked.
fn account_lockout_error(state: &AppState, actor: &str) -> Option<AppError> {
    let until = state.account_lockout_active_until(actor)?;
    let until_wire = until.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    Some(
        AppError::capability_denied(format!(
            "account temporarily locked due to repeated failed auth attempts; \
             retry after {until_wire}"
        ))
        .with_status(StatusCode::FORBIDDEN)
        .with_wire_code("policy_denied")
        .with_reason_detail("account_status=locked (failed-login lockout)"),
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
    // a policy denial and MUST surface as 403 with the registry code
    // `policy_denied`.
    //
    // `erased` is the exception kept at 401: erasure invalidates the
    // bearer itself, so re-auth is the right signal — registry code
    // `unauthenticated` ("authentication material is missing or invalid").
    match state.account_lifecycle_state(actor).as_str() {
        "locked" => Some((StatusCode::FORBIDDEN, "policy_denied", "account is locked")),
        "deactivated" => Some((
            StatusCode::FORBIDDEN,
            "policy_denied",
            "account has been deactivated",
        )),
        "erased" => Some((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
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
) -> JsonResult<SessionLoginOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    if !state.config.development_mode {
        return Err(AppError::not_found("endpoint not available"));
    }
    let body = body.into_inner();
    let actor = validate_did(&body.actor);
    let device_id = validate_device_id(&body.device_id);
    let (actor, device_id) = match (actor, device_id) {
        (Ok(actor), Ok(device_id)) => (actor, device_id),
        _ => {
            return Err(AppError::invalid_param(
                "actor must be a DID and device_id is required",
            ));
        }
    };
    let actor_str = actor.as_str();
    let device_id_str = device_id.as_str();
    if device_id_str.trim().is_empty() {
        return Err(AppError::invalid_param(
            "actor must be a DID and device_id is required",
        ));
    }
    crate::routing::extensions::sovereign::validate_sovereign_did_registration(state, actor_str)?;
    // Spec: A.3 — auth handlers consult the in-memory failed-login
    // counter before doing anything else. An actor that crossed the
    // threshold gets a 403 `policy_denied` (lockout) until the lockout window
    // expires, without revealing whether the credential would otherwise
    // have been valid.
    if let Some(error) = account_lockout_error(state, actor_str) {
        return Err(error);
    }
    let account = state
        .persistence
        .accounts()
        .get(actor_str)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if let Some(error) = account_new_session_error(state, actor_str) {
        return Err(error);
    }
    if account.is_none() {
        let synthetic_handle = handle_for_did(actor_str);
        let synthetic_display = body
            .display_name
            .clone()
            .unwrap_or_else(|| synthetic_handle.trim_start_matches('@').to_owned());
        let record = AccountRecord {
            id: crate::ids::generate_account_id(),
            did: actor_str.to_owned(),
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
            Some(actor_str),
            "account.register",
            json!({"handle": record.handle(), "via": "dev_login"}),
            "accepted",
        )
        .await;
    }

    let expires_at = now() + Duration::hours(12);
    let token = token_for(actor_str, device_id_str, expires_at.timestamp_millis());
    let token_hash = session_token_hash(&token, &state.config.service_did);
    let session = SessionRecord {
        token_hash,
        actor: actor_str.to_owned(),
        device_id: device_id_str.to_owned(),
        audience: state.config.service_did.clone(),
        // dev-login does not carry a ck.session.grant signing key; bearer-only.
        session_public_key: None,
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
    let existing_devices = state
        .persistence
        .devices()
        .list_for_actor(actor_str)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let verification_state =
        initial_session_device_verification_state(&existing_devices, device_id_str);
    let device_payload = json!({
        "device_id": device_id_str,
        "display_name": body.display_name.clone(),
        "verification": verification_state,
        "last_seen_at": seen_at
    });
    let device = DeviceInventoryRecord {
        actor: actor_str.to_owned(),
        device_id: device_id_str.to_owned(),
        display_name: body.display_name.clone(),
        verification_state: verification_state.to_owned(),
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
        Some(actor_str),
        "auth.dev_login",
        json!({"device_id": device_id_str}),
        "accepted",
    )
    .await;
    state.clear_failed_login(actor_str);

    json_ok(SessionLoginOutcome {
        access_token: token,
        token_type: "Bearer".to_owned(),
        actor: actor.clone(),
        device_id: device_id.clone(),
        expires_at,
    })
}

#[endpoint(
    operation_id = "ck.gate.account.command.issue_session_grant",
    tags("auth"),
    summary = "Issue a principal bearer session from a coauth session-grant proof"
)]
#[tracing::instrument(skip_all, fields(op = "ck.gate.account.command.issue_session_grant"))]
async fn exchange_session_grant(
    depot: &mut Depot,
    body: JsonBody<SessionGrantExchangeRequestBody>,
) -> JsonResult<SessionLoginOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    let principal_id = body.principal_id;
    let device_id = body.device_id;
    let principal_id_str = principal_id.as_str();
    let device_id_str = device_id.as_str();
    if body.grant_jwt.trim().is_empty() {
        return Err(AppError::invalid_param(
            "grant_jwt, principal_id, and device_id are required",
        ));
    }
    if let Some(error) = account_lockout_error(state, principal_id_str) {
        return Err(error);
    }
    let account = state
        .persistence
        .accounts()
        .get(principal_id_str)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if account.is_none() {
        return Err(AppError::not_found("account is not registered"));
    }
    if let Some(error) = account_new_session_error(state, principal_id_str) {
        return Err(error);
    }

    let grant = match validate_session_grant_binding(
        state,
        SessionGrantValidationInput {
            grant_jwt: body.grant_jwt.as_str(),
            principal_id: principal_id_str,
            device_id: device_id_str,
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
            record_failed_login_attempt(state, principal_id_str, "session_grant_exchange").await;
            return Err(error);
        }
    };
    // The principal session grant is the (minutes-to-hours, audience-bound)
    // refresh credential; the access bearer minted from it is a SHORT-lived
    // access token. Decouple the two: cap the bearer at SHORT_BEARER_TTL but
    // never let it outlive the grant. The client silently re-exchanges the
    // still-valid grant for a fresh short bearer (every <TTL), so the session
    // lives for the grant's full lifetime without ever holding a long-lived
    // bearer. (Previously the bearer inherited the grant's expiry verbatim,
    // which both produced long-lived bearers when grants are long and — with a
    // 5-minute grant — bounced the user to login every 5 minutes.)
    let grant_expires_at = grant
        .as_ref()
        .map(|grant| grant.expires_at)
        .unwrap_or_else(|| now() + Duration::hours(12));
    let expires_at = capped_bearer_expiry(grant_expires_at, now());
    let token = token_for(
        principal_id_str,
        device_id_str,
        expires_at.timestamp_millis(),
    );
    let token_hash = session_token_hash(&token, &state.config.service_did);
    let session = SessionRecord {
        token_hash,
        actor: principal_id_str.to_owned(),
        device_id: device_id_str.to_owned(),
        audience: state.config.service_did.clone(),
        session_public_key: grant
            .as_ref()
            .and_then(|grant| grant.session_public_key.clone()),
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
    let existing_devices = state
        .persistence
        .devices()
        .list_for_actor(principal_id_str)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let verification_state =
        initial_session_device_verification_state(&existing_devices, device_id_str);
    let device_public_key = validated_session_device_public_key(body.device_public_key.as_deref())?;
    let mut device_payload = json!({
        "device_id": device_id_str,
        "display_name": body.display_name.clone(),
        "verification": verification_state,
        "last_seen_at": seen_at,
        "session_grant_bridge": true,
    });
    if let Some(device_public_key) = device_public_key {
        device_payload["device_public_key"] = Value::String(device_public_key);
    }
    let device = DeviceInventoryRecord {
        actor: principal_id_str.to_owned(),
        device_id: device_id_str.to_owned(),
        display_name: body.display_name.clone(),
        verification_state: verification_state.to_owned(),
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
        Some(principal_id_str),
        "auth.session_grant_exchange",
        json!({
            "device_id": device_id_str,
            "grant_bridge": true,
            "coauth_introspection": grant.is_some(),
            "one_time_use_consumed": grant.as_ref().map(|grant| grant.one_time_use_consumed).unwrap_or(false),
        }),
        "accepted",
    )
    .await;
    state.clear_failed_login(principal_id_str);

    json_ok(SessionLoginOutcome {
        access_token: token,
        token_type: "Bearer".to_owned(),
        actor: principal_id.clone(),
        device_id: device_id.clone(),
        expires_at,
    })
}

// Session-grant introspection wire types come from the SDK
// (`SessionGrantIntrospectRequestBody` / `SessionGrantIntrospectOutcome` /
// `SessionGrantIntrospectStatus`), so this caller binds to the same strong
// types the spec/OpenAPI declare instead of hand-rolled structs.

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
    /// Session signing key (JWK) for RFC 9421 PoP verification, when the
    /// introspection bridge supplied it (SPEC-CR-001).
    pub session_public_key: Option<String>,
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
    let request = SessionGrantIntrospectRequestBody {
        id: None,
        grant_jwt: Some(input.grant_jwt.to_owned()),
        audience: Some(state.config.service_did.as_str().to_owned()),
        proof: input.proof.cloned(),
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
        .json::<SessionGrantIntrospectOutcome>()
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::TemporarilyUnavailable,
                format!("invalid session grant introspection response: {error}"),
            )
        })?;
    if !response.active || response.status != SessionGrantIntrospectStatus::Active {
        // Preserve the snake_case wire status in the message (e.g. "revoked")
        // rather than the Debug form, so downstream callers see the same token.
        let status_wire = serde_json::to_value(response.status)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| "unknown".to_owned());
        return Err(AppError::capability_denied(format!(
            "session grant is not active: {status_wire}"
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
        session_public_key: Some(grant.session_public_key),
    }))
}

#[endpoint(
    operation_id = "ck.gate.account.command.logout",
    tags("auth"),
    summary = "Principal Server device logout: revoke bearer + device session record + to-device"
)]
#[tracing::instrument(skip_all, fields(op = "ck.gate.account.command.logout"))]
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

/// `POST /_cokret/gate/account/session-grants/revoke` — spec
/// `ck.gate.account.command.revoke_session` (surface group `account_auth`).
///
/// Spec: sync/service-http-binding.md — the body MAY be omitted (revoke the
/// calling session); `target_grant_id` / `target_device_id` /
/// `all_sessions=true` are mutually exclusive selectors and the target MUST
/// belong to the calling principal. Revokes session grants / bearer
/// sessions only — device authorization is NOT touched and no
/// `ck.account.status` write happens implicitly. Cross-session selectors
/// require a fresh lifecycle proof; cryptographic verification of that
/// proof is future work (cf. the device-pairing scaffolds), presence is
/// enforced here.
#[endpoint(
    operation_id = "ck.gate.account.command.revoke_session",
    tags("auth"),
    summary = "Revoke session grants / bearer sessions for the calling principal",
    status_codes(200, 400, 401, 403, 404, 422, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.gate.account.command.revoke_session"))]
async fn session_revoke(
    aa: super::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SessionRevokeOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    // The empty-body form is valid, so parse by hand instead of `JsonBody`
    // (which answers a missing body with a 400 before the handler runs).
    let body: SessionRevokeRequestBody = match req.payload().await {
        Ok(bytes) if !bytes.is_empty() => serde_json::from_slice(bytes)
            .map_err(|error| AppError::bad_json(format!("invalid session-revoke body: {error}")))?,
        _ => SessionRevokeRequestBody {
            target_grant_id: None,
            target_device_id: None,
            all_sessions: None,
            proof: None,
        },
    };
    if body.all_sessions == Some(false) {
        // Schema pins `all_sessions` to `const true`; `false` is a shape error.
        return Err(AppError::invalid_param(
            "all_sessions must be true when present",
        ));
    }
    let selector_count = usize::from(body.target_grant_id.is_some())
        + usize::from(body.target_device_id.is_some())
        + usize::from(body.all_sessions == Some(true));
    if selector_count > 1 {
        return Err(AppError::new(
            ErrorCode::SessionRevokeSelectorConflict,
            "target_grant_id, target_device_id and all_sessions are mutually exclusive",
        ));
    }
    if selector_count == 1 && body.proof.is_none() {
        // Spec: revoking anything beyond the calling session needs a fresh
        // DID/device proof or an explicit capability.
        return Err(AppError::capability_denied(
            "cross-session revoke requires a lifecycle proof",
        ));
    }
    let revoked_at = now();
    let revoked_count: usize = if body.all_sessions == Some(true) {
        revoke_sessions_for_actor(state, &session.actor)
            .await
            .map_err(AppError::internal)?
    } else if let Some(target_device_id) = body.target_device_id.as_ref() {
        // Sessions are filtered by the calling actor, so a device owned by
        // another principal can never be revoked through this path.
        let sessions = state
            .persistence
            .sessions()
            .snapshot_all()
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        let mut count = 0usize;
        for mut record in sessions.into_iter().filter(|record| {
            record.actor == session.actor
                && record.device_id == target_device_id.as_str()
                && record.revoked_at.is_none()
        }) {
            record.revoked_at = Some(revoked_at);
            state
                .persistence
                .sessions()
                .put(&record)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            count += 1;
        }
        count
    } else if body.target_grant_id.is_some() {
        // Session grants are issued by coauth; soland only ever sees the
        // grant JWT during the exchange and keeps no grant_id -> session
        // mapping, so a grant-addressed revoke cannot resolve here.
        return Err(AppError::not_found("unknown session grant"));
    } else {
        // No selector: revoke the calling session only. Unlike `logout`,
        // device authorization stays untouched per the spec contract.
        match state
            .persistence
            .sessions()
            .get(&session.token_hash)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
        {
            Some(mut record) if record.revoked_at.is_none() => {
                record.revoked_at = Some(revoked_at);
                state
                    .persistence
                    .sessions()
                    .put(&record)
                    .await
                    .map_err(|error| AppError::internal(error.to_string()))?;
                1
            }
            _ => 0,
        }
    };
    append_audit_log(
        state,
        Some(&session.actor),
        "auth.session_revoke",
        json!({
            "all_sessions": body.all_sessions == Some(true),
            "target_device_id": body.target_device_id.as_ref().map(|device| device.as_str().to_owned()),
            "revoked_count": revoked_count,
        }),
        "accepted",
    )
    .await;
    json_ok(SessionRevokeOutcome {
        revoked_count: revoked_count as u64,
        revoked_grant_ids: Vec::new(),
    })
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
    )
    .await?;
    let oauth = parse_oauth_introspection(&value)?;
    ensure_oauth_account(state, &oauth).await?;
    if let Some((status, code, _reason_detail, message)) =
        account_new_session_tuple(state, &oauth.actor)
    {
        return Err((status, code, message));
    }
    ensure_oauth_device(state, &oauth).await?;

    Ok(SessionRecord {
        token_hash,
        actor: oauth.actor,
        device_id: oauth.device_id,
        audience: state.config.service_did.clone(),
        // OAuth-bridged sessions are bearer-only (no ck.session.grant PoP key).
        session_public_key: None,
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
const OAUTH_INTROSPECTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const OAUTH_INTROSPECTION_MIN_LATENCY: std::time::Duration = std::time::Duration::from_millis(40);
const OAUTH_INTROSPECTION_JITTER_MAX: std::time::Duration = std::time::Duration::from_millis(20);

async fn request_oauth_introspection(
    introspection_url: &str,
    introspection_bearer: &str,
    token: &str,
    development_mode: bool,
) -> Result<Value, (StatusCode, &'static str, &'static str)> {
    let started = tokio::time::Instant::now();
    let jitter_micros = jitter_micros(OAUTH_INTROSPECTION_JITTER_MAX);
    let result = perform_oauth_introspection(
        introspection_url,
        introspection_bearer,
        token,
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
    let floor = OAUTH_INTROSPECTION_MIN_LATENCY + std::time::Duration::from_micros(jitter_micros);
    let elapsed = started.elapsed();
    if elapsed < floor {
        tokio::time::sleep(floor - elapsed).await;
    }
    result
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

/// Sample a small jitter in microseconds for the introspection constant-time
/// floor. We pull from `rand::OsRng` rather than a fast PRNG so the floor
/// itself is not predictable from an external observer.
fn jitter_micros(max: std::time::Duration) -> u64 {
    use rand::RngExt;
    let max_micros = max.as_micros().min(u128::from(u64::MAX)) as u64;
    if max_micros == 0 {
        return 0;
    }
    let mut buf = [0u8; 8];
    rand::rng().fill(&mut buf);
    u64::from_le_bytes(buf) % max_micros
}

fn parse_oauth_introspection(
    value: &Value,
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

    // Device binding MUST come from the introspected `org.cokret.device_id`
    // claim (carried by the OAuth `urn:cokret:client:device:<id>` scope). It is
    // the stable protocol device identity (`ck:device:<uuid>`). We MUST NOT
    // fabricate one from the token (jti/session_id): a per-token derived id
    // drifts on every refresh and silently breaks every device-scoped binding
    // (sync cursor principal/device match, key-backup writer authorization).
    // Fail closed instead — a token with no valid device binding is not a
    // device session and cannot drive `/_cokret/self/*`.
    let raw_device_id = string_field(value, "org.cokret.device_id")
        .or_else(|| string_field(value, "device_id"))
        .map(str::to_owned);
    let device_id = raw_device_id
        .as_deref()
        .filter(|device_id| validate_device_id(device_id).is_ok())
        .map(str::to_owned)
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "OAuth introspection response carried no valid device binding (org.cokret.device_id); session is not device-bound",
        ))?;
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

    // Bootstrap exception (crypto-media/device-lifecycle.md §5.3): a device that
    // first appears for an account with no other device is the inception device
    // and self-authorizes; any additional device while others exist stays
    // `unverified` until an authorized device approves it. This is the same rule
    // the session paths apply via `initial_session_device_verification_state`,
    // so the OAuth-introspection lazy-create path honours it too — otherwise the
    // founding device of a fresh account is left permanently unauthorized with
    // no device able to approve it.
    let existing_devices = devices.list_for_actor(&oauth.actor).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "device store unavailable",
        )
    })?;
    let verification_state =
        initial_session_device_verification_state(&existing_devices, &oauth.device_id);
    let seen_at = now();
    let device = DeviceInventoryRecord {
        actor: oauth.actor.clone(),
        device_id: oauth.device_id.clone(),
        display_name: oauth.display_name.clone(),
        verification_state: verification_state.to_owned(),
        payload: json!({
            "device_id": oauth.device_id.clone(),
            "display_name": oauth.display_name.clone(),
            "verification": verification_state,
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

fn short_hex(bytes: &[u8], len: usize) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest).chars().take(len).collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_expiry_is_capped_short_and_never_outlives_grant() {
        let now = DateTime::parse_from_rfc3339("2026-06-15T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        // Long (8h) grant → bearer capped at the short 15-minute TTL, so a long
        // refresh credential never yields a long-lived access bearer.
        let long_grant = now + Duration::hours(8);
        assert_eq!(
            capped_bearer_expiry(long_grant, now),
            now + Duration::minutes(SHORT_BEARER_TTL_MINUTES),
        );

        // Grant nearer than the short TTL → bearer never outlives the grant.
        let near_grant = now + Duration::minutes(3);
        assert_eq!(capped_bearer_expiry(near_grant, now), near_grant);
    }
}
