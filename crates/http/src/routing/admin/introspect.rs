//! Per-scope admin gating via SDK
//! [`arkret_models_identity::admin_grant::SessionGrantIntrospection`].
//!
//! The SDK provides a typed view of an OAuth-style introspection
//! response carrying `(principal_id, admin_scopes, expires_at,
//! device_id)`. This module wires that into soland:
//!
//! 1. [`introspect_admin_scopes`] talks to the configured `session_grant_introspection_url` over
//!    HTTP, returning the typed [`SessionGrantIntrospection`]. Results are cached per-token-hash
//!    with a short TTL so a single admin request doesn't fan out into multiple introspection calls.
//!
//! 2. [`require_admin_scope`] is the production-mode gate: it introspects the caller's bearer token
//!    and rejects the request unless the granted `admin_scopes` include the requested scope.
//!
//! In `development_mode` (no introspection URL configured) the helpers
//! return a synthetic introspection asserting every well-known admin
//! scope for any DID in `admin_principal_dids` — keeps local smoke
//! tests working without an IdP dependency.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use arkret_identifiers::DidCoreId;
use arkret_models_collaboration::session_grant_bodies::{
    SessionGrantIntrospectOutcome, SessionGrantIntrospectRequestBody, SessionGrantIntrospectStatus,
};
use arkret_models_identity::admin_grant::{
    SessionGrantAdminIntrospectionStatus, SessionGrantIntrospection,
};
use parking_lot::Mutex;
use salvo::http::StatusCode;
use salvo::prelude::Request;
use soland_http::error::{AppError, ErrorCode};
use soland_services::identity::SessionIdentityState as SessionRecord;

use crate::state::AppState;

const INTROSPECTION_CACHE_TTL: Duration = Duration::from_secs(30);
const INTROSPECTION_CACHE_MAX_ENTRIES: usize = 1024;

struct CacheEntry {
    grant: SessionGrantIntrospection,
    inserted_at: Instant,
}

fn cache() -> &'static Mutex<HashMap<String, CacheEntry>> {
    static CACHE: OnceLock<Mutex<HashMap<String, CacheEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn read_cached(token_hash: &str) -> Option<SessionGrantIntrospection> {
    let mut cache = cache().lock();
    prune_cache_locked(&mut cache, Instant::now());
    let entry = cache.get(token_hash)?;
    if entry.inserted_at.elapsed() > INTROSPECTION_CACHE_TTL {
        return None;
    }
    Some(entry.grant.clone())
}

fn cache_grant(token_hash: String, grant: SessionGrantIntrospection) {
    {
        let mut cache = cache().lock();
        prune_cache_locked(&mut cache, Instant::now());
        while cache.len() >= INTROSPECTION_CACHE_MAX_ENTRIES {
            let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.inserted_at)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            cache.remove(&oldest_key);
        }
        cache.insert(
            token_hash,
            CacheEntry {
                grant,
                inserted_at: Instant::now(),
            },
        );
    }
}

fn prune_cache_locked(cache: &mut HashMap<String, CacheEntry>, now: Instant) {
    cache.retain(|_, entry| now.duration_since(entry.inserted_at) < INTROSPECTION_CACHE_TTL);
}

fn session_grant_status_wire(status: SessionGrantIntrospectStatus) -> String {
    serde_json::to_value(status)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

fn admin_grant_from_introspection_outcome(
    outcome: SessionGrantIntrospectOutcome,
) -> Result<SessionGrantIntrospection, AppError> {
    if !outcome.active || outcome.status != SessionGrantIntrospectStatus::Active {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            format!(
                "admin scope introspection returned inactive grant: {}",
                session_grant_status_wire(outcome.status)
            ),
        )
        .with_status(StatusCode::FORBIDDEN));
    }

    let grant = outcome.grant.ok_or_else(|| {
        AppError::new(
            ErrorCode::CapabilityDenied,
            "admin scope introspection omitted grant metadata".to_owned(),
        )
        .with_status(StatusCode::FORBIDDEN)
    })?;
    let principal_id =
        arkret_identifiers::DidCoreId::new(grant.subject.clone()).map_err(|error| {
            AppError::new(
                ErrorCode::CapabilityDenied,
                format!("admin scope introspection returned invalid subject DID: {error}"),
            )
            .with_status(StatusCode::FORBIDDEN)
        })?;

    Ok(SessionGrantIntrospection {
        active: true,
        status: SessionGrantAdminIntrospectionStatus::Active,
        principal_id,
        admin_scopes: grant.scopes,
        expires_at: Some(arkret_canonical::normalize_timestamp_canonical(
            grant.expires_at,
        )),
        device_id: grant
            .device_id
            .map(|device_id| device_id.as_str().to_owned()),
        audit_context: serde_json::json!({
            "source": "ak.gate.account.command.introspect_session_grant",
            "grant_id": grant.id.as_str(),
            "audience": grant.audience,
        }),
    })
}

/// Pull the raw bearer token from the request's `Authorization` header.
fn bearer_token_from_request(req: &Request) -> Option<String> {
    let header = req.headers().get(salvo::http::header::AUTHORIZATION)?;
    let value = header.to_str().ok()?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?;
    Some(token.trim().to_owned())
}

/// Synthetic introspection used in development mode when no upstream IdP
/// is configured. Grants every well-known admin scope to any DID listed
/// in `admin_principal_dids` (or any DID in development_mode).
fn synthetic_dev_grant(state: &AppState, session: &SessionRecord) -> SessionGrantIntrospection {
    use arkret_models_identity::admin_grant::admin_scopes::*;
    let scopes = vec![
        NOTARY_RECONFIGURE.to_owned(),
        SEAL_COMPACT.to_owned(),
        SEAL_PRUNE.to_owned(),
        BOTTOM_REPAIR.to_owned(),
        ADMIN_READ.to_owned(),
    ];
    let principal_id =
        arkret_identifiers::DidCoreId::new(session.actor.clone()).unwrap_or_else(|_| {
            // Dev-login actors may be handles rather than full DIDs. Reuse the
            // configured, verified service full_id; never reconstruct one from
            // the service core_id.
            arkret_identifiers::DidCoreId::new(state.service_id().clone())
                .expect("configured service id is a validated core id")
        });
    SessionGrantIntrospection {
        active: true,
        status: SessionGrantAdminIntrospectionStatus::Active,
        principal_id,
        admin_scopes: scopes,
        expires_at: Some(arkret_canonical::normalize_timestamp_canonical(
            session.expires_at,
        )),
        device_id: Some(session.device_id.clone()),
        audit_context: serde_json::json!({ "synthetic": "development_mode" }),
    }
}

/// Resolve the caller's [`SessionGrantIntrospection`]. Development mode
/// uses a local synthetic grant even when the joint harness also wires a
/// coauth introspection URL; dev-login bearers are local soland sessions,
/// not upstream session-grant tokens. Production mode POSTs the caller's
/// bearer token to `session_grant_introspection_url`.
pub(crate) async fn introspect_admin_scopes(
    state: &AppState,
    req: &Request,
    session: &SessionRecord,
) -> Result<SessionGrantIntrospection, AppError> {
    if state.config().development_mode {
        return Ok(synthetic_dev_grant(state, session));
    }

    let Some(url) = state.config().session_grant_introspection_url.as_deref() else {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "admin scope check requires SOLAND_SESSION_GRANT_INTROSPECTION_URL outside development mode"
                .to_owned(),
        )
        .with_status(StatusCode::FORBIDDEN));
    };

    // Cache hit — short-circuit the network call. The token_hash is
    // already a sha256-derived opaque id so it's a stable cache key.
    if let Some(grant) = read_cached(&session.token_hash) {
        return Ok(grant);
    }

    let token = bearer_token_from_request(req).ok_or_else(|| {
        AppError::new(
            ErrorCode::Unauthenticated,
            "missing or malformed Authorization header for admin scope check".to_owned(),
        )
        .with_status(StatusCode::UNAUTHORIZED)
    })?;
    let audience = DidCoreId::new(state.service_id().clone()).map_err(|error| {
        AppError::internal(format!(
            "runtime principal service_id is not a core_id: {error}"
        ))
    })?;
    let request = SessionGrantIntrospectRequestBody::ByJwt(
        arkret_models_collaboration::session_grant_bodies::SessionGrantIntrospectByJwt {
            grant_jwt: token,
            audience: Some(audience),
            proof: None,
        },
    );
    let bearer = state
        .config()
        .session_grant_introspection_bearer
        .as_deref()
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::InternalError,
                "session grant introspection requires SOLAND_SESSION_GRANT_INTROSPECTION_BEARER"
                    .to_owned(),
            )
        })?;

    // SOL-03-002: pin validated IPs into the client to close the DNS-rebinding
    // TOCTOU window between the egress check and the connection.
    let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        url,
        "admin session grant introspection",
        state.config().development_mode,
        Duration::from_secs(10),
    )
    .map_err(AppError::capability_denied)?;
    let response = client
        .post(url)
        .bearer_auth(bearer)
        .json(&request)
        .send()
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::TemporarilyUnavailable,
                format!("admin scope introspection request failed: {error}"),
            )
        })?;
    if !response.status().is_success() {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            format!(
                "admin scope introspection rejected by IdP: HTTP {}",
                response.status()
            ),
        )
        .with_status(StatusCode::FORBIDDEN));
    }
    let outcome = response
        .json::<SessionGrantIntrospectOutcome>()
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::TemporarilyUnavailable,
                format!("invalid admin scope introspection response: {error}"),
            )
        })?;
    let grant = admin_grant_from_introspection_outcome(outcome)?;

    let now_unix = chrono::Utc::now().timestamp();
    if !grant.is_currently_active(now_unix) {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "admin scope introspection returned an inactive grant".to_owned(),
        )
        .with_status(StatusCode::FORBIDDEN));
    }

    cache_grant(session.token_hash.clone(), grant.clone());
    Ok(grant)
}

/// Gate the calling admin operation on a specific scope. Production
/// strand: introspect the bearer, ensure the grant carries `scope`. Dev
/// strand: synthetic grant accepts every well-known scope.
pub(crate) async fn require_admin_scope(
    state: &AppState,
    req: &Request,
    session: &SessionRecord,
    scope: &str,
) -> Result<SessionGrantIntrospection, AppError> {
    let grant = introspect_admin_scopes(state, req, session).await?;
    if !grant.has_admin_scope(scope) {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            format!(
                "admin scope `{scope}` not granted to {}",
                grant.principal_id
            ),
        )
        .with_status(StatusCode::FORBIDDEN));
    }
    Ok(grant)
}
