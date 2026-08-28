//! `/_arkret/self/*` inbound credential: `ak.session.grant` + DPoP (RFC 9449).
//!
//! Per api-conventions.md §3.3 the Principal Server (soland) no longer mints a
//! local credential from a session grant. The client
//! presents the `ak.session.grant` directly on every `/_arkret/self/*` request
//! as `Authorization: DPoP <ak.session.grant>` plus a sender-constrained
//! `DPoP` proof. soland validates and serves; the resulting `SessionRecord` is
//! request-scoped and is NEVER persisted as a local bearer.
//!
//! Validation pipeline (any failure → `unauthenticated`, fail closed):
//!   1. grant active via session-grant introspection at coauth, with a small TTL (≤120s) cache
//!      keyed by the presented grant; sensitive operations bypass the cache and force a fresh
//!      introspection.
//!   2. DPoP signature valid against the grant's `cnf.jkt` (JWK SHA-256 thumbprint, RFC 7638) read
//!      from the introspection result.
//!   3. DPoP `htm` == request method, `htu` == request URL, `ath` == base64url(sha256(grant)).
//!   4. DPoP `jti` + `iat` freshness window for replay defense.
//!   5. grant audience == this service's `service_id`.
//!   6. human grants carry the exact typed holder/device binding; agent grants carry current
//!      runtime-key authorization metadata. Grant not expired.
//!
//! DPoP does NOT bind the request body — body integrity rides on TLS, same as
//! Matrix (api-conventions.md §3.3). Body-bound integrity is layered separately
//! by the RFC 9421 PoP hoop (`session_pop`).

use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::{Duration as StdDuration, Instant};

use arkret_identifiers::{DeviceId, DidCoreId};
use arkret_models_collaboration::session_grant_bodies::SessionGrantIntrospectByJwt;
use arkret_models_identity::session_credential::SessionGrantHolderBinding;
use arkret_wire::FreshnessState;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use parking_lot::Mutex;
use salvo::http::StatusCode;
use salvo::prelude::Request;
use sha2::{Digest, Sha256};
use soland_services::identity::{
    AgentSessionState as AgentSessionRecord, SessionGrantAuthorizationState,
    SessionIdentityState as SessionRecord,
};

use crate::state::AppState;
use crate::wire::{
    SessionGrantIntrospectGrant, SessionGrantIntrospectOutcome, SessionGrantIntrospectRequestBody,
    SessionGrantIntrospectStatus,
};

/// Device-scope prefix carried in a `ak.session.grant`'s scope set
/// (`urn:arkret:client:device:<device_id>`). A grant that drives
/// `/_arkret/self/*` MUST carry one so the request is device-bound.
/// TTL for the session-grant introspection cache (api-conventions.md §3.3 D2:
/// SHOULD ≤ 120s). The revocation-visibility upper bound equals this TTL;
/// sensitive operations bypass the cache entirely (`force_fresh`).
const INTROSPECTION_CACHE_TTL: StdDuration = StdDuration::from_secs(120);
const INTROSPECTION_CACHE_MAX_ENTRIES: usize = 4096;
const INTROSPECTION_HTTP_CLIENT_TTL: StdDuration = StdDuration::from_secs(300);
const INTROSPECTION_HTTP_CLIENT_MAX_ENTRIES: usize = 32;

/// DPoP proof freshness window. The proof's `iat` MUST be within
/// [now - WINDOW, now + skew]; combined with single-use `jti` tracking this
/// bounds replay to the same scale as the §3.2 / federation PoP windows.
const DPOP_MAX_AGE_SECONDS: i64 = 300;
const DPOP_MAX_FUTURE_SKEW_SECONDS: i64 = 30;
const DPOP_REPLAY_MAX_ENTRIES: usize = 50_000;

type AuthError = (StatusCode, &'static str, &'static str);

fn unauthenticated(message: &'static str) -> AuthError {
    (StatusCode::UNAUTHORIZED, "unauthenticated", message)
}

fn configured_service_audience(state: &AppState) -> Result<DidCoreId, AuthError> {
    DidCoreId::new(state.service_id().clone()).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "auth_misconfigured",
            "runtime principal service_id is not a core_id",
        )
    })
}

// ── Introspection cache ──────────────────────────────────────────────────────

#[derive(Clone)]
struct CachedIntrospection {
    grant: SessionGrantIntrospectGrant,
    inserted_at: Instant,
}

/// Process-local introspection cache. Same in-memory trade-off as the other
/// soland reducer projections (`handle_releases`, `account_lifecycle`): a
/// restart drops the cache and the next request re-introspects. Keyed by a
/// service-DID-bound hash of the presented grant so cross-audience grants never
/// collide.
static INTROSPECTION_CACHE: LazyLock<Mutex<HashMap<String, CachedIntrospection>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Clone)]
struct CachedIntrospectionHttpClient {
    url: reqwest::Url,
    client: reqwest::Client,
    inserted_at: Instant,
}

/// Reuse the connection pool for the configured Auth Server instead of
/// constructing a fresh reqwest client for every force-fresh introspection.
///
/// Sensitive self operations intentionally bypass the grant-result cache, so a
/// long-lived process can perform thousands of remote introspections. Creating
/// one client per request disables keep-alive and can exhaust ephemeral ports
/// under a full conformance run. The cache is bounded and keyed by the complete
/// configured URL plus the private-network posture; each cached client remains
/// pinned to the addresses that passed the egress guard when it was built.
static INTROSPECTION_HTTP_CLIENTS: LazyLock<Mutex<HashMap<String, CachedIntrospectionHttpClient>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn introspection_cache_key(grant_jwt: &str, audience: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(audience.as_bytes());
    hasher.update(b":");
    hasher.update(grant_jwt.as_bytes());
    format!(
        "grant-introspect:{}",
        URL_SAFE_NO_PAD.encode(hasher.finalize())
    )
}

fn cache_lookup(key: &str) -> Option<SessionGrantIntrospectGrant> {
    let mut cache = INTROSPECTION_CACHE.lock();
    prune_introspection_cache_locked(&mut cache, Instant::now());
    match cache.get(key) {
        Some(entry) if entry.inserted_at.elapsed() < INTROSPECTION_CACHE_TTL => {
            Some(entry.grant.clone())
        }
        Some(_) => {
            cache.remove(key);
            None
        }
        None => None,
    }
}

fn cache_store(key: String, grant: SessionGrantIntrospectGrant) {
    {
        let mut cache = INTROSPECTION_CACHE.lock();
        prune_introspection_cache_locked(&mut cache, Instant::now());
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
            key,
            CachedIntrospection {
                grant,
                inserted_at: Instant::now(),
            },
        );
    }
}

fn prune_introspection_cache_locked(
    cache: &mut HashMap<String, CachedIntrospection>,
    now: Instant,
) {
    cache.retain(|_, entry| now.duration_since(entry.inserted_at) < INTROSPECTION_CACHE_TTL);
}

fn introspection_http_client(
    raw_url: &str,
    development_mode: bool,
) -> Result<(reqwest::Url, reqwest::Client), String> {
    let cache_key = introspection_http_client_cache_key(raw_url, development_mode);
    let mut clients = INTROSPECTION_HTTP_CLIENTS.lock();
    let reusable = clients
        .get(&cache_key)
        .filter(|cached| cached.inserted_at.elapsed() < INTROSPECTION_HTTP_CLIENT_TTL)
        .map(|cached| (cached.url.clone(), cached.client.clone()));
    if let Some(cached) = reusable {
        return Ok(cached);
    }
    clients.remove(&cache_key);

    let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        raw_url,
        "session grant introspection",
        development_mode,
        StdDuration::from_secs(10),
    )?;
    while clients.len() >= INTROSPECTION_HTTP_CLIENT_MAX_ENTRIES {
        let Some(oldest_key) = clients
            .iter()
            .min_by_key(|(_, cached)| cached.inserted_at)
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        clients.remove(&oldest_key);
    }
    clients.insert(
        cache_key,
        CachedIntrospectionHttpClient {
            url: url.clone(),
            client: client.clone(),
            inserted_at: Instant::now(),
        },
    );
    Ok((url, client))
}

fn introspection_http_client_cache_key(raw_url: &str, development_mode: bool) -> String {
    let private_networks_allowed = crate::security::private_networks_allowed(development_mode);
    format!("{raw_url}\nprivate_networks={private_networks_allowed}")
}

fn invalidate_introspection_http_client(raw_url: &str, development_mode: bool) {
    let cache_key = introspection_http_client_cache_key(raw_url, development_mode);
    INTROSPECTION_HTTP_CLIENTS.lock().remove(&cache_key);
}

/// Drop any cached introspection entry for `grant_jwt`. Called by logout so the
/// next introspection of that grant goes to coauth and observes `active=false`
/// (account-lifecycle.md §4.1 step 3 — the local-side invalidation).
pub(crate) fn invalidate_cached_grant(state: &AppState, grant_jwt: &str) {
    let key = introspection_cache_key(grant_jwt, state.service_id());
    {
        let mut cache = INTROSPECTION_CACHE.lock();
        cache.remove(&key);
    }
}

/// Reusable coauth session-grant introspection with the ≤120s TTL cache.
///
/// `force_fresh = true` bypasses the cache (sensitive operations, §3.3 D2) and
/// re-introspects against coauth, refreshing the cached value on success.
/// Returns the active grant's full metadata (subject / device_id / audience /
/// scopes / expiry / session_public_key / cnf_jkt). An inactive / unknown grant
/// is an `unauthenticated` error, not `Ok(None)`.
pub(crate) async fn introspect_session_grant_cached(
    state: &AppState,
    grant_jwt: &str,
    force_fresh: bool,
) -> Result<SessionGrantIntrospectGrant, AuthError> {
    let key = introspection_cache_key(grant_jwt, state.service_id());
    if !force_fresh && let Some(grant) = cache_lookup(&key) {
        // Cached grants can still expire between introspection and use.
        if grant.expires_at <= crate::wire::now() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "auth_expired",
                "session grant has expired",
            ));
        }
        return Ok(grant);
    }

    let grant = introspect_session_grant_remote(state, grant_jwt).await?;
    cache_store(key, grant.clone());
    Ok(grant)
}

/// Raw coauth introspection (no cache). Reads `cnf_jkt`, `session_public_key`,
/// scopes, subject, device_id and expiry off the introspection response.
async fn introspect_session_grant_remote(
    state: &AppState,
    grant_jwt: &str,
) -> Result<SessionGrantIntrospectGrant, AuthError> {
    let Some(introspection_url) = state.config().session_grant_introspection_url.as_deref() else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "auth_misconfigured",
            "session grant introspection URL is not configured",
        ));
    };
    let Some(bearer) = state.config().session_grant_introspection_bearer.as_deref() else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "auth_misconfigured",
            "session grant introspection bearer is not configured",
        ));
    };
    let request = SessionGrantIntrospectRequestBody::ByJwt(SessionGrantIntrospectByJwt {
        grant_jwt: grant_jwt.to_owned(),
        audience_id: Some(configured_service_audience(state)?),
        // The Account Authority returns non-secret grant metadata over this
        // authenticated S2S channel; holder possession is verified below by the
        // request's DPoP proof against the returned `cnf_jkt`.
        proof: None,
    });
    // SOL-03-002: pin validated IPs into the client to close the DNS-rebinding
    // TOCTOU window between the egress check and the connection.
    // Introspection is read-only. A pooled keep-alive connection can be closed
    // by the Auth Server between requests, especially during long conformance
    // runs that force fresh introspection on every sensitive operation. Retry
    // one transport failure after discarding the pinned client; URL validation
    // and address pinning are repeated before the replacement connection is
    // used. Authentication/protocol failures below remain single-shot.
    let mut response = None;
    for attempt in 0..2 {
        let (validated_url, client) =
            introspection_http_client(introspection_url, state.config().development_mode).map_err(
                |_| {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "auth_unavailable",
                        "session grant introspection service unavailable",
                    )
                },
            )?;
        match crate::routing::with_arkret_operation(
            client.post(validated_url),
            arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_INTROSPECT_SESSION_GRANT_V1,
        )
        .bearer_auth(bearer)
        .json(&request)
        .send()
        .await
        {
            Ok(value) => {
                response = Some(value);
                break;
            }
            Err(_) if attempt == 0 => {
                invalidate_introspection_http_client(
                    introspection_url,
                    state.config().development_mode,
                );
            }
            Err(_) => {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "auth_unavailable",
                    "session grant introspection request failed",
                ));
            }
        }
    }
    let response = response.ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "auth_unavailable",
        "session grant introspection request failed",
    ))?;
    if !response.status().is_success() {
        return Err(unauthenticated(
            "session grant introspection was rejected by the Auth Server",
        ));
    }
    let outcome = response
        .json::<SessionGrantIntrospectOutcome>()
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "auth_unavailable",
                "session grant introspection response was invalid",
            )
        })?;
    if !outcome.active || outcome.status != SessionGrantIntrospectStatus::Active {
        return Err(unauthenticated("session grant is not active"));
    }
    outcome
        .grant
        .ok_or_else(|| unauthenticated("session grant introspection omitted grant metadata"))
}

// ── DPoP replay defense ──────────────────────────────────────────────────────

/// Single-use `jti` ledger for DPoP replay defense. An entry is the jti's
/// `iat`-bounded expiry; once past it, the jti is swept and re-usable only
/// because the `iat` freshness check would have already rejected it. Same
/// process-local trade-off as the introspection cache.
struct DpopReplayLedger {
    entries: HashMap<String, DateTime<Utc>>,
    next_sweep_at: DateTime<Utc>,
}

static DPOP_REPLAY: LazyLock<Mutex<DpopReplayLedger>> = LazyLock::new(|| {
    Mutex::new(DpopReplayLedger {
        entries: HashMap::new(),
        next_sweep_at: DateTime::<Utc>::MIN_UTC,
    })
});

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DpopReplayRegistration {
    Accepted,
    Replay,
    Full,
}

/// Record `jti` as seen. Sweeps expired entries opportunistically and fails
/// closed when the bounded replay ledger is full.
fn register_dpop_jti(jti: &str, expires_at: DateTime<Utc>) -> DpopReplayRegistration {
    let now = crate::wire::now();
    let mut ledger = DPOP_REPLAY.lock();
    let sweep_expired = now >= ledger.next_sweep_at;
    if sweep_expired {
        ledger.next_sweep_at = now + Duration::seconds(1);
    }
    register_dpop_jti_locked(
        &mut ledger.entries,
        jti,
        expires_at,
        now,
        DPOP_REPLAY_MAX_ENTRIES,
        sweep_expired,
    )
}

fn register_dpop_jti_locked(
    seen: &mut HashMap<String, DateTime<Utc>>,
    jti: &str,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
    max_entries: usize,
    sweep_expired: bool,
) -> DpopReplayRegistration {
    if sweep_expired || seen.len() >= max_entries {
        seen.retain(|_, expiry| *expiry > now);
    }
    if seen.contains_key(jti) {
        return DpopReplayRegistration::Replay;
    }
    if seen.len() >= max_entries {
        return DpopReplayRegistration::Full;
    }
    seen.insert(jti.to_owned(), expires_at);
    DpopReplayRegistration::Accepted
}

// ── DPoP proof verification ──────────────────────────────────────────────────

/// Read the verbatim `DPoP` header value.
pub(crate) fn dpop_header(req: &Request) -> Option<String> {
    req.headers()
        .get("dpop")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

// ── Orchestration ────────────────────────────────────────────────────────────

/// Whether an `ak.session.grant` is presented through the RFC 9449 token
/// scheme. Proof presence is validated separately so `Authorization: DPoP`
/// without a `DPoP` header fails as an incomplete grant presentation.
pub(crate) fn is_grant_dpop_presentation(req: &Request) -> bool {
    soland_http::util::dpop_token(req).is_some()
}

fn session_binding_from_introspection(
    grant: &SessionGrantIntrospectGrant,
) -> Result<(String, Option<AgentSessionRecord>), AuthError> {
    let authority = grant.principal_authority_key();
    if authority.principal_id != grant.subject_id
        || authority.principal_server_id != grant.audience_id
    {
        return Err(unauthenticated(
            "session grant authority context does not match its subject/audience",
        ));
    }
    if let SessionGrantHolderBinding::AgentRuntime {
        agent_id,
        device_id,
        agent_key_authorization_ref,
        verification_method,
    } = &grant.holder_binding
    {
        // The wire DTO closes agent grants to the self-contained typed holder
        // binding: top-level `device_id`/`device_binding` are the human-device
        // shape and MUST be absent, so the binding itself is the only device
        // authority to check.
        if agent_id != &grant.subject_id {
            return Err(unauthenticated(
                "agent holder binding does not match the introspected subject",
            ));
        }
        return Ok((
            device_id.as_str().to_owned(),
            Some(AgentSessionRecord {
                granted_scope: grant.scopes.clone(),
                scope_details: serde_json::json!({
                    "session_grant_id": grant.id,
                    "session_grant_revocation_ref": grant.revocation_ref,
                    "agent_key_authorization_ref": agent_key_authorization_ref,
                    "verification_method": verification_method,
                }),
                freshness_state: FreshnessState::Fresh,
            }),
        ));
    }

    if let SessionGrantHolderBinding::RecoveryCandidateDevice { device_id } = &grant.holder_binding
    {
        if grant.credential_class
            != arkret_models_identity::SessionGrantCredentialClass::RecoverySession
            || grant.device_binding.is_some()
            || grant.device_id.as_ref() != Some(device_id)
        {
            return Err(unauthenticated(
                "recovery session grant has an invalid candidate-device binding",
            ));
        }
        return Ok((device_id.to_string(), None));
    }

    let binding = grant.human_device_authorization_selector().map_err(|_| {
        unauthenticated("human session grant omitted its device authority selector")
    })?;
    let SessionGrantHolderBinding::HumanDevice { device_binding } = &grant.holder_binding else {
        return Err(unauthenticated("unsupported session grant holder binding"));
    };
    let holder_device_id = DeviceId::new(device_binding.clone())
        .map_err(|_| unauthenticated("session grant holder binding has an invalid device id"))?;
    // `api-conventions.md` §3.3 states two separate MUSTs, both fail-closed as
    // `unauthenticated`. First: the device authorization selector MUST name the
    // same device as the signed typed `holder_binding`.
    if binding.device_id != holder_device_id {
        return Err(unauthenticated(
            "session grant device selector does not match its holder binding",
        ));
    }
    // Second: when introspection also returns top-level device metadata, that
    // metadata MUST equal the signed holder binding verbatim. It is compared
    // against the signed binding itself, never against the selector, so the
    // clause never depends on the selector check having passed.
    if grant.device_id.as_ref() != Some(&holder_device_id) {
        return Err(unauthenticated(
            "session grant device metadata does not match its holder binding",
        ));
    }
    Ok((binding.device_id.to_string(), None))
}

pub(crate) fn session_record_from_introspected_grant_for_logout(
    state: &AppState,
    grant_jwt: &str,
    grant: &SessionGrantIntrospectGrant,
) -> Result<SessionRecord, AuthError> {
    if grant.audience_id.as_str() != state.service_id() {
        return Err(unauthenticated(
            "session grant audience does not match this principal server",
        ));
    }
    let (device_id, agent_session) = session_binding_from_introspection(grant)?;
    let token_hash =
        crate::routing::identity::auth::session_credential_hash(grant_jwt, state.service_id());
    Ok(SessionRecord {
        token_hash,
        actor: grant.subject_id.to_string(),
        device_id,
        audience: state.service_id().clone(),
        session_public_key: Some(grant.session_public_key.as_str().to_owned()),
        agent_session,
        session_grant: Some(SessionGrantAuthorizationState {
            grant_id: grant.id.clone(),
            issuer: grant.issuer_id.clone(),
            scopes: grant.scopes.clone(),
            credential_class: grant.credential_class,
            holder_binding: grant.holder_binding.clone(),
            device_binding: grant.device_binding.clone(),
            cnf_jkt: grant.cnf_jkt.clone(),
        }),
        expires_at: grant.expires_at,
        created_at: crate::wire::now(),
        revoked_at: None,
    })
}

pub(crate) fn verify_grant_dpop_request(
    state: &AppState,
    req: &Request,
    grant_jwt: &str,
    cnf_jkt: Option<&str>,
) -> Result<(), AuthError> {
    let dpop = dpop_header(req).ok_or_else(|| unauthenticated("missing DPoP proof"))?;
    let cnf_jkt = cnf_jkt.filter(|jkt| !jkt.is_empty()).ok_or_else(|| {
        unauthenticated("session grant introspection omitted cnf_jkt; cannot bind DPoP")
    })?;
    let expected_htu = format!(
        "{}{}",
        state.config().public_base_url.trim_end_matches('/'),
        req.uri().path()
    );
    let now = crate::wire::now();
    let verified = arkret_signatures::dpop::verify_dpop_proof(
        &arkret_signatures::dpop::DpopVerificationRequest {
            proof_jwt: &dpop,
            method: req.method().as_str(),
            htu: &expected_htu,
            access_token: Some(grant_jwt),
            now,
            max_age: Duration::seconds(DPOP_MAX_AGE_SECONDS),
            max_future_skew: Duration::seconds(DPOP_MAX_FUTURE_SKEW_SECONDS),
            expected_nonce: None,
        },
    )
    .map_err(|_| unauthenticated("DPoP proof validation failed"))?;
    if verified.jkt != cnf_jkt {
        return Err(unauthenticated(
            "DPoP proof key thumbprint does not match the grant's cnf.jkt",
        ));
    }

    let iat = DateTime::<Utc>::from_timestamp(verified.claims.iat, 0)
        .expect("SDK verifier accepts only representable DPoP timestamps");
    let jti_expiry = iat + Duration::seconds(DPOP_MAX_AGE_SECONDS + DPOP_MAX_FUTURE_SKEW_SECONDS);
    match register_dpop_jti(&verified.claims.jti, jti_expiry) {
        DpopReplayRegistration::Accepted => {}
        DpopReplayRegistration::Replay => {
            return Err(unauthenticated(
                "DPoP proof jti has already been used (replay)",
            ));
        }
        DpopReplayRegistration::Full => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "auth_unavailable",
                "DPoP replay cache is at capacity",
            ));
        }
    }
    Ok(())
}

/// Validate a presented `ak.session.grant` + DPoP and synthesize a
/// request-scoped `SessionRecord`. Not persisted as a local bearer.
///
/// `force_fresh` forces a non-cached introspection (sensitive operations,
/// §3.3 D2).
pub(crate) async fn grant_dpop_session(
    state: &AppState,
    req: &Request,
    grant_jwt: &str,
    force_fresh: bool,
) -> Result<SessionRecord, AuthError> {
    // 1. grant active (cached ≤120s; sensitive ops force fresh). Reads cnf_jkt, session_public_key,
    //    scopes, subject, device_id, expiry.
    let grant = introspect_session_grant_cached(state, grant_jwt, force_fresh).await?;

    // 5. audience == this service's service_id.
    if grant.audience_id.as_str() != state.service_id() {
        return Err(unauthenticated(
            "session grant audience does not match this principal server",
        ));
    }

    // 6a/6b. Human/device and agent grants carry closed typed holder bindings.
    let (device_id, agent_session) = session_binding_from_introspection(&grant)?;

    // 6c. grant not expired.
    if grant.expires_at <= crate::wire::now() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "auth_expired",
            "session grant has expired",
        ));
    }

    // 2. DPoP signature valid against the grant's cnf.jkt.
    verify_grant_dpop_request(state, req, grant_jwt, Some(&grant.cnf_jkt))?;

    Ok(session_from_verified_grant(
        state,
        grant_jwt,
        grant,
        device_id,
        agent_session,
    ))
}

/// Synthesize the request- or connection-scoped `SessionRecord` from an
/// already-verified grant. Not persisted as a local bearer.
///
/// `token_hash` carries a stable, grant-derived value so downstream code that
/// keys on it (e.g. self-path session-revoke of the calling session) resolves
/// to this grant.
pub(crate) fn session_from_verified_grant(
    state: &AppState,
    grant_jwt: &str,
    grant: SessionGrantIntrospectGrant,
    device_id: String,
    agent_session: Option<AgentSessionRecord>,
) -> SessionRecord {
    let grant_context = SessionGrantAuthorizationState {
        grant_id: grant.id.clone(),
        issuer: grant.issuer_id.clone(),
        scopes: grant.scopes.clone(),
        credential_class: grant.credential_class,
        holder_binding: grant.holder_binding.clone(),
        device_binding: grant.device_binding.clone(),
        cnf_jkt: grant.cnf_jkt.clone(),
    };
    SessionRecord {
        token_hash: crate::routing::identity::auth::session_credential_hash(
            grant_jwt,
            state.service_id(),
        ),
        actor: grant.subject_id.to_string(),
        device_id,
        audience: state.service_id().clone(),
        session_public_key: Some(grant.session_public_key.into_string()),
        agent_session,
        session_grant: Some(grant_context),
        expires_at: grant.expires_at,
        created_at: crate::wire::now(),
        revoked_at: None,
    }
}

/// The §6a/§6b session binding of an introspected grant, exposed for the
/// WebSocket binding which validates its holder proof out of band.
pub(crate) fn grant_session_binding(
    grant: &SessionGrantIntrospectGrant,
) -> Result<(String, Option<AgentSessionRecord>), AuthError> {
    session_binding_from_introspection(grant)
}

#[cfg(test)]
mod tests {
    use arkret_identifiers::SessionGrantId;

    use super::*;

    #[test]
    fn jti_replay_is_rejected_within_window() {
        let expiry = crate::wire::now() + Duration::seconds(60);
        let jti = "test-jti-unique-001";
        assert_eq!(
            register_dpop_jti(jti, expiry),
            DpopReplayRegistration::Accepted
        );
        assert_eq!(
            register_dpop_jti(jti, expiry),
            DpopReplayRegistration::Replay
        );
    }

    #[test]
    fn jti_replay_capacity_fails_closed() {
        let now = crate::wire::now();
        let expiry = now + Duration::seconds(60);
        let mut seen = HashMap::new();
        for index in 0..3 {
            assert_eq!(
                register_dpop_jti_locked(
                    &mut seen,
                    &format!("capacity-jti-{index}"),
                    expiry,
                    now,
                    3,
                    true,
                ),
                DpopReplayRegistration::Accepted
            );
        }

        assert_eq!(
            register_dpop_jti_locked(&mut seen, "capacity-overflow", expiry, now, 3, true),
            DpopReplayRegistration::Full
        );
        assert!(!seen.contains_key("capacity-overflow"));
    }

    #[test]
    fn introspection_cache_key_is_audience_bound() {
        let a = introspection_cache_key("grant", "did:web:a");
        let b = introspection_cache_key("grant", "did:web:b");
        assert_ne!(a, b);
    }

    #[test]
    fn introspection_http_client_reuses_the_pinned_connection_pool() {
        let raw_url = "http://127.0.0.1:65530/_arkret/admin/session-grants/introspect";
        let cache_key = introspection_http_client_cache_key(raw_url, true);
        INTROSPECTION_HTTP_CLIENTS.lock().remove(&cache_key);

        introspection_http_client(raw_url, true).unwrap();
        let first_inserted_at = INTROSPECTION_HTTP_CLIENTS
            .lock()
            .get(&cache_key)
            .expect("client cached after first construction")
            .inserted_at;

        introspection_http_client(raw_url, true).unwrap();
        let second_inserted_at = INTROSPECTION_HTTP_CLIENTS
            .lock()
            .get(&cache_key)
            .expect("client remains cached")
            .inserted_at;

        assert_eq!(first_inserted_at, second_inserted_at);
        INTROSPECTION_HTTP_CLIENTS.lock().remove(&cache_key);
    }

    #[test]
    fn introspection_http_client_rebuilds_an_expired_pinned_client() {
        let raw_url = "http://127.0.0.1:65529/_arkret/admin/session-grants/introspect";
        let cache_key = introspection_http_client_cache_key(raw_url, true);
        INTROSPECTION_HTTP_CLIENTS.lock().remove(&cache_key);

        introspection_http_client(raw_url, true).unwrap();
        {
            let mut clients = INTROSPECTION_HTTP_CLIENTS.lock();
            clients
                .get_mut(&cache_key)
                .expect("client cached after first construction")
                .inserted_at = Instant::now() - INTROSPECTION_HTTP_CLIENT_TTL;
        }
        let expired_inserted_at = INTROSPECTION_HTTP_CLIENTS
            .lock()
            .get(&cache_key)
            .expect("expired client remains present until next lookup")
            .inserted_at;

        introspection_http_client(raw_url, true).unwrap();
        let rebuilt_inserted_at = INTROSPECTION_HTTP_CLIENTS
            .lock()
            .get(&cache_key)
            .expect("expired client was rebuilt")
            .inserted_at;

        assert!(rebuilt_inserted_at > expired_inserted_at);
        INTROSPECTION_HTTP_CLIENTS.lock().remove(&cache_key);
    }

    fn test_introspection_grant() -> SessionGrantIntrospectGrant {
        SessionGrantIntrospectGrant {
            id: SessionGrantId::new(
                "ak:session_grant:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
            )
            .unwrap(),
            issuer_id: "did:web:coauth.local".to_owned(),
            subject_id: DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            service_account_id: "alice".to_owned(),
            device_id: Some(
                DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap(),
            ),
            device_binding: Some(
                arkret_models_identity::session_credential::SessionGrantDeviceBinding {
                    device_id: DeviceId::new(
                        "ak:device:0196419b-0000-7000-8000-000000000001",
                    )
                    .unwrap(),
                    authorization_event_id: arkret_identifiers::EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [0x42; 32],
                    ),
                    model_generation_ref: 1,
                },
            ),
            audience_id: arkret_wire::project_did_to_core_id(
                    &arkret_wire::Did::new("did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service").unwrap(),
                )
                .unwrap(),
            scopes: vec!["ak.self.events.read.scan.v1".to_owned()],
            expires_at: crate::wire::now() + Duration::minutes(5),
            revoked_at: None,
            revocation_ref: "ak:session:grant-1".to_owned(),
            session_public_key:
                arkret_models_identity::session_credential::CanonicalSessionPublicJwk::new(
                    r#"{"crv":"Ed25519","kty":"OKP","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
                )
                .unwrap(),
            cnf_jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            credential_class:
                arkret_models_identity::session_credential::SessionGrantCredentialClass::Standard,
            holder_binding: SessionGrantHolderBinding::HumanDevice {
                device_binding: "ak:device:0196419b-0000-7000-8000-000000000001".to_owned(),
            },
        }
    }

    #[test]
    fn device_session_binding_rejects_metadata_mismatch() {
        let mut grant = test_introspection_grant();
        grant.device_id =
            Some(DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000002").unwrap());

        let err = session_binding_from_introspection(&grant).unwrap_err();

        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        assert_eq!(err.1, "unauthenticated");
        assert_eq!(
            err.2,
            "session grant device metadata does not match its holder binding"
        );
    }

    #[test]
    fn agent_holder_binding_materializes_closed_authorization_context() {
        let mut grant = test_introspection_grant();
        // Wire-valid agent grants carry no top-level human device metadata;
        // the typed holder binding is self-contained.
        grant.device_id = None;
        grant.device_binding = None;
        grant.subject_id = DidCoreId::new("ak:did_core:web:agent.example").unwrap();
        grant.scopes = vec!["ak.self.events.read.scan.v1".to_owned()];
        grant.holder_binding = SessionGrantHolderBinding::AgentRuntime {
            agent_id: DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
            device_id: DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap(),
            agent_key_authorization_ref: arkret_identifiers::EventId::new(
                "ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            )
            .unwrap(),
            verification_method: arkret_wire::DidUrl::new(
                "did:web:agent.example#runtime-1".to_owned(),
            )
            .unwrap(),
        };

        let (_, agent_session) = session_binding_from_introspection(&grant).unwrap();
        let agent_session = agent_session.unwrap();
        assert_eq!(
            agent_session.granted_scope,
            vec!["ak.self.events.read.scan.v1"]
        );
        assert_eq!(agent_session.freshness_state, FreshnessState::Fresh);
        assert_eq!(
            agent_session.scope_details["session_grant_revocation_ref"],
            "ak:session:grant-1"
        );
    }
}
