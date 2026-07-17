//! `/_arkret/self/*` inbound credential: `ak.session.grant` + DPoP (RFC 9449).
//!
//! Per api-conventions.md §3.3 the Principal Server (soland) no longer mints a
//! local credential from a session grant. The client
//! presents the `ak.session.grant` directly on every `/_arkret/self/*` request
//! as `Authorization: Bearer <ak.session.grant>` plus a sender-constrained
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
//!   6. human/device grants contain `session.bind` plus a device scope; agent grants carry fresh
//!      `agent_key_proof` resource-scope metadata. Grant not expired.
//!
//! DPoP does NOT bind the request body — body integrity rides on TLS, same as
//! Matrix (api-conventions.md §3.3). Body-bound integrity is layered separately
//! by the RFC 9421 PoP hoop (`session_pop`).

use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::{Duration as StdDuration, Instant};

use arkret_sdk::http_signature::{Ed25519PublicKey, public_key_from_bytes};
use arkret_sdk::{DeviceId, Did, FreshnessState, SessionGrantProofKind};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Verifier};
use parking_lot::Mutex;
use salvo::http::StatusCode;
use salvo::prelude::Request;
use serde_json::Value;
use sha2::{Digest, Sha256};
use soland_storage::{AgentSessionRecord, SessionRecord};

use super::auth::PRINCIPAL_SESSION_BIND_SCOPE;
use crate::state::AppState;
use crate::wire::{
    SessionGrantIntrospectGrant, SessionGrantIntrospectOutcome, SessionGrantIntrospectRequestBody,
    SessionGrantIntrospectStatus,
};

/// Device-scope prefix carried in a `ak.session.grant`'s scope set
/// (`urn:arkret:client:device:<device_id>`). A grant that drives
/// `/_arkret/self/*` MUST carry one so the request is device-bound.
const DEVICE_SCOPE_PREFIX: &str = "urn:arkret:client:device:";

/// TTL for the session-grant introspection cache (api-conventions.md §3.3 D2:
/// SHOULD ≤ 120s). The revocation-visibility upper bound equals this TTL;
/// sensitive operations bypass the cache entirely (`force_fresh`).
const INTROSPECTION_CACHE_TTL: StdDuration = StdDuration::from_secs(120);
const INTROSPECTION_CACHE_MAX_ENTRIES: usize = 4096;

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

fn configured_service_audience(state: &AppState) -> Result<Did, AuthError> {
    Did::new(state.service_id.clone()).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "auth_misconfigured",
            "runtime principal service_id is not a DID",
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

/// Drop any cached introspection entry for `grant_jwt`. Called by logout so the
/// next introspection of that grant goes to coauth and observes `active=false`
/// (account-lifecycle.md §4.1 step 3 — the local-side invalidation).
pub(crate) fn invalidate_cached_grant(state: &AppState, grant_jwt: &str) {
    let key = introspection_cache_key(grant_jwt, &state.service_id);
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
    let key = introspection_cache_key(grant_jwt, &state.service_id);
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
    let Some(introspection_url) = state.config.session_grant_introspection_url.as_deref() else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "auth_misconfigured",
            "session grant introspection URL is not configured",
        ));
    };
    let Some(bearer) = state.config.session_grant_introspection_bearer.as_deref() else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "auth_misconfigured",
            "session grant introspection bearer is not configured",
        ));
    };
    let request = SessionGrantIntrospectRequestBody {
        id: None,
        grant_jwt: Some(grant_jwt.to_owned()),
        audience: Some(configured_service_audience(state)?),
        // The Account Authority returns non-secret grant metadata over this
        // authenticated S2S channel; holder possession is verified below by the
        // request's DPoP proof against the returned `cnf_jkt`.
        proof: None,
    };
    // SOL-03-002: pin validated IPs into the client to close the DNS-rebinding
    // TOCTOU window between the egress check and the connection.
    let (introspection_url, client) =
        crate::security::validate_http_url_for_egress_with_pinned_client(
            introspection_url,
            "session grant introspection",
            state.config.development_mode,
            StdDuration::from_secs(10),
        )
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "auth_unavailable",
                "session grant introspection service unavailable",
            )
        })?;
    let response = client
        .post(introspection_url)
        .bearer_auth(bearer)
        .json(&request)
        .send()
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "auth_unavailable",
                "session grant introspection request failed",
            )
        })?;
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

struct DpopClaims {
    htm: String,
    htu: String,
    ath: String,
    jti: String,
    iat: i64,
    jwk_thumbprint: String,
}

/// Parse + cryptographically verify a DPoP proof JWT (RFC 9449). Verifies the
/// EdDSA (Ed25519) signature against the embedded JWK and returns the decoded
/// claims plus the JWK's RFC 7638 thumbprint. The thumbprint MUST later be
/// matched against the grant's `cnf.jkt`.
fn verify_dpop_proof(dpop: &str) -> Result<DpopClaims, AuthError> {
    let mut parts = dpop.split('.');
    let (header_b64, payload_b64, signature_b64) =
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(header), Some(payload), Some(signature), None) => (header, payload, signature),
            _ => return Err(unauthenticated("DPoP proof is not a compact JWS")),
        };

    let header: Value = decode_json_segment(header_b64)
        .ok_or_else(|| unauthenticated("DPoP proof header is not valid base64url JSON"))?;
    if header.get("typ").and_then(Value::as_str) != Some("dpop+jwt") {
        return Err(unauthenticated("DPoP proof typ is not dpop+jwt"));
    }
    if header.get("alg").and_then(Value::as_str) != Some("EdDSA") {
        // soland session keys are Ed25519 OKP; only EdDSA DPoP is accepted.
        return Err(unauthenticated("DPoP proof alg is not EdDSA"));
    }
    let jwk = header
        .get("jwk")
        .ok_or_else(|| unauthenticated("DPoP proof header is missing the jwk"))?;
    let (public_key, thumbprint) = parse_dpop_jwk(jwk)?;

    // Verify the signature over `base64url(header) "." base64url(payload)`.
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .map_err(|_| unauthenticated("DPoP proof signature is not base64url"))?;
    let signature_array: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| unauthenticated("DPoP proof signature is not 64 bytes"))?;
    let signature = Signature::from_bytes(&signature_array);
    public_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| unauthenticated("DPoP proof signature is invalid"))?;

    let payload: Value = decode_json_segment(payload_b64)
        .ok_or_else(|| unauthenticated("DPoP proof payload is not valid base64url JSON"))?;
    let htm = string_claim(&payload, "htm")
        .ok_or_else(|| unauthenticated("DPoP proof is missing htm"))?;
    let htu = string_claim(&payload, "htu")
        .ok_or_else(|| unauthenticated("DPoP proof is missing htu"))?;
    let ath = string_claim(&payload, "ath")
        .ok_or_else(|| unauthenticated("DPoP proof is missing ath"))?;
    let jti = string_claim(&payload, "jti")
        .ok_or_else(|| unauthenticated("DPoP proof is missing jti"))?;
    let iat = payload
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or_else(|| unauthenticated("DPoP proof is missing iat"))?;

    Ok(DpopClaims {
        htm,
        htu,
        ath,
        jti,
        iat,
        jwk_thumbprint: thumbprint,
    })
}

/// Parse a DPoP JWK header into its Ed25519 public key and RFC 7638 thumbprint.
fn parse_dpop_jwk(jwk: &Value) -> Result<(Ed25519PublicKey, String), AuthError> {
    let kty = jwk.get("kty").and_then(Value::as_str).unwrap_or_default();
    let crv = jwk.get("crv").and_then(Value::as_str).unwrap_or_default();
    if kty != "OKP" || crv != "Ed25519" {
        return Err(unauthenticated("DPoP proof jwk is not an Ed25519 OKP key"));
    }
    let x = jwk
        .get("x")
        .and_then(Value::as_str)
        .filter(|x| !x.is_empty())
        .ok_or_else(|| unauthenticated("DPoP proof jwk is missing x"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(x.as_bytes())
        .map_err(|_| unauthenticated("DPoP proof jwk x is not base64url"))?;
    let public_key = public_key_from_bytes(&bytes)
        .map_err(|_| unauthenticated("DPoP proof jwk x is not a valid Ed25519 key"))?;
    Ok((public_key, jwk_thumbprint_ed25519(x)))
}

/// RFC 7638 JWK thumbprint for an Ed25519 OKP key (base64url `x`). The members
/// are serialized in lexicographic order with no whitespace, per RFC 7638 §3.
fn jwk_thumbprint_ed25519(x: &str) -> String {
    let canonical = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}");
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

fn decode_json_segment(segment: &str) -> Option<Value> {
    let bytes = URL_SAFE_NO_PAD.decode(segment.as_bytes()).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn string_claim(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

// ── Orchestration ────────────────────────────────────────────────────────────

/// Whether a `ak.session.grant` + DPoP credential is being presented: the
/// request carries BOTH an `Authorization: Bearer` and a `DPoP` header. This is
/// the discriminator §3.3 pins — a grant presentation MUST carry DPoP, while a
/// dev-login session credential does not. Branching on the `DPoP` header keeps
/// the local development path separate from production grant presentation.
pub(crate) fn is_grant_dpop_presentation(req: &Request) -> bool {
    req.headers().contains_key("dpop")
}

fn session_binding_from_introspection(
    grant: &SessionGrantIntrospectGrant,
) -> Result<(String, Option<AgentSessionRecord>), AuthError> {
    let is_agent_session = grant.proof_kind == Some(SessionGrantProofKind::AgentKeyProof);
    if is_agent_session {
        validate_agent_session_scope_details(grant)?;
        match grant.freshness_state.unwrap_or(FreshnessState::Unknown) {
            FreshnessState::Fresh => {}
            FreshnessState::Stale => {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    "auth_stale",
                    "agent session revocation freshness is stale",
                ));
            }
            FreshnessState::Unknown => {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "auth_unavailable",
                    "agent session revocation freshness is unknown",
                ));
            }
        }
        let scope_details = agent_session_scope_details(grant);
        return Ok((
            format!("agent-session:{}", grant.id.as_str()),
            Some(AgentSessionRecord {
                granted_scope: grant.scopes.clone(),
                scope_details,
                freshness_state: FreshnessState::Fresh,
            }),
        ));
    }

    if !grant
        .scopes
        .iter()
        .any(|scope| scope == PRINCIPAL_SESSION_BIND_SCOPE)
    {
        return Err(unauthenticated(
            "session grant is missing the principal-server session.bind scope",
        ));
    }
    let scope_device_id = grant
        .scopes
        .iter()
        .find_map(|scope| scope.strip_prefix(DEVICE_SCOPE_PREFIX))
        .map(str::to_owned);
    let Some(scope_device_id) = scope_device_id else {
        return Err(unauthenticated("session grant is missing a device scope"));
    };

    let device_id = match grant.device_id.as_ref().map(DeviceId::as_str) {
        Some(bound) if bound != scope_device_id => {
            return Err(unauthenticated(
                "session grant device binding does not match its device scope",
            ));
        }
        Some(bound) => bound.to_owned(),
        None => scope_device_id,
    };
    Ok((device_id, None))
}

fn validate_agent_session_scope_details(
    grant: &SessionGrantIntrospectGrant,
) -> Result<(), AuthError> {
    let Some(details) = grant.scope_details.as_ref() else {
        return Err(agent_scope_metadata_error());
    };
    if Did::new(grant.subject.clone()).is_err() {
        return Err(agent_scope_metadata_error());
    }
    if details.realm_ids.is_empty() && details.strand_ids.is_empty() {
        return Err(agent_scope_metadata_error());
    }
    Ok(())
}

fn agent_scope_metadata_error() -> AuthError {
    unauthenticated("agent session grant omitted resource scope metadata")
}

fn agent_session_scope_details(grant: &SessionGrantIntrospectGrant) -> Value {
    let mut scope_details = serde_json::to_value(&grant.scope_details).unwrap_or(Value::Null);
    if let Some(object) = scope_details.as_object_mut() {
        object
            .entry("session_grant_id".to_owned())
            .or_insert_with(|| Value::String(grant.id.to_string()));
        object
            .entry("session_grant_revocation_ref".to_owned())
            .or_insert_with(|| Value::String(grant.revocation_ref.clone()));
    }
    scope_details
}

pub(crate) fn session_record_from_introspected_grant_for_logout(
    state: &AppState,
    grant_jwt: &str,
    grant: &SessionGrantIntrospectGrant,
) -> Result<SessionRecord, AuthError> {
    if grant.audience.as_str() != state.service_id {
        return Err(unauthenticated(
            "session grant audience does not match this principal server",
        ));
    }
    let (device_id, agent_session) = session_binding_from_introspection(grant)?;
    let token_hash =
        crate::routing::identity::auth::session_credential_hash(grant_jwt, &state.service_id);
    Ok(SessionRecord {
        token_hash,
        actor: grant.subject.clone(),
        device_id,
        audience: state.service_id.clone(),
        session_public_key: Some(grant.session_public_key.clone()),
        agent_session,
        expires_at: grant.expires_at,
        created_at: crate::wire::now(),
        revoked_at: None,
    })
}

pub(crate) fn verify_grant_dpop_request(
    req: &Request,
    grant_jwt: &str,
    cnf_jkt: Option<&str>,
) -> Result<(), AuthError> {
    let dpop = dpop_header(req).ok_or_else(|| unauthenticated("missing DPoP proof"))?;
    let cnf_jkt = cnf_jkt.filter(|jkt| !jkt.is_empty()).ok_or_else(|| {
        unauthenticated("session grant introspection omitted cnf_jkt; cannot bind DPoP")
    })?;
    let claims = verify_dpop_proof(&dpop)?;
    if claims.jwk_thumbprint != cnf_jkt {
        return Err(unauthenticated(
            "DPoP proof key thumbprint does not match the grant's cnf.jkt",
        ));
    }

    let method = req.method().as_str();
    if !claims.htm.eq_ignore_ascii_case(method) {
        return Err(unauthenticated(
            "DPoP htm does not match the request method",
        ));
    }
    if !htu_matches(&claims.htu, req) {
        return Err(unauthenticated("DPoP htu does not match the request URL"));
    }
    let expected_ath = URL_SAFE_NO_PAD.encode(Sha256::digest(grant_jwt.as_bytes()));
    if claims.ath != expected_ath {
        return Err(unauthenticated(
            "DPoP ath does not match the presented session grant",
        ));
    }

    let now = crate::wire::now();
    let iat = DateTime::<Utc>::from_timestamp(claims.iat, 0)
        .ok_or_else(|| unauthenticated("DPoP iat is not a valid timestamp"))?;
    if iat > now + Duration::seconds(DPOP_MAX_FUTURE_SKEW_SECONDS) {
        return Err(unauthenticated("DPoP proof iat is in the future"));
    }
    if now - iat > Duration::seconds(DPOP_MAX_AGE_SECONDS) {
        return Err(unauthenticated(
            "DPoP proof iat is outside the freshness window",
        ));
    }
    let jti_expiry = iat + Duration::seconds(DPOP_MAX_AGE_SECONDS + DPOP_MAX_FUTURE_SKEW_SECONDS);
    match register_dpop_jti(&claims.jti, jti_expiry) {
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
    if grant.audience.as_str() != state.service_id {
        return Err(unauthenticated(
            "session grant audience does not match this principal server",
        ));
    }

    // 6a/6b. Human/device grants carry `session.bind` + a device scope; agent
    // grants carry fresh resource-scope metadata instead.
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
    verify_grant_dpop_request(req, grant_jwt, grant.cnf_jkt.as_deref())?;

    // Synthesize the request-scoped session. `token_hash` carries a stable,
    // grant-derived value so downstream code that keys on it (e.g. self-path
    // session-revoke of the calling session) resolves to this grant; it is NOT
    // a persisted local bearer.
    let token_hash =
        crate::routing::identity::auth::session_credential_hash(grant_jwt, &state.service_id);
    Ok(SessionRecord {
        token_hash,
        actor: grant.subject,
        device_id,
        audience: state.service_id.clone(),
        session_public_key: Some(grant.session_public_key),
        agent_session,
        expires_at: grant.expires_at,
        created_at: crate::wire::now(),
        revoked_at: None,
    })
}

/// Compare the DPoP `htu` to the request URL. RFC 9449 §4.3 normalizes away the
/// query and fragment before comparison, so we compare scheme + authority +
/// path. The request authority comes from the `Host` header (the
/// client-visible gate origin behind the deployment front).
fn htu_matches(htu: &str, req: &Request) -> bool {
    let Some(htu_normalized) = normalize_htu(htu) else {
        return false;
    };
    let path = req.uri().path();
    // The scheme/authority as the client saw them are not reliably reconstructable
    // server-side behind a TLS-terminating front, so bind on authority + path:
    // match when the htu ends with `<authority><path>` and its path component
    // equals the request path.
    match request_authority(req) {
        Some(authority) => {
            let want = format!("{authority}{path}");
            htu_normalized.ends_with(&want) && htu_path(&htu_normalized) == path
        }
        // No authority header: fall back to a path-only binding so a same-origin
        // deployment still validates.
        None => htu_path(&htu_normalized) == path,
    }
}

/// The client-visible authority (`host[:port]`) of the request. Behind the
/// deployment gateway the upstream `Host` header is frequently rewritten to the
/// internal origin (`soland:8080`), which would never equal the gate origin the
/// client signed into the DPoP `htu`. So prefer `X-Forwarded-Host` (the first /
/// client-facing hop the gateway records) and fall back to `Host` for a
/// same-origin deployment with no proxy in front.
fn request_authority(req: &Request) -> Option<&str> {
    let forwarded = req
        .headers()
        .get("x-forwarded-host")
        .and_then(|value| value.to_str().ok());
    let host = req
        .headers()
        .get("host")
        .and_then(|value| value.to_str().ok());
    select_authority(forwarded, host)
}

/// Choose the client-visible authority from the (`X-Forwarded-Host`, `Host`)
/// pair: prefer the first `X-Forwarded-Host` hop, fall back to `Host`. Whitespace
/// is trimmed and empty values are ignored.
fn select_authority<'a>(forwarded: Option<&'a str>, host: Option<&'a str>) -> Option<&'a str> {
    let forwarded = forwarded
        .map(|value| value.split(',').next().unwrap_or(value).trim())
        .filter(|value| !value.is_empty());
    if forwarded.is_some() {
        return forwarded;
    }
    host.map(str::trim).filter(|value| !value.is_empty())
}

/// Strip the query and fragment from an htu (RFC 9449 §4.3 normalization).
fn normalize_htu(htu: &str) -> Option<String> {
    let trimmed = htu.trim();
    if trimmed.is_empty() {
        return None;
    }
    let without_fragment = trimmed.split('#').next().unwrap_or(trimmed);
    let without_query = without_fragment
        .split('?')
        .next()
        .unwrap_or(without_fragment);
    Some(without_query.to_owned())
}

/// Extract the path component of a normalized htu (everything from the first `/`
/// after the scheme://authority).
fn htu_path(htu: &str) -> &str {
    let after_scheme = htu.split_once("://").map(|(_, rest)| rest).unwrap_or(htu);
    match after_scheme.find('/') {
        Some(index) => &after_scheme[index..],
        None => "/",
    }
}

#[cfg(test)]
mod tests {
    use arkret_sdk::{GrantId, RealmId};

    use super::*;

    const RFC8037_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
    const RFC8037_THUMBPRINT: &str = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";

    #[test]
    fn jwk_thumbprint_matches_rfc8037() {
        assert_eq!(jwk_thumbprint_ed25519(RFC8037_X), RFC8037_THUMBPRINT);
    }

    #[test]
    fn htu_path_strips_scheme_authority() {
        assert_eq!(
            htu_path("https://account.example/_arkret/self/events"),
            "/_arkret/self/events"
        );
        assert_eq!(htu_path("/_arkret/self/events"), "/_arkret/self/events");
        assert_eq!(htu_path("https://account.example"), "/");
    }

    #[test]
    fn normalize_htu_drops_query_and_fragment() {
        assert_eq!(
            normalize_htu("https://h/p?a=b#frag").as_deref(),
            Some("https://h/p"),
        );
    }

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
    fn select_authority_prefers_forwarded_host() {
        // Gateway records the client-facing host in X-Forwarded-Host while the
        // upstream Host is the internal origin: the forwarded value wins.
        assert_eq!(
            select_authority(Some("account.example"), Some("soland:8080")),
            Some("account.example")
        );
        // Multi-hop X-Forwarded-Host: only the first (client-facing) hop is used.
        assert_eq!(
            select_authority(Some("account.example, gw.internal"), Some("soland:8080")),
            Some("account.example")
        );
        // No forwarded header: fall back to Host.
        assert_eq!(
            select_authority(None, Some("account.example")),
            Some("account.example")
        );
        // Empty/whitespace forwarded value is ignored, not treated as authority.
        assert_eq!(
            select_authority(Some("  "), Some("account.example")),
            Some("account.example")
        );
        assert_eq!(select_authority(None, None), None);
    }

    #[test]
    fn introspection_cache_key_is_audience_bound() {
        let a = introspection_cache_key("grant", "did:web:a");
        let b = introspection_cache_key("grant", "did:web:b");
        assert_ne!(a, b);
    }

    fn test_introspection_grant() -> SessionGrantIntrospectGrant {
        SessionGrantIntrospectGrant {
            id: GrantId::new("ak:grant:0196419b-0000-7000-8000-000000000001").unwrap(),
            issuer: "did:web:coauth.local".to_owned(),
            subject: "did:web:alice.example".to_owned(),
            service_account_id: "alice".to_owned(),
            device_id: Some(
                DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap(),
            ),
            audience: Did::new("did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service").unwrap(),
            scopes: vec![
                PRINCIPAL_SESSION_BIND_SCOPE.to_owned(),
                format!("{DEVICE_SCOPE_PREFIX}ak:device:0196419b-0000-7000-8000-000000000001"),
            ],
            expires_at: crate::wire::now() + Duration::minutes(5),
            revoked_at: None,
            revocation_ref: "ak:session:grant-1".to_owned(),
            session_public_key: "{}".to_owned(),
            cnf_jkt: Some("holder-thumbprint".to_owned()),
            proof_kind: None,
            scope_details: None,
            freshness_state: None,
        }
    }

    #[test]
    fn device_session_binding_requires_device_scope() {
        let mut grant = test_introspection_grant();
        grant.scopes = vec![PRINCIPAL_SESSION_BIND_SCOPE.to_owned()];

        let err = session_binding_from_introspection(&grant).unwrap_err();

        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        assert_eq!(err.1, "unauthenticated");
        assert_eq!(err.2, "session grant is missing a device scope");
    }

    #[test]
    fn agent_session_binding_materializes_scope_details() {
        let mut grant = test_introspection_grant();
        grant.id = GrantId::new("ak:grant:0196419b-0000-7000-8000-000000000002").unwrap();
        grant.subject = "did:web:agent.example".to_owned();
        grant.device_id = None;
        grant.scopes = vec!["ak.agent.action:message.send".to_owned()];
        grant.proof_kind = Some(SessionGrantProofKind::AgentKeyProof);
        grant.scope_details = Some(arkret_sdk::SessionGrantScopeDetails {
            realm_ids: vec![
                RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000003".to_owned()).unwrap(),
            ],
            ..Default::default()
        });
        grant.freshness_state = Some(FreshnessState::Fresh);

        let (device_id, agent_session) = session_binding_from_introspection(&grant).unwrap();

        assert_eq!(
            device_id,
            "agent-session:ak:grant:0196419b-0000-7000-8000-000000000002"
        );
        let agent_session = agent_session.unwrap();
        assert_eq!(agent_session.freshness_state, FreshnessState::Fresh);
        assert_eq!(
            agent_session.granted_scope,
            vec!["ak.agent.action:message.send"]
        );
        assert_eq!(
            agent_session.scope_details["realm_ids"][0],
            "ak:realm:0196419b-0000-7000-8000-000000000003"
        );
    }

    #[test]
    fn agent_session_binding_requires_scope_details() {
        let mut grant = test_introspection_grant();
        grant.proof_kind = Some(SessionGrantProofKind::AgentKeyProof);
        grant.freshness_state = Some(FreshnessState::Fresh);

        let err = session_binding_from_introspection(&grant).unwrap_err();

        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        assert_eq!(err.1, "unauthenticated");
        assert_eq!(err.2, "agent session grant omitted resource scope metadata");
    }

    #[test]
    fn agent_session_binding_rejects_empty_scope_details() {
        let mut grant = test_introspection_grant();
        grant.subject = "did:web:agent.example".to_owned();
        grant.proof_kind = Some(SessionGrantProofKind::AgentKeyProof);
        grant.scope_details = Some(arkret_sdk::SessionGrantScopeDetails::default());
        grant.freshness_state = Some(FreshnessState::Fresh);

        let err = session_binding_from_introspection(&grant).unwrap_err();

        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        assert_eq!(err.1, "unauthenticated");
        assert_eq!(err.2, "agent session grant omitted resource scope metadata");
    }

    #[test]
    fn agent_session_binding_requires_fresh_introspection() {
        let mut grant = test_introspection_grant();
        grant.subject = "did:web:agent.example".to_owned();
        grant.proof_kind = Some(SessionGrantProofKind::AgentKeyProof);
        grant.scope_details = Some(arkret_sdk::SessionGrantScopeDetails {
            realm_ids: vec![
                RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000004".to_owned()).unwrap(),
            ],
            ..Default::default()
        });

        let err = session_binding_from_introspection(&grant).unwrap_err();

        assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.1, "auth_unavailable");
        assert_eq!(err.2, "agent session revocation freshness is unknown");
    }
}
