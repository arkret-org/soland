//! G3.S2 — outbound `/policy/check` client.
//!
//! [`PolicyClient`] issues `POST /_arkret/self/policy/check` against the
//! `policy_server_url` of the request's Realm
//! ([`crate::reducer::RealmPolicyServerConfig`]), with per-realm
//! `cache_ttl_seconds` decision caching and `timeout_ms` fail-closed
//! semantics.
//!
//! ## Cache
//!
//! Keyed by the canonical request hash (see
//! [`PolicyCheckRequestInput::canonical_request_hash`]) and guarded by
//! the caller's accepted authorization / policy / membership frontiers.
//! The cache is a flat in-memory map; entries expire after
//! `cache_ttl_seconds` from the realm config in effect at insert time
//! and are also rejected once the signed decision's own `expires_at`
//! has passed. A request with `bypass_cache=true` skips the lookup and
//! the resulting decision is NOT inserted.
//!
//! ## Timeout fail-closed
//!
//! The HTTP call is wrapped in `tokio::time::timeout(timeout_ms)`. On
//! timeout OR transport error, we synthesise a locally-signed
//! `decision="deny"` response with `decision_proxy: true` so callers
//! downstream can tell it didn't come from the real policy server. The
//! local signature is produced using the soland service signing key
//! ([`PolicyClient::local_signer`]); coauth-style verifiers won't
//! validate it, but soland's own audit path can — and the `kid` is
//! prefixed with `did:web:soland.local#proxy-` so it's never confused
//! with a genuine signature.
//!
//! Spec: `arkret-spec/spec/v1/zh/authz/policy-server.md` §5–§6.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arkret_sdk::identity::DidResolver;
use arkret_sdk::models::AuthzDecision;
use arkret_sdk::{
    Did, FreshnessState, Hash, PolicyCheckBoundTo, PolicyCheckOutcome, PolicyCheckRequestBody,
    PolicyCheckSignature, PolicyCheckSource, RealmId,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::Value;
use subtle::ConstantTimeEq as _;

use crate::reducer::RealmPolicyServerConfig;

type VerificationKeyResolver =
    Arc<dyn Fn(&str) -> Result<VerifyingKey, String> + Send + Sync + 'static>;
const POLICY_CACHE_MAX_ENTRIES: usize = 4096;

/// Accepted local frontiers captured when the policy request is built.
/// The signed response must echo these digests exactly before it can be
/// accepted or cached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyFrontierSnapshot {
    pub auth_state_digest: Hash,
    pub policy_frontier_digest: Hash,
    pub membership_frontier_digest: Hash,
}

impl PolicyFrontierSnapshot {
    pub fn new(
        auth_state_digest: Hash,
        policy_frontier_digest: Hash,
        membership_frontier_digest: Hash,
    ) -> Self {
        Self {
            auth_state_digest,
            policy_frontier_digest,
            membership_frontier_digest,
        }
    }
}

/// Inputs needed to build a [`PolicyCheckRequestBody`] plus a
/// per-request control surface (cache bypass).
#[derive(Clone, Debug)]
pub struct PolicyCheckRequestInput {
    pub request_id: String,
    pub realm_id: RealmId,
    pub actor_id: Did,
    pub action: String,
    pub source_service_id: Did,
    pub source_service_type: String,
    pub source_ip_digest: Hash,
    pub signed_transport: bool,
    pub event_preview: Value,
    pub auth_context: Value,
    pub expected_frontiers: PolicyFrontierSnapshot,
    /// When `true`, the cache lookup is skipped and the result is NOT
    /// inserted into the cache.
    pub bypass_cache: bool,
}

impl PolicyCheckRequestInput {
    /// Compute the canonical SHA-256 hash of the request transcript per
    /// spec §5. This is the cache key; coauth's signature transcript
    /// binds to the same digest via `request_canonical_digest`.
    pub fn canonical_request_hash(&self) -> Hash {
        let canonical_input = serde_json::json!({
            "request_id": self.request_id,
            "realm_id": self.realm_id.as_str(),
            "actor_id": self.actor_id.as_str(),
            "action": self.action,
            "source": {
                "service_id": self.source_service_id.as_str(),
                "service_type": self.source_service_type,
                "source_ip_digest": self.source_ip_digest.as_str(),
                "signed_transport": self.signed_transport,
            },
            "event_preview": self.event_preview,
            "auth_context": self.auth_context,
        });
        // SDK is the single source of canonical-JSON + sha256 + `sha256:` prefix
        // (arkret_sdk::canonical::canonical_sha256), shared with jws_verify /
        // notary / reducer so the digest is byte-identical across paths. Preserve
        // the prior fail-open all-zeros fallback for the (canonicalization-error)
        // edge case rather than introducing a new failure mode here.
        let digest = arkret_sdk::canonical::canonical_sha256(&canonical_input)
            .unwrap_or_else(|_| arkret_sdk::canonical::sha256_digest(b""));
        Hash::new(digest)
            .unwrap_or_else(|_| Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap())
    }

    fn into_wire(self) -> PolicyCheckRequestBody {
        let request_canonical_digest = self.canonical_request_hash();
        PolicyCheckRequestBody {
            request_id: self.request_id,
            realm_id: self.realm_id,
            actor_id: self.actor_id,
            device_id: None,
            action: self.action,
            request_canonical_digest,
            source: PolicyCheckSource {
                service_id: self.source_service_id,
                service_type: self.source_service_type,
                source_ip_digest: Some(self.source_ip_digest),
                signed_transport: self.signed_transport,
            },
            event_preview: self.event_preview,
            auth_context: self.auth_context,
        }
    }
}

/// Cached decision entry. Stores the canonical wire response plus the
/// wall-clock `expires_at` (computed at insert time from the realm's
/// `cache_ttl_seconds`).
#[derive(Clone, Debug)]
struct PolicyCacheEntry {
    response: PolicyCheckOutcome,
    expires_at: Instant,
}

/// In-memory decision cache keyed by `(realm_id, canonical_request_hash)`.
/// Keying by the (realm, hash) pair prevents cross-realm aliasing per
/// spec §5 paragraph 4.
#[derive(Default, Debug)]
pub struct PolicyCache {
    inner: Mutex<HashMap<(String, String), PolicyCacheEntry>>,
}

impl PolicyCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn lookup(
        &self,
        realm_id: &str,
        canonical_hash: &str,
        expected_frontiers: &PolicyFrontierSnapshot,
    ) -> Option<PolicyCheckOutcome> {
        let now = Instant::now();
        let wall_now = chrono::Utc::now();
        let mut guard = self.inner.lock();
        prune_policy_cache_locked(&mut guard, now);
        let key = (realm_id.to_owned(), canonical_hash.to_owned());
        if let Some(entry) = guard.get(&key)
            && entry.expires_at > now
            && policy_decision_unexpired(&entry.response, wall_now)
            && policy_frontiers_match(&entry.response, expected_frontiers)
        {
            return Some(entry.response.clone());
        }
        guard.remove(&key);
        None
    }

    fn insert(
        &self,
        realm_id: &str,
        canonical_hash: &str,
        response: PolicyCheckOutcome,
        ttl: Duration,
    ) {
        let expires_at = Instant::now() + ttl;
        let mut guard = self.inner.lock();
        prune_policy_cache_locked(&mut guard, Instant::now());
        while guard.len() >= POLICY_CACHE_MAX_ENTRIES {
            let Some(oldest_key) = guard
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            guard.remove(&oldest_key);
        }
        guard.insert(
            (realm_id.to_owned(), canonical_hash.to_owned()),
            PolicyCacheEntry {
                response,
                expires_at,
            },
        );
    }
}

fn prune_policy_cache_locked(
    guard: &mut HashMap<(String, String), PolicyCacheEntry>,
    now: Instant,
) {
    guard.retain(|_, entry| entry.expires_at > now);
}

fn policy_decision_unexpired(
    response: &PolicyCheckOutcome,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    response.expires_at > now
}

fn policy_frontiers_match(
    response: &PolicyCheckOutcome,
    expected: &PolicyFrontierSnapshot,
) -> bool {
    constant_time_hash_eq(&response.auth_state_digest, &expected.auth_state_digest)
        && constant_time_hash_eq(
            &response.policy_frontier_digest,
            &expected.policy_frontier_digest,
        )
        && constant_time_hash_eq(
            &response.membership_frontier_digest,
            &expected.membership_frontier_digest,
        )
}

fn constant_time_hash_eq(left: &Hash, right: &Hash) -> bool {
    let left = left.as_str().as_bytes();
    let right = right.as_str().as_bytes();
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

/// Errors the outbound client may surface to callers. The handler-level
/// integration treats `Timeout` / `Transport` as "trigger fail-closed
/// path"; `Configuration` is a hard fault.
#[derive(Debug)]
pub enum PolicyClientError {
    Configuration(String),
    Transport(String),
    Timeout,
    BadResponse(String),
    SignatureInvalid(String),
}

impl std::fmt::Display for PolicyClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configuration(s) => write!(f, "policy client misconfigured: {s}"),
            Self::Transport(s) => write!(f, "policy client transport error: {s}"),
            Self::Timeout => write!(f, "policy client timeout"),
            Self::BadResponse(s) => write!(f, "policy client bad response: {s}"),
            Self::SignatureInvalid(s) => write!(f, "policy client signature invalid: {s}"),
        }
    }
}

impl std::error::Error for PolicyClientError {}

/// Outbound client to a Realm's policy server.
pub struct PolicyClient {
    _http: reqwest::Client,
    cache: PolicyCache,
    /// Local soland service DID. Used to mint the "proxy" signature on
    /// timeout-fail-closed responses so audit logs can attribute the
    /// synthesised deny.
    local_service_id: String,
    verification_key_resolver: Option<VerificationKeyResolver>,
    allow_private_network_egress: bool,
}

impl PolicyClient {
    pub fn new(http: reqwest::Client, local_service_id: impl Into<String>) -> Self {
        Self {
            _http: http,
            cache: PolicyCache::new(),
            local_service_id: local_service_id.into(),
            verification_key_resolver: None,
            allow_private_network_egress: false,
        }
    }

    pub fn with_private_network_egress(mut self, allowed: bool) -> Self {
        self.allow_private_network_egress = allowed;
        self
    }

    /// Attach the DID resolver used to verify genuine policy-server
    /// signatures. Without this, upstream responses fail closed because
    /// the client cannot resolve `signature.kid` to trusted key material.
    pub fn with_policy_did_resolver(
        mut self,
        resolver: Arc<dyn DidResolver + Send + Sync>,
    ) -> Self {
        self.verification_key_resolver = Some(Arc::new(move |kid| {
            resolve_policy_ed25519_pubkey(&*resolver, kid)
        }));
        self
    }

    /// Issue a `/policy/check` against the policy server declared for
    /// the request's realm. Resolves the [`RealmPolicyServerConfig`]
    /// via the supplied closure so this client doesn't have to take
    /// the entire `ProjectionState` (which would force the caller to
    /// hold the lock across an HTTP round-trip).
    pub async fn check<F>(
        &self,
        input: PolicyCheckRequestInput,
        config_lookup: F,
    ) -> Result<PolicyCheckOutcome, PolicyClientError>
    where
        F: FnOnce(&str) -> Option<RealmPolicyServerConfig>,
    {
        let realm_id_str = input.realm_id.as_str().to_owned();
        let config = config_lookup(&realm_id_str).ok_or_else(|| {
            PolicyClientError::Configuration(format!(
                "no ak.realm.policy_server config for {realm_id_str}"
            ))
        })?;

        let canonical_hash = input.canonical_request_hash();
        let bypass_cache = input.bypass_cache;
        let expected_frontiers = input.expected_frontiers.clone();
        if !bypass_cache
            && let Some(hit) =
                self.cache
                    .lookup(&realm_id_str, canonical_hash.as_str(), &expected_frontiers)
        {
            return Ok(hit);
        }

        let wire_request = input.into_wire();
        let timeout = Duration::from_millis(config.timeout_ms);

        match tokio::time::timeout(
            timeout,
            self.post_check(&config.policy_server_url, &wire_request),
        )
        .await
        {
            Ok(Ok(response)) => {
                self.verify_signature(&config, &wire_request, &response)?;
                if !policy_decision_unexpired(&response, chrono::Utc::now()) {
                    tracing::warn!(
                        realm_id = %realm_id_str,
                        request_id = %wire_request.request_id,
                        "policy_client: expired policy decision replay rejected"
                    );
                    return Ok(self.frontier_fail_closed_response(
                        &wire_request,
                        &expected_frontiers,
                        "snapshot_risk",
                    ));
                }
                if !policy_frontiers_match(&response, &expected_frontiers) {
                    tracing::warn!(
                        realm_id = %realm_id_str,
                        request_id = %wire_request.request_id,
                        expected_auth_state_digest = %expected_frontiers.auth_state_digest.as_str(),
                        response_auth_state_digest = %response.auth_state_digest.as_str(),
                        expected_policy_frontier_digest = %expected_frontiers.policy_frontier_digest.as_str(),
                        response_policy_frontier_digest = %response.policy_frontier_digest.as_str(),
                        expected_membership_frontier_digest = %expected_frontiers.membership_frontier_digest.as_str(),
                        response_membership_frontier_digest = %response.membership_frontier_digest.as_str(),
                        "policy_client: policy decision frontier mismatch rejected"
                    );
                    return Ok(self.frontier_fail_closed_response(
                        &wire_request,
                        &expected_frontiers,
                        "fork_risk",
                    ));
                }
                if !bypass_cache {
                    let ttl = Duration::from_secs(config.cache_ttl_seconds);
                    self.cache.insert(
                        &realm_id_str,
                        canonical_hash.as_str(),
                        response.clone(),
                        ttl,
                    );
                }
                Ok(response)
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    realm_id = %realm_id_str,
                    error = %e,
                    "policy_client: HTTP error, fail-closed"
                );
                Ok(self.fail_closed_response(
                    &config,
                    &wire_request,
                    "policy_server_transport_error",
                ))
            }
            Err(_elapsed) => {
                tracing::warn!(
                    realm_id = %realm_id_str,
                    timeout_ms = config.timeout_ms,
                    "policy_client: deadline elapsed, fail-closed"
                );
                Ok(self.fail_closed_response(&config, &wire_request, "policy_server_timeout"))
            }
        }
    }

    fn frontier_fail_closed_response(
        &self,
        request: &PolicyCheckRequestBody,
        expected_frontiers: &PolicyFrontierSnapshot,
        reason_code: &str,
    ) -> PolicyCheckOutcome {
        let policy_server_id =
            Did::new(self.local_service_id.clone()).unwrap_or_else(|_| request.actor_id.clone());
        let bound_to = PolicyCheckBoundTo {
            realm_id: request.realm_id.clone(),
            actor_id: request.actor_id.clone(),
            action: request.action.clone(),
            request_canonical_digest: request.request_canonical_digest.clone(),
            policy_server_id,
        };
        let now = chrono::Utc::now();
        let signature = PolicyCheckSignature {
            kid: format!("{}#proxy-{}", self.local_service_id, reason_code),
            sig: "proxy".to_owned(),
        };
        PolicyCheckOutcome {
            request_id: request.request_id.clone(),
            decision: AuthzDecision::HardDeny,
            bound_to,
            reason_code: reason_code.to_owned(),
            expires_at: now,
            freshness_state: FreshnessState::Unknown,
            auth_state_digest: expected_frontiers.auth_state_digest.clone(),
            policy_frontier_digest: expected_frontiers.policy_frontier_digest.clone(),
            membership_frontier_digest: expected_frontiers.membership_frontier_digest.clone(),
            signature,
            next_retry_at: Some(now),
            obligations: vec![serde_json::json!({
                "kind": "log_to_audit",
                "fields": {"decision_proxy": true, "reason_code": reason_code}
            })],
        }
    }

    async fn post_check(
        &self,
        url: &str,
        body: &PolicyCheckRequestBody,
    ) -> Result<PolicyCheckOutcome, PolicyClientError> {
        let (url, client) =
            crate::security::validate_http_url_for_egress_with_pinned_client_allow_private(
                url,
                "policy server check",
                self.allow_private_network_egress,
                Duration::from_secs(10),
            )
            .map_err(PolicyClientError::Transport)?;
        let response = client
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(|e| PolicyClientError::Transport(e.to_string()))?;
        if !response.status().is_success() {
            return Err(PolicyClientError::BadResponse(format!(
                "non-2xx status {}",
                response.status()
            )));
        }
        response
            .json::<PolicyCheckOutcome>()
            .await
            .map_err(|e| PolicyClientError::BadResponse(e.to_string()))
    }

    /// Synthesise a locally-signed deny when the upstream policy server
    /// times out or errors. The `decision_proxy: true` audit hint lets
    /// downstream tooling distinguish synthesised denials from genuine
    /// upstream decisions.
    fn fail_closed_response(
        &self,
        config: &RealmPolicyServerConfig,
        request: &PolicyCheckRequestBody,
        reason_code: &str,
    ) -> PolicyCheckOutcome {
        let policy_server_id =
            Did::new(self.local_service_id.clone()).unwrap_or_else(|_| request.actor_id.clone());
        let bound_to = PolicyCheckBoundTo {
            realm_id: request.realm_id.clone(),
            actor_id: request.actor_id.clone(),
            action: request.action.clone(),
            request_canonical_digest: request.request_canonical_digest.clone(),
            policy_server_id,
        };
        let zero_hash =
            Hash::new(format!("sha256:{}", "0".repeat(64))).expect("zero hash valid shape");
        let signature = PolicyCheckSignature {
            kid: format!("{}#proxy-{}", self.local_service_id, reason_code),
            sig: "proxy".to_owned(),
        };
        PolicyCheckOutcome {
            request_id: request.request_id.clone(),
            decision: AuthzDecision::HardDeny,
            bound_to,
            reason_code: match config.on_timeout.as_str() {
                "deny" => "policy_server_denied_on_timeout".to_owned(),
                _ => reason_code.to_owned(),
            },
            expires_at: chrono::Utc::now()
                + chrono::Duration::seconds(config.cache_ttl_seconds as i64),
            freshness_state: FreshnessState::Unknown,
            auth_state_digest: zero_hash.clone(),
            policy_frontier_digest: zero_hash.clone(),
            membership_frontier_digest: zero_hash,
            signature,
            next_retry_at: None,
            obligations: vec![serde_json::json!({
                "kind": "log_to_audit",
                "fields": {"decision_proxy": true, "reason_code": reason_code}
            })],
        }
    }

    /// Verify the signature on a genuine `PolicyCheckOutcome`. The
    /// `kid` MUST be a verification method owned by the declared
    /// `policy_server_did`; the signature MUST verify over the canonical
    /// policy-check transcript reconstructed from the original request
    /// and the response.
    fn verify_signature(
        &self,
        config: &RealmPolicyServerConfig,
        request: &PolicyCheckRequestBody,
        response: &PolicyCheckOutcome,
    ) -> Result<(), PolicyClientError> {
        if response.signature.sig.is_empty() {
            return Err(PolicyClientError::SignatureInvalid("empty sig".to_owned()));
        }
        let kid = &response.signature.kid;
        let Some((kid_did_part, kid_fragment)) = kid.split_once('#') else {
            return Err(PolicyClientError::SignatureInvalid(format!(
                "kid missing fragment: {kid}"
            )));
        };
        if kid_did_part.is_empty() || kid_fragment.is_empty() {
            return Err(PolicyClientError::SignatureInvalid(format!(
                "kid has empty DID or fragment: {kid}"
            )));
        }
        // kid MUST be controlled by the declared policy_server_did.
        if kid_did_part != config.policy_server_did {
            return Err(PolicyClientError::SignatureInvalid(format!(
                "kid {kid_did_part} not under policy_server_did {server}",
                server = config.policy_server_did
            )));
        }
        // bound_to.policy_server_id MUST also match the declared DID.
        if response.bound_to.policy_server_id.as_str() != config.policy_server_did {
            return Err(PolicyClientError::SignatureInvalid(format!(
                "bound_to.policy_server_id {bt} != config {cfg}",
                bt = response.bound_to.policy_server_id.as_str(),
                cfg = config.policy_server_did
            )));
        }
        if response.bound_to.realm_id != request.realm_id {
            return Err(PolicyClientError::SignatureInvalid(format!(
                "bound_to.realm_id {bt} != request {req}",
                bt = response.bound_to.realm_id.as_str(),
                req = request.realm_id.as_str()
            )));
        }
        if response.bound_to.actor_id != request.actor_id {
            return Err(PolicyClientError::SignatureInvalid(format!(
                "bound_to.actor_id {bt} != request {req}",
                bt = response.bound_to.actor_id.as_str(),
                req = request.actor_id.as_str()
            )));
        }
        if response.bound_to.action != request.action {
            return Err(PolicyClientError::SignatureInvalid(format!(
                "bound_to.action {} != request {}",
                response.bound_to.action, request.action
            )));
        }
        if response.bound_to.request_canonical_digest != request.request_canonical_digest {
            return Err(PolicyClientError::SignatureInvalid(format!(
                "bound_to.request_canonical_digest {bt} != request {req}",
                bt = response.bound_to.request_canonical_digest.as_str(),
                req = request.request_canonical_digest.as_str()
            )));
        }

        let Some(resolve_key) = &self.verification_key_resolver else {
            return Err(PolicyClientError::Configuration(
                "policy decision verification key resolver not configured".to_owned(),
            ));
        };
        let verifying_key = resolve_key(kid).map_err(|e| {
            PolicyClientError::SignatureInvalid(format!("verification key resolution failed: {e}"))
        })?;
        let signature = decode_policy_signature(&response.signature.sig)?;
        let transcript = policy_decision_transcript_bytes(request, response)?;
        verifying_key.verify(&transcript, &signature).map_err(|e| {
            PolicyClientError::SignatureInvalid(format!("Ed25519 verify failed: {e}"))
        })?;
        Ok(())
    }
}

#[derive(Debug, Serialize)]
struct PolicyDecisionTranscript<'a> {
    kind: &'a str,
    request_id: &'a str,
    decision: &'a AuthzDecision,
    bound_to: &'a PolicyCheckBoundTo,
    freshness_state: &'a FreshnessState,
    auth_state_digest: &'a Hash,
    policy_frontier_digest: &'a Hash,
    membership_frontier_digest: &'a Hash,
    reason_code: &'a str,
    expires_at: &'a str,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    obligations: &'a [Value],
}

pub(crate) fn policy_decision_transcript_bytes(
    request: &PolicyCheckRequestBody,
    response: &PolicyCheckOutcome,
) -> Result<Vec<u8>, PolicyClientError> {
    let expires_at = format_canonical_rfc3339(&response.expires_at);
    let transcript = PolicyDecisionTranscript {
        kind: "ak.policy.check.transcript.v1",
        request_id: request.request_id.as_str(),
        decision: &response.decision,
        bound_to: &response.bound_to,
        freshness_state: &response.freshness_state,
        auth_state_digest: &response.auth_state_digest,
        policy_frontier_digest: &response.policy_frontier_digest,
        membership_frontier_digest: &response.membership_frontier_digest,
        reason_code: response.reason_code.as_str(),
        expires_at: expires_at.as_str(),
        obligations: &response.obligations,
    };
    arkret_sdk::canonical::canonical_json_bytes(&transcript)
        .map_err(|e| PolicyClientError::BadResponse(format!("policy transcript canonicalize: {e}")))
}

fn format_canonical_rfc3339(ts: &chrono::DateTime<chrono::Utc>) -> String {
    arkret_sdk::canonical::format_timestamp_canonical(*ts)
}

fn decode_policy_signature(sig: &str) -> Result<Signature, PolicyClientError> {
    if sig.bytes().all(|b| b == b'A') {
        return Err(PolicyClientError::SignatureInvalid(
            "signature is the all-zero sentinel".to_owned(),
        ));
    }
    let bytes = URL_SAFE_NO_PAD.decode(sig.as_bytes()).map_err(|e| {
        PolicyClientError::SignatureInvalid(format!("signature is not base64url: {e}"))
    })?;
    if bytes.len() != 64 {
        return Err(PolicyClientError::SignatureInvalid(format!(
            "Ed25519 signature must be 64 bytes, got {}",
            bytes.len()
        )));
    }
    let mut raw = [0u8; 64];
    raw.copy_from_slice(&bytes);
    Ok(Signature::from_bytes(&raw))
}

fn resolve_policy_ed25519_pubkey(
    resolver: &dyn DidResolver,
    verification_method: &str,
) -> Result<VerifyingKey, String> {
    let (did_str, fragment) = verification_method
        .split_once('#')
        .map(|(d, f)| (d.to_owned(), Some(f.to_owned())))
        .unwrap_or_else(|| (verification_method.to_owned(), None));
    let did = Did::new(did_str.clone()).map_err(|e| format!("invalid DID `{did_str}`: {e}"))?;
    let document = resolver
        .resolve_did(&did)
        .map_err(|e| format!("DID resolve failed for `{did_str}`: {e}"))?;

    let material = document
        .verification_methods
        .get(verification_method)
        .or_else(|| {
            fragment
                .as_ref()
                .and_then(|fragment| document.verification_methods.get(fragment))
        })
        .or_else(|| {
            if document.verification_methods.len() == 1 {
                document.verification_methods.values().next()
            } else {
                None
            }
        })
        .ok_or_else(|| {
            format!(
                "verification_method `{verification_method}` not found in DID document for `{did_str}` (have {:?})",
                document.verification_methods.keys().collect::<Vec<_>>()
            )
        })?;

    decode_policy_ed25519_public_key(material)
}

fn decode_policy_ed25519_public_key(material: &str) -> Result<VerifyingKey, String> {
    let material = material.trim();
    if material.starts_with('z') {
        return decode_ed25519_multibase(material);
    }

    let value: Value = serde_json::from_str(material)
        .map_err(|e| format!("public key material is neither multibase nor JWK JSON: {e}"))?;
    match value {
        Value::String(inner) => decode_policy_ed25519_public_key(&inner),
        Value::Object(object) => {
            let kty = object.get("kty").and_then(Value::as_str).unwrap_or("");
            let crv = object.get("crv").and_then(Value::as_str).unwrap_or("");
            if kty != "OKP" || crv != "Ed25519" {
                return Err(format!("unsupported publicKeyJwk kty/crv: {kty}/{crv}"));
            }
            let x = object
                .get("x")
                .and_then(Value::as_str)
                .ok_or_else(|| "Ed25519 publicKeyJwk missing x".to_owned())?;
            let bytes = URL_SAFE_NO_PAD
                .decode(x.as_bytes())
                .map_err(|e| format!("Ed25519 publicKeyJwk x is not base64url: {e}"))?;
            if bytes.len() != 32 {
                return Err(format!(
                    "Ed25519 publicKeyJwk x must be 32 bytes, got {}",
                    bytes.len()
                ));
            }
            let mut raw = [0u8; 32];
            raw.copy_from_slice(&bytes);
            VerifyingKey::from_bytes(&raw).map_err(|e| format!("invalid Ed25519 public key: {e}"))
        }
        other => Err(format!("unsupported public key material shape: {other}")),
    }
}

fn decode_ed25519_multibase(multibase: &str) -> Result<VerifyingKey, String> {
    let key_bytes = arkret_sdk::decode_ed25519_multibase(multibase).map_err(|e| e.to_string())?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|e| format!("invalid Ed25519 public key: {e}"))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use arkret_sdk::identity::{DidDocument, DidWebResolver};
    use chrono::Utc;
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn realm_config(url: &str) -> RealmPolicyServerConfig {
        RealmPolicyServerConfig {
            realm_id: "ak:realm:01904100-0000-7000-8000-000000000001".to_owned(),
            policy_server_did: "did:web:policy.example.com".to_owned(),
            policy_server_url: url.to_owned(),
            cache_ttl_seconds: 60,
            timeout_ms: 250,
            on_timeout: "fail_closed".to_owned(),
            updated_at: Utc::now(),
        }
    }

    fn hash_with(ch: char) -> Hash {
        Hash::new(format!("sha256:{}", ch.to_string().repeat(64))).unwrap()
    }

    fn frontiers(auth: char, policy: char, membership: char) -> PolicyFrontierSnapshot {
        PolicyFrontierSnapshot::new(hash_with(auth), hash_with(policy), hash_with(membership))
    }

    fn sample_input(bypass_cache: bool) -> PolicyCheckRequestInput {
        PolicyCheckRequestInput {
            request_id: "req-1".to_owned(),
            realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            actor_id: Did::new("did:web:alice.example").unwrap(),
            action: "ak.message.create".to_owned(),
            source_service_id: Did::new("did:web:soland.local").unwrap(),
            source_service_type: "principal_server".to_owned(),
            source_ip_digest: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
            signed_transport: true,
            event_preview: Value::Null,
            auth_context: Value::Null,
            expected_frontiers: frontiers('0', '0', '0'),
            bypass_cache,
        }
    }

    fn sample_response() -> PolicyCheckOutcome {
        let zero = Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
        PolicyCheckOutcome {
            request_id: "req-1".to_owned(),
            decision: AuthzDecision::Allow,
            bound_to: PolicyCheckBoundTo {
                realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap(),
                actor_id: Did::new("did:web:alice.example").unwrap(),
                action: "ak.message.create".to_owned(),
                request_canonical_digest: zero.clone(),
                policy_server_id: Did::new("did:web:policy.example.com").unwrap(),
            },
            freshness_state: FreshnessState::Fresh,
            auth_state_digest: zero.clone(),
            policy_frontier_digest: zero.clone(),
            membership_frontier_digest: zero,
            signature: PolicyCheckSignature {
                kid: "did:web:policy.example.com#key-1".to_owned(),
                sig: "base64stub".to_owned(),
            },
            reason_code: "ok".to_owned(),
            expires_at: Utc::now() + chrono::Duration::seconds(60),
            next_retry_at: None,
            obligations: Vec::new(),
        }
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[17u8; 32])
    }

    fn wrong_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[18u8; 32])
    }

    fn test_policy_resolver(signing: &SigningKey) -> Arc<dyn DidResolver + Send + Sync> {
        let mut resolver = DidWebResolver::new();
        resolver
            .insert(DidDocument::new(
                Did::new("did:web:policy.example.com").unwrap(),
                "did:web:policy.example.com#key-1",
                ed25519_public_multibase(signing),
            ))
            .unwrap();
        Arc::new(resolver)
    }

    fn ed25519_public_multibase(signing: &SigningKey) -> String {
        let mut bytes = vec![0xed, 0x01];
        bytes.extend_from_slice(signing.verifying_key().as_bytes());
        format!("z{}", bs58::encode(bytes).into_string())
    }

    fn client_with_policy_key(signing: &SigningKey) -> PolicyClient {
        PolicyClient::new(reqwest::Client::new(), "did:web:soland.local")
            .with_private_network_egress(true)
            .with_policy_did_resolver(test_policy_resolver(signing))
    }

    fn signed_sample_response(
        input: &PolicyCheckRequestInput,
        signing: &SigningKey,
    ) -> PolicyCheckOutcome {
        let wire_request = input.clone().into_wire();
        let response = PolicyCheckOutcome {
            request_id: wire_request.request_id.clone(),
            decision: AuthzDecision::Allow,
            bound_to: PolicyCheckBoundTo {
                realm_id: wire_request.realm_id.clone(),
                actor_id: wire_request.actor_id.clone(),
                action: wire_request.action.clone(),
                request_canonical_digest: wire_request.request_canonical_digest.clone(),
                policy_server_id: Did::new("did:web:policy.example.com").unwrap(),
            },
            freshness_state: FreshnessState::Fresh,
            auth_state_digest: input.expected_frontiers.auth_state_digest.clone(),
            policy_frontier_digest: input.expected_frontiers.policy_frontier_digest.clone(),
            membership_frontier_digest: input.expected_frontiers.membership_frontier_digest.clone(),
            signature: PolicyCheckSignature {
                kid: "did:web:policy.example.com#key-1".to_owned(),
                sig: String::new(),
            },
            reason_code: "ok".to_owned(),
            expires_at: Utc::now() + chrono::Duration::seconds(60),
            next_retry_at: None,
            obligations: Vec::new(),
        };
        sign_policy_response(input, signing, response)
    }

    fn sign_policy_response(
        input: &PolicyCheckRequestInput,
        signing: &SigningKey,
        mut response: PolicyCheckOutcome,
    ) -> PolicyCheckOutcome {
        response.signature.sig.clear();
        let wire_request = input.clone().into_wire();
        let transcript =
            policy_decision_transcript_bytes(&wire_request, &response).expect("transcript bytes");
        response.signature.sig = URL_SAFE_NO_PAD.encode(signing.sign(&transcript).to_bytes());
        response
    }

    #[tokio::test]
    async fn check_cache_hit_returns_cached() {
        let client = PolicyClient::new(reqwest::Client::new(), "did:web:soland.local")
            .with_private_network_egress(true);
        let cfg = realm_config("http://127.0.0.1:1/never-reached");
        let input = sample_input(false);
        let key = input.canonical_request_hash();

        // Pre-seed the cache with an "allow" response and assert the
        // network is never hit (the URL would refuse anyway).
        client.cache.insert(
            input.realm_id.as_str(),
            key.as_str(),
            sample_response(),
            Duration::from_secs(60),
        );

        let cfg_clone = cfg.clone();
        let resp = client.check(input, move |_| Some(cfg_clone)).await.unwrap();
        assert!(matches!(resp.decision, AuthzDecision::Allow));
        assert_eq!(resp.reason_code, "ok");
    }

    #[tokio::test]
    async fn check_cache_hit_requires_current_frontiers() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hit_count = Arc::new(AtomicUsize::new(0));
        let hit_count_clone = hit_count.clone();
        let signing = signing_key();
        let mut input = sample_input(false);
        input.expected_frontiers = frontiers('1', '2', '3');
        let stale_key = input.canonical_request_hash();
        let resp_body = serde_json::to_string(&signed_sample_response(&input, &signing)).unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                hit_count_clone.fetch_add(1, Ordering::SeqCst);
                let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut [0u8; 4096]).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    resp_body.len(),
                    resp_body
                );
                let _ = tokio::io::AsyncWriteExt::write_all(&mut sock, response.as_bytes()).await;
            }
        });

        let url = format!("http://{addr}/_arkret/self/policy/check");
        let cfg = realm_config(&url);
        let client = client_with_policy_key(&signing);
        client.cache.insert(
            input.realm_id.as_str(),
            stale_key.as_str(),
            sample_response(),
            Duration::from_secs(60),
        );

        let cfg_clone = cfg.clone();
        let resp = client.check(input, move |_| Some(cfg_clone)).await.unwrap();
        assert!(matches!(resp.decision, AuthzDecision::Allow));
        assert_eq!(
            hit_count.load(Ordering::SeqCst),
            1,
            "stale frontier cache entry must be bypassed"
        );
    }

    #[tokio::test]
    async fn check_cache_miss_calls_http() {
        // Spin up a one-shot mock server. We use tokio + a hand-rolled
        // TCP listener instead of pulling in wiremock; this keeps the
        // test deps in sync with what's already in soland/Cargo.toml.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hit_count = Arc::new(AtomicUsize::new(0));
        let hit_count_clone = hit_count.clone();
        let signing = signing_key();
        let input = sample_input(false);
        let resp_body = serde_json::to_string(&signed_sample_response(&input, &signing)).unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                hit_count_clone.fetch_add(1, Ordering::SeqCst);
                let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut [0u8; 4096]).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    resp_body.len(),
                    resp_body
                );
                let _ = tokio::io::AsyncWriteExt::write_all(&mut sock, response.as_bytes()).await;
            }
        });

        let url = format!("http://{addr}/_arkret/self/policy/check");
        let cfg = realm_config(&url);
        let client = client_with_policy_key(&signing);

        let cfg_clone = cfg.clone();
        let resp = client.check(input, move |_| Some(cfg_clone)).await.unwrap();
        assert!(matches!(resp.decision, AuthzDecision::Allow));
        assert_eq!(hit_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn check_rejects_expired_signed_decision() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let signing = signing_key();
        let input = sample_input(true);
        let mut expired = signed_sample_response(&input, &signing);
        expired.expires_at = Utc::now() - chrono::Duration::seconds(1);
        let expired = sign_policy_response(&input, &signing, expired);
        let resp_body = serde_json::to_string(&expired).unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut [0u8; 4096]).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    resp_body.len(),
                    resp_body
                );
                let _ = tokio::io::AsyncWriteExt::write_all(&mut sock, response.as_bytes()).await;
            }
        });

        let url = format!("http://{addr}/_arkret/self/policy/check");
        let cfg = realm_config(&url);
        let client = client_with_policy_key(&signing);

        let cfg_clone = cfg.clone();
        let resp = client.check(input, move |_| Some(cfg_clone)).await.unwrap();
        assert!(matches!(resp.decision, AuthzDecision::HardDeny));
        assert_eq!(resp.reason_code, "snapshot_risk");
        assert!(resp.signature.kid.ends_with("#proxy-snapshot_risk"));
    }

    #[tokio::test]
    async fn check_rejects_signed_frontier_mismatch() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let signing = signing_key();
        let input = sample_input(true);
        let mut mismatched = signed_sample_response(&input, &signing);
        mismatched.policy_frontier_digest = hash_with('a');
        let mismatched = sign_policy_response(&input, &signing, mismatched);
        let resp_body = serde_json::to_string(&mismatched).unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut [0u8; 4096]).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    resp_body.len(),
                    resp_body
                );
                let _ = tokio::io::AsyncWriteExt::write_all(&mut sock, response.as_bytes()).await;
            }
        });

        let url = format!("http://{addr}/_arkret/self/policy/check");
        let cfg = realm_config(&url);
        let client = client_with_policy_key(&signing);

        let cfg_clone = cfg.clone();
        let resp = client.check(input, move |_| Some(cfg_clone)).await.unwrap();
        assert!(matches!(resp.decision, AuthzDecision::HardDeny));
        assert_eq!(resp.reason_code, "fork_risk");
        assert!(resp.signature.kid.ends_with("#proxy-fork_risk"));
        assert_eq!(resp.policy_frontier_digest, hash_with('0'));
    }

    #[tokio::test]
    async fn check_timeout_fails_closed() {
        // Bind a listener but never `accept` — the client will time out.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Drop the listener after a long delay so the connect itself
        // doesn't ECONNREFUSED — we want the *send/recv* phase to time
        // out, demonstrating the wrapper deadline.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(listener);
        });

        let url = format!("http://{addr}/_arkret/self/policy/check");
        let mut cfg = realm_config(&url);
        cfg.timeout_ms = 150;
        let client = PolicyClient::new(reqwest::Client::new(), "did:web:soland.local")
            .with_private_network_egress(true);
        let input = sample_input(true); // bypass_cache=true so we always hit network

        let cfg_clone = cfg.clone();
        let resp = client.check(input, move |_| Some(cfg_clone)).await.unwrap();
        assert!(
            matches!(resp.decision, AuthzDecision::HardDeny),
            "fail-closed must produce a deny decision"
        );
        // The reason_code distinguishes synthesised vs upstream decisions.
        let reason = resp.reason_code.as_str();
        assert!(
            reason == "policy_server_timeout"
                || reason == "policy_server_transport_error"
                || reason == "policy_server_denied_on_timeout",
            "unexpected reason_code: {reason}"
        );
        // The proxy signature kid encodes the local DID for audit.
        assert!(
            resp.signature
                .kid
                .starts_with("did:web:soland.local#proxy-"),
            "proxy signature must be marked: {}",
            resp.signature.kid
        );
    }

    #[tokio::test]
    async fn check_signature_invalid_rejected() {
        // Spin up a mock that returns a response whose kid does NOT
        // match the declared policy_server_did.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let signing = signing_key();
        let input = sample_input(true);
        let mut bad_response = signed_sample_response(&input, &signing);
        bad_response.signature.kid = "did:web:imposter.example#key-1".to_owned();
        let resp_body = serde_json::to_string(&bad_response).unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut [0u8; 4096]).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    resp_body.len(),
                    resp_body
                );
                let _ = tokio::io::AsyncWriteExt::write_all(&mut sock, response.as_bytes()).await;
            }
        });

        let url = format!("http://{addr}/_arkret/self/policy/check");
        let cfg = realm_config(&url);
        let client = client_with_policy_key(&signing);
        let cfg_clone = cfg.clone();
        let err = client
            .check(input, move |_| Some(cfg_clone))
            .await
            .expect_err("signature mismatch must be rejected");
        match err {
            PolicyClientError::SignatureInvalid(_) => {}
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_forged_signature_rejected() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let signing = signing_key();
        let input = sample_input(true);
        let bad_response = signed_sample_response(&input, &wrong_signing_key());
        let resp_body = serde_json::to_string(&bad_response).unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut [0u8; 4096]).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    resp_body.len(),
                    resp_body
                );
                let _ = tokio::io::AsyncWriteExt::write_all(&mut sock, response.as_bytes()).await;
            }
        });

        let url = format!("http://{addr}/_arkret/self/policy/check");
        let cfg = realm_config(&url);
        let client = client_with_policy_key(&signing);
        let cfg_clone = cfg.clone();
        let err = client
            .check(input, move |_| Some(cfg_clone))
            .await
            .expect_err("forged signature must be rejected");
        match err {
            PolicyClientError::SignatureInvalid(message) => {
                assert!(
                    message.contains("Ed25519 verify failed"),
                    "unexpected message: {message}"
                );
            }
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }
}
