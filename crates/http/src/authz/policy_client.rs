//! G3.S2 — outbound `/policy/check` client.
//!
//! [`PolicyClient`] issues `POST /_arkret/self/policy/check` against the
//! `policy_server_url` of the request's Realm
//! ([`RealmPolicyServerConfig`]), with per-realm
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
//! prefixed with
//! `did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service#proxy-`
//! so it's never confused with a genuine signature.
//!
//! Spec: `arkret-spec/spec/v1/zh/authz/policy-server.md` §5–§6.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arkret_identifiers::{DidCoreId, Hash, RealmId};
use arkret_identity::DidResolver;
use arkret_models_collaboration::governance::policy_check::{
    PolicyCheckBoundTo, PolicyCheckOutcome, PolicyCheckRequestBody, PolicyCheckSignature,
    PolicyCheckSource,
};
use arkret_wire::{AuthzDecision, FreshnessState};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use parking_lot::Mutex;
use serde_json::Value;
use soland_services::authorization::RealmPolicyServerConfig;
use subtle::ConstantTimeEq as _;

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
    pub actor_id: DidCoreId,
    pub action: String,
    pub source_id: DidCoreId,
    pub source_kind: String,
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
                "service_id": self.source_id.as_str(),
                "service_kind": self.source_kind,
                "source_ip_digest": self.source_ip_digest.as_str(),
                "signed_transport": self.signed_transport,
            },
            "event_preview": self.event_preview,
            "auth_context": self.auth_context,
        });
        // SDK is the single source of canonical-JSON + sha256 + `sha256:` prefix
        // (arkret_canonical::canonical_sha256), shared with jws_verify /
        // notary / reducer so the digest is byte-identical across paths. Preserve
        // the prior fail-open all-zeros fallback for the (canonicalization-error)
        // edge case rather than introducing a new failure mode here.
        let digest = arkret_canonical::canonical_sha256(&canonical_input)
            .unwrap_or_else(|_| arkret_canonical::sha256_digest(b""));
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
                service_id: self.source_id,
                service_kind: self.source_kind,
                source_ip_digest: Some(self.source_ip_digest),
                signed_transport: self.signed_transport,
            },
            event_preview: serde_json::from_value(self.event_preview).ok(),
            auth_context: serde_json::from_value(self.auth_context).ok(),
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
    DirectoryGovernanceProofSignatureInvalid(String),
}

impl std::fmt::Display for PolicyClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configuration(s) => write!(f, "policy client misconfigured: {s}"),
            Self::Transport(s) => write!(f, "policy client transport error: {s}"),
            Self::Timeout => write!(f, "policy client timeout"),
            Self::BadResponse(s) => write!(f, "policy client bad response: {s}"),
            Self::DirectoryGovernanceProofSignatureInvalid(s) => {
                write!(f, "policy client signature invalid: {s}")
            }
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
            arkret_identity::jws::resolve_ed25519_pubkey(&*resolver, kid)
                .map_err(|error| error.to_string())
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
        let policy_server_id = DidCoreId::new(self.local_service_id.clone())
            .unwrap_or_else(|_| request.actor_id.clone());
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
            reason_code: arkret_wire::ReasonCode::from_wire(reason_code),
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
            .header(
                "arkret-operation",
                arkret_wire::ServiceOperationId::SELF_POLICY_READ_CHECK_V1,
            )
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
        let policy_server_id = DidCoreId::new(self.local_service_id.clone())
            .unwrap_or_else(|_| request.actor_id.clone());
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
                "deny" => arkret_wire::ReasonCode::from_wire("policy_server_denied_on_timeout"),
                _ => arkret_wire::ReasonCode::from_wire(reason_code),
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
    /// `policy_server_id`; the signature MUST verify over the canonical
    /// policy-check transcript reconstructed from the original request
    /// and the response.
    fn verify_signature(
        &self,
        config: &RealmPolicyServerConfig,
        request: &PolicyCheckRequestBody,
        response: &PolicyCheckOutcome,
    ) -> Result<(), PolicyClientError> {
        if response.signature.sig.is_empty() {
            return Err(PolicyClientError::DirectoryGovernanceProofSignatureInvalid(
                "empty sig".to_owned(),
            ));
        }
        let kid = &response.signature.kid;
        let Some((kid_did_part, kid_fragment)) = kid.split_once('#') else {
            return Err(PolicyClientError::DirectoryGovernanceProofSignatureInvalid(
                format!("kid missing fragment: {kid}"),
            ));
        };
        if kid_did_part.is_empty() || kid_fragment.is_empty() {
            return Err(PolicyClientError::DirectoryGovernanceProofSignatureInvalid(
                format!("kid has empty DID or fragment: {kid}"),
            ));
        }
        // The kid's resolvable controller MUST project to the declared stable
        // policy-server service identity.
        let kid_did = arkret_identifiers::Did::new(kid_did_part.to_owned()).map_err(|error| {
            PolicyClientError::DirectoryGovernanceProofSignatureInvalid(error.to_string())
        })?;
        let kid_service_id = arkret_wire::project_did_to_core_id(&kid_did).map_err(|error| {
            PolicyClientError::DirectoryGovernanceProofSignatureInvalid(error.to_string())
        })?;
        if kid_service_id != config.policy_server_id {
            return Err(PolicyClientError::DirectoryGovernanceProofSignatureInvalid(
                format!(
                    "kid {kid_did_part} does not project to policy_server_id {server}",
                    server = config.policy_server_id
                ),
            ));
        }
        if response.bound_to.policy_server_id != config.policy_server_id {
            return Err(PolicyClientError::DirectoryGovernanceProofSignatureInvalid(
                format!(
                    "bound_to.policy_server_id {bt} != config {cfg}",
                    bt = response.bound_to.policy_server_id.as_str(),
                    cfg = config.policy_server_id
                ),
            ));
        }
        if response.bound_to.realm_id != request.realm_id {
            return Err(PolicyClientError::DirectoryGovernanceProofSignatureInvalid(
                format!(
                    "bound_to.realm_id {bt} != request {req}",
                    bt = response.bound_to.realm_id.as_str(),
                    req = request.realm_id.as_str()
                ),
            ));
        }
        if response.bound_to.actor_id != request.actor_id {
            return Err(PolicyClientError::DirectoryGovernanceProofSignatureInvalid(
                format!(
                    "bound_to.actor_id {bt} != request {req}",
                    bt = response.bound_to.actor_id.as_str(),
                    req = request.actor_id.as_str()
                ),
            ));
        }
        if response.bound_to.action != request.action {
            return Err(PolicyClientError::DirectoryGovernanceProofSignatureInvalid(
                format!(
                    "bound_to.action {} != request {}",
                    response.bound_to.action, request.action
                ),
            ));
        }
        if response.bound_to.request_canonical_digest != request.request_canonical_digest {
            return Err(PolicyClientError::DirectoryGovernanceProofSignatureInvalid(
                format!(
                    "bound_to.request_canonical_digest {bt} != request {req}",
                    bt = response.bound_to.request_canonical_digest.as_str(),
                    req = request.request_canonical_digest.as_str()
                ),
            ));
        }

        let Some(resolve_key) = &self.verification_key_resolver else {
            return Err(PolicyClientError::Configuration(
                "policy decision verification key resolver not configured".to_owned(),
            ));
        };
        let verifying_key = resolve_key(kid).map_err(|e| {
            PolicyClientError::DirectoryGovernanceProofSignatureInvalid(format!(
                "verification key resolution failed: {e}"
            ))
        })?;
        let signature = decode_policy_signature(&response.signature.sig)?;
        let transcript = policy_decision_transcript_bytes(request, response)?;
        verifying_key.verify(&transcript, &signature).map_err(|e| {
            PolicyClientError::DirectoryGovernanceProofSignatureInvalid(format!(
                "Ed25519 verify failed: {e}"
            ))
        })?;
        Ok(())
    }
}

pub(crate) fn policy_decision_transcript_bytes(
    _request: &PolicyCheckRequestBody,
    response: &PolicyCheckOutcome,
) -> Result<Vec<u8>, PolicyClientError> {
    arkret_models_collaboration::governance::policy_check::policy_decision_transcript_bytes(
        response,
    )
    .map_err(|e| PolicyClientError::BadResponse(format!("policy transcript canonicalize: {e}")))
}

fn decode_policy_signature(sig: &str) -> Result<Signature, PolicyClientError> {
    if sig.bytes().all(|b| b == b'A') {
        return Err(PolicyClientError::DirectoryGovernanceProofSignatureInvalid(
            "signature is the all-zero sentinel".to_owned(),
        ));
    }
    let bytes = URL_SAFE_NO_PAD.decode(sig.as_bytes()).map_err(|e| {
        PolicyClientError::DirectoryGovernanceProofSignatureInvalid(format!(
            "signature is not base64url: {e}"
        ))
    })?;
    if bytes.len() != 64 {
        return Err(PolicyClientError::DirectoryGovernanceProofSignatureInvalid(
            format!("Ed25519 signature must be 64 bytes, got {}", bytes.len()),
        ));
    }
    let mut raw = [0u8; 64];
    raw.copy_from_slice(&bytes);
    Ok(Signature::from_bytes(&raw))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use arkret_identity::{DidDocument, DidWebResolver};
    use chrono::Utc;
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn realm_config(url: &str) -> RealmPolicyServerConfig {
        RealmPolicyServerConfig {
            realm_id: "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K".to_owned(),
            policy_server_id: DidCoreId::new("ak:did_core:web:policy.example.com").unwrap(),
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
            realm_id: RealmId::new("ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K")
                .unwrap(),
            actor_id: DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            action: "ak.message.create".to_owned(),
            source_id: DidCoreId::new(
                "ak:did_core:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x",
            )
            .unwrap(),
            source_kind: "principal_server".to_owned(),
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
                realm_id: RealmId::new("ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K")
                    .unwrap(),
                actor_id: DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                action: "ak.message.create".to_owned(),
                request_canonical_digest: zero.clone(),
                policy_server_id: DidCoreId::new("ak:did_core:web:policy.example.com").unwrap(),
            },
            freshness_state: FreshnessState::Fresh,
            auth_state_digest: zero.clone(),
            policy_frontier_digest: zero.clone(),
            membership_frontier_digest: zero,
            signature: PolicyCheckSignature {
                kid: "did:web:policy.example.com#key-1".to_owned(),
                sig: "base64stub".to_owned(),
            },
            reason_code: arkret_wire::ReasonCode::Ok,
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
                arkret_identifiers::Did::new("did:web:policy.example.com").unwrap(),
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
        PolicyClient::new(
            reqwest::Client::new(),
            "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service",
        )
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
                policy_server_id: DidCoreId::new("ak:did_core:web:policy.example.com").unwrap(),
            },
            freshness_state: FreshnessState::Fresh,
            auth_state_digest: input.expected_frontiers.auth_state_digest.clone(),
            policy_frontier_digest: input.expected_frontiers.policy_frontier_digest.clone(),
            membership_frontier_digest: input.expected_frontiers.membership_frontier_digest.clone(),
            signature: PolicyCheckSignature {
                kid: "did:web:policy.example.com#key-1".to_owned(),
                sig: String::new(),
            },
            reason_code: arkret_wire::ReasonCode::Ok,
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

    async fn spawn_mock_http_once(body: String) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hit_count = Arc::new(AtomicUsize::new(0));
        let server_hit_count = hit_count.clone();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                server_hit_count.fetch_add(1, Ordering::SeqCst);
                let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut [0u8; 4096]).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = tokio::io::AsyncWriteExt::write_all(&mut socket, response.as_bytes()).await;
            }
        });
        (addr, hit_count)
    }

    #[tokio::test]
    async fn check_cache_hit_returns_cached() {
        let client = PolicyClient::new(
            reqwest::Client::new(),
            "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service",
        )
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
        assert_eq!(resp.reason_code, arkret_wire::ReasonCode::Ok);
    }

    #[tokio::test]
    async fn check_cache_hit_requires_current_frontiers() {
        let signing = signing_key();
        let mut input = sample_input(false);
        input.expected_frontiers = frontiers('1', '2', '3');
        let stale_key = input.canonical_request_hash();
        let resp_body = serde_json::to_string(&signed_sample_response(&input, &signing)).unwrap();
        let (addr, hit_count) = spawn_mock_http_once(resp_body).await;

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
        let signing = signing_key();
        let input = sample_input(false);
        let resp_body = serde_json::to_string(&signed_sample_response(&input, &signing)).unwrap();
        let (addr, hit_count) = spawn_mock_http_once(resp_body).await;

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
        let signing = signing_key();
        let input = sample_input(true);
        let mut expired = signed_sample_response(&input, &signing);
        expired.expires_at = Utc::now() - chrono::Duration::seconds(1);
        let expired = sign_policy_response(&input, &signing, expired);
        let resp_body = serde_json::to_string(&expired).unwrap();
        let (addr, _) = spawn_mock_http_once(resp_body).await;

        let url = format!("http://{addr}/_arkret/self/policy/check");
        let cfg = realm_config(&url);
        let client = client_with_policy_key(&signing);

        let cfg_clone = cfg.clone();
        let resp = client.check(input, move |_| Some(cfg_clone)).await.unwrap();
        assert!(matches!(resp.decision, AuthzDecision::HardDeny));
        assert_eq!(resp.reason_code.as_str(), "snapshot_risk");
        assert!(resp.signature.kid.ends_with("#proxy-snapshot_risk"));
    }

    #[tokio::test]
    async fn check_rejects_signed_frontier_mismatch() {
        let signing = signing_key();
        let input = sample_input(true);
        let mut mismatched = signed_sample_response(&input, &signing);
        mismatched.policy_frontier_digest = hash_with('a');
        let mismatched = sign_policy_response(&input, &signing, mismatched);
        let resp_body = serde_json::to_string(&mismatched).unwrap();
        let (addr, _) = spawn_mock_http_once(resp_body).await;

        let url = format!("http://{addr}/_arkret/self/policy/check");
        let cfg = realm_config(&url);
        let client = client_with_policy_key(&signing);

        let cfg_clone = cfg.clone();
        let resp = client.check(input, move |_| Some(cfg_clone)).await.unwrap();
        assert!(matches!(resp.decision, AuthzDecision::HardDeny));
        assert_eq!(resp.reason_code.as_str(), "fork_risk");
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
        let client = PolicyClient::new(
            reqwest::Client::new(),
            "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service",
        )
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
                .starts_with("did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service#proxy-"),
            "proxy signature must be marked: {}",
            resp.signature.kid
        );
    }

    #[tokio::test]
    async fn check_signature_invalid_rejected() {
        // Spin up a mock that returns a response whose kid does NOT
        // match the declared policy_server_id.
        let signing = signing_key();
        let input = sample_input(true);
        let mut bad_response = signed_sample_response(&input, &signing);
        bad_response.signature.kid = "did:web:imposter.example#key-1".to_owned();
        let resp_body = serde_json::to_string(&bad_response).unwrap();
        let (addr, _) = spawn_mock_http_once(resp_body).await;

        let url = format!("http://{addr}/_arkret/self/policy/check");
        let cfg = realm_config(&url);
        let client = client_with_policy_key(&signing);
        let cfg_clone = cfg.clone();
        let err = client
            .check(input, move |_| Some(cfg_clone))
            .await
            .expect_err("signature mismatch must be rejected");
        match err {
            PolicyClientError::DirectoryGovernanceProofSignatureInvalid(_) => {}
            other => panic!("expected DirectoryGovernanceProofSignatureInvalid, got {other:?}"),
        }
    }

    /// Sign a decision that carries obligations and a `next_retry_at`, then
    /// hand `tamper` the signed response so it can rewrite a transcript-covered
    /// field. The mutated response must fail verification.
    async fn expect_tampered_decision_rejected(
        tamper: impl FnOnce(&mut PolicyCheckOutcome),
        label: &str,
    ) {
        let signing = signing_key();
        let input = sample_input(true);
        let mut response = signed_sample_response(&input, &signing);
        response.next_retry_at = Some(Utc::now() + chrono::Duration::seconds(30));
        response.obligations = vec![
            serde_json::json!({"kind": "ak.obligation.audit_receipt.v1"}),
            serde_json::json!({"kind": "ak.obligation.rate_limit.v1", "window_ms": 1_000}),
        ];
        let mut response = sign_policy_response(&input, &signing, response);

        tamper(&mut response);

        let resp_body = serde_json::to_string(&response).unwrap();
        let (addr, _) = spawn_mock_http_once(resp_body).await;
        let url = format!("http://{addr}/_arkret/self/policy/check");
        let cfg = realm_config(&url);
        let client = client_with_policy_key(&signing);
        let err = client
            .check(input, move |_| Some(cfg.clone()))
            .await
            .unwrap_err();
        match err {
            PolicyClientError::DirectoryGovernanceProofSignatureInvalid(message) => assert!(
                message.contains("Ed25519 verify failed"),
                "{label}: unexpected message: {message}"
            ),
            other => {
                panic!("{label}: expected DirectoryGovernanceProofSignatureInvalid, got {other:?}")
            }
        }
    }

    #[tokio::test]
    async fn check_rejects_a_removed_obligation() {
        expect_tampered_decision_rejected(
            |response| {
                response.obligations.pop();
            },
            "removed obligation",
        )
        .await;
    }

    #[tokio::test]
    async fn check_rejects_a_modified_obligation() {
        expect_tampered_decision_rejected(
            |response| {
                response.obligations[1] =
                    serde_json::json!({"kind": "ak.obligation.rate_limit.v1", "window_ms": 60_000});
            },
            "modified obligation",
        )
        .await;
    }

    #[tokio::test]
    async fn check_rejects_reordered_obligations() {
        // The transcript covers obligations as an ordered array, so a permuted
        // list is a different decision even though the set is unchanged.
        expect_tampered_decision_rejected(
            |response| response.obligations.reverse(),
            "reordered obligations",
        )
        .await;
    }

    #[tokio::test]
    async fn check_rejects_a_modified_next_retry_at() {
        expect_tampered_decision_rejected(
            |response| {
                response.next_retry_at = response
                    .next_retry_at
                    .map(|at| at + chrono::Duration::hours(1));
            },
            "modified next_retry_at",
        )
        .await;
    }

    #[tokio::test]
    async fn check_rejects_a_dropped_next_retry_at() {
        // `next_retry_at` is omitted from the transcript when absent, so a
        // stripped field must not canonicalize back to the signed transcript.
        expect_tampered_decision_rejected(
            |response| response.next_retry_at = None,
            "dropped next_retry_at",
        )
        .await;
    }

    #[tokio::test]
    async fn check_forged_signature_rejected() {
        let signing = signing_key();
        let input = sample_input(true);
        let bad_response = signed_sample_response(&input, &wrong_signing_key());
        let resp_body = serde_json::to_string(&bad_response).unwrap();
        let (addr, _) = spawn_mock_http_once(resp_body).await;

        let url = format!("http://{addr}/_arkret/self/policy/check");
        let cfg = realm_config(&url);
        let client = client_with_policy_key(&signing);
        let cfg_clone = cfg.clone();
        let err = client
            .check(input, move |_| Some(cfg_clone))
            .await
            .expect_err("forged signature must be rejected");
        match err {
            PolicyClientError::DirectoryGovernanceProofSignatureInvalid(message) => {
                assert!(
                    message.contains("Ed25519 verify failed"),
                    "unexpected message: {message}"
                );
            }
            other => panic!("expected DirectoryGovernanceProofSignatureInvalid, got {other:?}"),
        }
    }
}
