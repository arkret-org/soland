//! DID resolver chain wiring. The chain is the single source of truth that
//! `jws_verify` consults when it needs to resolve a JWS `verification_method`
//! DID into a public key.
//!
//! Priority order (first resolver that `supports()` a DID wins):
//!
//! 1. [`LocalIdentityResolver`] — resolves DID documents stored in soland's durable identity store.
//!    This is what makes the embedded `did:webvh` provider usable without an external StarID/webvh
//!    service.
//! 2. [`DidWebvhResolver`] — inserted when the external provider boot probe succeeds. The SDK
//!    resolver is cache-oriented; actual external fetching still belongs to a provider-specific
//!    client.
//! 3. [`DidWebResolver`] — generic `did:web:` fallback. Placed AFTER `DidWebvhResolver` so a
//!    `did:webvh:...` DID never falls through here (DidWebResolver does not support webvh, but
//!    ordering keeps intent clear and makes future `did:web` ↔ `did:webvh` migration semantics
//!    explicit).
//! 4. [`DidKeyResolver`] — pure-cryptographic last-resort.
//!
//! Filtering: [`AppConfig::did_resolver_allow_methods`] is honoured by
//! omitting any resolver whose method is not in the allow list. Method
//! names compared are bare ("web", "webvh", "key") — matching the
//! existing CSV shape produced by `env_csv` in `config.rs`. The allow
//! list MUST be non-empty; an empty list resolves nothing.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use arkret_egress_policy::OutboundPolicy;
use arkret_http_client::http_did_resolver::HttpDidResolver;
use arkret_identity::{
    CompositeDidResolver, DidDocument, DidKeyResolver, DidResolver, DidWebResolver,
    DidWebvhResolver, IdentityError, ResolverFailMode, ResolverPolicy,
    verify_did_webvh_v1_chain_and_witness_bytes,
};
use arkret_wire::{Did, Hash};
use parking_lot::RwLock;
use serde_json::Value;

use crate::config::AppConfig;

/// Build the no-IO fallback resolver chain used by tests and sync SDK bridges.
/// Honors the `did_resolver_allow_methods` filter.
pub fn build_did_resolver_chain(config: &AppConfig) -> CompositeDidResolver {
    build_fallback_did_resolver_chain(config)
}

/// Build the async-native resolver service used by `AppState`.
pub fn build_soland_did_resolver(config: &AppConfig) -> SolandDidResolver {
    SolandDidResolver::new(config)
}

fn build_fallback_did_resolver_chain(config: &AppConfig) -> CompositeDidResolver {
    let mut resolver = CompositeDidResolver::new();
    if method_allowed(config, "webvh") && config.external_webvh_provider_active {
        resolver.push(DidWebvhResolver::new());
    }
    if method_allowed(config, "web") {
        resolver.push(DidWebResolver::new());
    }
    if method_allowed(config, "key") {
        resolver.push(DidKeyResolver::new());
    }
    resolver
}

/// Soland DID resolver boundary.
///
/// Async callers use [`Self::resolve_did_async`], which awaits the durable
/// local DID store directly before falling back to the SDK resolver chain. The
/// sync [`DidResolver`] implementation exists only for SDK APIs that still
/// require a synchronous resolver; it reads the in-process document snapshot
/// and the no-IO SDK fallback chain, so it never blocks an async runtime.
pub struct SolandDidResolver {
    fallback: CompositeDidResolver,
    external: Option<Arc<HttpDidResolver>>,
    allowed_methods: Vec<String>,
    development_mode: bool,
    local_snapshot: RwLock<BTreeMap<Did, CachedDidDocument>>,
}

const LOCAL_DID_SNAPSHOT_CAPACITY: usize = 4_096;

#[derive(Clone)]
struct CachedDidDocument {
    seq: u64,
    document: DidDocument,
}

impl SolandDidResolver {
    fn new(config: &AppConfig) -> Self {
        let external_allowed_methods = config
            .did_resolver_allow_methods
            .iter()
            .filter_map(|method| match method.as_str() {
                "webvh" => Some("did:webvh:".to_owned()),
                "web" => Some("did:web:".to_owned()),
                _ => None,
            })
            .collect();
        let outbound_policy = if config.development_mode {
            OutboundPolicy::local_development()
        } else {
            OutboundPolicy::public_https()
        };
        let external = HttpDidResolver::with_policy_and_egress(
            ResolverPolicy {
                allowed_methods: external_allowed_methods,
                default_principal_method: Some("did:webvh:".to_owned()),
                trust_roots: Vec::new(),
                ttl: Some(chrono::Duration::days(7)),
                fail_mode: ResolverFailMode::FailClosed,
            },
            outbound_policy,
        )
        .ok()
        .map(Arc::new);
        Self {
            fallback: build_fallback_did_resolver_chain(config),
            external,
            allowed_methods: config.did_resolver_allow_methods.clone(),
            development_mode: config.development_mode,
            local_snapshot: RwLock::new(BTreeMap::new()),
        }
    }

    fn method_allowed(&self, method: &str) -> bool {
        self.allowed_methods
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(method))
    }

    fn cached_document(&self, did: &Did) -> Option<DidDocument> {
        if !self.method_allowed(did.method()) {
            return None;
        }
        self.local_snapshot
            .read()
            .get(did)
            .map(|cached| cached.document.clone())
    }

    fn document_from_parts(
        &self,
        did: &Did,
        did_document: Value,
        seq: u64,
    ) -> Result<DidDocument, IdentityError> {
        let document: DidDocument = serde_json::from_value(did_document).map_err(|e| {
            IdentityError::Protocol(format!("local DID document decode failed: {e}"))
        })?;
        if &document.id != did {
            return Err(IdentityError::Protocol(
                "local DID document id mismatch".to_owned(),
            ));
        }
        document.validate()?;
        let mut snapshot = self.local_snapshot.write();
        if let Some(cached) = snapshot.get(did)
            && cached.seq > seq
        {
            return Ok(cached.document.clone());
        }
        if !snapshot.contains_key(did) && snapshot.len() >= LOCAL_DID_SNAPSHOT_CAPACITY {
            // This snapshot is only the synchronous no-I/O fast path. Durable
            // persistence remains authoritative, so deterministic eviction is
            // safe and prevents unbounded growth under attacker-chosen DIDs.
            if let Some(evicted) = snapshot.keys().next().cloned() {
                snapshot.remove(&evicted);
            }
        }
        snapshot.insert(
            document.id.clone(),
            CachedDidDocument {
                seq,
                document: document.clone(),
            },
        );
        Ok(document)
    }

    pub(crate) fn cache_application_webvh_record(
        &self,
        record: soland_services::identity::DidDocumentState,
    ) -> Result<DidDocument, IdentityError> {
        let did = Did::new(record.did).map_err(IdentityError::from)?;
        self.document_from_parts(&did, record.did_document, record.seq)
    }

    pub async fn resolve_did_async(&self, did: &Did) -> Result<DidDocument, IdentityError> {
        if !self.method_allowed(did.method()) {
            return Err(IdentityError::Protocol("DID method not allowed".to_owned()));
        }
        if let Some(document) = self.cached_document(did) {
            return Ok(document);
        }
        if matches!(did.method(), "web" | "webvh")
            && let Some(external) = &self.external
        {
            return external
                .resolve_did_async(did)
                .await
                .map_err(|error| IdentityError::Protocol(error.to_string()));
        }
        self.fallback.resolve_did(did)
    }

    async fn fetch_verified_webvh_history(
        &self,
        did: &Did,
    ) -> Result<arkret_identity::VerifiedDidWebvhLog, String> {
        if !self.method_allowed("webvh") {
            return Err("did:webvh method is disabled by resolver policy".to_owned());
        }
        if did.method() != "webvh" {
            return Err("pinned DID resolution requires did:webvh".to_owned());
        }
        let log_url = self.webvh_url_for_environment(
            DidWebvhResolver::log_url(did).map_err(|error| error.to_string())?,
        )?;
        let log_body = self
            .fetch_webvh_bytes(
                &log_url,
                arkret_identity::DID_WEB_MAX_DOCUMENT_BYTES.saturating_mul(32),
                true,
                "did:webvh pinned history",
            )
            .await?;
        let witness_declared = log_body
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
            .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
            .any(|entry| entry.pointer("/parameters/witness").is_some());
        let witness_body = if witness_declared {
            let witness_url = self.webvh_url_for_environment(
                DidWebvhResolver::witness_url(did).map_err(|error| error.to_string())?,
            )?;
            Some(
                self.fetch_webvh_bytes(
                    &witness_url,
                    arkret_identity::DID_WEB_MAX_DOCUMENT_BYTES.saturating_mul(32),
                    false,
                    "did:webvh pinned witness history",
                )
                .await?,
            )
        } else {
            None
        };
        verify_did_webvh_v1_chain_and_witness_bytes(did, &log_body, witness_body.as_deref())
            .map(|verified| verified.log)
            .map_err(|error| format!("did:webvh history verification failed: {error}"))
    }

    fn webvh_url_for_environment(&self, raw_url: String) -> Result<String, String> {
        let mut url = reqwest::Url::parse(&raw_url)
            .map_err(|error| format!("did:webvh history URL is invalid: {error}"))?;
        if self.development_mode
            && url
                .host_str()
                .and_then(|host| host.parse::<std::net::IpAddr>().ok())
                .is_some_and(|address| address.is_loopback())
        {
            url.set_scheme("http")
                .map_err(|()| "did:webvh loopback history URL scheme is invalid".to_owned())?;
        }
        Ok(url.into())
    }

    async fn fetch_webvh_bytes(
        &self,
        raw_url: &str,
        max_bytes: usize,
        allow_json_lines: bool,
        purpose: &str,
    ) -> Result<Vec<u8>, String> {
        let request_timeout = Duration::from_secs(10);
        let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
            raw_url,
            purpose,
            self.development_mode,
            request_timeout,
        )?;
        let mut response = client
            .get(url)
            .send()
            .await
            .map_err(|error| format!("{purpose} fetch failed: {error}"))?;
        if !response.status().is_success() {
            return Err(format!(
                "{purpose} fetch returned HTTP {}",
                response.status()
            ));
        }
        if response
            .content_length()
            .is_some_and(|length| length > max_bytes as u64)
        {
            return Err(format!("{purpose} exceeds maximum size"));
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let content_type_allowed = matches!(
            content_type.as_str(),
            "application/json" | "application/did+ld+json"
        ) || (allow_json_lines
            && matches!(
                content_type.as_str(),
                "application/jsonl" | "application/jsonlines" | "application/ld+json"
            ));
        if !content_type_allowed {
            return Err(format!(
                "{purpose} response content type is not an allowed JSON type: {content_type}"
            ));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| format!("{purpose} body read failed: {error}"))?
        {
            if body.len().saturating_add(chunk.len()) > max_bytes {
                return Err(format!("{purpose} exceeds maximum size"));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

impl DidResolver for SolandDidResolver {
    fn supports(&self, did: &Did) -> bool {
        self.cached_document(did).is_some() || self.fallback.supports(did)
    }

    fn resolve_did(&self, did: &Did) -> arkret_identity::Result<DidDocument> {
        if let Some(document) = self.cached_document(did) {
            return Ok(document);
        }
        self.fallback.resolve_did(did)
    }
}

#[async_trait::async_trait]
impl soland_services::identity::DidResolverPort for SolandDidResolver {
    async fn resolve_did_async(&self, did: &Did) -> Result<DidDocument, String> {
        SolandDidResolver::resolve_did_async(self, did)
            .await
            .map_err(|error| error.to_string())
    }

    async fn resolve_current_external_webvh_state(
        &self,
        did: &Did,
    ) -> Result<
        soland_services::identity::PinnedDidDocumentState,
        soland_services::identity::PinnedDidResolutionError,
    > {
        use soland_services::identity::{PinnedDidResolutionError, select_pinned_did_webvh_state};
        if did.method() != "webvh" {
            return Err(PinnedDidResolutionError::UnsupportedMethod);
        }
        if !self.method_allowed("webvh") {
            return Err(PinnedDidResolutionError::MethodNotAllowed);
        }
        let history = self
            .fetch_verified_webvh_history(did)
            .await
            .map_err(PinnedDidResolutionError::HistoryUnverifiable)?;
        let head = history.raw_entries.last().ok_or_else(|| {
            PinnedDidResolutionError::HistoryUnverifiable(
                "verified did:webvh history has no head".to_owned(),
            )
        })?;
        let digest = Hash::new(arkret_canonical::canonical_sha256(head).map_err(|error| {
            PinnedDidResolutionError::HistoryUnverifiable(format!(
                "verified did:webvh head digest failed: {error}"
            ))
        })?)
        .map_err(|error| PinnedDidResolutionError::HistoryUnverifiable(error.to_string()))?;
        select_pinned_did_webvh_state(did, &history, &history.head_version_id, &digest)
    }

    async fn resolve_external_pinned_webvh_state(
        &self,
        did: &Did,
        version_id: &str,
        log_head_digest: &Hash,
    ) -> Result<
        soland_services::identity::PinnedDidDocumentState,
        soland_services::identity::PinnedDidResolutionError,
    > {
        use soland_services::identity::{PinnedDidResolutionError, select_pinned_did_webvh_state};
        if did.method() != "webvh" {
            return Err(PinnedDidResolutionError::UnsupportedMethod);
        }
        if !self.method_allowed("webvh") {
            return Err(PinnedDidResolutionError::MethodNotAllowed);
        }
        let history = self
            .fetch_verified_webvh_history(did)
            .await
            .map_err(PinnedDidResolutionError::HistoryUnverifiable)?;
        select_pinned_did_webvh_state(did, &history, version_id, log_head_digest)
    }

    fn cache_document_state(
        &self,
        document: soland_services::identity::DidDocumentState,
    ) -> Result<DidDocument, String> {
        self.cache_application_webvh_record(document)
            .map_err(|error| error.to_string())
    }
}

fn method_allowed(config: &AppConfig, method: &str) -> bool {
    config
        .did_resolver_allow_methods
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(method))
}

/// STA-07-002 — the canonical generic server-describe path. The resolver
/// freshness probe targets this endpoint (operation_id
/// `ak.server.query.describe`, schema `service-describe.schema.json`).
pub const CANONICAL_DESCRIBE_PATH: &str = "/_arkret/describe";

/// Probe an external webvh provider's canonical describe endpoint
/// (`<URL>/_arkret/describe`) and validate the trust-root handshake before
/// marking it active. The configured URL records admin intent and is still
/// advertised when the probe fails; this function only controls runtime
/// liveness.
pub async fn probe_webvh_provider_describe(
    url: &str,
    timeout: Duration,
    expected_service_id: Option<&str>,
    expected_trust_domain: Option<&str>,
    development_mode: bool,
) -> Result<(), String> {
    let trimmed = url.trim_end_matches('/');
    let describe_url = format!("{trimmed}{CANONICAL_DESCRIBE_PATH}");
    // SOL-03-002: pin validated IPs into the client to close the DNS-rebinding
    // TOCTOU window between the egress check and the connection.
    let (describe_url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &describe_url,
        "external webvh provider describe",
        development_mode,
        timeout,
    )?;
    let resp = client
        .get(describe_url)
        .send()
        .await
        .map_err(|e| format!("webvh provider describe request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "webvh provider describe returned non-2xx status {}",
            resp.status()
        ));
    }
    let body = resp
        .json::<Value>()
        .await
        .map_err(|e| format!("webvh provider describe JSON decode failed: {e}"))?;
    validate_webvh_provider_describe(&body, expected_service_id, expected_trust_domain)?;
    Ok(())
}

/// Validate a canonical ServiceDescribe body for use as a webvh resolver trust
/// root. The four `service-describe.schema.json` required fields are checked:
/// `service_kind`, `service_id`, `trust_domain`, `supported_operations`.
fn validate_webvh_provider_describe(
    body: &Value,
    expected_service_id: Option<&str>,
    expected_trust_domain: Option<&str>,
) -> Result<(), String> {
    let service_kind = body
        .get("service_kind")
        .and_then(Value::as_str)
        .ok_or_else(|| "webvh provider describe missing service_kind".to_owned())?;
    if !matches!(service_kind, "identity_registry" | "principal_server") {
        return Err(format!(
            "webvh provider service_kind must be an identity registry, got {service_kind:?}"
        ));
    }
    let service_id = body
        .get("service_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "webvh provider describe missing service_id".to_owned())?;
    Did::new(service_id.to_owned())
        .map_err(|error| format!("webvh provider service_id is invalid: {error}"))?;
    if let Some(expected) = expected_service_id
        && service_id != expected
    {
        return Err(format!(
            "webvh provider service_id mismatch: expected {expected}, got {service_id}"
        ));
    }
    let trust_domain = body
        .get("trust_domain")
        .and_then(Value::as_str)
        .ok_or_else(|| "webvh provider describe missing trust_domain".to_owned())?;
    if !valid_trust_domain(trust_domain) {
        return Err(format!(
            "webvh provider trust_domain is invalid: {trust_domain}"
        ));
    }
    if let Some(expected) = expected_trust_domain
        && trust_domain != expected
    {
        return Err(format!(
            "webvh provider trust_domain mismatch: expected {expected}, got {trust_domain}"
        ));
    }
    if body
        .get("development_mode")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err("webvh provider is in development_mode".to_owned());
    }
    if !string_array_contains(body.get("supported_operations"), "ak.server.query.describe") {
        return Err(
            "webvh provider describe does not advertise ak.server.query.describe".to_owned(),
        );
    }
    Ok(())
}

fn string_array_contains(value: Option<&Value>, needle: &str) -> bool {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|value| value.as_str() == Some(needle))
}

fn valid_trust_domain(value: &str) -> bool {
    let Some(scope) = value.strip_prefix("ak:trust_domain:") else {
        return false;
    };
    if scope.is_empty() || scope.len() > 128 {
        return false;
    }
    let bytes = scope.as_bytes();
    matches!(bytes[0], b'a'..=b'z' | b'0'..=b'9')
        && scope
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' | b':'))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use arkret_identifiers::Did;
    use arkret_identity::{DidResolver, VerifiedDidWebvhLog};
    use arkret_wire::{Hash, PayloadSigner};
    use serde_json::json;
    use soland_services::identity::{
        DidDocumentState, PinnedDidVersionStatus, select_pinned_did_webvh_state,
    };

    use super::*;
    use crate::config::ObjectStorageConfig;

    fn base_config() -> AppConfig {
        AppConfig {
            public_base_url: "http://127.0.0.1:0".to_owned(),
            object_storage: ObjectStorageConfig::local(std::env::temp_dir().join("soland-blobs")),
            did_resolver_allow_methods: vec![
                "web".to_owned(),
                "key".to_owned(),
                "uuid".to_owned(),
                "webvh".to_owned(),
            ],
            jws_replay_window_per_family: std::collections::BTreeMap::new(),
            seed_demo_data: true,
            ..AppConfig::test_default()
        }
    }

    /// `did:webvh:<scid>:<host>:<path...>` — well-formed sample that
    /// `DidWebvhResolver::supports()` accepts after URL-shape validation.
    fn sample_webvh_did() -> Did {
        Did::new("did:webvh:zabc:webvh.example:users:alice").expect("valid did:webvh")
    }

    fn sample_web_did() -> Did {
        Did::new("did:web:alice.example").expect("valid did:web")
    }

    #[test]
    fn current_key_cannot_back_sign_a_proof_for_a_pinned_old_version() {
        let did = Did::new("did:webvh:zFixture:organization.example".to_owned()).unwrap();
        let verification_method = format!("{did}#control");
        let old_signing_key = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
        let current_signing_key = ed25519_dalek::SigningKey::from_bytes(&[22; 32]);
        let document = |key: &ed25519_dalek::SigningKey| arkret_identity::DidDocument {
            id: did.clone(),
            verification_methods: BTreeMap::from([(
                verification_method.clone(),
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    key.verifying_key().as_bytes(),
                ),
            )]),
            also_known_as: Vec::new(),
            updated_at: None,
            raw_properties: BTreeMap::new(),
        };
        let old_document = serde_json::to_value(document(&old_signing_key)).unwrap();
        let current_document = serde_json::to_value(document(&current_signing_key)).unwrap();
        let first_raw = json!({
            "versionId": "1-old",
            "versionTime": "2026-07-01T00:00:00Z",
            "parameters": {"updateKeys": ["old"]},
            "state": old_document,
            "proof": []
        });
        let second_raw = json!({
            "versionId": "2-current",
            "versionTime": "2026-07-02T00:00:00Z",
            "parameters": {"updateKeys": ["current"]},
            "state": current_document,
            "proof": []
        });
        let history = VerifiedDidWebvhLog {
            raw_entries: vec![first_raw.clone(), second_raw],
            entries: vec![
                arkret_identity::DidWebvhLogEntry {
                    version_id: "1-old".to_owned(),
                    version_time: "2026-07-01T00:00:00Z".parse().unwrap(),
                    parameters: json!({"updateKeys": ["old"]}),
                    state: old_document.clone(),
                    proof: Vec::new(),
                },
                arkret_identity::DidWebvhLogEntry {
                    version_id: "2-current".to_owned(),
                    version_time: "2026-07-02T00:00:00Z".parse().unwrap(),
                    parameters: json!({"updateKeys": ["current"]}),
                    state: current_document.clone(),
                    proof: Vec::new(),
                },
            ],
            head_version_id: "2-current".to_owned(),
            head_state: current_document.clone(),
            active_update_keys: vec!["current".to_owned()],
        };
        let first_digest =
            Hash::new(arkret_canonical::canonical_sha256(&first_raw).unwrap()).unwrap();
        let pinned = select_pinned_did_webvh_state(&did, &history, "1-old", &first_digest).unwrap();
        assert_eq!(pinned.status, PinnedDidVersionStatus::Rotated);

        let payload = br#"{"context":"pinned-old-version"}"#;
        let current_signer = arkret_signatures::Ed25519PayloadSigner::new(
            current_signing_key,
            did.clone(),
            verification_method.clone(),
        );
        let signature = current_signer.sign_payload(payload).unwrap();
        assert!(
            crate::jws_verify::verify_jws_ed25519_with_document(
                payload,
                &signature.jws,
                &verification_method,
                did.as_str(),
                &current_document,
            )
            .is_ok(),
            "test signature must be valid under the current key"
        );
        assert!(
            crate::jws_verify::verify_jws_ed25519_with_document(
                payload,
                &signature.jws,
                &verification_method,
                did.as_str(),
                &pinned.document,
            )
            .is_err(),
            "a current key must not authenticate a transcript pinned to the old version"
        );
    }

    #[test]
    fn chain_includes_webvh_resolver_when_active() {
        let mut config = base_config();
        config.external_webvh_provider_url = Some("https://webvh.example".to_owned());
        config.external_webvh_provider_active = true;
        let chain = build_did_resolver_chain(&config);

        // The webvh resolver claims `supports()` purely on DID method +
        // URL shape — no cache hit required. So the chain reports
        // `supports()` true for a well-formed did:webvh DID exactly when
        // a webvh resolver is in the chain.
        assert!(
            chain.supports(&sample_webvh_did()),
            "chain should support did:webvh when external provider resolver is active"
        );
    }

    #[test]
    fn chain_omits_webvh_resolver_when_inactive_even_if_url_set() {
        // C36.2 — admin set the URL (intent) but the boot probe failed,
        // so `active` stays false. The chain MUST NOT mount the resolver,
        // but `/identity/describe` keeps advertising the profile (tested
        // separately in `routing/identity.rs`).
        let mut config = base_config();
        config.external_webvh_provider_url = Some("https://webvh.example".to_owned());
        config.external_webvh_provider_active = false;
        let chain = build_did_resolver_chain(&config);

        assert!(
            !chain.supports(&sample_webvh_did()),
            "chain must NOT support did:webvh when active flag is false"
        );
        // The other methods should still be reachable.
        assert!(chain.supports(&sample_web_did()));
    }

    #[test]
    fn chain_omits_webvh_resolver_when_url_absent() {
        let mut config = base_config();
        config.external_webvh_provider_url = None;
        config.external_webvh_provider_active = false;
        let chain = build_did_resolver_chain(&config);

        assert!(
            !chain.supports(&sample_webvh_did()),
            "chain must NOT support did:webvh when external provider url is absent"
        );
        // The other methods should still be reachable.
        assert!(chain.supports(&sample_web_did()));
    }

    #[test]
    fn chain_priority_puts_webvh_before_web() {
        // Property under test: when both webvh and web resolvers are in
        // the chain, a `did:webvh:...` DID is handled by the webvh
        // resolver — it does NOT fall through to `DidWebResolver`. This
        // matters because `DidWebResolver::supports()` returns false for
        // `did:webvh:` (method != "web"), but ordering still encodes
        // intent and protects against future fallback-style behavior.
        let mut config = base_config();
        config.external_webvh_provider_url = Some("https://webvh.example".to_owned());
        config.external_webvh_provider_active = true;
        let chain = build_did_resolver_chain(&config);

        // Resolver returns `Err("did:webvh document not cached")` from
        // the webvh resolver — proves dispatch went to webvh, not web
        // (web would say `did:web document not found`).
        let err = chain
            .resolve_did(&sample_webvh_did())
            .expect_err("uncached webvh DID should error");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("webvh"),
            "expected webvh-flavored error, got: {msg}"
        );
    }

    #[test]
    fn did_resolver_allow_methods_filter_applies_to_webvh() {
        // allow list excludes "webvh" → resolver omitted even when active.
        let mut config = base_config();
        config.did_resolver_allow_methods =
            vec!["web".to_owned(), "key".to_owned(), "uuid".to_owned()];
        config.external_webvh_provider_url = Some("https://webvh.example".to_owned());
        config.external_webvh_provider_active = true;
        let chain = build_did_resolver_chain(&config);
        assert!(
            !chain.supports(&sample_webvh_did()),
            "webvh resolver must be omitted when allow list excludes 'webvh'"
        );
    }

    #[test]
    fn empty_allow_methods_resolves_nothing() {
        let mut config = base_config();
        config.did_resolver_allow_methods.clear();
        config.external_webvh_provider_url = Some("https://webvh.example".to_owned());
        config.external_webvh_provider_active = true;
        let chain = build_did_resolver_chain(&config);
        assert!(!chain.supports(&sample_webvh_did()));
        assert!(!chain.supports(&sample_web_did()));
    }

    #[test]
    fn resolver_snapshot_does_not_regress_to_an_older_did_sequence() {
        let config = base_config();
        let resolver = build_soland_did_resolver(&config);
        let did = Did::new("did:web:cache.example".to_owned()).expect("valid DID");
        let verification_method = format!("{did}#key-1");
        let record = |seq: u64, key_byte: u8| {
            let document = DidDocument {
                id: did.clone(),
                verification_methods: BTreeMap::from([(
                    verification_method.clone(),
                    arkret_canonical::ed25519_pubkey_to_did_key_multibase(&[key_byte; 32]),
                )]),
                also_known_as: Vec::new(),
                updated_at: Some(chrono::Utc::now()),
                raw_properties: BTreeMap::new(),
            };
            let now = chrono::Utc::now();
            DidDocumentState {
                did: did.as_str().to_owned(),
                did_document: serde_json::to_value(document).expect("document JSON"),
                key_log_head: None,
                seq,
                method_evidence: json!({"mode": "test"}),
                fetched_at: now,
                expires_at: now,
                updated_at: now,
            }
        };

        resolver
            .cache_application_webvh_record(record(2, 2))
            .expect("newer record caches");
        resolver
            .cache_application_webvh_record(record(1, 1))
            .expect("stale cache fill returns the current projection");

        let resolved = resolver.resolve_did(&did).expect("snapshot resolve");
        assert_eq!(
            resolved.verification_methods[&verification_method],
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(&[2u8; 32])
        );
    }

    #[test]
    fn resolver_snapshot_has_a_hard_capacity() {
        let config = base_config();
        let resolver = build_soland_did_resolver(&config);
        let now = chrono::Utc::now();
        let public_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&[7u8; 32]);
        for index in 0..=LOCAL_DID_SNAPSHOT_CAPACITY {
            let did = Did::new(format!("did:web:cache-{index}.example")).expect("valid DID");
            let document =
                DidDocument::new(did.clone(), format!("{did}#key-1"), public_key.clone());
            resolver
                .cache_application_webvh_record(DidDocumentState {
                    did: did.to_string(),
                    did_document: serde_json::to_value(document).expect("document JSON"),
                    key_log_head: None,
                    seq: 1,
                    method_evidence: json!({"mode": "test"}),
                    fetched_at: now,
                    expires_at: now,
                    updated_at: now,
                })
                .expect("record caches");
        }

        assert_eq!(
            resolver.local_snapshot.read().len(),
            LOCAL_DID_SNAPSHOT_CAPACITY
        );
    }

    #[test]
    fn provider_describe_trust_handshake_accepts_canonical_identity_registry() {
        // STA-07-002 — canonical ServiceDescribe shape: service_kind +
        // service_id + trust_domain + supported_operations.
        let describe = json!({
            "service_kind": "identity_registry",
            "service_id": "did:web:starid.example",
            "trust_domain": "ak:trust_domain:example.net",
            "development_mode": false,
            "supported_operations": ["ak.server.query.describe"]
        });
        validate_webvh_provider_describe(
            &describe,
            Some("did:web:starid.example"),
            Some("ak:trust_domain:example.net"),
        )
        .expect("valid canonical identity_registry describe should pass");
    }

    #[test]
    fn provider_describe_trust_handshake_rejects_mismatch_and_dev() {
        let mut describe = json!({
            "service_kind": "identity_registry",
            "service_id": "did:web:starid.example",
            "trust_domain": "ak:trust_domain:example.net",
            "development_mode": false,
            "supported_operations": ["ak.server.query.describe"]
        });
        let err = validate_webvh_provider_describe(
            &describe,
            Some("did:web:starid.example"),
            Some("ak:trust_domain:other.example"),
        )
        .expect_err("trust-domain mismatch must fail closed");
        assert!(err.contains("trust_domain mismatch"), "{err}");

        describe["development_mode"] = json!(true);
        let err = validate_webvh_provider_describe(
            &describe,
            Some("did:web:starid.example"),
            Some("ak:trust_domain:example.net"),
        )
        .expect_err("development-mode provider must fail closed");
        assert!(err.contains("development_mode"), "{err}");
    }
}
