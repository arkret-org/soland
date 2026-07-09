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

use arkret_sdk::identity::{
    CompositeDidResolver, DidDocument, DidKeyResolver, DidResolver, DidWebResolver,
    DidWebvhResolver,
};
use arkret_sdk::{Did, Error};
use parking_lot::RwLock;
use serde_json::Value;

use crate::config::AppConfig;
use crate::persistence::PersistenceStore;

/// Build the no-IO fallback resolver chain used by tests and sync SDK bridges.
/// Honors the `did_resolver_allow_methods` filter.
pub fn build_did_resolver_chain(config: &AppConfig) -> CompositeDidResolver {
    build_fallback_did_resolver_chain(config)
}

/// Build the async-native resolver service used by `AppState`.
pub fn build_soland_did_resolver(
    config: &AppConfig,
    persistence: Option<Arc<dyn PersistenceStore>>,
) -> SolandDidResolver {
    SolandDidResolver::new(config, persistence)
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
    persistence: Arc<dyn PersistenceStore>,
    fallback: CompositeDidResolver,
    allowed_methods: Vec<String>,
    local_snapshot: RwLock<BTreeMap<Did, DidDocument>>,
}

impl SolandDidResolver {
    fn new(config: &AppConfig, persistence: Option<Arc<dyn PersistenceStore>>) -> Self {
        let persistence = persistence
            .unwrap_or_else(|| Arc::new(crate::persistence::SolandMemoryPersistenceStore::new()));
        Self {
            persistence,
            fallback: build_fallback_did_resolver_chain(config),
            allowed_methods: config.did_resolver_allow_methods.clone(),
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
        self.local_snapshot.read().get(did).cloned()
    }

    fn document_from_record(
        &self,
        did: &Did,
        record: crate::state::WebvhDocumentRecord,
    ) -> Result<DidDocument, Error> {
        let document: DidDocument = serde_json::from_value(record.did_document)
            .map_err(|e| Error::Protocol(format!("local DID document decode failed: {e}")))?;
        if &document.id != did {
            return Err(Error::Protocol("local DID document id mismatch".to_owned()));
        }
        document.validate()?;
        self.local_snapshot
            .write()
            .insert(document.id.clone(), document.clone());
        Ok(document)
    }

    pub fn cache_webvh_record(
        &self,
        record: crate::state::WebvhDocumentRecord,
    ) -> Result<DidDocument, Error> {
        let did = Did::new(record.did.clone()).map_err(Error::from)?;
        self.document_from_record(&did, record)
    }

    pub async fn resolve_did_async(&self, did: &Did) -> Result<DidDocument, Error> {
        if !self.method_allowed(did.method()) {
            return Err(Error::Protocol("DID method not allowed".to_owned()));
        }
        if let Some(document) = self.cached_document(did) {
            return Ok(document);
        }
        if let Some(record) = self
            .persistence
            .webvh()
            .get_document(did.as_str())
            .await
            .map_err(|e| Error::Protocol(format!("local DID store read failed: {e}")))?
        {
            return self.document_from_record(did, record);
        }
        self.fallback.resolve_did(did)
    }
}

impl DidResolver for SolandDidResolver {
    fn supports(&self, did: &Did) -> bool {
        self.cached_document(did).is_some() || self.fallback.supports(did)
    }

    fn resolve_did(&self, did: &Did) -> Result<DidDocument, Error> {
        if let Some(document) = self.cached_document(did) {
            return Ok(document);
        }
        self.fallback.resolve_did(did)
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
/// `ck.server.query.describe`, schema `service-describe.schema.json`).
pub const CANONICAL_DESCRIBE_PATH: &str = "/_arkret/describe";

/// Probe an external webvh provider's canonical describe endpoint
/// (`<URL>/_arkret/describe`) and validate the trust-root handshake before
/// marking it active. The configured URL records admin intent and is still
/// advertised when the probe fails; this function only controls runtime
/// liveness.
pub async fn probe_webvh_provider_describe(
    url: &str,
    timeout: Duration,
    expected_service_did: Option<&str>,
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
    validate_webvh_provider_describe(&body, expected_service_did, expected_trust_domain)?;
    Ok(())
}

/// Validate a canonical ServiceDescribe body for use as a webvh resolver trust
/// root. The four `service-describe.schema.json` required fields are checked:
/// `service_type`, `service_did`, `trust_domain`, `supported_operations`.
fn validate_webvh_provider_describe(
    body: &Value,
    expected_service_did: Option<&str>,
    expected_trust_domain: Option<&str>,
) -> Result<(), String> {
    let service_type = body
        .get("service_type")
        .and_then(Value::as_str)
        .ok_or_else(|| "webvh provider describe missing service_type".to_owned())?;
    if !matches!(service_type, "identity_registry" | "principal_server") {
        return Err(format!(
            "webvh provider service_type must be an identity registry, got {service_type:?}"
        ));
    }
    let service_did = body
        .get("service_did")
        .and_then(Value::as_str)
        .ok_or_else(|| "webvh provider describe missing service_did".to_owned())?;
    Did::new(service_did.to_owned())
        .map_err(|error| format!("webvh provider service_did is invalid: {error}"))?;
    if let Some(expected) = expected_service_did
        && service_did != expected
    {
        return Err(format!(
            "webvh provider service_did mismatch: expected {expected}, got {service_did}"
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
    if !string_array_contains(body.get("supported_operations"), "ck.server.query.describe") {
        return Err(
            "webvh provider describe does not advertise ck.server.query.describe".to_owned(),
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
    use std::net::SocketAddr;
    use std::sync::Arc;

    use arkret_sdk::Did;
    use arkret_sdk::identity::DidResolver;
    use serde_json::json;

    use super::*;
    use crate::config::{IceServersConfig, LiveKitConfig, ObjectStorageConfig};
    use crate::persistence::{PersistenceStore, SolandMemoryPersistenceStore};
    use crate::state::WebvhDocumentRecord;

    fn base_config() -> AppConfig {
        AppConfig {
            public_base_url: "http://127.0.0.1:0".to_owned(),
            service_did: "did:web:soland.test".to_owned(),
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

    #[tokio::test(flavor = "current_thread")]
    async fn soland_resolver_awaits_local_document_and_populates_sync_snapshot() {
        let config = base_config();
        let persistence = Arc::new(SolandMemoryPersistenceStore::new());
        let did = Did::new("did:web:local.example".to_owned()).expect("valid DID");
        let verification_method = format!("{did}#key-1");
        let mut verification_methods = BTreeMap::new();
        verification_methods.insert(
            verification_method,
            arkret_sdk::ed25519_pubkey_to_did_key_multibase(&[7u8; 32]),
        );
        let document = DidDocument {
            id: did.clone(),
            verification_methods,
            also_known_as: Vec::new(),
            updated_at: chrono::Utc::now(),
        };
        let now = chrono::Utc::now();
        persistence
            .webvh()
            .put_document(WebvhDocumentRecord {
                did: did.as_str().to_owned(),
                did_document: serde_json::to_value(&document).expect("document JSON"),
                key_log_head: None,
                seq: 1,
                method_evidence: json!({"mode": "test"}),
                fetched_at: now,
                expires_at: now,
                updated_at: now,
            })
            .await
            .expect("store document");

        let resolver = build_soland_did_resolver(&config, Some(persistence));
        let resolved = resolver
            .resolve_did_async(&did)
            .await
            .expect("async local resolve");

        assert_eq!(resolved.id, did);
        assert!(
            resolver.resolve_did(&did).is_ok(),
            "async resolve should populate the no-IO sync snapshot"
        );
    }

    #[test]
    fn provider_describe_trust_handshake_accepts_canonical_identity_registry() {
        // STA-07-002 — canonical ServiceDescribe shape: service_type +
        // service_did + trust_domain + supported_operations.
        let describe = json!({
            "service_type": "identity_registry",
            "service_did": "did:web:starid.example",
            "trust_domain": "ak:trust_domain:example.net",
            "development_mode": false,
            "supported_operations": ["ck.server.query.describe"]
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
            "service_type": "identity_registry",
            "service_did": "did:web:starid.example",
            "trust_domain": "ak:trust_domain:example.net",
            "development_mode": false,
            "supported_operations": ["ck.server.query.describe"]
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
