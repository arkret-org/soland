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

use std::sync::Arc;
use std::time::Duration;

use cokret_sdk::identity::{
    CompositeDidResolver, DidDocument, DidKeyResolver, DidResolver, DidWebResolver,
    DidWebvhResolver,
};
use cokret_sdk::{Did, Error};
use serde_json::Value;

use crate::config::AppConfig;
use crate::persistence::PersistenceStore;

/// Build the production `CompositeDidResolver` chain for `AppState`.
/// Honors the `did_resolver_allow_methods` filter.
pub fn build_did_resolver_chain(config: &AppConfig) -> CompositeDidResolver {
    build_did_resolver_chain_with_identity(config, None)
}

/// Build the resolver chain and optionally place soland's local identity
/// store first. Tests that only care about static resolver composition can use
/// [`build_did_resolver_chain`]; `AppState` uses this variant so newly
/// registered embedded webvh DIDs are immediately resolvable by signature
/// verification.
pub fn build_did_resolver_chain_with_identity(
    config: &AppConfig,
    persistence: Option<Arc<dyn PersistenceStore>>,
) -> CompositeDidResolver {
    let mut resolver = CompositeDidResolver::new();
    if let Some(persistence) = persistence {
        resolver.push(LocalIdentityResolver {
            persistence,
            allowed_methods: config.did_resolver_allow_methods.clone(),
        });
    }
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

struct LocalIdentityResolver {
    persistence: Arc<dyn PersistenceStore>,
    allowed_methods: Vec<String>,
}

impl LocalIdentityResolver {
    fn method_allowed(&self, method: &str) -> bool {
        self.allowed_methods
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(method))
    }

    fn document(&self, did: &Did) -> Result<DidDocument, Error> {
        if !self.method_allowed(did.method()) {
            return Err(Error::Protocol("DID method not allowed".to_owned()));
        }
        let persistence = self.persistence.clone();
        let did_str = did.as_str().to_owned();
        let lookup = blocking_webvh_document_lookup(persistence, did_str)
            .map_err(|e| Error::Protocol(format!("local DID store read failed: {e}")))?;
        let Some(record) =
            lookup.map_err(|e| Error::Protocol(format!("local DID store read failed: {e}")))?
        else {
            return Err(Error::Protocol("local DID document not found".to_owned()));
        };
        let document: DidDocument = serde_json::from_value(record.did_document)
            .map_err(|e| Error::Protocol(format!("local DID document decode failed: {e}")))?;
        if &document.id != did {
            return Err(Error::Protocol("local DID document id mismatch".to_owned()));
        }
        document.validate()?;
        Ok(document)
    }
}

fn blocking_webvh_document_lookup(
    persistence: Arc<dyn PersistenceStore>,
    did: String,
) -> Result<crate::persistence::PersistenceResult<Option<crate::state::WebvhDocumentRecord>>, String>
{
    let fut = async move { persistence.webvh().get_document(&did).await };
    match tokio::runtime::Handle::try_current() {
        // Inside the production multi-threaded runtime: reuse the shared runtime
        // handle rather than spawning a fresh OS thread + building a brand-new
        // current-thread runtime on every DID resolution. `block_in_place` moves
        // this worker off the async poll loop so blocking on the DB query does not
        // stall the executor (SOL-02-003).
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            Ok(tokio::task::block_in_place(|| handle.block_on(fut)))
        }
        // Inside a current-thread runtime (e.g. `#[tokio::test]`): `block_in_place`
        // would panic, so run the future on a separate thread with its own
        // throwaway runtime and join it.
        Ok(_) => std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?;
            Ok(runtime.block_on(fut))
        })
        .join()
        .map_err(|_| "local DID lookup worker panicked".to_owned())?,
        // No runtime in scope (cold path): build a throwaway runtime inline.
        Err(_) => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?;
            Ok(runtime.block_on(fut))
        }
    }
}

impl DidResolver for LocalIdentityResolver {
    fn supports(&self, did: &Did) -> bool {
        self.document(did).is_ok()
    }

    fn resolve_did(&self, did: &Did) -> Result<DidDocument, Error> {
        self.document(did)
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
pub const CANONICAL_DESCRIBE_PATH: &str = "/_cokret/describe";

/// Probe an external webvh provider's canonical describe endpoint
/// (`<URL>/_cokret/describe`) and validate the trust-root handshake before
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
    let Some(scope) = value.strip_prefix("ck:trust_domain:") else {
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
    use std::net::SocketAddr;

    use cokret_sdk::Did;
    use cokret_sdk::identity::DidResolver;
    use serde_json::json;

    use super::*;
    use crate::config::{IceServersConfig, ObjectStorageConfig};

    fn base_config() -> AppConfig {
        AppConfig {
            bind: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            metrics_bind: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            public_base_url: "http://127.0.0.1:0".to_owned(),
            service_did: "did:web:soland.test".to_owned(),
            tls_cert_path: None,
            tls_key_path: None,
            database_url: None,
            object_storage: ObjectStorageConfig::local(std::env::temp_dir().join("soland-blobs")),
            ice: IceServersConfig::default(),
            cors_allow_origin: None,
            auth_server_url: None,
            development_mode: false,
            oauth_introspection_url: None,
            oauth_introspection_bearer: None,
            session_grant_introspection_url: None,
            session_grant_introspection_bearer: None,
            did_resolver_allow_methods: vec![
                "web".to_owned(),
                "key".to_owned(),
                "uuid".to_owned(),
                "webvh".to_owned(),
            ],
            embedded_webvh_provider_enabled: false,
            embedded_webvh_registration_bearer: None,
            external_webvh_provider_url: None,
            external_webvh_provider_active: false,
            default_webvh_provider_id: None,
            jws_replay_window_seconds: 300,
            jws_replay_window_per_family: std::collections::BTreeMap::new(),
            notary_signing_key_seed: None,
            agent_audit_binding_signing_seed: None,
            use_keystore: false,
            federation_policy: crate::config::FederationPolicy::Mesh,
            federation_peers: Vec::new(),
            federation_outbound_enabled: false,
            admin_default_page_limit: 100,
            admin_max_page_limit: 1000,
            admin_principal_dids: Vec::new(),
            push_bridge_cache_ttl_seconds: 900,
            push_bridge_trusted_service_dids: Vec::new(),
            resumable_upload_dir: std::path::PathBuf::from("./soland-resumable-uploads"),
            resumable_upload_incomplete_ttl_seconds: 86_400,
            seal_compaction_min_age_seconds: 604_800,
            compaction_min_witnesses: 1,
            compaction_preserve_genesis: true,
            compaction_prune_only_singleton_successors: true,

            compaction_prune_walk_interval_seconds: 0,

            compaction_prune_walk_per_realm_limit: 50,
            seed_demo_data: true,
            trust_domain: "ck:trust_domain:soland.local".to_owned(),
            sovereign_enclave_enabled: false,
            sovereign_enclave_allowed_outbound_hosts: Vec::new(),
            erasure_propagation_window_ms: 604_800_000,
            log_format: crate::config::LogFormat::Plain,
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

    #[test]
    fn provider_describe_trust_handshake_accepts_canonical_identity_registry() {
        // STA-07-002 — canonical ServiceDescribe shape: service_type +
        // service_did + trust_domain + supported_operations.
        let describe = json!({
            "service_type": "identity_registry",
            "service_did": "did:web:starid.example",
            "trust_domain": "ck:trust_domain:example.net",
            "development_mode": false,
            "supported_operations": ["ck.server.query.describe"]
        });
        validate_webvh_provider_describe(
            &describe,
            Some("did:web:starid.example"),
            Some("ck:trust_domain:example.net"),
        )
        .expect("valid canonical identity_registry describe should pass");
    }

    #[test]
    fn provider_describe_trust_handshake_rejects_mismatch_and_dev() {
        let mut describe = json!({
            "service_type": "identity_registry",
            "service_did": "did:web:starid.example",
            "trust_domain": "ck:trust_domain:example.net",
            "development_mode": false,
            "supported_operations": ["ck.server.query.describe"]
        });
        let err = validate_webvh_provider_describe(
            &describe,
            Some("did:web:starid.example"),
            Some("ck:trust_domain:other.example"),
        )
        .expect_err("trust-domain mismatch must fail closed");
        assert!(err.contains("trust_domain mismatch"), "{err}");

        describe["development_mode"] = json!(true);
        let err = validate_webvh_provider_describe(
            &describe,
            Some("did:web:starid.example"),
            Some("ck:trust_domain:example.net"),
        )
        .expect_err("development-mode provider must fail closed");
        assert!(err.contains("development_mode"), "{err}");
    }
}
