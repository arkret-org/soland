//! DID resolver chain wiring. The chain is the single source of truth that
//! `jws_verify` consults when it needs to resolve a JWS `verification_method`
//! DID into a public key.
//!
//! Priority order (first resolver that `supports()` a DID wins):
//!
//! 1. [`LocalIdentityResolver`] — resolves DID documents stored in soland's
//!    durable identity store. This is what makes the embedded `did:webvh`
//!    provider usable without an external StarID/webvh service.
//! 2. [`DidWebvhResolver`] — inserted when the external provider boot probe
//!    succeeds. The SDK resolver is cache-oriented; actual external fetching
//!    still belongs to a provider-specific client.
//! 3. [`DidWebResolver`] — generic `did:web:` fallback. Placed AFTER `DidWebvhResolver` so a
//!    `did:webvh:...` DID never falls through here (DidWebResolver does not support webvh, but
//!    ordering keeps intent clear and makes future `did:web` ↔ `did:webvh` migration semantics
//!    explicit).
//! 4. [`DidKeyResolver`] — pure-cryptographic last-resort.
//!
//! Filtering: [`AppConfig::did_resolver_allow_methods`] is honoured by
//! omitting any resolver whose method is not in the allow list. Method
//! names compared are bare ("web", "webvh", "key") — matching
//! the existing CSV shape produced by `env_csv` in `config.rs`. An
//! empty / missing allow list (legacy config) is treated as "allow
//! everything" so we don't break existing deployments.

use std::sync::Arc;
use std::time::Duration;

use contrix_sdk::identity::{
    CompositeDidResolver, DidDocument, DidKeyResolver, DidResolver, DidWebResolver,
    DidWebvhResolver,
};
use contrix_sdk::{Did, Error};

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
        self.allowed_methods.is_empty()
            || self
                .allowed_methods
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(method))
    }

    fn document(&self, did: &Did) -> Result<DidDocument, Error> {
        if !self.method_allowed(did.method()) {
            return Err(Error::Protocol("DID method not allowed".to_owned()));
        }
        let Some(record) = self
            .persistence
            .identity()
            .get_document(did.as_str())
            .map_err(|e| Error::Protocol(format!("local DID store read failed: {e}")))?
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

impl DidResolver for LocalIdentityResolver {
    fn supports(&self, did: &Did) -> bool {
        self.document(did).is_ok()
    }

    fn resolve_did(&self, did: &Did) -> Result<DidDocument, Error> {
        self.document(did)
    }
}

fn method_allowed(config: &AppConfig, method: &str) -> bool {
    if config.did_resolver_allow_methods.is_empty() {
        return true;
    }
    config
        .did_resolver_allow_methods
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(method))
}

/// Probe an external webvh provider `<URL>/describe` endpoint. The configured
/// URL records admin intent and is still advertised when the probe fails; this
/// function only controls runtime liveness.
pub async fn probe_webvh_provider_describe(url: &str, timeout: Duration) -> Result<(), String> {
    let trimmed = url.trim_end_matches('/');
    let describe_url = format!("{trimmed}/describe");
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| format!("failed to build reqwest client: {e}"))?;
    let resp = client
        .get(&describe_url)
        .send()
        .await
        .map_err(|e| format!("webvh provider /describe request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "webvh provider /describe returned non-2xx status {}",
            resp.status()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use contrix_sdk::Did;
    use contrix_sdk::identity::DidResolver;

    use super::*;
    use crate::config::ObjectStorageConfig;

    fn base_config() -> AppConfig {
        AppConfig {
            bind: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            public_base_url: "http://127.0.0.1:0".to_owned(),
            service_did: "did:web:soland.test".to_owned(),
            database_url: None,
            object_storage: ObjectStorageConfig::local(std::env::temp_dir().join("soland-blobs")),
            cors_allow_origin: None,
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
            anchorer_signing_key_seed: None,
            use_keystore: false,
            federation_policy: crate::config::FederationPolicy::Mesh,
            federation_peers: Vec::new(),
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
    fn empty_allow_methods_treated_as_allow_all() {
        // Backward compat: legacy deployments may have an empty
        // allow_methods CSV. We must default to "allow everything" so
        // existing chains keep resolving did:web / did:key.
        let mut config = base_config();
        config.did_resolver_allow_methods.clear();
        config.external_webvh_provider_url = Some("https://webvh.example".to_owned());
        config.external_webvh_provider_active = true;
        let chain = build_did_resolver_chain(&config);
        assert!(chain.supports(&sample_webvh_did()));
        assert!(chain.supports(&sample_web_did()));
    }
}
