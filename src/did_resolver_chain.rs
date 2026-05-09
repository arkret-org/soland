//! C10.B (2026-05-09 十八轮 并行) — DID resolver chain wiring for
//! production. The chain is the single source of truth that
//! `jws_verify` consults when it needs to resolve a JWS
//! `verification_method` DID into a public key. Keeping the wiring in
//! its own helper means the chain composition can grow (`did:keri`,
//! `did:peer`, etc.) without `AppState::new` ballooning.
//!
//! Priority order (first resolver that `supports()` a DID wins):
//!
//! 1. [`DidUuidResolver`] — first because uuid DIDs are local-only,
//!    deterministic, and never need an upstream call.
//! 2. [`DidWebvhResolver`] — only inserted when
//!    [`AppConfig::starid_webvh_resolver_url`] is `Some(_)`. Production
//!    deployments configure `SERVERX_STARID_WEBVH_RESOLVER_URL` to point
//!    at the starid instance that hosts `did.json` /  `did.jsonl` for
//!    `did:webvh:` DIDs (per starid `_todos.md` "Production resolver
//!    chain"). The SDK resolver is a cache — production ingestion still
//!    requires a separate fetcher to call `insert_from_https_response` /
//!    `ingest_log` (tracked separately as a follow-up; the chain
//!    placement here is the precondition for that work).
//! 3. [`DidWebResolver`] — generic `did:web:` fallback. Placed AFTER
//!    `DidWebvhResolver` so a `did:webvh:...` DID never falls through
//!    here (DidWebResolver does not support webvh, but ordering keeps
//!    intent clear and makes future `did:web` ↔ `did:webvh` migration
//!    semantics explicit).
//! 4. [`DidKeyResolver`] — pure-cryptographic last-resort.
//!
//! Filtering: [`AppConfig::did_resolver_allow_methods`] is honoured by
//! omitting any resolver whose method is not in the allow list. Method
//! names compared are bare ("uuid", "web", "webvh", "key") — matching
//! the existing CSV shape produced by `env_csv` in `config.rs`. An
//! empty / missing allow list (legacy config) is treated as "allow
//! everything" so we don't break existing deployments.

use contrix_sdk::identity::{
    CompositeDidResolver, DidKeyResolver, DidUuidResolver, DidWebResolver, DidWebvhResolver,
};
use std::time::Duration;

use crate::config::AppConfig;

/// Build the production `CompositeDidResolver` chain for `AppState`.
/// Honors the `did_resolver_allow_methods` filter and the optional
/// `starid_webvh_resolver_url` toggle.
pub fn build_did_resolver_chain(config: &AppConfig) -> CompositeDidResolver {
    let mut resolver = CompositeDidResolver::new();
    if method_allowed(config, "uuid") {
        resolver.push(DidUuidResolver::new());
    }
    if method_allowed(config, "webvh") && config.starid_webvh_resolver_url.is_some() {
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

fn method_allowed(config: &AppConfig, method: &str) -> bool {
    if config.did_resolver_allow_methods.is_empty() {
        return true;
    }
    config
        .did_resolver_allow_methods
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(method))
}

/// Round 21: probe a starid `<URL>/describe` endpoint to confirm the
/// configured `starid_webvh_resolver_url` actually responds before we
/// commit to mounting the [`DidWebvhResolver`] in the chain. Returns
/// `Ok(())` only when the HTTP GET returns a 2xx response in under
/// `timeout`.
///
/// On the boot path (see `main.rs`), the caller catches `Err(_)` and
/// clears `config.starid_webvh_resolver_url = None` so
/// [`build_did_resolver_chain`] omits the webvh resolver. This keeps a
/// misconfigured deployment from silently breaking `did:webvh` lookups —
/// the chain reports `not supported` for `did:webvh` rather than dialing
/// an unreachable endpoint per request.
pub async fn probe_starid_describe(url: &str, timeout: Duration) -> Result<(), String> {
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
        .map_err(|e| format!("starid /describe request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "starid /describe returned non-2xx status {}",
            resp.status()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use contrix_sdk::Did;
    use contrix_sdk::identity::DidResolver;
    use std::{net::SocketAddr, path::PathBuf};

    fn base_config() -> AppConfig {
        AppConfig {
            bind: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            public_base_url: "http://127.0.0.1:0".to_owned(),
            service_did: "did:web:soland.test".to_owned(),
            database_url: None,
            blob_root: PathBuf::from("/tmp/soland-blobs"),
            cors_allow_origin: None,
            development_mode: false,
            session_grant_introspection_url: None,
            session_grant_introspection_bearer: None,
            did_resolver_allow_methods: vec![
                "web".to_owned(),
                "key".to_owned(),
                "uuid".to_owned(),
                "webvh".to_owned(),
            ],
            starid_webvh_resolver_url: None,
            jws_replay_window_seconds: 300,
            jws_replay_window_per_family: std::collections::BTreeMap::new(),
            lattice_first: false,
        }
    }

    /// `did:webvh:<scid>:<host>:<path...>` — well-formed sample that
    /// `DidWebvhResolver::supports()` accepts after URL-shape validation.
    fn sample_webvh_did() -> Did {
        Did::new("did:webvh:zabc:starid.example:users:alice").expect("valid did:webvh")
    }

    fn sample_web_did() -> Did {
        Did::new("did:web:alice.example").expect("valid did:web")
    }

    #[test]
    fn chain_includes_webvh_resolver_when_url_configured() {
        let mut config = base_config();
        config.starid_webvh_resolver_url = Some("https://starid.example".to_owned());
        let chain = build_did_resolver_chain(&config);

        // The webvh resolver claims `supports()` purely on DID method +
        // URL shape — no cache hit required. So the chain reports
        // `supports()` true for a well-formed did:webvh DID exactly when
        // a webvh resolver is in the chain.
        assert!(
            chain.supports(&sample_webvh_did()),
            "chain should support did:webvh when starid url is configured"
        );
    }

    #[test]
    fn chain_omits_webvh_resolver_when_url_absent() {
        let mut config = base_config();
        config.starid_webvh_resolver_url = None;
        let chain = build_did_resolver_chain(&config);

        assert!(
            !chain.supports(&sample_webvh_did()),
            "chain must NOT support did:webvh when starid url is absent"
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
        config.starid_webvh_resolver_url = Some("https://starid.example".to_owned());
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
        // allow list excludes "webvh" → resolver omitted even with URL set.
        let mut config = base_config();
        config.did_resolver_allow_methods =
            vec!["web".to_owned(), "key".to_owned(), "uuid".to_owned()];
        config.starid_webvh_resolver_url = Some("https://starid.example".to_owned());
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
        config.starid_webvh_resolver_url = Some("https://starid.example".to_owned());
        let chain = build_did_resolver_chain(&config);
        assert!(chain.supports(&sample_webvh_did()));
        assert!(chain.supports(&sample_web_did()));
    }
}
