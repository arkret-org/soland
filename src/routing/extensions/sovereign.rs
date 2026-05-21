//! G3.S9 — Sovereign enclave profile guards.
//!
//! When `AppConfig::sovereign_enclave_enabled` is true (env
//! `SOLAND_SOVEREIGN_ENCLAVE=1`), soland claims
//! `cx.profile.sovereign_enclave.v1` on `/server/describe` and refuses
//! every outbound HTTP call that isn't first whitelisted.
//!
//! The enclave profile MUST disable:
//!   - outbound federation (`federation_outbound_enabled == false`)
//!   - public discovery
//!   - public DID resolution (the resolver only accepts DIDs whose
//!     method appears in `allowed_did_methods`)
//!
//! Every outbound HTTP call from the enclave logs through
//! [`audit_outbound_call`] with `target = "sovereign_boundary_audit"`.
//! Call sites that need to make outbound HTTP MUST first check
//! [`outbound_allowed`] and bail if false.
//!
//! Spec anchor: `contrix-spec/spec/v1/zh/sync/sovereign-deployment.md`
//! §2 (sovereign client + trust roots), §4 (controlled collaboration
//! Realm / enclave deployment), §5 (enclave boundary — no escape to
//! main), §6 (network outage + audit).
//!
//! TODO(G3.S9-followup): wire the [`outbound_allowed`] guard into the
//! federation outbound worker, the DID resolver, and the directory
//! search path; persist the enclave boundary audit log to
//! `state.persistence`.

use crate::config::AppConfig;
use crate::state::AppState;

/// Result of [`assert_enclave_invariants`]. The enclave profile is
/// considered satisfied only when every invariant holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnclaveAssertionResult {
    pub enabled: bool,
    pub federation_outbound_disabled: bool,
    pub resolver_method_allowlist_present: bool,
    /// Violations the enclave caller MUST address before claiming the
    /// profile. Empty when `enabled=false` (the enclave isn't active),
    /// or when every invariant holds.
    pub violations: Vec<String>,
}

impl EnclaveAssertionResult {
    pub fn is_compliant(&self) -> bool {
        !self.enabled || self.violations.is_empty()
    }
}

/// Check the runtime config against the enclave invariants documented
/// at module top. Called once at startup (see `main.rs` boot path) and
/// referenced from tests.
pub fn assert_enclave_invariants(config: &AppConfig) -> EnclaveAssertionResult {
    let enabled = config.sovereign_enclave_enabled;
    let mut violations = Vec::new();
    let federation_outbound_disabled = !config.federation_outbound_enabled;
    let resolver_method_allowlist_present = !config.did_resolver_allow_methods.is_empty();
    if enabled {
        if config.federation_outbound_enabled {
            violations.push(
                "sovereign_enclave_enabled=true requires federation_outbound_enabled=false"
                    .to_owned(),
            );
        }
        if !resolver_method_allowlist_present {
            violations.push(
                "sovereign_enclave_enabled=true requires a non-empty did_resolver_allow_methods"
                    .to_owned(),
            );
        }
    }
    EnclaveAssertionResult {
        enabled,
        federation_outbound_disabled,
        resolver_method_allowlist_present,
        violations,
    }
}

/// Predicate the outbound HTTP guard checks before issuing a request.
/// When the enclave isn't enabled, every call is allowed (returns
/// true). When the enclave is enabled, only URLs whose host appears
/// in `config.sovereign_enclave_allowed_outbound_hosts` may proceed.
pub fn outbound_allowed(config: &AppConfig, target_url: &str) -> bool {
    if !config.sovereign_enclave_enabled {
        return true;
    }
    let host = match url_host(target_url) {
        Some(h) => h,
        None => return false,
    };
    config
        .sovereign_enclave_allowed_outbound_hosts
        .iter()
        .any(|h| h.eq_ignore_ascii_case(&host))
}

/// Log an outbound HTTP attempt to the sovereign-boundary audit log.
/// Always called BEFORE the call is issued so denied attempts also
/// land in the audit trail.
pub fn audit_outbound_call(state: &AppState, target_url: &str, reason: &str, allowed: bool) {
    let posture = if allowed { "allowed" } else { "denied" };
    tracing::info!(
        target: "sovereign_boundary_audit",
        sovereign_enclave_enabled = state.config.sovereign_enclave_enabled,
        target_url = target_url,
        reason = reason,
        posture = posture,
        "sovereign enclave outbound call audit",
    );
}

fn url_host(url: &str) -> Option<String> {
    // Tiny ad-hoc parser — we only need the host. Avoids pulling
    // `url` as a new dep when the caller already supplies a
    // well-formed http(s) URL.
    let without_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let host_with_path = without_scheme.split('/').next().unwrap_or("");
    let host_no_userinfo = host_with_path
        .rsplit_once('@')
        .map(|(_, rest)| rest)
        .unwrap_or(host_with_path);
    let host = host_no_userinfo.split(':').next().unwrap_or("");
    if host.is_empty() {
        None
    } else {
        Some(host.to_owned())
    }
}

/// The conformance profile id soland claims on `/server/describe` when
/// `sovereign_enclave_enabled=true`. Registered in
/// `contrix-spec/spec/v1/artifacts/profiles/conformance-profiles.json`.
pub const SOVEREIGN_ENCLAVE_PROFILE_ID: &str = "cx.profile.sovereign_enclave.v1";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FederationPolicy, ObjectStorageConfig};

    fn base_config() -> AppConfig {
        AppConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            public_base_url: "http://server".to_owned(),
            service_did: "did:web:soland.local".to_owned(),
            tls_cert_path: None,
            tls_key_path: None,
            database_url: None,
            object_storage: ObjectStorageConfig::local(
                std::env::temp_dir().join("soland-enclave-tests"),
            ),
            cors_allow_origin: None,
            auth_server_url: None,
            development_mode: true,
            oauth_introspection_url: None,
            oauth_introspection_bearer: None,
            session_grant_introspection_url: None,
            session_grant_introspection_bearer: None,
            did_resolver_allow_methods: vec!["web".to_owned()],
            embedded_webvh_provider_enabled: false,
            embedded_webvh_registration_bearer: None,
            external_webvh_provider_url: None,
            external_webvh_provider_active: false,
            default_webvh_provider_id: None,
            jws_replay_window_seconds: 0,
            jws_replay_window_per_family: std::collections::BTreeMap::new(),
            anchorer_signing_key_seed: None,
            agent_audit_binding_signing_seed: None,
            use_keystore: false,
            federation_policy: FederationPolicy::Mesh,
            federation_peers: Vec::new(),
            federation_outbound_enabled: false,
            admin_default_page_limit: 100,
            admin_max_page_limit: 1000,
            admin_principal_dids: Vec::new(),
            push_bridge_cache_ttl_seconds: 900,
            push_bridge_trusted_service_dids: Vec::new(),
            compaction_min_anchor_age_seconds: 0,
            compaction_min_witnesses: 0,
            compaction_preserve_genesis: true,
            compaction_prune_only_singleton_successors: true,
            compaction_prune_walk_interval_seconds: 0,
            compaction_prune_walk_per_space_limit: 50,
            seed_demo_data: false,
            trust_domain: "cx:trust_domain:soland.local".to_owned(),
            sovereign_enclave_enabled: false,
            sovereign_enclave_allowed_outbound_hosts: Vec::new(),
        }
    }

    #[test]
    fn sovereign_enclave_disabled_allows_everything() {
        let cfg = base_config();
        assert!(outbound_allowed(&cfg, "https://anywhere.example/path"));
        let result = assert_enclave_invariants(&cfg);
        assert!(result.is_compliant());
        assert!(result.violations.is_empty());
    }

    #[test]
    fn sovereign_enclave_rejects_outbound_when_enabled() {
        let mut cfg = base_config();
        cfg.sovereign_enclave_enabled = true;
        // No allowlist: every outbound is denied.
        assert!(!outbound_allowed(&cfg, "https://example.com/api"));
        cfg.sovereign_enclave_allowed_outbound_hosts = vec!["internal.example".to_owned()];
        assert!(outbound_allowed(&cfg, "https://internal.example/api"));
        assert!(!outbound_allowed(&cfg, "https://external.example/api"));
        // Malformed URLs are denied closed.
        assert!(!outbound_allowed(&cfg, "not-a-url"));
    }

    #[test]
    fn sovereign_enclave_requires_outbound_federation_off() {
        let mut cfg = base_config();
        cfg.sovereign_enclave_enabled = true;
        cfg.federation_outbound_enabled = true;
        let result = assert_enclave_invariants(&cfg);
        assert!(!result.is_compliant());
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.contains("federation_outbound_enabled"))
        );
    }

    #[test]
    fn sovereign_enclave_requires_did_method_allowlist() {
        let mut cfg = base_config();
        cfg.sovereign_enclave_enabled = true;
        cfg.did_resolver_allow_methods = Vec::new();
        let result = assert_enclave_invariants(&cfg);
        assert!(!result.is_compliant());
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.contains("did_resolver_allow_methods"))
        );
    }

    #[test]
    fn url_host_parses_typical_shapes() {
        assert_eq!(
            url_host("https://example.com/api"),
            Some("example.com".to_owned())
        );
        assert_eq!(
            url_host("http://user:pass@internal.example:8080/foo"),
            Some("internal.example".to_owned())
        );
        assert_eq!(url_host(""), None);
        assert_eq!(url_host("not-a-url"), Some("not-a-url".to_owned()));
    }
}
