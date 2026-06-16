use super::*;

#[test]
fn pattern_matches_concrete_path() {
    assert!(pattern_matches_path(
        "/_cokret/self/events",
        "/_cokret/self/events"
    ));
    assert!(!pattern_matches_path(
        "/_cokret/self/events",
        "/_cokret/self/other"
    ));
}

#[test]
fn pattern_matches_param_segment() {
    assert!(pattern_matches_path(
        "/_soland/self/spaces/{space_id}",
        "/_soland/self/spaces/ck:space:01"
    ));
    // Different segment count → no match.
    assert!(!pattern_matches_path(
        "/_soland/self/spaces/{space_id}",
        "/_soland/self/spaces/ck:space:01/policy"
    ));
    // Param must be non-empty.
    assert!(!pattern_matches_path(
        "/_soland/self/spaces/{space_id}",
        "/_soland/self/spaces/"
    ));
}

#[test]
fn pattern_matches_multi_param_segments() {
    assert!(pattern_matches_path(
        "/_cokret/self/events/{event_id}/refs/{ref_id}",
        "/_cokret/self/events/ck:event:01/refs/ck:event:02"
    ));
}

#[test]
fn pattern_rejects_segment_mismatch() {
    assert!(!pattern_matches_path("/_cokret/self/events", "/_cokret"));
    assert!(!pattern_matches_path("/_cokret", "/_cokret/self/events"));
}

#[test]
fn known_routes_map_resolves_known_path() {
    // Seed the known-routes table with the protocol surface we'd
    // expect the catch-all to disambiguate against. We don't go
    // through the full OpenAPI doc build path because that pulls in
    // the entire service router; the helper logic under test is
    // pattern-matching, not OpenAPI introspection.
    let _ = KNOWN_ROUTES.set(vec![
        (
            "/_cokret/self/events".to_owned(),
            vec![Method::GET, Method::POST],
        ),
        (
            "/_soland/self/spaces/{space_id}".to_owned(),
            vec![Method::GET],
        ),
    ]);

    // Known path → returns the canonical method set (in
    // `METHOD_HEADER_ORDER`) so the `Allow` header is stable.
    let methods = allow_methods_for_path("/_cokret/self/events")
        .expect("/_cokret/self/events is registered with at least one method");
    assert_eq!(methods, vec![Method::GET, Method::POST]);

    let methods = allow_methods_for_path("/_soland/self/spaces/ck:space:abc")
        .expect("/_soland/self/spaces/{id} resolves with a concrete id");
    assert_eq!(methods, vec![Method::GET]);

    // Unknown path → `None`, which is the cue for `api_not_found`
    // to emit `unrecognized_endpoint` instead of `method_not_allowed`.
    assert!(allow_methods_for_path("/_cokret/self/does-not-exist").is_none());
    assert!(allow_methods_for_path("/_soland/peer/does-not-exist").is_none());
}

/// End-to-end check that `/_cokret/*` unrecognized paths return
/// the canonical 404 + `unrecognized_endpoint` JSON envelope (see
/// `tests/http_api.rs::framework_errors_use_cokret_error_envelope`).
#[tokio::test]
async fn cokret_v1_unknown_path_returns_unrecognized_endpoint() {
    use salvo::test::{ResponseExt, TestClient};

    use crate::db::Db;
    use crate::state::AppState;

    let state = AppState::new(test_state_config(), Db { pool: None });
    let svc = crate::service(state);

    let mut response = TestClient::get("http://server/_cokret/does-not-exist")
        .send(&svc)
        .await;
    let status = response.status_code.unwrap();
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["ok"], false);
    assert_eq!(body["error"]["code"], "unrecognized_endpoint");
}

/// End-to-end check that hitting a known `/_cokret/*` path with the
/// wrong method returns 405 + the `method_not_allowed` JSON envelope
/// AND populates the `Allow` response header per
/// `cokret-spec/spec/v1/zh/sync/api-conventions.md` §10.
#[tokio::test]
async fn known_path_wrong_method_returns_method_not_allowed_with_allow_header() {
    use salvo::test::{ResponseExt, TestClient};

    use crate::db::Db;
    use crate::state::AppState;

    let state = AppState::new(test_state_config(), Db { pool: None });
    let svc = crate::service(state);

    let mut response = TestClient::patch("http://server/_cokret/self/events")
        .send(&svc)
        .await;
    let status = response.status_code.unwrap();
    let allow = response
        .headers()
        .get("allow")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(body["ok"], false);
    assert_eq!(body["error"]["code"], "method_not_allowed");
    // `/_cokret/self/events` supports POST (submit) + GET (query); the
    // `Allow` header must list them in canonical (`METHOD_HEADER_ORDER`)
    // order so it's stable across runs.
    assert_eq!(allow, "GET, POST", "got Allow: {allow}");
}

fn test_state_config() -> crate::config::AppConfig {
    use crate::config::{AppConfig, IceServersConfig, LiveKitConfig, ObjectStorageConfig};
    AppConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        metrics_bind: "127.0.0.1:0".parse().unwrap(),
        public_base_url: "http://server".to_owned(),
        service_did: "did:web:soland.local".to_owned(),
        tls_cert_path: None,
        tls_key_path: None,
        database_url: None,
        object_storage: ObjectStorageConfig::local(
            std::env::temp_dir().join("soland-framework-error-test-blobs"),
        ),
        ice: IceServersConfig::default(),
        livekit: LiveKitConfig::default(),
        cors_allow_origin: None,
        auth_server_url: None,
        oidc_client_id: None,
        development_mode: true,
        oauth_introspection_url: None,
        oauth_introspection_bearer: None,
        session_grant_introspection_url: None,
        session_grant_introspection_bearer: None,
        did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned(), "uuid".to_owned()],
        embedded_webvh_provider_enabled: false,
        embedded_webvh_registration_bearer: None,
        external_webvh_provider_url: None,
        external_webvh_provider_active: false,
        default_webvh_provider_id: None,
        jws_replay_window_seconds: 0,
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
