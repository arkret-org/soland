//! R2.2 (Phase 2, 2026-05-20) — Realm delivery-binding-policy admin
//! endpoint smoke tests.
//!
//! Pins the wire shape on the two paths the Realm/Space reversal
//! introduced on the admin surface:
//!
//! - `GET /api/admin/v1/realms/{realm_id}/delivery-binding-policy`
//!   returns 200 with the SDK-typed `RealmDeliveryBindingPolicy`
//!   envelope (sodmin's `RealmDeliveryBindingPolicy` DTO consumes
//!   this).
//! These tests boot the salvo `Service` in-process via
//! `salvo::test::TestClient` — no network, no separate process.

use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::Value;
use soland::config::{AppConfig, ObjectStorageConfig};
use soland::db::Db;
use soland::service;
use soland::state::AppState;

/// Build a minimal dev-mode `AppConfig`. Identical posture to the
/// helper in `tests/http_api.rs` (kept in-line so this test file
/// stands alone and does not depend on the other test module).
fn test_config() -> AppConfig {
    AppConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        metrics_bind: "127.0.0.1:0".parse().unwrap(),
        public_base_url: "http://server".to_owned(),
        service_did: "did:web:soland.local".to_owned(),
        tls_cert_path: None,
        tls_key_path: None,
        database_url: None,
        object_storage: ObjectStorageConfig::local(std::env::temp_dir().join("soland-test-blobs")),
        cors_allow_origin: None,
        auth_server_url: None,
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
        anchorer_signing_key_seed: None,
        agent_audit_binding_signing_seed: None,
        use_keystore: false,
        federation_policy: soland::config::FederationPolicy::Mesh,
        federation_peers: Vec::new(),
        federation_outbound_enabled: false,
        admin_default_page_limit: 100,
        admin_max_page_limit: 1000,
        admin_principal_dids: Vec::new(),
        push_bridge_cache_ttl_seconds: 900,
        push_bridge_trusted_service_dids: Vec::new(),
        compaction_min_anchor_age_seconds: 604_800,
        compaction_min_witnesses: 1,
        compaction_preserve_genesis: true,
        compaction_prune_only_singleton_successors: true,
        compaction_prune_walk_interval_seconds: 0,
        compaction_prune_walk_per_space_limit: 50,
        seed_demo_data: true,
        trust_domain: "cx:trust_domain:soland.local".to_owned(),
        sovereign_enclave_enabled: false,
        sovereign_enclave_allowed_outbound_hosts: Vec::new(),
        erasure_propagation_window_ms: 604_800_000,
        log_format: soland::config::LogFormat::Plain,
    }
}

fn app() -> salvo::Service {
    service(AppState::new(test_config(), Db { pool: None }))
}

/// Acquire a dev-mode bearer token for an arbitrary actor. Mirrors the
/// helper in `tests/http_api.rs`; admin handlers in `development_mode`
/// accept any authenticated session per `require_admin_principal`.
async fn dev_token(svc: &salvo::Service) -> String {
    let login: Value = TestClient::post("http://server/api/v1/auth/dev-login")
        .json(&serde_json::json!({
            "actor": "did:web:alice.example",
            "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
            "display_name": "Alice Desktop"
        }))
        .send(svc)
        .await
        .take_json()
        .await
        .unwrap();
    login["access_token"].as_str().unwrap().to_owned()
}

/// R2.2 — happy path. Unset policy MUST still respond 200 with the
/// typed envelope (just empty fields) so sodmin can render the empty
/// editor without special-casing 404. Mirrors sodmin's
/// `api/delivery_binding.rs::get_delivery_binding_policy` consumer.
#[tokio::test]
async fn realms_delivery_binding_policy_endpoint_responds() {
    let svc = app();
    let token = dev_token(&svc).await;
    let realm_id = "cx:space:01904100-0000-7000-8000-d00ddeadbeef";
    let body: Value = TestClient::get(format!(
        "http://server/api/admin/v1/realms/{realm_id}/delivery-binding-policy"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&svc)
    .await
    .take_json()
    .await
    .unwrap();

    // Typed envelope echoes the realm_id back even when no policy has
    // been projected for it yet. allowed_recipient_services may be
    // absent (skip_serializing_if = Vec::is_empty) — that's intentional
    // and the client side defaults to `vec![]` per
    // `RealmDeliveryBindingPolicy::default()`.
    assert_eq!(
        body["realm_id"], realm_id,
        "endpoint must echo the realm_id back in the typed envelope: {body}"
    );
    // policy_frontier MUST be absent / null on an unset policy — that's
    // the signal sodmin uses to render the "no policy set yet" state.
    assert!(
        body.get("policy_frontier").is_none() || body["policy_frontier"].is_null(),
        "policy_frontier must be unset on a fresh realm: {body}"
    );
}

/// R2.2 — bad realm_id surfaces as 400 (not 200 with garbage). Pins
/// the typed-id validation path so the endpoint cannot drift into
/// accepting raw strings as Realm identifiers.
#[tokio::test]
async fn realms_delivery_binding_policy_endpoint_rejects_invalid_id() {
    let svc = app();
    let token = dev_token(&svc).await;
    let response =
        TestClient::get("http://server/api/admin/v1/realms/not-a-typed-id/delivery-binding-policy")
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&svc)
            .await;
    assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
}
