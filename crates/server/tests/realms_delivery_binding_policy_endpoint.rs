//! Realm delivery-binding-policy admin endpoint smoke tests.
//!
//! Pins the wire shape on the admin Realm delivery-binding-policy surface:
//!
//! - `GET /_soland/admin/realms/{realm_id}/delivery-binding-policy` returns 200 with the SDK-typed
//!   `RealmDeliveryBindingPolicy` envelope (sodmin's `RealmDeliveryBindingPolicy` DTO consumes
//!   this).
//!
//! These tests boot the salvo `Service` in-process via
//! `salvo::test::TestClient` — no network, no separate process.

use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::Value;
use soland_http::config::AppConfig;
use soland_http::service;

/// Build a minimal dev-mode `AppConfig`. Identical posture to the
/// helper in `tests/http_api/common.rs` (kept in-line so this test file
/// stands alone and does not depend on the other test module).
fn test_config() -> AppConfig {
    AppConfig {
        development_mode: true,
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: std::collections::BTreeMap::new(),
        seed_demo_data: true,
        ..soland_test_support::app_config()
    }
}

fn app() -> salvo::Service {
    service(soland_test_support::app_state(test_config()))
}

/// Acquire a dev-mode bearer token for an arbitrary actor. Mirrors the
/// helper in `tests/http_api/common.rs`; admin handlers in `development_mode`
/// accept any authenticated session per `require_admin_principal`.
async fn dev_token(svc: &salvo::Service) -> String {
    let login: Value = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&serde_json::json!({
            "actor": "ak:did_core:web:alice.example",
            "device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001",
            "display_name": "Alice Desktop"
        }))
        .send(svc)
        .await
        .take_json()
        .await
        .unwrap();
    login["session_credential"].as_str().unwrap().to_owned()
}

/// R2.2 — happy path. Unset policy MUST still respond 200 with the
/// typed envelope (just empty fields) so sodmin can render the empty
/// editor without special-casing 404. Mirrors sodmin's
/// `api/delivery_binding.rs::get_delivery_binding_policy` consumer.
#[tokio::test]
async fn realms_delivery_binding_policy_endpoint_responds() {
    let svc = app();
    let token = dev_token(&svc).await;
    let realm_id = "ak:realm:ATtvDFNJFO-h1zle3_ulQJQNAk1tSUamRsHo37ll6mBW";
    let body: Value = TestClient::get(format!(
        "http://server/_soland/admin/realms/{realm_id}/delivery-binding-policy"
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
}

/// R2.2 — bad realm_id surfaces as 400 (not 200 with garbage). Pins
/// the typed-id validation path so the endpoint cannot drift into
/// accepting raw strings as Realm identifiers.
#[tokio::test]
async fn realms_delivery_binding_policy_endpoint_rejects_invalid_id() {
    let svc = app();
    let token = dev_token(&svc).await;
    let response = TestClient::get(
        "http://server/_soland/admin/realms/not-a-typed-id/delivery-binding-policy",
    )
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&svc)
    .await;
    assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
}
