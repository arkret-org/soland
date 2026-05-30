//! Integration tests — `auth` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

#![allow(unused_imports)]
use super::common::*;

#[tokio::test]
async fn oauth_bearer_introspection_authenticates_directly() {
    let (introspection_url, request_handle) = spawn_oauth_introspection_server();
    let mut config = test_config();
    config.development_mode = false;
    config.oauth_introspection_url = Some(introspection_url);
    config.oauth_introspection_bearer = Some("shared-secret".to_owned());
    let state = AppState::new(config, Db { pool: None });

    let me: Value = TestClient::get("http://server/api/v1/account/me")
        .add_header("authorization", "Bearer coauth_access_token", true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(me["did"], "did:web:oauth.example");
    assert_eq!(me["handle"], "@oauth-alice");

    let request = request_handle.join().unwrap();
    assert!(request.contains("token=coauth_access_token"));
    let devices = state
        .persistence
        .devices()
        .list_for_actor("did:web:oauth.example")
        .await
        .unwrap();
    let oauth_device = devices
        .iter()
        .find(|device| {
            device.payload["raw_device_id"] == "cx:device:01904100-0000-7000-8000-0a4a40000006"
        })
        .expect("OAuth device auto-provisioned");
    assert!(oauth_device.device_id.starts_with("cx:device:"));
}

#[tokio::test]
async fn dev_login_is_unavailable_in_production_mode() {
    let mut config = test_config();
    config.development_mode = false;
    let state = AppState::new(config, Db { pool: None });

    let response = TestClient::post("http://server/api/v1/auth/dev-login")
        .json(&serde_json::json!({
            "actor": "did:web:alice.example",
            "device_id": "cx:device:01904100-0000-7000-8000-0a4a40000006"
        }))
        .send(&app_from_state(state))
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn oversized_json_body_is_rejected_before_handler() {
    let state = AppState::new(test_config(), Db { pool: None });
    let body = serde_json::json!({
        "query": "x".repeat(128),
        "limit": 10,
    });

    let response = TestClient::post("http://server/api/v1/directory/search-realms")
        .json(&body)
        .send(&service_with_request_size_limit(state, 64))
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn rate_limit_errors_use_standard_envelope_with_retry_after() {
    let state = AppState::new(test_config(), Db { pool: None });
    let limited_service = service_with_rate_limiter_config(
        state,
        RateLimiterConfig {
            max_requests: 1,
            window: Duration::from_secs(60),
            // Mirror the strict default class ceilings on the `other` bucket
            // (`/health` is not under /api/v1/*, so it falls into `other`).
            auth_max_requests: 1,
            api_max_requests: 1,
        },
    );

    let first = TestClient::get("http://server/health")
        .send(&limited_service)
        .await;
    assert_eq!(first.status_code.unwrap(), StatusCode::OK);

    let mut second = TestClient::get("http://server/health")
        .send(&limited_service)
        .await;
    assert_eq!(second.status_code.unwrap(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after = second
        .headers
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .unwrap();
    assert_eq!(retry_after, "60");

    let limited: Value = second.take_json().await.unwrap();
    assert_eq!(limited["ok"], false);
    assert_eq!(limited["error"]["code"], "rate_limited");
    assert!(limited["error"]["retry_after_ms"].as_u64().unwrap() > 0);
    assert!(
        limited["request_id"]
            .as_str()
            .unwrap()
            .starts_with("cx:request:")
    );
}

#[tokio::test]
async fn framework_errors_use_contrix_error_envelope() {
    let not_found: Value = TestClient::get("http://server/api/v1/missing")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(not_found["ok"], false);
    assert_eq!(not_found["error"]["code"], "unrecognized_endpoint");

    let method_not_allowed: Value = TestClient::post("http://server/api/v1/server/describe")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(method_not_allowed["ok"], false);
    assert_eq!(method_not_allowed["error"]["code"], "method_not_allowed");
}

#[tokio::test]
async fn protected_endpoints_reject_query_auth_material() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let mut response = TestClient::get(format!(
        "http://server/api/v1/account/me?access_token={token}"
    ))
    .send(&app_from_state(state))
    .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::UNAUTHORIZED);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["ok"], false);
    assert_eq!(body["error"]["code"], "unauthenticated");
    assert_eq!(
        body["error"]["message"],
        "auth material in query strings is not allowed"
    );
}

#[tokio::test]
async fn postgres_startup_migrations_are_gated_by_database_url() {
    if std::env::var("DATABASE_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
        .is_none()
    {
        return;
    }

    let db = Db::from_env()
        .await
        .expect("postgres migrations should run");
    let health: Value = TestClient::get("http://server/health")
        .send(&app_from_state(AppState::new(test_config(), db)))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(health["storage"], "postgres");
}
