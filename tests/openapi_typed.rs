//! Verifies that the typed `#[endpoint]` handlers in
//! `src/routing/describe.rs` actually contribute their request/response
//! schemas to the generated OpenAPI document. The original
//! `contrix_openapi_spec_contains_facet_projection_contracts` test only
//! asserts on operationId presence; this one asserts the typed schema
//! references that prove the conversion is real (not just metadata).

use salvo::test::{ResponseExt, TestClient};
use soland::config::{AppConfig, ObjectStorageConfig};
use soland::db::Db;
use soland::service;
use soland::state::AppState;

fn test_config() -> AppConfig {
    AppConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        public_base_url: "http://server".to_owned(),
        service_did: "did:web:soland.local".to_owned(),
        tls_cert_path: None,
        tls_key_path: None,
        database_url: None,
        object_storage: ObjectStorageConfig::local(
            std::env::temp_dir().join("soland-openapi-typed-blobs"),
        ),
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
        use_keystore: false,
        federation_policy: soland::config::FederationPolicy::Mesh,
        federation_peers: Vec::new(),
        admin_default_page_limit: 100,
        admin_max_page_limit: 1000,
        admin_principal_dids: Vec::new(),
        push_bridge_cache_ttl_seconds: 900,
        push_bridge_trusted_service_dids: Vec::new(),
    }
}

#[tokio::test]
async fn typed_describe_handlers_publish_response_schemas() {
    let app = service(AppState::new(test_config(), Db { pool: None }));
    let mut response = TestClient::get("http://server/.well-known/contrix/openapi.yaml")
        .send(&app)
        .await;
    let body = response.take_string().await.unwrap();

    // The new typed describe endpoints must:
    // 1. publish their wire response types as components,
    assert!(
        body.contains("AuthBridgeDescribeResponse"),
        "AuthBridgeDescribeResponse missing — auth_bridge_describe didn't publish its schema"
    );
    assert!(
        body.contains("IntegrationDescribeResponse"),
        "IntegrationDescribeResponse missing — integration_describe didn't publish its schema"
    );
    assert!(
        body.contains("HealthResponse"),
        "HealthResponse missing — health didn't publish its schema"
    );

    // 2. publish AppError's standard error envelope on every typed handler,
    assert!(
        body.contains("ErrorEnvelope"),
        "ErrorEnvelope missing — AppError EndpointOutRegister didn't fire"
    );

    // 3. carry generated operation_ids for typed handlers,
    for typed_only in [
        "cx.auth.bridge.describe",
        "cx.authz.describe",
        "cx.policies.describe",
        "cx.device_messages.describe",
        "cx.keys.backups.describe",
        "cx.integration.describe",
    ] {
        assert!(
            body.contains(&format!("operationId: {typed_only}")),
            "missing typed-only operationId {typed_only}"
        );
    }

    // Phase C/D-converted endpoints must publish their request body types so
    // the OpenAPI spec carries the typed schemas (not synthetic placeholders).
    for typed_request_body in [
        "DevLoginRequest",
        "SessionGrantExchangeRequest",
        "RegisterAccountRequest",
        "ContactRequestRequest",
        "ContactRespondRequest",
        "AddReactionRequest",
        "RemoveReactionRequest",
        "SetReadMarkerRequest",
        "CreateSpaceRequest",
        "AddSpaceMemberRequest",
    ] {
        assert!(
            body.contains(typed_request_body),
            "missing request body schema {typed_request_body}"
        );
    }

    // Phase C/D-converted endpoints must publish typed response shapes too.
    for typed_response in [
        "DevLoginResponse",
        "LogoutResponse",
        "AccountResponse",
        "ContactResponse",
        "ContactsResponse",
        "ReactionResponse",
        "ReadMarkerResponse",
        "SpaceLifecycleResponse",
    ] {
        assert!(
            body.contains(typed_response),
            "missing response schema {typed_response}"
        );
    }
}
