//! Extension protocol describe, signature-order, and retired-route smoke tests.
//! Accepted Applet/Realm fixtures pending formal Event/RealmCommit migration are
//! tracked in arkret-work/tasks/impl-active/2026-09-19-2011.

use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use soland_http::config::AppConfig;
use soland_http::service;

fn test_config() -> AppConfig {
    AppConfig {
        development_mode: true,
        seed_demo_data: true,
        ..soland_test_support::app_config()
    }
}

#[tokio::test]
async fn applet_protocol_describe_smoke() {
    let state = soland_test_support::app_state(test_config());
    let app = service(state);

    // applet-integration.md 7 fixes the ping response fields; there is no
    // free-form `ok` flag to assert.
    let ping: arkret_models_integration::AppletPingOutcome =
        TestClient::get("http://server/_arkret/edge/applet/ping")
            .add_header("Arkret-Operation", "ak.edge.applet.read.ping.v1", true)
            .send(&app)
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(ping.protocol_version, arkret_wire::PROTOCOL_VERSION);

    let describe: arkret_models_discovery::ServiceDescribe =
        TestClient::get("http://server/_arkret/edge/applet/describe")
            .add_header("Arkret-Operation", "ak.edge.applet.read.describe.v1", true)
            .send(&app)
            .await
            .take_json()
            .await
            .unwrap();
    describe
        .validate()
        .expect("Applet describe must be the canonical ServiceDescribe");
    assert_eq!(
        describe.protocol_version.as_str(),
        arkret_wire::PROTOCOL_VERSION
    );
    for operation_id in [
        arkret_wire::ServiceOperationId::EDGE_APPLET_READ_PING_V1,
        arkret_wire::ServiceOperationId::EDGE_APPLET_READ_DESCRIBE_V1,
        arkret_wire::ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1,
        arkret_wire::ServiceOperationId::SELF_APPLET_COMMAND_INSTALL_V1,
    ] {
        assert!(
            describe.supports_operation(
                arkret_wire::ServiceOperationId::from_wire(operation_id)
                    .expect("fixture operation must be registered")
            ),
            "Applet describe must advertise {operation_id}"
        );
    }
}

#[tokio::test]
async fn applet_transaction_requires_signature_before_typed_body_validation() {
    let state = soland_test_support::app_state(test_config());
    let app = service(state);
    let mut response = TestClient::post("http://server/_arkret/edge/applet/transactions")
        .add_header(
            "Arkret-Operation",
            "ak.edge.applet.command.transaction.v1",
            true,
        )
        .add_header("Authorization", "Bearer bearer-only", true)
        .add_header("Idempotency-Key", "missing-signature-order", true)
        .json(&json!({
            "source_id": "not-a-did",
            "events": "not-an-array"
        }))
        .send(&app)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::UNAUTHORIZED);
    let error: Value = response.take_json().await.unwrap();
    assert_eq!(
        error["type"],
        json!("https://arkret.org/problems/http_signature_required")
    );
}

#[tokio::test]
async fn retired_sovereign_shadow_routes_are_unrecognized() {
    let state = soland_test_support::app_state(test_config());
    state.hydrate().await.unwrap();
    let app = service(state);

    for path in [
        "/_soland/admin/deployment/audit",
        "/_soland/admin/deployment/enclave-frontier?realm_id=ak:realm:retired",
        "/_soland/admin/deployment/info",
        "/_soland/self/account/did:web:retired.example",
        "/_soland/self/directory/realms",
        "/_soland/self/realm/ak:realm:retired",
        "/_soland/self/realm/ak:realm:retired/access",
    ] {
        let mut response = TestClient::get(format!("http://server{path}"))
            .send(&app)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND), "{path}");
        let problem: Value = response.take_json().await.unwrap();
        assert_eq!(
            problem["type"],
            json!("https://arkret.org/problems/unrecognized_endpoint"),
            "{path}"
        );
    }

    for path in [
        "/_soland/admin/deployment/configure",
        "/_soland/admin/deployment/external-invite",
        "/_soland/admin/deployment/network/link",
        "/_soland/admin/deployment/realm.create",
        "/_soland/admin/deployment/register-enclave",
        "/_soland/admin/deployment/store-and-forward/messages",
        "/_soland/admin/deployment/store-and-forward/drain",
        "/_soland/admin/deployment/store-and-forward/ingest",
        "/_soland/self/account/accept-external-invite",
        "/_soland/self/deployment/enclave-proxy",
    ] {
        let mut response = TestClient::post(format!("http://server{path}"))
            .send(&app)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND), "{path}");
        let problem: Value = response.take_json().await.unwrap();
        assert_eq!(
            problem["type"],
            json!("https://arkret.org/problems/unrecognized_endpoint"),
            "{path}"
        );
    }
}
