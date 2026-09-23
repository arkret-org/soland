//! Actor Profile resolution authorization at a durable PCR authority cut.
//!
//! Positive profile-current coverage is pending the accepted profile provider:
//! `resolved_actor_profile_evidence` currently fails closed. See task 2011.

use arkret_identifiers::RealmId;
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::Value;
use soland_http::config::AppConfig;
use soland_http::service;
use soland_test_support::pcr_genesis::PcrGenesisFixture;

#[tokio::test]
async fn pcr_cannot_be_used_as_actor_profile_relationship_selector() {
    let state = soland_test_support::app_state(AppConfig {
        development_mode: true,
        embedded_webvh_registration_bearer: Some("fixture-registration".to_owned()),
        jws_replay_window_seconds: 0,
        ..soland_test_support::app_config()
    });
    let fixture = PcrGenesisFixture::new(state.service_did());
    fixture.admit(&state).await.expect("durable PCR genesis");
    let app = service(state.clone());
    let did = fixture.history.did.clone();
    let principal_id = fixture.history.account.principal_id.clone();
    let mut registration = TestClient::post("http://server/_soland/gate/account/project")
        .add_header("authorization", "Bearer fixture-registration", true)
        .json(&serde_json::json!({
            "principal_id": principal_id,
            "did": did,
            "display_name": "Actor Profile fixture",
        }))
        .send(&app)
        .await;
    assert!(
        matches!(
            registration.status_code,
            Some(StatusCode::OK | StatusCode::CONFLICT)
        ),
        "account projection: {:?}",
        registration.take_string().await
    );

    let mut login = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&serde_json::json!({
            "actor": principal_id,
            "device_id": fixture.history.founding_device_id,
            "display_name": "Actor Profile fixture",
        }))
        .send(&app)
        .await;
    assert_eq!(login.status_code, Some(StatusCode::OK));
    let login_body: Value = login.take_json().await.expect("dev-login response");
    let token = login_body["session_credential"]
        .as_str()
        .expect("dev-login credential");
    let actor = arkret_wire::ActorId::account(fixture.history.account.clone());
    let request = arkret_models_identity::actor_profile_operations::ActorProfileResolveRequest::new(
        RealmId::new(fixture.unit.transactions[0].event.realm_id.to_string())
            .expect("typed PCR Realm id"),
        vec![actor],
    );
    let mut response = TestClient::post("http://server/_arkret/self/actor-profiles/query")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_ACTOR_PROFILE_READ_RESOLVE_V1,
            true,
        )
        .json(&request)
        .send(&app)
        .await;
    let status = response.status_code;
    let body = response.take_string().await;
    assert_eq!(
        status,
        Some(StatusCode::NOT_FOUND),
        "a PCR must not become a relationship selector: {body:?}"
    );
}
