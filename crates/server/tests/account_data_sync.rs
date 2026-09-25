//! Account data writes use a caller-signed actor-private Event on an accepted
//! PCR. The fixture never inserts an uncommitted Event as accepted state.

use arkret_wire::{EventKind, ScopeRef};
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use soland_http::config::AppConfig;
use soland_http::service;
use soland_http::state::AppState;
use soland_test_support::AppStateTestExt as _;
use soland_test_support::pcr_genesis::PcrGenesisFixture;

fn test_config() -> AppConfig {
    AppConfig {
        development_mode: true,
        embedded_webvh_registration_bearer: Some("fixture-registration".to_owned()),
        jws_replay_window_seconds: 0,
        ..soland_test_support::app_config()
    }
}

async fn account_session(state: &AppState, fixture: &PcrGenesisFixture) -> String {
    fixture.admit(state).await.expect("durable PCR genesis");
    let app = service(state.clone());
    let mut registration = TestClient::post("http://server/_soland/gate/account/project")
        .add_header("authorization", "Bearer fixture-registration", true)
        .json(&json!({
            "principal_id": fixture.history.account.principal_id,
            "did": fixture.history.did,
            "display_name": "Account Data fixture",
        }))
        .send(&app)
        .await;
    let status = registration.status_code;
    let body = registration.take_string().await;
    assert!(
        matches!(status, Some(StatusCode::OK | StatusCode::CONFLICT)),
        "account projection: {body:?}"
    );
    let mut login = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&json!({
            "actor": fixture.history.account.principal_id,
            "device_id": fixture.history.founding_device_id,
            "display_name": "Account Data fixture",
        }))
        .send(&app)
        .await;
    assert_eq!(login.status_code, Some(StatusCode::OK));
    let body: Value = login.take_json().await.expect("dev-login JSON");
    body["session_credential"]
        .as_str()
        .expect("session credential")
        .to_owned()
}

fn signed_account_data_event(
    state: &AppState,
    fixture: &PcrGenesisFixture,
    key: &str,
) -> arkret_wire::Event {
    let actor = arkret_wire::ActorId::account(fixture.history.account.clone());
    let encrypted = arkret_crypto::account_data_crypto::seal_account_data_value_with_nonce(
        &[7; 32],
        &actor,
        key,
        &json!({"enabled": true}),
        [9; 24],
    )
    .expect("encrypted account data value");
    let realm_id = fixture.unit.transactions[0].event.realm_id.clone();
    let event = arkret_wire::test_support::raw_event_at(
        EventKind::AccountDataSet.as_str(),
        ScopeRef::Realm { realm_id },
        fixture.history.account.principal_id.clone(),
        state.service_core_id(),
        json!({
            "key": key,
            "expected_server_revision": 0,
            "body": encrypted,
            "updated_at": arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
        }),
        chrono::Utc::now(),
    )
    .expect("typed account data Event");
    soland_test_support::signed_event::sign_fixture_event(
        event,
        fixture.history.did.as_str(),
        fixture.history.founding_device_id.as_str(),
        fixture.history.founding_device_signing_seed,
    )
}

/// `device-lifecycle.md` §10.1: a verified device_summary's provenance is
/// exactly `verification_source` plus `authorized_event_ref`, so the account
/// projection returns the verified founding device instead of failing closed.
#[tokio::test]
async fn verified_device_summary_carries_only_authorization_provenance() {
    let state = soland_test_support::app_state(test_config());
    let fixture = PcrGenesisFixture::new(state.service_did());
    fixture.admit(&state).await.expect("durable PCR genesis");
    let app = service(state.clone());
    let mut projection = TestClient::post("http://server/_soland/gate/account/project")
        .add_header("authorization", "Bearer fixture-registration", true)
        .json(&json!({
            "principal_id": fixture.history.account.principal_id,
            "did": fixture.history.did,
            "display_name": "Device summary fixture",
        }))
        .send(&app)
        .await;
    let status = projection.status_code;
    let body: Value = projection
        .take_json()
        .await
        .expect("account projection JSON");
    assert_eq!(status, Some(StatusCode::OK), "account projection: {body}");
    let device = body["devices"]
        .as_array()
        .expect("account projection devices")
        .iter()
        .find(|device| device["device_id"] == fixture.history.founding_device_id.as_str())
        .unwrap_or_else(|| panic!("the founding device is listed: {body}"));
    assert_eq!(device["verification_state"], "verified", "{device}");
    assert!(device["verification_source"].is_string(), "{device}");
    assert!(
        device["authorized_event_ref"]
            .as_str()
            .is_some_and(|reference| reference.starts_with("ak:event:")),
        "{device}"
    );
    assert!(
        device.get("signer_resolution_evidence_ref").is_none(),
        "device_summary carries no signer evidence reference: {device}"
    );
}

/// An account-data write is an actor-private Event whose producer is the
/// holder's device under a standard DPoP SessionGrant. A development bearer
/// session binds no device grant, so it cannot produce the Event and nothing
/// is stored. The admitted path runs live in Cotest `protocol_payloads`.
#[tokio::test]
async fn development_bearer_session_cannot_produce_account_data_events() {
    let state = soland_test_support::app_state(test_config());
    let fixture = PcrGenesisFixture::new(state.service_did());
    let token = account_session(&state, &fixture).await;
    let app = service(state.clone());
    let key = arkret_wire::AccountDataKey::PUSH_RULES;
    let event = signed_account_data_event(&state, &fixture, key);
    let response = TestClient::put(format!("http://server/_arkret/self/account_data/{key}"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_ACCOUNT_DATA_RESOURCE_REPLACE_V1,
            true,
        )
        .json(&json!({"set_event": event}))
        .send(&app)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::FORBIDDEN));
    let actor = arkret_wire::ActorId::account(fixture.history.account.clone()).to_string();
    assert!(
        state
            .test_persistence()
            .account_data()
            .get(&actor, key)
            .await
            .expect("account data read")
            .is_none(),
        "a refused producer writes nothing"
    );
}

#[tokio::test]
async fn account_data_write_rejects_another_actors_signed_event() {
    let state = soland_test_support::app_state(test_config());
    let holder = PcrGenesisFixture::new(state.service_did());
    let token = account_session(&state, &holder).await;
    let other = PcrGenesisFixture::new(state.service_did());
    other.admit(&state).await.expect("second accepted PCR");
    let key = arkret_wire::AccountDataKey::PUSH_RULES;
    let event = signed_account_data_event(&state, &other, key);
    let app = service(state);
    let response = TestClient::put(format!("http://server/_arkret/self/account_data/{key}"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_ACCOUNT_DATA_RESOURCE_REPLACE_V1,
            true,
        )
        .json(&json!({"set_event": event}))
        .send(&app)
        .await;
    assert!(
        matches!(
            response.status_code,
            Some(StatusCode::FORBIDDEN | StatusCode::BAD_REQUEST)
        ),
        "holder isolation must reject a different actor's Event"
    );
}
