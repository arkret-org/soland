//! Account data writes use a caller-signed actor-private Event on an accepted
//! PCR. The fixture never inserts an uncommitted Event as accepted state.

use arkret_wire::{EventKind, ScopeRef};
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use soland_http::config::AppConfig;
use soland_http::service;
use soland_http::state::AppState;
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

#[tokio::test]
async fn signed_account_data_set_uses_the_accepted_pcr_and_cas_revision() {
    let state = soland_test_support::app_state(test_config());
    let fixture = PcrGenesisFixture::new(state.service_did());
    let token = account_session(&state, &fixture).await;
    let app = service(state.clone());
    let key = arkret_wire::AccountDataKey::PUSH_RULES;
    let event = signed_account_data_event(&state, &fixture, key);
    let mut response = TestClient::put(format!("http://server/_arkret/self/account_data/{key}"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_ACCOUNT_DATA_RESOURCE_REPLACE_V1,
            true,
        )
        .json(&json!({"set_event": event}))
        .send(&app)
        .await;
    let status = response.status_code;
    let body: Value = response.take_json().await.expect("account-data outcome");
    assert_eq!(
        status,
        Some(StatusCode::OK),
        "signed Event admission: {body}"
    );
    assert_eq!(body["revision"], 1);
    assert_eq!(body["account_data_key"], key);
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

#[tokio::test]
async fn push_registration_returns_only_the_station_pairwise_target() {
    let state = soland_test_support::app_state(test_config());
    let fixture = PcrGenesisFixture::new(state.service_did());
    let token = account_session(&state, &fixture).await;
    let app = service(state.clone());
    let mut response = TestClient::post("http://server/_arkret/edge/push/register-device")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_REGISTER_DEVICE_V1,
            true,
        )
        .json(&json!({
            "device_id": fixture.history.founding_device_id,
            "push_gateway_url": "https://push.example",
            "push_key": "opaque",
            "platform": "desktop",
            "app_id": "inkson",
        }))
        .send(&app)
        .await;
    let status = response.status_code;
    let registered: Value = response.take_json().await.expect("push registration JSON");
    assert_eq!(
        status,
        Some(StatusCode::OK),
        "push registration: {registered}"
    );
    assert!(
        registered["registration_id"]
            .as_str()
            .expect("opaque registration handle")
            .starts_with("push_registration:")
    );
    let expected = soland_test_support::registered_push_target_id(
        &state,
        fixture.history.account.principal_id.as_str(),
        fixture.history.founding_device_id.as_str(),
    )
    .await;
    assert_eq!(registered["push_target_id"], expected);
    for private_field in [
        "push_key",
        "account_id",
        "principal_id",
        "recipient_id",
        "device_id",
    ] {
        assert!(
            registered.get(private_field).is_none(),
            "leaked {private_field}"
        );
    }
}
