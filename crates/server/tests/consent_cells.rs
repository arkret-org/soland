use arkret_identifiers::Did;
use arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy;
use arkret_wire::{AccountId, DidCoreId, InviteReceiveAction, UnknownInviteAction};
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::Value;
use soland_http::config::AppConfig;
use soland_http::service;

const ACCOUNT_REGISTER_BEARER: &str = "soland-test-account-register-bearer";

fn fixture_account_actor(
    state: &soland_http::state::AppState,
    principal_did: &str,
) -> arkret_wire::ActorId {
    let principal_id = arkret_wire::project_did_to_core_id(
        &Did::new(principal_did.to_owned()).expect("fixture account DID"),
    )
    .expect("fixture account core id");
    arkret_wire::ActorId::account(AccountId::new(principal_id, state.service_core_id()))
}

fn test_config() -> AppConfig {
    AppConfig {
        development_mode: true,
        embedded_webvh_registration_bearer: Some(ACCOUNT_REGISTER_BEARER.to_owned()),
        did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned(), "peer".to_owned()],
        jws_replay_window_seconds: 0,
        ..soland_test_support::app_config()
    }
}

async fn ensure_account(app: &salvo::Service, actor: &str) {
    let did = Did::new(actor.to_owned()).expect("fixture account DID");
    let principal_id = arkret_wire::project_did_to_core_id(&did).expect("fixture account core id");
    let mut response = TestClient::post("http://server/_soland/gate/account/project")
        .add_header(
            "authorization",
            format!("Bearer {ACCOUNT_REGISTER_BEARER}"),
            true,
        )
        .json(&serde_json::json!({
            "principal_id": principal_id,
            "did": did,
            "display_name": actor,
        }))
        .send(app)
        .await;
    let status = response.status_code.expect("register status");
    let body: Value = response.take_json().await.unwrap();
    assert!(
        matches!(status, StatusCode::OK | StatusCode::CONFLICT),
        "account register failed: {body}"
    );
}

async fn dev_token(
    state: &soland_http::state::AppState,
    app: &salvo::Service,
    fixture: &soland_test_support::pcr_genesis::PcrGenesisFixture,
) -> String {
    let actor = fixture.history.did.as_str();
    fixture.admit(state).await.expect("accepted PCR genesis");
    ensure_account(app, actor).await;
    let actor_core = arkret_wire::project_did_to_core_id(
        &Did::new(actor.to_owned()).expect("fixture actor DID"),
    )
    .expect("fixture actor core id");
    let device_id = fixture.history.founding_device_id.to_string();
    let login: Value = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&serde_json::json!({
            "actor": actor_core,
            "device_id": device_id,
            "display_name": actor,
        }))
        .send(app)
        .await
        .take_json()
        .await
        .unwrap();
    let token = login["session_credential"].as_str().unwrap().to_owned();
    token
}

#[tokio::test]
#[ignore = "requires accepted PCR Event/RealmCommit device authorization fixture"]
async fn opaque_consent_request_does_not_create_a_pending_cell() {
    let state = soland_test_support::app_state(test_config());
    let app = service(state.clone());
    let alice_fixture =
        soland_test_support::pcr_genesis::PcrGenesisFixture::new(state.service_core_id());
    let bob_fixture =
        soland_test_support::pcr_genesis::PcrGenesisFixture::new(state.service_core_id());
    let alice_did = alice_fixture.history.did.as_str();
    let bob_did = bob_fixture.history.did.as_str();
    let alice_token = dev_token(&state, &app, &alice_fixture).await;
    let bob_token = dev_token(&state, &app, &bob_fixture).await;

    let mut requested = TestClient::post("http://server/_arkret/self/consent/request")
        .add_header("Authorization", format!("Bearer {alice_token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_CONSENT_COMMAND_REQUEST_V1,
            true,
        )
        .json(&serde_json::json!({
            "holder_account_id": fixture_account_actor(&state, bob_did)
                .as_account_id()
                .expect("fixture account actor"),
            "consent_scope": "voice_call",
        }))
        .send(&app)
        .await;
    assert_eq!(requested.status_code.unwrap(), StatusCode::OK);
    assert_eq!(
        requested.take_json::<Value>().await.unwrap(),
        serde_json::json!({
            "accepted_for_processing": true,
        })
    );

    let peer = serde_json::json!({
        "kind": "actor",
        "actor_id": fixture_account_actor(&state, alice_did),
    });
    let mut cell_url = url::Url::parse("http://server/_arkret/self/consent/cell").unwrap();
    cell_url
        .query_pairs_mut()
        .append_pair("peer", &serde_json::to_string(&peer).unwrap())
        .append_pair("consent_scope", "voice_call");
    let response = TestClient::get(cell_url.as_str())
        .add_header("Authorization", format!("Bearer {bob_token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_CONSENT_RESOURCE_GET_V1,
            true,
        )
        .send(&app)
        .await;
    assert_eq!(response.status_code.unwrap(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn invite_receive_policy_get_set_round_trips() {
    let state = soland_test_support::app_state(test_config());
    let app = service(state.clone());
    let alice_fixture =
        soland_test_support::pcr_genesis::PcrGenesisFixture::new(state.service_core_id());
    let alice = alice_fixture.history.account.clone();
    let mallory = DidCoreId::new("ak:did_core:web:irp-mallory.example").unwrap();
    let alice_token = dev_token(&state, &app, &alice_fixture).await;

    let default_policy: InviteReceivePolicy =
        TestClient::get("http://server/_arkret/self/invite-receive-policy")
            .add_header("Authorization", format!("Bearer {alice_token}"), true)
            .add_header(
                "Arkret-Operation",
                arkret_wire::ServiceOperationId::SELF_INVITE_RECEIVE_POLICY_RESOURCE_GET_V1,
                true,
            )
            .send(&app)
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(default_policy.account_id, alice);
    assert!(
        default_policy
            .holder_allowed_introduction_kinds
            .iter()
            .any(|kind| kind == "consent_grant")
    );

    let mut custom = default_policy.clone();
    custom.holder_allowed_introduction_kinds = vec!["consent_grant".to_owned()];
    custom.explicit_address_behavior = InviteReceiveAction::Drop;
    custom.unknown_invites = UnknownInviteAction::Drop;
    custom.denied_actor_ids = vec![arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        mallory.clone(),
        arkret_wire::DidCoreId::new("ak:did_core:web:remote.example").unwrap(),
    ))];
    let mut stored_response = TestClient::put("http://server/_arkret/self/invite-receive-policy")
        .add_header("Authorization", format!("Bearer {alice_token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_INVITE_RECEIVE_POLICY_RESOURCE_REPLACE_V1,
            true,
        )
        .add_header("content-type", "application/json", true)
        .body(arkret_canonical::canonical_json_bytes(&custom).unwrap())
        .send(&app)
        .await;
    let stored_status = stored_response.status_code.unwrap();
    let stored_value: Value = stored_response.take_json().await.unwrap();
    assert_eq!(stored_status, StatusCode::OK, "{stored_value}");
    let stored: InviteReceivePolicy = serde_json::from_value(stored_value).unwrap();
    assert_eq!(stored, custom);

    let reread: InviteReceivePolicy =
        TestClient::get("http://server/_arkret/self/invite-receive-policy")
            .add_header("Authorization", format!("Bearer {alice_token}"), true)
            .add_header(
                "Arkret-Operation",
                arkret_wire::ServiceOperationId::SELF_INVITE_RECEIVE_POLICY_RESOURCE_GET_V1,
                true,
            )
            .send(&app)
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(reread, custom);

    for mismatched_account in [
        AccountId::new(mallory, alice.station_id.clone()),
        AccountId::new(
            alice.principal_id.clone(),
            DidCoreId::new("ak:did_core:web:foreign-station.example").unwrap(),
        ),
    ] {
        let mismatched = InviteReceivePolicy::spec_default(mismatched_account.clone());
        let rejected = TestClient::put("http://server/_arkret/self/invite-receive-policy")
            .add_header("Authorization", format!("Bearer {alice_token}"), true)
            .add_header(
                "Arkret-Operation",
                arkret_wire::ServiceOperationId::SELF_INVITE_RECEIVE_POLICY_RESOURCE_REPLACE_V1,
                true,
            )
            .add_header("content-type", "application/json", true)
            .body(arkret_canonical::canonical_json_bytes(&mismatched).unwrap())
            .send(&app)
            .await;
        assert_eq!(
            rejected.status_code.unwrap(),
            StatusCode::FORBIDDEN,
            "cannot replace another account's policy: {mismatched_account}"
        );
    }

    let unchanged: InviteReceivePolicy =
        TestClient::get("http://server/_arkret/self/invite-receive-policy")
            .add_header("Authorization", format!("Bearer {alice_token}"), true)
            .add_header(
                "Arkret-Operation",
                arkret_wire::ServiceOperationId::SELF_INVITE_RECEIVE_POLICY_RESOURCE_GET_V1,
                true,
            )
            .send(&app)
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(unchanged, custom);
}
