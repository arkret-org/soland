use arkret_identifiers::Did;
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::Value;
use soland_http::config::AppConfig;
use soland_http::{ids, service};

const ACCOUNT_REGISTER_BEARER: &str = "soland-test-account-register-bearer";

fn test_config() -> AppConfig {
    AppConfig {
        development_mode: true,
        embedded_webvh_registration_bearer: Some(ACCOUNT_REGISTER_BEARER.to_owned()),
        did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned(), "peer".to_owned()],
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: std::collections::BTreeMap::new(),
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
    actor: &str,
) -> String {
    ensure_account(app, actor).await;
    let actor_core = arkret_wire::project_did_to_core_id(
        &Did::new(actor.to_owned()).expect("fixture actor DID"),
    )
    .expect("fixture actor core id");
    let device_id = ids::generate("device");
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
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[21_u8; 32]);
    soland_test_support::project_authorized_principal_device(
        state,
        actor,
        &device_id,
        &signing_key,
    )
    .await;
    token
}

#[tokio::test]
async fn opaque_consent_request_does_not_create_a_pending_cell() {
    let state = soland_test_support::app_state(test_config());
    let app = service(state.clone());
    let alice_did = "did:web:opaque-consent-request-alice.example";
    let bob_did = "did:web:opaque-consent-request-bob.example";
    let alice = "ak:did_core:web:opaque-consent-request-alice.example";
    let bob = "ak:did_core:web:opaque-consent-request-bob.example";
    let alice_token = dev_token(&state, &app, alice_did).await;
    let bob_token = dev_token(&state, &app, bob_did).await;

    let mut requested = TestClient::post("http://server/_arkret/self/consent/request")
        .add_header("Authorization", format!("Bearer {alice_token}"), true)
        .json(&serde_json::json!({
            "holder_principal_id": bob,
            "consent_scope": "direct_message",
        }))
        .send(&app)
        .await;
    assert_eq!(requested.status_code.unwrap(), StatusCode::OK);
    assert_eq!(
        requested.take_json::<Value>().await.unwrap(),
        serde_json::json!({
            "ok": true,
            "accepted_for_processing": true,
        })
    );

    let response = TestClient::get(format!(
        "http://server/_arkret/self/consent/cells/{bob}?peer={alice}&consent_scope=direct_message"
    ))
    .add_header("Authorization", format!("Bearer {bob_token}"), true)
    .send(&app)
    .await;
    assert_eq!(response.status_code.unwrap(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn invite_receive_policy_get_set_round_trips() {
    let state = soland_test_support::app_state(test_config());
    let app = service(state.clone());
    let alice_did = "did:web:irp-alice.example";
    let alice = "ak:did_core:web:irp-alice.example";
    let mallory = "ak:did_core:web:irp-mallory.example";
    let alice_token = dev_token(&state, &app, alice_did).await;

    let default_policy: Value = TestClient::get("http://server/_arkret/self/invite-receive-policy")
        .add_header("Authorization", format!("Bearer {alice_token}"), true)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(default_policy["subject_id"], alice);
    assert!(
        default_policy["holder_allowed_introduction_kinds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|kind| kind == "consent_grant")
    );

    let custom = serde_json::json!({
        "schema": default_policy["schema"],
        "subject_id": alice,
        "holder_allowed_introduction_kinds": ["consent_grant"],
        "explicit_address_behavior": "drop",
        "unknown_invites": "drop",
        "denied_subjects": [mallory],
    });
    let stored: Value = TestClient::put("http://server/_arkret/self/invite-receive-policy")
        .add_header("Authorization", format!("Bearer {alice_token}"), true)
        .json(&custom)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(stored["explicit_address_behavior"], "drop");
    assert_eq!(stored["denied_subjects"][0], mallory);

    let reread: Value = TestClient::get("http://server/_arkret/self/invite-receive-policy")
        .add_header("Authorization", format!("Bearer {alice_token}"), true)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(reread["explicit_address_behavior"], "drop");
    assert_eq!(reread["denied_subjects"][0], mallory);

    let mismatched = serde_json::json!({
        "schema": default_policy["schema"],
        "subject_id": mallory,
        "holder_allowed_introduction_kinds": ["consent_grant"],
        "explicit_address_behavior": "quarantine",
        "unknown_invites": "drop",
    });
    let rejected = TestClient::put("http://server/_arkret/self/invite-receive-policy")
        .add_header("Authorization", format!("Bearer {alice_token}"), true)
        .json(&mismatched)
        .send(&app)
        .await;
    assert_eq!(rejected.status_code.unwrap(), StatusCode::FORBIDDEN);
}
