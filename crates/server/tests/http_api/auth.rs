//! Integration tests — `auth` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

use soland::state::DeviceMessageRecord;

use super::common::*;

fn registration_secret_digest(value: &str) -> arkret_sdk::Hash {
    arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(value.as_bytes())).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn external_bearer_without_dpop_is_rejected() {
    let state = AppState::new(test_config(), Db { pool: None });

    let mut response = TestClient::get("http://server/_arkret/self/account/viewer")
        .add_header("authorization", "Bearer external-session-credential", true)
        .send(&app_from_state(state))
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::UNAUTHORIZED);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["ok"], false);
    assert_eq!(body["error"]["code"], "unauthenticated");
}

#[tokio::test]
async fn account_registration_policy_rejects_closed_and_audits() {
    let state = AppState::new(test_config(), Db { pool: None });
    {
        let mut policy = state.account_registration_policy.lock();
        policy.enabled = false;
    }

    let mut response = TestClient::post("http://server/_arkret/gate/account/register")
        .json(&serde_json::json!({
            "principal_id": "did:web:closed-register.example",
        }))
        .send(&app_from_state(state.clone()))
        .await;
    let status = response.status_code.unwrap();
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"]["code"], "failed_precondition");
    assert_eq!(
        body["error"]["details"]["reason_detail"],
        "registration_closed"
    );

    let audit = state
        .persistence
        .audit()
        .list_for_actor("did:web:closed-register.example")
        .await
        .unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["outcome"], "registration_closed");
    assert_eq!(
        audit[0]["payload"]["registration_audit"]["outcome"],
        "registration_closed"
    );
}

#[tokio::test]
async fn account_registration_policy_evidence_and_rate_limit_are_enforced() {
    let state = AppState::new(test_config(), Db { pool: None });
    {
        let mut policy = state.account_registration_policy.lock();
        *policy = arkret_sdk::AccountRegistrationPolicy {
            verification_code: arkret_sdk::AccountRegistrationVerificationPolicy {
                required: true,
                code_digest: Some(registration_secret_digest("246810")),
            },
            organization_allowlist: vec!["example.edu".to_owned()],
            invitation: arkret_sdk::AccountRegistrationInvitationPolicy {
                required: true,
                token_digests: vec![registration_secret_digest("invite-token")],
            },
            ..arkret_sdk::AccountRegistrationPolicy::default()
        };
    }

    let mut missing_code = TestClient::post("http://server/_arkret/gate/account/register")
        .json(&serde_json::json!({
            "principal_id": "did:web:alice.example.edu",
        }))
        .send(&app_from_state(state.clone()))
        .await;
    let status = missing_code.status_code.unwrap();
    let missing_code: Value = missing_code.take_json().await.unwrap();
    assert_eq!(status, StatusCode::CONFLICT, "{missing_code}");
    assert_eq!(
        missing_code["error"]["details"]["reason_detail"],
        "verification_code_required"
    );

    let mut wrong_org = TestClient::post("http://server/_arkret/gate/account/register")
        .json(&serde_json::json!({
            "principal_id": "did:web:bob.other.example",
            "policy_evidence": {
                "verification_code": "246810",
                "organization": "other.example",
                "invitation_token": "invite-token"
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(wrong_org.status_code.unwrap(), StatusCode::CONFLICT);
    let wrong_org: Value = wrong_org.take_json().await.unwrap();
    assert_eq!(
        wrong_org["error"]["details"]["reason_detail"],
        "organization_not_allowed"
    );

    let mut missing_invite = TestClient::post("http://server/_arkret/gate/account/register")
        .json(&serde_json::json!({
            "principal_id": "did:web:invite-missing.example.edu",
            "policy_evidence": {
                "verification_code": "246810",
                "organization": "example.edu"
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(missing_invite.status_code.unwrap(), StatusCode::CONFLICT);
    let missing_invite: Value = missing_invite.take_json().await.unwrap();
    assert_eq!(
        missing_invite["error"]["details"]["reason_detail"],
        "invitation_required"
    );

    let accepted: Value = TestClient::post("http://server/_arkret/gate/account/register")
        .json(&serde_json::json!({
            "principal_id": "did:web:carol.example.edu",
            "display_name": "Carol",
            "policy_evidence": {
                "verification_code": "246810",
                "organization": "example.edu",
                "invitation_token": "invite-token"
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(accepted["principal_id"], "did:web:carol.example.edu");
    assert_eq!(accepted["registration_audit"]["outcome"], "accepted");
    assert_eq!(
        accepted["registration_audit"]["evidence"]["organization"],
        "example.edu"
    );

    // sync/api-conventions.md §7 — `principal_id` is a resource identity, not a
    // request-level idempotency key. Re-registering the same principal is a
    // successor/idempotent bind (the handler returns the existing account with
    // `state=active`), NOT a `duplicate_conflict`: that reason is reserved for a
    // request-level idempotency-key collision carrying a different canonical
    // body ("同一对象...的不同 canonical body 是普通后继写...MUST NOT 仅因
    // identity 相同返回 duplicate_conflict").
    let duplicate: Value = TestClient::post("http://server/_arkret/gate/account/register")
        .json(&serde_json::json!({
            "principal_id": "did:web:carol.example.edu",
            "policy_evidence": {
                "verification_code": "246810",
                "organization": "example.edu",
                "invitation_token": "invite-token"
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(duplicate["principal_id"], "did:web:carol.example.edu");
    assert_eq!(duplicate["state"], "active");
    assert_eq!(duplicate["registration_audit"]["outcome"], "accepted");

    let rate_limited_state = AppState::new(test_config(), Db { pool: None });
    {
        let mut policy = rate_limited_state.account_registration_policy.lock();
        policy.rate_limit = Some(arkret_sdk::AccountRegistrationRateLimitPolicy {
            max_attempts: 1,
            window_seconds: 60,
        });
    }
    let _: Value = TestClient::post("http://server/_arkret/gate/account/register")
        .json(&serde_json::json!({
            "principal_id": "did:web:rate-register.example",
        }))
        .send(&app_from_state(rate_limited_state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let mut limited = TestClient::post("http://server/_arkret/gate/account/register")
        .json(&serde_json::json!({
            "principal_id": "did:web:rate-register.example",
        }))
        .send(&app_from_state(rate_limited_state.clone()))
        .await;
    assert_eq!(limited.status_code.unwrap(), StatusCode::TOO_MANY_REQUESTS);
    let limited: Value = limited.take_json().await.unwrap();
    assert_eq!(limited["error"]["code"], "rate_limited");
    assert_eq!(limited["error"]["details"]["reason_detail"], "rate_limited");
}

#[tokio::test]
async fn dev_login_is_unavailable_in_production_mode() {
    let mut config = test_config();
    config.development_mode = false;
    let state = AppState::new(config, Db { pool: None });

    let response = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&serde_json::json!({
            "actor": "did:web:alice.example",
            "device_id": "ak:device:01904100-0000-7000-8000-0a4a40000006"
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

    let response = TestClient::post("http://server/_arkret/find/directory/search-realms")
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
            // (`/health` is not under /_arkret/*, so it falls into `other`).
            auth_max_requests: 1,
            api_max_requests: 1,
            probe_max_requests: 1,
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
            .starts_with("ak:request:")
    );
}

#[tokio::test]
async fn framework_errors_use_arkret_error_envelope() {
    let not_found: Value = TestClient::get("http://server/_arkret/self/missing")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(not_found["ok"], false);
    assert_eq!(not_found["error"]["code"], "unrecognized_endpoint");

    let method_not_allowed: Value = TestClient::post("http://server/_arkret/describe")
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
        "http://server/_arkret/self/account/viewer?access_token={token}"
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
async fn hard_logout_removes_push_registration_and_to_device_queue_for_device() {
    let state = AppState::new(test_config(), Db { pool: None });
    let actor = "did:web:alice.example";
    let device_a = "ak:device:01904100-0000-7000-8000-a11ce00000aa";
    let device_b = "ak:device:01904100-0000-7000-8000-a11ce00000bb";
    let token_a = dev_token_for_device(state.clone(), actor, device_a, "Alice Phone").await;
    let _token_b = dev_token_for_device(state.clone(), actor, device_b, "Alice Tablet").await;

    state
        .persistence
        .push_devices()
        .register(serde_json::json!({
            "registration_id": "ak:push:device-a-main",
            "actor": actor,
            "device_id": device_a,
            "push_gateway": "https://floria.example",
            "push_key": "push-key-a-main",
            "app_id": "inkson-main",
        }))
        .await
        .unwrap();
    state
        .persistence
        .push_devices()
        .register(serde_json::json!({
            "registration_id": "ak:push:device-a-voip",
            "actor": actor,
            "device_id": device_a,
            "push_gateway": "https://floria.example",
            "push_key": "push-key-a-voip",
            "app_id": "inkson-voip",
        }))
        .await
        .unwrap();
    state
        .persistence
        .push_devices()
        .register(serde_json::json!({
            "registration_id": "ak:push:device-b-main",
            "actor": actor,
            "device_id": device_b,
            "push_gateway": "https://floria.example",
            "push_key": "push-key-b-main",
            "app_id": "inkson-main",
        }))
        .await
        .unwrap();
    state
        .persistence
        .device_messages()
        .append(DeviceMessageRecord {
            idempotency_key: "logout-device-a".to_owned(),
            sender: actor.to_owned(),
            recipient: actor.to_owned(),
            device_id: device_a.to_owned(),
            position: 1,
            content: serde_json::json!({"type": "ak.test.device_message"}),
            created_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
    state
        .persistence
        .device_messages()
        .append(DeviceMessageRecord {
            idempotency_key: "logout-device-b".to_owned(),
            sender: actor.to_owned(),
            recipient: actor.to_owned(),
            device_id: device_b.to_owned(),
            position: 2,
            content: serde_json::json!({"type": "ak.test.device_message"}),
            created_at: chrono::Utc::now(),
        })
        .await
        .unwrap();

    let mut response = TestClient::post("http://server/_arkret/gate/account/logout")
        .add_header("authorization", format!("Bearer {token_a}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["revoked"], true);

    let push_devices = state
        .persistence
        .push_devices()
        .snapshot_all()
        .await
        .unwrap();
    assert_eq!(push_devices.len(), 1);
    assert_eq!(push_devices[0]["device_id"], device_b);
    let device_a_messages = state
        .persistence
        .device_messages()
        .list_after(actor, device_a, 0)
        .await
        .unwrap();
    assert!(device_a_messages.is_empty());
    let device_b_messages = state
        .persistence
        .device_messages()
        .list_after(actor, device_b, 0)
        .await
        .unwrap();
    assert_eq!(device_b_messages.len(), 1);
    assert_eq!(device_b_messages[0].device_id, device_b);
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
