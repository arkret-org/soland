//! Integration tests — `auth` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

use soland_storage::DeviceMessageRecord;

use super::common::*;

fn registration_secret_digest(value: &str) -> arkret_identifiers::Hash {
    arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(value.as_bytes())).unwrap()
}

#[test]
fn external_bearer_without_dpop_is_rejected() {
    run_on_deep_stack_multi_thread(
        "external_bearer_without_dpop_is_rejected",
        external_bearer_without_dpop_is_rejected_body,
    );
}

async fn external_bearer_without_dpop_is_rejected_body() {
    let state = soland_test_support::app_state(test_config());

    let mut response = TestClient::get("http://server/_arkret/self/account/viewer")
        .add_header("authorization", "Bearer external-session-credential", true)
        .send(&app_from_state(state))
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::UNAUTHORIZED);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(problem_code(&body), "unauthenticated");
}

#[test]
fn account_register_requires_account_authority_bearer() {
    run_on_deep_stack(
        "account_register_requires_account_authority_bearer",
        account_register_requires_account_authority_bearer_body,
    );
}

async fn account_register_requires_account_authority_bearer_body() {
    let state = soland_test_support::app_state(test_config());

    let mut response = TestClient::post("http://server/_soland/gate/account/project")
        .json(&serde_json::json!({
            "principal_id": fixture_actor_core_id("did:web:unauthorized-register.example"),
            "did": "did:web:unauthorized-register.example",
        }))
        .send(&app_from_state(state))
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::UNAUTHORIZED);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["type"], "https://arkret.org/problems/unauthenticated");
    assert_eq!(body["status"], 401);
}

#[test]
fn account_registration_policy_rejects_closed_and_audits() {
    run_on_deep_stack(
        "account_registration_policy_rejects_closed_and_audits",
        account_registration_policy_rejects_closed_and_audits_body,
    );
}

async fn account_registration_policy_rejects_closed_and_audits_body() {
    let state = soland_test_support::app_state(test_config());
    {
        let mut policy = state.test_account_registration_policy().lock();
        policy.enabled = false;
    }

    let mut response = TestClient::post("http://server/_soland/gate/account/project")
        .add_header(
            "authorization",
            format!("Bearer {ACCOUNT_REGISTER_BEARER}"),
            true,
        )
        .json(&serde_json::json!({
            "principal_id": fixture_actor_core_id("did:web:closed-register.example"),
            "did": "did:web:closed-register.example",
        }))
        .send(&app_from_state(state.clone()))
        .await;
    let status = response.status_code.unwrap();
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        body["type"],
        "https://arkret.org/problems/failed_precondition"
    );
    assert_eq!(body["reason_detail"], "registration_closed");

    let audit = state
        .test_persistence()
        .audit()
        .list_for_actor(fixture_actor_core_id("did:web:closed-register.example").as_str())
        .await
        .unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["outcome"], "registration_closed");
    assert_eq!(
        audit[0]["payload"]["registration_audit"]["outcome"],
        "registration_closed"
    );
}

#[test]
fn account_registration_policy_and_closed_projection_wire_are_enforced() {
    run_on_deep_stack(
        "account_registration_policy_and_closed_projection_wire_are_enforced",
        account_registration_policy_and_closed_projection_wire_are_enforced_body,
    );
}

async fn account_registration_policy_and_closed_projection_wire_are_enforced_body() {
    let state = soland_test_support::app_state(test_config());
    {
        let mut policy = state.test_account_registration_policy().lock();
        *policy = arkret_models_identity::AccountRegistrationPolicy {
            verification_code: arkret_models_identity::AccountRegistrationVerificationPolicy {
                required: true,
                code_digest: Some(registration_secret_digest("246810")),
            },
            organization_allowlist: vec!["example.edu".to_owned()],
            invitation: arkret_models_identity::AccountRegistrationInvitationPolicy {
                required: true,
                token_digests: vec![registration_secret_digest("invite-token")],
            },
            ..arkret_models_identity::AccountRegistrationPolicy::default()
        };
    }

    let mut missing_code = TestClient::post("http://server/_soland/gate/account/project")
        .add_header(
            "authorization",
            format!("Bearer {ACCOUNT_REGISTER_BEARER}"),
            true,
        )
        .json(&serde_json::json!({
            "principal_id": fixture_actor_core_id("did:web:alice.example.edu"),
            "did": "did:web:alice.example.edu",
        }))
        .send(&app_from_state(state.clone()))
        .await;
    let status = missing_code.status_code.unwrap();
    let missing_code: Value = missing_code.take_json().await.unwrap();
    assert_eq!(status, StatusCode::CONFLICT, "{missing_code}");
    assert_eq!(missing_code["reason_detail"], "verification_code_required");

    let mut wrong_org = TestClient::post("http://server/_soland/gate/account/project")
        .add_header(
            "authorization",
            format!("Bearer {ACCOUNT_REGISTER_BEARER}"),
            true,
        )
        .json(&serde_json::json!({
            "principal_id": fixture_actor_core_id("did:web:bob.other.example"),
            "did": "did:web:bob.other.example",
            "policy_evidence": {
                "verification_code": "246810",
                "organization": "other.example",
                "invitation_token": "invite-token"
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;
    let wrong_org_status = wrong_org.status_code.unwrap();
    let wrong_org: Value = wrong_org.take_json().await.unwrap();
    assert_eq!(
        wrong_org_status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{wrong_org}"
    );
    assert_eq!(
        wrong_org["type"],
        "https://arkret.org/problems/schema_violation"
    );

    let rate_limited_state = soland_test_support::app_state(test_config());
    {
        let mut policy = rate_limited_state.test_account_registration_policy().lock();
        policy.rate_limit = Some(arkret_models_identity::AccountRegistrationRateLimitPolicy {
            max_attempts: 1,
            window_seconds: 60,
        });
    }
    let _: Value = TestClient::post("http://server/_soland/gate/account/project")
        .add_header(
            "authorization",
            format!("Bearer {ACCOUNT_REGISTER_BEARER}"),
            true,
        )
        .json(&serde_json::json!({
            "principal_id": fixture_actor_core_id("did:web:rate-register.example"),
            "did": "did:web:rate-register.example",
        }))
        .send(&app_from_state(rate_limited_state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let mut limited = TestClient::post("http://server/_soland/gate/account/project")
        .add_header(
            "authorization",
            format!("Bearer {ACCOUNT_REGISTER_BEARER}"),
            true,
        )
        .json(&serde_json::json!({
            "principal_id": fixture_actor_core_id("did:web:rate-register.example"),
            "did": "did:web:rate-register.example",
        }))
        .send(&app_from_state(rate_limited_state.clone()))
        .await;
    assert_eq!(limited.status_code.unwrap(), StatusCode::TOO_MANY_REQUESTS);
    let limited: Value = limited.take_json().await.unwrap();
    assert_eq!(limited["type"], "https://arkret.org/problems/rate_limited");
    assert_eq!(limited["reason_detail"], "rate_limited");
}

#[test]
fn dev_login_is_unavailable_in_production_mode() {
    run_on_deep_stack(
        "dev_login_is_unavailable_in_production_mode",
        dev_login_is_unavailable_in_production_mode_body,
    );
}

async fn dev_login_is_unavailable_in_production_mode_body() {
    let mut config = test_config();
    config.development_mode = false;
    let state = soland_test_support::app_state(config);

    let response = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&serde_json::json!({
            "actor": "did:web:alice.example",
            "device_id": "ak:device:01904100-0000-7000-8000-0a4a40000006"
        }))
        .send(&app_from_state(state))
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::NOT_FOUND);
}

#[test]
fn oversized_json_body_is_rejected_before_handler() {
    run_on_deep_stack(
        "oversized_json_body_is_rejected_before_handler",
        oversized_json_body_is_rejected_before_handler_body,
    );
}

async fn oversized_json_body_is_rejected_before_handler_body() {
    let state = soland_test_support::app_state(test_config());
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

#[test]
fn rate_limit_errors_use_problem_details_with_retry_after() {
    run_on_deep_stack(
        "rate_limit_errors_use_problem_details_with_retry_after",
        rate_limit_errors_use_problem_details_with_retry_after_body,
    );
}

async fn rate_limit_errors_use_problem_details_with_retry_after_body() {
    let state = soland_test_support::app_state(test_config());
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
    assert_eq!(problem_code(&limited), "rate_limited");
    assert!(limited["retry_after_ms"].as_u64().unwrap() > 0);
    assert!(
        limited["instance"]
            .as_str()
            .unwrap()
            .starts_with("ak:request:")
    );
}

#[test]
fn framework_errors_use_problem_details() {
    run_on_deep_stack(
        "framework_errors_use_problem_details",
        framework_errors_use_problem_details_body,
    );
}

async fn framework_errors_use_problem_details_body() {
    let not_found: Value = TestClient::get("http://server/_arkret/self/missing")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(problem_code(&not_found), "unrecognized_endpoint");

    let method_not_allowed: Value = TestClient::post("http://server/_arkret/describe")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(problem_code(&method_not_allowed), "method_not_allowed");
}

#[test]
fn protected_endpoints_reject_query_auth_material() {
    run_on_deep_stack(
        "protected_endpoints_reject_query_auth_material",
        protected_endpoints_reject_query_auth_material_body,
    );
}

async fn protected_endpoints_reject_query_auth_material_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let mut response = TestClient::get(format!(
        "http://server/_arkret/self/account/viewer?access_token={token}"
    ))
    .send(&app_from_state(state))
    .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::UNAUTHORIZED);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(problem_code(&body), "unauthenticated");
    assert_eq!(
        body["detail"],
        "auth material in query strings is not allowed"
    );
}

#[test]
fn hard_logout_removes_push_registration_and_to_device_queue_for_device() {
    run_on_deep_stack(
        "hard_logout_removes_push_registration_and_to_device_queue_for_device",
        hard_logout_removes_push_registration_and_to_device_queue_for_device_body,
    );
}

async fn hard_logout_removes_push_registration_and_to_device_queue_for_device_body() {
    let state = soland_test_support::app_state(test_config());
    let actor_did = "did:web:alice.example";
    let actor = "ak:did_core:web:alice.example";
    let device_a = "ak:device:01904100-0000-7000-8000-a11ce00000aa";
    let device_b = "ak:device:01904100-0000-7000-8000-a11ce00000bb";
    let token_a = dev_token_for_device(state.clone(), actor_did, device_a, "Alice Phone").await;
    let _token_b = dev_token_for_device(state.clone(), actor_did, device_b, "Alice Tablet").await;

    state
        .test_persistence()
        .push_devices()
        .register(serde_json::json!({
            "registration_id": "push:device-a-main",
            "actor": actor,
            "device_id": device_a,
            "push_gateway": "https://floria.example",
            "push_key": "push-key-a-main",
            "app_id": "inkson-main",
        }))
        .await
        .unwrap();
    state
        .test_persistence()
        .push_devices()
        .register(serde_json::json!({
            "registration_id": "push:device-a-voip",
            "actor": actor,
            "device_id": device_a,
            "push_gateway": "https://floria.example",
            "push_key": "push-key-a-voip",
            "app_id": "inkson-voip",
        }))
        .await
        .unwrap();
    state
        .test_persistence()
        .push_devices()
        .register(serde_json::json!({
            "registration_id": "push:device-b-main",
            "actor": actor,
            "device_id": device_b,
            "push_gateway": "https://floria.example",
            "push_key": "push-key-b-main",
            "app_id": "inkson-main",
        }))
        .await
        .unwrap();
    state
        .test_persistence()
        .device_messages()
        .append(
            None,
            DeviceMessageRecord {
                idempotency_key: "logout-device-a".to_owned(),
                sender: actor.to_owned(),
                recipient: actor.to_owned(),
                device_id: device_a.to_owned(),
                position: 1,
                content: serde_json::json!({"type": "ak.test.device_message"}),
                created_at: chrono::Utc::now(),
            },
        )
        .await
        .unwrap();
    state
        .test_persistence()
        .device_messages()
        .append(
            None,
            DeviceMessageRecord {
                idempotency_key: "logout-device-b".to_owned(),
                sender: actor.to_owned(),
                recipient: actor.to_owned(),
                device_id: device_b.to_owned(),
                position: 2,
                content: serde_json::json!({"type": "ak.test.device_message"}),
                created_at: chrono::Utc::now(),
            },
        )
        .await
        .unwrap();

    let device_b_messages_before_logout = state
        .test_persistence()
        .device_messages()
        .list_after(actor, device_b, 0)
        .await
        .unwrap();
    assert!(
        device_b_messages_before_logout
            .iter()
            .any(|message| message.idempotency_key == "logout-device-b"),
        "the control device queue must contain the test message before logout"
    );
    let push_devices_before_logout = state
        .test_persistence()
        .push_devices()
        .snapshot_all()
        .await
        .unwrap();
    let device_b_push_devices_before_logout = push_devices_before_logout
        .iter()
        .filter(|registration| registration["device_id"] == device_b)
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        device_b_push_devices_before_logout
            .iter()
            .any(|registration| registration["registration_id"] == "push:device-b-main"),
        "the control device must have the test push registration before logout"
    );

    let mut response = TestClient::post("http://server/_arkret/gate/account/logout")
        .add_header("authorization", format!("Bearer {token_a}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["revoked"], true);

    let push_devices = state
        .test_persistence()
        .push_devices()
        .snapshot_all()
        .await
        .unwrap();
    assert!(
        push_devices
            .iter()
            .all(|registration| registration["device_id"] != device_a),
        "hard logout must remove every push registration for the revoked device"
    );
    let device_b_push_devices = push_devices
        .iter()
        .filter(|registration| registration["device_id"] == device_b)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        device_b_push_devices, device_b_push_devices_before_logout,
        "hard logout must preserve every push registration for other devices"
    );
    let device_a_messages = state
        .test_persistence()
        .device_messages()
        .list_after(actor, device_a, 0)
        .await
        .unwrap();
    assert!(device_a_messages.is_empty());
    let device_b_messages = state
        .test_persistence()
        .device_messages()
        .list_after(actor, device_b, 0)
        .await
        .unwrap();
    assert_eq!(
        device_b_messages.len(),
        device_b_messages_before_logout.len(),
        "hard logout must preserve every queued message for other devices"
    );
    for (before, after) in device_b_messages_before_logout
        .iter()
        .zip(&device_b_messages)
    {
        assert_eq!(after.idempotency_key, before.idempotency_key);
        assert_eq!(after.sender, before.sender);
        assert_eq!(after.recipient, before.recipient);
        assert_eq!(after.device_id, before.device_id);
        assert_eq!(after.position, before.position);
        assert_eq!(after.content, before.content);
        assert_eq!(after.created_at, before.created_at);
    }
}

#[test]
fn postgres_startup_migrations_are_gated_by_database_url() {
    run_on_deep_stack(
        "postgres_startup_migrations_are_gated_by_database_url",
        postgres_startup_migrations_are_gated_by_database_url_body,
    );
}

async fn postgres_startup_migrations_are_gated_by_database_url_body() {
    if std::env::var("DATABASE_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
        .is_none()
    {
        return;
    }

    let db = Db::connect(
        std::env::var("DATABASE_URL").ok().as_deref(),
        Default::default(),
    )
    .await
    .expect("postgres migrations should run");
    let health: Value = TestClient::get("http://server/health")
        .send(&app_from_state(app_state_for_postgres(test_config(), db)))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(health["storage"], "postgres");
}
