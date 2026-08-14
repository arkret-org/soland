//! Integration tests — `policy_snapshot` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

use super::common::*;

#[tokio::test]
async fn policy_check_and_validation_work() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let actor_id = fixture_actor_core_id("did:web:alice.example");
    let source_service_id = state.service_id().to_owned();

    let policy: Value = TestClient::post("http://server/_arkret/self/policy/check")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "request_id": "req1",
            "realm_id": DEMO_REALM_ID,
            "request_canonical_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "action": "message.send",
            "actor_id": actor_id,
            "source": {
                "service_id": source_service_id,
                "service_kind": "soland",
                "signed_transport": true
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    // service-operation-dtos.schema.json#PolicyCheckOutcome (Round 4): the
    // response carries a signed `bound_to` request transcript, not a
    // `decision_trace`. No owner policy document matches yet → fail-closed
    // default decision.
    assert_eq!(policy["decision"], "require_review");
    assert_eq!(policy["request_id"], "req1");
    assert_eq!(policy["bound_to"]["actor_id"], actor_id.as_str());
    assert_eq!(policy["bound_to"]["action"], "message.send");
    assert_eq!(policy["bound_to"]["realm_id"], DEMO_REALM_ID);

    let unauthenticated_policy = TestClient::post("http://server/_soland/self/policies")
        .json(&serde_json::json!({
            "scope": DEMO_REALM_ID,
            "subject_ref": "did:web:alice.example",
            "policy_kind": "message.send",
            "effect": "hard_deny"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        unauthenticated_policy.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );

    let policy_document: Value = TestClient::post("http://server/_soland/self/policies")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "scope": DEMO_REALM_ID,
            "subject_ref": "did:web:alice.example",
            "policy_kind": "message.send",
            "effect": "hard_deny",
            "actions": ["message.send"],
            // policy_resource_matches compares `resource.kind` against the
            // request `source.service_kind`; scope by `realm_id` only so the
            // realm-scoped policy matches the message.send check below.
            "resource": {"realm_id": DEMO_REALM_ID},
            "obligations": [{"type": "audit", "level": "high"}]
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let policy_id = policy_document["policy_id"].as_str().unwrap().to_owned();
    assert_eq!(policy_document["payload"]["effect"], "hard_deny");

    let policies: Value = TestClient::get("http://server/_soland/self/policies")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(policies["policies"].as_array().unwrap().len(), 1);

    let denied: Value = TestClient::post("http://server/_arkret/self/policy/check")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "request_id": "req2",
            "realm_id": DEMO_REALM_ID,
            "request_canonical_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "action": "message.send",
            "actor_id": actor_id,
            "source": {
                "service_id": source_service_id,
                "service_kind": "soland",
                "signed_transport": true
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    // PolicyCheckOutcome (Round 4): decision + reason_code + obligations +
    // bound_to transcript; the matched policy id is not echoed.
    assert_eq!(denied["decision"], "hard_deny");
    assert_eq!(denied["reason_code"], "policy_denied");
    assert_eq!(denied["bound_to"]["actor_id"], actor_id.as_str());
    assert_eq!(denied["bound_to"]["action"], "message.send");
    assert_eq!(denied["obligations"][0]["type"], "audit");

    let deleted: Value =
        TestClient::delete(format!("http://server/_soland/self/policies/{policy_id}"))
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(deleted["ok"], true);

    let after_delete: Value = TestClient::post("http://server/_arkret/self/policy/check")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "request_id": "req3",
            "realm_id": DEMO_REALM_ID,
            "request_canonical_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "action": "message.send",
            "actor_id": actor_id,
            "source": {
                "service_id": source_service_id,
                "service_kind": "soland",
                "signed_transport": true
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    // Policy removed → back to the fail-closed default.
    assert_eq!(after_delete["decision"], "require_review");

    let invalid = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&serde_json::json!({
            "actor": "alice",
            "device_id": "bad-device"
        }))
        .send(&app())
        .await;
    assert_eq!(invalid.status_code.unwrap().as_u16(), 400);
}
