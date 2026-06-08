//! Contract tests for spec-canonical contacts and direct conversation resolve.

use super::common::*;

const BOB_DID: &str = "did:web:bob.example";
const BOB_DEVICE: &str = "ck:device:01904100-0000-7000-8000-b0b0b0000002";

#[tokio::test]
async fn direct_resolve_fails_closed_without_accepted_contact() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = dev_token(state.clone()).await;
    let _bob = register_account(state.clone(), BOB_DID, "@bob", BOB_DEVICE).await;

    let mut response = TestClient::post("http://server/_cokret/self/direct-conversations/resolve")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({"peer": BOB_DID, "create": true}))
        .send(&app_from_state(state.clone()))
        .await;

    assert_eq!(response.status_code.unwrap().as_u16(), 412);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "contact_not_accepted");
}

#[tokio::test]
async fn direct_resolve_fails_closed_when_consent_missing() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = dev_token(state.clone()).await;
    let _bob = register_account(state.clone(), BOB_DID, "@bob", BOB_DEVICE).await;
    let now = chrono::Utc::now();
    state
        .persistence
        .contacts()
        .put(&soland::state::ContactRecord {
            requester: "did:web:alice.example".to_owned(),
            target: BOB_DID.to_owned(),
            scope: "message".to_owned(),
            status: "accepted".to_owned(),
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();

    let mut response = TestClient::post("http://server/_cokret/self/direct-conversations/resolve")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({"peer": BOB_DID, "create": true}))
        .send(&app_from_state(state.clone()))
        .await;

    assert_eq!(response.status_code.unwrap().as_u16(), 412);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "contact_consent_missing");
}

#[tokio::test]
async fn contacts_spec_path_projects_directional_scopes_and_resolve_is_idempotent() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = dev_token(state.clone()).await;
    let bob = register_account(state.clone(), BOB_DID, "@bob", BOB_DEVICE).await;

    let request: Value = TestClient::post("http://server/_cokret/self/contacts/request")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "target": BOB_DID,
            "requested_scopes": ["direct_message"]
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(request["state"], "pending_outgoing");
    let request_id = request["request_event_ref"].as_str().unwrap().to_owned();

    let accepted: Value = TestClient::post("http://server/_cokret/self/contacts/respond")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .json(&serde_json::json!({
            "request_id": request_id,
            "requester": "did:web:alice.example",
            "action": "accept",
            "granted_scopes": ["direct_message"]
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(accepted["state"], "accepted");

    let contacts: Value = TestClient::get("http://server/_cokret/self/contacts")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let row = &contacts["contacts"][0];
    assert_eq!(row["peer"], BOB_DID);
    assert_eq!(row["state"], "accepted");
    assert_eq!(row["granted_by_me"][0], "direct_message");
    assert_eq!(row["granted_to_me"][0], "direct_message");
    assert_eq!(row["bidirectional_scopes"][0], "direct_message");

    let not_found: Value =
        TestClient::post("http://server/_cokret/self/direct-conversations/resolve")
            .add_header("authorization", format!("Bearer {alice}"), true)
            .json(&serde_json::json!({"peer": BOB_DID, "create": false}))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(not_found["state"], "not_found", "body: {not_found}");
    assert!(not_found.get("reason_code").is_none(), "body: {not_found}");
    assert!(not_found.get("canonical").is_none(), "body: {not_found}");

    let created: Value =
        TestClient::post("http://server/_cokret/self/direct-conversations/resolve")
            .add_header("authorization", format!("Bearer {alice}"), true)
            .json(&serde_json::json!({"peer": BOB_DID, "create": true}))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(created["state"], "created");
    assert_eq!(created["created"], true);
    assert!(created.get("canonical").is_none(), "body: {created}");
    assert!(created.get("reason_code").is_none(), "body: {created}");
    assert!(
        created["realm_id"]
            .as_str()
            .unwrap()
            .starts_with("ck:realm:")
    );
    assert!(
        created["main_flow_id"]
            .as_str()
            .unwrap()
            .starts_with("ck:flow:")
    );

    let found: Value = TestClient::post("http://server/_cokret/self/direct-conversations/resolve")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .json(&serde_json::json!({"peer": "did:web:alice.example", "create": true}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(found["state"], "found");
    assert_eq!(found["realm_id"], created["realm_id"]);
    assert_eq!(found["main_flow_id"], created["main_flow_id"]);
}

#[tokio::test]
async fn concurrent_direct_resolve_create_converges_to_one_binding() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = dev_token(state.clone()).await;
    let bob = register_account(state.clone(), BOB_DID, "@bob", BOB_DEVICE).await;

    let request: Value = TestClient::post("http://server/_cokret/self/contacts/request")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "target": BOB_DID,
            "requested_scopes": ["direct_message"]
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let request_id = request["request_event_ref"].as_str().unwrap().to_owned();
    TestClient::post("http://server/_cokret/self/contacts/respond")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .json(&serde_json::json!({
            "request_id": request_id,
            "requester": "did:web:alice.example",
            "action": "accept",
            "granted_scopes": ["direct_message"]
        }))
        .send(&app_from_state(state.clone()))
        .await;

    let state_a = state.clone();
    let state_b = state.clone();
    let alice_a = alice.clone();
    let alice_b = alice.clone();
    let create_a = async move {
        TestClient::post("http://server/_cokret/self/direct-conversations/resolve")
            .add_header("authorization", format!("Bearer {alice_a}"), true)
            .json(&serde_json::json!({
                "peer": BOB_DID,
                "create": true,
                "idempotency_key": "direct-concurrent-a"
            }))
            .send(&app_from_state(state_a))
            .await
            .take_json()
            .await
            .unwrap()
    };
    let create_b = async move {
        TestClient::post("http://server/_cokret/self/direct-conversations/resolve")
            .add_header("authorization", format!("Bearer {alice_b}"), true)
            .json(&serde_json::json!({
                "peer": BOB_DID,
                "create": true,
                "idempotency_key": "direct-concurrent-b"
            }))
            .send(&app_from_state(state_b))
            .await
            .take_json()
            .await
            .unwrap()
    };

    let (first, second): (Value, Value) = tokio::join!(create_a, create_b);
    assert_eq!(first["realm_id"], second["realm_id"]);
    assert_eq!(first["main_flow_id"], second["main_flow_id"]);
    assert_eq!(first["binding_event_ref"], second["binding_event_ref"]);
    assert_eq!(
        [
            first["created"].as_bool().unwrap(),
            second["created"].as_bool().unwrap()
        ]
        .into_iter()
        .filter(|created| *created)
        .count(),
        1,
        "exactly one concurrent request should create the binding: {first} {second}"
    );
    assert_eq!(
        state
            .direct_conversation_bindings
            .lock()
            .expect("direct_conversation_bindings lock")
            .len(),
        1
    );
}
