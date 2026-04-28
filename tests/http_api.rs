use salvo::test::{ResponseExt, TestClient};
use serde_json::Value;
use serverx::{db::Db, service, state::AppState};

use chrono::Utc;
use contrix_sdk::{Commit, CommitId, Did, Hash, Operation, OperationId, Proof, SpaceId};

fn app() -> salvo::Service {
    service(AppState::new(Db { pool: None }))
}

fn app_from_state(state: AppState) -> salvo::Service {
    service(state)
}

async fn dev_token(state: AppState) -> String {
    let login: Value = TestClient::post("http://server/api/v1/auth/dev-login")
        .json(&serde_json::json!({
            "actor": "did:web:alice.example",
            "device_id": "dev_alice",
            "display_name": "Alice Desktop"
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    login["access_token"].as_str().unwrap().to_owned()
}

async fn register_account(state: AppState, did: &str, handle: &str, device_id: &str) -> String {
    let registered: Value = TestClient::post("http://server/api/v1/account/register")
        .json(&serde_json::json!({
            "did": did,
            "handle": handle,
            "display_name": handle.trim_start_matches('@'),
            "device_id": device_id
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(registered["did"], did);

    let login: Value = TestClient::post("http://server/api/v1/auth/dev-login")
        .json(&serde_json::json!({
            "actor": did,
            "device_id": device_id,
            "display_name": handle.trim_start_matches('@')
        }))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    login["access_token"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn health_and_describe_work() {
    let health: Value = TestClient::get("http://server/health")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(health["ok"], true);

    let describe: Value = TestClient::get("http://server/api/v1/server/describe")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(describe["protocol_version"], "1.0");
    assert_eq!(describe["service_type"], "principal_server");
}

#[tokio::test]
async fn account_contacts_and_space_lifecycle_workflow() {
    let state = AppState::new(Db { pool: None });
    let alice = dev_token(state.clone()).await;
    let bob = register_account(state.clone(), "did:web:bob.example", "@bob", "dev_bob").await;

    let duplicate = TestClient::post("http://server/api/v1/account/register")
        .json(&serde_json::json!({
            "did": "did:web:bob.example",
            "handle": "@bob",
            "device_id": "dev_bob2"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(duplicate.status_code.unwrap().as_u16(), 409);

    let hidden_bob: Value = TestClient::get("http://server/api/v1/directory/search-users?q=bob")
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(hidden_bob["results"].as_array().unwrap().is_empty());

    let me: Value = TestClient::get("http://server/api/v1/account/me")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(me["did"], "did:web:bob.example");

    let contact_request: Value = TestClient::post("http://server/api/v1/contacts/request")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({"target": "did:web:bob.example"}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(contact_request["status"], "pending");

    let accepted: Value = TestClient::post("http://server/api/v1/contacts/respond")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .json(&serde_json::json!({
            "requester": "did:web:alice.example",
            "action": "accept"
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(accepted["status"], "accepted");

    let bob_contacts: Value = TestClient::get("http://server/api/v1/contacts")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(bob_contacts["contacts"].as_array().unwrap().len(), 1);

    let visible_bob: Value = TestClient::get("http://server/api/v1/directory/search-users?q=bob")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(visible_bob["results"][0]["did"], "did:web:bob.example");

    let created_space: Value = TestClient::post("http://server/api/v1/spaces")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "title": "Workflow Space",
            "summary": "created by lifecycle workflow",
            "public": true
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let space_id = created_space["space_id"].as_str().unwrap().to_owned();
    assert_eq!(created_space["owner"], "did:web:alice.example");

    let with_bob: Value =
        TestClient::post(format!("http://server/api/v1/spaces/{space_id}/members"))
            .add_header("authorization", format!("Bearer {alice}"), true)
            .json(&serde_json::json!({"member": "did:web:bob.example"}))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert!(
        with_bob["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|member| member == "did:web:bob.example")
    );

    let sent_message: Value = TestClient::post("http://server/api/v1/messages/send")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "space_id": space_id,
            "thread_id": "cx:thread:workflow",
            "content": {"body": "hello workflow"},
            "encrypted": false
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        sent_message["operation_id"]
            .as_str()
            .unwrap()
            .starts_with("cx:operation:")
    );

    let thread: Value =
        TestClient::get("http://server/api/v1/index/thread?thread_id=cx:thread:workflow")
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(thread["events"][0]["content"]["body"], "hello workflow");

    let message_search: Value = TestClient::post("http://server/api/v1/index/search")
        .json(&serde_json::json!({
            "query": "workflow",
            "space_ids": [space_id],
            "entity_types": ["message"]
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        message_search["results"][0]["event_id"],
        sent_message["event_id"]
    );

    let notifications: Value =
        TestClient::get("http://server/api/v1/index/notifications?actor=did:web:bob.example")
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(notifications["unread_count"], 1);
    assert_eq!(
        notifications["notifications"][0]["event_ref"],
        sent_message["event_id"]
    );

    let sync_with_message: Value = TestClient::post("http://server/api/v1/sync")
        .json(&serde_json::json!({}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        sync_with_message["spaces"][&space_id]["timeline"]["events"][0]["event_id"],
        sent_message["event_id"]
    );

    let snapshot: Value = TestClient::get(format!(
        "http://server/api/v1/sync/snapshot-head?space_id={space_id}"
    ))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(snapshot["frontier"]["message_count"], 1);
    assert!(
        snapshot["snapshot_ref"]
            .as_str()
            .unwrap()
            .starts_with("cx:snapshot:")
    );
    assert!(!snapshot["signature"]["sig"].as_str().unwrap().is_empty());

    let kicked: Value = TestClient::delete(format!(
        "http://server/api/v1/spaces/{space_id}/members/did:web:bob.example"
    ))
    .add_header("authorization", format!("Bearer {alice}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert!(
        !kicked["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|member| member == "did:web:bob.example")
    );

    let deleted: Value = TestClient::delete(format!("http://server/api/v1/spaces/{space_id}"))
        .add_header("authorization", format!("Bearer {alice}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(deleted["deleted"], true);

    let directory: Value = TestClient::post("http://server/api/v1/directory/search-spaces")
        .json(&serde_json::json!({"query": "Workflow Space"}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(directory["results"].as_array().unwrap().is_empty());

    let index: Value = TestClient::post("http://server/api/v1/index/query")
        .json(&serde_json::json!({"space_ids": [space_id]}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(index["results"].as_array().unwrap().is_empty());

    let sync: Value = TestClient::post("http://server/api/v1/sync")
        .json(&serde_json::json!({}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(!sync["spaces"].as_object().unwrap().contains_key(&space_id));

    let logout: Value = TestClient::post("http://server/api/v1/auth/logout")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(logout["revoked"], true);
    let revoked_me = TestClient::get("http://server/api/v1/account/me")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(revoked_me.status_code.unwrap().as_u16(), 401);
}

#[tokio::test]
async fn framework_errors_use_contrix_error_envelope() {
    let not_found: Value = TestClient::get("http://server/api/v1/missing")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(not_found["ok"], false);
    assert_eq!(not_found["error"]["errcode"], "not_found");

    let method_not_allowed: Value = TestClient::post("http://server/api/v1/server/describe")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(method_not_allowed["ok"], false);
    assert_eq!(method_not_allowed["error"]["errcode"], "method_not_allowed");
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

    let db = Db::from_env().expect("postgres migrations should run");
    let health: Value = TestClient::get("http://server/health")
        .send(&app_from_state(AppState::new(db)))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(health["storage"], "postgres");
}

#[tokio::test]
async fn identity_surface_works() {
    let describe: Value = TestClient::get("http://server/api/v1/identity/describe")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(describe["protocol_version"], "1.0");

    let resolved: Value = TestClient::post("http://server/api/v1/identity/resolve")
        .json(&serde_json::json!({"did": "did:web:alice.example"}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resolved["did_document"]["id"], "did:web:alice.example");

    let document: Value =
        TestClient::get("http://server/api/v1/identity/document?did=did:web:alice.example")
            .send(&app())
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(document["did_document"]["id"], "did:web:alice.example");

    let log: Value = TestClient::get("http://server/api/v1/identity/log?did=did:web:alice.example")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(log["has_more"], false);

    let submitted: Value = TestClient::post("http://server/api/v1/identity/submit-did-operation")
        .json(&serde_json::json!({
            "did": "did:web:alice.example",
            "seq": 1,
            "patch": {"service": []},
            "proofs": [{"kid": "did:web:alice.example#key-1", "sig": "dev"}]
        }))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(submitted["status"], "accepted");

    let receipts: Value =
        TestClient::get("http://server/api/v1/identity/receipts?did=did:web:alice.example")
            .send(&app())
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(receipts["threshold_met"], true);
}

#[tokio::test]
async fn sync_directory_and_index_share_demo_space() {
    let sync: Value = TestClient::post("http://server/api/v1/sync")
        .json(&serde_json::json!({}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        sync["spaces"]
            .as_object()
            .unwrap()
            .contains_key("cx:space:01js0sp0000000000000000000")
    );

    let directory: Value = TestClient::post("http://server/api/v1/directory/search-spaces")
        .json(&serde_json::json!({"query": "demo", "limit": 10}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(directory["results"].as_array().unwrap().len(), 1);

    let index: Value = TestClient::post("http://server/api/v1/index/query")
        .json(&serde_json::json!({"space_ids": ["cx:space:01js0sp0000000000000000000"]}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(index["results"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn directory_product_endpoints_return_demo_projection_shapes() {
    let organizations: Value =
        TestClient::post("http://server/api/v1/directory/search-organizations")
            .json(&serde_json::json!({"query": "contrix", "limit": 10}))
            .send(&app())
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(
        organizations["results"][0]["organization_id"],
        "cx:org:demo"
    );

    let organization: Value =
        TestClient::post("http://server/api/v1/directory/resolve-organization")
            .json(&serde_json::json!({"organization_id": "cx:org:demo"}))
            .send(&app())
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(organization["organization"]["handle"], "@contrix-demo");
    assert_eq!(organization["spaces"].as_array().unwrap().len(), 1);

    let actors: Value = TestClient::post("http://server/api/v1/directory/search-actors")
        .json(&serde_json::json!({"query": "alice"}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(actors["results"][0]["did"], "did:web:alice.example");

    let users: Value = TestClient::get("http://server/api/v1/directory/search-users?q=alice")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(users["results"][0]["handle"], "@alice");

    let handle: Value = TestClient::post("http://server/api/v1/directory/resolve-handle")
        .json(&serde_json::json!({"handle": "alice"}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(handle["did"], "did:web:alice.example");

    let invalid = TestClient::get("http://server/api/v1/directory/search-users?limit=0")
        .send(&app())
        .await;
    assert_eq!(invalid.status_code.unwrap().as_u16(), 400);
}

#[tokio::test]
async fn index_product_endpoints_return_demo_projection_shapes() {
    let entity: Value = TestClient::get(
        "http://server/api/v1/index/entity?entity_id=cx:space:01js0sp0000000000000000000",
    )
    .send(&app())
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(entity["entity"]["kind"], "space");

    let thread: Value =
        TestClient::get("http://server/api/v1/index/thread?thread_id=cx:thread:demo")
            .send(&app())
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(thread["thread"]["thread_id"], "cx:thread:demo");
    assert!(thread["events"].as_array().unwrap().is_empty());

    let notifications: Value =
        TestClient::get("http://server/api/v1/index/notifications?actor=did:web:alice.example")
            .send(&app())
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(notifications["unread_count"], 0);

    let inbox: Value = TestClient::get("http://server/api/v1/index/inbox")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(inbox["rooms"].as_array().unwrap().len(), 1);

    let search: Value = TestClient::post("http://server/api/v1/index/search")
        .json(&serde_json::json!({"query": "demo", "entity_types": ["space"], "limit": 5}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(search["results"].as_array().unwrap().len(), 1);

    let hierarchy: Value = TestClient::get(
        "http://server/api/v1/index/space-hierarchy?root_space_id=cx:space:01js0sp0000000000000000000",
    )
    .send(&app())
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        hierarchy["root_space_id"],
        "cx:space:01js0sp0000000000000000000"
    );

    let invalid = TestClient::post("http://server/api/v1/index/search")
        .json(&serde_json::json!({"query": ""}))
        .send(&app())
        .await;
    assert_eq!(invalid.status_code.unwrap().as_u16(), 400);
}

#[tokio::test]
async fn broader_protocol_surface_returns_contract_shapes() {
    let directory_describe: Value = TestClient::get("http://server/api/v1/directory/describe")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(directory_describe["service_did"], "did:web:serverx.local");

    let resolved: Value = TestClient::post("http://server/api/v1/directory/resolve-space")
        .json(&serde_json::json!({"space_id": "cx:space:01js0sp0000000000000000000"}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        resolved["space_preview"]["space_id"],
        "cx:space:01js0sp0000000000000000000"
    );

    let backfill: Value = TestClient::get(
        "http://server/api/v1/sync/backfill?space_id=cx:space:01js0sp0000000000000000000",
    )
    .send(&app())
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(backfill["limited"], false);

    let repo: Value = TestClient::get("http://server/api/v1/repo/describe")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert!(repo["supported_signatures"].as_array().unwrap().len() >= 1);

    let operations: Value = TestClient::post("http://server/api/v1/repo/operations")
        .json(&serde_json::json!({"operation_ids": []}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(operations["missing"].as_array().unwrap().len(), 0);

    let authz: Value = TestClient::post("http://server/api/v1/authz/check")
        .json(&serde_json::json!({
            "actor": "did:web:alice.example",
            "action": "space.read",
            "resource": {"kind": "space", "space_id": "cx:space:01js0sp0000000000000000000"}
        }))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(authz["allowed"], true);
}

#[tokio::test]
async fn push_profile_and_moderation_contracts_work() {
    let state = AppState::new(Db { pool: None });
    let token = dev_token(state.clone()).await;
    let profile: Value =
        TestClient::get("http://server/api/v1/profile/presence?did=did:web:alice.example")
            .send(&app())
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(profile["actor"], "did:web:alice.example");

    let push: Value = TestClient::post("http://server/api/v1/push/register-device")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "device_id": "dev_alice",
            "push_gateway": "https://push.example",
            "push_key": "opaque",
            "platform": "desktop",
            "app_id": "clientx"
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(push["ok"], true);

    let report: Value = TestClient::post("http://server/api/v1/moderation/report")
        .json(&serde_json::json!({
            "space_id": "cx:space:01js0sp0000000000000000000",
            "target_ref": "cx:event:demo",
            "reason": "spam",
            "reporter": "did:web:alice.example"
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(report["status"], "queued");
}

#[tokio::test]
async fn auth_keys_device_messages_and_blobs_work() {
    let state = AppState::new(Db { pool: None });
    let token = dev_token(state.clone()).await;

    let upload: Value = TestClient::post("http://server/api/v1/keys/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "device_id": "dev_alice",
            "device_keys": {"alg": "mls-rfc9420", "key": "alice-device-key"},
            "one_time_keys": [{"key_id": "otk1", "key": "one-time"}],
            "fallback_keys": {"signed_curve25519:fallback": {"key": "fallback-key"}},
            "mls_key_packages": [{"package_id": "mls-package-1", "key": "opaque-package"}],
            "device_signature": {"alg": "none"}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(upload["one_time_key_counts"]["signed_curve25519"], 1);

    let query: Value = TestClient::post("http://server/api/v1/keys/query")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "device_keys": {"did:web:alice.example": ["dev_alice"]}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(query["device_keys"].is_object());
    assert_eq!(
        query["device_keys"]["did:web:alice.example"]["dev_alice"]["device_keys"]["key"],
        "alice-device-key"
    );
    assert_eq!(
        query["device_keys"]["did:web:alice.example"]["dev_alice"]["device_signature"]["alg"],
        "none"
    );
    assert_eq!(
        query["device_keys"]["did:web:alice.example"]["dev_alice"]["fallback_keys"]["signed_curve25519:fallback"]
            ["key"],
        "fallback-key"
    );
    assert_eq!(
        query["device_keys"]["did:web:alice.example"]["dev_alice"]["mls_key_packages"][0]["package_id"],
        "mls-package-1"
    );

    let send: Value = TestClient::put("http://server/api/v1/device_messages/txn1")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "messages": {
                "did:web:alice.example": {
                    "dev_alice": {
                        "type": "cx.mls.welcome",
                        "content": {"ciphertext": "opaque"}
                    }
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(send["ok"], true);

    let duplicate: Value = TestClient::put("http://server/api/v1/device_messages/txn1")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "messages": {
                "did:web:alice.example": {
                    "dev_alice": {
                        "type": "cx.mls.welcome",
                        "content": {"ciphertext": "opaque"}
                    }
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(duplicate["delivered"].as_object().unwrap().len(), 0);

    let bad_blob = TestClient::post("http://server/api/v1/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("x-contrix-sha256", "sha256:deadbeef", true)
        .body("encrypted-bytes")
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(bad_blob.status_code.unwrap().as_u16(), 409);

    let blob: Value = TestClient::post("http://server/api/v1/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "text/plain", true)
        .body("encrypted-bytes")
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(blob["size"], 15);
    assert!(
        blob["blob_ref"]
            .as_str()
            .unwrap()
            .starts_with("cx:blob:sha256:")
    );

    let body = TestClient::get(format!(
        "http://server/api/v1/blob/get?blob_ref={}",
        blob["blob_ref"].as_str().unwrap()
    ))
    .send(&app_from_state(state.clone()))
    .await
    .take_string()
    .await
    .unwrap();
    assert_eq!(body, "encrypted-bytes");

    let mut range = TestClient::get(format!(
        "http://server/api/v1/blob/get?blob_ref={}",
        blob["blob_ref"].as_str().unwrap()
    ))
    .add_header("range", "bytes=0-8", true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(range.status_code.unwrap().as_u16(), 206);
    assert_eq!(range.take_string().await.unwrap(), "encrypted");

    let push_registration: Value = TestClient::post("http://server/api/v1/push/register-device")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "device_id": "dev_alice",
            "push_gateway": "https://push.example",
            "push_key": "opaque",
            "platform": "desktop",
            "app_id": "clientx"
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(push_registration["ok"], true);

    let notify: Value = TestClient::post("http://server/api/v1/push/notify")
        .json(&serde_json::json!({
            "notification": {
                "type": "blind_wakeup",
                "devices": [{"device_id": "dev_alice"}, {"device_id": "dev_missing"}]
            }
        }))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(notify["rejected"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn server_preserves_e2ee_payloads_as_opaque_data() {
    let state = AppState::new(Db { pool: None });
    let token = dev_token(state.clone()).await;
    let ciphertext = "base64url-opaque-ciphertext";

    TestClient::put("http://server/api/v1/device_messages/e2ee-txn")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "messages": {
                "did:web:alice.example": {
                    "dev_alice": {
                        "type": "cx.mls.application",
                        "content": {
                            "algorithm": "mls-rfc9420",
                            "ciphertext": ciphertext,
                            "sender_key_id": "did:web:alice.example#device"
                        }
                    }
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;

    let delivered: Value = TestClient::get("http://server/api/v1/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    let content = &delivered["events"][0]["content"]["content"];
    assert_eq!(content["ciphertext"], ciphertext);
    assert!(content.get("plaintext").is_none());
}

#[tokio::test]
async fn policy_check_and_validation_work() {
    let policy: Value = TestClient::post("http://server/contrix/v1/check")
        .json(&serde_json::json!({
            "request_id": "req1",
            "space_id": "cx:space:01js0sp0000000000000000000",
            "request_canonical_hash": "sha256:test",
            "action": "message.send",
            "actor": "did:web:alice.example",
            "source": {"service": "serverx"}
        }))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(policy["decision"], "allow");

    let invalid = TestClient::post("http://server/api/v1/auth/dev-login")
        .json(&serde_json::json!({
            "actor": "alice",
            "device_id": "bad-device"
        }))
        .send(&app())
        .await;
    assert_eq!(invalid.status_code.unwrap().as_u16(), 400);
}

#[tokio::test]
async fn repo_submit_rejects_unsigned_commits() {
    let response = TestClient::post("http://server/api/v1/repo/submit-commit")
        .json(&serde_json::json!({
            "repo_id": "did:web:alice.example",
            "expected_head": null,
            "commit": {
                "schema": "cx.schema.commit.v1",
                "commit_id": "cx:commit:01",
                "type": "commit",
                "repo_id": "did:web:alice.example",
                "author": "did:web:alice.example",
                "author_seq": 1,
                "operations": [],
                "created_at": "2026-04-28T00:00:00Z",
                "proofs": []
            }
        }))
        .send(&app())
        .await;
    assert_eq!(response.status_code.unwrap().as_u16(), 409);
}

#[tokio::test]
async fn repo_adapter_memory_submit_list_get_and_sync_work() {
    let state = AppState::new(Db { pool: None });
    let operation = Operation::create(
        OperationId::new("cx:operation:adapter-01").unwrap(),
        SpaceId::new("cx:space:adapter").unwrap(),
        "message",
        serde_json::json!({"body": "hello"}),
    );
    let operation_digest = Hash::new(operation.operation_digest().unwrap()).unwrap();

    let mut commit = Commit::new(
        CommitId::new("cx:commit:adapter-01").unwrap(),
        "did:web:alice.example",
        Did::new("did:web:alice.example").unwrap(),
        1,
    );
    commit.operations.push(operation_digest);
    commit.proofs.push(dummy_proof());
    let commit_digest = commit.commit_digest().unwrap();

    let submit: Value = TestClient::post("http://server/api/v1/repo/submit-commit")
        .json(&serde_json::json!({
            "repo_id": "did:web:alice.example",
            "expected_head": null,
            "operations": [operation],
            "commit": commit
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(submit["status"], "accepted");
    assert_eq!(submit["head_commit"], commit_digest);

    let describe: Value =
        TestClient::get("http://server/api/v1/repo/describe?repo_id=did:web:alice.example")
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(describe["head_commit"], commit_digest);

    let other_repo: Value =
        TestClient::get("http://server/api/v1/repo/describe?repo_id=did:web:bob.example")
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert!(other_repo["head_commit"].is_null());

    let commits: Value =
        TestClient::get("http://server/api/v1/repo/commits?repo_id=did:web:alice.example&limit=1")
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(commits["commits"].as_array().unwrap().len(), 1);

    let commit: Value =
        TestClient::get("http://server/api/v1/repo/commit?commit_id=cx:commit:adapter-01")
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(commit["commit"]["commit_id"], "cx:commit:adapter-01");
    assert!(commit["operations"].as_array().unwrap().is_empty());

    let expanded_commit: Value = TestClient::get(
        "http://server/api/v1/repo/commit?commit_id=cx:commit:adapter-01&include_operations=true",
    )
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        expanded_commit["operations"][0]["operation_id"],
        "cx:operation:adapter-01"
    );

    let operations: Value = TestClient::post("http://server/api/v1/repo/operations")
        .json(&serde_json::json!({"operation_ids": ["cx:operation:adapter-01"]}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(operations["operations"].as_array().unwrap().len(), 1);
    assert_eq!(operations["missing"].as_array().unwrap().len(), 0);

    let sync: Value = TestClient::post("http://server/api/v1/repo/sync")
        .json(&serde_json::json!({"repo_id": "did:web:alice.example", "limit": 1}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(sync["operations"].as_array().unwrap().len(), 1);

    let backfill: Value =
        TestClient::get("http://server/api/v1/sync/backfill?space_id=cx:space:adapter&limit=1")
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(backfill["events"][0]["event_id"], "cx:operation:adapter-01");
    assert_eq!(backfill["limited"], false);

    let subscribe: Value =
        TestClient::get("http://server/api/v1/sync/subscribe?space_id=cx:space:adapter&limit=1")
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(
        subscribe["frames"][0]["payload"]["operation_id"],
        "cx:operation:adapter-01"
    );

    let mut stale_commit = Commit::new(
        CommitId::new("cx:commit:adapter-02").unwrap(),
        "did:web:alice.example",
        Did::new("did:web:alice.example").unwrap(),
        2,
    );
    stale_commit.proofs.push(dummy_proof());
    let stale = TestClient::post("http://server/api/v1/repo/submit-commit")
        .json(&serde_json::json!({
            "repo_id": "did:web:alice.example",
            "expected_head": null,
            "commit": stale_commit
        }))
        .send(&app_from_state(state))
        .await;
    assert_eq!(stale.status_code.unwrap().as_u16(), 409);

    let bad_operation = Operation::create(
        OperationId::new("cx:operation:adapter-bad").unwrap(),
        SpaceId::new("cx:space:adapter").unwrap(),
        "unknown.family",
        serde_json::json!({"body": "bad"}),
    );
    let mut bad_commit = Commit::new(
        CommitId::new("cx:commit:adapter-bad").unwrap(),
        "did:web:alice.example",
        Did::new("did:web:alice.example").unwrap(),
        2,
    );
    bad_commit.proofs.push(dummy_proof());
    let invalid = TestClient::post("http://server/api/v1/repo/submit-commit")
        .json(&serde_json::json!({
            "repo_id": "did:web:alice.example",
            "expected_head": commit_digest,
            "operations": [bad_operation],
            "commit": bad_commit
        }))
        .send(&app_from_state(state))
        .await;
    assert_eq!(invalid.status_code.unwrap().as_u16(), 400);
}

fn dummy_proof() -> Proof {
    Proof {
        kind: "detached_jws".to_owned(),
        alg: "none".to_owned(),
        verification_method: "did:web:alice.example#dev".to_owned(),
        payload_hash: Hash::new(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap(),
        created_at: Utc::now(),
        domain: None,
        audience: None,
        jws: "dev-proof".to_owned(),
    }
}
