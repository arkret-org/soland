//! G3.S5 — HTTP integration tests for the realm-links surface:
//!
//! - `POST /_arkret/self/realms/{realm_id}/links` — create / status-flip a `ak.realm.link`.
//! - `DELETE /_arkret/self/realms/{realm_id}/links/{target_realm_id}` — tombstone an existing link.
//! - `GET /_arkret/self/realms/{realm_id}/effective-policy` — read the merged effective policy
//!   (walks the inheritance chain).
//! - General directed cycles are accepted; self-links and illegal FSM transitions are rejected.

use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use soland::config::AppConfig;
use soland::service;
use soland::state::AppState;
use soland_storage_postgres::Db;

fn test_config() -> AppConfig {
    AppConfig {
        development_mode: true,
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: std::collections::BTreeMap::new(),
        seed_demo_data: true,
        ..soland_test_support::app_config()
    }
}

fn app() -> salvo::Service {
    service(AppState::new(test_config(), Db { pool: None }))
}

async fn dev_token(svc: &salvo::Service) -> String {
    let login: Value = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&json!({
            "actor": "did:web:alice.example",
            "device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001",
            "display_name": "Alice Desktop"
        }))
        .send(svc)
        .await
        .take_json()
        .await
        .unwrap();
    login["session_credential"].as_str().unwrap().to_owned()
}

const REALM_A: &str = "ak:realm:01904100-0000-7000-8000-aaaaaaaaaaa1";
const REALM_B: &str = "ak:realm:01904100-0000-7000-8000-bbbbbbbbbbb2";
const REALM_C: &str = "ak:realm:01904100-0000-7000-8000-ccccccccccc3";
const REALM_D: &str = "ak:realm:01904100-0000-7000-8000-ddddddddddd4";

/// Submit a `ak.realm.inheritance_policy` event directly through the
/// reducer (the dedicated HTTP route is the standard `/_arkret/self/events`
/// envelope path; for setup we bypass it by injecting an Operation
/// into the projection).
fn project_inheritance_policy(
    state: &AppState,
    realm_id: &str,
    source_realm_id: &str,
    allowed_policies: &[&str],
) {
    use arkret_core::{Operation, OperationId, RealmId};
    let op = Operation::create(
        OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7())).unwrap(),
        RealmId::new(realm_id).unwrap(),
        arkret_core::events::EventKind::REALM_INHERITANCE_POLICY,
        json!({
            "source_realm_id": source_realm_id,
            "allowed_policies": allowed_policies,
            "max_depth": 1,
        }),
    );
    let mut proj = state.test_projection().lock();
    proj.apply(&op, &state.test_hlc());
}

/// G3.S5 — happy path: POST a `governed_by` link from B → A, GET the
/// effective policy on B (after an explicit `ak.realm.inheritance_policy`
/// opt-in) and assert the chain walked back to A.
#[tokio::test]
async fn realm_links_post_parent_then_effective_policy_walks_chain() {
    let state = AppState::new(test_config(), Db { pool: None });
    let svc = service(state.clone());
    let token = dev_token(&svc).await;

    // 1. POST B → A (`governed_by`, active). HTTP 200, body echoes the projected status.
    let body: Value =
        TestClient::post(format!("http://server/_arkret/self/realms/{REALM_B}/links"))
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&json!({
                "target_realm_id": REALM_A,
                "link_kind": "governed_by",
                "status": "active",
            }))
            .send(&svc)
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(body["realm_id"], REALM_B);
    assert_eq!(body["target_realm_id"], REALM_A);
    assert_eq!(body["status"], "active");

    // 2. Explicit inheritance opt-in on B (spec §6.1 — a link alone doesn't enable inheritance).
    project_inheritance_policy(&state, REALM_B, REALM_A, &["b.policy"]);
    project_inheritance_policy(&state, REALM_A, REALM_A, &["a.policy"]);

    // 3. GET effective-policy on B. Body shape pinned by the task spec: `{realm_id,
    //    effective_policy, inheritance_chain, inheritance_mode}`.
    let ep: Value = TestClient::get(format!(
        "http://server/_arkret/self/realms/{REALM_B}/effective-policy"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&svc)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(ep["realm_id"], REALM_B);
    assert_eq!(ep["inheritance_mode"], "explicit");
    let chain = ep["inheritance_chain"]
        .as_array()
        .expect("inheritance_chain array");
    assert!(
        chain.iter().any(|v| v.as_str() == Some(REALM_A)),
        "inheritance_chain MUST include REALM_A (declared parent), got {chain:?}"
    );
    let allowed = ep["effective_policy"]["allowed_policies"]
        .as_array()
        .expect("effective_policy.allowed_policies array");
    let allowed_strs: Vec<&str> = allowed.iter().filter_map(Value::as_str).collect();
    // B's own declared `b.policy` is in the merged set. A's `a.policy`
    // is also included because the walk reaches A via the governed_by
    // edge AND A has its own inheritance_policy declaration.
    assert!(
        allowed_strs.contains(&"b.policy"),
        "expected b.policy in merged set: {allowed_strs:?}"
    );
    assert!(
        allowed_strs.contains(&"a.policy"),
        "expected a.policy (walked from parent): {allowed_strs:?}"
    );
}

/// Realm Link is a general graph: a directed triangle is valid.
#[tokio::test]
async fn realm_links_post_general_directed_cycle_is_allowed() {
    let svc = app();
    let token = dev_token(&svc).await;

    // Edge A → B.
    let r1 = TestClient::post(format!("http://server/_arkret/self/realms/{REALM_A}/links"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "target_realm_id": REALM_B,
            "link_kind": "governed_by",
            "status": "active",
        }))
        .send(&svc)
        .await;
    assert_eq!(r1.status_code, Some(StatusCode::OK));

    // Edge B → C.
    let r2 = TestClient::post(format!("http://server/_arkret/self/realms/{REALM_B}/links"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "target_realm_id": REALM_C,
            "link_kind": "governed_by",
            "status": "active",
        }))
        .send(&svc)
        .await;
    assert_eq!(r2.status_code, Some(StatusCode::OK));

    // Edge C → A closes A→B→C→A and remains valid.
    let r3 = TestClient::post(format!("http://server/_arkret/self/realms/{REALM_C}/links"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "target_realm_id": REALM_A,
            "link_kind": "governed_by",
            "status": "active",
        }))
        .send(&svc)
        .await;
    assert_eq!(r3.status_code, Some(StatusCode::OK));
}

/// G3.S5 — DELETE a link, verify the effective policy recomputes
/// (the deleted edge is treated as severed, so it no longer
/// contributes to the inheritance walk).
#[tokio::test]
async fn realm_links_delete_recomputes_effective_policy() {
    let state = AppState::new(test_config(), Db { pool: None });
    let svc = service(state.clone());
    let token = dev_token(&svc).await;

    // Build D → C → B chain via POSTs, opt-in inheritance at each level.
    let _ = TestClient::post(format!("http://server/_arkret/self/realms/{REALM_D}/links"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "target_realm_id": REALM_C,
            "link_kind": "governed_by",
            "status": "active",
        }))
        .send(&svc)
        .await;
    let _ = TestClient::post(format!("http://server/_arkret/self/realms/{REALM_C}/links"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "target_realm_id": REALM_B,
            "link_kind": "governed_by",
            "status": "active",
        }))
        .send(&svc)
        .await;
    project_inheritance_policy(&state, REALM_D, REALM_C, &["d.policy"]);
    project_inheritance_policy(&state, REALM_C, REALM_B, &["c.policy"]);
    project_inheritance_policy(&state, REALM_B, REALM_B, &["b.policy"]);

    // Effective policy on D includes c.policy + b.policy via the walk.
    let ep1: Value = TestClient::get(format!(
        "http://server/_arkret/self/realms/{REALM_D}/effective-policy"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&svc)
    .await
    .take_json()
    .await
    .unwrap();
    let allowed1: Vec<&str> = ep1["effective_policy"]["allowed_policies"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(allowed1.contains(&"d.policy"));
    assert!(allowed1.contains(&"c.policy"));
    assert!(
        allowed1.contains(&"b.policy"),
        "2-level walk MUST surface grandparent's allowed_policies: {allowed1:?}"
    );

    // DELETE D → C. Severs the chain at the first edge — D's chain
    // walk now stops at C (still declared in D's inheritance_policy)
    // but cannot transit further because the governed_by edge is
    // tombstoned. C's own `c.policy` still surfaces because D's
    // inheritance_policy explicitly names C as the parent; B drops out.
    let del = TestClient::delete(format!(
        "http://server/_arkret/self/realms/{REALM_D}/links/{REALM_C}?link_kind=governed_by"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&svc)
    .await;
    assert_eq!(del.status_code, Some(StatusCode::OK));

    let ep2: Value = TestClient::get(format!(
        "http://server/_arkret/self/realms/{REALM_D}/effective-policy"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&svc)
    .await
    .take_json()
    .await
    .unwrap();
    let allowed2: Vec<&str> = ep2["effective_policy"]["allowed_policies"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        !allowed2.contains(&"b.policy"),
        "after DELETE D→C, the transitive walk to B must be cut: {allowed2:?}"
    );

    // Tombstoned is terminal. A later attempt to reactivate the same cell
    // fails with the canonical FSM reason.
    let mut reactivate =
        TestClient::post(format!("http://server/_arkret/self/realms/{REALM_D}/links"))
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&json!({
                "target_realm_id": REALM_C,
                "link_kind": "governed_by",
                "status": "active",
            }))
            .send(&svc)
            .await;
    assert_eq!(
        reactivate.status_code,
        Some(StatusCode::UNPROCESSABLE_ENTITY)
    );
    let body: Value = reactivate
        .take_json()
        .await
        .expect("error envelope is JSON");
    assert_eq!(body["error"]["code"], "failed_precondition");
    assert_eq!(
        body["error"]["details"]["reason_code"],
        "realm_link_invalid_transition"
    );
}

/// G3.S5 — self-link is rejected as a schema violation with HTTP 422.
#[tokio::test]
async fn realm_links_post_self_link_rejected() {
    let svc = app();
    let token = dev_token(&svc).await;
    let mut r = TestClient::post(format!("http://server/_arkret/self/realms/{REALM_A}/links"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "target_realm_id": REALM_A,
            "link_kind": "governed_by",
            "status": "active",
        }))
        .send(&svc)
        .await;
    assert_eq!(r.status_code, Some(StatusCode::UNPROCESSABLE_ENTITY));
    let body: Value = r.take_json().await.expect("error envelope is JSON");
    assert_eq!(body["error"]["code"], "schema_violation");
    assert_eq!(
        body["error"]["details"]["reason_code"],
        "realm_link_self_reference"
    );
}

/// G3.S5 — effective-policy on a Realm with no
/// `ak.realm.inheritance_policy` declaration MUST report
/// `inheritance_mode = "none"` with an empty chain (spec §5 — no
/// implicit cascade).
#[tokio::test]
async fn effective_policy_returns_none_mode_without_explicit_optin() {
    let svc = app();
    let token = dev_token(&svc).await;
    let body: Value = TestClient::get(format!(
        "http://server/_arkret/self/realms/{REALM_A}/effective-policy"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&svc)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(body["realm_id"], REALM_A);
    assert_eq!(body["inheritance_mode"], "none");
    assert!(
        body["inheritance_chain"].as_array().unwrap().is_empty(),
        "chain must be empty without explicit opt-in: {body}"
    );
}
