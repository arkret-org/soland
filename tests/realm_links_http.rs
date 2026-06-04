//! G3.S5 — HTTP integration tests for the realm-links surface:
//!
//! - `POST /_cokret/self/realms/{realm_id}/links` — create / status-flip a `ck.realm.link`.
//! - `DELETE /_cokret/self/realms/{realm_id}/links/{target_realm_id}` — tombstone an existing link.
//! - `GET /_cokret/self/realms/{realm_id}/effective-policy` — read the merged effective policy
//!   (walks the inheritance chain).
//! - Cycle-detection negative: a 3-realm `governed_by` triangle MUST be rejected with
//!   `realm_link_cycle` at the third POST.

use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use soland::config::{AppConfig, ObjectStorageConfig};
use soland::db::Db;
use soland::service;
use soland::state::AppState;

fn test_config() -> AppConfig {
    AppConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        metrics_bind: "127.0.0.1:0".parse().unwrap(),
        public_base_url: "http://server".to_owned(),
        service_did: "did:web:soland.local".to_owned(),
        tls_cert_path: None,
        tls_key_path: None,
        database_url: None,
        object_storage: ObjectStorageConfig::local(std::env::temp_dir().join("soland-test-blobs")),
        cors_allow_origin: None,
        auth_server_url: None,
        development_mode: true,
        oauth_introspection_url: None,
        oauth_introspection_bearer: None,
        session_grant_introspection_url: None,
        session_grant_introspection_bearer: None,
        did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned(), "uuid".to_owned()],
        embedded_webvh_provider_enabled: false,
        embedded_webvh_registration_bearer: None,
        external_webvh_provider_url: None,
        external_webvh_provider_active: false,
        default_webvh_provider_id: None,
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: std::collections::BTreeMap::new(),
        anchorer_signing_key_seed: None,
        agent_audit_binding_signing_seed: None,
        use_keystore: false,
        federation_policy: soland::config::FederationPolicy::Mesh,
        federation_peers: Vec::new(),
        federation_outbound_enabled: false,
        admin_default_page_limit: 100,
        admin_max_page_limit: 1000,
        admin_principal_dids: Vec::new(),
        push_bridge_cache_ttl_seconds: 900,
        push_bridge_trusted_service_dids: Vec::new(),
        compaction_min_anchor_age_seconds: 604_800,
        compaction_min_witnesses: 1,
        compaction_preserve_genesis: true,
        compaction_prune_only_singleton_successors: true,
        compaction_prune_walk_interval_seconds: 0,
        compaction_prune_walk_per_space_limit: 50,
        seed_demo_data: true,
        trust_domain: "ck:trust_domain:soland.local".to_owned(),
        sovereign_enclave_enabled: false,
        sovereign_enclave_allowed_outbound_hosts: Vec::new(),
        erasure_propagation_window_ms: 604_800_000,
        log_format: soland::config::LogFormat::Plain,
    }
}

fn app() -> salvo::Service {
    service(AppState::new(test_config(), Db { pool: None }))
}

async fn dev_token(svc: &salvo::Service) -> String {
    let login: Value = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&json!({
            "actor": "did:web:alice.example",
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "display_name": "Alice Desktop"
        }))
        .send(svc)
        .await
        .take_json()
        .await
        .unwrap();
    login["access_token"].as_str().unwrap().to_owned()
}

const REALM_A: &str = "ck:realm:01904100-0000-7000-8000-aaaaaaaaaaa1";
const REALM_B: &str = "ck:realm:01904100-0000-7000-8000-bbbbbbbbbbb2";
const REALM_C: &str = "ck:realm:01904100-0000-7000-8000-ccccccccccc3";
const REALM_D: &str = "ck:realm:01904100-0000-7000-8000-ddddddddddd4";

/// Submit a `ck.realm.inheritance_policy` event directly through the
/// reducer (the dedicated HTTP route is the standard `/_cokret/self/events`
/// envelope path; for setup we bypass it by injecting an Operation
/// into the projection).
fn project_inheritance_policy(
    state: &AppState,
    realm_id: &str,
    source_realm_id: &str,
    allowed_policies: &[&str],
) {
    use cokret_sdk::{Operation, OperationId, RealmId};
    let op = Operation::create(
        OperationId::new(format!("ck:operation:{}", uuid::Uuid::now_v7())).unwrap(),
        RealmId::new(realm_id).unwrap(),
        soland::kinds::CK_REALM_INHERITANCE_POLICY,
        json!({
            "source_realm_id": source_realm_id,
            "allowed_policies": allowed_policies,
            "max_depth": 1,
        }),
    );
    let mut proj = state.projection.lock().expect("projection mutex");
    proj.apply(&op, &state.hlc);
}

/// G3.S5 — happy path: POST a `governed_by` link from B → A, GET the
/// effective policy on B (after an explicit `ck.realm.inheritance_policy`
/// opt-in) and assert the chain walked back to A.
#[tokio::test]
async fn realm_links_post_parent_then_effective_policy_walks_chain() {
    let state = AppState::new(test_config(), Db { pool: None });
    let svc = service(state.clone());
    let token = dev_token(&svc).await;

    // 1. POST B → A (`governed_by`, active). HTTP 200, body echoes the projected status.
    let body: Value =
        TestClient::post(format!("http://server/_cokret/self/realms/{REALM_B}/links"))
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

    // 2. Explicit inheritance opt-in on B (spec §6.1 — opt-in is mandatory; cycle detection alone
    //    doesn't enable inheritance).
    project_inheritance_policy(&state, REALM_B, REALM_A, &["b.policy"]);
    project_inheritance_policy(&state, REALM_A, REALM_A, &["a.policy"]);

    // 3. GET effective-policy on B. Body shape pinned by the task spec: `{realm_id,
    //    effective_policy, inheritance_chain, inheritance_mode}`.
    let ep: Value = TestClient::get(format!(
        "http://server/_cokret/self/realms/{REALM_B}/effective-policy"
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

/// G3.S5 acceptance — cycle detection rejects a 3-realm `governed_by`
/// triangle. A → B and B → C succeed; C → A closes the cycle and MUST
/// be rejected with HTTP 422 + `error.code` `realm_link_cycle`.
#[tokio::test]
async fn realm_links_post_cycle_rejected_with_realm_link_cycle() {
    let svc = app();
    let token = dev_token(&svc).await;

    // Edge A → B.
    let r1 = TestClient::post(format!("http://server/_cokret/self/realms/{REALM_A}/links"))
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
    let r2 = TestClient::post(format!("http://server/_cokret/self/realms/{REALM_B}/links"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "target_realm_id": REALM_C,
            "link_kind": "governed_by",
            "status": "active",
        }))
        .send(&svc)
        .await;
    assert_eq!(r2.status_code, Some(StatusCode::OK));

    // Edge C → A would close A→B→C→A — MUST be rejected.
    let mut r3 = TestClient::post(format!("http://server/_cokret/self/realms/{REALM_C}/links"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "target_realm_id": REALM_A,
            "link_kind": "governed_by",
            "status": "active",
        }))
        .send(&svc)
        .await;
    assert_eq!(
        r3.status_code,
        Some(StatusCode::UNPROCESSABLE_ENTITY),
        "cycle MUST be rejected with 422 Unprocessable Entity"
    );
    let body: Value = r3.take_json().await.expect("error envelope is JSON");
    assert_eq!(
        body["error"]["code"], "realm_link_cycle",
        "rejection MUST carry the spec reason code: {body}"
    );
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
    let _ = TestClient::post(format!("http://server/_cokret/self/realms/{REALM_D}/links"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "target_realm_id": REALM_C,
            "link_kind": "governed_by",
            "status": "active",
        }))
        .send(&svc)
        .await;
    let _ = TestClient::post(format!("http://server/_cokret/self/realms/{REALM_C}/links"))
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
        "http://server/_cokret/self/realms/{REALM_D}/effective-policy"
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
        "http://server/_cokret/self/realms/{REALM_D}/links/{REALM_C}?link_kind=governed_by"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&svc)
    .await;
    assert_eq!(del.status_code, Some(StatusCode::OK));

    let ep2: Value = TestClient::get(format!(
        "http://server/_cokret/self/realms/{REALM_D}/effective-policy"
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
}

/// G3.S5 — self-link is rejected via the same 422 path used for cycle
/// detection (different code, same HTTP shape).
#[tokio::test]
async fn realm_links_post_self_link_rejected() {
    let svc = app();
    let token = dev_token(&svc).await;
    let mut r = TestClient::post(format!("http://server/_cokret/self/realms/{REALM_A}/links"))
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
    assert_eq!(body["error"]["code"], "realm_link_self_reference");
}

/// G3.S5 — effective-policy on a Realm with no
/// `ck.realm.inheritance_policy` declaration MUST report
/// `inheritance_mode = "none"` with an empty chain (spec §5 — no
/// implicit cascade).
#[tokio::test]
async fn effective_policy_returns_none_mode_without_explicit_optin() {
    let svc = app();
    let token = dev_token(&svc).await;
    let body: Value = TestClient::get(format!(
        "http://server/_cokret/self/realms/{REALM_A}/effective-policy"
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
