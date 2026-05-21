//! G3.S1 integration test — exercises the MLS lifecycle HTTP surface
//! end-to-end:
//!
//!   1. publish a KeyPackage,
//!   2. claim it atomically (and assert a second claim returns 409),
//!   3. enqueue a Welcome (driven from the same test process, since
//!      the public Welcome-fanout route lives behind a federation
//!      receive path that's out-of-scope for this slice — we simulate
//!      it by writing through `MlsWelcomeStore::enqueue`),
//!   4. drain the calling device's queue via `GET /welcomes/pending`,
//!   5. submit an MLS commit and observe the epoch bump; replay it
//!      and assert `412 mls_epoch_skew`.
//!
//! The test runs against a fresh in-memory soland (no Pg) using the
//! shared `dev-login` shortcut for bearer issuance — same pattern as
//! `tests/http_api.rs`.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use soland::config::{AppConfig, FederationPolicy, ObjectStorageConfig};
use soland::db::Db;
use soland::persistence::MlsWelcomeRecord;
use soland::service;
use soland::state::AppState;

fn test_config() -> AppConfig {
    AppConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        public_base_url: "http://server".to_owned(),
        service_did: "did:web:soland-mls-test.local".to_owned(),
        tls_cert_path: None,
        tls_key_path: None,
        database_url: None,
        object_storage: ObjectStorageConfig::local(std::env::temp_dir().join("soland-mls-blobs")),
        cors_allow_origin: None,
        auth_server_url: None,
        development_mode: true,
        oauth_introspection_url: None,
        oauth_introspection_bearer: None,
        session_grant_introspection_url: None,
        session_grant_introspection_bearer: None,
        did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
        embedded_webvh_provider_enabled: false,
        embedded_webvh_registration_bearer: None,
        external_webvh_provider_url: None,
        external_webvh_provider_active: false,
        default_webvh_provider_id: None,
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: BTreeMap::new(),
        anchorer_signing_key_seed: None,
        agent_audit_binding_signing_seed: None,
        use_keystore: false,
        federation_policy: FederationPolicy::Mesh,
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
        seed_demo_data: false,
        trust_domain: "cx:trust_domain:soland-mls-test.local".to_owned(),
        sovereign_enclave_enabled: false,
        sovereign_enclave_allowed_outbound_hosts: Vec::new(),
    }
}

fn app_from_state(state: AppState) -> salvo::Service {
    service(state)
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

async fn dev_token(state: AppState, actor: &str, device_id: &str, display: &str) -> String {
    let login: Value = TestClient::post("http://server/api/v1/auth/dev-login")
        .json(&json!({
            "actor": actor,
            "device_id": device_id,
            "display_name": display,
        }))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    login["access_token"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn mls_lifecycle_end_to_end() {
    let state = AppState::new(test_config(), Db { pool: None });

    let alice_did = "did:web:alice.example";
    let alice_device = "cx:device:01904100-0000-7000-8000-a11ce0000001";
    let alice_token = dev_token(state.clone(), alice_did, alice_device, "Alice").await;

    // ── 1. publish a KeyPackage ──────────────────────────────────
    let keypackage_id = "cx:mls_keypackage:t-01";
    let publish_body = json!({
        "keypackage_id": keypackage_id,
        "actor_did": alice_did,
        "device_id": alice_device,
        "lifetime": {"not_before": 1, "not_after": 4_102_444_800_i64},
        "key_package_bytes_b64": b64(b"opaque-mls-keypackage"),
    });
    let publish_resp = TestClient::post("http://server/api/v1/mls/keypackages")
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .json(&publish_body)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(publish_resp.status_code, Some(StatusCode::OK));
    let mut publish_resp = publish_resp;
    let publish_json: Value = publish_resp.take_json().await.unwrap();
    assert_eq!(publish_json["keypackage_id"], json!(keypackage_id));
    assert_eq!(publish_json["claimed"], json!(false));
    assert!(
        state
            .persistence
            .mls_key_packages()
            .get(keypackage_id)
            .unwrap()
            .is_some(),
        "publish must mirror into the store"
    );

    // ── 2a. atomic claim wins ────────────────────────────────────
    let claim_url = format!("http://server/api/v1/mls/keypackages/{keypackage_id}/claim");
    let claim_resp = TestClient::post(&claim_url)
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .json(&json!({"group_id": "cx:mls_group:abc"}))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(claim_resp.status_code, Some(StatusCode::OK));
    let mut claim_resp = claim_resp;
    let claim_json: Value = claim_resp.take_json().await.unwrap();
    assert_eq!(claim_json["group_id"], json!("cx:mls_group:abc"));

    // ── 2b. second claim must collide with 409 ───────────────────
    let collide_resp = TestClient::post(&claim_url)
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .json(&json!({"group_id": "cx:mls_group:second"}))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(collide_resp.status_code, Some(StatusCode::CONFLICT));
    let mut collide_resp = collide_resp;
    let collide_json: Value = collide_resp.take_json().await.unwrap();
    // Error envelopes wrap the canonical errcode under `error.errcode`.
    let collide_code = collide_json["error"]["errcode"]
        .as_str()
        .or_else(|| collide_json["errcode"].as_str());
    assert_eq!(
        collide_code,
        Some("mls_keypackage_already_claimed"),
        "second claim must surface the wire reason: {collide_json}"
    );

    // ── 3. simulate a Welcome enqueue for Bob's device ──────────
    //
    // The public Welcome fanout path is fed by federation receive
    // (see TODO(G3.S1-followup): governance_binding / covered_frontier
    // for the routes that emit cx.mls.welcome.enqueue from the public
    // /api/v1/federation surface). For this integration test we
    // drive the persistence store directly to set up the precondition
    // for the GET /welcomes/pending drain in step 4.
    let bob_did = "did:web:bob.example";
    let bob_device = "cx:device:01904100-0000-7000-8000-b0b0e0000001";
    state
        .persistence
        .mls_welcomes()
        .enqueue(&MlsWelcomeRecord {
            id: "cx:mls_welcome:w-01".to_owned(),
            group_id: "cx:mls_group:abc".to_owned(),
            recipient_actor_did: bob_did.to_owned(),
            recipient_device_id: bob_device.to_owned(),
            welcome_bytes: b"opaque-mls-welcome".to_vec(),
            key_package_id: keypackage_id.to_owned(),
            enqueued_at: 1_700_000_000,
            delivered_at: None,
        })
        .expect("enqueue welcome");

    // ── 4. Bob drains his Welcome queue via the HTTP route ──────
    let bob_token = dev_token(state.clone(), bob_did, bob_device, "Bob").await;
    let drain_resp = TestClient::get("http://server/api/v1/mls/welcomes/pending")
        .add_header("authorization", format!("Bearer {bob_token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(drain_resp.status_code, Some(StatusCode::OK));
    let mut drain_resp = drain_resp;
    let drain_json: Value = drain_resp.take_json().await.unwrap();
    let welcomes = drain_json["welcomes"].as_array().expect("welcomes array");
    assert_eq!(welcomes.len(), 1);
    assert_eq!(welcomes[0]["welcome_id"], json!("cx:mls_welcome:w-01"));
    assert_eq!(welcomes[0]["group_id"], json!("cx:mls_group:abc"));
    assert_eq!(welcomes[0]["key_package_id"], json!(keypackage_id));
    assert!(
        welcomes[0]["delivered_at"].is_i64(),
        "delivered_at must be set after drain"
    );

    // Second drain must return zero rows — `delivered_at` flips
    // ensures we don't redeliver.
    let drain2_resp = TestClient::get("http://server/api/v1/mls/welcomes/pending")
        .add_header("authorization", format!("Bearer {bob_token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    let mut drain2_resp = drain2_resp;
    let drain2_json: Value = drain2_resp.take_json().await.unwrap();
    assert!(
        drain2_json["welcomes"].as_array().unwrap().is_empty(),
        "second drain must return zero welcomes (delivered_at flag): {drain2_json}"
    );

    // ── 5a. first commit bumps the group's epoch from 0 to 1 ────
    let commit_resp = TestClient::post("http://server/api/v1/mls/commits")
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .json(&json!({
            "group_id": "cx:mls_group:abc",
            "expected_prev_epoch": 0,
            "leader_actor_did": alice_did,
            "commit_bytes_b64": b64(b"opaque-mls-commit-1"),
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(commit_resp.status_code, Some(StatusCode::OK));
    let mut commit_resp = commit_resp;
    let commit_json: Value = commit_resp.take_json().await.unwrap();
    assert_eq!(commit_json["epoch"], json!(1));
    assert_eq!(commit_json["previous_epoch"], json!(0));

    // ── 5b. replay (expected_prev_epoch=0 again) must be rejected
    //         with 412 mls_epoch_skew ─────────────────────────────
    let replay_resp = TestClient::post("http://server/api/v1/mls/commits")
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .json(&json!({
            "group_id": "cx:mls_group:abc",
            "expected_prev_epoch": 0,
            "leader_actor_did": alice_did,
            "commit_bytes_b64": b64(b"opaque-mls-commit-replay"),
        }))
        .send(&app_from_state(state.clone()))
        .await;
    // `failed_precondition` maps to HTTP 409 in the canonical registry
    // (see `contrix_core::error::error_code_http_status`).
    assert_eq!(
        replay_resp.status_code,
        Some(StatusCode::CONFLICT),
        "replay commit must return 409 (failed_precondition mapping)"
    );
    let mut replay_resp = replay_resp;
    let replay_json: Value = replay_resp.take_json().await.unwrap();
    let replay_code = replay_json["error"]["errcode"]
        .as_str()
        .or_else(|| replay_json["errcode"].as_str());
    assert_eq!(
        replay_code,
        Some("mls_epoch_skew"),
        "replay commit must surface mls_epoch_skew: {replay_json}"
    );

    // ── 5c. an in-order commit (expected_prev_epoch=1) lands ────
    let next_resp = TestClient::post("http://server/api/v1/mls/commits")
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .json(&json!({
            "group_id": "cx:mls_group:abc",
            "expected_prev_epoch": 1,
            "leader_actor_did": alice_did,
            "commit_bytes_b64": b64(b"opaque-mls-commit-2"),
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(next_resp.status_code, Some(StatusCode::OK));
    let mut next_resp = next_resp;
    let next_json: Value = next_resp.take_json().await.unwrap();
    assert_eq!(next_json["epoch"], json!(2));
    assert_eq!(next_json["previous_epoch"], json!(1));

    // Persistence mirror must agree with the projection state.
    let stored = state
        .persistence
        .mls_commits()
        .get("cx:mls_group:abc")
        .unwrap()
        .expect("commit epoch row present after two bumps");
    assert_eq!(stored.epoch, 2);
    assert_eq!(stored.leader_actor_did, alice_did);
}
