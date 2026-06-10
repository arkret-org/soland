//! G3.S1 integration test — exercises the keypackage/welcome HTTP surface
//! end-to-end:
//!
//!   1. upload a KeyPackage,
//!   2. claim it atomically (and assert a second claim returns 409),
//!   3. submit canonical `ck.mls.genesis` and `ck.mls.welcome` events and assert they mirror into
//!      the MLS epoch / Welcome stores,
//!   4. drain the calling device's queue via `GET /_cokret/self/keys/keypackages/welcomes/pending`.
//!
//! MLS commits no longer have a dedicated REST surface — clients submit
//! `ck.mls.commit` events via the canonical `POST /_cokret/self/events` pipeline
//! (W1C). The commit-bump path is covered by reducer-level unit tests in
//! `reducer::mls`; we don't re-test it here.
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
use sha2::{Digest, Sha256};
use soland::config::{AppConfig, FederationPolicy, ObjectStorageConfig};
use soland::db::Db;
use soland::service;
use soland::state::AppState;

fn test_config() -> AppConfig {
    AppConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        metrics_bind: "127.0.0.1:0".parse().unwrap(),
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
        resumable_upload_dir: std::path::PathBuf::from("./soland-resumable-uploads"),
        resumable_upload_incomplete_ttl_seconds: 86_400,
        compaction_min_anchor_age_seconds: 604_800,
        compaction_min_witnesses: 1,
        compaction_preserve_genesis: true,
        compaction_prune_only_singleton_successors: true,
        compaction_prune_walk_interval_seconds: 0,
        compaction_prune_walk_per_realm_limit: 50,
        seed_demo_data: false,
        trust_domain: "ck:trust_domain:soland-mls-test.local".to_owned(),
        sovereign_enclave_enabled: false,
        sovereign_enclave_allowed_outbound_hosts: Vec::new(),
        erasure_propagation_window_ms: 604_800_000,
        log_format: soland::config::LogFormat::Plain,
    }
}

fn app_from_state(state: AppState) -> salvo::Service {
    service(state)
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn sha256_json(value: &Value) -> String {
    let bytes = cokret_sdk::canonical::canonical_json_bytes(value)
        .unwrap_or_else(|_| serde_json::to_vec(value).unwrap());
    format!("sha256:{:x}", Sha256::digest(&bytes))
}

fn event_canonical_digest(event: &Value) -> String {
    let mut canonical = event.clone();
    if let Value::Object(object) = &mut canonical {
        object.remove("proofs");
        object.remove("unsigned");
        object.remove("canonical_digest");
        object.remove("canonical_hash");
    }
    sha256_json(&canonical)
}

fn signed_event(
    event_id: &str,
    actor_seq: u64,
    actor: &str,
    device_id: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
) -> Value {
    let mut event = json!({
        "event_id": event_id,
        "kind": kind,
        "schema_id": "ck.schema.event.v1",
        "actor_id": actor,
        "actor_seq": actor_seq,
        "realm_id": realm_id,
        "device_id": device_id,
        "audience": "did:web:soland-mls-test.local",
        "domain": "did:web:soland-mls-test.local",
        "prev_refs": [],
        "auth_refs": [],
        "payload": payload,
        "proofs": [{
            "type": "dev-proof",
            "verification_method": format!("{actor}#{device_id}"),
            "device_id": device_id,
            "audience": "did:web:soland-mls-test.local",
            "domain": "did:web:soland-mls-test.local",
            "payload_digest": sha256_json(&payload),
        }],
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));
    event
}

async fn dev_token(state: AppState, actor: &str, device_id: &str, display: &str) -> String {
    let login: Value = TestClient::post("http://server/_soland/gate/auth/dev-login")
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
    let alice_device = "ck:device:01904100-0000-7000-8000-a11ce0000001";
    let alice_token = dev_token(state.clone(), alice_did, alice_device, "Alice").await;

    // ── 1. upload a KeyPackage (W1C: ck.self.keys.keypackages.upload) ──
    let keypackage_id = "ck:mls_keypackage:t-01";
    let publish_body = json!({
        "keypackage_id": keypackage_id,
        "actor_id": alice_did,
        "device_id": alice_device,
        "lifetime": {"not_before": 1, "not_after": 4_102_444_800_i64},
        "key_package_bytes_b64": b64(b"opaque-mls-keypackage"),
    });
    let publish_resp = TestClient::post("http://server/_cokret/self/keys/keypackages/upload")
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
            .await
            .unwrap()
            .is_some(),
        "publish must mirror into the store"
    );

    // ── 2a. atomic claim wins (W1C: ck.self.keys.keypackages.claim) ───
    // keypackage_id is now carried in the body, not the URL.
    let claim_url = "http://server/_cokret/self/keys/keypackages/claim".to_owned();
    let claim_resp = TestClient::post(&claim_url)
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .json(&json!({
            "keypackage_id": keypackage_id,
            "mls_group_ref": "ck:mls_group:abc"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(claim_resp.status_code, Some(StatusCode::OK));
    let mut claim_resp = claim_resp;
    let claim_json: Value = claim_resp.take_json().await.unwrap();
    assert_eq!(claim_json["mls_group_ref"], json!("ck:mls_group:abc"));
    assert!(claim_json.get("group_id").is_none());

    // ── 2b. second claim must collide with 409 ───────────────────
    let collide_resp = TestClient::post(&claim_url)
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .json(&json!({
            "keypackage_id": keypackage_id,
            "mls_group_ref": "ck:mls_group:second"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(collide_resp.status_code, Some(StatusCode::CONFLICT));
    let mut collide_resp = collide_resp;
    let collide_json: Value = collide_resp.take_json().await.unwrap();
    // Error envelopes wrap the canonical code under `error.code`.
    let collide_code = collide_json["error"]["code"]
        .as_str()
        .or_else(|| collide_json["code"].as_str());
    assert_eq!(
        collide_code,
        Some("mls_keypackage_already_claimed"),
        "second claim must surface the wire reason: {collide_json}"
    );

    let bob_did = "did:web:bob.example";
    let bob_device = "ck:device:01904100-0000-7000-8000-b0b0e0000001";
    let realm_id = "ck:realm:01904100-0000-7000-8000-00000000e2ee";
    let group_id = "ck:mls_group:abc";
    let effective_scope = json!({"kind": "realm", "realm_id": realm_id});
    let frontier_ref = "ck:event:01904100-0000-7000-8000-00000000f00d";
    let keypackage_ref = "sha256:5555555555555555555555555555555555555555555555555555555555555555";
    let welcome_ref =
        "ck:blob:sha256:8888888888888888888888888888888888888888888888888888888888888888";
    let governance_binding = json!({
        "binding_version": 1,
        "encoding_profile": "cbor-deterministic-rfc8949-v1",
        "realm_id": realm_id,
        "effective_scope": effective_scope.clone(),
        "mls_group_id": group_id,
        "previous_epoch": 0,
        "next_epoch": 0,
        "membership_frontier": [frontier_ref],
        "policy_root": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
    });

    // ── 3a. Realm + MLS group genesis enter through canonical events ─
    let realm_create = signed_event(
        "ck:event:01904100-0000-7000-8000-00000000e2e0",
        1,
        alice_did,
        alice_device,
        realm_id,
        "ck.realm.create",
        json!({
            "object": {
                "id": realm_id,
                "schema": "ck.schema.realm.v1",
                "title": "MLS lifecycle",
                "created_by": alice_did,
                "trust_domain": "ck:trust_domain:soland-mls-test.local",
                "schema_refs": ["ck.schema.realm.v1"],
                "default_discoverability": "listed",
                "default_join_rule": "invite",
                "history_visibility": "joined",
                "encryption_profile": "mls_rfc9420",
                "security_class": "standard",
                "federation_policy": "restricted",
                "anchor_profile": "single_did",
                "digest_algorithm": "sha256",
                "anchorer": {
                    "type": "single_did",
                    "did": alice_did,
                    "recovery_members": ["did:web:recovery.example"],
                    "controller_organization": "did:web:organization.primary.example",
                    "recovery_controller_organizations": ["did:web:organization.recovery.example"]
                },
                "created_at": "2026-05-25T00:00:00Z"
            }
        }),
    );
    let create_resp = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .json(&realm_create)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(create_resp.status_code, Some(StatusCode::OK));

    let genesis = signed_event(
        "ck:event:01904100-0000-7000-8000-00000000e2e1",
        2,
        alice_did,
        alice_device,
        realm_id,
        "ck.mls.genesis",
        json!({
            "mls_group_id": group_id,
            "effective_scope": effective_scope.clone(),
            "epoch": 0,
            "creator_principal_id": alice_did,
            "creator_device_id": alice_device,
            "cipher_suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            "group_info_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            "ratchet_tree_digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
            "governance_binding": governance_binding,
            "created_at": "2026-05-25T00:00:01Z"
        }),
    );
    let genesis_resp = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .json(&genesis)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(genesis_resp.status_code, Some(StatusCode::OK));
    assert_eq!(
        state
            .persistence
            .mls_commits()
            .get(group_id)
            .await
            .unwrap()
            .expect("genesis persisted")
            .epoch,
        0
    );

    // ── 3b. Welcome is a durable event and mirrors into the pending queue ─
    let welcome = signed_event(
        "ck:event:01904100-0000-7000-8000-00000000e2e2",
        3,
        alice_did,
        alice_device,
        realm_id,
        "ck.mls.welcome",
        json!({
            "mls_group_id": group_id,
            "epoch": 1,
            "recipient_principal_id": bob_did,
            "recipient_device_id": bob_device,
            "keypackage_ref": keypackage_ref,
            "keypackage_digest": "sha256:5555555555555555555555555555555555555555555555555555555555555555",
            "claim_id": "claim-01",
            "claim_ref": {
                "claim_id": "claim-01",
                "keypackage_ref": keypackage_ref,
                "keypackage_digest": "sha256:5555555555555555555555555555555555555555555555555555555555555555",
                "capabilities_digest": "sha256:6666666666666666666666666666666666666666666666666666666666666666",
                "ssk_generation": 1
            },
            "welcome_ref": welcome_ref,
            "ciphertext": "opaque-mls-welcome",
            "expires_at": "2026-05-25T01:00:00Z",
            "commit_ref": "ck:event:01904100-0000-7000-8000-00000000e2e3",
            "governance_binding": governance_binding
        }),
    );
    let welcome_resp = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .json(&welcome)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(welcome_resp.status_code, Some(StatusCode::OK));
    assert_eq!(
        state
            .persistence
            .mls_welcomes()
            .snapshot_all()
            .await
            .unwrap()
            .len(),
        1
    );

    // ── 3c. Canonical commit event advances the durable epoch row ─
    let commit_binding = json!({
        "binding_version": 1,
        "encoding_profile": "cbor-deterministic-rfc8949-v1",
        "realm_id": realm_id,
        "effective_scope": effective_scope.clone(),
        "mls_group_id": group_id,
        "previous_epoch": 0,
        "next_epoch": 1,
        "membership_frontier": [frontier_ref],
        "policy_root": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
    });
    let commit = signed_event(
        "ck:event:01904100-0000-7000-8000-00000000e2e3",
        4,
        alice_did,
        alice_device,
        realm_id,
        "ck.mls.commit",
        json!({
            "mls_group_id": group_id,
            "base_epoch": 0,
            "base_epoch_ref": "ck:event:01904100-0000-7000-8000-00000000e2e1",
            "proposal_refs": [],
            "next_epoch": 1,
            "commit_digest": "sha256:7777777777777777777777777777777777777777777777777777777777777777",
            "governance_binding": commit_binding
        }),
    );
    let commit_resp = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {alice_token}"), true)
        .json(&commit)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(commit_resp.status_code, Some(StatusCode::OK));
    assert_eq!(
        state
            .persistence
            .mls_commits()
            .get(group_id)
            .await
            .unwrap()
            .expect("commit persisted")
            .epoch,
        1
    );

    // ── 4. Bob drains his Welcome queue via the HTTP route ──────
    let bob_token = dev_token(state.clone(), bob_did, bob_device, "Bob").await;
    let drain_resp =
        TestClient::get("http://server/_cokret/self/keys/keypackages/welcomes/pending")
            .add_header("authorization", format!("Bearer {bob_token}"), true)
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(drain_resp.status_code, Some(StatusCode::OK));
    let mut drain_resp = drain_resp;
    let drain_json: Value = drain_resp.take_json().await.unwrap();
    let welcomes = drain_json["welcomes"].as_array().expect("welcomes array");
    assert_eq!(welcomes.len(), 1);
    assert_eq!(welcomes[0]["welcome_id"], json!(welcome_ref));
    assert_eq!(welcomes[0]["mls_group_ref"], json!("ck:mls_group:abc"));
    assert!(welcomes[0].get("group_id").is_none());
    assert_eq!(welcomes[0]["key_package_id"], json!(keypackage_ref));
    assert!(
        welcomes[0]["delivered_at"].is_i64(),
        "delivered_at must be set after drain"
    );

    // Second drain must return zero rows — `delivered_at` flips
    // ensures we don't redeliver.
    let drain2_resp =
        TestClient::get("http://server/_cokret/self/keys/keypackages/welcomes/pending")
            .add_header("authorization", format!("Bearer {bob_token}"), true)
            .send(&app_from_state(state.clone()))
            .await;
    let mut drain2_resp = drain2_resp;
    let drain2_json: Value = drain2_resp.take_json().await.unwrap();
    assert!(
        drain2_json["welcomes"].as_array().unwrap().is_empty(),
        "second drain must return zero welcomes (delivered_at flag): {drain2_json}"
    );

    // ── 5. MLS commits no longer have a dedicated REST surface ──
    // The dedicated `POST /_cokret/self/mls/commits` endpoint was removed in
    // W1C; clients now submit `ck.mls.commit` events via the canonical
    // `POST /_cokret/self/events` pipeline (ck.self.events.submit of the registered
    // durable `ck.mls.commit` kind). The reducer-level epoch-bump path is
    // covered by unit tests in `reducer::mls`. We deliberately do not
    // re-exercise it here from the HTTP layer.
}
