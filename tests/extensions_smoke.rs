//! G3.S9 — integration smoke for the four new extensions routes.
//!
//! Per `cotest/e2e/scenarios/extensions/applet-bridge.md`,
//! `cotest/e2e/scenarios/identity/tsp-bootstrap.md`, and the existing
//! cotest fixture mocks (`cotest/e2e/mocks/mock-applet-registry.mjs`,
//! `cotest/e2e/mocks/mock-tsp-endpoint.mjs`). The integration test
//! posts to each route and verifies the spec-shaped envelope.

use std::net::SocketAddr;

use cokret_sdk::{
    AppletNamespaceEntry, AppletPackage, AppletWireNamespaces, Did, Ed25519MoveSigner, Hash,
};
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use soland::config::{AppConfig, FederationPolicy, ObjectStorageConfig};
use soland::db::Db;
use soland::service;
use soland::state::AppState;

fn test_config() -> AppConfig {
    AppConfig {
        bind: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        metrics_bind: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        public_base_url: "http://server".to_owned(),
        service_did: "did:web:soland.local".to_owned(),
        tls_cert_path: None,
        tls_key_path: None,
        database_url: None,
        object_storage: ObjectStorageConfig::local(
            std::env::temp_dir().join("soland-extensions-smoke"),
        ),
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
        compaction_prune_walk_per_realm_limit: 50,
        seed_demo_data: true,
        trust_domain: "ck:trust_domain:soland.local".to_owned(),
        sovereign_enclave_enabled: false,
        sovereign_enclave_allowed_outbound_hosts: Vec::new(),
        erasure_propagation_window_ms: 604_800_000,
        log_format: soland::config::LogFormat::Plain,
    }
}

async fn dev_token(state: AppState) -> String {
    let login: Value = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&json!({
            "actor": "did:web:alice.example",
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "display_name": "Alice"
        }))
        .send(&service(state))
        .await
        .take_json()
        .await
        .unwrap();
    login["access_token"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn applet_protocol_describe_smoke() {
    let state = AppState::new(test_config(), Db { pool: None });
    let app = service(state);

    let ping: Value = TestClient::get("http://server/_cokret/edge/applet/ping")
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(ping["ok"], json!(true));

    let describe: Value = TestClient::get("http://server/_cokret/edge/applet/describe")
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(describe["contract"], json!("ck.applet.v1"));
    assert_eq!(
        describe["install"]["commit_path"],
        json!("/_cokret/self/applets/install")
    );
    assert_eq!(
        describe["transaction_path"],
        json!("/_cokret/edge/applet/transactions")
    );
}

#[tokio::test]
async fn applet_install_package_registers_bot_projection_smoke() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let realm_id = cokret_sdk::new_prefixed_uuid7("ck:realm:");
    let applet_id = format!("applet:bridge:install-{suffix}");
    let namespace = format!("bridge.install.{suffix}");
    let package = signed_applet_package(&applet_id, &namespace);

    let install = install_applet_package(
        &app,
        &token,
        &package,
        &realm_id,
        &format!("install-{suffix}"),
    )
    .await;
    assert_eq!(install["effective_status"], json!("installed"));
    assert_eq!(install["applet_id"], json!(applet_id));
    let bot_actor_id = install["bot_actor_id"].as_str().unwrap().to_owned();
    assert_eq!(bot_actor_id, package.bot_actor_id.to_string());

    let projection_events = state
        .persistence
        .projection_events()
        .snapshot_all()
        .await
        .unwrap();
    assert!(
        projection_events.iter().any(|event| {
            event.event_kind == "ck.applet.registration"
                && event.payload["applet_id"] == json!(applet_id)
                && event.payload["bot_actor_id"] == json!(bot_actor_id)
        }),
        "install must append ck.applet.registration projection"
    );

    let bot_doc = canonical_did_document(&app, &bot_actor_id).await;
    assert_eq!(bot_doc["id"], json!(bot_actor_id));
    assert_eq!(bot_doc["status"], json!("active"));
    assert_eq!(bot_doc["applet_id"], json!(applet_id));
}

async fn canonical_did_document(app: &salvo::Service, did: &str) -> Value {
    let body: Value = TestClient::get(format!(
        "http://server/_cokret/root/identity/document?did={did}"
    ))
    .send(app)
    .await
    .take_json()
    .await
    .unwrap();
    body["did_document"].clone()
}

#[tokio::test]
async fn applet_bridge_register_ghost_route_revoke_smoke() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let applet_id = format!("applet:bridge:smoke-{suffix}");
    let namespace = format!("bridge.smoke.{suffix}");
    let package = signed_applet_package(&applet_id, &namespace);
    let space_id = cokret_sdk::new_prefixed_uuid7("ck:realm:");
    let install = install_applet_package(
        &app,
        &token,
        &package,
        &space_id,
        &format!("bridge-{suffix}"),
    )
    .await;
    assert_eq!(install["effective_status"], json!("installed"));
    let bot_actor_did = install["bot_actor_id"].as_str().unwrap().to_owned();

    let ghost: Value = TestClient::post("http://server/_cokret/edge/applet/transactions")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "applet_id": applet_id,
            "realm_id": space_id,
            "external_user": {"id": "ext-user-x", "display_name": "External X"},
            "payload": {"kind": "message", "text": format!("hi from outside {suffix}")},
        }))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(ghost["ok"], json!(true), "transaction response: {ghost}");
    let ghost_actor_did = ghost["ghost_actor_did"].as_str().unwrap().to_owned();
    assert!(ghost_actor_did.starts_with("did:web:ghost-ext-user-x-"));
    assert!(
        ghost["message_id"]
            .as_str()
            .unwrap()
            .starts_with("ck:message:")
    );
    assert!(
        ghost["accountability"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["kind"] == "bot_actor" && entry["did"] == bot_actor_did)
    );
    let messages = state
        .persistence
        .messages()
        .list_for_space(&space_id, 10)
        .await
        .unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].sender, ghost_actor_did);
    assert_eq!(
        messages[0].content["portal"]["bot_actor_did"],
        json!(bot_actor_did)
    );

    let ghost_doc = canonical_did_document(&app, &ghost_actor_did).await;
    assert_eq!(ghost_doc["id"], json!(ghost_actor_did));
    assert_eq!(ghost_doc["status"], json!("active"));
    assert!(
        ghost_doc["accountability"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["kind"] == "applet_registry"
                && entry["did"] == package.controller_did.to_string())
    );

    let revoke: Value = TestClient::post(format!(
        "http://server/_cokret/self/applets/{applet_id}/revoke"
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .json(&json!({
        "effective_scope": {"kind": "realm", "realm_id": space_id},
        "registration_epoch": package.registration_epoch.clone(),
        "reason": "smoke-test",
    }))
    .send(&app)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(revoke["status"], json!("revoked"));

    let rejected: Value = TestClient::post("http://server/_cokret/edge/applet/transactions")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "applet_id": applet_id,
            "realm_id": space_id,
            "external_id": "ext-user-x",
            "payload": {"kind": "message", "text": "after revoke"},
        }))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(rejected["error"]["code"], json!("applet_revoked"));

    let revoked_doc = canonical_did_document(&app, &ghost_actor_did).await;
    assert_eq!(revoked_doc["status"], json!("revoked"));

    let bot_rejected: Value = TestClient::post("http://server/_cokret/edge/applet/transactions")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "applet_id": applet_id,
            "realm_id": space_id,
            "payload": {"kind": "message", "text": "bot after revoke"},
        }))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(bot_rejected["error"]["code"], json!("bot_actor_revoked"));
}

#[tokio::test]
async fn tsp_transport_route_audit_smoke() {
    // Smoke test uses unique transport_id / route_id strings
    // (`tspt:alice-smoke`, `rt:alice-bob-smoke`) so it doesn't
    // collide with parallel test binaries.
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state);

    // 1) declare a transport
    let transport: Value = TestClient::post("http://server/_soland/self/extensions/tsp/transports")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "transport_id": "tspt:alice-smoke",
            "transport_type": "tsp-pairwise",
            "endpoint_url": "https://alice.example/tsp",
            "supported_protocols": ["cokret"]
        }))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(transport["transport_id"], json!("tspt:alice-smoke"));

    // 2) list transports
    let list: Value = TestClient::get("http://server/_soland/self/extensions/tsp/transports")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        list["transports"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["transport_id"] == json!("tspt:alice-smoke")),
        "smoke transport should appear in listing, got: {list}"
    );

    // 3) establish a route
    let route: Value = TestClient::post("http://server/_soland/self/extensions/tsp/routes")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "route_id": "rt:alice-bob-smoke",
            "destination_actor_did": "did:web:bob.example",
            "via_transports": ["tspt:alice-smoke"]
        }))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(route["route_id"], json!("rt:alice-bob-smoke"));
    assert_eq!(route["destination_actor_did"], json!("did:web:bob.example"));

    // 4) fetch the audit chain — establish_route auto-appends one entry
    let audit: Value = TestClient::get(
        "http://server/_soland/self/extensions/tsp/routes/rt:alice-bob-smoke/audit",
    )
    .add_header("Authorization", format!("Bearer {token}"), true)
    .send(&app)
    .await
    .take_json()
    .await
    .unwrap();
    let entries = audit["entries"].as_array().unwrap();
    assert!(
        !entries.is_empty(),
        "audit chain should have at least the route_established entry"
    );
    assert_eq!(entries[0]["event_kind"], json!("route_established"));
}

fn signed_applet_package(applet_id: &str, namespace: &str) -> AppletPackage {
    let controller_did = Did::new("did:web:registry.example".to_owned()).unwrap();
    let service_did = Did::new(format!(
        "did:web:{}.applet.example",
        safe_did_token(namespace)
    ))
    .unwrap();
    let bot_actor_id = Did::new(format!(
        "did:web:bot-{}.soland.local",
        safe_did_token(namespace)
    ))
    .unwrap();
    let registration_epoch = Hash::new(format!("sha256:{}", "42".repeat(32))).unwrap();
    let mut package = AppletPackage::new(
        format!("package:{applet_id}"),
        applet_id.to_owned(),
        service_did,
        controller_did.clone(),
        format!("https://{}.applet.example", safe_did_token(namespace)),
        bot_actor_id,
        vec!["cokret.portal".to_owned()],
        AppletWireNamespaces {
            handles: vec![AppletNamespaceEntry::exclusive(namespace.to_owned())],
            ..Default::default()
        },
        registration_epoch,
    );
    package.requested_scopes = vec![
        "ck.message.create".to_owned(),
        "ck.applet.ghost.provision".to_owned(),
    ];
    package.endpoint_set = json!({
        "transactions": "/_cokret/edge/applet/transactions",
        "actors": "/_cokret/edge/applet/actors/{actor_id}",
        "realms": "/_cokret/edge/applet/realms/{realm_id_or_alias}",
    });
    package.ghost_policy = json!({
        "allow_ghost_actors": true,
        "accountability": ["bot_actor", "applet_registry"],
    });
    package.receive_events = true;
    package.receive_ephemeral = true;
    package.seal().unwrap();
    let verification_method = format!("{controller_did}#applet-package");
    let signer =
        Ed25519MoveSigner::from_did_key_seed([13u8; 32], controller_did, &verification_method);
    package.sign(&signer, &verification_method).unwrap();
    package
}

async fn install_applet_package(
    app: &salvo::Service,
    token: &str,
    package: &AppletPackage,
    realm_id: &str,
    idempotency_key: &str,
) -> Value {
    let effective_scope = json!({"kind": "realm", "realm_id": realm_id});
    let preview: Value = TestClient::post("http://server/_cokret/self/applets/install/preview")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "applet_package": package,
            "effective_scope": effective_scope,
            "approval_request": {
                "approve_actions": package.requested_scopes.clone(),
                "allow_ghost_actors": true,
            },
        }))
        .send(app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        preview["schema"],
        json!("ck.schema.applet_install_plan.v1"),
        "install preview: {preview}"
    );

    let commit: Value = TestClient::post("http://server/_cokret/self/applets/install")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", idempotency_key.to_owned(), true)
        .json(&json!({
            "plan_digest": preview["plan_digest"].clone(),
            "applet_package": package,
            "effective_scope": {"kind": "realm", "realm_id": realm_id},
            "approved_scopes": preview["approved_scopes"].clone(),
            "actor_policy": {
                "bot_membership": "join",
                "ghost_actor_mode": "policy_declared",
            },
            "e2ee_policy": {"allow_mls_join": false},
            "widget_policy": {"allow_widget": false},
        }))
        .send(app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(commit["ok"], json!(true), "install commit: {commit}");
    commit
}

fn safe_did_token(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '.' {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}
