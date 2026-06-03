//! G3.S9 — integration smoke for the four new extensions routes.
//!
//! Per `cotest/e2e/scenarios/extensions/applet-bridge.md`,
//! `cotest/e2e/scenarios/identity/tsp-bootstrap.md`, and the existing
//! cotest fixture mocks (`cotest/e2e/mocks/mock-applet-registry.mjs`,
//! `cotest/e2e/mocks/mock-tsp-endpoint.mjs`). The integration test
//! posts to each route and verifies the spec-shaped envelope.

use std::net::SocketAddr;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use soland::config::{AppConfig, FederationPolicy, ObjectStorageConfig};
use soland::db::Db;
use soland::state::AppState;
use soland::{routing, service};

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
        compaction_prune_walk_per_space_limit: 50,
        seed_demo_data: true,
        trust_domain: "ck:trust_domain:soland.local".to_owned(),
        sovereign_enclave_enabled: false,
        sovereign_enclave_allowed_outbound_hosts: Vec::new(),
        erasure_propagation_window_ms: 604_800_000,
        log_format: soland::config::LogFormat::Plain,
    }
}

async fn dev_token(state: AppState) -> String {
    let login: Value = TestClient::post("http://server/_cokret/gate/auth/dev-login")
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
async fn applet_manifest_verify_smoke() {
    // Build a freshly-signed manifest and verify it via the HTTP
    // route. We don't need an authenticated session for this route —
    // it's intentionally open so applet registries can probe before
    // committing to a Cokret account.
    let state = AppState::new(test_config(), Db { pool: None });
    let app = service(state);

    let signing = SigningKey::from_bytes(&[11u8; 32]);
    let pubkey = signing.verifying_key();
    let signer_did = "did:web:registry.example";
    let signer_public_key = URL_SAFE_NO_PAD.encode(pubkey.as_bytes());

    let mut manifest = json!({
        "id": "applet:bridge:demo-smoke",
        "version": "1.0.0",
        "signer_did": signer_did,
        "signature": "",
        "signer_public_key": signer_public_key,
        "requested_capabilities": ["realm:portal", "message:write"],
        "schema_hash": routing::extensions::applet_manifest::current_applet_schema_hash(),
        "metadata": {"namespace": "bridge.smoke"},
    });
    // Sign over the canonical body shape `manifest_signing_bytes`
    // builds. We mirror it here so the test is fully self-contained.
    let manifest_struct: routing::extensions::applet_manifest::AppletManifest =
        serde_json::from_value(manifest.clone()).unwrap();
    let signing_bytes =
        routing::extensions::applet_manifest::manifest_signing_bytes(&manifest_struct);
    let sig = signing.sign(&signing_bytes);
    manifest["signature"] = json!(URL_SAFE_NO_PAD.encode(sig.to_bytes()));

    let resp: Value = TestClient::post("http://server/_cokret/edge/applets/manifest/verify")
        .json(&json!({
            "manifest_json": manifest,
            "trusted_registry_did": signer_did,
        }))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["verified"], json!(true), "got: {resp}");
    assert_eq!(resp["signer_did"], json!(signer_did));
    assert!(resp["capabilities"].as_array().unwrap().len() >= 2);
}

#[tokio::test]
async fn bot_actor_register_then_list_smoke() {
    // Smoke test uses a unique DID per case (`did:web:bot-smoke`) so
    // it doesn't collide with parallel test binaries that share the
    // module-local registry.
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state);

    let resp: Value = TestClient::post("http://server/_cokret/self/extensions/bots")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "did": "did:web:bot-smoke",
            "name": "Smoke Bot",
            "kind": "bot"
        }))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["did"], json!("did:web:bot-smoke"));
    assert_eq!(resp["kind"], json!("bot"));
    assert_eq!(resp["owner_actor_did"], json!("did:web:alice.example"));

    let list: Value = TestClient::get("http://server/_cokret/self/extensions/bots")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    let bots = list["bots"].as_array().unwrap();
    assert!(
        bots.iter().any(|b| b["did"] == json!("did:web:bot-smoke")),
        "smoke bot should appear in listing, got: {list}"
    );

    // Revoke removes it from the listing.
    let _: Value =
        TestClient::delete("http://server/_cokret/self/extensions/bots/did:web:bot-smoke")
            .add_header("Authorization", format!("Bearer {token}"), true)
            .send(&app)
            .await
            .take_json()
            .await
            .unwrap();
    let list_after: Value = TestClient::get("http://server/_cokret/self/extensions/bots")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        !list_after["bots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["did"] == json!("did:web:bot-smoke")),
        "smoke bot should not appear in listing after revoke, got: {list_after}"
    );
}

#[tokio::test]
async fn applet_bridge_register_ghost_route_revoke_smoke() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let signer_did = "did:web:registry.example";
    let applet_id = format!("applet:bridge:smoke-{suffix}");
    let namespace = format!("bridge.smoke.{suffix}");
    let manifest = signed_applet_manifest(&applet_id, &namespace, signer_did);

    let register: Value = TestClient::post("http://server/_cokret/edge/applets/register")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", format!("idem-{suffix}"), true)
        .json(&json!({
            "manifest": manifest,
            "trusted_registry_did": signer_did,
        }))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(register["applet_id"], json!(applet_id));
    assert_eq!(register["namespace"], json!(namespace));
    assert_eq!(register["status"], json!("registered"));
    let bot_actor_did = register["bot_actor_did"].as_str().unwrap().to_owned();
    assert!(bot_actor_did.starts_with("did:web:bot-bridge-smoke-"));
    assert!(
        register["portal_realm_id"]
            .as_str()
            .unwrap()
            .starts_with("ck:realm:portal:bridge-smoke-")
    );

    let space_id = format!("ck:realm:applet-bridge-smoke-{suffix}");
    let ghost: Value = TestClient::post(format!(
        "http://server/_cokret/edge/applets/{applet_id}/ghosts"
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .json(&json!({
        "space_id": space_id,
        "external_user": {"id": "ext-user-x", "display_name": "External X"},
        "payload": {"kind": "message", "text": format!("hi from outside {suffix}")},
    }))
    .send(&app)
    .await
    .take_json()
    .await
    .unwrap();
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

    let ghost_doc: Value = TestClient::get(format!(
        "http://server/_cokret/root/identity/{ghost_actor_did}/did-document"
    ))
    .send(&app)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(ghost_doc["id"], json!(ghost_actor_did));
    assert_eq!(ghost_doc["status"], json!("active"));
    assert!(
        ghost_doc["accountability"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["kind"] == "applet_registry" && entry["did"] == signer_did)
    );

    let revoke: Value = TestClient::post(format!(
        "http://server/_cokret/edge/applets/{applet_id}/revoke"
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .json(&json!({}))
    .send(&app)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(revoke["status"], json!("revoked"));

    let rejected: Value = TestClient::post(format!(
        "http://server/_cokret/edge/applets/{applet_id}/ghosts"
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .json(&json!({
        "space_id": space_id,
        "external_id": "ext-user-x",
        "payload": {"kind": "message", "text": "after revoke"},
    }))
    .send(&app)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(rejected["error"]["code"], json!("applet_revoked"));

    let revoked_doc: Value = TestClient::get(format!(
        "http://server/_cokret/root/identity/{ghost_actor_did}/did-document"
    ))
    .send(&app)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(revoked_doc["status"], json!("revoked"));

    let bot_rejected: Value = TestClient::post(format!(
        "http://server/_cokret/edge/applets/{applet_id}/bot/messages"
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .json(&json!({
        "space_id": space_id,
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
    let transport: Value = TestClient::post("http://server/_cokret/self/extensions/tsp/transports")
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
    let list: Value = TestClient::get("http://server/_cokret/self/extensions/tsp/transports")
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
    let route: Value = TestClient::post("http://server/_cokret/self/extensions/tsp/routes")
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
        "http://server/_cokret/self/extensions/tsp/routes/rt:alice-bob-smoke/audit",
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

fn signed_applet_manifest(applet_id: &str, namespace: &str, signer_did: &str) -> Value {
    let signing = SigningKey::from_bytes(&[13u8; 32]);
    let pubkey = signing.verifying_key();
    let signer_public_key = URL_SAFE_NO_PAD.encode(pubkey.as_bytes());
    let mut manifest = json!({
        "id": applet_id,
        "version": "1.0.0",
        "signer_did": signer_did,
        "signature": "",
        "signer_public_key": signer_public_key,
        "requested_capabilities": [
            "realm:portal",
            "message:write",
            "actor:provision-ghost",
            "actor:provision-bot"
        ],
        "schema_hash": routing::extensions::applet_manifest::current_applet_schema_hash(),
        "metadata": {
            "namespace": namespace,
            "display_name": "Smoke Bridge Applet"
        },
    });
    let manifest_struct: routing::extensions::applet_manifest::AppletManifest =
        serde_json::from_value(manifest.clone()).unwrap();
    let signing_bytes =
        routing::extensions::applet_manifest::manifest_signing_bytes(&manifest_struct);
    manifest["signature"] = json!(URL_SAFE_NO_PAD.encode(signing.sign(&signing_bytes).to_bytes()));
    manifest
}
