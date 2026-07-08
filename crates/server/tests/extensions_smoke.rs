//! G3.S9 — integration smoke for the four new extensions routes.
//!
//! Per `cotest/e2e/scenarios/extensions/applet-bridge.md`,
//! `cotest/e2e/scenarios/identity/tsp-bootstrap.md`, and the existing
//! cotest fixture mocks (`cotest/e2e/mocks/mock-applet-registry.mjs`,
//! `cotest/e2e/mocks/mock-tsp-endpoint.mjs`). The integration test
//! posts to each route and verifies the spec-shaped envelope.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use base64::Engine as _;
use cokret_sdk::applet::WebhookSignatureAlg;
use cokret_sdk::{
    AppletNamespaceEntry, AppletPackage, AppletWireNamespaces, Did, Ed25519MoveSigner, Hash,
    WebhookAuth,
};
use ed25519_dalek::{Signer, SigningKey};
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use soland::config::{AppConfig, IceServersConfig, LiveKitConfig, ObjectStorageConfig};
use soland::service;
use soland::state::AppState;
use soland_data::Db;

const DEMO_REALM_ID: &str = "ck:realm:0196419b-0000-7000-8000-000000000000";

fn test_config() -> AppConfig {
    AppConfig {
        object_storage: ObjectStorageConfig::local(
            std::env::temp_dir().join("soland-extensions-smoke"),
        ),
        development_mode: true,
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: std::collections::BTreeMap::new(),
        seed_demo_data: true,
        ..AppConfig::test_default()
    }
}

async fn dev_token(state: AppState) -> String {
    state.hydrate().await.unwrap();
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
    login["session_credential"].as_str().unwrap().to_owned()
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
        describe["install"]["ghost_actor_provision_path"],
        json!("/_cokret/self/applets/{applet_id}/ghosts/provision")
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
    let realm_id = DEMO_REALM_ID;
    let applet_id = cokret_sdk::new_prefixed_uuid7("ck:applet:");
    let namespace = format!("bridge.install.{suffix}");
    let package = signed_applet_package(&applet_id, &namespace);
    ingest_applet_service_did_document(&state, &package).await;

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

    let stored_applet = state
        .persistence
        .applets()
        .get(&applet_id)
        .await
        .unwrap()
        .expect("applet record is durable");
    let execution = &stored_applet["install_execution"];
    assert_eq!(execution["status"], json!("completed"));
    assert_eq!(
        execution["idempotency_key"],
        json!(format!("install-{suffix}"))
    );
    assert_eq!(
        execution["produced_event_refs"][0],
        install["registration_event_ref"]
    );
    let steps = execution["steps"].as_array().unwrap();
    assert_eq!(
        steps[0]["target_event_kind"],
        json!("ck.applet.registration")
    );
    assert_eq!(steps[0]["status"], json!("accepted"));
    assert_eq!(steps[0]["event_ref"], install["registration_event_ref"]);
    assert!(steps.iter().any(
        |step| step["target_event_kind"] == json!("ck.capability.grant")
            && step["grant_binding"]["registration_epoch"]
                == json!(package.registration_epoch.to_string())
    ));

    let bot_doc = canonical_did_document(&app, &bot_actor_id).await;
    assert_eq!(bot_doc["id"], json!(bot_actor_id));
    assert_eq!(bot_doc["status"], json!("active"));
    assert_eq!(bot_doc["applet_id"], json!(applet_id));
}

#[tokio::test]
async fn applet_ghost_actor_provision_writes_durable_profile_and_grant_events() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let applet_id = cokret_sdk::new_prefixed_uuid7("ck:applet:");
    let namespace = format!("bridge.provision.{suffix}");
    let package = signed_applet_package(&applet_id, &namespace);
    ingest_applet_service_did_document(&state, &package).await;
    let realm_id = DEMO_REALM_ID;
    let install = install_applet_package(
        &app,
        &token,
        &package,
        &realm_id,
        &format!("ghost-provision-{suffix}"),
    )
    .await;
    assert_eq!(install["effective_status"], json!("installed"));

    let ghost_actor_id = format!(
        "did:web:{}.applet.example:ghost:u123",
        safe_did_token(&namespace)
    );
    let mut response = TestClient::post(format!(
        "http://server/_cokret/self/applets/{applet_id}/ghosts/provision"
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .json(&json!({
        "schema": "ck.applet.ghost_actor.provision_request.v1",
        "applet_id": applet_id,
        "service_did": package.service_did.to_string(),
        "ghost_actor_id": ghost_actor_id,
        "protocol": "slack",
        "tenant": "T123",
        "external_user_id": "U123",
        "display_name": "Alice on Slack",
        "realm_id": realm_id,
        "external_ref": {
            "team_id": "T123",
            "user_id": "U123"
        }
    }))
    .send(&app)
    .await;
    assert_eq!(response.status_code.unwrap(), StatusCode::CREATED);
    let provision: Value = response.take_json().await.unwrap();
    assert_eq!(provision["ghost_actor_id"], json!(ghost_actor_id));
    assert_eq!(provision["display_name"], json!("Alice on Slack"));
    let profile_event_ref = provision["profile_event_ref"].as_str().unwrap();
    let accountability_grant_ref = provision["accountability_grant_ref"].as_str().unwrap();
    let authorization_ref = provision["authorization_ref"].as_str().unwrap();
    assert!(profile_event_ref.starts_with("ck:event:"));
    assert!(accountability_grant_ref.starts_with("ck:event:"));
    assert_eq!(authorization_ref, accountability_grant_ref);

    let profile_event = state
        .persistence
        .events()
        .get(profile_event_ref)
        .await
        .unwrap()
        .expect("profile event is durable");
    assert_eq!(profile_event.kind, "ck.profile.create");
    assert_eq!(profile_event.actor_id, ghost_actor_id);
    assert_eq!(
        profile_event.envelope["executed_by"],
        json!(package.service_did.to_string())
    );
    assert_eq!(
        profile_event.envelope["authorization_ref"],
        json!(authorization_ref)
    );
    // The applet binding is carried by `executed_by` + `authorization_ref`
    // (CKP-0008/0009 delegated authorization) and by the profile's
    // `managed_by_applet` below — NOT by a top-level envelope `applet_id`.
    // `event-envelope.schema.json` is `additionalProperties:false` and has no
    // `applet_id`, so asserting one here contradicts the canonical wire shape.
    assert_eq!(
        profile_event.envelope["payload"]["object"]["profile_fields"]["managed_by_applet"],
        json!(applet_id)
    );
    assert_eq!(
        profile_event.envelope["payload"]["object"]["profile_fields"]["external_ref"]["external_user_id"],
        json!("U123")
    );
    assert!(
        profile_event.envelope["payload"]["object"]["accountable_principal_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|did| did == &json!(package.service_did.to_string()))
    );
    assert_eq!(
        profile_event.envelope["proofs"][0]["kind"],
        json!("detached_jws")
    );

    let grant_event = state
        .persistence
        .events()
        .get(accountability_grant_ref)
        .await
        .unwrap()
        .expect("accountability grant event is durable");
    assert_eq!(grant_event.kind, "ck.identity.accountability_grant");
    assert_eq!(grant_event.actor_id, package.service_did.to_string());
    assert_eq!(
        grant_event.envelope["payload"]["issuer"],
        json!(package.service_did.to_string())
    );
    assert_eq!(
        grant_event.envelope["payload"]["subject"],
        json!(ghost_actor_id)
    );
    assert_eq!(
        grant_event.envelope["payload"]["proof"]["kind"],
        json!("detached_jws")
    );

    let projection_events = state
        .persistence
        .projection_events()
        .snapshot_all()
        .await
        .unwrap();
    assert!(projection_events.iter().any(|event| {
        event.event_id == profile_event_ref && event.event_kind == "ck.profile.create"
    }));
    assert!(projection_events.iter().any(|event| {
        event.event_id == accountability_grant_ref
            && event.event_kind == "ck.identity.accountability_grant"
    }));
}

#[tokio::test]
async fn applet_ghost_actor_provision_requires_approved_ghost_scope() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let applet_id = cokret_sdk::new_prefixed_uuid7("ck:applet:");
    let namespace = format!("bridge.no-ghost-scope.{suffix}");
    let package = signed_applet_package(&applet_id, &namespace);
    ingest_applet_service_did_document(&state, &package).await;
    let realm_id = DEMO_REALM_ID;
    let install = install_applet_package_with_approved_actions(
        &app,
        &token,
        &package,
        &realm_id,
        &format!("ghost-denied-{suffix}"),
        vec!["ck.message.create".to_owned()],
    )
    .await;
    assert_eq!(install["effective_status"], json!("partially_installed"));

    let ghost_actor_id = format!(
        "did:web:{}.applet.example:ghost:u-denied",
        safe_did_token(&namespace)
    );
    let rejected: Value = TestClient::post(format!(
        "http://server/_cokret/self/applets/{applet_id}/ghosts/provision"
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .json(&json!({
        "schema": "ck.applet.ghost_actor.provision_request.v1",
        "applet_id": applet_id,
        "service_did": package.service_did.to_string(),
        "ghost_actor_id": ghost_actor_id,
        "protocol": "slack",
        "tenant": "T123",
        "external_user_id": "U-denied",
        "realm_id": realm_id,
        "external_ref": {"team_id": "T123", "user_id": "U-denied"}
    }))
    .send(&app)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(rejected["error"]["code"], json!("capability_denied"));
}

#[tokio::test]
async fn applet_ghost_actor_provision_rejects_actor_namespace_mismatch() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let applet_id = cokret_sdk::new_prefixed_uuid7("ck:applet:");
    let namespace = format!("bridge.namespace.{suffix}");
    let package = signed_applet_package(&applet_id, &namespace);
    ingest_applet_service_did_document(&state, &package).await;
    let realm_id = DEMO_REALM_ID;
    let install = install_applet_package(
        &app,
        &token,
        &package,
        &realm_id,
        &format!("ghost-namespace-{suffix}"),
    )
    .await;
    assert_eq!(install["effective_status"], json!("installed"));

    let rejected: Value = TestClient::post(format!(
        "http://server/_cokret/self/applets/{applet_id}/ghosts/provision"
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .json(&json!({
        "schema": "ck.applet.ghost_actor.provision_request.v1",
        "applet_id": applet_id,
        "service_did": package.service_did.to_string(),
        "ghost_actor_id": "did:web:other.applet.example:ghost:u123",
        "protocol": "slack",
        "tenant": "T123",
        "external_user_id": "U123",
        "realm_id": realm_id,
        "external_ref": {"team_id": "T123", "user_id": "U123"}
    }))
    .send(&app)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        rejected["error"]["code"],
        json!("applet_namespace_mismatch")
    );
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
    body.pointer("/did_document/document")
        .or_else(|| body.get("did_document"))
        .cloned()
        .filter(|value| !value.is_null())
        .filter(|value| value.get("id").is_some())
        .unwrap_or(body)
}

async fn post_signed_applet_message_transaction(
    app: &salvo::Service,
    package: &AppletPackage,
    applet_id: &str,
    actor_id: &str,
    realm_id: &str,
    authorization_ref: &str,
    text: &str,
    idempotency_key: &str,
) -> Value {
    let event = applet_message_event(
        package,
        applet_id,
        actor_id,
        realm_id,
        authorization_ref,
        text,
    );
    let body = json!({
        "source_service_did": package.service_did.to_string(),
        "events": [event],
    });
    let body_bytes = cokret_sdk::canonical::canonical_json_bytes(&body).unwrap();
    let content_digest = content_digest_header(&body_bytes);
    let verification_method = format!("{}#applet-service-key", package.service_did);
    let created = chrono::Utc::now().timestamp();
    let signature_params = format!(
        "(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \
         \"source-service-did\" \"destination-service-did\" \"idempotency-key\");\
         created={created};expires={};keyid=\"{verification_method}\";alg=\"ed25519\"",
        created + 60
    );
    let signature_base = applet_signature_base(
        &content_digest,
        package.service_did.as_str(),
        "did:web:soland.local",
        idempotency_key,
        &signature_params,
    );
    let signing_key = applet_service_signing_key(&verification_method);
    let signature = signing_key.sign(signature_base.as_bytes());
    let signature_header = format!(
        "sig1=:{}:",
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    );
    TestClient::post("http://server/_cokret/edge/applet/transactions")
        .add_header("Content-Digest", content_digest, true)
        .add_header("Source-Service-DID", package.service_did.to_string(), true)
        .add_header("Destination-Service-DID", "did:web:soland.local", true)
        .add_header("Idempotency-Key", idempotency_key.to_owned(), true)
        .add_header("Signature-Input", format!("sig1={signature_params}"), true)
        .add_header("Signature", signature_header, true)
        .json(&body)
        .send(app)
        .await
        .take_json()
        .await
        .unwrap()
}

fn applet_message_event(
    package: &AppletPackage,
    applet_id: &str,
    actor_id: &str,
    realm_id: &str,
    authorization_ref: &str,
    text: &str,
) -> Value {
    let now = chrono::Utc::now();
    let created_at = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let payload = json!({
        "strand_id": strand_id_for_realm(realm_id),
        "track_name": "discussion",
        "content": {
            "kind": "ck.content.text",
            "body": text,
        },
    });
    let mut event = json!({
        "event_id": cokret_sdk::new_prefixed_uuid7("ck:event:"),
        "kind": "ck.message.create",
        "realm_id": realm_id,
        "actor_id": actor_id,
        "actor_seq": 1,
        "created_at": created_at,
        "hlc": format!("{:012x}-0000-00000000", now.timestamp_millis().max(0) as u64),
        "prev_refs": [],
        "refs": [],
        "payload": payload,
        "executed_by": package.service_did.to_string(),
        "authorization_ref": authorization_ref,
        "applet_id": applet_id,
        "external_ref": {
            "protocol": "smoke",
            "external_id": actor_id,
        },
        "proofs": [],
    });
    let event_digest = canonical_event_digest(&event);
    event["proofs"] = json!([{
        "kind": "detached_jws",
        "alg": "EdDSA",
        "verification_method": format!("{}#applet-service-key", package.service_did),
        "event_digest": event_digest,
        "created_at": created_at,
        "jws": "dev-mode-fixture"
    }]);
    event
}

fn canonical_event_digest(event: &Value) -> String {
    let mut canonical = event.clone();
    if let Value::Object(object) = &mut canonical {
        object.remove("proofs");
        object.remove("unsigned");
        object.remove("canonical_digest");
        object.remove("canonical_hash");
    }
    let bytes = cokret_sdk::canonical::canonical_json_bytes(&canonical).unwrap();
    cokret_sdk::canonical::sha256_digest(&bytes)
}

fn content_digest_header(bytes: &[u8]) -> String {
    let raw = Sha256::digest(bytes);
    format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(raw)
    )
}

fn applet_signature_base(
    content_digest: &str,
    source_service_did: &str,
    destination_service_did: &str,
    idempotency_key: &str,
    signature_params: &str,
) -> String {
    format!(
        "\"@method\": POST\n\
         \"@target-uri\": http://server/_cokret/edge/applet/transactions\n\
         \"@authority\": server\n\
         \"content-digest\": {content_digest}\n\
         \"source-service-did\": {source_service_did}\n\
         \"destination-service-did\": {destination_service_did}\n\
         \"idempotency-key\": {idempotency_key}\n\
         \"@signature-params\": {signature_params}",
    )
}

fn applet_service_signing_key(verification_method: &str) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"soland:applet-service-key:");
    hasher.update(verification_method.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&seed)
}

fn strand_id_for_realm(realm_id: &str) -> String {
    realm_id
        .strip_prefix("ck:realm:")
        .map(|suffix| format!("ck:strand:{suffix}"))
        .unwrap_or_else(|| "ck:strand:01904100-0000-7000-8000-f10dc0000001".to_owned())
}

#[tokio::test]
async fn applet_bridge_register_ghost_route_revoke_smoke() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let applet_id = cokret_sdk::new_prefixed_uuid7("ck:applet:");
    let namespace = format!("bridge.smoke.{suffix}");
    let package = signed_applet_package(&applet_id, &namespace);
    ingest_applet_service_did_document(&state, &package).await;
    let realm_id = DEMO_REALM_ID;
    let install = install_applet_package(
        &app,
        &token,
        &package,
        &realm_id,
        &format!("bridge-{suffix}"),
    )
    .await;
    assert_eq!(install["effective_status"], json!("installed"));
    let bot_actor_id = install["bot_actor_id"].as_str().unwrap().to_owned();
    let message_grant_ref =
        capability_grant_ref_for_action(&install, &package.requested_scopes, "ck.message.create");

    let ghost_actor_id = format!(
        "did:web:{}.applet.example:ghost:ext-user-x",
        safe_did_token(&namespace)
    );
    let mut provision_response = TestClient::post(format!(
        "http://server/_cokret/self/applets/{applet_id}/ghosts/provision"
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .json(&json!({
        "schema": "ck.applet.ghost_actor.provision_request.v1",
        "applet_id": applet_id,
        "service_did": package.service_did.to_string(),
        "ghost_actor_id": ghost_actor_id,
        "protocol": "smoke",
        "tenant": "T-smoke",
        "external_user_id": "ext-user-x",
        "display_name": "External X",
        "realm_id": realm_id,
        "external_ref": {"tenant": "T-smoke", "user_id": "ext-user-x"}
    }))
    .send(&app)
    .await;
    assert_eq!(provision_response.status_code.unwrap(), StatusCode::CREATED);
    let provision: Value = provision_response.take_json().await.unwrap();
    assert_eq!(provision["ghost_actor_id"], json!(ghost_actor_id));

    let transaction = post_signed_applet_message_transaction(
        &app,
        &package,
        &applet_id,
        &ghost_actor_id,
        &realm_id,
        &message_grant_ref,
        &format!("hi from outside {suffix}"),
        &format!("tx-{suffix}"),
    )
    .await;
    assert_eq!(
        transaction["ok"],
        json!(true),
        "transaction response: {transaction}"
    );
    let messages = state
        .persistence
        .messages()
        .list_for_realm(&realm_id, 10)
        .await
        .unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].sender, ghost_actor_id);
    assert_eq!(
        messages[0].content["body"],
        json!(format!("hi from outside {suffix}"))
    );

    let ghost_doc = canonical_did_document(&app, &ghost_actor_id).await;
    assert_eq!(ghost_doc["id"], json!(ghost_actor_id));
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
        "effective_scope": {"kind": "realm", "realm_id": realm_id},
        "reason_code": "smoke_test",
        "revoke_mode": "revoke_all",
    }))
    .send(&app)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(revoke["ok"], json!(true));

    let rejected = post_signed_applet_message_transaction(
        &app,
        &package,
        &applet_id,
        &ghost_actor_id,
        &realm_id,
        &message_grant_ref,
        "after revoke",
        &format!("tx-after-revoke-{suffix}"),
    )
    .await;
    assert_eq!(
        rejected["error"]["code"],
        json!("applet_registration_unauthorized")
    );

    let revoked_doc = canonical_did_document(&app, &ghost_actor_id).await;
    assert_eq!(revoked_doc["status"], json!("revoked"));
    assert!(bot_actor_id.starts_with("did:web:bot-"));
}

fn capability_grant_ref_for_action(
    install: &Value,
    approved_actions: &[String],
    action: &str,
) -> String {
    let mut actions = approved_actions.to_vec();
    actions.sort();
    actions.dedup();
    let index = actions
        .iter()
        .position(|candidate| candidate == action)
        .expect("approved action exists");
    install["capability_grant_refs"][index]
        .as_str()
        .expect("grant ref exists")
        .to_owned()
}

#[tokio::test]
async fn tsp_local_stub_routes_are_not_mounted() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state);

    let rejected: Value = TestClient::post("http://server/_soland/self/extensions/tsp/transports")
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
    assert_eq!(rejected["error"]["code"], json!("unrecognized_endpoint"));
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
            actors: vec![AppletNamespaceEntry::exclusive(format!(
                "did:web:{}.applet.example:ghost:*",
                safe_did_token(namespace)
            ))],
            handles: vec![AppletNamespaceEntry::exclusive(namespace.to_owned())],
            ..Default::default()
        },
        registration_epoch,
    );
    package.webhook_auth = WebhookAuth::http_message_signature(
        format!("{}#applet-service-key", package.service_did),
        vec![WebhookSignatureAlg::EdDsa],
    );
    let service_document = applet_service_did_document(&package);
    package.registration_epoch_evidence = Some(
        cokret_sdk::AppletRegistrationEpochEvidence::from_did_document(&service_document, None)
            .unwrap(),
    );
    package.requested_scopes = vec![
        "ck.message.create".to_owned(),
        "ck.applet.ghost.provision".to_owned(),
    ];
    package.endpoint_policy = cokret_sdk::applet::AppletEndpointPolicy {
        extra: BTreeMap::from([
            (
                "transactions".to_owned(),
                json!("/_cokret/edge/applet/transactions"),
            ),
            (
                "actors".to_owned(),
                json!("/_cokret/edge/applet/actors/{actor_id}"),
            ),
            (
                "realms".to_owned(),
                json!("/_cokret/edge/applet/realms/{realm_id_or_alias}"),
            ),
        ]),
        ..Default::default()
    };
    package.ghost_policy = cokret_sdk::applet::AppletGhostPolicy {
        enabled: true,
        accountability_template: Some("bot_actor_and_applet_registry".to_owned()),
        ..Default::default()
    };
    package.receive_events = true;
    package.receive_ephemeral = true;
    package.seal().unwrap();
    let verification_method = format!("{controller_did}#applet-package");
    let signer =
        Ed25519MoveSigner::from_did_key_seed([13u8; 32], controller_did, &verification_method);
    package.sign(&signer, &verification_method).unwrap();
    package
}

fn applet_service_did_document(package: &AppletPackage) -> cokret_sdk::identity::DidDocument {
    cokret_sdk::identity::DidDocument {
        id: package.service_did.clone(),
        verification_methods: BTreeMap::from([(
            package.webhook_auth.key_ref.clone(),
            "dev-applet-service-key-material".to_owned(),
        )]),
        also_known_as: Vec::new(),
        updated_at: package.created_at,
    }
}

async fn ingest_applet_service_did_document(state: &AppState, package: &AppletPackage) {
    let now = chrono::Utc::now();
    let document = applet_service_did_document(package);
    state
        .persistence
        .webvh()
        .put_document(soland::state::WebvhDocumentRecord {
            did: package.service_did.to_string(),
            did_document: serde_json::to_value(document).unwrap(),
            key_log_head: Some(package.registration_epoch.to_string()),
            seq: 1,
            method_evidence: json!({ "mode": "test_fixture" }),
            fetched_at: now,
            expires_at: now + chrono::Duration::minutes(15),
            updated_at: now,
        })
        .await
        .unwrap();
}

async fn install_applet_package(
    app: &salvo::Service,
    token: &str,
    package: &AppletPackage,
    realm_id: &str,
    idempotency_key: &str,
) -> Value {
    install_applet_package_with_approved_actions(
        app,
        token,
        package,
        realm_id,
        idempotency_key,
        package.requested_scopes.clone(),
    )
    .await
}

async fn install_applet_package_with_approved_actions(
    app: &salvo::Service,
    token: &str,
    package: &AppletPackage,
    realm_id: &str,
    idempotency_key: &str,
    approve_actions: Vec<String>,
) -> Value {
    let effective_scope = json!({"kind": "realm", "realm_id": realm_id});
    let allow_ghost_actors = approve_actions
        .iter()
        .any(|action| action == "ck.applet.ghost.provision");
    let preview: Value = TestClient::post("http://server/_cokret/self/applets/install/preview")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "applet_package": package,
            "effective_scope": effective_scope,
            "approval_request": {
                "approve_actions": approve_actions,
                "allow_ghost_actors": allow_ghost_actors,
                "allow_delegated_native_actors": false,
                "allow_e2ee_join": false,
                "allow_widget": false,
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
