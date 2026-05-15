use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use contrix_sdk::{Did, Hash, Operation, OperationId, Proof, SpaceId};
use ed25519_dalek::{Signer, SigningKey};
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use soland::config::{AppConfig, ObjectStorageConfig};
use soland::db::Db;
use soland::ratelimit::RateLimiterConfig;
use soland::state::AppState;
use soland::{artifacts, kinds, service, service_with_rate_limiter_config};

#[derive(Clone, Debug, Serialize)]
#[serde(transparent)]
struct CommitId(String);

impl CommitId {
    fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        (!value.trim().is_empty())
            .then_some(Self(value))
            .ok_or_else(|| "commit id must not be empty".to_owned())
    }
}

#[derive(Clone, Debug, Serialize)]
struct Commit {
    schema: String,
    commit_id: CommitId,
    #[serde(rename = "type")]
    kind: String,
    repo_id: String,
    author: Did,
    pub author_seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_commit: Option<Hash>,
    pub operations: Vec<Hash>,
    created_at: chrono::DateTime<Utc>,
    pub proofs: Vec<Proof>,
}

impl Commit {
    fn new(commit_id: CommitId, repo_id: &str, author: Did, author_seq: u64) -> Self {
        Self {
            schema: "cx.schema.commit.v1".to_owned(),
            commit_id,
            kind: "commit".to_owned(),
            repo_id: repo_id.to_owned(),
            author,
            author_seq,
            prev_commit: None,
            operations: Vec::new(),
            created_at: Utc::now(),
            proofs: Vec::new(),
        }
    }

    fn commit_digest(&self) -> Result<String, serde_json::Error> {
        let value = serde_json::to_value(self)?;
        let bytes = serde_json::to_vec(&value)?;
        let digest = Sha256::digest(bytes);
        Ok(format!("sha256:{digest:x}"))
    }
}

fn test_config() -> AppConfig {
    AppConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
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
        // Tests use fixed-time HLC fixtures; window=0 disables replay-window
        // enforcement so they keep passing.
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: std::collections::BTreeMap::new(),
        anchorer_signing_key_seed: None,
        use_keystore: false,
        federation_policy: soland::config::FederationPolicy::Mesh,
        federation_peers: Vec::new(),
        admin_default_page_limit: 100,
        admin_max_page_limit: 1000,
        admin_principal_dids: Vec::new(),
    }
}

fn test_config_with_service_did(service_did: &str) -> AppConfig {
    AppConfig {
        service_did: service_did.to_owned(),
        ..test_config()
    }
}

fn app() -> salvo::Service {
    service(AppState::new(test_config(), Db { pool: None }))
}

fn app_from_state(state: AppState) -> salvo::Service {
    service(state)
}

fn decode_cursor(token: &str) -> Value {
    let encoded = token
        .strip_prefix("cx:cursor:")
        .expect("structured cursor prefix");
    let bytes = URL_SAFE_NO_PAD.decode(encoded).expect("base64url cursor");
    serde_json::from_slice(&bytes).expect("cursor json")
}

fn encode_cursor(cursor: &Value) -> String {
    format!("cx:cursor:{}", URL_SAFE_NO_PAD.encode(cursor.to_string()))
}

async fn dev_token(state: AppState) -> String {
    dev_token_for_device(state, "did:web:alice.example", "dev_alice", "Alice Desktop").await
}

async fn dev_token_for_device(
    state: AppState,
    actor: &str,
    device_id: &str,
    display_name: &str,
) -> String {
    let login: Value = TestClient::post("http://server/api/v1/auth/dev-login")
        .json(&serde_json::json!({
            "actor": actor,
            "device_id": device_id,
            "display_name": display_name
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    login["access_token"].as_str().unwrap().to_owned()
}

fn encrypted_envelope(content_type: &str, ciphertext: &str) -> Value {
    serde_json::json!({
        "scheme": "mls-rfc9420",
        "version": 1,
        "group_id": "cx:mls:test",
        "epoch": 1,
        "content_type": content_type,
        "ciphertext": ciphertext,
        "authentication_tag": "opaque-tag",
        "aad": {"suite": "test"},
        "key_ref": {"kid": "did:web:alice.example#device"},
        "digests": {
            "ciphertext": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
    })
}

fn sha256_json(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).expect("json serializes");
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn event_canonical_digest(event: &Value) -> String {
    let mut canonical = event.clone();
    if let Value::Object(object) = &mut canonical {
        object.remove("canonical_digest");
        object.remove("canonical_hash");
    }
    sha256_json(&canonical)
}

fn signed_event_envelope(event_id: &str, actor_seq: u64, prev_refs: Vec<&str>) -> Value {
    let payload = serde_json::json!({
        "body": format!("event body {actor_seq}"),
        "msgtype": "m.text"
    });
    let mut event = serde_json::json!({
        "event_id": event_id,
        "kind": "cx.message.create",
        "schema_id": "cx.schema.message.v1",
        "actor_id": "did:web:alice.example",
        "actor_seq": actor_seq,
        "space_id": "cx:space:0196419b-0000-7000-8000-000000000000",
        "device_id": "dev_alice",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": prev_refs,
        "auth_refs": [],
        "payload": payload,
        "proofs": [{
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#dev_alice",
            "device_id": "dev_alice",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_hash": sha256_json(&payload)
        }]
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));
    event
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
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    login["access_token"].as_str().unwrap().to_owned()
}

fn spawn_oauth_introspection_server() -> (String, std::thread::JoinHandle<String>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "http://{}/oauth/introspect",
        listener.local_addr().unwrap()
    );
    let handle = std::thread::spawn(move || {
        use std::io::{Read, Write};

        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut buffer = [0_u8; 4096];
        let read = stream.read(&mut buffer).unwrap();
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let request_lc = request.to_ascii_lowercase();
        let accepted = request_lc.contains("authorization: bearer shared-secret")
            && request.contains("token=coauth_access_token")
            && request.contains("token_type_hint=access_token");
        let (status, body) = if accepted {
            (
                "200 OK",
                serde_json::json!({
                    "active": true,
                    "scope": "urn:contrix:principal-server:session.bind",
                    "sub": "coauth-subject-1",
                    "username": "OAuth Alice",
                    "org.contrix.principal_did": "did:web:oauth.example",
                    "org.contrix.device_id": "dev_oauth",
                    "exp": 4102444800_i64
                })
                .to_string(),
            )
        } else {
            ("401 Unauthorized", "{}".to_owned())
        };
        let response = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
        request
    });
    (url, handle)
}

#[tokio::test]
async fn oauth_bearer_introspection_authenticates_directly() {
    let (introspection_url, request_handle) = spawn_oauth_introspection_server();
    let mut config = test_config();
    config.development_mode = false;
    config.oauth_introspection_url = Some(introspection_url);
    config.oauth_introspection_bearer = Some("shared-secret".to_owned());
    let state = AppState::new(config, Db { pool: None });

    let me: Value = TestClient::get("http://server/api/v1/account/me")
        .add_header("authorization", "Bearer coauth_access_token", true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(me["did"], "did:web:oauth.example");
    assert_eq!(me["handle"], "@oauth-alice");

    let request = request_handle.join().unwrap();
    assert!(request.contains("token=coauth_access_token"));
    let devices = state
        .persistence
        .devices()
        .list_for_actor("did:web:oauth.example")
        .unwrap();
    let oauth_device = devices
        .iter()
        .find(|device| device.payload["raw_device_id"] == "dev_oauth")
        .expect("OAuth device auto-provisioned");
    assert!(oauth_device.device_id.starts_with("cx:device:"));
}

#[tokio::test]
async fn health_and_describe_work() {
    let mut home = TestClient::get("http://server/").send(&app()).await;
    assert_eq!(home.status_code.unwrap(), StatusCode::OK);
    let home_body = home.take_string().await.unwrap();
    assert!(home_body.contains("<h1>it works</h1>"));

    let health: Value = TestClient::get("http://server/health")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(health["ok"], true);
    assert_eq!(health["checks"]["database"]["ok"], true);
    assert_eq!(health["checks"]["events"]["ok"], true);

    let describe: Value = TestClient::get("http://server/api/v1/server/describe")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(describe["protocol_version"], "1.0");
    assert_eq!(describe["service_type"], "principal_server");
    assert!(
        describe["supported_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile == "cx.profile.soland_limited_server.v1")
    );
    assert!(
        !describe["supported_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile == "cx.schema.core.v1" || profile == "cx.reducer.v1")
    );
    assert!(
        describe["supported_schema_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile == "cx.schema.core.v1")
    );
    assert!(
        describe["supported_reducer_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile == "cx.reducer.v1")
    );
    assert_eq!(
        describe["limits"]["profile_status"]["conformance"],
        "limited_reference"
    );
    assert_eq!(
        describe["limits"]["registries"]["source"],
        "contrix-spec/spec/v1/artifacts"
    );
    assert_eq!(
        describe["limits"]["registries"]["versions"]["event_kind"],
        artifacts::event_kind_registry()["version"]
    );
    assert_eq!(
        describe["limits"]["plaintext_visible_service_capability"]["supported"],
        true
    );
    assert!(
        describe["supported_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile == "cx.profile.mimi_interop.v1")
    );
    assert!(
        describe["supported_operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| operation == "cx.mimi.submit_message")
    );
    assert!(
        describe["supported_operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| operation == "cx.events.submit")
    );
}

#[tokio::test]
async fn events_describe_and_single_event_submit_work() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let describe: Value = TestClient::get("http://server/api/v1/events/describe")
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(describe["protocol_version"], "1.0");
    assert_eq!(describe["primary_write_path"], "/api/v1/events");
    assert_eq!(describe["event_envelope"]["schema"], "cx.schema.event.v1");
    assert_eq!(
        describe["registry"]["event_kind_registry_version"],
        "2026-05-08"
    );
    assert_eq!(
        describe["registry"]["source"],
        "contrix-spec/spec/v1/artifacts"
    );
    assert!(
        describe["registry"]["event_kinds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|kind| kind == "cx.flow.create")
    );
    assert_eq!(describe["schema_profile"], "cx.schema.core.v1");
    assert_eq!(describe["reducer_profile"], "cx.reducer.v1");
    assert_eq!(describe["capabilities"]["batch_receipt"], false);
    assert_eq!(describe["capabilities"]["snapshot"], false);
    assert_eq!(describe["capabilities"]["witness"], false);
    assert_eq!(describe["capabilities"]["high_assurance"], false);

    let first = signed_event_envelope(
        "cx:event:01904100-0000-7000-8000-f15c8ea06c11",
        1,
        Vec::new(),
    );
    let submitted: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&first)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(submitted["status"], "accepted");
    assert_eq!(
        submitted["event_id"],
        "cx:event:01904100-0000-7000-8000-f15c8ea06c11"
    );
    assert_eq!(submitted["canonical_digest"], first["canonical_digest"]);

    let duplicate: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&first)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(duplicate["status"], "duplicate");
    assert_eq!(duplicate["receipt"]["idempotent"], true);

    let fetched: Value = TestClient::get(
        "http://server/api/v1/events/cx:event:01904100-0000-7000-8000-f15c8ea06c11",
    )
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        fetched["event"]["event_id"],
        "cx:event:01904100-0000-7000-8000-f15c8ea06c11"
    );
    assert_eq!(
        fetched["metadata"]["canonical_digest"],
        first["canonical_digest"]
    );

    let second = signed_event_envelope(
        "cx:event:01904100-0000-7000-8000-63f16896f0b0",
        2,
        vec!["cx:event:01904100-0000-7000-8000-f15c8ea06c11"],
    );
    let second_submitted: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&second)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(second_submitted["status"], "accepted");

    let mut artifact_kind_event = signed_event_envelope(
        "cx:event:01904100-0000-7000-8000-df827a7269a3",
        3,
        Vec::new(),
    );
    artifact_kind_event["kind"] = Value::String("cx.flow.create".to_owned());
    artifact_kind_event["schema_id"] = Value::String("cx.schema.flow.v1".to_owned());
    artifact_kind_event["canonical_digest"] =
        Value::String(event_canonical_digest(&artifact_kind_event));
    let artifact_kind_submitted: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&artifact_kind_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(artifact_kind_submitted["status"], "accepted");

    let mut unknown_schema = signed_event_envelope(
        "cx:event:01904100-0000-7000-8000-80be9d943c27",
        4,
        Vec::new(),
    );
    unknown_schema["schema_id"] = Value::String("cx.schema.not_registered.v1".to_owned());
    unknown_schema["canonical_digest"] = Value::String(event_canonical_digest(&unknown_schema));
    let mut unknown_schema_response = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&unknown_schema)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        unknown_schema_response.status_code.unwrap(),
        StatusCode::BAD_REQUEST
    );
    let unknown_schema_body: Value = unknown_schema_response.take_json().await.unwrap();
    assert_eq!(unknown_schema_body["error"]["errcode"], "unknown_schema");

    let mut legacy_schema = signed_event_envelope(
        "cx:event:01904100-0000-7000-8000-90ddb6d74138",
        5,
        Vec::new(),
    );
    legacy_schema["schema_id"] = Value::String("cx.schema.room.v1".to_owned());
    legacy_schema["canonical_digest"] = Value::String(event_canonical_digest(&legacy_schema));
    let mut legacy_schema_response = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&legacy_schema)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        legacy_schema_response.status_code.unwrap(),
        StatusCode::BAD_REQUEST
    );
    let legacy_schema_body: Value = legacy_schema_response.take_json().await.unwrap();
    assert_eq!(
        legacy_schema_body["error"]["errcode"],
        "legacy_contract_removed"
    );

    let mut legacy_kind = signed_event_envelope(
        "cx:event:01904100-0000-7000-8000-0d77e6a44b05",
        6,
        Vec::new(),
    );
    legacy_kind["kind"] = Value::String("cx.room.message".to_owned());
    legacy_kind["canonical_digest"] = Value::String(event_canonical_digest(&legacy_kind));
    let mut legacy_kind_response = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&legacy_kind)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        legacy_kind_response.status_code.unwrap(),
        StatusCode::BAD_REQUEST
    );
    let legacy_kind_body: Value = legacy_kind_response.take_json().await.unwrap();
    assert_eq!(
        legacy_kind_body["error"]["errcode"],
        "legacy_contract_removed"
    );

    let mut legacy_field = signed_event_envelope(
        "cx:event:01904100-0000-7000-8000-bba6bd8c8c00",
        7,
        Vec::new(),
    );
    legacy_field["payload"]["room_id"] = Value::String("!legacy:example.com".to_owned());
    let legacy_field_payload_hash = sha256_json(&legacy_field["payload"]);
    legacy_field["proofs"][0]["payload_hash"] = Value::String(legacy_field_payload_hash);
    legacy_field["canonical_digest"] = Value::String(event_canonical_digest(&legacy_field));
    let mut legacy_field_response = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&legacy_field)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        legacy_field_response.status_code.unwrap(),
        StatusCode::BAD_REQUEST
    );
    let legacy_field_body: Value = legacy_field_response.take_json().await.unwrap();
    assert_eq!(
        legacy_field_body["error"]["errcode"],
        "legacy_contract_removed"
    );

    let mut legacy_typed_id = signed_event_envelope(
        "cx:event:01904100-0000-7000-8000-206613515f76",
        8,
        Vec::new(),
    );
    legacy_typed_id["payload"]["flow_id"] = Value::String("cx:card:legacy-card".to_owned());
    let legacy_typed_id_payload_hash = sha256_json(&legacy_typed_id["payload"]);
    legacy_typed_id["proofs"][0]["payload_hash"] = Value::String(legacy_typed_id_payload_hash);
    legacy_typed_id["canonical_digest"] = Value::String(event_canonical_digest(&legacy_typed_id));
    let mut legacy_typed_id_response = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&legacy_typed_id)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        legacy_typed_id_response.status_code.unwrap(),
        StatusCode::BAD_REQUEST
    );
    let legacy_typed_id_body: Value = legacy_typed_id_response.take_json().await.unwrap();
    assert_eq!(
        legacy_typed_id_body["error"]["errcode"],
        "legacy_contract_removed"
    );

    let batch: Value = TestClient::post("http://server/api/v1/events/batch-get")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "event_ids": ["cx:event:01904100-0000-7000-8000-f15c8ea06c11", "cx:event:01904100-0000-7000-8000-30f4e405b35e"]
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(batch["events"].as_array().unwrap().len(), 1);
    assert_eq!(
        batch["missing"],
        serde_json::json!(["cx:event:01904100-0000-7000-8000-30f4e405b35e"])
    );

    let listed: Value =
        TestClient::get("http://server/api/v1/events?actor_id=did:web:alice.example&limit=10")
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(listed["events"].as_array().unwrap().len(), 3);
    assert_eq!(listed["frontier"]["actors"]["did:web:alice.example"], 3);

    let frontier: Value =
        TestClient::get("http://server/api/v1/events/frontier?actor_id=did:web:alice.example")
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(frontier["actor_frontier"]["did:web:alice.example"], 3);

    let mut conflicting = signed_event_envelope(
        "cx:event:01904100-0000-7000-8000-f15c8ea06c11",
        4,
        Vec::new(),
    );
    conflicting["payload"]["body"] = Value::String("different canonical body".to_owned());
    let payload_hash = sha256_json(&conflicting["payload"]);
    conflicting["proofs"][0]["payload_hash"] = Value::String(payload_hash);
    conflicting["canonical_digest"] = Value::String(event_canonical_digest(&conflicting));
    let mut conflict = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&conflicting)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(conflict.status_code.unwrap(), StatusCode::CONFLICT);
    let conflict_body: Value = conflict.take_json().await.unwrap();
    assert_eq!(conflict_body["error"]["errcode"], "duplicate_conflict");
}

#[tokio::test]
async fn contrix_openapi_spec_contains_facet_projection_contracts() {
    let mut response = TestClient::get("http://server/.well-known/contrix/openapi.yaml")
        .send(&app())
        .await;
    assert_eq!(response.status_code.unwrap().as_u16(), 200);
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert!(content_type.contains("application/yaml"));
    let body = response.take_string().await.unwrap();
    assert!(body.contains("openapi: 3.1.0"));
    assert!(body.contains("FacetName"));
    assert!(body.contains("ViewRenderer"));
    assert!(body.contains("allowed_entity_facets"));
    assert!(body.contains("x-operation-aliases"));
    assert!(body.contains("x-contrix-artifacts"));
    let expected_operation_ids = [
        "cx.system.health",
        "cx.account.register",
        "cx.account.me",
        "cx.auth.logout",
        "cx.contacts.request",
        "cx.contacts.respond",
        "cx.contacts.list",
        "cx.spaces.create",
        "cx.spaces.delete",
        "cx.server.describe",
        "cx.spaces.add_member",
        "cx.spaces.remove_member",
        "cx.messages.send",
        "cx.events.describe",
        "cx.events.submit",
        "cx.events.get",
        "cx.events.batch_get",
        "cx.events.query",
        "cx.events.subscribe",
        "cx.events.frontier",
        "cx.repo.describe",
        "cx.repo.list_commits",
        "cx.repo.get_operations",
        "cx.repo.sync",
        "cx.index.query",
        "cx.authz.get_effective_grants",
        "cx.authz.get_invites",
        "cx.repo.submit_commit",
        "cx.federation.transaction",
        "cx.federation.push_operations",
        "cx.federation.pull_operations",
        "cx.federation.space_members",
        "cx.federation.verify_actor",
        "cx.sync.account",
        "cx.sync.typing",
        "cx.sync.backfill_gap",
        "cx.sync.get_snapshot_head",
        "cx.sync.get_snapshot_chunk",
        "cx.directory.describe",
        "cx.directory.search_spaces",
        "cx.directory.resolve_space",
        "cx.index.describe",
        "cx.index.debug_reducer",
        "cx.admin.actors",
        "cx.admin.spaces",
        "cx.admin.devices",
        "cx.admin.capabilities",
        "cx.admin.federation",
        "cx.admin.applets",
        "cx.admin.agents",
        "cx.admin.reports",
        "cx.admin.invite_tokens",
        "cx.admin.audit",
        "cx.admin.policy",
        "cx.admin.media",
        "cx.authz.check",
        "cx.policies.list",
        "cx.policies.get",
        "cx.policies.upsert",
        "cx.policies.delete",
        "cx.push.register_device",
        "cx.devices.pairing_challenge",
        "cx.devices.authorize_pairing",
        "cx.push.unregister_device",
        "cx.push.rules",
        "cx.push.notify",
        "cx.webrtc.create_session",
        "cx.webrtc.send_signal",
        "cx.webrtc.close_session",
        "cx.policy.check",
        "cx.moderation.report",
        "cx.mimi.provider_directory",
        "cx.mimi.key_material",
        "cx.mimi.room_update",
        "cx.mimi.notify",
        "cx.mimi.submit_message",
        "cx.mimi.group_info",
        "cx.mimi.request_consent",
        "cx.mimi.update_consent",
        "cx.mimi.identifier_query",
        "cx.mimi.report_abuse",
        "cx.mimi.proxy_download",
    ];
    for operation_id in expected_operation_ids {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing {operation_id} in generated openapi"
        );
    }
}

#[tokio::test]
async fn index_query_supports_facet_projection_binding() {
    let query: Value = TestClient::post("http://server/api/v1/index/query")
        .json(&serde_json::json!({
            "space_ids": ["cx:space:0196419b-0000-7000-8000-000000000000"],
            "facets": ["container", "replyable"],
            "renderer": "collection",
            "limit": 20
        }))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    let unsupported: Value = TestClient::post("http://server/api/v1/index/query")
        .json(&serde_json::json!({
            "space_ids": ["cx:space:0196419b-0000-7000-8000-000000000000"],
            "facets": ["not_supported"],
            "limit": 20
        }))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert!(query["results"].as_array().unwrap().len() >= 1);
    for result in query["results"].as_array().unwrap() {
        assert_eq!(result["renderer"], "collection");
        assert_eq!(
            result["facets"],
            serde_json::json!(["container", "replyable"])
        );
    }

    assert!(unsupported["results"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn index_reducer_debug_reports_projection_frontier() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let space_id = "cx:space:0196419b-0000-7000-8000-000000000000";

    let sent: Value = TestClient::post("http://server/api/v1/messages/send")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "space_id": space_id,
            "thread_id": "cx:thread:debug-reducer",
            "content": {"body": "debug reducer"},
            "encrypted": false
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();

    let debug: Value = TestClient::get(format!(
        "http://server/api/v1/index/debug/reducer?space_id={space_id}&limit=5"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(debug["reducer_profile"], "cx.reducer.v1");
    assert_eq!(
        debug["schema_profiles"],
        serde_json::json!(["cx.schema.core.v1"])
    );
    assert_eq!(debug["space_id"], space_id);
    assert_eq!(debug["frontier"]["message_count"], 1);
    assert_eq!(debug["frontier"]["projection_event_count"], 1);
    assert_eq!(debug["frontier"]["latest_event_id"], sent["event_id"]);
    assert_eq!(debug["recent_events"][0]["event_id"], sent["event_id"]);
    assert_eq!(
        debug["production_gap"],
        "durable_reducer_replay_and_conflict_records"
    );

    let invalid = TestClient::get("http://server/api/v1/index/debug/reducer?space_id=bad")
        .send(&app_from_state(state))
        .await;
    assert_eq!(invalid.status_code.unwrap().as_u16(), 400);
}

#[tokio::test]
async fn index_query_supports_structured_filters_sort_and_cursor() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    for title in ["Zulu Query Space", "Alpha Query Space"] {
        let created: Value = TestClient::post("http://server/api/v1/spaces")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&serde_json::json!({
                "title": title,
                "summary": "index query pagination fixture",
                "public": true
            }))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
        assert!(created["space_id"].as_str().is_some());
    }

    let first_page: Value = TestClient::post("http://server/api/v1/index/query")
        .json(&serde_json::json!({
            "filters": {"text": "Query Space"},
            "sort": [{"field": "title", "direction": "asc"}],
            "limit": 1
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(first_page["results"].as_array().unwrap().len(), 1);
    assert_eq!(first_page["results"][0]["title"], "Alpha Query Space");
    assert_eq!(first_page["frontier"]["limited"], true);
    let cursor = first_page["next_cursor"].as_str().unwrap().to_owned();

    let second_page: Value = TestClient::post("http://server/api/v1/index/query")
        .json(&serde_json::json!({
            "filters": {"text": "Query Space"},
            "sort": [{"field": "title", "direction": "asc"}],
            "cursor": cursor,
            "limit": 1
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(second_page["results"].as_array().unwrap().len(), 1);
    assert_eq!(second_page["results"][0]["title"], "Zulu Query Space");
    assert!(second_page["next_cursor"].is_null());

    let mismatch = TestClient::post("http://server/api/v1/index/query")
        .json(&serde_json::json!({
            "filters": {"text": "Alpha"},
            "sort": [{"field": "title", "direction": "asc"}],
            "cursor": first_page["next_cursor"],
            "limit": 1
        }))
        .send(&app_from_state(state))
        .await;
    assert_eq!(mismatch.status_code.unwrap().as_u16(), 400);
}

#[tokio::test]
async fn sync_cursor_rejects_facets_and_renderer_changes() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let first: Value = TestClient::post("http://server/api/v1/sync")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "renderer": "collection",
            "facets": ["stateful"],
            "filter": {"spaces": ["cx:space:0196419b-0000-7000-8000-000000000000"]},
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(first["next_batch"].as_str().is_some());

    let renderer_changed = TestClient::post("http://server/api/v1/sync")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "since": first["next_batch"],
            "renderer": "queue",
            "facets": ["stateful"],
            "filter": {"spaces": ["cx:space:0196419b-0000-7000-8000-000000000000"]},
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(renderer_changed.status_code.unwrap().as_u16(), 400);

    let facets_changed = TestClient::post("http://server/api/v1/sync")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "since": first["next_batch"],
            "renderer": "collection",
            "facets": ["replyable"],
            "filter": {"spaces": ["cx:space:0196419b-0000-7000-8000-000000000000"]},
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(facets_changed.status_code.unwrap().as_u16(), 400);
}

#[tokio::test]
async fn sync_backfill_exposes_prev_batch_and_limited_timeline_pages() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let space_id = "cx:space:0196419b-0000-7000-8000-000000000000";

    for body in ["first backfill page", "second backfill page"] {
        let sent: Value = TestClient::post("http://server/api/v1/messages/send")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&serde_json::json!({
                "space_id": space_id,
                "thread_id": "cx:thread:backfill-pages",
                "content": {"body": body},
                "encrypted": false
            }))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
        assert!(sent["operation_id"].as_str().is_some());
    }

    let first_page: Value = TestClient::get(format!(
        "http://server/api/v1/events?space_id={space_id}&limit=1"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(first_page["events"].as_array().unwrap().len(), 1);
    assert_eq!(first_page["limited"], true);
    assert!(first_page["prev_batch"].is_null());
    let next_cursor = first_page["next_cursor"].as_str().unwrap();

    let second_page: Value = TestClient::get(format!(
        "http://server/api/v1/events?space_id={space_id}&limit=1&cursor={next_cursor}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(second_page["prev_batch"], next_cursor);
    assert_eq!(second_page["events"].as_array().unwrap().len(), 1);
    let to_cursor = second_page["events"][0]["event_id"].as_str().unwrap();
    let gap: Value = TestClient::get(format!(
        "http://server/api/v1/sync/backfill/gap?space_id={space_id}&from_cursor={next_cursor}&to_cursor={to_cursor}&limit=10"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(gap["from_cursor"], next_cursor);
    assert_eq!(gap["to_cursor"], to_cursor);
    assert_eq!(gap["prev_batch"], next_cursor);
    assert_eq!(gap["gap_complete"], true);
    assert_eq!(gap["events"].as_array().unwrap().len(), 1);
    assert_eq!(gap["production_gap"], "durable_sync_position_validation");

    let mut invalid_cursor = TestClient::get(format!(
        "http://server/api/v1/events?space_id={space_id}&cursor=cx:event:01904100-0000-7000-8000-b8ab57920a67"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(invalid_cursor.status_code.unwrap().as_u16(), 400);
    let invalid_cursor_body: Value = invalid_cursor.take_json().await.unwrap();
    assert_eq!(invalid_cursor_body["error"]["errcode"], "invalid_cursor");
}

#[tokio::test]
async fn mimi_provider_facade_contracts_work() {
    let service = app();

    let well_known: Value = TestClient::get("http://server/.well-known/mimi-protocol-directory")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(well_known["service_type"], "mimi_provider_facade");
    assert_eq!(
        well_known["mimi"]["protocol_draft"],
        "draft-ietf-mimi-protocol-06"
    );
    assert!(
        well_known["supported_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile == "cx.profile.mimi_interop.v1")
    );

    let directory: Value = TestClient::get("http://server/api/v1/mimi/provider-directory")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        directory["mimi"]["content_draft"],
        "draft-ietf-mimi-content-08"
    );
    assert!(
        directory["mimi"]["features"]
            .as_array()
            .unwrap()
            .iter()
            .any(|feature| feature == "submit_message")
    );

    let unsupported = TestClient::post("http://server/api/v1/mimi/key-material")
        .json(&serde_json::json!({"protocol_draft": "draft-ietf-mimi-protocol-99"}))
        .send(&service)
        .await;
    assert_eq!(unsupported.status_code.unwrap().as_u16(), 400);

    let key_material: Value = TestClient::post("http://server/api/v1/mimi/key-material")
        .json(&serde_json::json!({
            "target_identifier": "mimi://soland.local/users/alice",
            "protocol_draft": "draft-ietf-mimi-protocol-06"
        }))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(key_material["ok"], true);
    assert_eq!(
        key_material["receipt"]["operation_id"],
        "cx.mimi.key_material"
    );

    let group_info: Value = TestClient::get("http://server/api/v1/mimi/rooms/01JSMIMI/group-info")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(group_info["room_id"], "01JSMIMI");
    assert_eq!(
        group_info["group_info"]["canonical_truth"],
        "contrix_signed_event_reducer"
    );

    let identifier: Value = TestClient::post("http://server/api/v1/mimi/identifiers/query")
        .json(&serde_json::json!({
            "query": "mimi://remote.example/alice",
            "privacy_mode": "private_contact_discovery"
        }))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(identifier["reachable"], true);
    assert_eq!(identifier["mapped_did"], "did:web:alice.example");
    assert_eq!(
        identifier["receipt"]["extra"]["contact_graph_exposed"],
        false
    );

    let mapped: Value = TestClient::post("http://server/api/v1/mimi/rooms/01JSMIMI/messages")
        .json(&serde_json::json!({
            "source_format": "text/markdown;variant=GFM-MIMI",
            "body": "hello from MIMI"
        }))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(mapped["ok"], true);
    assert_eq!(mapped["receipt"]["operation_id"], "cx.mimi.submit_message");
    assert_eq!(
        mapped["receipt"]["extra"]["target_format"],
        "cx.message.create"
    );

    let proxy: Value = TestClient::post("http://server/api/v1/mimi/proxy-download")
        .json(&serde_json::json!({
            "blob_ref": "cx:blob:sha256:e2e",
            "asset_privacy_policy": "provider_proxy"
        }))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(proxy["ok"], true);
    assert!(
        proxy["proxy_url"]
            .as_str()
            .unwrap()
            .contains("/mimi/proxy-download")
    );
    assert_eq!(
        proxy["receipt"]["extra"]["direct_object_store_url_returned"],
        false
    );

    let report = TestClient::post("http://server/api/v1/mimi/report-abuse")
        .json(&serde_json::json!({
            "mimi_room_uri": "mimi://soland.local/rooms/01JSMIMI",
            "target_event_hash": "sha256:target",
            "frank": {"scheme": "dev-frank"}
        }))
        .send(&service)
        .await;
    assert_eq!(report.status_code.unwrap().as_u16(), 202);
}

#[tokio::test]
async fn configured_cors_allows_only_explicit_origin() {
    let mut config = test_config();
    config.cors_allow_origin = Some("https://app.example".to_owned());
    let service = app_from_state(AppState::new(config, Db { pool: None }));

    let allowed = TestClient::options("http://server/api/v1/sync")
        .add_header("Origin", "https://app.example", true)
        .add_header("Access-Control-Request-Method", "POST", true)
        .add_header(
            "Access-Control-Request-Headers",
            "authorization, content-type, x-contrix-wait-for",
            true,
        )
        .send(&service)
        .await;
    assert_eq!(
        allowed
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("https://app.example")
    );
    assert_eq!(
        allowed
            .headers()
            .get("access-control-allow-credentials")
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );

    let denied = TestClient::options("http://server/api/v1/sync")
        .add_header("Origin", "https://evil.example", true)
        .add_header("Access-Control-Request-Method", "POST", true)
        .send(&service)
        .await;
    assert!(
        denied
            .headers()
            .get("access-control-allow-origin")
            .is_none()
    );
}

#[tokio::test]
async fn server_describe_advertises_auth_server_url_when_configured() {
    let mut config = test_config();
    config.auth_server_url = Some("https://auth.local.host".to_owned());
    let service = app_from_state(AppState::new(config, Db { pool: None }));

    let describe: Value = TestClient::get("http://server/api/v1/server/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(
        describe["auth_metadata"]["auth_server_url"],
        "https://auth.local.host"
    );
}

#[tokio::test]
async fn service_did_is_config_driven_across_public_metadata() {
    let service_did = "did:web:configured.example";
    let service = app_from_state(AppState::new(
        test_config_with_service_did(service_did),
        Db { pool: None },
    ));

    let server: Value = TestClient::get("http://server/api/v1/server/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(server["service_did"], service_did);

    let identity: Value = TestClient::get("http://server/api/v1/identity/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(identity["service_did"], service_did);

    let sync: Value = TestClient::get("http://server/api/v1/sync/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(sync["service_did"], service_did);

    let events: Value = TestClient::get("http://server/api/v1/events/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(events["service_did"], service_did);

    let directory: Value = TestClient::get("http://server/api/v1/directory/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(directory["service_did"], service_did);

    let resolved: Value = TestClient::post("http://server/api/v1/directory/resolve-space")
        .json(&serde_json::json!({"space_id": "cx:space:0196419b-0000-7000-8000-000000000000"}))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resolved["via_services"], serde_json::json!([service_did]));

    let index: Value = TestClient::get("http://server/api/v1/index/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(index["service_did"], service_did);

    let repo: Value = TestClient::get("http://server/api/v1/repo/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(repo["repo_did"], service_did);

    let ice: Value = TestClient::post("http://server/contrix/v1/ice-config")
        .json(&serde_json::json!({}))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(ice["service_did"], service_did);
}

#[tokio::test]
async fn rate_limit_errors_use_standard_envelope_with_retry_after() {
    let state = AppState::new(test_config(), Db { pool: None });
    let limited_service = service_with_rate_limiter_config(
        state,
        RateLimiterConfig {
            max_requests: 1,
            window: Duration::from_secs(60),
        },
    );

    let first = TestClient::get("http://server/health")
        .send(&limited_service)
        .await;
    assert_eq!(first.status_code.unwrap(), StatusCode::OK);

    let mut second = TestClient::get("http://server/health")
        .send(&limited_service)
        .await;
    assert_eq!(second.status_code.unwrap(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after = second
        .headers
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .unwrap();
    assert_eq!(retry_after, "60");

    let limited: Value = second.take_json().await.unwrap();
    assert_eq!(limited["ok"], false);
    assert_eq!(limited["error"]["errcode"], "rate_limited");
    assert!(limited["error"]["retry_after_ms"].as_u64().unwrap() > 0);
    assert!(
        limited["error"]["request_id"]
            .as_str()
            .unwrap()
            .starts_with("cx:req:")
    );
}

#[tokio::test]
async fn account_contacts_and_space_lifecycle_workflow() {
    let state = AppState::new(test_config(), Db { pool: None });
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

    let duplicate_contact_request: Value =
        TestClient::post("http://server/api/v1/contacts/request")
            .add_header("authorization", format!("Bearer {alice}"), true)
            .json(&serde_json::json!({"target": "did:web:bob.example"}))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(duplicate_contact_request["status"], "pending");

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

    let accepted_again: Value = TestClient::post("http://server/api/v1/contacts/respond")
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
    assert_eq!(accepted_again["status"], "accepted");

    let reject_after_accept = TestClient::post("http://server/api/v1/contacts/respond")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .json(&serde_json::json!({
            "requester": "did:web:alice.example",
            "action": "reject"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(reject_after_accept.status_code.unwrap().as_u16(), 409);

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
            "public": false,
            "plaintext_visible_services": ["did:web:soland.local"]
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let space_id = created_space["space_id"].as_str().unwrap().to_owned();
    assert_eq!(created_space["owner"], "did:web:alice.example");

    let hidden_space: Value = TestClient::post("http://server/api/v1/directory/search-spaces")
        .json(&serde_json::json!({"query": "Workflow Space"}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(hidden_space["results"].as_array().unwrap().is_empty());

    let invite_space: Value = TestClient::post("http://server/api/v1/spaces")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "title": "Invite Token Space",
            "discoverability": "invite_only",
            "invitees": ["did:web:bob.example"]
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let invite_space_id = invite_space["space_id"].as_str().unwrap().to_owned();
    let bob_invites: Value = TestClient::get("http://server/api/v1/authz/invites")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(bob_invites["invites"].as_array().unwrap().len(), 1);
    assert_eq!(bob_invites["invites"][0]["space_id"], invite_space_id);
    let invite_token = bob_invites["invites"][0]["invite_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let invalid_invite_resolve = TestClient::post("http://server/api/v1/directory/resolve-space")
        .json(&serde_json::json!({"invite_token": "cx:invite-token:invalid"}))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(invalid_invite_resolve.status_code.unwrap().as_u16(), 404);
    let invite_resolve: Value = TestClient::post("http://server/api/v1/directory/resolve-space")
        .json(&serde_json::json!({"invite_token": invite_token}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(invite_resolve["space_preview"]["space_id"], invite_space_id);

    let listed_space: Value = TestClient::post("http://server/api/v1/spaces")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "title": "Listed Directory Space",
            "discoverability": "listed"
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let listed_space_id = listed_space["space_id"].as_str().unwrap().to_owned();
    let listed_search: Value = TestClient::post("http://server/api/v1/directory/search-spaces")
        .json(&serde_json::json!({"query": "Listed Directory Space"}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        listed_search["results"][0]["space_id"],
        listed_space_id.as_str()
    );
    let anonymous_sync_after_listed: Value = TestClient::post("http://server/api/v1/sync")
        .json(&serde_json::json!({}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        !anonymous_sync_after_listed["spaces"]
            .as_object()
            .unwrap()
            .contains_key(&listed_space_id)
    );

    let unlisted_space: Value = TestClient::post("http://server/api/v1/spaces")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "title": "Unlisted Directory Space",
            "discoverability": "unlisted"
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let unlisted_space_id = unlisted_space["space_id"].as_str().unwrap().to_owned();
    let unlisted_search: Value = TestClient::post("http://server/api/v1/directory/search-spaces")
        .json(&serde_json::json!({"query": "Unlisted Directory Space"}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(unlisted_search["results"].as_array().unwrap().is_empty());
    let unlisted_resolve: Value = TestClient::post("http://server/api/v1/directory/resolve-space")
        .json(&serde_json::json!({"space_id": unlisted_space_id.clone()}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        unlisted_resolve["space_preview"]["space_id"],
        unlisted_space_id
    );

    let anonymous_resolve = TestClient::post("http://server/api/v1/directory/resolve-space")
        .json(&serde_json::json!({"space_id": space_id}))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(anonymous_resolve.status_code.unwrap().as_u16(), 404);

    let owner_resolve: Value = TestClient::post("http://server/api/v1/directory/resolve-space")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({"space_id": space_id}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(owner_resolve["space_preview"]["space_id"], space_id);

    let locked_space: Value = TestClient::post("http://server/api/v1/spaces")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "title": "Locked Plaintext Space",
            "public": false
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let locked_space_id = locked_space["space_id"].as_str().unwrap();
    let plaintext_without_service = TestClient::post("http://server/api/v1/messages/send")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "space_id": locked_space_id,
            "content": {"body": "should be denied"},
            "encrypted": false
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(plaintext_without_service.status_code.unwrap().as_u16(), 403);

    let invalid_encrypted = TestClient::post("http://server/api/v1/messages/send")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "space_id": locked_space_id,
            "content": {"ciphertext": "opaque"},
            "encrypted": true
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(invalid_encrypted.status_code.unwrap().as_u16(), 400);

    let encrypted_message: Value = TestClient::post("http://server/api/v1/messages/send")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "space_id": locked_space_id,
            "content": encrypted_envelope("cx.message.v1", "opaque-ciphertext"),
            "encrypted": true
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        encrypted_message["event_id"]
            .as_str()
            .unwrap()
            .starts_with("cx:event:")
    );

    let bob_private_sync: Value = TestClient::post("http://server/api/v1/sync")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .json(&serde_json::json!({}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        !bob_private_sync["spaces"]
            .as_object()
            .unwrap()
            .contains_key(&space_id)
    );

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
    let send_cursor = decode_cursor(sent_message["sync_token"].as_str().unwrap());
    assert_eq!(send_cursor["schema"], "cx.schema.cursor.v1");
    assert!(send_cursor["positions"]["spaces"].is_object());
    let sent_commit: Value = TestClient::get(format!(
        "http://server/api/v1/repo/commit?commit_id={}&include_operations=true",
        sent_message["commit_id"].as_str().unwrap()
    ))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        sent_commit["operations"][0]["object_type"],
        "cx.message.create"
    );

    let invalid_block_message = TestClient::post("http://server/api/v1/messages/send")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "space_id": space_id,
            "content": {"blocks": [{"kind": "image"}]},
            "encrypted": false
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(invalid_block_message.status_code.unwrap().as_u16(), 400);

    let non_canonical_message = TestClient::post("http://server/api/v1/messages/send")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "space_id": space_id,
            "content": {"blocks": [{"kind": "location", "latitude": 31.2304, "longitude": 121.4737}]},
            "encrypted": false
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(non_canonical_message.status_code.unwrap().as_u16(), 400);

    let invalid_mention_message = TestClient::post("http://server/api/v1/messages/send")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "space_id": space_id,
            "content": {"body": "bad mention", "mentions": [{"type": "actor", "did": "alice"}]},
            "encrypted": false
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(invalid_mention_message.status_code.unwrap().as_u16(), 400);

    let block_message: Value = TestClient::post("http://server/api/v1/messages/send")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "space_id": space_id,
            "thread_id": "cx:thread:workflow",
            "content": {
                "mentions": [
                    "did:web:bob.example",
                    {"type": "entity", "entity_id": "cx:entity:01904100-0000-7000-8000-170d4f3bfc7b"}
                ],
                "blocks": [
                    {"kind": "text", "text": "structured hello"},
                    {"kind": "location", "latitude": 312304000, "longitude": 1214737000},
                    {"kind": "poll", "question": "ship?", "options": ["yes", "no"]}
                ]
            },
            "encrypted": false
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        block_message["event_id"]
            .as_str()
            .is_some_and(|event_id| event_id.starts_with("cx:event:")),
        "block message response: {block_message}"
    );

    let thread: Value =
        TestClient::get("http://server/api/v1/index/thread?thread_id=cx:thread:workflow")
            .add_header("authorization", format!("Bearer {alice}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(thread["events"][0]["content"]["body"], "hello workflow");

    let message_search: Value = TestClient::post("http://server/api/v1/index/search")
        .add_header("authorization", format!("Bearer {alice}"), true)
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
    assert_eq!(notifications["unread_count"], 2);
    assert!(
        notifications["notifications"]
            .as_array()
            .unwrap()
            .iter()
            .any(|notification| notification["event_ref"] == sent_message["event_id"])
    );

    let sync_with_message: Value = TestClient::post("http://server/api/v1/sync")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let next_batch = decode_cursor(sync_with_message["next_batch"].as_str().unwrap());
    assert_eq!(next_batch["profile"], "incremental");
    assert_eq!(next_batch["principal_id"], "did:web:alice.example");
    assert_eq!(next_batch["device_id"], "dev_alice");
    assert_eq!(next_batch["service_id"], "did:web:soland.local");
    assert!(
        next_batch["filter_hash"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert!(
        next_batch["expires_at_ms"].as_i64().unwrap()
            > next_batch["issued_at_ms"].as_i64().unwrap()
    );
    assert!(
        next_batch["positions"]["spaces"][&space_id]
            .as_i64()
            .unwrap()
            > 0
    );
    assert_eq!(
        sync_with_message["spaces"][&space_id]["timeline"]["events"][0]["event_id"],
        sent_message["event_id"]
    );
    assert_eq!(
        sync_with_message["spaces"][&space_id]["timeline"]["events"][0]["flow_id"],
        space_id.replace("cx:space:", "cx:flow:")
    );
    assert_eq!(
        sync_with_message["spaces"][&space_id]["timeline"]["events"][0]["branch"]["branch_id"],
        "cx:thread:workflow"
    );
    assert_eq!(
        sync_with_message["spaces"][&space_id]["summary"]["flow"]["schema"],
        "cx.schema.flow.v1"
    );

    let incremental_noop: Value = TestClient::post("http://server/api/v1/sync")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({"since": sync_with_message["next_batch"]}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        incremental_noop["spaces"][&space_id]["timeline"]["events"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    tokio::time::sleep(Duration::from_millis(2)).await;
    let second_message: Value = TestClient::post("http://server/api/v1/messages/send")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "space_id": space_id,
            "thread_id": "cx:thread:workflow",
            "content": {"body": "second workflow"},
            "encrypted": false
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let incremental_after_message: Value = TestClient::post("http://server/api/v1/sync")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({"since": sync_with_message["next_batch"]}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let incremental_events = incremental_after_message["spaces"][&space_id]["timeline"]["events"]
        .as_array()
        .unwrap();
    assert_eq!(incremental_events.len(), 1);
    assert_eq!(
        incremental_events[0]["event_id"],
        second_message["event_id"]
    );

    let mismatch = TestClient::post("http://server/api/v1/sync")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .json(&serde_json::json!({"since": sync_with_message["next_batch"]}))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(mismatch.status_code.unwrap().as_u16(), 400);

    let filter_mismatch = TestClient::post("http://server/api/v1/sync")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "since": sync_with_message["next_batch"],
            "filter": {"spaces": [space_id.clone()]}
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(filter_mismatch.status_code.unwrap().as_u16(), 400);

    let mut legacy_filter = TestClient::post("http://server/api/v1/sync")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "filter": {"room_id": "cx:room:legacy-room"}
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(legacy_filter.status_code.unwrap().as_u16(), 400);
    let legacy_filter_body: Value = legacy_filter.take_json().await.unwrap();
    assert_eq!(legacy_filter_body["error"]["errcode"], "invalid_param");

    let mut legacy_card_filter = TestClient::post("http://server/api/v1/sync")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "filter": {"card_id": "cx:card:legacy-card"}
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(legacy_card_filter.status_code.unwrap().as_u16(), 400);
    let legacy_card_filter_body: Value = legacy_card_filter.take_json().await.unwrap();
    assert_eq!(legacy_card_filter_body["error"]["errcode"], "invalid_param");

    let mut legacy_subject_filter = TestClient::post("http://server/api/v1/sync")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "filter": {"subject_id": "cx:subject:legacy-subject"}
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(legacy_subject_filter.status_code.unwrap().as_u16(), 400);
    let legacy_subject_filter_body: Value = legacy_subject_filter.take_json().await.unwrap();
    assert_eq!(
        legacy_subject_filter_body["error"]["errcode"],
        "invalid_param"
    );

    let renderer_bound_sync: Value = TestClient::post("http://server/api/v1/sync")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "renderer": "collection",
            "facets": ["stateful"],
            "filter": {"spaces": [space_id.clone()]}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let renderer_mismatch = TestClient::post("http://server/api/v1/sync")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "since": renderer_bound_sync["next_batch"],
            "renderer": "queue",
            "facets": ["stateful"],
            "filter": {"spaces": [space_id.clone()]}
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(renderer_mismatch.status_code.unwrap().as_u16(), 400);

    let mut expired_cursor = next_batch.clone();
    expired_cursor["expires_at_ms"] = serde_json::json!(1);
    let mut expired = TestClient::post("http://server/api/v1/sync")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({"since": encode_cursor(&expired_cursor)}))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(expired.status_code.unwrap(), StatusCode::GONE);
    let expired_body: Value = expired.take_json().await.unwrap();
    assert_eq!(expired_body["error"]["errcode"], "sync_token_expired");

    let exported: Value = TestClient::get(format!("http://server/api/v1/spaces/{space_id}/export"))
        .add_header("authorization", format!("Bearer {alice}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(exported["schema"], "cx.export.space.v1");
    assert!(
        exported["operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| operation["operation_id"] == sent_message["operation_id"])
    );

    let waited_sync: Value = TestClient::post("http://server/api/v1/sync")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .add_header(
            "x-contrix-wait-for",
            sent_message["sync_token"].as_str().unwrap(),
            true,
        )
        .json(&serde_json::json!({}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        waited_sync["spaces"][&space_id]["timeline"]["events"][0]["event_id"],
        sent_message["event_id"]
    );

    let invalid_wait = TestClient::post("http://server/api/v1/sync")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .add_header("x-contrix-wait-for", "not-a-sync-token", true)
        .json(&serde_json::json!({}))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(invalid_wait.status_code.unwrap().as_u16(), 400);

    let snapshot: Value = TestClient::get(format!(
        "http://server/api/v1/sync/snapshot-head?space_id={space_id}"
    ))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(snapshot["frontier"]["message_count"], 3);
    assert!(
        snapshot["snapshot_ref"]
            .as_str()
            .unwrap()
            .starts_with("cx:snapshot:")
    );
    assert!(!snapshot["signature"]["sig"].as_str().unwrap().is_empty());
    assert_eq!(snapshot["manifest"]["reducer_profile"], "cx.reducer.v1");
    assert_eq!(snapshot["chunks"][0]["chunk_id"], "0");
    assert_eq!(snapshot["chunks"][0]["digest"], snapshot["state_hash"]);

    let snapshot_chunk: Value = TestClient::get(format!(
        "http://server/api/v1/sync/snapshot-chunk?snapshot_ref={}&chunk_id=0",
        snapshot["snapshot_ref"].as_str().unwrap()
    ))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(snapshot_chunk["digest"], snapshot["state_hash"]);
    assert_eq!(snapshot_chunk["verified"], true);
    assert!(!snapshot_chunk["bytes_base64"].as_str().unwrap().is_empty());

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

    let lifecycle_events: Value =
        TestClient::get(format!("http://server/api/v1/events?space_id={space_id}"))
            .add_header("authorization", format!("Bearer {alice}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    let event_kinds: std::collections::BTreeSet<_> = lifecycle_events["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| {
            event["event_kind"].as_str().is_some_and(|event_kind| {
                event_kind.starts_with("cx.space.") || event_kind.starts_with("cx.membership.")
            })
        })
        .map(|event| event["event_kind"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        event_kinds,
        [
            "cx.membership.join",
            "cx.membership.leave",
            "cx.space.create",
            "cx.space.destroy"
        ]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect()
    );

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

    let audit_events: Value = TestClient::get("http://server/api/v1/audit/events?limit=20")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let space_create_audit = audit_events["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["action"] == "space.create")
        .expect("space create audit event");
    assert!(
        space_create_audit["request_id"]
            .as_str()
            .unwrap()
            .starts_with("cx:req:")
    );
    assert_eq!(space_create_audit["outcome"], "accepted");
    let audit_page_one: Value = TestClient::get("http://server/api/v1/audit/events?limit=1")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let audit_cursor = audit_page_one["next_cursor"]
        .as_str()
        .expect("audit page should expose next cursor");
    let audit_page_two: Value = TestClient::get(format!(
        "http://server/api/v1/audit/events?limit=1&cursor={audit_cursor}"
    ))
    .add_header("authorization", format!("Bearer {alice}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_ne!(
        audit_page_one["events"][0]["audit_id"],
        audit_page_two["events"][0]["audit_id"]
    );
    let forbidden_audit =
        TestClient::get("http://server/api/v1/audit/events?actor=did:web:bob.example")
            .add_header("authorization", format!("Bearer {alice}"), true)
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(forbidden_audit.status_code.unwrap().as_u16(), 403);

    let logout: Value = TestClient::post("http://server/api/v1/auth/logout")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(logout["revoked"], true);
    {
        let sessions = state.persistence.sessions().snapshot_all().unwrap();
        assert!(!sessions.iter().any(|session| session.token_hash == bob));
        let bob_session = sessions
            .iter()
            .find(|session| session.actor == "did:web:bob.example")
            .expect("hashed bob session remains for revocation audit");
        assert_ne!(bob_session.token_hash, bob);
        assert_eq!(bob_session.audience, "did:web:soland.local");
        assert!(bob_session.revoked_at.is_some());
    }
    let revoked_me = TestClient::get("http://server/api/v1/account/me")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(revoked_me.status_code.unwrap().as_u16(), 401);

    let audit_actions: std::collections::BTreeSet<_> = state
        .persistence
        .audit()
        .snapshot_all()
        .unwrap()
        .iter()
        .filter_map(|entry| entry["action"].as_str().map(ToOwned::to_owned))
        .collect();
    for expected in [
        "account.register",
        "auth.dev_login",
        "space.create",
        "space.member.add",
        "space.member.remove",
        "space.delete",
        "auth.logout",
    ] {
        assert!(audit_actions.contains(expected));
    }
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
async fn protected_endpoints_reject_query_auth_material() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let mut response = TestClient::get(format!(
        "http://server/api/v1/account/me?access_token={token}"
    ))
    .send(&app_from_state(state))
    .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::UNAUTHORIZED);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["ok"], false);
    assert_eq!(body["error"]["errcode"], "unauthenticated");
    assert_eq!(
        body["error"]["error"],
        "auth material in query strings is not allowed"
    );
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
        .send(&app_from_state(AppState::new(test_config(), db)))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(health["storage"], "postgres");
}

#[tokio::test]
async fn identity_surface_works() {
    let state = AppState::new(test_config(), Db { pool: None });
    let describe: Value = TestClient::get("http://server/api/v1/identity/describe")
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(describe["protocol_version"], "1.0");
    assert_eq!(
        describe["resolver_policy"]["allow_methods"],
        serde_json::json!(["web", "key", "uuid"])
    );
    assert_eq!(describe["did_webvh"]["enabled"], false);

    let resolved: Value = TestClient::post("http://server/api/v1/identity/resolve")
        .json(&serde_json::json!({"did": "did:web:alice.example"}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resolved["did_document"]["id"], "did:web:alice.example");

    let document: Value =
        TestClient::get("http://server/api/v1/identity/document?did=did:web:alice.example")
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(document["did_document"]["id"], "did:web:alice.example");

    let log: Value = TestClient::get("http://server/api/v1/identity/log?did=did:web:alice.example")
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(log["has_more"], false);
}

#[tokio::test]
async fn identity_describe_exposes_external_webvh_provider() {
    let mut config = test_config();
    config.external_webvh_provider_url = Some("http://webvh.local".to_owned());
    config.external_webvh_provider_active = true;
    config.did_resolver_allow_methods = vec![
        "web".to_owned(),
        "key".to_owned(),
        "uuid".to_owned(),
        "webvh".to_owned(),
    ];
    let describe: Value = TestClient::get("http://server/api/v1/identity/describe")
        .send(&app_from_state(AppState::new(config, Db { pool: None })))
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(describe["did_webvh"]["enabled"], true);
    assert_eq!(describe["did_webvh"]["method"], "did:webvh");
    assert_eq!(
        describe["did_webvh"]["providers"][0]["id"],
        "external.webvh"
    );
    assert_eq!(
        describe["did_webvh"]["providers"][0]["base_url"],
        "http://webvh.local"
    );
    assert_eq!(
        describe["did_webvh"]["providers"][0]["health"]["active"],
        true
    );
    assert_eq!(
        describe["did_webvh"]["providers"][0]["health"]["probe"],
        "ok"
    );
    assert!(
        describe["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile.as_str() == Some("cx.identity.webvh.provider.v1"))
    );
}

#[tokio::test]
async fn identity_describe_keeps_external_webvh_provider_when_probe_fails() {
    let mut config = test_config();
    config.external_webvh_provider_url = Some("http://webvh.unreachable.local".to_owned());
    config.external_webvh_provider_active = false;
    config.did_resolver_allow_methods = vec![
        "web".to_owned(),
        "key".to_owned(),
        "uuid".to_owned(),
        "webvh".to_owned(),
    ];
    let describe: Value = TestClient::get("http://server/api/v1/identity/describe")
        .send(&app_from_state(AppState::new(config, Db { pool: None })))
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(describe["did_webvh"]["enabled"], true);
    assert_eq!(
        describe["did_webvh"]["providers"][0]["id"],
        "external.webvh"
    );
    assert_eq!(
        describe["did_webvh"]["providers"][0]["base_url"],
        "http://webvh.unreachable.local"
    );
    assert!(
        describe["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile.as_str() == Some("cx.identity.webvh.provider.v1"))
    );
    assert_eq!(
        describe["did_webvh"]["providers"][0]["health"]["active"],
        false
    );
    assert_eq!(
        describe["did_webvh"]["providers"][0]["health"]["probe"],
        "probe_failed_at_boot"
    );
}

#[tokio::test]
async fn embedded_webvh_provider_registers_and_serves_identity() {
    let mut config = test_config();
    config.public_base_url = "https://soland.example".to_owned();
    config.embedded_webvh_provider_enabled = true;
    config.embedded_webvh_registration_bearer = Some("test-webvh-token".to_owned());
    config.did_resolver_allow_methods = vec![
        "web".to_owned(),
        "key".to_owned(),
        "uuid".to_owned(),
        "webvh".to_owned(),
    ];
    let state = AppState::new(config, Db { pool: None });

    let describe: Value = TestClient::get("http://server/api/v1/identity/describe")
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        describe["did_webvh"]["default_provider_id"],
        "soland.embedded"
    );
    assert_eq!(
        describe["did_webvh"]["providers"][0]["id"],
        "soland.embedded"
    );
    assert_eq!(describe["did_webvh"]["providers"][0]["default"], true);
    assert_eq!(describe["did_webvh"]["providers"][0]["active"], true);
    assert_eq!(
        describe["did_webvh"]["providers"][0]["registration_auth"]["configured"],
        true
    );
    assert_eq!(
        describe["did_webvh"]["providers"][0]["document_url_template"],
        "https://soland.example/webvh/{local_id}/did.json"
    );
    assert_eq!(
        describe["did_webvh"]["providers"][0]["log_url_template"],
        "https://soland.example/webvh/{local_id}/did.jsonl"
    );

    let unauthorized = TestClient::post("http://server/api/v1/identity/webvh/register")
        .json(&serde_json::json!({
            "local_id": "mallory",
            "did_public_key_multibase": "z6Mkmallory",
            "update_public_key_multibase": "z6Mkmalloryupdate"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthorized.status_code.unwrap(), StatusCode::UNAUTHORIZED);

    let reused_key = TestClient::post("http://server/api/v1/identity/webvh/register")
        .add_header("authorization", "Bearer test-webvh-token", true)
        .json(&serde_json::json!({
            "local_id": "reused",
            "did_public_key_multibase": "z6Mkreused",
            "update_public_key_multibase": "z6Mkreused"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(reused_key.status_code.unwrap(), StatusCode::BAD_REQUEST);

    let did_signing = SigningKey::from_bytes(&[41u8; 32]);
    let update_signing = SigningKey::from_bytes(&[42u8; 32]);
    let did_public_key = test_ed25519_multibase_public(&did_signing);
    let update_public_key = test_ed25519_multibase_public(&update_signing);
    let version_time = "2026-05-12T00:00:00Z";
    let proof = test_embedded_webvh_proof(
        "https://soland.example",
        "alice",
        &did_public_key,
        &update_public_key,
        "did-key-1",
        &update_signing,
        version_time,
    );

    let registered: Value = TestClient::post("http://server/api/v1/identity/webvh/register")
        .add_header("authorization", "Bearer test-webvh-token", true)
        .json(&serde_json::json!({
            "local_id": "alice",
            "did_public_key_multibase": did_public_key,
            "update_public_key_multibase": update_public_key,
            "did_key_id": "did-key-1",
            "update_key_id": "update-key-1",
            "also_known_as": ["acct:alice@example.com"],
            "version_time": version_time,
            "proof": proof,
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(registered["status"], "created");
    assert!(
        registered["did"]
            .as_str()
            .unwrap()
            .starts_with("did:webvh:z")
    );
    assert!(
        registered["did"]
            .as_str()
            .unwrap()
            .ends_with(":soland.example:webvh:alice")
    );
    assert!(
        !registered["did"]
            .as_str()
            .unwrap()
            .contains(":api:v1:identity:")
    );
    assert_eq!(
        registered["document_url"],
        "https://soland.example/webvh/alice/did.json"
    );
    assert_eq!(
        registered["did_key_id"],
        format!("{}#did-key-1", registered["did"].as_str().unwrap())
    );
    assert_eq!(
        registered["update_key_id"],
        format!("{}#update-key-1", registered["did"].as_str().unwrap())
    );

    let did_document: Value = TestClient::get("http://server/webvh/alice/did.json")
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(did_document["id"], registered["did"]);
    assert_eq!(
        did_document["verificationMethod"][0]["publicKeyMultibase"],
        did_public_key
    );
    assert_eq!(did_document["authentication"][0], registered["did_key_id"]);
    assert_eq!(did_document["assertionMethod"][0], registered["did_key_id"]);

    let mut log_response = TestClient::get("http://server/webvh/alice/did.jsonl")
        .send(&app_from_state(state.clone()))
        .await;
    let log_body = log_response.take_string().await.unwrap();
    assert!(log_body.contains("\"versionId\""));
    assert!(log_body.contains("\"did:webvh:1.0\""));
    assert!(log_body.contains(&update_public_key));
    assert!(!log_body.contains(&format!("\"updateKeys\":[\"{did_public_key}\"]")));
    assert!(log_body.contains("\"DataIntegrityProof\""));

    let resolved: Value = TestClient::post("http://server/api/v1/identity/resolve")
        .json(&serde_json::json!({"did": registered["did"]}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resolved["did_document"]["id"], registered["did"]);
    assert_eq!(resolved["key_log_head"], registered["key_log_head"]);
}

fn test_ed25519_multibase_public(signing: &SigningKey) -> String {
    let mut bytes = Vec::with_capacity(34);
    bytes.extend_from_slice(&[0xed, 0x01]);
    bytes.extend_from_slice(signing.verifying_key().as_bytes());
    format!("z{}", bs58::encode(bytes).into_string())
}

fn test_embedded_webvh_proof(
    principal_server_url: &str,
    local_id: &str,
    did_public_key_multibase: &str,
    update_public_key_multibase: &str,
    did_key_fragment: &str,
    update_signing: &SigningKey,
    version_time: &str,
) -> Value {
    let method_authority = test_webvh_method_authority(principal_server_url);
    let placeholder_did = format!("did:webvh:{{SCID}}:{method_authority}:webvh:{local_id}");
    let did_key_id = format!("{placeholder_did}#{did_key_fragment}");
    let skeleton = serde_json::json!({
        "versionId": "0-{SCID}",
        "versionTime": version_time,
        "parameters": {
            "scid": "{SCID}",
            "method": "did:webvh:1.0",
            "updateKeys": [update_public_key_multibase],
        },
        "state": {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": placeholder_did,
            "verificationMethod": [{
                "id": did_key_id,
                "type": "Multikey",
                "controller": placeholder_did,
                "publicKeyMultibase": did_public_key_multibase,
            }],
            "authentication": [did_key_id],
            "assertionMethod": [did_key_id],
            "alsoKnownAs": ["acct:alice@example.com"],
            "service": [{
                "id": format!("{placeholder_did}#soland"),
                "type": "ContrixPrincipalServer",
                "serviceEndpoint": principal_server_url.trim_end_matches('/'),
            }],
        },
    });
    let scid = test_scid(&skeleton);
    let did = format!("did:webvh:{scid}:{method_authority}:webvh:{local_id}");
    let mut entry = test_replace_scid(skeleton, &scid);
    let entry_hash = test_webvh_entry_hash(&entry);
    if let Value::Object(map) = &mut entry {
        map.insert(
            "versionId".to_owned(),
            Value::String(format!("1-{entry_hash}")),
        );
    }
    let payload = contrix_sdk::canonical::canonical_json_bytes(&entry).unwrap();
    let signature = update_signing.sign(&payload);
    serde_json::json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "proofPurpose": "authentication",
        "verificationMethod": format!("{did}#{update_public_key_multibase}"),
        "proofValue": format!("z{}", bs58::encode(signature.to_bytes()).into_string()),
    })
}

fn test_webvh_method_authority(url: &str) -> String {
    let authority = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url)
        .trim_end_matches('/')
        .split('/')
        .next()
        .unwrap_or(url);
    authority.replace(':', "%3A")
}

fn test_scid(value: &Value) -> String {
    let canonical = contrix_sdk::canonical::canonical_json_bytes(value).unwrap();
    test_sha256_multihash_multibase(&canonical)
}

fn test_webvh_entry_hash(value: &Value) -> String {
    let mut clone = value.clone();
    if let Value::Object(map) = &mut clone {
        map.remove("proof");
        map.remove("versionId");
    }
    let canonical = contrix_sdk::canonical::canonical_json_bytes(&clone).unwrap();
    test_sha256_multihash_multibase(&canonical)
}

fn test_replace_scid(value: Value, scid: &str) -> Value {
    serde_json::from_str(
        &serde_json::to_string(&value)
            .unwrap()
            .replace("{SCID}", scid),
    )
    .unwrap()
}

fn test_sha256_multihash_multibase(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut multihash = Vec::with_capacity(34);
    multihash.push(0x12);
    multihash.push(0x20);
    multihash.extend_from_slice(&digest);
    format!("z{}", bs58::encode(multihash).into_string())
}

#[tokio::test]
async fn sync_directory_and_index_share_demo_space() {
    let sync_describe: Value = TestClient::get("http://server/api/v1/sync/describe")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    for profile in ["board", "chat", "topic"] {
        assert!(
            sync_describe["supported_sync_profiles"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == profile)
        );
    }

    let invalid_profile = TestClient::post("http://server/api/v1/sync")
        .json(&serde_json::json!({"profile": "invalid"}))
        .send(&app())
        .await;
    assert_eq!(invalid_profile.status_code.unwrap().as_u16(), 400);

    let sync: Value = TestClient::post("http://server/api/v1/sync")
        .json(&serde_json::json!({"profile": "chat"}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        sync["spaces"]
            .as_object()
            .unwrap()
            .contains_key("cx:space:0196419b-0000-7000-8000-000000000000")
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
        .json(&serde_json::json!({"space_ids": ["cx:space:0196419b-0000-7000-8000-000000000000"]}))
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
async fn standard_entity_types_and_reverse_domain_custom_types_work() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let space_id = "cx:space:0196419b-0000-7000-8000-000000000000";

    let invalid = TestClient::post("http://server/api/v1/entities")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "space_id": space_id,
            "entity_type": "todo",
            "title": "Invalid"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(invalid.status_code.unwrap().as_u16(), 400);

    let unsupported_standard = TestClient::post("http://server/api/v1/entities")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "space_id": space_id,
            "entity_type": "cx.unsupported.object",
            "title": "Unsupported"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unsupported_standard.status_code.unwrap().as_u16(), 400);

    for (entity_type, title) in [
        ("cx.task", "Task"),
        ("cx.channel", "Support"),
        ("cx.topic", "Roadmap"),
        ("cx.memory.semantic", "Decision memory"),
        ("cx.agent.run", "Agent run"),
        ("com.example.widget", "Custom widget"),
    ] {
        let entity: Value = TestClient::post("http://server/api/v1/entities")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&serde_json::json!({
                "space_id": space_id,
                "entity_type": entity_type,
                "title": title,
                "content": {"status": "active"},
                "fields": {"kind": entity_type}
            }))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
        assert_eq!(entity["entity_type"], entity_type);
    }

    let channels: Value = TestClient::get(format!(
        "http://server/api/v1/entities?space_id={space_id}&entity_type=cx.channel"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(channels["entities"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn view_endpoints_project_common_presentation_shapes() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let space_id = "cx:space:0196419b-0000-7000-8000-000000000000";

    let mut entities = Vec::new();
    for (title, status, due_at, priority, facets) in [
        (
            "Draft spec",
            "todo",
            "2026-05-01T00:00:00Z",
            2,
            serde_json::json!({"rankable": {"rank_field": "priority"}, "stateful": {"field": "status"}}),
        ),
        (
            "Ship reducer",
            "done",
            "2026-05-02T00:00:00Z",
            1,
            serde_json::json!(["renderable", "stateful"]),
        ),
    ] {
        let entity: Value = TestClient::post("http://server/api/v1/entities")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&serde_json::json!({
                "space_id": space_id,
                "entity_type": "cx.task",
                "facets": facets,
                "title": title,
                "content": {"description": title},
                "fields": {
                    "status": status,
                    "due_at": due_at,
                    "priority": priority
                }
            }))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
        assert_eq!(entity["entity_type"], "cx.task");
        entities.push(entity);
    }

    let kanban: Value = TestClient::post("http://server/api/v1/views")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "space_id": space_id,
            "kind": "kanban",
            "title": "Task board",
            "entity_type": "cx.task",
            "options": {"group_by": "status"}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(kanban["projection"]["kind"], "kanban");
    assert_eq!(kanban["projection"]["group_by"], "status");
    assert_eq!(kanban["projection"]["columns"].as_array().unwrap().len(), 2);

    let table: Value = TestClient::post("http://server/api/v1/views")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "space_id": space_id,
            "kind": "table",
            "entity_type": "cx.task"
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(table["projection"]["kind"], "table");
    assert_eq!(table["projection"]["rows"].as_array().unwrap().len(), 2);
    assert!(
        table["projection"]["columns"]
            .as_array()
            .unwrap()
            .iter()
            .any(|column| column["key"] == "status")
    );

    let calendar: Value = TestClient::post("http://server/api/v1/views")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "space_id": space_id,
            "kind": "calendar",
            "entity_type": "cx.task",
            "options": {"date_field": "due_at"}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(calendar["projection"]["kind"], "calendar");
    assert_eq!(
        calendar["projection"]["events"].as_array().unwrap().len(),
        2
    );
    assert_eq!(
        calendar["projection"]["events"][0]["start"],
        "2026-05-01T00:00:00Z"
    );

    let collection: Value = TestClient::post("http://server/api/v1/views")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "space_id": space_id,
            "kind": "collection",
            "entity_type": "cx.task",
            "options": {"item_facets": {"stateful": {"field": "status"}}}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(collection["projection"]["kind"], "collection");
    assert_eq!(
        collection["projection"]["item_facets"],
        serde_json::json!(["stateful"])
    );
    assert_eq!(
        collection["projection"]["items"].as_array().unwrap().len(),
        2
    );

    let graph: Value = TestClient::post("http://server/api/v1/views")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "space_id": space_id,
            "kind": "graph",
            "entity_type": "cx.task",
            "options": {"node_facets": ["rankable"]}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(graph["projection"]["kind"], "graph");
    assert_eq!(graph["projection"]["nodes"].as_array().unwrap().len(), 1);

    let facet_grant: Value = TestClient::post("http://server/api/v1/authz/grants")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "space_id": space_id,
            "subject": "did:web:bob.example",
            "resource": "entity:*",
            "actions": ["entity.update"],
            "constraints": [{"type": "allowed_entity_facets", "facets": ["rankable"]}]
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(facet_grant["subject"], "did:web:bob.example");

    let rankable_authz: Value = TestClient::post("http://server/api/v1/authz/check")
        .json(&serde_json::json!({
            "actor": "did:web:bob.example",
            "action": "entity.update",
            "resource": {
                "kind": "entity",
                "space_id": space_id,
                "entity_id": entities[0]["entity_id"]
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(rankable_authz["allowed"], true);

    let non_rankable_authz: Value = TestClient::post("http://server/api/v1/authz/check")
        .json(&serde_json::json!({
            "actor": "did:web:bob.example",
            "action": "entity.update",
            "resource": {
                "kind": "entity",
                "space_id": space_id,
                "entity_id": entities[1]["entity_id"]
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(non_rankable_authz["allowed"], false);
    assert_eq!(
        non_rankable_authz["reason_code"].as_str().unwrap(),
        "constraints_not_satisfied"
    );
    assert!(
        non_rankable_authz["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("allowed_entity_facets"))
    );

    let timeline: Value = TestClient::get(format!(
        "http://server/api/v1/views/virtual-timeline?space_id={space_id}&entity_type=cx.task&kind=timeline"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(timeline["projection"]["kind"], "timeline");
    assert_eq!(timeline["projection"]["items"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn index_product_endpoints_return_demo_projection_shapes() {
    let entity: Value = TestClient::get(
        "http://server/api/v1/index/entity?entity_id=cx:space:0196419b-0000-7000-8000-000000000000",
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
    assert_eq!(inbox["flows"].as_array().unwrap().len(), 1);
    assert_eq!(inbox["flows"][0]["flow"]["schema"], "cx.schema.flow.v1");

    let search: Value = TestClient::post("http://server/api/v1/index/search")
        .json(&serde_json::json!({"query": "demo", "entity_types": ["space"], "limit": 5}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(search["results"].as_array().unwrap().len(), 1);

    let hierarchy: Value = TestClient::get(
        "http://server/api/v1/index/space-hierarchy?root_space_id=cx:space:0196419b-0000-7000-8000-000000000000",
    )
    .send(&app())
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        hierarchy["root_space_id"],
        "cx:space:0196419b-0000-7000-8000-000000000000"
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
    assert_eq!(directory_describe["service_did"], "did:web:soland.local");

    let resolved: Value = TestClient::post("http://server/api/v1/directory/resolve-space")
        .json(&serde_json::json!({"space_id": "cx:space:0196419b-0000-7000-8000-000000000000"}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        resolved["space_preview"]["space_id"],
        "cx:space:0196419b-0000-7000-8000-000000000000"
    );

    let backfill: Value = TestClient::get(
        "http://server/api/v1/events?space_id=cx:space:0196419b-0000-7000-8000-000000000000",
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
    assert!(!repo["supported_signatures"].as_array().unwrap().is_empty());

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
            "resource": {"kind": "space", "space_id": "cx:space:0196419b-0000-7000-8000-000000000000"}
        }))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(authz["allowed"], true);

    let ice: Value = TestClient::post("http://server/contrix/v1/ice-config")
        .json(&serde_json::json!({}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(ice["service_did"], "did:web:soland.local");
    assert!(ice["ice_servers"].is_array());
}

#[tokio::test]
async fn admin_collection_surfaces_return_sodmin_shapes() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let unauthenticated = TestClient::get("http://server/api/v1/admin/actors")
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthenticated.status_code, Some(StatusCode::UNAUTHORIZED));

    let collections = [
        ("actors", "actors"),
        ("spaces", "spaces"),
        ("devices", "devices"),
        ("capabilities", "capabilities"),
        ("federation", "federation"),
        ("applets", "applets"),
        ("agents", "agents"),
        ("reports", "reports"),
        ("invite-tokens", "invite_tokens"),
        ("audit", "audit"),
        ("policy", "policy"),
        ("media", "media"),
    ];
    for (resource, field) in collections {
        let body: Value = TestClient::get(format!("http://server/api/v1/admin/{resource}?limit=5"))
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
        assert_eq!(body["resource"], resource);
        assert!(body["items"].is_array(), "admin {resource} missing items");
        assert!(
            body[field].is_array(),
            "admin {resource} missing typed field"
        );
        assert_eq!(
            body["production_gap"],
            "admin_authorization_and_durable_pagination"
        );
    }

    let actors: Value = TestClient::get("http://server/api/v1/admin/actors")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        actors["actors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|actor| { actor["did"] == "did:web:alice.example" && actor["kind"] == "actor" })
    );

    let devices: Value = TestClient::get("http://server/api/v1/admin/devices")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(devices["devices"].as_array().unwrap().iter().any(|device| {
        device["actor"] == "did:web:alice.example" && device["device_id"] == "dev_alice"
    }));

    let unknown = TestClient::get("http://server/api/v1/admin/not-real")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state))
        .await;
    assert_eq!(unknown.status_code, Some(StatusCode::NOT_FOUND));
}

#[tokio::test]
async fn device_pairing_challenge_and_authorization_surface_work() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let unauthenticated = TestClient::post("http://server/api/v1/devices/pairing-challenge")
        .json(&serde_json::json!({"device_id": "dev_phone"}))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthenticated.status_code, Some(StatusCode::UNAUTHORIZED));

    let challenge: Value = TestClient::post("http://server/api/v1/devices/pairing-challenge")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({"device_id": "dev_phone"}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        challenge["challenge_id"]
            .as_str()
            .unwrap()
            .starts_with("cx:device_pairing:")
    );
    assert_eq!(challenge["device_id"], "dev_phone");
    assert_eq!(
        challenge["production_gap"],
        "device_pairing_proof_verification"
    );

    let authorized: Value = TestClient::post("http://server/api/v1/devices/authorize-pairing")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "challenge_id": challenge["challenge_id"],
            "device_id": "dev_phone",
            "display_name": "Paired Phone",
            "proof": {"alg": "dev-none"}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(authorized["status"], "authorized");
    assert_eq!(authorized["device"]["device_id"], "dev_phone");
    assert_eq!(
        authorized["authorization_event"]["event_kind"],
        "cx.device.pairing.authorized"
    );
    assert_eq!(
        authorized["production_gap"],
        "authorization_event_not_yet_in_operation_stream"
    );
    assert!(
        state
            .persistence
            .audit()
            .snapshot_all()
            .unwrap()
            .iter()
            .any(|event| {
                event["action"] == "device.authorize_pairing"
                    && event["outcome"] == "accepted"
                    && event["target"]["target_device_id"] == "dev_phone"
            })
    );
}

#[tokio::test]
async fn webrtc_signaling_contracts_work() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let unauthenticated = TestClient::post("http://server/api/v1/webrtc/sessions")
        .json(&serde_json::json!({
            "space_id": "cx:space:0196419b-0000-7000-8000-000000000000"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthenticated.status_code, Some(StatusCode::UNAUTHORIZED));

    let session: Value = TestClient::post("http://server/api/v1/webrtc/sessions")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "space_id": "cx:space:0196419b-0000-7000-8000-000000000000",
            "participants": ["did:web:alice.example"],
            "ttl_ms": 60000
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let session_id = session["session_id"].as_str().unwrap().to_owned();
    assert!(session_id.starts_with("cx:webrtc:"));
    assert_eq!(session["participants"].as_array().unwrap().len(), 1);

    let unsigned_signal = TestClient::post(format!(
        "http://server/api/v1/webrtc/sessions/{session_id}/signals"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .json(&serde_json::json!({
        "message_type": "offer",
        "payload": {"description_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
    }))
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(unsigned_signal.status_code.unwrap().as_u16(), 400);

    let signal: Value = TestClient::post(format!(
        "http://server/api/v1/webrtc/sessions/{session_id}/signals"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .json(&serde_json::json!({
        "message_type": "offer",
        "payload": {
            "description_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "encrypted_description_ref": "cx:blob:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        },
        "proofs": [{"kid": "did:web:alice.example#device", "sig": "dev"}]
    }))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(signal["seq"], 1);
    assert_eq!(signal["next_cursor"], "1");

    let events: Value = TestClient::get(format!(
        "http://server/api/v1/webrtc/sessions/{session_id}/signals?since=0"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(events["events"].as_array().unwrap().len(), 1);
    assert_eq!(events["events"][0]["type"], "offer");
    assert_eq!(events["events"][0]["sender"], "did:web:alice.example");

    let empty_events: Value = TestClient::get(format!(
        "http://server/api/v1/webrtc/sessions/{session_id}/signals?since=1"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert!(empty_events["events"].as_array().unwrap().is_empty());

    let closed: Value =
        TestClient::delete(format!("http://server/api/v1/webrtc/sessions/{session_id}"))
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(closed["ok"], true);

    let after_close = TestClient::get(format!(
        "http://server/api/v1/webrtc/sessions/{session_id}/signals"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state))
    .await;
    assert_eq!(after_close.status_code.unwrap().as_u16(), 404);
}

#[tokio::test]
async fn federation_rejects_replayed_operations() {
    let state = AppState::new(test_config(), Db { pool: None });
    let operation = Operation::create(
        OperationId::new("cx:operation:01904100-0000-7000-8000-4b147e97831e").unwrap(),
        SpaceId::new("cx:space:01904100-0000-7000-8000-20d6cfd24be6").unwrap(),
        kinds::CX_MESSAGE_CREATE,
        serde_json::json!({
            "event_id": "cx:event:01904100-0000-7000-8000-19d11d370b0e",
            "sender": "did:web:remote.example",
            "thread_id": "cx:thread:federation",
            "body": "from federation"
        }),
    );

    let first: Value = TestClient::post("http://server/api/v1/federation/push-operations")
        .json(&serde_json::json!({
            "origin": "did:web:remote.example",
            "destination": "did:web:soland.local",
            "space_id": "cx:space:01904100-0000-7000-8000-20d6cfd24be6",
            "service_binding_ref": "did:web:remote.example#soland",
            "operations": [operation.clone()]
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        first["accepted"][0],
        "cx:operation:01904100-0000-7000-8000-4b147e97831e"
    );
    assert!(first["rejected"].as_array().unwrap().is_empty());

    let pulled: Value = TestClient::get(
        "http://server/api/v1/federation/pull-operations?space_id=cx:space:01904100-0000-7000-8000-20d6cfd24be6",
    )
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        pulled["operations"][0]["operation_id"],
        "cx:operation:01904100-0000-7000-8000-4b147e97831e"
    );

    let bootstrap: Value = TestClient::get(
        "http://server/api/v1/federation/pull-operations?space_id=cx:space:01904100-0000-7000-8000-20d6cfd24be6&snapshot_bootstrap=true",
    )
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        bootstrap["snapshot_bootstrap"]["manifest"]["space_id"],
        "cx:space:01904100-0000-7000-8000-20d6cfd24be6"
    );
    assert!(
        bootstrap["snapshot_bootstrap"]["state_hash"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );

    let replay: Value = TestClient::post("http://server/api/v1/federation/push-operations")
        .json(&serde_json::json!({
            "origin": "did:web:remote.example",
            "destination": "did:web:soland.local",
            "space_id": "cx:space:01904100-0000-7000-8000-20d6cfd24be6",
            "service_binding_ref": "did:web:remote.example#soland",
            "operations": [operation]
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(replay["accepted"].as_array().unwrap().is_empty());
    assert_eq!(
        replay["rejected"][0]["operation_id"],
        "cx:operation:01904100-0000-7000-8000-4b147e97831e"
    );
    assert_eq!(replay["rejected"][0]["reason"], "replay");

    let invalid_operation = Operation::create(
        OperationId::new("cx:operation:01904100-0000-7000-8000-1cac81a395b6").unwrap(),
        SpaceId::new("cx:space:01904100-0000-7000-8000-20d6cfd24be6").unwrap(),
        kinds::CX_MESSAGE_CREATE,
        serde_json::json!({
            "event_id": "cx:event:01904100-0000-7000-8000-97aea7e40a20",
            "sender": "did:web:remote.example",
            "encrypted": true,
            "content": {"ciphertext": "missing-envelope-fields"}
        }),
    );
    let invalid_push: Value = TestClient::post("http://server/api/v1/federation/push-operations")
        .json(&serde_json::json!({
            "origin": "did:web:remote.example",
            "destination": "did:web:soland.local",
            "space_id": "cx:space:01904100-0000-7000-8000-20d6cfd24be6",
            "service_binding_ref": "did:web:remote.example#soland",
            "operations": [invalid_operation]
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(invalid_push["accepted"].as_array().unwrap().is_empty());
    assert_eq!(invalid_push["rejected"][0]["reason"], "invalid_semantics");

    let legacy_push_operation = Operation::create(
        OperationId::new("cx:operation:01904100-0000-7000-8000-94aa4d18b027").unwrap(),
        SpaceId::new("cx:space:01904100-0000-7000-8000-20d6cfd24be6").unwrap(),
        kinds::CX_MESSAGE_CREATE,
        serde_json::json!({
            "event_id": "cx:event:01904100-0000-7000-8000-73cff2049160",
            "sender": "did:web:remote.example",
            "room_id": "!legacy:example.com",
            "body": "legacy contract field"
        }),
    );
    let legacy_push: Value = TestClient::post("http://server/api/v1/federation/push-operations")
        .json(&serde_json::json!({
            "origin": "did:web:remote.example",
            "destination": "did:web:soland.local",
            "space_id": "cx:space:01904100-0000-7000-8000-20d6cfd24be6",
            "service_binding_ref": "did:web:remote.example#soland",
            "operations": [legacy_push_operation]
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(legacy_push["accepted"].as_array().unwrap().is_empty());
    assert_eq!(
        legacy_push["rejected"][0]["operation_id"],
        "cx:operation:01904100-0000-7000-8000-94aa4d18b027"
    );
    assert_eq!(legacy_push["rejected"][0]["reason"], "invalid_semantics");
    assert_eq!(
        legacy_push["rejected"][0]["message"],
        "removed legacy subject/room/card contract is forbidden on the active v1 wire"
    );

    let redaction = Operation::create(
        OperationId::new("cx:operation:01904100-0000-7000-8000-fd0b34f35181").unwrap(),
        SpaceId::new("cx:space:01904100-0000-7000-8000-20d6cfd24be6").unwrap(),
        kinds::CX_MESSAGE_REDACT,
        serde_json::json!({
            "event_id": "cx:event:01904100-0000-7000-8000-9494a7271728",
            "target_event_id": "cx:event:01904100-0000-7000-8000-19d11d370b0e"
        }),
    );
    let redaction_push: Value = TestClient::post("http://server/api/v1/federation/push-operations")
        .json(&serde_json::json!({
            "origin": "did:web:remote.example",
            "destination": "did:web:soland.local",
            "space_id": "cx:space:01904100-0000-7000-8000-20d6cfd24be6",
            "service_binding_ref": "did:web:remote.example#soland",
            "operations": [redaction]
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        redaction_push["accepted"][0],
        "cx:operation:01904100-0000-7000-8000-fd0b34f35181"
    );

    let redacted_pull: Value = TestClient::get(
        "http://server/api/v1/federation/pull-operations?space_id=cx:space:01904100-0000-7000-8000-20d6cfd24be6",
    )
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert!(redacted_pull["operations"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn federation_transactions_are_idempotent_by_origin_and_body() {
    let state = AppState::new(test_config(), Db { pool: None });
    let operation = Operation::create(
        OperationId::new("cx:operation:01904100-0000-7000-8000-91a2f2e7a3b4").unwrap(),
        SpaceId::new("cx:space:01904100-0000-7000-8000-788d17d38a52").unwrap(),
        kinds::CX_MESSAGE_CREATE,
        serde_json::json!({
            "event_id": "cx:event:01904100-0000-7000-8000-f10d061a12a7",
            "sender": "did:web:remote.example",
            "thread_id": "cx:thread:federation-txn",
            "body": "transaction body"
        }),
    );

    let transaction_body = serde_json::json!({
        "origin": "did:web:remote.example",
        "destination": "did:web:soland.local",
        "service_binding_ref": "did:web:remote.example#soland",
        "operations": [operation]
    });
    let first: Value = TestClient::put("http://server/api/v1/federation/transactions/txn-idem")
        .json(&transaction_body)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        first["accepted"][0],
        "cx:operation:01904100-0000-7000-8000-91a2f2e7a3b4"
    );

    let duplicate: Value = TestClient::put("http://server/api/v1/federation/transactions/txn-idem")
        .json(&transaction_body)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        duplicate["accepted"][0],
        "cx:operation:01904100-0000-7000-8000-91a2f2e7a3b4"
    );
    assert!(duplicate["rejected"].as_array().unwrap().is_empty());

    let conflict = TestClient::put("http://server/api/v1/federation/transactions/txn-idem")
        .json(&serde_json::json!({
            "origin": "did:web:remote.example",
            "destination": "did:web:soland.local",
            "service_binding_ref": "did:web:remote.example#soland",
            "operations": [],
            "receipts": [{"changed": true}]
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(conflict.status_code.unwrap().as_u16(), 409);

    let wrong_destination =
        TestClient::put("http://server/api/v1/federation/transactions/txn-wrong-destination")
            .json(&serde_json::json!({
                "origin": "did:web:remote.example",
                "destination": "did:web:other.example",
                "service_binding_ref": "did:web:remote.example#soland",
                "operations": []
            }))
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(wrong_destination.status_code.unwrap().as_u16(), 403);

    let legacy_transaction_operation = Operation::create(
        OperationId::new("cx:operation:01904100-0000-7000-8000-e4214375a21c").unwrap(),
        SpaceId::new("cx:space:01904100-0000-7000-8000-788d17d38a52").unwrap(),
        kinds::CX_MESSAGE_CREATE,
        serde_json::json!({
            "event_id": "cx:event:01904100-0000-7000-8000-38e7dab19280",
            "sender": "did:web:remote.example",
            "flow_id": "cx:card:legacy-card",
            "body": "legacy typed id"
        }),
    );
    let legacy_transaction: Value =
        TestClient::put("http://server/api/v1/federation/transactions/txn-legacy-contract")
            .json(&serde_json::json!({
                "origin": "did:web:remote.example",
                "destination": "did:web:soland.local",
                "service_binding_ref": "did:web:remote.example#soland",
                "operations": [legacy_transaction_operation]
            }))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert!(
        legacy_transaction["accepted"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        legacy_transaction["rejected"][0]["operation_id"],
        "cx:operation:01904100-0000-7000-8000-e4214375a21c"
    );
    assert_eq!(
        legacy_transaction["rejected"][0]["reason"],
        "invalid_semantics"
    );
    assert_eq!(
        legacy_transaction["rejected"][0]["message"],
        "removed legacy subject/room/card contract is forbidden on the active v1 wire"
    );
}

#[tokio::test]
async fn push_profile_and_moderation_contracts_work() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let unauth_presence = TestClient::post("http://server/api/v1/sync")
        .json(&serde_json::json!({"set_presence": "online"}))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauth_presence.status_code, Some(StatusCode::UNAUTHORIZED));

    let presence_sync: Value = TestClient::post("http://server/api/v1/sync")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({"set_presence": "unavailable"}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(presence_sync["next_batch"].is_string());

    let profile: Value =
        TestClient::get("http://server/api/v1/profile/presence?did=did:web:alice.example")
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(profile["actor"], "did:web:alice.example");
    assert_eq!(profile["presence"]["status"], "unavailable");

    let unauth_typing = TestClient::post("http://server/api/v1/sync/typing")
        .json(&serde_json::json!({
            "space_id": "cx:space:0196419b-0000-7000-8000-000000000000",
            "typing": true
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauth_typing.status_code, Some(StatusCode::UNAUTHORIZED));

    let typing: Value = TestClient::post("http://server/api/v1/sync/typing")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "space_id": "cx:space:0196419b-0000-7000-8000-000000000000",
            "scope_id": "cx:thread:demo",
            "typing": true,
            "timeout_ms": 30000
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(typing["typing"], true);
    assert!(typing["expires_at"].is_string());

    let sync_with_typing: Value = TestClient::post("http://server/api/v1/sync")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let ephemeral =
        &sync_with_typing["spaces"]["cx:space:0196419b-0000-7000-8000-000000000000"]["ephemeral"];
    assert_eq!(ephemeral[0]["type"], "cx.typing");
    assert_eq!(ephemeral[0]["scope_id"], "cx:thread:demo");
    assert_eq!(ephemeral[0]["actors"][0]["actor"], "did:web:alice.example");

    let typing_stopped: Value = TestClient::post("http://server/api/v1/sync/typing")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "space_id": "cx:space:0196419b-0000-7000-8000-000000000000",
            "typing": false
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(typing_stopped["typing"], false);

    let sync_without_typing: Value = TestClient::post("http://server/api/v1/sync")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        sync_without_typing["spaces"]["cx:space:0196419b-0000-7000-8000-000000000000"]["ephemeral"]
            .as_array()
            .unwrap()
            .is_empty()
    );

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

    let initial_rules: Value = TestClient::get("http://server/api/v1/push/rules")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(initial_rules["rules"].as_array().unwrap().is_empty());

    let push_rule: Value = TestClient::post("http://server/api/v1/push/rules")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "rule_id": "mute-device",
            "enabled": true,
            "actions": ["dont_notify"],
            "conditions": {
                "device_id": "dev_alice",
                "type": "blind_wakeup"
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(push_rule["ok"], true);
    assert_eq!(push_rule["rule"]["rule_id"], "mute-device");

    let listed_rules: Value = TestClient::get("http://server/api/v1/push/rules")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(listed_rules["rules"].as_array().unwrap().len(), 1);

    let muted_notify: Value = TestClient::post("http://server/api/v1/push/notify")
        .json(&serde_json::json!({
            "notification": {
                "type": "blind_wakeup",
                "devices": [{"device_id": "dev_alice"}, {"device_id": "dev_missing"}]
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let rejected = muted_notify["rejected"].as_array().unwrap();
    assert_eq!(rejected.len(), 2);
    assert!(rejected.iter().any(|device| {
        device["device_id"] == "dev_alice"
            && device["reason"] == "push_rule"
            && device["rule_id"] == "mute-device"
    }));
    assert!(rejected.iter().any(|device| {
        device["device_id"] == "dev_missing" && device["reason"] == "unknown_device"
    }));

    let deleted_rule: Value = TestClient::delete("http://server/api/v1/push/rules/mute-device")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(deleted_rule["ok"], true);

    let unmuted_notify: Value = TestClient::post("http://server/api/v1/push/notify")
        .json(&serde_json::json!({
            "notification": {
                "type": "blind_wakeup",
                "devices": [{"device_id": "dev_alice"}]
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(unmuted_notify["rejected"].as_array().unwrap().is_empty());

    let report: Value = TestClient::post("http://server/api/v1/moderation/report")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "space_id": "cx:space:0196419b-0000-7000-8000-000000000000",
            "target_ref": "cx:event:01904100-0000-7000-8000-4a4116cba4e8",
            "reason": "spam",
            "reporter": "did:web:alice.example"
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(report["status"], "queued");
    assert!(
        state
            .persistence
            .audit()
            .snapshot_all()
            .unwrap()
            .iter()
            .any(|entry| {
                entry["action"] == "moderation.report" && entry["outcome"] == "queued"
            })
    );
    assert!(
        state
            .persistence
            .moderation()
            .list_actions()
            .unwrap()
            .iter()
            .any(|action| action["report_id"] == report["report_id"] && action["status"] == "open")
    );

    let unauthenticated_report = TestClient::post("http://server/api/v1/moderation/report")
        .json(&serde_json::json!({
            "space_id": "cx:space:0196419b-0000-7000-8000-000000000000",
            "target_ref": "cx:event:01904100-0000-7000-8000-4a4116cba4e8",
            "reason": "spam",
            "reporter": "did:web:alice.example"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthenticated_report.status_code.unwrap().as_u16(), 401);
}

#[tokio::test]
async fn auth_keys_device_messages_and_blobs_work() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let upload: Value = TestClient::post("http://server/api/v1/keys/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "device_id": "dev_alice",
            "device_keys": {"alg": "mls-rfc9420", "key": "alice-device-key"},
            "principal_signing_keys": [{"kid": "did:web:alice.example#principal", "key": "principal-key"}],
            "recovery_keys": [{"kid": "did:web:alice.example#recovery", "key": "recovery-key"}],
            "session_keys": [{"kid": "did:web:alice.example#session", "key": "session-key"}],
            "agent_keys": [{"kid": "did:web:alice.example#agent", "key": "agent-key"}],
            "one_time_keys": [{"key_id": "otk1", "key": "one-time"}],
            "fallback_keys": {"signed_curve25519:fallback": {"key": "fallback-key"}},
            "mls_key_packages": [{"package_id": "mls-package-1", "key": "opaque-package"}],
            "backup_restore_keys": [{"kid": "did:web:alice.example#backup", "key": "backup-key"}],
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
    assert_eq!(
        query["device_keys"]["did:web:alice.example"]["dev_alice"]["principal_signing_keys"][0]["key"],
        "principal-key"
    );
    assert_eq!(
        query["device_keys"]["did:web:alice.example"]["dev_alice"]["recovery_keys"][0]["key"],
        "recovery-key"
    );
    assert_eq!(
        query["device_keys"]["did:web:alice.example"]["dev_alice"]["session_keys"][0]["key"],
        "session-key"
    );
    assert_eq!(
        query["device_keys"]["did:web:alice.example"]["dev_alice"]["agent_keys"][0]["key"],
        "agent-key"
    );
    assert_eq!(
        query["device_keys"]["did:web:alice.example"]["dev_alice"]["backup_restore_keys"][0]["key"],
        "backup-key"
    );

    let invalid_device_message = TestClient::post("http://server/api/v1/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "bad-txn", true)
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
        .await;
    assert_eq!(invalid_device_message.status_code.unwrap().as_u16(), 400);

    let send: Value = TestClient::post("http://server/api/v1/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "txn1", true)
        .json(&serde_json::json!({
            "messages": {
                "did:web:alice.example": {
                    "dev_alice": {
                        "type": "cx.mls.welcome",
                        "content": encrypted_envelope("cx.mls.welcome", "opaque")
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

    let duplicate: Value = TestClient::post("http://server/api/v1/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "txn1", true)
        .json(&serde_json::json!({
            "messages": {
                "did:web:alice.example": {
                    "dev_alice": {
                        "type": "cx.mls.welcome",
                        "content": encrypted_envelope("cx.mls.welcome", "opaque")
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
        .add_header(
            "x-contrix-sha256",
            "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            true,
        )
        .body("encrypted-bytes")
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(bad_blob.status_code.unwrap().as_u16(), 409);

    let bad_attachment = TestClient::post("http://server/api/v1/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header(
            "x-contrix-attachment-envelope",
            serde_json::json!({
                "algorithm": "mls-rfc9420",
                "nonce": "nonce",
                "key_ref": {"kid": "did:web:alice.example#device"},
                "ciphertext_digest": "sha256:bad"
            })
            .to_string(),
            true,
        )
        .body("encrypted-bytes")
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(bad_attachment.status_code.unwrap().as_u16(), 400);

    let missing_envelope = TestClient::post("http://server/api/v1/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("x-contrix-blob-encrypted", "true", true)
        .body("encrypted-bytes")
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(missing_envelope.status_code.unwrap().as_u16(), 400);

    let locked_space: Value = TestClient::post("http://server/api/v1/spaces")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "title": "Blob Policy Space",
            "public": false
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let plaintext_private_blob = TestClient::post("http://server/api/v1/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header(
            "x-contrix-space-id",
            locked_space["space_id"].as_str().unwrap(),
            true,
        )
        .body("plaintext-private")
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(plaintext_private_blob.status_code.unwrap().as_u16(), 403);

    let blob: Value = TestClient::post("http://server/api/v1/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "Text/Plain; charset=utf-8", true)
        .add_header("x-contrix-filename", "..\\danger<script>.txt", true)
        .add_header(
            "x-contrix-attachment-envelope",
            serde_json::json!({
                "algorithm": "mls-rfc9420",
                "nonce": "nonce",
                "key_ref": {"kid": "did:web:alice.example#device"},
                "ciphertext_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            })
            .to_string(),
            true,
        )
        .body("encrypted-bytes")
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(blob["size"], 15);
    assert_eq!(blob["media_type"], "text/plain");
    assert_eq!(blob["upload_receipt"]["filename"], "danger_script_.txt");
    assert!(
        blob["blob_ref"]
            .as_str()
            .unwrap()
            .starts_with("cx:blob:sha256:")
    );
    assert_eq!(
        blob["upload_receipt"]["encrypted_attachment"]["algorithm"],
        "mls-rfc9420"
    );
    let ObjectStorageConfig::Local { root, .. } = test_config().object_storage else {
        panic!("test config uses local object storage");
    };
    let blob_path = root.join("sha256").join(blob["sha256"].as_str().unwrap());
    assert_eq!(std::fs::read(blob_path).unwrap(), b"encrypted-bytes");

    let anonymous_blob = TestClient::get(format!(
        "http://server/api/v1/blob/get?blob_ref={}&purpose=message_attachment",
        blob["blob_ref"].as_str().unwrap()
    ))
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(anonymous_blob.status_code.unwrap().as_u16(), 401);

    let body = TestClient::get(format!(
        "http://server/api/v1/blob/get?blob_ref={}&purpose=message_attachment",
        blob["blob_ref"].as_str().unwrap()
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_string()
    .await
    .unwrap();
    assert_eq!(body, "encrypted-bytes");

    let mut range = TestClient::get(format!(
        "http://server/api/v1/blob/get?blob_ref={}&purpose=message_attachment",
        blob["blob_ref"].as_str().unwrap()
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .add_header("range", "bytes=0-8", true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(range.status_code.unwrap().as_u16(), 206);
    assert_eq!(range.take_string().await.unwrap(), "encrypted");

    let bob = register_account(
        state.clone(),
        "did:web:blob-bob.example",
        "@blob-bob",
        "dev_blob_bob",
    )
    .await;
    let invisible_blob = TestClient::get(format!(
        "http://server/api/v1/blob/get?blob_ref={}&purpose=message_attachment",
        blob["blob_ref"].as_str().unwrap()
    ))
    .add_header("authorization", format!("Bearer {bob}"), true)
    .add_header("range", "bytes=0-8", true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(invisible_blob.status_code.unwrap().as_u16(), 404);
    assert!(invisible_blob.headers().get("content-range").is_none());
    assert!(invisible_blob.headers().get("accept-ranges").is_none());

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

    let plaintext_push = TestClient::post("http://server/api/v1/push/notify")
        .json(&serde_json::json!({
            "notification": {
                "type": "message",
                "devices": [{"device_id": "dev_alice"}],
                "preview": "plaintext should not be sent to push gateway"
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(plaintext_push.status_code.unwrap().as_u16(), 400);

    let mut legacy_field_push = TestClient::post("http://server/api/v1/push/notify")
        .json(&serde_json::json!({
            "notification": {
                "type": "blind_wakeup",
                "devices": [{"device_id": "dev_alice"}],
                "room_id": "!legacy:example.com"
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(legacy_field_push.status_code.unwrap().as_u16(), 400);
    let legacy_field_push_body: Value = legacy_field_push.take_json().await.unwrap();
    assert_eq!(legacy_field_push_body["error"]["errcode"], "invalid_param");
    assert_eq!(
        legacy_field_push_body["error"]["error"],
        "removed legacy subject/room/card contract is forbidden on the active v1 wire"
    );

    let mut legacy_typed_id_push = TestClient::post("http://server/api/v1/push/notify")
        .json(&serde_json::json!({
            "notification": {
                "type": "blind_wakeup",
                "devices": [{"device_id": "dev_alice"}],
                "flow_id": "cx:card:legacy-card"
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(legacy_typed_id_push.status_code.unwrap().as_u16(), 400);
    let legacy_typed_id_push_body: Value = legacy_typed_id_push.take_json().await.unwrap();
    assert_eq!(
        legacy_typed_id_push_body["error"]["errcode"],
        "invalid_param"
    );
    assert_eq!(
        legacy_typed_id_push_body["error"]["error"],
        "removed legacy subject/room/card contract is forbidden on the active v1 wire"
    );

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
async fn keys_query_hides_revoked_device() {
    let state = AppState::new(test_config(), Db { pool: None });
    let desktop = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        "dev_alice",
        "Alice Desktop",
    )
    .await;
    let mobile = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        "dev_phone",
        "Alice Phone",
    )
    .await;

    let _desktop_keys: Value = TestClient::post("http://server/api/v1/keys/upload")
        .add_header("authorization", format!("Bearer {desktop}"), true)
        .json(&serde_json::json!({
            "device_id": "dev_alice",
            "device_keys": {"alg": "mls-rfc9420", "key": "desktop-device-key"},
            "principal_signing_keys": [{"kid": "did:web:alice.example#principal", "key": "principal-key"}],
            "recovery_keys": [{"kid": "did:web:alice.example#recovery", "key": "recovery-key"}],
            "session_keys": [{"kid": "did:web:alice.example#session", "key": "session-key"}],
            "agent_keys": [{"kid": "did:web:alice.example#agent", "key": "agent-key"}],
            "one_time_keys": [{"key_id": "desktop-otk", "key": "one-time"}],
            "fallback_keys": {"signed_curve25519:desktop": {"key": "fallback-desktop"}},
            "mls_key_packages": [{"package_id": "desktop-package", "key": "opaque-package"}],
            "backup_restore_keys": [{"kid": "did:web:alice.example#backup", "key": "backup-key"}],
            "device_signature": {"alg": "none"}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();

    let _phone_keys: Value = TestClient::post("http://server/api/v1/keys/upload")
        .add_header("authorization", format!("Bearer {mobile}"), true)
        .json(&serde_json::json!({
            "device_id": "dev_phone",
            "device_keys": {"alg": "mls-rfc9420", "key": "phone-device-key"},
            "principal_signing_keys": [{"kid": "did:web:alice.example#principal", "key": "principal-key"}],
            "recovery_keys": [{"kid": "did:web:alice.example#recovery", "key": "recovery-key"}],
            "session_keys": [{"kid": "did:web:alice.example#session", "key": "session-key"}],
            "agent_keys": [{"kid": "did:web:alice.example#agent", "key": "agent-key"}],
            "one_time_keys": [{"key_id": "phone-otk", "key": "one-time"}],
            "fallback_keys": {"signed_curve25519:phone": {"key": "fallback-phone"}},
            "mls_key_packages": [{"package_id": "phone-package", "key": "opaque-package"}],
            "backup_restore_keys": [{"kid": "did:web:alice.example#backup", "key": "backup-key"}],
            "device_signature": {"alg": "none"}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();

    let pre_revoke_query: Value = TestClient::post("http://server/api/v1/keys/query")
        .add_header("authorization", format!("Bearer {desktop}"), true)
        .json(&serde_json::json!({
            "device_keys": {"did:web:alice.example": ["dev_alice", "dev_phone"]}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        pre_revoke_query["device_keys"]["did:web:alice.example"]["dev_alice"]["device_keys"]["key"],
        "desktop-device-key"
    );
    assert_eq!(
        pre_revoke_query["device_keys"]["did:web:alice.example"]["dev_phone"]["device_keys"]["key"],
        "phone-device-key"
    );

    let logout: Value = TestClient::post("http://server/api/v1/auth/logout")
        .add_header("authorization", format!("Bearer {mobile}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(logout["revoked"], true);

    let post_revoke_query: Value = TestClient::post("http://server/api/v1/keys/query")
        .add_header("authorization", format!("Bearer {desktop}"), true)
        .json(&serde_json::json!({
            "device_keys": {"did:web:alice.example": ["dev_alice", "dev_phone"]}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(post_revoke_query["device_keys"]["did:web:alice.example"]["dev_phone"].is_null());
    assert_eq!(
        post_revoke_query["device_keys"]["did:web:alice.example"]["dev_alice"]["device_keys"]["key"],
        "desktop-device-key"
    );
}

#[tokio::test]
async fn revoked_device_blocks_encrypted_writes() {
    let state = AppState::new(test_config(), Db { pool: None });
    let device_token = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        "dev_mobile",
        "Alice Mobile",
    )
    .await;
    let stale_session = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        "dev_mobile",
        "Alice Mobile",
    )
    .await;

    let logout: Value = TestClient::post("http://server/api/v1/auth/logout")
        .add_header("authorization", format!("Bearer {device_token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(logout["revoked"], true);

    let blocked_send = TestClient::post("http://server/api/v1/messages/send")
        .add_header("authorization", format!("Bearer {stale_session}"), true)
        .json(&serde_json::json!({
            "space_id": "cx:space:0196419b-0000-7000-8000-000000000000",
            "content": encrypted_envelope("cx.message.v1", "blocked-ciphertext"),
            "encrypted": true
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(blocked_send.status_code.unwrap().as_u16(), 401);

    let blocked_upload = TestClient::post("http://server/api/v1/keys/upload")
        .add_header("authorization", format!("Bearer {stale_session}"), true)
        .json(&serde_json::json!({
            "device_id": "dev_mobile",
            "device_keys": {"alg": "mls-rfc9420", "key": "new-key"},
            "principal_signing_keys": [],
            "recovery_keys": [],
            "session_keys": [],
            "agent_keys": [],
            "one_time_keys": [],
            "fallback_keys": {},
            "mls_key_packages": [],
            "backup_restore_keys": [],
            "device_signature": {"alg": "none"}
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(blocked_upload.status_code.unwrap().as_u16(), 401);
}

#[tokio::test]
async fn server_preserves_e2ee_payloads_as_opaque_data() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let ciphertext = "base64url-opaque-ciphertext";

    TestClient::post("http://server/api/v1/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "e2ee-txn", true)
        .json(&serde_json::json!({
            "messages": {
                "did:web:alice.example": {
                    "dev_alice": {
                        "type": "cx.mls.application",
                        "content": encrypted_envelope("cx.mls.application", ciphertext)
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
    assert!(delivered["events"][0]["position"].as_i64().unwrap() > 0);
}

#[tokio::test]
async fn to_device_messages_survive_duplicate_sync_until_cursor_ack() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    TestClient::post("http://server/api/v1/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "ack-txn", true)
        .json(&serde_json::json!({
            "messages": {
                "did:web:alice.example": {
                    "dev_alice": {
                        "type": "cx.mls.application",
                        "content": encrypted_envelope("cx.mls.application", "ack-ciphertext")
                    }
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;

    let first: Value = TestClient::post("http://server/api/v1/sync")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(first["to_device"].as_array().unwrap().len(), 1);
    let first_cursor = decode_cursor(first["next_batch"].as_str().unwrap());
    assert!(first_cursor["positions"]["to_device"].as_i64().unwrap() > 0);

    let duplicate: Value = TestClient::post("http://server/api/v1/sync")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(duplicate["to_device"].as_array().unwrap().len(), 1);

    let acked: Value = TestClient::post("http://server/api/v1/sync")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({"since": first["next_batch"]}))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(acked["to_device"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn device_messages_evicted_after_session_logout() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    TestClient::post("http://server/api/v1/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "logout-txn", true)
        .json(&serde_json::json!({
            "messages": {
                "did:web:alice.example": {
                    "dev_alice": {
                        "type": "cx.mls.welcome",
                        "content": encrypted_envelope("cx.mls.welcome", "logout-ciphertext")
                    }
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;

    let pre_logout: Value = TestClient::get("http://server/api/v1/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(pre_logout["events"].as_array().unwrap().len(), 1);

    let logout: Value = TestClient::post("http://server/api/v1/auth/logout")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(logout["ok"], true);
    assert_eq!(logout["revoked"], true);

    let revoked_session_messages = TestClient::get("http://server/api/v1/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(revoked_session_messages.status_code.unwrap().as_u16(), 401);

    let new_token = dev_token(state.clone()).await;
    let post_logout: Value = TestClient::get("http://server/api/v1/device_messages")
        .add_header("authorization", format!("Bearer {new_token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(post_logout["events"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn policy_check_and_validation_work() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let policy: Value = TestClient::post("http://server/contrix/v1/check")
        .json(&serde_json::json!({
            "request_id": "req1",
            "space_id": "cx:space:0196419b-0000-7000-8000-000000000000",
            "request_canonical_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "action": "message.send",
            "actor": "did:web:alice.example",
            "source": {"service": "soland"}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(policy["decision"], "allow");

    let unauthenticated_policy = TestClient::post("http://server/api/v1/policies")
        .json(&serde_json::json!({
            "scope": "cx:space:0196419b-0000-7000-8000-000000000000",
            "subject_ref": "did:web:alice.example",
            "policy_type": "message.send",
            "effect": "deny"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        unauthenticated_policy.status_code,
        Some(StatusCode::UNAUTHORIZED)
    );

    let policy_document: Value = TestClient::post("http://server/api/v1/policies")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "scope": "cx:space:0196419b-0000-7000-8000-000000000000",
            "subject_ref": "did:web:alice.example",
            "policy_type": "message.send",
            "effect": "deny",
            "actions": ["message.send"],
            "resource": {"kind": "space", "space_id": "cx:space:0196419b-0000-7000-8000-000000000000"},
            "obligations": [{"type": "audit", "level": "high"}]
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let policy_id = policy_document["policy_id"].as_str().unwrap().to_owned();
    assert_eq!(policy_document["payload"]["effect"], "deny");

    let policies: Value = TestClient::get("http://server/api/v1/policies")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(policies["policies"].as_array().unwrap().len(), 1);

    let denied: Value = TestClient::post("http://server/contrix/v1/check")
        .json(&serde_json::json!({
            "request_id": "req2",
            "space_id": "cx:space:0196419b-0000-7000-8000-000000000000",
            "request_canonical_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "action": "message.send",
            "actor": "did:web:alice.example",
            "source": {"service": "soland", "kind": "space"}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(denied["decision"], "deny");
    assert_eq!(denied["reason_code"], "policy_denied");
    assert_eq!(denied["policy_id"], policy_id);
    assert_eq!(denied["obligations"][0]["type"], "audit");

    let deleted: Value = TestClient::delete(format!("http://server/api/v1/policies/{policy_id}"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(deleted["ok"], true);

    let allowed_again: Value = TestClient::post("http://server/contrix/v1/check")
        .json(&serde_json::json!({
            "request_id": "req3",
            "space_id": "cx:space:0196419b-0000-7000-8000-000000000000",
            "request_canonical_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "action": "message.send",
            "actor": "did:web:alice.example",
            "source": {"service": "soland"}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(allowed_again["decision"], "allow");

    let invalid = TestClient::post("http://server/api/v1/auth/dev-login")
        .json(&serde_json::json!({
            "actor": "alice",
            "device_id": "bad-device"
        }))
        .send(&app())
        .await;
    assert_eq!(invalid.status_code.unwrap().as_u16(), 400);
}

#[cfg(any())]
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

#[cfg(any())]
#[tokio::test]
async fn plaintext_policy_applies_to_repo_and_federation_message_ingest() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = dev_token(state.clone()).await;
    let locked_space: Value = TestClient::post("http://server/api/v1/spaces")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "title": "Repo Plaintext Policy Space",
            "public": false
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let space_id = locked_space["space_id"].as_str().unwrap().to_owned();

    let operation = Operation::create(
        OperationId::new("cx:operation:01904100-0000-7000-8000-1af1d5b68700").unwrap(),
        SpaceId::new(space_id.clone()).unwrap(),
        kinds::CX_MESSAGE_CREATE,
        serde_json::json!({
            "event_id": "cx:event:01904100-0000-7000-8000-6fa8a665b47e",
            "sender": "did:web:alice.example",
            "content": {"body": "plaintext should be denied"},
            "encrypted": false
        }),
    );
    let operation_digest = Hash::new(operation.operation_digest().unwrap()).unwrap();
    let expected_head = locked_space["head_commit"]
        .as_str()
        .expect("space creation records a repo head")
        .to_owned();
    let mut commit = Commit::new(
        CommitId::new("cx:commit:01904100-0000-7000-8000-4a08399d5516").unwrap(),
        "did:web:alice.example",
        Did::new("did:web:alice.example").unwrap(),
        2,
    );
    commit.prev_commit = Some(Hash::new(expected_head.clone()).unwrap());
    commit.operations.push(operation_digest);
    commit.proofs.push(dummy_proof());

    let mut denied_repo = TestClient::post("http://server/api/v1/repo/submit-commit")
        .json(&serde_json::json!({
            "repo_id": "did:web:alice.example",
            "expected_head": expected_head,
            "operations": [operation],
            "commit": commit
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(denied_repo.status_code.unwrap(), StatusCode::FORBIDDEN);
    let denied_repo_body: Value = denied_repo.take_json().await.unwrap();
    assert_eq!(denied_repo_body["error"]["errcode"], "policy_denied");
    {
        let audits = state.persistence.audit().snapshot_all().unwrap();
        assert!(audits.iter().any(|event| {
            event["action"] == "repo.submit_commit"
                && event["outcome"] == "policy_denied"
                && event["target"]["reason"] == "policy_denied"
        }));
    }

    let federation_operation = Operation::create(
        OperationId::new("cx:operation:01904100-0000-7000-8000-b565a2b993c0").unwrap(),
        SpaceId::new(space_id.clone()).unwrap(),
        kinds::CX_MESSAGE_CREATE,
        serde_json::json!({
            "event_id": "cx:event:01904100-0000-7000-8000-20e543cca299",
            "sender": "did:web:remote.example",
            "content": {"body": "federated plaintext should be denied"},
            "encrypted": false
        }),
    );
    let denied_federation: Value =
        TestClient::post("http://server/api/v1/federation/push-operations")
            .json(&serde_json::json!({
                "origin": "did:web:remote.example",
                "destination": "did:web:soland.local",
                "space_id": space_id,
                "service_binding_ref": "did:web:remote.example#soland",
                "operations": [federation_operation]
            }))
            .send(&app_from_state(state))
            .await
            .take_json()
            .await
            .unwrap();
    assert!(denied_federation["accepted"].as_array().unwrap().is_empty());
    assert_eq!(denied_federation["rejected"][0]["reason"], "policy_denied");
}

#[cfg(any())]
#[tokio::test]
async fn repo_adapter_memory_submit_list_get_and_sync_work() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = dev_token(state.clone()).await;
    let bare_legacy_operation = Operation::create(
        OperationId::new("cx:operation:01904100-0000-7000-8000-9189cc06f68f").unwrap(),
        SpaceId::new("cx:space:01904100-0000-7000-8000-743871bb0e87").unwrap(),
        "message",
        serde_json::json!({
            "event_id": "cx:event:01904100-0000-7000-8000-587f7a4b3d94",
            "sender": "did:web:alice.example",
            "thread_id": "cx:thread:adapter",
            "body": "missing migration profile"
        }),
    );
    let mut bare_legacy_commit = Commit::new(
        CommitId::new("cx:commit:01904100-0000-7000-8000-6143d958d2e7").unwrap(),
        "did:web:alice.example",
        Did::new("did:web:alice.example").unwrap(),
        1,
    );
    bare_legacy_commit.proofs.push(dummy_proof());
    let bare_legacy = TestClient::post("http://server/api/v1/repo/submit-commit")
        .json(&serde_json::json!({
            "repo_id": "did:web:alice.example",
            "expected_head": null,
            "operations": [bare_legacy_operation],
            "commit": bare_legacy_commit
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(bare_legacy.status_code.unwrap().as_u16(), 400);

    let operation = Operation::create(
        OperationId::new("cx:operation:01904100-0000-7000-8000-a888ba9a5f08").unwrap(),
        SpaceId::new("cx:space:01904100-0000-7000-8000-743871bb0e87").unwrap(),
        "message",
        serde_json::json!({
            "migration_profile": kinds::LEGACY_KIND_MIGRATION_PROFILE,
            "event_id": "cx:event:01904100-0000-7000-8000-28fd99f5698a",
            "sender": "did:web:alice.example",
            "thread_id": "cx:thread:adapter",
            "body": "hello"
        }),
    );
    let operation_digest = Hash::new(operation.operation_digest().unwrap()).unwrap();

    let mut commit = Commit::new(
        CommitId::new("cx:commit:01904100-0000-7000-8000-6f78e063a63f").unwrap(),
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
            "operations": [operation.clone()],
            "commit": commit.clone()
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(submit["status"], "accepted");
    assert_eq!(submit["head_commit"], commit_digest);

    let mut conflicting_commit = commit.clone();
    conflicting_commit.author_seq = 2;
    let conflict: Value = TestClient::post("http://server/api/v1/repo/submit-commit")
        .json(&serde_json::json!({
            "repo_id": "did:web:alice.example",
            "expected_head": null,
            "operations": [operation.clone()],
            "commit": conflicting_commit
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(conflict["error"]["errcode"], "duplicate_conflict");
    assert!(
        state
            .persistence
            .audit()
            .snapshot_all()
            .unwrap()
            .iter()
            .any(|entry| {
                entry["action"] == "repo.submit_commit"
                    && entry["outcome"] == "duplicate_conflict"
                    && entry["target"]["operation_kinds"][0]["input_kind"] == "message"
                    && entry["target"]["operation_kinds"][0]["canonical_kind"]
                        == "cx.message.create"
            })
    );

    let projected_thread: Value =
        TestClient::get("http://server/api/v1/index/thread?thread_id=cx:thread:adapter")
            .add_header("authorization", format!("Bearer {alice}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(
        projected_thread["events"][0]["event_id"],
        "cx:event:01904100-0000-7000-8000-28fd99f5698a"
    );
    assert_eq!(projected_thread["events"][0]["content"]["body"], "hello");

    let projected_sync: Value = TestClient::post("http://server/api/v1/sync")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        projected_sync["spaces"]["cx:space:01904100-0000-7000-8000-743871bb0e87"]["timeline"]["events"]
            [0]["event_id"],
        "cx:event:01904100-0000-7000-8000-28fd99f5698a"
    );

    let duplicate_submit: Value = TestClient::post("http://server/api/v1/repo/submit-commit")
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
    assert_eq!(duplicate_submit["status"], "accepted");
    assert_eq!(duplicate_submit["head_commit"], commit_digest);

    let invalid_reaction = Operation::create(
        OperationId::new("cx:operation:01904100-0000-7000-8000-68cfb393b370").unwrap(),
        SpaceId::new("cx:space:01904100-0000-7000-8000-743871bb0e87").unwrap(),
        kinds::CX_REACTION_ADD,
        serde_json::json!({
            "event_id": "cx:event:01904100-0000-7000-8000-28fd99f5698a",
            "actor": "did:web:alice.example"
        }),
    );
    let invalid_reaction_digest = Hash::new(invalid_reaction.operation_digest().unwrap()).unwrap();
    let mut invalid_reaction_commit = Commit::new(
        CommitId::new("cx:commit:01904100-0000-7000-8000-8492c575b3b3").unwrap(),
        "did:web:alice.example",
        Did::new("did:web:alice.example").unwrap(),
        2,
    );
    invalid_reaction_commit
        .operations
        .push(invalid_reaction_digest);
    invalid_reaction_commit.proofs.push(dummy_proof());
    let invalid_reaction_response: Value =
        TestClient::post("http://server/api/v1/repo/submit-commit")
            .json(&serde_json::json!({
                "repo_id": "did:web:alice.example",
                "expected_head": commit_digest,
                "operations": [invalid_reaction],
                "commit": invalid_reaction_commit
            }))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(
        invalid_reaction_response["error"]["errcode"],
        "invalid_param"
    );
    assert_eq!(
        invalid_reaction_response["error"]["error"],
        "reaction operation requires reaction key"
    );

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

    let commit: Value = TestClient::get(
        "http://server/api/v1/repo/commit?commit_id=cx:commit:01904100-0000-7000-8000-6f78e063a63f",
    )
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        commit["commit"]["commit_id"],
        "cx:commit:01904100-0000-7000-8000-6f78e063a63f"
    );
    assert!(commit["operations"].as_array().unwrap().is_empty());

    let expanded_commit: Value = TestClient::get(
        "http://server/api/v1/repo/commit?commit_id=cx:commit:01904100-0000-7000-8000-6f78e063a63f&include_operations=true",
    )
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        expanded_commit["operations"][0]["operation_id"],
        "cx:operation:01904100-0000-7000-8000-a888ba9a5f08"
    );

    let operations: Value = TestClient::post("http://server/api/v1/repo/operations")
        .json(&serde_json::json!({"operation_ids": ["cx:operation:01904100-0000-7000-8000-a888ba9a5f08"]}))
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

    let unauthorized_backfill =
        TestClient::get("http://server/api/v1/events?space_id=cx:space:01904100-0000-7000-8000-743871bb0e87&limit=1")
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(unauthorized_backfill.status_code.unwrap().as_u16(), 404);

    let backfill: Value =
        TestClient::get("http://server/api/v1/events?space_id=cx:space:01904100-0000-7000-8000-743871bb0e87&limit=1")
            .add_header("authorization", format!("Bearer {alice}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(
        backfill["events"][0]["event_id"],
        "cx:event:01904100-0000-7000-8000-28fd99f5698a"
    );
    assert_eq!(backfill["events"][0]["event_kind"], "cx.message.create");
    // Spec M-01 collapsed `event_type / input_event_type /
    // canonical_event_type` into `event_kind`; the legacy duplicates are
    // gone from the wire.
    assert!(backfill["events"][0].get("event_type").is_none());
    assert!(backfill["events"][0].get("input_event_type").is_none());
    assert!(backfill["events"][0].get("canonical_event_type").is_none());
    assert_eq!(
        backfill["events"][0]["operation_id"],
        "cx:operation:01904100-0000-7000-8000-a888ba9a5f08"
    );
    assert_eq!(backfill["limited"], false);

    let unauthorized_subscribe =
        TestClient::get("http://server/api/v1/events/subscribe?space_id=cx:space:01904100-0000-7000-8000-743871bb0e87&limit=1")
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(unauthorized_subscribe.status_code.unwrap().as_u16(), 404);

    let subscribe: Value =
        TestClient::get("http://server/api/v1/events/subscribe?space_id=cx:space:01904100-0000-7000-8000-743871bb0e87&limit=1")
            .add_header("authorization", format!("Bearer {alice}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(
        subscribe["frames"][0]["payload"]["operation_id"],
        "cx:operation:01904100-0000-7000-8000-a888ba9a5f08"
    );

    let redaction = Operation::create(
        OperationId::new("cx:operation:01904100-0000-7000-8000-996dbfcff223").unwrap(),
        SpaceId::new("cx:space:01904100-0000-7000-8000-743871bb0e87").unwrap(),
        "redaction",
        serde_json::json!({
            "migration_profile": kinds::LEGACY_KIND_MIGRATION_PROFILE,
            "event_id": "cx:event:01904100-0000-7000-8000-a1a72934992d",
            "target_event_id": "cx:event:01904100-0000-7000-8000-28fd99f5698a"
        }),
    );
    let redaction_digest = Hash::new(redaction.operation_digest().unwrap()).unwrap();
    let mut redaction_commit = Commit::new(
        CommitId::new("cx:commit:01904100-0000-7000-8000-e9bc44779acc").unwrap(),
        "did:web:alice.example",
        Did::new("did:web:alice.example").unwrap(),
        2,
    );
    redaction_commit.operations.push(redaction_digest);
    redaction_commit.proofs.push(dummy_proof());
    let redaction_submit: Value = TestClient::post("http://server/api/v1/repo/submit-commit")
        .json(&serde_json::json!({
            "repo_id": "did:web:alice.example",
            "expected_head": commit_digest,
            "operations": [redaction],
            "commit": redaction_commit
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(redaction_submit["status"], "accepted");

    let redacted_backfill: Value =
        TestClient::get("http://server/api/v1/events?space_id=cx:space:01904100-0000-7000-8000-743871bb0e87&limit=10")
            .add_header("authorization", format!("Bearer {alice}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert!(redacted_backfill["events"].as_array().unwrap().is_empty());

    let redacted_subscribe: Value =
        TestClient::get("http://server/api/v1/events/subscribe?space_id=cx:space:01904100-0000-7000-8000-743871bb0e87&limit=10")
            .add_header("authorization", format!("Bearer {alice}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert!(redacted_subscribe["frames"].as_array().unwrap().is_empty());

    let redacted_sync: Value = TestClient::post("http://server/api/v1/sync")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        redacted_sync["spaces"]["cx:space:01904100-0000-7000-8000-743871bb0e87"]["timeline"]["events"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let mut stale_commit = Commit::new(
        CommitId::new("cx:commit:01904100-0000-7000-8000-ac601680afcf").unwrap(),
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
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(stale.status_code.unwrap().as_u16(), 409);

    let bad_operation = Operation::create(
        OperationId::new("cx:operation:01904100-0000-7000-8000-7fe7fcbbf658-bad").unwrap(),
        SpaceId::new("cx:space:01904100-0000-7000-8000-743871bb0e87").unwrap(),
        "unknown.family",
        serde_json::json!({"body": "bad"}),
    );
    let mut bad_commit = Commit::new(
        CommitId::new("cx:commit:01904100-0000-7000-8000-4a82e26a6487").unwrap(),
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

#[cfg(any())]
#[tokio::test]
async fn repo_submit_commit_cas_conflict_and_idempotent_duplicate() {
    let state = AppState::new(test_config(), Db { pool: None });

    let first_operation = Operation::create(
        OperationId::new("cx:operation:01904100-0000-7000-8000-d1f98f6fb367").unwrap(),
        SpaceId::new("cx:space:0196419b-0000-7000-8000-000000000000").unwrap(),
        kinds::CX_MESSAGE_CREATE,
        serde_json::json!({
            "event_id": "cx:event:01904100-0000-7000-8000-df1c7fd33e41",
            "sender": "did:web:alice.example",
            "body": "idempotent payload",
            "encrypted": false
        }),
    );
    let first_operation_digest = Hash::new(first_operation.operation_digest().unwrap()).unwrap();

    let mut first_commit = Commit::new(
        CommitId::new("cx:commit:01904100-0000-7000-8000-dcad0eb0a675").unwrap(),
        "did:web:alice.example",
        Did::new("did:web:alice.example").unwrap(),
        1,
    );
    first_commit.operations.push(first_operation_digest);
    first_commit.proofs.push(dummy_proof());

    let first_submit: Value = TestClient::post("http://server/api/v1/repo/submit-commit")
        .json(&serde_json::json!({
            "repo_id": "did:web:alice.example",
            "expected_head": null,
            "operations": [first_operation],
            "commit": first_commit.clone()
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(first_submit["status"], "accepted");
    let first_head = first_submit["head_commit"].as_str().unwrap().to_owned();

    let duplicate_submit: Value = TestClient::post("http://server/api/v1/repo/submit-commit")
        .json(&serde_json::json!({
            "repo_id": "did:web:alice.example",
            "expected_head": null,
            "operations": [first_operation],
            "commit": first_commit
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(duplicate_submit["status"], "accepted");
    assert_eq!(
        duplicate_submit["head_commit"].as_str().unwrap(),
        first_head
    );

    let conflicting_operation = Operation::create(
        OperationId::new("cx:operation:01904100-0000-7000-8000-d1f98f6fb367").unwrap(),
        SpaceId::new("cx:space:0196419b-0000-7000-8000-000000000000").unwrap(),
        kinds::CX_MESSAGE_CREATE,
        serde_json::json!({
            "event_id": "cx:event:01904100-0000-7000-8000-df1c7fd33e41",
            "sender": "did:web:alice.example",
            "body": "different payload",
            "encrypted": false
        }),
    );
    let conflicting_operation_digest =
        Hash::new(conflicting_operation.operation_digest().unwrap()).unwrap();
    let mut conflicting_commit = Commit::new(
        CommitId::new("cx:commit:01904100-0000-7000-8000-cc28f1d0d5d4").unwrap(),
        "did:web:alice.example",
        Did::new("did:web:alice.example").unwrap(),
        2,
    );
    conflicting_commit
        .operations
        .push(conflicting_operation_digest);
    conflicting_commit.proofs.push(dummy_proof());

    let conflicting_submit: Value = TestClient::post("http://server/api/v1/repo/submit-commit")
        .json(&serde_json::json!({
            "repo_id": "did:web:alice.example",
            "expected_head": first_head,
            "operations": [conflicting_operation],
            "commit": conflicting_commit
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(conflicting_submit["error"]["errcode"], "quarantine");

    let mut stale_commit = Commit::new(
        CommitId::new("cx:commit:01904100-0000-7000-8000-6a4b81ef7588").unwrap(),
        "did:web:alice.example",
        Did::new("did:web:alice.example").unwrap(),
        2,
    );
    stale_commit.proofs.push(dummy_proof());
    let mut stale = TestClient::post("http://server/api/v1/repo/submit-commit")
        .json(&serde_json::json!({
            "repo_id": "did:web:alice.example",
            "expected_head": "cx:commit:01904100-0000-7000-8000-fb6de0eed655",
            "commit": stale_commit
        }))
        .send(&app_from_state(state))
        .await;
    assert_eq!(stale.status_code.unwrap().as_u16(), 409);
    let stale_body: Value = stale.take_json().await.unwrap();
    assert_eq!(stale_body["error"]["errcode"], "cas_conflict");
}

#[cfg(any())]
#[tokio::test]
async fn repo_submit_commit_operation_id_different_digest_quarantine() {
    let state = AppState::new(test_config(), Db { pool: None });

    let operation = Operation::create(
        OperationId::new("cx:operation:01904100-0000-7000-8000-e966cfd59e5a").unwrap(),
        SpaceId::new("cx:space:0196419b-0000-7000-8000-000000000000").unwrap(),
        kinds::CX_MESSAGE_CREATE,
        serde_json::json!({
            "event_id": "cx:event:01904100-0000-7000-8000-184d6a958479",
            "sender": "did:web:alice.example",
            "body": "first payload",
            "encrypted": false
        }),
    );
    let operation_digest = Hash::new(operation.operation_digest().unwrap()).unwrap();

    let mut first_commit = Commit::new(
        CommitId::new("cx:commit:01904100-0000-7000-8000-f0cc67b83006").unwrap(),
        "did:web:alice.example",
        Did::new("did:web:alice.example").unwrap(),
        1,
    );
    first_commit.operations.push(operation_digest);
    first_commit.proofs.push(dummy_proof());

    let first_submit: Value = TestClient::post("http://server/api/v1/repo/submit-commit")
        .json(&serde_json::json!({
            "repo_id": "did:web:alice.example",
            "expected_head": null,
            "operations": [operation],
            "commit": first_commit.clone()
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(first_submit["status"], "accepted");
    let head_commit = first_submit["head_commit"].as_str().unwrap().to_owned();

    let duplicate_operation = Operation::create(
        OperationId::new("cx:operation:01904100-0000-7000-8000-e966cfd59e5a").unwrap(),
        SpaceId::new("cx:space:0196419b-0000-7000-8000-000000000000").unwrap(),
        kinds::CX_MESSAGE_CREATE,
        serde_json::json!({
            "event_id": "cx:event:01904100-0000-7000-8000-184d6a958479",
            "sender": "did:web:alice.example",
            "body": "different payload",
            "encrypted": false
        }),
    );
    let duplicate_operation_digest =
        Hash::new(duplicate_operation.operation_digest().unwrap()).unwrap();
    let mut duplicate_commit = Commit::new(
        CommitId::new("cx:commit:01904100-0000-7000-8000-3d28d704b977").unwrap(),
        "did:web:alice.example",
        Did::new("did:web:alice.example").unwrap(),
        2,
    );
    duplicate_commit.operations.push(duplicate_operation_digest);
    duplicate_commit.proofs.push(dummy_proof());

    let duplicate_submit: Value = TestClient::post("http://server/api/v1/repo/submit-commit")
        .json(&serde_json::json!({
            "repo_id": "did:web:alice.example",
            "expected_head": head_commit,
            "operations": [duplicate_operation],
            "commit": duplicate_commit
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(duplicate_submit["error"]["errcode"], "quarantine");
    assert!(
        duplicate_submit["error"]["error"]
            .as_str()
            .unwrap()
            .contains("conflicting bytes for idempotent object")
    );

    assert!(
        state
            .persistence
            .audit()
            .snapshot_all()
            .unwrap()
            .iter()
            .any(|event| {
                event["action"] == "repo.submit_commit"
                    && event["outcome"] == "quarantine"
                    && event["target"]["commit_id"]
                        == "cx:commit:01904100-0000-7000-8000-3d28d704b977"
            })
    );
}

#[cfg(any())]
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
