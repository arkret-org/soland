use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use contrix_sdk::{Did, Operation, OperationId, RealmId, new_prefixed_uuid7};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::Value;
use sha2::{Digest, Sha256};
use soland::config::{AppConfig, ObjectStorageConfig};
use soland::db::Db;
use soland::ratelimit::RateLimiterConfig;
use soland::state::{AppState, RealmDirectoryEntry, RealmMetaRecord, SpaceInviteRecord};
use soland::{
    artifacts, kinds, service, service_with_rate_limiter_config, service_with_request_size_limit,
};

const DEMO_REALM_ID: &str = "cx:realm:0196419b-0000-7000-8000-000000000000";
static TEST_EVENT_SEQ: AtomicU64 = AtomicU64::new(10_000);
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
        trust_domain: "cx:trust_domain:soland.local".to_owned(),
        sovereign_enclave_enabled: false,
        sovereign_enclave_allowed_outbound_hosts: Vec::new(),
        erasure_propagation_window_ms: 604_800_000,
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

async fn account_subscribe_frame(
    state: AppState,
    token: Option<&str>,
    query: &str,
) -> serde_json::Value {
    let url = if query.is_empty() {
        "http://server/api/v1/account/subscribe".to_owned()
    } else {
        format!("http://server/api/v1/account/subscribe?{query}")
    };
    let mut request = TestClient::get(url);
    if let Some(token) = token {
        request = request.add_header("authorization", format!("Bearer {token}"), true);
    }
    let body = request
        .send(&app_from_state(state))
        .await
        .take_string()
        .await
        .unwrap();
    serde_json::from_str(body.lines().next().unwrap()).unwrap()
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
    dev_token_for_device(
        state,
        "did:web:alice.example",
        "cx:device:01904100-0000-7000-8000-a11ce0000001",
        "Alice Desktop",
    )
    .await
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

fn seed_test_realm(
    state: &AppState,
    owner: &str,
    title: &str,
    summary: Option<&str>,
    discoverability: &str,
    plaintext_visible_services: &[&str],
    invitees: &[&str],
) -> Value {
    let realm_id = new_prefixed_uuid7("cx:realm:");
    let typed_realm_id = RealmId::new(realm_id.clone()).unwrap();
    let owner_did = Did::new(owner.to_owned()).unwrap();
    let now = chrono::Utc::now();

    let mut entry = RealmDirectoryEntry::new(typed_realm_id, title);
    entry.description = summary.map(ToOwned::to_owned);
    entry.public = discoverability == "public";
    entry.members.insert(owner_did);
    state.realms.lock().unwrap().upsert(entry);

    let plaintext_visible_services = plaintext_visible_services
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    state
        .persistence
        .realm_meta()
        .put(
            &realm_id,
            &RealmMetaRecord {
                owner: owner.to_owned(),
                deleted: false,
                discoverability: discoverability.to_owned(),
                history_visibility: "joined".to_owned(),
                encryption_profile: None,
                plaintext_visible_services,
                created_at: now,
                updated_at: now,
            },
        )
        .unwrap();

    for invitee in invitees {
        let invite_id = new_prefixed_uuid7("cx:invite:");
        let invite_token = new_prefixed_uuid7("cx:invite-token:");
        state
            .persistence
            .space_invites()
            .put(SpaceInviteRecord {
                invite_id,
                space_id: realm_id.clone(),
                inviter: owner.to_owned(),
                invitee: Some((*invitee).to_owned()),
                invite_token,
                status: "pending".to_owned(),
                expires_at: None,
                created_at: now,
            })
            .unwrap();
    }

    serde_json::json!({
        "ok": true,
        "space_id": realm_id,
        "owner": owner,
        "members": [owner],
        "deleted": false
    })
}

fn add_test_realm_member(state: &AppState, realm_id: &str, member: &str) -> Value {
    let typed_realm_id = RealmId::new(realm_id.to_owned()).unwrap();
    let member_did = Did::new(member.to_owned()).unwrap();
    let mut realms = state.realms.lock().unwrap();
    if let Some(mut entry) = realms.get(&typed_realm_id).cloned() {
        entry.members.insert(member_did);
        let members: Vec<String> = entry.members.iter().map(ToString::to_string).collect();
        realms.upsert(entry);
        serde_json::json!({
            "ok": true,
            "space_id": realm_id,
            "members": members,
            "deleted": false
        })
    } else {
        serde_json::json!({"ok": false, "error": "realm_not_found"})
    }
}

fn remove_test_realm_member(state: &AppState, realm_id: &str, member: &str) -> Value {
    let typed_realm_id = RealmId::new(realm_id.to_owned()).unwrap();
    let member_did = Did::new(member.to_owned()).unwrap();
    let mut realms = state.realms.lock().unwrap();
    if let Some(mut entry) = realms.get(&typed_realm_id).cloned() {
        entry.members.remove(&member_did);
        let members: Vec<String> = entry.members.iter().map(ToString::to_string).collect();
        realms.upsert(entry);
        serde_json::json!({
            "ok": true,
            "space_id": realm_id,
            "members": members,
            "deleted": false
        })
    } else {
        serde_json::json!({"ok": false, "error": "realm_not_found"})
    }
}

fn delete_test_realm(state: &AppState, realm_id: &str) -> Value {
    let store = state.persistence.realm_meta();
    if let Some(mut meta) = store.get(realm_id).unwrap() {
        meta.deleted = true;
        meta.updated_at = chrono::Utc::now();
        store.put(realm_id, &meta).unwrap();
    }
    serde_json::json!({
        "ok": true,
        "space_id": realm_id,
        "deleted": true
    })
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
    let bytes = contrix_sdk::canonical::canonical_json_bytes(value)
        .unwrap_or_else(|_| serde_json::to_vec(value).unwrap());
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn expected_flow_id_for_scope(scope_id: &str) -> String {
    scope_id
        .strip_prefix("cx:space:")
        .or_else(|| scope_id.strip_prefix("cx:realm:"))
        .map(|suffix| format!("cx:flow:{suffix}"))
        .unwrap_or_else(|| {
            let digest = Sha256::digest(scope_id.as_bytes());
            format!("cx:flow:{:x}", digest)
                .chars()
                .take("cx:flow:".len() + 26)
                .collect()
        })
}

fn event_canonical_digest(event: &Value) -> String {
    // Mirror server-side `event_canonical_source` (contrix-spec
    // conformance-vectors.md §1.6): canonical digest is sha256 over the
    // event envelope JSON with `proofs`, `unsigned`, and the derived
    // `canonical_digest` / `canonical_hash` slots removed.
    let mut canonical = event.clone();
    if let Value::Object(object) = &mut canonical {
        object.remove("proofs");
        object.remove("unsigned");
        object.remove("canonical_digest");
        object.remove("canonical_hash");
    }
    sha256_json(&canonical)
}

fn signed_event_envelope(event_id: &str, actor_seq: u64, prev_refs: Vec<&str>) -> Value {
    let payload = serde_json::json!({
        "flow_id": "cx:flow:01904100-0000-7000-8000-f10dc0000001",
        "track": "discussion",
        "content": {
            "kind": "cx.content.text",
            "body": format!("event body {actor_seq}"),
            "format": "plain"
        }
    });
    let mut event = serde_json::json!({
        "event_id": event_id,
        "kind": "cx.message.create",
        "schema_id": "cx.schema.message.v1",
        "actor_id": "did:web:alice.example",
        "actor_seq": actor_seq,
        "realm_id": "cx:realm:0196419b-0000-7000-8000-000000000000",
        "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": prev_refs,
        "auth_refs": [],
        "payload": payload,
        "proofs": [{
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#01904100-0000-7000-8000-a11ce0000001",
            "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload)
        }]
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));
    event
}

fn signed_message_event_envelope(
    actor: &str,
    realm_id: &str,
    thread_id: &str,
    content: Value,
    encrypted: bool,
) -> Value {
    let event_id = new_prefixed_uuid7("cx:event:");
    let actor_seq = TEST_EVENT_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut payload = serde_json::json!({
        "flow_id": expected_flow_id_for_scope(realm_id),
        "track": "discussion",
        "thread_id": thread_id,
    });
    if encrypted {
        let mut encrypted_payload = content;
        if let Some(object) = encrypted_payload.as_object_mut()
            && object.get("scheme").and_then(Value::as_str) == Some("mls-rfc9420")
        {
            object.insert("version".to_owned(), Value::String("1.0".to_owned()));
            object.insert("group_id".to_owned(), Value::String("mls_test".to_owned()));
            object.insert(
                "content_type".to_owned(),
                Value::String("application/vnd.contrix.message+json".to_owned()),
            );
            object.insert(
                "aad_visibility_event_id".to_owned(),
                Value::String("hidden".to_owned()),
            );
            object.insert(
                "aad".to_owned(),
                serde_json::json!({
                    "realm_id": realm_id,
                    "event_kind": "cx.message.create"
                }),
            );
            object.insert(
                "key_ref".to_owned(),
                serde_json::json!({
                    "algorithm": "MLS",
                    "group_state_ref": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                }),
            );
            object.insert(
                "aad_digest".to_owned(),
                Value::String(
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                        .to_owned(),
                ),
            );
            object.insert(
                "payload_digest".to_owned(),
                Value::String(
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                        .to_owned(),
                ),
            );
        }
        payload["encrypted_payload"] = encrypted_payload;
    } else {
        let mut content = content;
        if let Some(object) = content.as_object_mut()
            && object.get("body").is_some()
            && object.get("kind").is_none()
        {
            object.insert(
                "kind".to_owned(),
                Value::String("cx.content.text".to_owned()),
            );
        }
        payload["content"] = content;
    }
    let mut event = serde_json::json!({
        "event_id": event_id,
        "kind": "cx.message.create",
        "schema_id": "cx.schema.message.v1",
        "actor_id": actor,
        "actor_seq": actor_seq,
        "realm_id": realm_id,
        "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": [],
        "auth_refs": [],
        "payload": payload,
        "proofs": [{
            "type": "dev-proof",
            "verification_method": format!("{actor}#01904100-0000-7000-8000-a11ce0000001"),
            "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload)
        }]
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));
    event
}

async fn post_message_event(
    state: AppState,
    token: &str,
    actor: &str,
    realm_id: &str,
    thread_id: &str,
    content: Value,
    encrypted: bool,
) -> StatusCode {
    let event = signed_message_event_envelope(actor, realm_id, thread_id, content, encrypted);
    TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&event)
        .send(&app_from_state(state))
        .await
        .status_code
        .unwrap()
}

async fn submit_message_event(
    state: AppState,
    token: &str,
    actor: &str,
    realm_id: &str,
    thread_id: &str,
    content: Value,
    encrypted: bool,
) -> Value {
    let event = signed_message_event_envelope(actor, realm_id, thread_id, content, encrypted);
    let mut response: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&event)
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    if let Some(event_id) = response["event_id"].as_str() {
        let event_id = event_id.to_owned();
        let event_suffix = event_id.strip_prefix("cx:event:").unwrap_or(&event_id);
        response["operation_id"] = Value::String(format!("cx:operation:{event_suffix}"));
        response["kind"] = Value::String("cx.message.create".to_owned());
        response["message_id"] = Value::String(format!("cx:message:{event_suffix}"));
        response["realm_id"] = Value::String(realm_id.to_owned());
        response["space_id"] = Value::String(realm_id.to_owned());
        response["source_realm_id"] = Value::String(realm_id.to_owned());
        response["sender"] = Value::String(actor.to_owned());
        response["encrypted"] = Value::Bool(encrypted);
        response["canonical_event_envelope"] = Value::Bool(true);
    }
    response
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
    let url = format!("http://{}/oauth/introspect", listener.local_addr().unwrap());
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
                    "org.contrix.device_id": "cx:device:01904100-0000-7000-8000-0a4a40000006",
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
        .find(|device| {
            device.payload["raw_device_id"] == "cx:device:01904100-0000-7000-8000-0a4a40000006"
        })
        .expect("OAuth device auto-provisioned");
    assert!(oauth_device.device_id.starts_with("cx:device:"));
}

#[tokio::test]
async fn dev_login_is_unavailable_in_production_mode() {
    let mut config = test_config();
    config.development_mode = false;
    let state = AppState::new(config, Db { pool: None });

    let response = TestClient::post("http://server/api/v1/auth/dev-login")
        .json(&serde_json::json!({
            "actor": "did:web:alice.example",
            "device_id": "cx:device:01904100-0000-7000-8000-0a4a40000006"
        }))
        .send(&app_from_state(state))
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn oversized_json_body_is_rejected_before_handler() {
    let state = AppState::new(test_config(), Db { pool: None });
    let body = serde_json::json!({
        "query": "x".repeat(128),
        "limit": 10,
    });

    let response = TestClient::post("http://server/api/v1/directory/search-realms")
        .json(&body)
        .send(&service_with_request_size_limit(state, 64))
        .await;

    assert_eq!(
        response.status_code.unwrap(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
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

    let readyz: Value = TestClient::get("http://server/readyz")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(readyz["ok"], true);
    assert_eq!(readyz["checks"]["database"]["ok"], true);

    let describe: Value = TestClient::get("http://server/api/v1/server/describe")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(describe["protocol_version"], "1.0");
    assert_eq!(describe["service_type"], "principal_server");
    assert!(
        !describe["supported_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile == "cx.profile.soland_limited_server.v1")
    );
    assert!(
        describe["unsupported_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |profile| profile["profile"] == "cx.profile.soland_limited_server.v1"
                    && profile["status"] == "unsupported"
            )
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
    assert!(
        describe["supported_operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| operation == "cx.blob.upload")
    );
    assert!(
        describe["supported_operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| operation == "cx.keys.backups.put")
    );
    for operation in describe["supported_operations"].as_array().unwrap() {
        let operation = operation.as_str().expect("operation id string");
        assert!(
            artifacts::operation_ids().contains(operation),
            "supported_operations must only advertise spec operation ids, got {operation}"
        );
    }
    assert_eq!(
        describe["limits"]["profile_status"]["local_extension_operation_source"],
        "routing::SOLAND_EXTENSION_OPERATIONS"
    );
    assert!(
        describe["limits"]["profile_status"]["local_extension_operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| operation == "cx.extension.soland.admin.actors")
    );
    assert!(
        describe["limits"]["profile_status"]["supported_operation_catalog"]["derived_surface_groups"]
            .as_array()
            .unwrap()
            .iter()
            .any(|surface| surface == "events_sync")
    );
    assert!(
        !describe["limits"]["profile_status"]["full_profiles_not_claimed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile == "cx.profile.index_node.v1")
    );
    assert!(
        describe["limits"]["profile_status"]["full_profiles_not_claimed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile == "cx.profile.directory_service.v1")
    );
    let limitation_areas = describe["limits"]["profile_status"]["limitations"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|limitation| limitation["area"].as_str())
        .collect::<Vec<_>>();
    assert!(limitation_areas.contains(&"authz.describe"));
    assert!(limitation_areas.contains(&"policies.describe"));
    assert!(limitation_areas.contains(&"admin.bottom.manual_repair"));
    assert!(limitation_areas.contains(&"index.query"));
    assert!(limitation_areas.contains(&"federation.outbound_push"));
    let federation_limitation = describe["limits"]["profile_status"]["limitations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|limitation| limitation["area"] == "federation.outbound_push")
        .expect("federation outbound limitation should remain described");
    assert_eq!(federation_limitation["status"], "partial");
    assert!(
        federation_limitation["remaining"]
            .as_array()
            .unwrap()
            .iter()
            .any(|gap| gap == "RFC 9421 HTTP Message Signatures header emission")
    );
    let full_gap = describe["limits"]["profile_status"]["principal_server_full_profile_gaps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|gap| gap["profile"] == "cx.profile.principal_server.v1")
        .expect("principal server full-profile gap summary should be visible");
    assert_eq!(full_gap["status"], "not_claimed");
}

#[tokio::test]
async fn readyz_returns_503_until_introspection_bearer_is_configured() {
    let mut config = test_config();
    config.development_mode = false;
    config.oauth_introspection_url = Some("https://coauth.example/oauth2/introspect".to_owned());
    config.oauth_introspection_bearer = None;
    let service = app_from_state(AppState::new(config, Db { pool: None }));

    let mut response = TestClient::get("http://server/readyz").send(&service).await;
    assert_eq!(
        response.status_code.unwrap(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["ok"], false);
    assert_eq!(body["checks"]["oauth_introspection"]["ok"], false);
}

/// T6.1 — describe response MUST partition into `supported_operations`
/// (wire-callable), `implemented_features`, `claimed_profiles`
/// (self_claimed only), `verified_profiles` (cotest_verified only),
/// `experimental_features` and `compat_surfaces`. The test config has
/// `development_mode: true`, so the spec invariant
/// (development_mode=true => verified_profiles=[]) is exercised
/// directly.
#[tokio::test]
async fn describe_separates_claim_levels() {
    let describe: Value = TestClient::get("http://server/api/v1/server/describe")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(describe["development_mode"], true);

    let verified = describe["verified_profiles"]
        .as_array()
        .expect("verified_profiles array present");
    assert!(
        verified.is_empty(),
        "dev mode must not advertise any cotest_verified profile, got {verified:?}"
    );

    let claimed = describe["claimed_profiles"]
        .as_array()
        .expect("claimed_profiles array present");
    assert!(
        !claimed.is_empty(),
        "soland self-claims at least one profile"
    );
    for entry in claimed {
        assert_eq!(
            entry["claim_kind"], "self_claimed",
            "claimed_profiles entries MUST be self_claimed; verified entries belong in verified_profiles"
        );
        assert!(entry["profile_id"].is_string());
    }

    let implemented = describe["implemented_features"]
        .as_array()
        .expect("implemented_features array present");
    assert!(!implemented.is_empty());

    let experimental: std::collections::HashSet<&str> = describe["experimental_features"]
        .as_array()
        .expect("experimental_features array present")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    let verified_ids: std::collections::HashSet<&str> = verified
        .iter()
        .filter_map(|v| v["profile_id"].as_str())
        .collect();
    assert!(
        experimental.is_disjoint(&verified_ids),
        "experimental_features must not overlap verified_profiles"
    );

    let compat = describe["compat_surfaces"]
        .as_array()
        .expect("compat_surfaces array present");
    for surface in compat {
        let kind = surface["kind"].as_str().expect("compat surface kind");
        assert!(
            matches!(
                kind,
                "matrix_passthrough"
                    | "mimi_passthrough"
                    | "legacy_alias"
                    | "external_interop"
                    | "deprecated_alias"
            ),
            "unknown compat_surfaces kind: {kind}"
        );
    }
}

/// T1.4: `/health` and `/api/v1/server/describe` both surface the runtime
/// dev-mode posture so monitoring + sodmin can flag dev deployments with
/// a red "DEVELOPMENT MODE" banner. `test_config()` boots with
/// `development_mode = true` and no admin allowlist, so the expected
/// `admin_auth_mode` is `"development"`.
#[tokio::test]
async fn describe_returns_development_mode_field() {
    // Default test config — `development_mode = true`, no admin allowlist.
    let dev_app = app();

    let health: Value = TestClient::get("http://server/health")
        .send(&dev_app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(health["development_mode"], true);
    assert_eq!(health["proof_verifier_mode"], "development");
    assert_eq!(health["admin_auth_mode"], "development");

    let describe: Value = TestClient::get("http://server/api/v1/server/describe")
        .send(&dev_app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(describe["development_mode"], true);
    assert_eq!(describe["proof_verifier_mode"], "development");
    assert_eq!(describe["admin_auth_mode"], "development");

    // Now flip to production posture with an explicit admin allowlist to
    // make sure the derivation tracks the config — this is the production
    // shape sodmin must NOT render a red banner for.
    let prod_config = AppConfig {
        development_mode: false,
        admin_principal_dids: vec!["did:web:ops.example".to_owned()],
        ..test_config()
    };
    let prod_state = AppState::new(prod_config, Db { pool: None });
    let prod_app = app_from_state(prod_state);

    let prod_health: Value = TestClient::get("http://server/health")
        .send(&prod_app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(prod_health["development_mode"], false);
    assert_eq!(prod_health["proof_verifier_mode"], "production");
    assert_eq!(prod_health["admin_auth_mode"], "did_allowlist");

    let prod_describe: Value = TestClient::get("http://server/api/v1/server/describe")
        .send(&prod_app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(prod_describe["development_mode"], false);
    assert_eq!(prod_describe["proof_verifier_mode"], "production");
    assert_eq!(prod_describe["admin_auth_mode"], "did_allowlist");
}

/// T8.3 — `/health` (and `/api/v1/server/describe`) MUST expose a
/// `hardening` block so sodmin's aggregate dashboard can render the
/// production checklist without scraping every config value. The
/// default test config is a hostile worst case (development_mode=true,
/// no TLS, no admin allowlist, no secret manager), so the score MUST
/// be strictly less than `checklist_max` and `development_mode` MUST
/// surface as true.
#[tokio::test]
async fn healthz_exposes_hardening_status() {
    let dev_app = app();

    let health: Value = TestClient::get("http://server/health")
        .send(&dev_app)
        .await
        .take_json()
        .await
        .unwrap();
    let hardening = &health["hardening"];
    assert!(hardening.is_object(), "hardening block must be present");
    assert_eq!(hardening["development_mode"], true);
    assert_eq!(hardening["rate_limit_enabled"], true);
    assert_eq!(hardening["admin_auth_mode"], "development");
    let score = hardening["checklist_score"].as_u64().unwrap();
    let max = hardening["checklist_max"].as_u64().unwrap();
    assert!(max >= 8, "checklist_max should cover at least 8 fields");
    assert!(
        score < max,
        "dev test config must fail at least one check (got {score}/{max})"
    );
    let warnings = hardening["warnings"].as_array().unwrap();
    assert!(
        warnings
            .iter()
            .any(|w| w.as_str() == Some("development_mode_disabled")),
        "warnings must flag development_mode (got {warnings:?})"
    );

    // Production posture: flip dev mode off, configure an admin
    // allowlist + TLS + a CORS origin + an anchorer key. The score
    // should rise materially.
    let prod_config = AppConfig {
        development_mode: false,
        admin_principal_dids: vec!["did:web:ops.example".to_owned()],
        tls_cert_path: Some(std::path::PathBuf::from("/etc/soland/tls.crt")),
        tls_key_path: Some(std::path::PathBuf::from("/etc/soland/tls.key")),
        cors_allow_origin: Some("https://app.example.com".to_owned()),
        anchorer_signing_key_seed: Some([7u8; 32]),
        seed_demo_data: false,
        ..test_config()
    };
    let prod_state = AppState::new(prod_config, Db { pool: None });
    let prod_app = app_from_state(prod_state);

    let prod_health: Value = TestClient::get("http://server/health")
        .send(&prod_app)
        .await
        .take_json()
        .await
        .unwrap();
    let prod_hardening = &prod_health["hardening"];
    assert_eq!(prod_hardening["development_mode"], false);
    assert_eq!(prod_hardening["tls_enabled"], true);
    assert_eq!(prod_hardening["admin_auth_mode"], "did_allowlist");
    assert_eq!(prod_hardening["csp_header_configured"], true);
    assert_eq!(prod_hardening["cors_strict"], true);
    assert_eq!(prod_hardening["secret_manager_in_use"], true);
    let prod_score = prod_hardening["checklist_score"].as_u64().unwrap();
    assert!(
        prod_score >= score + 4,
        "prod posture should clear several extra checks (dev={score} prod={prod_score})"
    );

    // /api/v1/server/describe should also embed the same hardening block.
    let describe: Value = TestClient::get("http://server/api/v1/server/describe")
        .send(&prod_app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(describe["hardening"]["development_mode"], false);
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
    assert_eq!(
        fetched["metadata"]["realm_id"],
        "cx:realm:0196419b-0000-7000-8000-000000000000"
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

    // Round 13: `cx.flow.create` now has a schema requirement (payload
    // MUST carry `object`) because it's in the canonical-kind registry;
    // prior to round 13 it passed as an opaque envelope. Use a real Flow
    // object payload so this smoke test still exercises the cross-family
    // accept path (kind/schema combo distinct from `cx.message.create`).
    let artifact_kind_payload = serde_json::json!({
        "object": {
            "id": "cx:flow:01904100-0000-7000-8000-aa11ccff0001",
            "schema": "cx.schema.flow.v1",
            "realm_id": DEMO_REALM_ID,
            "title": "Onboarding flow",
            "stage": "draft",
            "tracks": {
                "discussion": {
                    "is_primary": true,
                    "profile": "discussion"
                }
            },
            "created_by": "did:web:alice.example",
            "created_at": "2026-05-17T00:00:00Z"
        }
    });
    let mut artifact_kind_event = signed_event_envelope(
        "cx:event:01904100-0000-7000-8000-df827a7269a3",
        3,
        Vec::new(),
    );
    artifact_kind_event["kind"] = Value::String("cx.flow.create".to_owned());
    artifact_kind_event["schema_id"] = Value::String("cx.schema.flow.v1".to_owned());
    artifact_kind_event["payload"] = artifact_kind_payload.clone();
    artifact_kind_event["proofs"][0]["payload_digest"] =
        Value::String(sha256_json(&artifact_kind_payload));
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
    assert_eq!(unknown_schema_body["error"]["code"], "unknown_schema");

    let batch: Value = TestClient::post("http://server/api/v1/events/resolve")
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
        TestClient::get("http://server/api/v1/events?actors=did:web:alice.example&limit=10")
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(listed["events"].as_array().unwrap().len(), 3);
    assert_eq!(listed["frontier"]["actors"]["did:web:alice.example"], 3);
    assert_eq!(
        listed["frontier"]["realms"]["cx:realm:0196419b-0000-7000-8000-000000000000"],
        "cx:event:01904100-0000-7000-8000-df827a7269a3"
    );

    let frontier: Value =
        TestClient::get("http://server/api/v1/events/frontier?actor_id=did:web:alice.example&realm_id=cx:realm:0196419b-0000-7000-8000-000000000000")
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(frontier["actor_frontier"]["did:web:alice.example"], 3);
    assert_eq!(
        frontier["realm_frontier"]["cx:realm:0196419b-0000-7000-8000-000000000000"]["event_id"],
        "cx:event:01904100-0000-7000-8000-df827a7269a3"
    );

    let mut conflicting = signed_event_envelope(
        "cx:event:01904100-0000-7000-8000-f15c8ea06c11",
        4,
        Vec::new(),
    );
    conflicting["payload"]["body"] = Value::String("different canonical body".to_owned());
    let payload_digest = sha256_json(&conflicting["payload"]);
    conflicting["proofs"][0]["payload_digest"] = Value::String(payload_digest);
    conflicting["canonical_digest"] = Value::String(event_canonical_digest(&conflicting));
    let mut conflict = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&conflicting)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(conflict.status_code.unwrap(), StatusCode::CONFLICT);
    let conflict_body: Value = conflict.take_json().await.unwrap();
    assert_eq!(conflict_body["error"]["code"], "duplicate_conflict");
}

#[tokio::test]
async fn scaffold_describe_surfaces_are_marked_limited_not_profile_claims() {
    let service = app();
    let authz: Value = TestClient::get("http://server/api/v1/authz/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(authz["stability"], "scaffold_contract");
    assert_eq!(authz["profile_claim"], "not_claimed");
    assert!(
        authz["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item.as_str().unwrap().contains("not complete profile"))
    );

    let policies: Value = TestClient::get("http://server/api/v1/policies/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(policies["stability"], "scaffold_contract");
    assert_eq!(policies["profile_claim"], "not_claimed");

    let index: Value = TestClient::get("http://server/api/v1/index/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(index["stability"], "limited_projection");
    assert_eq!(index["profile_claim"], "not_claimed");

    let integration: Value = TestClient::get("http://server/api/v1/integration/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    let surfaces = integration["surfaces"].as_array().unwrap();
    assert!(surfaces.iter().any(|surface| {
        surface["name"] == "admin_bottom_manual_repair"
            && surface["stability"] == "unsupported_signing_path"
    }));
    assert!(surfaces.iter().any(|surface| {
        surface["name"] == "index_query" && surface["stability"] == "limited_projection"
    }));
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
    // `FacetName` / `ViewRenderer` / `allowed_entity_facets` were removed
    // alongside the entity/view scaffold in round 6 (no spec counterpart).
    // The renamed cell-family-bound constraint surfaces as
    // `allowed_object_facets` in the `x-contrix-artifacts` extension.
    assert!(body.contains("x-operation-aliases"));
    assert!(body.contains("x-contrix-artifacts"));
    assert!(body.contains("allowed_object_facets"));
    let expected_operation_ids = [
        "cx.system.health",
        "cx.extension.soland.account.register",
        "cx.extension.soland.account.me",
        "cx.extension.soland.auth.logout",
        "cx.extension.soland.contacts.request",
        "cx.extension.soland.contacts.respond",
        "cx.extension.soland.contacts.list",
        "cx.server.describe",
        "cx.events.describe",
        "cx.events.submit",
        "cx.events.get",
        "cx.events.resolve",
        "cx.events.query",
        "cx.events.subscribe",
        "cx.events.frontier",
        "cx.extension.soland.index.query",
        "cx.authz.get_effective_grants",
        "cx.authz.get_invites",
        "cx.extension.soland.federation.transaction",
        "cx.extension.soland.federation.push_operations",
        "cx.extension.soland.federation.pull_operations",
        "cx.extension.soland.federation.space_members",
        "cx.extension.soland.federation.verify_actor",
        "cx.account.subscribe",
        "cx.ephemeral.send",
        "cx.events.query_post",
        "cx.extension.soland.sync.backfill_gap",
        "cx.snapshot.head",
        "cx.extension.soland.sync.get_snapshot_chunk",
        "cx.directory.describe",
        "cx.directory.search_realms",
        "cx.directory.resolve_realm",
        "cx.directory.private_contact_discovery",
        "cx.directory.announce",
        "cx.directory.withdraw",
        "cx.directory.push.register",
        "cx.extension.soland.index.describe",
        "cx.extension.soland.index.debug_reducer",
        "cx.extension.soland.admin.actors",
        "cx.extension.soland.admin.spaces",
        "cx.extension.soland.admin.devices",
        "cx.extension.soland.admin.capabilities",
        "cx.extension.soland.admin.federation",
        "cx.extension.soland.admin.applets",
        "cx.extension.soland.admin.agents",
        "cx.extension.soland.admin.reports",
        "cx.extension.soland.admin.invite_tokens",
        "cx.extension.soland.admin.audit",
        "cx.extension.soland.admin.policy",
        "cx.extension.soland.admin.media",
        "cx.authz.check",
        "cx.extension.soland.policies.list",
        "cx.extension.soland.policies.get",
        "cx.extension.soland.policies.upsert",
        "cx.extension.soland.policies.delete",
        "cx.push.register_device",
        "cx.extension.soland.devices.pairing_challenge",
        "cx.extension.soland.devices.authorize_pairing",
        "cx.push.unregister_device",
        "cx.extension.soland.push.rules",
        "cx.push.notify",
        "cx.blob.upload",
        "cx.blob.presign",
        "cx.blob.head",
        "cx.blob.get",
        "cx.extension.soland.webrtc.create_session",
        "cx.extension.soland.webrtc.send_signal",
        "cx.extension.soland.webrtc.close_session",
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
        "cx.keys.keypackages.consume",
        "cx.keys.keypackages.revoke",
        "cx.identity.submit_did_operation",
        "cx.admin.get_server_status",
        "cx.admin.update_account_status",
        "cx.admin.revoke_device",
        "cx.admin.get_moderation_queue",
    ];
    for operation_id in expected_operation_ids {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing {operation_id} in generated openapi"
        );
    }
    for removed_operation_id in [
        "cx.extension.soland.spaces.create",
        "cx.extension.soland.spaces.update",
        "cx.extension.soland.spaces.set_policy",
        "cx.extension.soland.spaces.delete",
        "cx.extension.soland.spaces.add_member",
        "cx.extension.soland.spaces.remove_member",
    ] {
        assert!(
            !body.contains(&format!("operationId: {removed_operation_id}")),
            "removed non-canonical write API still advertised: {removed_operation_id}"
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
    let space_id = DEMO_REALM_ID;

    let sent = submit_message_event(
        state.clone(),
        &token,
        "did:web:alice.example",
        space_id,
        "cx:flow:debug-reducer",
        serde_json::json!({"body": "debug reducer"}),
        false,
    )
    .await;

    let debug: Value = TestClient::get(format!(
        "http://server/api/v1/index/debug/reducer?realm_id={space_id}&limit=5"
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
    assert_eq!(debug["realm_id"], space_id);
    assert_eq!(debug["frontier"]["message_count"], 1);
    assert_eq!(debug["frontier"]["projection_event_count"], 1);
    assert_eq!(debug["frontier"]["latest_event_id"], sent["event_id"]);
    assert_eq!(debug["recent_events"][0]["event_id"], sent["event_id"]);
    assert_eq!(
        debug["production_gap"],
        "durable_reducer_replay_and_conflict_records"
    );

    let invalid = TestClient::get("http://server/api/v1/index/debug/reducer?realm_id=bad")
        .send(&app_from_state(state))
        .await;
    assert_eq!(invalid.status_code.unwrap().as_u16(), 400);
}

#[tokio::test]
async fn index_query_supports_structured_filters_sort_and_cursor() {
    let state = AppState::new(test_config(), Db { pool: None });
    for title in ["Zulu Query Space", "Alpha Query Space"] {
        let created = seed_test_realm(
            &state,
            "did:web:alice.example",
            title,
            Some("index query pagination fixture"),
            "public",
            &[],
            &[],
        );
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

    let first = account_subscribe_frame(state.clone(), Some(&token), "catchup=true").await;
    assert!(first["cursor"].as_str().is_some());
    let cursor = first["cursor"].as_str().unwrap();

    let filter_changed = TestClient::get(format!(
        "http://server/api/v1/account/subscribe?catchup=true&after={cursor}&filter=%7B%22spaces%22%3A%5B%22cx%3Aspace%3A0196419b-0000-7000-8000-000000000000%22%5D%7D"
    ))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(filter_changed.status_code.unwrap().as_u16(), 400);
}

#[tokio::test]
async fn sync_backfill_exposes_prev_cursor_and_limited_timeline_pages() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let space_id = DEMO_REALM_ID;

    for body in ["first backfill page", "second backfill page"] {
        let sent = submit_message_event(
            state.clone(),
            &token,
            "did:web:alice.example",
            space_id,
            "cx:flow:backfill-pages",
            serde_json::json!({"body": body}),
            false,
        )
        .await;
        assert!(sent["operation_id"].as_str().is_some());
    }

    let first_page: Value = TestClient::get(format!(
        "http://server/api/v1/events?realms={space_id}&limit=1"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(first_page["events"].as_array().unwrap().len(), 1);
    assert_eq!(first_page["limited"], true);
    assert!(first_page["prev_cursor"].is_null());
    let next_cursor = first_page["next_cursor"].as_str().unwrap();

    let second_page: Value = TestClient::get(format!(
        "http://server/api/v1/events?realms={space_id}&limit=1&after={next_cursor}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(second_page["prev_cursor"], next_cursor);
    assert_eq!(second_page["events"].as_array().unwrap().len(), 1);
    let to_cursor = second_page["events"][0]["event_id"].as_str().unwrap();
    let gap: Value = TestClient::get(format!(
        "http://server/api/v1/sync/backfill/gap?realm_id={space_id}&from_cursor={next_cursor}&to_cursor={to_cursor}&limit=10"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(gap["from_cursor"], next_cursor);
    assert_eq!(gap["to_cursor"], to_cursor);
    assert_eq!(gap["prev_cursor"], next_cursor);
    assert_eq!(gap["gap_complete"], true);
    assert_eq!(gap["events"].as_array().unwrap().len(), 1);
    assert_eq!(gap["production_gap"], "durable_sync_position_validation");

    let mut invalid_cursor = TestClient::get(format!(
        "http://server/api/v1/events?realms={space_id}&after=cx:event:01904100-0000-7000-8000-b8ab57920a67"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(invalid_cursor.status_code.unwrap().as_u16(), 400);
    let invalid_cursor_body: Value = invalid_cursor.take_json().await.unwrap();
    assert_eq!(invalid_cursor_body["error"]["code"], "invalid_cursor");
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

    let room_binding: Value = TestClient::put("http://server/api/v1/mimi/flows/01JSMIMI/update")
        .json(&serde_json::json!({
            "room_binding": {
                "mimi_room_uri": "mimi://soland.local/rooms/01JSMIMI",
                "binding_scope": {
                    "space_id": "cx:space:0196419b-0000-7000-8000-000000000000"
                }
            }
        }))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(room_binding["ok"], true);

    let group_info: Value = TestClient::get("http://server/api/v1/mimi/flows/01JSMIMI/group-info")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        group_info["room_id"], "01JSMIMI",
        "group_info response: {group_info}"
    );
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

    let mapped: Value = TestClient::post("http://server/api/v1/mimi/flows/01JSMIMI/messages")
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
            "target_event_digest": "sha256:target",
            "frank": {"scheme": "dev-frank"}
        }))
        .send(&service)
        .await;
    // Round 15ab — mimi handlers converted to typed `JsonResult<Value>`
    // signatures; Salvo's typed Writer defaults to 200 OK. Status-code
    // distinction was never load-bearing (no caller branched on 202 vs
    // 200), but the wire body still carries `ok=true` + `status="queued"`.
    assert_eq!(report.status_code.unwrap().as_u16(), 200);
}

/// MIMI facade writes map into the canonical Contrix reducer
/// chain. This e2e walks through the four reducer-bound mappings:
///
///   1. `room_update` with a `room_binding` block emits a
///      `cx.mimi.room_binding` projection event.
///   2. Subsequent `submit_message` uses the bound `space_id` (not
///      the demo fallback) and lands a `cx.message.create` event in
///      the projection log so the Contrix timeline observes it.
///   3. `notify` broadcasts a `cx.mimi.notify` synthetic event to
///      subscribers (verified via response shape; broadcast is
///      ephemeral so it doesn't appear in projection_events).
///   4. `report_abuse` emits a `cx.moderation.report` event with
///      mimi_provenance metadata.
#[tokio::test]
async fn mimi_facade_writes_flow_into_canonical_reducer_chain() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let service = app_from_state(state.clone());
    let demo_space = DEMO_REALM_ID;
    let custom_space = "cx:realm:0196419b-0000-7000-8000-aaaaaaaaaaaa";
    let room_id = "01JSMIMI-P4-E2E";

    // Step 1: post a room_update carrying a room_binding block.
    let update_resp: Value =
        TestClient::put(format!("http://server/api/v1/mimi/flows/{room_id}/update"))
            .json(&serde_json::json!({
                "room_binding": {
                    "profile": "cx.profile.mimi_interop.v1",
                    "mimi_room_uri": format!("mimi://soland.local/rooms/{room_id}"),
                    "binding_scope": {
                        "space_id": demo_space,
                        "flow_id": null,
                    },
                    "hub_provider": "did:web:test.local",
                    "local_provider_role": "hub",
                    "follower_providers": [],
                    "mls_group_id": "base64url-test",
                    "content_profile": "application/mimi-content",
                    "policy_component_root": "sha256:test",
                    "created_at": "2026-05-16T00:00:00Z",
                },
                "protocol_draft": "draft-ietf-mimi-protocol-06",
            }))
            .send(&service)
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(update_resp["ok"], true);
    assert_eq!(
        update_resp["receipt"]["extra"]["binding_emitted"], true,
        "room_update receipt must announce binding emission"
    );
    let binding_event_id = update_resp["binding_event_id"]
        .as_str()
        .expect("binding_event_id missing from response");
    assert!(binding_event_id.starts_with("cx:event:"));

    // Step 2: submit_message into the same room.
    let msg_resp: Value = TestClient::post(format!(
        "http://server/api/v1/mimi/flows/{room_id}/messages"
    ))
    .json(&serde_json::json!({
        "source_format": "text/plain;charset=utf-8",
        "content": {
            "kind": "cx.content.composite",
            "body": "hello from MIMI P4",
            "parts": [{"kind": "cx.content.text", "body": "hello from MIMI P4"}],
        },
        "sender_did": "did:web:remote.example",
        "mimi_message_id": "mimi-msg-p4-001",
        "original_envelope_hash": "sha256:p4-orig",
        "protocol_draft": "draft-ietf-mimi-protocol-06",
        "content_draft": "draft-ietf-mimi-content-08",
    }))
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(msg_resp["ok"], true);
    assert_eq!(
        msg_resp["space_id"], demo_space,
        "submit_message must use bound space_id"
    );
    assert_eq!(
        msg_resp["receipt"]["extra"]["reducer_chain"], "wired",
        "submit_message receipt should announce reducer-chain wire-up"
    );
    let contrix_event_id = msg_resp["contrix_event_id"]
        .as_str()
        .expect("contrix_event_id missing");

    // Step 3: query /api/v1/events against the bound space and
    // verify both the room_binding event and the message event are
    // present.
    let events: Value = TestClient::get(format!("http://server/api/v1/events?realms={demo_space}"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    let list = events["events"].as_array().expect("events array");

    let binding_event = list
        .iter()
        .find(|e| e["event_id"] == binding_event_id)
        .expect("room_binding event missing from projection log");
    assert_eq!(binding_event["event_kind"], "cx.mimi.room_binding");
    assert_eq!(
        binding_event["payload"]["mimi_room_id"], room_id,
        "room_binding payload must echo room_id for bound-space dispatch"
    );
    assert_eq!(
        binding_event["payload"]["binding_scope"]["space_id"],
        demo_space
    );

    let message_event = list
        .iter()
        .find(|e| e["event_id"] == contrix_event_id)
        .expect("MIMI-ingressed message missing from projection log");
    assert_eq!(message_event["event_kind"], "cx.message.create");
    assert_eq!(message_event["sender"], "did:web:remote.example");
    assert_eq!(
        message_event["payload"]["content"]["parts"][0]["body"],
        "hello from MIMI P4"
    );
    // mimi_provenance metadata MUST be preserved.
    assert_eq!(
        message_event["payload"]["mimi_provenance"]["mimi_message_id"],
        "mimi-msg-p4-001"
    );
    assert_eq!(
        message_event["payload"]["mimi_provenance"]["original_envelope_hash"],
        "sha256:p4-orig"
    );
    assert_eq!(
        message_event["payload"]["mimi_provenance"]["facade"],
        "soland.mimi.v1"
    );

    // Step 4: report_abuse emits a cx.moderation.report event.
    let report_resp: Value = TestClient::post("http://server/api/v1/mimi/report-abuse")
        .json(&serde_json::json!({
            "mimi_room_uri": format!("mimi://soland.local/rooms/{room_id}"),
            "target_event_digest": "sha256:abuse-target",
            "frank": {"scheme": "dev-frank"},
            "reporter_did": "did:web:reporter.example",
            "space_id": demo_space,
            "protocol_draft": "draft-ietf-mimi-protocol-06",
        }))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(report_resp["ok"], true);
    let report_event_id = report_resp["report_event_id"]
        .as_str()
        .expect("report_event_id missing");
    assert_eq!(
        report_resp["receipt"]["extra"]["moderation_event_emitted"], true,
        "report_abuse receipt must announce moderation event emission"
    );

    let events_again: Value =
        TestClient::get(format!("http://server/api/v1/events?realms={demo_space}"))
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&service)
            .await
            .take_json()
            .await
            .unwrap();
    let list2 = events_again["events"].as_array().unwrap();
    let report_event = list2
        .iter()
        .find(|e| e["event_id"] == report_event_id)
        .expect("moderation.report event missing from projection log");
    assert_eq!(report_event["event_kind"], "cx.moderation.report");
    assert_eq!(report_event["sender"], "did:web:reporter.example");
    assert_eq!(
        report_event["payload"]["mimi_provenance"]["mimi_room_uri"],
        format!("mimi://soland.local/rooms/{room_id}")
    );

    // Step 5: a second room_update with a different binding_scope
    // updates the dispatch lookup. The most-recently-recorded
    // binding wins per `mimi_bound_space_id` semantics.
    let _: Value = TestClient::put(format!("http://server/api/v1/mimi/flows/{room_id}/update"))
        .json(&serde_json::json!({
            "room_binding": {
                "profile": "cx.profile.mimi_interop.v1",
                "mimi_room_uri": format!("mimi://soland.local/rooms/{room_id}"),
                "binding_scope": {
                    "space_id": custom_space,
                    "flow_id": null,
                },
                "hub_provider": "did:web:test.local",
                "local_provider_role": "hub",
                "mls_group_id": "base64url-test-2",
                "policy_component_root": "sha256:test-2",
                "created_at": "2026-05-16T00:00:01Z",
            },
            "protocol_draft": "draft-ietf-mimi-protocol-06",
        }))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();

    let msg_resp_2: Value = TestClient::post(format!(
        "http://server/api/v1/mimi/flows/{room_id}/messages"
    ))
    .json(&serde_json::json!({
        "source_format": "application/mimi-content",
        "content": {
            "kind": "cx.content.composite",
            "body": "second message",
            "parts": [{"kind": "cx.content.text", "body": "second message"}]
        },
        "protocol_draft": "draft-ietf-mimi-protocol-06",
    }))
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        msg_resp_2["space_id"], custom_space,
        "second message must route to the rebound space_id"
    );
}

#[tokio::test]
async fn configured_cors_allows_only_explicit_origin() {
    let mut config = test_config();
    config.cors_allow_origin = Some("https://app.example".to_owned());
    let service = app_from_state(AppState::new(config, Db { pool: None }));

    let allowed = TestClient::options("http://server/api/v1/account/subscribe?catchup=true")
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

    let denied = TestClient::options("http://server/api/v1/account/subscribe?catchup=true")
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
async fn seed_member_invite_event_surfaces_via_authz_invites() {
    // The Realm bootstrap flow in yougen emits a
    // `cx.member.state{membership="invite"}` event for each seed member
    // (see contrix-rust-sdk + yougen/src/api.rs `build_realm_bootstrap_events`).
    // `models/realm-and-space.md` §3 + `governance/join-policy.md` §6 then
    // expect the invitee to see that invite via `GET /authz/invites`.
    // This test pins that contract on the event path.
    let state = AppState::new(test_config(), Db { pool: None });
    // dev-login auto-registers the actor; we don't need /account/register's
    // strict schema here. Use yougen-style unique DIDs (with hyphens and
    // uuid suffixes) so the test exercises the same DID validator path the
    // e2e suite hits.
    let alice_did = "did:web:s23-alice-c58c7ec9-39a4-40ce-acfd-e7318c944230.example";
    let bob_did = "did:web:s23-bob-f7ec8919-f086-4735-b4d2-8632440d98f8.example";
    let alice = dev_token_for_device(
        state.clone(),
        alice_did,
        "cx:device:01904100-0000-7000-8000-a11ce0000001",
        "Alice",
    )
    .await;
    let bob = dev_token_for_device(
        state.clone(),
        bob_did,
        "cx:device:01904100-0000-7000-8000-b0b000000002",
        "Bob",
    )
    .await;

    let created_space = seed_test_realm(
        &state,
        alice_did,
        "Seed Invite Event Path",
        None,
        "invite_only",
        &[],
        &[],
    );
    let space_id = created_space["space_id"].as_str().unwrap().to_owned();

    // Submit alice's cx.member.state{membership=invite} pointing at bob.
    let event_id = "cx:event:01904100-0000-7000-8000-aa00000000ee";
    let payload = serde_json::json!({
        "actor_id": bob_did,
        "membership": "invite",
        "reason": "space_create",
    });
    let mut event = serde_json::json!({
        "event_id": event_id,
        "kind": "cx.member.state",
        "schema_id": "cx.schema.event.v1",
        "actor_id": alice_did,
        "actor_seq": 100_u64,
        "realm_id": space_id.clone(),
        "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "created_at": "2026-05-20T16:00:00Z",
        "prev_refs": [],
        "auth_refs": [],
        "refs": [],
        "proofs": [{
            "type": "dev-proof",
            "verification_method": format!("{alice_did}#01904100-0000-7000-8000-a11ce0000001"),
            "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload),
        }],
        "payload": payload,
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));

    let submit = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&event)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        submit.status_code.unwrap().as_u16(),
        200,
        "cx.member.state{{invite}} should be accepted"
    );

    // Bob should now see a pending invite for the space.
    let bob_invites: Value = TestClient::get("http://server/api/v1/authz/invites")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let invites = bob_invites["invites"].as_array().unwrap();
    assert!(
        invites.iter().any(|invite| {
            invite["space_id"].as_str() == Some(space_id.as_str())
                && invite["invitee"].as_str() == Some(bob_did)
                && invite["status"].as_str() == Some("pending")
        }),
        "expected pending invite for bob in {space_id} (got: {invites:?})"
    );
}

#[tokio::test]
async fn wildcard_cors_mirrors_origin_without_credentials() {
    // api-conventions.md §10 recommends `Access-Control-Allow-Origin: *` for
    // browser-facing services. The combination `*` + Access-Control-Allow-
    // Credentials is rejected by browsers, so the wildcard posture must
    // reflect the request `Origin` and omit credentials. This is what
    // local-dev (and any deployment carrying auth in the `Authorization`
    // header) needs.
    let mut config = test_config();
    config.cors_allow_origin = Some("*".to_owned());
    let service = app_from_state(AppState::new(config, Db { pool: None }));

    let from_yougen = TestClient::options("http://server/api/v1/account/subscribe?catchup=true")
        .add_header("Origin", "http://127.0.0.1:8080", true)
        .add_header("Access-Control-Request-Method", "POST", true)
        .add_header(
            "Access-Control-Request-Headers",
            "authorization, content-type",
            true,
        )
        .send(&service)
        .await;
    assert_eq!(
        from_yougen
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("http://127.0.0.1:8080"),
        "wildcard posture must mirror the request origin"
    );
    assert!(
        from_yougen
            .headers()
            .get("access-control-allow-credentials")
            .is_none(),
        "wildcard posture must not advertise credentials (browser would reject)"
    );

    // A second, unrelated origin gets the same treatment — the handler is
    // genuinely origin-agnostic, not tied to a single hard-coded URL.
    let from_other = TestClient::options("http://server/api/v1/account/subscribe?catchup=true")
        .add_header("Origin", "https://app.elsewhere.example", true)
        .add_header("Access-Control-Request-Method", "POST", true)
        .send(&service)
        .await;
    assert_eq!(
        from_other
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("https://app.elsewhere.example")
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
    let state = AppState::new(test_config_with_service_did(service_did), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let service = app_from_state(state.clone());

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

    let sync: Value = TestClient::get("http://server/api/v1/account/describe")
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

    let resolved: Value = TestClient::post("http://server/api/v1/directory/resolve-realm")
        .json(&serde_json::json!({"realm_id": DEMO_REALM_ID}))
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

    let ice: Value = TestClient::post("http://server/contrix/v1/ice-config")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "call_id": "cx:call:01964137-0000-7000-8000-000000000001",
            "actor_id": "did:web:alice.example",
            "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001"
        }))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(ice["signature"]["kid"], format!("{service_did}#media-ice"));
    assert!(
        ice["signature"]["sig"]
            .as_str()
            .is_some_and(|sig| sig.starts_with("eddsa-ed25519:"))
    );
    assert_ne!(ice["signature"]["sig"], "placeholder");
    assert!(
        ice["signature"]["payload_digest"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:"))
    );
    let mut signed_payload = ice.clone();
    signed_payload.as_object_mut().unwrap().remove("signature");
    let payload_bytes = contrix_sdk::canonical::canonical_json_bytes(&signed_payload).unwrap();
    assert_eq!(
        ice["signature"]["payload_digest"],
        format!("sha256:{:x}", Sha256::digest(&payload_bytes))
    );
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(
            ice["signature"]["sig"]
                .as_str()
                .unwrap()
                .strip_prefix("eddsa-ed25519:")
                .unwrap(),
        )
        .unwrap();
    let signature = Signature::from_bytes(&signature_bytes.try_into().unwrap());
    let mut signing_input = Vec::with_capacity(
        b"soland-media-ice-config-v1".len() + service_did.len() + payload_bytes.len() + 2,
    );
    signing_input.extend_from_slice(b"soland-media-ice-config-v1");
    signing_input.push(0);
    signing_input.extend_from_slice(service_did.as_bytes());
    signing_input.push(0);
    signing_input.extend_from_slice(&payload_bytes);
    state
        .anchorer_signing_key()
        .verifying_key()
        .verify(&signing_input, &signature)
        .unwrap();
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
    assert_eq!(limited["error"]["code"], "rate_limited");
    assert!(limited["error"]["retry_after_ms"].as_u64().unwrap() > 0);
    assert!(
        limited["request_id"]
            .as_str()
            .unwrap()
            .starts_with("cx:request:")
    );
}

#[tokio::test]
async fn account_contacts_and_space_lifecycle_workflow() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = dev_token(state.clone()).await;
    let bob = register_account(
        state.clone(),
        "did:web:bob.example",
        "@bob",
        "cx:device:01904100-0000-7000-8000-b0b0b0000002",
    )
    .await;

    let duplicate = TestClient::post("http://server/api/v1/account/register")
        .json(&serde_json::json!({
            "did": "did:web:bob.example",
            "handle": "@bob",
            "device_id": "cx:device:01904100-0000-7000-8000-b0b0b0000022"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(duplicate.status_code.unwrap().as_u16(), 409);

    let hidden_bob: Value = TestClient::post("http://server/api/v1/directory/search-users")
        .json(&serde_json::json!({"query": "bob"}))
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

    let visible_bob: Value = TestClient::post("http://server/api/v1/directory/search-users")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({"query": "bob"}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(visible_bob["results"][0]["did"], "did:web:bob.example");

    let created_space = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Workflow Space",
        Some("created by lifecycle workflow"),
        "invite_only",
        &["did:web:soland.local"],
        &[],
    );
    let space_id = created_space["space_id"].as_str().unwrap().to_owned();
    assert!(space_id.starts_with("cx:realm:"));
    let realm_id = space_id.clone();
    assert_eq!(created_space["owner"], "did:web:alice.example");

    let hidden_space: Value = TestClient::post("http://server/api/v1/directory/search-realms")
        .json(&serde_json::json!({"query": "Workflow Space"}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(hidden_space["results"].as_array().unwrap().is_empty());

    let invite_space = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Invite Token Space",
        None,
        "invite_only",
        &[],
        &["did:web:bob.example"],
    );
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
    let invalid_invite_resolve = TestClient::post("http://server/api/v1/directory/resolve-realm")
        .json(&serde_json::json!({"invite_token": "cx:invite-token:invalid"}))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(invalid_invite_resolve.status_code.unwrap().as_u16(), 404);
    let invite_resolve: Value = TestClient::post("http://server/api/v1/directory/resolve-realm")
        .json(&serde_json::json!({"invite_token": invite_token}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(invite_resolve["space_preview"]["realm_id"], invite_space_id);

    let listed_space = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Listed Directory Space",
        None,
        "listed",
        &[],
        &[],
    );
    let listed_space_id = listed_space["space_id"].as_str().unwrap().to_owned();
    let listed_search: Value = TestClient::post("http://server/api/v1/directory/search-realms")
        .json(&serde_json::json!({"query": "Listed Directory Space"}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        listed_search["results"][0]["realm_id"],
        listed_space_id.as_str()
    );
    let anonymous_sync_after_listed =
        account_subscribe_frame(state.clone(), None, "catchup=true").await;
    assert!(
        !anonymous_sync_after_listed["realms"]
            .as_object()
            .unwrap()
            .contains_key(&listed_space_id)
    );

    let unlisted_space = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Unlisted Directory Space",
        None,
        "unlisted",
        &[],
        &[],
    );
    let unlisted_space_id = unlisted_space["space_id"].as_str().unwrap().to_owned();
    let unlisted_search: Value = TestClient::post("http://server/api/v1/directory/search-realms")
        .json(&serde_json::json!({"query": "Unlisted Directory Space"}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(unlisted_search["results"].as_array().unwrap().is_empty());
    let unlisted_resolve: Value = TestClient::post("http://server/api/v1/directory/resolve-realm")
        .json(&serde_json::json!({"realm_id": unlisted_space_id.clone()}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        unlisted_resolve["space_preview"]["realm_id"],
        unlisted_space_id
    );

    let anonymous_resolve = TestClient::post("http://server/api/v1/directory/resolve-realm")
        .json(&serde_json::json!({"realm_id": space_id}))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(anonymous_resolve.status_code.unwrap().as_u16(), 404);

    let owner_resolve: Value = TestClient::post("http://server/api/v1/directory/resolve-realm")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({"realm_id": space_id}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(owner_resolve["space_preview"]["realm_id"], space_id);

    let locked_space = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Locked Plaintext Space",
        None,
        "invite_only",
        &[],
        &[],
    );
    let locked_space_id = locked_space["space_id"].as_str().unwrap();
    let plaintext_without_service = post_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        locked_space_id,
        locked_space_id,
        serde_json::json!({"body": "should be denied"}),
        false,
    )
    .await;
    assert_eq!(plaintext_without_service.as_u16(), 403);

    let invalid_encrypted = post_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        locked_space_id,
        locked_space_id,
        serde_json::json!({"ciphertext": "opaque"}),
        true,
    )
    .await;
    assert_eq!(invalid_encrypted.as_u16(), 400);

    let encrypted_message = submit_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        locked_space_id,
        locked_space_id,
        encrypted_envelope("cx.message.v1", "opaque-ciphertext"),
        true,
    )
    .await;
    assert!(
        encrypted_message["event_id"]
            .as_str()
            .unwrap()
            .starts_with("cx:event:")
    );

    let bob_private_sync = account_subscribe_frame(state.clone(), Some(&bob), "catchup=true").await;
    assert!(
        !bob_private_sync["realms"]
            .as_object()
            .unwrap()
            .contains_key(&space_id)
    );

    let with_bob = add_test_realm_member(&state, &space_id, "did:web:bob.example");
    assert!(
        with_bob["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|member| member == "did:web:bob.example")
    );

    let sent_message = submit_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        &realm_id,
        "cx:flow:workflow",
        serde_json::json!({"body": "hello workflow"}),
        false,
    )
    .await;
    assert!(
        sent_message["operation_id"]
            .as_str()
            .unwrap()
            .starts_with("cx:operation:")
    );
    assert_eq!(sent_message["realm_id"], realm_id);
    assert_eq!(sent_message["space_id"], space_id);
    assert_eq!(sent_message["source_realm_id"], realm_id);
    let send_cursor = decode_cursor(sent_message["sync_token"].as_str().unwrap());
    assert_eq!(send_cursor["v"], "1");
    assert!(send_cursor["h"].as_str().is_some_and(|h| h.len() >= 22));
    assert!(send_cursor.get("_positions").is_none());

    let invalid_block_message = post_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        &space_id,
        "cx:flow:workflow",
        serde_json::json!({"kind": "cx.content.composite", "body": "invalid", "parts": [{"kind": "cx.content.image", "body": "image"}]}),
        false,
    )
    .await;
    assert_eq!(invalid_block_message.as_u16(), 400);

    let non_canonical_message = post_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        &space_id,
        "cx:flow:workflow",
        serde_json::json!({"kind": "cx.content.location", "body": "location", "latitude": 31.2304, "longitude": 121.4737}),
        false,
    )
    .await;
    assert_eq!(non_canonical_message.as_u16(), 400);

    let invalid_mention_message = post_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        &space_id,
        "cx:flow:workflow",
        serde_json::json!({"body": "bad mention", "mentions": [{"type": "actor", "did": "alice"}]}),
        false,
    )
    .await;
    assert_eq!(invalid_mention_message.as_u16(), 400);

    let block_message = submit_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        &space_id,
        "cx:flow:workflow",
        serde_json::json!({
            "kind": "cx.content.composite",
            "body": "structured hello",
            "mentions": [
                "did:web:bob.example",
                {"type": "flow", "flow_id": "cx:flow:01904100-0000-7000-8000-170d4f3bfc7b"}
            ],
            "parts": [
                {"kind": "cx.content.text", "body": "structured hello"},
                {"kind": "cx.content.location", "body": "location", "latitude": 312304000, "longitude": 1214737000},
                {"kind": "cx.content.poll", "body": "ship?", "question": "ship?", "options": ["yes", "no"]}
            ]
        }),
        false,
    )
    .await;
    assert!(
        block_message["event_id"]
            .as_str()
            .is_some_and(|event_id| event_id.starts_with("cx:event:")),
        "block message response: {block_message}"
    );

    let thread: Value =
        TestClient::get("http://server/api/v1/index/thread?thread_id=cx:flow:workflow")
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
            "object_kinds": ["message"]
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

    let sync_with_message =
        account_subscribe_frame(state.clone(), Some(&alice), "catchup=true").await;
    let cursor = decode_cursor(
        sync_with_message["cursor"]
            .as_str()
            .unwrap_or_else(|| panic!("sync response missing cursor: {sync_with_message}")),
    );
    assert_eq!(cursor["v"], "1");
    assert_eq!(cursor["purpose"], "stream");
    assert!(cursor["t"].as_str().is_some());
    assert!(cursor["x"].as_i64().unwrap() > 0);
    assert!(cursor["h"].as_str().is_some_and(|h| h.len() >= 22));
    assert!(cursor.get("_ctx").is_none());
    assert!(cursor.get("_positions").is_none());
    assert!(cursor.get("_mac").is_none());
    assert!(cursor.get("_sig").is_none());
    assert!(cursor.get("issuer_kid").is_none());
    assert_eq!(
        sync_with_message["realms"][&space_id]["timeline"]["events"][0]["event_id"],
        sent_message["event_id"]
    );
    assert_eq!(
        sync_with_message["realms"][&space_id]["timeline"]["events"][0]["flow_id"],
        expected_flow_id_for_scope(&space_id)
    );
    // Message v1 exposes the timeline track as the const string `discussion`.
    assert_eq!(
        sync_with_message["realms"][&space_id]["timeline"]["events"][0]["track"],
        "discussion"
    );
    assert_eq!(
        sync_with_message["realms"][&space_id]["summary"]["flow"]["schema"],
        "cx.schema.flow.v1"
    );

    let incremental_noop = account_subscribe_frame(
        state.clone(),
        Some(&alice),
        &format!(
            "catchup=true&after={}",
            sync_with_message["cursor"].as_str().unwrap()
        ),
    )
    .await;
    assert!(
        incremental_noop["realms"][&space_id]["timeline"]["events"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    tokio::time::sleep(Duration::from_millis(2)).await;
    let second_message = submit_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        &space_id,
        "cx:flow:workflow",
        serde_json::json!({"body": "second workflow"}),
        false,
    )
    .await;
    let incremental_after_message = account_subscribe_frame(
        state.clone(),
        Some(&alice),
        &format!(
            "catchup=true&after={}",
            sync_with_message["cursor"].as_str().unwrap()
        ),
    )
    .await;
    let incremental_events = incremental_after_message["realms"][&space_id]["timeline"]["events"]
        .as_array()
        .unwrap();
    assert_eq!(incremental_events.len(), 1);
    assert_eq!(
        incremental_events[0]["event_id"],
        second_message["event_id"]
    );

    let mismatch = TestClient::get(format!(
        "http://server/api/v1/account/subscribe?catchup=true&after={}",
        sync_with_message["cursor"].as_str().unwrap()
    ))
    .add_header("authorization", format!("Bearer {bob}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(mismatch.status_code.unwrap().as_u16(), 400);

    let filter_mismatch = TestClient::get(format!(
        "http://server/api/v1/account/subscribe?catchup=true&after={}&filter=%7B%22spaces%22%3A%5B%22{}%22%5D%7D",
        sync_with_message["cursor"].as_str().unwrap(),
        space_id
    ))
        .add_header("authorization", format!("Bearer {alice}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(filter_mismatch.status_code.unwrap().as_u16(), 400);

    let mut expired_cursor = cursor.clone();
    expired_cursor["x"] = serde_json::json!(1);
    let mut expired = TestClient::get(format!(
        "http://server/api/v1/account/subscribe?catchup=true&after={}",
        encode_cursor(&expired_cursor)
    ))
    .add_header("authorization", format!("Bearer {alice}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(expired.status_code.unwrap(), StatusCode::GONE);
    let expired_body: Value = expired.take_json().await.unwrap();
    assert_eq!(expired_body["error"]["code"], "cursor_expired");

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

    let waited_sync = account_subscribe_frame(state.clone(), Some(&alice), "catchup=true").await;
    assert_eq!(
        waited_sync["realms"][&space_id]["timeline"]["events"][0]["event_id"],
        sent_message["event_id"]
    );

    let invalid_wait = TestClient::get("http://server/api/v1/account/subscribe?catchup=true")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .add_header("x-contrix-wait-for", "not-a-sync-token", true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(invalid_wait.status_code.unwrap().as_u16(), 400);

    let snapshot: Value = TestClient::get(format!(
        "http://server/api/v1/snapshot/head?realm_id={space_id}"
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
    // Snapshot v2 (round 9): chunk_id is now a typed integer in the SDK
    // shape; small test states fit in a single 256 KiB chunk so chunk[0]
    // .digest is the state_digest and chunk_count == 1.
    assert_eq!(snapshot["chunks"][0]["chunk_id"], 0);
    assert_eq!(snapshot["chunks"][0]["digest"], snapshot["state_digest"]);
    assert_eq!(snapshot["chunk_count"], 1);
    assert_eq!(
        snapshot["merkle_root"].as_str().unwrap(),
        snapshot["state_digest"].as_str().unwrap(),
        "single-chunk Merkle root collapses to the leaf digest"
    );
    // GeneratorProof envelope is present + carries a non-empty signature.
    let proof = &snapshot["generator_proof"];
    assert!(proof.is_object(), "generator_proof must be present");
    assert!(
        !proof["signature"]["jws"].as_str().unwrap().is_empty(),
        "generator_proof.signature.jws must be non-empty"
    );
    assert_eq!(proof["chunk_count"], 1);
    assert_eq!(
        proof["realm_id"].as_str().unwrap(),
        space_id,
        "generator_proof.realm_id matches the snapshot Realm"
    );

    let snapshot_chunk: Value = TestClient::get(format!(
        "http://server/api/v1/sync/snapshot-chunk?snapshot_ref={}&chunk_id=0",
        snapshot["snapshot_ref"].as_str().unwrap()
    ))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(snapshot_chunk["digest"], snapshot["state_digest"]);
    assert_eq!(snapshot_chunk["verified"], true);
    assert!(!snapshot_chunk["bytes_base64"].as_str().unwrap().is_empty());
    // Snapshot v2: chunk responses surface the audit-path so receivers
    // can verify the chunk against the head's merkle_root without
    // trusting the chunk source.
    assert!(snapshot_chunk["audit_path"].is_array());
    assert_eq!(
        snapshot_chunk["tree_size"], 1,
        "single-chunk tree has tree_size == 1"
    );
    assert_eq!(
        snapshot_chunk["merkle_root"].as_str().unwrap(),
        snapshot["merkle_root"].as_str().unwrap(),
        "chunk merkle_root matches head merkle_root"
    );

    let kicked = remove_test_realm_member(&state, &space_id, "did:web:bob.example");
    assert!(
        !kicked["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|member| member == "did:web:bob.example")
    );

    let deleted = delete_test_realm(&state, &space_id);
    assert_eq!(deleted["deleted"], true);

    let directory: Value = TestClient::post("http://server/api/v1/directory/search-realms")
        .json(&serde_json::json!({"query": "Workflow Space"}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(directory["results"].as_array().unwrap().is_empty());

    let index: Value = TestClient::post("http://server/api/v1/index/query")
        .json(&serde_json::json!({"realm_ids": [space_id]}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(index["results"].as_array().unwrap().is_empty());

    let sync = account_subscribe_frame(state.clone(), None, "catchup=true").await;
    assert!(!sync["realms"].as_object().unwrap().contains_key(&space_id));

    let audit_events: Value = TestClient::get("http://server/api/v1/audit/events?limit=20")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(!audit_events["events"].as_array().unwrap().is_empty());
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
    for expected in ["account.register", "auth.dev_login", "auth.logout"] {
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
    assert_eq!(not_found["error"]["code"], "unrecognized_endpoint");

    let method_not_allowed: Value = TestClient::post("http://server/api/v1/server/describe")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(method_not_allowed["ok"], false);
    assert_eq!(method_not_allowed["error"]["code"], "method_not_allowed");
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
    assert_eq!(body["error"]["code"], "unauthenticated");
    assert_eq!(
        body["error"]["message"],
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
    let sync_describe: Value = TestClient::get("http://server/api/v1/account/describe")
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

    let invalid_profile = TestClient::post("http://server/api/v1/account/subscribe?catchup=true")
        .json(&serde_json::json!({"profile": "invalid"}))
        .send(&app())
        .await;
    assert_eq!(invalid_profile.status_code.unwrap().as_u16(), 405);

    let sync = account_subscribe_frame(
        AppState::new(test_config(), Db { pool: None }),
        None,
        "catchup=true",
    )
    .await;
    assert!(
        sync["realms"]
            .as_object()
            .unwrap()
            .contains_key("cx:realm:0196419b-0000-7000-8000-000000000000")
    );

    let directory: Value = TestClient::post("http://server/api/v1/directory/search-realms")
        .json(&serde_json::json!({"query": "demo", "limit": 10}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(directory["results"].as_array().unwrap().len(), 1);

    let index: Value = TestClient::post("http://server/api/v1/index/query")
        .json(&serde_json::json!({"realm_ids": ["cx:realm:0196419b-0000-7000-8000-000000000000"]}))
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

    let users: Value = TestClient::post("http://server/api/v1/directory/search-users")
        .json(&serde_json::json!({"query": "alice"}))
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
    assert_eq!(handle["handle_claim"]["schema"], "cx.schema.handle_claim.v1");
    assert_eq!(handle["handle_claim"]["handle_uri"], "contrix://soland.local/users/alice");
    assert_eq!(
        handle["handle_claim"]["member_delivery_binding"]["recipient_service_did"],
        "did:web:soland.local"
    );
    assert_eq!(handle["handle_claim"]["proofs"][0]["kind"], "detached_jws");
    assert!(
        handle["handle_claim"]["proofs"][0]["payload_digest"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("sha256:"))
    );

    let invalid = TestClient::post("http://server/api/v1/directory/search-users")
        .json(&serde_json::json!({"limit": 0}))
        .send(&app())
        .await;
    assert_eq!(invalid.status_code.unwrap().as_u16(), 400);
}

#[tokio::test]
async fn directory_demo_projection_rejects_outside_development_mode() {
    let mut config = test_config();
    config.development_mode = false;
    config.seed_demo_data = true;
    let service = app_from_state(AppState::new(config, Db { pool: None }));

    let cases = [
        (
            "search-organizations",
            serde_json::json!({"query": "contrix", "limit": 10}),
        ),
        (
            "resolve-organization",
            serde_json::json!({"organization_id": "cx:org:demo"}),
        ),
        ("search-actors", serde_json::json!({"query": "alice"})),
        ("search-users", serde_json::json!({"query": "alice"})),
        ("resolve-handle", serde_json::json!({"handle": "alice"})),
        (
            "private-contact-discovery",
            serde_json::json!({"contacts": [{"handle": "@alice"}]}),
        ),
    ];

    for (path, body) in cases {
        let response = TestClient::post(format!("http://server/api/v1/directory/{path}"))
            .json(&body)
            .send(&service)
            .await;
        assert_eq!(
            response.status_code.unwrap(),
            StatusCode::NOT_FOUND,
            "{path} must not expose demo directory data outside development mode"
        );
    }
}

// `standard_entity_types_and_reverse_domain_custom_types_work` and
// `view_endpoints_project_common_presentation_shapes` were deleted in
// round 6: the `entity` / `view` abstraction they exercised never landed in
// `contrix-spec/v1`. Typed objects in the protocol are `cx:flow:` / `cx:space:`
// / `cx:morph:` / `cx:relation:` / `cx:view:`, each with its own dedicated
// event kind; presentation concerns belong on `cx.view.*` events going
// through the reducer, not on a free-form `/api/v1/entities` /
// `/api/v1/views` scaffold.

#[tokio::test]
async fn index_product_endpoints_return_demo_projection_shapes() {
    // `/api/v1/index/object` is the polymorphic typed-id describe (renamed
    // from `/index/entity` in round 6); it returns `{object: {object_id,
    // kind, schema}}` for any spec-registered `cx:<kind>:` prefix.
    let object: Value = TestClient::get(
        "http://server/api/v1/index/object?object_id=cx:space:0196419b-0000-7000-8000-000000000000",
    )
    .send(&app())
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(object["object"]["kind"], "space");

    let thread: Value = TestClient::get("http://server/api/v1/index/thread?thread_id=cx:flow:demo")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(thread["thread"]["thread_id"], "cx:flow:demo");
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
        .json(&serde_json::json!({"query": "demo", "object_kinds": ["space"], "limit": 5}))
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

    let resolved: Value = TestClient::post("http://server/api/v1/directory/resolve-realm")
        .json(&serde_json::json!({"realm_id": DEMO_REALM_ID}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resolved["space_preview"]["realm_id"], DEMO_REALM_ID);

    let backfill: Value = TestClient::get(
        "http://server/api/v1/events?realms=cx:realm:0196419b-0000-7000-8000-000000000000",
    )
    .send(&app())
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(backfill["limited"], false);

    let authz: Value = TestClient::post("http://server/api/v1/authz/check")
        .json(&serde_json::json!({
            "actor": "did:web:alice.example",
            "action": "realm.read",
            "resource": {"kind": "realm", "realm_id": DEMO_REALM_ID}
        }))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(authz["allowed"], true);
    assert_eq!(authz["decision_trace"]["actor"], "did:web:alice.example");
    assert_eq!(authz["decision_trace"]["action"], "realm.read");
    assert_eq!(authz["decision_trace"]["realm_id"], DEMO_REALM_ID);
    assert!(authz["decision_trace"]["matched_grants"].is_array());
    assert_eq!(authz["decision_trace"]["cache"]["mode"], "in_memory");

    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let ice: Value = TestClient::post("http://server/contrix/v1/ice-config")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "call_id": "cx:call:01964137-0000-7000-8000-000000000001",
            "actor_id": "did:web:alice.example",
            "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001"
        }))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(ice["actor_id"], "did:web:alice.example");
    assert!(ice["ice_servers"].is_array());
    assert!(ice["signature"].is_object());
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
        device["actor"] == "did:web:alice.example"
            && device["device_id"] == "cx:device:01904100-0000-7000-8000-a11ce0000001"
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
        .json(&serde_json::json!({"device_id": "cx:device:01904100-0000-7000-8000-9b04e0000007"}))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthenticated.status_code, Some(StatusCode::UNAUTHORIZED));

    let challenge: Value = TestClient::post("http://server/api/v1/devices/pairing-challenge")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({"device_id": "cx:device:01904100-0000-7000-8000-9b04e0000007"}))
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
    assert_eq!(
        challenge["device_id"],
        "cx:device:01904100-0000-7000-8000-9b04e0000007"
    );
    assert_eq!(
        challenge["production_gap"],
        "device_pairing_proof_verification"
    );

    let authorized: Value = TestClient::post("http://server/api/v1/devices/authorize-pairing")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "challenge_id": challenge["challenge_id"],
            "device_id": "cx:device:01904100-0000-7000-8000-9b04e0000007",
            "display_name": "Paired Phone",
            "proof": {"alg": "dev-none"}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(authorized["status"], "authorized");
    assert_eq!(
        authorized["device"]["device_id"],
        "cx:device:01904100-0000-7000-8000-9b04e0000007"
    );
    assert_eq!(
        authorized["authorization_event"]["event_kind"],
        "cx.device.pairing.authorized"
    );
    assert_eq!(
        authorized["production_gap"],
        "authorization_event_not_yet_in_operation_stream"
    );
    let devices: Value = TestClient::get("http://server/api/v1/devices")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(devices["actor"], "did:web:alice.example");
    assert_eq!(
        devices["current_device_id"],
        "cx:device:01904100-0000-7000-8000-a11ce0000001"
    );
    assert!(devices["devices"].as_array().unwrap().iter().any(|device| {
        device["device_id"] == "cx:device:01904100-0000-7000-8000-9b04e0000007"
            && device["verification_state"] == "verified"
            && device["is_current_session_device"] == false
    }));
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
                    && event["target"]["target_device_id"]
                        == "cx:device:01904100-0000-7000-8000-9b04e0000007"
            })
    );
}

#[tokio::test]
async fn webrtc_signaling_contracts_work() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let unauthenticated = TestClient::post("http://server/api/v1/webrtc/sessions")
        .json(&serde_json::json!({
            "space_id": DEMO_REALM_ID
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthenticated.status_code, Some(StatusCode::UNAUTHORIZED));

    let session: Value = TestClient::post("http://server/api/v1/webrtc/sessions")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "space_id": DEMO_REALM_ID,
            "participants": ["did:web:alice.example"],
            "ttl_ms": 60000
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let session_id = session["session_id"].as_str().unwrap().to_owned();
    assert!(session_id.starts_with("cx:call:"));
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
        RealmId::new("cx:realm:01904100-0000-7000-8000-20d6cfd24be6").unwrap(),
        kinds::CX_MESSAGE_CREATE,
        serde_json::json!({
            "event_id": "cx:event:01904100-0000-7000-8000-19d11d370b0e",
            "sender": "did:web:remote.example",
            "thread_id": "cx:flow:federation",
            "body": "from federation"
        }),
    );

    let first: Value = TestClient::post("http://server/api/v1/federation/push-operations")
        .json(&serde_json::json!({
            "origin": "did:web:remote.example",
            "destination": "did:web:soland.local",
            "space_id": "cx:realm:01904100-0000-7000-8000-20d6cfd24be6",
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
        "http://server/api/v1/federation/pull-operations?space_id=cx:realm:01904100-0000-7000-8000-20d6cfd24be6",
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
        "http://server/api/v1/federation/pull-operations?space_id=cx:realm:01904100-0000-7000-8000-20d6cfd24be6&snapshot_bootstrap=true",
    )
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        bootstrap["snapshot_bootstrap"]["manifest"]["space_id"],
        "cx:realm:01904100-0000-7000-8000-20d6cfd24be6"
    );
    assert!(
        bootstrap["snapshot_bootstrap"]["state_digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );

    let replay: Value = TestClient::post("http://server/api/v1/federation/push-operations")
        .json(&serde_json::json!({
            "origin": "did:web:remote.example",
            "destination": "did:web:soland.local",
            "space_id": "cx:realm:01904100-0000-7000-8000-20d6cfd24be6",
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
        RealmId::new("cx:realm:01904100-0000-7000-8000-20d6cfd24be6").unwrap(),
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
            "space_id": "cx:realm:01904100-0000-7000-8000-20d6cfd24be6",
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

    let redaction = Operation::create(
        OperationId::new("cx:operation:01904100-0000-7000-8000-fd0b34f35181").unwrap(),
        RealmId::new("cx:realm:01904100-0000-7000-8000-20d6cfd24be6").unwrap(),
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
            "space_id": "cx:realm:01904100-0000-7000-8000-20d6cfd24be6",
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
        "http://server/api/v1/federation/pull-operations?space_id=cx:realm:01904100-0000-7000-8000-20d6cfd24be6",
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
        RealmId::new("cx:realm:01904100-0000-7000-8000-788d17d38a52").unwrap(),
        kinds::CX_MESSAGE_CREATE,
        serde_json::json!({
            "event_id": "cx:event:01904100-0000-7000-8000-f10d061a12a7",
            "sender": "did:web:remote.example",
            "thread_id": "cx:flow:federation-txn",
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
}

#[tokio::test]
async fn push_profile_and_moderation_contracts_work() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let sent_at = chrono::Utc::now();
    let expires_at = sent_at + chrono::Duration::seconds(30);
    let unauth_presence = TestClient::post("http://server/api/v1/ephemeral")
        .json(&serde_json::json!({
            "kind": "cx.presence",
            "realm_id": DEMO_REALM_ID,
            "actor_id": "did:web:alice.example",
            "sent_at": sent_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "expires_at": expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "payload": {
                "status": "online"
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauth_presence.status_code, Some(StatusCode::UNAUTHORIZED));

    let presence: Value = TestClient::post("http://server/api/v1/ephemeral")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "kind": "cx.presence",
            "realm_id": DEMO_REALM_ID,
            "actor_id": "did:web:alice.example",
            "sent_at": sent_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "expires_at": expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "payload": {
                "status": "unavailable"
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(presence["accepted"], true);
    assert_eq!(presence["kind"], "cx.presence");

    let profile: Value =
        TestClient::get("http://server/api/v1/profile/presence?did=did:web:alice.example")
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(profile["actor"], "did:web:alice.example");
    assert_eq!(profile["presence"]["status"], "unavailable");

    let unauth_typing = TestClient::post("http://server/api/v1/ephemeral")
        .json(&serde_json::json!({
            "kind": "cx.typing",
            "realm_id": DEMO_REALM_ID,
            "actor_id": "did:web:alice.example",
            "sent_at": sent_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "expires_at": expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "payload": {
                "typing": true
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauth_typing.status_code, Some(StatusCode::UNAUTHORIZED));

    let typing: Value = TestClient::post("http://server/api/v1/ephemeral")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "kind": "cx.typing",
            "realm_id": DEMO_REALM_ID,
            "actor_id": "did:web:alice.example",
            "sent_at": sent_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "expires_at": expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "payload": {
                "scope_id": "cx:flow:demo",
                "typing": true
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(typing["accepted"], true);
    assert_eq!(typing["kind"], "cx.typing");

    let active_typing = state
        .persistence
        .typing()
        .list_for_space(DEMO_REALM_ID)
        .unwrap();
    assert_eq!(active_typing.len(), 1);
    assert_eq!(active_typing[0].actor, "did:web:alice.example");
    assert_eq!(active_typing[0].scope_id.as_deref(), Some("cx:flow:demo"));

    let stop_sent_at = chrono::Utc::now();
    let stop_expires_at = stop_sent_at + chrono::Duration::seconds(30);
    let typing_stopped: Value = TestClient::post("http://server/api/v1/ephemeral")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "kind": "cx.typing",
            "realm_id": DEMO_REALM_ID,
            "actor_id": "did:web:alice.example",
            "sent_at": stop_sent_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "expires_at": stop_expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "payload": {
                "typing": false
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(typing_stopped["accepted"], true);

    let cleared_typing = state
        .persistence
        .typing()
        .list_for_space(DEMO_REALM_ID)
        .unwrap();
    assert!(cleared_typing.is_empty());

    let push: Value = TestClient::post("http://server/api/v1/push/register-device")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
            "push_gateway": "https://push.example",
            "push_key": "opaque",
            "platform": "desktop",
            "app_id": "yougen"
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
                "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
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
                "devices": [{"device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001"}, {"device_id": "cx:device:01904100-0000-7000-8000-71551c000004"}]
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
        device["device_id"] == "cx:device:01904100-0000-7000-8000-a11ce0000001"
            && device["reason"] == "push_rule"
            && device["rule_id"] == "mute-device"
    }));
    assert!(rejected.iter().any(|device| {
        device["device_id"] == "cx:device:01904100-0000-7000-8000-71551c000004"
            && device["reason"] == "unknown_device"
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
                "devices": [{"device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001"}]
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
            "realm_id": DEMO_REALM_ID,
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
            "realm_id": DEMO_REALM_ID,
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
            "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
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
            "device_keys": {"did:web:alice.example": ["cx:device:01904100-0000-7000-8000-a11ce0000001"]}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(query["device_keys"].is_object());
    assert_eq!(
        query["device_keys"]["did:web:alice.example"]["cx:device:01904100-0000-7000-8000-a11ce0000001"]
            ["device_keys"]["key"],
        "alice-device-key"
    );
    assert_eq!(
        query["device_keys"]["did:web:alice.example"]["cx:device:01904100-0000-7000-8000-a11ce0000001"]
            ["device_signature"]["alg"],
        "none"
    );
    assert_eq!(
        query["device_keys"]["did:web:alice.example"]["cx:device:01904100-0000-7000-8000-a11ce0000001"]
            ["fallback_keys"]["signed_curve25519:fallback"]["key"],
        "fallback-key"
    );
    assert_eq!(
        query["device_keys"]["did:web:alice.example"]["cx:device:01904100-0000-7000-8000-a11ce0000001"]
            ["mls_key_packages"][0]["package_id"],
        "mls-package-1"
    );
    assert_eq!(
        query["device_keys"]["did:web:alice.example"]["cx:device:01904100-0000-7000-8000-a11ce0000001"]
            ["principal_signing_keys"][0]["key"],
        "principal-key"
    );
    assert_eq!(
        query["device_keys"]["did:web:alice.example"]["cx:device:01904100-0000-7000-8000-a11ce0000001"]
            ["recovery_keys"][0]["key"],
        "recovery-key"
    );
    assert_eq!(
        query["device_keys"]["did:web:alice.example"]["cx:device:01904100-0000-7000-8000-a11ce0000001"]
            ["session_keys"][0]["key"],
        "session-key"
    );
    assert_eq!(
        query["device_keys"]["did:web:alice.example"]["cx:device:01904100-0000-7000-8000-a11ce0000001"]
            ["agent_keys"][0]["key"],
        "agent-key"
    );
    assert_eq!(
        query["device_keys"]["did:web:alice.example"]["cx:device:01904100-0000-7000-8000-a11ce0000001"]
            ["backup_restore_keys"][0]["key"],
        "backup-key"
    );

    let claimed_once: Value = TestClient::post("http://server/api/v1/keys/claim")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "one_time_keys": {
                "did:web:alice.example": {
                    "cx:device:01904100-0000-7000-8000-a11ce0000001": "signed_curve25519"
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        claimed_once["one_time_keys"]["did:web:alice.example"]["cx:device:01904100-0000-7000-8000-a11ce0000001"]
            ["key_id"],
        "otk1"
    );
    let claimed_replay: Value = TestClient::post("http://server/api/v1/keys/claim")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "one_time_keys": {
                "did:web:alice.example": {
                    "cx:device:01904100-0000-7000-8000-a11ce0000001": "signed_curve25519"
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        claimed_replay["one_time_keys"]["did:web:alice.example"]["cx:device:01904100-0000-7000-8000-a11ce0000001"].is_null(),
        "one-time key claim must be single-use"
    );

    let invalid_device_message = TestClient::post("http://server/api/v1/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "bad-txn", true)
        .json(&serde_json::json!({
            "messages": {
                "did:web:alice.example": {
                    "cx:device:01904100-0000-7000-8000-a11ce0000001": {
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
                    "cx:device:01904100-0000-7000-8000-a11ce0000001": {
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
                    "cx:device:01904100-0000-7000-8000-a11ce0000001": {
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

    let large_plaintext = "a".repeat(96 * 1024);
    let large_blob: Value = TestClient::post("http://server/api/v1/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "image/jpeg", true)
        .body(large_plaintext.clone())
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(large_blob["size"], large_plaintext.len());
    assert_eq!(large_blob["media_type"], "image/jpeg");

    let locked_space = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Blob Policy Space",
        None,
        "invite_only",
        &[],
        &[],
    );
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

    let mut blocked_blob = TestClient::get(format!(
        "http://server/api/v1/blob/get?blob_ref={}&purpose=message_attachment",
        blob["blob_ref"].as_str().unwrap()
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(blocked_blob.status_code.unwrap().as_u16(), 403);
    let body: Value = blocked_blob.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "capability_denied");

    let mut range = TestClient::get(format!(
        "http://server/api/v1/blob/get?blob_ref={}&purpose=message_attachment",
        blob["blob_ref"].as_str().unwrap()
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .add_header("range", "bytes=0-8", true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(range.status_code.unwrap().as_u16(), 403);
    let body: Value = range.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "capability_denied");

    let bob = register_account(
        state.clone(),
        "did:web:blob-bob.example",
        "@blob-bob",
        "cx:device:01904100-0000-7000-8000-b10bb0000003",
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
            "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
            "push_gateway": "https://push.example",
            "push_key": "opaque",
            "platform": "desktop",
            "app_id": "yougen"
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
                "devices": [{"device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001"}],
                "preview": "plaintext should not be sent to push gateway"
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(plaintext_push.status_code.unwrap().as_u16(), 400);

    let notify: Value = TestClient::post("http://server/api/v1/push/notify")
        .json(&serde_json::json!({
            "notification": {
                "type": "blind_wakeup",
                "devices": [{"device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001"}, {"device_id": "cx:device:01904100-0000-7000-8000-71551c000004"}]
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
async fn push_unregister_mutates_registration_and_gateway_snapshot_gates_notify() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let service = app_from_state(state.clone());
    let device_id = "cx:device:01904100-0000-7000-8000-a11ce0000001";
    let push_gateway = "https://push.example/api/v1/push/notify";
    let bridge_describe = "https://push.example/api/v1/push/bridge/describe";
    let stale_at = chrono::Utc::now() - chrono::Duration::hours(25);

    let stale_import: Value = TestClient::post(
        "http://server/api/v1/push/outbound/bridge/cache/import",
    )
    .json(&serde_json::json!({
        "replace_existing": true,
        "entries": [{
            "push_gateway_url": push_gateway,
            "service_base_url": "https://push.example",
            "bridge_describe_url": bridge_describe,
            "fetch_state": "cotest_seed",
            "cache_state": "imported_replace_existing",
            "contract_digest": "sha256:stale",
            "fetched_at": stale_at,
            "remote_contract": {
                "contract": "cx.push.bridge.describe",
                "service_did": "did:web:push.example",
                "delivery": {"notify_path": "/api/v1/push/notify", "operation_id": "cx.push.notify"}
            },
            "trust_level": "trusted",
            "freshness_at": stale_at,
            "etag": "stale"
        }]
    }))
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(stale_import["imported_count"], 1);

    let registered: Value = TestClient::post("http://server/api/v1/push/register-device")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "device_id": device_id,
            "push_gateway": push_gateway,
            "push_key": "opaque-token",
            "platform": "desktop",
            "app_id": "yougen"
        }))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(registered["ok"], true);

    let stale_notify: Value = TestClient::post("http://server/api/v1/push/notify")
        .json(&serde_json::json!({
            "notification": {
                "type": "blind_wakeup",
                "devices": [{"device_id": device_id}]
            }
        }))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(stale_notify["rejected"][0]["reason"], "contract_drift");
    assert_eq!(stale_notify["rejected"][0]["drift_result"], "stale");

    let now = chrono::Utc::now();
    let fresh_import: Value = TestClient::post(
        "http://server/api/v1/push/outbound/bridge/cache/import",
    )
    .json(&serde_json::json!({
        "replace_existing": true,
        "entries": [{
            "push_gateway_url": push_gateway,
            "service_base_url": "https://push.example",
            "bridge_describe_url": bridge_describe,
            "fetch_state": "cotest_seed",
            "cache_state": "imported_replace_existing",
            "contract_digest": "sha256:fresh",
            "fetched_at": now,
            "remote_contract": {
                "contract": "cx.push.bridge.describe",
                "service_did": "did:web:push.example",
                "delivery": {"notify_path": "/api/v1/push/notify", "operation_id": "cx.push.notify"}
            },
            "trust_level": "trusted",
            "freshness_at": now,
            "etag": "fresh"
        }]
    }))
    .send(&service)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(fresh_import["total_entries"], 1);

    let fresh_notify: Value = TestClient::post("http://server/api/v1/push/notify")
        .json(&serde_json::json!({
            "notification": {
                "type": "blind_wakeup",
                "devices": [{"device_id": device_id}]
            }
        }))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert!(fresh_notify["rejected"].as_array().unwrap().is_empty());

    let unregistered: Value = TestClient::post("http://server/api/v1/push/unregister-device")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "device_id": device_id,
            "push_key": "opaque-token",
            "app_id": "yougen"
        }))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(unregistered["ok"], true);

    let after_unregister: Value = TestClient::post("http://server/api/v1/push/notify")
        .json(&serde_json::json!({
            "notification": {
                "type": "blind_wakeup",
                "devices": [{"device_id": device_id}]
            }
        }))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(after_unregister["rejected"][0]["reason"], "unknown_device");
}

#[tokio::test]
async fn keys_query_hides_revoked_device() {
    let state = AppState::new(test_config(), Db { pool: None });
    let desktop = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        "cx:device:01904100-0000-7000-8000-a11ce0000001",
        "Alice Desktop",
    )
    .await;
    let mobile = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        "cx:device:01904100-0000-7000-8000-9b04e0000007",
        "Alice Phone",
    )
    .await;

    let _desktop_keys: Value = TestClient::post("http://server/api/v1/keys/upload")
        .add_header("authorization", format!("Bearer {desktop}"), true)
        .json(&serde_json::json!({
            "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
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
            "device_id": "cx:device:01904100-0000-7000-8000-9b04e0000007",
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
            "device_keys": {"did:web:alice.example": ["cx:device:01904100-0000-7000-8000-a11ce0000001", "cx:device:01904100-0000-7000-8000-9b04e0000007"]}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        pre_revoke_query["device_keys"]["did:web:alice.example"]["cx:device:01904100-0000-7000-8000-a11ce0000001"]
            ["device_keys"]["key"],
        "desktop-device-key"
    );
    assert_eq!(
        pre_revoke_query["device_keys"]["did:web:alice.example"]["cx:device:01904100-0000-7000-8000-9b04e0000007"]
            ["device_keys"]["key"],
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
            "device_keys": {"did:web:alice.example": ["cx:device:01904100-0000-7000-8000-a11ce0000001", "cx:device:01904100-0000-7000-8000-9b04e0000007"]}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(post_revoke_query["device_keys"]["did:web:alice.example"]["cx:device:01904100-0000-7000-8000-9b04e0000007"].is_null());
    assert_eq!(
        post_revoke_query["device_keys"]["did:web:alice.example"]["cx:device:01904100-0000-7000-8000-a11ce0000001"]
            ["device_keys"]["key"],
        "desktop-device-key"
    );
}

#[tokio::test]
async fn revoked_device_blocks_encrypted_writes() {
    let state = AppState::new(test_config(), Db { pool: None });
    let device_token = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        "cx:device:01904100-0000-7000-8000-30b11e000005",
        "Alice Mobile",
    )
    .await;
    let stale_session = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        "cx:device:01904100-0000-7000-8000-30b11e000005",
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

    let blocked_send = post_message_event(
        state.clone(),
        &stale_session,
        "did:web:alice.example",
        DEMO_REALM_ID,
        DEMO_REALM_ID,
        encrypted_envelope("cx.message.v1", "blocked-ciphertext"),
        true,
    )
    .await;
    assert_eq!(blocked_send.as_u16(), 401);

    let blocked_upload = TestClient::post("http://server/api/v1/keys/upload")
        .add_header("authorization", format!("Bearer {stale_session}"), true)
        .json(&serde_json::json!({
            "device_id": "cx:device:01904100-0000-7000-8000-30b11e000005",
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
                    "cx:device:01904100-0000-7000-8000-a11ce0000001": {
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
                    "cx:device:01904100-0000-7000-8000-a11ce0000001": {
                        "type": "cx.mls.application",
                        "content": encrypted_envelope("cx.mls.application", "ack-ciphertext")
                    }
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;

    let first = account_subscribe_frame(state.clone(), Some(&token), "catchup=true").await;
    assert_eq!(first["to_device"]["messages"].as_array().unwrap().len(), 1);
    let first_cursor = decode_cursor(first["cursor"].as_str().unwrap());
    assert!(first_cursor["h"].as_str().is_some_and(|h| h.len() >= 22));
    assert!(first_cursor.get("_positions").is_none());

    let duplicate = account_subscribe_frame(state.clone(), Some(&token), "catchup=true").await;
    assert_eq!(
        duplicate["to_device"]["messages"].as_array().unwrap().len(),
        1
    );

    let acked = account_subscribe_frame(
        state,
        Some(&token),
        &format!("catchup=true&after={}", first["cursor"].as_str().unwrap()),
    )
    .await;
    assert!(
        acked["to_device"]["messages"].is_array(),
        "acked sync response must be a sync body: {acked}"
    );
    assert!(acked["to_device"]["messages"].as_array().unwrap().is_empty());
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
                    "cx:device:01904100-0000-7000-8000-a11ce0000001": {
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

    let policy: Value = TestClient::post("http://server/api/v1/policy/check")
        .json(&serde_json::json!({
            "request_id": "req1",
            "realm_id": "cx:realm:0196419b-0000-7000-8000-000000000000",
            "request_canonical_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
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
    assert_eq!(policy["decision_trace"]["request_id"], "req1");
    assert_eq!(policy["decision_trace"]["actor"], "did:web:alice.example");
    assert_eq!(policy["decision_trace"]["action"], "message.send");
    assert_eq!(policy["decision_trace"]["cache"]["mode"], "in_memory");

    let unauthenticated_policy = TestClient::post("http://server/api/v1/policies")
        .json(&serde_json::json!({
            "scope": "cx:realm:0196419b-0000-7000-8000-000000000000",
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
            "scope": "cx:realm:0196419b-0000-7000-8000-000000000000",
            "subject_ref": "did:web:alice.example",
            "policy_type": "message.send",
            "effect": "deny",
            "actions": ["message.send"],
            "resource": {"kind": "realm", "realm_id": "cx:realm:0196419b-0000-7000-8000-000000000000"},
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

    let denied: Value = TestClient::post("http://server/api/v1/policy/check")
        .json(&serde_json::json!({
            "request_id": "req2",
            "realm_id": "cx:realm:0196419b-0000-7000-8000-000000000000",
            "request_canonical_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "action": "message.send",
            "actor": "did:web:alice.example",
            "source": {"service": "soland", "kind": "realm"}
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
    assert_eq!(denied["decision_trace"]["request_id"], "req2");
    assert_eq!(denied["decision_trace"]["matched_policy"], policy_id);
    assert_eq!(denied["decision_trace"]["obligations"][0]["level"], "high");
    assert!(denied["decision_trace"]["missing_proofs"].is_array());

    let deleted: Value = TestClient::delete(format!("http://server/api/v1/policies/{policy_id}"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(deleted["ok"], true);

    let allowed_again: Value = TestClient::post("http://server/api/v1/policy/check")
        .json(&serde_json::json!({
            "request_id": "req3",
            "realm_id": "cx:realm:0196419b-0000-7000-8000-000000000000",
            "request_canonical_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
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

#[tokio::test]
async fn snapshot_v2_audit_path_verifies_against_merkle_root() {
    // B4: end-to-end snapshot v2 wire shape check. The single-chunk
    // case is exercised inline in `account_contacts_and_space_lifecycle_workflow`
    // — this test focuses on the SDK round-trip: head publishes a
    // generator-proof + merkle_root; chunk returns a chunk-bytes +
    // audit_path; `SnapshotMerkleTree::verify(root, leaf, idx, path, n)`
    // accepts the result. For a single-chunk snapshot the audit path is
    // empty and the leaf digest IS the root, so verify reduces to
    // `leaf == root` — but the wire-shape contract is what matters here.
    let state = AppState::new(test_config(), Db { pool: None });
    let space = seed_test_realm(
        &state,
        "did:web:alice.example",
        "snapshot-v2-test",
        Some("B4 snapshot v2 wire-shape test"),
        "public",
        &[],
        &[],
    );
    let space_id = space["space_id"].as_str().unwrap().to_owned();

    let head: Value = TestClient::get(format!(
        "http://server/api/v1/snapshot/head?realm_id={space_id}"
    ))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();

    // Wire shape — v2 fields all present.
    assert!(head["merkle_root"].is_string());
    assert!(head["chunk_count"].is_number());
    assert!(head["chunk_bytes"].is_number());
    assert!(head["total_bytes"].is_number());
    let proof = &head["generator_proof"];
    assert_eq!(
        proof["realm_id"].as_str().unwrap(),
        space_id,
        "generator_proof binds the snapshot to its Realm"
    );
    assert_eq!(
        proof["merkle_root"].as_str().unwrap(),
        head["merkle_root"].as_str().unwrap()
    );
    assert!(
        !proof["signature"]["jws"].as_str().unwrap().is_empty(),
        "generator_proof.signature.jws is populated"
    );

    // Walk every chunk: pull the chunk, verify the audit path round-trips
    // through `SnapshotMerkleTree::verify`.
    let chunk_count = head["chunk_count"].as_u64().unwrap();
    let tree_size = chunk_count as usize;
    let snapshot_ref = head["snapshot_ref"].as_str().unwrap();
    let root = contrix_sdk::Hash::new(head["merkle_root"].as_str().unwrap().to_owned()).unwrap();
    for chunk_id in 0..chunk_count {
        let chunk: Value = TestClient::get(format!(
            "http://server/api/v1/sync/snapshot-chunk?snapshot_ref={snapshot_ref}&chunk_id={chunk_id}"
        ))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
        assert_eq!(chunk["chunk_id"], chunk_id);
        let leaf = contrix_sdk::Hash::new(chunk["digest"].as_str().unwrap().to_owned()).unwrap();
        let audit_path: Vec<contrix_sdk::Hash> = chunk["audit_path"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| contrix_sdk::Hash::new(h.as_str().unwrap().to_owned()).unwrap())
            .collect();
        assert!(
            contrix_sdk::SnapshotMerkleTree::verify(
                &root,
                &leaf,
                chunk_id as usize,
                &audit_path,
                tree_size,
            ),
            "audit_path for chunk {chunk_id} must reconstruct to merkle_root"
        );
    }

    // Out-of-range chunk_id returns 404, not a placeholder.
    let oob = TestClient::get(format!(
        "http://server/api/v1/sync/snapshot-chunk?snapshot_ref={snapshot_ref}&chunk_id={chunk_count}"
    ))
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(oob.status_code.unwrap().as_u16(), 404);
}

/// Build a signed container `cx.space.*` event envelope for the Space
/// (container) state-machine integration test. Post-R1.2 the container
/// namespace moved from `cx.place.*` to `cx.space.*`. Mirrors
/// [`signed_event_envelope`] but with a custom `kind` + `payload`
/// (container lifecycle events do not carry a message body).
fn signed_place_event(
    event_id: &str,
    actor_seq: u64,
    kind: &str,
    mut payload: Value,
    prev_refs: Vec<&str>,
) -> Value {
    normalize_space_container_payload(kind, &mut payload);
    let mut event = serde_json::json!({
        "event_id": event_id,
        "kind": kind,
        "schema_id": "cx.schema.space.v1",
        "actor_id": "did:web:alice.example",
        "actor_seq": actor_seq,
        "realm_id": "cx:realm:0196419b-0000-7000-8000-000000000000",
        "created_at": "2026-05-17T00:00:00Z",
        "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": prev_refs,
        "auth_refs": [],
        "payload": payload.clone(),
        "proofs": [{
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#01904100-0000-7000-8000-a11ce0000001",
            "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload)
        }]
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));
    event
}

fn normalize_space_container_payload(kind: &str, payload: &mut Value) {
    let Some(object) = payload.as_object_mut() else {
        return;
    };
    if kind == "cx.space.create" {
        if let Some(space) = object.get_mut("object").and_then(Value::as_object_mut) {
            space
                .entry("schema".to_owned())
                .or_insert_with(|| Value::String("cx.schema.space.v1".to_owned()));
            space.entry("realm_id".to_owned()).or_insert_with(|| {
                Value::String("cx:realm:0196419b-0000-7000-8000-000000000000".to_owned())
            });
            space
                .entry("created_at".to_owned())
                .or_insert_with(|| Value::String("2026-05-17T00:00:00Z".to_owned()));
        }
    }
}

/// End-to-end check that the server-side Space-container state-machine guard rejects
/// illegal lifecycle transitions with HTTP 412 + the spec-canonical
/// reason_code per `contrix-spec/v1/zh/models/common-fields.md §5.1`.
/// Reducer-level unit coverage lives in `src/reducer.rs::tests`; this test
/// verifies the wire mapping (`event_log::submit_event` →
/// `check_space_container_lifecycle_transition` → `StatusCode::PRECONDITION_FAILED`).
#[tokio::test]
async fn space_container_lifecycle_state_machine_returns_412_for_illegal_transitions() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let container_space_id = "cx:space:01904100-0000-7000-8000-c10dc0000001";

    // 1) cx.space.create — Active.
    let create_event = signed_place_event(
        "cx:event:01904100-0000-7000-8000-d10dc0000001",
        1,
        "cx.space.create",
        serde_json::json!({
            "object": {
                "id": container_space_id,
                "realm_id": "cx:realm:0196419b-0000-7000-8000-000000000000",
                "kind": "list",
                "title": "Roadmap",
                "created_by": "did:web:alice.example",
            }
        }),
        Vec::new(),
    );
    let create_response: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(create_response["status"], "accepted");

    // 2) cx.space.restore on Active → 412 place_not_archived.
    let bad_restore = signed_place_event(
        "cx:event:01904100-0000-7000-8000-d10dc0000002",
        2,
        "cx.space.restore",
        serde_json::json!({ "space_id": container_space_id }),
        vec!["cx:event:01904100-0000-7000-8000-d10dc0000001"],
    );
    let mut bad_restore_response = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&bad_restore)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        bad_restore_response.status_code.unwrap().as_u16(),
        412,
        "restore on Active must yield HTTP 412 failed_precondition"
    );
    let body: Value = bad_restore_response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "place_not_archived");

    // 3) cx.space.archive — legal (Active → Archived).
    let archive_event = signed_place_event(
        "cx:event:01904100-0000-7000-8000-d10dc0000003",
        3,
        "cx.space.archive",
        serde_json::json!({ "space_id": container_space_id }),
        vec!["cx:event:01904100-0000-7000-8000-d10dc0000001"],
    );
    let archive_response: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&archive_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(archive_response["status"], "accepted");

    // 4) cx.space.restore — legal now (Archived → Active).
    let good_restore = signed_place_event(
        "cx:event:01904100-0000-7000-8000-d10dc0000004",
        4,
        "cx.space.restore",
        serde_json::json!({ "space_id": container_space_id }),
        vec!["cx:event:01904100-0000-7000-8000-d10dc0000003"],
    );
    let restore_response: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&good_restore)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(restore_response["status"], "accepted");

    // 5) cx.space.tombstone — legal (Active → Tombstoned).
    let tombstone_event = signed_place_event(
        "cx:event:01904100-0000-7000-8000-d10dc0000005",
        5,
        "cx.space.tombstone",
        serde_json::json!({ "space_id": container_space_id }),
        vec!["cx:event:01904100-0000-7000-8000-d10dc0000004"],
    );
    let tombstone_response: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&tombstone_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(tombstone_response["status"], "accepted");

    // 6) cx.space.tombstone again on Tombstoned → 412 place_already_terminal.
    let bad_tombstone = signed_place_event(
        "cx:event:01904100-0000-7000-8000-d10dc0000006",
        6,
        "cx.space.tombstone",
        serde_json::json!({ "space_id": container_space_id }),
        vec!["cx:event:01904100-0000-7000-8000-d10dc0000005"],
    );
    let mut bad_tombstone_response = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&bad_tombstone)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        bad_tombstone_response.status_code.unwrap().as_u16(),
        412,
        "tombstone-again on Tombstoned must yield HTTP 412 failed_precondition"
    );
    let body: Value = bad_tombstone_response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "place_already_terminal");

    // 7) cx.space.restore on Tombstoned → 412 place_not_archived (terminal
    // state cannot be revived even though tombstone-vs-restore are different
    // transitions).
    let bad_restore_terminal = signed_place_event(
        "cx:event:01904100-0000-7000-8000-d10dc0000007",
        7,
        "cx.space.restore",
        serde_json::json!({ "space_id": container_space_id }),
        vec!["cx:event:01904100-0000-7000-8000-d10dc0000005"],
    );
    let mut bad_restore_terminal_response = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&bad_restore_terminal)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        bad_restore_terminal_response.status_code.unwrap().as_u16(),
        412
    );
    let body: Value = bad_restore_terminal_response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "place_not_archived");
}

/// Build a signed `cx.flow.*` event envelope for the Flow state-machine
/// integration test. Mirror of `signed_place_event` with a Flow-specific
/// schema_id.
fn signed_flow_event(
    event_id: &str,
    actor_seq: u64,
    kind: &str,
    mut payload: Value,
    prev_refs: Vec<&str>,
) -> Value {
    normalize_flow_payload(kind, &mut payload);
    let mut event = serde_json::json!({
        "event_id": event_id,
        "kind": kind,
        "schema_id": "cx.schema.flow.v1",
        "actor_id": "did:web:alice.example",
        "actor_seq": actor_seq,
        "realm_id": "cx:realm:0196419b-0000-7000-8000-000000000000",
        "created_at": "2026-05-17T00:00:00Z",
        "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": prev_refs,
        "auth_refs": [],
        "payload": payload.clone(),
        "proofs": [{
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#01904100-0000-7000-8000-a11ce0000001",
            "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload)
        }]
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));
    event
}

fn normalize_flow_payload(kind: &str, payload: &mut Value) {
    let Some(object) = payload.as_object_mut() else {
        return;
    };
    if kind == "cx.flow.create" {
        if let Some(flow) = object.get_mut("object").and_then(Value::as_object_mut) {
            flow.entry("schema".to_owned())
                .or_insert_with(|| Value::String("cx.schema.flow.v1".to_owned()));
            flow.entry("realm_id".to_owned()).or_insert_with(|| {
                Value::String("cx:realm:0196419b-0000-7000-8000-000000000000".to_owned())
            });
            flow.entry("created_at".to_owned())
                .or_insert_with(|| Value::String("2026-05-17T00:00:00Z".to_owned()));
            flow.entry("stage".to_owned())
                .or_insert_with(|| Value::String("draft".to_owned()));
            flow.entry("tracks".to_owned()).or_insert_with(|| {
                serde_json::json!({
                    "discussion": {
                        "is_primary": true,
                        "profile": "discussion"
                    }
                })
            });
        }
    }
    if matches!(
        kind,
        "cx.flow.archive" | "cx.flow.restore" | "cx.flow.tombstone"
    ) && !object.contains_key("target_ref")
        && !object.contains_key("object_ref")
        && let Some(flow_id) = object.get("flow_id").and_then(Value::as_str)
    {
        object.insert("target_ref".to_owned(), Value::String(flow_id.to_owned()));
    }
}

/// Build a signed `cx.morph.*` event envelope.
fn signed_morph_event(
    event_id: &str,
    actor_seq: u64,
    kind: &str,
    mut payload: Value,
    prev_refs: Vec<&str>,
) -> Value {
    normalize_morph_payload(kind, &mut payload);
    let mut event = serde_json::json!({
        "event_id": event_id,
        "kind": kind,
        "schema_id": "cx.schema.morph.v1",
        "actor_id": "did:web:alice.example",
        "actor_seq": actor_seq,
        "realm_id": "cx:realm:0196419b-0000-7000-8000-000000000000",
        "created_at": "2026-05-17T00:00:00Z",
        "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": prev_refs,
        "auth_refs": [],
        "payload": payload.clone(),
        "proofs": [{
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#01904100-0000-7000-8000-a11ce0000001",
            "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload)
        }]
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));
    event
}

fn normalize_morph_payload(kind: &str, payload: &mut Value) {
    let Some(object) = payload.as_object_mut() else {
        return;
    };
    if kind == "cx.morph.create" {
        if let Some(morph) = object.get_mut("object").and_then(Value::as_object_mut) {
            morph
                .entry("schema".to_owned())
                .or_insert_with(|| Value::String("cx.schema.morph.v1".to_owned()));
            morph.entry("realm_id".to_owned()).or_insert_with(|| {
                Value::String("cx:realm:0196419b-0000-7000-8000-000000000000".to_owned())
            });
            morph
                .entry("created_at".to_owned())
                .or_insert_with(|| Value::String("2026-05-17T00:00:00Z".to_owned()));
            morph
                .entry("stage".to_owned())
                .or_insert_with(|| Value::String("draft".to_owned()));
            morph
                .entry("schema_refs".to_owned())
                .or_insert_with(|| serde_json::json!(["cx.schema.morph.v1"]));
        }
    }
    if matches!(
        kind,
        "cx.morph.archive" | "cx.morph.restore" | "cx.morph.tombstone"
    ) && !object.contains_key("target_ref")
        && !object.contains_key("object_ref")
        && let Some(morph_id) = object.get("morph_id").and_then(Value::as_str)
    {
        object.insert("target_ref".to_owned(), Value::String(morph_id.to_owned()));
    }
}

/// Round 13 — end-to-end check that Flow / Morph lifecycle state-machine
/// guards map to HTTP 412 + canonical reason_code per spec §5.1. Mirrors
/// `space_container_lifecycle_state_machine_returns_412_for_illegal_transitions`
/// from round 11. Combined Flow+Morph in one test to keep the suite small.
#[tokio::test]
async fn flow_morph_lifecycle_state_machine_returns_412_for_illegal_transitions() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let flow_id = "cx:flow:01904100-0000-7000-8000-e10dc0000001";
    let morph_id = "cx:morph:01904100-0000-7000-8000-e20dc0000001";

    // ── Flow path ────────────────────────────────────────────────────

    // 1) flow create — Active.
    let create_flow = signed_flow_event(
        "cx:event:01904100-0000-7000-8000-e10ec0000001",
        1,
        "cx.flow.create",
        serde_json::json!({
            "object": {
                "id": flow_id,
                "space_id": DEMO_REALM_ID,
                "title": "Launch flow",
                "created_by": "did:web:alice.example",
            }
        }),
        Vec::new(),
    );
    let response: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_flow)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(response["status"], "accepted");

    // 2) flow restore on Active → 412 flow_not_archived.
    let bad_restore = signed_flow_event(
        "cx:event:01904100-0000-7000-8000-e10ec0000002",
        2,
        "cx.flow.restore",
        serde_json::json!({ "flow_id": flow_id }),
        vec!["cx:event:01904100-0000-7000-8000-e10ec0000001"],
    );
    let mut resp = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&bad_restore)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 412);
    let body: Value = resp.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "flow_not_archived");

    // 3) flow archive — legal.
    let archive = signed_flow_event(
        "cx:event:01904100-0000-7000-8000-e10ec0000003",
        3,
        "cx.flow.archive",
        serde_json::json!({ "flow_id": flow_id }),
        vec!["cx:event:01904100-0000-7000-8000-e10ec0000001"],
    );
    let resp: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&archive)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "redact flow response: {resp}");

    // 4) flow archive again on Archived → 412 flow_not_active.
    let bad_archive = signed_flow_event(
        "cx:event:01904100-0000-7000-8000-e10ec0000004",
        4,
        "cx.flow.archive",
        serde_json::json!({ "flow_id": flow_id }),
        vec!["cx:event:01904100-0000-7000-8000-e10ec0000003"],
    );
    let mut resp = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&bad_archive)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 412);
    let body: Value = resp.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "flow_not_active");

    // 5) flow update on Archived → 412 flow_not_active.
    let bad_update = signed_flow_event(
        "cx:event:01904100-0000-7000-8000-e10ec0000005",
        5,
        "cx.flow.update",
        serde_json::json!({ "flow_id": flow_id, "patch": { "title": "Edit while archived" } }),
        vec!["cx:event:01904100-0000-7000-8000-e10ec0000003"],
    );
    let mut resp = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&bad_update)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 412);
    let body: Value = resp.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "flow_not_active");

    // 6) flow restore — legal now.
    let good_restore = signed_flow_event(
        "cx:event:01904100-0000-7000-8000-e10ec0000006",
        6,
        "cx.flow.restore",
        serde_json::json!({ "flow_id": flow_id }),
        vec!["cx:event:01904100-0000-7000-8000-e10ec0000003"],
    );
    let resp: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&good_restore)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "redact flow response: {resp}");

    // ── Morph path ───────────────────────────────────────────────────

    let create_morph = signed_morph_event(
        "cx:event:01904100-0000-7000-8000-e20ec0000001",
        7,
        "cx.morph.create",
        serde_json::json!({
            "object": {
                "id": morph_id,
                "space_id": DEMO_REALM_ID,
                "morph_type": "task",
                "title": "Backfill",
                "created_by": "did:web:alice.example",
            }
        }),
        Vec::new(),
    );
    let resp: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_morph)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "create morph response: {resp}");

    // morph restore on Active → 412 morph_not_archived.
    let bad_morph_restore = signed_morph_event(
        "cx:event:01904100-0000-7000-8000-e20ec0000002",
        8,
        "cx.morph.restore",
        serde_json::json!({ "morph_id": morph_id }),
        vec!["cx:event:01904100-0000-7000-8000-e20ec0000001"],
    );
    let mut resp = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&bad_morph_restore)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 412);
    let body: Value = resp.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "morph_not_archived");

    // morph archive — legal.
    let morph_archive = signed_morph_event(
        "cx:event:01904100-0000-7000-8000-e20ec0000003",
        9,
        "cx.morph.archive",
        serde_json::json!({ "morph_id": morph_id }),
        vec!["cx:event:01904100-0000-7000-8000-e20ec0000001"],
    );
    let resp: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&morph_archive)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted");

    // morph update on Archived → 412 morph_not_active.
    let bad_morph_update = signed_morph_event(
        "cx:event:01904100-0000-7000-8000-e20ec0000004",
        10,
        "cx.morph.update",
        serde_json::json!({ "morph_id": morph_id, "patch": { "title": "Renamed" } }),
        vec!["cx:event:01904100-0000-7000-8000-e20ec0000003"],
    );
    let mut resp = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&bad_morph_update)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 412);
    let body: Value = resp.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "morph_not_active");
}

/// Build a signed `cx.redaction` event envelope, used by round 14b to
/// test object-level redaction (Flow / Morph). Mirror of
/// `signed_event_envelope` for the redaction kind. The spec schema
/// registry doesn't carry a dedicated `cx.schema.redaction.v1` —
/// `cx.redaction` is `category=message` per event-kind-registry, so
/// reuses `cx.schema.message.v1`.
fn signed_redaction_event(
    event_id: &str,
    actor_seq: u64,
    mut payload: Value,
    prev_refs: Vec<&str>,
) -> Value {
    if let Some(object) = payload.as_object_mut()
        && !object.contains_key("target_ref")
        && let Some(object_ref) = object.get("object_ref").cloned()
    {
        object.insert("target_ref".to_owned(), object_ref);
    }
    let mut event = serde_json::json!({
        "event_id": event_id,
        "kind": "cx.redaction",
        "schema_id": "cx.schema.message.v1",
        "actor_id": "did:web:alice.example",
        "actor_seq": actor_seq,
        "realm_id": DEMO_REALM_ID,
        "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": prev_refs,
        "auth_refs": [],
        "payload": payload.clone(),
        "proofs": [{
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#01904100-0000-7000-8000-a11ce0000001",
            "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload)
        }]
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));
    event
}

/// Round 14b — end-to-end check that `cx.redaction` events with an
/// `object_ref` pointing at a Flow / Morph successfully flip the
/// projection state to Redacted, and that a second redaction against
/// the same (now terminal) object is rejected with HTTP 412 +
/// `<kind>_already_terminal` per spec common-fields.md §5.1.
#[tokio::test]
async fn redaction_targeting_flow_morph_flips_to_redacted_and_rejects_terminal_repeat() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let flow_id = "cx:flow:01904100-0000-7000-8000-f10dc0000001";
    let morph_id = "cx:morph:01904100-0000-7000-8000-f20dc0000001";

    // ── Flow path ────────────────────────────────────────────────────

    let create_flow = signed_flow_event(
        "cx:event:01904100-0000-7000-8000-f10ec0000001",
        1,
        "cx.flow.create",
        serde_json::json!({
            "object": {
                "id": flow_id,
                "space_id": DEMO_REALM_ID,
                "title": "Sensitive flow",
                "created_by": "did:web:alice.example",
            }
        }),
        Vec::new(),
    );
    let resp: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_flow)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted");

    // First redaction — legal (Active source).
    let redact1 = signed_redaction_event(
        "cx:event:01904100-0000-7000-8000-f10ec0000002",
        2,
        serde_json::json!({
            "target_event_id": "cx:event:01904100-0000-7000-8000-f10ec0000001",
            "object_ref": flow_id,
            "by": "did:web:alice.example",
            "reason": "policy",
        }),
        vec!["cx:event:01904100-0000-7000-8000-f10ec0000001"],
    );
    let resp: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&redact1)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "redact flow response: {resp}");

    // Confirm projection flipped to Redacted.
    {
        let proj = state.projection.lock().unwrap();
        let flow = proj.flows.get(flow_id).expect("flow projection");
        assert_eq!(
            flow.state.as_str(),
            "redacted",
            "Flow MUST be in Redacted terminal state after cx.redaction with object_ref"
        );
    }

    // Second redaction against terminal Flow → 412 flow_already_terminal.
    let redact2 = signed_redaction_event(
        "cx:event:01904100-0000-7000-8000-f10ec0000003",
        3,
        serde_json::json!({
            "target_event_id": "cx:event:01904100-0000-7000-8000-f10ec0000001",
            "object_ref": flow_id,
        }),
        vec!["cx:event:01904100-0000-7000-8000-f10ec0000002"],
    );
    let mut resp = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&redact2)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 412);
    let body: Value = resp.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "flow_already_terminal");

    // ── Morph path ───────────────────────────────────────────────────

    let create_morph = signed_morph_event(
        "cx:event:01904100-0000-7000-8000-f20ec0000001",
        4,
        "cx.morph.create",
        serde_json::json!({
            "object": {
                "id": morph_id,
                "space_id": DEMO_REALM_ID,
                "morph_type": "task",
                "title": "Sensitive task",
                "created_by": "did:web:alice.example",
            }
        }),
        Vec::new(),
    );
    let resp: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_morph)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted");

    let morph_redact = signed_redaction_event(
        "cx:event:01904100-0000-7000-8000-f20ec0000002",
        5,
        serde_json::json!({
            "target_event_id": "cx:event:01904100-0000-7000-8000-f20ec0000001",
            "object_ref": morph_id,
        }),
        vec!["cx:event:01904100-0000-7000-8000-f20ec0000001"],
    );
    let resp: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&morph_redact)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted");
    {
        let proj = state.projection.lock().unwrap();
        let morph = proj.morphs.get(morph_id).expect("morph projection");
        assert_eq!(morph.state.as_str(), "redacted");
    }

    // Second morph redaction → 412 morph_already_terminal.
    let bad_morph_redact = signed_redaction_event(
        "cx:event:01904100-0000-7000-8000-f20ec0000003",
        6,
        serde_json::json!({
            "target_event_id": "cx:event:01904100-0000-7000-8000-f20ec0000001",
            "object_ref": morph_id,
        }),
        vec!["cx:event:01904100-0000-7000-8000-f20ec0000002"],
    );
    let mut resp = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&bad_morph_redact)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 412);
    let body: Value = resp.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "morph_already_terminal");
}

/// `cx.contacts.space.<space_id>` Space remarks: PUT → GET → /sync round-trip
/// proves the actor-private account_data plumbing works end-to-end. Mirrors
/// the spec at `discovery/client-preferences.md` §3.7 — server treats the
/// payload as opaque, scopes by authenticated actor, and rehydrates the
/// entry into the `/sync` response so other devices pick up the override.
#[tokio::test]
async fn account_data_space_remark_round_trip() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        "device-alice-1",
        "Alice",
    )
    .await;
    let bob =
        dev_token_for_device(state.clone(), "did:web:bob.example", "device-bob-1", "Bob").await;

    let space_id = "cx:space:0196419b-0000-7000-8000-000000000000";
    let key = format!("cx.contacts.space.{space_id}");
    let remark = serde_json::json!({
        "version": 1,
        "subject": {"kind": "space", "id": space_id},
        "local_name": "Acme 内部 · 工程",
        "note": "和外包侧 Engineering Space 同名",
        "tags": ["work"],
        "pinned": true,
        "verified_title_at_save": "Engineering",
        "saved_at": "2026-05-08T10:00:00Z"
    });

    // First PUT → 201 Created with the echoed entry.
    let mut put_resp = TestClient::put(format!("http://server/api/v1/account_data/{key}"))
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({"content": remark.clone()}))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(put_resp.status_code.unwrap().as_u16(), 201);
    let body: Value = put_resp.take_json().await.unwrap();
    assert_eq!(body["data_type"], key);
    assert_eq!(body["content"]["local_name"], "Acme 内部 · 工程");

    // GET round-trips the same payload.
    let fetched: Value = TestClient::get(format!("http://server/api/v1/account_data/{key}"))
        .add_header("authorization", format!("Bearer {alice}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(fetched["content"]["pinned"], true);
    assert_eq!(fetched["content"]["tags"][0], "work");

    // Second PUT (update) → 200 OK with the new payload.
    let updated_remark = serde_json::json!({
        "version": 1,
        "subject": {"kind": "space", "id": space_id},
        "local_name": "Acme · Eng (final)",
        "pinned": false,
        "saved_at": "2026-05-08T10:00:00Z",
        "updated_at": "2026-05-09T10:00:00Z"
    });
    let put_again = TestClient::put(format!("http://server/api/v1/account_data/{key}"))
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({"content": updated_remark.clone()}))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(put_again.status_code.unwrap().as_u16(), 200);

    // /sync hydrates the actor's account_data entries.
    let sync_resp_body =
        TestClient::get("http://server/api/v1/account/subscribe?catchup=true&set_presence=online")
            .add_header("authorization", format!("Bearer {alice}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_string()
            .await
            .unwrap();
    let sync_resp: Value = serde_json::from_str(sync_resp_body.lines().next().unwrap()).unwrap();
    let entries = sync_resp["account_data"]["events"].as_array().unwrap();
    let entry = entries
        .iter()
        .find(|e| e["data_type"] == key.as_str())
        .expect("account_data entry present in sync response");
    assert_eq!(entry["content"]["local_name"], "Acme · Eng (final)");
    assert_eq!(entry["content"]["pinned"], false);

    // Actor isolation: Bob's /sync does NOT see Alice's remark.
    let bob_sync_body =
        TestClient::get("http://server/api/v1/account/subscribe?catchup=true&set_presence=online")
            .add_header("authorization", format!("Bearer {bob}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_string()
            .await
            .unwrap();
    let bob_sync: Value = serde_json::from_str(bob_sync_body.lines().next().unwrap()).unwrap();
    let bob_entries = bob_sync["account_data"]["events"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        bob_entries.iter().all(|e| e["data_type"] != key.as_str()),
        "bob must not see alice's account_data"
    );

    // DELETE removes the entry; subsequent GET → 404.
    let del = TestClient::delete(format!("http://server/api/v1/account_data/{key}"))
        .add_header("authorization", format!("Bearer {alice}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(del.status_code.unwrap().as_u16(), 200);
    let not_found = TestClient::get(format!("http://server/api/v1/account_data/{key}"))
        .add_header("authorization", format!("Bearer {alice}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(not_found.status_code.unwrap().as_u16(), 404);
}

/// `PUT /api/v1/account_data/{type}` without auth → 401.
#[tokio::test]
async fn account_data_requires_auth() {
    let resp = TestClient::put("http://server/api/v1/account_data/cx.contacts.space.cx:space:0196419b-0000-7000-8000-000000000000")
        .json(&serde_json::json!({"content": {"local_name": "x"}}))
        .send(&app())
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 401);
}

/// `GET /api/v1/projection/spaces?realm_id=...` returns the
/// canonical `state` for every board/list Space container in a Realm so a client can
/// re-hydrate the archived-vs-active split after a refresh. After a
/// happy archive the projection MUST report `"archived"`; after
/// restore it MUST report
/// `"active"`. The endpoint MUST also fail closed without a session.
#[tokio::test]
async fn projection_space_containers_endpoint_reports_lifecycle_state() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let realm_id = "cx:realm:0196419b-0000-7000-8000-000000000000";
    let container_space_id = "cx:space:01904100-0000-7000-8000-f10dc0000001";

    // ── auth required ──────────────────────────────────────────────────
    let unauth = TestClient::get(format!(
        "http://server/api/v1/projection/spaces?realm_id={realm_id}"
    ))
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(unauth.status_code.unwrap().as_u16(), 401);

    // ── seed: create + archive a Space container ────────────────────────
    let create_event = signed_place_event(
        "cx:event:01904100-0000-7000-8000-f10ec0000001",
        1,
        "cx.space.create",
        serde_json::json!({
            "object": {
                "id": container_space_id,
                "realm_id": realm_id,
                "kind": "list",
                "title": "Hydration target",
                "created_by": "did:web:alice.example",
            }
        }),
        Vec::new(),
    );
    let r: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        r["status"], "accepted",
        "create space container response: {r}"
    );

    let archive_event = signed_place_event(
        "cx:event:01904100-0000-7000-8000-f10ec0000002",
        2,
        "cx.space.archive",
        serde_json::json!({ "space_id": container_space_id }),
        vec!["cx:event:01904100-0000-7000-8000-f10ec0000001"],
    );
    let r: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&archive_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        r["status"], "accepted",
        "archive space container response: {r}"
    );

    // ── projection now reports archived ───────────────────────────────
    let body: Value = TestClient::get(format!(
        "http://server/api/v1/projection/spaces?realm_id={realm_id}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(body["realm_id"], realm_id);
    let spaces = body["spaces"].as_array().unwrap();
    let row = spaces
        .iter()
        .find(|p| p["space_id"] == container_space_id)
        .expect("place not in projection response");
    assert_eq!(row["state"], "archived");
    assert_eq!(row["title"], "Hydration target");

    // ── restore + re-fetch → active ───────────────────────────────────
    let restore_event = signed_place_event(
        "cx:event:01904100-0000-7000-8000-f10ec0000003",
        3,
        "cx.space.restore",
        serde_json::json!({ "space_id": container_space_id }),
        vec!["cx:event:01904100-0000-7000-8000-f10ec0000002"],
    );
    let r: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&restore_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        r["status"], "accepted",
        "restore space container response: {r}"
    );

    let body: Value = TestClient::get(format!(
        "http://server/api/v1/projection/spaces?realm_id={realm_id}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let row = body["spaces"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["space_id"] == container_space_id)
        .expect("place still missing post-restore");
    assert_eq!(row["state"], "active");

    let legacy_underscore = TestClient::get(format!(
        "http://server/api/v1/projection/space_containers?realm_id={realm_id}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(legacy_underscore.status_code, Some(StatusCode::NOT_FOUND));

    let legacy_hyphen = TestClient::get(format!(
        "http://server/api/v1/projection/space-containers?realm_id={realm_id}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(legacy_hyphen.status_code, Some(StatusCode::NOT_FOUND));
}

/// `GET /api/v1/projection/flows?realm_id=...` mirrors the Place
/// test at the Flow object layer. After archive -> state is
/// `archived`; after redaction `object_ref` -> state is `redacted`
/// (terminal).
#[tokio::test]
async fn projection_flows_endpoint_reports_lifecycle_state() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let space_id = DEMO_REALM_ID;
    let flow_id = "cx:flow:01904100-0000-7000-8000-f20dc0000001";

    let create_event = signed_flow_event(
        "cx:event:01904100-0000-7000-8000-f20ec0000001",
        1,
        "cx.flow.create",
        serde_json::json!({
            "object": {
                "id": flow_id,
                "space_id": space_id,
                "title": "Hydration flow",
                "created_by": "did:web:alice.example",
            }
        }),
        Vec::new(),
    );
    let r: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(r["status"], "accepted");

    let archive_event = signed_flow_event(
        "cx:event:01904100-0000-7000-8000-f20ec0000002",
        2,
        "cx.flow.archive",
        serde_json::json!({ "flow_id": flow_id }),
        vec!["cx:event:01904100-0000-7000-8000-f20ec0000001"],
    );
    let r: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&archive_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(r["status"], "accepted");

    let body: Value = TestClient::get(format!(
        "http://server/api/v1/projection/flows?realm_id={space_id}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let row = body["flows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["flow_id"] == flow_id)
        .expect("flow not in projection response");
    assert_eq!(row["state"], "archived");
}

/// `cx.flow.tracks.update` is accepted against an Active Flow (server-side
/// touch bumps Flow.updated_at; per-track state lives in SDK reducer's
/// Flow.tracks map) but MUST be rejected with HTTP 412 + `flow_not_active`
/// once the parent Flow is archived, per spec common-fields.md §5.1
/// update-on-non-active rule.
#[tokio::test]
async fn flow_tracks_update_rejected_when_parent_flow_archived() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let flow_id = "cx:flow:01904100-0000-7000-8000-aabbccdd0001";

    let create_flow = signed_flow_event(
        "cx:event:01904100-0000-7000-8000-aabbcc000001",
        1,
        "cx.flow.create",
        serde_json::json!({
            "object": {
                "id": flow_id,
                "space_id": DEMO_REALM_ID,
                "title": "Launch flow",
                "created_by": "did:web:alice.example",
            }
        }),
        Vec::new(),
    );
    let resp: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_flow)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted");

    let tracks_active = signed_flow_event(
        "cx:event:01904100-0000-7000-8000-aabbcc000002",
        2,
        "cx.flow.tracks.update",
        serde_json::json!({
            "flow_id": flow_id,
            "patch": {"tracks": {"discussion": {"profile": "discussion"}}}
        }),
        vec!["cx:event:01904100-0000-7000-8000-aabbcc000001"],
    );
    let resp: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&tracks_active)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted");

    let archive = signed_flow_event(
        "cx:event:01904100-0000-7000-8000-aabbcc000003",
        3,
        "cx.flow.archive",
        serde_json::json!({ "flow_id": flow_id }),
        vec!["cx:event:01904100-0000-7000-8000-aabbcc000002"],
    );
    let resp: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&archive)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted");

    let tracks_archived = signed_flow_event(
        "cx:event:01904100-0000-7000-8000-aabbcc000004",
        4,
        "cx.flow.tracks.update",
        serde_json::json!({
            "flow_id": flow_id,
            "patch": {"tracks": {"synthesis": {"profile": "synthesis"}}}
        }),
        vec!["cx:event:01904100-0000-7000-8000-aabbcc000003"],
    );
    let mut resp = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&tracks_archived)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(resp.status_code.unwrap().as_u16(), 412);
    let body: Value = resp.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "flow_not_active");
}

/// `POST /api/v1/audit/user-action` accepts client-side user-action
/// telemetry posts and appends them to the session-actor's audit
/// log. Yougen's `flush_telemetry_to_server` posts against this URL;
/// the 404-tolerant caller buffers entries when the route is
/// unavailable.
#[tokio::test]
async fn audit_user_action_endpoint_persists_session_actor_entries_and_rejects_cross_actor() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    // ── 1. auth required ──────────────────────────────────────────────
    let unauth = TestClient::post("http://server/api/v1/audit/user-action")
        .json(&serde_json::json!({
            "actor": "did:web:alice.example",
            "action": "ui.button.click",
            "outcome": "ok",
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauth.status_code.unwrap().as_u16(), 401);

    // ── 2. happy path: session actor posts ────────────────────────────
    let ok: Value = TestClient::post("http://server/api/v1/audit/user-action")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "actor": "did:web:alice.example",
            "action": "ui.kanban.archive_list",
            "outcome": "ok",
            "note": "user clicked Archive on list cx:space:demo",
            "recorded_at": "2026-05-16T12:34:56Z",
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(ok["ok"], true);

    // ── 3. cross-actor post → 403 ─────────────────────────────────────
    let mut bad = TestClient::post("http://server/api/v1/audit/user-action")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "actor": "did:web:eve.example",
            "action": "ui.button.click",
            "outcome": "ok",
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(bad.status_code.unwrap().as_u16(), 403);
    let body: Value = bad.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "capability_denied");

    // ── 4. missing actor / action → 400 ──────────────────────────────
    let mut missing_actor = TestClient::post("http://server/api/v1/audit/user-action")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({"action": "ui.click"}))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(missing_actor.status_code.unwrap().as_u16(), 400);
    let body: Value = missing_actor.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "invalid_param");

    let missing_action = TestClient::post("http://server/api/v1/audit/user-action")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({"actor": "did:web:alice.example"}))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(missing_action.status_code.unwrap().as_u16(), 400);

    // ── 5. entry shows up in GET /audit/events for the same actor ────
    let events: Value = TestClient::get("http://server/api/v1/audit/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let rows = events["events"].as_array().unwrap();
    let posted = rows
        .iter()
        .find(|e| e["action"] == "ui.kanban.archive_list")
        .expect("user-action entry not surfaced through audit/events");
    assert_eq!(posted["outcome"], "ok");
    assert_eq!(posted["actor"], "did:web:alice.example");
}

/// Round 15a (2026-05-16) — `GET /api/v1/projection/morphs?realm_id=...`
/// completes the read-side trifecta started in round 14d (places + flows).
/// After create → state == `active`; after archive → `archived`; after
/// `cx.redaction` with object_ref → `redacted` (terminal). Same shape
/// guarantees as the flow / place endpoints.
#[tokio::test]
async fn projection_morphs_endpoint_reports_lifecycle_state() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let space_id = DEMO_REALM_ID;
    let morph_id = "cx:morph:01904100-0000-7000-8000-d20dc0000001";

    let create_event = signed_morph_event(
        "cx:event:01904100-0000-7000-8000-d20ec0000001",
        1,
        "cx.morph.create",
        serde_json::json!({
            "object": {
                "id": morph_id,
                "space_id": space_id,
                "morph_type": "task",
                "title": "Hydration morph",
                "created_by": "did:web:alice.example",
            }
        }),
        Vec::new(),
    );
    let r: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(r["status"], "accepted");

    // Initial state — Active.
    let body: Value = TestClient::get(format!(
        "http://server/api/v1/projection/morphs?realm_id={space_id}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let row = body["morphs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["morph_id"] == morph_id)
        .expect("morph not in projection response");
    assert_eq!(row["state"], "active");
    assert_eq!(row["morph_type"], "task");

    // Archive → state flips to `archived`.
    let archive_event = signed_morph_event(
        "cx:event:01904100-0000-7000-8000-d20ec0000002",
        2,
        "cx.morph.archive",
        serde_json::json!({ "morph_id": morph_id }),
        vec!["cx:event:01904100-0000-7000-8000-d20ec0000001"],
    );
    let r: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&archive_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(r["status"], "accepted");

    let body: Value = TestClient::get(format!(
        "http://server/api/v1/projection/morphs?realm_id={space_id}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let row = body["morphs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["morph_id"] == morph_id)
        .expect("morph not in projection response");
    assert_eq!(row["state"], "archived");

    // Unauthenticated → 401, no body leak.
    let unauth = TestClient::get(format!(
        "http://server/api/v1/projection/morphs?realm_id={space_id}"
    ))
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(unauth.status_code, Some(StatusCode::UNAUTHORIZED));
}

/// Round 15b (2026-05-16) — `cx.applet.registration` + `cx.applet.discovery`
/// populate `ProjectionState::applets`, exposed via `GET /api/v1/admin/applets`.
/// Same for `cx.agent.endpoint` → `ProjectionState::agents` → `admin/agents`.
/// Replaces the round 14f stub that returned an empty array.
#[tokio::test]
async fn admin_applets_agents_endpoints_reflect_submitted_registry_events() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let service_did = "did:web:applet.example";
    let agent_did = "did:web:agent.example";

    // Build an applet registration event. cx.applet.registration uses
    // cx.schema.event_payload.v1 since there's no dedicated applet
    // schema in the spec registry (applet payload is free-form per
    // spec extensions/applet-integration.md).
    let registration_payload = serde_json::json!({
        "service_did": service_did,
        "namespace": "com.example.applet",
        "capabilities": ["read", "write"],
    });
    let mut registration_event = signed_event_envelope(
        "cx:event:01904100-0000-7000-8000-ab10de000001",
        1,
        Vec::new(),
    );
    registration_event["kind"] = Value::String("cx.applet.registration".to_owned());
    registration_event["schema_id"] = Value::String("cx.schema.event_payload.v1".to_owned());
    registration_event["payload"] = registration_payload.clone();
    registration_event["proofs"][0]["payload_digest"] =
        Value::String(sha256_json(&registration_payload));
    registration_event["canonical_digest"] =
        Value::String(event_canonical_digest(&registration_event));
    let resp: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&registration_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted");

    // Discovery — adds a manifest to the same applet.
    let discovery_payload = serde_json::json!({
        "service_did": service_did,
        "manifest": {"protocol": "http", "endpoint": "https://applet.example"},
    });
    let mut discovery_event = signed_event_envelope(
        "cx:event:01904100-0000-7000-8000-ab10de000002",
        2,
        vec!["cx:event:01904100-0000-7000-8000-ab10de000001"],
    );
    discovery_event["kind"] = Value::String("cx.applet.discovery".to_owned());
    discovery_event["schema_id"] = Value::String("cx.schema.event_payload.v1".to_owned());
    discovery_event["payload"] = discovery_payload.clone();
    discovery_event["proofs"][0]["payload_digest"] = Value::String(sha256_json(&discovery_payload));
    discovery_event["canonical_digest"] = Value::String(event_canonical_digest(&discovery_event));
    let resp: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&discovery_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted");

    // Agent endpoint event.
    let agent_payload = serde_json::json!({
        "agent_did": agent_did,
        "agent_id": agent_did,
        "protocol": "mcp",
        "endpoints": [{
            "protocol": "mcp"
        }],
    });
    let mut agent_event = signed_event_envelope(
        "cx:event:01904100-0000-7000-8000-ab10de000003",
        3,
        vec!["cx:event:01904100-0000-7000-8000-ab10de000002"],
    );
    agent_event["kind"] = Value::String("cx.agent.endpoint".to_owned());
    agent_event["schema_id"] = Value::String("cx.schema.event_payload.v1".to_owned());
    agent_event["payload"] = agent_payload.clone();
    agent_event["proofs"][0]["payload_digest"] = Value::String(sha256_json(&agent_payload));
    agent_event["canonical_digest"] = Value::String(event_canonical_digest(&agent_event));
    let resp: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&agent_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted");

    // `admin/applets` now reports the registered applet with the manifest.
    let applets_body: Value = TestClient::get("http://server/api/v1/admin/applets?limit=10")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let applet_row = applets_body["applets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["service_did"] == service_did)
        .expect("registered applet missing from admin/applets");
    assert_eq!(applet_row["namespace"], "com.example.applet");
    assert_eq!(applet_row["capabilities"][0], "read");
    assert_eq!(
        applet_row["manifest"]["endpoint"], "https://applet.example",
        "discovery manifest must be merged into the applet projection"
    );

    // `admin/agents` reports the registered agent.
    let agents_body: Value = TestClient::get("http://server/api/v1/admin/agents?limit=10")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let agent_row = agents_body["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["agent_did"] == agent_did)
        .expect("registered agent missing from admin/agents");
    assert_eq!(agent_row["protocol"], "mcp");
}

/// Round 15d (2026-05-16) — projection_query endpoints filter out
/// terminal-state rows by default (tombstoned for Space containers; deleted /
/// redacted for Flow / Morph). Explicit `include_terminal=true` returns
/// the full set. Spec: terminal states are unrecoverable per
/// `common-fields.md §5.1`; clients hydrating a kanban view shouldn't
/// see them unless explicitly opting in.
#[tokio::test]
async fn projection_endpoints_hide_terminal_state_by_default() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let realm_id = "cx:realm:0196419b-0000-7000-8000-000000000000";
    let space_id = realm_id;
    let container_space_id = "cx:space:01904100-0000-7000-8000-c15d70000001";
    let flow_id = "cx:flow:01904100-0000-7000-8000-c15d70000002";

    // Create + tombstone a Space container.
    let create_place = signed_place_event(
        "cx:event:01904100-0000-7000-8000-c15d70010001",
        1,
        "cx.space.create",
        serde_json::json!({
            "object": {
                "id": container_space_id,
                "realm_id": realm_id,
                "kind": "list",
                "title": "Doomed Space",
                "created_by": "did:web:alice.example",
            }
        }),
        Vec::new(),
    );
    let r: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_place)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(r["status"], "accepted");

    let tombstone_place = signed_place_event(
        "cx:event:01904100-0000-7000-8000-c15d70010002",
        2,
        "cx.space.tombstone",
        serde_json::json!({ "space_id": container_space_id }),
        vec!["cx:event:01904100-0000-7000-8000-c15d70010001"],
    );
    let r: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&tombstone_place)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(r["status"], "accepted");

    // Default Space-container projection — tombstoned Space container is hidden.
    let body: Value = TestClient::get(format!(
        "http://server/api/v1/projection/spaces?realm_id={realm_id}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert!(
        body["spaces"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["space_id"] != container_space_id),
        "tombstoned Space container MUST be hidden from default projection listing"
    );

    // Explicit include_terminal=true — tombstoned Space container is visible.
    let body: Value = TestClient::get(format!(
        "http://server/api/v1/projection/spaces?realm_id={realm_id}&include_terminal=true"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let row = body["spaces"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["space_id"] == container_space_id)
        .expect("tombstoned Space container MUST appear when include_terminal=true");
    assert_eq!(row["state"], "tombstoned");

    // Create a Flow + redact it.
    let create_flow = signed_flow_event(
        "cx:event:01904100-0000-7000-8000-c15d70020001",
        3,
        "cx.flow.create",
        serde_json::json!({
            "object": {
                "id": flow_id,
                "space_id": space_id,
                "title": "Doomed Flow",
                "created_by": "did:web:alice.example",
            }
        }),
        vec!["cx:event:01904100-0000-7000-8000-c15d70010002"],
    );
    let r: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_flow)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(r["status"], "accepted");

    let redact_flow = signed_redaction_event(
        "cx:event:01904100-0000-7000-8000-c15d70020002",
        4,
        serde_json::json!({
            "target_event_id": "cx:event:01904100-0000-7000-8000-c15d70020001",
            "object_ref": flow_id,
        }),
        vec!["cx:event:01904100-0000-7000-8000-c15d70020001"],
    );
    let r: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&redact_flow)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(r["status"], "accepted");

    // Default Flow listing — redacted Flow hidden.
    let body: Value = TestClient::get(format!(
        "http://server/api/v1/projection/flows?realm_id={space_id}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert!(
        body["flows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["flow_id"] != flow_id),
        "redacted Flow MUST be hidden from default projection listing"
    );

    // Explicit include_terminal=true — redacted Flow visible.
    let body: Value = TestClient::get(format!(
        "http://server/api/v1/projection/flows?realm_id={space_id}&include_terminal=true"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let row = body["flows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["flow_id"] == flow_id)
        .expect("redacted Flow MUST appear when include_terminal=true");
    assert_eq!(row["state"], "redacted");
}

/// Submitting a `cx.applet.protocol_session.start` event MUST
/// trigger the reference applet bridge runtime to emit a matching
/// `cx.applet.protocol_session.status` event into the same
/// projection log. The synthetic status carries
/// `bridge = soland.reference.echo` and echoes the original `params`
/// under `detail.echo` so the timeline observes the full round trip
/// without a real applet service plugged in.
#[tokio::test]
async fn applet_bridge_emits_synthetic_status_for_session_start() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let session_id = "cx:session:01904100-0000-7000-8000-b3b3b3b3b3b3";
    let applet_id = "cx:applet:01904100-0000-7000-8000-c3c3c3c3c3c3";

    // Submit the start event via the canonical events surface.
    let mut payload = serde_json::json!({
        "applet_id": applet_id,
        "session_id": session_id,
        "params": {"op": "ping", "tag": "b3-e2e"},
    });
    let mut start_event = serde_json::json!({
        "event_id": "cx:event:01904100-0000-7000-8000-d3d3d3d3d3d3",
        "kind": "cx.applet.protocol_session.start",
        "schema_id": "cx.schema.applet.v1",
        "actor_id": "did:web:alice.example",
        "actor_seq": 1u64,
        "realm_id": DEMO_REALM_ID,
        "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": Vec::<String>::new(),
        "auth_refs": Vec::<String>::new(),
        "payload": payload.clone(),
        "proofs": [{
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#01904100-0000-7000-8000-a11ce0000001",
            "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload),
        }],
    });
    start_event["canonical_digest"] = Value::String(event_canonical_digest(&start_event));
    let _ = &mut payload;

    let resp: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&start_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "submit response: {resp}");

    // The reference bridge should have appended a synthetic status
    // event for the same session_id. Pull it out of the projection
    // log via the events list endpoint.
    let events: Value = TestClient::get(format!(
        "http://server/api/v1/events?realms={DEMO_REALM_ID}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let list = events["events"].as_array().expect("events array");
    let status_event = list
        .iter()
        .find(|e| {
            e["event_kind"] == "cx.applet.protocol_session.status"
                && e["payload"]["session_id"] == session_id
        })
        .expect("synthetic status event missing from projection log");
    assert_eq!(status_event["payload"]["status"], "completed");
    assert_eq!(status_event["payload"]["detail"]["echo"]["op"], "ping");
    assert_eq!(status_event["payload"]["detail"]["echo"]["tag"], "b3-e2e");
    assert_eq!(
        status_event["payload"]["detail"]["bridge"],
        "soland.reference.echo"
    );
}

/// Submitting a `cx.agent.protocol_session.start` event against a
/// registered agent MUST trigger the reference agent runtime to
/// emit both a `cx.agent.protocol_session.status` (running) and a
/// terminal `cx.agent.protocol_session.result` (completed) event
/// with an Ed25519 `audit_binding.signature` that round-trips
/// through the SDK verify helper. The agent must be registered
/// first via `cx.agent.endpoint` - otherwise the dispatch lookup
/// fails closed (covered by the sibling
/// `agent_bridge_fails_closed_on_unknown_agent` test below).
#[tokio::test]
async fn agent_bridge_emits_status_and_result_for_session_start() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    // Use the seeded demo Realm — dev_token's actor is a member of
    // `cx:realm:0196419b-0000-7000-8000-000000000000` so the events
    // surface accepts writes against it (mirror of the B3 test).
    let session_id = "cx:agent_session:01904100-0000-7000-8000-b4b4b4b4b4b4";
    let agent_did = "did:web:agent.example";

    // Register the agent first so B4c's dispatch lookup succeeds.
    let endpoint_payload = serde_json::json!({
        "agent_did": agent_did,
        "agent_id": agent_did,
        "protocol": "echo",
        "endpoints": [{
            "protocol": "echo"
        }],
    });
    let mut endpoint_event = serde_json::json!({
        "event_id": "cx:event:01904100-0000-7000-8000-e4e4e4e4e4e4",
        "kind": "cx.agent.endpoint",
        "schema_id": "cx.schema.agent.v1",
        "actor_id": "did:web:alice.example",
        "actor_seq": 1u64,
        "realm_id": DEMO_REALM_ID,
        "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": Vec::<String>::new(),
        "auth_refs": Vec::<String>::new(),
        "payload": endpoint_payload.clone(),
        "proofs": [{
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#01904100-0000-7000-8000-a11ce0000001",
            "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&endpoint_payload),
        }],
    });
    endpoint_event["canonical_digest"] = Value::String(event_canonical_digest(&endpoint_event));
    let endpoint_resp: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&endpoint_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        endpoint_resp["status"], "accepted",
        "endpoint submit response: {endpoint_resp}"
    );

    let echo_params = serde_json::json!({"op": "summarize", "doc": "b4-e2e"});
    let mut payload = serde_json::json!({
        "agent_did": agent_did,
        "counterparty_agent": agent_did,
        "session_id": session_id,
        "protocol": "http_custom",
        "params": echo_params,
        "capability_grant": "cx:grant:01904100-0000-7000-8000-000000000099",
        "capability_proof": {
            "grant_ref": "cx:grant:01904100-0000-7000-8000-000000000099",
            "note": "B4 e2e placeholder — reference echo runtime does not verify the proof",
        },
    });
    let mut start_event = serde_json::json!({
        "event_id": "cx:event:01904100-0000-7000-8000-d4d4d4d4d4d4",
        "kind": "cx.agent.protocol_session.start",
        "schema_id": "cx.schema.agent.v1",
        "actor_id": "did:web:alice.example",
        "actor_seq": 2u64,
        "realm_id": DEMO_REALM_ID,
        "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": Vec::<String>::new(),
        "auth_refs": Vec::<String>::new(),
        "payload": payload.clone(),
        "proofs": [{
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#01904100-0000-7000-8000-a11ce0000001",
            "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload),
        }],
    });
    start_event["canonical_digest"] = Value::String(event_canonical_digest(&start_event));
    let _ = &mut payload;

    let resp: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&start_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "submit response: {resp}");

    let events: Value = TestClient::get(format!(
        "http://server/api/v1/events?realms={DEMO_REALM_ID}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let list = events["events"].as_array().expect("events array");

    let status_event = list
        .iter()
        .find(|e| {
            e["event_kind"] == "cx.agent.protocol_session.status"
                && e["payload"]["session_id"] == session_id
        })
        .expect("synthetic agent status event missing from projection log");
    assert_eq!(status_event["payload"]["status"], "running");
    assert_eq!(
        status_event["payload"]["detail"]["bridge"],
        "soland.reference.agent_echo"
    );

    let result_event = list
        .iter()
        .find(|e| {
            e["event_kind"] == "cx.agent.protocol_session.result"
                && e["payload"]["session_id"] == session_id
        })
        .expect("synthetic agent result event missing from projection log");
    assert_eq!(result_event["payload"]["status"], "completed");
    assert_eq!(result_event["payload"]["result"]["echo"]["op"], "summarize");
    assert_eq!(result_event["payload"]["result"]["echo"]["doc"], "b4-e2e");
    assert_eq!(result_event["payload"]["result"]["agent_did"], agent_did);
    let binding = &result_event["payload"]["audit_binding"];
    assert_eq!(binding["binding_kind"], "ed25519_v1");
    assert_eq!(binding["actor_id"], "did:web:alice.example");
    assert_eq!(
        binding["key_id"],
        soland::REFERENCE_AGENT_AUDIT_ED25519_KEY_ID
    );

    // Verify the Ed25519 signature round-trips against the SDK
    // helper using the public key the envelope carries. The
    // verifier needs no access to the signing seed.
    let sig_b64 = binding["signature"].as_str().expect("signature base64");
    let public_key_b64 = binding["public_key_b64"].as_str().expect("public_key_b64");
    let canonical_subject = binding["canonical_subject"]
        .as_str()
        .expect("canonical_subject");
    let echo_value = result_event["payload"]["result"]["echo"].clone();
    let outcome = contrix_sdk::agent_binding::verify_ed25519_audit_binding(
        public_key_b64,
        session_id,
        agent_did,
        &echo_value,
        "did:web:alice.example",
        sig_b64,
        canonical_subject,
    );
    assert_eq!(
        outcome,
        contrix_sdk::agent_binding::Ed25519AuditBindingVerifyOutcome::Valid,
        "audit_binding Ed25519 signature must verify under the carried public key"
    );
}

/// When `cx.agent.protocol_session.start` names an agent_did that
/// has not been registered via `cx.agent.endpoint`, the bridge MUST
/// emit exactly one `cx.agent.protocol_session.result` carrying
/// `status=failed` + `error.code=unknown_agent`, and NO
/// `status(running)` event.
#[tokio::test]
async fn agent_bridge_fails_closed_on_unknown_agent() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let session_id = "cx:agent_session:01904100-0000-7000-8000-deaddeaddead";
    let agent_did = "did:web:unregistered-agent.example";

    // Intentionally skip the cx.agent.endpoint step — this is the
    // dispatch-failure path.
    let echo_params = serde_json::json!({"op": "ping"});
    let mut payload = serde_json::json!({
        "agent_did": agent_did,
        "counterparty_agent": agent_did,
        "session_id": session_id,
        "protocol": "http_custom",
        "params": echo_params,
        "capability_grant": "cx:grant:01904100-0000-7000-8000-000000000099",
        "capability_proof": {
            "grant_ref": "cx:grant:01904100-0000-7000-8000-000000000099",
            "note": "B4c e2e placeholder",
        },
    });
    let mut start_event = serde_json::json!({
        "event_id": "cx:event:01904100-0000-7000-8000-deadbeefdead",
        "kind": "cx.agent.protocol_session.start",
        "schema_id": "cx.schema.agent.v1",
        "actor_id": "did:web:alice.example",
        "actor_seq": 1u64,
        "realm_id": DEMO_REALM_ID,
        "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": Vec::<String>::new(),
        "auth_refs": Vec::<String>::new(),
        "payload": payload.clone(),
        "proofs": [{
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#01904100-0000-7000-8000-a11ce0000001",
            "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload),
        }],
    });
    start_event["canonical_digest"] = Value::String(event_canonical_digest(&start_event));
    let _ = &mut payload;

    let resp: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&start_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "submit response: {resp}");

    let events: Value = TestClient::get(format!(
        "http://server/api/v1/events?realms={DEMO_REALM_ID}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let list = events["events"].as_array().expect("events array");

    // No status(running) event should be present.
    assert!(
        !list.iter().any(|e| {
            e["event_kind"] == "cx.agent.protocol_session.status"
                && e["payload"]["session_id"] == session_id
        }),
        "B4c failed-closed dispatch must skip the status(running) event"
    );

    let result_event = list
        .iter()
        .find(|e| {
            e["event_kind"] == "cx.agent.protocol_session.result"
                && e["payload"]["session_id"] == session_id
        })
        .expect("error result event missing from projection log");
    assert_eq!(result_event["payload"]["status"], "failed");
    assert_eq!(result_event["payload"]["error"]["code"], "unknown_agent");
    assert!(
        result_event["payload"]["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains(agent_did),
        "error message should mention the missing agent_did"
    );
    assert!(
        result_event["payload"].get("audit_binding").is_none(),
        "failure path must not carry an audit_binding"
    );
}

/// When `cx.agent.endpoint` carries an `endpoint_url`, the bridge
/// MUST surface it on both the status(running) and result envelopes'
/// `detail.endpoint_url`. The runtime needs to know where to
/// forward, and observers need to see where the answer came from.
#[tokio::test]
async fn agent_bridge_plumbs_endpoint_url_through_session_envelopes() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let session_id = "cx:agent_session:01904100-0000-7000-8000-c0c0c0c0c0c0";
    let agent_did = "did:web:b4d-agent.example";
    let endpoint_url = "https://b4d-agent.example/api/v1/agent";

    let endpoint_payload = serde_json::json!({
        "agent_did": agent_did,
        "agent_id": agent_did,
        "protocol": "echo",
        "endpoint_url": endpoint_url,
        "endpoints": [{
            "protocol": "echo",
            "url": endpoint_url
        }],
    });
    let mut endpoint_event = serde_json::json!({
        "event_id": "cx:event:01904100-0000-7000-8000-c1c1c1c1c1c1",
        "kind": "cx.agent.endpoint",
        "schema_id": "cx.schema.agent.v1",
        "actor_id": "did:web:alice.example",
        "actor_seq": 1u64,
        "realm_id": DEMO_REALM_ID,
        "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": Vec::<String>::new(),
        "auth_refs": Vec::<String>::new(),
        "payload": endpoint_payload.clone(),
        "proofs": [{
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#01904100-0000-7000-8000-a11ce0000001",
            "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&endpoint_payload),
        }],
    });
    endpoint_event["canonical_digest"] = Value::String(event_canonical_digest(&endpoint_event));
    let endpoint_resp: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&endpoint_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        endpoint_resp["status"], "accepted",
        "endpoint submit response: {endpoint_resp}"
    );

    let echo_params = serde_json::json!({"op": "ping"});
    let mut payload = serde_json::json!({
        "agent_did": agent_did,
        "counterparty_agent": agent_did,
        "session_id": session_id,
        "protocol": "http_custom",
        "params": echo_params,
        "capability_grant": "cx:grant:01904100-0000-7000-8000-000000000099",
        "capability_proof": {
            "grant_ref": "cx:grant:01904100-0000-7000-8000-000000000099",
            "note": "B4d e2e placeholder",
        },
    });
    let mut start_event = serde_json::json!({
        "event_id": "cx:event:01904100-0000-7000-8000-c2c2c2c2c2c2",
        "kind": "cx.agent.protocol_session.start",
        "schema_id": "cx.schema.agent.v1",
        "actor_id": "did:web:alice.example",
        "actor_seq": 2u64,
        "realm_id": DEMO_REALM_ID,
        "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": Vec::<String>::new(),
        "auth_refs": Vec::<String>::new(),
        "payload": payload.clone(),
        "proofs": [{
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#01904100-0000-7000-8000-a11ce0000001",
            "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload),
        }],
    });
    start_event["canonical_digest"] = Value::String(event_canonical_digest(&start_event));
    let _ = &mut payload;

    let resp: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&start_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "submit response: {resp}");

    // When endpoint_url is set the bridge spawns outbound HTTP and
    // emits the result event asynchronously. The test endpoint
    // above resolves but doesn't accept (b4d-agent.example resolves
    // to AAAA::1 / fail), so the outcome is `upstream_unreachable`.
    // Poll up to ~5 s for the result event to land.
    let result_event = {
        let mut found = None;
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let events: Value = TestClient::get(format!(
                "http://server/api/v1/events?realms={DEMO_REALM_ID}"
            ))
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
            if let Some(arr) = events["events"].as_array() {
                if let Some(e) = arr.iter().find(|e| {
                    e["event_kind"] == "cx.agent.protocol_session.result"
                        && e["payload"]["session_id"] == session_id
                }) {
                    found = Some(e.clone());
                    break;
                }
            }
        }
        found.expect("result event never landed within 5s")
    };

    let events: Value = TestClient::get(format!(
        "http://server/api/v1/events?realms={DEMO_REALM_ID}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let list = events["events"].as_array().expect("events array");

    let status_event = list
        .iter()
        .find(|e| {
            e["event_kind"] == "cx.agent.protocol_session.status"
                && e["payload"]["session_id"] == session_id
        })
        .expect("status event missing");
    assert_eq!(
        status_event["payload"]["detail"]["endpoint_url"], endpoint_url,
        "status event must echo registered endpoint_url"
    );
    assert_eq!(status_event["payload"]["detail"]["protocol"], "echo");

    // Result event MUST carry the registered endpoint_url in detail,
    // regardless of whether the upstream succeeded (it won't here —
    // b4d-agent.example doesn't resolve, so we expect the
    // `upstream_unreachable` fail-closed path).
    assert_eq!(
        result_event["payload"]["detail"]["endpoint_url"], endpoint_url,
        "result event must echo registered endpoint_url"
    );
    assert_eq!(
        result_event["payload"]["status"], "failed",
        "outbound to unresolved host must fail closed"
    );
    assert_eq!(
        result_event["payload"]["error"]["code"], "upstream_unreachable",
        "fail-closed code must be upstream_unreachable"
    );
    assert_eq!(
        result_event["payload"]["detail"]["bridge"],
        "soland.reference.agent_outbound"
    );

    // The admin agents collection should also surface endpoint_url so
    // sodmin operators see it.
    let admin_agents: Value = TestClient::get("http://server/api/v1/admin/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let agents_list = admin_agents["items"]
        .as_array()
        .or_else(|| admin_agents["agents"].as_array())
        .expect("admin agents list shape");
    let entry = agents_list
        .iter()
        .find(|a| a["agent_did"] == agent_did)
        .expect("admin agents missing freshly-registered agent");
    assert_eq!(
        entry["endpoint_url"], endpoint_url,
        "admin agents row must surface endpoint_url"
    );
}

/// Round 15f (2026-05-16) — multi-chunk snapshot fixture. The single-chunk
/// case is covered by `snapshot_v2_audit_path_verifies_against_merkle_root`,
/// but for single-chunk snapshots the audit path is empty (the root IS the
/// leaf) so the `SnapshotMerkleTree::verify` codepath never exercises a
/// real Merkle sibling chain. This test pumps a Space full of large
/// messages until the canonical snapshot bytes exceed the chunker's
/// default 256 KiB target, then verifies every chunk's non-empty audit
/// path reconstructs to the head's merkle_root.
#[tokio::test]
async fn snapshot_v2_multi_chunk_fixture_verifies_non_empty_audit_path() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let space = seed_test_realm(
        &state,
        "did:web:alice.example",
        "snapshot-v2-multi-chunk-test",
        Some("B4 follow-up: ensure multi-chunk audit_path verifies"),
        "public",
        &[],
        &[],
    );
    let space_id = space["space_id"].as_str().unwrap().to_owned();

    // 64 messages × ~4 KB body each ≈ 256 KB serialized — should land
    // ≥ 2 chunks once the snapshot wrapper + per-message JSON overhead
    // is included. Body is a deterministic ASCII pattern so the test is
    // reproducible run-to-run.
    //
    // Snapshot's `messages` array comes from the MessageRecord store, now
    // populated by canonical `POST /api/v1/events` projection.
    let body_text: String = (0..40)
        .map(|i| {
            format!(
                "para{:02}: lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor.\n",
                i
            )
        })
        .collect();
    let messages_to_submit = 80u64;
    for seq in 1..=messages_to_submit {
        let resp = submit_message_event(
            state.clone(),
            &token,
            "did:web:alice.example",
            &space_id,
            &format!("cx:flow:multi-chunk-{:02}", seq % 4),
            serde_json::json!({"body": body_text, "msgtype": "m.text", "seq": seq}),
            false,
        )
        .await;
        assert!(
            resp["event_id"].is_string(),
            "send failed at seq {seq}: {resp:?}"
        );
    }

    let head: Value = TestClient::get(format!(
        "http://server/api/v1/snapshot/head?realm_id={space_id}"
    ))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let chunk_count = head["chunk_count"].as_u64().unwrap();
    let total_bytes = head["total_bytes"].as_u64().unwrap();
    assert!(
        chunk_count >= 2,
        "expected multi-chunk snapshot but got chunk_count={chunk_count} \
         (total_bytes={total_bytes}); bump message count + body size if \
         this regresses"
    );
    assert!(
        total_bytes > 256 * 1024,
        "expected total_bytes > 256 KiB to force the chunker but got {total_bytes}"
    );

    // For each chunk, audit_path MUST be non-empty (multi-chunk case)
    // AND reconstruct to merkle_root via SnapshotMerkleTree::verify.
    let snapshot_ref = head["snapshot_ref"].as_str().unwrap();
    let root = contrix_sdk::Hash::new(head["merkle_root"].as_str().unwrap().to_owned()).unwrap();
    let tree_size = chunk_count as usize;
    let mut any_non_empty_path = false;
    for chunk_id in 0..chunk_count {
        let chunk: Value = TestClient::get(format!(
            "http://server/api/v1/sync/snapshot-chunk?snapshot_ref={snapshot_ref}&chunk_id={chunk_id}"
        ))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
        let leaf = contrix_sdk::Hash::new(chunk["digest"].as_str().unwrap().to_owned()).unwrap();
        let audit_path: Vec<contrix_sdk::Hash> = chunk["audit_path"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| contrix_sdk::Hash::new(h.as_str().unwrap().to_owned()).unwrap())
            .collect();
        if !audit_path.is_empty() {
            any_non_empty_path = true;
        }
        assert!(
            contrix_sdk::SnapshotMerkleTree::verify(
                &root,
                &leaf,
                chunk_id as usize,
                &audit_path,
                tree_size,
            ),
            "audit_path for chunk {chunk_id}/{chunk_count} must reconstruct to merkle_root"
        );
    }
    assert!(
        any_non_empty_path,
        "at least one chunk MUST have a non-empty audit_path in a multi-chunk snapshot \
         (this is the codepath single-chunk fixtures don't exercise)"
    );
}

/// Round 15h (2026-05-16) — Space-container / Flow / Morph projection write-through
/// to durable persistence. After each accepted lifecycle event, the
/// in-memory `ProjectionState::{space_containers,flows,morphs}` mutation is
/// mirrored to `state.persistence.{place,flow,morph}_projections()` so
/// process restart (via `AppState::new` hydrate path) can rebuild the
/// projection cache. This test exercises the write-through; hydrate is
/// the symmetric read of the same trait so it's covered indirectly.
#[tokio::test]
async fn projection_persistence_write_through_mirrors_lifecycle_events() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let container_space_id = "cx:space:01904100-0000-7000-8000-15a15a000001";
    let flow_id = "cx:flow:01904100-0000-7000-8000-15a15a000002";
    let morph_id = "cx:morph:01904100-0000-7000-8000-15a15a000003";

    // Space container: create + archive → persistence has state=archived.
    let create_place = signed_place_event(
        "cx:event:01904100-0000-7000-8000-15a15ae00001",
        1,
        "cx.space.create",
        serde_json::json!({
            "object": {
                "id": container_space_id,
                "realm_id": "cx:realm:0196419b-0000-7000-8000-000000000000",
                "kind": "list",
                "title": "Persistent Space",
                "created_by": "did:web:alice.example",
            }
        }),
        Vec::new(),
    );
    let r: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_place)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(r["status"], "accepted");

    let archive_place = signed_place_event(
        "cx:event:01904100-0000-7000-8000-15a15ae00002",
        2,
        "cx.space.archive",
        serde_json::json!({ "space_id": container_space_id }),
        vec!["cx:event:01904100-0000-7000-8000-15a15ae00001"],
    );
    let r: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&archive_place)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(r["status"], "accepted");

    let place_row = state
        .persistence
        .space_container_projections()
        .get(container_space_id)
        .unwrap()
        .expect("place projection MUST be mirrored to persistence after create+archive");
    assert_eq!(place_row.state, "archived");
    assert_eq!(place_row.title, "Persistent Space");

    // list_for_space + snapshot_all reach the same row.
    let by_space = state
        .persistence
        .space_container_projections()
        .list_for_space(DEMO_REALM_ID)
        .unwrap();
    assert!(
        by_space
            .iter()
            .any(|p| p.container_space_id == container_space_id),
        "list_for_space MUST surface the persisted space container"
    );
    let snapshot = state
        .persistence
        .space_container_projections()
        .snapshot_all()
        .unwrap();
    assert!(
        snapshot
            .iter()
            .any(|p| p.container_space_id == container_space_id)
    );

    // Flow: create + redact → persistence has state=redacted.
    let create_flow = signed_flow_event(
        "cx:event:01904100-0000-7000-8000-15a15af00001",
        3,
        "cx.flow.create",
        serde_json::json!({
            "object": {
                "id": flow_id,
                "space_id": DEMO_REALM_ID,
                "title": "Persistent Flow",
                "created_by": "did:web:alice.example",
            }
        }),
        vec!["cx:event:01904100-0000-7000-8000-15a15ae00002"],
    );
    let r: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_flow)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(r["status"], "accepted");
    let flow_row = state
        .persistence
        .flow_projections()
        .get(flow_id)
        .unwrap()
        .expect("flow projection MUST be mirrored to persistence after create");
    assert_eq!(flow_row.state, "active");
    assert_eq!(flow_row.title, "Persistent Flow");

    let redact_flow = signed_redaction_event(
        "cx:event:01904100-0000-7000-8000-15a15af00002",
        4,
        serde_json::json!({
            "target_event_id": "cx:event:01904100-0000-7000-8000-15a15af00001",
            "object_ref": flow_id,
        }),
        vec!["cx:event:01904100-0000-7000-8000-15a15af00001"],
    );
    let r: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&redact_flow)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(r["status"], "accepted");
    let flow_row = state
        .persistence
        .flow_projections()
        .get(flow_id)
        .unwrap()
        .expect("flow projection MUST still exist after redaction");
    assert_eq!(
        flow_row.state, "redacted",
        "cx.redaction with object_ref MUST flip flow projection in persistence too"
    );

    // Morph: create + archive → persistence has state=archived.
    let create_morph = signed_morph_event(
        "cx:event:01904100-0000-7000-8000-15a15a000004",
        5,
        "cx.morph.create",
        serde_json::json!({
            "object": {
                "id": morph_id,
                "space_id": DEMO_REALM_ID,
                "morph_type": "task",
                "title": "Persistent Morph",
                "created_by": "did:web:alice.example",
            }
        }),
        vec!["cx:event:01904100-0000-7000-8000-15a15af00002"],
    );
    let r: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&create_morph)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(r["status"], "accepted");

    let archive_morph = signed_morph_event(
        "cx:event:01904100-0000-7000-8000-15a15a000005",
        6,
        "cx.morph.archive",
        serde_json::json!({ "morph_id": morph_id }),
        vec!["cx:event:01904100-0000-7000-8000-15a15a000004"],
    );
    let r: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&archive_morph)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(r["status"], "accepted");
    let morph_row = state
        .persistence
        .morph_projections()
        .get(morph_id)
        .unwrap()
        .expect("morph projection MUST be mirrored to persistence");
    assert_eq!(morph_row.state, "archived");
    assert_eq!(morph_row.morph_type, "task");
}
