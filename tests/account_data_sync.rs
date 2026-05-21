use contrix_sdk::{Did, RealmId};
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use soland::config::{AppConfig, ObjectStorageConfig};
use soland::db::Db;
use soland::service;
use soland::state::{AppState, RealmDirectoryEntry, RealmMetaRecord};
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_EVENT_SEQ: AtomicU64 = AtomicU64::new(2_000);

fn test_config() -> AppConfig {
    AppConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        public_base_url: "http://server".to_owned(),
        service_did: "did:web:soland.local".to_owned(),
        tls_cert_path: None,
        tls_key_path: None,
        database_url: None,
        object_storage: ObjectStorageConfig::local(
            std::env::temp_dir().join("soland-account-data-sync-blobs"),
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
        seed_demo_data: false,
        trust_domain: "cx:trust_domain:soland.local".to_owned(),
        sovereign_enclave_enabled: false,
        sovereign_enclave_allowed_outbound_hosts: Vec::new(),
        erasure_propagation_window_ms: 604_800_000,
    }
}

fn app_from_state(state: AppState) -> salvo::Service {
    service(state)
}

async fn dev_token(state: AppState, actor: &str, device_id: &str, display_name: &str) -> String {
    let login: Value = TestClient::post("http://server/api/v1/auth/dev-login")
        .json(&json!({
            "actor": actor,
            "device_id": device_id,
            "display_name": display_name,
        }))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    login["access_token"].as_str().unwrap().to_owned()
}

async fn create_plaintext_space(state: AppState, _token: &str, title: &str) -> String {
    let realm_id = contrix_sdk::new_prefixed_uuid7("cx:realm:");
    let typed_realm_id = RealmId::new(realm_id.clone()).unwrap();
    let owner = Did::new("did:web:alice.example".to_owned()).unwrap();
    let now = chrono::Utc::now();

    let mut entry = RealmDirectoryEntry::new(typed_realm_id, title);
    entry.description = Some("G3.S6 account-private sync fixture".to_owned());
    entry.members.insert(owner);
    state.realms.lock().unwrap().upsert(entry);
    state
        .persistence
        .realm_meta()
        .put(
            &realm_id,
            &RealmMetaRecord {
                owner: "did:web:alice.example".to_owned(),
                deleted: false,
                discoverability: "invite_only".to_owned(),
                history_visibility: "joined".to_owned(),
                encryption_profile: None,
                plaintext_visible_services: std::collections::BTreeSet::from([
                    "did:web:soland.local".to_owned(),
                ]),
                created_at: now,
                updated_at: now,
            },
        )
        .unwrap();
    realm_id
}

async fn add_space_member(state: AppState, _token: &str, space_id: &str, member: &str) {
    let typed_realm_id = RealmId::new(space_id.to_owned()).unwrap();
    let member_did = Did::new(member.to_owned()).unwrap();
    let mut realms = state.realms.lock().unwrap();
    let entry = realms
        .get(&typed_realm_id)
        .cloned()
        .expect("seeded test realm exists before member add");
    let mut updated = entry;
    updated.members.insert(member_did);
    assert!(updated.members.iter().any(|did| did.as_str() == member));
    realms.upsert(updated);
}

async fn send_plaintext_message(
    state: AppState,
    token: &str,
    actor: &str,
    space_id: &str,
    body: &str,
) -> Value {
    let payload = json!({
        "flow_id": flow_id_for_realm(space_id),
        "thread_id": space_id,
        "track": "discussion",
        "content": {"kind": "cx.content.text", "body": body},
        "encrypted": false
    });
    let mut event = json!({
        "event_id": contrix_sdk::new_prefixed_uuid7("cx:event:"),
        "kind": "cx.message.create",
        "schema_id": "cx.schema.message.v1",
        "actor_id": actor,
        "actor_seq": TEST_EVENT_SEQ.fetch_add(1, Ordering::Relaxed),
        "realm_id": space_id,
        "device_id": "cx:device:01904100-0000-7000-8000-b0b000000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": [],
        "auth_refs": [],
        "payload": payload,
        "proofs": [{
            "type": "dev-proof",
            "verification_method": format!("{actor}#01904100-0000-7000-8000-b0b000000001"),
            "device_id": "cx:device:01904100-0000-7000-8000-b0b000000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_hash": sha256_json(&payload)
        }]
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));
    let response: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&event)
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        response["event_id"].is_string(),
        "message event submit must return event_id, got {response}"
    );
    response
}

fn sha256_json(value: &Value) -> String {
    let bytes = contrix_sdk::canonical::canonical_json_bytes(value).expect("json canonicalizes");
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
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

fn flow_id_for_realm(realm_id: &str) -> String {
    realm_id
        .strip_prefix("cx:realm:")
        .map(|suffix| format!("cx:flow:{suffix}"))
        .unwrap_or_else(|| "cx:flow:01904100-0000-7000-8000-f10dc0000001".to_owned())
}

#[tokio::test]
async fn blocklist_account_data_fans_out_and_filters_notifications() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice_desktop = dev_token(
        state.clone(),
        "did:web:alice.example",
        "cx:device:01904100-0000-7000-8000-a11ce0000001",
        "Alice Desktop",
    )
    .await;
    let alice_phone = dev_token(
        state.clone(),
        "did:web:alice.example",
        "cx:device:01904100-0000-7000-8000-a11ce0000002",
        "Alice Phone",
    )
    .await;
    let bob = dev_token(
        state.clone(),
        "did:web:bob.example",
        "cx:device:01904100-0000-7000-8000-b0b000000001",
        "Bob",
    )
    .await;
    let space_id = create_plaintext_space(state.clone(), &alice_desktop, "Blocklist Fixture").await;
    add_space_member(
        state.clone(),
        &alice_desktop,
        &space_id,
        "did:web:bob.example",
    )
    .await;

    let blocklist = json!({
        "version": 1,
        "entries": [{
            "target": "did:web:bob.example",
            "kind": "block",
            "created_at": "2026-05-21T00:00:00Z"
        }]
    });
    let mut put = TestClient::put("http://server/api/v1/account_data/cx.account.blocklist.v1")
        .add_header("authorization", format!("Bearer {alice_desktop}"), true)
        .json(&json!({"content": blocklist.clone()}))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(put.status_code.unwrap().as_u16(), 201);
    let put_body: Value = put.take_json().await.unwrap();
    assert_eq!(put_body["content"], blocklist);

    let phone_account_data: Value =
        TestClient::get("http://server/api/v1/account_data/cx.account.blocklist.v1")
            .add_header("authorization", format!("Bearer {alice_phone}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(phone_account_data["content"], blocklist);

    let phone_messages: Value = TestClient::get("http://server/api/v1/device_messages")
        .add_header("authorization", format!("Bearer {alice_phone}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let phone_events = phone_messages["events"].as_array().unwrap();
    let blocklist_event = phone_events
        .iter()
        .find(|event| event["content"]["type"] == "cx.account.blocklist.update")
        .expect("blocklist update fanout reaches Alice's sibling device");
    assert_eq!(
        blocklist_event["content"]["content"]["data_type"],
        "cx.account.blocklist.v1"
    );
    assert_eq!(
        blocklist_event["content"]["content"]["content"]["entries"][0]["target"],
        "did:web:bob.example"
    );

    let bob_messages: Value = TestClient::get("http://server/api/v1/device_messages")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(bob_messages["events"].as_array().unwrap().is_empty());

    let blocked_message = send_plaintext_message(
        state.clone(),
        &bob,
        "did:web:bob.example",
        &space_id,
        "blocked notification",
    )
    .await;
    let notifications: Value =
        TestClient::get("http://server/api/v1/index/notifications?actor=did:web:alice.example")
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert!(
        notifications["notifications"]
            .as_array()
            .unwrap()
            .iter()
            .all(|notification| notification["event_ref"] != blocked_message["event_id"])
    );

    let unblock = TestClient::put("http://server/api/v1/account_data/cx.account.blocklist.v1")
        .add_header("authorization", format!("Bearer {alice_desktop}"), true)
        .json(&json!({"content": {"version": 1, "entries": []}}))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unblock.status_code.unwrap().as_u16(), 200);

    let visible_message = send_plaintext_message(
        state.clone(),
        &bob,
        "did:web:bob.example",
        &space_id,
        "visible notification",
    )
    .await;
    let notifications_after: Value =
        TestClient::get("http://server/api/v1/index/notifications?actor=did:web:alice.example")
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert!(
        notifications_after["notifications"]
            .as_array()
            .unwrap()
            .iter()
            .any(|notification| notification["event_ref"] == visible_message["event_id"])
    );
}

#[tokio::test]
async fn read_marker_fans_out_per_realm_without_cross_actor_leakage() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice_desktop = dev_token(
        state.clone(),
        "did:web:alice.example",
        "cx:device:01904100-0000-7000-8000-a11ce0000001",
        "Alice Desktop",
    )
    .await;
    let alice_phone = dev_token(
        state.clone(),
        "did:web:alice.example",
        "cx:device:01904100-0000-7000-8000-a11ce0000002",
        "Alice Phone",
    )
    .await;
    let bob = dev_token(
        state.clone(),
        "did:web:bob.example",
        "cx:device:01904100-0000-7000-8000-b0b000000001",
        "Bob",
    )
    .await;
    let realm_a = create_plaintext_space(state.clone(), &alice_desktop, "Parent Realm").await;
    let realm_b = create_plaintext_space(state.clone(), &alice_desktop, "Discussion Realm").await;
    let event_a = "cx:event:01904100-0000-7000-8000-0000000000aa";
    let event_b = "cx:event:01904100-0000-7000-8000-0000000000bb";

    let marker_a: Value = TestClient::post("http://server/api/v1/read-markers")
        .add_header("authorization", format!("Bearer {alice_desktop}"), true)
        .json(&json!({
            "realm_id": realm_a,
            "event_id": event_a,
            "scope_id": "timeline"
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        marker_a["realm_id"], realm_a,
        "marker_a response: {marker_a}"
    );
    assert_eq!(
        marker_a["space_id"], realm_a,
        "marker_a response: {marker_a}"
    );

    let marker_b: Value = TestClient::post("http://server/api/v1/read-markers")
        .add_header("authorization", format!("Bearer {alice_desktop}"), true)
        .json(&json!({
            "realm_id": realm_b,
            "event_id": event_b,
            "scope_id": "timeline"
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        marker_b["realm_id"], realm_b,
        "marker_b response: {marker_b}"
    );

    let only_a: Value = TestClient::get(format!(
        "http://server/api/v1/read-markers?realm_id={realm_a}"
    ))
    .add_header("authorization", format!("Bearer {alice_desktop}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let markers_a = only_a["markers"].as_array().unwrap();
    assert_eq!(markers_a.len(), 1);
    assert_eq!(markers_a[0]["event_id"], event_a);
    assert_eq!(markers_a[0]["realm_id"], realm_a);

    let only_b: Value = TestClient::get(format!(
        "http://server/api/v1/read-markers?space_id={realm_b}"
    ))
    .add_header("authorization", format!("Bearer {alice_desktop}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let markers_b = only_b["markers"].as_array().unwrap();
    assert_eq!(markers_b.len(), 1);
    assert_eq!(markers_b[0]["event_id"], event_b);
    assert_eq!(markers_b[0]["realm_id"], realm_b);

    let phone_messages: Value = TestClient::get("http://server/api/v1/device_messages")
        .add_header("authorization", format!("Bearer {alice_phone}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let read_marker_fanouts = phone_messages["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["content"]["type"] == "cx.read_marker.update")
        .collect::<Vec<_>>();
    assert_eq!(read_marker_fanouts.len(), 2);
    assert!(read_marker_fanouts.iter().any(|event| {
        event["content"]["content"]["realm_id"] == realm_a
            && event["content"]["content"]["event_id"] == event_a
    }));
    assert!(read_marker_fanouts.iter().any(|event| {
        event["content"]["content"]["realm_id"] == realm_b
            && event["content"]["content"]["event_id"] == event_b
    }));

    let bob_markers: Value = TestClient::get("http://server/api/v1/read-markers")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(bob_markers["markers"].as_array().unwrap().is_empty());
    let bob_messages: Value = TestClient::get("http://server/api/v1/device_messages")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(bob_messages["events"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn push_blind_wakeup_rejects_e2ee_stable_identifiers() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(
        state.clone(),
        "did:web:alice.example",
        "cx:device:01904100-0000-7000-8000-a11ce0000001",
        "Alice Desktop",
    )
    .await;
    let registered: Value = TestClient::post("http://server/api/v1/push/register-device")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
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
    assert_eq!(registered["ok"], true);

    let rejected = TestClient::post("http://server/api/v1/push/notify")
        .json(&json!({
            "notification": {
                "type": "blind_wakeup",
                "event_id": "cx:event:01904100-0000-7000-8000-0000000000ee",
                "realm_id": "cx:space:0190419b-0000-7000-8000-0000000000ee",
                "sender": "did:web:bob.example",
                "devices": [{"device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001"}]
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(rejected.status_code, Some(StatusCode::BAD_REQUEST));

    let accepted: Value = TestClient::post("http://server/api/v1/push/notify")
        .json(&json!({
            "notification": {
                "type": "blind_wakeup",
                "wakeup_kind": "message",
                "devices": [{"device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001"}]
            }
        }))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(accepted["rejected"].as_array().unwrap().is_empty());
}
