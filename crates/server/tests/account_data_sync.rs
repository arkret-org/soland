use std::sync::atomic::{AtomicU64, Ordering};

use cokret_sdk::{Did, RealmId};
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use soland::config::{AppConfig, ObjectStorageConfig};
use soland::db::Db;
use soland::service;
use soland::state::{AppState, RealmDirectoryEntry, RealmMetaRecord};

static TEST_EVENT_SEQ: AtomicU64 = AtomicU64::new(2_000);

fn test_config() -> AppConfig {
    AppConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        metrics_bind: "127.0.0.1:0".parse().unwrap(),
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
        notary_signing_key_seed: None,
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
        resumable_upload_dir: std::path::PathBuf::from("./soland-resumable-uploads"),
        resumable_upload_incomplete_ttl_seconds: 86_400,
        seal_compaction_min_age_seconds: 604_800,
        compaction_min_witnesses: 1,
        compaction_preserve_genesis: true,
        compaction_prune_only_singleton_successors: true,
        compaction_prune_walk_interval_seconds: 0,
        compaction_prune_walk_per_realm_limit: 50,
        seed_demo_data: false,
        trust_domain: "ck:trust_domain:soland.local".to_owned(),
        sovereign_enclave_enabled: false,
        sovereign_enclave_allowed_outbound_hosts: Vec::new(),
        erasure_propagation_window_ms: 604_800_000,
        log_format: soland::config::LogFormat::Plain,
    }
}

fn app_from_state(state: AppState) -> salvo::Service {
    service(state)
}

async fn dev_token(state: AppState, actor: &str, device_id: &str, display_name: &str) -> String {
    let mut response = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&json!({
            "actor": actor,
            "device_id": device_id,
            "display_name": display_name,
        }))
        .send(&app_from_state(state))
        .await;
    let status = response.status_code;
    let login: Value = response
        .take_json()
        .await
        .unwrap_or_else(|error| panic!("dev-login did not return JSON: {error:?}"));
    assert_eq!(
        status,
        Some(StatusCode::OK),
        "dev-login failed for {actor} / {device_id}: {login}"
    );
    login["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("dev-login response missing access_token: {login}"))
        .to_owned()
}

async fn account_subscribe_frame(state: AppState, token: &str, query: &str) -> Value {
    let url = if query.is_empty() {
        "http://server/_cokret/self/account/subscribe".to_owned()
    } else {
        format!("http://server/_cokret/self/account/subscribe?{query}")
    };
    let body = TestClient::get(url)
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state))
        .await
        .take_string()
        .await
        .unwrap();
    serde_json::from_str(body.lines().next().unwrap()).unwrap()
}

async fn create_plaintext_realm(state: AppState, _token: &str, title: &str) -> String {
    let realm_id = cokret_sdk::new_prefixed_uuid7("ck:realm:");
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
                history_sharing_policy: None,
                history_sharing_policy_digest: None,
                preview_policy: None,
                preview_policy_digest: None,
                encryption_profile: None,
                plaintext_visible_services: std::collections::BTreeSet::from([
                    "did:web:soland.local".to_owned(),
                ]),
                minimal_metadata_realm: false,
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .unwrap();
    realm_id
}

async fn add_realm_member(state: AppState, _token: &str, realm_id: &str, member: &str) {
    let typed_realm_id = RealmId::new(realm_id.to_owned()).unwrap();
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
    realm_id: &str,
    body: &str,
) -> Value {
    let payload = json!({
        "flow_id": flow_id_for_realm(realm_id),
        "track_name": "discussion",
        "content": {"kind": "ck.content.text", "body": body}
    });
    let mut event = json!({
        "event_id": cokret_sdk::new_prefixed_uuid7("ck:event:"),
        "kind": "ck.message.create",
        "schema_id": "ck.schema.message.v1",
        "actor_id": actor,
        "actor_seq": TEST_EVENT_SEQ.fetch_add(1, Ordering::Relaxed),
        "realm_id": realm_id,
        "device_id": "ck:device:01904100-0000-7000-8000-b0b000000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": [],
        "auth_refs": [],
        "payload": payload,
        "proofs": [{
            "type": "dev-proof",
            "verification_method": format!("{actor}#01904100-0000-7000-8000-b0b000000001"),
            "device_id": "ck:device:01904100-0000-7000-8000-b0b000000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload)
        }]
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));
    let mut response: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&event)
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    if response["event_id"].is_null()
        && let Some(event_id) = response["accepted"]
            .as_array()
            .and_then(|events| events.first())
    {
        response["event_id"] = event_id.clone();
    }
    assert!(
        response["event_id"].is_string(),
        "message event submit must return event_id, got {response}"
    );
    response
}

fn signed_actor_private_event_envelope(
    actor: &str,
    device_id: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
) -> Value {
    let mut event = json!({
        "event_id": cokret_sdk::new_prefixed_uuid7("ck:event:"),
        "kind": kind,
        "schema_id": "ck.schema.event.v1",
        "actor_id": actor,
        "actor_seq": TEST_EVENT_SEQ.fetch_add(1, Ordering::Relaxed),
        "realm_id": realm_id,
        "device_id": device_id,
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": [],
        "auth_refs": [],
        "payload": payload,
        "proofs": [{
            "type": "dev-proof",
            "verification_method": format!("{actor}#{device_id}"),
            "device_id": device_id,
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload)
        }]
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));
    event
}

async fn submit_actor_private_event(
    state: AppState,
    token: &str,
    actor: &str,
    device_id: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
) -> Value {
    let event = signed_actor_private_event_envelope(actor, device_id, realm_id, kind, payload);
    TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&event)
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap()
}

fn account_data_entry<'a>(sync: &'a Value, key: &str) -> Option<&'a Value> {
    sync["account_data"]["events"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|entry| entry["data_type"] == key)
}

fn read_cursor_payload(
    actor: &str,
    device_id: &str,
    realm_id: &str,
    event_id: &str,
    hlc: &str,
) -> Value {
    json!({
        "id": cokret_sdk::new_prefixed_uuid7("ck:read_cursor:"),
        "schema": "ck.schema.read_cursor.v1",
        "actor_id": actor,
        "device_id": device_id,
        "realm_id": realm_id,
        "read_scope": {
            "kind": "flow",
            "ref": flow_id_for_realm(realm_id),
            "track_name": "discussion"
        },
        "position": {
            "event_id": event_id,
            "hlc": hlc
        },
        "updated_at": "2026-05-21T00:00:00Z",
    })
}

fn projected_read_markers(state: &AppState, actor: &str, realm_id: Option<&str>) -> Vec<Value> {
    let projection = state.projection.lock().expect("projection lock");
    projection
        .read_cursors
        .values()
        .filter(|marker| {
            marker.actor_id == actor && realm_id.is_none_or(|realm_id| marker.realm_id == realm_id)
        })
        .map(|marker| {
            json!({
                "realm_id": marker.realm_id.clone(),
                "actor_id": marker.actor_id.clone(),
                "device_id": marker.device_id.clone(),
                "read_scope": marker.read_scope.clone(),
                "position": marker.position.clone(),
                "updated_at": marker.updated_at.to_rfc3339(),
            })
        })
        .collect()
}

fn sha256_json(value: &Value) -> String {
    let bytes = cokret_sdk::canonical::canonical_json_bytes(value).expect("json canonicalizes");
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
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
        .strip_prefix("ck:realm:")
        .map(|suffix| format!("ck:flow:{suffix}"))
        .unwrap_or_else(|| "ck:flow:01904100-0000-7000-8000-f10dc0000001".to_owned())
}

#[tokio::test]
async fn blocklist_account_data_fans_out_and_filters_notifications() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice_desktop = dev_token(
        state.clone(),
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-a11ce0000001",
        "Alice Desktop",
    )
    .await;
    let alice_phone = dev_token(
        state.clone(),
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-a11ce0000002",
        "Alice Phone",
    )
    .await;
    let bob = dev_token(
        state.clone(),
        "did:web:bob.example",
        "ck:device:01904100-0000-7000-8000-b0b000000001",
        "Bob",
    )
    .await;
    let realm_id = create_plaintext_realm(state.clone(), &alice_desktop, "Blocklist Fixture").await;
    add_realm_member(
        state.clone(),
        &alice_desktop,
        &realm_id,
        "did:web:bob.example",
    )
    .await;

    let blocklist = json!({
        "version": 1,
        "entries": [{
            "target": {
                "kind": "actor",
                "did": "did:web:bob.example"
            },
            "mode": "block",
            "applies_to": ["messages", "mentions", "notifications"],
            "created_at": "2026-05-21T00:00:00Z"
        }]
    });
    let put = submit_actor_private_event(
        state.clone(),
        &alice_desktop,
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-a11ce0000001",
        &realm_id,
        "ck.account_data.set",
        json!({
            "key": "ck.account.blocklist.v1",
            "owner": "did:web:alice.example",
            "body": blocklist.clone(),
            "updated_at": "2026-05-21T00:00:00Z",
        }),
    )
    .await;
    assert_eq!(put["status"], "accepted", "account_data event: {put}");
    let stored_account_data = state
        .persistence
        .account_data()
        .list_for_actor("did:web:alice.example")
        .await
        .unwrap();
    assert!(
        stored_account_data
            .iter()
            .any(|record| record.data_type == "ck.account.blocklist.v1"),
        "account_data projection must persist blocklist after accepted event: {stored_account_data:?}"
    );

    let phone_sync = account_subscribe_frame(
        state.clone(),
        &alice_phone,
        "catchup=true&set_presence=online",
    )
    .await;
    let phone_account_data = account_data_entry(&phone_sync, "ck.account.blocklist.v1")
        .expect("blocklist account_data visible to Alice's sibling device");
    assert_eq!(phone_account_data["content"], blocklist);

    let phone_messages: Value = TestClient::get("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {alice_phone}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let phone_events = phone_messages["messages"].as_array().unwrap();
    let blocklist_event = phone_events
        .iter()
        .find(|event| event["kind"] == "ck.account.blocklist.update")
        .expect("blocklist update fanout reaches Alice's sibling device");
    assert_eq!(
        blocklist_event["content"]["data_type"],
        "ck.account.blocklist.v1"
    );
    assert_eq!(
        blocklist_event["content"]["content"]["entries"][0]["target"]["did"],
        "did:web:bob.example"
    );

    let bob_messages: Value = TestClient::get("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(bob_messages["messages"].as_array().unwrap().is_empty());

    let blocked_message = send_plaintext_message(
        state.clone(),
        &bob,
        "did:web:bob.example",
        &realm_id,
        "blocked notification",
    )
    .await;
    let notifications: Value = TestClient::get(
        "http://server/_soland/self/index/notifications?actor=did:web:alice.example",
    )
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

    let unblock = submit_actor_private_event(
        state.clone(),
        &alice_desktop,
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-a11ce0000001",
        &realm_id,
        "ck.account_data.set",
        json!({
            "key": "ck.account.blocklist.v1",
            "owner": "did:web:alice.example",
            "body": {"version": 1, "entries": []},
            "updated_at": "2026-05-21T00:01:00Z",
        }),
    )
    .await;
    assert_eq!(unblock["status"], "accepted", "unblock event: {unblock}");

    let visible_message = send_plaintext_message(
        state.clone(),
        &bob,
        "did:web:bob.example",
        &realm_id,
        "visible notification",
    )
    .await;
    let notifications_after: Value = TestClient::get(
        "http://server/_soland/self/index/notifications?actor=did:web:alice.example",
    )
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
async fn read_cursor_fans_out_per_realm_without_cross_actor_leakage() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice_desktop = dev_token(
        state.clone(),
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-a11ce0000001",
        "Alice Desktop",
    )
    .await;
    let alice_phone = dev_token(
        state.clone(),
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-a11ce0000002",
        "Alice Phone",
    )
    .await;
    let bob = dev_token(
        state.clone(),
        "did:web:bob.example",
        "ck:device:01904100-0000-7000-8000-b0b000000001",
        "Bob",
    )
    .await;
    let realm_a = create_plaintext_realm(state.clone(), &alice_desktop, "Parent Realm").await;
    let realm_b = create_plaintext_realm(state.clone(), &alice_desktop, "Discussion Realm").await;
    let event_a = "ck:event:01904100-0000-7000-8000-0000000000aa";
    let event_b = "ck:event:01904100-0000-7000-8000-0000000000bb";

    let marker_a = submit_actor_private_event(
        state.clone(),
        &alice_desktop,
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-a11ce0000001",
        &realm_a,
        "ck.read_cursor.advance",
        read_cursor_payload(
            "did:web:alice.example",
            "ck:device:01904100-0000-7000-8000-a11ce0000001",
            &realm_a,
            event_a,
            "019041000000-0001-a11ce001",
        ),
    )
    .await;
    assert_eq!(
        marker_a["status"], "accepted",
        "marker_a response: {marker_a}"
    );

    let marker_b = submit_actor_private_event(
        state.clone(),
        &alice_desktop,
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-a11ce0000001",
        &realm_b,
        "ck.read_cursor.advance",
        read_cursor_payload(
            "did:web:alice.example",
            "ck:device:01904100-0000-7000-8000-a11ce0000001",
            &realm_b,
            event_b,
            "019041000000-0001-a11ce002",
        ),
    )
    .await;
    assert_eq!(
        marker_b["status"], "accepted",
        "marker_b response: {marker_b}"
    );

    let markers_a = projected_read_markers(&state, "did:web:alice.example", Some(&realm_a));
    assert_eq!(markers_a.len(), 1);
    assert_eq!(markers_a[0]["position"]["event_id"], event_a);
    assert_eq!(markers_a[0]["realm_id"], realm_a);
    assert_eq!(markers_a[0]["read_scope"]["track_name"], "discussion");

    let markers_b = projected_read_markers(&state, "did:web:alice.example", Some(&realm_b));
    assert_eq!(markers_b.len(), 1);
    assert_eq!(markers_b[0]["position"]["event_id"], event_b);
    assert_eq!(markers_b[0]["realm_id"], realm_b);

    let phone_messages: Value = TestClient::get("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {alice_phone}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let read_cursor_fanouts = phone_messages["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["kind"] == "ck.read_cursor.update")
        .collect::<Vec<_>>();
    assert_eq!(read_cursor_fanouts.len(), 2);
    assert!(read_cursor_fanouts.iter().any(|event| {
        event["content"]["realm_id"] == realm_a
            && event["content"]["position"]["event_id"] == event_a
    }));
    assert!(read_cursor_fanouts.iter().any(|event| {
        event["content"]["realm_id"] == realm_b
            && event["content"]["position"]["event_id"] == event_b
    }));

    let bob_markers = projected_read_markers(&state, "did:web:bob.example", None);
    assert!(bob_markers.is_empty());
    let bob_messages: Value = TestClient::get("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(bob_messages["messages"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn push_blind_wakeup_rejects_e2ee_stable_identifiers() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(
        state.clone(),
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-a11ce0000001",
        "Alice Desktop",
    )
    .await;
    let registered: Value = TestClient::post("http://server/_cokret/edge/push/register-device")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
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
    assert_eq!(registered["ok"], true);

    let rejected = TestClient::post("http://server/_cokret/edge/push/notify")
        .json(&json!({
            "notification": {
                "type": "blind_wakeup",
                "event_id": "ck:event:01904100-0000-7000-8000-0000000000ee",
                "realm_id": "ck:realm:0190419b-0000-7000-8000-0000000000ee",
                "sender": "did:web:bob.example",
                "devices": [{"device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001"}]
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(rejected.status_code, Some(StatusCode::BAD_REQUEST));

    let accepted: Value = TestClient::post("http://server/_cokret/edge/push/notify")
        .json(&json!({
            "notification": {
                "type": "blind_wakeup",
                "wakeup_kind": "message",
                "devices": [{"device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001"}]
            }
        }))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(accepted["rejected"].as_array().unwrap().is_empty());
}
