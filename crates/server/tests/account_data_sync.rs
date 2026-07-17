use std::sync::atomic::{AtomicU64, Ordering};

use arkret_sdk::{Did, RealmId};
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use soland::config::{AppConfig, ObjectStorageConfig};
use soland::service;
use soland::state::{AppState, RealmDirectoryEntry};
use soland_storage::RealmMetaRecord;
use soland_storage_postgres::Db;

static TEST_EVENT_SEQ: AtomicU64 = AtomicU64::new(2_000);

fn test_config() -> AppConfig {
    AppConfig {
        object_storage: ObjectStorageConfig::local(
            std::env::temp_dir().join("soland-account-data-sync-blobs"),
        ),
        development_mode: true,
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: std::collections::BTreeMap::new(),
        ..AppConfig::test_default()
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
    login["session_credential"]
        .as_str()
        .unwrap_or_else(|| panic!("dev-login response missing session_credential: {login}"))
        .to_owned()
}

async fn account_subscribe_frame(state: AppState, token: &str, query: &str) -> Value {
    let url = if query.is_empty() {
        "http://server/_arkret/self/account/subscribe".to_owned()
    } else {
        format!("http://server/_arkret/self/account/subscribe?{query}")
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
    let realm_id = arkret_sdk::new_prefixed_uuid7("ak:realm:");
    let typed_realm_id = RealmId::new(realm_id.clone()).unwrap();
    let owner = Did::new("did:web:alice.example".to_owned()).unwrap();
    let now = chrono::Utc::now();

    let mut entry = RealmDirectoryEntry::new(typed_realm_id, title);
    entry.description = Some("G3.S6 account-private sync fixture".to_owned());
    entry.members.insert(owner);
    state.realms.lock().upsert(entry);
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
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: None,
                plaintext_visible_services: std::collections::BTreeSet::from([
                    "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service".to_owned(),
                ]),
                plaintext_visible_service_classes: std::collections::BTreeMap::from([(
                    "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service".to_owned(),
                    std::collections::BTreeSet::from([
                        arkret_sdk::PlaintextDataClassKind::MessageContent,
                    ]),
                )]),
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
    let mut realms = state.realms.lock();
    let entry = realms
        .get(&typed_realm_id)
        .cloned()
        .expect("seeded test realm exists before member add");
    let mut updated = entry;
    updated.members.insert(member_did);
    assert!(updated.members.iter().any(|did| did.as_str() == member));
    realms.upsert(updated);
}

fn signed_actor_private_event_envelope(
    actor: &str,
    device_id: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
) -> Value {
    let now = chrono::Utc::now();
    let created_at = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut event = json!({
        "event_id": arkret_sdk::new_prefixed_uuid7("ak:event:"),
        "kind": kind,
        "realm_id": realm_id,
        "actor_id": actor,
        "actor_seq": TEST_EVENT_SEQ.fetch_add(1, Ordering::Relaxed),
        "created_at": created_at,
        "hlc": format!("{:012x}-0000-00000000", now.timestamp_millis().max(0) as u64),
        "prev_refs": [],
        "refs": [],
        "payload": payload,
        "proofs": []
    });
    let event_digest = event_canonical_digest(&event);
    event["proofs"] = json!([{
        "kind": "detached_jws",
        "alg": "EdDSA",
        "verification_method": format!("{actor}#{device_id}"),
        "event_digest": event_digest,
        "created_at": created_at,
        "jws": "dev-mode-fixture"
    }]);
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
    TestClient::post("http://server/_arkret/self/events")
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
        .find(|entry| entry["payload"]["key"] == key)
}

fn read_cursor_payload(
    actor: &str,
    device_id: &str,
    realm_id: &str,
    event_id: &str,
    hlc: &str,
) -> Value {
    json!({
        "id": arkret_sdk::new_prefixed_uuid7("ak:read_cursor:"),
        "schema": "ak.schema.read_cursor.v1",
        "actor_id": actor,
        "device_id": device_id,
        "realm_id": realm_id,
        "read_scope": {
            "kind": "strand",
            "container_ref": strand_id_for_realm(realm_id),
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
    let projection = state.projection.lock();
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

fn event_canonical_digest(event: &Value) -> String {
    let mut canonical = event.clone();
    if let Value::Object(object) = &mut canonical {
        object.remove("proofs");
        object.remove("unsigned");
        object.remove("canonical_digest");
        object.remove("canonical_hash");
    }
    let bytes =
        arkret_sdk::canonical::canonical_json_bytes(&canonical).expect("json canonicalizes");
    arkret_sdk::canonical::sha256_digest(&bytes)
}

fn encrypted_account_data_value(actor_id: &str, data_type: &str, plaintext: &Value) -> Value {
    serde_json::to_value(
        arkret_sdk::account_data_crypto::seal_account_data_value_with_nonce(
            &[7u8; 32], actor_id, data_type, plaintext, [9u8; 24],
        )
        .unwrap(),
    )
    .unwrap()
}

fn strand_id_for_realm(realm_id: &str) -> String {
    realm_id
        .strip_prefix("ak:realm:")
        .map(|suffix| format!("ak:strand:{suffix}"))
        .unwrap_or_else(|| "ak:strand:01904100-0000-7000-8000-f10dc0000001".to_owned())
}

#[tokio::test]
async fn blocklist_account_data_requires_encrypted_carrier_and_fans_out_opaque() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice_desktop = dev_token(
        state.clone(),
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        "Alice Desktop",
    )
    .await;
    let alice_phone = dev_token(
        state.clone(),
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-a11ce0000002",
        "Alice Phone",
    )
    .await;
    let bob = dev_token(
        state.clone(),
        "did:web:bob.example",
        "ak:device:01904100-0000-7000-8000-b0b000000001",
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

    let plaintext_blocklist = json!({
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
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        &realm_id,
        "ak.account_data.set",
        json!({
            "key": "ak.account.blocklist",
            "owner": "did:web:alice.example",
            "body": plaintext_blocklist,
            "updated_at": "2026-05-21T00:00:00Z",
        }),
    )
    .await;
    assert_ne!(
        put["status"], "accepted",
        "plaintext blocklist must be rejected: {put}"
    );

    let encrypted_blocklist = encrypted_account_data_value(
        "did:web:alice.example",
        "ak.account.blocklist",
        &plaintext_blocklist,
    );
    let put = submit_actor_private_event(
        state.clone(),
        &alice_desktop,
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        &realm_id,
        "ak.account_data.set",
        json!({
            "key": "ak.account.blocklist",
            "owner": "did:web:alice.example",
            "body": encrypted_blocklist.clone(),
            "updated_at": "2026-05-21T00:00:00Z",
        }),
    )
    .await;
    assert_eq!(
        put["status"], "accepted",
        "encrypted blocklist event: {put}"
    );
    let stored_account_data = state
        .persistence
        .account_data()
        .list_for_actor("did:web:alice.example")
        .await
        .unwrap();
    assert!(
        stored_account_data
            .iter()
            .any(|record| record.data_type == "ak.account.blocklist"),
        "account_data projection must persist encrypted blocklist after accepted event: {stored_account_data:?}"
    );

    let phone_sync = account_subscribe_frame(
        state.clone(),
        &alice_phone,
        "catchup=true&set_presence=online",
    )
    .await;
    let phone_account_data = account_data_entry(&phone_sync, "ak.account.blocklist")
        .expect("blocklist account_data visible to Alice's sibling device");
    assert_eq!(phone_account_data["payload"]["body"], encrypted_blocklist);

    let phone_messages: Value = TestClient::get("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {alice_phone}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let phone_events = phone_messages["messages"].as_array().unwrap();
    let blocklist_event = phone_events
        .iter()
        .find(|event| event["kind"] == "ak.account.blocklist.update")
        .expect("blocklist update fanout reaches Alice's sibling device");
    assert_eq!(
        blocklist_event["content"]["data_type"],
        "ak.account.blocklist"
    );
    assert_eq!(blocklist_event["content"]["content"], encrypted_blocklist);

    let bob_messages: Value = TestClient::get("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(bob_messages["messages"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn read_cursor_fans_out_per_realm_without_cross_actor_leakage() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice_desktop = dev_token(
        state.clone(),
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        "Alice Desktop",
    )
    .await;
    let alice_phone = dev_token(
        state.clone(),
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-a11ce0000002",
        "Alice Phone",
    )
    .await;
    let bob = dev_token(
        state.clone(),
        "did:web:bob.example",
        "ak:device:01904100-0000-7000-8000-b0b000000001",
        "Bob",
    )
    .await;
    let realm_a = create_plaintext_realm(state.clone(), &alice_desktop, "Parent Realm").await;
    let realm_b = create_plaintext_realm(state.clone(), &alice_desktop, "Discussion Realm").await;
    let event_a = "ak:event:01904100-0000-7000-8000-0000000000aa";
    let event_b = "ak:event:01904100-0000-7000-8000-0000000000bb";

    let marker_a = submit_actor_private_event(
        state.clone(),
        &alice_desktop,
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        &realm_a,
        "ak.read_cursor.advance",
        read_cursor_payload(
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-a11ce0000001",
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
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        &realm_b,
        "ak.read_cursor.advance",
        read_cursor_payload(
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-a11ce0000001",
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

    let phone_messages: Value = TestClient::get("http://server/_arkret/self/device_messages")
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
        .filter(|event| event["kind"] == "ak.read_cursor.update")
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
    let bob_messages: Value = TestClient::get("http://server/_arkret/self/device_messages")
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
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        "Alice Desktop",
    )
    .await;
    let registered: Value = TestClient::post("http://server/_arkret/edge/push/register-device")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001",
            "push_gateway": "https://push.example",
            "push_key": "opaque",
            "platform": "desktop",
            "app_id": "inkson"
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(registered["ok"], true);
    let push_target_id = registered["registration_id"]
        .as_str()
        .expect("register-device returns push target registration id");

    let rejected = TestClient::post("http://server/_arkret/edge/push/notify")
        .json(&json!({
            "notification": {
                "push_target_id": push_target_id,
                "wakeup_kind": "message",
                "event_id": "ak:event:01904100-0000-7000-8000-0000000000ee",
                "realm_id": "ak:realm:0190419b-0000-7000-8000-0000000000ee",
                "sender_actor_id": "did:web:bob.example",
                "devices": [{"device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001"}]
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(rejected.status_code, Some(StatusCode::BAD_REQUEST));

    let accepted: Value = TestClient::post("http://server/_arkret/edge/push/notify")
        .json(&json!({
            "notification": {
                "push_target_id": push_target_id,
                "wakeup_kind": "message",
                "devices": [{"device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001"}]
            }
        }))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(accepted["rejected"].as_array().unwrap().is_empty());
}
