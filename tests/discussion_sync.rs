use contrix_sdk::{Did, RealmId, new_prefixed_uuid7};
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use soland::config::{AppConfig, ObjectStorageConfig};
use soland::db::Db;
use soland::service;
use soland::state::{AppState, RealmDirectoryEntry, RealmMetaRecord};
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_EVENT_SEQ: AtomicU64 = AtomicU64::new(1_000);

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

fn app_from_state(state: AppState) -> salvo::Service {
    service(state)
}

async fn account_subscribe_frame(state: AppState, token: &str, query: &str) -> Value {
    let body = TestClient::get(format!("http://server/api/v1/account/subscribe?{query}"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state))
        .await
        .take_string()
        .await
        .unwrap();
    serde_json::from_str(body.lines().next().unwrap()).unwrap()
}

async fn dev_token(state: AppState, actor: &str, device_suffix: &str) -> String {
    let login: Value = TestClient::post("http://server/api/v1/auth/dev-login")
        .json(&json!({
            "actor": actor,
            "device_id": format!("cx:device:01904100-0000-7000-8000-{device_suffix}"),
            "display_name": actor,
        }))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    login["access_token"].as_str().unwrap().to_owned()
}

/// Seed a Realm directly via AppState (the Realm REST mutation surface
/// `POST /api/v1/spaces` was removed in W2A; tests now set up Realm
/// fixtures internally and exercise downstream behaviour via the canonical
/// `POST /api/v1/events` path).
fn seed_realm(state: &AppState, owner: &str, title: &str, history_visibility: &str) -> String {
    let realm_id = new_prefixed_uuid7("cx:realm:");
    let typed_realm_id = RealmId::new(realm_id.clone()).unwrap();
    let owner_did = Did::new(owner.to_owned()).unwrap();
    let now = chrono::Utc::now();

    let mut entry = RealmDirectoryEntry::new(typed_realm_id, title);
    entry.description = Some("history visibility fixture".to_owned());
    entry.public = true;
    entry.members.insert(owner_did);
    state.realms.lock().unwrap().upsert(entry);

    state
        .persistence
        .realm_meta()
        .put(
            &realm_id,
            &RealmMetaRecord {
                owner: owner.to_owned(),
                deleted: false,
                discoverability: "public".to_owned(),
                history_visibility: history_visibility.to_owned(),
                encryption_profile: None,
                plaintext_visible_services: std::collections::BTreeSet::new(),
                created_at: now,
                updated_at: now,
            },
        )
        .unwrap();

    realm_id
}

/// Have the owner admit a new member by submitting a
/// `cx.member.state{membership:"join", actor_id: new_member}` event. The
/// projection layer records `member.joined_at` (used by sync's
/// history_visibility gate) and updates `state.realms.members` via
/// `project_member_state`. The owner is already a member (seeded by
/// `seed_realm`), so the event-log preflight `realm_has_member` check
/// admits the event.
async fn admit_member(
    state: AppState,
    owner_token: &str,
    owner_did: &str,
    owner_device_id: &str,
    new_member_did: &str,
    realm_id: &str,
) {
    let payload = json!({
        "actor_id": new_member_did,
        "membership": "join",
        "role": "member",
        "delivery_status": "unroutable",
    });
    let mut event = json!({
        "event_id": new_prefixed_uuid7("cx:event:"),
        "kind": "cx.member.state",
        "schema_id": "cx.schema.event.v1",
        "actor_id": owner_did,
        "actor_seq": TEST_EVENT_SEQ.fetch_add(1, Ordering::Relaxed),
        "realm_id": realm_id,
        "device_id": owner_device_id,
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": [],
        "auth_refs": [],
        "refs": [],
        "payload": payload,
        "proofs": [{
            "type": "dev-proof",
            "verification_method": format!("{owner_did}#{owner_device_id}"),
            "device_id": owner_device_id,
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_hash": sha256_json(&payload)
        }]
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));
    let resp: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {owner_token}"), true)
        .json(&event)
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        resp["event_id"].is_string(),
        "cx.member.state{{join}} admit failed: {resp:?}"
    );
}

async fn send_message(state: AppState, token: &str, space_id: &str, body: &str) {
    let payload = json!({
        "flow_id": flow_id_for_realm(space_id),
        "track": "discussion",
        "thread_id": space_id,
        "content": {
            "kind": "cx.content.text",
            "body": body,
            "format": "plain"
        },
        "encrypted": false,
    });
    let mut event = json!({
        "event_id": new_prefixed_uuid7("cx:event:"),
        "kind": "cx.message.create",
        "schema_id": "cx.schema.message.v1",
        "actor_id": "did:web:alice.example",
        "actor_seq": TEST_EVENT_SEQ.fetch_add(1, Ordering::Relaxed),
        "realm_id": space_id,
        "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": [],
        "auth_refs": [],
        "payload": payload,
        "proofs": [{
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#01904100-0000-7000-8000-a11ce0000001",
            "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_hash": sha256_json(&payload)
        }]
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));
    let sent: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&event)
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(sent["event_id"].is_string(), "send failed: {sent:?}");
}

fn sha256_json(value: &Value) -> String {
    let bytes = contrix_sdk::canonical::canonical_json_bytes(value).expect("json canonicalizes");
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn flow_id_for_realm(realm_id: &str) -> String {
    realm_id
        .strip_prefix("cx:realm:")
        .map(|suffix| format!("cx:flow:{suffix}"))
        .unwrap_or_else(|| "cx:flow:01904100-0000-7000-8000-f10dc0000001".to_owned())
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

fn sync_bodies(sync: &Value, space_id: &str) -> Vec<String> {
    sync["realms"]["join"][space_id]["timeline"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|event| event["content"]["body"].as_str().map(ToOwned::to_owned))
        .collect()
}

fn event_query_bodies(events: &Value) -> Vec<String> {
    events["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|event| {
            event["payload"]["content"]["body"]
                .as_str()
                .map(ToOwned::to_owned)
        })
        .collect()
}

#[tokio::test]
async fn joined_history_hides_pre_join_messages_from_sync_and_events_query() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice_did = "did:web:alice.example";
    let alice_device_id = "cx:device:01904100-0000-7000-8000-a11ce0000001";
    let alice = dev_token(state.clone(), alice_did, "a11ce0000001").await;
    let bob_did = "did:web:bob.example";
    let _bob_session_device = dev_token(state.clone(), bob_did, "b0b000000000").await;
    let bob = _bob_session_device;
    let space_id = seed_realm(&state, alice_did, "joined history", "joined");

    send_message(state.clone(), &alice, &space_id, "before bob joined").await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    admit_member(
        state.clone(),
        &alice,
        alice_did,
        alice_device_id,
        bob_did,
        &space_id,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    send_message(state.clone(), &alice, &space_id, "after bob joined").await;

    let sync = account_subscribe_frame(state.clone(), &bob, "catchup=true").await;
    let bodies = sync_bodies(&sync, &space_id);
    assert!(
        !bodies.contains(&"before bob joined".to_owned()),
        "{bodies:?}"
    );
    assert!(
        bodies.contains(&"after bob joined".to_owned()),
        "{bodies:?}"
    );

    let events: Value = TestClient::get(format!(
        "http://server/api/v1/events?realms={space_id}&limit=20"
    ))
    .add_header("authorization", format!("Bearer {bob}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let bodies = event_query_bodies(&events);
    assert!(
        !bodies.contains(&"before bob joined".to_owned()),
        "{bodies:?}"
    );
    assert!(
        bodies.contains(&"after bob joined".to_owned()),
        "{bodies:?}"
    );
}

#[tokio::test]
async fn shared_history_allows_late_joiner_to_backfill_prior_messages() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice_did = "did:web:alice.example";
    let alice_device_id = "cx:device:01904100-0000-7000-8000-a11ce0000001";
    let alice = dev_token(state.clone(), alice_did, "a11ce0000001").await;
    let bob_did = "did:web:bob.example";
    let bob = dev_token(state.clone(), bob_did, "b0b000000002").await;
    let space_id = seed_realm(&state, alice_did, "shared history", "shared");

    send_message(state.clone(), &alice, &space_id, "shared before join").await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    admit_member(
        state.clone(),
        &alice,
        alice_did,
        alice_device_id,
        bob_did,
        &space_id,
    )
    .await;

    let sync = account_subscribe_frame(state.clone(), &bob, "catchup=true").await;
    assert!(
        sync_bodies(&sync, &space_id).contains(&"shared before join".to_owned()),
        "{sync:?}"
    );

    let events: Value = TestClient::get(format!(
        "http://server/api/v1/events?realms={space_id}&limit=20"
    ))
    .add_header("authorization", format!("Bearer {bob}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert!(
        event_query_bodies(&events).contains(&"shared before join".to_owned()),
        "{events:?}"
    );
}

#[test]
fn flow_update_records_discussion_realm_ref_and_rejects_orphans() {
    use contrix_sdk::{Operation, OperationId};
    use soland::hlc::ServerHlc;
    use soland::reducer::{ProjectionEffect, ProjectionState};

    const PARENT: &str = "cx:realm:01904100-0000-7000-8000-d11111111111";
    const CHILD: &str = "cx:realm:01904100-0000-7000-8000-d22222222222";
    const MISSING: &str = "cx:realm:01904100-0000-7000-8000-d33333333333";
    const FLOW: &str = "cx:flow:01904100-0000-7000-8000-f11111111111";

    fn op(kind: &str, realm_id: &str, payload: Value) -> Operation {
        Operation::create(
            OperationId::new(format!("cx:operation:{}", uuid::Uuid::now_v7())).unwrap(),
            RealmId::new(realm_id).unwrap(),
            kind,
            payload,
        )
    }

    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("discussion-route-test");
    for realm in [PARENT, CHILD] {
        state.apply(
            &op(
                soland::kinds::CX_REALM_CREATE,
                realm,
                json!({"action": "create", "owner": "did:web:alice.example", "public": true}),
            ),
            &hlc,
        );
    }
    state.apply(
        &op(
            soland::kinds::CX_FLOW_CREATE,
            PARENT,
            json!({"object": {"id": FLOW, "space_id": PARENT, "title": "Card"}}),
        ),
        &hlc,
    );

    let accepted = state.apply(
        &op(
            soland::kinds::CX_FLOW_UPDATE,
            PARENT,
            json!({"flow_id": FLOW, "patch": {"discussion_realm_ref": CHILD}}),
        ),
        &hlc,
    );
    assert!(matches!(accepted, ProjectionEffect::FlowLifecycle { .. }));
    assert_eq!(state.discussion_realm_for_flow(FLOW), Some(CHILD));
    assert_eq!(state.discussion_space_for_flow(FLOW, PARENT), CHILD);

    let rejected = state.apply(
        &op(
            soland::kinds::CX_FLOW_UPDATE,
            PARENT,
            json!({"flow_id": FLOW, "patch": {"discussion_realm_ref": MISSING}}),
        ),
        &hlc,
    );
    assert!(matches!(
        rejected,
        ProjectionEffect::Rejected { reason } if reason == "orphan_discussion_realm_ref"
    ));
}
