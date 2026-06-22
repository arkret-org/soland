use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};

use cokret_sdk::{Did, RealmId, new_prefixed_uuid7};
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use soland::config::{AppConfig, IceServersConfig, LiveKitConfig, ObjectStorageConfig};
use soland::db::Db;
use soland::reducer::{
    CircleLifecycleState, CircleMembershipState, CircleProjection, ObjectLifecycleState,
    StrandProjection,
};
use soland::service;
use soland::state::{AppState, RealmDirectoryEntry, RealmMetaRecord};

static TEST_EVENT_SEQ: AtomicU64 = AtomicU64::new(1_000);

fn test_config() -> AppConfig {
    AppConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        metrics_bind: "127.0.0.1:0".parse().unwrap(),
        public_base_url: "http://server".to_owned(),
        service_did: "did:web:soland.local".to_owned(),
        tls_cert_path: None,
        tls_key_path: None,
        database_url: None,
        object_storage: ObjectStorageConfig::local(std::env::temp_dir().join("soland-test-blobs")),
        ice: IceServersConfig::default(),
        livekit: LiveKitConfig::default(),
        cors_allow_origin: None,
        account_authority_url: None,
        oidc_client_id: None,
        development_mode: true,
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
        to_device_queue_capacity: 10_000,
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
        seed_demo_data: true,
        trust_domain: "ck:trust_domain:soland.local".to_owned(),
        receive_policy_constraints: None,
        sovereign_enclave_enabled: false,
        sovereign_enclave_allowed_outbound_hosts: Vec::new(),
        erasure_propagation_window_ms: 604_800_000,
        log_format: soland::config::LogFormat::Plain,
    }
}

fn app_from_state(state: AppState) -> salvo::Service {
    service(state)
}

async fn account_subscribe_frame(state: AppState, token: &str, query: &str) -> Value {
    let body = TestClient::get(format!(
        "http://server/_cokret/self/account/subscribe?{query}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state))
    .await
    .take_string()
    .await
    .unwrap();
    serde_json::from_str(body.lines().next().unwrap()).unwrap()
}

async fn dev_token(state: AppState, actor: &str, device_suffix: &str) -> String {
    let login: Value = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&json!({
            "actor": actor,
            "device_id": format!("ck:device:01904100-0000-7000-8000-{device_suffix}"),
            "display_name": actor,
        }))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    login["session_credential"].as_str().unwrap().to_owned()
}

/// Seed a Realm directly via AppState so the tests can focus on downstream
/// sync behaviour through the canonical `POST /_cokret/self/events` path.
async fn seed_realm(
    state: &AppState,
    owner: &str,
    title: &str,
    history_visibility: &str,
) -> String {
    let realm_id = new_prefixed_uuid7("ck:realm:");
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
                history_sharing_policy: None,
                history_sharing_policy_digest: None,
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: None,
                plaintext_visible_services: std::collections::BTreeSet::new(),
                minimal_metadata_realm: false,
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .unwrap();

    realm_id
}

/// Have the owner admit a new member by submitting a
/// `ck.member.state{membership:"join", actor_id: new_member}` event. The
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
        "realm_id": realm_id,
        "actor_id": new_member_did,
        "membership": "join",
        "delivery_status": "unroutable",
    });
    let mut event = json!({
        "event_id": new_prefixed_uuid7("ck:event:"),
        "kind": "ck.member.state",
        "schema_id": "ck.schema.event.v1",
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
            "payload_digest": sha256_json(&payload)
        }]
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));
    let resp: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {owner_token}"), true)
        .json(&event)
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        resp["accepted"][0].is_string(),
        "ck.member.state{{join}} admit failed: {resp:?}"
    );
}

async fn send_message(state: AppState, token: &str, realm_id: &str, body: &str) {
    let payload = json!({
        "strand_id": strand_id_for_realm(realm_id),
        "track_name": "discussion",
        "content": {
            "kind": "ck.content.text",
            "body": body,
            "format": "plain"
        }
    });
    let mut event = json!({
        "event_id": new_prefixed_uuid7("ck:event:"),
        "kind": "ck.message.create",
        "schema_id": "ck.schema.message.v1",
        "actor_id": "did:web:alice.example",
        "actor_seq": TEST_EVENT_SEQ.fetch_add(1, Ordering::Relaxed),
        "realm_id": realm_id,
        "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": [],
        "auth_refs": [],
        "payload": payload,
        "proofs": [{
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#01904100-0000-7000-8000-a11ce0000001",
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload)
        }]
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));
    let sent: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&event)
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(sent["accepted"][0].is_string(), "send failed: {sent:?}");
}

fn install_projected_circle_scope(
    state: &AppState,
    realm_id: &str,
    circle_id: &str,
    created_by: &str,
    members: &[&str],
) {
    let now = chrono::Utc::now();
    let members = members
        .iter()
        .map(|member| (*member).to_owned())
        .collect::<BTreeSet<_>>();
    state
        .projection
        .lock()
        .expect("projection mutex")
        .circles
        .insert(
            circle_id.to_owned(),
            CircleProjection {
                circle_id: circle_id.to_owned(),
                realm_id: realm_id.to_owned(),
                title: "Need to know".to_owned(),
                summary: None,
                directory_visibility: "members".to_owned(),
                join_rule: "invite".to_owned(),
                history_visibility: "joined".to_owned(),
                content_encryption_floor: Some("e2ee_required".to_owned()),
                metadata_encryption_floor: Some("e2ee_required".to_owned()),
                encryption_profile: "mls_rfc9420".to_owned(),
                mls_group_ref: Some(format!("ck:mls:mls_rfc9420:{circle_id}")),
                state: CircleLifecycleState::Active,
                state_changed_at: None,
                created_by: created_by.to_owned(),
                created_at: now,
                updated_by: None,
                updated_at: None,
                members,
            },
        );
    let mut projection = state.projection.lock().expect("projection mutex");
    for member in projection
        .circles
        .get(circle_id)
        .expect("circle projection inserted")
        .members
        .iter()
        .cloned()
        .collect::<Vec<_>>()
    {
        projection.circle_memberships.insert(
            (circle_id.to_owned(), member.clone()),
            CircleMembershipState {
                circle_id: circle_id.to_owned(),
                member,
                state: "join".to_owned(),
                invited_at: Some(now),
                joined_at: now,
                updated_at: now,
            },
        );
    }
}

/// CKP-0007 — bind a Strand to a Circle scope in the projection. A message
/// posted to this Strand inherits the Circle scope server-side (spec:
/// `scope_circle_id` is a Strand field, never carried on the message).
fn install_projected_strand_scope(
    state: &AppState,
    realm_id: &str,
    strand_id: &str,
    circle_id: &str,
    created_by: &str,
) {
    let now = chrono::Utc::now();
    state
        .projection
        .lock()
        .expect("projection mutex")
        .strands
        .insert(
            strand_id.to_owned(),
            StrandProjection {
                strand_id: strand_id.to_owned(),
                realm_id: realm_id.to_owned(),
                tracks: std::collections::BTreeMap::from([(
                    cokret_sdk::STRAND_TRACK_NAME_DISCUSSION.to_owned(),
                    cokret_sdk::StrandTrackConfig::discussion_primary(),
                )]),
                title: "Confidential discussion".to_owned(),
                summary: None,
                fields: Default::default(),
                state: ObjectLifecycleState::Active,
                state_changed_at: None,
                created_by: created_by.to_owned(),
                created_at: now,
                history_basis_seals: Vec::new(),
                updated_by: None,
                updated_at: None,
                scope_circle_id: Some(circle_id.to_owned()),
            },
        );
}

async fn send_circle_scoped_encrypted_message(
    state: AppState,
    token: &str,
    actor_id: &str,
    device_id: &str,
    realm_id: &str,
) -> String {
    let event_id = new_prefixed_uuid7("ck:event:");
    // Spec-conforming encrypted message: `encrypted_content` (not the retired
    // `encrypted_payload`), `track_name`, and an aad carrying ONLY realm_id +
    // event_kind. The message does NOT carry scope_circle_id — its circle
    // scope is derived server-side from the Strand (install_projected_strand_scope).
    let payload = json!({
        "strand_id": strand_id_for_realm(realm_id),
        "track_name": "discussion",
        "encrypted_content": {
            "scheme": "mls-rfc9420",
            "version": "1.0",
            "group_id": "circleGroup123",
            "epoch": 1,
            "content_type": "application/json",
            "ciphertext": "Q2lyY2xlQ2lwaGVydGV4dA",
            "aad_visibility_event_id": "hidden",
            "aad": {
                "realm_id": realm_id,
                "event_kind": "ck.message.create"
            },
            "key_ref": {
                "algorithm": "MLS",
                "group_state_ref": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
            },
            "aad_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            "payload_digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444"
        }
    });
    let mut event = json!({
        "event_id": event_id,
        "kind": "ck.message.create",
        "schema_id": "ck.schema.message.v1",
        "actor_id": actor_id,
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
            "verification_method": format!("{actor_id}#{device_id}"),
            "device_id": device_id,
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload)
        }]
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));
    let sent: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&event)
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        sent["accepted"][0], event["event_id"],
        "circle scoped encrypted message submit failed: {sent:?}"
    );
    event["event_id"].as_str().unwrap().to_owned()
}

async fn submit_projection_event(
    state: AppState,
    token: &str,
    actor_id: &str,
    device_id: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
) -> String {
    let event_id = new_prefixed_uuid7("ck:event:");
    let mut event = json!({
        "event_id": event_id.clone(),
        "kind": kind,
        "schema_id": "ck.schema.event.v1",
        "actor_id": actor_id,
        "actor_seq": TEST_EVENT_SEQ.fetch_add(1, Ordering::Relaxed),
        "realm_id": realm_id,
        "device_id": device_id,
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": [],
        "auth_refs": [],
        "refs": [],
        "payload": payload,
        "proofs": [{
            "type": "dev-proof",
            "verification_method": format!("{actor_id}#{device_id}"),
            "device_id": device_id,
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload)
        }]
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));
    let sent: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&event)
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        sent["accepted"][0].as_str() == Some(event_id.as_str()),
        "{kind} submit failed: {sent:?}"
    );
    event_id
}

async fn submit_projection_event_status(
    state: AppState,
    token: &str,
    actor_id: &str,
    device_id: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
) -> (u16, String) {
    let event_id = new_prefixed_uuid7("ck:event:");
    let mut event = json!({
        "event_id": event_id.clone(),
        "kind": kind,
        "schema_id": "ck.schema.event.v1",
        "actor_id": actor_id,
        "actor_seq": TEST_EVENT_SEQ.fetch_add(1, Ordering::Relaxed),
        "realm_id": realm_id,
        "device_id": device_id,
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": [],
        "auth_refs": [],
        "refs": [],
        "payload": payload,
        "proofs": [{
            "type": "dev-proof",
            "verification_method": format!("{actor_id}#{device_id}"),
            "device_id": device_id,
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload)
        }]
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));
    let mut response = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&event)
        .send(&app_from_state(state))
        .await;
    let status = response.status_code.unwrap().as_u16();
    let body = response.take_string().await.unwrap_or_default();
    (status, body)
}

fn sha256_json(value: &Value) -> String {
    let bytes = cokret_sdk::canonical::canonical_json_bytes(value).expect("json canonicalizes");
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn strand_id_for_realm(realm_id: &str) -> String {
    realm_id
        .strip_prefix("ck:realm:")
        .map(|suffix| format!("ck:strand:{suffix}"))
        .unwrap_or_else(|| "ck:strand:01904100-0000-7000-8000-f10dc0000001".to_owned())
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

fn sync_bodies(sync: &Value, realm_id: &str) -> Vec<String> {
    sync["realms"][realm_id]["timeline"]["events"]
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
    let alice_device_id = "ck:device:01904100-0000-7000-8000-a11ce0000001";
    let alice = dev_token(state.clone(), alice_did, "a11ce0000001").await;
    let bob_did = "did:web:bob.example";
    let _bob_session_device = dev_token(state.clone(), bob_did, "b0b000000000").await;
    let bob = _bob_session_device;
    let realm_id = seed_realm(&state, alice_did, "joined history", "joined").await;

    send_message(state.clone(), &alice, &realm_id, "before bob joined").await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    admit_member(
        state.clone(),
        &alice,
        alice_did,
        alice_device_id,
        bob_did,
        &realm_id,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    send_message(state.clone(), &alice, &realm_id, "after bob joined").await;

    let sync = account_subscribe_frame(state.clone(), &bob, "catchup=true").await;
    let bodies = sync_bodies(&sync, &realm_id);
    assert!(
        !bodies.contains(&"before bob joined".to_owned()),
        "{bodies:?}"
    );
    assert!(
        bodies.contains(&"after bob joined".to_owned()),
        "{bodies:?}"
    );

    let events: Value = TestClient::get(format!(
        "http://server/_cokret/self/events?realms={realm_id}&limit=20"
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
    let alice_device_id = "ck:device:01904100-0000-7000-8000-a11ce0000001";
    let alice = dev_token(state.clone(), alice_did, "a11ce0000001").await;
    let bob_did = "did:web:bob.example";
    let bob = dev_token(state.clone(), bob_did, "b0b000000002").await;
    let realm_id = seed_realm(&state, alice_did, "shared history", "shared").await;

    send_message(state.clone(), &alice, &realm_id, "shared before join").await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    admit_member(
        state.clone(),
        &alice,
        alice_did,
        alice_device_id,
        bob_did,
        &realm_id,
    )
    .await;

    let sync = account_subscribe_frame(state.clone(), &bob, "catchup=true").await;
    assert!(
        sync_bodies(&sync, &realm_id).contains(&"shared before join".to_owned()),
        "{sync:?}"
    );

    let events: Value = TestClient::get(format!(
        "http://server/_cokret/self/events?realms={realm_id}&limit=20"
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

#[tokio::test]
async fn circle_scoped_encrypted_message_is_hidden_from_realm_member_outside_circle() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice_did = "did:web:alice.example";
    let alice_device_id = "ck:device:01904100-0000-7000-8000-a11ce0000010";
    let alice = dev_token(state.clone(), alice_did, "a11ce0000010").await;
    let bob_did = "did:web:bob.example";
    let bob = dev_token(state.clone(), bob_did, "b0b000000010").await;
    let mallory_did = "did:web:mallory.example";
    let mallory = dev_token(state.clone(), mallory_did, "ca2010000010").await;
    let realm_id = seed_realm(&state, alice_did, "circle scoped e2ee", "shared").await;
    for actor in [alice_did, bob_did, mallory_did] {
        admit_member(
            state.clone(),
            &alice,
            alice_did,
            alice_device_id,
            actor,
            &realm_id,
        )
        .await;
    }

    let circle_id = new_prefixed_uuid7("ck:circle:");
    install_projected_circle_scope(
        &state,
        &realm_id,
        &circle_id,
        alice_did,
        &[alice_did, bob_did],
    );
    // Bind the discussion Strand to the Circle. The message posted below carries
    // NO scope_circle_id — soland derives its effective scope from this Strand.
    install_projected_strand_scope(
        &state,
        &realm_id,
        &strand_id_for_realm(&realm_id),
        &circle_id,
        alice_did,
    );
    let event_id = send_circle_scoped_encrypted_message(
        state.clone(),
        &alice,
        alice_did,
        alice_device_id,
        &realm_id,
    )
    .await;

    let bob_sync = account_subscribe_frame(state.clone(), &bob, "catchup=true").await;
    let bob_events = bob_sync["realms"][&realm_id]["timeline"]["events"]
        .as_array()
        .unwrap();
    let bob_event = bob_events
        .iter()
        .find(|event| event["event_id"].as_str() == Some(event_id.as_str()))
        .unwrap_or_else(|| panic!("Circle member did not receive scoped event: {bob_sync:?}"));
    assert_eq!(bob_event["scope_circle_id"], circle_id);
    assert_eq!(bob_event["effective_scope"], circle_id);
    assert_eq!(bob_event["encrypted"], true);

    let mallory_sync = account_subscribe_frame(state.clone(), &mallory, "catchup=true").await;
    let mallory_events = mallory_sync["realms"][&realm_id]["timeline"]["events"]
        .as_array()
        .unwrap();
    assert!(
        mallory_events
            .iter()
            .all(|event| event["event_id"].as_str() != Some(event_id.as_str())),
        "Realm member outside Circle must not receive Circle-scoped ciphertext: {mallory_sync:?}"
    );

    let bob_read: Value = TestClient::get(format!("http://server/_cokret/self/events/{event_id}"))
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(bob_read["event"]["event_id"], event_id);
    // The Circle scope is server-derived from the Strand and surfaced through
    // the SDK Event `effective_scope` object — NOT carried inside the
    // encrypted envelope's aad (spec: messages don't carry scope_circle_id).
    assert_eq!(
        bob_read["event"]["effective_scope"],
        json!({
            "kind": "circle",
            "realm_id": realm_id,
            "circle_id": circle_id,
        })
    );
    assert!(
        bob_read["event"]["payload"]["encrypted_content"]["aad"]
            .get("scope_circle_id")
            .is_none(),
        "encrypted message aad MUST NOT carry scope_circle_id (spec): {bob_read:?}"
    );

    let mallory_read = TestClient::get(format!("http://server/_cokret/self/events/{event_id}"))
        .add_header("authorization", format!("Bearer {mallory}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(mallory_read.status_code.unwrap().as_u16(), 404);
}

#[tokio::test]
async fn chat_projection_exposes_reactions_reply_and_mention_routing() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice_did = "did:web:alice.example";
    let alice_device_id = "ck:device:01904100-0000-7000-8000-a11ce0000001";
    let alice = dev_token(state.clone(), alice_did, "a11ce0000001").await;
    let bob_did = "did:web:bob.example";
    let bob_device_id = "ck:device:01904100-0000-7000-8000-b0b000000011";
    let bob = dev_token(state.clone(), bob_did, "b0b000000011").await;
    let realm_id = seed_realm(&state, alice_did, "chat projection metadata", "shared").await;
    admit_member(
        state.clone(),
        &alice,
        alice_did,
        alice_device_id,
        bob_did,
        &realm_id,
    )
    .await;

    let root_event_id = submit_projection_event(
        state.clone(),
        &alice,
        alice_did,
        alice_device_id,
        &realm_id,
        "ck.message.create",
        json!({
            "strand_id": strand_id_for_realm(&realm_id),
            "track_name": "discussion",
            "content": {
                "kind": "ck.content.text",
                "body": "root mentions bob",
                "mention_routing_hint": {
                    "mentioned": [bob_did]
                },
                "mentions": [{
                    "subject_id": bob_did,
                    "mention_text_original": "@bob"
                }]
            }
        }),
    )
    .await;
    let root_message_ref = root_event_id.replacen("ck:event:", "ck:message:", 1);
    let reply_event_id = submit_projection_event(
        state.clone(),
        &bob,
        bob_did,
        bob_device_id,
        &realm_id,
        "ck.message.create",
        json!({
            "strand_id": strand_id_for_realm(&realm_id),
            "track_name": "discussion",
            "reply_to": root_message_ref.clone(),
            "content": {
                "kind": "ck.content.text",
                "body": "reply to root"
            }
        }),
    )
    .await;
    submit_projection_event(
        state.clone(),
        &alice,
        alice_did,
        alice_device_id,
        &realm_id,
        "ck.reaction.add",
        json!({
            "target_ref": root_message_ref.clone(),
            "key": "+1"
        }),
    )
    .await;
    submit_projection_event(
        state.clone(),
        &bob,
        bob_did,
        bob_device_id,
        &realm_id,
        "ck.reaction.add",
        json!({
            "target_ref": root_message_ref.clone(),
            "key": "+1"
        }),
    )
    .await;
    submit_projection_event(
        state.clone(),
        &bob,
        bob_did,
        bob_device_id,
        &realm_id,
        "ck.reaction.remove",
        json!({
            "target_ref": root_message_ref.clone(),
            "key": "+1"
        }),
    )
    .await;

    let sync = account_subscribe_frame(state.clone(), &alice, "catchup=true").await;
    let timeline = sync["realms"][&realm_id]["timeline"]["events"]
        .as_array()
        .expect("timeline events");
    let root = timeline
        .iter()
        .find(|event| event["event_id"] == root_event_id)
        .unwrap_or_else(|| panic!("root message missing from sync projection: {timeline:?}"));
    assert_eq!(root["mention_routing_hint"]["mentioned"], json!([bob_did]));
    assert_eq!(root["mentions"][0]["subject_id"], bob_did);
    assert_eq!(root["reaction_summary"]["+1"], json!([alice_did]));
    assert!(
        !root["reaction_summary"]["+1"]
            .as_array()
            .unwrap()
            .iter()
            .any(|actor| actor.as_str() == Some(bob_did)),
        "{root:?}"
    );
    assert!(
        root["reactions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|reaction| {
                reaction["actor"] == alice_did
                    && reaction["key"] == "+1"
                    && reaction["active"] == true
            }),
        "{root:?}"
    );

    let reply = timeline
        .iter()
        .find(|event| event["event_id"] == reply_event_id)
        .unwrap_or_else(|| panic!("reply message missing from sync projection: {timeline:?}"));
    assert_eq!(reply["reply_to"], root_message_ref);
    assert_eq!(
        reply["relations"][0],
        json!({
            "kind": "reply_to",
            "target_ref": root_message_ref.clone()
        })
    );
}

#[tokio::test]
async fn poll_content_projection_replaces_votes_and_rejects_after_close() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice_did = "did:web:alice.example";
    let alice_device_id = "ck:device:01904100-0000-7000-8000-a11ce0000001";
    let alice = dev_token(state.clone(), alice_did, "a11ce0000001").await;
    let bob_did = "did:web:bob.example";
    let bob_device_id = "ck:device:01904100-0000-7000-8000-b0b000000022";
    let bob = dev_token(state.clone(), bob_did, "b0b000000022").await;
    let carol_did = "did:web:carol.example";
    let carol_device_id = "ck:device:01904100-0000-7000-8000-ca2010000022";
    let carol = dev_token(state.clone(), carol_did, "ca2010000022").await;
    let realm_id = seed_realm(&state, alice_did, "poll content reducer", "shared").await;
    admit_member(
        state.clone(),
        &alice,
        alice_did,
        alice_device_id,
        bob_did,
        &realm_id,
    )
    .await;
    admit_member(
        state.clone(),
        &alice,
        alice_did,
        alice_device_id,
        carol_did,
        &realm_id,
    )
    .await;

    let poll_id = "poll-content-fixture";
    let poll_event_id = submit_projection_event(
        state.clone(),
        &alice,
        alice_did,
        alice_device_id,
        &realm_id,
        "ck.message.create",
        json!({
            "strand_id": strand_id_for_realm(&realm_id),
            "track_name": "discussion",
            "content": {
                "kind": "ck.content.poll",
                "body": "Which window?",
                "poll_id": poll_id,
                "question": "Which window?",
                "options": [
                    {"id": "now", "label": "Now"},
                    {"id": "backup", "label": "After backup"}
                ],
                "max_selections": 1
            }
        }),
    )
    .await;
    submit_projection_event(
        state.clone(),
        &bob,
        bob_did,
        bob_device_id,
        &realm_id,
        "ck.message.create",
        json!({
            "strand_id": strand_id_for_realm(&realm_id),
            "track_name": "discussion",
            "content": {
                "kind": "ck.content.poll.response",
                "body": "poll response",
                "poll_id": poll_id,
                "choice": "now"
            }
        }),
    )
    .await;
    submit_projection_event(
        state.clone(),
        &bob,
        bob_did,
        bob_device_id,
        &realm_id,
        "ck.message.create",
        json!({
            "strand_id": strand_id_for_realm(&realm_id),
            "track_name": "discussion",
            "content": {
                "kind": "ck.content.poll.response",
                "body": "poll response",
                "poll_id": poll_id,
                "choice": "backup"
            }
        }),
    )
    .await;
    submit_projection_event(
        state.clone(),
        &carol,
        carol_did,
        carol_device_id,
        &realm_id,
        "ck.message.create",
        json!({
            "strand_id": strand_id_for_realm(&realm_id),
            "track_name": "discussion",
            "content": {
                "kind": "ck.content.poll.response",
                "body": "poll response",
                "poll_id": poll_id,
                "choice": "backup"
            }
        }),
    )
    .await;

    let sync = account_subscribe_frame(state.clone(), &alice, "catchup=true").await;
    let timeline = sync["realms"][&realm_id]["timeline"]["events"]
        .as_array()
        .expect("timeline events");
    let poll = timeline
        .iter()
        .find(|event| event["event_id"] == poll_event_id)
        .unwrap_or_else(|| panic!("poll missing from sync projection: {timeline:?}"));
    assert_eq!(poll["poll"]["results"][0]["count"], 0);
    assert_eq!(poll["poll"]["results"][1]["count"], 2);
    assert_eq!(
        poll["poll"]["results"][1]["voters"],
        json!([bob_did, carol_did])
    );

    submit_projection_event(
        state.clone(),
        &alice,
        alice_did,
        alice_device_id,
        &realm_id,
        "ck.message.create",
        json!({
            "strand_id": strand_id_for_realm(&realm_id),
            "track_name": "discussion",
            "content": {
                "kind": "ck.content.poll.close",
                "body": "poll closed",
                "poll_id": poll_id
            }
        }),
    )
    .await;
    let (status, body) = submit_projection_event_status(
        state.clone(),
        &bob,
        bob_did,
        bob_device_id,
        &realm_id,
        "ck.message.create",
        json!({
            "strand_id": strand_id_for_realm(&realm_id),
            "track_name": "discussion",
            "content": {
                "kind": "ck.content.poll.response",
                "body": "poll response",
                "poll_id": poll_id,
                "choice": "now"
            }
        }),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("poll_closed"), "{body}");
}
