use chrono::{Duration, SecondsFormat, Utc};
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::Value;
use sha2::{Digest, Sha256};
use soland::config::{AppConfig, ObjectStorageConfig};
use soland::db::Db;
use soland::state::AppState;
use soland::{ids, service};

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
        cors_allow_origin: None,
        auth_server_url: None,
        development_mode: true,
        oauth_introspection_url: None,
        oauth_introspection_bearer: None,
        session_grant_introspection_url: None,
        session_grant_introspection_bearer: None,
        did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned(), "peer".to_owned()],
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
        trust_domain: "ck:trust_domain:soland.local".to_owned(),
        sovereign_enclave_enabled: false,
        sovereign_enclave_allowed_outbound_hosts: Vec::new(),
        erasure_propagation_window_ms: 604_800_000,
        log_format: soland::config::LogFormat::Plain,
    }
}

async fn dev_token(app: &salvo::Service, actor: &str) -> String {
    let login: Value = TestClient::post("http://server/api/v1/auth/dev-login")
        .json(&serde_json::json!({
            "actor": actor,
            "device_id": format!("ck:device:test-{}", actor.replace(':', "-")),
            "display_name": actor,
        }))
        .send(app)
        .await
        .take_json()
        .await
        .unwrap();
    login["access_token"].as_str().unwrap().to_owned()
}

async fn request_contact(app: &salvo::Service, token: &str, target: &str, scope: &str) -> Value {
    TestClient::post("http://server/api/v1/contacts/request")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({ "target": target, "scope": scope }))
        .send(app)
        .await
        .take_json()
        .await
        .unwrap()
}

async fn get_cell(
    app: &salvo::Service,
    token: &str,
    holder: &str,
    peer: &str,
    scope: &str,
) -> Value {
    TestClient::get(format!(
        "http://server/api/v1/consent/cells/{holder}?peer={peer}&consent_scope={scope}"
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .send(app)
    .await
    .take_json()
    .await
    .unwrap()
}

async fn grant_cell(
    app: &salvo::Service,
    token: &str,
    holder: &str,
    peer: &str,
    scope: &str,
    valid_until: Option<String>,
) -> Value {
    TestClient::post(format!("http://server/api/v1/consent/cells/{holder}/grant"))
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "peer_did": peer,
            "consent_scope": scope,
            "valid_until": valid_until,
        }))
        .send(app)
        .await
        .take_json()
        .await
        .unwrap()
}

async fn revoke_cell(
    app: &salvo::Service,
    token: &str,
    holder: &str,
    peer: &str,
    scope: &str,
) -> Value {
    TestClient::post(format!(
        "http://server/api/v1/consent/cells/{holder}/revoke"
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .json(&serde_json::json!({ "peer_did": peer, "consent_scope": scope }))
    .send(app)
    .await
    .take_json()
    .await
    .unwrap()
}

fn sha256_json(value: &Value) -> String {
    let bytes = cokret_sdk::canonical::canonical_json_bytes(value)
        .unwrap_or_else(|_| serde_json::to_vec(value).unwrap());
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

fn iso_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn signed_event(actor: &str, realm_id: &str, kind: &str, actor_seq: u64, payload: Value) -> Value {
    let operation_id = ids::generate_operation_id();
    let mut event = serde_json::json!({
        "event_id": ids::generate_event_id(),
        "kind": kind,
        "schema_id": "cx.schema.event.v1",
        "actor_id": actor,
        "actor_seq": actor_seq,
        "realm_id": realm_id,
        "prev_refs": [],
        "refs": [],
        "requirements": {
            "schema": ["cx.schema.event.v1"],
            "features": [],
            "critical_extensions": []
        },
        "created_at": iso_now(),
        "payload": payload,
        "unsigned": {
            "local_operation_idempotency_alias": operation_id
        },
        "proofs": [{
            "type": "dev-proof",
            "verification_method": format!("{actor}#device"),
            "payload_digest": sha256_json(&payload)
        }]
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));
    event
}

async fn submit_event(
    app: &salvo::Service,
    token: &str,
    actor: &str,
    realm_id: &str,
    kind: &str,
    actor_seq: u64,
    payload: Value,
) -> Value {
    let event = signed_event(actor, realm_id, kind, actor_seq, payload);
    let mut response = TestClient::post("http://server/api/v1/events")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&event)
        .send(app)
        .await;
    let status = response.status_code.unwrap();
    let body = response.take_string().await.unwrap_or_default();
    assert!(
        matches!(status, StatusCode::OK | StatusCode::CREATED),
        "submit {kind} failed with {status}: {body}"
    );
    serde_json::from_str(&body).unwrap()
}

async fn create_realm(app: &salvo::Service, token: &str, actor: &str) -> String {
    let realm_id = ids::generate_realm_id();
    let created_at = iso_now();
    submit_event(
        app,
        token,
        actor,
        &realm_id,
        "cx.realm.create",
        1,
        serde_json::json!({
            "object": {
                "id": realm_id,
                "schema": "cx.schema.realm.v1",
                "title": "Consent event projection",
                "summary": "Consent reducer test realm",
                "created_by": actor,
                "trust_domain": "ck:trust_domain:soland.local",
                "schema_refs": ["cx.schema.realm.v1"],
                "default_discoverability": "listed",
                "default_join_rule": "invite",
                "history_visibility": "shared",
                "encryption_profile": "none",
                "plaintext_visible_services": ["did:web:soland.local"],
                "security_class": "standard",
                "federation_policy": "restricted",
                "anchor_profile": "single_did",
                "digest_algorithm": "sha256",
                "anchorer": {
                    "type": "single_did",
                    "did": actor,
                    "recovery_members": ["did:web:recovery.soland.local"],
                    "controller_organization": "did:web:organization.primary.soland.local",
                    "recovery_controller_organizations": ["did:web:organization.recovery.soland.local"]
                },
                "created_at": created_at
            }
        }),
    )
    .await;
    realm_id
}

#[tokio::test]
async fn consent_pending_grant_revoke_regrant_controls_contact_gate() {
    let state = AppState::new(test_config(), Db { pool: None });
    let app = service(state);
    let alice = "did:web:consent-alice.example";
    let bob = "did:web:consent-bob.example";
    let alice_token = dev_token(&app, alice).await;
    let bob_token = dev_token(&app, bob).await;

    let pending_contact = request_contact(&app, &bob_token, alice, "message").await;
    assert_eq!(pending_contact["status"], "pending");
    assert_eq!(pending_contact["scope"], "message");
    assert_eq!(
        get_cell(&app, &alice_token, alice, bob, "message").await["state"],
        "pending"
    );

    let granted = grant_cell(&app, &alice_token, alice, bob, "message", None).await;
    assert_eq!(granted["state"], "granted");
    let accepted_contact = request_contact(&app, &bob_token, alice, "message").await;
    assert_eq!(accepted_contact["status"], "accepted");

    let revoked = revoke_cell(&app, &alice_token, alice, bob, "message").await;
    assert_eq!(revoked["state"], "revoked");
    let blocked_contact = request_contact(&app, &bob_token, alice, "message").await;
    assert_eq!(blocked_contact["status"], "pending");

    let regranted = grant_cell(&app, &alice_token, alice, bob, "message", None).await;
    assert_eq!(regranted["state"], "granted");
    let accepted_again = request_contact(&app, &bob_token, alice, "message").await;
    assert_eq!(accepted_again["status"], "accepted");
}

#[tokio::test]
async fn consent_events_project_cells_and_contact_gate() {
    let state = AppState::new(test_config(), Db { pool: None });
    let app = service(state);
    let alice = "did:web:event-consent-alice.example";
    let bob = "did:web:event-consent-bob.example";
    let alice_token = dev_token(&app, alice).await;
    let bob_token = dev_token(&app, bob).await;
    let realm_id = create_realm(&app, &alice_token, alice).await;

    let pending_contact = request_contact(&app, &bob_token, alice, "message").await;
    assert_eq!(pending_contact["status"], "pending");

    let consent_id = ids::generate("consent");
    let grant_seq = 2_u64;
    let grant_response = submit_event(
        &app,
        &alice_token,
        alice,
        &realm_id,
        "cx.consent.grant",
        grant_seq,
        serde_json::json!({
            "consent_id": consent_id,
            "peer": bob,
            "consent_scope": "direct_message",
            "expires_at": (Utc::now() + Duration::days(1)).to_rfc3339_opts(SecondsFormat::Secs, true),
        }),
    )
    .await;
    let grant_event_id = grant_response["event_id"].as_str().unwrap();
    let grant_dot = format!("{grant_event_id}:{grant_seq}");

    let granted = get_cell(&app, &alice_token, alice, bob, "message").await;
    assert_eq!(granted["state"], "granted");
    assert_eq!(
        granted["cell_id"],
        format!("ck:cell:cx.component.consent.grant.v1:{consent_id}")
    );
    assert!(
        granted["grant_dots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|dot| dot.as_str() == Some(&grant_dot))
    );
    let accepted_contact = request_contact(&app, &bob_token, alice, "message").await;
    assert_eq!(accepted_contact["status"], "accepted");

    submit_event(
        &app,
        &alice_token,
        alice,
        &realm_id,
        "cx.consent.revoke",
        3,
        serde_json::json!({
            "consent_id": consent_id,
            "observed_dots": [grant_dot],
            "revoked_at": (Utc::now() + Duration::seconds(1)).to_rfc3339_opts(SecondsFormat::Secs, true),
        }),
    )
    .await;

    let revoked = get_cell(&app, &alice_token, alice, bob, "message").await;
    assert_eq!(revoked["state"], "revoked");
    assert!(
        revoked["revoked_dots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|dot| dot.as_str() == Some(&grant_dot))
    );
    let blocked_contact = request_contact(&app, &bob_token, alice, "message").await;
    assert_eq!(blocked_contact["status"], "pending");
}

#[tokio::test]
async fn consent_expiry_scope_and_pairwise_did_isolation() {
    let state = AppState::new(test_config(), Db { pool: None });
    let app = service(state);
    let alice = "did:web:scope-alice.example";
    let bob = "did:web:scope-bob.example";
    let pairwise_bob = "did:peer:scope-bob-pairwise";
    let alice_token = dev_token(&app, alice).await;
    let bob_token = dev_token(&app, bob).await;
    let pairwise_token = dev_token(&app, pairwise_bob).await;

    request_contact(&app, &bob_token, alice, "invite").await;
    let expired_at = (Utc::now() - Duration::seconds(1)).to_rfc3339();
    let expired = grant_cell(&app, &alice_token, alice, bob, "invite", Some(expired_at)).await;
    assert_eq!(expired["state"], "expired");
    let expired_contact = request_contact(&app, &bob_token, alice, "invite").await;
    assert_eq!(expired_contact["status"], "pending");

    grant_cell(&app, &alice_token, alice, bob, "invite", None).await;
    let invite_contact = request_contact(&app, &bob_token, alice, "invite").await;
    assert_eq!(invite_contact["status"], "accepted");
    let call_contact = request_contact(&app, &bob_token, alice, "call").await;
    assert_eq!(call_contact["status"], "pending");
    assert_eq!(
        get_cell(&app, &alice_token, alice, bob, "call").await["state"],
        "pending"
    );

    request_contact(&app, &pairwise_token, alice, "message").await;
    grant_cell(&app, &alice_token, alice, pairwise_bob, "message", None).await;
    assert_eq!(
        request_contact(&app, &pairwise_token, alice, "message").await["status"],
        "accepted"
    );
    assert_eq!(
        request_contact(&app, &bob_token, alice, "message").await["status"],
        "pending"
    );
    assert_eq!(
        get_cell(&app, &alice_token, alice, pairwise_bob, "message").await["state"],
        "granted"
    );
    assert_eq!(
        get_cell(&app, &alice_token, alice, bob, "message").await["state"],
        "pending"
    );
}
