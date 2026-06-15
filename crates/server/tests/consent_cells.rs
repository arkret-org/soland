use chrono::{Duration, SecondsFormat, Utc};
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::Value;
use sha2::{Digest, Sha256};
use soland::config::{AppConfig, IceServersConfig, ObjectStorageConfig};
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
        ice: IceServersConfig::default(),
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

async fn dev_token(app: &salvo::Service, actor: &str) -> String {
    let login: Value = TestClient::post("http://server/_soland/gate/auth/dev-login")
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
    TestClient::post("http://server/_soland/self/contacts/request")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({ "target": target, "requested_scopes": [scope] }))
        .send(app)
        .await
        .take_json()
        .await
        .unwrap()
}

async fn respond_contact(
    app: &salvo::Service,
    token: &str,
    requester: &str,
    request_id: &str,
    action: &str,
    granted_scopes: &[&str],
) -> Value {
    TestClient::post("http://server/_soland/self/contacts/respond")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "request_id": request_id,
            "requester": requester,
            "action": action,
            "granted_scopes": granted_scopes,
        }))
        .send(app)
        .await
        .take_json()
        .await
        .unwrap()
}

async fn get_contacts(app: &salvo::Service, token: &str) -> Value {
    TestClient::get("http://server/_cokret/self/contacts")
        .add_header("Authorization", format!("Bearer {token}"), true)
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
        "http://server/_cokret/self/consent/cells/{holder}?peer={peer}&consent_scope={scope}"
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
    expires_at: Option<String>,
) -> Value {
    TestClient::post(format!(
        "http://server/_cokret/self/consent/cells/{holder}/grant"
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .json(&serde_json::json!({
        "peer_did": peer,
        "consent_scope": scope,
        "expires_at": expires_at,
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
        "http://server/_cokret/self/consent/cells/{holder}/revoke"
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

fn iso_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn signed_event(actor: &str, realm_id: &str, kind: &str, actor_seq: u64, payload: Value) -> Value {
    let operation_id = ids::generate_operation_id();
    let mut event = serde_json::json!({
        "event_id": ids::generate_event_id(),
        "kind": kind,
        "schema_id": "ck.schema.event.v1",
        "actor_id": actor,
        "actor_seq": actor_seq,
        "realm_id": realm_id,
        "prev_refs": [],
        "refs": [],
        "requirements": {
            "schema": ["ck.schema.event.v1"],
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
    let mut response = TestClient::post("http://server/_cokret/self/events")
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
        "ck.realm.create",
        1,
        serde_json::json!({
            "object": {
                "id": realm_id,
                "schema": "ck.schema.realm.v1",
                "title": "Consent event projection",
                "summary": "Consent reducer test realm",
                "created_by": actor,
                "trust_domain": "ck:trust_domain:soland.local",
                "schema_refs": ["ck.schema.realm.v1"],
                "default_discoverability": "listed",
                "default_join_rule": "invite",
                "history_visibility": "shared",
                "encryption_profile": "none",
                "plaintext_visible_services": ["did:web:soland.local"],
                "security_class": "standard",
                "federation_policy": "restricted",
                "notary_profile": "single_did",
                "digest_algorithm": "sha256",
                "notary": {
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
        "ck.consent.grant",
        grant_seq,
        serde_json::json!({
            "consent_id": consent_id,
            "peer": bob,
            "consent_scope": "direct_message",
            "expires_at": (Utc::now() + Duration::days(1)).to_rfc3339_opts(SecondsFormat::Secs, true),
        }),
    )
    .await;
    let grant_event_id = grant_response["accepted"][0].as_str().unwrap();
    let grant_dot = format!("{grant_event_id}:{grant_seq}");

    let granted = get_cell(&app, &alice_token, alice, bob, "message").await;
    assert_eq!(granted["state"], "granted");
    assert_eq!(
        granted["cell_id"],
        format!("ck:cell:ck.component.consent.grant.v1:{consent_id}")
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
        "ck.consent.revoke",
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

/// contact-operations.schema.json — when `peer` (bob) gives the holder
/// (alice) an active `invite` consent grant via the reducer path, the
/// holder's `GET /_cokret/self/contacts` row for bob MUST surface that
/// grant's event ref in `invite_consent_grant_ref`. The ref is the event
/// id of bob's `ck.consent.grant`, so alice can hand it back to bob as
/// `consent_grant` introduction evidence. Direction self-check: the row is
/// alice's view of a bob→alice grant; when alice later invites bob into a
/// Realm, bob's server verifies "subject=bob gave inviter=alice an
/// invite/any grant" — exactly this cell.
#[tokio::test]
async fn contact_row_surfaces_invite_consent_grant_ref() {
    let state = AppState::new(test_config(), Db { pool: None });
    let app = service(state);
    let alice = "did:web:icgr-alice.example";
    let bob = "did:web:icgr-bob.example";
    let alice_token = dev_token(&app, alice).await;
    let bob_token = dev_token(&app, bob).await;
    // bob (the consent-cell holder) grants alice (peer) an `invite` scope.
    let realm_id = create_realm(&app, &bob_token, bob).await;

    // Open the contact relationship so a row exists for alice's list.
    request_contact(&app, &alice_token, bob, "invite").await;

    let consent_id = ids::generate("consent");
    let grant_seq = 2_u64;
    let grant_response = submit_event(
        &app,
        &bob_token,
        bob,
        &realm_id,
        "ck.consent.grant",
        grant_seq,
        serde_json::json!({
            "consent_id": consent_id,
            "peer": alice,
            "consent_scope": "invite",
            "expires_at": (Utc::now() + Duration::days(1)).to_rfc3339_opts(SecondsFormat::Secs, true),
        }),
    )
    .await;
    let grant_event_id = grant_response["accepted"][0].as_str().unwrap().to_owned();

    // alice's contact list row for bob carries the bob-issued grant event ref.
    let alice_contacts: Value = TestClient::get("http://server/_cokret/self/contacts")
        .add_header("Authorization", format!("Bearer {alice_token}"), true)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    let rows = alice_contacts["contacts"].as_array().unwrap();
    let bob_row = rows
        .iter()
        .find(|row| row["peer"] == bob)
        .expect("alice has a contact row for bob");
    assert!(
        bob_row["granted_to_me"]
            .as_array()
            .unwrap()
            .iter()
            .any(|scope| scope == "invite"),
        "bob granted alice invite scope: {bob_row}"
    );
    assert_eq!(
        bob_row["invite_consent_grant_ref"], grant_event_id,
        "row carries bob's ck.consent.grant event ref: {bob_row}"
    );
    assert!(
        grant_event_id.starts_with("ck:event:"),
        "the surfaced ref is a canonical event id"
    );
}

/// invite-addressing.md §5 — `GET`/`POST /_cokret/self/invite-receive-policy`
/// round-trip the subject's private policy through the same in-memory store
/// the tombstone `blocked_subjects` writes to, and reject a mismatched
/// `subject_id` with an authorization error.
#[tokio::test]
async fn invite_receive_policy_get_set_round_trips() {
    let state = AppState::new(test_config(), Db { pool: None });
    let app = service(state);
    let alice = "did:web:irp-alice.example";
    let mallory = "did:web:irp-mallory.example";
    let alice_token = dev_token(&app, alice).await;

    // Default policy is returned before any override is set.
    let default_policy: Value = TestClient::get("http://server/_cokret/self/invite-receive-policy")
        .add_header("Authorization", format!("Bearer {alice_token}"), true)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(default_policy["subject_id"], alice);
    assert!(
        default_policy["allowed_introduction_kinds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|kind| kind == "consent_grant")
    );

    // Set a custom override blocking mallory.
    let custom = serde_json::json!({
        "schema": default_policy["schema"],
        "subject_id": alice,
        "allowed_introduction_kinds": ["consent_grant"],
        "explicit_address_behavior": "drop",
        "unknown_invites": "drop",
        "blocked_subjects": [mallory],
    });
    let stored: Value = TestClient::post("http://server/_cokret/self/invite-receive-policy")
        .add_header("Authorization", format!("Bearer {alice_token}"), true)
        .json(&custom)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(stored["explicit_address_behavior"], "drop");
    assert_eq!(stored["blocked_subjects"][0], mallory);

    // GET now reflects the stored override.
    let reread: Value = TestClient::get("http://server/_cokret/self/invite-receive-policy")
        .add_header("Authorization", format!("Bearer {alice_token}"), true)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(reread["explicit_address_behavior"], "drop");
    assert_eq!(reread["blocked_subjects"][0], mallory);

    // A policy whose subject_id is not the session actor is rejected.
    let mismatched = serde_json::json!({
        "schema": default_policy["schema"],
        "subject_id": mallory,
        "allowed_introduction_kinds": ["consent_grant"],
        "explicit_address_behavior": "quarantine",
        "unknown_invites": "drop",
    });
    let rejected = TestClient::post("http://server/_cokret/self/invite-receive-policy")
        .add_header("Authorization", format!("Bearer {alice_token}"), true)
        .json(&mismatched)
        .send(&app)
        .await;
    assert_eq!(rejected.status_code.unwrap().as_u16(), 403);
}

/// Spec contact-and-direct-conversation.md §3 — `ck.self.contact.command.respond(accept)`
/// MUST write a target-controlled `ck.consent.grant` per granted scope. The
/// minted grant dot uses the event-bearing `{event_id}:{seq}` form, so the
/// holder's `GET /_cokret/self/contacts` row for the peer surfaces a canonical
/// `ck:event:<uuid>` `invite_consent_grant_ref` (no longer `None`). End to end:
/// alice requests bob with `invite` scope, bob accepts, alice's contact row
/// for bob carries bob's grant event ref — usable as `consent_grant`
/// introduction evidence to invite bob into a Realm.
#[tokio::test]
async fn contact_accept_grants_event_backed_invite_consent_ref() {
    let state = AppState::new(test_config(), Db { pool: None });
    let app = service(state);
    let alice = "did:web:cagebir-alice.example";
    let bob = "did:web:cagebir-bob.example";
    let alice_token = dev_token(&app, alice).await;
    let bob_token = dev_token(&app, bob).await;

    // alice requests bob with the `invite` scope.
    let requested = request_contact(&app, &alice_token, bob, "invite").await;
    assert_eq!(requested["state"], "pending_outgoing");
    // The requester-side contact-managed grant is referenced as a real event.
    let requester_refs = requested["requester_consent_refs"].as_array().unwrap();
    assert_eq!(requester_refs.len(), 1, "requester_consent_refs populated");
    assert!(
        requester_refs[0].as_str().unwrap().starts_with("ck:event:"),
        "requester consent ref is a canonical event id: {requested}"
    );

    // bob accepts, granting the `invite` scope back to alice. The respond
    // body MUST reference the original request event id.
    let request_id = requested["request_event_ref"].as_str().unwrap();
    let responded =
        respond_contact(&app, &bob_token, alice, request_id, "accept", &["invite"]).await;
    assert_eq!(responded["state"], "accepted");
    let grant_refs = responded["consent_grant_refs"].as_array().unwrap();
    assert_eq!(
        grant_refs.len(),
        1,
        "consent_grant_refs populated on accept"
    );
    let bob_grant_ref = grant_refs[0].as_str().unwrap().to_owned();
    assert!(
        bob_grant_ref.starts_with("ck:event:"),
        "accept consent ref is a canonical event id: {responded}"
    );

    // alice's contact row for bob surfaces bob's grant event ref (not None).
    let alice_contacts = get_contacts(&app, &alice_token).await;
    let rows = alice_contacts["contacts"].as_array().unwrap();
    let bob_row = rows
        .iter()
        .find(|row| row["peer"] == bob)
        .expect("alice has a contact row for bob");
    assert!(
        bob_row["granted_to_me"]
            .as_array()
            .unwrap()
            .iter()
            .any(|scope| scope == "invite"),
        "bob granted alice invite scope: {bob_row}"
    );
    let surfaced_ref = bob_row["invite_consent_grant_ref"].as_str();
    assert_eq!(
        surfaced_ref,
        Some(bob_grant_ref.as_str()),
        "row carries bob's accept grant event ref: {bob_row}"
    );
    assert!(
        surfaced_ref.unwrap().starts_with("ck:event:"),
        "the surfaced ref is a canonical event id"
    );
}
