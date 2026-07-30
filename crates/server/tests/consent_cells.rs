use chrono::{Duration, Utc};
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::Value;
use soland_http::config::AppConfig;
use soland_http::state::AppState;
use soland_http::{ids, service};
use soland_test_support::AppStateTestExt as _;

const ACCOUNT_REGISTER_BEARER: &str = "soland-test-account-register-bearer";

fn test_config() -> AppConfig {
    AppConfig {
        development_mode: true,
        embedded_webvh_registration_bearer: Some(ACCOUNT_REGISTER_BEARER.to_owned()),
        did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned(), "peer".to_owned()],
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: std::collections::BTreeMap::new(),
        ..soland_test_support::app_config()
    }
}

async fn ensure_account(app: &salvo::Service, actor: &str) {
    let mut response = TestClient::post("http://server/_arkret/gate/account/register")
        .add_header(
            "authorization",
            format!("Bearer {ACCOUNT_REGISTER_BEARER}"),
            true,
        )
        .json(&serde_json::json!({
            "principal_id": actor,
            "display_name": actor,
        }))
        .send(app)
        .await;
    let status = response.status_code.expect("register status");
    let body: Value = response.take_json().await.unwrap();
    assert!(
        matches!(status, StatusCode::OK | StatusCode::CONFLICT),
        "account register failed: {body}"
    );
}

async fn dev_token(app: &salvo::Service, actor: &str) -> String {
    ensure_account(app, actor).await;
    let login: Value = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&serde_json::json!({
            "actor": actor,
            "device_id": ids::generate("device"),
            "display_name": actor,
        }))
        .send(app)
        .await
        .take_json()
        .await
        .unwrap();
    login["session_credential"].as_str().unwrap().to_owned()
}

async fn request_contact(app: &salvo::Service, token: &str, target: &str, scope: &str) -> Value {
    let mut response = TestClient::post("http://server/_arkret/self/contacts/request")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({ "target": target, "requested_scopes": [scope] }))
        .send(app)
        .await;
    let status = response.status_code.expect("contact request status");
    let mut body: Value = response.take_json().await.unwrap();
    assert!(
        status.is_success(),
        "contact request failed with {status}: {body}"
    );
    if let Some(object) = body.as_object_mut() {
        if !object.contains_key("status")
            && let Some(state) = object.get("state").and_then(Value::as_str)
        {
            let status = match state {
                "active" => "accepted",
                "pending_incoming" | "pending_outgoing" => "pending",
                other => other,
            };
            object.insert("status".to_owned(), Value::String(status.to_owned()));
        }
        object
            .entry("scope".to_owned())
            .or_insert_with(|| Value::String(scope.to_owned()));
    }
    body
}

async fn respond_contact(
    app: &salvo::Service,
    token: &str,
    requester: &str,
    request_id: &str,
    action: &str,
    granted_scopes: &[&str],
) -> Value {
    TestClient::post("http://server/_arkret/self/contacts/respond")
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
    TestClient::get("http://server/_arkret/self/contacts")
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
        "http://server/_arkret/self/consent/cells/{holder}?peer={peer}&consent_scope={scope}"
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .send(app)
    .await
    .take_json()
    .await
    .unwrap()
}

async fn assert_requester_consent_revoked(
    app: &salvo::Service,
    token: &str,
    holder: &str,
    peer: &str,
    scope: &str,
) {
    let cell = get_cell(app, token, holder, peer, scope).await;
    assert_eq!(cell["state"], "revoked", "cell revoked: {cell}");
    assert!(
        cell["active_grant_dots"].as_array().unwrap().is_empty(),
        "no active requester-side dots remain: {cell}"
    );
    let grant_dots = cell["grant_dots"].as_array().unwrap();
    assert!(
        !grant_dots.is_empty(),
        "requester-side grant dots existed before revoke: {cell}"
    );
    let revoked_dots = cell["revoked_dots"].as_array().unwrap();
    for dot in grant_dots {
        assert!(
            revoked_dots.contains(dot),
            "grant dot must be enumerated in revoked_dots: {cell}"
        );
    }
}

async fn assert_auto_revoke_audit(state: &AppState, actor: &str, reason: &str) {
    let entries = state
        .test_persistence()
        .audit()
        .list_for_actor(actor)
        .await
        .unwrap();
    assert!(
        entries.iter().any(|entry| {
            entry["action"].as_str() == Some("consent.requester_side.auto_revoke")
                && entry["payload"]["reason"].as_str() == Some(reason)
        }),
        "auto revoke audit reason {reason} missing from {entries:?}"
    );
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
        "http://server/_arkret/self/consent/cells/{holder}/grant"
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
        "http://server/_arkret/self/consent/cells/{holder}/revoke"
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .json(&serde_json::json!({ "peer_did": peer, "consent_scope": scope }))
    .send(app)
    .await
    .take_json()
    .await
    .unwrap()
}

fn iso_now() -> String {
    arkret_canonical::format_timestamp_canonical(Utc::now())
}

fn signing_actor(seed: [u8; 32]) -> String {
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    format!(
        "did:key:{}",
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes())
    )
}

fn signed_event(
    seed: [u8; 32],
    actor: &str,
    realm_id: &str,
    kind: &str,
    actor_seq: u64,
    payload: Value,
) -> Value {
    signed_event_with_prev_refs(
        seed,
        actor,
        realm_id,
        kind,
        actor_seq,
        payload,
        Vec::new(),
        None,
    )
}

/// The Realm's accepted Seal frontier, which is the registered sourcing for a
/// single-leaf Control Move `seal_basis` (`events.rs::events_frontier` — a
/// Realm-only selector returns the `RealmSeal` view precisely for this).
///
/// These fixtures bootstrap their Realm through `ak.realm.create` +
/// `ak.capability.grant`, so the Realm really does have an accepted Seal: the
/// basis is read back from the server rather than fabricated.
async fn realm_seal_basis(
    app: &salvo::Service,
    token: &str,
    realm_id: &str,
) -> arkret_wire::SealBasis {
    let mut response = TestClient::get(format!(
        "http://server/_arkret/self/events/frontier?realm_id={realm_id}"
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .send(app)
    .await;
    let status = response.status_code.expect("Realm Seal frontier status");
    let body = response.take_string().await.unwrap_or_default();
    assert_eq!(
        status,
        StatusCode::OK,
        "Realm Seal frontier failed with {status}: {body}"
    );
    let frontier: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
        serde_json::from_str(&body).expect("typed Realm Seal frontier");
    let arkret_models_collaboration::event_sync::EventsFrontierView::RealmSeal(frontier) =
        frontier.frontier
    else {
        panic!("Realm-only selector returned the wrong frontier variant");
    };
    frontier.seal_basis()
}

#[expect(
    clippy::too_many_arguments,
    reason = "the fixture mirrors the complete signed-event envelope"
)]
fn signed_event_with_prev_refs(
    seed: [u8; 32],
    actor: &str,
    realm_id: &str,
    kind: &str,
    actor_seq: u64,
    payload: Value,
    prev_refs: Vec<arkret_wire::EventId>,
    seal_basis: Option<arkret_wire::SealBasis>,
) -> Value {
    let now = Utc::now();
    assert_eq!(actor, signing_actor(seed));
    let actor_id = arkret_identifiers::Did::new(actor.to_owned()).expect("fixture actor DID");
    let key = actor
        .strip_prefix("did:key:")
        .expect("fixture did:key actor");
    let verification_method = format!("{actor}#{key}");
    let mut event = arkret_wire::Event::new_with_id_at(
        arkret_wire::EventId::new(ids::generate_event_id()).expect("fixture Event id"),
        kind,
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(realm_id.to_owned())
                .expect("fixture Realm id"),
        },
        actor_id.clone(),
        actor_seq,
        arkret_identifiers::Hlc::new(format!(
            "{:012x}-0000-00000000",
            now.timestamp_millis().max(0) as u64
        ))
        .expect("fixture HLC"),
        payload,
        now,
    )
    .expect("SDK Event builder accepts consent fixture");
    event.prev_refs = prev_refs;
    event.seal_basis = seal_basis;
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        seed,
        actor_id,
        verification_method.clone(),
    );
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(now),
    )
    .expect("SDK Event signer accepts consent fixture");
    serde_json::to_value(event).expect("SDK Event serializes")
}

#[expect(
    clippy::too_many_arguments,
    reason = "the fixture mirrors the complete signed-event envelope"
)]
async fn submit_event(
    app: &salvo::Service,
    token: &str,
    seed: [u8; 32],
    actor: &str,
    realm_id: &str,
    kind: &str,
    actor_seq: u64,
    payload: Value,
) -> Value {
    let frontier: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
        TestClient::get(format!(
            "http://server/_arkret/self/events/frontier?actor_id={actor}&realm_id={realm_id}"
        ))
        .add_header("Authorization", format!("Bearer {token}"), true)
        .send(app)
        .await
        .take_json()
        .await
        .expect("typed actor Realm frontier");
    let arkret_models_collaboration::event_sync::EventsFrontierView::RealmActor(frontier) =
        frontier.frontier
    else {
        panic!("combined Realm+actor selector returned the wrong variant");
    };
    assert!(
        actor_seq >= frontier.next_actor_seq,
        "fixture-requested actor_seq must not precede the accepted frontier"
    );
    let seal_basis = realm_seal_basis(app, token, realm_id).await;
    let event = signed_event_with_prev_refs(
        seed,
        actor,
        realm_id,
        kind,
        frontier.next_actor_seq,
        payload,
        frontier.frontier_event_ids,
        Some(seal_basis),
    );
    let mut response = TestClient::post("http://server/_arkret/self/events")
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

async fn create_realm(
    app: &salvo::Service,
    token: &str,
    seed: [u8; 32],
    actor: &str,
    service_id: &str,
) -> String {
    let realm_id = ids::generate_realm_id();
    let created_at = iso_now();
    let create = signed_event(
        seed,
        actor,
        &realm_id,
        "ak.realm.create",
        0,
        serde_json::json!({
            "object": {
                "id": realm_id,
                "schema": "ak.schema.realm.v1",
                "title": "Consent event projection",
                "summary": "Consent reducer test realm",
                "created_by": actor,
                "trust_domain": "ak:trust_domain:soland.local",
                "schema_refs": ["ak.schema.realm.v1"],
                "default_discoverability": "listed",
                "default_join_rule": "invite",
                "history_visibility": "shared",
                "encryption_profile": "none",
                // No `plaintext_visible_services` on the object: `realm.schema.json`
                // is closed and its only carrier is the dedicated
                // `ak.realm.plaintext_visible_services` facet Event.
                "security_class": "standard",
                "federation_policy": "restricted",
                "notary_profile": "single_did",
                "digest_algorithm": "sha256",
                // This deployment hosts the Realm, so it is the Realm's
                // notary: `notary.rs::is_authorized_for_notary_ops` only lets
                // the service materialize accepted Seals for a `single_did`
                // Realm whose notary DID is its own `service_id`, and without
                // an accepted Seal no Control Move of this Realm could ever
                // resolve a `seal_basis`.
                "notary": {
                    "kind": "single_did",
                    "did": service_id,
                    "recovery_members": ["did:web:recovery.soland.local"],
                    "controller_organization": "did:web:organization.primary.soland.local",
                    "recovery_controller_organizations": ["did:web:organization.recovery.soland.local"]
                },
                "created_at": created_at
            }
        }),
    );
    let create_event_id = arkret_wire::EventId::new(
        create["event_id"]
            .as_str()
            .expect("Realm create fixture has an Event id")
            .to_owned(),
    )
    .expect("Realm create fixture Event id is canonical");
    let grant_id = ids::generate_grant_id();
    let mut grant: arkret_models_collaboration::governance::grant_constraint::CapabilityGrant = serde_json::from_value(serde_json::json!({
        "id": grant_id,
        "schema": "ak.schema.capability.v1",
        "realm_id": realm_id,
        "issuer": actor,
        "subject": actor,
        "actions": [
            "ak.realm.admin",
            "ak.capability.grant",
            "ak.capability.revoke",
            "ak.realm_key.share"
        ],
        "capability_action_registry_digest": arkret_policy::current_capability_action_registry_digest().unwrap(),
        "resources": [{
            "kind": "realm",
            "realm_id": realm_id,
            "match_scope": "realm_wide"
        }],
        "issued_at": created_at,
        "proofs": []
    }))
    .expect("founding capability grant fixture decodes");
    let verification_method = format!(
        "{actor}#{}",
        actor
            .strip_prefix("did:key:")
            .expect("founding grant actor uses did:key")
    );
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let mut grant_proof = arkret_wire::PayloadProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method,
        payload_digest: grant.payload_digest().expect("founding grant digest"),
        created_at: chrono::DateTime::parse_from_rfc3339(&created_at)
            .expect("fixture created_at")
            .with_timezone(&Utc),
        domain: None,
        audience: None,
        proof_purpose: Some(arkret_wire::PayloadProofPurpose::IssuerAttestation),
        jws: String::new(),
    };
    grant_proof.jws = arkret_signatures::sign_eddsa_detached_jws(
        &signing_key,
        &grant
            .canonical_proof_binding_bytes(&grant_proof)
            .expect("founding grant proof binding"),
    )
    .expect("founding grant proof signature");
    grant.proofs.push(grant_proof);
    let founding = signed_event_with_prev_refs(
        seed,
        actor,
        &realm_id,
        arkret_wire::events::EventKind::CAPABILITY_GRANT,
        1,
        serde_json::json!({
            "grant_id": grant_id,
            "grant": grant
        }),
        vec![create_event_id],
        // `realm-and-space.md` §2.5 — the founding grant is the recognized
        // `ak.realm.create` bootstrap followup, submitted in the genesis batch
        // before any Seal of this Realm exists, so it carries no basis.
        None,
    );
    let mut response = TestClient::post("http://server/_arkret/self/events")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({"events": [create, founding]}))
        .send(app)
        .await;
    let status = response.status_code.expect("Realm bootstrap status");
    let body = response.take_string().await.unwrap_or_default();
    assert!(
        matches!(status, StatusCode::OK | StatusCode::CREATED),
        "Realm bootstrap failed with {status}: {body}"
    );
    realm_id
}

#[tokio::test]
async fn consent_grant_revoke_regrant_does_not_implicitly_accept_contact_request() {
    let state = soland_test_support::app_state(test_config());
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
    assert_eq!(granted["state"], "active");
    let repeated_contact = request_contact(&app, &bob_token, alice, "message").await;
    assert_eq!(repeated_contact["status"], "pending");

    let revoked = revoke_cell(&app, &alice_token, alice, bob, "message").await;
    assert_eq!(revoked["state"], "revoked");
    let blocked_contact = request_contact(&app, &bob_token, alice, "message").await;
    assert_eq!(blocked_contact["status"], "pending");

    let regranted = grant_cell(&app, &alice_token, alice, bob, "message", None).await;
    assert_eq!(regranted["state"], "active");
    let repeated_again = request_contact(&app, &bob_token, alice, "message").await;
    assert_eq!(repeated_again["status"], "pending");
}

#[tokio::test]
async fn consent_events_project_cells_without_implicitly_accepting_contact_request() {
    let state = soland_test_support::app_state(test_config());
    let app = service(state.clone());
    let alice_seed = [31_u8; 32];
    let alice = signing_actor(alice_seed);
    let bob = "did:web:event-consent-bob.example";
    let alice_token = dev_token(&app, &alice).await;
    let bob_token = dev_token(&app, bob).await;
    let realm_id = create_realm(&app, &alice_token, alice_seed, &alice, state.service_id()).await;

    let pending_contact = request_contact(&app, &bob_token, &alice, "message").await;
    assert_eq!(pending_contact["status"], "pending");

    let consent_id = ids::generate("consent");
    let grant_seq = 2_u64;
    let grant_response = submit_event(
        &app,
        &alice_token,
        alice_seed,
        &alice,
        &realm_id,
        "ak.consent.grant",
        grant_seq,
        serde_json::json!({
            "consent_id": consent_id,
            "peer": bob,
            "consent_scope": "direct_message",
            "expires_at": arkret_canonical::format_timestamp_canonical(
                Utc::now() + Duration::days(1)
            ),
        }),
    )
    .await;
    let grant_event_id = grant_response["accepted"][0].as_str().unwrap();
    let grant_dot = format!("{grant_event_id}:{grant_seq}");

    let granted = get_cell(&app, &alice_token, &alice, bob, "message").await;
    assert_eq!(granted["state"], "active");
    assert_eq!(
        granted["cell_id"],
        format!("ak:cell:ak.component.consent.grant.v1:{consent_id}")
    );
    assert!(
        granted["grant_dots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|dot| dot.as_str() == Some(&grant_dot))
    );
    let repeated_contact = request_contact(&app, &bob_token, &alice, "message").await;
    assert_eq!(repeated_contact["status"], "pending");

    let revoke_payload = serde_json::json!({
        "consent_id": consent_id,
        "observed_dots": [grant_dot],
        "revoked_at": arkret_canonical::format_timestamp_canonical(
            Utc::now() + Duration::seconds(1)
        ),
    });
    let typed_revoke: arkret_models_collaboration::governance_payloads::ConsentRevokePayload =
        serde_json::from_value(revoke_payload.clone()).unwrap_or_else(|error| {
            panic!(
                "canonical consent revoke fixture must decode: {error}; payload={revoke_payload}"
            )
        });
    typed_revoke
        .validate_minimal()
        .expect("canonical consent revoke fixture must validate");
    submit_event(
        &app,
        &alice_token,
        alice_seed,
        &alice,
        &realm_id,
        "ak.consent.revoke",
        3,
        revoke_payload,
    )
    .await;

    let revoked = get_cell(&app, &alice_token, &alice, bob, "message").await;
    assert_eq!(revoked["state"], "revoked");
    assert!(
        revoked["revoked_dots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|dot| dot.as_str() == Some(&grant_dot))
    );
    let blocked_contact = request_contact(&app, &bob_token, &alice, "message").await;
    assert_eq!(blocked_contact["status"], "pending");
}

#[tokio::test]
async fn consent_expiry_scope_and_pairwise_did_isolation() {
    let state = soland_test_support::app_state(test_config());
    let app = service(state);
    let alice = "did:web:scope-alice.example";
    let bob = "did:web:scope-bob.example";
    let pairwise_bob = "did:peer:scope-bob-pairwise";
    let alice_token = dev_token(&app, alice).await;
    let bob_token = dev_token(&app, bob).await;
    let pairwise_token = dev_token(&app, pairwise_bob).await;

    request_contact(&app, &bob_token, alice, "invite").await;
    let expired_at =
        arkret_canonical::format_timestamp_canonical(Utc::now() - Duration::seconds(1));
    let expired = grant_cell(&app, &alice_token, alice, bob, "invite", Some(expired_at)).await;
    assert_eq!(expired["state"], "pending");
    assert!(expired["active_grant_dots"].as_array().unwrap().is_empty());
    let expired_contact = request_contact(&app, &bob_token, alice, "invite").await;
    assert_eq!(expired_contact["status"], "pending");

    grant_cell(&app, &alice_token, alice, bob, "invite", None).await;
    let invite_contact = request_contact(&app, &bob_token, alice, "invite").await;
    assert_eq!(invite_contact["status"], "pending");
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
        "pending"
    );
    assert_eq!(
        request_contact(&app, &bob_token, alice, "message").await["status"],
        "pending"
    );
    assert_eq!(
        get_cell(&app, &alice_token, alice, pairwise_bob, "message").await["state"],
        "active"
    );
    assert_eq!(
        get_cell(&app, &alice_token, alice, bob, "message").await["state"],
        "pending"
    );
}

/// contact-operations.schema.json — when `peer` (bob) gives the holder
/// (alice) an active `invite` consent grant via the reducer path, the
/// holder's `GET /_arkret/self/contacts` row for bob MUST surface that
/// grant's event ref in `invite_consent_grant_ref`. The ref is the event
/// id of bob's `ak.consent.grant`, so alice can hand it back to bob as
/// `consent_grant` introduction evidence. Direction self-check: the row is
/// alice's view of a bob→alice grant; when alice later invites bob into a
/// Realm, bob's server verifies "subject=bob gave inviter=alice an
/// invite/any grant" — exactly this cell.
#[tokio::test]
async fn contact_row_surfaces_invite_consent_grant_ref() {
    let state = soland_test_support::app_state(test_config());
    let app = service(state.clone());
    let alice = "did:web:icgr-alice.example";
    let bob_seed = [32_u8; 32];
    let bob = signing_actor(bob_seed);
    let alice_token = dev_token(&app, alice).await;
    let bob_token = dev_token(&app, &bob).await;
    // bob (the consent-cell holder) grants alice (peer) an `invite` scope.
    let realm_id = create_realm(&app, &bob_token, bob_seed, &bob, state.service_id()).await;

    // Open the contact relationship so a row exists for alice's list.
    request_contact(&app, &alice_token, &bob, "invite").await;

    let consent_id = ids::generate("consent");
    let grant_seq = 3_u64;
    let grant_response = submit_event(
        &app,
        &bob_token,
        bob_seed,
        &bob,
        &realm_id,
        "ak.consent.grant",
        grant_seq,
        serde_json::json!({
            "consent_id": consent_id,
            "peer": alice,
            "consent_scope": "invite",
            "expires_at": arkret_canonical::format_timestamp_canonical(
                Utc::now() + Duration::days(1)
            ),
        }),
    )
    .await;
    let grant_event_id = grant_response["accepted"][0].as_str().unwrap().to_owned();

    // alice's contact list row for bob carries the bob-issued grant event ref.
    let alice_contacts: Value = TestClient::get("http://server/_arkret/self/contacts")
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
        "row carries bob's ak.consent.grant event ref: {bob_row}"
    );
    assert!(
        grant_event_id.starts_with("ak:event:"),
        "the surfaced ref is a canonical event id"
    );
}

/// invite-addressing.md §5 — `GET`/`PUT /_arkret/self/invite-receive-policy`
/// round-trip the subject's private policy through the same in-memory store
/// the tombstone `denied_subjects` writes to, and reject a mismatched
/// `subject_id` with an authorization error.
#[tokio::test]
async fn invite_receive_policy_get_set_round_trips() {
    let state = soland_test_support::app_state(test_config());
    let app = service(state);
    let alice = "did:web:irp-alice.example";
    let mallory = "did:web:irp-mallory.example";
    let alice_token = dev_token(&app, alice).await;

    // Default policy is returned before any override is set.
    let default_policy: Value = TestClient::get("http://server/_arkret/self/invite-receive-policy")
        .add_header("Authorization", format!("Bearer {alice_token}"), true)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(default_policy["subject_id"], alice);
    assert!(
        default_policy["holder_allowed_introduction_kinds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|kind| kind == "consent_grant")
    );

    // Set a custom override blocking mallory.
    let custom = serde_json::json!({
        "schema": default_policy["schema"],
        "subject_id": alice,
        "holder_allowed_introduction_kinds": ["consent_grant"],
        "explicit_address_behavior": "drop",
        "unknown_invites": "drop",
        "denied_subjects": [mallory],
    });
    let stored: Value = TestClient::put("http://server/_arkret/self/invite-receive-policy")
        .add_header("Authorization", format!("Bearer {alice_token}"), true)
        .json(&custom)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(stored["explicit_address_behavior"], "drop");
    assert_eq!(stored["denied_subjects"][0], mallory);

    // GET now reflects the stored override.
    let reread: Value = TestClient::get("http://server/_arkret/self/invite-receive-policy")
        .add_header("Authorization", format!("Bearer {alice_token}"), true)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(reread["explicit_address_behavior"], "drop");
    assert_eq!(reread["denied_subjects"][0], mallory);

    // A policy whose subject_id is not the session actor is rejected.
    let mismatched = serde_json::json!({
        "schema": default_policy["schema"],
        "subject_id": mallory,
        "holder_allowed_introduction_kinds": ["consent_grant"],
        "explicit_address_behavior": "quarantine",
        "unknown_invites": "drop",
    });
    let rejected = TestClient::put("http://server/_arkret/self/invite-receive-policy")
        .add_header("Authorization", format!("Bearer {alice_token}"), true)
        .json(&mismatched)
        .send(&app)
        .await;
    assert_eq!(rejected.status_code.unwrap().as_u16(), 403);
}

/// Spec contact-and-direct-conversation.md §3 — `ak.self.contact.command.respond(accept)`
/// MUST write a target-controlled `ak.consent.grant` per granted scope. The
/// minted grant dot uses the event-bearing `{event_id}:{seq}` form, so the
/// holder's `GET /_arkret/self/contacts` row for the peer surfaces a canonical
/// `ak:event:<uuid>` `invite_consent_grant_ref` (no longer `None`). End to end:
/// alice requests bob with `invite` scope, bob accepts, alice's contact row
/// for bob carries bob's grant event ref — usable as `consent_grant`
/// introduction evidence to invite bob into a Realm.
#[tokio::test]
async fn contact_accept_grants_event_backed_invite_consent_ref() {
    let state = soland_test_support::app_state(test_config());
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
        requester_refs[0].as_str().unwrap().starts_with("ak:event:"),
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
        bob_grant_ref.starts_with("ak:event:"),
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
        surfaced_ref.unwrap().starts_with("ak:event:"),
        "the surfaced ref is a canonical event id"
    );
}

#[tokio::test]
async fn contact_reject_revokes_requester_side_consent_ref() {
    let state = soland_test_support::app_state(test_config());
    let app = service(state.clone());
    let alice = "did:web:crrscr-alice.example";
    let bob = "did:web:crrscr-bob.example";
    let alice_token = dev_token(&app, alice).await;
    let bob_token = dev_token(&app, bob).await;

    let requested = request_contact(&app, &alice_token, bob, "invite").await;
    let request_id = requested["request_event_ref"].as_str().unwrap();
    assert_eq!(
        get_cell(&app, &alice_token, alice, bob, "invite").await["state"],
        "active"
    );

    let rejected = respond_contact(&app, &bob_token, alice, request_id, "reject", &[]).await;
    assert_eq!(rejected["state"], "rejected");

    assert_requester_consent_revoked(&app, &alice_token, alice, bob, "invite").await;
    assert_auto_revoke_audit(&state, alice, "contact_rejected").await;
}

#[tokio::test]
async fn pending_contact_tombstone_revokes_requester_side_consent_ref() {
    let state = soland_test_support::app_state(test_config());
    let app = service(state.clone());
    let alice = "did:web:pctrrscr-alice.example";
    let bob = "did:web:pctrrscr-bob.example";
    let alice_token = dev_token(&app, alice).await;
    let bob_token = dev_token(&app, bob).await;

    request_contact(&app, &alice_token, bob, "invite").await;
    assert_eq!(
        get_cell(&app, &alice_token, alice, bob, "invite").await["state"],
        "active"
    );

    let mut response = TestClient::post("http://server/_arkret/self/contacts/tombstone")
        .add_header("Authorization", format!("Bearer {bob_token}"), true)
        .json(&serde_json::json!({
            "contact": alice,
            "revoke_scopes": [],
            "full_peer_revoke": false,
            "block_peer": false,
        }))
        .send(&app)
        .await;
    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let tombstoned: Value = response.take_json().await.unwrap();
    assert_eq!(tombstoned["state"], "tombstoned");

    assert_requester_consent_revoked(&app, &alice_token, alice, bob, "invite").await;
    assert_auto_revoke_audit(&state, alice, "contact_tombstoned").await;
}

#[tokio::test]
async fn expired_contact_respond_revokes_requester_side_consent_and_fails_closed() {
    let state = soland_test_support::app_state(test_config());
    let app = service(state.clone());
    let alice = "did:web:ecrrrscafc-alice.example";
    let bob = "did:web:ecrrrscafc-bob.example";
    let alice_token = dev_token(&app, alice).await;
    let bob_token = dev_token(&app, bob).await;

    let requested = request_contact(&app, &alice_token, bob, "invite").await;
    let request_id = requested["request_event_ref"].as_str().unwrap();
    let mut contact = state
        .test_persistence()
        .contacts()
        .get_scoped(alice, bob, "invite")
        .await
        .unwrap()
        .expect("stored contact request");
    contact.created_at = Utc::now() - Duration::days(15);
    contact.updated_at = contact.created_at;
    state
        .test_persistence()
        .contacts()
        .put(&contact)
        .await
        .unwrap();

    let mut response = TestClient::post("http://server/_arkret/self/contacts/respond")
        .add_header("Authorization", format!("Bearer {bob_token}"), true)
        .json(&serde_json::json!({
            "request_id": request_id,
            "requester": alice,
            "action": "accept",
            "granted_scopes": ["invite"],
        }))
        .send(&app)
        .await;
    assert_eq!(
        response.status_code.unwrap(),
        StatusCode::PRECONDITION_FAILED
    );
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "contact_request_expired");

    assert_requester_consent_revoked(&app, &alice_token, alice, bob, "invite").await;
    assert_auto_revoke_audit(&state, alice, "contact_request_pending_ttl").await;
}
