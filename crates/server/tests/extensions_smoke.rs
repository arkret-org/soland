//! G3.S9 — integration smoke for the four new extensions routes.
//!
//! Per `cotest/e2e/scenarios/extensions/applet-bridge.md`,
//! `cotest/e2e/scenarios/identity/tsp-bootstrap.md`, and the existing
//! cotest fixture mocks (`cotest/e2e/mocks/mock-applet-registry.mjs`,
//! `cotest/e2e/mocks/mock-tsp-endpoint.mjs`). The integration test
//! posts to each route and verifies the spec-shaped envelope.

use std::collections::BTreeMap;

use arkret_identifiers::{AppletId, Did, EventId, Hlc, RealmId};
use arkret_models_collaboration::events_payloads::{
    CapabilityGrantCreateBody, CapabilityGrantPayload,
};
use arkret_models_collaboration::governance::grant_constraint::{
    CapabilitySubject, GrantConstraint,
};
use arkret_models_integration::applet::{
    AppletEndpointAuth, AppletEndpointEntry, AppletEndpointMethod, AppletEndpointPolicy,
    AppletGhostPolicy, AppletNamespaceEntry, AppletPackage, AppletWireNamespaces,
    HttpMessageSignatureAlgorithm, WebhookAuth,
};
use arkret_signatures::{Ed25519PayloadSigner, SignEventOptions};
use arkret_wire::{Event, ScopeRef};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use soland_http::config::{AppConfig, ObjectStorageConfig};
use soland_http::service;
use soland_http::state::AppState;
use soland_test_support::AppStateTestExt as _;

const DEMO_REALM_ID: &str = "ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1";
const EXTENSION_TEST_SIGNING_SEED: [u8; 32] = [0x5a; 32];

fn test_config() -> AppConfig {
    AppConfig {
        object_storage: ObjectStorageConfig::local(
            std::env::temp_dir().join("soland-extensions-smoke"),
        ),
        development_mode: true,
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: std::collections::BTreeMap::new(),
        seed_demo_data: true,
        notary_signing_key_seed: Some(EXTENSION_TEST_SIGNING_SEED),
        ..soland_test_support::app_config()
    }
}

async fn allow_service_message_plaintext(state: &AppState, realm_id: &str) {
    let service_id = state.service_id().clone();
    let mut meta = state
        .test_persistence()
        .realm_meta()
        .get(realm_id)
        .await
        .unwrap()
        .unwrap();
    meta.plaintext_visible_services.insert(service_id.clone());
    meta.plaintext_visible_service_classes.insert(
        service_id,
        std::collections::BTreeSet::from([arkret_wire::PlaintextDataClassKind::MessageContent]),
    );
    meta.updated_at = chrono::Utc::now();
    state
        .test_persistence()
        .realm_meta()
        .put(realm_id, &meta)
        .await
        .unwrap();
}

async fn dev_token(state: AppState) -> String {
    dev_token_for(state, "did:web:alice.example", "a11ce0000001").await
}

async fn dev_login_token(state: AppState, actor: &str, device_suffix: &str) -> String {
    state.hydrate().await.unwrap();
    let login: Value = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&json!({
            "actor": actor,
            "device_id": format!("ak:device:01904100-0000-7000-8000-{device_suffix}"),
            "display_name": "Applet service"
        }))
        .send(&service(state))
        .await
        .take_json()
        .await
        .unwrap();
    login["session_credential"].as_str().unwrap().to_owned()
}

async fn dev_token_for(state: AppState, actor: &str, device_suffix: &str) -> String {
    state.hydrate().await.unwrap();
    let typed_realm_id = arkret_identifiers::RealmId::new(DEMO_REALM_ID.to_owned()).unwrap();
    let actor_did = Did::new(actor.to_owned()).unwrap();
    let now = chrono::Utc::now();
    {
        let mut realms = state.test_realms().lock();
        let mut realm = realms
            .get(&typed_realm_id)
            .cloned()
            .expect("seeded extension test realm");
        realm.members.insert(actor_did);
        realms.upsert(realm);
    }
    state.test_projection().lock().members.insert(
        (DEMO_REALM_ID.to_owned(), actor.to_owned()),
        soland_domain::reducer::SolandMembershipState {
            member: actor.to_owned(),
            realm_id: DEMO_REALM_ID.to_owned(),
            state: "join".to_owned(),
            role: "member".to_owned(),
            delivery_status: None,
            recipient_service_id: None,
            membership_event_ref: None,
            delivery_binding_frontier: None,
            invited_at: None,
            joined_at: now,
            updated_at: now,
            reason: None,
        },
    );
    dev_login_token(state, actor, device_suffix).await
}

/// A citable accepted Seal of the demo Realm that establishes this service as
/// the current single-DID proposal/notary authority.
///
/// `event-auth-state-resolution.md` §5 makes a control-plane Event a Control
/// Move whose `seal_basis.leaves` must be non-empty; unlike a DataEvent
/// `seal_ref`, the leaves are not resolved into an authorization pre-state at
/// admission, but Control Proposal Ack admission still resolves the accepted
/// notary cell.
async fn seed_extension_test_seal(state: &AppState) -> arkret_wire::SealBasis {
    const ADMIN_GRANT_ID: &str = "ak:grant:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    ingest_extension_admin_document(state).await;
    let realm = arkret_identifiers::RealmId::new(DEMO_REALM_ID).unwrap();
    let create = arkret_wire::Event::new(
        arkret_wire::EventKind::REALM_CREATE,
        arkret_wire::ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        Did::new("did:web:alice.example").unwrap(),
        0,
        arkret_identifiers::Hlc::new("0196419b0000-0000-a11ce000").unwrap(),
        json!({
            "object": {
                "id": realm,
                "created_by": "did:web:alice.example",
                "capability_action_registry_digest":
                    arkret_policy::current_capability_action_registry_digest().unwrap(),
                "notary": {
                    "kind": "single_did",
                    "did": state.service_id(),
                },
            }
        }),
    )
    .unwrap();
    let move_id = arkret_identifiers::Hash::new(create.event_digest().unwrap()).unwrap();
    let admin_grant_move_id =
        arkret_identifiers::Hash::new(format!("sha256:{}", "41".repeat(32))).unwrap();
    let notary_cell: arkret_identifiers::CellRef = arkret_wire::REALM_NOTARY_CELL.parse().unwrap();
    let notary_op = arkret_state::lattice::ordered_log::IssuedOp {
        issuer: Did::new(state.service_id().clone()).unwrap(),
        op: arkret_state::lattice::SealedOp::new(
            move_id.clone(),
            arkret_wire::LatticeOp {
                op_type: arkret_wire::LatticeOpType::Set,
                tag: None,
                value: Some(json!({
                    "kind": "single_did",
                    "did": state.service_id(),
                })),
                from: None,
                to: None,
                reason: None,
                issuer_seq: None,
            },
        ),
    };
    let admin_grant_cell = arkret_identifiers::CellRef::new(format!(
        "ak:cell:ak.component.capability.grant.v1:{ADMIN_GRANT_ID}"
    ))
    .unwrap();
    let admin_grant_op = arkret_state::lattice::ordered_log::IssuedOp {
        issuer: Did::new("did:web:alice.example").unwrap(),
        op: arkret_state::lattice::SealedOp::new(
            admin_grant_move_id.clone(),
            arkret_wire::LatticeOp {
                op_type: arkret_wire::LatticeOpType::Add,
                tag: Some(admin_grant_move_id.to_string()),
                value: Some(json!({
                    "grant_id": ADMIN_GRANT_ID,
                    "schema": arkret_wire::SchemaId::CAPABILITY_V1,
                    "realm_id": DEMO_REALM_ID,
                    "issuer": "did:web:alice.example",
                    "issuer_authority_refs": [{
                        "kind": "realm_root",
                        "realm_id": DEMO_REALM_ID,
                        "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
                        "controller_epoch_at_issuance": 0,
                        "authority_generation": 0
                    }],
                    "subject": "did:web:alice.example",
                    "actions": soland_services::conformance_basis::OWNER_BOOTSTRAP_GRANT_ACTIONS,
                    "resources": [{
                        "kind": "realm",
                        "realm_id": DEMO_REALM_ID,
                        "match_scope": "realm_wide"
                    }],
                    "capability_action_registry_digest":
                        arkret_policy::current_capability_action_registry_digest().unwrap(),
                    "issued_at": "2026-01-01T00:00:00.000Z"
                })),
                from: None,
                to: None,
                reason: None,
                issuer_seq: None,
            },
        ),
    };
    let registry = soland_services::projection::ProjectionService::sdk_cell_registry();
    let notary_binding = registry
        .resolve(&realm, &notary_cell)
        .expect("notary cell family is registered");
    let notary_joined = arkret_state::join_cell(
        notary_binding.lattice.as_ref(),
        &notary_cell,
        std::slice::from_ref(&notary_op),
    );
    let grant_binding = registry
        .resolve(&realm, &admin_grant_cell)
        .expect("capability grant cell family is registered");
    let grant_joined = arkret_state::join_cell(
        grant_binding.lattice.as_ref(),
        &admin_grant_cell,
        std::slice::from_ref(&admin_grant_op),
    );
    let state_root = arkret_state::compute_state_root(&BTreeMap::from([
        (notary_cell.clone(), notary_joined),
        (admin_grant_cell.clone(), grant_joined),
    ]))
    .unwrap();
    let signer = Ed25519PayloadSigner::from_did_key_seed(
        [0x21; 32],
        Did::new("did:web:alice.example").unwrap(),
        arkret_wire::DidUrl::new("did:web:alice.example#extension-test-notary").unwrap(),
    );
    let mut delta = vec![move_id, admin_grant_move_id];
    delta.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    let seal = arkret_wire::Seal::sign_single(
        realm.clone(),
        Vec::new(),
        delta,
        state_root,
        arkret_identifiers::Hlc::new("0196419b0000-0000-a11ce001").unwrap(),
        &signer,
    )
    .unwrap();
    state.test_put_seal(&seal).unwrap();
    state
        .test_append_sealed_effects(
            &realm,
            &seal.id,
            &[(notary_cell, notary_op), (admin_grant_cell, admin_grant_op)],
        )
        .unwrap();
    state.test_refresh_grant_from_sealed_cells(&realm, ADMIN_GRANT_ID);
    let envelope = serde_json::to_value(&create).unwrap();
    state
        .test_persistence()
        .events()
        .put(soland_storage::CanonicalEventRecord {
            event_id: create.event_id.to_string(),
            actor_id: create.actor_id.to_string(),
            actor_seq: create.actor_seq,
            realm_id: Some(DEMO_REALM_ID.to_owned()),
            kind: arkret_wire::EventKind::REALM_CREATE.to_owned(),
            schema_id: "ak.schema.event_envelope.v1".to_owned(),
            canonical_digest: create.event_digest().unwrap(),
            canonical_bytes: arkret_canonical::canonical_json_bytes(&envelope).unwrap(),
            envelope,
            received_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
    seal.seal_basis()
}

async fn ingest_extension_admin_document(state: &AppState) {
    let now = chrono::Utc::now();
    let did = Did::new("did:web:alice.example").unwrap();
    let verification_method =
        arkret_wire::DidUrl::new("did:web:alice.example#extension-test-notary".to_owned())
            .expect("fixture verification method is a DID URL");
    let signing_key = SigningKey::from_bytes(&[0x21; 32]);
    let document = arkret_identity::DidDocument {
        id: did.clone(),
        verification_methods: BTreeMap::from([(
            verification_method.as_str().to_owned(),
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                signing_key.verifying_key().as_bytes(),
            ),
        )]),
        also_known_as: Vec::new(),
        updated_at: Some(now),
        raw_properties: BTreeMap::new(),
    };
    let record = soland_storage::WebvhDocumentRecord {
        did: did.to_string(),
        did_document: serde_json::to_value(document).unwrap(),
        key_log_head: None,
        seq: 1,
        method_evidence: json!({ "mode": "test_fixture" }),
        fetched_at: now,
        expires_at: now + chrono::Duration::minutes(15),
        updated_at: now,
    };
    state
        .test_persistence()
        .webvh()
        .put_document(record.clone())
        .await
        .unwrap();
    state
        .test_cache_resolved_webvh_record(soland_services::identity::DidDocumentState {
            did: record.did,
            did_document: record.did_document,
            key_log_head: record.key_log_head,
            seq: record.seq,
            method_evidence: record.method_evidence,
            fetched_at: record.fetched_at,
            expires_at: record.expires_at,
            updated_at: record.updated_at,
        })
        .unwrap();
}

// Each parameter is a separate signed field of the ghost provision body.
#[allow(clippy::too_many_arguments)]
fn signed_ghost_provision_body(
    package: &AppletPackage,
    install: &Value,
    ghost_actor_id: &str,
    protocol: &str,
    tenant: &str,
    external_user_id: &str,
    display_name: Option<&str>,
    seal_basis: &arkret_wire::SealBasis,
) -> Value {
    use arkret_models_collaboration::governance::accountability::{
        AccountabilityGrantPayload, AccountabilityScope, AccountabilityScopeKind,
    };

    let realm_id = arkret_identifiers::RealmId::new(DEMO_REALM_ID.to_owned()).unwrap();
    let ghost_actor_id = Did::new(ghost_actor_id.to_owned()).unwrap();
    let applet_id =
        arkret_identifiers::AppletId::new(package.applet_id.clone()).expect("valid applet id");
    let authorization_ref = if install["effective_status"] == json!("installed") {
        capability_grant_ref_for_action(
            install,
            &package.requested_scopes,
            "ak.applet.ghost.provision",
        )
    } else {
        "ak:grant:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk".to_owned()
    };
    let verification_method = arkret_wire::DidUrl::new(package.webhook_auth.key_ref.clone())
        .expect("fixture verification method is a DID URL");
    let signing_key = applet_service_signing_key(&verification_method);
    let signer = Ed25519PayloadSigner::new(
        signing_key.clone(),
        package.service_id.clone(),
        verification_method.clone(),
    );
    let now =
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
    let mut grant = AccountabilityGrantPayload::new(
        package.service_id.clone(),
        ghost_actor_id.clone(),
        AccountabilityScope::Single(AccountabilityScopeKind::ContractedService),
        now - chrono::Duration::seconds(1),
        None,
        arkret_wire::PayloadProof {
            kind: "detached_jws".to_owned(),
            verification_method: verification_method.clone(),
            payload_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
                .unwrap(),
            created_at: now,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "pending".to_owned(),
        },
    );
    grant.proof.payload_digest = grant.payload_digest().unwrap();
    let grant_binding = grant.canonical_proof_binding_bytes().unwrap();
    grant.proof.jws =
        arkret_signatures::jws::sign_jws_ed25519(&grant_binding, &signing_key).unwrap();
    let mut accountability_event = arkret_event_draft::accountability_grant_event(
        &grant,
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        0,
        arkret_identifiers::Hlc::new(format!(
            "{:012x}-0000-a11ce001",
            now.timestamp_millis().max(0) as u64
        ))
        .unwrap(),
        None,
    )
    .unwrap();
    accountability_event.applet_id = Some(applet_id.clone());
    accountability_event.authorization_ref =
        Some(arkret_wire::AuthorizationRef::new(authorization_ref.clone()).unwrap());
    accountability_event.seal_basis = Some(seal_basis.clone());
    let event_grant: AccountabilityGrantPayload =
        serde_json::from_value(serde_json::to_value(&accountability_event.payload).unwrap())
            .unwrap();
    assert_eq!(
        event_grant.canonical_proof_binding_bytes().unwrap(),
        grant_binding
    );
    arkret_signatures::sign_event(
        &mut accountability_event,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(now),
    )
    .unwrap();

    let profile_external_ref = json!({
        "schema": "ak.applet.ghost_actor.external_ref.v1",
        "protocol": protocol,
        "tenant": tenant,
        "external_user_id": external_user_id,
        "realm_id": realm_id,
        "external_ref": {
            "protocol": protocol,
            "external_id": external_user_id,
            "instance_id": tenant,
        },
    });
    let profile = arkret_event_draft::GhostActorProfileRequest::new(
        ghost_actor_id.clone(),
        display_name.unwrap_or(external_user_id),
        applet_id.clone(),
    )
    .with_realm_id(realm_id.clone())
    .with_accountable_principal_ids(vec![package.service_id.clone()])
    .with_external_ref(serde_json::from_value(profile_external_ref).unwrap());
    let delegation = arkret_models_integration::AppletDelegatedEventAuthorization::new(
        package.service_id.clone(),
        arkret_wire::AuthorizationRef::new(authorization_ref).unwrap(),
        applet_id,
    );
    let mut profile_event = profile
        .profile_create_event(
            arkret_wire::ScopeRef::Realm { realm_id },
            0,
            arkret_identifiers::Hlc::new(format!(
                "{:012x}-0001-a11ce001",
                now.timestamp_millis().max(0) as u64
            ))
            .unwrap(),
            Some(&delegation),
        )
        .unwrap();
    profile_event.refs.push(arkret_wire::EventRef::new(
        accountability_event.event_id.as_str(),
        "accountability",
    ));
    // `ak.profile.create` is a control-plane reducer input in the event-kind
    // registry, so `event-auth-state-resolution.md` §5 makes it a Control Move:
    // it names the same accepted Seal basis as the accountability grant it
    // travels with. The delegated applet authorization on the envelope is a
    // separate, additive check — it never substitutes for the CBA basis.
    profile_event.seal_basis = Some(seal_basis.clone());
    arkret_signatures::sign_event(
        &mut profile_event,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(now),
    )
    .unwrap();
    json!({
        "schema": "ak.applet.ghost_actor.provision_request.v1",
        "applet_id": package.applet_id,
        "service_id": package.service_id,
        "ghost_actor_id": ghost_actor_id,
        "protocol": protocol,
        "tenant": tenant,
        "external_user_id": external_user_id,
        "display_name": display_name,
        "realm_id": DEMO_REALM_ID,
        "external_ref": {
            "protocol": protocol,
            "external_id": external_user_id,
            "instance_id": tenant,
        },
        "accountability_grant_event": accountability_event,
        "profile_event": profile_event,
    })
}

#[tokio::test]
async fn applet_protocol_describe_smoke() {
    let state = soland_test_support::app_state(test_config());
    let app = service(state);

    let ping: Value = TestClient::get("http://server/_arkret/edge/applet/ping")
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(ping["ok"], json!(true));

    let describe: Value = TestClient::get("http://server/_arkret/edge/applet/describe")
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(describe["contract"], json!("ak.applet.v1"));
    assert_eq!(
        describe["install"]["commit_path"],
        json!("/_arkret/self/applets/install")
    );
    assert_eq!(
        describe["install"]["ghost_actor_provision_path"],
        json!("/_arkret/self/applets/{applet_id}/ghosts/provision")
    );
    assert_eq!(
        describe["transaction_path"],
        json!("/_arkret/edge/applet/transactions")
    );
}

#[tokio::test]
async fn applet_transaction_requires_signature_before_typed_body_validation() {
    let state = soland_test_support::app_state(test_config());
    let app = service(state);
    let mut response = TestClient::post("http://server/_arkret/edge/applet/transactions")
        .add_header("Authorization", "Bearer bearer-only", true)
        .add_header("Idempotency-Key", "missing-signature-order", true)
        .json(&json!({
            "source_service_id": "not-a-did",
            "events": "not-an-array"
        }))
        .send(&app)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::UNAUTHORIZED);
    let error: Value = response.take_json().await.unwrap();
    assert_eq!(error["reason"], json!("http_signature_required"));
}

#[tokio::test]
async fn applet_install_package_registers_bot_projection_smoke() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    seed_extension_test_seal(&state).await;
    let app = service(state.clone());
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let realm_id = DEMO_REALM_ID;
    let applet_id = arkret_identifiers::new_prefixed_uuid7("ak:applet:");
    let namespace = format!("bridge.install.{suffix}");
    let package = signed_applet_package(&applet_id, &namespace);
    ingest_applet_service_id_document(&state, &package).await;

    let install = install_applet_package(
        &state,
        &app,
        &token,
        &package,
        realm_id,
        &format!("install-{suffix}"),
    )
    .await;
    assert_eq!(install["effective_status"], json!("installed"));
    assert_eq!(install["applet_id"], json!(applet_id));
    let bot_actor_id = install["bot_actor_id"].as_str().unwrap().to_owned();
    assert_eq!(bot_actor_id, package.bot_actor_id.to_string());

    let projection_events = state
        .test_persistence()
        .projection_events()
        .snapshot_all()
        .await
        .unwrap();
    assert!(
        projection_events.iter().any(|event| {
            event.event_kind == "ak.applet.registration"
                && event.payload["applet_id"] == json!(applet_id)
                && event.payload["bot_actor_id"] == json!(bot_actor_id)
        }),
        "install must append ak.applet.registration projection"
    );

    let stored_applet = state
        .test_persistence()
        .applets()
        .get(&applet_id)
        .await
        .unwrap()
        .expect("applet record is durable");
    let execution = &stored_applet["install_execution"];
    assert_eq!(execution["status"], json!("completed"));
    assert_eq!(
        execution["idempotency_key"],
        json!(format!("install-{suffix}"))
    );
    assert_eq!(
        execution["produced_event_refs"][0],
        install["registration_event_ref"]
    );
    let steps = execution["steps"].as_array().unwrap();
    assert_eq!(
        steps[0]["target_event_kind"],
        json!("ak.applet.registration")
    );
    assert_eq!(steps[0]["status"], json!("accepted"));
    assert_eq!(steps[0]["event_ref"], install["registration_event_ref"]);
    assert!(steps.iter().any(
        |step| step["target_event_kind"] == json!("ak.capability.grant")
            && step["grant_binding"]["registration_epoch"]
                == json!(package.registration_epoch.to_string())
    ));
    let accepted_event_refs = steps
        .iter()
        .map(|step| {
            step["event_ref"]
                .as_str()
                .expect("accepted install step has an Event ref")
                .to_owned()
        })
        .collect::<Vec<_>>();
    let canonical_events = state
        .test_persistence()
        .events()
        .snapshot_all()
        .await
        .unwrap();
    let install_events = canonical_events
        .iter()
        .filter(|event| accepted_event_refs.contains(&event.event_id))
        .collect::<Vec<_>>();
    assert_eq!(install_events.len(), accepted_event_refs.len());
    assert!(install_events.iter().any(|event| {
        event.kind == arkret_wire::EventKind::APPLET_REGISTRATION
            && event.envelope["payload"]["applet_id"] == json!(applet_id)
    }));
    assert!(install_events.iter().any(|event| {
        event.kind == arkret_wire::EventKind::CAPABILITY_GRANT
            && event.envelope["payload"]["grant"]["constraints"][0]["constraint_kind"]
                == json!("authority_control")
            && event.envelope["payload"]["grant"]["constraints"][0]["constraint_subkind"]
                == json!("applet_authority")
    }));
    let bot_doc = canonical_did_document(&app, &bot_actor_id).await;
    assert_eq!(bot_doc["id"], json!(bot_actor_id));
    assert_eq!(bot_doc["status"], json!("active"));
    assert_eq!(bot_doc["applet_id"], json!(applet_id));
}

#[tokio::test]
async fn applet_ghost_actor_provision_writes_durable_profile_and_grant_events() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let seal_basis = seed_extension_test_seal(&state).await;
    let app = service(state.clone());
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let applet_id = arkret_identifiers::new_prefixed_uuid7("ak:applet:");
    let namespace = format!("bridge.provision.{suffix}");
    let package = signed_applet_package(&applet_id, &namespace);
    ingest_applet_service_id_document(&state, &package).await;
    let realm_id = DEMO_REALM_ID;
    let install = install_applet_package(
        &state,
        &app,
        &token,
        &package,
        realm_id,
        &format!("ghost-provision-{suffix}"),
    )
    .await;
    assert_eq!(install["effective_status"], json!("installed"));
    let service_token =
        dev_login_token(state.clone(), package.service_id.as_str(), "a11ce0000002").await;

    let ghost_actor_id = format!(
        "did:web:{}.applet.example:ghost:u123",
        safe_did_token(&namespace)
    );
    let mut rejected_body = signed_ghost_provision_body(
        &package,
        &install,
        &ghost_actor_id,
        "slack",
        "T123",
        "U123",
        Some("Alice on Slack"),
        &seal_basis,
    );
    let rejected_profile_ref = rejected_body["profile_event"]["event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let rejected_grant_ref = rejected_body["accountability_grant_event"]["event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    rejected_body["accountability_grant_event"]["payload"]["proof"]["jws"] = json!("invalid-jws");
    let rejected: Value = TestClient::post(format!(
        "http://server/_arkret/self/applets/{applet_id}/ghosts/provision"
    ))
    .add_header("Authorization", format!("Bearer {service_token}"), true)
    .add_header("Idempotency-Key", format!("invalid-proof-{suffix}"), true)
    .json(&rejected_body)
    .send(&app)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        rejected["error"]["code"],
        json!("invalid_proof"),
        "rejection: {rejected}"
    );
    assert!(
        state
            .test_persistence()
            .events()
            .get(&rejected_profile_ref)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        state
            .test_persistence()
            .events()
            .get(&rejected_grant_ref)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        state
            .test_persistence()
            .applets()
            .get(&applet_id)
            .await
            .unwrap()
            .unwrap()["ghosts"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let provision_body = signed_ghost_provision_body(
        &package,
        &install,
        &ghost_actor_id,
        "slack",
        "T123",
        "U123",
        Some("Alice on Slack"),
        &seal_basis,
    );
    let idempotency_key = format!("provision-{suffix}");
    let mut response = TestClient::post(format!(
        "http://server/_arkret/self/applets/{applet_id}/ghosts/provision"
    ))
    .add_header("Authorization", format!("Bearer {service_token}"), true)
    .add_header("Idempotency-Key", &idempotency_key, true)
    .json(&provision_body)
    .send(&app)
    .await;
    let status = response.status_code.unwrap();
    let provision: Value = response.take_json().await.unwrap();
    assert_eq!(
        status,
        StatusCode::CREATED,
        "provision response: {provision}"
    );
    assert_eq!(provision["ghost_actor_id"], json!(ghost_actor_id));
    assert_eq!(provision["display_name"], json!("Alice on Slack"));
    let profile_event_ref = provision["profile_event_ref"].as_str().unwrap();
    let accountability_grant_ref = provision["accountability_grant_ref"].as_str().unwrap();
    let authorization_ref = provision["authorization_ref"].as_str().unwrap();
    assert!(profile_event_ref.starts_with("ak:event:"));
    assert!(accountability_grant_ref.starts_with("ak:event:"));
    assert_eq!(
        authorization_ref,
        capability_grant_ref_for_action(
            &install,
            &package.requested_scopes,
            "ak.applet.ghost.provision"
        )
    );

    let profile_event = state
        .test_persistence()
        .events()
        .get(profile_event_ref)
        .await
        .unwrap()
        .expect("profile event is durable");
    assert_eq!(profile_event.kind, "ak.profile.create");
    assert_eq!(profile_event.actor_id, ghost_actor_id);
    assert_eq!(
        profile_event.envelope["executed_by"],
        json!(package.service_id.to_string())
    );
    assert_eq!(
        profile_event.envelope["authorization_ref"],
        json!(authorization_ref)
    );
    assert_eq!(profile_event.envelope["applet_id"], json!(applet_id));
    assert_eq!(
        profile_event.envelope["payload"]["object"]["profile_fields"]["managed_by_applet"],
        json!(applet_id)
    );
    assert_eq!(
        profile_event.envelope["payload"]["object"]["profile_fields"]["external_ref"]["external_user_id"],
        json!("U123")
    );
    assert!(
        profile_event.envelope["payload"]["object"]["accountable_principal_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|did| did == &json!(package.service_id.to_string()))
    );
    assert_eq!(
        profile_event.envelope["proofs"][0]["kind"],
        json!("detached_jws")
    );

    let grant_event = state
        .test_persistence()
        .events()
        .get(accountability_grant_ref)
        .await
        .unwrap()
        .expect("accountability grant event is durable");
    assert_eq!(grant_event.kind, "ak.identity.accountability_grant");
    assert_eq!(grant_event.actor_id, package.service_id.to_string());
    assert_eq!(
        grant_event.envelope["payload"]["issuer"],
        json!(package.service_id.to_string())
    );
    assert_eq!(
        grant_event.envelope["payload"]["subject"],
        json!(ghost_actor_id)
    );
    assert_eq!(
        grant_event.envelope["payload"]["proof"]["kind"],
        json!("detached_jws")
    );

    let projection_events = state
        .test_persistence()
        .projection_events()
        .snapshot_all()
        .await
        .unwrap();
    assert!(projection_events.iter().any(|event| {
        event.event_id == profile_event_ref && event.event_kind == "ak.profile.create"
    }));
    assert!(projection_events.iter().any(|event| {
        event.event_id == accountability_grant_ref
            && event.event_kind == "ak.identity.accountability_grant"
    }));

    let mut replay_response = TestClient::post(format!(
        "http://server/_arkret/self/applets/{applet_id}/ghosts/provision"
    ))
    .add_header("Authorization", format!("Bearer {service_token}"), true)
    .add_header("Idempotency-Key", &idempotency_key, true)
    .json(&provision_body)
    .send(&app)
    .await;
    assert_eq!(replay_response.status_code.unwrap(), StatusCode::OK);
    let replay: Value = replay_response.take_json().await.unwrap();
    assert_eq!(replay, provision);

    let mut conflicting_body = provision_body;
    conflicting_body["display_name"] = json!("Changed on retry");
    let mut conflict_response = TestClient::post(format!(
        "http://server/_arkret/self/applets/{applet_id}/ghosts/provision"
    ))
    .add_header("Authorization", format!("Bearer {service_token}"), true)
    .add_header("Idempotency-Key", idempotency_key, true)
    .json(&conflicting_body)
    .send(&app)
    .await;
    assert_eq!(conflict_response.status_code.unwrap(), StatusCode::CONFLICT);
    let conflict: Value = conflict_response.take_json().await.unwrap();
    assert_eq!(conflict["error"]["code"], json!("duplicate_conflict"));
}

#[tokio::test]
async fn applet_ghost_actor_provision_requires_approved_ghost_scope() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let seal_basis = seed_extension_test_seal(&state).await;
    let app = service(state.clone());
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let applet_id = arkret_identifiers::new_prefixed_uuid7("ak:applet:");
    let namespace = format!("bridge.no-ghost-scope.{suffix}");
    let package = signed_applet_package(&applet_id, &namespace);
    ingest_applet_service_id_document(&state, &package).await;
    let realm_id = DEMO_REALM_ID;
    let install = install_applet_package_with_approved_actions(
        &state,
        &app,
        &token,
        &package,
        realm_id,
        &format!("ghost-denied-{suffix}"),
        vec!["ak.message.create".to_owned()],
    )
    .await;
    assert_eq!(install["effective_status"], json!("partially_installed"));
    let service_token =
        dev_login_token(state.clone(), package.service_id.as_str(), "a11ce0000003").await;

    let ghost_actor_id = format!(
        "did:web:{}.applet.example:ghost:u-denied",
        safe_did_token(&namespace)
    );
    let rejected: Value = TestClient::post(format!(
        "http://server/_arkret/self/applets/{applet_id}/ghosts/provision"
    ))
    .add_header("Authorization", format!("Bearer {service_token}"), true)
    .add_header("Idempotency-Key", format!("denied-{suffix}"), true)
    .json(&signed_ghost_provision_body(
        &package,
        &install,
        &ghost_actor_id,
        "slack",
        "T123",
        "U-denied",
        None,
        &seal_basis,
    ))
    .send(&app)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(rejected["error"]["code"], json!("capability_denied"));
}

#[tokio::test]
async fn applet_ghost_actor_provision_rejects_actor_namespace_mismatch() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let seal_basis = seed_extension_test_seal(&state).await;
    let app = service(state.clone());
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let applet_id = arkret_identifiers::new_prefixed_uuid7("ak:applet:");
    let namespace = format!("bridge.namespace.{suffix}");
    let package = signed_applet_package(&applet_id, &namespace);
    ingest_applet_service_id_document(&state, &package).await;
    let realm_id = DEMO_REALM_ID;
    let install = install_applet_package(
        &state,
        &app,
        &token,
        &package,
        realm_id,
        &format!("ghost-namespace-{suffix}"),
    )
    .await;
    assert_eq!(install["effective_status"], json!("installed"));
    let service_token =
        dev_login_token(state.clone(), package.service_id.as_str(), "a11ce0000004").await;
    let mismatched_ghost = "did:web:other.applet.example:ghost:u123";

    let rejected: Value = TestClient::post(format!(
        "http://server/_arkret/self/applets/{applet_id}/ghosts/provision"
    ))
    .add_header("Authorization", format!("Bearer {service_token}"), true)
    .add_header("Idempotency-Key", format!("namespace-{suffix}"), true)
    .json(&signed_ghost_provision_body(
        &package,
        &install,
        mismatched_ghost,
        "slack",
        "T123",
        "U123",
        None,
        &seal_basis,
    ))
    .send(&app)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        rejected["error"]["code"],
        json!("applet_namespace_mismatch")
    );
}

async fn canonical_did_document(app: &salvo::Service, did: &str) -> Value {
    let body: Value = TestClient::get(format!(
        "http://server/_arkret/root/identity/document?did={did}"
    ))
    .send(app)
    .await
    .take_json()
    .await
    .unwrap();
    body.pointer("/did_document/document")
        .or_else(|| body.get("did_document"))
        .cloned()
        .filter(|value| !value.is_null())
        .filter(|value| value.get("id").is_some())
        .unwrap_or(body)
}

struct AppletMessageTransactionRequest<'a> {
    state: &'a AppState,
    applet_id: &'a str,
    actor_id: &'a str,
    realm_id: &'a str,
    authorization_ref: &'a str,
    actor_seq: u64,
    prev_ref: &'a str,
    text: &'a str,
    idempotency_key: &'a str,
}

async fn post_signed_applet_message_transaction(
    app: &salvo::Service,
    package: &AppletPackage,
    request: AppletMessageTransactionRequest<'_>,
) -> Value {
    let event = applet_message_event(package, &request).await;
    let body = json!({
        "source_service_id": package.service_id.to_string(),
        "events": [event],
    });
    let body_bytes = arkret_canonical::canonical_json_bytes(&body).unwrap();
    let content_digest = content_digest_header(&body_bytes);
    let verification_method =
        arkret_wire::DidUrl::new(format!("{}#applet-service-key", package.service_id))
            .expect("fixture verification method is a DID URL");
    let created = chrono::Utc::now().timestamp();
    let signature_params = format!(
        "(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \
         \"source-service-id\" \"destination-service-id\" \"idempotency-key\");\
         created={created};expires={};keyid=\"{verification_method}\";alg=\"ed25519\"",
        created + 60
    );
    let signature_base = applet_signature_base(
        &content_digest,
        package.service_id.as_str(),
        "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service",
        request.idempotency_key,
        &signature_params,
    );
    let signing_key = applet_service_signing_key(&verification_method);
    let signature = signing_key.sign(signature_base.as_bytes());
    let signature_header = format!(
        "sig1=:{}:",
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    );
    TestClient::post("http://server/_arkret/edge/applet/transactions")
        .add_header("Content-Digest", content_digest, true)
        .add_header("Source-Service-ID", package.service_id.to_string(), true)
        .add_header(
            "Destination-Service-ID",
            "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service",
            true,
        )
        .add_header("Idempotency-Key", request.idempotency_key.to_owned(), true)
        .add_header("Signature-Input", format!("sig1={signature_params}"), true)
        .add_header("Signature", signature_header, true)
        .json(&body)
        .send(app)
        .await
        .take_json()
        .await
        .unwrap()
}

async fn applet_message_event(
    package: &AppletPackage,
    request: &AppletMessageTransactionRequest<'_>,
) -> Value {
    let AppletMessageTransactionRequest {
        state,
        applet_id,
        actor_id,
        realm_id,
        authorization_ref,
        actor_seq,
        prev_ref,
        text,
        ..
    } = request;
    let now = chrono::Utc::now();
    let payload = json!({
        "strand_id": strand_id_for_realm(realm_id),
        "track_name": "discussion",
        "content": {
            "kind": "ak.content.text",
            "body": text,
        },
    });
    let mut event = arkret_wire::Event::new_with_derived_id_at(
        "ak.message.create",
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new((*realm_id).to_owned())
                .expect("fixture Realm id"),
        },
        Did::new((*actor_id).to_owned()).expect("fixture ghost actor DID"),
        *actor_seq,
        arkret_identifiers::Hlc::new(format!(
            "{:012x}-0000-00000000",
            now.timestamp_millis().max(0) as u64
        ))
        .expect("fixture HLC"),
        payload,
        now,
    )
    .expect("SDK Event builder accepts applet transaction fixture");
    event.prev_refs =
        vec![arkret_wire::EventId::new((*prev_ref).to_owned()).expect("fixture prev_ref")];
    event.executed_by = Some(package.service_id.clone());
    event.authorization_ref =
        Some(arkret_wire::AuthorizationRef::new((*authorization_ref).to_owned()).unwrap());
    event.applet_id = Some(
        arkret_identifiers::AppletId::new((*applet_id).to_owned()).expect("fixture applet id"),
    );
    event.external_ref = Some(std::collections::BTreeMap::from([
        ("protocol".to_owned(), json!("smoke")),
        ("external_id".to_owned(), json!(actor_id)),
    ]));
    let verification_method =
        arkret_wire::DidUrl::new(format!("{}#applet-service-key", package.service_id))
            .expect("fixture verification method is a DID URL");
    // `ak.message.create` is a DataEvent. Formal Applet install grants are
    // issued to the executing service, while actor_id remains the accountable
    // ghost, so the frozen CBA view must cover the exact install
    // authorization_ref for the executing service.
    let seal_id =
        seed_applet_message_grant_basis(state, package, realm_id, authorization_ref).await;
    event.seal_ref = Some(seal_id);
    event.auth_context = Some(arkret_wire::AuthContext {
        did: package.service_id.clone(),
        key_id: verification_method.as_str().split_once('#').map_or_else(
            || verification_method.as_str().to_owned(),
            |(_, key)| key.to_owned(),
        ),
        key_epoch: 0,
        credential_epoch: None,
    });
    let signing_key = applet_service_signing_key(&verification_method);
    let signer = Ed25519PayloadSigner::new(
        signing_key,
        package.service_id.clone(),
        verification_method.clone(),
    );
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(now),
    )
    .unwrap();
    serde_json::to_value(event).unwrap()
}

fn content_digest_header(bytes: &[u8]) -> String {
    let raw = Sha256::digest(bytes);
    format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(raw)
    )
}

fn applet_signature_base(
    content_digest: &str,
    source_service_id: &str,
    destination_service_id: &str,
    idempotency_key: &str,
    signature_params: &str,
) -> String {
    format!(
        "\"@method\": POST\n\
         \"@target-uri\": http://server/_arkret/edge/applet/transactions\n\
         \"@authority\": server\n\
         \"content-digest\": {content_digest}\n\
         \"source-service-id\": {source_service_id}\n\
         \"destination-service-id\": {destination_service_id}\n\
         \"idempotency-key\": {idempotency_key}\n\
         \"@signature-params\": {signature_params}",
    )
}

fn applet_service_signing_key(verification_method: &str) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"soland:applet-service-key:");
    hasher.update(verification_method.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&seed)
}

/// The Applet's `ak.message.create` grant, seeded as an accepted protocol fact.
///
/// Goes through the shared test-support builder so the Seal covers a Move
/// digest that names a stored `ak.capability.grant` Event, rather than a
/// literal digest that no Event backs.
async fn seed_applet_message_grant_basis(
    state: &AppState,
    package: &AppletPackage,
    realm_id: &str,
    grant_id: &str,
) -> arkret_identifiers::SealId {
    let actions = ["ak.message.create"];
    let fixture = soland_test_support::sealed_grant::CapabilityGrantFixture {
        realm_id,
        grant_id,
        issuer: "did:web:alice.example",
        subject: package.service_id.as_str(),
        actions: &actions,
        resources: json!([{"kind": "realm", "realm_id": realm_id}]),
        constraints: json!([{
            "constraint_kind": "authority_control",
            "constraint_subkind": "applet_authority",
            "effect": "allow",
            "evaluation_class": "grant_local",
            "applet_id": package.applet_id,
            "executed_by": package.service_id,
            "registration_epoch": package.registration_epoch
        }]),
    };
    soland_test_support::sealed_grant::seed_sealed_capability_grant(state, fixture, Vec::new())
        .await
        .seal_id
}

fn strand_id_for_realm(realm_id: &str) -> String {
    realm_id
        .strip_prefix("ak:realm:")
        .map(|suffix| format!("ak:strand:{suffix}"))
        .unwrap_or_else(|| "ak:strand:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC".to_owned())
}

#[tokio::test]
async fn applet_bridge_register_ghost_route_revoke_smoke() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let seal_basis = seed_extension_test_seal(&state).await;
    let app = service(state.clone());
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let applet_id = arkret_identifiers::new_prefixed_uuid7("ak:applet:");
    let namespace = format!("bridge.smoke.{suffix}");
    let package = signed_applet_package(&applet_id, &namespace);
    ingest_applet_service_id_document(&state, &package).await;
    let realm_id = DEMO_REALM_ID;
    let install = install_applet_package(
        &state,
        &app,
        &token,
        &package,
        realm_id,
        &format!("bridge-{suffix}"),
    )
    .await;
    assert_eq!(install["effective_status"], json!("installed"));
    let service_token =
        dev_login_token(state.clone(), package.service_id.as_str(), "a11ce0000005").await;
    allow_service_message_plaintext(&state, DEMO_REALM_ID).await;
    let bot_actor_id = install["bot_actor_id"].as_str().unwrap().to_owned();
    let message_grant_ref =
        capability_grant_ref_for_action(&install, &package.requested_scopes, "ak.message.create");

    let ghost_actor_id = format!(
        "did:web:{}.applet.example:ghost:ext-user-x",
        safe_did_token(&namespace)
    );
    let mut provision_response = TestClient::post(format!(
        "http://server/_arkret/self/applets/{applet_id}/ghosts/provision"
    ))
    .add_header("Authorization", format!("Bearer {service_token}"), true)
    .add_header("Idempotency-Key", format!("ghost-{suffix}"), true)
    .json(&signed_ghost_provision_body(
        &package,
        &install,
        &ghost_actor_id,
        "smoke",
        "T-smoke",
        "ext-user-x",
        Some("External X"),
        &seal_basis,
    ))
    .send(&app)
    .await;
    let provision_status = provision_response.status_code.unwrap();
    let provision: Value = provision_response.take_json().await.unwrap();
    assert_eq!(
        provision_status,
        StatusCode::CREATED,
        "provision response: {provision}"
    );
    assert_eq!(provision["ghost_actor_id"], json!(ghost_actor_id));

    let transaction_text = format!("hi from outside {suffix}");
    let transaction_idempotency_key = format!("tx-{suffix}");
    let transaction = post_signed_applet_message_transaction(
        &app,
        &package,
        AppletMessageTransactionRequest {
            state: &state,
            applet_id: &applet_id,
            actor_id: &ghost_actor_id,
            realm_id,
            authorization_ref: &message_grant_ref,
            actor_seq: 1,
            prev_ref: provision["profile_event_ref"].as_str().unwrap(),
            text: &transaction_text,
            idempotency_key: &transaction_idempotency_key,
        },
    )
    .await;
    assert_eq!(
        transaction["ok"],
        json!(true),
        "transaction response: {transaction}"
    );
    let messages = state
        .test_persistence()
        .messages()
        .list_for_realm(realm_id, 10)
        .await
        .unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].sender, ghost_actor_id);
    assert_eq!(
        messages[0].content["body"],
        json!(format!("hi from outside {suffix}"))
    );

    let ghost_doc = canonical_did_document(&app, &ghost_actor_id).await;
    assert_eq!(ghost_doc["id"], json!(ghost_actor_id));
    assert_eq!(ghost_doc["status"], json!("active"));
    assert!(
        ghost_doc["accountability"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["kind"] == "applet_registry"
                && entry["did"] == package.controller_id.to_string())
    );

    let revoke_preview: Value = TestClient::post(format!(
        "http://server/_arkret/self/applets/{applet_id}/revoke/preview"
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .json(&json!({
        "effective_scope": {"kind": "realm", "realm_id": realm_id},
        "reason_code": "smoke_test",
        "revoke_mode": "revoke_runtime_only",
    }))
    .send(&app)
    .await
    .take_json()
    .await
    .unwrap();
    let (capability_revoke_events, membership_state_events) =
        signed_revoke_events(&state, realm_id, &revoke_preview).await;
    let revoke_body = json!({
        "revoke_plan_digest": revoke_preview["revoke_plan_digest"].clone(),
        "effective_scope": {"kind": "realm", "realm_id": realm_id},
        "reason_code": "smoke_test",
        "revoke_mode": "revoke_runtime_only",
        "capability_revoke_events": capability_revoke_events,
        "membership_state_events": membership_state_events,
    });
    let revoke_key = format!("revoke-{suffix}");
    let revoke: Value = TestClient::post(format!(
        "http://server/_arkret/self/applets/{applet_id}/revoke"
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .add_header("Idempotency-Key", revoke_key.clone(), true)
    .json(&revoke_body)
    .send(&app)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(revoke["ok"], json!(true));
    assert_eq!(revoke["status"], json!("complete"));

    let replay: Value = TestClient::post(format!(
        "http://server/_arkret/self/applets/{applet_id}/revoke"
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .add_header("Idempotency-Key", revoke_key.clone(), true)
    .json(&revoke_body)
    .send(&app)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(replay["operation_id"], revoke["operation_id"]);
    assert_eq!(replay["steps"], revoke["steps"]);

    let mut conflicting_body = revoke_body.clone();
    conflicting_body["reason_code"] = json!("different_reason");
    let conflict: Value = TestClient::post(format!(
        "http://server/_arkret/self/applets/{applet_id}/revoke"
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .add_header("Idempotency-Key", revoke_key, true)
    .json(&conflicting_body)
    .send(&app)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(conflict["error"]["code"], json!("duplicate_conflict"));

    let rejected_idempotency_key = format!("tx-after-revoke-{suffix}");
    let rejected = post_signed_applet_message_transaction(
        &app,
        &package,
        AppletMessageTransactionRequest {
            state: &state,
            applet_id: &applet_id,
            actor_id: &ghost_actor_id,
            realm_id,
            authorization_ref: &message_grant_ref,
            actor_seq: 1,
            prev_ref: provision["profile_event_ref"].as_str().unwrap(),
            text: "after revoke",
            idempotency_key: &rejected_idempotency_key,
        },
    )
    .await;
    assert_eq!(
        rejected["error"]["code"],
        json!("applet_registration_unauthorized")
    );

    let revoked_doc = canonical_did_document(&app, &ghost_actor_id).await;
    assert_eq!(revoked_doc["status"], json!("revoked"));
    assert!(bot_actor_id.starts_with("did:web:bot-"));
}

fn capability_grant_ref_for_action(
    install: &Value,
    approved_actions: &[String],
    action: &str,
) -> String {
    let index = approved_actions
        .iter()
        .position(|candidate| candidate == action)
        .expect("approved action exists");
    install["capability_grant_refs"][index]
        .as_str()
        .expect("grant ref exists")
        .to_owned()
}

#[tokio::test]
async fn tsp_local_stub_routes_are_not_mounted() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let app = service(state);

    let rejected: Value = TestClient::post("http://server/_soland/self/extensions/tsp/transports")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "transport_id": "tspt:alice-smoke",
            "transport_type": "tsp-pairwise",
            "endpoint_url": "https://alice.example/tsp",
            "supported_protocols": ["arkret"]
        }))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(rejected["error"]["code"], json!("unrecognized_endpoint"));
}

fn signed_applet_package(applet_id: &str, namespace: &str) -> AppletPackage {
    let controller_id = Did::new("did:web:registry.example".to_owned()).unwrap();
    let service_id = Did::new(format!(
        "did:web:{}.applet.example",
        safe_did_token(namespace)
    ))
    .unwrap();
    let bot_actor_id = Did::new(format!(
        "did:web:bot-{}.soland.local",
        safe_did_token(namespace)
    ))
    .unwrap();
    let mut package = AppletPackage::new(
        format!("package:{applet_id}"),
        applet_id.to_owned(),
        service_id,
        controller_id.clone(),
        format!("https://{}.applet.example", safe_did_token(namespace)),
        bot_actor_id,
        vec!["arkret.portal".to_owned()],
        AppletWireNamespaces {
            actors: vec![AppletNamespaceEntry::exclusive(format!(
                "did:web:{}.applet.example:ghost:*",
                safe_did_token(namespace)
            ))],
            handles: vec![AppletNamespaceEntry::exclusive(namespace.to_owned())],
            ..Default::default()
        },
    );
    package.webhook_auth = WebhookAuth::http_message_signature(
        format!("{}#applet-service-key", package.service_id),
        vec![HttpMessageSignatureAlgorithm::Ed25519],
    );
    let service_document = applet_service_id_document(&package);
    let registration_epoch_evidence =
        arkret_models_integration::applet::AppletRegistrationEpochEvidence::from_did_document(
            &service_document,
            arkret_models_integration::applet::AppletDidMethodVersionEvidence::unversioned(
                "did:web",
            )
            .unwrap(),
        )
        .unwrap();
    package.requested_scopes = vec![
        "ak.message.create".to_owned(),
        "ak.applet.ghost.provision".to_owned(),
    ];
    package.claimed_profiles = vec![
        "ak.profile.applet_bridge.v1".to_owned(),
        "ak.profile.applet_service.v1".to_owned(),
    ];
    package.endpoint_policy = AppletEndpointPolicy {
        endpoints: [
            "/_arkret/edge/applet/transactions",
            "/_arkret/edge/applet/actors/{actor_id}",
            "/_arkret/edge/applet/realms/{realm_id_or_alias}",
        ]
        .into_iter()
        .map(|path| AppletEndpointEntry {
            method: AppletEndpointMethod::Post,
            path: path.to_owned(),
            auth: Some(AppletEndpointAuth::WebhookSignature),
            description: None,
            extra: Default::default(),
        })
        .collect(),
        extra: Default::default(),
    };
    package.ghost_policy = AppletGhostPolicy {
        enabled: true,
        accountability_template: Some("bot_actor_and_applet_registry".to_owned()),
        ..Default::default()
    };
    package.receive_events = true;
    package.receive_signals = true;
    package
        .seal_registration_epoch(registration_epoch_evidence)
        .unwrap();
    package.seal().unwrap();
    let verification_method = arkret_wire::DidUrl::new(format!("{controller_id}#applet-package"))
        .expect("fixture verification method is a DID URL");
    let signer = Ed25519PayloadSigner::from_did_key_seed(
        [13u8; 32],
        controller_id,
        verification_method.clone(),
    );
    package.sign(&signer, &verification_method).unwrap();
    package
}

fn applet_service_id_document(package: &AppletPackage) -> arkret_identity::DidDocument {
    let signing_key = SigningKey::from_bytes(&EXTENSION_TEST_SIGNING_SEED);
    let notary_method = format!("{}#notary-key", package.service_id);
    let applet_signing_key = applet_service_signing_key(&package.webhook_auth.key_ref);
    arkret_identity::DidDocument {
        id: package.service_id.clone(),
        verification_methods: BTreeMap::from([
            (
                package.webhook_auth.key_ref.clone(),
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    applet_signing_key.verifying_key().as_bytes(),
                ),
            ),
            (
                notary_method,
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    signing_key.verifying_key().as_bytes(),
                ),
            ),
        ]),
        also_known_as: Vec::new(),
        updated_at: Some(package.created_at),
        raw_properties: BTreeMap::new(),
    }
}

async fn ingest_applet_service_id_document(state: &AppState, package: &AppletPackage) {
    let now = chrono::Utc::now();
    let document = applet_service_id_document(package);
    let record = soland_storage::WebvhDocumentRecord {
        did: package.service_id.to_string(),
        did_document: serde_json::to_value(document).unwrap(),
        key_log_head: Some(package.registration_epoch.to_string()),
        seq: 1,
        method_evidence: json!({ "mode": "test_fixture" }),
        fetched_at: now,
        expires_at: now + chrono::Duration::minutes(15),
        updated_at: now,
    };
    state
        .test_persistence()
        .webvh()
        .put_document(record.clone())
        .await
        .unwrap();
    state
        .test_cache_resolved_webvh_record(soland_services::identity::DidDocumentState {
            did: record.did,
            did_document: record.did_document,
            key_log_head: record.key_log_head,
            seq: record.seq,
            method_evidence: record.method_evidence,
            fetched_at: record.fetched_at,
            expires_at: record.expires_at,
            updated_at: record.updated_at,
        })
        .unwrap();
}

async fn install_applet_package(
    state: &AppState,
    app: &salvo::Service,
    token: &str,
    package: &AppletPackage,
    realm_id: &str,
    idempotency_key: &str,
) -> Value {
    install_applet_package_with_approved_actions(
        state,
        app,
        token,
        package,
        realm_id,
        idempotency_key,
        package.requested_scopes.clone(),
    )
    .await
}

async fn signed_install_events(
    state: &AppState,
    package: &AppletPackage,
    realm_id: &str,
    preview: &Value,
    approved_actions: &[String],
) -> (Event, Vec<Event>) {
    let actor_id = Did::new("did:web:alice.example").unwrap();
    let realm_id = RealmId::new(realm_id.to_owned()).unwrap();
    let scope_ref = ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let verification_method =
        arkret_wire::DidUrl::new("did:web:alice.example#extension-test-notary")
            .expect("fixture verification method is a DID URL");
    let signing_key = SigningKey::from_bytes(&[0x21; 32]);
    let signer = Ed25519PayloadSigner::new(
        signing_key.clone(),
        actor_id.clone(),
        verification_method.clone(),
    );
    let seal_id = state
        .test_seal_leaves(&realm_id)
        .unwrap()
        .into_iter()
        .next()
        .expect("extension test Realm has an accepted Seal");
    let seal_basis = state
        .test_seal(&seal_id)
        .unwrap()
        .expect("extension test Seal is readable")
        .seal_basis();
    let existing = state
        .test_persistence()
        .events()
        .snapshot_all()
        .await
        .unwrap();
    let frontier = existing
        .iter()
        .filter(|event| {
            event.actor_id == actor_id.as_str()
                && event.realm_id.as_deref() == Some(realm_id.as_str())
        })
        .max_by_key(|event| event.actor_seq)
        .expect("extension test Realm has Alice's founding Event");
    let now =
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
    let millis = now.timestamp_millis().max(0) as u64;
    let mut registration_event = Event::new(
        arkret_wire::EventKind::APPLET_REGISTRATION,
        scope_ref.clone(),
        actor_id.clone(),
        frontier.actor_seq + 1,
        Hlc::new(format!("{millis:012x}-0001-a11ce001")).unwrap(),
        preview["events_to_submit"][0]["payload"].clone(),
    )
    .unwrap();
    registration_event.prev_refs = vec![EventId::new(frontier.event_id.clone()).unwrap()];
    registration_event.seal_basis = Some(seal_basis.clone());
    arkret_signatures::sign_event(
        &mut registration_event,
        &signer,
        &verification_method,
        SignEventOptions::new().with_created_at(now),
    )
    .unwrap();

    let mut previous_event_id = registration_event.event_id.clone();
    let mut capability_grant_events = Vec::with_capacity(approved_actions.len());
    for (offset, action) in approved_actions.iter().enumerate() {
        let grant = CapabilityGrantCreateBody {
            schema: arkret_wire::SchemaId::CAPABILITY_V1.to_owned(),
            realm_id: Some(realm_id.clone()),
            issuer: actor_id.clone(),
            subject: CapabilitySubject::Did(package.service_id.clone()),
            actions: vec![action.clone()],
            resources: vec![
                serde_json::from_value(json!({
                    "kind": "realm",
                    "realm_id": realm_id,
                }))
                .unwrap(),
            ],
            capability_action_registry_digest: None,
            constraints: vec![GrantConstraint::applet_authority(
                AppletId::new(package.applet_id.clone()).unwrap(),
                package.service_id.clone(),
                package.registration_epoch.clone(),
            )],
            // The installing owner issues these under the Realm authority root.
            issuer_authority_refs: vec![
                arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef::RealmRoot {
                    realm_id: realm_id.clone(),
                    cell_ref: "ak:cell:ak.component.realm.authority_root.v1:null".to_owned(),
                    controller_epoch_at_issuance: 0,
                    authority_generation: 0,
                },
            ],
            issued_at: now,
            not_before: None,
            expires_at: None,
        };
        let payload = CapabilityGrantPayload { grant };
        let counter = offset + 2;
        let mut event = Event::new(
            arkret_wire::EventKind::CAPABILITY_GRANT,
            scope_ref.clone(),
            actor_id.clone(),
            frontier.actor_seq + counter as u64,
            Hlc::new(format!("{millis:012x}-{counter:04x}-a11ce001")).unwrap(),
            serde_json::to_value(payload).unwrap(),
        )
        .unwrap();
        event.prev_refs = vec![previous_event_id];
        event.seal_basis = Some(seal_basis.clone());
        arkret_signatures::sign_event(
            &mut event,
            &signer,
            &verification_method,
            SignEventOptions::new().with_created_at(now),
        )
        .unwrap();
        previous_event_id = event.event_id.clone();
        capability_grant_events.push(event);
    }
    (registration_event, capability_grant_events)
}

async fn signed_revoke_events(
    state: &AppState,
    realm_id: &str,
    preview: &Value,
) -> (
    Vec<arkret_wire::EventInitialSubmission>,
    Vec<arkret_wire::EventInitialSubmission>,
) {
    let actor_id = Did::new("did:web:alice.example").unwrap();
    let realm_id = RealmId::new(realm_id.to_owned()).unwrap();
    let scope_ref = ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let verification_method =
        arkret_wire::DidUrl::new("did:web:alice.example#extension-test-notary").unwrap();
    let signer = Ed25519PayloadSigner::new(
        SigningKey::from_bytes(&[0x21; 32]),
        actor_id.clone(),
        verification_method.clone(),
    );
    let seal_id = state
        .test_seal_leaves(&realm_id)
        .unwrap()
        .into_iter()
        .next()
        .expect("extension test Realm has an accepted Seal");
    let seal_basis = state
        .test_seal(&seal_id)
        .unwrap()
        .expect("extension test Seal is readable")
        .seal_basis();
    let existing = state
        .test_persistence()
        .events()
        .snapshot_all()
        .await
        .unwrap();
    let frontier = existing
        .iter()
        .filter(|event| {
            event.actor_id == actor_id.as_str()
                && event.realm_id.as_deref() == Some(realm_id.as_str())
        })
        .max_by_key(|event| event.actor_seq)
        .expect("extension test Realm has Alice's install frontier");
    let now =
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
    let millis = now.timestamp_millis().max(0) as u64;
    let mut previous_event_id = EventId::new(frontier.event_id.clone()).unwrap();
    let intents = preview["revoke_plan"]["capability_revocations"]
        .as_array()
        .expect("preview capability revoke intents");
    let mut submissions = Vec::with_capacity(intents.len());
    for (offset, intent) in intents.iter().enumerate() {
        let counter = offset + 1;
        let mut event = Event::new(
            arkret_wire::EventKind::CAPABILITY_REVOKE,
            scope_ref.clone(),
            actor_id.clone(),
            frontier.actor_seq + counter as u64,
            Hlc::new(format!("{millis:012x}-{counter:04x}-a11ce001")).unwrap(),
            json!({
                "grant_id": intent["grant_id"].clone(),
                "reason": intent["reason_code"].clone(),
            }),
        )
        .unwrap();
        event.prev_refs = vec![previous_event_id];
        event.seal_basis = Some(seal_basis.clone());
        arkret_signatures::sign_event(
            &mut event,
            &signer,
            &verification_method,
            SignEventOptions::new().with_created_at(now),
        )
        .unwrap();
        previous_event_id = event.event_id.clone();
        submissions.push(arkret_wire::EventInitialSubmission {
            event,
            authorization_lease: None,
            cba_proof_bundles: Vec::new(),
            control_proposal_ack: None,
            membership_compensation_evidence: None,
        });
    }
    assert!(
        preview["revoke_plan"]["membership_removals"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "this runtime-only smoke install does not create managed membership Events"
    );
    (submissions, Vec::new())
}

async fn install_applet_package_with_approved_actions(
    state: &AppState,
    app: &salvo::Service,
    token: &str,
    package: &AppletPackage,
    realm_id: &str,
    idempotency_key: &str,
    approve_actions: Vec<String>,
) -> Value {
    let effective_scope = json!({"kind": "realm", "realm_id": realm_id});
    let applet_package = applet_package_wire_with_epoch_evidence(package);
    let ghost_actors_allowed = approve_actions
        .iter()
        .any(|action| action == "ak.applet.ghost.provision");
    let preview: Value = TestClient::post("http://server/_arkret/self/applets/install/preview")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "applet_package": applet_package,
            "effective_scope": effective_scope,
            "approval_request": {
                "approve_actions": approve_actions,
                "ghost_actors_allowed": ghost_actors_allowed,
                "delegated_native_actors_allowed": false,
                "e2ee_join_allowed": false,
                "widget_allowed": false,
            },
        }))
        .send(app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        preview["schema"],
        json!("ak.schema.applet_install_plan.v1"),
        "install preview: {preview}"
    );
    let (registration_event, capability_grant_events) =
        signed_install_events(state, package, realm_id, &preview, &approve_actions).await;

    let commit: Value = TestClient::post("http://server/_arkret/self/applets/install")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", idempotency_key.to_owned(), true)
        .json(&json!({
            "plan_digest": preview["plan_digest"].clone(),
            "applet_package": applet_package,
            "effective_scope": {"kind": "realm", "realm_id": realm_id},
            "registration_event": registration_event,
            "capability_grant_events": capability_grant_events,
            "actor_policy": {
                "bot_membership": "join",
                "ghost_actor_mode": "policy_declared",
            },
            "e2ee_policy": {"mls_join_allowed": false},
            "widget_policy": {"widget_allowed": false},
        }))
        .send(app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(commit["ok"], json!(true), "install commit: {commit}");
    commit
}

fn applet_package_wire_with_epoch_evidence(package: &AppletPackage) -> Value {
    let mut wire = serde_json::to_value(package).expect("Applet package serializes");
    wire.as_object_mut()
        .expect("Applet package wire value is an object")
        .insert(
            "registration_epoch_evidence".to_owned(),
            serde_json::to_value(
                package
                    .registration_epoch_evidence
                    .as_ref()
                    .expect("Applet package fixture has registration epoch evidence"),
            )
            .expect("registration epoch evidence serializes"),
        );
    wire
}

fn safe_did_token(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '.' {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

// S-00 regression: the sovereign deployment surface
// (`/_soland/admin/deployment/*`, `/_soland/self/account/*`, etc.) MUST
// reject unauthenticated callers. Before the fix the whole `self` segment
// mounted `sovereign::router()` with no auth hoop and no per-handler
// `authenticated_session`, exposing every read/write handler to anonymous
// access. These negatives assert the fail-closed 401 on both a management
// write and an operator read.

#[tokio::test]
async fn sovereign_deployment_configure_rejects_unauthenticated() {
    let state = soland_test_support::app_state(test_config());
    state.hydrate().await.unwrap();
    let app = service(state);

    let response = TestClient::post("http://server/_soland/admin/deployment/configure")
        .json(&json!({ "upstream_available": true }))
        .send(&app)
        .await;
    assert_eq!(
        response.status_code.unwrap(),
        StatusCode::UNAUTHORIZED,
        "deployment.configure must reject an unauthenticated caller"
    );
}

#[tokio::test]
async fn sovereign_deployment_audit_rejects_unauthenticated() {
    let state = soland_test_support::app_state(test_config());
    state.hydrate().await.unwrap();
    let app = service(state);

    let response = TestClient::get("http://server/_soland/admin/deployment/audit")
        .send(&app)
        .await;
    assert_eq!(
        response.status_code.unwrap(),
        StatusCode::UNAUTHORIZED,
        "deployment.audit must reject an unauthenticated caller"
    );
}
