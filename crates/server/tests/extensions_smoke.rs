//! G3.S9 — integration smoke for the four new extensions routes.
//!
//! Per `cotest/e2e/scenarios/extensions/applet-bridge.md`,
//! `cotest/e2e/scenarios/identity/tsp-bootstrap.md`, and the existing
//! cotest fixture mocks (`cotest/e2e/mocks/mock-applet-registry.mjs`,
//! `cotest/e2e/mocks/mock-tsp-endpoint.mjs`). The integration test
//! posts to each route and verifies the spec-shaped envelope.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

use arkret_identifiers::{AppletId, Did, EventId, Hlc, RealmId};
use arkret_models_collaboration::events_payloads::{
    ActorProfileCreatePayload, CapabilityGrantCreateBody, CapabilityGrantPayload,
    RealmCreatePayload, RealmGenesis,
};
use arkret_models_collaboration::governance::grant_constraint::{
    CapabilitySubject, GrantConstraint, GrantConstraintEffect, GrantConstraintKind,
};
use arkret_models_integration::applet::{
    AppletEndpointAuth, AppletEndpointEntry, AppletEndpointMethod, AppletEndpointPolicy,
    AppletGhostPolicy, AppletManagedActorProvisionPayload, AppletManagedActorRole,
    AppletNamespaceEntry, AppletPackage, AppletWireNamespaces, HttpMessageSignatureAlgorithm,
    WebhookAuth,
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
use url::Url;

/// The durable Applet installation key is `(applet_id, effective_scope_key)`
/// since Applet identity was split from scoped installations. Tests derive the
/// scope key the same way production does instead of hardcoding a digest.
fn realm_scope_key(realm_id: &str) -> String {
    soland_storage::applet_effective_scope_key(&ScopeRef::Realm {
        realm_id: arkret_identifiers::RealmId::new(realm_id.to_owned()).expect("fixture Realm id"),
    })
    .expect("canonical Applet effective scope key")
}

/// Derived, never copied: the demo Realm id is `retype(genesis.event_id)` and
/// moves with any `arkret-spec` change that touches the genesis payload.
fn demo_realm_id() -> &'static str {
    static ID: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        soland_test_support::app_state(test_config())
            .development_demo_realm_id()
            .to_string()
    });
    &ID
}
// `new_with_demo_data` metadata still uses a historical fixture Realm id.
// Clone it into the Realm derived from the shared canonical development
// genesis before exercising authenticated routes.
const SEEDED_METADATA_DEMO_REALM_ID: &str = "ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1";
const EXTENSION_TEST_SIGNING_SEED: [u8; 32] = [0x5a; 32];
const ALICE_DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-a11ce0000001";

fn fixture_suffix() -> String {
    uuid::Uuid::now_v7().simple().to_string()[..12].to_owned()
}

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
        service_id.clone(),
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
    let actor_core = arkret_identifiers::DidCoreId::new(actor.to_owned()).unwrap_or_else(|_| {
        arkret_wire::project_did_to_core_id(&Did::new(actor.to_owned()).unwrap()).unwrap()
    });
    let login: Value = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&json!({
            "actor": actor_core,
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
    let typed_realm_id = arkret_identifiers::RealmId::new(demo_realm_id().to_owned()).unwrap();
    if state
        .test_persistence()
        .realm_meta()
        .get(demo_realm_id())
        .await
        .unwrap()
        .is_none()
    {
        let meta = state
            .test_persistence()
            .realm_meta()
            .get(SEEDED_METADATA_DEMO_REALM_ID)
            .await
            .unwrap()
            .expect("seeded demo Realm metadata");
        state
            .test_persistence()
            .realm_meta()
            .put(demo_realm_id(), &meta)
            .await
            .unwrap();
    }
    let actor_did =
        arkret_wire::project_did_to_core_id(&Did::new(actor.to_owned()).unwrap()).unwrap();
    let now = chrono::Utc::now();
    {
        let mut realms = state.test_realms().lock();
        let mut realm = realms.get(&typed_realm_id).cloned().unwrap_or_else(|| {
            let seeded_realm_id = RealmId::new(demo_realm_id().to_owned()).unwrap();
            let mut seeded = realms
                .get(&seeded_realm_id)
                .cloned()
                .expect("seeded demo Realm directory entry");
            seeded.realm_id = typed_realm_id.clone();
            seeded
        });
        realm.members.insert(actor_did.clone());
        realms.upsert(realm);
    }
    // Login hydrates the projection from persistence, so install the explicit
    // test membership only after that boundary, never before it is reset.
    let token = dev_login_token(state.clone(), actor, device_suffix).await;
    let member_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        actor_did,
        state.service_core_id(),
    ));
    state.test_projection().lock().members.insert(
        (demo_realm_id().to_owned(), member_actor.to_string()),
        soland_domain::reducer::SolandMembershipState {
            member: member_actor.to_string(),
            realm_id: demo_realm_id().to_owned(),
            state: "join".to_owned(),
            role: "member".to_owned(),
            membership_event_ref: None,
            invited_at: None,
            joined_at: now,
            updated_at: now,
            reason: None,
        },
    );
    let device_id = format!("ak:device:01904100-0000-7000-8000-{device_suffix}");
    let verification_method = format!("{actor}#{device_id}");
    let signing_key = SigningKey::from_bytes(&arkret_signatures::development_signing_key_seed(
        &verification_method,
    ));
    soland_test_support::project_authorized_principal_device(
        &state,
        actor,
        &device_id,
        &signing_key,
    )
    .await;
    token
}

/// A citable accepted Seal of the demo Realm that establishes this service as
/// the current single-signer proposal/notary authority.
///
/// `event-auth-state-resolution.md` §5 makes a control-plane Event a Control
/// Move whose `seal_basis.leaves` must be non-empty; unlike a DataEvent
/// `seal_ref`, the leaves are not resolved into an authorization pre-state at
/// admission, but Control Proposal Ack admission still resolves the accepted
/// notary cell.
async fn seed_extension_test_seal(state: &AppState) -> arkret_wire::SealBasis {
    ingest_extension_admin_document(state).await;
    let device_verification_method = format!("did:web:alice.example#{ALICE_DEVICE_ID}");
    let device_signing_key = SigningKey::from_bytes(
        &arkret_signatures::development_signing_key_seed(&device_verification_method),
    );
    soland_test_support::project_authorized_principal_device(
        state,
        "did:web:alice.example",
        ALICE_DEVICE_ID,
        &device_signing_key,
    )
    .await;
    let realm = arkret_identifiers::RealmId::new(demo_realm_id()).unwrap();
    let admin_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::project_did_to_core_id(&Did::new("did:web:alice.example").unwrap()).unwrap(),
        state.service_core_id(),
    ));
    {
        let mut projection = state.test_projection().lock();
        let genesis = projection
            .realm_null_subject_cells
            .entry((
                demo_realm_id().to_owned(),
                arkret_wire::REALM_GENESIS_CELL.to_owned(),
            ))
            .or_insert_with(|| arkret_state::lattice::CellState::Value(serde_json::json!({})));
        if let arkret_state::lattice::CellState::Value(Value::Object(object)) = genesis {
            object.insert(
                "digest_algorithm".to_owned(),
                Value::String("sha256".to_owned()),
            );
            let schema_refs = object
                .entry("schema_refs".to_owned())
                .or_insert_with(|| Value::Array(Vec::new()))
                .as_array_mut()
                .expect("fixture Realm schema_refs must be an array");
            let applet_profile = Value::String(arkret_wire::ProfileId::APPLET_BRIDGE_V1.to_owned());
            if !schema_refs.contains(&applet_profile) {
                schema_refs.push(applet_profile);
            }
        }
        projection.realm_null_subject_cells.insert(
            (
                demo_realm_id().to_owned(),
                format!(
                    "ak:cell:{}:null",
                    arkret_wire::CellFamilyId::REALM_REDUCER_PROFILE_V1
                ),
            ),
            arkret_state::lattice::CellState::Value(Value::String(
                arkret_wire::CORE_REDUCER_PROFILE.to_owned(),
            )),
        );
        let authority_root =
            arkret_policy::realm_bootstrap::RealmAuthorityRootValue::genesis(admin_actor.clone());
        projection.realm_null_subject_cells.insert(
            (
                demo_realm_id().to_owned(),
                arkret_wire::REALM_AUTHORITY_ROOT_CELL.to_owned(),
            ),
            arkret_state::lattice::CellState::Value(serde_json::to_value(authority_root).unwrap()),
        );
    }
    let create = soland_http::state::development_demo_genesis_event(
        &state.service_did(),
        &arkret_identifiers::DidCoreId::new(state.service_id().clone()).unwrap(),
        state.notary_signing_key().to_bytes(),
    )
    .into_event();
    assert_eq!(RealmId::from_event_id(&create.event_id), realm);
    let move_id = arkret_identifiers::Hash::new(
        create
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap(),
    )
    .unwrap();
    let admin_grant_create_body = json!({
        "schema": arkret_wire::SchemaId::CAPABILITY_V1,
        "realm_id": demo_realm_id(),
        "issuer_id": admin_actor,
        "issuer_authority_refs": [{
            "kind": "realm_root",
            "realm_id": demo_realm_id(),
            "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
            "controller_epoch_at_issuance": 0,
            "authority_generation": 0
        }],
        "subject": admin_actor,
        "actions": soland_services::conformance_basis::OWNER_BOOTSTRAP_GRANT_ACTIONS,
        "resources": [{
            "kind": "realm",
            "realm_id": demo_realm_id(),
            "match_scope": "realm_wide"
        }],
        "issued_at": "2026-01-01T00:00:00.000Z"
    });
    let admin_grant_event = arkret_wire::test_support::raw_event(
        arkret_wire::EventKind::CapabilityGrant.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        admin_actor.signing_principal_id().clone(),
        admin_actor.route_service_id().clone(),
        1,
        arkret_identifiers::Hlc::new("0196419a0000-0000-a11ce001").unwrap(),
        json!({"grant": admin_grant_create_body.clone()}),
    )
    .unwrap();
    let admin_grant_id = arkret_identifiers::GrantId::from_event_id(&admin_grant_event.event_id);
    let mut admin_grant_value = admin_grant_create_body;
    admin_grant_value
        .as_object_mut()
        .unwrap()
        .insert("grant_id".to_owned(), json!(admin_grant_id.clone()));
    let admin_grant_move_id = arkret_identifiers::Hash::new(
        admin_grant_event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap(),
    )
    .unwrap();
    let notary_cell: arkret_identifiers::CellRef = arkret_wire::REALM_NOTARY_CELL.parse().unwrap();
    let notary_op = arkret_state::lattice::ordered_log::IssuedOp {
        issuer_id: arkret_wire::ActorId::service(
            arkret_identifiers::DidCoreId::new(state.service_id().clone()).unwrap(),
        ),
        op: arkret_state::lattice::SealedOp::new(
            move_id.clone(),
            arkret_wire::LatticeOp {
                op_type: arkret_wire::LatticeOpType::Set,
                tag: None,
                value: Some(
                    serde_json::to_value(arkret_wire::NotaryValue::single_signer(
                        state.service_notary_signer_descriptor().unwrap(),
                    ))
                    .unwrap(),
                ),
                from: None,
                to: None,
                reason: None,
                issuer_seq: None,
            },
        ),
    };
    let admin_grant_cell = arkret_identifiers::CellRef::new(format!(
        "ak:cell:ak.component.capability.grant.v1:{admin_grant_id}"
    ))
    .unwrap();
    let admin_grant_op = arkret_state::lattice::ordered_log::IssuedOp {
        issuer_id: admin_actor.clone(),
        op: arkret_state::lattice::SealedOp::new(
            admin_grant_move_id.clone(),
            arkret_wire::LatticeOp {
                op_type: arkret_wire::LatticeOpType::Add,
                tag: Some(admin_grant_move_id.to_string()),
                value: Some(admin_grant_value),
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
    let state_root = arkret_state::compute_state_root(
        &BTreeMap::from([
            (notary_cell.clone(), notary_joined),
            (admin_grant_cell.clone(), grant_joined),
        ]),
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let signer = soland_services::identity::FrozenEd25519NotarySigner::from_seed(
        state.notary_signing_key().to_bytes(),
        state.service_did(),
        state.service_verification_method("notary-key").unwrap(),
    );
    let authority_set_ref = arkret_identifiers::Hash::new(
        arkret_canonical::canonical_sha256(&state.service_notary_signer_descriptor().unwrap())
            .unwrap(),
    )
    .unwrap();
    let create_authority_ack = arkret_wire::ControlProposalAuthorityAck::issue_with_signer(
        realm.clone(),
        move_id.clone(),
        authority_set_ref.clone(),
        create.created_at,
        arkret_wire::ControlProposalDecisionPolicy::default(),
        &signer,
    )
    .unwrap();
    let create_ack = arkret_wire::ControlProposalAck::from_authority_acks_protocol_bounds(vec![
        create_authority_ack,
    ])
    .unwrap();
    state
        .test_put_pending_control_event_with_ack(
            &create,
            &create_ack,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
    state
        .test_persistence()
        .events()
        .put(soland_test_support::signed_event::canonical_event_record(
            &admin_grant_event,
            Some(realm.as_str()),
            admin_grant_event.created_at,
        ))
        .await
        .unwrap();
    let admin_grant_authority_ack = arkret_wire::ControlProposalAuthorityAck::issue_with_signer(
        realm.clone(),
        admin_grant_move_id.clone(),
        authority_set_ref,
        admin_grant_event.created_at,
        arkret_wire::ControlProposalDecisionPolicy::default(),
        &signer,
    )
    .unwrap();
    let admin_grant_ack =
        arkret_wire::ControlProposalAck::from_authority_acks_protocol_bounds(vec![
            admin_grant_authority_ack,
        ])
        .unwrap();
    state
        .test_put_pending_control_event_with_ack(
            &admin_grant_event,
            &admin_grant_ack,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
    let mut delta = vec![move_id, admin_grant_move_id];
    delta.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    let covered = delta.iter().cloned().collect::<BTreeSet<_>>();
    let control_event_set_root =
        arkret_state::control_event_set_root(&covered, arkret_canonical::DigestSuite::Sha256)
            .unwrap();
    let listed = delta
        .iter()
        .enumerate()
        .map(|(index, event_digest)| arkret_state::ListedControlEvent {
            actor_id: notary_op.issuer_id.clone(),
            actor_seq: u64::try_from(index + 1).unwrap(),
            event_digest: event_digest.clone(),
        })
        .collect::<Vec<_>>();
    let completeness_root = arkret_state::control_event_completeness_root_from_listed(
        &listed,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let seal = arkret_wire::Seal::sign_single_with_roots(
        realm.clone(),
        Vec::new(),
        delta,
        control_event_set_root,
        completeness_root,
        state_root,
        arkret_identifiers::Hlc::new("0196419b0000-0000-a11ce001").unwrap(),
        arkret_canonical::DigestSuite::Sha256,
        &signer,
    )
    .unwrap();
    state
        .test_put_seal(&seal, arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    state
        .test_append_sealed_effects(
            &realm,
            &seal.id,
            &[(notary_cell, notary_op), (admin_grant_cell, admin_grant_op)],
        )
        .unwrap();
    state.test_refresh_grant_from_sealed_cells(&realm, admin_grant_id.as_str());
    soland_test_support::cba_basis::seed_realm_genesis_event(
        state,
        demo_realm_id(),
        "did:web:alice.example",
    )
    .await;
    seal.seal_basis()
}

async fn ingest_extension_admin_document(state: &AppState) {
    let now = chrono::Utc::now();
    let did = Did::new("did:web:alice.example").unwrap();
    let verification_method =
        arkret_wire::DidUrl::new("did:web:alice.example#extension-test-notary".to_owned())
            .expect("fixture verification method is a DID URL");
    let signing_key = SigningKey::from_bytes(&[0x21; 32]);
    let device_verification_method = format!("did:web:alice.example#{ALICE_DEVICE_ID}");
    let device_signing_key = SigningKey::from_bytes(
        &arkret_signatures::development_signing_key_seed(&device_verification_method),
    );
    let document = arkret_identity::DidDocument {
        id: did.clone(),
        verification_methods: BTreeMap::from([
            (
                verification_method.as_str().to_owned(),
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    signing_key.verifying_key().as_bytes(),
                ),
            ),
            (
                device_verification_method,
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    device_signing_key.verifying_key().as_bytes(),
                ),
            ),
        ]),
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

#[derive(Clone)]
struct ManagedActorFixture {
    actor_id: arkret_identifiers::DidCoreId,
    initial_resolution: arkret_models_identity::ResolutionCommitment,
    method_history_evidence: arkret_models_identity::ResolutionMethodHistoryEvidence,
    inception_log_entry: Value,
}

fn deterministic_managed_actor_seed(label: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"soland:extensions-smoke:managed-actor:");
    hasher.update(label.as_bytes());
    hasher.finalize().into()
}

fn managed_actor_fixture(
    namespace: &str,
    local_id: &str,
    controller_id: &arkret_identifiers::DidCoreId,
) -> ManagedActorFixture {
    let endpoint: Url = format!(
        "https://managed-{}.applet.example/",
        safe_did_token(namespace)
    )
    .parse()
    .expect("fixture managed-actor endpoint");
    let local_id = safe_did_token(local_id);
    let root_seed = deterministic_managed_actor_seed(&format!(
        "{}:{local_id}:root:{controller_id}",
        safe_did_token(namespace)
    ));
    let next_seed = deterministic_managed_actor_seed(&format!(
        "{}:{local_id}:next:{controller_id}",
        safe_did_token(namespace)
    ));
    let next_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&next_seed)
            .verifying_key()
            .as_bytes(),
    );
    let version_time = chrono::DateTime::parse_from_rfc3339("2026-08-24T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let inception = arkret_signatures::webvh::prepare_agent_inception(
        &arkret_signatures::webvh::AgentInceptionInput {
            principal_endpoint: &endpoint,
            local_id: &local_id,
            controller_id,
            version_time,
            root_seed: &root_seed,
            next_root_public_key_multibase: &next_key,
        },
    )
    .expect("fixture managed-actor WebVH inception");
    let did = Did::new(inception.did.clone()).expect("fixture managed-actor DID");
    let actor_id = arkret_wire::project_did_to_core_id(&did)
        .expect("fixture managed-actor Core DID projection");
    let method_history_head = arkret_canonical::canonical_sha256(&inception.log_entry)
        .expect("fixture WebVH history head");
    let normalized_document: arkret_models_identity::DidDocument =
        serde_json::from_value(inception.log_entry["state"].clone())
            .expect("fixture WebVH DID document");
    let document_digest = arkret_identity::document_canonical_digest(&normalized_document)
        .expect("fixture WebVH document digest");
    let witness_records = Vec::<Value>::new();
    let witness_proofs_digest = arkret_identifiers::Hash::new(
        arkret_canonical::canonical_sha256(&witness_records).expect("fixture WebVH witness digest"),
    )
    .unwrap();
    let boundary = arkret_models_identity::ResolutionMethodEvidenceBoundary {
        from_method_history_head: method_history_head.clone(),
        from_version_id: inception.version_id.clone(),
        to_method_history_head: method_history_head.clone(),
        to_version_id: inception.version_id.clone(),
    };
    let method_history_evidence =
        arkret_models_identity::ResolutionMethodHistoryEvidence::WebvhLog {
            adapter_version: "did:webvh:1.0".to_owned(),
            boundary,
            evidence: arkret_models_identity::ResolutionDidBindingEvidenceReceipt {
                kind:
                    arkret_models_identity::ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                method: "webvh".to_owned(),
                document_digest,
                method_proofs: vec![arkret_models_identity::ResolutionDidBindingMethodProof {
                    kind: arkret_models_identity::ResolutionDidBindingMethodProofKind::WebvhLog,
                    history_head: method_history_head.clone(),
                    witnesses: Vec::new(),
                    witness_proofs_digest,
                }],
            },
            log_entries: vec![inception.log_entry.clone()],
            witness_records,
        };
    ManagedActorFixture {
        actor_id,
        initial_resolution: arkret_models_identity::ResolutionCommitment {
            did,
            method_history_head,
            version_id: inception.version_id,
        },
        method_history_evidence,
        inception_log_entry: inception.log_entry,
    }
}

async fn ingest_managed_actor_current_document(state: &AppState, actor: &ManagedActorFixture) {
    let now = chrono::Utc::now();
    let did = actor.initial_resolution.did.to_string();
    let document = actor.inception_log_entry["state"].clone();
    let record = soland_storage::WebvhDocumentRecord {
        did: did.clone(),
        did_document: document,
        key_log_head: Some(actor.initial_resolution.method_history_head.clone()),
        seq: 1,
        method_evidence: serde_json::to_value(&actor.method_history_evidence).unwrap(),
        fetched_at: now,
        expires_at: now + chrono::Duration::minutes(15),
        updated_at: now,
    };
    state
        .test_persistence()
        .webvh()
        .append_log_event(soland_storage::WebvhLogRecord {
            event_digest: actor.initial_resolution.method_history_head.clone(),
            did,
            seq: 1,
            operation: actor.inception_log_entry.clone(),
            created_at: now,
        })
        .await
        .unwrap();
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

fn finalize_and_sign_applet_event(
    event: Event,
    package: &AppletPackage,
    now: chrono::DateTime<chrono::Utc>,
) -> Event {
    let verification_method = package.webhook_auth.key_ref.clone();
    let signer = Ed25519PayloadSigner::new(
        applet_service_signing_key(&verification_method),
        Did::new(
            verification_method
                .as_str()
                .split_once('#')
                .expect("fixture verification method has a fragment")
                .0,
        )
        .unwrap(),
        verification_method.clone(),
    );
    let mut event = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .expect("fixture envelope finalizes");
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        &verification_method,
        SignEventOptions::new().with_created_at(now),
    )
    .unwrap();
    event.into_event()
}

#[allow(clippy::too_many_arguments)]
fn managed_actor_provision_event(
    package: &AppletPackage,
    actor: &ManagedActorFixture,
    actor_role: AppletManagedActorRole,
    actor_station_id: arkret_identifiers::DidCoreId,
    realm_id: RealmId,
    registration_ref: EventId,
    applet_authority_ref: arkret_identifiers::GrantId,
    external_ref: Option<arkret_models_integration::GhostExternalTuple>,
    actor_seq: u64,
    prev_refs: Vec<EventId>,
    seal_basis: arkret_wire::SealBasis,
    now: chrono::DateTime<chrono::Utc>,
) -> Event {
    let payload = AppletManagedActorProvisionPayload {
        schema: AppletManagedActorProvisionPayload::SCHEMA.to_owned(),
        applet_id: package.applet_id.clone(),
        service_id: package.service_id.clone(),
        actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            actor.actor_id.clone(),
            actor_station_id.clone(),
        )),
        actor_role,
        initial_resolution: actor.initial_resolution.clone(),
        method_history_evidence: actor.method_history_evidence.clone().try_into().unwrap(),
        registration_ref,
        applet_authority_ref: applet_authority_ref.clone(),
        external_ref,
    };
    payload.validate().expect("fixture managed-actor payload");
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        "ak.applet.managed_actor.provision",
        ScopeRef::Realm { realm_id },
        arkret_wire::ActorId::service(package.service_id.clone()),
        actor_seq,
        Hlc::new(format!(
            "{:012x}-0100-a11ce001",
            now.timestamp_millis().max(0) as u64
        ))
        .unwrap(),
        serde_json::to_value(payload).unwrap(),
        now,
    )
    .unwrap();
    event.prev_refs = prev_refs;
    event.applet_id = Some(package.applet_id.clone());
    event.authorization_ref = Some(applet_authority_ref.into());
    event.seal_basis = Some(seal_basis);
    finalize_and_sign_applet_event(event, package, now)
}

fn applet_managed_pcr_genesis_event(
    package: &AppletPackage,
    actor: &ManagedActorFixture,
    actor_station_id: arkret_identifiers::DidCoreId,
    target_station_notary: arkret_wire::NotarySignerDescriptor,
    applet_authority_ref: arkret_identifiers::GrantId,
    provision_ref: EventId,
    now: chrono::DateTime<chrono::Utc>,
) -> Event {
    let salt_seed =
        deterministic_managed_actor_seed(&format!("{}:{}:pcr", package.applet_id, actor.actor_id));
    let genesis = RealmGenesis::applet_managed_control(
        arkret_wire::GenesisSalt::new(arkret_canonical::base64url_encode(salt_seed)).unwrap(),
        actor.initial_resolution.clone(),
        arkret_identifiers::TrustDomainId::new("ak:trust_domain:applet.example").unwrap(),
        vec![
            arkret_wire::SchemaId::REALM_V1.to_owned(),
            arkret_wire::ProfileId::PRINCIPAL_CONTROL_REALM_V1.to_owned(),
        ],
        arkret_wire::CORE_REDUCER_PROFILE,
        arkret_canonical::DigestSuite::Sha256,
        arkret_wire::SecurityClass::HighAssurance,
        arkret_wire::EncryptionProfile::MlsRfc9420,
        arkret_wire::NotaryValue::single_signer(target_station_notary),
    )
    .expect("fixture Applet-managed PCR genesis");
    let mut event = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::RealmCreate.as_str(),
        ScopeRef::RealmGenesis,
        actor.actor_id.clone(),
        actor_station_id.clone(),
        0,
        Hlc::new(format!(
            "{:012x}-0101-a11ce001",
            now.timestamp_millis().max(0) as u64
        ))
        .unwrap(),
        serde_json::to_value(RealmCreatePayload::new(genesis)).unwrap(),
        now,
    )
    .unwrap();
    event.executed_by = Some(arkret_wire::ActorId::service(package.service_id.clone()));
    event.authorization_ref = Some(applet_authority_ref.into());
    event.applet_id = Some(package.applet_id.clone());
    event.refs = vec![arkret_wire::EventRef::new(
        provision_ref.to_string(),
        "applet_managed_actor_provision",
    )];
    finalize_and_sign_applet_event(event, package, now)
}

// Each parameter is a separate signed field of the ghost provision body.
#[allow(clippy::too_many_arguments)]
async fn signed_ghost_provision_body(
    app: &salvo::Service,
    state: &AppState,
    package: &AppletPackage,
    install: &Value,
    ghost_actor: &ManagedActorFixture,
    protocol: &str,
    instance_id: &str,
    external_id: &str,
    display_name: Option<&str>,
    seal_basis: &arkret_wire::SealBasis,
) -> Value {
    use arkret_models_collaboration::governance::accountability::{
        AccountabilityGrantPayload, AccountabilityScope, AccountabilityScopeKind,
    };

    let realm_id = arkret_identifiers::RealmId::new(demo_realm_id().to_owned()).unwrap();
    let ghost_actor_id = ghost_actor.actor_id.clone();
    let applet_id = package.applet_id.clone();
    let authorization_ref = if install["effective_status"] == json!("installed") {
        capability_grant_ref_for_action(
            install,
            &package.requested_scopes,
            "ak.applet.ghost.provision",
        )
    } else {
        "ak:grant:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk".to_owned()
    };
    let bot_actor_id: arkret_wire::ActorId =
        serde_json::from_value(install["bot_actor_id"].clone())
            .expect("install outcome has a complete bot ActorId");
    let actor_station_id = bot_actor_id.route_service_id().clone();
    let registration_ref = EventId::new(
        install["registration_event_ref"]
            .as_str()
            .expect("install outcome has registration Event")
            .to_owned(),
    )
    .unwrap();
    let applet_authority_ref = arkret_identifiers::GrantId::new(authorization_ref.clone()).unwrap();
    let verification_method = package.webhook_auth.key_ref.clone();
    let signing_key = applet_service_signing_key(&verification_method);
    let external_ref = arkret_models_integration::GhostExternalTuple {
        protocol: protocol.to_owned(),
        instance_id: instance_id.to_owned(),
        external_id: external_id.to_owned(),
    };
    let preview_body = json!({
        "realm_id": realm_id,
        "external_ref": external_ref,
        "display_name": display_name,
    });
    let mut preview_response = post_signed_ghost_preview(
        app,
        state,
        package,
        applet_id.as_str(),
        &format!("preview-{external_id}"),
        &preview_body,
    )
    .await;
    let preview_status = preview_response.status_code;
    let preview: Value = preview_response.take_json().await.unwrap();
    assert_eq!(
        preview_status,
        Some(StatusCode::OK),
        "Ghost preview must succeed before a provision request: {preview}"
    );
    let authoring_request: arkret_models_integration::AppletManagedActorAuthoringRequest =
        serde_json::from_value(preview["authoring_request"].clone())
            .expect("Ghost preview returns a typed authoring request");
    let now = authoring_request.issued_at;
    let managed_actor_provision_event = managed_actor_provision_event(
        package,
        ghost_actor,
        AppletManagedActorRole::Ghost,
        actor_station_id.clone(),
        realm_id.clone(),
        registration_ref,
        applet_authority_ref.clone(),
        Some(external_ref.clone()),
        2,
        vec![
            EventId::new(
                install["_fixture_bot_accountability_ref"]
                    .as_str()
                    .expect("fixture install records the service actor frontier")
                    .to_owned(),
            )
            .unwrap(),
        ],
        seal_basis.clone(),
        now,
    );
    let pcr_genesis_event = applet_managed_pcr_genesis_event(
        package,
        ghost_actor,
        actor_station_id.clone(),
        state.service_notary_signer_descriptor().unwrap(),
        applet_authority_ref,
        managed_actor_provision_event.event_id.clone(),
        now,
    );
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
    let mut accountability_event = arkret_wire::test_support::raw_event_for_actor_at(
        arkret_wire::EventKind::IdentityAccountabilityGrant.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        arkret_wire::ActorId::service(package.service_id.clone()),
        3,
        arkret_identifiers::Hlc::new(format!(
            "{:012x}-0102-a11ce001",
            now.timestamp_millis().max(0) as u64
        ))
        .unwrap(),
        serde_json::to_value(grant).unwrap(),
        now,
    )
    .unwrap();
    accountability_event.applet_id = Some(applet_id.clone());
    accountability_event.authorization_ref =
        Some(arkret_wire::AuthorizationRef::new(authorization_ref.clone()).unwrap());
    accountability_event.prev_refs = vec![managed_actor_provision_event.event_id.clone()];
    accountability_event.seal_basis = Some(seal_basis.clone());
    let accountability_event = finalize_and_sign_applet_event(accountability_event, package, now);

    let profile = arkret_event_draft::GhostActorProfileRequest::new(
        ghost_actor_id.clone(),
        display_name.unwrap_or(external_id),
        applet_id.clone(),
        external_ref.clone(),
    )
    .with_realm_id(realm_id.clone())
    .with_accountable_principal_ids(vec![package.service_id.clone()]);
    let delegation = arkret_models_integration::AppletDelegatedEventAuthorization::new(
        package.service_id.clone(),
        arkret_wire::AuthorizationRef::new(authorization_ref).unwrap(),
        applet_id.clone(),
    );
    // `ak.profile.create` is a control-plane reducer input in the event-kind
    // registry, so `event-auth-state-resolution.md` §5 makes it a Control Move:
    // it names the same accepted Seal basis as the accountability grant it
    // travels with. The delegated applet authorization on the envelope is a
    // separate, additive check — it never substitutes for the CBA basis. Both
    // are producer-signed content, so they ride the intent, and the reference
    // to the grant names its FINAL id.
    let profile_intent = profile
        .profile_create_intent(
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                ghost_actor_id.clone(),
                actor_station_id.clone(),
            )),
            now,
            Some(&delegation),
        )
        .unwrap();
    let mut profile_event = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::ProfileCreate.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        ghost_actor_id.clone(),
        actor_station_id.clone(),
        0,
        arkret_identifiers::Hlc::new(format!(
            "{:012x}-0103-a11ce001",
            now.timestamp_millis().max(0) as u64
        ))
        .unwrap(),
        serde_json::to_value(profile_intent.payload()).unwrap(),
        now,
    )
    .unwrap();
    profile_event.executed_by = Some(arkret_wire::ActorId::service(package.service_id.clone()));
    profile_event.applet_id = Some(applet_id.clone());
    profile_event.authorization_ref = Some(delegation.authorization_ref.clone());
    profile_event.refs = vec![arkret_wire::EventRef::new(
        accountability_event.event_id.as_str(),
        "accountability",
    )];
    profile_event.seal_basis = Some(seal_basis.clone());
    let profile_event = finalize_and_sign_applet_event(profile_event, package, now);
    let mut managed_actor_bundle = arkret_models_integration::AppletManagedActorAuthoringBundle {
        schema: arkret_models_integration::AppletManagedActorAuthoringBundle::SCHEMA.to_owned(),
        authoring_request_digest: authoring_request.canonical_digest().unwrap(),
        managed_actor_provision_event,
        pcr_genesis_event,
        accountability_grant_event: accountability_event,
        profile_event,
        proof: arkret_models_integration::AppletManagedActorProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method,
            payload_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
                .unwrap(),
            created_at: now,
            audience_id: actor_station_id,
            jws: String::new(),
        },
    };
    managed_actor_bundle.proof.payload_digest = managed_actor_bundle.payload_digest().unwrap();
    managed_actor_bundle.proof.jws = arkret_signatures::sign_ed25519_detached_jws(
        &signing_key,
        &managed_actor_bundle.proof_binding_bytes().unwrap(),
    )
    .unwrap();
    serde_json::to_value(arkret_models_integration::GhostActorProvisionRequestBody {
        authoring_request,
        managed_actor_bundle,
    })
    .expect("fixture Ghost provision request serializes")
}

#[tokio::test]
async fn applet_protocol_describe_smoke() {
    let state = soland_test_support::app_state(test_config());
    let app = service(state);

    // applet-integration.md 7 fixes the ping response fields; there is no
    // free-form `ok` flag to assert.
    let ping: arkret_models_integration::AppletPingOutcome =
        TestClient::get("http://server/_arkret/edge/applet/ping")
            .add_header("Arkret-Operation", "ak.edge.applet.read.ping.v1", true)
            .send(&app)
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(ping.protocol_version, arkret_wire::PROTOCOL_VERSION);

    let describe: arkret_models_discovery::ServiceDescribe =
        TestClient::get("http://server/_arkret/edge/applet/describe")
            .add_header("Arkret-Operation", "ak.edge.applet.read.describe.v1", true)
            .send(&app)
            .await
            .take_json()
            .await
            .unwrap();
    describe
        .validate()
        .expect("Applet describe must be the canonical ServiceDescribe");
    assert_eq!(describe.protocol_version, arkret_wire::PROTOCOL_VERSION);
    for operation_id in [
        arkret_wire::ServiceOperationId::EDGE_APPLET_READ_PING_V1,
        arkret_wire::ServiceOperationId::EDGE_APPLET_READ_DESCRIBE_V1,
        arkret_wire::ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1,
        arkret_wire::ServiceOperationId::SELF_APPLET_COMMAND_INSTALL_V1,
    ] {
        assert!(
            describe.supports_operation(
                arkret_wire::ServiceOperationId::from_wire(operation_id)
                    .expect("fixture operation must be registered")
            ),
            "Applet describe must advertise {operation_id}"
        );
    }
}

#[tokio::test]
async fn applet_transaction_requires_signature_before_typed_body_validation() {
    let state = soland_test_support::app_state(test_config());
    let app = service(state);
    let mut response = TestClient::post("http://server/_arkret/edge/applet/transactions")
        .add_header(
            "Arkret-Operation",
            "ak.edge.applet.command.transaction.v1",
            true,
        )
        .add_header("Authorization", "Bearer bearer-only", true)
        .add_header("Idempotency-Key", "missing-signature-order", true)
        .json(&json!({
            "source_id": "not-a-did",
            "events": "not-an-array"
        }))
        .send(&app)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::UNAUTHORIZED);
    let error: Value = response.take_json().await.unwrap();
    assert_eq!(
        error["type"],
        json!("https://arkret.org/problems/http_signature_required")
    );
}

#[tokio::test]
async fn applet_install_package_registers_bot_projection_smoke() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    seed_extension_test_seal(&state).await;
    let app = service(state.clone());
    let suffix = fixture_suffix();
    let realm_id = demo_realm_id();
    let applet_id = arkret_identifiers::new_prefixed_uuid7("ak:applet:");
    let namespace = format!("bridge.install.{suffix}");
    let package = signed_applet_package(&applet_id, &namespace, &state.service_core_id());
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
    let bot_actor_id: arkret_wire::ActorId =
        serde_json::from_value(install["bot_actor_id"].clone()).unwrap();
    assert_eq!(bot_actor_id, package.bot_actor_id);

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
        .get(&applet_id, &realm_scope_key(realm_id))
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
        event.kind == arkret_wire::EventKind::AppletRegistration.as_str()
            && event.envelope["payload"]["applet_id"] == json!(applet_id)
    }));
    assert!(install_events.iter().any(|event| {
        event.kind == arkret_wire::EventKind::CapabilityGrant.as_str()
            && event.envelope["payload"]["grant"]["constraints"][0]["constraint_kind"]
                == json!("authority_control")
            && event.envelope["payload"]["grant"]["constraints"][0]["constraint_subkind"]
                == json!("applet_authority")
    }));
    let pcr_genesis_record = install_events
        .iter()
        .find(|event| {
            event.kind == arkret_wire::EventKind::RealmCreate.as_str()
                && event.envelope["payload"]["object"]["purpose"] == json!("applet_managed_control")
        })
        .expect("formal install stores the Bot PCR genesis");
    let pcr_genesis: Event = serde_json::from_value(pcr_genesis_record.envelope.clone()).unwrap();
    let pcr_digest = arkret_identifiers::Hash::new(
        pcr_genesis
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap(),
    )
    .unwrap();
    let pcr_ack = state
        .test_persistence()
        .events()
        .control_proposal_ack_for_digest(pcr_digest.as_ref())
        .await
        .unwrap()
        .expect("formal Bot PCR genesis stores its AckRequired ingress proof");
    assert_eq!(pcr_ack.realm_id, pcr_genesis.realm_id);
    assert_eq!(pcr_ack.proposal_digest, pcr_digest);
    assert_eq!(pcr_ack.authority_acks.len(), 1);
    let authority_ack = &pcr_ack.authority_acks[0];
    let host_notary = state.service_notary_signer_descriptor().unwrap();
    assert_eq!(
        authority_ack.signature.verification_method,
        host_notary.verification_method
    );
    arkret_signatures::verify_frozen_notary_detached_jws(
        &arkret_wire::SealSignature::from(authority_ack.signature.clone()),
        &host_notary,
        &authority_ack.canonical_bytes_for_signature().unwrap(),
    )
    .expect("stored PCR Ack is cryptographically bound to the exact host notary");

    let bot_view = extension_actor_view(&app, bot_actor_id.signing_principal_id().as_str()).await;
    assert_eq!(bot_view["exists"], json!(true));
    assert_eq!(bot_view["actor_id"], json!(bot_actor_id));
}

/// Run the two closed-aggregate scenarios on a realistic server-sized stack.
///
/// Salvo's in-process `TestClient` drives request decoding, four-Event
/// admission, response encoding, and recursive response drop in one call
/// stack. The production server runs handlers on configurable Tokio workers;
/// the default Windows libtest thread is only 2 MiB and overflows after the
/// successful commit even though every admission and persistence step has
/// completed. Keeping this scoped to the harness preserves the ordinary
/// production runtime configuration.
fn run_large_extensions_smoke_scenario<F, Fut>(scenario: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + 'static,
{
    std::thread::Builder::new()
        .name("extensions-smoke-large-scenario".to_owned())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("large extensions smoke Tokio runtime")
                .block_on(scenario());
        })
        .expect("spawn large extensions smoke scenario")
        .join()
        .expect("large extensions smoke scenario completes");
}

#[test]
fn applet_ghost_actor_provision_writes_durable_four_event_unit() {
    run_large_extensions_smoke_scenario(
        applet_ghost_actor_provision_writes_durable_four_event_unit_scenario,
    );
}

async fn applet_ghost_actor_provision_writes_durable_four_event_unit_scenario() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let seal_basis = seed_extension_test_seal(&state).await;
    let app = service(state.clone());
    let suffix = fixture_suffix();
    let applet_id = arkret_identifiers::new_prefixed_uuid7("ak:applet:");
    let namespace = format!("bridge.provision.{suffix}");
    let package = signed_applet_package(&applet_id, &namespace, &state.service_core_id());
    ingest_applet_service_id_document(&state, &package).await;
    let realm_id = demo_realm_id();
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

    let ghost_actor = managed_actor_fixture(&namespace, "u123", &package.service_id);
    ingest_managed_actor_current_document(&state, &ghost_actor).await;
    let ghost_actor_id = ghost_actor.actor_id.to_string();
    let ghost_account_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        ghost_actor.actor_id.clone(),
        state.service_core_id(),
    ));
    let mut rejected_body = signed_ghost_provision_body(
        &app,
        &state,
        &package,
        &install,
        &ghost_actor,
        "slack",
        "T123",
        "U123",
        Some("Alice on Slack"),
        &seal_basis,
    )
    .await;
    let rejected_profile_ref = rejected_body["managed_actor_bundle"]["profile_event"]["event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let rejected_grant_ref =
        rejected_body["managed_actor_bundle"]["accountability_grant_event"]["event_id"]
            .as_str()
            .unwrap()
            .to_owned();
    let rejected_provision_ref =
        rejected_body["managed_actor_bundle"]["managed_actor_provision_event"]["event_id"]
            .as_str()
            .unwrap()
            .to_owned();
    let rejected_pcr_ref = rejected_body["managed_actor_bundle"]["pcr_genesis_event"]["event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    rejected_body["managed_actor_bundle"]["accountability_grant_event"]["payload"]["proof"]["jws"] =
        json!("invalid-jws");
    let rejected: Value = post_signed_ghost_provision(
        &app,
        &state,
        &package,
        &applet_id,
        &format!("invalid-proof-{suffix}"),
        &rejected_body,
    )
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        rejected["type"],
        json!("https://arkret.org/problems/param_invalid"),
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
            .get(&rejected_provision_ref)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        state
            .test_persistence()
            .events()
            .get(&rejected_pcr_ref)
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
            .get(&applet_id, &realm_scope_key(realm_id))
            .await
            .unwrap()
            .unwrap()["ghosts"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let provision_body = signed_ghost_provision_body(
        &app,
        &state,
        &package,
        &install,
        &ghost_actor,
        "slack",
        "T123",
        "U123",
        Some("Alice on Slack"),
        &seal_basis,
    )
    .await;
    let idempotency_key = format!("provision-{suffix}");
    let mut response = post_signed_ghost_provision(
        &app,
        &state,
        &package,
        &applet_id,
        &idempotency_key,
        &provision_body,
    )
    .await;
    let status = response.status_code.unwrap();
    let provision: Value = response.take_json().await.unwrap();
    assert_eq!(
        status,
        StatusCode::CREATED,
        "provision response: {provision}"
    );
    assert_eq!(provision["ghost_actor_id"], json!(ghost_account_actor));
    assert_eq!(provision["display_name"], json!("Alice on Slack"));
    let profile_event_ref = provision["profile_event_ref"].as_str().unwrap();
    let accountability_grant_ref = provision["accountability_grant_ref"].as_str().unwrap();
    let managed_actor_provision_ref = provision["managed_actor_provision_ref"].as_str().unwrap();
    let principal_control_realm_id = provision["principal_control_realm_id"].as_str().unwrap();
    let authorization_ref = provision["authorization_ref"].as_str().unwrap();
    assert!(profile_event_ref.starts_with("ak:event:"));
    assert!(accountability_grant_ref.starts_with("ak:event:"));
    assert!(managed_actor_provision_ref.starts_with("ak:event:"));
    assert!(principal_control_realm_id.starts_with("ak:realm:"));
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
    assert_eq!(profile_event.actor_id, ghost_account_actor.to_string());
    assert_eq!(
        profile_event.envelope["executed_by"],
        json!(arkret_wire::ActorId::service(package.service_id.clone()))
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
        profile_event.envelope["payload"]["object"]["profile_fields"]["external_ref"]["external_id"],
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
    assert_eq!(
        grant_event.actor_id,
        arkret_wire::ActorId::service(package.service_id.clone()).to_string()
    );
    assert_eq!(
        grant_event.envelope["payload"]["issuer_id"],
        json!(package.service_id.to_string())
    );
    assert_eq!(
        grant_event.envelope["payload"]["subject_id"],
        json!(ghost_actor_id)
    );
    assert_eq!(
        grant_event.envelope["payload"]["proof"]["kind"],
        json!("detached_jws")
    );

    let managed_provision_event = state
        .test_persistence()
        .events()
        .get(managed_actor_provision_ref)
        .await
        .unwrap()
        .expect("managed-actor provision event is durable");
    assert_eq!(
        managed_provision_event.kind,
        "ak.applet.managed_actor.provision"
    );
    assert_eq!(
        managed_provision_event.envelope["payload"]["actor_role"],
        json!("ghost")
    );
    let pcr_event_ref = provision_body["managed_actor_bundle"]["pcr_genesis_event"]["event_id"]
        .as_str()
        .unwrap();
    let pcr_event = state
        .test_persistence()
        .events()
        .get(pcr_event_ref)
        .await
        .unwrap()
        .expect("Applet-managed PCR genesis is durable");
    assert_eq!(pcr_event.kind, "ak.realm.create");
    assert_eq!(
        pcr_event.envelope["payload"]["object"]["purpose"],
        json!("applet_managed_control")
    );
    assert_eq!(
        pcr_event.realm_id.as_deref(),
        Some(principal_control_realm_id)
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

    let mut replay_response = post_signed_ghost_provision(
        &app,
        &state,
        &package,
        &applet_id,
        &idempotency_key,
        &provision_body,
    )
    .await;
    assert_eq!(replay_response.status_code.unwrap(), StatusCode::OK);
    let replay: Value = replay_response.take_json().await.unwrap();
    assert_eq!(replay, provision);

    let conflicting_body = signed_ghost_provision_body(
        &app,
        &state,
        &package,
        &install,
        &ghost_actor,
        "slack",
        "T123",
        "U123",
        Some("Changed on retry"),
        &seal_basis,
    )
    .await;
    let mut conflict_response = post_signed_ghost_provision(
        &app,
        &state,
        &package,
        &applet_id,
        &idempotency_key,
        &conflicting_body,
    )
    .await;
    assert_eq!(conflict_response.status_code.unwrap(), StatusCode::CONFLICT);
    let conflict: Value = conflict_response.take_json().await.unwrap();
    assert_eq!(
        conflict["type"],
        json!("https://arkret.org/problems/duplicate_conflict")
    );
}

#[tokio::test]
async fn applet_ghost_actor_provision_requires_approved_ghost_scope() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    seed_extension_test_seal(&state).await;
    let app = service(state.clone());
    let suffix = fixture_suffix();
    let applet_id = arkret_identifiers::new_prefixed_uuid7("ak:applet:");
    let namespace = format!("bridge.no-ghost-scope.{suffix}");
    let package = signed_applet_package(&applet_id, &namespace, &state.service_core_id());
    ingest_applet_service_id_document(&state, &package).await;
    let realm_id = demo_realm_id();
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

    let mut response = post_signed_ghost_preview(
        &app,
        &state,
        &package,
        &applet_id,
        &format!("preview-denied-{suffix}"),
        &json!({
            "realm_id": realm_id,
            "external_ref": {
                "protocol": "slack",
                "instance_id": "T123",
                "external_id": "U-denied",
            },
            "display_name": null,
        }),
    )
    .await;
    let rejected: Value = response.take_json().await.unwrap();
    assert_eq!(
        rejected["type"],
        json!("https://arkret.org/problems/capability_denied"),
        "rejection: {rejected}"
    );
}

#[tokio::test]
async fn applet_ghost_actor_provision_rejects_actor_namespace_mismatch() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let seal_basis = seed_extension_test_seal(&state).await;
    let app = service(state.clone());
    let suffix = fixture_suffix();
    let applet_id = arkret_identifiers::new_prefixed_uuid7("ak:applet:");
    let namespace = format!("bridge.namespace.{suffix}");
    let package = signed_applet_package(&applet_id, &namespace, &state.service_core_id());
    ingest_applet_service_id_document(&state, &package).await;
    let realm_id = demo_realm_id();
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
    let mismatched_ghost = managed_actor_fixture("other-namespace", "u123", &package.service_id);
    ingest_managed_actor_current_document(&state, &mismatched_ghost).await;

    let body = signed_ghost_provision_body(
        &app,
        &state,
        &package,
        &install,
        &mismatched_ghost,
        "slack",
        "T123",
        "U123",
        None,
        &seal_basis,
    )
    .await;
    let rejected: Value = post_signed_ghost_provision(
        &app,
        &state,
        &package,
        &applet_id,
        &format!("namespace-{suffix}"),
        &body,
    )
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        rejected["type"],
        json!("https://arkret.org/problems/applet_namespace_mismatch"),
        "rejection: {rejected}"
    );
}

async fn extension_actor_view(app: &salvo::Service, actor_id: &str) -> Value {
    TestClient::get(format!(
        "http://server/_arkret/edge/applet/actors/{actor_id}"
    ))
    .add_header(
        "Arkret-Operation",
        "ak.edge.applet.actor.read.resolve.v1",
        true,
    )
    .send(app)
    .await
    .take_json()
    .await
    .unwrap()
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
    seal_ref: Option<arkret_identifiers::SealId>,
}

async fn post_signed_applet_message_transaction(
    app: &salvo::Service,
    package: &AppletPackage,
    request: AppletMessageTransactionRequest<'_>,
) -> Value {
    let event = applet_message_event(package, &request).await;
    post_signed_applet_transaction_events(
        app,
        package,
        request.state,
        request.applet_id,
        request.idempotency_key,
        vec![event],
    )
    .await
}

async fn post_signed_applet_transaction_events(
    app: &salvo::Service,
    package: &AppletPackage,
    state: &AppState,
    applet_id: &str,
    idempotency_key: &str,
    events: Vec<Value>,
) -> Value {
    let body = json!({
        "applet_id": applet_id,
        "source_id": package.service_id.to_string(),
        "events": events,
    });
    let body_bytes = arkret_canonical::canonical_json_bytes(&body).unwrap();
    let content_digest = content_digest_header(&body_bytes);
    let verification_method = package.webhook_auth.key_ref.clone();
    let created = chrono::Utc::now().timestamp();
    let signature_params = format!(
        "(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \
         \"source-service-id\" \"destination-service-id\" \"idempotency-key\");\
         created={created};expires={};keyid=\"{verification_method}\";alg=\"ed25519\"",
        created + 60
    );
    let target_scheme = state
        .config()
        .public_base_url
        .split_once("://")
        .map_or("http", |(scheme, _)| scheme);
    let target_uri = format!("{target_scheme}://server/_arkret/edge/applet/transactions");
    let signature_base = applet_signature_base(
        &target_uri,
        &content_digest,
        package.service_id.as_str(),
        state.service_id(),
        idempotency_key,
        &signature_params,
    );
    let signing_key = applet_service_signing_key(&verification_method);
    assert_eq!(
        soland_http::jws_verify::resolve_ed25519_pubkey(state, verification_method.as_str(),)
            .expect("Applet webhook verification key resolves"),
        signing_key.verifying_key(),
        "Applet webhook DID document binds the fixture signing key",
    );
    let signature = signing_key.sign(signature_base.as_bytes());
    let signature_header = format!(
        "sig1=:{}:",
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    );
    TestClient::post("http://server/_arkret/edge/applet/transactions")
        .add_header(
            "Arkret-Operation",
            "ak.edge.applet.command.transaction.v1",
            true,
        )
        .add_header("Content-Digest", content_digest, true)
        .add_header("Source-Service-ID", package.service_id.to_string(), true)
        .add_header("Destination-Service-ID", state.service_id(), true)
        .add_header("Idempotency-Key", idempotency_key.to_owned(), true)
        .add_header("Signature-Input", format!("sig1={signature_params}"), true)
        .add_header("Signature", signature_header, true)
        .json(&body)
        .send(app)
        .await
        .take_json()
        .await
        .unwrap()
}

async fn post_signed_ghost_provision(
    app: &salvo::Service,
    state: &AppState,
    package: &AppletPackage,
    applet_id: &str,
    idempotency_key: &str,
    body: &Value,
) -> salvo::Response {
    let body_bytes = arkret_canonical::canonical_json_bytes(body).unwrap();
    let content_digest = content_digest_header(&body_bytes);
    let verification_method = package.webhook_auth.key_ref.clone();
    let created = chrono::Utc::now().timestamp();
    let signature_params = format!(
        "(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \
         \"source-service-id\" \"destination-service-id\" \"idempotency-key\");\
         created={created};expires={};keyid=\"{verification_method}\";alg=\"ed25519\"",
        created + 60
    );
    let target_scheme = state
        .config()
        .public_base_url
        .split_once("://")
        .map_or("http", |(scheme, _)| scheme);
    let target_uri =
        format!("{target_scheme}://server/_arkret/self/applets/{applet_id}/ghosts/provision");
    let signature_base = applet_signature_base(
        &target_uri,
        &content_digest,
        package.service_id.as_str(),
        state.service_id(),
        idempotency_key,
        &signature_params,
    );
    let signing_key = applet_service_signing_key(&verification_method);
    assert_eq!(
        soland_http::jws_verify::resolve_ed25519_pubkey(state, verification_method.as_str())
            .expect("Applet webhook verification key resolves"),
        signing_key.verifying_key(),
        "Applet webhook DID document binds the fixture signing key",
    );
    let signature = signing_key.sign(signature_base.as_bytes());
    let signature_header = format!(
        "sig1=:{}:",
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    );
    TestClient::post(format!(
        "http://server/_arkret/self/applets/{applet_id}/ghosts/provision"
    ))
    .add_header(
        "Arkret-Operation",
        "ak.self.applet.ghost.command.provision.v1",
        true,
    )
    .add_header("Content-Digest", content_digest, true)
    .add_header("Source-Service-ID", package.service_id.to_string(), true)
    .add_header("Destination-Service-ID", state.service_id(), true)
    .add_header("Idempotency-Key", idempotency_key.to_owned(), true)
    .add_header("Signature-Input", format!("sig1={signature_params}"), true)
    .add_header("Signature", signature_header, true)
    .json(body)
    .send(app)
    .await
}

async fn post_signed_ghost_preview(
    app: &salvo::Service,
    state: &AppState,
    package: &AppletPackage,
    applet_id: &str,
    idempotency_key: &str,
    body: &Value,
) -> salvo::Response {
    let body_bytes = arkret_canonical::canonical_json_bytes(body).unwrap();
    let content_digest = content_digest_header(&body_bytes);
    let verification_method = package.webhook_auth.key_ref.clone();
    let created = chrono::Utc::now().timestamp();
    let signature_params = format!(
        "(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \
         \"source-service-id\" \"destination-service-id\" \"idempotency-key\");\
         created={created};expires={};keyid=\"{verification_method}\";alg=\"ed25519\"",
        created + 60
    );
    let target_scheme = state
        .config()
        .public_base_url
        .split_once("://")
        .map_or("http", |(scheme, _)| scheme);
    let target_uri = format!(
        "{target_scheme}://server/_arkret/self/applets/{applet_id}/ghosts/provision/preview"
    );
    let signature_base = applet_signature_base(
        &target_uri,
        &content_digest,
        package.service_id.as_str(),
        state.service_id(),
        idempotency_key,
        &signature_params,
    );
    let signing_key = applet_service_signing_key(&verification_method);
    let signature = signing_key.sign(signature_base.as_bytes());
    let signature_header = format!(
        "sig1=:{}:",
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    );
    TestClient::post(format!(
        "http://server/_arkret/self/applets/{applet_id}/ghosts/provision/preview"
    ))
    .add_header(
        "Arkret-Operation",
        "ak.self.applet.ghost.command.preview.v1",
        true,
    )
    .add_header("Content-Digest", content_digest, true)
    .add_header("Source-Service-ID", package.service_id.to_string(), true)
    .add_header("Destination-Service-ID", state.service_id(), true)
    .add_header("Idempotency-Key", idempotency_key.to_owned(), true)
    .add_header("Signature-Input", format!("sig1={signature_params}"), true)
    .add_header("Signature", signature_header, true)
    .json(body)
    .send(app)
    .await
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
    let mut event = arkret_wire::test_support::raw_event_at(
        "ak.message.create",
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new((*realm_id).to_owned())
                .expect("fixture Realm id"),
        },
        arkret_identifiers::DidCoreId::new((*actor_id).to_owned())
            .expect("fixture ghost actor DID"),
        arkret_identifiers::DidCoreId::new(state.service_id().clone())
            .expect("extension test service core DID"),
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
    event.executed_by = Some(arkret_wire::ActorId::service(package.service_id.clone()));
    event.authorization_ref =
        Some(arkret_wire::AuthorizationRef::new((*authorization_ref).to_owned()).unwrap());
    event.applet_id = Some(
        arkret_identifiers::AppletId::new((*applet_id).to_owned()).expect("fixture applet id"),
    );
    event.external_ref = Some(std::collections::BTreeMap::from([
        ("protocol".to_owned(), json!("smoke")),
        ("external_id".to_owned(), json!(actor_id)),
    ]));
    let verification_method = package.webhook_auth.key_ref.clone();
    // `ak.message.create` is a DataEvent. Formal Applet install grants are
    // issued to the executing service, while actor_id remains the accountable
    // ghost, so the frozen CBA view must cover the exact install
    // authorization_ref for the executing service.
    let seal_id = match &request.seal_ref {
        Some(seal_id) => seal_id.clone(),
        None => seed_applet_message_grant_basis(state, package, realm_id, authorization_ref).await,
    };
    event.seal_ref = Some(seal_id);
    event.auth_context = Some(arkret_wire::AuthContext {
        key_id: arkret_wire::OpaqueLocalId::new(
            verification_method
                .as_str()
                .split_once('#')
                .map_or(verification_method.as_str(), |(_, key)| key),
        )
        .expect("fixture auth_context key id is an opaque local id"),
        key_epoch: 0,
        credential_epoch: None,
    });
    let signing_key = applet_service_signing_key(&verification_method);
    let signer = Ed25519PayloadSigner::new(
        signing_key,
        Did::new(
            verification_method
                .as_str()
                .split_once('#')
                .expect("fixture verification method has a fragment")
                .0,
        )
        .unwrap(),
        verification_method.clone(),
    );
    let mut event = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .expect("fixture envelope finalizes");
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(now),
    )
    .unwrap();
    let event = event.into_event();
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
    target_uri: &str,
    content_digest: &str,
    source_id: &str,
    destination_id: &str,
    idempotency_key: &str,
    signature_params: &str,
) -> String {
    format!(
        "\"@method\": POST\n\
         \"@target-uri\": {target_uri}\n\
         \"@authority\": server\n\
         \"content-digest\": {content_digest}\n\
         \"source-service-id\": {source_id}\n\
         \"destination-service-id\": {destination_id}\n\
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
    _package: &AppletPackage,
    realm_id: &str,
    grant_id: &str,
) -> arkret_identifiers::SealId {
    let realm = arkret_identifiers::RealmId::new(realm_id.to_owned()).unwrap();
    let predecessors = state
        .test_seal_leaves(&realm)
        .expect("fixture reads the current accepted Realm Seal frontier");
    assert!(
        !predecessors.is_empty(),
        "the Applet grant Seal must extend the accepted Realm authority chain"
    );
    soland_test_support::sealed_grant::seal_accepted_capability_grant(
        state,
        realm_id,
        grant_id,
        predecessors,
    )
    .await
    .seal_id
}

fn strand_id_for_realm(realm_id: &str) -> String {
    arkret_identifiers::RealmId::new(realm_id.to_owned())
        .map(|realm_id| {
            arkret_identifiers::StrandId::from_event_id(&realm_id.event_id()).to_string()
        })
        .unwrap_or_else(|_| "ak:strand:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC".to_owned())
}

#[test]
fn applet_bridge_register_ghost_route_revoke_smoke() {
    run_large_extensions_smoke_scenario(applet_bridge_register_ghost_route_revoke_scenario);
}

async fn applet_bridge_register_ghost_route_revoke_scenario() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let seal_basis = seed_extension_test_seal(&state).await;
    let app = service(state.clone());
    let suffix = fixture_suffix();
    let applet_id = arkret_identifiers::new_prefixed_uuid7("ak:applet:");
    let namespace = format!("bridge.smoke.{suffix}");
    let package = signed_applet_package(&applet_id, &namespace, &state.service_core_id());
    ingest_applet_service_id_document(&state, &package).await;
    let realm_id = demo_realm_id();
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
    allow_service_message_plaintext(&state, demo_realm_id()).await;
    let bot_actor_id: arkret_wire::ActorId =
        serde_json::from_value(install["bot_actor_id"].clone()).unwrap();
    let message_grant_ref =
        capability_grant_ref_for_action(&install, &package.requested_scopes, "ak.message.create");

    let ghost_actor = managed_actor_fixture(&namespace, "ext-user-x", &package.service_id);
    ingest_managed_actor_current_document(&state, &ghost_actor).await;
    let ghost_actor_id = ghost_actor.actor_id.to_string();
    let ghost_account_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        ghost_actor.actor_id.clone(),
        state.service_core_id(),
    ));
    let body = signed_ghost_provision_body(
        &app,
        &state,
        &package,
        &install,
        &ghost_actor,
        "smoke",
        "T-smoke",
        "ext-user-x",
        Some("External X"),
        &seal_basis,
    )
    .await;
    let mut provision_response = post_signed_ghost_provision(
        &app,
        &state,
        &package,
        &applet_id,
        &format!("ghost-{suffix}"),
        &body,
    )
    .await;
    let provision_status = provision_response.status_code.unwrap();
    let provision: Value = provision_response.take_json().await.unwrap();
    assert_eq!(
        provision_status,
        StatusCode::CREATED,
        "provision response: {provision}"
    );
    assert_eq!(provision["ghost_actor_id"], json!(ghost_account_actor));

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
            seal_ref: None,
        },
    )
    .await;
    assert_eq!(transaction["status"], json!("rejected"));
    assert_eq!(
        transaction["rejections"][0]["reason_code"],
        json!("capability_denied"),
        "an installed Ghost is not a Realm member until the ordinary invite/join FSM accepts it"
    );
    let messages = state
        .test_persistence()
        .messages()
        .list_for_realm(realm_id, 10)
        .await
        .unwrap();
    assert!(
        messages.is_empty(),
        "a pre-membership Applet-managed write must have no durable message effect"
    );
    let pre_revoke_message_seals = state
        .test_seal_leaves(&arkret_identifiers::RealmId::new(realm_id.to_owned()).unwrap())
        .unwrap();
    let [pre_revoke_message_seal] = pre_revoke_message_seals.as_slice() else {
        panic!(
            "the rejected write must retain exactly one frozen grant Seal, got {pre_revoke_message_seals:?}"
        );
    };
    let pre_revoke_message_seal = pre_revoke_message_seal.clone();

    let ghost_view = extension_actor_view(&app, &ghost_actor_id).await;
    assert_eq!(ghost_view["exists"], json!(true));
    assert_eq!(ghost_view["actor_id"], json!(ghost_account_actor));
    assert_eq!(ghost_view["display_name"], json!("External X"));
    let stored_applet = state
        .test_persistence()
        .applets()
        .get(&applet_id, &realm_scope_key(realm_id))
        .await
        .unwrap()
        .expect("applet record remains durable after ghost provision");
    assert!(
        stored_applet.get("identity").is_none()
            && stored_applet.get("registry_id").is_none()
            && stored_applet.get("bot_actor_id").is_none(),
        "exact-scope installation must not copy managed identity anchors"
    );
    let stored_identity = state
        .test_persistence()
        .applets()
        .get_identity(&applet_id, state.service_id())
        .await
        .unwrap()
        .expect("accepted Applet identity winner remains durable after ghost provision");
    assert_eq!(stored_identity["registry_id"], json!(package.controller_id));

    let membership_event_ref = admit_applet_managed_member(
        &state,
        &app,
        &token,
        &package,
        realm_id,
        &ghost_account_actor,
        &message_grant_ref,
    )
    .await;
    assert_eq!(
        state
            .test_projections()
            .snapshot()
            .member(realm_id, &ghost_account_actor.to_string())
            .and_then(|membership| membership.membership_event_ref.as_deref()),
        Some(membership_event_ref.as_str()),
        "managed membership inventory must be backed by the current accepted join generation"
    );

    let revoke_preview: Value = TestClient::post(format!(
        "http://server/_arkret/self/applets/{applet_id}/revoke/preview"
    ))
    .add_header(
        "Arkret-Operation",
        "ak.self.applet.revoke.command.preview.v1",
        true,
    )
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
    assert_eq!(
        revoke_preview["revoke_plan"]["capability_revocations"]
            .as_array()
            .expect("revoke preview capability intents")
            .len(),
        install["capability_grant_refs"]
            .as_array()
            .expect("install outcome capability grants")
            .len(),
        "revoke preview must resolve every exact (service_id, target_station_id) grant"
    );
    assert_eq!(
        revoke_preview["revoke_plan"]["membership_removals"],
        json!([{
            "event_kind": "ak.member.state",
            "member_id": ghost_account_actor,
            "membership": "leave",
            "reason_code": "smoke_test",
        }]),
        "preview must enumerate the exact current managed membership"
    );
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
    .add_header("Arkret-Operation", "ak.self.applet.command.revoke.v1", true)
    .add_header("Authorization", format!("Bearer {token}"), true)
    .add_header("Idempotency-Key", revoke_key.clone(), true)
    .json(&revoke_body)
    .send(&app)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(revoke["status"], json!("complete"));

    let replay: Value = TestClient::post(format!(
        "http://server/_arkret/self/applets/{applet_id}/revoke"
    ))
    .add_header("Arkret-Operation", "ak.self.applet.command.revoke.v1", true)
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
    .add_header("Arkret-Operation", "ak.self.applet.command.revoke.v1", true)
    .add_header("Authorization", format!("Bearer {token}"), true)
    .add_header("Idempotency-Key", revoke_key, true)
    .json(&conflicting_body)
    .send(&app)
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        conflict["type"],
        json!("https://arkret.org/problems/duplicate_conflict")
    );

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
            seal_ref: Some(pre_revoke_message_seal),
        },
    )
    .await;
    assert_eq!(
        rejected["type"],
        json!("https://arkret.org/problems/applet_registration_unauthorized")
    );

    let revoked_applet = state
        .test_persistence()
        .applets()
        .get(&applet_id, &realm_scope_key(realm_id))
        .await
        .unwrap()
        .expect("revoked applet record remains durable");
    assert!(revoked_applet["revoked_at"].is_string());
    let revoked_membership = state
        .test_projections()
        .snapshot()
        .member(realm_id, &ghost_account_actor.to_string())
        .cloned()
        .expect("revoked managed member remains as a terminal membership projection");
    assert_eq!(revoked_membership.state, "leave");
    assert_ne!(
        revoked_membership.membership_event_ref.as_deref(),
        Some(membership_event_ref.as_str()),
        "revoke saga must advance the managed member beyond its accepted join generation"
    );
    revoked_applet["ghosts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|ghost| ghost["ghost_actor_id"] == json!(ghost_account_actor))
        .expect("ghost remains in the revoked applet record");
    assert!(
        bot_actor_id
            .signing_principal_id()
            .as_str()
            .starts_with("ak:did_core:webvh:")
    );
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
    // api-conventions.md 5: non-2xx replies are RFC 9457 Problem Details, so the
    // discriminator is the root `type`, not a nested `error.code` envelope.
    assert_eq!(
        rejected["type"],
        json!("https://arkret.org/problems/unrecognized_endpoint")
    );
}

fn signed_applet_package(
    applet_id: &str,
    namespace: &str,
    target_station_id: &arkret_identifiers::DidCoreId,
) -> AppletPackage {
    let controller_did = Did::new("did:web:registry.example".to_owned()).unwrap();
    let controller_id = arkret_wire::project_did_to_core_id(&controller_did).unwrap();
    let service_did = Did::new(format!(
        "did:web:{}.applet.example",
        safe_did_token(namespace)
    ))
    .unwrap();
    let service_id = arkret_wire::project_did_to_core_id(&service_did).unwrap();
    let bot_actor = managed_actor_fixture(namespace, "bot", &service_id);
    let bot_actor_id = bot_actor.actor_id;
    let mut package = AppletPackage::new(
        format!("package:{applet_id}"),
        AppletId::new(applet_id.to_owned()).unwrap(),
        service_id.clone(),
        service_did.clone(),
        controller_id.clone(),
        format!("https://{}.applet.example", safe_did_token(namespace)),
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            bot_actor_id,
            target_station_id.clone(),
        )),
        vec!["arkret.portal".to_owned()],
        AppletWireNamespaces {
            actors: vec![AppletNamespaceEntry::exclusive(format!(
                "did:webvh:*:managed-{}.applet.example:webvh:*",
                safe_did_token(namespace)
            ))],
            handles: vec![AppletNamespaceEntry::exclusive(namespace.to_owned())],
            ..Default::default()
        },
    );
    package.webhook_auth = WebhookAuth::http_message_signature(
        arkret_wire::DidUrl::new(format!("{service_did}#applet-service-key")).unwrap(),
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
        .seal_registration_epoch(&registration_epoch_evidence)
        .unwrap();
    package.seal().unwrap();
    let verification_method = arkret_wire::DidUrl::new(format!("{controller_did}#applet-package"))
        .expect("fixture verification method is a DID URL");
    let signer = Ed25519PayloadSigner::from_did_key_seed(
        [13u8; 32],
        controller_did,
        verification_method.clone(),
    );
    package.sign(&signer, &verification_method).unwrap();
    package
}

fn applet_service_id_document(package: &AppletPackage) -> arkret_identity::DidDocument {
    let applet_signing_key = applet_service_signing_key(&package.webhook_auth.key_ref);
    arkret_identity::DidDocument {
        id: Did::new(
            package
                .webhook_auth
                .key_ref
                .as_str()
                .split_once('#')
                .expect("fixture verification method has a fragment")
                .0,
        )
        .unwrap(),
        verification_methods: BTreeMap::from([(
            package.webhook_auth.key_ref.to_string(),
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                applet_signing_key.verifying_key().as_bytes(),
            ),
        )]),
        also_known_as: Vec::new(),
        updated_at: Some(package.created_at),
        raw_properties: BTreeMap::new(),
    }
}

async fn ingest_applet_service_id_document(state: &AppState, package: &AppletPackage) {
    let now = chrono::Utc::now();
    let document = applet_service_id_document(package);
    let record = soland_storage::WebvhDocumentRecord {
        did: document.id.to_string(),
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

#[allow(
    clippy::too_many_arguments,
    reason = "the integration fixture exposes each independently varied authoring boundary"
)]
async fn signed_install_events(
    state: &AppState,
    package: &AppletPackage,
    realm_id: &str,
    registration_epoch_evidence: &arkret_models_integration::AppletRegistrationEpochEvidence,
    approved_actions: &[String],
    authored_at: chrono::DateTime<chrono::Utc>,
    managed_actor_authored_at: chrono::DateTime<chrono::Utc>,
    accepted_admin_events: Option<(Event, Vec<Event>)>,
) -> (Event, Vec<Event>, Event, Event, Event, Event) {
    let ingest_actor_document = accepted_admin_events.is_none();
    let actor_did = Did::new("did:web:alice.example").unwrap();
    let actor_core_id = arkret_wire::project_did_to_core_id(&actor_did).unwrap();
    let realm_id = RealmId::new(realm_id.to_owned()).unwrap();
    let scope_ref = ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let verification_method =
        arkret_wire::DidUrl::new(format!("did:web:alice.example#{ALICE_DEVICE_ID}"))
            .expect("fixture verification method is a DID URL");
    let signer = Ed25519PayloadSigner::from_did_key_seed(
        arkret_signatures::development_signing_key_seed(verification_method.as_str()),
        actor_did.clone(),
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
            event.actor_id
                == arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    actor_core_id.clone(),
                    state.service_core_id().clone(),
                ))
                .to_string()
                && event.realm_id.as_deref() == Some(realm_id.as_str())
        })
        .max_by_key(|event| event.actor_seq)
        .expect("extension test Realm has Alice's founding Event");
    let now = authored_at;
    let millis = now.timestamp_millis().max(0) as u64;
    let mut registration_event = arkret_wire::test_support::raw_event(
        arkret_wire::EventKind::AppletRegistration.as_str(),
        scope_ref.clone(),
        actor_core_id.clone(),
        arkret_identifiers::DidCoreId::new(state.service_id().clone())
            .expect("extension test service core DID"),
        frontier.actor_seq + 1,
        Hlc::new(format!("{millis:012x}-0001-a11ce001")).unwrap(),
        serde_json::to_value(
            package
                .to_registration(registration_epoch_evidence)
                .expect("fixture package derives registration payload"),
        )
        .unwrap(),
    )
    .unwrap();
    registration_event.prev_refs = vec![EventId::new(frontier.event_id.clone()).unwrap()];
    registration_event.seal_basis = Some(seal_basis.clone());
    let mut registration_event = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        registration_event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .expect("fixture envelope finalizes");
    arkret_signatures::sign_event(
        &mut registration_event,
        &signer,
        &verification_method,
        SignEventOptions::new().with_created_at(now),
    )
    .unwrap();
    let registration_event = registration_event.into_event();

    let mut previous_event_id = registration_event.event_id.clone();
    let mut capability_grant_events = Vec::with_capacity(approved_actions.len());
    for (offset, action) in approved_actions.iter().enumerate() {
        let grant = CapabilityGrantCreateBody {
            schema: arkret_wire::SchemaId::CAPABILITY_V1.to_owned(),
            realm_id: Some(realm_id.clone()),
            issuer_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                actor_core_id.clone(),
                arkret_identifiers::DidCoreId::new(state.service_id().clone()).unwrap(),
            )),
            subject: CapabilitySubject::Actor(arkret_wire::ActorId::service(
                package.service_id.clone(),
            )),
            actions: vec![action.clone()],
            resources: vec![
                serde_json::from_value(json!({
                    "kind": "realm",
                    "realm_id": realm_id,
                }))
                .unwrap(),
            ],
            constraints: vec![
                GrantConstraint::applet_authority(
                    package.applet_id.clone(),
                    arkret_wire::ActorId::service(package.service_id.clone()),
                    package.registration_epoch.clone(),
                ),
                {
                    let mut temporal = GrantConstraint::new(
                        GrantConstraintKind::Temporal,
                        GrantConstraintEffect::Allow,
                    );
                    temporal.expires_at = Some(now + chrono::Duration::hours(1));
                    temporal
                },
            ],
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
        };
        let payload = CapabilityGrantPayload { grant };
        let counter = offset + 2;
        let mut event = arkret_wire::test_support::raw_event(
            arkret_wire::EventKind::CapabilityGrant.as_str(),
            scope_ref.clone(),
            actor_core_id.clone(),
            arkret_identifiers::DidCoreId::new(state.service_id().clone())
                .expect("extension test service core DID"),
            frontier.actor_seq + counter as u64,
            Hlc::new(format!("{millis:012x}-{counter:04x}-a11ce001")).unwrap(),
            serde_json::to_value(payload).unwrap(),
        )
        .unwrap();
        event.prev_refs = vec![previous_event_id];
        event.seal_basis = Some(seal_basis.clone());
        let mut event = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .expect("fixture envelope finalizes");
        arkret_signatures::sign_event(
            &mut event,
            &signer,
            &verification_method,
            SignEventOptions::new().with_created_at(now),
        )
        .unwrap();
        let event = event.into_event();
        previous_event_id = event.event_id.clone();
        capability_grant_events.push(event);
    }

    let (registration_event, capability_grant_events) =
        accepted_admin_events.unwrap_or((registration_event, capability_grant_events));

    let now = managed_actor_authored_at;
    let millis = now.timestamp_millis().max(0) as u64;

    let namespace = package
        .namespaces
        .handles
        .first()
        .expect("fixture Applet package has a handle namespace")
        .pattern
        .as_str();
    let bot_actor = managed_actor_fixture(namespace, "bot", &package.service_id);
    assert_eq!(
        bot_actor.actor_id,
        *package.bot_actor_id.signing_principal_id()
    );
    if ingest_actor_document {
        ingest_managed_actor_current_document(state, &bot_actor).await;
    }
    let actor_station_id = arkret_identifiers::DidCoreId::new(state.service_id().clone())
        .expect("extension test service core DID");
    let applet_authority_ref = arkret_identifiers::GrantId::from_event_id(
        &capability_grant_events
            .first()
            .expect("formal install has an approved Applet capability")
            .event_id,
    );
    let bot_actor_provision_event = managed_actor_provision_event(
        package,
        &bot_actor,
        AppletManagedActorRole::Bot,
        actor_station_id.clone(),
        realm_id.clone(),
        registration_event.event_id.clone(),
        applet_authority_ref.clone(),
        None,
        0,
        Vec::new(),
        seal_basis.clone(),
        now,
    );
    let bot_pcr_genesis_event = applet_managed_pcr_genesis_event(
        package,
        &bot_actor,
        actor_station_id.clone(),
        state.service_notary_signer_descriptor().unwrap(),
        applet_authority_ref.clone(),
        bot_actor_provision_event.event_id.clone(),
        now,
    );

    use arkret_models_collaboration::governance::accountability::{
        AccountabilityGrantPayload, AccountabilityScope, AccountabilityScopeKind,
    };
    let service_signing_key = applet_service_signing_key(&package.webhook_auth.key_ref);
    let mut accountability_grant = AccountabilityGrantPayload::new(
        package.service_id.clone(),
        package.bot_actor_id.signing_principal_id().clone(),
        AccountabilityScope::Single(AccountabilityScopeKind::ContractedService),
        now - chrono::Duration::seconds(1),
        None,
        arkret_wire::PayloadProof {
            kind: "detached_jws".to_owned(),
            verification_method: package.webhook_auth.key_ref.clone(),
            payload_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
                .unwrap(),
            created_at: now,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "pending".to_owned(),
        },
    );
    accountability_grant.proof.payload_digest = accountability_grant.payload_digest().unwrap();
    accountability_grant.proof.jws = arkret_signatures::jws::sign_jws_ed25519(
        &accountability_grant
            .canonical_proof_binding_bytes()
            .unwrap(),
        &service_signing_key,
    )
    .unwrap();
    let mut bot_accountability_grant_event = arkret_wire::test_support::raw_event_for_actor_at(
        arkret_wire::EventKind::IdentityAccountabilityGrant.as_str(),
        ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        arkret_wire::ActorId::service(package.service_id.clone()),
        1,
        Hlc::new(format!("{millis:012x}-0102-a11ce001")).unwrap(),
        serde_json::to_value(accountability_grant).unwrap(),
        now,
    )
    .unwrap();
    bot_accountability_grant_event.prev_refs = vec![bot_actor_provision_event.event_id.clone()];
    bot_accountability_grant_event.applet_id = Some(package.applet_id.clone());
    bot_accountability_grant_event.authorization_ref = Some(applet_authority_ref.clone().into());
    bot_accountability_grant_event.seal_basis = Some(seal_basis.clone());
    let bot_accountability_grant_event =
        finalize_and_sign_applet_event(bot_accountability_grant_event, package, now);

    let bot_profile = arkret_models_identity::ActorProfile {
        id: None,
        schema: arkret_wire::SchemaId::ACTOR_PROFILE_V1.to_owned(),
        realm_id: Some(realm_id.clone()),
        principal_id: package.bot_actor_id.signing_principal_id().clone(),
        actor_kind: arkret_wire::ActorKind::Bot,
        display_name: "Applet Bot".to_owned(),
        handle: None,
        agent_slug: None,
        avatar_blob_ref: None,
        status: None,
        accountable_principal_ids: vec![package.service_id.clone()],
        resolution: None,
        profile_fields: BTreeMap::from([(
            "managed_by_applet".to_owned(),
            json!(package.applet_id),
        )]),
        created_at: now,
        updated_by: None,
        updated_at: None,
    };
    let mut bot_profile_event = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::ProfileCreate.as_str(),
        ScopeRef::Realm { realm_id },
        package.bot_actor_id.signing_principal_id().clone(),
        actor_station_id,
        0,
        Hlc::new(format!("{millis:012x}-0103-a11ce001")).unwrap(),
        serde_json::to_value(ActorProfileCreatePayload {
            object: bot_profile,
        })
        .unwrap(),
        now,
    )
    .unwrap();
    bot_profile_event.executed_by = Some(arkret_wire::ActorId::service(package.service_id.clone()));
    bot_profile_event.authorization_ref = Some(applet_authority_ref.into());
    bot_profile_event.applet_id = Some(package.applet_id.clone());
    bot_profile_event.refs = vec![arkret_wire::EventRef::new(
        bot_accountability_grant_event.event_id.as_str(),
        "accountability",
    )];
    bot_profile_event.seal_basis = Some(seal_basis);
    let bot_profile_event = finalize_and_sign_applet_event(bot_profile_event, package, now);

    (
        registration_event,
        capability_grant_events,
        bot_actor_provision_event,
        bot_pcr_genesis_event,
        bot_accountability_grant_event,
        bot_profile_event,
    )
}

async fn admit_applet_managed_member(
    state: &AppState,
    app: &salvo::Service,
    token: &str,
    _package: &AppletPackage,
    realm_id: &str,
    member_id: &arkret_wire::ActorId,
    _install_grant_ref: &str,
) -> String {
    let actor_did = Did::new("did:web:alice.example").unwrap();
    let actor_core_id = arkret_wire::project_did_to_core_id(&actor_did).unwrap();
    let verification_method =
        arkret_wire::DidUrl::new(format!("did:web:alice.example#{ALICE_DEVICE_ID}")).unwrap();
    let signer = Ed25519PayloadSigner::from_did_key_seed(
        arkret_signatures::development_signing_key_seed(verification_method.as_str()),
        actor_did,
        verification_method.clone(),
    );
    let realm_id = RealmId::new(realm_id.to_owned()).unwrap();
    let scope_ref = ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
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
    let event_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        actor_core_id.clone(),
        state.service_core_id(),
    ));
    let authority_grant_ref = existing
        .iter()
        .find(|event| {
            event.actor_id == event_actor.to_string()
                && event.realm_id.as_deref() == Some(realm_id.as_str())
                && event.kind == arkret_wire::EventKind::CapabilityGrant.as_str()
        })
        .map(|event| {
            arkret_identifiers::GrantId::from_event_id(
                &EventId::new(event.event_id.clone()).unwrap(),
            )
        })
        .expect("extension test Realm has Alice's accepted authority grant");
    let frontier = existing
        .iter()
        .filter(|event| {
            event.actor_id == event_actor.to_string()
                && event.realm_id.as_deref() == Some(realm_id.as_str())
        })
        .max_by_key(|event| event.actor_seq)
        .expect("extension test Realm has Alice's install frontier");
    let now =
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
    let millis = now.timestamp_millis().max(0) as u64;
    let mut event = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::MemberState.as_str(),
        scope_ref,
        actor_core_id,
        state.service_core_id(),
        frontier.actor_seq + 1,
        Hlc::new(format!("{millis:012x}-0001-a11ce001")).unwrap(),
        json!({
            "realm_id": realm_id,
            "member_id": member_id,
            "membership": "join",
        }),
        now,
    )
    .unwrap();
    event.prev_refs = vec![EventId::new(frontier.event_id.clone()).unwrap()];
    event.seal_basis = Some(seal_basis);
    event.authorization_ref = Some(authority_grant_ref.into());
    let mut event = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .expect("fixture managed membership Event finalizes");
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        &verification_method,
        SignEventOptions::new().with_created_at(now),
    )
    .unwrap();
    let event = event.into_event();
    let event_id = event.event_id.to_string();
    let response: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            true,
        )
        .add_header("Authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(arkret_canonical::canonical_json_bytes(&event).unwrap())
        .send(app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        response["accepted"],
        json!([event_id.clone()]),
        "managed membership join must pass the production Event admission path: {response}"
    );
    event_id
}

async fn signed_revoke_events(
    state: &AppState,
    realm_id: &str,
    preview: &Value,
) -> (
    Vec<arkret_wire::EventInitialSubmission>,
    Vec<arkret_wire::EventInitialSubmission>,
) {
    let actor_did = Did::new("did:web:alice.example").unwrap();
    let actor_core_id = arkret_wire::project_did_to_core_id(&actor_did).unwrap();
    let realm_id = RealmId::new(realm_id.to_owned()).unwrap();
    let scope_ref = ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let verification_method =
        arkret_wire::DidUrl::new(format!("did:web:alice.example#{ALICE_DEVICE_ID}")).unwrap();
    let signer = Ed25519PayloadSigner::from_did_key_seed(
        arkret_signatures::development_signing_key_seed(verification_method.as_str()),
        actor_did.clone(),
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
            event.actor_id
                == arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    actor_core_id.clone(),
                    state.service_core_id(),
                ))
                .to_string()
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
        let mut event = arkret_wire::test_support::raw_event(
            arkret_wire::EventKind::CapabilityRevoke.as_str(),
            scope_ref.clone(),
            actor_core_id.clone(),
            arkret_identifiers::DidCoreId::new(state.service_id().clone())
                .expect("extension test service core DID"),
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
        let mut event = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .expect("fixture envelope finalizes");
        arkret_signatures::sign_event(
            &mut event,
            &signer,
            &verification_method,
            SignEventOptions::new().with_created_at(now),
        )
        .unwrap();
        let event = event.into_event();
        previous_event_id = event.event_id.clone();
        submissions.push(arkret_wire::EventInitialSubmission {
            event,
            authorization_lease: None,
            cba_proof_bundles: Vec::new(),
            control_proposal_ack: None,
            membership_compensation_evidence: None,
        });
    }
    let membership_intents = preview["revoke_plan"]["membership_removals"]
        .as_array()
        .expect("preview membership removal intents");
    let mut membership_submissions = Vec::with_capacity(membership_intents.len());
    for (offset, intent) in membership_intents.iter().enumerate() {
        let counter = intents.len() + offset + 1;
        let mut event = arkret_wire::test_support::raw_event(
            arkret_wire::EventKind::MemberState.as_str(),
            scope_ref.clone(),
            actor_core_id.clone(),
            arkret_identifiers::DidCoreId::new(state.service_id().clone())
                .expect("extension test service core DID"),
            frontier.actor_seq + counter as u64,
            Hlc::new(format!("{millis:012x}-{counter:04x}-a11ce001")).unwrap(),
            json!({
                "member_id": intent["member_id"].clone(),
                "membership": intent["membership"].clone(),
                "reason": intent["reason_code"].clone(),
            }),
        )
        .unwrap();
        event.prev_refs = vec![previous_event_id];
        event.seal_basis = Some(seal_basis.clone());
        let mut event = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .expect("fixture membership leave Event finalizes");
        arkret_signatures::sign_event(
            &mut event,
            &signer,
            &verification_method,
            SignEventOptions::new().with_created_at(now),
        )
        .unwrap();
        let event = event.into_event();
        previous_event_id = event.event_id.clone();
        membership_submissions.push(arkret_wire::EventInitialSubmission {
            event,
            authorization_lease: None,
            cba_proof_bundles: Vec::new(),
            control_proposal_ack: None,
            membership_compensation_evidence: None,
        });
    }
    (submissions, membership_submissions)
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
    let applet_package = serde_json::to_value(package).expect("Applet package serializes");
    let registration_epoch_evidence = applet_registration_epoch_evidence(package);
    let ghost_actors_allowed = approve_actions
        .iter()
        .any(|action| action == "ak.applet.ghost.provision");
    let requested_at =
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
    let (registration_event, capability_grant_events, ..) = signed_install_events(
        state,
        package,
        realm_id,
        &registration_epoch_evidence,
        &approve_actions,
        requested_at,
        requested_at,
        None,
    )
    .await;
    let target_station_id = state.service_id().clone();
    let preview: Value = TestClient::post("http://server/_arkret/self/applets/install/preview")
        .add_header("Arkret-Operation", "ak.self.applet.install.command.preview.v1", true)
        .add_header("Authorization", format!("Bearer {token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_APPLET_INSTALL_COMMAND_PREVIEW_V1,
            true,
        )
        .json(&json!({
            "applet_package": applet_package,
            "authoring_request_basis": {
                "schema": "ak.schema.applet_install_authoring_request_basis.v1",
                "purpose": "install_bot",
                "target_station_id": target_station_id,
                "install_actor_id": registration_event.actor_id,
                "applet_id": package.applet_id,
                "service_id": package.service_id,
                "package_digest": package.package_digest,
                "effective_scope": effective_scope,
                "approval_request": {
                    "approve_actions": approve_actions,
                    "ghost_actor_mode": if ghost_actors_allowed { "policy_declared" } else { "disallowed" },
                    "delegated_native_actors_allowed": false,
                    "e2ee_join_allowed": false,
                    "widget_allowed": false,
                },
                "actor_policy": {
                    "ghost_actor_mode": "policy_declared"
                },
                "e2ee_policy": {"mls_join_allowed": false},
                "widget_policy": {"widget_allowed": false},
                "registration_event": registration_event,
                "capability_grant_events": capability_grant_events,
            },
        }))
        .send(app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        preview["plan"]["schema"],
        json!("ak.schema.applet_install_plan.v1"),
        "install preview: {preview}"
    );
    let authoring_request: arkret_models_integration::AppletManagedActorAuthoringRequest =
        serde_json::from_value(preview["authoring_request"].clone())
            .expect("preview returns a typed authoring request");
    let now = authoring_request.issued_at;
    let (
        _,
        _,
        bot_actor_provision_event,
        bot_pcr_genesis_event,
        bot_accountability_grant_event,
        bot_profile_event,
    ) = signed_install_events(
        state,
        package,
        realm_id,
        &registration_epoch_evidence,
        &approve_actions,
        requested_at,
        now,
        Some((registration_event.clone(), capability_grant_events.clone())),
    )
    .await;
    let bot_accountability_ref = bot_accountability_grant_event.event_id.to_string();
    let target_station_id = authoring_request
        .basis
        .install()
        .expect("install preview returns install_bot basis")
        .target_station_id
        .clone();
    let mut managed_actor_bundle = arkret_models_integration::AppletManagedActorAuthoringBundle {
        schema: arkret_models_integration::AppletManagedActorAuthoringBundle::SCHEMA.to_owned(),
        authoring_request_digest: authoring_request.canonical_digest().unwrap(),
        managed_actor_provision_event: bot_actor_provision_event,
        pcr_genesis_event: bot_pcr_genesis_event,
        accountability_grant_event: bot_accountability_grant_event,
        profile_event: bot_profile_event,
        proof: arkret_models_integration::AppletManagedActorProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: package.webhook_auth.key_ref.clone(),
            payload_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
                .unwrap(),
            created_at: now,
            audience_id: target_station_id,
            jws: String::new(),
        },
    };
    managed_actor_bundle.proof.payload_digest = managed_actor_bundle.payload_digest().unwrap();
    managed_actor_bundle.proof.jws = arkret_signatures::sign_ed25519_detached_jws(
        &applet_service_signing_key(&package.webhook_auth.key_ref),
        &managed_actor_bundle.proof_binding_bytes().unwrap(),
    )
    .unwrap();
    let mut commit: Value = TestClient::post("http://server/_arkret/self/applets/install")
        .add_header(
            "Arkret-Operation",
            "ak.self.applet.command.install.v1",
            true,
        )
        .add_header("Authorization", format!("Bearer {token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_APPLET_COMMAND_INSTALL_V1,
            true,
        )
        .add_header("Idempotency-Key", idempotency_key.to_owned(), true)
        .json(&json!({
            "applet_package": applet_package,
            "authoring_request": authoring_request,
            "managed_actor_bundle": managed_actor_bundle,
        }))
        .send(app)
        .await
        .take_json()
        .await
        .unwrap();
    let _: arkret_models_integration::AppletInstallOutcome = serde_json::from_value(commit.clone())
        .unwrap_or_else(|error| panic!("install commit is not a typed success: {error}: {commit}"));
    commit
        .as_object_mut()
        .expect("install outcome is an object")
        .insert(
            "_fixture_bot_accountability_ref".to_owned(),
            Value::String(bot_accountability_ref),
        );
    commit
}

fn applet_registration_epoch_evidence(
    package: &AppletPackage,
) -> arkret_models_integration::AppletRegistrationEpochEvidence {
    arkret_models_integration::AppletRegistrationEpochEvidence::from_did_document(
        &applet_service_id_document(package),
        arkret_models_integration::AppletDidMethodVersionEvidence::unversioned("did:web").unwrap(),
    )
    .unwrap()
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
