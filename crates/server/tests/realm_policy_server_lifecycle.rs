//! SOL-STATE-01 — `ak.realm.policy_server` self-management end-to-end:
//!
//!   1. HTTP `PUT`/`DELETE /_arkret/self/realms/{realm_id}/policy-server` drive the canonical
//!      Control-Move pipeline: unified admission, the durable canonical Event log, an accepted Seal
//!      from the local signing pass, and the cas-register projection — on a Realm bootstrapped
//!      through the real `ak.realm.create` genesis batch (this deployment is its notary).
//!   2. `DELETE` against an inherited-only or never-declared Realm answers `not_found` and leaves
//!      the ancestor cell untouched.
//!   3. The organization fallback resolves through the `governed_by` chain.
//!   4. Same-basis replace/delete siblings join the cell to `⊥` and every dependent read/write
//!      fails closed instead of resolving by arrival order.
//!   5. A restart over the same persistence replays the declaration from the durable projection
//!      stream.
//!
//! Spec: `arkret-spec/spec/v1/zh/authz/policy-server.md` §2.2.
//!
//! The value-tombstone legs of §2.2 (`DELETE` on a settled declaration, the
//! idempotent repeat, and the fallback restored by the tombstone) are NOT
//! asserted here: they are blocked by
//! `arkret-work/review/spec-open/2026-07-30-cas-register-join-lacks-reachability.md`
//! — `cas_register.join` receives no reachability information, so the second
//! accepted write to the cell joins to `⊥` and every dependent read fails
//! closed. That finding carries the reproduction; once the protocol decides
//! how the join learns reachability, those legs belong in this file.

use std::collections::BTreeMap;
use std::sync::Arc;

use arkret_identifiers::{Did, TypedTrustDomainId};
use arkret_models_identity::{
    CrossSigningPublish, KeyFormat, PublishedKey, SubordinateSignedKey, SubordinateSignedKeyBinding,
};
use arkret_wire::NonEmptyString;
use chrono::Utc;
use ed25519_dalek::SigningKey;
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use soland_http::config::AppConfig;
use soland_http::service;
use soland_http::state::AppState;
use soland_storage::PersistenceStore;
use soland_storage_memory::SolandMemoryPersistenceStore;
use soland_test_support::AppStateTestExt as _;

const ALICE: &str = "did:web:alice.example";
const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-a11ce0000001";
const POLICY_CELL: &str = "ak:cell:ak.component.realm.policy_server.v1:null";
const EVENT_SIGNING_SEED: [u8; 32] = [21_u8; 32];

fn test_config() -> AppConfig {
    AppConfig {
        development_mode: true,
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: BTreeMap::new(),
        trust_domain: "ak:trust_domain:soland-policy-test.local".to_owned(),
        ..soland_test_support::app_config()
    }
}

fn app_from_state(state: AppState) -> salvo::Service {
    service(state)
}

fn ed25519_public_multibase(signing: &SigningKey) -> String {
    let mut bytes = Vec::with_capacity(34);
    bytes.extend_from_slice(&[0xed, 0x01]);
    bytes.extend_from_slice(signing.verifying_key().as_bytes());
    format!("z{}", bs58::encode(bytes).into_string())
}

async fn dev_token(state: AppState, actor: &str, device_id: &str, display: &str) -> String {
    let login: Value = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&json!({
            "actor": actor,
            "device_id": device_id,
            "display_name": display,
        }))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    login["session_credential"].as_str().unwrap().to_owned()
}

fn cross_signing_publish(principal: &str, generation: u64) -> CrossSigningPublish {
    let principal_id = Did::new(principal.to_owned()).unwrap();
    let ssk = SigningKey::from_bytes(&[42_u8; 32]);
    CrossSigningPublish {
        principal_id,
        trust_domain: TypedTrustDomainId::new("ak:trust_domain:soland-policy-test.local").unwrap(),
        principal_signing_key: PublishedKey {
            kid: NonEmptyString::new(format!("{principal}#principal-signing")).unwrap(),
            alg: NonEmptyString::new("EdDSA").unwrap(),
            public_key: NonEmptyString::new("z6MkPrincipalAlice").unwrap(),
            key_format: KeyFormat::Multibase,
        },
        self_signing_key: SubordinateSignedKey {
            kid: NonEmptyString::new(format!("{principal}#self-signing")).unwrap(),
            alg: NonEmptyString::new("EdDSA").unwrap(),
            public_key: NonEmptyString::new(ed25519_public_multibase(&ssk)).unwrap(),
            key_format: KeyFormat::Multibase,
            binding: SubordinateSignedKeyBinding {
                verification_method: NonEmptyString::new(format!("{principal}#principal-signing"))
                    .unwrap(),
                alg: NonEmptyString::new("EdDSA").unwrap(),
                signature: NonEmptyString::new(format!("psk-sig-ssk-gen-{generation}")).unwrap(),
            },
        },
        user_signing_key: SubordinateSignedKey {
            kid: NonEmptyString::new(format!("{principal}#user-signing")).unwrap(),
            alg: NonEmptyString::new("EdDSA").unwrap(),
            public_key: NonEmptyString::new("z6MkUserAlice").unwrap(),
            key_format: KeyFormat::Multibase,
            binding: SubordinateSignedKeyBinding {
                verification_method: NonEmptyString::new(format!("{principal}#principal-signing"))
                    .unwrap(),
                alg: NonEmptyString::new("EdDSA").unwrap(),
                signature: NonEmptyString::new(format!("psk-sig-usk-gen-{generation}")).unwrap(),
            },
        },
        expected_previous_generation: generation.saturating_sub(1),
        generation: std::num::NonZeroU64::new(generation).unwrap(),
        issued_at: Utc::now(),
    }
}

async fn prepare_alice(state: &AppState) -> String {
    let token = dev_token(state.clone(), ALICE, ALICE_DEVICE, "Alice").await;
    let signing = SigningKey::from_bytes(&EVENT_SIGNING_SEED);
    let mut device = state
        .test_persistence()
        .devices()
        .get(ALICE, ALICE_DEVICE)
        .await
        .unwrap()
        .unwrap();
    device.payload["device_public_key"] = json!(ed25519_public_multibase(&signing));
    device.verification_state = "verified".to_owned();
    state
        .test_persistence()
        .devices()
        .put(&device)
        .await
        .unwrap();
    state
        .test_record_cross_signing_publish(cross_signing_publish(ALICE, 1))
        .unwrap();
    token
}

#[expect(
    clippy::too_many_arguments,
    reason = "the fixture mirrors the complete canonical event envelope"
)]
fn signed_event(
    event_id: &str,
    actor_seq: u64,
    actor: &str,
    device_id: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
    prev_refs: &[&str],
) -> Value {
    let now = Utc::now();
    let actor = Did::new(actor.to_owned()).unwrap();
    let verification_method = format!("{}#{device_id}", actor.as_str());
    let mut event = arkret_wire::Event::new_with_id_at(
        arkret_wire::EventId::new(event_id.to_owned()).unwrap(),
        kind,
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(realm_id.to_owned()).unwrap(),
        },
        actor.clone(),
        actor_seq,
        arkret_identifiers::Hlc::new(format!(
            "{:012x}-0000-00000000",
            now.timestamp_millis().max(0) as u64
        ))
        .unwrap(),
        payload,
        now,
    )
    .unwrap();
    event.prev_refs = prev_refs
        .iter()
        .map(|id| arkret_wire::EventId::new((*id).to_owned()).unwrap())
        .collect();
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        EVENT_SIGNING_SEED,
        actor,
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

/// Bootstrap `realm_id` through the real `ak.realm.create` genesis batch, with
/// this deployment as its `single_did` notary, so the Realm ends up with a
/// genuine accepted governance Seal the policy-server Control Moves can cite.
async fn bootstrap_realm(state: &AppState, token: &str, realm_id: &str, slot: u8, seq_base: u64) {
    let realm_event_id = format!("ak:event:01904100-0000-7000-8000-00000000{slot:02x}e0");
    let grant_event_id = format!("ak:event:01904100-0000-7000-8000-00000000{slot:02x}e1");
    let grant_id = format!("ak:grant:01904100-0000-7000-8000-00000000{slot:02x}ef");
    let realm_create = signed_event(
        &realm_event_id,
        seq_base,
        ALICE,
        ALICE_DEVICE,
        realm_id,
        "ak.realm.create",
        json!({
            "object": {
                "id": realm_id,
                "schema": "ak.schema.realm.v1",
                "title": format!("policy server lifecycle {slot}"),
                "created_by": ALICE,
                "trust_domain": "ak:trust_domain:soland-policy-test.local",
                "schema_refs": ["ak.schema.realm.v1"],
                "default_discoverability": "listed",
                "default_join_rule": "invite",
                "history_visibility": "joined",
                "encryption_profile": "none",
                "security_class": "standard",
                "federation_policy": "restricted",
                "notary_profile": "single_did",
                "notary": {
                    "kind": "single_did",
                    "did": state.service_id(),
                },
                "created_at": "2026-05-25T00:00:00.000Z"
            }
        }),
        &[],
    );
    let grant_created_at = realm_create["created_at"].as_str().unwrap().to_owned();
    let mut grant: arkret_models_collaboration::governance::grant_constraint::CapabilityGrant =
        serde_json::from_value(json!({
            "id": grant_id,
            "schema": "ak.schema.capability.v1",
            "realm_id": realm_id,
            "issuer": ALICE,
            "subject": ALICE,
            "actions": [
                "ak.realm.admin",
                "ak.capability.grant",
                "ak.capability.revoke",
                "ak.realm_key.share",
                "ak.message.create"
            ],
            "capability_action_registry_digest":
                arkret_policy::current_capability_action_registry_digest().unwrap(),
            "resources": [{
                "kind": "realm",
                "realm_id": realm_id,
                "match_scope": "realm_wide"
            }],
            "issued_at": grant_created_at,
            "proofs": []
        }))
        .unwrap();
    let event_signing_key = SigningKey::from_bytes(&EVENT_SIGNING_SEED);
    let mut grant_proof = arkret_wire::PayloadProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: format!("{ALICE}#{ALICE_DEVICE}"),
        payload_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
            .unwrap(),
        created_at: chrono::DateTime::parse_from_rfc3339(&grant_created_at)
            .unwrap()
            .with_timezone(&Utc),
        domain: None,
        audience: None,
        proof_purpose: Some(arkret_wire::PayloadProofPurpose::IssuerAttestation),
        jws: "pending".to_owned(),
    };
    grant_proof.payload_digest = grant.payload_digest().unwrap();
    grant_proof.jws = arkret_signatures::jws::sign_jws_ed25519(
        &grant.canonical_proof_binding_bytes(&grant_proof).unwrap(),
        &event_signing_key,
    )
    .unwrap();
    grant.proofs.push(grant_proof);
    let founding_grant = signed_event(
        &grant_event_id,
        seq_base + 1,
        ALICE,
        ALICE_DEVICE,
        realm_id,
        arkret_wire::events::EventKind::CAPABILITY_GRANT,
        json!({"grant_id": grant_id, "grant": grant}),
        &[&realm_event_id],
    );
    let mut create_resp = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&json!({"events": [realm_create, founding_grant]}))
        .send(&app_from_state(state.clone()))
        .await;
    let create_status = create_resp.status_code;
    if create_status != Some(StatusCode::OK) {
        let error: Value = create_resp.take_json().await.unwrap_or(Value::Null);
        panic!("Realm create failed with {create_status:?}: {error}");
    }
    grant_policy_manage(state, realm_id);
    // Admin Control Moves need an accepted Seal to cite; wait for the
    // coordinator to materialize the bootstrap Seal.
    accepted_seal_frontier(state, token, realm_id).await;
}

/// The founding grant deliberately excludes `ak.policy.manage`; register the
/// explicit grant the admission gate requires in the shared authz engine.
fn grant_policy_manage(state: &AppState, realm_id: &str) {
    soland_http::authz::install_projected_grant(
        state.test_authz(),
        realm_id.to_owned(),
        ALICE.to_owned(),
        ALICE.to_owned(),
        realm_id.to_owned(),
        vec![arkret_wire::CapabilityActionId::POLICY_MANAGE.to_owned()],
        Vec::new(),
    );
}

fn declaration_body(host: &str) -> Value {
    json!({
        "policy_server_did": format!("did:web:{host}"),
        "policy_server_url": format!("https://{host}/_arkret/self/policy/check"),
        "cache_ttl_seconds": 60,
        "timeout_ms": 1500,
        "on_timeout": "fail_closed",
    })
}

async fn put_policy_server(
    state: &AppState,
    token: &str,
    realm_id: &str,
    body: &Value,
) -> (StatusCode, Value) {
    let mut response = TestClient::put(format!(
        "http://server/_arkret/self/realms/{realm_id}/policy-server"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .json(body)
    .send(&app_from_state(state.clone()))
    .await;
    let status = response.status_code.expect("PUT status");
    let body = response.take_json().await.unwrap_or(Value::Null);
    (status, body)
}

async fn get_policy_server(state: &AppState, token: &str, realm_id: &str) -> (StatusCode, Value) {
    let mut response = TestClient::get(format!(
        "http://server/_arkret/self/realms/{realm_id}/policy-server"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    let status = response.status_code.expect("GET status");
    let body = response.take_json().await.unwrap_or(Value::Null);
    (status, body)
}

async fn delete_policy_server(
    state: &AppState,
    token: &str,
    realm_id: &str,
) -> (StatusCode, Value) {
    let mut response = TestClient::delete(format!(
        "http://server/_arkret/self/realms/{realm_id}/policy-server"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    let status = response.status_code.expect("DELETE status");
    let body = response.take_json().await.unwrap_or(Value::Null);
    (status, body)
}

async fn policy_server_events(state: &AppState, token: &str, realm_id: &str) -> Vec<Value> {
    let events: Value = TestClient::get(format!(
        "http://server/_arkret/self/events?realms={realm_id}&limit=200"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    events["events"]
        .as_array()
        .expect("events array")
        .iter()
        .filter(|event| {
            event
                .get("event_kind")
                .or_else(|| event.get("kind"))
                .and_then(Value::as_str)
                == Some("ak.realm.policy_server")
        })
        .cloned()
        .collect()
}

async fn accepted_seal_frontier(state: &AppState, token: &str, realm_id: &str) -> String {
    for attempt in 0..50 {
        let mut response = TestClient::get(format!(
            "http://server/_arkret/self/events/frontier?realm_id={realm_id}"
        ))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
        let status = response.status_code;
        let body: Value = response.take_json().await.unwrap_or(Value::Null);
        if status == Some(StatusCode::OK) {
            let frontier: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
                serde_json::from_value(body).expect("typed Realm Seal frontier");
            let arkret_models_collaboration::event_sync::EventsFrontierView::RealmSeal(frontier) =
                frontier.frontier
            else {
                panic!("Realm-only selector returned the wrong frontier variant");
            };
            return frontier.seal_id.to_string();
        }
        assert_eq!(
            status,
            Some(StatusCode::SERVICE_UNAVAILABLE),
            "Realm Seal frontier failed with {status:?}: {body}"
        );
        assert!(
            attempt < 49,
            "Realm Seal frontier remained unavailable: {body}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    unreachable!("bounded Realm Seal frontier retry returns or panics")
}

async fn link_governed_by(state: &AppState, token: &str, realm_id: &str, target: &str) {
    let body: Value = TestClient::post(format!(
        "http://server/_arkret/self/realms/{realm_id}/links"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .json(&json!({
        "target_realm_id": target,
        "link_kind": "governed_by",
        "status": "active",
    }))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(body["status"], "active", "governed_by link: {body}");
}

const CHILD_REALM: &str = "ak:realm:01904100-0000-7000-8000-00000000c001";
const ORG_REALM: &str = "ak:realm:01904100-0000-7000-8000-00000000c002";

#[tokio::test(flavor = "multi_thread")]
async fn policy_server_declaration_is_sealed_and_resolves_org_fallback() {
    let persistence: Arc<dyn PersistenceStore> = Arc::new(SolandMemoryPersistenceStore::new());
    let state = soland_test_support::app_state_with_persistence(test_config(), persistence);
    let _control_seal_coordinator = soland_http::control_seal_coordinator::spawn(state.clone());
    let token = prepare_alice(&state).await;
    bootstrap_realm(&state, &token, CHILD_REALM, 1, 0).await;
    bootstrap_realm(&state, &token, ORG_REALM, 2, 0).await;
    link_governed_by(&state, &token, CHILD_REALM, ORG_REALM).await;

    // 1. The org declares; the child resolves it through the governed_by walk.
    let seal_before = accepted_seal_frontier(&state, &token, ORG_REALM).await;
    let (status, view) = put_policy_server(
        &state,
        &token,
        ORG_REALM,
        &declaration_body("org-policy.example"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "org PUT: {view}");
    assert_eq!(view["policy_server_did"], "did:web:org-policy.example");
    assert_eq!(view["from_org_fallback"], false);

    // The declaration is a canonical Control Move in the durable Event log,
    // authored by the caller and executed by the service.
    let declared = policy_server_events(&state, &token, ORG_REALM).await;
    assert_eq!(declared.len(), 1, "declaration events: {declared:?}");
    assert_eq!(
        declared[0]["payload"]["policy_server_did"],
        "did:web:org-policy.example"
    );
    assert_eq!(declared[0]["actor_id"], ALICE);

    // The self-management handler runs a local notary signing pass, so the
    // accepted Seal frontier advances: the Move is Seal-covered, not merely
    // projected.
    let seal_after_put = accepted_seal_frontier(&state, &token, ORG_REALM).await;
    assert_ne!(
        seal_before, seal_after_put,
        "policy-server Control Move must be covered by a newly accepted Seal"
    );

    // 2. The child has no direct binding; the resolver walks governed_by.
    let (status, inherited) = get_policy_server(&state, &token, CHILD_REALM).await;
    assert_eq!(status, StatusCode::OK, "inherited GET: {inherited}");
    assert_eq!(inherited["policy_server_did"], "did:web:org-policy.example");
    assert_eq!(inherited["from_org_fallback"], true);

    // 3. An inherited value is not a direct declaration: DELETE answers not_found and must not
    //    touch the ancestor cell.
    let (status, body) = delete_policy_server(&state, &token, CHILD_REALM).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "inherited DELETE: {body}");
    let org_events_after = policy_server_events(&state, &token, ORG_REALM).await;
    assert_eq!(
        org_events_after.len(),
        1,
        "an inherited DELETE must not append to the ancestor: {org_events_after:?}"
    );
    let seal_after_refusal = accepted_seal_frontier(&state, &token, ORG_REALM).await;
    assert_eq!(
        seal_after_put, seal_after_refusal,
        "a refused DELETE must not advance the accepted Seal frontier"
    );

    // 4. A Realm that never declared anything, and has no governed_by chain, answers not_found as
    //    well.
    let never_declared = "ak:realm:01904100-0000-7000-8000-00000000c003";
    bootstrap_realm(&state, &token, never_declared, 3, 0).await;
    let (status, body) = delete_policy_server(&state, &token, never_declared).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "never-declared DELETE: {body}"
    );
    let (status, body) = get_policy_server(&state, &token, never_declared).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "never-declared GET: {body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_server_declaration_survives_restart() {
    let persistence: Arc<dyn PersistenceStore> = Arc::new(SolandMemoryPersistenceStore::new());
    let state = soland_test_support::app_state_with_persistence(test_config(), persistence.clone());
    let _control_seal_coordinator = soland_http::control_seal_coordinator::spawn(state.clone());
    let token = prepare_alice(&state).await;
    bootstrap_realm(&state, &token, ORG_REALM, 2, 0).await;

    let (status, view) = put_policy_server(
        &state,
        &token,
        ORG_REALM,
        &declaration_body("org-policy.example"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "org PUT: {view}");

    // Restart: a fresh AppState over the same persistence, rehydrated from the
    // durable projection stream. Before this suite existed, `hydration.rs` had
    // no `ak.realm.policy_server` replay arm at all, so a restart silently lost
    // every declaration.
    let restarted =
        soland_test_support::app_state_with_persistence(test_config(), persistence.clone());
    restarted.hydrate().await.expect("restarted state hydrates");
    let restarted_token = dev_token(restarted.clone(), ALICE, ALICE_DEVICE, "Alice").await;

    let (status, view) = get_policy_server(&restarted, &restarted_token, ORG_REALM).await;
    assert_eq!(status, StatusCode::OK, "restarted GET: {view}");
    assert_eq!(view["policy_server_did"], "did:web:org-policy.example");
    assert_eq!(view["from_org_fallback"], false);

    let projection = restarted.test_projection().lock();
    assert_eq!(
        projection
            .realm_null_subject_cells
            .get(&(ORG_REALM.to_owned(), POLICY_CELL.to_owned()))
            .and_then(|cell| match cell {
                arkret_state::lattice::CellState::Value(value) =>
                    value.get("policy_server_did").and_then(Value::as_str),
                arkret_state::lattice::CellState::Bottom(_) => None,
            }),
        Some("did:web:org-policy.example"),
        "the declaration cell must survive restart"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_server_same_basis_sibling_fails_closed() {
    let persistence: Arc<dyn PersistenceStore> = Arc::new(SolandMemoryPersistenceStore::new());
    let state = soland_test_support::app_state_with_persistence(test_config(), persistence);
    let _control_seal_coordinator = soland_http::control_seal_coordinator::spawn(state.clone());
    let token = prepare_alice(&state).await;
    bootstrap_realm(&state, &token, CHILD_REALM, 1, 0).await;

    let settled = declaration_body("first-policy.example");
    let (status, view) = put_policy_server(&state, &token, CHILD_REALM, &settled).await;
    assert_eq!(status, StatusCode::OK, "settle PUT: {view}");

    // Two Moves that cite the SAME frozen basis and write different values are
    // cas-register siblings. `policy-server.md` §2.2 forbids resolving them by
    // arrival order: they join to `⊥`, and every dependent read or write then
    // fails closed until a §9.5 conflict-recovery Move.
    let settled_basis = {
        let projection = state.test_projection().lock();
        projection
            .realm_null_subject_cells
            .get(&(CHILD_REALM.to_owned(), POLICY_CELL.to_owned()))
            .and_then(|cell| match cell {
                arkret_state::lattice::CellState::Value(value) => Some(value.clone()),
                arkret_state::lattice::CellState::Bottom(_) => None,
            })
            .expect("settled declaration")
    };
    let sibling_move = |mut payload: Value| {
        payload["preconditions"] = json!([{
            "cell": POLICY_CELL,
            "predicate": {"op": "head_eq", "value": settled_basis.clone()},
        }]);
        arkret_event_draft::Operation::create(
            arkret_identifiers::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
                .unwrap(),
            arkret_identifiers::RealmId::new(CHILD_REALM).unwrap(),
            arkret_wire::events::EventKind::REALM_POLICY_SERVER,
            payload,
        )
    };
    {
        let mut projection = state.test_projection().lock();
        let replace = projection.apply(
            &sibling_move(declaration_body("second-policy.example")),
            state.test_hlc(),
        );
        assert!(
            matches!(
                replace,
                soland_domain::reducer::ProjectionEffect::RealmPolicyServerProjected { .. }
            ),
            "the first sibling advances the head, got {replace:?}"
        );
        let delete = projection.apply(&sibling_move(json!({"tombstone": true})), state.test_hlc());
        assert!(
            matches!(
                delete,
                soland_domain::reducer::ProjectionEffect::RealmPolicyServerConflicted { .. }
            ),
            "the same-basis sibling must join to ⊥, got {delete:?}"
        );
    }

    // Every dependent read and write now fails closed with the canonical
    // `failed_bottom` wire code.
    let (status, body) = get_policy_server(&state, &token, CHILD_REALM).await;
    assert_eq!(status, StatusCode::CONFLICT, "GET after ⊥: {body}");
    assert_eq!(body["error"]["code"], "failed_bottom", "GET body: {body}");

    let (status, body) = put_policy_server(
        &state,
        &token,
        CHILD_REALM,
        &declaration_body("third-policy.example"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "PUT after ⊥: {body}");

    let (status, body) = delete_policy_server(&state, &token, CHILD_REALM).await;
    assert_eq!(status, StatusCode::CONFLICT, "DELETE after ⊥: {body}");
}
