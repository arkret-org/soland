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
use std::collections::BTreeMap;
use std::sync::Arc;

use arkret_identifiers::{DidFullId, RealmId, SealId};
use arkret_models_collaboration::governance::realm_governance::{
    RealmLinkCreateRequestBody, RealmPolicyServerDeleteRequestBody,
    RealmPolicyServerReplaceRequestBody,
};
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
use soland_test_support::signed_event::{
    CallerSignedEvent, FIXTURE_EVENT_SIGNING_SEED, complete_realm_bootstrap_unit,
    head_eq_precondition,
};

const ALICE: &str = "did:web:alice.example";
const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-a11ce0000001";
const POLICY_CELL: &str = "ak:cell:ak.component.realm.policy_server.v1:null";
const TRUST_DOMAIN: &str = "ak:trust_domain:soland-policy-test.local";

fn test_config() -> AppConfig {
    AppConfig {
        development_mode: true,
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: BTreeMap::new(),
        trust_domain: arkret_identifiers::TrustDomainId::new(TRUST_DOMAIN).unwrap(),
        ..soland_test_support::app_config()
    }
}

fn app_from_state(state: AppState) -> salvo::Service {
    service(state)
}

async fn dev_token(state: AppState, actor: &str, device_id: &str, display: &str) -> String {
    let actor_core = arkret_wire::project_full_id_to_core_id(
        &DidFullId::new(actor.to_owned()).expect("fixture actor full DID"),
    )
    .expect("fixture actor core id");
    let login: Value = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&json!({
            "actor": actor_core,
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

async fn prepare_alice(state: &AppState) -> String {
    let token = dev_token(state.clone(), ALICE, ALICE_DEVICE, "Alice").await;
    let signing = SigningKey::from_bytes(&FIXTURE_EVENT_SIGNING_SEED);
    soland_test_support::project_authorized_principal_device(state, ALICE, ALICE_DEVICE, &signing)
        .await;
    token
}

/// Bootstrap a Realm through the real `ak.realm.create` genesis batch, with this
/// deployment as its frozen `single_signer` notary, so the Realm ends up with a genuine
/// accepted governance Seal the policy-server Control Moves can cite.
///
/// The Realm id is not chosen here: `realm-and-space.md` section 2.5.0 derives it
/// from the genesis Event, so the fixture reads it back off the Event it signed.
/// The previous version picked an id, restated it in `object.id` and sent the
/// Move under `ScopeRef::Realm` — three ways of asserting a Realm the receiver
/// derives for itself.
async fn bootstrap_realm(state: &AppState, token: &str, title: &str) -> String {
    let genesis = CallerSignedEvent::realm_genesis(
        ALICE,
        ALICE_DEVICE,
        soland_test_support::cba_basis::realm_genesis_payload(
            state,
            ALICE,
            title,
            TRUST_DOMAIN,
            Utc::now(),
        ),
    )
    .build();
    let realm_id = RealmId::from_event_id(&genesis.event_id).to_string();
    let bootstrap = complete_realm_bootstrap_unit(genesis, ALICE, ALICE_DEVICE, title);
    let mut create_resp = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "events": bootstrap
                .into_iter()
                .map(arkret_wire::EventInitialSubmission::online)
                .collect::<Vec<_>>()
        }))
        .send(&app_from_state(state.clone()))
        .await;
    let create_status = create_resp.status_code;
    if create_status != Some(StatusCode::OK) {
        let error: Value = create_resp.take_json().await.unwrap_or(Value::Null);
        panic!("Realm create failed with {create_status:?}: {error}");
    }
    grant_policy_manage(state, &realm_id);
    // Admin Control Moves need an accepted Seal to cite; wait for the
    // coordinator to materialize the bootstrap Seal.
    accepted_seal_frontier(state, token, &realm_id).await;
    realm_id
}

/// Realm genesis grants nothing: the create Event registers the authority-root
/// cell and nothing else. Register the explicit `ak.policy.manage` grant the
/// admission gate requires in the shared authz engine.
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

/// The registered operation bodies are read as canonical JSON, so a fixture
/// posts RFC 8785 bytes rather than whatever field order `serde_json` happens to
/// emit.
fn canonical_body<T: serde::Serialize>(body: &T) -> Vec<u8> {
    arkret_canonical::canonical_json_bytes(body).expect("canonical operation body")
}

fn declaration_body(host: &str) -> Value {
    json!({
        "policy_server_service_id": format!("ak:did_core:web:{host}"),
        "policy_server_url": format!("https://{host}/_arkret/self/policy/check"),
        "cache_ttl_seconds": 60,
        "timeout_ms": 1500,
        "on_timeout": "fail_closed",
    })
}

/// The Control Move a policy-server write carries, guarded by whatever the cell
/// has already settled on.
///
/// Reading the settled value first is not fixture convenience: the guard is
/// inside the bytes the caller signs, so the service can no longer attach it.
/// This is the burden `key-management.md` section 411 moves onto every real
/// caller, and a fixture that skipped it would be testing a surface nobody can
/// reach.
fn policy_server_move(
    state: &AppState,
    realm_id: &str,
    payload: Value,
    seal: &SealId,
    actor_seq: u64,
    prev_refs: Vec<&str>,
) -> arkret_wire::EventInitialSubmission {
    let preconditions = settled_policy_server_value(state, realm_id)
        .map(|settled| vec![head_eq_precondition(POLICY_CELL, settled)])
        .unwrap_or_default();
    unguarded_policy_server_move(realm_id, payload, seal)
        .with_actor_seq(actor_seq)
        .with_prev_refs(prev_refs)
        .with_preconditions(preconditions)
        .build_submission()
}

/// The same Control Move with no guard at all.
fn unguarded_policy_server_move<'a>(
    realm_id: &'a str,
    payload: Value,
    seal: &SealId,
) -> CallerSignedEvent<'a> {
    CallerSignedEvent::new(
        arkret_wire::EventKind::RealmPolicyServer.as_str(),
        ALICE,
        ALICE_DEVICE,
        realm_id,
        payload,
    )
    .with_accepted_seal_basis(seal.clone())
}

/// The value the policy-server register has settled on, if it has settled.
fn settled_policy_server_value(state: &AppState, realm_id: &str) -> Option<Value> {
    let projection = state.test_projection();
    let projection = projection.lock();
    match projection
        .realm_null_subject_cells
        .get(&(realm_id.to_owned(), POLICY_CELL.to_owned()))
    {
        Some(arkret_state::lattice::CellState::Value(value)) => Some(value.clone()),
        _ => None,
    }
}

async fn put_policy_server(
    state: &AppState,
    token: &str,
    realm_id: &str,
    body: &Value,
) -> (StatusCode, Value) {
    let seal = accepted_seal_id(state, token, realm_id).await;
    let (actor_seq, prev_refs) = actor_frontier(state, token, realm_id).await;
    let request = RealmPolicyServerReplaceRequestBody {
        policy_server_event: policy_server_move(
            state,
            realm_id,
            body.clone(),
            &seal,
            actor_seq,
            prev_refs.iter().map(String::as_str).collect(),
        ),
    };
    send_put_policy_server(state, token, realm_id, &request).await
}

async fn send_put_policy_server(
    state: &AppState,
    token: &str,
    realm_id: &str,
    request: &RealmPolicyServerReplaceRequestBody,
) -> (StatusCode, Value) {
    let mut response = TestClient::put(format!(
        "http://server/_arkret/self/realms/{realm_id}/policy-server"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .add_header("content-type", "application/json", true)
    .body(canonical_body(request))
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
    // The removal is a signed Event, so this DELETE carries a body the way
    // `ak.self.keys.backups.resource.delete` already does.
    let seal = accepted_seal_id(state, token, realm_id).await;
    let (actor_seq, prev_refs) = actor_frontier(state, token, realm_id).await;
    let request = RealmPolicyServerDeleteRequestBody {
        policy_server_event: policy_server_move(
            state,
            realm_id,
            json!({"tombstone": true}),
            &seal,
            actor_seq,
            prev_refs.iter().map(String::as_str).collect(),
        ),
    };
    let mut response = TestClient::delete(format!(
        "http://server/_arkret/self/realms/{realm_id}/policy-server"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .add_header("content-type", "application/json", true)
    .body(canonical_body(&request))
    .send(&app_from_state(state.clone()))
    .await;
    let status = response.status_code.expect("DELETE status");
    let body = response.take_json().await.unwrap_or(Value::Null);
    (status, body)
}

async fn policy_server_events(state: &AppState, token: &str, realm_id: &str) -> Vec<Value> {
    let events: Value = TestClient::query("http://server/_arkret/self/events")
        .json(&serde_json::json!({"realms": [realm_id], "limit": 200}))
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

/// The accepted Seal a Control Move of `realm_id` cites in `seal_basis`.
async fn accepted_seal_id(state: &AppState, token: &str, realm_id: &str) -> SealId {
    SealId::new(accepted_seal_frontier(state, token, realm_id).await)
        .expect("accepted Realm Seal id")
}

async fn accepted_seal_frontier(state: &AppState, token: &str, realm_id: &str) -> String {
    for attempt in 0..50 {
        let mut response = TestClient::query("http://server/_arkret/self/events/frontier")
            .json(&serde_json::json!({"realm_id": realm_id}))
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
            return frontier
                .sole_leaf()
                .expect("single-signer Realm frontier")
                .to_string();
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

async fn actor_frontier(state: &AppState, token: &str, realm_id: &str) -> (u64, Vec<String>) {
    let actor_core = arkret_wire::project_full_id_to_core_id(
        &DidFullId::new(ALICE.to_owned()).expect("fixture frontier actor full DID"),
    )
    .expect("fixture frontier actor core DID");
    let frontier_value: Value = TestClient::query("http://server/_arkret/self/events/frontier")
        .json(
            &arkret_models_collaboration::event_query::EventsFrontierRequestBody {
                actor_id: Some(actor_core),
                realm_id: Some(
                    RealmId::new(realm_id.to_owned()).expect("fixture frontier Realm id"),
                ),
            },
        )
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .expect("typed actor Realm frontier");
    let frontier: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
        serde_json::from_value(frontier_value.clone()).unwrap_or_else(|error| {
            panic!("invalid typed actor Realm frontier: {error}; {frontier_value}")
        });
    let arkret_models_collaboration::event_sync::EventsFrontierView::RealmActor(frontier) =
        frontier.frontier
    else {
        panic!("combined Realm+actor selector returned the wrong frontier variant");
    };
    frontier.validate().expect("valid actor Realm frontier");
    (
        frontier.next_actor_seq,
        frontier
            .frontier_event_ids
            .into_iter()
            .map(|event_id| event_id.to_string())
            .collect(),
    )
}

async fn link_governed_by(state: &AppState, token: &str, realm_id: &str, target: &str) {
    let seal = accepted_seal_id(state, token, realm_id).await;
    let (actor_seq, prev_refs) = actor_frontier(state, token, realm_id).await;
    let request = RealmLinkCreateRequestBody {
        link_event: CallerSignedEvent::new(
            arkret_wire::EventKind::RealmLink.as_str(),
            ALICE,
            ALICE_DEVICE,
            realm_id,
            json!({
                "target_realm_id": target,
                "link_kind": "governed_by",
                "status": "active",
            }),
        )
        .with_actor_seq(actor_seq)
        .with_prev_refs(prev_refs.iter().map(String::as_str).collect())
        .with_accepted_seal_basis(seal)
        .build_submission(),
    };
    let body: Value = TestClient::post(format!(
        "http://server/_arkret/self/realms/{realm_id}/links"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .add_header("content-type", "application/json", true)
    .body(canonical_body(&request))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(body["status"], "active", "governed_by link: {body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_server_declaration_is_sealed_and_resolves_org_fallback() {
    let persistence: Arc<dyn PersistenceStore> = Arc::new(SolandMemoryPersistenceStore::new());
    let state = soland_test_support::app_state_with_persistence(test_config(), persistence).await;
    let _control_seal_coordinator = soland_http::control_seal_coordinator::spawn(state.clone());
    let token = prepare_alice(&state).await;
    let child_realm = bootstrap_realm(&state, &token, "policy server lifecycle child").await;
    let org_realm = bootstrap_realm(&state, &token, "policy server lifecycle org").await;
    let (child_realm, org_realm) = (child_realm.as_str(), org_realm.as_str());
    link_governed_by(&state, &token, child_realm, org_realm).await;

    // 1. The org declares; the child resolves it through the governed_by walk.
    let seal_before = accepted_seal_frontier(&state, &token, org_realm).await;
    let (status, view) = put_policy_server(
        &state,
        &token,
        org_realm,
        &declaration_body("org-policy.example"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "org PUT: {view}");
    assert_eq!(
        view["policy_server_service_id"],
        "ak:did_core:web:org-policy.example"
    );
    assert_eq!(view["from_organization_fallback"], false);

    // The declaration is a canonical Control Move in the durable Event log,
    // authored by the caller and executed by the service.
    let declared = policy_server_events(&state, &token, org_realm).await;
    assert_eq!(declared.len(), 1, "declaration events: {declared:?}");
    assert_eq!(
        declared[0]["payload"]["policy_server_service_id"],
        "ak:did_core:web:org-policy.example"
    );
    let alice_core = arkret_wire::project_full_id_to_core_id(
        &DidFullId::new(ALICE.to_owned()).expect("fixture actor full DID"),
    )
    .expect("fixture actor core DID");
    assert_eq!(declared[0]["actor_id"], alice_core.as_str());

    // The self-management handler runs a local notary signing pass, so the
    // accepted Seal frontier advances: the Move is Seal-covered, not merely
    // projected.
    let seal_after_put = accepted_seal_frontier(&state, &token, org_realm).await;
    assert_ne!(
        seal_before, seal_after_put,
        "policy-server Control Move must be covered by a newly accepted Seal"
    );

    // 2. The child has no direct binding; the resolver walks governed_by.
    let (status, inherited) = get_policy_server(&state, &token, child_realm).await;
    assert_eq!(status, StatusCode::OK, "inherited GET: {inherited}");
    assert_eq!(
        inherited["policy_server_service_id"],
        "ak:did_core:web:org-policy.example"
    );
    assert_eq!(inherited["from_organization_fallback"], true);

    // 3. An inherited value is not a direct declaration: DELETE answers not_found and must not
    //    touch the ancestor cell.
    let (status, body) = delete_policy_server(&state, &token, child_realm).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "inherited DELETE: {body}");
    let org_events_after = policy_server_events(&state, &token, org_realm).await;
    assert_eq!(
        org_events_after.len(),
        1,
        "an inherited DELETE must not append to the ancestor: {org_events_after:?}"
    );
    let seal_after_refusal = accepted_seal_frontier(&state, &token, org_realm).await;
    assert_eq!(
        seal_after_put, seal_after_refusal,
        "a refused DELETE must not advance the accepted Seal frontier"
    );

    // 4. A direct child declaration can be tombstoned. The settled tombstone restores the inherited
    //    organization value, and repeating DELETE is an idempotent empty success.
    let (status, direct) = put_policy_server(
        &state,
        &token,
        child_realm,
        &declaration_body("child-policy.example"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "child PUT: {direct}");
    assert_eq!(direct["from_organization_fallback"], false);
    let (status, deleted) = delete_policy_server(&state, &token, child_realm).await;
    assert_eq!(status, StatusCode::OK, "settled child DELETE: {deleted}");
    let child_events = policy_server_events(&state, &token, child_realm).await;
    assert_eq!(child_events.len(), 2, "declaration plus tombstone");
    assert_eq!(child_events[1]["payload"]["tombstone"], true);
    let (status, inherited_again) = get_policy_server(&state, &token, child_realm).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "fallback after tombstone: {inherited_again}"
    );
    assert_eq!(
        inherited_again["policy_server_service_id"],
        "ak:did_core:web:org-policy.example"
    );
    assert_eq!(inherited_again["from_organization_fallback"], true);
    let (status, repeated) = delete_policy_server(&state, &token, child_realm).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "repeated tombstone DELETE: {repeated}"
    );
    assert_eq!(
        policy_server_events(&state, &token, child_realm)
            .await
            .len(),
        2,
        "repeat must not append another tombstone"
    );

    // 5. A Realm that never declared anything, and has no governed_by chain, answers not_found as
    //    well.
    let never_declared =
        bootstrap_realm(&state, &token, "policy server lifecycle never declared").await;
    let never_declared = never_declared.as_str();
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
    let state =
        soland_test_support::app_state_with_persistence(test_config(), persistence.clone()).await;
    let _control_seal_coordinator = soland_http::control_seal_coordinator::spawn(state.clone());
    let token = prepare_alice(&state).await;
    let org_realm = bootstrap_realm(&state, &token, "policy server restart org").await;
    let org_realm = org_realm.as_str();

    let (status, view) = put_policy_server(
        &state,
        &token,
        org_realm,
        &declaration_body("org-policy.example"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "org PUT: {view}");

    // Restart: a fresh AppState over the same persistence, rehydrated from the
    // durable projection stream. Before this suite existed, `hydration.rs` had
    // no `ak.realm.policy_server` replay arm at all, so a restart silently lost
    // every declaration.
    let restarted =
        soland_test_support::app_state_with_persistence(test_config(), persistence.clone()).await;
    restarted.hydrate().await.expect("restarted state hydrates");
    let restarted_token = dev_token(restarted.clone(), ALICE, ALICE_DEVICE, "Alice").await;

    let (status, view) = get_policy_server(&restarted, &restarted_token, org_realm).await;
    assert_eq!(status, StatusCode::OK, "restarted GET: {view}");
    assert_eq!(
        view["policy_server_service_id"],
        "ak:did_core:web:org-policy.example"
    );
    assert_eq!(view["from_organization_fallback"], false);

    let restored_policy_server_service_id = {
        let projection = restarted.test_projection().lock();
        projection
            .realm_null_subject_cells
            .get(&(org_realm.to_owned(), POLICY_CELL.to_owned()))
            .and_then(|cell| match cell {
                arkret_state::lattice::CellState::Value(value) => value
                    .get("policy_server_service_id")
                    .and_then(Value::as_str),
                arkret_state::lattice::CellState::Bottom(_) => None,
            })
            .map(ToOwned::to_owned)
    };
    assert_eq!(
        restored_policy_server_service_id.as_deref(),
        Some("ak:did_core:web:org-policy.example"),
        "the declaration cell must survive restart"
    );

    // A later settled tombstone is equally durable: after a second restart it
    // remains a direct absence and does not resurrect the declaration.
    // The lightweight hydration harness restores the durable projection but
    // deliberately does not reconstruct the accepted-Seal coordinator state
    // needed to author a new Control Move. Author the tombstone on the original
    // still-live node, then verify that a fresh node rehydrates that durable
    // tombstone instead of resurrecting the declaration.
    grant_policy_manage(&state, org_realm);
    let (status, deleted) = delete_policy_server(&state, &token, org_realm).await;
    assert_eq!(status, StatusCode::OK, "settled DELETE: {deleted}");
    let restarted_again =
        soland_test_support::app_state_with_persistence(test_config(), persistence).await;
    restarted_again
        .hydrate()
        .await
        .expect("tombstoned state hydrates");
    let token = dev_token(restarted_again.clone(), ALICE, ALICE_DEVICE, "Alice").await;
    let (status, view) = get_policy_server(&restarted_again, &token, org_realm).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "tombstone after restart: {view}"
    );
    let projection = restarted_again.test_projection().lock();
    assert_eq!(
        projection
            .realm_null_subject_cells
            .get(&(org_realm.to_owned(), POLICY_CELL.to_owned()))
            .and_then(|cell| match cell {
                arkret_state::lattice::CellState::Value(value) => {
                    value.get("tombstone").and_then(Value::as_bool)
                }
                arkret_state::lattice::CellState::Bottom(_) => None,
            }),
        Some(true),
        "the tombstone cell must survive restart"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_server_same_basis_sibling_fails_closed() {
    let persistence: Arc<dyn PersistenceStore> = Arc::new(SolandMemoryPersistenceStore::new());
    let state = soland_test_support::app_state_with_persistence(test_config(), persistence).await;
    let _control_seal_coordinator = soland_http::control_seal_coordinator::spawn(state.clone());
    let token = prepare_alice(&state).await;
    let child_realm = bootstrap_realm(&state, &token, "policy server sibling child").await;
    let child_realm = child_realm.as_str();

    let settled = declaration_body("first-policy.example");
    let (status, view) = put_policy_server(&state, &token, child_realm, &settled).await;
    assert_eq!(status, StatusCode::OK, "settle PUT: {view}");

    // Two Moves that cite the SAME frozen basis and write different values are
    // cas-register siblings. `policy-server.md` §2.2 forbids resolving them by
    // arrival order: they join to `⊥`, and every dependent read or write then
    // fails closed until a §9.5 conflict-recovery Move.
    let settled_basis = {
        let projection = state.test_projection().lock();
        projection
            .realm_null_subject_cells
            .get(&(child_realm.to_owned(), POLICY_CELL.to_owned()))
            .and_then(|cell| match cell {
                arkret_state::lattice::CellState::Value(value) => Some(value.clone()),
                arkret_state::lattice::CellState::Bottom(_) => None,
            })
            .expect("settled declaration")
    };
    let sibling_move = |payload: Value| {
        let preconditions = serde_json::from_value(json!([{
            "cell": POLICY_CELL,
            "predicate": {"op": "head_eq", "value": settled_basis.clone()},
        }]))
        .expect("typed policy-server precondition");
        let mut operation = arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
                .unwrap(),
            arkret_identifiers::RealmId::new(child_realm).unwrap(),
            arkret_wire::EventKind::RealmPolicyServer.as_str(),
            payload,
        );
        operation.context.preconditions = preconditions;
        operation
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
    let (status, body) = get_policy_server(&state, &token, child_realm).await;
    assert_eq!(status, StatusCode::CONFLICT, "GET after ⊥: {body}");
    assert_eq!(body["error"]["code"], "failed_bottom", "GET body: {body}");

    let (status, body) = put_policy_server(
        &state,
        &token,
        child_realm,
        &declaration_body("third-policy.example"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "PUT after ⊥: {body}");

    let (status, body) = delete_policy_server(&state, &token, child_realm).await;
    assert_eq!(status, StatusCode::CONFLICT, "DELETE after ⊥: {body}");
}

/// An unguarded write against a settled register is refused, and refusing is
/// the only thing left the service may do about the guard.
///
/// The precondition is inside the bytes the caller signs, so the service can no
/// longer read the settled value and attach a `head_eq` itself — that is the
/// substitution `key-management.md` §411 forbids. What it can still do is
/// require the guard to be there, which is what turns a concurrent overwrite
/// from "last writer silently wins the register" into a visible
/// `failed_precondition`.
#[tokio::test(flavor = "multi_thread")]
async fn policy_server_replace_without_head_eq_is_refused() {
    let persistence: Arc<dyn PersistenceStore> = Arc::new(SolandMemoryPersistenceStore::new());
    let state = soland_test_support::app_state_with_persistence(test_config(), persistence).await;
    let _control_seal_coordinator = soland_http::control_seal_coordinator::spawn(state.clone());
    let token = prepare_alice(&state).await;
    let realm = bootstrap_realm(&state, &token, "policy server unguarded write").await;
    let realm = realm.as_str();

    // An unguarded write is fine while the register is still empty: there is no
    // settled value for a guard to name.
    let (status, view) =
        put_policy_server(&state, &token, realm, &declaration_body("first.example")).await;
    assert_eq!(status, StatusCode::OK, "first PUT: {view}");

    let seal = accepted_seal_id(&state, &token, realm).await;
    let (actor_seq, prev_refs) = actor_frontier(&state, &token, realm).await;
    let unguarded = RealmPolicyServerReplaceRequestBody {
        policy_server_event: unguarded_policy_server_move(
            realm,
            declaration_body("second.example"),
            &seal,
        )
        .with_actor_seq(actor_seq)
        .with_prev_refs(prev_refs.iter().map(String::as_str).collect())
        .build_submission(),
    };
    let (status, body) = send_put_policy_server(&state, &token, realm, &unguarded).await;
    assert_eq!(
        status,
        StatusCode::PRECONDITION_FAILED,
        "unguarded replace of a settled register: {body}"
    );
    assert_eq!(body["error"]["code"], "failed_precondition", "body: {body}");

    // The refusal is total: the register still holds the first declaration and
    // the Event log did not grow.
    let (status, view) = get_policy_server(&state, &token, realm).await;
    assert_eq!(status, StatusCode::OK, "GET after refusal: {view}");
    assert_eq!(
        view["policy_server_service_id"],
        "ak:did_core:web:first.example"
    );
    assert_eq!(
        policy_server_events(&state, &token, realm).await.len(),
        1,
        "a refused write must not append to the Event log"
    );

    // The same Move with the guard the caller now owes is accepted.
    let (status, view) =
        put_policy_server(&state, &token, realm, &declaration_body("second.example")).await;
    assert_eq!(status, StatusCode::OK, "guarded replace: {view}");
    assert_eq!(
        view["policy_server_service_id"],
        "ak:did_core:web:second.example"
    );
}

/// `ak.self.events.read.resolve` returns the Seal covering each resolved Event.
///
/// `service-http-binding.md` (`ak.self.events.read.resolve`) makes `seals[]` a
/// closed derived set — for every returned Event, the accepted Seal whose
/// `delta[]` carries that Event's `event_digest` — not merely the answer to
/// `seal_refs[]`. A Realm creator bootstrapping its MLS governance anchor
/// (`encryption-and-audit.md` section 2.5.4 T1) resolves the `ak.realm.create`
/// it authored and cannot name the genesis Seal id in advance; while this
/// endpoint filled `seals[]` from `seal_refs[]` alone the creator got an empty
/// set, never pinned an anchor, and every encrypted write in the Realm failed.
#[tokio::test(flavor = "multi_thread")]
async fn events_resolve_returns_the_seal_covering_each_resolved_event() {
    let persistence: Arc<dyn PersistenceStore> = Arc::new(SolandMemoryPersistenceStore::new());
    let state = soland_test_support::app_state_with_persistence(test_config(), persistence).await;
    let _control_seal_coordinator = soland_http::control_seal_coordinator::spawn(state.clone());
    let token = prepare_alice(&state).await;
    let realm = bootstrap_realm(&state, &token, "events resolve derived seals").await;
    let create_event_id = RealmId::new(realm.clone()).unwrap().event_id();

    let resolved: Value = TestClient::query("http://server/_arkret/self/events/resolve")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_body(
            &json!({"event_ids": [create_event_id.to_string()]}),
        ))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();

    let events = resolved["events"]
        .as_array()
        .unwrap_or_else(|| panic!("events array: {resolved}"));
    assert_eq!(events.len(), 1, "resolve response: {resolved}");
    let create_digest = events[0]["proofs"][0]["event_digest"]
        .as_str()
        .expect("create Event carries its canonical digest");

    let seals = resolved["seals"].as_array().expect("seals array");
    assert_eq!(
        seals.len(),
        1,
        "the create Event's covering Seal must be derived without a seal_refs selector: {resolved}"
    );
    assert!(
        seals[0]["delta"]
            .as_array()
            .expect("Seal delta")
            .iter()
            .any(|entry| entry.as_str() == Some(create_digest)),
        "the returned Seal must be the one covering the create Event, not a descendant: {resolved}"
    );
    assert_eq!(
        seals[0]["id"].as_str(),
        Some(
            accepted_seal_frontier(&state, &token, &realm)
                .await
                .as_str()
        ),
        "a freshly bootstrapped Realm's covering Seal is its accepted frontier: {resolved}"
    );

    // An Event id that does not exist stays in `missing[]` and contributes no
    // Seal: the derived set never invents coverage for an unresolved selector.
    let unknown: Value = TestClient::query("http://server/_arkret/self/events/resolve")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_body(&json!({
            "event_ids": ["ak:event:Ac7-1lLzCCcEO_GkBXRnpMT7IfFyRdjN8kL8i9-ztQcg"]
        })))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(unknown["events"].as_array().unwrap().is_empty());
    assert!(
        unknown["seals"]
            .as_array()
            .map(|seals| seals.is_empty())
            .unwrap_or(true),
        "unresolved selectors contribute no Seal: {unknown}"
    );
}
