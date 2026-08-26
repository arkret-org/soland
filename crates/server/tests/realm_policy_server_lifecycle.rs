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
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use arkret_event_draft::EventPayloadExt as _;
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
    CallerSignedBasis, CallerSignedEvent, FIXTURE_EVENT_SIGNING_SEED,
    complete_realm_bootstrap_unit, head_eq_precondition,
};

const ALICE: &str = "did:web:alice.example";
const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-a11ce0000001";
const POLICY_CELL: &str = "ak:cell:ak.component.realm.policy_server.v1:null";
const TRUST_DOMAIN: &str = "ak:trust_domain:soland-policy-test.local";
static CONTROL_SEAL_LOAD_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
    let realm_id = submit_realm_bootstrap(state, token, title).await;
    // Admin Control Moves need an accepted Seal to cite; wait for the
    // coordinator to materialize the bootstrap Seal.
    accepted_seal_frontier(state, token, &realm_id).await;
    realm_id
}

/// Submit a complete Realm bootstrap without waiting for its first Seal. This
/// lets concurrency tests accumulate multiple durable pending Realms before
/// starting the coordinator.
async fn submit_realm_bootstrap(state: &AppState, token: &str, title: &str) -> String {
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
    let founder_actor_id = genesis.actor_id.clone();
    let mut bootstrap = complete_realm_bootstrap_unit(genesis, ALICE, ALICE_DEVICE, title);
    let prior_event_id = bootstrap
        .get(bootstrap.len().saturating_sub(2))
        .expect("bootstrap delivery policy precedes founder membership")
        .event_id
        .to_string();
    bootstrap
        .pop()
        .expect("replace unroutable founder membership");
    let recipient_service_id = arkret_identifiers::DidCoreId::new(state.service_id().to_owned())
        .expect("fixture Principal Server core id");
    let current_record_url = format!(
        "https://server.test{}",
        arkret_models_identity::canonical_service_current_record_path(&recipient_service_id)
    );
    bootstrap.push(
        CallerSignedEvent::new(
            arkret_wire::EventKind::MemberState.as_str(),
            ALICE,
            ALICE_DEVICE,
            &realm_id,
            json!({
                "realm_id": realm_id.as_str(),
                "actor_id": founder_actor_id.as_str(),
                "membership": "join",
                "delivery_status": "routable",
                "delivery_binding": {
                    "recipient_service_id": recipient_service_id,
                    "recipient_service_kind": "principal_server",
                    "binding_scope": "realm",
                    "binding_source": "explicit",
                    "delivery_modes": ["events"],
                    "service_resolution": {
                        "current_record_url": current_record_url
                    },
                    "service_acceptance_ref": prior_event_id,
                    "resolved_at": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                }
            }),
        )
        .with_actor_seq(7)
        .with_prev_refs(vec![prior_event_id.as_str()])
        .with_preconditions(vec![head_eq_precondition(
            &format!(
                "ak:cell:ak.component.member.state.v1:{}",
                founder_actor_id.as_str()
            ),
            Value::Null,
        )])
        .with_basis(CallerSignedBasis::AnchorUnit)
        .build(),
    );
    bootstrap
        .last()
        .expect("fixture founder membership")
        .typed_payload::<arkret_wire::event_spec::MemberState>()
        .expect("typed routable founder membership payload");
    arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit(&bootstrap)
        .expect("routable fixture ordinary Realm bootstrap unit");
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
    send_delete_policy_server(state, token, realm_id, &request).await
}

async fn send_delete_policy_server(
    state: &AppState,
    token: &str,
    realm_id: &str,
    request: &RealmPolicyServerDeleteRequestBody,
) -> (StatusCode, Value) {
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
    const MAX_ATTEMPTS: usize = 400;
    for attempt in 0..MAX_ATTEMPTS {
        let mut response = TestClient::query("http://server/_arkret/self/seals/frontier")
            .json(
                &arkret_models_collaboration::event_query::SealFrontierRequestBody {
                    realm_id: RealmId::new(realm_id.to_owned())
                        .expect("fixture Seal frontier Realm id"),
                },
            )
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await;
        let status = response.status_code;
        let body: Value = response.take_json().await.unwrap_or(Value::Null);
        if status == Some(StatusCode::OK) {
            let frontier: arkret_models_collaboration::event_sync::SealFrontierState =
                serde_json::from_value(body).expect("typed Realm Seal frontier");
            return frontier
                .frontier
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
            attempt + 1 < MAX_ATTEMPTS,
            "Realm Seal frontier remained unavailable: {body}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    unreachable!("bounded Realm Seal frontier retry returns or panics")
}

fn accepted_seal_frontier_covering<'a>(
    state: &'a AppState,
    token: &'a str,
    realm_id: &'a str,
    event_digest: &'a arkret_identifiers::Hash,
) -> Pin<Box<dyn Future<Output = String> + 'a>> {
    Box::pin(async move {
        const MAX_ATTEMPTS: usize = 400;
        for attempt in 0..MAX_ATTEMPTS {
            let frontier = accepted_seal_id(state, token, realm_id).await;
            let mut response = TestClient::query("http://server/_arkret/self/seals/resolve")
                .json(
                    &arkret_models_collaboration::http_bodies::SelfSealResolveRequestBody {
                        realm_id: RealmId::new(realm_id.to_owned())
                            .expect("fixture Seal resolve Realm id"),
                        seal_refs: vec![frontier.clone()],
                        history_traversal_access: None,
                    },
                )
                .add_header("authorization", format!("Bearer {token}"), true)
                .send(&app_from_state(state.clone()))
                .await;
            let status = response.status_code;
            let body: Value = response.take_json().await.unwrap_or(Value::Null);
            assert_eq!(status, Some(StatusCode::OK), "Seal resolve: {body}");
            let resolved: arkret_models_collaboration::http_bodies::SealResolveOutcome =
                serde_json::from_value(body).expect("typed Seal resolve outcome");
            if resolved.seals.iter().any(|seal| {
                seal.delta.contains(event_digest)
                    || seal.covered_event_digests.contains(event_digest)
            }) {
                return frontier.to_string();
            }
            assert!(
                attempt + 1 < MAX_ATTEMPTS,
                "Realm Seal frontier never covered Control Event digest {event_digest}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        unreachable!("bounded Realm Seal coverage retry returns or panics")
    })
}

fn accepted_control_event_digest<'a>(
    state: &'a AppState,
    token: &'a str,
    event_id: &'a str,
) -> Pin<Box<dyn Future<Output = arkret_identifiers::Hash> + 'a>> {
    Box::pin(async move {
        let mut response = TestClient::get(format!("http://server/_arkret/self/events/{event_id}"))
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let body: Value = response
            .take_json()
            .await
            .expect("accepted Control Event read");
        let event: arkret_wire::Event = serde_json::from_value(body["event"].clone())
            .expect("stored accepted Control Event envelope");
        arkret_state::state::control_event_digest(&event, arkret_canonical::DigestSuite::Sha256)
            .expect("accepted Control Event digest")
    })
}

async fn actor_frontier(state: &AppState, token: &str, realm_id: &str) -> (u64, Vec<String>) {
    let actor_core = arkret_wire::project_full_id_to_core_id(
        &DidFullId::new(ALICE.to_owned()).expect("fixture frontier actor full DID"),
    )
    .expect("fixture frontier actor core DID");
    let frontier_value: Value = TestClient::query("http://server/_arkret/self/events/frontier")
        .json(
            &arkret_models_collaboration::event_query::EventsFrontierRequestBody {
                actor_id: actor_core,
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
    let frontier: arkret_models_collaboration::event_sync::EventsFrontierState =
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
async fn control_seal_coordinator_drains_multiple_bounded_concurrency_waves() {
    let _load_test_guard = CONTROL_SEAL_LOAD_TEST_LOCK.lock().await;
    const REALM_COUNT: usize = 32;

    let persistence: Arc<dyn PersistenceStore> = Arc::new(SolandMemoryPersistenceStore::new());
    let state = soland_test_support::app_state_with_persistence(test_config(), persistence).await;
    let token = prepare_alice(&state).await;
    let mut realms = Vec::with_capacity(REALM_COUNT);
    for index in 0..REALM_COUNT {
        realms.push(
            submit_realm_bootstrap(
                &state,
                &token,
                &format!("bounded control-seal Realm {index}"),
            )
            .await,
        );
    }
    for realm_id in &realms {
        let response = TestClient::query("http://server/_arkret/self/seals/frontier")
            .json(
                &arkret_models_collaboration::event_query::SealFrontierRequestBody {
                    realm_id: RealmId::new(realm_id.clone()).expect("fixture pending Realm id"),
                },
            )
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await;
        assert_eq!(
            response.status_code,
            Some(StatusCode::SERVICE_UNAVAILABLE),
            "every Realm must remain pending before the coordinator starts"
        );
    }

    let control_seal_coordinator = soland_http::control_seal_coordinator::spawn(state.clone());
    for realm_id in &realms {
        accepted_seal_frontier(&state, &token, realm_id).await;
    }
    assert!(
        !control_seal_coordinator.is_finished(),
        "the coordinator must survive every bounded concurrency wave"
    );
    control_seal_coordinator.abort();
}

async fn postgres_release_state() -> AppState {
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL is required for the Control Seal release gate");
    let db = soland_storage_postgres::Db::connect(
        Some(database_url.as_str()),
        soland_storage_postgres::PoolTuning::default(),
    )
    .await
    .expect("connect release-gate PostgreSQL");
    let pool = db.pool.clone().expect("release gate requires PostgreSQL");
    let persistence_store: Arc<dyn PersistenceStore> =
        Arc::new(soland_storage_postgres::PgPersistenceStore::new(pool));
    let persistence =
        soland_services::persistence::PersistenceHandle::from_shared(persistence_store.clone());
    let config = test_config();
    let identity = soland_test_support::fixture_service_identity(&config);
    let signing_seed = soland_test_support::fixture_signing_seed(&config, &identity);
    let fixture_identity = identity.identity().expect("fixture serving identity");
    let resolution_commitment = arkret_models_identity::ResolutionCommitment {
        full_id: fixture_identity.full_id.clone(),
        method_history_head: format!("sha256:{}", "0".repeat(64)),
        version_id: "fixture-v1".to_owned(),
    };
    let state = soland::runtime::build_app_state(
        config,
        db,
        persistence,
        identity,
        resolution_commitment,
        signing_seed,
    )
    .expect("build PostgreSQL release-gate AppState");
    soland_test_support::register_persistence(&state, persistence_store);
    state
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "release-quality gate: requires a disposable PostgreSQL DATABASE_URL"]
async fn control_seal_postgres_release_drains_1025_realms_with_bounded_claims() {
    assert_eq!(
        std::env::var("SOLAND_CONTROL_SEAL_RELEASE_GATE").as_deref(),
        Ok("1"),
        "set SOLAND_CONTROL_SEAL_RELEASE_GATE=1 only with a disposable release-gate database"
    );
    const REALM_COUNT: usize = 1_025;
    const MAX_IN_FLIGHT: usize = 16;

    let state = postgres_release_state().await;
    let token = prepare_alice(&state).await;
    let mut realms = Vec::with_capacity(REALM_COUNT);
    for index in 0..REALM_COUNT {
        realms.push(
            submit_realm_bootstrap(
                &state,
                &token,
                &format!("PostgreSQL Control Seal release Realm {index}"),
            )
            .await,
        );
    }

    let sampling_done = Arc::new(AtomicBool::new(false));
    let max_claimed = Arc::new(AtomicUsize::new(0));
    let sampler = {
        let state = state.clone();
        let sampling_done = sampling_done.clone();
        let max_claimed = max_claimed.clone();
        tokio::spawn(async move {
            while !sampling_done.load(Ordering::Relaxed) {
                let sample_state = state.clone();
                let stats = tokio::task::spawn_blocking(move || {
                    sample_state
                        .test_projections()
                        .control_seal_schedule_stats(Utc::now().timestamp_millis())
                })
                .await
                .expect("schedule sampler task")
                .expect("schedule sampler store");
                max_claimed.fetch_max(stats.claimed, Ordering::Relaxed);
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
    };

    let control_seal_coordinator = soland_http::control_seal_coordinator::spawn(state.clone());
    for realm_id in &realms {
        accepted_seal_frontier(&state, &token, realm_id).await;
    }
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let sample_state = state.clone();
            let stats = tokio::task::spawn_blocking(move || {
                sample_state
                    .test_projections()
                    .control_seal_schedule_stats(Utc::now().timestamp_millis())
            })
            .await
            .expect("final schedule sampler task")
            .expect("final schedule sampler store");
            if stats.pending == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("all release-gate schedules must drain");
    sampling_done.store(true, Ordering::Relaxed);
    sampler.await.expect("schedule sampler");

    let observed_max = max_claimed.load(Ordering::Relaxed);
    assert!(observed_max > 0, "the sampler must observe active claims");
    assert!(
        observed_max <= MAX_IN_FLIGHT,
        "claim high-water {observed_max} exceeded the {MAX_IN_FLIGHT}-slot execution bound"
    );
    assert!(!control_seal_coordinator.is_finished());
    control_seal_coordinator.abort();
}

#[test]
fn policy_server_declaration_is_sealed_and_resolves_org_fallback() {
    // Workspace feature unification makes this broad async state machine large
    // enough to overflow Rust's default Windows test-thread stack when sibling
    // tests execute concurrently. Give this test-only executor an explicit
    // bounded stack; production runtime configuration remains untouched.
    std::thread::Builder::new()
        .name("policy-server-lifecycle".to_owned())
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(16 * 1024 * 1024)
                .build()
                .expect("policy-server lifecycle runtime")
                .block_on(policy_server_declaration_is_sealed_and_resolves_org_fallback_scenario());
        })
        .expect("spawn policy-server lifecycle test thread")
        .join()
        .expect("policy-server lifecycle test thread panicked");
}

async fn policy_server_declaration_is_sealed_and_resolves_org_fallback_scenario() {
    let _load_test_guard = CONTROL_SEAL_LOAD_TEST_LOCK.lock().await;
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
    let declared_event_id = declared[0]["event_id"].as_str().expect("declared Event id");
    let declared_digest = Box::pin(accepted_control_event_digest(
        &state,
        &token,
        declared_event_id,
    ))
    .await;

    // The self-management handler runs a local notary signing pass, so the
    // accepted Seal frontier advances: the Move is Seal-covered, not merely
    // projected.
    let seal_after_put = Box::pin(accepted_seal_frontier_covering(
        &state,
        &token,
        org_realm,
        &declared_digest,
    ))
    .await;
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
    // A Seal frontier may still advance for other already-pending governance
    // work. The protocol-level no-op invariant is the exact Event history
    // assertion above, not equality of two asynchronously observed leaves.

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
    let child_declaration_events = policy_server_events(&state, &token, child_realm).await;
    let child_declaration_id = child_declaration_events[0]["event_id"]
        .as_str()
        .expect("child declaration Event id");
    let child_declaration_digest = Box::pin(accepted_control_event_digest(
        &state,
        &token,
        child_declaration_id,
    ))
    .await;
    Box::pin(accepted_seal_frontier_covering(
        &state,
        &token,
        child_realm,
        &child_declaration_digest,
    ))
    .await;
    let (status, deleted) = delete_policy_server(&state, &token, child_realm).await;
    assert_eq!(status, StatusCode::OK, "settled child DELETE: {deleted}");
    let child_events = policy_server_events(&state, &token, child_realm).await;
    assert_eq!(child_events.len(), 2, "declaration plus tombstone");
    assert_eq!(child_events[1]["payload"]["tombstone"], true);
    let tombstone_event_id = child_events[1]["event_id"]
        .as_str()
        .expect("child tombstone Event id");
    let tombstone_digest = Box::pin(accepted_control_event_digest(
        &state,
        &token,
        tombstone_event_id,
    ))
    .await;
    Box::pin(accepted_seal_frontier_covering(
        &state,
        &token,
        child_realm,
        &tombstone_digest,
    ))
    .await;
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
    let control_seal_coordinator = soland_http::control_seal_coordinator::spawn(state.clone());
    let token = prepare_alice(&state).await;
    let child_realm = bootstrap_realm(&state, &token, "policy server sibling child").await;
    let child_realm = child_realm.as_str();

    let settled = declaration_body("first-policy.example");
    let (status, view) = put_policy_server(&state, &token, child_realm, &settled).await;
    assert_eq!(status, StatusCode::OK, "settle PUT: {view}");
    let settled_events = policy_server_events(&state, &token, child_realm).await;
    let settled_event_id = settled_events[0]["event_id"]
        .as_str()
        .expect("settled policy-server Event id");
    let settled_digest = Box::pin(accepted_control_event_digest(
        &state,
        &token,
        settled_event_id,
    ))
    .await;
    Box::pin(accepted_seal_frontier_covering(
        &state,
        &token,
        child_realm,
        &settled_digest,
    ))
    .await;
    // Build the writes while the register is still settled. Their signed
    // head_eq guards must name that last settled value, not the synthetic
    // Bottom state introduced below.
    let blocked_seal = accepted_seal_id(&state, &token, child_realm).await;
    let (blocked_actor_seq, blocked_prev_refs) = actor_frontier(&state, &token, child_realm).await;
    let blocked_put = RealmPolicyServerReplaceRequestBody {
        policy_server_event: policy_server_move(
            &state,
            child_realm,
            declaration_body("third-policy.example"),
            &blocked_seal,
            blocked_actor_seq,
            blocked_prev_refs.iter().map(String::as_str).collect(),
        ),
    };
    let blocked_delete = RealmPolicyServerDeleteRequestBody {
        policy_server_event: policy_server_move(
            &state,
            child_realm,
            json!({"tombstone": true}),
            &blocked_seal,
            blocked_actor_seq,
            blocked_prev_refs.iter().map(String::as_str).collect(),
        ),
    };
    let app = app_from_state(state.clone());
    // The remainder injects an artificial same-basis sibling directly into
    // the reducer to exercise Bottom semantics. Stop the asynchronous local
    // notary first so it cannot concurrently replay the already-accepted
    // declaration over that synthetic test-only projection state.
    control_seal_coordinator.abort();
    let _ = control_seal_coordinator.await;

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
    let bottom_projection = state.test_projection().lock().clone();

    // Every dependent read and write now fails closed with the canonical
    // `failed_bottom` wire code.
    let mut response = TestClient::get(format!(
        "http://server/_arkret/self/realms/{child_realm}/policy-server"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app)
    .await;
    let status = response.status_code.expect("GET status");
    let body = response.take_json().await.unwrap_or(Value::Null);
    assert_eq!(status, StatusCode::CONFLICT, "GET after ⊥: {body}");
    assert_eq!(body["error"]["code"], "failed_bottom", "GET body: {body}");

    // The conflict above exists only in this in-memory projection; it is not
    // in the durable Event log. Restore that exact synthetic snapshot before
    // each independent HTTP assertion because request teardown may reconcile
    // the shared projection from durable state.
    *state.test_projection().lock() = bottom_projection.clone();
    let mut response = TestClient::put(format!(
        "http://server/_arkret/self/realms/{child_realm}/policy-server"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .add_header("content-type", "application/json", true)
    .body(canonical_body(&blocked_put))
    .send(&app)
    .await;
    let status = response.status_code.expect("PUT status");
    let body = response.take_json().await.unwrap_or(Value::Null);
    assert_eq!(status, StatusCode::CONFLICT, "PUT after ⊥: {body}");

    *state.test_projection().lock() = bottom_projection;
    let mut response = TestClient::delete(format!(
        "http://server/_arkret/self/realms/{child_realm}/policy-server"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .add_header("content-type", "application/json", true)
    .body(canonical_body(&blocked_delete))
    .send(&app)
    .await;
    let status = response.status_code.expect("DELETE status");
    let body = response.take_json().await.unwrap_or(Value::Null);
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

/// Event and Seal discovery remain separate closed surfaces.
///
/// `service-http-binding.md` makes `ak.self.events.read.resolve` return Event
/// bytes only. A caller discovers the current Seal leaf independently, then
/// resolves that exact leaf through `ak.self.seals.read.resolve` and verifies
/// its `delta[]` against the Event digest.
#[tokio::test(flavor = "multi_thread")]
async fn events_resolve_excludes_seals_and_seal_resolve_returns_exact_leaf() {
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

    assert!(
        resolved.get("seals").is_none(),
        "Event resolve must not attach a covering or activation Seal: {resolved}"
    );
    let seal_ref = accepted_seal_frontier(&state, &token, &realm).await;
    let mut seal_response = TestClient::query("http://server/_arkret/self/seals/resolve")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_body(&json!({
            "realm_id": realm,
            "seal_refs": [seal_ref]
        })))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        seal_response.status_code,
        Some(StatusCode::OK),
        "Seal resolve status"
    );
    let seal_resolved: Value = seal_response.take_json().await.unwrap();
    let seals = seal_resolved["seals"].as_array().expect("seals array");
    assert_eq!(
        seals.len(),
        1,
        "the exact current Seal leaf must resolve independently: {seal_resolved}"
    );
    assert!(
        seals[0]["delta"]
            .as_array()
            .expect("Seal delta")
            .iter()
            .any(|entry| entry.as_str() == Some(create_digest)),
        "the resolved current Seal must cover the create Event: {seal_resolved}"
    );

    // An Event id that does not exist stays in `missing[]`; Event resolve still
    // cannot expose any Seal material.
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
    assert!(unknown.get("seals").is_none());
}
