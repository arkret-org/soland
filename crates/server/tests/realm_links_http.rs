//! G3.S5 — integration tests for Realm Link Event admission and reads:
//!
//! - `POST /_arkret/self/events` — create, status-flip, or tombstone an `ak.realm.link`.
//! - `GET /_arkret/self/realms/{realm_id}/effective-policy` — read the merged effective policy
//!   (walks the inheritance chain).
//! - General directed cycles are accepted; self-links and illegal transition transitions are
//!   rejected.

use arkret_identifiers::{RealmId, SealId};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use soland_http::config::AppConfig;
use soland_http::service;
use soland_http::state::AppState;
use soland_test_support::AppStateTestExt as _;
use soland_test_support::signed_event::{
    CallerSignedEvent, FIXTURE_EVENT_SIGNING_SEED, complete_realm_bootstrap_unit,
};

const ALICE: &str = "did:web:alice.example";
const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-a11ce0000001";
const TRUST_DOMAIN: &str = "ak:trust_domain:soland-links-test.local";

fn test_config() -> AppConfig {
    AppConfig {
        development_mode: true,
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: std::collections::BTreeMap::new(),
        trust_domain: arkret_identifiers::TrustDomainId::new(TRUST_DOMAIN).unwrap(),
        ..soland_test_support::app_config()
    }
}

fn app_from_state(state: &AppState) -> salvo::Service {
    service(state.clone())
}

/// A session plus the device key the submitted Events are signed with.
///
/// The Move is admitted on the caller's own signature now, so the device
/// directory has to authorize the key the envelope names; without this the
/// Events fail the device proof rather than anything the test is about.
async fn prepare_alice(state: &AppState) -> String {
    let alice_core =
        arkret_wire::project_did_to_core_id(&arkret_identifiers::Did::new(ALICE).unwrap()).unwrap();
    let login: Value = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&json!({
            "actor": alice_core,
            "device_id": ALICE_DEVICE,
            "display_name": "Alice Desktop"
        }))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    let token = login["session_credential"].as_str().unwrap().to_owned();
    let signing = SigningKey::from_bytes(&FIXTURE_EVENT_SIGNING_SEED);
    soland_test_support::project_authorized_principal_device(state, ALICE, ALICE_DEVICE, &signing)
        .await;
    token
}

fn alice_core_id() -> String {
    arkret_wire::project_did_to_core_id(&arkret_identifiers::Did::new(ALICE).unwrap())
        .unwrap()
        .to_string()
}

/// Bootstrap a Realm through the real `ak.realm.create` genesis batch, with this
/// deployment as its frozen `f=0` quorum notary, and grant the caller `ak.realm.link`.
///
/// The Realm id is derived from the genesis Event (`realm-and-space.md` section
/// 2.5.0), so it is read back off the Event rather than chosen here.
async fn bootstrap_realm(state: &AppState, token: &str, title: &str) -> String {
    let genesis = CallerSignedEvent::realm_genesis(
        ALICE,
        ALICE_DEVICE,
        soland_test_support::cbs_basis::realm_genesis_payload(
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
    let mut created = TestClient::post("http://server/_arkret/self/events")
        .add_header("Arkret-Operation", "ak.self.events.command.submit.v1", true)
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "events": bootstrap
                .into_iter()
                .map(arkret_wire::EventInitialSubmission::online)
                .collect::<Vec<_>>()
        }))
        .send(&app_from_state(state))
        .await;
    if created.status_code != Some(StatusCode::OK) {
        let error: Value = created.take_json().await.unwrap_or(Value::Null);
        panic!(
            "Realm create failed with {:?}: {error}",
            created.status_code
        );
    }
    // Realm genesis grants nothing beyond the authority root, so the explicit
    // `ak.realm.link` grant the admission gate requires is registered here.
    let alice_core = alice_core_id();
    soland_http::authz::install_projected_grant(
        state.test_authz(),
        realm_id.clone(),
        alice_core.clone(),
        alice_core,
        realm_id.clone(),
        vec![arkret_wire::CapabilityActionId::REALM_LINK.to_owned()],
        Vec::new(),
    );
    accepted_seal_id(state, token, &realm_id).await;
    realm_id
}

/// The accepted Seal a Control Move of `realm_id` cites in `seal_basis`.
async fn accepted_seal_id(state: &AppState, token: &str, realm_id: &str) -> SealId {
    // An accepted Event may still be ahead of the coordinator's signed head.
    // Sequential transition writes must cite a Seal covering the prior write, not
    // merely any existing Seal returned while a successor is pending.
    let required_link_digests = state
        .test_persistence()
        .events()
        .realm_events_newest_first(realm_id)
        .await
        .expect("accepted Realm Link history")
        .into_iter()
        .filter(|record| record.kind == arkret_wire::EventKind::RealmLink.as_str())
        .map(|record| arkret_wire::Hash::new(record.canonical_digest).unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    for attempt in 0..50 {
        let mut response = TestClient::query("http://server/_arkret/self/seals/frontier")
            .add_header("Arkret-Operation", "retired-seal-frontier", true)
            .json(&serde_json::json!({"realm_id": realm_id}))
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state))
            .await;
        let status = response.status_code;
        let body: Value = response.take_json().await.unwrap_or(Value::Null);
        if status == Some(StatusCode::OK) {
            let frontier: arkret_models_collaboration::event_sync::SealFrontierState =
                serde_json::from_value(body).expect("typed Realm Seal frontier");
            let leaf = frontier
                .frontier
                .sole_leaf()
                .expect("f=0 Realm frontier")
                .clone();
            if seal_covers_link_history(state, &leaf, &required_link_digests).await {
                return leaf;
            }
            assert!(
                attempt < 49,
                "Realm Seal {leaf} never covered accepted Realm Links: {required_link_digests:?}"
            );
        } else {
            let diagnostics = if status != Some(StatusCode::SERVICE_UNAVAILABLE) {
                realm_link_diagnostics(state, realm_id).await
            } else {
                Value::Null
            };
            assert_eq!(
                status,
                Some(StatusCode::SERVICE_UNAVAILABLE),
                "Realm Seal frontier failed with {status:?}: {body}; history: {diagnostics}"
            );
            assert!(
                attempt < 49,
                "Realm Seal frontier remained unavailable: {body}"
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    unreachable!("bounded Realm Seal frontier retry returns or panics")
}

async fn realm_link_diagnostics(state: &AppState, realm_id: &str) -> Value {
    let realm_id = RealmId::new(realm_id).unwrap();
    let history = state
        .test_persistence()
        .events()
        .realm_events_newest_first(realm_id.as_str())
        .await
        .expect("read Realm Link failure history")
        .into_iter()
        .filter(|record| record.kind == arkret_wire::EventKind::RealmLink.as_str())
        .map(|record| {
            json!({
                "event_id": record.event_id,
                "digest": record.canonical_digest,
                "actor_seq": record.actor_seq,
                "received_at": record.received_at,
                "payload": record.envelope["payload"],
                "seal_basis": record.envelope["seal_basis"],
                "prev_refs": record.envelope["prev_refs"],
            })
        })
        .collect::<Vec<_>>();
    let cells = state
        .test_projections()
        .realm_cells(&realm_id)
        .await
        .unwrap()
        .into_iter()
        .filter(|cell| {
            cell.as_str()
                .starts_with("ak:cell:ak.component.realm.link.v1:")
        })
        .collect::<Vec<_>>();
    let mut batches = Vec::with_capacity(cells.len());
    for cell in cells {
        let cell_batches = state
            .test_projections()
            .confirmed_write_batches_for_cell(&realm_id, &cell)
            .await
            .unwrap();
        batches.push(json!({"cell": cell, "batches": format!("{cell_batches:?}")}));
    }
    json!({"events_newest_first": history, "persisted_batches": batches})
}

async fn seal_covers_link_history(
    state: &AppState,
    leaf: &SealId,
    required: &std::collections::BTreeSet<arkret_wire::Hash>,
) -> bool {
    let mut pending = vec![leaf.clone()];
    let mut visited = std::collections::BTreeSet::new();
    let mut covered = std::collections::BTreeSet::new();
    while let Some(seal_id) = pending.pop() {
        if !visited.insert(seal_id.clone()) {
            continue;
        }
        let seal = state
            .test_seal(&seal_id)
            .await
            .expect("read accepted Seal")
            .expect("frontier and predecessor Seals are durably available");
        covered.extend(seal.delta);
        pending.extend(seal.predecessor_ref);
    }
    required.is_subset(&covered)
}

/// The next position on the caller's Realm-scoped actor chain.
async fn actor_frontier(state: &AppState, token: &str, realm_id: &str) -> (u64, Vec<String>) {
    let request = serde_json::json!({
        "actor_id": arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(alice_core_id()).unwrap(),
            state.service_core_id(),
        )),
        "realm_id": realm_id
    });
    let frontier: arkret_models_collaboration::event_sync::EventsFrontierState =
        TestClient::query("http://server/_arkret/self/events/frontier")
            .add_header("Arkret-Operation", "retired-event-frontier", true)
            .add_header("content-type", "application/json", true)
            .body(arkret_canonical::canonical_json_bytes(&request).unwrap())
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state))
            .await
            .take_json()
            .await
            .expect("typed actor Realm frontier");
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

/// The caller-signed `ak.realm.link` Move naming one edge.
async fn link_move(
    state: &AppState,
    token: &str,
    realm_id: &str,
    target: &str,
    status: &str,
) -> arkret_wire::EventInitialSubmission {
    let seal = accepted_seal_id(state, token, realm_id).await;
    let (actor_seq, prev_refs) = actor_frontier(state, token, realm_id).await;
    CallerSignedEvent::new(
        arkret_wire::EventKind::RealmLink.as_str(),
        ALICE,
        ALICE_DEVICE,
        realm_id,
        json!({
            "target_realm_id": target,
            "link_kind": "governed_by",
            "status": status,
        }),
    )
    .with_actor_seq(actor_seq)
    .with_prev_refs(prev_refs.iter().map(String::as_str).collect())
    .with_accepted_seal_basis(seal)
    .build_submission()
}

async fn submit_link(
    state: &AppState,
    token: &str,
    realm_id: &str,
    target: &str,
    status: &str,
) -> salvo::http::Response {
    let submission = link_move(state, token, realm_id, target, status).await;
    TestClient::post("http://server/_arkret/self/events")
        .add_header("Arkret-Operation", "ak.self.events.command.submit.v1", true)
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(
            arkret_canonical::canonical_json_bytes(&submission)
                .expect("canonical Realm Link submission"),
        )
        .send(&app_from_state(state))
        .await
}

async fn effective_policy(state: &AppState, token: &str, realm_id: &str) -> Value {
    TestClient::get(format!(
        "http://server/_arkret/self/realms/{realm_id}/effective-policy"
    ))
    .add_header(
        "Arkret-Operation",
        "ak.self.realm_link.read.effective_policy.v1",
        true,
    )
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state))
    .await
    .take_json()
    .await
    .unwrap()
}

fn allowed_policies(effective: &Value) -> Vec<String> {
    effective["effective_policy"]["allowed_policies"]
        .as_array()
        .expect("effective_policy.allowed_policies array")
        .iter()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect()
}

/// Submit a `ak.realm.inheritance_policy` event directly through the
/// reducer (the dedicated HTTP route is the standard `/_arkret/self/events`
/// envelope path; for setup we bypass it by injecting an Operation
/// into the projection).
fn project_inheritance_policy(
    state: &AppState,
    realm_id: &str,
    source_realm_id: &str,
    allowed_policies: &[&str],
) {
    use arkret_identifiers::OperationId;
    let op = arkret_event_draft::test_support::raw_projected_operation(
        OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7())).unwrap(),
        RealmId::new(realm_id).unwrap(),
        arkret_wire::EventKind::RealmInheritancePolicy.as_str(),
        json!({
            "source_realm_id": source_realm_id,
            "allowed_policies": allowed_policies,
            "max_depth": 1,
        }),
    );
    let mut proj = state.test_projection().lock();
    proj.apply(&op, state.test_hlc());
}

/// G3.S5 — happy path: submit a `governed_by` link from B → A, GET the
/// effective policy on B (after an explicit `ak.realm.inheritance_policy`
/// opt-in) and assert the chain walked back to A.
#[tokio::test(flavor = "multi_thread")]
async fn realm_link_event_then_effective_policy_walks_chain() {
    let state = soland_test_support::app_state(test_config());
    let _control_seal_coordinator = soland_http::control_seal_coordinator::spawn(state.clone());
    let token = prepare_alice(&state).await;
    let realm_a = bootstrap_realm(&state, &token, "links chain parent").await;
    let realm_b = bootstrap_realm(&state, &token, "links chain child").await;

    // 1. Submit B → A (`governed_by`, active) through ordinary Event admission.
    let mut response = submit_link(&state, &token, &realm_b, &realm_a, "active").await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["status"], "accepted");

    // 2. Explicit inheritance opt-in on B (spec §6.1 — a link alone doesn't enable inheritance).
    project_inheritance_policy(&state, &realm_b, &realm_a, &["b.policy"]);
    project_inheritance_policy(&state, &realm_a, &realm_a, &["a.policy"]);

    // 3. GET effective-policy on B. Body shape pinned by the task spec: `{realm_id,
    //    effective_policy, inheritance_chain_ids, inheritance_mode}`.
    let ep = effective_policy(&state, &token, &realm_b).await;
    assert_eq!(ep["realm_id"], realm_b);
    assert_eq!(ep["inheritance_mode"], "explicit");
    let chain = ep["inheritance_chain_ids"]
        .as_array()
        .expect("inheritance_chain_ids array");
    assert!(
        chain.iter().any(|v| v.as_str() == Some(realm_a.as_str())),
        "inheritance_chain_ids MUST include realm A (declared parent), got {chain:?}"
    );
    // B's own declared `b.policy` is in the merged set. A's `a.policy`
    // is also included because the walk reaches A via the governed_by
    // edge AND A has its own inheritance_policy declaration.
    let allowed = allowed_policies(&ep);
    assert!(
        allowed.iter().any(|policy| policy == "b.policy"),
        "expected b.policy in merged set: {allowed:?}"
    );
    assert!(
        allowed.iter().any(|policy| policy == "a.policy"),
        "expected a.policy (walked from parent): {allowed:?}"
    );
}

/// Realm Link is a general graph: a directed triangle is valid.
#[tokio::test(flavor = "multi_thread")]
async fn realm_link_events_allow_general_directed_cycle() {
    let state = soland_test_support::app_state(test_config());
    let _control_seal_coordinator = soland_http::control_seal_coordinator::spawn(state.clone());
    let token = prepare_alice(&state).await;
    let realm_a = bootstrap_realm(&state, &token, "links cycle a").await;
    let realm_b = bootstrap_realm(&state, &token, "links cycle b").await;
    let realm_c = bootstrap_realm(&state, &token, "links cycle c").await;

    // A → B, B → C, then C → A closes A→B→C→A and remains valid.
    for (source, target) in [
        (&realm_a, &realm_b),
        (&realm_b, &realm_c),
        (&realm_c, &realm_a),
    ] {
        let mut response = submit_link(&state, &token, source, target, "active").await;
        let status = response.status_code;
        let body: Value = response.take_json().await.unwrap_or(Value::Null);
        assert_eq!(status, Some(StatusCode::OK), "{source} -> {target}: {body}");
    }
}

/// G3.S5 — tombstone a link, verify the effective policy recomputes
/// (the tombstoned edge is treated as severed, so it no longer
/// contributes to the inheritance walk).
#[tokio::test(flavor = "multi_thread")]
async fn realm_link_tombstone_recomputes_effective_policy() {
    let state = soland_test_support::app_state(test_config());
    let _control_seal_coordinator = soland_http::control_seal_coordinator::spawn(state.clone());
    let token = prepare_alice(&state).await;
    let realm_b = bootstrap_realm(&state, &token, "links delete grandparent").await;
    let realm_c = bootstrap_realm(&state, &token, "links delete parent").await;
    let realm_d = bootstrap_realm(&state, &token, "links delete child").await;

    // Build D → C → B chain via Event submissions, opt-in inheritance at each level.
    for (source, target) in [(&realm_d, &realm_c), (&realm_c, &realm_b)] {
        let mut response = submit_link(&state, &token, source, target, "active").await;
        let status = response.status_code;
        let body: Value = response.take_json().await.unwrap_or(Value::Null);
        assert_eq!(status, Some(StatusCode::OK), "{source} -> {target}: {body}");
    }
    project_inheritance_policy(&state, &realm_d, &realm_c, &["d.policy"]);
    project_inheritance_policy(&state, &realm_c, &realm_b, &["c.policy"]);
    project_inheritance_policy(&state, &realm_b, &realm_b, &["b.policy"]);

    // Effective policy on D includes c.policy + b.policy via the walk.
    let allowed1 = allowed_policies(&effective_policy(&state, &token, &realm_d).await);
    assert!(allowed1.iter().any(|policy| policy == "d.policy"));
    assert!(allowed1.iter().any(|policy| policy == "c.policy"));
    assert!(
        allowed1.iter().any(|policy| policy == "b.policy"),
        "2-level walk MUST surface grandparent's allowed_policies: {allowed1:?}"
    );

    // Tombstone D → C. Severs the chain at the first edge — D's chain
    // walk now stops at C (still declared in D's inheritance_policy)
    // but cannot transit further because the governed_by edge is
    // tombstoned. C's own `c.policy` still surfaces because D's
    // inheritance_policy explicitly names C as the parent; B drops out.
    let mut deleted = submit_link(&state, &token, &realm_d, &realm_c, "tombstoned").await;
    let delete_status = deleted.status_code;
    let delete_body: Value = deleted.take_json().await.unwrap_or(Value::Null);
    assert_eq!(
        delete_status,
        Some(StatusCode::OK),
        "tombstone: {delete_body}"
    );
    assert_eq!(delete_body["status"], "accepted");

    let settled_seal = accepted_seal_id(&state, &token, &realm_d).await;
    assert_link_moves_are_sealed_once(&state, &realm_d, &settled_seal).await;

    let allowed2 = allowed_policies(&effective_policy(&state, &token, &realm_d).await);
    assert!(
        !allowed2.iter().any(|policy| policy == "b.policy"),
        "after tombstoning D→C, the transitive walk to B must be cut: {allowed2:?}"
    );

    // Tombstoned is terminal. A later attempt to reactivate the same cell
    // fails with the canonical transition reason. `error-code-registry.json` maps
    // `failed_precondition` to HTTP 409, and `realm_link_invalid_transition`
    // is a `state_resolution` reason carried under it -- 422 is not the
    // status any part of the registry gives this rejection.
    let mut reactivate = submit_link(&state, &token, &realm_d, &realm_c, "active").await;
    assert_eq!(reactivate.status_code, Some(StatusCode::CONFLICT));
    let body: Value = reactivate
        .take_json()
        .await
        .expect("error envelope is JSON");
    assert_eq!(
        body["type"],
        "https://arkret.org/problems/failed_precondition"
    );
    assert_eq!(body["reason_code"], "realm_link_invalid_transition");
}

async fn assert_link_moves_are_sealed_once(state: &AppState, realm_id: &str, leaf: &SealId) {
    let realm_id = RealmId::new(realm_id).unwrap();
    let accepted_links = state
        .test_persistence()
        .events()
        .realm_events_newest_first(realm_id.as_str())
        .await
        .unwrap()
        .into_iter()
        .filter(|record| record.kind == arkret_wire::EventKind::RealmLink.as_str())
        .map(|record| arkret_wire::Hash::new(record.canonical_digest).unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        accepted_links.len(),
        2,
        "active and tombstone were accepted"
    );

    let pending = state
        .test_projections()
        .pending_control_units_for_notary(&realm_id, None, 100)
        .await
        .unwrap();
    for unit in pending {
        for member in unit.members {
            let digest =
                arkret_state::state::control_event_digest(&member.event, member.digest_suite)
                    .unwrap();
            assert!(
                !accepted_links.contains(&digest),
                "a covered Realm Link Move must not remain pending: {digest}"
            );
        }
    }

    let mut seals = vec![leaf.clone()];
    let mut visited = std::collections::BTreeSet::new();
    let mut counts = std::collections::BTreeMap::<arkret_wire::Hash, usize>::new();
    while let Some(seal_id) = seals.pop() {
        if !visited.insert(seal_id.clone()) {
            continue;
        }
        let seal = state.test_seal(&seal_id).await.unwrap().unwrap();
        for digest in seal.delta {
            if accepted_links.contains(&digest) {
                *counts.entry(digest).or_default() += 1;
            }
        }
        seals.extend(seal.predecessor_ref);
    }
    for digest in accepted_links {
        assert_eq!(
            counts.get(&digest),
            Some(&1),
            "each accepted Realm Link Move must occur in exactly one Seal delta: {digest}"
        );
    }
}

/// G3.S5 — self-link is rejected as a schema violation with HTTP 422.
#[tokio::test(flavor = "multi_thread")]
async fn realm_link_event_self_reference_is_rejected() {
    let state = soland_test_support::app_state(test_config());
    let _control_seal_coordinator = soland_http::control_seal_coordinator::spawn(state.clone());
    let token = prepare_alice(&state).await;
    let realm_a = bootstrap_realm(&state, &token, "links self reference").await;

    let mut response = submit_link(&state, &token, &realm_a, &realm_a, "active").await;
    assert_eq!(response.status_code, Some(StatusCode::UNPROCESSABLE_ENTITY));
    let body: Value = response.take_json().await.expect("error envelope is JSON");
    assert_eq!(body["type"], "https://arkret.org/problems/schema_violation");
    assert_eq!(body["reason_code"], "realm_link_self_reference");
}

/// G3.S5 — effective-policy on a Realm with no
/// `ak.realm.inheritance_policy` declaration MUST report
/// `inheritance_mode = "none"` with an empty chain (spec §5 — no
/// implicit cascade).
#[tokio::test(flavor = "multi_thread")]
async fn effective_policy_returns_none_mode_without_explicit_optin() {
    let state = soland_test_support::app_state(test_config());
    let _control_seal_coordinator = soland_http::control_seal_coordinator::spawn(state.clone());
    let token = prepare_alice(&state).await;
    let realm_a = bootstrap_realm(&state, &token, "links no opt-in").await;

    let body = effective_policy(&state, &token, &realm_a).await;
    assert_eq!(body["realm_id"], realm_a);
    assert_eq!(body["inheritance_mode"], "none");
    assert!(
        body["inheritance_chain_ids"].as_array().unwrap().is_empty(),
        "chain must be empty without explicit opt-in: {body}"
    );
}
