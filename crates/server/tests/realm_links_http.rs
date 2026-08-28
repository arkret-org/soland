//! G3.S5 — HTTP integration tests for the realm-links surface:
//!
//! - `POST /_arkret/self/realms/{realm_id}/links` — create / status-flip a `ak.realm.link`.
//! - `DELETE /_arkret/self/realms/{realm_id}/links/{target_realm_id}` — tombstone an existing link.
//! - `GET /_arkret/self/realms/{realm_id}/effective-policy` — read the merged effective policy
//!   (walks the inheritance chain).
//! - General directed cycles are accepted; self-links and illegal FSM transitions are rejected.
//!
//! Both writes carry the caller-signed `ak.realm.link` Move rather than the edge
//! fields: only the caller can produce the signature the operation's `event_log`
//! durable effect requires (`zh/extensions/capabilities.md` sections 118/361,
//! `zh/security/key-management.md` section 411). That is why every Realm here is
//! bootstrapped through the real `ak.realm.create` genesis batch — a Control Move
//! has to cite an accepted Seal, and a Realm that was never created has none.

use arkret_identifiers::{RealmId, SealId};
use arkret_models_collaboration::governance::realm_governance::{
    RealmLinkCreateRequestBody, RealmLinkDeleteRequestBody,
};
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

/// The registered operation bodies are read as canonical JSON, so a fixture
/// posts RFC 8785 bytes rather than whatever field order `serde_json` emits.
fn canonical_body<T: serde::Serialize>(body: &T) -> Vec<u8> {
    arkret_canonical::canonical_json_bytes(body).expect("canonical operation body")
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
/// deployment as its frozen `single_signer` notary, and grant the caller `ak.realm.link`.
///
/// The Realm id is derived from the genesis Event (`realm-and-space.md` section
/// 2.5.0), so it is read back off the Event rather than chosen here.
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
    let mut created = TestClient::post("http://server/_arkret/self/events")
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
    for attempt in 0..50 {
        let mut response = TestClient::query("http://server/_arkret/self/seals/frontier")
            .json(&serde_json::json!({"realm_id": realm_id}))
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state))
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
                .clone();
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

/// The next position on the caller's Realm-scoped actor chain.
async fn actor_frontier(state: &AppState, token: &str, realm_id: &str) -> (u64, Vec<String>) {
    let frontier: arkret_models_collaboration::event_sync::EventsFrontierState =
        TestClient::query("http://server/_arkret/self/events/frontier")
            .json(&serde_json::json!({"actor_id": alice_core_id(), "realm_id": realm_id}))
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

async fn post_link(
    state: &AppState,
    token: &str,
    realm_id: &str,
    target: &str,
) -> salvo::http::Response {
    let request = RealmLinkCreateRequestBody {
        link_event: link_move(state, token, realm_id, target, "active").await,
    };
    TestClient::post(format!(
        "http://server/_arkret/self/realms/{realm_id}/links"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .add_header("content-type", "application/json", true)
    .body(canonical_body(&request))
    .send(&app_from_state(state))
    .await
}

/// Tombstone the edge.
///
/// The DELETE carries a request body because the removal is as durable a signed
/// Event as the creation, and `link_kind` travels in that signed payload: a query
/// parameter is outside the bytes the caller signs.
async fn delete_link(
    state: &AppState,
    token: &str,
    realm_id: &str,
    target: &str,
) -> salvo::http::Response {
    let request = RealmLinkDeleteRequestBody {
        link_event: link_move(state, token, realm_id, target, "tombstoned").await,
    };
    TestClient::delete(format!(
        "http://server/_arkret/self/realms/{realm_id}/links/{target}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .add_header("content-type", "application/json", true)
    .body(canonical_body(&request))
    .send(&app_from_state(state))
    .await
}

async fn effective_policy(state: &AppState, token: &str, realm_id: &str) -> Value {
    TestClient::get(format!(
        "http://server/_arkret/self/realms/{realm_id}/effective-policy"
    ))
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

/// G3.S5 — happy path: POST a `governed_by` link from B → A, GET the
/// effective policy on B (after an explicit `ak.realm.inheritance_policy`
/// opt-in) and assert the chain walked back to A.
#[tokio::test(flavor = "multi_thread")]
async fn realm_links_post_parent_then_effective_policy_walks_chain() {
    let state = soland_test_support::app_state(test_config());
    let _control_seal_coordinator = soland_http::control_seal_coordinator::spawn(state.clone());
    let token = prepare_alice(&state).await;
    let realm_a = bootstrap_realm(&state, &token, "links chain parent").await;
    let realm_b = bootstrap_realm(&state, &token, "links chain child").await;

    // 1. POST B → A (`governed_by`, active). HTTP 200, body echoes the projected status.
    let mut response = post_link(&state, &token, &realm_b, &realm_a).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["realm_id"], realm_b);
    assert_eq!(body["target_realm_id"], realm_a);
    assert_eq!(body["status"], "active");

    // 2. Explicit inheritance opt-in on B (spec §6.1 — a link alone doesn't enable inheritance).
    project_inheritance_policy(&state, &realm_b, &realm_a, &["b.policy"]);
    project_inheritance_policy(&state, &realm_a, &realm_a, &["a.policy"]);

    // 3. GET effective-policy on B. Body shape pinned by the task spec: `{realm_id,
    //    effective_policy, inheritance_chain, inheritance_mode}`.
    let ep = effective_policy(&state, &token, &realm_b).await;
    assert_eq!(ep["realm_id"], realm_b);
    assert_eq!(ep["inheritance_mode"], "explicit");
    let chain = ep["inheritance_chain"]
        .as_array()
        .expect("inheritance_chain array");
    assert!(
        chain.iter().any(|v| v.as_str() == Some(realm_a.as_str())),
        "inheritance_chain MUST include realm A (declared parent), got {chain:?}"
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
async fn realm_links_post_general_directed_cycle_is_allowed() {
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
        let mut response = post_link(&state, &token, source, target).await;
        let status = response.status_code;
        let body: Value = response.take_json().await.unwrap_or(Value::Null);
        assert_eq!(status, Some(StatusCode::OK), "{source} -> {target}: {body}");
    }
}

/// G3.S5 — DELETE a link, verify the effective policy recomputes
/// (the deleted edge is treated as severed, so it no longer
/// contributes to the inheritance walk).
#[tokio::test(flavor = "multi_thread")]
async fn realm_links_delete_recomputes_effective_policy() {
    let state = soland_test_support::app_state(test_config());
    let _control_seal_coordinator = soland_http::control_seal_coordinator::spawn(state.clone());
    let token = prepare_alice(&state).await;
    let realm_b = bootstrap_realm(&state, &token, "links delete grandparent").await;
    let realm_c = bootstrap_realm(&state, &token, "links delete parent").await;
    let realm_d = bootstrap_realm(&state, &token, "links delete child").await;

    // Build D → C → B chain via POSTs, opt-in inheritance at each level.
    for (source, target) in [(&realm_d, &realm_c), (&realm_c, &realm_b)] {
        let mut response = post_link(&state, &token, source, target).await;
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

    // DELETE D → C. Severs the chain at the first edge — D's chain
    // walk now stops at C (still declared in D's inheritance_policy)
    // but cannot transit further because the governed_by edge is
    // tombstoned. C's own `c.policy` still surfaces because D's
    // inheritance_policy explicitly names C as the parent; B drops out.
    let mut deleted = delete_link(&state, &token, &realm_d, &realm_c).await;
    let delete_status = deleted.status_code;
    let delete_body: Value = deleted.take_json().await.unwrap_or(Value::Null);
    assert_eq!(delete_status, Some(StatusCode::OK), "DELETE: {delete_body}");
    assert_eq!(delete_body["status"], "tombstoned");

    let allowed2 = allowed_policies(&effective_policy(&state, &token, &realm_d).await);
    assert!(
        !allowed2.iter().any(|policy| policy == "b.policy"),
        "after DELETE D→C, the transitive walk to B must be cut: {allowed2:?}"
    );

    // Tombstoned is terminal. A later attempt to reactivate the same cell
    // fails with the canonical FSM reason.
    let mut reactivate = post_link(&state, &token, &realm_d, &realm_c).await;
    assert_eq!(
        reactivate.status_code,
        Some(StatusCode::UNPROCESSABLE_ENTITY)
    );
    let body: Value = reactivate
        .take_json()
        .await
        .expect("error envelope is JSON");
    assert_eq!(body["error"]["code"], "failed_precondition");
    assert_eq!(
        body["error"]["details"]["reason_code"],
        "realm_link_invalid_transition"
    );
}

/// G3.S5 — self-link is rejected as a schema violation with HTTP 422.
#[tokio::test(flavor = "multi_thread")]
async fn realm_links_post_self_link_rejected() {
    let state = soland_test_support::app_state(test_config());
    let _control_seal_coordinator = soland_http::control_seal_coordinator::spawn(state.clone());
    let token = prepare_alice(&state).await;
    let realm_a = bootstrap_realm(&state, &token, "links self reference").await;

    let mut response = post_link(&state, &token, &realm_a, &realm_a).await;
    assert_eq!(response.status_code, Some(StatusCode::UNPROCESSABLE_ENTITY));
    let body: Value = response.take_json().await.expect("error envelope is JSON");
    assert_eq!(body["error"]["code"], "schema_violation");
    assert_eq!(
        body["error"]["details"]["reason_code"],
        "realm_link_self_reference"
    );
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
        body["inheritance_chain"].as_array().unwrap().is_empty(),
        "chain must be empty without explicit opt-in: {body}"
    );
}
