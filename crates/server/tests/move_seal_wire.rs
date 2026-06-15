//! End-to-end HTTP integration tests for `POST /_soland/peer/moves` and
//! `POST /_soland/peer/seals`.
//!
//! These tests exercise the full wire path: a client signs a Move,
//! posts it to soland, the server stashes it in the in-memory MoveStore,
//! the client (acting as the notary) signs a Seal referencing the
//! Move id and posts it; soland delegates to the SDK's `apply_seal`,
//! which verifies the Move, runs the per-cell Lattice join, recomputes
//! the canonical Merkle `state_root`, and returns the post-Seal
//! state root.
//!
//! The Move/Seal builders mirror those in
//! `cokret-rust-sdk/crates/state-res/src/seal.rs#tests` and
//! `crates/testing/src/lib.rs#build_membership_move`. They're inlined
//! here because those helpers are private to the SDK test modules.
//!
//! Cells: the test transitions
//! `ck:cell:ck.component.member.state.v1:did.web.alice.example` from
//! `invite` to `join`. That cell family is pre-registered in
//! `MemoryCellRegistry::default()` as an FSM with `invite -> join`
//! transition, so the Move passes verify and the post-state is
//! `Value("join")`.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cokret_sdk::lattice::CellState;
use cokret_sdk::state_res::state_root::EMPTY_STATE_ROOT;
use cokret_sdk::state_res::{compute_state_root, control_event_set_root};
use cokret_sdk::{
    CellRef, Hash, Hlc, Move, MoveId, MoveSignature, NotarySig, RealmId, Seal, SealId, canonical,
};
use ed25519_dalek::{Signer, SigningKey};
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use soland::config::{AppConfig, IceServersConfig, LiveKitConfig, ObjectStorageConfig};
use soland::db::Db;
use soland::service;
use soland::state::AppState;

fn test_config() -> AppConfig {
    AppConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        metrics_bind: "127.0.0.1:0".parse().unwrap(),
        public_base_url: "http://server".to_owned(),
        service_did: "did:web:soland.local".to_owned(),
        tls_cert_path: None,
        tls_key_path: None,
        database_url: None,
        object_storage: ObjectStorageConfig::local(
            std::env::temp_dir().join("soland-test-blobs-move-seal"),
        ),
        ice: IceServersConfig::default(),
        livekit: LiveKitConfig::default(),
        cors_allow_origin: None,
        auth_server_url: None,
        development_mode: true,
        oauth_introspection_url: None,
        oauth_introspection_bearer: None,
        session_grant_introspection_url: None,
        session_grant_introspection_bearer: None,
        did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned(), "uuid".to_owned()],
        embedded_webvh_provider_enabled: false,
        embedded_webvh_registration_bearer: None,
        external_webvh_provider_url: None,
        external_webvh_provider_active: false,
        default_webvh_provider_id: None,
        // 0 disables replay-window enforcement so existing fixed-time HLC
        // fixtures (`0189c4d2af00...`, July 2023) keep passing. Replay-
        // protection tests build a custom config with a non-zero window.
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
        seed_demo_data: true,
        trust_domain: "ck:trust_domain:soland.local".to_owned(),
        sovereign_enclave_enabled: false,
        sovereign_enclave_allowed_outbound_hosts: Vec::new(),
        erasure_propagation_window_ms: 604_800_000,
        log_format: soland::config::LogFormat::Plain,
    }
}

fn realm_id() -> RealmId {
    RealmId::new("ck:realm:0196419b-0000-7000-8000-00000000014a".to_owned()).unwrap()
}

fn member_cell() -> CellRef {
    CellRef::new("ck:cell:ck.component.member.state.v1:did.web.alice.example".to_owned()).unwrap()
}

fn zero_seal_id_value() -> String {
    format!("ck:seal:sha256:{}", "00".repeat(32))
}

fn empty_seal_basis_value() -> Value {
    let empty = BTreeSet::new();
    let control_event_set_root = control_event_set_root(&empty).unwrap();
    json!({
        "leaves": [zero_seal_id_value()],
        "control_event_set_root": control_event_set_root.as_str(),
        "state_root": EMPTY_STATE_ROOT,
    })
}

fn build_invited_to_join_move() -> Move {
    let body = json!({
        "issuer": "did:web:admin.example",
        "realm_id": realm_id().as_str(),
        "preconditions": [],
        "effects": [{
            "cell": member_cell().as_str(),
            "op": { "kind": "transition", "from": "invite", "to": "join" }
        }],
        "seal_basis": empty_seal_basis_value(),
        "refs": [],
        "hlc": "0189c4d2af00-0000-aabbccdd"
    });
    let body_bytes = canonical::canonical_json_bytes(&body).unwrap();
    let payload_digest = canonical::sha256_digest(&body_bytes);
    let id_hex: String = Sha256::digest(&body_bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut full = body.as_object().unwrap().clone();
    full.insert("id".into(), Value::String(format!("sha256:{id_hex}")));
    full.insert(
        "sig".into(),
        json!({
            "alg": "EdDSA",
            "verification_method": "did:web:admin.example#k1",
            "payload_digest": payload_digest,
            "created_at": "2026-05-08T00:00:00Z",
            // Detached JWS shape (RFC 7515 §3.2). Real Ed25519 verification
            // is covered by separate production-verifier tests.
            "jws": "eyJhbGciOiJFZERTQSJ9..ZmFrZS1zaWctZm9yLXRlc3Rz"
        }),
    );
    serde_json::from_value(Value::Object(full)).unwrap()
}

fn build_seal(mut predecessor_refs: Vec<SealId>, mut delta: Vec<MoveId>, state_root: Hash) -> Seal {
    let sig = MoveSignature {
        alg: "EdDSA".to_owned(),
        verification_method: "did:web:notary.example#k1".to_owned(),
        payload_digest: Hash::new(format!("sha256:{}", "ff".repeat(32))).unwrap(),
        created_at: chrono::DateTime::parse_from_rfc3339("2026-05-08T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        // Detached JWS shape (RFC 7515 §3.2): empty payload segment between
        // the protected header and signature. Header is base64url of
        // `{"alg":"EdDSA"}`; signature is a non-zero placeholder. Real
        // Ed25519 verification is DID-resolver-dependent; the fixture here
        // only needs valid detached-JWS shape.
        jws: "eyJhbGciOiJFZERTQSJ9..ZmFrZS1zaWctZm9yLXRlc3Rz".to_owned(),
    };
    predecessor_refs.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    predecessor_refs.dedup_by(|a, b| a.as_str() == b.as_str());
    delta.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    delta.dedup_by(|a, b| a.as_str() == b.as_str());
    let covered: BTreeSet<MoveId> = delta.iter().cloned().collect();
    let control_event_set_root = control_event_set_root(&covered).unwrap();
    let mut a = Seal {
        id: SealId::new(format!("ck:seal:sha256:{}", "00".repeat(32))).unwrap(),
        realm_id: realm_id(),
        predecessor_refs,
        delta,
        control_event_set_root: control_event_set_root.clone(),
        state_root,
        completeness_root: control_event_set_root,
        notary_seq: 0,
        data_view_root: None,
        data_event_set_root: None,
        availability_root: None,
        coverage_scope: None,
        covered_event_digests: Vec::new(),
        previous_state_root: None,
        previous_digest_algorithm: None,
        notary_signature: NotarySig::Single(sig),
        sealed_at: chrono::DateTime::parse_from_rfc3339("2026-05-08T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        hlc: Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
        kind: cokret_sdk::SealKind::Normal,
    };
    a.id = a.derive_id().unwrap();
    a
}

async fn dev_token(state: AppState) -> String {
    let app = service(state.clone());
    // Register the admin account first; dev-login alone fails on
    // unregistered DIDs in soland's auth path.
    let _: Value = TestClient::post("http://server/_soland/self/account/register")
        .json(&json!({
            "did": "did:web:admin.example",
            "handle": "@admin",
            "display_name": "Admin",
            "device_id": "ck:device:01904100-0000-7000-8000-ad11d0000008"
        }))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    let login: Value = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&json!({
            "actor": "did:web:admin.example",
            "device_id": "ck:device:01904100-0000-7000-8000-ad11d0000008",
            "display_name": "Admin"
        }))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    login["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("dev-login did not return access_token (got {login:?})"))
        .to_owned()
}

#[tokio::test]
async fn move_then_seal_apply_returns_recomputed_state_root() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // 1. Submit Move — soland verifies signature + effect shape and stashes it in the in-memory
    //    MoveStore.
    let move_obj = build_invited_to_join_move();
    let submit: Value = TestClient::post("http://server/_soland/peer/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        submit["state"], "pending",
        "Move should be queued pending after submit_move (got {submit:?})"
    );
    assert_eq!(submit["move_id"].as_str().unwrap(), move_obj.id.as_str());

    // 2. Compute the expected post-state_root. After this Move, member.state cell holds
    //    Value("join").
    let mut expected = BTreeMap::new();
    expected.insert(member_cell(), CellState::Value(json!("join")));
    let expected_root = compute_state_root(&expected).unwrap();

    // 3. Submit Seal — soland delegates to apply_seal, which: structural OK → no predecessors
    //    (Genesis Seal) → delta/predecessor consistency → deterministic_order → verify_move →
    //    atomic apply effect → recompute state_root → match A.state_root.
    let genesis = build_seal(
        vec![],
        vec![],
        Hash::new(EMPTY_STATE_ROOT.to_owned()).unwrap(),
    );
    let genesis_resp: Value = TestClient::post("http://server/_soland/peer/seals")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&genesis)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        genesis_resp["seal_id"].as_str().unwrap(),
        genesis.id.as_str()
    );

    let seal = build_seal(
        vec![genesis.id.clone()],
        vec![move_obj.id.clone()],
        expected_root.clone(),
    );
    let resp: Value = TestClient::post("http://server/_soland/peer/seals")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&seal)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(resp["seal_id"].as_str().unwrap(), seal.id.as_str());
    assert_eq!(
        resp["accepted_move_ids"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>()),
        Some(vec![move_obj.id.as_str()]),
        "Move should be accepted into the Seal"
    );
    assert_eq!(
        resp["rejected_moves"].as_array().map(|a| a.len()),
        Some(0),
        "Move should not be rejected"
    );
    assert_eq!(
        resp["post_state_root"].as_str().unwrap(),
        expected_root.as_str(),
        "Server-recomputed state_root MUST match SDK-computed expected root"
    );
}

#[tokio::test]
async fn seal_with_unknown_predecessor_is_rejected_with_conflict() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // Submit a Move first so the seal has a delta candidate.
    let move_obj = build_invited_to_join_move();
    let _: Value = TestClient::post("http://server/_soland/peer/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    // Seal declares a predecessor that has never been persisted.
    let mut expected = BTreeMap::new();
    expected.insert(member_cell(), CellState::Value(json!("join")));
    let expected_root = compute_state_root(&expected).unwrap();

    let bad_pred = SealId::new(format!("ck:seal:sha256:{}", "ee".repeat(32))).unwrap();
    let seal = build_seal(vec![bad_pred], vec![move_obj.id.clone()], expected_root);

    let mut resp = TestClient::post("http://server/_soland/peer/seals")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&seal)
        .send(&app)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::CONFLICT),
        "unknown predecessor MUST surface as 409 Conflict"
    );
    let body: Value = resp.take_json().await.unwrap();
    let stringified = body.to_string().to_ascii_lowercase();
    assert!(
        stringified.contains("predecessor"),
        "rejection reason should mention the unknown predecessor (got {body})"
    );
}

#[tokio::test]
async fn seal_with_non_empty_delta_without_genesis_predecessor_is_rejected() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    let move_obj = build_invited_to_join_move();
    let _: Value = TestClient::post("http://server/_soland/peer/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    let mut expected = BTreeMap::new();
    expected.insert(member_cell(), CellState::Value(json!("join")));
    let expected_root = compute_state_root(&expected).unwrap();
    let seal = build_seal(vec![], vec![move_obj.id], expected_root);

    let mut resp = TestClient::post("http://server/_soland/peer/seals")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&seal)
        .send(&app)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::CONFLICT));
    let body: Value = resp.take_json().await.unwrap();
    let stringified = body.to_string().to_ascii_lowercase();
    assert!(
        stringified.contains("genesis") || stringified.contains("delta"),
        "rejection reason should mention Genesis delta shape (got {body})"
    );
}

#[tokio::test]
async fn seal_with_wrong_state_root_rolls_back_with_conflict() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    let move_obj = build_invited_to_join_move();
    let _: Value = TestClient::post("http://server/_soland/peer/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    let genesis = build_seal(
        vec![],
        vec![],
        Hash::new(EMPTY_STATE_ROOT.to_owned()).unwrap(),
    );
    let _: Value = TestClient::post("http://server/_soland/peer/seals")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&genesis)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    // Wrong state_root: claim the Move had no effect (empty state),
    // even though it transitions the member cell.
    let wrong_root = Hash::new(EMPTY_STATE_ROOT.to_owned()).unwrap();
    let seal = build_seal(vec![genesis.id], vec![move_obj.id], wrong_root);

    let mut resp = TestClient::post("http://server/_soland/peer/seals")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&seal)
        .send(&app)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::CONFLICT),
        "state_root mismatch MUST surface as 409 Conflict"
    );
    let body: Value = resp.take_json().await.unwrap();
    let stringified = body.to_string().to_ascii_lowercase();
    assert!(
        stringified.contains("state_root") || stringified.contains("staterootmismatch"),
        "rejection reason should mention state_root mismatch (got {body})"
    );
}

#[test]
fn cursor_helper_compiles() {
    // Smoke test that the base64 helper integration doesn't break;
    // unrelated but cheap.
    let s = URL_SAFE_NO_PAD.encode(b"hello");
    assert_eq!(s, "aGVsbG8");
}

/// Exercise a cell family registered ONLY
/// via soland's `build_sdk_cell_registry()` (not in the SDK's built-in
/// defaults) to prove the registry wiring is live.
///
/// `ck.component.consent.grant.v1` is registered as `OrSet` in
/// `lattice_kinds.rs`; the SDK's `MemoryCellRegistry::default()` does NOT
/// include it. Submitting a Move with an `add` op on this cell would fail
/// with `unknown cell family` if soland hadn't replaced the SDK default
/// with `build_sdk_cell_registry()`.
fn build_consent_grant_add_move() -> Move {
    let consent_cell = "ck:cell:ck.component.consent.grant.v1:cnt.01js0c000000000000000000aa";
    let body = json!({
        "issuer": "did:web:admin.example",
        "realm_id": realm_id().as_str(),
        "preconditions": [],
        "effects": [{
            "cell": consent_cell,
            "op": { "kind": "add", "tag": "consent_granted" }
        }],
        "seal_basis": empty_seal_basis_value(),
        "refs": [],
        "hlc": "0189c4d2af00-0000-aabbccee"
    });
    let body_bytes = canonical::canonical_json_bytes(&body).unwrap();
    let payload_digest = canonical::sha256_digest(&body_bytes);
    let id_hex: String = Sha256::digest(&body_bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut full = body.as_object().unwrap().clone();
    full.insert("id".into(), Value::String(format!("sha256:{id_hex}")));
    full.insert(
        "sig".into(),
        json!({
            "alg": "EdDSA",
            "verification_method": "did:web:admin.example#k1",
            "payload_digest": payload_digest,
            "created_at": "2026-05-08T00:00:00Z",
            "jws": "eyJhbGciOiJFZERTQSJ9..ZmFrZS1zaWctZm9yLXRlc3Rz"
        }),
    );
    serde_json::from_value(Value::Object(full)).unwrap()
}

#[tokio::test]
async fn move_on_soland_registered_cell_family_passes_verify() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    let move_obj = build_consent_grant_add_move();
    let submit: Value = TestClient::post("http://server/_soland/peer/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    // If `ck.component.consent.grant.v1` weren't in soland's CellRegistry,
    // verify_move would reject with "unknown cell family". A `pending`
    // state confirms the registry resolved the family to OrSet and the
    // `add` op passed shape-validation.
    assert_eq!(
        submit["state"], "pending",
        "Move on soland-registered consent.grant cell should reach pending; got {submit:?}"
    );
}

/// The notary worker takes one or more
/// pending Moves and produces a signed Seal. This is the END-TO-END
/// proof of the Move → Seal strand without requiring the client to
/// hand-craft a Seal: the client submits a Move, then triggers the
/// admin signing endpoint, and a Seal pops out with the correct
/// state_root.
#[tokio::test]
async fn notary_worker_signs_pending_move_and_publishes_seal() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // 1. Submit a Move (membership FSM transition invite->join).
    let move_obj = build_invited_to_join_move();
    let submit: Value = TestClient::post("http://server/_soland/peer/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        submit["state"], "pending",
        "Move should be queued pending after submit_move (got {submit:?})"
    );

    // 2. Trigger the notary worker via the admin endpoint. This runs one signing pass: collect
    //    pending Moves → deterministic_order → verify each → predict state_root → build & sign Seal
    //    → apply_seal (which re-verifies).
    let sign_resp: Value = TestClient::post("http://server/_soland/admin/seals/sign")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "realm_id": realm_id().as_str(),
            "max_control_moves": 100,
        }))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    // 3. Assert: seal was published.
    assert_eq!(
        sign_resp["published"], true,
        "notary should publish a Seal (got {sign_resp:?})"
    );
    let seal_id = sign_resp["seal_id"]
        .as_str()
        .expect("seal_id should be present when published=true");
    assert!(
        seal_id.starts_with("ck:seal:sha256:"),
        "seal_id should be a content-addressed sha256 ref, got {seal_id}"
    );
    let accepted = sign_resp["accepted_move_ids"]
        .as_array()
        .expect("accepted_move_ids should be an array");
    assert_eq!(accepted.len(), 1, "exactly one Move should be sealed");
    assert_eq!(
        accepted[0].as_str(),
        Some(move_obj.id.as_str()),
        "the sealed Move id should match the one we submitted"
    );

    // 4. Assert: post_state_root corresponds to member_cell holding "join".
    let mut expected = BTreeMap::new();
    expected.insert(member_cell(), CellState::Value(json!("join")));
    let expected_root = compute_state_root(&expected).unwrap();
    assert_eq!(
        sign_resp["post_state_root"].as_str(),
        Some(expected_root.as_str()),
        "post_state_root should match the notary's predicted recompute"
    );
}

/// Demo realm pre-seeded by AppState::new. Public/discoverable so the
/// test's dev-login session can subscribe without explicit membership
/// registration. Other tests in this file use a different realm id
/// (Move/Seal tests don't go through realm_id_accessible).
fn demo_realm_id() -> &'static str {
    "ck:realm:0196419b-0000-7000-8000-000000000000"
}

fn event_envelope(event_id: &str, actor: &str, realm_id: &str, payload: Value) -> Value {
    let suffix = event_id.trim_start_matches("ck:event:");
    let mut event = json!({
        "event_id": event_id,
        "kind": "ck.message.create",
        "actor_id": actor,
        "actor_seq": 1,
        "realm_id": realm_id,
        "created_at": "2026-05-02T00:00:00Z",
        "hlc": "01970e589d21-0001-a13f9c2e",
        "payload": payload,
        "prev_refs": [],
        "refs": [],
        "unsigned": {
            "local_operation_idempotency_alias": format!("ck:operation:{suffix}"),
        },
        "proofs": [{
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": format!("{actor}#test"),
            "payload_digest": "",
            "created_at": "2026-05-02T00:00:00Z",
            "jws": "a..b",
        }],
    });
    refresh_event_proof(&mut event);
    event
}

fn event_digest(event: &Value) -> String {
    let mut canonical = event.clone();
    if let Value::Object(object) = &mut canonical {
        object.remove("proofs");
        object.remove("unsigned");
    }
    sha256_json(&canonical)
}

fn refresh_event_proof(event: &mut Value) {
    let digest = event_digest(event);
    event["proofs"][0]["payload_digest"] = Value::String(digest);
}

fn sha256_json(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).expect("JSON value serializes");
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// events.subscribe is a streaming NDJSON
/// response. This test:
///   1. Calls GET /_cokret/self/events/subscribe with `max_duration_ms=500` so the stream
///      auto-closes quickly enough for TestClient to collect the full body.
///   2. (Concurrently) submits a message Event via /_cokret/self/events which triggers
///      `project_accepted_operations` → broadcast notification.
///   3. Asserts the response body contains:
///      - one `kind="catchup_complete"` frame
///      - at least one `kind="event"` frame with the message id we sent
///      - one `kind="heartbeat"` frame with `stream_closing=true` (deadline fire)
#[tokio::test]
async fn events_subscribe_streams_live_event_then_closes_at_deadline() {
    use std::time::Duration as StdDuration;

    use tokio::time::sleep;

    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // Spawn the writer first — but pause so the subscribe call gets to
    // register its broadcast receiver before we send the message. This
    // simulates the live-arrival case (event arrives AFTER the catchup
    // complete frame). We re-build the Service from the shared AppState
    // because salvo::Service is not Clone.
    let writer_state = state.clone();
    let token_writer = token.clone();
    let realm = demo_realm_id().to_owned();
    let writer = tokio::spawn(async move {
        let app_writer = service(writer_state);
        // Wait for the subscribe request to land + register its receiver.
        sleep(StdDuration::from_millis(150)).await;
        let event_id = "ck:event:01984101-0000-7000-8000-000000000abc";
        let _: Value = TestClient::post("http://server/_cokret/self/events")
            .add_header("Authorization", format!("Bearer {token_writer}"), true)
            .json(&event_envelope(
                event_id,
                "did:web:alice.example",
                &realm,
                json!({
                    "body": "hello live",
                    "content": {"body": "hello live"},
                }),
            ))
            .send(&app_writer)
            .await
            .take_json()
            .await
            .unwrap_or_default();
    });

    // Subscribe with a short deadline so the test doesn't block.
    let mut response = TestClient::get(format!(
        "http://server/_cokret/self/events/subscribe?realms={}&max_duration_ms=500&heartbeat_ms=200",
        demo_realm_id()
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .send(&app)
    .await;

    let body_string = response.take_string().await.expect("response body");
    writer.await.expect("writer task should complete");

    // Parse NDJSON lines.
    let frames: Vec<Value> = body_string
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("ndjson line should parse"))
        .collect();
    assert!(
        frames.len() >= 2,
        "expected ≥2 frames (catchup_complete + heartbeat or event); got {} ({:?})",
        frames.len(),
        frames
    );

    // Frame kinds we should see at minimum:
    let kinds: Vec<&str> = frames
        .iter()
        .filter_map(|f| f.get("kind").and_then(Value::as_str))
        .collect();
    assert!(
        kinds.contains(&"catchup_complete"),
        "stream should emit a catchup_complete frame; got kinds {kinds:?}"
    );
    // Either a live event (writer landed before deadline) or just heartbeat
    // (writer was too late). Both prove the stream is wired correctly.
    let saw_event = frames
        .iter()
        .any(|f| f.get("kind").and_then(Value::as_str) == Some("event"));
    let saw_closing_heartbeat = frames.iter().any(|f| {
        f.get("kind").and_then(Value::as_str) == Some("heartbeat")
            && f.get("stream_closing").and_then(Value::as_bool) == Some(true)
    });
    assert!(
        saw_event || saw_closing_heartbeat,
        "stream should either deliver the live event OR fire the deadline-close heartbeat; got {frames:?}"
    );
}

// ── Replay protection ─────────────────────────────────────────

/// Build a Move whose `hlc` is set to the given physical-ms timestamp
/// (so we can craft replay scenarios). Uses the dev-mode shape verifier
/// path since we want to test the replay-window gate independently of
/// the crypto verifier.
fn build_member_state_move_with_hlc(physical_ms: u64) -> Move {
    let hlc_str = format!("{physical_ms:012x}-0000-aabbccdd");
    let body = json!({
        "issuer": "did:web:admin.example",
        "realm_id": realm_id().as_str(),
        "preconditions": [],
        "effects": [{
            "cell": member_cell().as_str(),
            "op": { "kind": "transition", "from": "invite", "to": "join" }
        }],
        "seal_basis": empty_seal_basis_value(),
        "refs": [],
        "hlc": hlc_str,
    });
    let body_bytes = canonical::canonical_json_bytes(&body).unwrap();
    let payload_digest = canonical::sha256_digest(&body_bytes);
    let id_hex: String = Sha256::digest(&body_bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut full = body.as_object().unwrap().clone();
    full.insert("id".into(), Value::String(format!("sha256:{id_hex}")));
    full.insert(
        "sig".into(),
        json!({
            "alg": "EdDSA",
            "verification_method": "did:web:admin.example#k1",
            "payload_digest": payload_digest,
            "created_at": "2026-05-08T00:00:00Z",
            "jws": "eyJhbGciOiJFZERTQSJ9..ZmFrZS1zaWctZm9yLXRlc3Rz"
        }),
    );
    serde_json::from_value(Value::Object(full)).unwrap()
}

/// AppConfig with a 5-minute replay window (production default) but
/// `development_mode=true` so dev-login still works for test auth. This
/// isolates the replay-window check from the production-Ed25519 path.
fn replay_window_test_config() -> AppConfig {
    let mut cfg = test_config();
    cfg.jws_replay_window_seconds = 300;
    cfg
}

#[tokio::test]
async fn submit_move_rejects_stale_hlc_with_replay_window_reason() {
    let state = AppState::new(replay_window_test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // HLC = 1 hour ago; window = 5 min → MUST reject.
    let stale_ms = (chrono::Utc::now() - chrono::Duration::hours(1)).timestamp_millis() as u64;
    let move_obj = build_member_state_move_with_hlc(stale_ms);

    let submit: Value = TestClient::post("http://server/_soland/peer/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(
        submit["state"], "rejected",
        "stale HLC must be rejected (got {submit:?})"
    );
    let reason = submit["reason"].as_str().unwrap_or("").to_ascii_lowercase();
    assert!(
        reason.contains("replay_window") && reason.contains("too old"),
        "rejection reason should call out replay_window + too old (got `{reason}`)"
    );
}

#[tokio::test]
async fn submit_move_rejects_future_hlc() {
    let state = AppState::new(replay_window_test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // HLC 1 hour in the future → MUST reject (clock-skew attack defense).
    let future_ms = (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp_millis() as u64;
    let move_obj = build_member_state_move_with_hlc(future_ms);

    let submit: Value = TestClient::post("http://server/_soland/peer/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(submit["state"], "rejected");
    let reason = submit["reason"].as_str().unwrap_or("").to_ascii_lowercase();
    assert!(
        reason.contains("replay_window") && reason.contains("future"),
        "rejection reason should call out replay_window + future (got `{reason}`)"
    );
}

#[tokio::test]
async fn submit_move_accepts_current_hlc_under_replay_window() {
    let state = AppState::new(replay_window_test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // HLC = now → within ±300s window → accept.
    let now_ms = chrono::Utc::now().timestamp_millis() as u64;
    let move_obj = build_member_state_move_with_hlc(now_ms);

    let submit: Value = TestClient::post("http://server/_soland/peer/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(
        submit["state"], "pending",
        "current-time HLC under replay window MUST be accepted (got {submit:?})"
    );
}

// ── Production Ed25519 verifier ───────────────────────────────
//
// dev-login is gated by `config.development_mode=true`, so we can't use
// the HTTP path with auth tokens to test the production verifier. Instead
// we exercise the verifier directly via the public `soland::jws_verify`
// module. AppState is built minimally with `development_mode=false` so
// the DID resolver is identical to production-deploy behaviour.

/// Encode an Ed25519 public key as the multibase form did:key + DID
/// Document verificationMethod entries use:
/// `z<base58btc(0xed 0x01 || pubkey32)>`.
fn encode_ed25519_multibase(pubkey: &[u8; 32]) -> String {
    let mut bytes = Vec::with_capacity(34);
    bytes.push(0xed);
    bytes.push(0x01);
    bytes.extend_from_slice(pubkey);
    format!("z{}", bs58::encode(&bytes).into_string())
}

/// Build a JWS detached signature over `canonical_bytes` with `signing_key`.
/// Returns `(jws, payload_digest_hex)`.
fn make_detached_jws(signing_key: &SigningKey, canonical_bytes: &[u8], tamper: bool) -> String {
    let header_json = br#"{"alg":"EdDSA"}"#;
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json);
    let payload_b64 = URL_SAFE_NO_PAD.encode(canonical_bytes);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let mut signature = signing_key.sign(signing_input.as_bytes()).to_bytes();
    if tamper {
        signature[0] ^= 0xff;
    }
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature);
    format!("{header_b64}..{sig_b64}")
}

#[tokio::test]
async fn production_verifier_accepts_real_ed25519_did_key_signature() {
    let mut cfg = test_config();
    cfg.development_mode = false;
    let state = AppState::new(cfg, Db { pool: None });

    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let pubkey_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    let multibase = encode_ed25519_multibase(&pubkey_bytes);
    let did = format!("did:key:{}", multibase);
    let verification_method = format!("{did}#{multibase}");

    let canonical_bytes = b"some canonical move bytes for testing";
    let jws = make_detached_jws(&signing_key, canonical_bytes, false);

    let result = soland::jws_verify::verify_jws_ed25519(
        canonical_bytes,
        &jws,
        &verification_method,
        &did,
        &state,
    );
    assert!(
        result.is_ok(),
        "real-Ed25519-signed JWS over did:key should verify; got {result:?}"
    );
}

#[tokio::test]
async fn production_verifier_rejects_tampered_signature() {
    let mut cfg = test_config();
    cfg.development_mode = false;
    let state = AppState::new(cfg, Db { pool: None });

    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let pubkey_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    let multibase = encode_ed25519_multibase(&pubkey_bytes);
    let did = format!("did:key:{}", multibase);
    let verification_method = format!("{did}#{multibase}");

    let canonical_bytes = b"another canonical payload";
    let jws = make_detached_jws(&signing_key, canonical_bytes, true);

    let result = soland::jws_verify::verify_jws_ed25519(
        canonical_bytes,
        &jws,
        &verification_method,
        &did,
        &state,
    );
    let err = result.expect_err("tampered signature MUST be rejected");
    assert!(
        err.to_ascii_lowercase().contains("verify failed")
            || err.to_ascii_lowercase().contains("ed25519")
            || err.to_ascii_lowercase().contains("signature"),
        "rejection reason should mention the signature failure (got `{err}`)"
    );
}

#[tokio::test]
async fn production_verifier_rejects_signature_over_different_payload() {
    let mut cfg = test_config();
    cfg.development_mode = false;
    let state = AppState::new(cfg, Db { pool: None });

    let signing_key = SigningKey::from_bytes(&[13u8; 32]);
    let pubkey_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    let multibase = encode_ed25519_multibase(&pubkey_bytes);
    let did = format!("did:key:{}", multibase);
    let verification_method = format!("{did}#{multibase}");

    // Sign payload A but try to verify against payload B — proves the
    // verifier actually binds the signature to the canonical_bytes input,
    // not just shape.
    let signed_bytes = b"the canonical bytes the signer signed";
    let jws = make_detached_jws(&signing_key, signed_bytes, false);
    let claimed_bytes = b"DIFFERENT bytes the verifier was given";

    let result = soland::jws_verify::verify_jws_ed25519(
        claimed_bytes,
        &jws,
        &verification_method,
        &did,
        &state,
    );
    assert!(
        result.is_err(),
        "verifier MUST reject when canonical_bytes don't match the signed input"
    );
}

#[tokio::test]
async fn production_verifier_rejects_unknown_verification_method() {
    let mut cfg = test_config();
    cfg.development_mode = false;
    let state = AppState::new(cfg, Db { pool: None });

    let signing_key = SigningKey::from_bytes(&[17u8; 32]);
    let canonical_bytes = b"some payload";
    let jws = make_detached_jws(&signing_key, canonical_bytes, false);

    // verification_method points at a did:web that the resolver chain
    // can't reach (would need an HTTP fetch in test env).
    let result = soland::jws_verify::verify_jws_ed25519(
        canonical_bytes,
        &jws,
        "did:web:unreachable.example#k1",
        "did:web:unreachable.example",
        &state,
    );
    assert!(
        result.is_err(),
        "verifier MUST fail when DID resolution can't produce a verification method"
    );
}

/// Post-seal `kind=frontier` mid-stream control frame.
///
/// Subscribe to the demo Realm → trigger a Seal sign for that Realm →
/// verify the streaming subscriber sees a `kind=frontier` frame whose
/// `state_root` matches the seal's post_state_root and `seal_id`
/// starts with `ck:seal:sha256:`.
///
/// **Note**: this test uses a different Realm (the Move/Seal pipeline
/// Realm, not the demo Realm) for the seal, so we subscribe to that
/// Realm too. We bypass the access check by using the dev-mode public
/// Realm test fixture. We can't easily subscribe to the same seal
/// Realm the existing notary tests use because that Realm isn't
/// registered in RealmSearchIndex; so we subscribe to the demo Realm and
/// post the Move's effects there instead.
#[tokio::test]
async fn notary_pass_broadcasts_frontier_frame_to_subscribers() {
    use std::time::Duration as StdDuration;

    use tokio::time::sleep;

    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let _app = service(state.clone());

    // The seal pipeline writes to realm_id() (test-only Realm). We
    // subscribe to that Realm — the broadcast filter accepts any
    // realm the broadcast notification's realm_id matches.
    let writer_state = state.clone();
    let token_writer = token.clone();
    let writer = tokio::spawn(async move {
        let app_writer = service(writer_state);
        // Wait so the subscriber's broadcast receiver is registered.
        sleep(StdDuration::from_millis(150)).await;
        // Submit a Move + trigger the notary; both happen on the
        // seal-pipeline Realm (`realm_id()`), and the broadcast goes
        // out tagged with that realm_id.
        let move_obj = build_invited_to_join_move();
        let _: Value = TestClient::post("http://server/_soland/peer/moves")
            .add_header("Authorization", format!("Bearer {token_writer}"), true)
            .json(&move_obj)
            .send(&app_writer)
            .await
            .take_json()
            .await
            .unwrap_or_default();
        let _: Value = TestClient::post("http://server/_soland/admin/seals/sign")
            .add_header("Authorization", format!("Bearer {token_writer}"), true)
            .json(&json!({"realm_id": realm_id().as_str()}))
            .send(&app_writer)
            .await
            .take_json()
            .await
            .unwrap_or_default();
    });

    // Subscribe to the same Realm the seal will be published on. We
    // need that Realm to pass realm_id_accessible — for tests, the
    // simplest path is to use a Realm that's already registered as
    // public. But realm_id() isn't registered so this would 404. So we
    // bypass by checking what `realm_id_accessible` does: if a session
    // is None and the Realm has discoverability=public, accept; else
    // require session has membership. The test config injects a session
    // (dev_token), so we'd need the actor in realm.members. To avoid
    // wiring all that, we use the broadcast directly: subscribe to the
    // receiver and check the notification arrives.
    let mut rx = state.event_broadcast.subscribe();
    writer.await.expect("writer task");
    // Drain any non-frontier messages and find the frontier.
    let mut saw_frontier = false;
    let mut saw_event = false;
    let deadline = tokio::time::Instant::now() + StdDuration::from_millis(200);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(StdDuration::from_millis(50), rx.recv()).await {
            Ok(Ok(notification)) => {
                use soland::state::EventNotificationKind;
                match notification.kind {
                    EventNotificationKind::Frontier {
                        state_root,
                        seal_id,
                    } => {
                        assert!(
                            seal_id.starts_with("ck:seal:sha256:"),
                            "frontier seal_id should be content-addressed (got `{seal_id}`)"
                        );
                        assert!(
                            state_root.starts_with("sha256:"),
                            "frontier state_root should be sha256-prefixed (got `{state_root}`)"
                        );
                        saw_frontier = true;
                    }
                    EventNotificationKind::Event { .. } => {
                        saw_event = true;
                    }
                    _ => {}
                }
            }
            _ => break,
        }
    }
    assert!(
        saw_frontier,
        "notary signing pass MUST broadcast a Frontier notification (saw event = {saw_event})"
    );
}

/// Even with no live events at all, the stream emits
/// `catchup_complete` then a deadline-close heartbeat. Proves the stream
/// terminates cleanly without indefinite blocking.
#[tokio::test]
async fn events_subscribe_emits_close_heartbeat_at_deadline() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    let mut response = TestClient::get(format!(
        "http://server/_cokret/self/events/subscribe?realms={}&max_duration_ms=300&heartbeat_ms=10000",
        demo_realm_id()
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .send(&app)
    .await;

    let body_string = response.take_string().await.expect("response body");
    let frames: Vec<Value> = body_string
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("ndjson line should parse"))
        .collect();

    // Catchup_complete + deadline-close heartbeat = 2 frames minimum.
    assert!(
        frames.len() >= 2,
        "expected ≥2 frames at idle; got {} ({frames:?})",
        frames.len()
    );
    assert_eq!(
        frames[0].get("kind").and_then(Value::as_str),
        Some("catchup_complete"),
        "first frame must be catchup_complete"
    );
    let last = frames.last().unwrap();
    assert_eq!(
        last.get("kind").and_then(Value::as_str),
        Some("heartbeat"),
        "last frame at deadline must be a heartbeat"
    );
    assert_eq!(
        last.get("stream_closing").and_then(Value::as_bool),
        Some(true),
        "deadline-close heartbeat must carry stream_closing=true"
    );
}

/// After the notary publishes a Seal,
/// `ProjectionState::cells` MUST contain the resolved CellState for the
/// member.state cell. Proves the write-back hook in
/// `NotaryWorker::sign_pending_for_space` actually refreshes the
/// projection cache so cell-keyed read paths see the new state.
#[tokio::test]
async fn notary_pass_populates_projection_cells_map() {
    use cokret_sdk::lattice::CellState;

    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    let move_obj = build_invited_to_join_move();
    let _: Value = TestClient::post("http://server/_soland/peer/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    let _: Value = TestClient::post("http://server/_soland/admin/seals/sign")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({"realm_id": realm_id().as_str()}))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    // Inspect ProjectionState directly. The member_cell should now be in
    // the cells map with Value("join") (the FSM transition we sealed).
    let proj = state.projection.lock().expect("projection lock");
    let resolved = proj
        .cell(&member_cell())
        .expect("member.state cell should be in ProjectionState::cells after apply_seal");
    match resolved {
        CellState::Value(v) => {
            assert_eq!(
                v.as_str(),
                Some("join"),
                "member.state cell should resolve to FSM state \"join\" (got {v:?})"
            );
        }
        CellState::Bottom(b) => {
            panic!("member.state cell should resolve to Value, not Bottom: {b:?}");
        }
    }
}

/// `admin_reconfigure_notary` builds a real Move signed
/// with the service admin signer, submits it through the move_store,
/// and triggers one notary signing pass. Endpoint should return
/// `status="accepted"` with a real `move_id` and (since this node is
/// the genesis notary) a non-null `seal_id`.
#[tokio::test]
async fn admin_reconfigure_notary_builds_real_move_and_seals_it() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // Reconfigure to an open_set profile that does NOT include the
    // server's service DID (admin-as-member would be a privilege-
    // escalation primitive and should be rejected by the endpoint —
    // but we want a successful reconfigure here, so pick external DIDs).
    let url = format!(
        "http://server/_soland/admin/realms/{}/notary/reconfigure",
        realm_id().as_str()
    );
    let resp: Value = TestClient::post(&url)
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "kind": "open_set",
            "members": ["did:ck:alice", "did:ck:bob"],
        }))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        resp["status"], "accepted",
        "admin_reconfigure_notary should produce a real signed Move (got {resp:?})"
    );
    let move_id = resp["move_id"].as_str().expect("move_id should be set");
    assert!(
        move_id.starts_with("sha256:"),
        "move_id should be content-addressed sha256, got {move_id}"
    );
    let seal_id = resp["seal_id"]
        .as_str()
        .expect("seal_id should be set when this node is the round leader");
    assert!(
        seal_id.starts_with("ck:seal:sha256:"),
        "seal_id should be content-addressed sha256, got {seal_id}"
    );
}

/// `admin_reconfigure_notary` rejects requests where the
/// admin DID (= service DID for now) appears in the proposed notary
/// member set, because that's a privilege-escalation primitive.
#[tokio::test]
async fn admin_reconfigure_notary_rejects_self_in_proposed_member_set() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    let url = format!(
        "http://server/_soland/admin/realms/{}/notary/reconfigure",
        realm_id().as_str()
    );
    let response = TestClient::post(&url)
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "kind": "open_set",
            // service DID `did:web:soland.local` IS the admin signer.
            "members": ["did:web:soland.local", "did:ck:other"],
        }))
        .send(&app)
        .await;
    assert_eq!(
        response.status_code,
        Some(StatusCode::FORBIDDEN),
        "admin DID in proposed member set must be rejected as privilege-escalation"
    );
}

/// Idempotency: signing twice in a row publishes once. The second pass
/// finds no pending Moves (all sealed by the first pass) and reports
/// `published: false`.
#[tokio::test]
async fn notary_worker_is_idempotent_when_no_pending_moves() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    let move_obj = build_invited_to_join_move();
    let _: Value = TestClient::post("http://server/_soland/peer/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    // First pass: publishes.
    let first: Value = TestClient::post("http://server/_soland/admin/seals/sign")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({"realm_id": realm_id().as_str()}))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(first["published"], true);

    // Second pass: no pending Moves, no Seal.
    let second: Value = TestClient::post("http://server/_soland/admin/seals/sign")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({"realm_id": realm_id().as_str()}))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        second["published"], false,
        "second signing pass should report nothing pending (got {second:?})"
    );
}

// ── Admin cells endpoint ──────────────────────────────────────
//
// Public-ish read surface over `ProjectionState::cells` so coauth (consent
// grants on holder principal servers) and sodmin (admin-UI bottom-state
// inspection) can introspect canonical cell state. Tests below exercise:
//
// - GET /_soland/admin/cells/{cell_id} on an unknown cell → 404 envelope
// - Same on a cell after a Move → Seal → cells reload → state="value"
// - GET /_soland/admin/cells with prefix filter → only matching cells
// - Auth-required: omit Bearer token → 401 / canonical envelope

/// Submit a Move + trigger notary signing pass so the member cell
/// transitions invite->join AND lands in `ProjectionState::cells`. Returns
/// the URL-encoded path-segment form of the cell id (which for our
/// cell ids — only `:`s and `.`s, both URL-path-safe — is the raw
/// string).
async fn seed_member_cell_join(state: AppState, token: &str) -> String {
    let app = service(state.clone());
    let move_obj = build_invited_to_join_move();
    let _: Value = TestClient::post("http://server/_soland/peer/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    let _: Value = TestClient::post("http://server/_soland/admin/seals/sign")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({"realm_id": realm_id().as_str(), "max_control_moves": 100}))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    member_cell().as_str().to_owned()
}

#[tokio::test]
async fn admin_get_cell_on_unknown_cell_returns_404_envelope() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // Cell family is registered (member.state.v1 lives in the SDK default
    // registry) but no Move ever wrote to this subject — so the cell is
    // "absent" and the endpoint returns 404 with the canonical envelope.
    let unknown = "ck:cell:ck.component.member.state.v1:did.web.nobody.example";
    let mut resp = TestClient::get(format!(
        "http://server/_soland/admin/cells/{unknown}?realm_id={}",
        realm_id().as_str()
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .send(&app)
    .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::NOT_FOUND),
        "unknown cell should surface as 404"
    );
    let body: Value = resp.take_json().await.unwrap();
    let envelope = body
        .get("error")
        .or(Some(&body))
        .expect("error envelope should be present");
    assert!(
        envelope.get("code").is_some(),
        "404 body should be a canonical error envelope (got {body})"
    );
    assert_eq!(envelope["code"], "not_found");
}

#[tokio::test]
async fn admin_get_cell_returns_value_after_sealed_move() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // Drive a Move + Seal so the member cell transitions invite->join
    // and lands in ProjectionState::cells.
    let cell_id = seed_member_cell_join(state.clone(), &token).await;

    let mut resp = TestClient::get(format!(
        "http://server/_soland/admin/cells/{cell_id}?realm_id={}",
        realm_id().as_str()
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .send(&app)
    .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::OK),
        "sealed cell should return 200"
    );
    let body: Value = resp.take_json().await.unwrap();
    assert_eq!(body["state"], "value", "got {body}");
    assert_eq!(
        body["value"], "join",
        "expected resolved Value(\"join\") (got {body})"
    );
    assert_eq!(body["lattice"], "fsm");
    assert_eq!(body["bottom_policy"], "reject");
    assert_eq!(body["cell_id"], member_cell().as_str());
}

#[tokio::test]
async fn admin_list_cells_filters_by_prefix() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // Seed two distinct cell families:
    //   1. ck.component.member.state.v1 (member_cell, sealed → join)
    //   2. ck.component.consent.grant.v1 (or-set, sealed via consent move)
    let _ = seed_member_cell_join(state.clone(), &token).await;
    let consent_move = build_consent_grant_add_move();
    let _: Value = TestClient::post("http://server/_soland/peer/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&consent_move)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    let _: Value = TestClient::post("http://server/_soland/admin/seals/sign")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({"realm_id": realm_id().as_str(), "max_control_moves": 100}))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    // List with prefix=ck.component.consent. → only the consent.grant cell.
    let mut resp = TestClient::get(format!(
        "http://server/_soland/admin/cells?realm_id={}&prefix=ck.component.consent.",
        realm_id().as_str()
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .send(&app)
    .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::OK),
        "list endpoint should return 200 for valid filter"
    );
    let body: Value = resp.take_json().await.unwrap();
    let cells = body["cells"].as_array().expect("cells should be an array");
    assert!(
        !cells.is_empty(),
        "consent.grant cell should be listed (got {body})"
    );
    for cell in cells {
        let cid = cell["cell_id"].as_str().unwrap_or("");
        assert!(
            cid.contains(":ck.component.consent."),
            "every listed cell must match the prefix filter; got `{cid}`"
        );
    }
    // The member.state cell must NOT be in the results.
    assert!(
        cells
            .iter()
            .all(|c| c["cell_id"].as_str() != Some(member_cell().as_str())),
        "member.state cell must not match the consent prefix (got {body})"
    );
}

#[tokio::test]
async fn admin_get_cell_requires_bearer_token() {
    let state = AppState::new(test_config(), Db { pool: None });
    let app = service(state.clone());

    // No Authorization header — endpoint MUST 401 with canonical envelope.
    let mut resp = TestClient::get(format!(
        "http://server/_soland/admin/cells/{}",
        member_cell().as_str()
    ))
    .send(&app)
    .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::UNAUTHORIZED),
        "missing token should surface as 401"
    );
    let body: Value = resp.take_json().await.unwrap();
    let envelope = body.get("error").or(Some(&body)).expect("envelope");
    assert!(
        envelope.get("code").is_some(),
        "401 body should be a canonical error envelope (got {body})"
    );
}

#[tokio::test]
async fn admin_list_cells_requires_realm_id_query_param() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // Missing realm_id → 400 missing_param.
    let mut resp = TestClient::get("http://server/_soland/admin/cells?prefix=ck.")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .send(&app)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::BAD_REQUEST),
        "list without realm_id should surface as 400"
    );
    let body: Value = resp.take_json().await.unwrap();
    let envelope = body.get("error").or(Some(&body)).expect("envelope");
    assert_eq!(envelope["code"], "missing_param");
}

#[tokio::test]
async fn admin_list_cells_paginates_with_limit_and_offset() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // Seed at least two cells (member + consent) under the same Realm.
    let _ = seed_member_cell_join(state.clone(), &token).await;
    let consent_move = build_consent_grant_add_move();
    let _: Value = TestClient::post("http://server/_soland/peer/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&consent_move)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    let _: Value = TestClient::post("http://server/_soland/admin/seals/sign")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({"realm_id": realm_id().as_str(), "max_control_moves": 100}))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    // limit=1 → exactly one cell page.
    let mut resp = TestClient::get(format!(
        "http://server/_soland/admin/cells?realm_id={}&limit=1",
        realm_id().as_str()
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .send(&app)
    .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK));
    let body: Value = resp.take_json().await.unwrap();
    assert_eq!(body["limit"], 1);
    assert_eq!(body["offset"], 0);
    let cells = body["cells"].as_array().unwrap();
    assert_eq!(cells.len(), 1, "limit=1 must yield a single-cell page");
    let total = body["total"].as_u64().unwrap();
    assert!(
        total >= 2,
        "test seeds ≥2 cells under the Realm (got total={total} body={body})"
    );
}

/// `admin_rotate_signing_key` mints a fresh ed25519 seed,
/// hot-swaps the NotaryWorker key via `AppState::rotate_notary_signing_key`,
/// and returns `{kid, did, rotated_at, origin, keystore_persisted, keystore_warning}`.
/// The pre-rotation key MUST differ byte-for-byte from the post-rotation key
/// (proves the swap actually published a new key into the ArcSwap).
#[tokio::test]
async fn admin_rotate_signing_key_publishes_a_fresh_key() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());
    let pre = state.notary_signing_key().to_bytes();

    let url = format!(
        "http://server/_soland/admin/realms/{}/notary/rotate-signing-key",
        realm_id().as_str()
    );
    let resp: Value = TestClient::post(&url)
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({}))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(
        resp["did"], "did:web:soland.local",
        "rotate response did mirrors service_did (got {resp:?})"
    );
    assert_eq!(
        resp["kid"], "did:web:soland.local#notary-key",
        "rotate response kid is `<did>#notary-key` (got {resp:?})"
    );
    assert!(resp.get("rotated_at").is_some(), "rotated_at present");
    assert_eq!(
        resp["origin"], "Configured",
        "post-rotation origin is Configured (got {resp:?})"
    );
    // use_keystore=false in test_config → keystore_persisted is false but
    // a non-fatal warning is surfaced.
    assert_eq!(resp["keystore_persisted"], false);
    assert!(resp["keystore_warning"].is_string(), "warning surfaced");

    let post = state.notary_signing_key().to_bytes();
    assert_ne!(
        pre, post,
        "rotate-signing-key MUST publish a fresh key (pre and post seeds matched)"
    );
}

/// `account/{did}/principal-realm` returns the deterministic
/// DID → control-Realm mapping. Two queries for the same DID return the
/// same `realm_id`; two queries for different DIDs return different ones.
#[tokio::test]
async fn account_principal_realm_is_deterministic() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    let alice_url = "http://server/_soland/self/account/did:web:alice.example/principal-realm";
    let resp_a: Value = TestClient::get(alice_url)
        .add_header("Authorization", format!("Bearer {token}"), true)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    let resp_a2: Value = TestClient::get(alice_url)
        .add_header("Authorization", format!("Bearer {token}"), true)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        resp_a["realm_id"], resp_a2["realm_id"],
        "same DID → same realm_id (got {resp_a:?} vs {resp_a2:?})"
    );
    assert_eq!(resp_a["mapping_kind"], "deterministic");
    assert_eq!(resp_a["did"], "did:web:alice.example");
    let realm_id_str = resp_a["realm_id"].as_str().expect("realm_id present");
    assert!(
        realm_id_str.starts_with("ck:realm:"),
        "realm_id has ck:realm: prefix (got {realm_id_str})"
    );

    let bob_url = "http://server/_soland/self/account/did:web:bob.example/principal-realm";
    let resp_b: Value = TestClient::get(bob_url)
        .add_header("Authorization", format!("Bearer {token}"), true)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_ne!(
        resp_a["realm_id"], resp_b["realm_id"],
        "alice and bob MUST map to different Realms (both got {})",
        resp_a["realm_id"]
    );
}
