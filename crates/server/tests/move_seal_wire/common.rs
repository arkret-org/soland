//! Shared helpers, fixtures, and imports for the `move_seal_wire`
//! integration-test binary.
//!
//! Originally lived inline at the top of `tests/move_seal_wire.rs` before
//! the file was split into per-topic submodules. All items are reachable
//! to siblings via `super::common::*` (re-exported through the crate root
//! `tests/move_seal_wire.rs`).
//!
//! The Move/Seal builders mirror those in
//! `cokret-rust-sdk/crates/state-res/src/seal.rs#tests` and
//! `crates/testing/src/lib.rs#build_membership_move`. They're inlined
//! here because those helpers are private to the SDK test modules.
//!
//! Cells: the tests transition
//! `ck:cell:ck.component.member.state.v1:did.web.alice.example` from
//! `invite` to `join`. That cell family is pre-registered in
//! `MemoryCellRegistry::default()` as an FSM with `invite -> join`
//! transition, so the Move passes verify and the post-state is
//! `Value("join")`.

#![allow(dead_code)]

pub(crate) use std::collections::{BTreeMap, BTreeSet};

pub(crate) use base64::Engine;
pub(crate) use base64::engine::general_purpose::URL_SAFE_NO_PAD;
pub(crate) use cokret_sdk::lattice::CellState;
pub(crate) use cokret_sdk::signatures::sign_eddsa_detached_jws;
pub(crate) use cokret_sdk::state_res::state_root::EMPTY_STATE_ROOT;
pub(crate) use cokret_sdk::state_res::{compute_state_root, control_event_set_root};
pub(crate) use cokret_sdk::{
    CellRef, Hash, Hlc, Move, MoveId, MoveSignature, NotarySig, RealmId, Seal, SealId, canonical,
};
pub(crate) use ed25519_dalek::SigningKey;
pub(crate) use salvo::http::StatusCode;
pub(crate) use salvo::test::{ResponseExt, TestClient};
pub(crate) use serde_json::{Value, json};
pub(crate) use sha2::{Digest, Sha256};
pub(crate) use soland::config::{AppConfig, IceServersConfig, LiveKitConfig, ObjectStorageConfig};
pub(crate) use soland::service;
pub(crate) use soland::state::AppState;
pub(crate) use soland_data::Db;

pub(crate) fn test_config() -> AppConfig {
    AppConfig {
        object_storage: ObjectStorageConfig::local(
            std::env::temp_dir().join("soland-test-blobs-move-seal"),
        ),
        development_mode: true,
        // 0 disables replay-window enforcement so existing fixed-time HLC
        // fixtures (`0189c4d2af00...`, July 2023) keep passing. Replay-
        // protection tests build a custom config with a non-zero window.
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: std::collections::BTreeMap::new(),
        seed_demo_data: true,
        ..AppConfig::test_default()
    }
}

pub(crate) fn realm_id() -> RealmId {
    RealmId::new("ck:realm:0196419b-0000-7000-8000-00000000014a".to_owned()).unwrap()
}

pub(crate) fn member_cell() -> CellRef {
    CellRef::new("ck:cell:ck.component.member.state.v1:did.web.alice.example".to_owned()).unwrap()
}

pub(crate) fn zero_seal_id_value() -> String {
    format!("ck:seal:sha256:{}", "00".repeat(32))
}

pub(crate) fn empty_seal_basis_value() -> Value {
    let empty = BTreeSet::new();
    let control_event_set_root = control_event_set_root(&empty).unwrap();
    json!({
        "leaves": [zero_seal_id_value()],
        "control_event_set_root": control_event_set_root.as_str(),
        "state_root": EMPTY_STATE_ROOT,
    })
}

/// Ed25519 seed whose verifying key matches soland's dev-mode shape
/// verifier (`jws_verify::dev_shape_only_public_key` uses
/// `SigningKey::from_bytes(&[7u8; 32])`). Signing fixtures with this seed
/// produces a real 64-byte Ed25519 detached-JWS signature that passes the
/// tightened SDK verifier (`Ed25519DetachedJwsVerifier::verify_proof`),
/// which now rejects non-64-byte placeholder signatures.
const DEV_SIGNING_SEED: [u8; 32] = [7u8; 32];

/// Produce a real detached-JWS signature string over `canonical_bytes`
/// using the dev signing key. The signing input is
/// `b64u({"alg":"EdDSA"}).b64u(canonical_bytes)`, matching the SDK
/// `verify_proof` reconstruction exactly.
pub(crate) fn dev_detached_jws(canonical_bytes: &[u8]) -> String {
    let signing_key = SigningKey::from_bytes(&DEV_SIGNING_SEED);
    sign_eddsa_detached_jws(&signing_key, canonical_bytes)
        .expect("sign canonical move bytes with dev key")
}

pub(crate) fn build_invited_to_join_move() -> Move {
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
            // Real 64-byte Ed25519 detached JWS over the canonical body
            // bytes, signed with the dev verifier key. The SDK verifier
            // (wave-2 tightening) rejects shorter placeholder signatures.
            "jws": dev_detached_jws(&body_bytes)
        }),
    );
    serde_json::from_value(Value::Object(full)).unwrap()
}

pub(crate) fn build_seal(
    mut predecessor_refs: Vec<SealId>,
    mut delta: Vec<MoveId>,
    state_root: Hash,
) -> Seal {
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

pub(crate) async fn dev_token(state: AppState) -> String {
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
    login["session_credential"]
        .as_str()
        .unwrap_or_else(|| panic!("dev-login did not return session_credential (got {login:?})"))
        .to_owned()
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
pub(crate) fn build_consent_grant_add_move() -> Move {
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
            "jws": dev_detached_jws(&body_bytes)
        }),
    );
    serde_json::from_value(Value::Object(full)).unwrap()
}
