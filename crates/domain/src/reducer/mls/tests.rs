use arkret_event_draft::Operation;
use arkret_identifiers::{OperationId, RealmId};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{TimeZone, Utc};
use serde_json::json;

use super::*;
use crate::reducer::{MlsEffect, ProjectionEffect, ProjectionState};

fn op_at(secs: i64, object_type: &str, payload: serde_json::Value) -> Operation {
    let mut op = Operation::create(
        OperationId::new("ak:operation:0196419b-0000-7000-8000-000000000001")
            .expect("op id parses"),
        RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000000").expect("realm id parses"),
        object_type,
        payload,
    );
    op.created_at = Utc.timestamp_opt(secs, 0).single().expect("ts in range");
    op
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn realm_scope() -> Value {
    json!({
        "kind": "realm",
        "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000000"
    })
}

fn circle_scope(circle_id: &str) -> Value {
    json!({
        "kind": "circle",
        "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000000",
        "circle_id": circle_id
    })
}

fn governance_binding_for_scope(
    previous_epoch: u64,
    group_id: &str,
    effective_scope: Value,
) -> Value {
    let realm_id = "ak:realm:0196419b-0000-7000-8000-000000000000";
    let frontier = format!("ak:event:0196419b-0000-7000-8000-{previous_epoch:012x}");
    let mut binding = json!({
        "binding_version": 1,
        "encoding_profile": "cbor-deterministic-rfc8949-v1",
        "realm_id": realm_id,
        "effective_scope": effective_scope,
        "mls_group_id": group_id,
        "previous_epoch": previous_epoch,
        "next_epoch": previous_epoch + 1,
        "membership_frontier": [
            frontier
        ],
        "policy_root": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "binding_profile": crate::kinds::MLS_GOVERNANCE_BINDING_FULL_PROFILE,
        "reducer_profile": crate::kinds::MLS_REDUCER_PROFILE_V1
    });
    if let Some(circle_id) = binding["effective_scope"]
        .get("circle_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
    {
        binding["circle_id"] = Value::String(circle_id);
    }
    binding
}

fn governance_binding(previous_epoch: u64) -> Value {
    governance_binding_for_scope(previous_epoch, "ak:mls_group:abc", realm_scope())
}

fn welcome_payload(welcome_id: &str) -> Value {
    let keypackage_ref = "ak:mls_keypackage:01";
    let keypackage_digest =
        "sha256:5555555555555555555555555555555555555555555555555555555555555555";
    json!({
        "welcome_id": welcome_id,
        "group_id": "ak:mls_group:abc",
        "epoch": 1,
        "commit_ref": "ak:event:0196419b-0000-7000-8000-000000000010",
        "recipient_actor_id": "did:web:bob.example",
        "recipient_device_id": "ak:device:bob-phone",
        "welcome_bytes_b64": b64(b"opaque-welcome-bytes"),
        "key_package_id": keypackage_ref,
        "keypackage_ref": keypackage_ref,
        "keypackage_digest": keypackage_digest,
        "claim_id": "claim-01",
        "claim_ref": {
            "claim_id": "claim-01",
            "keypackage_ref": keypackage_ref,
            "keypackage_digest": keypackage_digest,
            "capabilities_digest": "sha256:6666666666666666666666666666666666666666666666666666666666666666",
            "ssk_generation": 7
        },
        "claim_envelope": {
            "keypackage_ref": keypackage_ref,
            "keypackage_digest": keypackage_digest,
            "intended_realm_id": "ak:realm:0196419b-0000-7000-8000-000000000000",
            "claim_id": "claim-01",
            "requester_did": "did:web:alice.example",
            "ssk_generation": 7,
            "nonce": b64(b"welcome-claim-nonce-01-128-bit"),
            "welcome_digest": arkret_canonical::sha256_digest(b"opaque-welcome-bytes"),
            "created_at": "2026-05-25T00:00:02.000Z",
            "signature": {
                "kid": "did:web:alice.example#self-signing",
                "alg": "EdDSA",
                "sig": b64(b"welcome-claim-envelope-signature")
            }
        },
        "governance_binding": governance_binding(0)
    })
}

fn genesis_binding(group_id: &str, effective_scope: Value) -> Value {
    let realm_id = "ak:realm:0196419b-0000-7000-8000-000000000000";
    let mut binding = json!({
        "binding_version": 1,
        "encoding_profile": "cbor-deterministic-rfc8949-v1",
        "realm_id": realm_id,
        "effective_scope": effective_scope,
        "mls_group_id": group_id,
        "previous_epoch": 0,
        "next_epoch": 0,
        "membership_frontier": [
            "ak:event:0196419b-0000-7000-8000-000000000000"
        ],
        "policy_root": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "binding_profile": crate::kinds::MLS_GOVERNANCE_BINDING_FULL_PROFILE,
        "reducer_profile": crate::kinds::MLS_REDUCER_PROFILE_V1
    });
    if let Some(circle_id) = binding["effective_scope"]
        .get("circle_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
    {
        binding["circle_id"] = Value::String(circle_id);
    }
    binding
}

fn genesis_payload(group_id: &str, effective_scope: Value) -> Value {
    json!({
        "mls_group_id": group_id,
        "effective_scope": effective_scope.clone(),
        "epoch": 0,
        "creator_principal_id": "did:web:alice.example",
        "creator_device_id": "ak:device:alice-desktop",
        "cipher_suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "group_info_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        "ratchet_tree_digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
        "governance_binding": genesis_binding(group_id, effective_scope),
        "created_at": "2026-05-25T00:00:00.000Z"
    })
}

fn initialize_genesis(state: &mut ProjectionState) {
    let genesis = op_at(
        499,
        "ak.mls.genesis",
        genesis_payload("ak:mls_group:abc", realm_scope()),
    );
    let effect = apply_group_genesis(state, &genesis);
    assert!(matches!(
        effect,
        ProjectionEffect::Mls(MlsEffect::GroupGenesis { .. })
    ));
}

fn publish_payload(id: &str, actor: &str, device: &str, not_after: i64) -> serde_json::Value {
    json!({
        "action": "publish",
        "keypackage_id": id,
        "actor_id": actor,
        "device_id": device,
        "lifetime": {"not_before": 1, "not_after": not_after},
        "ssk_generation": 7,
        "key_package_bytes_b64": b64(b"opaque-keypackage-bytes"),
    })
}

#[test]
fn keypackage_publish_then_claim_succeeds() {
    let mut state = ProjectionState::default();
    let publish = op_at(
        100,
        "ak.mls.keypackage",
        publish_payload(
            "ak:mls_keypackage:01",
            "did:web:alice.example",
            "ak:device:alice-desktop",
            1_000_000,
        ),
    );
    let effect = apply_keypackage_publish(&mut state, &publish);
    assert!(matches!(
        effect,
        ProjectionEffect::Mls(MlsEffect::KeyPackagePublished { ref keypackage_id, .. })
            if keypackage_id == "ak:mls_keypackage:01"
    ));
    assert!(
        state
            .mls_key_packages
            .get("ak:mls_keypackage:01")
            .unwrap()
            .claimed_by
            .is_none()
    );

    let claim = op_at(
        200,
        "ak.mls.keypackage",
        json!({
            "action": "claim",
            "keypackage_id": "ak:mls_keypackage:01",
            "group_id": "ak:mls_group:abc",
            "ssk_generation": 7
        }),
    );
    let claim_effect = apply_keypackage_claim(&mut state, &claim);
    match claim_effect {
        ProjectionEffect::Mls(MlsEffect::KeyPackageClaimed {
            keypackage_id,
            group_id,
            claimed_at,
            ..
        }) => {
            assert_eq!(keypackage_id, "ak:mls_keypackage:01");
            assert_eq!(group_id, "ak:mls_group:abc");
            assert_eq!(claimed_at, 200);
        }
        other => panic!("expected KeyPackageClaimed, got {other:?}"),
    }
    let row = state.mls_key_packages.get("ak:mls_keypackage:01").unwrap();
    assert_eq!(row.claimed_by.as_deref(), Some("ak:mls_group:abc"));
    assert_eq!(row.claimed_at, Some(200));
    assert_eq!(row.consumed_at, None);
}

#[test]
fn keypackage_claim_twice_second_fails() {
    let mut state = ProjectionState::default();
    let publish = op_at(
        100,
        "ak.mls.keypackage",
        publish_payload(
            "ak:mls_keypackage:02",
            "did:web:alice.example",
            "ak:device:alice-desktop",
            1_000_000,
        ),
    );
    let _ = apply_keypackage_publish(&mut state, &publish);

    // First claim — wins.
    let claim1 = op_at(
        200,
        "ak.mls.keypackage",
        json!({
            "action": "claim",
            "keypackage_id": "ak:mls_keypackage:02",
            "group_id": "ak:mls_group:first",
            "ssk_generation": 7
        }),
    );
    let e1 = apply_keypackage_claim(&mut state, &claim1);
    assert!(matches!(
        e1,
        ProjectionEffect::Mls(MlsEffect::KeyPackageClaimed { .. })
    ));

    // Second claim — must be rejected by the CAS.
    let claim2 = op_at(
        201,
        "ak.mls.keypackage",
        json!({
            "action": "claim",
            "keypackage_id": "ak:mls_keypackage:02",
            "group_id": "ak:mls_group:second",
            "ssk_generation": 7
        }),
    );
    let e2 = apply_keypackage_claim(&mut state, &claim2);
    match e2 {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, REASON_KEYPACKAGE_ALREADY_CLAIMED);
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
    // First claim's group must still own the row — losers don't overwrite.
    let row = state.mls_key_packages.get("ak:mls_keypackage:02").unwrap();
    assert_eq!(row.claimed_by.as_deref(), Some("ak:mls_group:first"));
    assert_eq!(row.claimed_at, Some(200));
    assert_eq!(row.consumed_at, None);
}

#[test]
fn last_resort_keypackage_reuses_within_realm_only() {
    let mut state = ProjectionState::default();
    let mut payload = publish_payload(
        "ak:mls_keypackage:last-resort",
        "did:web:alice.example",
        "ak:device:alice-desktop",
        1_000_000,
    );
    payload["last_resort"] = json!(true);
    let publish = op_at(100, "ak.mls.keypackage", payload);
    let _ = apply_keypackage_publish(&mut state, &publish);

    for group_id in ["ak:mls_group:first", "ak:mls_group:second"] {
        let claim = op_at(
            200,
            "ak.mls.keypackage",
            json!({
                "action": "claim",
                "keypackage_id": "ak:mls_keypackage:last-resort",
                "group_id": group_id,
                "intended_realm_id": "ak:realm:alpha",
                "ssk_generation": 7
            }),
        );
        assert!(matches!(
            apply_keypackage_claim(&mut state, &claim),
            ProjectionEffect::Mls(MlsEffect::KeyPackageClaimed {
                last_resort: true,
                ..
            })
        ));
    }

    let row = state
        .mls_key_packages
        .get("ak:mls_keypackage:last-resort")
        .unwrap();
    assert!(row.claimed_by.is_none());
    assert!(row.consumed_at.is_none());
    assert_eq!(row.last_resort_realm_id.as_deref(), Some("ak:realm:alpha"));

    let cross_realm = op_at(
        201,
        "ak.mls.keypackage",
        json!({
            "action": "claim",
            "keypackage_id": "ak:mls_keypackage:last-resort",
            "group_id": "ak:mls_group:other",
            "intended_realm_id": "ak:realm:beta",
            "ssk_generation": 7
        }),
    );
    match apply_keypackage_claim(&mut state, &cross_realm) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, REASON_KEYPACKAGE_REALM_MISMATCH);
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
}

#[test]
fn revoked_last_resort_keypackage_cannot_be_reused() {
    let mut state = ProjectionState::default();
    let mut payload = publish_payload(
        "ak:mls_keypackage:revoked-last-resort",
        "did:web:alice.example",
        "ak:device:alice-desktop",
        1_000_000,
    );
    payload["last_resort"] = json!(true);
    let publish = op_at(100, "ak.mls.keypackage", payload);
    let _ = apply_keypackage_publish(&mut state, &publish);
    state
        .mls_key_packages
        .get_mut("ak:mls_keypackage:revoked-last-resort")
        .unwrap()
        .claimed_by = Some("revoked".to_owned());

    let claim = op_at(
        200,
        "ak.mls.keypackage",
        json!({
            "action": "claim",
            "keypackage_id": "ak:mls_keypackage:revoked-last-resort",
            "group_id": "ak:mls_group:first",
            "intended_realm_id": "ak:realm:alpha",
            "ssk_generation": 7
        }),
    );
    match apply_keypackage_claim(&mut state, &claim) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, REASON_KEYPACKAGE_NOT_FOUND);
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
}

#[test]
fn keypackage_claim_rejects_stale_cross_signing_generation() {
    let mut state = ProjectionState::default();
    let publish = op_at(
        100,
        "ak.mls.keypackage",
        publish_payload(
            "ak:mls_keypackage:03",
            "did:web:alice.example",
            "ak:device:alice-desktop",
            1_000_000,
        ),
    );
    let _ = apply_keypackage_publish(&mut state, &publish);

    let claim = op_at(
        200,
        "ak.mls.keypackage",
        json!({
            "action": "claim",
            "keypackage_id": "ak:mls_keypackage:03",
            "group_id": "ak:mls_group:abc",
            "ssk_generation": 8
        }),
    );
    let effect = apply_keypackage_claim(&mut state, &claim);
    match effect {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, arkret_wire::ReasonCode::CLAIM_GENERATION_MISMATCH);
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
    let row = state.mls_key_packages.get("ak:mls_keypackage:03").unwrap();
    assert!(row.claimed_by.is_none());
    assert_eq!(row.ssk_generation, Some(7));
}

#[test]
fn welcome_enqueue_then_fetch_marks_delivered() {
    let mut state = ProjectionState::default();
    let enqueue = op_at(300, "ak.mls.welcome", welcome_payload("ak:mls_welcome:w1"));
    let effect = apply_welcome_enqueue(&mut state, &enqueue);
    assert!(matches!(
        effect,
        ProjectionEffect::Mls(MlsEffect::WelcomeEnqueued { .. })
    ));

    let key = MlsWelcomeQueueKey::new("did:web:bob.example", "ak:device:bob-phone");
    let queue = state.mls_welcomes.get(&key).unwrap();
    assert_eq!(queue.len(), 1);
    assert!(queue[0].delivered_at.is_none());

    // Simulate the route draining the queue: mark all undelivered rows.
    let now = 400_i64;
    let drained: Vec<MlsWelcome> = state
        .mls_welcomes
        .get_mut(&key)
        .unwrap()
        .iter_mut()
        .map(|row| {
            if row.delivered_at.is_none() {
                row.delivered_at = Some(now);
            }
            row.clone()
        })
        .collect();
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].delivered_at, Some(400));

    // A re-poll would skip these — already marked delivered.
    let still_pending: Vec<_> = state
        .mls_welcomes
        .get(&key)
        .unwrap()
        .iter()
        .filter(|r| r.delivered_at.is_none())
        .collect();
    assert!(still_pending.is_empty());
}

fn agent_bound_welcome_payload(welcome_id: &str, authorize_event_id: &str) -> Value {
    let mut payload = welcome_payload(welcome_id);
    let claim_ref = payload
        .get_mut("claim_ref")
        .and_then(Value::as_object_mut)
        .unwrap();
    claim_ref.remove("ssk_generation");
    claim_ref.insert(
        "agent_key_authorize_event_id".to_owned(),
        json!(authorize_event_id),
    );
    payload
}

#[test]
fn welcome_enqueue_rejects_inactive_agent_key_authorization() {
    let mut state = ProjectionState::default();
    let payload = agent_bound_welcome_payload(
        "ak:mls_welcome:w-agent-stale",
        "ak:event:0196419b-0000-7000-8000-0000000000a1",
    );
    let effect = apply_welcome_enqueue(&mut state, &op_at(300, "ak.mls.welcome", payload));
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { reason }
            if reason == arkret_wire::ReasonCode::CLAIM_GENERATION_MISMATCH
    ));
}

#[test]
fn welcome_enqueue_accepts_current_agent_key_authorization() {
    let mut state = ProjectionState::default();
    let authorize_event_id = "ak:event:0196419b-0000-7000-8000-0000000000a2";
    let authorize = op_at(
        200,
        arkret_wire::events::EventKind::AGENT_KEY_AUTHORIZE,
        json!({
            "agent_id": "did:web:bob.example",
            "key_id": "ak:agent_key:0196419b-0000-7000-8000-0000000000a2",
            "accepted_event_id": authorize_event_id,
            "verification_method": "did:web:bob.example#runtime-1"
        }),
    );
    let effect = state.apply(&authorize, &crate::hlc::ServerHlc::new("mls-agent-test"));
    assert!(matches!(
        effect,
        ProjectionEffect::AgentKeyAuthorizeProjected { .. }
    ));

    let payload = agent_bound_welcome_payload("ak:mls_welcome:w-agent-current", authorize_event_id);
    let effect = apply_welcome_enqueue(&mut state, &op_at(300, "ak.mls.welcome", payload));
    assert!(matches!(
        effect,
        ProjectionEffect::Mls(MlsEffect::WelcomeEnqueued { .. })
    ));
}

#[test]
fn welcome_enqueue_accepts_requester_device_envelope_without_sender_device_id() {
    let mut state = ProjectionState::default();
    let mut payload = welcome_payload("ak:mls_welcome:w-device");
    let claim_ref = payload
        .get_mut("claim_ref")
        .and_then(Value::as_object_mut)
        .unwrap();
    claim_ref.remove("ssk_generation");
    claim_ref.insert(
        "device_authorize_event_id".to_owned(),
        json!("ak:event:01904100-0000-7000-8000-00000000d001"),
    );
    let claim_envelope = payload
        .get_mut("claim_envelope")
        .and_then(Value::as_object_mut)
        .unwrap();
    claim_envelope.remove("ssk_generation");
    claim_envelope.insert(
        "requester_device_id".to_owned(),
        json!("ak:device:alice-desktop"),
    );
    claim_envelope["signature"]["kid"] = json!("did:key:z6MkRequesterDevice#device");
    assert!(payload.get("sender_device_id").is_none());

    let enqueue = op_at(300, "ak.mls.welcome", payload);
    let effect = apply_welcome_enqueue(&mut state, &enqueue);

    assert!(matches!(
        effect,
        ProjectionEffect::Mls(MlsEffect::WelcomeEnqueued { .. })
    ));
}

#[test]
fn welcome_enqueue_rejects_mismatched_sender_device_id_when_present() {
    let mut state = ProjectionState::default();
    let mut payload = welcome_payload("ak:mls_welcome:w-device-mismatch");
    let claim_ref = payload
        .get_mut("claim_ref")
        .and_then(Value::as_object_mut)
        .unwrap();
    claim_ref.remove("ssk_generation");
    claim_ref.insert(
        "device_authorize_event_id".to_owned(),
        json!("ak:event:01904100-0000-7000-8000-00000000d001"),
    );
    let claim_envelope = payload
        .get_mut("claim_envelope")
        .and_then(Value::as_object_mut)
        .unwrap();
    claim_envelope.remove("ssk_generation");
    claim_envelope.insert(
        "requester_device_id".to_owned(),
        json!("ak:device:alice-desktop"),
    );
    claim_envelope["signature"]["kid"] = json!("did:key:z6MkRequesterDevice#device");
    payload["sender_device_id"] = json!("ak:device:other");

    let enqueue = op_at(300, "ak.mls.welcome", payload);
    let effect = apply_welcome_enqueue(&mut state, &enqueue);

    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { reason }
            if reason == arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH
    ));
}

#[test]
fn welcome_enqueue_decodes_schema_ciphertext_base64_to_raw_welcome_bytes() {
    let mut state = ProjectionState::default();
    let raw_welcome = b"real-openmls-welcome-bytes";
    let mut payload = welcome_payload("ak:mls_welcome:w-ciphertext");
    let object = payload.as_object_mut().unwrap();
    object.remove("welcome_bytes_b64");
    object.remove("key_package_id");
    object.insert("ciphertext".to_owned(), Value::String(b64(raw_welcome)));
    payload["claim_envelope"]["welcome_digest"] =
        Value::String(arkret_canonical::sha256_digest(raw_welcome));

    let enqueue = op_at(300, "ak.mls.welcome", payload);
    let effect = apply_welcome_enqueue(&mut state, &enqueue);

    assert!(matches!(
        effect,
        ProjectionEffect::Mls(MlsEffect::WelcomeEnqueued { .. })
    ));
    let key = MlsWelcomeQueueKey::new("did:web:bob.example", "ak:device:bob-phone");
    let queue = state.mls_welcomes.get(&key).unwrap();
    assert_eq!(queue[0].welcome_bytes, raw_welcome);
    assert_eq!(queue[0].key_package_id, "ak:mls_keypackage:01");
}

#[test]
fn welcome_enqueue_rejects_plaintext_identity_metadata() {
    let mut state = ProjectionState::default();
    let mut payload = welcome_payload("ak:mls_welcome:w-leaky");
    payload["metadata"] = json!({
        "sender_handle": "@alice",
        "routing_hint": "ok"
    });
    let enqueue = op_at(300, "ak.mls.welcome", payload);
    let effect = apply_welcome_enqueue(&mut state, &enqueue);
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { reason } if reason == REASON_WELCOME_METADATA_LEAK
    ));
    assert!(state.mls_welcomes.is_empty());
}

#[test]
fn welcome_enqueue_rejects_missing_claim_envelope() {
    let mut state = ProjectionState::default();
    let mut payload = welcome_payload("ak:mls_welcome:w-unbound");
    payload.as_object_mut().unwrap().remove("claim_envelope");
    let enqueue = op_at(300, "ak.mls.welcome", payload);
    let effect = apply_welcome_enqueue(&mut state, &enqueue);
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { reason }
            if reason == arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH
    ));
    assert!(state.mls_welcomes.is_empty());
}

#[test]
fn commit_epoch_in_order_succeeds() {
    let mut state = ProjectionState::default();
    initialize_genesis(&mut state);

    // First commit after genesis — expected_prev_epoch=0 → epoch=1.
    let c1 = op_at(
        500,
        "ak.mls.commit",
        json!({
            "group_id": "ak:mls_group:abc",
            "expected_prev_epoch": 0,
            "next_epoch": 1,
            "leader_actor_id": "did:web:alice.example",
            "commit_bytes_b64": b64(b"opaque-commit-1"),
            "governance_binding": governance_binding(0),
        }),
    );
    let e1 = apply_commit_epoch(&mut state, &c1);
    match e1 {
        ProjectionEffect::Mls(MlsEffect::CommitEpochAdvanced {
            previous_epoch,
            new_epoch,
            ref covered_seals,
            ..
        }) => {
            assert_eq!(previous_epoch, 0);
            assert_eq!(new_epoch, 1);
            assert_eq!(
                covered_seals,
                &vec!["ak:event:0196419b-0000-7000-8000-000000000000".to_owned()]
            );
        }
        other => panic!("expected CommitEpochAdvanced, got {other:?}"),
    }

    // Second commit — expected_prev_epoch=1 → epoch=2.
    let c2 = op_at(
        501,
        "ak.mls.commit",
        json!({
            "group_id": "ak:mls_group:abc",
            "expected_prev_epoch": 1,
            "next_epoch": 2,
            "leader_actor_id": "did:web:alice.example",
            "commit_bytes_b64": b64(b"opaque-commit-2"),
            "governance_binding": governance_binding(1),
        }),
    );
    let e2 = apply_commit_epoch(&mut state, &c2);
    assert!(matches!(
        e2,
        ProjectionEffect::Mls(MlsEffect::CommitEpochAdvanced { new_epoch: 2, .. })
    ));
    assert_eq!(
        state
            .mls_commit_epochs
            .get(&mls_epoch_key(&realm_scope(), "ak:mls_group:abc").unwrap())
            .unwrap(),
        &MlsCommitEpoch {
            group_id: "ak:mls_group:abc".to_owned(),
            effective_scope: realm_scope(),
            epoch: 2,
            leader_actor_id: "did:web:alice.example".to_owned(),
            creator_device_id: "ak:device:alice-desktop".to_owned(),
            genesis_event_ref: "ak:operation:0196419b-0000-7000-8000-000000000001".to_owned(),
            covered_seals: vec![
                "ak:event:0196419b-0000-7000-8000-000000000000".to_owned(),
                "ak:event:0196419b-0000-7000-8000-000000000001".to_owned()
            ],
            committed_at: 501,
            governance_binding: governance_binding(1),
            policy_root: "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                .to_owned(),
            accepted_commit_digest: Some(b64(b"opaque-commit-2")),
            accepted_commit_ref: Some(
                "ak:operation:0196419b-0000-7000-8000-000000000001".to_owned(),
            ),
            accepted_from_epoch: Some(1),
            frontier_contested: false,
        }
    );
}

#[test]
fn pending_device_revoke_requires_remove_commit_frontier() {
    let mut state = ProjectionState::default();
    initialize_genesis(&mut state);
    let revoke_event = "ak:event:0196419b-0000-7000-8000-00000000d002";
    let proposal_ref = "ak:event:0196419b-0000-7000-8000-00000000d003";
    state.pending_mls_removals.push(MlsRemoveObligation {
        realm_id: "ak:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
        circle_id: None,
        mls_group_ref: Some("ak:mls_group:abc".to_owned()),
        actor_id: "did:web:alice.example".to_owned(),
        device_id: Some("ak:device:lost".to_owned()),
        membership_frontier: vec![revoke_event.to_owned()],
        trigger_membership: "device_revoke".to_owned(),
        triggered_at: Utc.timestamp_opt(500, 0).single().unwrap(),
    });
    assert!(matches!(
        apply_remove_proposal(
            &mut state,
            &op_at(
                500,
                "ak.mls.proposal",
                json!({
                    "event_id": proposal_ref,
                    "mls_group_id": "ak:mls_group:abc",
                    "base_epoch": 0,
                    "proposal_type": "remove",
                    "proposal_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "target_principal_id": "did:web:alice.example",
                    "target_device_id": "ak:device:lost",
                }),
            )
        ),
        ProjectionEffect::Mls(MlsEffect::RemoveProposalRecorded { .. })
    ));

    let effect = apply_commit_epoch(
        &mut state,
        &op_at(
            501,
            "ak.mls.commit",
            json!({
                "group_id": "ak:mls_group:abc",
                "expected_prev_epoch": 0,
                "next_epoch": 1,
                "leader_actor_id": "did:web:alice.example",
                "commit_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "proposal_refs": [proposal_ref],
                "governance_binding": governance_binding(0),
            }),
        ),
    );
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { reason }
            if reason == REASON_REMOVE_MISSING_GOVERNANCE_FRONTIER
    ));
    assert_eq!(state.pending_mls_removals.len(), 1);
}

#[test]
fn remove_commit_covering_device_revoke_advances_and_clears_obligation() {
    let mut state = ProjectionState::default();
    initialize_genesis(&mut state);
    let revoke_event = "ak:event:0196419b-0000-7000-8000-00000000d102";
    let proposal_ref = "ak:event:0196419b-0000-7000-8000-00000000d103";
    state.pending_mls_removals.push(MlsRemoveObligation {
        realm_id: "ak:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
        circle_id: None,
        mls_group_ref: Some("ak:mls_group:abc".to_owned()),
        actor_id: "did:web:alice.example".to_owned(),
        device_id: Some("ak:device:lost".to_owned()),
        membership_frontier: vec![revoke_event.to_owned()],
        trigger_membership: "device_revoke".to_owned(),
        triggered_at: Utc.timestamp_opt(500, 0).single().unwrap(),
    });
    assert!(matches!(
        apply_remove_proposal(
            &mut state,
            &op_at(
                500,
                "ak.mls.proposal",
                json!({
                    "event_id": proposal_ref,
                    "mls_group_id": "ak:mls_group:abc",
                    "base_epoch": 0,
                    "proposal_type": "remove",
                    "proposal_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "target_principal_id": "did:web:alice.example",
                    "target_device_id": "ak:device:lost",
                }),
            )
        ),
        ProjectionEffect::Mls(MlsEffect::RemoveProposalRecorded { .. })
    ));
    let mut binding = governance_binding(0);
    binding["membership_frontier"] = json!([revoke_event]);

    let effect = apply_commit_epoch(
        &mut state,
        &op_at(
            501,
            "ak.mls.commit",
            json!({
                "group_id": "ak:mls_group:abc",
                "expected_prev_epoch": 0,
                "next_epoch": 1,
                "leader_actor_id": "did:web:alice.example",
                "commit_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "proposal_refs": [proposal_ref],
                "governance_binding": binding,
            }),
        ),
    );
    assert!(matches!(
        effect,
        ProjectionEffect::Mls(MlsEffect::CommitEpochAdvanced { new_epoch: 1, .. })
    ));
    assert!(state.pending_mls_removals.is_empty());
    let row = state
        .mls_commit_epochs
        .get(&mls_epoch_key(&realm_scope(), "ak:mls_group:abc").unwrap())
        .unwrap();
    assert_eq!(row.epoch, 1);
    assert!(row.covered_seals.iter().any(|seal| seal == revoke_event));
}

#[test]
fn realm_remove_commit_covers_all_pending_principals_in_one_rotation() {
    let mut state = ProjectionState::default();
    initialize_genesis(&mut state);
    let frontier = "ak:event:0196419b-0000-7000-8000-00000000d202";
    let targets = [
        (
            "did:web:bob.example",
            "ak:event:0196419b-0000-7000-8000-00000000d203",
        ),
        (
            "did:web:charlie.example",
            "ak:event:0196419b-0000-7000-8000-00000000d204",
        ),
    ];
    for (target, proposal_ref) in targets {
        state.pending_mls_removals.push(MlsRemoveObligation {
            realm_id: "ak:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
            circle_id: None,
            mls_group_ref: Some("ak:mls_group:abc".to_owned()),
            actor_id: target.to_owned(),
            device_id: None,
            membership_frontier: vec![frontier.to_owned()],
            trigger_membership: "realm_member_remove".to_owned(),
            triggered_at: Utc.timestamp_opt(500, 0).single().unwrap(),
        });
        assert!(matches!(
            apply_remove_proposal(
                &mut state,
                &op_at(
                    500,
                    "ak.mls.proposal",
                    json!({
                        "event_id": proposal_ref,
                        "mls_group_id": "ak:mls_group:abc",
                        "base_epoch": 0,
                        "proposal_type": "remove",
                        "proposal_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                        "target_principal_id": target,
                    }),
                )
            ),
            ProjectionEffect::Mls(MlsEffect::RemoveProposalRecorded { .. })
        ));
    }
    let mut binding = governance_binding(0);
    binding["membership_frontier"] = json!([frontier]);

    let effect = apply_commit_epoch(
        &mut state,
        &op_at(
            501,
            "ak.mls.commit",
            json!({
                "group_id": "ak:mls_group:abc",
                "expected_prev_epoch": 0,
                "next_epoch": 1,
                "leader_actor_id": "did:web:alice.example",
                "commit_digest": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "proposal_refs": targets.map(|(_, proposal_ref)| proposal_ref),
                "governance_binding": binding,
            }),
        ),
    );

    assert!(matches!(
        effect,
        ProjectionEffect::Mls(MlsEffect::CommitEpochAdvanced { new_epoch: 1, .. })
    ));
    assert!(state.pending_mls_removals.is_empty());
}

#[test]
fn commit_epoch_requires_covered_seals() {
    let mut state = ProjectionState::default();
    let effect = apply_commit_epoch(
        &mut state,
        &op_at(
            500,
            "ak.mls.commit",
            json!({
                "group_id": "ak:mls_group:abc",
                "expected_prev_epoch": 0,
                "next_epoch": 1,
                "leader_actor_id": "did:web:alice.example",
                "commit_bytes_b64": b64(b"opaque-commit-1"),
                "governance_binding": {
                    "binding_version": 1,
                    "encoding_profile": "cbor-deterministic-rfc8949-v1",
                    "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000000",
                    "effective_scope": {
                        "kind": "realm",
                        "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000000"
                    },
                    "mls_group_id": "ak:mls_group:abc",
                    "previous_epoch": 0,
                    "next_epoch": 1,
                    "policy_root": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                    "binding_profile": crate::kinds::MLS_GOVERNANCE_BINDING_FULL_PROFILE,
                    "reducer_profile": crate::kinds::MLS_REDUCER_PROFILE_V1
                },
            }),
        ),
    );
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { reason } if reason == "mls_governance_binding_membership_frontier_missing"
    ));
    assert!(state.mls_commit_epochs.is_empty());
}

#[test]
fn commit_epoch_requires_effective_genesis() {
    let mut state = ProjectionState::default();
    let effect = apply_commit_epoch(
        &mut state,
        &op_at(
            500,
            "ak.mls.commit",
            json!({
                "group_id": "ak:mls_group:abc",
                "expected_prev_epoch": 0,
                "next_epoch": 1,
                "leader_actor_id": "did:web:alice.example",
                "commit_bytes_b64": b64(b"opaque-commit-1"),
                "governance_binding": governance_binding(0),
            }),
        ),
    );
    assert!(
        matches!(effect, ProjectionEffect::Rejected { reason } if reason == "mls_genesis_missing")
    );
    assert!(state.mls_commit_epochs.is_empty());
}

#[test]
fn same_group_id_is_independent_across_effective_scopes() {
    let mut state = ProjectionState::default();
    let realm_scope = realm_scope();
    let circle_scope = circle_scope("ak:circle:0196419b-0000-7000-8000-000000000123");
    let realm_genesis = op_at(
        500,
        "ak.mls.genesis",
        genesis_payload("ak:mls_group:abc", realm_scope.clone()),
    );
    let circle_genesis = op_at(
        501,
        "ak.mls.genesis",
        genesis_payload("ak:mls_group:abc", circle_scope.clone()),
    );
    assert!(matches!(
        apply_group_genesis(&mut state, &realm_genesis),
        ProjectionEffect::Mls(MlsEffect::GroupGenesis { .. })
    ));
    assert!(matches!(
        apply_group_genesis(&mut state, &circle_genesis),
        ProjectionEffect::Mls(MlsEffect::GroupGenesis { .. })
    ));

    let realm_commit = op_at(
        502,
        "ak.mls.commit",
        json!({
            "group_id": "ak:mls_group:abc",
            "expected_prev_epoch": 0,
            "next_epoch": 1,
            "leader_actor_id": "did:web:alice.example",
            "commit_bytes_b64": b64(b"realm-commit"),
            "governance_binding": governance_binding_for_scope(
                0,
                "ak:mls_group:abc",
                realm_scope.clone()
            ),
        }),
    );
    assert!(matches!(
        apply_commit_epoch(&mut state, &realm_commit),
        ProjectionEffect::Mls(MlsEffect::CommitEpochAdvanced { new_epoch: 1, .. })
    ));

    assert_eq!(
        state
            .mls_commit_epochs
            .get(&mls_epoch_key(&realm_scope, "ak:mls_group:abc").unwrap())
            .unwrap()
            .epoch,
        1
    );
    assert_eq!(
        state
            .mls_commit_epochs
            .get(&mls_epoch_key(&circle_scope, "ak:mls_group:abc").unwrap())
            .unwrap()
            .epoch,
        0
    );
    assert_eq!(state.mls_commit_epochs.len(), 2);
}

#[test]
fn commit_epoch_stale_rejected() {
    let mut state = ProjectionState::default();
    initialize_genesis(&mut state);
    // Land epoch 1 first.
    let _ = apply_commit_epoch(
        &mut state,
        &op_at(
            600,
            "ak.mls.commit",
            json!({
                "group_id": "ak:mls_group:abc",
                "expected_prev_epoch": 0,
                "next_epoch": 1,
                "leader_actor_id": "did:web:alice.example",
                "commit_bytes_b64": b64(b"first"),
                "governance_binding": governance_binding(0),
            }),
        ),
    );

    // Replay the same commit (expected_prev_epoch=0) — must be rejected.
    let replay = apply_commit_epoch(
        &mut state,
        &op_at(
            601,
            "ak.mls.commit",
            json!({
                "group_id": "ak:mls_group:abc",
                "expected_prev_epoch": 0,
                "next_epoch": 1,
                "leader_actor_id": "did:web:alice.example",
                "commit_bytes_b64": b64(b"replay"),
                "governance_binding": governance_binding(0),
            }),
        ),
    );
    match replay {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, REASON_COMMIT_EPOCH_SKEW);
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
    // Stored epoch must still be 1 — the rejected replay didn't clobber it.
    assert_eq!(
        state
            .mls_commit_epochs
            .get(&mls_epoch_key(&realm_scope(), "ak:mls_group:abc").unwrap())
            .unwrap()
            .epoch,
        1
    );

    // A future-epoch commit (expected_prev_epoch=5) is also rejected.
    let leap = apply_commit_epoch(
        &mut state,
        &op_at(
            602,
            "ak.mls.commit",
            json!({
                "group_id": "ak:mls_group:abc",
                "expected_prev_epoch": 5,
                "next_epoch": 6,
                "leader_actor_id": "did:web:alice.example",
                "commit_bytes_b64": b64(b"leap"),
                "governance_binding": governance_binding(5),
            }),
        ),
    );
    assert!(
        matches!(leap, ProjectionEffect::Rejected { reason } if reason == REASON_COMMIT_EPOCH_SKEW)
    );
    assert_eq!(
        state
            .mls_commit_epochs
            .get(&mls_epoch_key(&realm_scope(), "ak:mls_group:abc").unwrap())
            .unwrap()
            .epoch,
        1
    );
}

fn commit_op(secs: i64, label: &[u8], extra: Value) -> Operation {
    let mut payload = json!({
        "group_id": "ak:mls_group:abc",
        "expected_prev_epoch": 0,
        "next_epoch": 1,
        "leader_actor_id": "did:web:alice.example",
        "commit_bytes_b64": b64(label),
        "governance_binding": governance_binding(0),
    });
    if let (Some(object), Some(extra)) = (payload.as_object_mut(), extra.as_object()) {
        for (key, value) in extra {
            object.insert(key.clone(), value.clone());
        }
    }
    op_at(secs, "ak.mls.commit", payload)
}

#[test]
fn commit_rejects_policy_root_mismatch() {
    let mut state = ProjectionState::default();
    initialize_genesis(&mut state);
    // A commit whose governance_binding.policy_root differs from the
    // genesis-locked root is rejected with governance_binding_mismatch.
    let mut binding = governance_binding(0);
    binding["policy_root"] =
        json!("sha256:9999999999999999999999999999999999999999999999999999999999999999");
    let effect = apply_commit_epoch(
        &mut state,
        &commit_op(
            500,
            b"forged-binding",
            json!({ "governance_binding": binding }),
        ),
    );
    match effect {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, arkret_wire::ReasonCode::GOVERNANCE_BINDING_MISMATCH);
        }
        other => panic!("expected governance_binding_mismatch, got {other:?}"),
    }
    // The epoch is untouched.
    assert_eq!(
        state
            .mls_commit_epochs
            .get(&mls_epoch_key(&realm_scope(), "ak:mls_group:abc").unwrap())
            .unwrap()
            .epoch,
        0
    );
}

#[test]
fn concurrent_commits_contend_then_resolve() {
    let mut state = ProjectionState::default();
    initialize_genesis(&mut state);
    let epoch_key = mls_epoch_key(&realm_scope(), "ak:mls_group:abc").unwrap();

    // First commit at base epoch 0 lands → epoch 1.
    assert!(matches!(
        apply_commit_epoch(&mut state, &commit_op(500, b"commit-a", json!({}))),
        ProjectionEffect::Mls(MlsEffect::CommitEpochAdvanced { new_epoch: 1, .. })
    ));

    // A racing commit that explicitly forks base epoch 0 with different
    // material drives covered_frontier_cell to ⊥ (CommitFrontierContested).
    // The effect reports the group's current (untouched) stored epoch — 1,
    // set by commit-a — because the contested-frontier mirror locates the
    // durable epoch row by that value; the contention does not rewind it to
    // the forked base.
    let contended = apply_commit_epoch(
        &mut state,
        &commit_op(501, b"commit-b", json!({ "concurrent_commit": true })),
    );
    assert!(matches!(
        contended,
        ProjectionEffect::Mls(MlsEffect::CommitFrontierContested { epoch: 1, .. })
    ));
    assert!(
        state
            .mls_commit_epochs
            .get(&epoch_key)
            .unwrap()
            .frontier_contested
    );
    // Epoch unchanged while contested.
    assert_eq!(state.mls_commit_epochs.get(&epoch_key).unwrap().epoch, 1);

    // A further racing commit at the contested base fails closed as
    // decryption_pending.
    let pending = apply_commit_epoch(
        &mut state,
        &commit_op(502, b"commit-c", json!({ "concurrent_commit": true })),
    );
    assert!(matches!(
        pending,
        ProjectionEffect::Rejected { reason } if reason == arkret_wire::ReasonCode::DECRYPTION_PENDING
    ));

    // A resolving commit at the current epoch advances and clears ⊥. The
    // governance binding's previous_epoch MUST match expected_prev_epoch
    // (the reducer cross-checks them), so advance the binding to epoch 1.
    let resolve = apply_commit_epoch(
        &mut state,
        &commit_op(
            503,
            b"commit-resolve",
            json!({
                "expected_prev_epoch": 1,
                "next_epoch": 2,
                "governance_binding": governance_binding(1),
            }),
        ),
    );
    assert!(matches!(
        resolve,
        ProjectionEffect::Mls(MlsEffect::CommitEpochAdvanced { new_epoch: 2, .. })
    ));
    let row = state.mls_commit_epochs.get(&epoch_key).unwrap();
    assert_eq!(row.epoch, 2);
    assert!(!row.frontier_contested);
}
