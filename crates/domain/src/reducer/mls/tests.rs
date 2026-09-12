use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_identifiers::{DeviceId, OperationId, RealmId};
use arkret_wire::{CORE_REDUCER_PROFILE, ProfileId};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{TimeZone, Utc};
use serde_json::json;

use super::*;
use crate::reducer::{MlsEffect, ProjectionEffect, ProjectionState};

fn fixture_actor(principal_id: &str) -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(principal_id.to_owned()).unwrap(),
        arkret_wire::DidCoreId::new("ak:did_core:web:station.example".to_owned()).unwrap(),
    ))
}

fn op_at(secs: i64, object_kind: impl AsRef<str>, mut payload: serde_json::Value) -> Operation {
    if let Some(payload) = payload.as_object_mut()
        && let Some(accepted_event_id) = payload.remove("accepted_event_id")
    {
        payload.insert("event_id".to_owned(), accepted_event_id);
    }
    let mut op = arkret_event_draft::test_support::raw_projected_operation(
        OperationId::new("ak:operation:0196419b-0000-7000-8000-000000000001")
            .expect("op id parses"),
        RealmId::new("ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1")
            .expect("realm id parses"),
        object_kind.as_ref(),
        payload,
    );
    op.created_at = Utc.timestamp_opt(secs, 0).single().expect("ts in range");
    op.context.producer_device_id = Some(
        DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001")
            .expect("fixture device id parses"),
    );
    op
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn realm_scope() -> Value {
    json!({
        "kind": "realm",
        "realm_id": "ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1"
    })
}

fn circle_scope(circle_id: &str) -> Value {
    json!({
        "kind": "circle",
        "realm_id": "ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1",
        "circle_id": circle_id
    })
}

fn scope_group(scope: &Value) -> String {
    serde_json::from_value::<arkret_wire::ScopeRef>(scope.clone())
        .unwrap()
        .canonical_mls_group_id()
        .unwrap()
}

fn realm_group() -> &'static str {
    static GROUP: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    GROUP.get_or_init(|| scope_group(&realm_scope())).as_str()
}

fn governance_binding_for_scope(previous_epoch: u64, effective_scope: Value) -> Value {
    json!({
        "binding_version": 1,
        "encoding_profile": "cbor-deterministic-rfc8949-v1",
        "effective_scope": effective_scope,
        "previous_epoch": previous_epoch,
        "next_epoch": previous_epoch + 1,
        "security_frontier_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "content_scheme": "mls_rfc9420",
        "binding_profile": ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
        "reducer_profile": CORE_REDUCER_PROFILE
    })
}

fn governance_binding(previous_epoch: u64) -> Value {
    governance_binding_for_scope(previous_epoch, realm_scope())
}

fn welcome_payload() -> Value {
    let keypackage_ref = "keypackage-01";
    let keypackage_digest =
        "sha256:5555555555555555555555555555555555555555555555555555555555555555";
    json!({
        "commit_ref": "ak:event:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
        "recipient_principal_id": "ak:did_core:web:bob.example",
        "recipient_device_id": "ak:device:0196419b-0000-7000-8000-000000000002",
        "ciphertext": b64(b"opaque-welcome-bytes"),
        "keypackage_ref": keypackage_ref,
        "claim_id": "claim-01",
        "claim_ref": {
            "claim_id": "claim-01",
            "keypackage_ref": keypackage_ref,
            "keypackage_digest": keypackage_digest,
            "capabilities_digest": "sha256:6666666666666666666666666666666666666666666666666666666666666666",
            "device_authorize_event_id": "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa"
        },
        "claim_envelope": {
            "keypackage_ref": keypackage_ref,
            "keypackage_digest": keypackage_digest,
            "intended_realm_id": "ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1",
            "claim_id": "claim-01",
            "requester_actor_id": arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                arkret_identifiers::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                arkret_identifiers::DidCoreId::new("ak:did_core:web:server.example").unwrap(),
            )),
            "requester_device_id": "ak:device:0196419b-0000-7000-8000-000000000001",
            "requester_device_authorize_event_id": "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa",
            "welcome_digest": arkret_canonical::sha256_digest(b"opaque-welcome-bytes"),
            "created_at": "2026-05-25T00:00:02.000Z",
            "signature": {
                "kid": "did:web:alice.example#device-0196419b-0000-7000-8000-000000000001",
                "signature_algorithm": "Ed25519",
                "sig": b64(b"welcome-claim-envelope-signature")
            }
        },
        "claim_receipt": {
            "claim_request_id": b64(b"welcome-claim-nonce-01-128-bit"),
            "request_digest": "sha256:7777777777777777777777777777777777777777777777777777777777777777",
            "claims_digest": "sha256:8888888888888888888888888888888888888888888888888888888888888888",
            "source_id": "ak:did_core:web:server.example",
            "destination_id": "ak:did_core:web:server.example",
            "request": {
                "claim_request_id": b64(b"welcome-claim-nonce-01-128-bit"),
                "target_account_id": {
                    "principal_id": "ak:did_core:web:bob.example",
                    "station_id": "ak:did_core:web:server.example"
                },
                "requester_account_id": {
                    "principal_id": "ak:did_core:web:alice.example",
                    "station_id": "ak:did_core:web:server.example"
                },
                "intended_realm_id": "ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1",
                "mls_group_id": realm_group(),
                "claim_purpose": "realm_membership",
                "required_capabilities": ["ak.content.v1"],
                "expires_at": "2026-05-25T00:05:00.000Z"
            },
            "claimed_at": "2026-05-25T00:00:30.000Z",
            "expires_at": "2026-05-25T00:05:00.000Z",
            "signature": {
                "kid": "did:web:server.example#notary-key",
                "signature_algorithm": "Ed25519",
                "sig": b64(b"claim-receipt-signature")
            }
        },
        "governance_binding": governance_binding(0),
        "expires_at": "2026-05-25T00:05:00.000Z"
    })
}

fn genesis_binding(effective_scope: Value) -> Value {
    let mut binding = governance_binding_for_scope(0, effective_scope);
    binding["next_epoch"] = json!(0);
    binding
}

fn genesis_payload(effective_scope: Value) -> Value {
    json!({
        "cipher_suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "group_info_ref": "ak:blob:sha256:3333333333333333333333333333333333333333333333333333333333333333",
        "ratchet_tree_ref": "ak:blob:sha256:4444444444444444444444444444444444444444444444444444444444444444",
        "governance_binding": genesis_binding(effective_scope),
        "created_at": "2026-05-25T00:00:00.000Z"
    })
}

fn initialize_genesis(state: &mut ProjectionState) -> String {
    let genesis = op_at(499, "ak.mls.genesis", genesis_payload(realm_scope()));
    let effect = apply_group_genesis(state, &genesis);
    assert!(matches!(
        effect,
        ProjectionEffect::Mls(MlsEffect::GroupGenesis { .. })
    ));
    genesis.context.event_id.to_string()
}

#[test]
fn welcome_fixture_is_the_current_closed_wire_contract() {
    serde_json::from_value::<arkret_models_collaboration::events_payloads::MlsWelcomePayload>(
        welcome_payload(),
    )
    .expect("Welcome fixture must deserialize through the current closed SDK model");
}

fn publish_projection(
    id: &str,
    actor: &str,
    device: &str,
    not_after: i64,
    last_resort: bool,
) -> MlsKeyPackagePublishProjection {
    let key_package_bytes = b"opaque-keypackage-bytes".to_vec();
    MlsKeyPackagePublishProjection {
        keypackage_id: id.to_owned(),
        keypackage_ref: id.to_owned(),
        keypackage_digest: arkret_canonical::sha256_digest(&key_package_bytes),
        owner_account_pk: 1,
        actor_id: fixture_actor(actor).to_string(),
        device_id: Some(device.to_owned()),
        lifetime: KeyPackageLifetimeProjection {
            not_before: 1,
            not_after,
        },
        key_package_bytes,
        capabilities: Vec::new(),
        last_resort,
        trust_anchor: MlsKeyPackagePublishTrustAnchor::DeviceAuthorize(
            "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa".to_owned(),
        ),
        created_at: 100,
    }
}

#[test]
fn keypackage_publish_then_claim_succeeds() {
    let mut state = ProjectionState::default();
    let publish = publish_projection(
        "keypackage-01",
        "ak:did_core:web:alice.example",
        "ak:device:alice-desktop",
        1_000_000,
        false,
    );
    let effect = apply_keypackage_upload_projection(&mut state, &publish);
    assert!(matches!(
        effect,
        ProjectionEffect::Mls(MlsEffect::KeyPackagePublished { ref keypackage_id, .. })
            if keypackage_id == "keypackage-01"
    ));
    assert!(
        state
            .mls_key_packages
            .get("keypackage-01")
            .unwrap()
            .claimed_by
            .is_none()
    );

    let claim = op_at(
        200,
        "ak.mls.keypackage",
        json!({
            "action": "claim",
            "keypackage_id": "keypackage-01",
            "group_id": realm_group(),
            "device_authorize_event_id": "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa"
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
            assert_eq!(keypackage_id, "keypackage-01");
            assert_eq!(group_id, realm_group());
            assert_eq!(claimed_at, 200);
        }
        other => panic!("expected KeyPackageClaimed, got {other:?}"),
    }
    let row = state.mls_key_packages.get("keypackage-01").unwrap();
    assert_eq!(row.claimed_by.as_deref(), Some(realm_group()));
    assert_eq!(row.claimed_at, Some(200));
    assert_eq!(row.consumed_at, None);
}

#[test]
fn keypackage_claim_twice_second_fails() {
    let mut state = ProjectionState::default();
    let publish = publish_projection(
        "keypackage-02",
        "ak:did_core:web:alice.example",
        "ak:device:alice-desktop",
        1_000_000,
        false,
    );
    let _ = apply_keypackage_upload_projection(&mut state, &publish);

    // First claim — wins.
    let claim1 = op_at(
        200,
        "ak.mls.keypackage",
        json!({
            "action": "claim",
            "keypackage_id": "keypackage-02",
            "group_id": "mls-group-first",
            "device_authorize_event_id": "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa"
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
            "keypackage_id": "keypackage-02",
            "group_id": "mls-group-second",
            "device_authorize_event_id": "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa"
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
    let row = state.mls_key_packages.get("keypackage-02").unwrap();
    assert_eq!(row.claimed_by.as_deref(), Some("mls-group-first"));
    assert_eq!(row.claimed_at, Some(200));
    assert_eq!(row.consumed_at, None);
}

#[test]
fn keypackage_claim_same_group_renews_instead_of_conflicting() {
    let mut state = ProjectionState::default();
    let publish = publish_projection(
        "keypackage-renew",
        "ak:did_core:web:alice.example",
        "ak:device:alice-desktop",
        1_000_000,
        false,
    );
    let _ = apply_keypackage_upload_projection(&mut state, &publish);

    let claim = |at: i64| {
        op_at(
            at,
            "ak.mls.keypackage",
            json!({
                "action": "claim",
                "keypackage_id": "keypackage-renew",
                "group_id": "mls-group-same",
                "device_authorize_event_id": "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa",
                "claim_expires_at_unix_ms": (at + 300) * 1000
            }),
        )
    };
    let e1 = apply_keypackage_claim(&mut state, &claim(200));
    assert!(matches!(
        e1,
        ProjectionEffect::Mls(MlsEffect::KeyPackageClaimed { .. })
    ));

    // Re-claim by the SAME group (interrupted materialization retry after the
    // claim window lapsed) is idempotent renewal, not a CAS conflict.
    let e2 = apply_keypackage_claim(&mut state, &claim(600));
    assert!(matches!(
        e2,
        ProjectionEffect::Mls(MlsEffect::KeyPackageClaimed { .. })
    ));
    let row = state.mls_key_packages.get("keypackage-renew").unwrap();
    assert_eq!(row.claimed_by.as_deref(), Some("mls-group-same"));
    assert_eq!(row.claimed_at, Some(600));
    assert_eq!(row.claim_expires_at_unix_ms, Some(900_000));

    // A different group is still rejected by the CAS.
    let other = op_at(
        700,
        "ak.mls.keypackage",
        json!({
            "action": "claim",
            "keypackage_id": "keypackage-renew",
            "group_id": "mls-group-other",
            "device_authorize_event_id": "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa"
        }),
    );
    match apply_keypackage_claim(&mut state, &other) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, REASON_KEYPACKAGE_ALREADY_CLAIMED);
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
}

#[test]
fn last_resort_keypackage_reuses_within_realm_only() {
    let mut state = ProjectionState::default();
    let publish = publish_projection(
        "keypackage-last-resort",
        "ak:did_core:web:alice.example",
        "ak:device:alice-desktop",
        1_000_000,
        true,
    );
    let _ = apply_keypackage_upload_projection(&mut state, &publish);

    for group_id in ["mls-group-first", "mls-group-second"] {
        let claim = op_at(
            200,
            "ak.mls.keypackage",
            json!({
                "action": "claim",
                "keypackage_id": "keypackage-last-resort",
                "group_id": group_id,
                "intended_realm_id": "ak:realm:alpha",
                "device_authorize_event_id": "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa"
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
        .get("keypackage-last-resort")
        .unwrap();
    assert!(row.claimed_by.is_none());
    assert!(row.consumed_at.is_none());
    assert_eq!(row.last_resort_realm_id.as_deref(), Some("ak:realm:alpha"));

    let cross_realm = op_at(
        201,
        "ak.mls.keypackage",
        json!({
            "action": "claim",
            "keypackage_id": "keypackage-last-resort",
            "group_id": "mls-group-other",
            "intended_realm_id": "ak:realm:beta",
            "device_authorize_event_id": "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa"
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
    let publish = publish_projection(
        "keypackage-revoked-last-resort",
        "ak:did_core:web:alice.example",
        "ak:device:alice-desktop",
        1_000_000,
        true,
    );
    let _ = apply_keypackage_upload_projection(&mut state, &publish);
    state
        .mls_key_packages
        .get_mut("keypackage-revoked-last-resort")
        .unwrap()
        .claimed_by = Some("revoked".to_owned());

    let claim = op_at(
        200,
        "ak.mls.keypackage",
        json!({
            "action": "claim",
            "keypackage_id": "keypackage-revoked-last-resort",
            "group_id": "mls-group-first",
            "intended_realm_id": "ak:realm:alpha",
            "device_authorize_event_id": "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa"
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
fn keypackage_claim_rejects_mismatched_device_authorization() {
    let mut state = ProjectionState::default();
    let publish = publish_projection(
        "keypackage-03",
        "ak:did_core:web:alice.example",
        "ak:device:alice-desktop",
        1_000_000,
        false,
    );
    let _ = apply_keypackage_upload_projection(&mut state, &publish);

    let claim = op_at(
        200,
        "ak.mls.keypackage",
        json!({
            "action": "claim",
            "keypackage_id": "keypackage-03",
            "group_id": realm_group(),
            "device_authorize_event_id": "ak:event:Af7kHhjQt9bXM9MVmV6uu7VNZY1P_sjoIUGS2rxLV8Qt"
        }),
    );
    let effect = apply_keypackage_claim(&mut state, &claim);
    match effect {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, arkret_wire::ReasonCode::CLAIM_GENERATION_MISMATCH);
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
    let row = state.mls_key_packages.get("keypackage-03").unwrap();
    assert!(row.claimed_by.is_none());
    assert_eq!(
        row.device_authorize_event_id.as_deref(),
        Some("ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa")
    );
}

#[test]
fn welcome_enqueue_then_fetch_marks_delivered() {
    let mut state = ProjectionState::default();
    let enqueue = op_at(300, "ak.mls.welcome", welcome_payload());
    let effect = apply_welcome_enqueue(&mut state, &enqueue);
    assert!(
        matches!(
            effect,
            ProjectionEffect::Mls(MlsEffect::WelcomeEnqueued { .. })
        ),
        "unexpected effect: {effect:?}"
    );

    let key = MlsWelcomeQueueKey::new(
        "ak:did_core:web:bob.example",
        "ak:device:0196419b-0000-7000-8000-000000000002",
    );
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

fn agent_bound_welcome_payload(authorize_event_id: &str) -> Value {
    let mut payload = welcome_payload();
    let claim_ref = payload
        .get_mut("claim_ref")
        .and_then(Value::as_object_mut)
        .unwrap();
    claim_ref.remove("device_authorize_event_id");
    claim_ref.insert(
        "agent_key_authorize_event_id".to_owned(),
        json!(authorize_event_id),
    );
    payload
}

#[test]
fn welcome_enqueue_rejects_inactive_agent_key_authorization() {
    let mut state = ProjectionState::default();
    let payload =
        agent_bound_welcome_payload("ak:event:Af7kHhjQt9bXM9MVmV6uu7VNZY1P_sjoIUGS2rxLV8Qt");
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
    let authorize_event_id = "ak:event:Ad0zM3xkilGkLE8K9IPZrZvbQzit2do46Wb6ECOCaX6k";
    let authorize = op_at(
        200,
        arkret_wire::EventKind::AgentKeyAuthorize,
        json!({
            "agent_id": "ak:did_core:web:bob.example",
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

    let payload = agent_bound_welcome_payload(authorize_event_id);
    let effect = apply_welcome_enqueue(&mut state, &op_at(300, "ak.mls.welcome", payload));
    assert!(
        matches!(
            effect,
            ProjectionEffect::Mls(MlsEffect::WelcomeEnqueued { .. })
        ),
        "unexpected effect: {effect:?}"
    );
}

#[test]
fn welcome_enqueue_accepts_requester_device_envelope_without_sender_device_id() {
    let mut state = ProjectionState::default();
    let mut payload = welcome_payload();
    let claim_ref = payload
        .get_mut("claim_ref")
        .and_then(Value::as_object_mut)
        .unwrap();
    claim_ref.insert(
        "device_authorize_event_id".to_owned(),
        json!("ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa"),
    );
    let claim_envelope = payload
        .get_mut("claim_envelope")
        .and_then(Value::as_object_mut)
        .unwrap();
    claim_envelope.insert(
        "requester_device_id".to_owned(),
        json!("ak:device:0196419b-0000-7000-8000-000000000001"),
    );
    claim_envelope.insert(
        "requester_device_authorize_event_id".to_owned(),
        json!("ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa"),
    );
    claim_envelope["signature"]["kid"] = json!("did:key:z6MkRequesterDevice#device");
    assert!(payload.get("sender_device_id").is_none());

    let enqueue = op_at(300, "ak.mls.welcome", payload);
    let effect = apply_welcome_enqueue(&mut state, &enqueue);

    assert!(
        matches!(
            effect,
            ProjectionEffect::Mls(MlsEffect::WelcomeEnqueued { .. })
        ),
        "unexpected effect: {effect:?}"
    );
}

#[test]
fn welcome_enqueue_rejects_mismatched_sender_device_id_when_present() {
    let mut state = ProjectionState::default();
    let mut payload = welcome_payload();
    let claim_ref = payload
        .get_mut("claim_ref")
        .and_then(Value::as_object_mut)
        .unwrap();
    claim_ref.insert(
        "device_authorize_event_id".to_owned(),
        json!("ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa"),
    );
    let claim_envelope = payload
        .get_mut("claim_envelope")
        .and_then(Value::as_object_mut)
        .unwrap();
    claim_envelope.insert(
        "requester_device_id".to_owned(),
        json!("ak:device:0196419b-0000-7000-8000-000000000003"),
    );
    claim_envelope["signature"]["kid"] = json!("did:key:z6MkRequesterDevice#device");
    payload["sender_device_id"] = json!("ak:device:0196419b-0000-7000-8000-000000000004");

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
    let mut payload = welcome_payload();
    let object = payload.as_object_mut().unwrap();
    object.remove("ciphertext");
    object.insert("ciphertext".to_owned(), Value::String(b64(raw_welcome)));
    payload["claim_envelope"]["welcome_digest"] =
        Value::String(arkret_canonical::sha256_digest(raw_welcome));

    let enqueue = op_at(300, "ak.mls.welcome", payload);
    let effect = apply_welcome_enqueue(&mut state, &enqueue);

    assert!(
        matches!(
            effect,
            ProjectionEffect::Mls(MlsEffect::WelcomeEnqueued { .. })
        ),
        "unexpected effect: {effect:?}"
    );
    let key = MlsWelcomeQueueKey::new(
        "ak:did_core:web:bob.example",
        "ak:device:0196419b-0000-7000-8000-000000000002",
    );
    let queue = state.mls_welcomes.get(&key).unwrap();
    assert_eq!(queue[0].welcome_bytes, raw_welcome);
    assert_eq!(queue[0].key_package_id, "keypackage-01");
}

#[test]
fn welcome_enqueue_rejects_retired_reference_carriers() {
    for retired_field in ["welcome_ref", "encrypted_welcome_ref"] {
        let mut state = ProjectionState::default();
        let mut payload = welcome_payload();
        payload[retired_field] = json!(
            "ak:blob:sha256:8888888888888888888888888888888888888888888888888888888888888888"
        );

        let effect = apply_welcome_enqueue(&mut state, &op_at(300, "ak.mls.welcome", payload));
        assert!(matches!(
            effect,
            ProjectionEffect::Rejected { reason } if reason == "mls_welcome_payload_invalid"
        ));
        assert!(state.mls_welcomes.is_empty());
    }
}

#[test]
fn welcome_enqueue_rejects_retired_claim_envelope_nonce() {
    let mut state = ProjectionState::default();
    let mut payload = welcome_payload();
    payload["claim_envelope"]["nonce"] = json!("AAAAAAAAAAAAAAAAAAAAAA");

    let effect = apply_welcome_enqueue(&mut state, &op_at(300, "ak.mls.welcome", payload));
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { reason } if reason == "mls_welcome_payload_invalid"
    ));
    assert!(state.mls_welcomes.is_empty());
}

#[test]
fn welcome_enqueue_rejects_noncanonical_base64url_without_utf8_fallback() {
    for invalid_ciphertext in ["AA==", "AB", "not base64url"] {
        let mut state = ProjectionState::default();
        let mut payload = welcome_payload();
        payload["ciphertext"] = json!(invalid_ciphertext);

        let effect = apply_welcome_enqueue(&mut state, &op_at(300, "ak.mls.welcome", payload));
        assert!(matches!(
            effect,
            ProjectionEffect::Rejected { reason } if reason == "mls_welcome_payload_invalid"
        ));
        assert!(state.mls_welcomes.is_empty());
    }
}

#[test]
fn welcome_enqueue_rejects_plaintext_identity_metadata() {
    let mut state = ProjectionState::default();
    let mut payload = welcome_payload();
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
    let mut payload = welcome_payload();
    payload.as_object_mut().unwrap().remove("claim_envelope");
    let enqueue = op_at(300, "ak.mls.welcome", payload);
    let effect = apply_welcome_enqueue(&mut state, &enqueue);
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { reason } if reason == "mls_welcome_payload_invalid"
    ));
    assert!(state.mls_welcomes.is_empty());
}

#[test]
fn commit_epoch_in_order_succeeds() {
    let mut state = ProjectionState::default();
    let genesis_event_ref = initialize_genesis(&mut state);

    // First commit after genesis — expected_prev_epoch=0 → epoch=1.
    let c1 = op_at(
        500,
        "ak.mls.commit",
        json!({
            "proposal_refs": [],
            "base_epoch_ref": genesis_event_ref,
            "commit_bytes_b64": b64(b"opaque-commit-1"),
            "governance_binding": governance_binding(0),
        }),
    );
    let e1 = apply_commit_epoch(&mut state, &c1);
    match e1 {
        ProjectionEffect::Mls(MlsEffect::CommitEpochAdvanced {
            previous_epoch,
            new_epoch,
            ..
        }) => {
            assert_eq!(previous_epoch, 0);
            assert_eq!(new_epoch, 1);
        }
        other => panic!("expected CommitEpochAdvanced, got {other:?}"),
    }

    // Second commit — expected_prev_epoch=1 → epoch=2.
    let c2 = op_at(
        501,
        "ak.mls.commit",
        json!({
            "proposal_refs": [],
            "base_epoch_ref": c1.context.event_id,
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
            .get(&mls_epoch_key(&realm_scope(), realm_group()).unwrap())
            .unwrap(),
        &MlsCommitEpoch {
            group_id: realm_group().to_owned(),
            effective_scope: realm_scope(),
            epoch: 2,
            leader_actor_id: c2.context.sender.to_string(),
            creator_device_id: "ak:device:0196419b-0000-7000-8000-000000000001".to_owned(),
            genesis_event_ref,
            committed_at: 501,
            governance_binding: governance_binding(1),
            accepted_commit_digest: Some(arkret_canonical::sha256_digest(b"opaque-commit-2")),
            accepted_commit_ref: Some(c2.context.event_id.to_string()),
        }
    );
}

#[test]
fn commit_epoch_rejects_content_scheme_drift_from_genesis() {
    let mut state = ProjectionState::default();
    let mut genesis = genesis_payload(realm_scope());
    genesis["governance_binding"]["content_scheme"] = json!("mls_exporter_aead_v1");
    genesis["governance_binding"]["durability_policy"] = json!("none");
    assert!(matches!(
        apply_group_genesis(&mut state, &op_at(499, "ak.mls.genesis", genesis)),
        ProjectionEffect::Mls(MlsEffect::GroupGenesis { .. })
    ));

    let effect = apply_commit_epoch(
        &mut state,
        &op_at(
            500,
            "ak.mls.commit",
            json!({
            "proposal_refs": [],
            "base_epoch_ref": "ak:event:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
                "commit_bytes_b64": b64(b"scheme-drift-commit"),
                "governance_binding": governance_binding(0),
            }),
        ),
    );

    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { reason }
            if reason == arkret_wire::ReasonCode::MLS_CONTENT_SCHEME_IMMUTABLE
    ));
    let row = state
        .mls_commit_epochs
        .get(&mls_epoch_key(&realm_scope(), realm_group()).unwrap())
        .expect("genesis row remains accepted");
    assert_eq!(row.epoch, 0);
    assert_eq!(
        row.governance_binding["content_scheme"],
        "mls_exporter_aead_v1"
    );
    assert_eq!(row.governance_binding["durability_policy"], "none");
}

#[test]
fn remove_commit_covering_device_revoke_advances_and_clears_obligation() {
    let mut state = ProjectionState::default();
    initialize_genesis(&mut state);
    let revoke_event = "ak:event:AafCYpmebjO4g4U44BB6290CiEHtsdaspFppDQcaFrjv";
    let proposal_ref = "ak:event:AQ_AVnBjhDRbcSwwa5FDgoABRUHUthd1DA4Y2aDKTfvV";
    state.pending_mls_removals.push(MlsRemoveObligation {
        realm_id: "ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1".to_owned(),
        circle_id: None,
        mls_group_ref: Some(realm_group().to_owned()),
        actor_id: fixture_actor("ak:did_core:web:alice.example").to_string(),
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
                    "mls_group_id": realm_group(),
                    "base_epoch": 0,
                    "proposal_type": "remove",
                    "proposal_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "target_actor_id": fixture_actor("ak:did_core:web:alice.example"),
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
            "base_epoch_ref": "ak:event:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
                "commit_bytes_b64": b64(b"remove-commit"),
                "proposal_refs": [proposal_ref],
                "governance_binding": governance_binding(0),
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
        .get(&mls_epoch_key(&realm_scope(), realm_group()).unwrap())
        .unwrap();
    assert_eq!(row.epoch, 1);
}

#[test]
fn realm_remove_commit_covers_all_pending_principals_in_one_rotation() {
    let mut state = ProjectionState::default();
    initialize_genesis(&mut state);
    let frontier = "ak:event:Aenxxuj1jGJoLHv5bnuHV1awQ_gKwK2elnGlpIES2Nu4";
    let targets = [
        (
            "ak:did_core:web:bob.example",
            "ak:event:AQnbGFYH6ZHKM4sQnK_8kg0bmuqX4U5wGRs8Vbxp3u9h",
        ),
        (
            "ak:did_core:web:charlie.example",
            "ak:event:ARbbiTuRZqECoqMK9qlbv1t2-8v9s_6fOm2bY2rAJt6n",
        ),
    ];
    for (target, proposal_ref) in targets {
        state.pending_mls_removals.push(MlsRemoveObligation {
            realm_id: "ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1".to_owned(),
            circle_id: None,
            mls_group_ref: Some(realm_group().to_owned()),
            actor_id: fixture_actor(target).to_string(),
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
                        "mls_group_id": realm_group(),
                        "base_epoch": 0,
                        "proposal_type": "remove",
                        "proposal_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                        "target_actor_id": fixture_actor(target),
                    }),
                )
            ),
            ProjectionEffect::Mls(MlsEffect::RemoveProposalRecorded { .. })
        ));
    }
    let effect = apply_commit_epoch(
        &mut state,
        &op_at(
            501,
            "ak.mls.commit",
            json!({
            "base_epoch_ref": "ak:event:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
                "commit_bytes_b64": b64(b"remove-all-commit"),
                "proposal_refs": targets.map(|(_, proposal_ref)| proposal_ref),
                "governance_binding": governance_binding(0),
            }),
        ),
    );

    assert!(matches!(
        effect,
        ProjectionEffect::Mls(MlsEffect::CommitEpochAdvanced { new_epoch: 1, .. })
    ));
    assert!(state.pending_mls_removals.is_empty());
}

/// `event-payload.schema.json#/$defs/mls_commit_payload` is a closed object
/// with no committer field, and `encryption-and-audit.md` §5.6 puts the
/// committing identity on the signed Event envelope. A payload carrying only
/// the registered fields MUST therefore be accepted, and the epoch row MUST
/// record the envelope author.
#[test]
fn schema_exact_commit_without_a_payload_committer_is_accepted() {
    let mut state = ProjectionState::default();
    initialize_genesis(&mut state);
    let commit = op_at(
        500,
        "ak.mls.commit",
        json!({
            "base_epoch_ref": "ak:event:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
            "proposal_refs": [],
            "commit_bytes_b64": b64(b"schema-exact-commit"),
            "governance_binding": governance_binding(0),
        }),
    );
    let committer = commit.context.sender.to_string();
    assert!(matches!(
        apply_commit_epoch(&mut state, &commit),
        ProjectionEffect::Mls(MlsEffect::CommitEpochAdvanced { new_epoch: 1, .. })
    ));
    let row = state
        .mls_commit_epochs
        .get(&mls_epoch_key(&realm_scope(), realm_group()).unwrap())
        .expect("epoch row advanced");
    assert_eq!(row.epoch, 1);
    assert_eq!(row.leader_actor_id, committer);
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
            "proposal_refs": [],
            "base_epoch_ref": "ak:event:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
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
fn scope_derived_groups_advance_independently() {
    let mut state = ProjectionState::default();
    let realm_scope = realm_scope();
    let circle_scope = circle_scope("ak:circle:AYeXMA_Q84Rr4i1LlwOPbkhybNKeukU9ehFA-XsuidnF");
    let realm_genesis = op_at(500, "ak.mls.genesis", genesis_payload(realm_scope.clone()));
    let circle_genesis = op_at(501, "ak.mls.genesis", genesis_payload(circle_scope.clone()));
    assert_ne!(scope_group(&realm_scope), scope_group(&circle_scope));
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
            "proposal_refs": [],
            "base_epoch_ref": "ak:event:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
            "commit_bytes_b64": b64(b"realm-commit"),
            "governance_binding": governance_binding_for_scope(
                0,
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
            .get(&mls_epoch_key(&realm_scope, realm_group()).unwrap())
            .unwrap()
            .epoch,
        1
    );
    assert_eq!(
        state
            .mls_commit_epochs
            .get(&mls_epoch_key(&circle_scope, &scope_group(&circle_scope)).unwrap())
            .unwrap()
            .epoch,
        0
    );
    assert_eq!(state.mls_commit_epochs.len(), 2);
}

#[test]
fn commit_future_epoch_rejected() {
    let mut state = ProjectionState::default();
    initialize_genesis(&mut state);
    // A future-epoch commit (expected_prev_epoch=5) is rejected.
    let leap = apply_commit_epoch(
        &mut state,
        &op_at(
            602,
            "ak.mls.commit",
            json!({
            "proposal_refs": [],
            "base_epoch_ref": "ak:event:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
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
            .get(&mls_epoch_key(&realm_scope(), realm_group()).unwrap())
            .unwrap()
            .epoch,
        0
    );
}

fn commit_op(secs: i64, label: &[u8], extra: Value) -> Operation {
    let mut payload = json!({
            "proposal_refs": [],
            "base_epoch_ref": "ak:event:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
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
fn commit_rejects_retired_binding_fields() {
    let mut state = ProjectionState::default();
    initialize_genesis(&mut state);
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
            assert_eq!(reason, "mls_commit_payload_invalid");
        }
        other => panic!("expected invalid closed Commit payload, got {other:?}"),
    }
    assert_eq!(
        state
            .mls_commit_epochs
            .get(&mls_epoch_key(&realm_scope(), realm_group()).unwrap())
            .unwrap()
            .epoch,
        0
    );
}

#[test]
fn stale_base_competitors_never_change_the_accepted_epoch() {
    let mut state = ProjectionState::default();
    let genesis_ref = initialize_genesis(&mut state);
    let epoch_key = mls_epoch_key(&realm_scope(), realm_group()).unwrap();
    let first = commit_op(500, b"commit-a", json!({"base_epoch_ref": genesis_ref}));
    assert!(matches!(
        apply_commit_epoch(&mut state, &first),
        ProjectionEffect::Mls(MlsEffect::CommitEpochAdvanced { new_epoch: 1, .. })
    ));
    let accepted = state.mls_commit_epochs[&epoch_key].clone();
    let accepted_refs = state.accepted_mls_commit_refs.clone();
    for (time, bytes) in [(501, b"commit-b".as_slice()), (502, b"commit-c".as_slice())] {
        let competing = commit_op(time, bytes, json!({"base_epoch_ref": genesis_ref}));
        assert!(matches!(apply_commit_epoch(&mut state, &competing),
            ProjectionEffect::Rejected { reason } if reason == REASON_COMMIT_EPOCH_SKEW));
        assert_eq!(state.mls_commit_epochs[&epoch_key], accepted);
        assert_eq!(state.accepted_mls_commit_refs, accepted_refs);
    }
    let successor = commit_op(
        503,
        b"commit-next",
        json!({
            "base_epoch_ref": first.context.event_id,
            "governance_binding": governance_binding(1),
        }),
    );
    assert!(matches!(
        apply_commit_epoch(&mut state, &successor),
        ProjectionEffect::Mls(MlsEffect::CommitEpochAdvanced { new_epoch: 2, .. })
    ));
    let current = &state.mls_commit_epochs[&epoch_key];
    assert_eq!(current.epoch, 2);
    assert_eq!(
        current.accepted_commit_digest.as_deref(),
        Some(arkret_canonical::sha256_digest(b"commit-next").as_str())
    );
    assert_eq!(
        current.accepted_commit_ref.as_deref(),
        Some(successor.context.event_id.as_str())
    );
}
