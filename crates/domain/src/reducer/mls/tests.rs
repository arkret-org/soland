use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_identifiers::{DeviceId, OperationId, RealmId};
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
    // The binding is the closed SDK shape: no content scheme, no encoding or
    // reducer profile, and no security frontier digest. The accepted
    // `RealmCommit` is the ordering and governance authority.
    json!({
        "effective_scope": effective_scope,
        "previous_epoch": previous_epoch,
        "next_epoch": previous_epoch + 1,
        "key_access_revision": 0
    })
}

fn governance_binding(previous_epoch: u64) -> Value {
    governance_binding_for_scope(previous_epoch, realm_scope())
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

const DEVICE_AUTHORIZE: &str = "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa";

fn claim_projection(id: &str, group_id: &str, claimed_at: i64) -> MlsKeyPackageClaimProjection {
    MlsKeyPackageClaimProjection {
        keypackage_id: id.to_owned(),
        group_id: group_id.to_owned(),
        intended_realm_id: None,
        trust_binding: KeyPackageTrustBinding::device_authorize(DEVICE_AUTHORIZE.to_owned()),
        claim_expires_at_unix_ms: None,
        claimed_at,
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

    let claim = claim_projection("keypackage-01", realm_group(), 200);
    match apply_keypackage_claim_projection(&mut state, &claim) {
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

    // First claim wins.
    let e1 = apply_keypackage_claim_projection(
        &mut state,
        &claim_projection("keypackage-02", "mls-group-first", 200),
    );
    assert!(matches!(
        e1,
        ProjectionEffect::Mls(MlsEffect::KeyPackageClaimed { .. })
    ));

    // Second claim must be rejected by the CAS.
    let e2 = apply_keypackage_claim_projection(
        &mut state,
        &claim_projection("keypackage-02", "mls-group-second", 201),
    );
    match e2 {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, REASON_KEYPACKAGE_ALREADY_CLAIMED);
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
    // The winning group must still own the row: a loser never overwrites.
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

    let claim = |at: i64| MlsKeyPackageClaimProjection {
        claim_expires_at_unix_ms: Some((at + 300) * 1000),
        ..claim_projection("keypackage-renew", "mls-group-same", at)
    };
    let e1 = apply_keypackage_claim_projection(&mut state, &claim(200));
    assert!(matches!(
        e1,
        ProjectionEffect::Mls(MlsEffect::KeyPackageClaimed { .. })
    ));

    // Re-claim by the SAME group (an interrupted materialization retrying after
    // the claim window lapsed) is idempotent renewal, not a CAS conflict.
    let e2 = apply_keypackage_claim_projection(&mut state, &claim(600));
    assert!(matches!(
        e2,
        ProjectionEffect::Mls(MlsEffect::KeyPackageClaimed { .. })
    ));
    let row = state.mls_key_packages.get("keypackage-renew").unwrap();
    assert_eq!(row.claimed_by.as_deref(), Some("mls-group-same"));
    assert_eq!(row.claimed_at, Some(600));
    assert_eq!(row.claim_expires_at_unix_ms, Some(900_000));

    // A different group is still rejected by the CAS.
    match apply_keypackage_claim_projection(
        &mut state,
        &claim_projection("keypackage-renew", "mls-group-other", 700),
    ) {
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
        let claim = MlsKeyPackageClaimProjection {
            intended_realm_id: Some("ak:realm:alpha".to_owned()),
            ..claim_projection("keypackage-last-resort", group_id, 200)
        };
        assert!(matches!(
            apply_keypackage_claim_projection(&mut state, &claim),
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

    let cross_realm = MlsKeyPackageClaimProjection {
        intended_realm_id: Some("ak:realm:beta".to_owned()),
        ..claim_projection("keypackage-last-resort", "mls-group-other", 201)
    };
    match apply_keypackage_claim_projection(&mut state, &cross_realm) {
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

    let claim = MlsKeyPackageClaimProjection {
        intended_realm_id: Some("ak:realm:alpha".to_owned()),
        ..claim_projection("keypackage-revoked-last-resort", "mls-group-first", 200)
    };
    match apply_keypackage_claim_projection(&mut state, &claim) {
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

    let claim = MlsKeyPackageClaimProjection {
        trust_binding: KeyPackageTrustBinding::device_authorize(
            "ak:event:Af7kHhjQt9bXM9MVmV6uu7VNZY1P_sjoIUGS2rxLV8Qt".to_owned(),
        ),
        ..claim_projection("keypackage-03", realm_group(), 200)
    };
    match apply_keypackage_claim_projection(&mut state, &claim) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, arkret_wire::ReasonCode::CLAIM_GENERATION_MISMATCH);
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
    let row = state.mls_key_packages.get("keypackage-03").unwrap();
    assert!(row.claimed_by.is_none());
    assert_eq!(
        row.device_authorize_event_id.as_deref(),
        Some(DEVICE_AUTHORIZE)
    );
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
fn a_second_genesis_cannot_reactivate_an_already_activated_scope() {
    // A scope is plaintext until its own `ak.mls.genesis` is accepted, and that
    // acceptance is irreversible: there is no protocol path back to plaintext
    // and no second activation with different parameters.
    let mut state = ProjectionState::default();
    assert!(matches!(
        apply_group_genesis(
            &mut state,
            &op_at(499, "ak.mls.genesis", genesis_payload(realm_scope()))
        ),
        ProjectionEffect::Mls(MlsEffect::GroupGenesis { .. })
    ));

    let effect = apply_group_genesis(
        &mut state,
        &op_at(500, "ak.mls.genesis", genesis_payload(realm_scope())),
    );
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { reason }
            if reason == arkret_wire::ReasonCode::MLS_ACTIVATION_IRREVERSIBLE
    ));
    let row = state
        .mls_commit_epochs
        .get(&mls_epoch_key(&realm_scope(), realm_group()).unwrap())
        .expect("the first activation remains accepted");
    assert_eq!(row.epoch, 0);
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
    // The remove Proposal travels inline in the opaque Commit body, so the
    // Station never sees it as its own Event: the accepted Commit alone has to
    // discharge the obligation.
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
