use super::*;

const REALM: &str = "ak:realm:AW2XhEBfjbMHqDBzRGwBXCaBZtSGUQTBe5CkC4pjU8O2";
const OWNER: &str = "did:web:owner.example";
const SUCCESSOR: &str = "did:web:successor.example";

fn operation(kind: impl AsRef<str>, payload: Value) -> Operation {
    arkret_event_draft::test_support::raw_projected_operation(
        arkret_identifiers::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
            .unwrap(),
        arkret_identifiers::RealmId::new(REALM).unwrap(),
        kind.as_ref(),
        payload,
    )
}

fn root_digest(state: &ProjectionState) -> String {
    arkret_canonical::canonical_sha256(&state.realm_authority_root(REALM).unwrap()).unwrap()
}

fn state_with_successor() -> ProjectionState {
    let mut state = ProjectionState::default();
    install_realm_authority_root(&mut state, REALM, OWNER);
    let now = chrono::Utc::now();
    state.members.insert(
        (REALM.to_owned(), SUCCESSOR.to_owned()),
        SolandMembershipState {
            member: SUCCESSOR.to_owned(),
            realm_id: REALM.to_owned(),
            state: "join".to_owned(),
            role: "member".to_owned(),
            delivery_status: Some("unroutable".to_owned()),
            recipient_service_id: None,
            recipient_service_resolution: None,
            membership_event_ref: None,
            delivery_binding_frontier: None,
            invited_at: None,
            joined_at: now,
            updated_at: now,
            reason: None,
        },
    );
    state
}

#[test]
fn transfer_changes_only_controller_and_epoch() {
    let mut state = state_with_successor();
    let before = state.realm_authority_root(REALM).unwrap();
    let effect = state.apply_realm_authority_transition(
        &operation(
            arkret_wire::EventKind::RealmOwnerTransfer,
            serde_json::json!({
                "realm_id": REALM,
                "expected_state_digest": root_digest(&state),
                "patch": {
                    "controller_id": SUCCESSOR,
                    "controller_epoch": 1
                },
                "successor_acceptance": { "proof": "accepted" },
                "sender": OWNER
            }),
        ),
        arkret_wire::EventKind::RealmOwnerTransfer,
    );
    assert!(matches!(effect, ProjectionEffect::RealmLifecycle { .. }));
    let after = state.realm_authority_root(REALM).unwrap();
    assert_eq!(after.controller_id.as_str(), SUCCESSOR);
    assert_eq!(after.controller_epoch, before.controller_epoch + 1);
    assert_eq!(after.authority_generation, before.authority_generation);
    assert_eq!(
        after.capability_action_registry_digest,
        before.capability_action_registry_digest
    );
}

#[test]
fn transfer_rejects_nonmember_and_stale_expected_state() {
    let mut state = state_with_successor();
    let expected = root_digest(&state);
    let nonmember = state.apply_realm_authority_transition(
        &operation(
            arkret_wire::EventKind::RealmOwnerTransfer,
            serde_json::json!({
                "realm_id": REALM,
                "expected_state_digest": expected,
                "patch": {
                    "controller_id": "did:web:outsider.example",
                    "controller_epoch": 1
                },
                "successor_acceptance": "accepted",
                "sender": OWNER
            }),
        ),
        arkret_wire::EventKind::RealmOwnerTransfer,
    );
    assert!(matches!(
        nonmember,
        ProjectionEffect::Rejected { reason }
            if reason == "realm_authority_controller_mismatch"
    ));

    let stale = state.apply_realm_authority_transition(
        &operation(
            arkret_wire::EventKind::RealmOwnerTransfer,
            serde_json::json!({
                "realm_id": REALM,
                "expected_state_digest": format!("sha256:{}", "0".repeat(64)),
                "patch": {
                    "controller_id": SUCCESSOR,
                    "controller_epoch": 1
                },
                "successor_acceptance": "accepted",
                "sender": OWNER
            }),
        ),
        arkret_wire::EventKind::RealmOwnerTransfer,
    );
    assert!(matches!(
        stale,
        ProjectionEffect::Rejected { reason } if reason == "realm_authority_root_conflict"
    ));
}

#[test]
fn reset_changes_only_generation_and_basis_update_fails_closed() {
    let mut state = state_with_successor();
    let before = state.realm_authority_root(REALM).unwrap();
    let reset = state.apply_realm_authority_transition(
        &operation(
            arkret_wire::EventKind::RealmAuthorityReset,
            serde_json::json!({
                "realm_id": REALM,
                "expected_state_digest": root_digest(&state),
                "patch": { "authority_generation": 1 },
                "destructive_confirmation": "ak.realm.authority.reset",
                "sender": OWNER
            }),
        ),
        arkret_wire::EventKind::RealmAuthorityReset,
    );
    assert!(matches!(reset, ProjectionEffect::RealmLifecycle { .. }));
    let after_reset = state.realm_authority_root(REALM).unwrap();
    assert_eq!(after_reset.controller_id, before.controller_id);
    assert_eq!(after_reset.controller_epoch, before.controller_epoch);
    assert_eq!(after_reset.authority_generation, 1);
    assert_eq!(
        after_reset.capability_action_registry_digest,
        before.capability_action_registry_digest
    );

    let rejected = state.apply_realm_authority_transition(
        &operation(
            arkret_wire::EventKind::RealmAuthorityBasisUpdate,
            serde_json::json!({
                "realm_id": REALM,
                "expected_state_digest": root_digest(&state),
                "patch": {
                    "capability_action_registry_digest": format!("sha256:{}", "1".repeat(64))
                },
                "sender": OWNER
            }),
        ),
        arkret_wire::EventKind::RealmAuthorityBasisUpdate,
    );
    assert!(matches!(
        rejected,
        ProjectionEffect::Rejected { reason }
            if reason == "capability_registry_basis_unavailable"
    ));
    assert_eq!(state.realm_authority_root(REALM).unwrap(), after_reset);
}
