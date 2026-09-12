use super::*;

const REALM: &str = "ak:realm:AW2XhEBfjbMHqDBzRGwBXCaBZtSGUQTBe5CkC4pjU8O2";
const OWNER: &str = "ak:did_core:web:owner.example";
const SUCCESSOR: &str = "ak:did_core:web:successor.example";

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
    let value =
        arkret_policy::realm_bootstrap::RealmAuthorityRootValue::genesis(account_actor(OWNER));
    state.realm_null_subject_cells.insert(
        (
            REALM.to_owned(),
            arkret_wire::REALM_AUTHORITY_ROOT_CELL.to_owned(),
        ),
        ResolvedCellState::Value(serde_json::to_value(value).unwrap()),
    );
    let now = chrono::Utc::now();
    let successor = account_actor_string(SUCCESSOR);
    state.members.insert(
        (REALM.to_owned(), successor.clone()),
        SolandMembershipState {
            member: successor,
            realm_id: REALM.to_owned(),
            state: "join".to_owned(),
            role: "member".to_owned(),
            membership_event_ref: None,
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
                    "controller_actor_id": account_actor(SUCCESSOR)
                },
                "successor_acceptance": { "proof": "accepted" },
                "sender": OWNER
            }),
        ),
        arkret_wire::EventKind::RealmOwnerTransfer,
    );
    assert!(matches!(effect, ProjectionEffect::RealmLifecycle { .. }));
    let after = state.realm_authority_root(REALM).unwrap();
    assert_eq!(
        after.controller_actor_id.signing_principal_id().as_str(),
        SUCCESSOR
    );
    assert_eq!(after.controller_epoch, before.controller_epoch + 1);
    assert_eq!(after.authority_generation, before.authority_generation);
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
                    "controller_actor_id": account_actor("ak:did_core:web:outsider.example")
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
                    "controller_actor_id": account_actor(SUCCESSOR)
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
fn reset_changes_only_generation() {
    let mut state = state_with_successor();
    let before = state.realm_authority_root(REALM).unwrap();
    let reset = state.apply_realm_authority_transition(
        &operation(
            arkret_wire::EventKind::RealmAuthorityReset,
            serde_json::json!({
                "realm_id": REALM,
                "expected_state_digest": root_digest(&state),
                "destructive_confirmation": "ak.realm.authority.reset",
                "sender": OWNER
            }),
        ),
        arkret_wire::EventKind::RealmAuthorityReset,
    );
    assert!(matches!(reset, ProjectionEffect::RealmLifecycle { .. }));
    let after_reset = state.realm_authority_root(REALM).unwrap();
    assert_eq!(after_reset.controller_actor_id, before.controller_actor_id);
    assert_eq!(after_reset.controller_epoch, before.controller_epoch);
    assert_eq!(after_reset.authority_generation, 1);
}

#[test]
fn successor_counter_overflow_fails_closed_without_mutation() {
    let mut state = state_with_successor();
    let mut root = state.realm_authority_root(REALM).unwrap();
    root.authority_generation = 9_007_199_254_740_991;
    state.realm_null_subject_cells.insert(
        (
            REALM.to_owned(),
            arkret_wire::REALM_AUTHORITY_ROOT_CELL.to_owned(),
        ),
        arkret_state::state_model::ResolvedCellState::Value(serde_json::to_value(&root).unwrap()),
    );
    let effect = state.apply_realm_authority_transition(
        &operation(
            arkret_wire::EventKind::RealmAuthorityReset,
            serde_json::json!({
                "realm_id": REALM,
                "expected_state_digest": root_digest(&state),
                "destructive_confirmation": "ak.realm.authority.reset",
                "sender": OWNER
            }),
        ),
        arkret_wire::EventKind::RealmAuthorityReset,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { reason } if reason == "reducer_projection_failed"
    ));
    assert_eq!(state.realm_authority_root(REALM).unwrap(), root);
}
