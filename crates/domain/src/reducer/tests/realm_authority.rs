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
    arkret_canonical::canonical_sha256(state.realm_authority_root(REALM).unwrap()).unwrap()
}

fn controller(state: &ProjectionState) -> arkret_wire::ActorId {
    serde_json::from_value(
        state
            .realm_authority_root(REALM)
            .unwrap()
            .get("controller_actor_id")
            .unwrap()
            .clone(),
    )
    .unwrap()
}

fn controller_epoch(state: &ProjectionState) -> u64 {
    state
        .realm_authority_root(REALM)
        .unwrap()
        .get("controller_epoch")
        .and_then(Value::as_u64)
        .unwrap()
}

fn authority_generation(state: &ProjectionState) -> u64 {
    state
        .realm_authority_root(REALM)
        .unwrap()
        .get("authority_generation")
        .and_then(Value::as_u64)
        .unwrap()
}

fn state_with_successor() -> ProjectionState {
    let mut state = ProjectionState::default();
    state.set_realm_facet(
        REALM,
        facet::REALM_AUTHORITY_ROOT,
        serde_json::json!({
            "controller_actor_id": account_actor(OWNER),
            "controller_epoch": 0,
            "governance_station_id": FIXTURE_GOVERNANCE_STATION,
            "authority_generation": 0,
        }),
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
    let before_epoch = controller_epoch(&state);
    let before_generation = authority_generation(&state);
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
    assert_eq!(
        controller(&state).signing_principal_id().as_str(),
        SUCCESSOR
    );
    assert_eq!(controller_epoch(&state), before_epoch + 1);
    assert_eq!(authority_generation(&state), before_generation);
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
    let before_controller = controller(&state);
    let before_epoch = controller_epoch(&state);
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
    assert_eq!(controller(&state), before_controller);
    assert_eq!(controller_epoch(&state), before_epoch);
    assert_eq!(authority_generation(&state), 1);
}

#[test]
fn successor_counter_overflow_fails_closed_without_mutation() {
    let mut state = state_with_successor();
    let mut root = state.realm_authority_root(REALM).unwrap().clone();
    root["authority_generation"] = serde_json::json!(9_007_199_254_740_991u64);
    state.set_realm_facet(REALM, facet::REALM_AUTHORITY_ROOT, root.clone());
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
    assert_eq!(state.realm_authority_root(REALM), Some(&root));
}
