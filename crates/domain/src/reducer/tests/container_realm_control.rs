use super::*;

const REALM_ID: &str = "ak:realm:01904100-0000-8000-8000-cfc039892036";
const CONTAINER_A: &str = "ak:morph:01904100-0000-8000-8000-000000000101";
const CONTAINER_B: &str = "ak:morph:01904100-0000-8000-8000-000000000102";
const ITEM_A: &str = "ak:morph:01904100-0000-8000-8000-000000000201";
const ITEM_B: &str = "ak:morph:01904100-0000-8000-8000-000000000202";

fn cell_digest(value: &Value) -> String {
    let bytes = arkret_canonical::canonical_json_bytes(value).unwrap();
    arkret_canonical::sha256_digest(bytes)
}

fn position_cell(container_ref: &str, item_ref: &str) -> CellRef {
    let subject = arkret_wire::composite_subject(&[container_ref, item_ref]).unwrap();
    CellRef::new(format!(
        "ak:cell:ak.component.container.position.v1:{subject}"
    ))
    .unwrap()
}

fn order_cell(container_ref: &str) -> CellRef {
    CellRef::new(format!(
        "ak:cell:ak.component.container.order.v1:{container_ref}"
    ))
    .unwrap()
}

#[test]
fn container_move_uses_canonical_position_cell_and_enforces_cas() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let first = state.apply(
        &make_operation(
            arkret_wire::EventKind::CONTAINER_MOVE_ITEM,
            REALM_ID,
            serde_json::json!({
                "item_ref": ITEM_A,
                "container_ref": CONTAINER_A,
                "relation_kind": "contains",
                "rank": "A"
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        first,
        ProjectionEffect::ContainerPositionProjected { ref container_ref, ref item_ref }
            if container_ref == CONTAINER_A && item_ref == ITEM_A
    ));

    let cell_id = position_cell(CONTAINER_A, ITEM_A);
    let current = state.cell_value(&cell_id).cloned().unwrap();
    let rejected = state.apply(
        &make_operation(
            arkret_wire::EventKind::CONTAINER_MOVE_ITEM,
            REALM_ID,
            serde_json::json!({
                "item_ref": ITEM_A,
                "container_ref": CONTAINER_A,
                "relation_kind": "contains",
                "rank": "B",
                "expected_position_digest": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        rejected,
        ProjectionEffect::Rejected { reason } if reason == arkret_wire::ErrorCode::CAS_CONFLICT
    ));
    assert_eq!(state.cell_value(&cell_id), Some(&current));

    let accepted = state.apply(
        &make_operation(
            arkret_wire::EventKind::CONTAINER_MOVE_ITEM,
            REALM_ID,
            serde_json::json!({
                "item_ref": ITEM_A,
                "from_container_ref": CONTAINER_A,
                "container_ref": CONTAINER_B,
                "relation_kind": "contains",
                "rank": "B"
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        accepted,
        ProjectionEffect::ContainerPositionProjected { .. }
    ));
    assert!(state.cell(&cell_id).is_none());
    assert_eq!(
        state
            .cell_value(&position_cell(CONTAINER_B, ITEM_A))
            .and_then(|value| value.get("rank"))
            .and_then(Value::as_str),
        Some("B")
    );
}

#[test]
fn container_rebalance_is_atomic_against_order_digest() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let initial_digest = cell_digest(&Value::Null);
    let accepted = state.apply(
        &make_operation(
            arkret_wire::EventKind::CONTAINER_REBALANCE,
            REALM_ID,
            serde_json::json!({
                "container_ref": CONTAINER_A,
                "relation_kind": "contains",
                "positions": [
                    {"item_ref": ITEM_A, "rank": "A"},
                    {"item_ref": ITEM_B, "rank": "B"}
                ],
                "expected_order_digest": initial_digest
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        accepted,
        ProjectionEffect::ContainerOrderProjected {
            position_count: 2,
            ..
        }
    ));
    let cell_id = order_cell(CONTAINER_A);
    let current = state.cell_value(&cell_id).cloned().unwrap();

    let rejected = state.apply(
        &make_operation(
            arkret_wire::EventKind::CONTAINER_REBALANCE,
            REALM_ID,
            serde_json::json!({
                "container_ref": CONTAINER_A,
                "relation_kind": "contains",
                "positions": [{"item_ref": ITEM_A, "rank": "Z"}],
                "expected_order_digest": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        rejected,
        ProjectionEffect::Rejected { reason } if reason == arkret_wire::ErrorCode::CAS_CONFLICT
    ));
    assert_eq!(state.cell_value(&cell_id), Some(&current));
}

#[test]
fn realm_notary_and_digest_suite_transition_project_control_cells() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    state.apply(
        &make_operation(
            arkret_wire::EventKind::REALM_CREATE,
            REALM_ID,
            serde_json::json!({
                "object": {
                    "created_by": "did:web:alice.example",
                    "title": "Control Realm",
                    "digest_algorithm": "sha256",
                    "capability_action_registry_digest": arkret_policy::current_capability_action_registry_digest().unwrap(),
                    "notary": {"kind": "single_did", "did": "did:web:notary.example"}
                }
            }),
        ),
        &hlc,
    );

    let notary = state.apply(
        &make_operation(
            arkret_wire::EventKind::REALM_NOTARY,
            REALM_ID,
            serde_json::json!({
                "realm_id": REALM_ID,
                "notary": {"kind": "single_did", "did": "did:web:new-notary.example"}
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        notary,
        ProjectionEffect::RealmNotaryProjected { .. }
    ));
    assert_eq!(
        state
            .realm_notary_cells
            .get(REALM_ID)
            .and_then(|state| match state {
                CellState::Value(value) => Some(value),
                CellState::Bottom(_) => None,
            })
            .and_then(|value| value.get("did"))
            .and_then(Value::as_str),
        Some("did:web:new-notary.example")
    );

    let transition = state.apply(
        &make_operation(
            arkret_wire::EventKind::REALM_DIGEST_SUITE_TRANSITION,
            REALM_ID,
            serde_json::json!({
                "from_digest_algorithm": "sha256",
                "to_digest_algorithm": "blake3",
                "transition_snapshot_ref": "ak:snapshot:01904100-0000-7000-8000-000000000301",
                "snapshot_commitment": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        transition,
        ProjectionEffect::RealmDigestSuiteTransitionProjected { ref digest_algorithm, .. }
            if digest_algorithm == "blake3"
    ));
    assert_eq!(
        state.realm_digest_algorithm(REALM_ID).as_deref(),
        Some("blake3")
    );

    let downgrade = state.apply(
        &make_operation(
            arkret_wire::EventKind::REALM_DIGEST_SUITE_TRANSITION,
            REALM_ID,
            serde_json::json!({
                "from_digest_algorithm": "blake3",
                "to_digest_algorithm": "sha256",
                "transition_snapshot_ref": "ak:snapshot:01904100-0000-7000-8000-000000000302",
                "snapshot_commitment": "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        downgrade,
        ProjectionEffect::Rejected { reason } if reason == arkret_wire::ErrorCode::SCHEMA_VIOLATION
    ));
    assert_eq!(
        state.realm_digest_algorithm(REALM_ID).as_deref(),
        Some("blake3")
    );
}
