use super::*;

const REALM_ID: &str = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
const CONTAINER_A: &str = "ak:morph:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z";
const CONTAINER_B: &str = "ak:morph:AbHexNOxiiU334tA-ZHyM5pRxJxbMY0jvwlMVDY3Xjrz";
const ITEM_A: &str = "ak:morph:AXh0mpVGb536xVxbSPfM4Wc_1WuXAxTYgmtXEncKM9T0";
const ITEM_B: &str = "ak:morph:AaIJHtxd23N3TkS66mYyI4XGESjS7Gjt_fonMdJe9inQ";

fn facet_digest(value: &Value) -> String {
    let bytes = arkret_canonical::canonical_json_bytes(value).unwrap();
    arkret_canonical::sha256_digest(bytes)
}

fn position_facet(container_ref: &str, item_ref: &str) -> FacetRef {
    FacetRef::composite(facet::CONTAINER_POSITION, &[container_ref, item_ref])
}

fn order_facet(container_ref: &str) -> FacetRef {
    FacetRef::new(facet::CONTAINER_ORDER, container_ref)
}

#[test]
fn container_move_uses_the_canonical_position_facet_and_enforces_cas() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let first = state.apply(
        &make_operation(
            arkret_wire::EventKind::ContainerMoveItem,
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

    let position = position_facet(CONTAINER_A, ITEM_A);
    let current = state.facet_value(REALM_ID, &position).cloned().unwrap();
    let rejected = state.apply(
        &make_operation(
            arkret_wire::EventKind::ContainerMoveItem,
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
    assert_eq!(state.facet_value(REALM_ID, &position), Some(&current));

    let accepted = state.apply(
        &make_operation(
            arkret_wire::EventKind::ContainerMoveItem,
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
    assert!(state.facet_value(REALM_ID, &position).is_none());
    assert_eq!(
        state
            .facet_value(REALM_ID, &position_facet(CONTAINER_B, ITEM_A))
            .and_then(|value| value.get("rank"))
            .and_then(Value::as_str),
        Some("B")
    );
}

#[test]
fn container_rebalance_is_atomic_against_order_digest() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let initial_digest = facet_digest(&Value::Null);
    let accepted = state.apply(
        &make_operation(
            arkret_wire::EventKind::ContainerRebalance,
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
    let order = order_facet(CONTAINER_A);
    let current = state.facet_value(REALM_ID, &order).cloned().unwrap();

    let rejected = state.apply(
        &make_operation(
            arkret_wire::EventKind::ContainerRebalance,
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
    assert_eq!(state.facet_value(REALM_ID, &order), Some(&current));
}
