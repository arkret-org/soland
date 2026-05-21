//! Reducer-level tests for `cx.realm.inheritance_policy` +
//! `cx.capability.derived` (R3.2).

use contrix_sdk::Operation;
use serde_json::{Value, json};
use soland::hlc::ServerHlc;
use soland::reducer::{ProjectionEffect, ProjectionState};

const REALM_PARENT: &str = "cx:space:01904100-0000-7000-8000-aaaaaaaaaaaa";
const REALM_CHILD: &str = "cx:space:01904100-0000-7000-8000-bbbbbbbbbbbb";

fn op(kind: &str, space_id: &str, payload: Value) -> Operation {
    Operation::create(
        contrix_sdk::OperationId::new(format!("cx:operation:{}", uuid::Uuid::now_v7())).unwrap(),
        contrix_sdk::SpaceId::new(space_id).unwrap(),
        kind,
        payload,
    )
}

#[test]
fn inheritance_policy_projects_cell_and_cache() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let effect = state.apply(
        &op(
            soland::kinds::CX_REALM_INHERITANCE_POLICY,
            REALM_CHILD,
            json!({
                "source_realm_id": REALM_PARENT,
                "allowed_policies": ["join_policy.v1", "retention_policy.v1"],
                "allowed_capability_bundles": ["bundle.admin.v1"],
                "max_depth": 1,
            }),
        ),
        &hlc,
    );
    match effect {
        ProjectionEffect::RealmInheritancePolicyProjected {
            realm_id,
            source_realm_id,
        } => {
            assert_eq!(realm_id, REALM_CHILD);
            assert_eq!(source_realm_id, REALM_PARENT);
        }
        other => panic!("expected RealmInheritancePolicyProjected, got {other:?}"),
    }

    let cached = state.realm_inheritance_policy(REALM_CHILD).expect("cached");
    assert_eq!(cached.source_realm_id, REALM_PARENT);
    assert_eq!(cached.allowed_policies.len(), 2);
    assert_eq!(cached.allowed_capability_bundles.len(), 1);
    assert_eq!(cached.max_depth, 1);

    // Cell projection.
    let cell_id = contrix_sdk::CellRef::new(format!(
        "cx:cell:cx.component.realm.inheritance_policy.v1:{REALM_CHILD}"
    ))
    .unwrap();
    let value = state.cell_value(&cell_id).expect("cell present");
    assert_eq!(
        value.get("source_realm_id").and_then(Value::as_str),
        Some(REALM_PARENT)
    );
}

#[test]
fn inheritance_policy_rejects_max_depth_above_cap() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let bad = op(
        soland::kinds::CX_REALM_INHERITANCE_POLICY,
        REALM_CHILD,
        json!({
            "source_realm_id": REALM_PARENT,
            "allowed_policies": [],
            "allowed_capability_bundles": [],
            "max_depth": 2,
        }),
    );
    match state.apply(&bad, &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "realm_inheritance_max_depth_exceeded");
        }
        other => panic!("expected Rejected(realm_inheritance_max_depth_exceeded), got {other:?}"),
    }
    assert!(state.realm_inheritance_policy(REALM_CHILD).is_none());
}

#[test]
fn inheritance_policy_rejects_missing_source_realm() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let bad = op(
        soland::kinds::CX_REALM_INHERITANCE_POLICY,
        REALM_CHILD,
        json!({
            "allowed_policies": [],
            "max_depth": 1,
        }),
    );
    match state.apply(&bad, &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "realm_inheritance_source_missing");
        }
        other => panic!("expected Rejected(realm_inheritance_source_missing), got {other:?}"),
    }
}

#[test]
fn capability_derived_projects_cell_and_cache() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let capability_id = "cx:capability:01904100-0000-7000-8000-dddddddddddd";
    let effect = state.apply(
        &op(
            soland::kinds::CX_CAPABILITY_DERIVED,
            REALM_CHILD,
            json!({
                "capability_id": capability_id,
                "source_grant_ref": {
                    "id": "cx:event:01904100-0000-7000-8000-eeeeeeeeeeee",
                    "role": "authorized_by",
                },
                "source_realm_inheritance_policy_ref": {
                    "id": "cx:event:01904100-0000-7000-8000-ffffffffffff",
                    "role": "inherits_from",
                },
                "causal_frontier": "cx:frontier:02000000",
                "bundle": {"capabilities": ["read"]},
            }),
        ),
        &hlc,
    );
    match effect {
        ProjectionEffect::CapabilityDerivedProjected {
            capability_id: cid,
            realm_id,
        } => {
            assert_eq!(cid, capability_id);
            assert_eq!(realm_id, REALM_CHILD);
        }
        other => panic!("expected CapabilityDerivedProjected, got {other:?}"),
    }
    let cached = state
        .capability_derived_state(capability_id)
        .expect("cached");
    assert_eq!(
        cached.source_grant_ref,
        "cx:event:01904100-0000-7000-8000-eeeeeeeeeeee"
    );
    assert_eq!(
        cached.source_realm_inheritance_policy_ref,
        "cx:event:01904100-0000-7000-8000-ffffffffffff"
    );
    assert_eq!(cached.causal_frontier, "cx:frontier:02000000");
}

#[test]
fn capability_derived_rejects_missing_source_grant() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let bad = op(
        soland::kinds::CX_CAPABILITY_DERIVED,
        REALM_CHILD,
        json!({
            "capability_id": "cx:capability:01904100-0000-7000-8000-dddddddddddd",
            "source_realm_inheritance_policy_ref": {
                "id": "cx:event:01904100-0000-7000-8000-ffffffffffff",
                "role": "inherits_from",
            },
            "causal_frontier": "cx:frontier:02000000",
        }),
    );
    match state.apply(&bad, &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "capability_derived_source_grant_ref_missing");
        }
        other => {
            panic!("expected Rejected(capability_derived_source_grant_ref_missing), got {other:?}")
        }
    }
}
