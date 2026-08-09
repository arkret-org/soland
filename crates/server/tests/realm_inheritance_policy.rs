//! Reducer-level tests for `ak.realm.inheritance_policy` +
//! `ak.capability.derived` (R3.2).

use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_identifiers::{OperationId, RealmId};
use arkret_state::lattice::CellState;
use serde_json::{Value, json};
use soland_domain::hlc::ServerHlc;
use soland_domain::reducer::{ProjectionEffect, ProjectionState};

const REALM_PARENT: &str = "ak:realm:ATYL-87CDhaLQem29G2JQCXbZ_8zuu7khej2MbrsGLK6";
const REALM_CHILD: &str = "ak:realm:AS1N4QnbZ6JgVObAF-yTx1GWoK2XnO_vUaZ2qe0WCyQV";

fn op(kind: impl AsRef<str>, realm_id: &str, payload: Value) -> Operation {
    arkret_event_draft::test_support::raw_projected_operation(
        OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7())).unwrap(),
        RealmId::new(realm_id).unwrap(),
        kind.as_ref(),
        payload,
    )
}

fn link_op(source: &str, target: &str, link_kind: &str) -> Operation {
    op(
        arkret_wire::EventKind::RealmLink,
        source,
        json!({
            "target_realm_id": target,
            "link_kind": link_kind,
            "status": "active",
        }),
    )
}

fn inheritance_op(child: &str, parent: &str, bundles: &[&str]) -> Operation {
    op(
        arkret_wire::EventKind::RealmInheritancePolicy,
        child,
        json!({
            "source_realm_id": parent,
            "allowed_policies": [],
            "allowed_capability_bundles": bundles,
            "max_depth": 1,
        }),
    )
}

fn seed_source_grant(
    state: &mut ProjectionState,
    grant_ref: &str,
    realm_id: &str,
    actions: &[&str],
    bundles: &[&str],
) {
    let cell_id = arkret_identifiers::CellRef::new(format!(
        "ak:cell:ak.component.capability.grant.v1:{grant_ref}"
    ))
    .unwrap();
    state.cells.insert(
        cell_id,
        CellState::Value(json!([
            {
                "tag": grant_ref,
                "value": {
                    "event_id": grant_ref,
                    "grant_id": "ak:grant:ATqrupSFYozzL7O90hPaSlvHmLnxxSRiRUZA4RgeuZpD",
                    "realm_id": realm_id,
                    "actions": actions,
                    "resources": [{"kind": "realm", "id": realm_id}],
                    "capability_bundles": bundles,
                }
            }
        ])),
    );
}

#[test]
fn inheritance_policy_projects_cell_and_cache() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let effect = state.apply(
        &op(
            arkret_wire::EventKind::RealmInheritancePolicy,
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
    let cell_id = arkret_identifiers::CellRef::new(format!(
        "ak:cell:ak.component.realm.inheritance_policy.v1:{REALM_CHILD}"
    ))
    .unwrap();
    let value = state.cell_value(&cell_id).expect("cell present");
    assert_eq!(
        value.get("source_realm_id").and_then(Value::as_str),
        Some(REALM_PARENT)
    );
}

#[test]
fn inheritance_policy_rejects_non_capability_bearing_link_kind() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    state.apply(
        &link_op(REALM_CHILD, REALM_PARENT, "discoverable_from"),
        &hlc,
    );

    let bad = inheritance_op(REALM_CHILD, REALM_PARENT, &[]);
    match state.apply(&bad, &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "realm_inheritance_link_kind_not_capability_bearing");
        }
        other => panic!(
            "expected Rejected(realm_inheritance_link_kind_not_capability_bearing), got {other:?}"
        ),
    }
}

#[test]
fn inheritance_policy_rejects_max_depth_above_cap() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let bad = op(
        arkret_wire::EventKind::RealmInheritancePolicy,
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
        arkret_wire::EventKind::RealmInheritancePolicy,
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
    let capability_id = "ak:capability:01904100-0000-7000-8000-dddddddddddd";
    let source_grant_ref = "ak:event:AZCc-CJRr_EnSA1hXfjiVtD6nI1eIW9UxyXlBM3kKnfd";
    state.apply(&link_op(REALM_CHILD, REALM_PARENT, "governed_by"), &hlc);
    seed_source_grant(
        &mut state,
        source_grant_ref,
        REALM_PARENT,
        &["read"],
        &["bundle.read.v1"],
    );
    let inheritance = inheritance_op(REALM_CHILD, REALM_PARENT, &["bundle.read.v1"]);
    let inheritance_ref = inheritance.operation_id.to_string();
    assert!(matches!(
        state.apply(&inheritance, &hlc),
        ProjectionEffect::RealmInheritancePolicyProjected { .. }
    ));

    let effect = state.apply(
        &op(
            arkret_wire::EventKind::CapabilityDerived,
            REALM_CHILD,
            json!({
                "capability_id": capability_id,
                "source_grant_ref": {
                    "id": source_grant_ref,
                    "role": "authorized_by",
                },
                "source_realm_inheritance_policy_ref": {
                    "id": inheritance_ref,
                    "role": "inherits_from",
                },
                "causal_frontier": "ak:frontier:02000000",
                "bundle": {
                    "capability_bundles": ["bundle.read.v1"],
                    "capabilities": ["read"],
                    "resources": [{"kind": "realm", "id": REALM_PARENT}],
                },
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
    assert_eq!(cached.source_grant_ref, source_grant_ref);
    assert_eq!(cached.source_realm_inheritance_policy_ref, inheritance_ref);
    assert_eq!(cached.causal_frontier, "ak:frontier:02000000");
    assert_eq!(cached.effective_actions, vec!["read".to_owned()]);
    assert_eq!(
        cached.effective_capability_bundles,
        vec!["bundle.read.v1".to_owned()]
    );
}

#[test]
fn capability_derived_rejects_missing_source_grant() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let bad = op(
        arkret_wire::EventKind::CapabilityDerived,
        REALM_CHILD,
        json!({
            "capability_id": "ak:capability:01904100-0000-7000-8000-dddddddddddd",
            "source_realm_inheritance_policy_ref": {
                "id": "ak:event:AQZU3LOaSy4GhEHnYFmJaYYvDYn2WVDsPLSUYwGHDZ7Q",
                "role": "inherits_from",
            },
            "causal_frontier": "ak:frontier:02000000",
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

#[test]
fn capability_derived_rejects_action_widening() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let source_grant_ref = "ak:event:AZCc-CJRr_EnSA1hXfjiVtD6nI1eIW9UxyXlBM3kKnfd";
    state.apply(
        &link_op(REALM_CHILD, REALM_PARENT, "inherits_policy_from"),
        &hlc,
    );
    seed_source_grant(
        &mut state,
        source_grant_ref,
        REALM_PARENT,
        &["read"],
        &["bundle.read.v1"],
    );
    let inheritance = inheritance_op(REALM_CHILD, REALM_PARENT, &["bundle.read.v1"]);
    let inheritance_ref = inheritance.operation_id.to_string();
    state.apply(&inheritance, &hlc);

    let bad = op(
        arkret_wire::EventKind::CapabilityDerived,
        REALM_CHILD,
        json!({
            "capability_id": "ak:capability:01904100-0000-7000-8000-dddddddddddd",
            "source_grant_ref": {"id": source_grant_ref, "role": "authorized_by"},
            "source_realm_inheritance_policy_ref": {"id": inheritance_ref, "role": "inherits_from"},
            "causal_frontier": "ak:frontier:02000000",
            "bundle": {
                "capability_bundles": ["bundle.read.v1"],
                "capabilities": ["write"],
            },
        }),
    );

    match state.apply(&bad, &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "capability_derived_action_widening");
        }
        other => panic!("expected Rejected(capability_derived_action_widening), got {other:?}"),
    }
}

#[test]
fn capability_derived_rejects_non_capability_bearing_link_kind() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let source_grant_ref = "ak:event:AZCc-CJRr_EnSA1hXfjiVtD6nI1eIW9UxyXlBM3kKnfd";
    seed_source_grant(
        &mut state,
        source_grant_ref,
        REALM_PARENT,
        &["read"],
        &["bundle.read.v1"],
    );
    let inheritance = inheritance_op(REALM_CHILD, REALM_PARENT, &["bundle.read.v1"]);
    let inheritance_ref = inheritance.operation_id.to_string();
    state.apply(&inheritance, &hlc);
    state.apply(&link_op(REALM_CHILD, REALM_PARENT, "join_gate_from"), &hlc);

    let bad = op(
        arkret_wire::EventKind::CapabilityDerived,
        REALM_CHILD,
        json!({
            "capability_id": "ak:capability:01904100-0000-7000-8000-dddddddddddd",
            "source_grant_ref": {"id": source_grant_ref, "role": "authorized_by"},
            "source_realm_inheritance_policy_ref": {"id": inheritance_ref, "role": "inherits_from"},
            "causal_frontier": "ak:frontier:02000000",
            "bundle": {
                "capability_bundles": ["bundle.read.v1"],
                "capabilities": ["read"],
            },
        }),
    );

    match state.apply(&bad, &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(
                reason,
                "capability_derived_link_kind_not_capability_bearing"
            );
        }
        other => panic!(
            "expected Rejected(capability_derived_link_kind_not_capability_bearing), got {other:?}"
        ),
    }
}
