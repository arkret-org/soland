//! Reducer-level tests for `cx.realm.audit_policy_downgrade` (R3.3).

use contrix_sdk::Operation;
use serde_json::{Value, json};
use soland::hlc::ServerHlc;
use soland::reducer::{ProjectionEffect, ProjectionState};

const REALM_A: &str = "ck:realm:01904100-0000-7000-8000-aaaaaaaaaaaa";

fn op(kind: &str, space_id: &str, payload: Value) -> Operation {
    Operation::create(
        contrix_sdk::OperationId::new(format!("ck:operation:{}", uuid::Uuid::now_v7())).unwrap(),
        contrix_sdk::RealmId::new(space_id).unwrap(),
        kind,
        payload,
    )
}

#[test]
fn audit_policy_downgrade_projects_log_and_cache() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let payload = json!({
        "from_policy": "attested_hardware",
        "to_policy": "disclosed_policy",
        "reason": "attestation_deadline_missed",
        "approver": "did:web:audit.acme.example",
    });
    let effect = state.apply(
        &op(
            soland::kinds::CX_REALM_AUDIT_POLICY_DOWNGRADE,
            REALM_A,
            payload,
        ),
        &hlc,
    );
    match effect {
        ProjectionEffect::RealmAuditPolicyDowngradeProjected { realm_id } => {
            assert_eq!(realm_id, REALM_A);
        }
        other => panic!("expected RealmAuditPolicyDowngradeProjected, got {other:?}"),
    }

    let entries = state.realm_audit_downgrades(REALM_A);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].from_policy.as_deref(), Some("attested_hardware"));
    assert_eq!(entries[0].to_policy.as_deref(), Some("disclosed_policy"));
    assert_eq!(
        entries[0].approver.as_deref(),
        Some("did:web:audit.acme.example")
    );

    // Cell projection.
    let cell_id = contrix_sdk::CellRef::new(format!(
        "ck:cell:cx.component.realm.audit_policy_downgrade.v1:{REALM_A}"
    ))
    .unwrap();
    let value = state.cell_value(&cell_id).expect("cell present");
    let arr = value.as_array().expect("ordered-log array");
    assert_eq!(arr.len(), 1);
    assert_eq!(
        arr[0].get("from_policy").and_then(Value::as_str),
        Some("attested_hardware")
    );
}

#[test]
fn audit_policy_downgrade_appends_to_existing_log() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    for reason in ["attestation_deadline_missed", "operator_request"] {
        state.apply(
            &op(
                soland::kinds::CX_REALM_AUDIT_POLICY_DOWNGRADE,
                REALM_A,
                json!({
                    "from_policy": "attested_hardware",
                    "to_policy": "disclosed_policy",
                    "reason": reason,
                }),
            ),
            &hlc,
        );
    }
    let entries = state.realm_audit_downgrades(REALM_A);
    assert_eq!(entries.len(), 2);
    let cell_id = contrix_sdk::CellRef::new(format!(
        "ck:cell:cx.component.realm.audit_policy_downgrade.v1:{REALM_A}"
    ))
    .unwrap();
    let value = state.cell_value(&cell_id).expect("cell present");
    let arr = value.as_array().expect("ordered-log array");
    assert_eq!(arr.len(), 2);
}
