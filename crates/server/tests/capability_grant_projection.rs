//! P1 reducer-level tests for capability control-plane projection
//! (`ck.capability.grant` / `ck.capability.revoke`).
//!
//! Covers capabilities.md §12.1 grant-cell convergence:
//!   ① grant → projected into `ck.component.capability.grant.v1` or_set +
//!      the derived engine grant authorizes `check(subject, action)`.
//!   ② revoke → observed-remove on the same cell + check denies.
//!   ③ revoke then re-grant of the same grant_id → still denied (terminal,
//!      no revive).
//!   ④ repeated revoke is idempotent (converges, still denied).
//!
//! The grant cell is the source of truth; these tests drive the reducer with
//! events and read back the projected cell + the engine-shaped effective
//! grant the projection driver folds into `SolandAuthzEngine`.

use cokret_sdk::{Operation, OperationId, RealmId};
use serde_json::{Value, json};
use soland::authz::SolandAuthzEngine;
use soland::hlc::ServerHlc;
use soland::reducer::{ProjectionEffect, ProjectionState};

const REALM: &str = "ck:realm:01904100-0000-7000-8000-cccccccccccc";
const GRANT_ID: &str = "ck:grant:01904100-0000-7000-8000-dddddddddddd";
const ISSUER: &str = "did:web:owner.example";
const SUBJECT: &str = "did:web:bob.example";
const ACTION: &str = "ck.realm.admin";

fn op(kind: &str, realm_id: &str, payload: Value) -> Operation {
    Operation::create(
        OperationId::new(format!("ck:operation:{}", uuid::Uuid::now_v7())).unwrap(),
        RealmId::new(realm_id).unwrap(),
        kind,
        payload,
    )
}

fn grant_op(grant_id: &str) -> Operation {
    op(
        soland::kinds::CK_CAPABILITY_GRANT,
        REALM,
        json!({
            "grant_id": grant_id,
            "grant": {
                "id": grant_id,
                "grant_id": grant_id,
                "realm_id": REALM,
                "issuer": ISSUER,
                "subject": SUBJECT,
                "actions": [ACTION],
                "resources": [{ "kind": "realm", "id": REALM }],
            }
        }),
    )
}

fn revoke_op(grant_id: &str) -> Operation {
    op(
        soland::kinds::CK_CAPABILITY_REVOKE,
        REALM,
        json!({ "grant_id": grant_id }),
    )
}

/// Mirror the projection driver: derive the engine grant from the cell and
/// fold it into a fresh engine, then run a check for the subject/action.
fn check_allows(state: &ProjectionState, grant_id: &str) -> bool {
    let engine = SolandAuthzEngine::new();
    if let Some(grant) = state.effective_engine_grant(grant_id) {
        engine.upsert_projected_grant(grant);
    }
    engine
        .check(SUBJECT, ACTION, REALM, REALM, None, &[], &[])
        .allowed
}

fn grant_cell_items(state: &ProjectionState, grant_id: &str) -> Vec<Value> {
    let cell_ref = cokret_sdk::CellRef::new(format!(
        "ck:cell:ck.component.capability.grant.v1:{grant_id}"
    ))
    .unwrap();
    match state.cell_value(&cell_ref) {
        Some(Value::Array(items)) => items.clone(),
        _ => Vec::new(),
    }
}

fn item_revoked(item: &Value) -> bool {
    let value = item.get("value").unwrap_or(item);
    value.get("revoked").and_then(Value::as_bool) == Some(true)
}

#[test]
fn grant_projects_cell_and_authorizes_check() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let effect = state.apply(&grant_op(GRANT_ID), &hlc);
    match effect {
        ProjectionEffect::CapabilityGrantProjected { grant_id, realm_id } => {
            assert_eq!(grant_id, GRANT_ID);
            assert_eq!(realm_id, REALM);
        }
        other => panic!("expected CapabilityGrantProjected, got {other:?}"),
    }

    let items = grant_cell_items(&state, GRANT_ID);
    assert_eq!(items.len(), 1, "one or_set add");
    assert!(!item_revoked(&items[0]), "add is live");

    // Derived engine grant authorizes the subject for the action.
    assert!(check_allows(&state, GRANT_ID), "grant must authorize check");
}

#[test]
fn revoke_observed_removes_and_denies_check() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    state.apply(&grant_op(GRANT_ID), &hlc);
    assert!(check_allows(&state, GRANT_ID));

    let effect = state.apply(&revoke_op(GRANT_ID), &hlc);
    match effect {
        ProjectionEffect::CapabilityRevokeProjected { grant_id, .. } => {
            assert_eq!(grant_id, GRANT_ID);
        }
        other => panic!("expected CapabilityRevokeProjected, got {other:?}"),
    }

    let items = grant_cell_items(&state, GRANT_ID);
    assert!(
        items.iter().all(item_revoked),
        "every surviving add is observed-removed"
    );
    assert!(!check_allows(&state, GRANT_ID), "revoked grant must deny");
}

#[test]
fn re_grant_after_revoke_stays_denied_terminal() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    state.apply(&grant_op(GRANT_ID), &hlc);
    state.apply(&revoke_op(GRANT_ID), &hlc);
    assert!(!check_allows(&state, GRANT_ID));

    // Re-grant with the SAME grant_id must NOT revive (terminal §12.1).
    state.apply(&grant_op(GRANT_ID), &hlc);
    let items = grant_cell_items(&state, GRANT_ID);
    assert!(
        items.iter().all(item_revoked),
        "re-add of an observed-removed grant_id stays revoked"
    );
    assert!(
        !check_allows(&state, GRANT_ID),
        "re-grant after revoke must remain denied"
    );
}

#[test]
fn repeated_revoke_is_idempotent() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    state.apply(&grant_op(GRANT_ID), &hlc);
    state.apply(&revoke_op(GRANT_ID), &hlc);
    let after_first = grant_cell_items(&state, GRANT_ID);
    state.apply(&revoke_op(GRANT_ID), &hlc);
    let after_second = grant_cell_items(&state, GRANT_ID);

    assert_eq!(
        after_first.len(),
        after_second.len(),
        "repeated revoke does not grow the or_set"
    );
    assert!(after_second.iter().all(item_revoked));
    assert!(!check_allows(&state, GRANT_ID));
}
