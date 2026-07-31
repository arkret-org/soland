//! P1 reducer-level tests for capability control-plane projection
//! (`ak.capability.grant` / `ak.capability.revoke`).
//!
//! Covers capabilities.md §12.1 grant-cell convergence:
//!   ① grant → projected into `ak.component.capability.grant.v1` or_set +
//!      the derived engine grant authorizes `check(subject, action)`.
//!   ② revoke → observed-remove on the same cell + check denies.
//!   ③ revoke then re-grant of the same grant_id → still denied (terminal,
//!      no revive).
//!   ④ repeated revoke is idempotent (converges, still denied).
//!
//! The grant cell is the source of truth; these tests drive the reducer with
//! events and read back the projected cell + the engine-shaped effective
//! grant the projection driver folds into `SolandAuthzEngine`.

use arkret_event_draft::Operation;
use arkret_identifiers::{OperationId, RealmId};
use arkret_wire::CapabilityActionId;
use serde_json::{Value, json};
use soland_domain::hlc::ServerHlc;
use soland_domain::reducer::{ProjectionEffect, ProjectionState, SolandRealmState};
use soland_http::authz::SolandAuthzEngine;

const REALM: &str = "ak:realm:01904100-0000-7000-8000-cccccccccccc";
const GRANT_ID: &str = "ak:grant:01904100-0000-7000-8000-dddddddddddd";
const ISSUER: &str = "did:web:owner.example";
const SUBJECT: &str = "did:web:bob.example";
const STRAND_ID: &str = "ak:strand:01904100-0000-7000-8000-eeeeeeeeeeee";
const CIRCLE_A: &str = "ak:circle:01904100-0000-7000-8000-c1c1c1c1c1c1";
const CIRCLE_B: &str = "ak:circle:01904100-0000-7000-8000-c2c2c2c2c2c2";

fn op(kind: &str, realm_id: &str, payload: Value) -> Operation {
    Operation::create(
        OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7())).unwrap(),
        RealmId::new(realm_id).unwrap(),
        kind,
        payload,
    )
}

fn grant_op(grant_id: &str) -> Operation {
    grant_op_with(
        grant_id,
        vec![json!(CapabilityActionId::REALM_ADMIN)],
        vec![json!({ "kind": "realm", "realm_id": REALM })],
    )
}

fn grant_op_with(grant_id: &str, actions: Vec<Value>, resources: Vec<Value>) -> Operation {
    let registry_digest = arkret_policy::current_capability_action_registry_digest()
        .expect("embedded capability action registry");
    op(
        arkret_wire::EventKind::CAPABILITY_GRANT,
        REALM,
        json!({
            "grant_id": grant_id,
            "grant": {
                "id": grant_id,
                "grant_id": grant_id,
                "realm_id": REALM,
                "issuer": ISSUER,
                "issuer_authority_refs": [{
                    "kind": "realm_root",
                    "realm_id": REALM,
                    "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
                    "controller_epoch_at_issuance": 0,
                    "authority_generation": 0
                }],
                "subject": SUBJECT,
                "actions": actions,
                "capability_action_registry_digest": registry_digest,
                "resources": resources,
            }
        }),
    )
}

fn revoke_op(grant_id: &str) -> Operation {
    op(
        arkret_wire::EventKind::CAPABILITY_REVOKE,
        REALM,
        json!({ "grant_id": grant_id }),
    )
}

/// Give the Realm the one authority genesis establishes.
///
/// `realm-and-space.md` section 2.5: the create Event registers an
/// `ak.component.realm.authority_root.v1` singleton whose controller holds
/// effective `ak.realm.owner`, and that aggregate is what lets the issuer here
/// sign the grants below. The `realm_states[..].owner` mirror seeded alongside
/// it is deliberately a different principal in spirit - it is a discardable
/// presentation field and authorizes nothing.
fn seed_realm_owner(state: &mut ProjectionState) {
    let now = chrono::Utc::now();
    state.realm_null_subject_cells.insert(
        (
            REALM.to_owned(),
            arkret_wire::REALM_AUTHORITY_ROOT_CELL.to_owned(),
        ),
        arkret_state::lattice::CellState::Value(
            serde_json::to_value(
                arkret_policy::realm_bootstrap::RealmAuthorityRootValue::genesis(
                    arkret_identifiers::Did::new(ISSUER).unwrap(),
                    arkret_policy::current_capability_action_registry_digest().unwrap(),
                ),
            )
            .unwrap(),
        ),
    );
    state.realm_states.insert(
        REALM.to_owned(),
        SolandRealmState {
            realm_id: REALM.to_owned(),
            owner: Some(ISSUER.to_owned()),
            title: None,
            deleted: false,
            archived: false,
            frozen: false,
            freeze_expires_at: None,
            created_at: now,
            updated_at: now,
            trust_domain: None,
            terminal_state: None,
            successor_realm_id: None,
            default_strand_id: None,
            active_profiles: Vec::new(),
        },
    );
}

/// Mirror the projection driver: derive the engine grant from the cell and
/// fold it into a fresh engine, then run a check for the subject/action.
fn check_allows(state: &ProjectionState, grant_id: &str) -> bool {
    check_allows_for(state, grant_id, CapabilityActionId::REALM_ADMIN, REALM)
}

fn check_allows_for(state: &ProjectionState, grant_id: &str, action: &str, resource: &str) -> bool {
    let engine = SolandAuthzEngine::new();
    if let Some(grant) = state.effective_engine_grant(grant_id) {
        engine.upsert_projected_grant(grant);
    }
    engine
        .check(SUBJECT, action, resource, REALM, None, &[], &[])
        .allowed
}

fn grant_cell_items(state: &ProjectionState, grant_id: &str) -> Vec<Value> {
    let cell_ref = arkret_identifiers::CellRef::new(format!(
        "ak:cell:ak.component.capability.grant.v1:{grant_id}"
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
    seed_realm_owner(&mut state);
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
fn canonical_circle_selector_and_constraint_project_to_narrow_runtime_grant() {
    let mut state = ProjectionState::new();
    seed_realm_owner(&mut state);
    let hlc = ServerHlc::new("test");
    let effect = state.apply(
        &op(
            arkret_wire::EventKind::CAPABILITY_GRANT,
            REALM,
            json!({
                "grant_id": GRANT_ID,
                "grant": {
                    "id": GRANT_ID,
                    "grant_id": GRANT_ID,
                    "realm_id": REALM,
                    "issuer": ISSUER,
                    "issuer_authority_refs": [{
                        "kind": "realm_root",
                        "realm_id": REALM,
                        "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
                        "controller_epoch_at_issuance": 0,
                        "authority_generation": 0
                    }],
                    "subject": SUBJECT,
                    "actions": ["ak.circle.member.manage"],
                    "resources": [{ "kind": "circle", "realm_id": REALM, "circle_id": CIRCLE_A }],
                    "constraints": [{
                        "constraint_kind": "scope_limitation",
                        "effect": "allow",
                        "allowed_circle_ids": [CIRCLE_A],
                    }],
                }
            }),
        ),
        &hlc,
    );
    assert!(
        matches!(effect, ProjectionEffect::CapabilityGrantProjected { .. }),
        "canonical Circle grant should project, got {effect:?}"
    );
    let engine = SolandAuthzEngine::new();
    let grant = state
        .effective_engine_grant(GRANT_ID)
        .expect("canonical Circle grant must map to runtime grant");
    engine.upsert_projected_grant(grant);
    assert!(
        engine
            .check(
                SUBJECT,
                "ak.circle.member.manage",
                CIRCLE_A,
                REALM,
                Some(ISSUER),
                &[],
                &[]
            )
            .allowed,
        "grant should authorize the allowed Circle"
    );
    assert!(
        !engine
            .check(
                SUBJECT,
                "ak.circle.member.manage",
                CIRCLE_B,
                REALM,
                Some(ISSUER),
                &[],
                &[]
            )
            .allowed,
        "grant must not authorize a different Circle"
    );
}

#[test]
fn revoke_observed_removes_and_denies_check() {
    let mut state = ProjectionState::new();
    seed_realm_owner(&mut state);
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
    seed_realm_owner(&mut state);
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
    seed_realm_owner(&mut state);
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

#[test]
fn wildcard_action_grant_is_rejected() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let effect = state.apply(
        &grant_op_with(
            GRANT_ID,
            vec![json!("ak.pin.*")],
            vec![json!({ "kind": "realm", "id": REALM })],
        ),
        &hlc,
    );
    match effect {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "capability_grant_action_wildcard_forbidden");
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
    assert!(grant_cell_items(&state, GRANT_ID).is_empty());
}

#[test]
fn bare_wildcard_resource_grant_is_rejected() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let effect = state.apply(
        &grant_op_with(GRANT_ID, vec![json!("ak.pin.add")], vec![json!("*")]),
        &hlc,
    );
    match effect {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "capability_grant_resource_wildcard_forbidden");
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
    assert!(grant_cell_items(&state, GRANT_ID).is_empty());
}

#[test]
fn selector_resource_count_limit_is_enforced() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let resources = (0..257)
        .map(|_| json!({ "kind": "realm", "id": REALM }))
        .collect();
    let effect = state.apply(
        &grant_op_with(GRANT_ID, vec![json!("ak.pin.add")], resources),
        &hlc,
    );
    match effect {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "selector_too_complex");
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
    assert!(grant_cell_items(&state, GRANT_ID).is_empty());
}

#[test]
fn canonical_strand_selector_projects_to_exact_resource() {
    let mut state = ProjectionState::new();
    seed_realm_owner(&mut state);
    let hlc = ServerHlc::new("test");
    let effect = state.apply(
        &grant_op_with(
            GRANT_ID,
            vec![json!("ak.strand.read")],
            vec![json!({ "kind": "strand", "realm_id": REALM, "strand_id": STRAND_ID })],
        ),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::CapabilityGrantProjected { .. }
    ));
    assert!(check_allows_for(
        &state,
        GRANT_ID,
        "ak.strand.read",
        STRAND_ID
    ));
    assert!(!check_allows_for(
        &state,
        GRANT_ID,
        "ak.strand.read",
        "ak:strand:01904100-0000-7000-8000-ffffffffffff"
    ));
}

#[test]
fn multiple_resource_selectors_are_disjoined_in_engine_projection() {
    let mut state = ProjectionState::new();
    seed_realm_owner(&mut state);
    let hlc = ServerHlc::new("test");
    let other_strand = "ak:strand:01904100-0000-7000-8000-ffffffffffff";
    let effect = state.apply(
        &grant_op_with(
            GRANT_ID,
            vec![json!("ak.strand.read")],
            vec![
                json!({ "kind": "strand", "realm_id": REALM, "strand_id": STRAND_ID }),
                json!({ "kind": "strand", "realm_id": REALM, "strand_id": other_strand }),
            ],
        ),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::CapabilityGrantProjected { .. }
    ));
    assert!(check_allows_for(
        &state,
        GRANT_ID,
        "ak.strand.read",
        STRAND_ID
    ));
    assert!(check_allows_for(
        &state,
        GRANT_ID,
        "ak.strand.read",
        other_strand
    ));
}
