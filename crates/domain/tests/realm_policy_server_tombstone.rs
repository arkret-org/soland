use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_identifiers::{OperationId, RealmId};
use arkret_state::lattice::CellState;
use arkret_wire::{Bottom, BottomKind, CellRef};
use chrono::Utc;
use serde_json::{Value, json};
use soland_domain::reducer::realm_policy_server::apply_realm_policy_server;
use soland_domain::reducer::{ProjectionEffect, ProjectionState, RealmLinkState};

const CHILD_REALM: &str = "ak:realm:ARUgpqlRQEOsctG13hpmVzQjx09UVbnHOe3BxpK76Jj_";
const ORG_REALM: &str = "ak:realm:AWJFMKcHr4DUa3zaD-8OM-lGsu9eMHxFq5OHnkdJrT07";
const CELL_ID: &str = "ak:cell:ak.component.realm.policy_server.v1:null";

fn operation(realm_id: &str, mut payload: Value) -> Operation {
    let preconditions = payload
        .as_object_mut()
        .and_then(|payload| payload.remove("preconditions"))
        .map(serde_json::from_value)
        .transpose()
        .unwrap()
        .unwrap_or_default();
    let mut operation = arkret_event_draft::test_support::raw_projected_operation(
        OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7())).unwrap(),
        RealmId::new(realm_id).unwrap(),
        arkret_wire::EventKind::RealmPolicyServer.as_str(),
        payload,
    );
    operation.context.preconditions = preconditions;
    operation
}

#[test]
fn tombstone_is_durable_idempotent_and_restores_org_fallback() {
    let mut state = ProjectionState::new();
    apply_realm_policy_server(
        &mut state,
        &operation(
            ORG_REALM,
            json!({
                "policy_server_did": "did:web:org-policy.example",
                "policy_server_url": "https://org-policy.example/_arkret/self/policy/check"
            }),
        ),
    );
    apply_realm_policy_server(
        &mut state,
        &operation(
            CHILD_REALM,
            json!({
                "policy_server_did": "did:web:child-policy.example",
                "policy_server_url": "https://child-policy.example/_arkret/self/policy/check"
            }),
        ),
    );
    let now = Utc::now();
    state
        .realm_links
        .entry(CHILD_REALM.to_owned())
        .or_default()
        .push(RealmLinkState {
            realm_id: CHILD_REALM.to_owned(),
            target_realm_id: ORG_REALM.to_owned(),
            link_kind: "governed_by".to_owned(),
            status: "active".to_owned(),
            label: None,
            commitment: None,
            created_at: now,
            updated_at: now,
        });

    // Spec §2.2: a delete Move always cites the settled declaration through a
    // `head_eq` precondition; the duplicate replay keeps the same frozen basis.
    for _ in 0..2 {
        let effect = apply_realm_policy_server(
            &mut state,
            &operation(
                CHILD_REALM,
                json!({
                    "tombstone": true,
                    "preconditions": [{
                        "cell": CELL_ID,
                        "predicate": {"op": "head_eq", "value": {
                            "policy_server_did": "did:web:child-policy.example",
                            "policy_server_url": "https://child-policy.example/_arkret/self/policy/check"
                        }},
                    }],
                }),
            ),
        );
        assert!(matches!(
            effect,
            ProjectionEffect::RealmPolicyServerTombstoned { .. }
        ));
        assert_eq!(
            state
                .realm_null_subject_cells
                .get(&(CHILD_REALM.to_owned(), CELL_ID.to_owned())),
            Some(&CellState::Value(json!({"tombstone": true})))
        );
    }

    let effective = state
        .try_realm_policy_server_config(CHILD_REALM)
        .expect("resolvable policy-server chain")
        .expect("organization fallback");
    assert_eq!(effective.realm_id, ORG_REALM);
    assert!(!state.realm_policy_servers.contains_key(CHILD_REALM));
}

#[test]
fn same_basis_replace_and_delete_siblings_join_bottom_in_either_order() {
    let declaration = json!({
        "policy_server_did": "did:web:child-policy.example",
        "policy_server_url": "https://child-policy.example/_arkret/self/policy/check"
    });
    let replace = json!({
        "policy_server_did": "did:web:next-policy.example",
        "policy_server_url": "https://next-policy.example/_arkret/self/policy/check",
        "preconditions": [{
            "cell": CELL_ID,
            "predicate": {"op": "head_eq", "value": declaration.clone()},
        }],
    });
    let delete = json!({
        "tombstone": true,
        "preconditions": [{
            "cell": CELL_ID,
            "predicate": {"op": "head_eq", "value": declaration.clone()},
        }],
    });
    for (first, second) in [
        (replace.clone(), delete.clone()),
        (delete.clone(), replace.clone()),
    ] {
        let mut state = ProjectionState::new();
        apply_realm_policy_server(&mut state, &operation(CHILD_REALM, declaration.clone()));
        apply_realm_policy_server(&mut state, &operation(CHILD_REALM, first));
        let effect = apply_realm_policy_server(&mut state, &operation(CHILD_REALM, second));
        assert!(matches!(
            effect,
            ProjectionEffect::RealmPolicyServerConflicted { .. }
        ));
        assert!(matches!(
            state
                .realm_null_subject_cells
                .get(&(CHILD_REALM.to_owned(), CELL_ID.to_owned())),
            Some(CellState::Bottom(_))
        ));
        assert_eq!(
            state.try_realm_policy_server_config(CHILD_REALM),
            Err("cell_bottom_state")
        );
        assert!(!state.realm_policy_servers.contains_key(CHILD_REALM));
        // `⊥` is sticky: replaying either sibling cannot resurrect a value head.
        let replay = apply_realm_policy_server(
            &mut state,
            &operation(CHILD_REALM, json!({"tombstone": true})),
        );
        assert!(matches!(
            replay,
            ProjectionEffect::RealmPolicyServerConflicted { .. }
        ));
        assert!(matches!(
            state
                .realm_null_subject_cells
                .get(&(CHILD_REALM.to_owned(), CELL_ID.to_owned())),
            Some(CellState::Bottom(_))
        ));
    }
}

#[test]
fn resolution_fails_closed_for_bottom_and_ambiguous_governance() {
    let mut bottom_state = ProjectionState::new();
    bottom_state.realm_null_subject_cells.insert(
        (CHILD_REALM.to_owned(), CELL_ID.to_owned()),
        CellState::Bottom(Bottom::new(
            BottomKind::Conflict,
            vec![CellRef::new(CELL_ID.to_owned()).unwrap()],
        )),
    );
    assert_eq!(
        bottom_state.try_realm_policy_server_config(CHILD_REALM),
        Err("cell_bottom_state")
    );

    let mut ambiguous_state = ProjectionState::new();
    let now = Utc::now();
    for target_realm_id in [
        ORG_REALM,
        "ak:realm:ASyD_Vn3M1MpuekoxTO6YGME46X1AXzYor22WYgNNpEZ",
    ] {
        ambiguous_state
            .realm_links
            .entry(CHILD_REALM.to_owned())
            .or_default()
            .push(RealmLinkState {
                realm_id: CHILD_REALM.to_owned(),
                target_realm_id: target_realm_id.to_owned(),
                link_kind: "governed_by".to_owned(),
                status: "active".to_owned(),
                label: None,
                commitment: None,
                created_at: now,
                updated_at: now,
            });
    }
    assert_eq!(
        ambiguous_state.try_realm_policy_server_config(CHILD_REALM),
        Err("realm_policy_server_governance_ambiguous")
    );
}
