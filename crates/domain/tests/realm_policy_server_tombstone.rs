use arkret_event_draft::Operation;
use arkret_identifiers::{OperationId, RealmId};
use arkret_state::lattice::CellState;
use arkret_wire::{Bottom, BottomKind, CellRef};
use chrono::Utc;
use serde_json::{Value, json};
use soland_domain::reducer::realm_policy_server::apply_realm_policy_server;
use soland_domain::reducer::{ProjectionEffect, ProjectionState, RealmLinkState};

const CHILD_REALM: &str = "ak:realm:0196414c-8000-7000-8000-000000000000";
const ORG_REALM: &str = "ak:realm:0196414c-8000-7000-8000-000000000001";
const CELL_ID: &str = "ak:cell:ak.component.realm.policy_server.v1:null";

fn operation(realm_id: &str, payload: Value) -> Operation {
    Operation::create(
        OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7())).unwrap(),
        RealmId::new(realm_id).unwrap(),
        arkret_wire::events::EventKind::REALM_POLICY_SERVER,
        payload,
    )
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

    for _ in 0..2 {
        let effect = apply_realm_policy_server(
            &mut state,
            &operation(CHILD_REALM, json!({"tombstone": true})),
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
    for target_realm_id in [ORG_REALM, "ak:realm:0196414c-8000-7000-8000-000000000002"] {
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
