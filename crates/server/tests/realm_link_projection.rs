//! Reducer-level tests for `ak.realm.link` (R3.1).
//!
//! Exercises:
//! - all eight canonical link_kinds write their cell + are queryable
//! - the structured `realm_links` / `realm_links_inbound` caches populate
//! - the query API filters by direction + link_kind_allow
//! - schema validation rejects bad kinds / self-references / bad status

use arkret_event_draft::Operation;
use arkret_models_collaboration::governance::realm_governance::RealmLinkDirection;
use serde_json::{Value, json};
use soland_domain::hlc::ServerHlc;
use soland_domain::reducer::{ProjectionEffect, ProjectionState};

const REALM_A: &str = "ak:realm:01904100-0000-7000-8000-aaaaaaaaaaaa";
const REALM_B: &str = "ak:realm:01904100-0000-7000-8000-bbbbbbbbbbbb";
const REALM_C: &str = "ak:realm:01904100-0000-7000-8000-cccccccccccc";

fn op(kind: &str, realm_id: &str, payload: Value) -> Operation {
    Operation::create(
        arkret_identifiers::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
            .unwrap(),
        arkret_identifiers::RealmId::new(realm_id).unwrap(),
        kind,
        payload,
    )
}

fn link_op(source: &str, target: &str, link_kind: &str, status: Option<&str>) -> Operation {
    let mut payload = json!({
        "target_realm_id": target,
        "link_kind": link_kind,
    });
    if let Some(s) = status {
        payload["status"] = json!(s);
    }
    op(arkret_wire::EventKind::REALM_LINK, source, payload)
}

#[test]
fn realm_link_projects_all_eight_canonical_kinds() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let kinds = [
        "governed_by",
        "discoverable_from",
        "join_gate_from",
        "inherits_policy_from",
        "confidential_extension_of",
        "mirror_of",
        "split_from",
        "replaces",
    ];

    for kind in &kinds {
        let effect = state.apply(&link_op(REALM_A, REALM_B, kind, None), &hlc);
        match effect {
            ProjectionEffect::RealmLinkProjected {
                realm_id,
                target_realm_id,
                link_kind,
                status,
            } => {
                assert_eq!(realm_id, REALM_A);
                assert_eq!(target_realm_id, REALM_B);
                assert_eq!(link_kind, *kind);
                assert_eq!(status, "active");
            }
            other => panic!("expected RealmLinkProjected for kind {kind}, got {other:?}"),
        }
    }

    // Structured cache has eight rows for REALM_A (outbound) + eight
    // mirrored rows for REALM_B (inbound).
    let outbound = state.realm_links_query(REALM_A, RealmLinkDirection::Outbound, None);
    assert_eq!(outbound.len(), 8);
    let inbound = state.realm_links_query(REALM_B, RealmLinkDirection::Inbound, None);
    assert_eq!(inbound.len(), 8);
    let both = state.realm_links_query(REALM_A, RealmLinkDirection::Both, None);
    assert_eq!(both.len(), 8); // REALM_A has no inbound from its outbound, so still 8.
}

#[test]
fn realm_link_query_filters_by_link_kind_allow() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    state.apply(&link_op(REALM_A, REALM_B, "governed_by", None), &hlc);
    state.apply(&link_op(REALM_A, REALM_C, "mirror_of", None), &hlc);
    state.apply(&link_op(REALM_A, REALM_B, "split_from", None), &hlc);

    let only_govern = state.realm_links_query(
        REALM_A,
        RealmLinkDirection::Outbound,
        Some(&["governed_by".to_owned()]),
    );
    assert_eq!(only_govern.len(), 1);
    assert_eq!(only_govern[0].link_kind, "governed_by");

    let multi = state.realm_links_query(
        REALM_A,
        RealmLinkDirection::Outbound,
        Some(&["governed_by".to_owned(), "mirror_of".to_owned()]),
    );
    assert_eq!(multi.len(), 2);
}

#[test]
fn realm_link_rejects_invalid_link_kind() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let bad = link_op(REALM_A, REALM_B, "totally_made_up_kind", None);
    match state.apply(&bad, &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "realm_link_kind_invalid");
        }
        other => panic!("expected Rejected(realm_link_kind_invalid), got {other:?}"),
    }
}

#[test]
fn realm_link_rejects_self_reference() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let bad = link_op(REALM_A, REALM_A, "governed_by", None);
    match state.apply(&bad, &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "realm_link_self_reference");
        }
        other => panic!("expected Rejected(realm_link_self_reference), got {other:?}"),
    }
}

#[test]
fn realm_link_rejects_invalid_status() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let bad = link_op(REALM_A, REALM_B, "governed_by", Some("not_a_status"));
    match state.apply(&bad, &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "realm_link_status_invalid");
        }
        other => panic!("expected Rejected(realm_link_status_invalid), got {other:?}"),
    }
}

#[test]
fn realm_link_status_flip_replaces_in_place() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    state.apply(
        &link_op(REALM_A, REALM_B, "governed_by", Some("active")),
        &hlc,
    );
    state.apply(
        &link_op(REALM_A, REALM_B, "governed_by", Some("rejected")),
        &hlc,
    );
    let rows = state.realm_links_query(REALM_A, RealmLinkDirection::Outbound, None);
    // Exactly one row per (source, target, kind) tuple.
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, "rejected");
}

#[test]
fn realm_link_cell_value_persisted() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    state.apply(&link_op(REALM_A, REALM_B, "join_gate_from", None), &hlc);
    let cell_id = soland_domain::reducer::realm_links::realm_link_projection_cell_ref(
        REALM_A,
        REALM_B,
        "join_gate_from",
    )
    .unwrap();
    let value = state.cell_value(&cell_id).expect("cell must be projected");
    assert_eq!(
        value.get("link_kind").and_then(Value::as_str),
        Some("join_gate_from")
    );
    assert_eq!(value.get("status").and_then(Value::as_str), Some("active"));
    assert_eq!(
        value.get("target_realm_id").and_then(Value::as_str),
        Some(REALM_B)
    );
}
