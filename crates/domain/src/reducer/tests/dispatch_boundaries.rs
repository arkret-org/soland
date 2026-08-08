use serde_json::json;

use super::*;

const REALM_ID: &str = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";

#[test]
fn projection_context_stripping_removes_the_complete_shared_field_set() {
    let mut payload = serde_json::Map::from_iter([
        ("wire_field".to_owned(), json!("preserved")),
        ("nested".to_owned(), json!({"event_id": "wire-value"})),
    ]);
    for field in PROJECTION_CONTEXT_FIELDS {
        payload.insert((*field).to_owned(), json!("projection-only"));
    }

    let stripped = projection_context_stripped_payload(&Value::Object(payload));

    assert_eq!(
        stripped,
        json!({
            "wire_field": "preserved",
            "nested": {"event_id": "wire-value"}
        })
    );
    assert_eq!(PROJECTION_CONTEXT_FIELDS.len(), 15);
}

#[test]
fn lattice_registry_dispatch_rejects_unknown_event_kind_observably() {
    let operation = make_operation("ak.unknown.projection", REALM_ID, json!({}));
    let effect = ProjectionState::default().apply_via_lattice_registry(
        &operation,
        &[],
        &ServerHlc::new("dispatch-boundary-test"),
        &lattice_kinds::default_lattice_registry(),
    );

    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason } if reason == "unknown_event_kind"
    ));
}
