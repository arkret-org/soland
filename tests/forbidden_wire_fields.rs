//! CXP-0007 (spec b7d35be / floor 2b0d70d) — soland wire-layer hard-reject
//! coverage for the SDK's `forbidden-wire-fields.json` set.
//!
//! The reducer no longer exposes a fallback path for the legacy
//! `discussion_realm_ref` field; the wire validator
//! (`routing/events/event_log::first_forbidden_wire_field`) walks any inbound
//! payload sub-tree and refuses to admit an Event Envelope whose `payload`
//! carries one of the SDK's `FORBIDDEN_WIRE_FIELDS` keys.
//!
//! This integration test exercises the SDK predicate directly so the rejection
//! contract stays anchored to the spec registry. The full HTTP round-trip
//! (POST /api/v1/events → 400 `forbidden_wire_field`) is exercised by the
//! main conformance gate suite once a Postgres harness is wired; this
//! lightweight check guarantees the SDK→soland contract that the wire
//! rejection depends on, and protects against accidental removal of any of
//! the load-bearing legacy keys (`discussion_realm_ref`, `discussion_space_ref`,
//! and the CXP-0007 batch-renamed `*_ref` set).

use contrix_sdk::forbidden_wire_fields::{FORBIDDEN_WIRE_FIELDS, is_forbidden_wire_field};

#[test]
fn discussion_realm_ref_is_hard_rejected() {
    assert!(
        is_forbidden_wire_field("discussion_realm_ref"),
        "discussion_realm_ref MUST stay in the SDK hard-reject set so the \
         soland wire validator can fail closed without re-implementing the \
         spec's forbidden-wire-fields table",
    );
}

#[test]
fn cxp_0007_batch_renamed_ref_fields_are_hard_rejected() {
    for field in [
        "discussion_realm_ref",
        "discussion_space_ref",
        "parent_ref",
        "default_realm_ref",
        "scope_ref",
        "default_scope_ref",
        "retention_policy_ref",
        "disclosure_policy_ref",
        "rate_limit_policy_ref",
    ] {
        assert!(
            is_forbidden_wire_field(field),
            "{field} MUST be in the SDK hard-reject set per \
             spec/v1/artifacts/registry/forbidden-wire-fields.json"
        );
    }
}

#[test]
fn canonical_scope_circle_id_is_accepted() {
    // The CXP-0007 replacement field for the pre-rename `scope_ref` /
    // `discussion_realm_ref` family. soland's payload walker MUST NOT
    // reject the canonical form.
    assert!(!is_forbidden_wire_field("scope_circle_id"));
    assert!(!is_forbidden_wire_field("default_scope_circle_id"));
    assert!(!is_forbidden_wire_field("effective_scope"));
}

#[test]
fn forbidden_set_is_nonempty_and_static() {
    // Smoke check that the upstream constant stays a non-empty static slice;
    // if the SDK ever flattens this into a Vec or moves it behind a function,
    // soland's `first_forbidden_wire_field` walker would need to be updated
    // in lock-step.
    assert!(!FORBIDDEN_WIRE_FIELDS.is_empty());
}
