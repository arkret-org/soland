//! Reducer-level tests for the `cx.space.delivery_binding_policy`
//! cell projection + `cx.member.state{join,routable}` validation
//! (Round C46, spec join-policy.md §5.1).
//!
//! These tests drive `ProjectionState` directly so they stay tight on
//! the reducer's policy enforcement and don't depend on the full HTTP /
//! Move/Anchor pipeline. The HTTP wire path that feeds these reducer
//! calls is exercised separately in `tests/http_api.rs`.

use contrix_sdk::Operation;
use serde_json::{Value, json};
use soland::hlc::ServerHlc;
use soland::reducer::{ProjectionEffect, ProjectionState};

const SPACE_A: &str = "cx:space:01904100-0000-7000-8000-cfc039892036";

fn op(kind: &str, space_id: &str, payload: Value) -> Operation {
    Operation::create(
        contrix_sdk::OperationId::new(format!("cx:operation:{}", uuid::Uuid::now_v7())).unwrap(),
        contrix_sdk::SpaceId::new(space_id).unwrap(),
        kind,
        payload,
    )
}

fn apply_policy(state: &mut ProjectionState, hlc: &ServerHlc, payload: Value) {
    let effect = state.apply(
        &op(
            soland::kinds::CX_SPACE_DELIVERY_BINDING_POLICY,
            SPACE_A,
            payload,
        ),
        hlc,
    );
    assert!(
        !matches!(effect, ProjectionEffect::Ignored),
        "delivery_binding_policy projection produced Ignored; expected the cell to be written"
    );
}

fn join_op(member: &str, binding: Value) -> Operation {
    op(
        soland::kinds::CX_MEMBER_STATE,
        SPACE_A,
        json!({
            "actor_id": member,
            "membership": "join",
            "role": "member",
            "delivery_status": "routable",
            "delivery_binding": binding,
        }),
    )
}

// ── 1. delivery_binding_policy_member_join_test ─────────────────────────
//
// `recipient_service_did` outside the policy's `allowed_recipient_services`
// allow-list MUST be rejected with `recipient_service_not_allowed`.

#[test]
fn delivery_binding_policy_rejects_disallowed_recipient_service() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    apply_policy(
        &mut state,
        &hlc,
        json!({
            "allow_binding_sources": ["explicit", "invite"],
            "allow_did_document_default": false,
            "allowed_recipient_services": ["did:web:principal.acme.example"],
            "required_endorsers": [],
            "allow_unroutable_membership": false,
            "rebind_authorization": "member_and_admin"
        }),
    );

    // Cell projected — sanity check.
    assert!(state.delivery_binding_policy_cell_value(SPACE_A).is_some());

    // Recipient is NOT in the allow-list → reject.
    let bad = join_op(
        "did:web:bob",
        json!({
            "binding_source": "explicit",
            "recipient_service_did": "did:web:rogue.example",
            "service_acceptance_ref": "cx:event:01904100-0000-7000-8000-aaaaaaaaaaaa",
            "resolved_at": "2026-05-19T00:00:00Z",
        }),
    );
    match state.apply(&bad, &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "recipient_service_not_allowed");
        }
        other => panic!("expected Rejected(recipient_service_not_allowed), got {other:?}"),
    }
    // Membership cache NOT populated on rejection.
    assert!(state.member(SPACE_A, "did:web:bob").is_none());

    // Recipient IN the allow-list → accept.
    let good = join_op(
        "did:web:alice",
        json!({
            "binding_source": "explicit",
            "recipient_service_did": "did:web:principal.acme.example",
            "service_acceptance_ref": "cx:event:01904100-0000-7000-8000-bbbbbbbbbbbb",
            "resolved_at": "2026-05-19T00:00:00Z",
        }),
    );
    let effect = state.apply(&good, &hlc);
    assert!(
        matches!(effect, ProjectionEffect::MembershipChanged { .. }),
        "expected MembershipChanged on policy-passing join, got {effect:?}"
    );
}

// `binding_source` not in `allow_binding_sources` → reject.
#[test]
fn delivery_binding_policy_rejects_disallowed_binding_source() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    apply_policy(
        &mut state,
        &hlc,
        json!({
            "allow_binding_sources": ["invite", "organization_policy"],
            "allow_did_document_default": false,
            "allowed_recipient_services": [],
            "required_endorsers": [],
        }),
    );

    let bad = join_op(
        "did:web:carol",
        json!({
            "binding_source": "explicit",
            "recipient_service_did": "did:web:principal.acme.example",
            "service_acceptance_ref": "cx:event:01904100-0000-7000-8000-cccccccccccc",
        }),
    );
    match state.apply(&bad, &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "binding_source_not_allowed");
        }
        other => panic!("expected Rejected(binding_source_not_allowed), got {other:?}"),
    }
}

// `binding_source=explicit` but no `service_acceptance_ref` → reject.
#[test]
fn delivery_binding_policy_rejects_missing_service_acceptance() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    apply_policy(
        &mut state,
        &hlc,
        json!({
            "allow_binding_sources": ["explicit", "invite"],
            "allow_did_document_default": false,
            "allowed_recipient_services": [],
            "required_endorsers": ["did:web:acme.example"],
        }),
    );

    let bad = join_op(
        "did:web:dave",
        json!({
            "binding_source": "explicit",
            "recipient_service_did": "did:web:principal.acme.example",
            // service_acceptance_ref omitted
        }),
    );
    match state.apply(&bad, &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "service_acceptance_missing");
        }
        other => panic!("expected Rejected(service_acceptance_missing), got {other:?}"),
    }
}

// ── 2. delivery_binding_policy_no_did_fallback ──────────────────────────
//
// When the policy cell is unset, the reducer MUST fail-closed for
// routable joins — no DID Document fallback path.

#[test]
fn delivery_binding_policy_no_did_fallback_when_policy_unset() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    // No `cx.space.delivery_binding_policy` was projected for this Space.
    assert!(state.delivery_binding_policy_cell_value(SPACE_A).is_none());

    // Reasonable-looking binding (would pass a permissive policy) MUST
    // still be rejected because policy is unset.
    let bad = join_op(
        "did:web:eve",
        json!({
            "binding_source": "did_document_default",
            "recipient_service_did": "did:web:principal.example",
            "did_document_hash": "sha256:deadbeef",
            "resolved_at": "2026-05-19T00:00:00Z",
        }),
    );
    match state.apply(&bad, &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "delivery_binding_policy_unset");
        }
        other => panic!("expected Rejected(delivery_binding_policy_unset), got {other:?}"),
    }
    assert!(state.member(SPACE_A, "did:web:eve").is_none());
}

// Even when a policy exists, `did_document_default` is rejected unless
// `allow_did_document_default=true`. Spec §5.1.3 — organization /
// compliance Spaces MUST set this to false.
#[test]
fn delivery_binding_policy_rejects_did_document_default_when_disabled() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    apply_policy(
        &mut state,
        &hlc,
        json!({
            // Note: did_document_default deliberately included in the
            // source allow-list to test that the explicit
            // `allow_did_document_default` toggle still gates it.
            "allow_binding_sources": ["did_document_default", "explicit"],
            "allow_did_document_default": false,
            "allowed_recipient_services": [],
            "required_endorsers": [],
        }),
    );

    let bad = join_op(
        "did:web:fred",
        json!({
            "binding_source": "did_document_default",
            "recipient_service_did": "did:web:principal.example",
            "did_document_hash": "sha256:deadbeef",
        }),
    );
    match state.apply(&bad, &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "binding_source_not_allowed");
        }
        other => panic!("expected Rejected(binding_source_not_allowed), got {other:?}"),
    }
}

// ── 3. delivery_binding_handover_stale_test ─────────────────────────────
//
// When the policy carries a `policy_frontier` newer than the sender's
// carried `delivery_binding_frontier`, the join MUST be rejected with
// `delivery_binding_stale` so the sender re-resolves the new target
// rather than falling back to DID Document.

#[test]
fn delivery_binding_handover_stale_when_frontier_behind_policy() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    apply_policy(
        &mut state,
        &hlc,
        json!({
            "allow_binding_sources": ["explicit"],
            "allow_did_document_default": false,
            "allowed_recipient_services": ["did:web:principal.acme.example"],
            "required_endorsers": [],
            // Lexicographic comparison is fine here — frontier strings
            // are spec'd as monotonic per-Space identifiers.
            "policy_frontier": "cx:frontier:02000000",
        }),
    );

    // Carried frontier strictly older than policy_frontier → stale.
    let stale = join_op(
        "did:web:greta",
        json!({
            "binding_source": "explicit",
            "recipient_service_did": "did:web:principal.acme.example",
            "service_acceptance_ref": "cx:event:01904100-0000-7000-8000-dddddddddddd",
            "delivery_binding_frontier": "cx:frontier:01000000",
        }),
    );
    match state.apply(&stale, &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "delivery_binding_stale");
        }
        other => panic!("expected Rejected(delivery_binding_stale), got {other:?}"),
    }

    // Frontier caught up → accept.
    let fresh = join_op(
        "did:web:greta",
        json!({
            "binding_source": "explicit",
            "recipient_service_did": "did:web:principal.acme.example",
            "service_acceptance_ref": "cx:event:01904100-0000-7000-8000-eeeeeeeeeeee",
            "delivery_binding_frontier": "cx:frontier:02000000",
        }),
    );
    let effect = state.apply(&fresh, &hlc);
    assert!(
        matches!(effect, ProjectionEffect::MembershipChanged { .. }),
        "expected MembershipChanged on caught-up frontier, got {effect:?}"
    );
}

// Missing `delivery_binding_frontier` while the policy declares one is
// also stale — sender MUST be told to refresh, never fall back to DID
// Document.
#[test]
fn delivery_binding_handover_stale_when_frontier_absent() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    apply_policy(
        &mut state,
        &hlc,
        json!({
            "allow_binding_sources": ["explicit"],
            "allow_did_document_default": false,
            "allowed_recipient_services": [],
            "required_endorsers": [],
            "policy_frontier": "cx:frontier:02000000",
        }),
    );

    let no_frontier = join_op(
        "did:web:henry",
        json!({
            "binding_source": "explicit",
            "recipient_service_did": "did:web:principal.acme.example",
            "service_acceptance_ref": "cx:event:01904100-0000-7000-8000-ffffffffffff",
        }),
    );
    match state.apply(&no_frontier, &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "delivery_binding_stale");
        }
        other => panic!("expected Rejected(delivery_binding_stale), got {other:?}"),
    }
}

// ── 4. Cell projection round-trip ───────────────────────────────────────
//
// The policy event MUST land in the canonical cells map so other
// consumers (admin / sync / future sender redirect logic) can read it
// without the structured side-band cache.

#[test]
fn delivery_binding_policy_event_projects_cell_value() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    apply_policy(
        &mut state,
        &hlc,
        json!({
            "allow_binding_sources": ["explicit", "invite"],
            "allow_did_document_default": false,
            "allowed_recipient_services": ["did:web:principal.acme.example"],
            "required_endorsers": ["did:web:acme.example"],
            "allow_unroutable_membership": false,
            "rebind_authorization": "member_and_admin",
            "policy_frontier": "cx:frontier:02000000"
        }),
    );

    let value = state
        .delivery_binding_policy_cell_value(SPACE_A)
        .expect("policy cell must be projected");
    let allowed = value
        .get("allowed_recipient_services")
        .and_then(Value::as_array)
        .expect("allowed_recipient_services must be an array");
    assert_eq!(
        allowed.iter().filter_map(Value::as_str).collect::<Vec<_>>(),
        vec!["did:web:principal.acme.example"]
    );
    assert_eq!(
        state.delivery_binding_policy_frontier(SPACE_A),
        Some("cx:frontier:02000000")
    );
}
