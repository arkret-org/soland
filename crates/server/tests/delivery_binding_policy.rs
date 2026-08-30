//! Reducer-level tests for the `ak.realm.delivery_binding_policy`
//! cell projection + `ak.member.state{join,routable}` validation
//! (Round C46, spec join-policy.md §5.1).
//!
//! These tests drive `ProjectionState` directly so they stay tight on
//! the reducer's policy enforcement and don't depend on the full HTTP /
//! Move/Seal pipeline. The HTTP wire path that feeds these reducer
//! calls is exercised separately in `tests/http_api/`.

use arkret_event_draft::ProjectedEventOperation as Operation;
use serde_json::{Value, json};
use soland_domain::hlc::ServerHlc;
use soland_domain::reducer::{ProjectionEffect, ProjectionState};

const REALM_A: &str = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";

fn op(kind: impl AsRef<str>, realm_id: &str, payload: Value) -> Operation {
    arkret_event_draft::test_support::raw_projected_operation(
        arkret_identifiers::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
            .unwrap(),
        arkret_identifiers::RealmId::new(realm_id).unwrap(),
        kind.as_ref(),
        payload,
    )
}

fn apply_policy(state: &mut ProjectionState, hlc: &ServerHlc, payload: Value) {
    let operation = op(
        arkret_wire::EventKind::RealmDeliveryBindingPolicy,
        REALM_A,
        payload,
    );
    operation
        .typed_payload::<arkret_wire::event_spec::RealmDeliveryBindingPolicy>()
        .expect("delivery-binding policy fixture must use the canonical typed wire shape");
    let effect = state.apply(&operation, hlc);
    assert!(
        !matches!(effect, ProjectionEffect::Ignored),
        "delivery_binding_policy projection produced Ignored; expected the cell to be written"
    );
}

fn join_op(member: &str, binding: Value) -> Operation {
    join_op_for_realm(REALM_A, member, binding)
}

fn complete_binding(mut binding: Value) -> Value {
    if binding.get("recipient_kind").is_none() {
        binding["recipient_kind"] = json!("principal_server");
    }
    if binding.get("binding_scope").is_none() {
        binding["binding_scope"] = json!("realm");
    }
    if binding.get("delivery_modes").is_none() {
        binding["delivery_modes"] = json!(["events"]);
    }
    if binding.get("service_resolution").is_none()
        && let Some(recipient_id) = binding.get("recipient_id").and_then(Value::as_str)
    {
        let service_id = arkret_identifiers::DidCoreId::new(recipient_id).unwrap();
        binding["service_resolution"] = json!({
            "current_record_url": format!(
                "https://fixture.example{}",
                arkret_models_identity::identity_resolution::canonical_service_current_record_path(
                    &service_id,
                )
            )
        });
    }
    if binding.get("resolved_at").is_none() {
        binding["resolved_at"] = json!("2026-05-19T00:00:00.000Z");
    }
    binding
}

fn join_op_for_realm(realm_id: &str, member: &str, binding: Value) -> Operation {
    let binding = complete_binding(binding);
    let operation = op(
        arkret_wire::EventKind::MemberState,
        realm_id,
        json!({
            "realm_id": realm_id,
            "actor_id": member,
            "membership": "join",
            "delivery_status": "routable",
            "delivery_binding": binding,
        }),
    );
    operation
        .typed_payload::<arkret_wire::event_spec::MemberState>()
        .expect("delivery-policy fixture membership payload");
    operation
}

fn create_direct_conversation(state: &mut ProjectionState, hlc: &ServerHlc) -> String {
    let creator = arkret_identifiers::Did::new("did:web:alice.example").unwrap();
    let creator_actor_id = arkret_wire::project_did_to_core_id(&creator).unwrap();
    let payload = arkret_models_collaboration::objects::direct_conversation::direct_conversation_realm_create_payload(
        arkret_wire::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
        arkret_identifiers::TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
        soland_test_support::cba_basis::test_single_signer_notary("did:web:alice.example"),
        chrono::Utc::now(),
    )
    .unwrap();
    let payload = serde_json::to_value(payload).unwrap();
    let event = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::RealmCreate.as_str(),
        arkret_wire::ScopeRef::RealmGenesis,
        creator_actor_id,
        soland_test_support::fixture_principal_server_id(),
        0,
        arkret_identifiers::Hlc::new("000000000000-0000-00000000").unwrap(),
        payload.clone(),
        chrono::DateTime::parse_from_rfc3339("2026-07-25T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
    );
    let event = event.unwrap();
    let realm_id = arkret_identifiers::RealmId::from_event_id(&event.event_id);
    let writes = arkret_schema::project_registered_cell_writes(
        &event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let create = arkret_event_draft::ProjectedEventOperation::from_accepted_event(
        arkret_identifiers::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
            .unwrap(),
        arkret_wire::OperationKind::Create,
        None,
        &event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let effect = state.apply_projected(&create, &writes, hlc);
    assert!(matches!(
        effect,
        ProjectionEffect::RealmLifecycle { action, .. } if action == "create"
    ));
    assert!(
        state.realm_is_direct_conversation(realm_id.as_str()),
        "projected Realm genesis was not recognized as Direct Conversation: {:?}",
        state.realm_genesis_cell_value(realm_id.as_str())
    );
    realm_id.to_string()
}

// ── 1. delivery_binding_policy_member_join_test ─────────────────────────
//
// `recipient_id` outside the policy's `allowed_recipient_ids`
// allow-list MUST be rejected with `recipient_service_not_allowed`.

#[test]
fn delivery_binding_policy_rejects_disallowed_recipient_service() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    apply_policy(
        &mut state,
        &hlc,
        json!({
            "allowed_binding_sources": ["explicit", "join_policy"],
            "did_document_default_allowed": false,
            "allowed_recipient_ids": ["ak:did_core:web:principal.acme.example"],
            "required_endorser_ids": [],
            "unroutable_membership_allowed": false,
            "rebind_authorization": "member_and_admin"
        }),
    );

    // Cell projected — sanity check.
    assert!(
        state
            .realm_delivery_binding_policy_cell_value(REALM_A)
            .is_some()
    );

    // Recipient is NOT in the allow-list → reject.
    let bad = join_op(
        "ak:did_core:web:bob",
        json!({
            "binding_source": "explicit",
            "recipient_id": "ak:did_core:web:rogue.example",
            "service_acceptance_ref": "ak:event:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu",
            "resolved_at": "2026-05-19T00:00:00.000Z",
        }),
    );
    match state.apply(&bad, &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "recipient_service_not_allowed");
        }
        other => panic!("expected Rejected(recipient_service_not_allowed), got {other:?}"),
    }
    // Membership cache NOT populated on rejection.
    assert!(state.member(REALM_A, "ak:did_core:web:bob").is_none());

    // Recipient IN the allow-list → accept.
    let good = join_op(
        "ak:did_core:web:alice",
        json!({
            "binding_source": "explicit",
            "recipient_id": "ak:did_core:web:principal.acme.example",
            "service_acceptance_ref": "ak:event:AeJsr0sf3TZ_Cuzj2uLddhd-O-Cywvdj8ypnqpVG8zim",
            "resolved_at": "2026-05-19T00:00:00.000Z",
        }),
    );
    let effect = state.apply(&good, &hlc);
    assert!(
        matches!(effect, ProjectionEffect::MembershipChanged { .. }),
        "expected MembershipChanged on policy-passing join, got {effect:?}"
    );
}

// `allowed_recipient_ids` is fail-closed (member-delivery-binding.md
// §2 / §4): an empty array `[]` — and an omitted field, which defaults to
// `[]` — rejects every recipient service; only the explicit sentinel
// `["*"]` means unrestricted.

#[test]
fn delivery_binding_policy_empty_recipient_allow_list_rejects_all() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    apply_policy(
        &mut state,
        &hlc,
        json!({
            "allowed_binding_sources": ["explicit"],
            "did_document_default_allowed": false,
            "allowed_recipient_ids": [],
            "required_endorser_ids": [],
        }),
    );

    let bad = join_op(
        "ak:did_core:web:ida",
        json!({
            "binding_source": "explicit",
            "recipient_id": "ak:did_core:web:principal.acme.example",
            "service_acceptance_ref": "ak:event:AQlHdUE3urVdfxTt7ycDMQRrgYPGEa5lOPTTdGDDO7w_",
        }),
    );
    match state.apply(&bad, &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "recipient_service_not_allowed");
        }
        other => panic!("expected Rejected(recipient_service_not_allowed), got {other:?}"),
    }
}

#[test]
fn delivery_binding_policy_omitted_recipient_allow_list_rejects_all() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    apply_policy(
        &mut state,
        &hlc,
        json!({
            "allowed_binding_sources": ["explicit"],
            "did_document_default_allowed": false,
            // allowed_recipient_ids omitted → defaults to [] (fail-closed).
            "required_endorser_ids": [],
        }),
    );

    let bad = join_op(
        "ak:did_core:web:jane",
        json!({
            "binding_source": "explicit",
            "recipient_id": "ak:did_core:web:principal.acme.example",
            "service_acceptance_ref": "ak:event:AdaVg413OwhSu62wpakXmVkeXGpGgVIRhwmIKtrcSFcT",
        }),
    );
    match state.apply(&bad, &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "recipient_service_not_allowed");
        }
        other => panic!("expected Rejected(recipient_service_not_allowed), got {other:?}"),
    }
}

#[test]
fn delivery_binding_policy_star_sentinel_is_unrestricted() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    apply_policy(
        &mut state,
        &hlc,
        json!({
            "allowed_binding_sources": ["did_document_default"],
            "did_document_default_allowed": true,
            "allowed_recipient_ids": ["*"],
            "required_endorser_ids": [],
        }),
    );

    let good = join_op(
        "ak:did_core:web:kim",
        json!({
            "binding_source": "did_document_default",
            "recipient_id": "ak:did_core:web:principal.anywhere.example",
            "document_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        }),
    );
    let effect = state.apply(&good, &hlc);
    assert!(
        matches!(effect, ProjectionEffect::MembershipChanged { .. }),
        "expected MembershipChanged under the [\"*\"] sentinel, got {effect:?}"
    );
}

#[test]
fn delivery_binding_policy_legacy_recipient_field_does_not_authorize_join() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let legacy_policy = op(
        arkret_wire::EventKind::RealmDeliveryBindingPolicy,
        REALM_A,
        json!({
            "allowed_binding_sources": ["did_document_default"],
            "did_document_default_allowed": true,
            "allowed_recipient_services": ["*"],
        }),
    );
    assert!(
        legacy_policy
            .typed_payload::<arkret_wire::event_spec::RealmDeliveryBindingPolicy>()
            .is_err(),
        "the removed allowed_recipient_services wire field must fail typed decoding"
    );
    assert!(!matches!(
        state.apply(&legacy_policy, &hlc),
        ProjectionEffect::Ignored
    ));

    let join = join_op(
        "ak:did_core:web:legacy-field-member",
        json!({
            "binding_source": "did_document_default",
            "recipient_id": "ak:did_core:web:principal.anywhere.example",
            "document_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        }),
    );
    assert!(matches!(
        state.apply(&join, &hlc),
        ProjectionEffect::Rejected { reason } if reason == "recipient_service_not_allowed"
    ));
}

// `binding_source` not in `allowed_binding_sources` → reject.
#[test]
fn delivery_binding_policy_rejects_disallowed_binding_source() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    apply_policy(
        &mut state,
        &hlc,
        json!({
            "allowed_binding_sources": ["organization_policy"],
            "did_document_default_allowed": false,
            "allowed_recipient_ids": [],
            "required_endorser_ids": [],
        }),
    );

    let bad = join_op(
        "ak:did_core:web:carol",
        json!({
            "binding_source": "explicit",
            "recipient_id": "ak:did_core:web:principal.acme.example",
            "service_acceptance_ref": "ak:event:AdIAmf-J5rIPxEomGXwJblJdhNg-TllVN8uRTI85EUIM",
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
            "allowed_binding_sources": ["explicit", "join_policy"],
            "did_document_default_allowed": false,
            // Sentinel ["*"] lifts only the recipient allow-list dimension so
            // this test exercises the service_acceptance_ref check.
            "allowed_recipient_ids": ["*"],
            "required_endorser_ids": ["ak:did_core:web:acme.example"],
        }),
    );

    let bad = join_op(
        "ak:did_core:web:dave",
        json!({
            "binding_source": "explicit",
            "recipient_id": "ak:did_core:web:principal.acme.example",
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

    // No `ak.realm.delivery_binding_policy` was projected for this Realm.
    assert!(
        state
            .realm_delivery_binding_policy_cell_value(REALM_A)
            .is_none()
    );

    // Reasonable-looking binding (would pass a permissive policy) MUST
    // still be rejected because policy is unset.
    let bad = join_op(
        "ak:did_core:web:eve",
        json!({
            "binding_source": "did_document_default",
            "recipient_id": "ak:did_core:web:principal.example",
            "document_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "resolved_at": "2026-05-19T00:00:00.000Z",
        }),
    );
    match state.apply(&bad, &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "delivery_binding_policy_unset");
        }
        other => panic!("expected Rejected(delivery_binding_policy_unset), got {other:?}"),
    }
    assert!(state.member(REALM_A, "ak:did_core:web:eve").is_none());
}

#[test]
fn direct_conversation_bootstrap_reason_does_not_bypass_atomic_unit() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = create_direct_conversation(&mut state, &hlc);

    let founding_binding = complete_binding(json!({
        "binding_source": "explicit",
        "recipient_id": "ak:did_core:web:soland-beta.example",
        "service_acceptance_ref": "ak:event:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu",
        "resolved_at": "2026-07-25T00:00:00.000Z"
    }));
    let founding_peer = op(
        arkret_wire::EventKind::MemberState,
        &realm_id,
        json!({
            "realm_id": realm_id,
            "actor_id": "ak:did_core:web:bob.example",
            "sender": "ak:did_core:web:alice.example",
            "membership": "join",
            "reason": "direct_conversation_bootstrap",
            "delivery_status": "routable",
            "delivery_binding": founding_binding
        }),
    );
    let effect = state.apply(&founding_peer, &hlc);
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { reason } if reason == "delivery_binding_policy_unset"
    ));
}

#[test]
fn direct_conversation_join_without_bootstrap_reason_still_requires_policy() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = create_direct_conversation(&mut state, &hlc);

    let ordinary_join = join_op_for_realm(
        &realm_id,
        "ak:did_core:web:bob.example",
        json!({
            "binding_source": "explicit",
            "recipient_id": "ak:did_core:web:soland-beta.example",
            "service_acceptance_ref": "ak:event:AdIAmf-J5rIPxEomGXwJblJdhNg-TllVN8uRTI85EUIM",
            "resolved_at": "2026-07-25T00:00:00.000Z"
        }),
    );
    assert!(matches!(
        state.apply(&ordinary_join, &hlc),
        ProjectionEffect::Rejected { reason } if reason == "delivery_binding_policy_unset"
    ));
}

// Even when a policy exists, `did_document_default` is rejected unless
// `did_document_default_allowed=true`. Spec §5.1.3 — organization /
// compliance Realms MUST set this to false.
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
            // `did_document_default_allowed` toggle still gates it.
            "allowed_binding_sources": ["did_document_default", "explicit"],
            "did_document_default_allowed": false,
            "allowed_recipient_ids": [],
            "required_endorser_ids": [],
        }),
    );

    let bad = join_op(
        "ak:did_core:web:fred",
        json!({
            "binding_source": "did_document_default",
            "recipient_id": "ak:did_core:web:principal.example",
            "document_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        }),
    );
    match state.apply(&bad, &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "binding_source_not_allowed");
        }
        other => panic!("expected Rejected(binding_source_not_allowed), got {other:?}"),
    }
}

// ── 3. Cell projection round-trip ───────────────────────────────────────
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
            "allowed_binding_sources": ["explicit", "join_policy"],
            "did_document_default_allowed": false,
            "allowed_recipient_ids": ["ak:did_core:web:principal.acme.example"],
            "required_endorser_ids": ["ak:did_core:web:acme.example"],
            "unroutable_membership_allowed": false,
            "rebind_authorization": "member_and_admin"
        }),
    );

    let value = state
        .realm_delivery_binding_policy_cell_value(REALM_A)
        .expect("policy cell must be projected");
    let allowed = value
        .get("allowed_recipient_ids")
        .and_then(Value::as_array)
        .expect("allowed_recipient_ids must be an array");
    assert_eq!(
        allowed.iter().filter_map(Value::as_str).collect::<Vec<_>>(),
        vec!["ak:did_core:web:principal.acme.example"]
    );
}
