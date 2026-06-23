use super::*;
use crate::reducer::*;

#[test]
fn redaction_human_reason_prefers_explicit_field() {
    let payload = serde_json::json!({
        "target_event_id": "ck:event:01904100-0000-7000-8000-000000000abc",
        "reason": "machine policy",
        "human_reason": "moderator request"
    });

    assert_eq!(
        redaction_human_reason(&payload).as_deref(),
        Some("moderator request")
    );
}

#[test]
fn message_create_and_query() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let op = make_operation(
        cokret_sdk::events::kinds::MESSAGE_CREATE,
        "ck:realm:01904100-0000-7000-8000-cfc039892036",
        serde_json::json!({
            "event_id": "ck:event:01904100-0000-7000-8000-caaa6a15bce1",
            "sender": "did:web:alice",
            "thread_id": "ck:strand:1",
            "content": {"kind": "ck.content.text", "body": "hello"}
        }),
    );
    let effect = state.apply(&op, &hlc);
    assert!(matches!(effect, ProjectionEffect::MessageCreated(_)));

    let msgs = state.messages_for_realm("ck:realm:01904100-0000-7000-8000-cfc039892036");
    assert_eq!(msgs.len(), 1);
    assert_eq!(
        msgs[0].event_id,
        "ck:event:01904100-0000-7000-8000-caaa6a15bce1"
    );
}

#[test]
fn redaction_hides_message() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    state.apply(
        &make_operation(
            cokret_sdk::events::kinds::MESSAGE_CREATE,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "event_id": "ck:event:01904100-0000-7000-8000-caaa6a15bce1",
                "sender": "did:web:alice",
                "thread_id": "ck:strand:1",
                "content": {"kind": "ck.content.text", "body": "hello"}
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            cokret_sdk::events::kinds::MESSAGE_REDACT,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "target_event_id": "ck:event:01904100-0000-7000-8000-caaa6a15bce1",
                "by": "did:web:alice",
                "reason": "wrong room"
            }),
        ),
        &hlc,
    );

    assert!(
        state
            .messages_for_realm("ck:realm:01904100-0000-7000-8000-cfc039892036")
            .is_empty()
    );
    assert!(
        state
            .redactions
            .contains("ck:event:01904100-0000-7000-8000-caaa6a15bce1")
    );
    // The original MessageState is preserved (only the
    // parallel cell + flat redactions index move).
    assert!(
        state
            .messages
            .contains_key("ck:event:01904100-0000-7000-8000-caaa6a15bce1")
    );
    let cell = state
        .redaction_cells
        .get("ck:event:01904100-0000-7000-8000-caaa6a15bce1")
        .cloned()
        .unwrap()
        .unwrap();
    assert_eq!(cell.by, "did:web:alice");
    assert_eq!(cell.reason.as_deref(), Some("wrong room"));
}

// ── Redaction reducer tests ───────────────────────────────────────

fn redact_make_message(state: &mut ProjectionState, hlc: &ServerHlc, event_id: &str) {
    state.apply(
        &make_operation(
            cokret_sdk::events::kinds::MESSAGE_CREATE,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "event_id": event_id,
                "sender": "did:web:alice",
                "thread_id": "ck:strand:1",
                "content": {"kind": "ck.content.text", "body": "hello"}
            }),
        ),
        hlc,
    );
}

#[test]
fn mal14_tombstone_visible_to_author() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let event_id = "ck:event:01904100-0000-7000-8000-aaaaaaaaaaa1";
    redact_make_message(&mut state, &hlc, event_id);
    state.apply(
        &make_operation(
            cokret_sdk::events::kinds::MESSAGE_REDACT,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "target_event_id": event_id,
                "by": "did:web:alice",
                "reason": "policy:auto",
                "human_reason": "rethink",
            }),
        ),
        &hlc,
    );
    let view = state.projected_message(event_id, true).unwrap();
    // Author still sees the original payload (audit-view).
    assert!(view.content.is_some(), "author should see original content");
    // Tombstone metadata is also present.
    let r = view.redaction.unwrap();
    assert_eq!(r.by, "did:web:alice");
    assert_eq!(r.reason.as_deref(), Some("rethink"));
}

#[test]
fn mal14_tombstone_hidden_from_members() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let event_id = "ck:event:01904100-0000-7000-8000-aaaaaaaaaaa2";
    redact_make_message(&mut state, &hlc, event_id);
    state.apply(
        &make_operation(
            cokret_sdk::events::kinds::MESSAGE_REDACT,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "target_event_id": event_id,
                "by": "did:web:alice",
            }),
        ),
        &hlc,
    );
    let view = state.projected_message(event_id, false).unwrap();
    assert!(view.content.is_none(), "non-author should see tombstone");
    assert!(view.redaction.is_some());
}

#[test]
fn mal14_unredaction_clears_cell_and_index() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let event_id = "ck:event:01904100-0000-7000-8000-aaaaaaaaaaa3";
    redact_make_message(&mut state, &hlc, event_id);
    // Redact.
    state.apply(
        &make_operation(
            cokret_sdk::events::kinds::MESSAGE_REDACT,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "target_event_id": event_id,
                "by": "did:web:alice",
            }),
        ),
        &hlc,
    );
    assert!(state.redactions.contains(event_id));
    // Un-redact via cas-register set null.
    state.apply(
        &make_operation(
            cokret_sdk::events::kinds::MESSAGE_REDACT,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "target_event_id": event_id,
                "redaction_value": serde_json::Value::Null,
            }),
        ),
        &hlc,
    );
    assert!(
        !state.redactions.contains(event_id),
        "un-redaction must clear the flat tombstone index"
    );
    let cell = state.redaction_cells.get(event_id).unwrap();
    assert!(cell.is_none(), "parallel cell must be set to null");
    // Un-redacted message renders content for everyone again.
    let view_member = state.projected_message(event_id, false).unwrap();
    assert!(view_member.content.is_some());
    assert!(view_member.redaction.is_none());
}

#[test]
fn mal14_late_arriving_redaction_still_takes_effect() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let event_id = "ck:event:01904100-0000-7000-8000-aaaaaaaaaaa4";
    // Pre-create the projected message and let the projection
    // rendering query it once before the redaction lands.
    redact_make_message(&mut state, &hlc, event_id);
    let pre = state.projected_message(event_id, false).unwrap();
    assert!(pre.content.is_some());
    assert!(pre.redaction.is_none());
    // Now a delayed redaction arrives.
    state.apply(
        &make_operation(
            cokret_sdk::events::kinds::MESSAGE_REDACT,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "target_event_id": event_id,
                "by": "did:web:alice",
                "reason": "late",
            }),
        ),
        &hlc,
    );
    let post = state.projected_message(event_id, false).unwrap();
    assert!(
        post.content.is_none(),
        "late-arriving redaction must hide payload from non-authors"
    );
    let r = post.redaction.unwrap();
    assert_eq!(r.reason.as_deref(), Some("late"));
    // The flat-redactions index now has the entry.
    assert!(state.redactions.contains(event_id));
    // Author still sees the audit-view.
    let post_author = state.projected_message(event_id, true).unwrap();
    assert!(post_author.content.is_some());
}

#[test]
fn reaction_or_set_convergence() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    state.apply(
        &make_operation(
            cokret_sdk::events::kinds::REACTION_ADD,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "event_id": "ck:event:01904100-0000-7000-8000-caaa6a15bce1",
                "actor": "did:web:alice",
                "key": "👍"
            }),
        ),
        &hlc,
    );
    assert_eq!(
        state
            .reactions_for_event("ck:event:01904100-0000-7000-8000-caaa6a15bce1")
            .len(),
        1
    );

    state.apply(
        &make_operation(
            cokret_sdk::events::kinds::REACTION_REMOVE,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "event_id": "ck:event:01904100-0000-7000-8000-caaa6a15bce1",
                "actor": "did:web:alice",
                "key": "👍"
            }),
        ),
        &hlc,
    );
    assert_eq!(
        state
            .reactions_for_event("ck:event:01904100-0000-7000-8000-caaa6a15bce1")
            .len(),
        0
    );
}

#[test]
fn membership_join_leave() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    // `membership=join` MUST carry `delivery_status` per
    // cokret-spec/spec/v1/zh/governance/join-policy.md §5.1.1.
    // We use `unroutable` so the projection write path does not
    // additionally require a projected `ck.realm.delivery_binding_policy`
    // cell (`routable` joins are exercised by the delivery-binding
    // suite).
    state.apply(
        &make_operation(
            cokret_sdk::events::kinds::MEMBER_STATE,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "actor_id": "did:web:bob",
                "membership": "join",
                "role": "member",
                "delivery_status": "unroutable"
            }),
        ),
        &hlc,
    );
    assert_eq!(
        state
            .members_of_realm("ck:realm:01904100-0000-7000-8000-cfc039892036")
            .len(),
        1
    );

    state.apply(
        &make_operation(
            cokret_sdk::events::kinds::MEMBER_STATE,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "actor_id": "did:web:bob",
                "membership": "leave"
            }),
        ),
        &hlc,
    );
    assert_eq!(
        state
            .members_of_realm("ck:realm:01904100-0000-7000-8000-cfc039892036")
            .len(),
        0
    );
}

#[test]
fn message_revise_creates_chain() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    state.apply(
        &make_operation(
            cokret_sdk::events::kinds::MESSAGE_CREATE,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "event_id": "ck:event:01904100-0000-7000-8000-caaa6a15bce1",
                "sender": "did:web:alice",
                "thread_id": "ck:strand:1",
                "content": {"kind": "ck.content.text", "body": "original"}
            }),
        ),
        &hlc,
    );

    let revise = make_operation(
        cokret_sdk::events::kinds::MESSAGE_REVISE,
        "ck:realm:01904100-0000-7000-8000-cfc039892036",
        serde_json::json!({
            "target_ref": "ck:event:01904100-0000-7000-8000-caaa6a15bce1",
            "content": {"kind": "ck.content.text", "body": "revised"}
        }),
    );
    let revision_id = revise.operation_id.to_string();
    state.apply(&revise, &hlc);

    let msgs = state.messages_for_realm("ck:realm:01904100-0000-7000-8000-cfc039892036");
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].event_id, revision_id);
    assert_eq!(msgs[0].content["body"], "revised");
    assert_eq!(state.messages.len(), 2);
    let revision = state.messages.get(&revision_id).unwrap();
    assert_eq!(
        revision.revision_of.as_deref(),
        Some("ck:event:01904100-0000-7000-8000-caaa6a15bce1")
    );
}
