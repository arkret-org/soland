use super::*;

const REALM: &str = "ak:realm:01904100-0000-7000-8000-cfc039892036";
const SPACE: &str = "ak:space:01904100-0000-7000-8000-cfc039892037";
const STRAND: &str = "ak:strand:01904100-0000-7000-8000-cfc039892038";
const RELATION: &str = "ak:relation:01904100-0000-7000-8000-cfc039892039";
const EVENT: &str = "ak:event:01904100-0000-7000-8000-cfc039892040";

fn space_create() -> Operation {
    make_operation(
        arkret_wire::EventKind::SPACE_CREATE,
        REALM,
        serde_json::json!({
            "object": {
                "id": SPACE,
                "realm_id": REALM,
                "kind": "list",
                "title": "Inbox",
                "created_by": "did:web:alice.example"
            }
        }),
    )
}

fn strand_create() -> Operation {
    make_operation(
        arkret_wire::EventKind::STRAND_CREATE,
        REALM,
        serde_json::json!({
            "object": {
                "id": STRAND,
                "realm_id": REALM,
                "metadata": { "title": "Original" },
                "created_by": "did:web:alice.example"
            }
        }),
    )
}

#[test]
fn space_lifecycle_pending_replays_after_create() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let archive = make_operation(
        arkret_wire::EventKind::SPACE_ARCHIVE,
        REALM,
        serde_json::json!({ "space_id": SPACE }),
    );

    let effect = state.apply(&archive, &hlc);
    assert!(matches!(
        effect,
        ProjectionEffect::PendingReplayQueued { ref target_ref, .. } if target_ref == SPACE
    ));
    assert_eq!(state.pending_replay.get(SPACE).map(Vec::len), Some(1));

    state.apply(&space_create(), &hlc);

    assert_eq!(state.pending_replay.get(SPACE).map(Vec::len), None);
    assert_eq!(
        state.space_containers[SPACE].state,
        SpaceContainerLifecycleState::Archived
    );
}

#[test]
fn strand_update_pending_replays_after_create() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let update = make_operation(
        arkret_wire::EventKind::STRAND_UPDATE,
        REALM,
        serde_json::json!({
            "target_ref": STRAND,
            "patch": { "metadata.title": "Backfilled title" }
        }),
    );

    assert!(matches!(
        state.apply(&update, &hlc),
        ProjectionEffect::PendingReplayQueued { ref target_ref, .. } if target_ref == STRAND
    ));

    state.apply(&strand_create(), &hlc);

    assert!(!state.pending_replay.contains_key(STRAND));
    assert_eq!(state.strands[STRAND].title, "Backfilled title");
}

#[test]
fn relation_create_waits_for_unknown_endpoint() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let relation = make_operation(
        arkret_wire::EventKind::RELATION_CREATE,
        REALM,
        serde_json::json!({
            "relation_id": RELATION,
            "relation_kind": "references",
            "from_ref": STRAND,
            "to_ref": "did:web:bob.example"
        }),
    );

    assert!(matches!(
        state.apply(&relation, &hlc),
        ProjectionEffect::PendingReplayQueued { ref target_ref, .. } if target_ref == STRAND
    ));
    assert!(!state.relations.contains_key(RELATION));

    state.apply(&strand_create(), &hlc);

    assert!(!state.pending_replay.contains_key(STRAND));
    assert!(state.relations.contains_key(RELATION));
}

#[test]
fn relation_update_pending_replays_after_create() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let update = make_operation(
        arkret_wire::EventKind::RELATION_UPDATE,
        REALM,
        serde_json::json!({
            "relation_id": RELATION,
            "fields": { "rank": "m" }
        }),
    );

    assert!(matches!(
        state.apply(&update, &hlc),
        ProjectionEffect::PendingReplayQueued { ref target_ref, .. } if target_ref == RELATION
    ));

    let create = make_operation(
        arkret_wire::EventKind::RELATION_CREATE,
        REALM,
        serde_json::json!({
            "relation_id": RELATION,
            "relation_kind": "assigned_to",
            "from_ref": "did:web:alice.example",
            "to_ref": "did:web:bob.example"
        }),
    );
    state.apply(&create, &hlc);

    assert!(!state.pending_replay.contains_key(RELATION));
    assert_eq!(state.relations[RELATION].fields["rank"], "m");
}

#[test]
fn message_revision_pending_replays_after_original_event() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let revise = make_operation(
        arkret_wire::EventKind::MESSAGE_REVISE,
        REALM,
        serde_json::json!({
            "target_ref": EVENT,
            "content": { "kind": "ak.content.text", "body": "revised" }
        }),
    );
    let revision_id = revise.operation_id.to_string();

    assert!(matches!(
        state.apply(&revise, &hlc),
        ProjectionEffect::PendingReplayQueued { ref target_ref, .. } if target_ref == EVENT
    ));

    let create = make_operation(
        arkret_wire::EventKind::MESSAGE_CREATE,
        REALM,
        serde_json::json!({
            "event_id": EVENT,
            "sender": "did:web:alice.example",
            "thread_id": STRAND,
            "content": { "kind": "ak.content.text", "body": "original" }
        }),
    );
    state.apply(&create, &hlc);

    assert!(!state.pending_replay.contains_key(EVENT));
    assert_eq!(
        state.messages[&revision_id].revision_of.as_deref(),
        Some(EVENT)
    );
    assert_eq!(state.messages[&revision_id].content["body"], "revised");
}

#[test]
fn object_redaction_pending_replays_after_object_create() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let redaction = make_operation(
        arkret_wire::EventKind::REDACTION,
        REALM,
        serde_json::json!({
            "target_event_id": EVENT,
            "object_ref": STRAND,
            "by": "did:web:alice.example"
        }),
    );

    assert!(matches!(
        state.apply(&redaction, &hlc),
        ProjectionEffect::PendingReplayQueued { ref target_ref, .. } if target_ref == STRAND
    ));

    state.apply(&strand_create(), &hlc);

    assert!(!state.pending_replay.contains_key(STRAND));
    assert_eq!(state.strands[STRAND].state, ObjectLifecycleState::Redacted);
}
