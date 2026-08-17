use super::*;

const REALM: &str = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
const SPACE: &str = "ak:space:ATu1E_hCvaxzpXDswPMlN3ypwETWAa7O994Etg387rA6";
const STRAND: &str = "ak:strand:ATw_yJRaz2EEXAz-44u3FE2jGCVrpM3MQQZhKmxheDqW";
const RELATION: &str = "ak:relation:AdGtCyltkLGkKlrj8jazJOSalIEWRmqDqr2ikq7IOWcL";
/// The Event a `ak.relation.create` for [`RELATION`] must carry: the id is
/// `retype(event_id)` (`relation_create_payload` has no `relation_id` member),
/// so the fixture pins the Event token instead of the object id.
const RELATION_CREATE_EVENT: &str =
    "ak:event:AdGtCyltkLGkKlrj8jazJOSalIEWRmqDqr2ikq7IOWcL";
const EVENT: &str = "ak:event:AUiaY2u0jL7j0v1YowBxmn8e4QEpBDWA7QtOlNdhtZ1N";

fn space_create() -> Operation {
    make_operation(
        arkret_wire::EventKind::SpaceCreate,
        REALM,
        serde_json::json!({
            "object": {
                "id": SPACE,
                "realm_id": REALM,
                "kind": "list",
                "title": "Inbox",
                "created_by": "ak:did_core:web:alice.example"
            }
        }),
    )
}

fn strand_create() -> Operation {
    make_operation(
        arkret_wire::EventKind::StrandCreate,
        REALM,
        serde_json::json!({
            "object": {
                "id": STRAND,
                "realm_id": REALM,
                "metadata": { "title": "Original" },
                "created_by": "ak:did_core:web:alice.example"
            }
        }),
    )
}

#[test]
fn space_lifecycle_pending_replays_after_create() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let archive = make_operation(
        arkret_wire::EventKind::SpaceArchive,
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
        arkret_wire::EventKind::StrandUpdate,
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
        arkret_wire::EventKind::RelationCreate,
        REALM,
        serde_json::json!({
            "event_id": RELATION_CREATE_EVENT,
            "relation": {
                "kind": "references",
                "from_ref": STRAND,
                "to_ref": "ak:did_core:web:bob.example"
            }
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
        arkret_wire::EventKind::RelationUpdate,
        REALM,
        serde_json::json!({
            "relation_id": RELATION,
            "patch": { "fields.label": "m" }
        }),
    );

    assert!(matches!(
        state.apply(&update, &hlc),
        ProjectionEffect::PendingReplayQueued { ref target_ref, .. } if target_ref == RELATION
    ));

    let create = make_operation(
        arkret_wire::EventKind::RelationCreate,
        REALM,
        serde_json::json!({
            "event_id": RELATION_CREATE_EVENT,
            "relation": {
                "kind": "assigned_to",
                "from_ref": "ak:did_core:web:alice.example",
                "to_ref": "ak:did_core:web:bob.example"
            }
        }),
    );
    state.apply(&create, &hlc);

    assert!(!state.pending_replay.contains_key(RELATION));
    assert_eq!(state.relations[RELATION].fields["label"], "m");
}

#[test]
fn message_revision_pending_replays_after_original_event() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let revise = make_operation(
        arkret_wire::EventKind::MessageRevise,
        REALM,
        serde_json::json!({
            "target_ref": EVENT,
            "content": { "kind": "ak.content.text", "body": "revised" }
        }),
    );
    let revision_id = revise.context.event_id.to_string();

    assert!(matches!(
        state.apply(&revise, &hlc),
        ProjectionEffect::PendingReplayQueued { ref target_ref, .. } if target_ref == EVENT
    ));

    let create = make_operation(
        arkret_wire::EventKind::MessageCreate,
        REALM,
        serde_json::json!({
            "event_id": EVENT,
            "sender": "ak:did_core:web:alice.example",
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
        arkret_wire::EventKind::Redaction,
        REALM,
        serde_json::json!({
            "target_event_id": EVENT,
            "target_ref": STRAND,
            "by": "ak:did_core:web:alice.example"
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
