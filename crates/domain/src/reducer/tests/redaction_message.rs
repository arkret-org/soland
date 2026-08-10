use super::*;

#[test]
fn redaction_human_reason_prefers_explicit_field() {
    let payload = serde_json::json!({
        "target_event_id": "ak:event:AYTeR35PxnHtaUMXFLoHqGA1yiou3pai07-tzQyViJnt",
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
        arkret_wire::EventKind::MessageCreate,
        "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
        serde_json::json!({
            "event_id": "ak:event:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R",
            "sender": "did:web:alice",
            "thread_id": "ak:strand:1",
            "content": {"kind": "ak.content.text", "body": "hello"}
        }),
    );
    let effect = state.apply(&op, &hlc);
    assert!(matches!(effect, ProjectionEffect::MessageCreated(_)));

    let msgs = state.messages_for_realm("ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb");
    assert_eq!(msgs.len(), 1);
    assert_eq!(
        msgs[0].event_id,
        "ak:event:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R"
    );
}

#[test]
fn redaction_hides_message() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageCreate,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "event_id": "ak:event:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R",
                "sender": "did:web:alice",
                "thread_id": "ak:strand:1",
                "content": {"kind": "ak.content.text", "body": "hello"}
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageRedact,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "target_event_id": "ak:event:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R",
                "by": "did:web:alice",
                "reason": "wrong room"
            }),
        ),
        &hlc,
    );

    assert!(
        state
            .messages_for_realm("ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb")
            .is_empty()
    );
    assert!(
        state
            .redactions
            .contains("ak:event:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R")
    );
    // The original MessageState is preserved (only the
    // parallel cell + flat redactions index move).
    assert!(
        state
            .messages
            .contains_key("ak:event:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R")
    );
    let cell = state
        .redaction_cells
        .get("ak:event:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R")
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
            arkret_wire::EventKind::MessageCreate,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "event_id": event_id,
                "sender": "did:web:alice",
                "thread_id": "ak:strand:1",
                "content": {"kind": "ak.content.text", "body": "hello"}
            }),
        ),
        hlc,
    );
}

#[test]
fn mal14_tombstone_visible_to_author() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let event_id = "ak:event:AVH4Dy1ng6HIwqHRIemmcRdGF6ErKqNeNOzRpc2sGDV2";
    redact_make_message(&mut state, &hlc, event_id);
    state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageRedact,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
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
    let event_id = "ak:event:AfqWfYd8Ne_ep-HLww8vFeZV55RaKPRMN4cOWHP3uQt8";
    redact_make_message(&mut state, &hlc, event_id);
    state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageRedact,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
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
    let event_id = "ak:event:AViQpp7Hdb367Fjsw1SI_B0MoIcCLeMT4hP2sjx5ILUG";
    redact_make_message(&mut state, &hlc, event_id);
    // Redact.
    state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageRedact,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
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
            arkret_wire::EventKind::MessageRedact,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
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
    let event_id = "ak:event:AWFQAWZebUfJ-E0wgUFcO4HGLOIjmZHbM8U5PZLfGeED";
    // Pre-create the projected message and let the projection
    // rendering query it once before the redaction lands.
    redact_make_message(&mut state, &hlc, event_id);
    let pre = state.projected_message(event_id, false).unwrap();
    assert!(pre.content.is_some());
    assert!(pre.redaction.is_none());
    // Now a delayed redaction arrives.
    state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageRedact,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
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
            arkret_wire::EventKind::ReactionAdd,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "target_ref": "ak:message:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R",
                "sender": "did:web:alice",
                "key": "👍"
            }),
        ),
        &hlc,
    );
    assert_eq!(
        state
            .reactions_for_event("ak:event:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R")
            .len(),
        1
    );

    state.apply(
        &make_operation(
            arkret_wire::EventKind::ReactionRemove,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "target_ref": "ak:message:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R",
                "sender": "did:web:alice",
                "key": "👍"
            }),
        ),
        &hlc,
    );
    assert_eq!(
        state
            .reactions_for_event("ak:event:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R")
            .len(),
        0
    );
}

#[test]
fn membership_join_leave() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    state
        .realm_join_rules
        .insert(realm_id.to_owned(), "public".to_owned());

    // `membership=join` MUST carry `delivery_status` per
    // arkret-spec/spec/v1/zh/governance/join-policy.md §5.1.1.
    // We use `unroutable` so the projection write path does not
    // additionally require a projected `ak.realm.delivery_binding_policy`
    // cell (`routable` joins are exercised by the delivery-binding
    // suite).
    let join_payload = serde_json::json!({
        "realm_id": realm_id,
        "actor_id": "did:web:bob",
        "membership": "join",
        "delivery_status": "unroutable"
    });
    let (_, join_writes) =
        projected_cell_writes(arkret_wire::EventKind::MemberState, realm_id, &join_payload);
    let mut join = make_operation(arkret_wire::EventKind::MemberState, realm_id, join_payload);
    join.context.sender = arkret_wire::project_full_id_to_core_id(
        &arkret_identifiers::DidFullId::new("did:web:bob").unwrap(),
    )
    .unwrap();
    state.apply_projected(&join, &join_writes, &hlc);
    assert_eq!(state.members_of_realm(realm_id).len(), 1);

    let leave_payload = serde_json::json!({
        "actor_id": "did:web:bob",
        "membership": "leave"
    });
    let (_, leave_writes) = projected_cell_writes(
        arkret_wire::EventKind::MemberState,
        realm_id,
        &leave_payload,
    );
    let mut leave = make_operation(arkret_wire::EventKind::MemberState, realm_id, leave_payload);
    leave.context.sender = arkret_wire::project_full_id_to_core_id(
        &arkret_identifiers::DidFullId::new("did:web:bob").unwrap(),
    )
    .unwrap();
    state.apply_projected(&leave, &leave_writes, &hlc);
    assert_eq!(state.members_of_realm(realm_id).len(), 0);
}

#[test]
fn message_revise_creates_chain() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageCreate,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "event_id": "ak:event:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R",
                "sender": "did:web:alice",
                "thread_id": "ak:strand:1",
                "content": {"kind": "ak.content.text", "body": "original"}
            }),
        ),
        &hlc,
    );

    let revise = make_operation(
        arkret_wire::EventKind::MessageRevise,
        "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
        serde_json::json!({
            "target_ref": "ak:event:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R",
            "content": {"kind": "ak.content.text", "body": "revised"}
        }),
    );
    let revision_id = revise.context.event_id.to_string();
    state.apply(&revise, &hlc);

    let msgs = state.messages_for_realm("ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb");
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].event_id, revision_id);
    assert_eq!(msgs[0].content["body"], "revised");
    assert_eq!(state.messages.len(), 2);
    let revision = state.messages.get(&revision_id).unwrap();
    assert_eq!(
        revision.revision_of.as_deref(),
        Some("ak:event:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R")
    );
}

#[test]
fn message_revise_resolves_schema_message_id_and_preserves_event_id() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let event_id = "ak:event:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R";
    let message_id = "ak:message:AXQ-Zb-ajLPUppedkeoOdGiFw_IFS5rx-tvwRdwirjrR";
    let revision_event_id = "ak:event:AY3yMyh6E9PG9a6M5sarXiHRk89RGO88qpJX6TmFfw4K";

    state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageCreate,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "event_id": event_id,
                "message_id": message_id,
                "sender": "did:web:alice",
                "thread_id": "ak:strand:1",
                "content": {"kind": "ak.content.text", "body": "original"}
            }),
        ),
        &hlc,
    );

    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageRevise,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "event_id": revision_event_id,
                "target_ref": message_id,
                "content": {"kind": "ak.content.text", "body": "revised"}
            }),
        ),
        &hlc,
    );

    assert!(matches!(
        effect,
        ProjectionEffect::MessageRevised { ref original_id, ref revision }
            if original_id == event_id && revision.event_id == revision_event_id
    ));
    let msgs = state.messages_for_realm("ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb");
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].event_id, revision_event_id);
    assert_eq!(msgs[0].message_id, message_id);
    assert_eq!(msgs[0].revision_of.as_deref(), Some(event_id));
    assert_eq!(msgs[0].content["body"], "revised");
}

#[test]
fn redaction_accepts_schema_message_id_target() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let event_id = "ak:event:ARM_vloO6RecwhzJiZLJp_sEMbLAlYxMqDRCnIx5zTYC";
    let message_id = "ak:message:AWTw005aQJnsZUX29qLAWeCR8A5FmteYPybO7uylwJfW";
    let redaction_event_id = "ak:event:AeV1nAe67z8tQd57ghKnYX3pO3XHc0CWcgZeG1UtWi7m";

    state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageCreate,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "event_id": event_id,
                "message_id": message_id,
                "sender": "did:web:alice",
                "thread_id": "ak:strand:1",
                "content": {"kind": "ak.content.text", "body": "hello"}
            }),
        ),
        &hlc,
    );
    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageRedact,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "event_id": redaction_event_id,
                "message_id": message_id,
                "by": "did:web:alice",
                "reason": "wrong room"
            }),
        ),
        &hlc,
    );

    assert!(matches!(
        effect,
        ProjectionEffect::MessageRedacted { event_id: target } if target == event_id
    ));
    assert!(state.redactions.contains(event_id));
    assert!(!state.redactions.contains(redaction_event_id));
    assert!(
        state
            .projected_message(event_id, false)
            .unwrap()
            .content
            .is_none()
    );
}

#[test]
fn redaction_by_message_id_hides_latest_revision() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let event_id = "ak:event:AYFOTCo9ihbm1rHVVboZzk8j6Y76eIOqKgzp0m3azE5f";
    let message_id = "ak:message:AWZOZT9AgLT5geqcOmOD7V_v1AjKMAoPHInmsnnbsapn";
    let revision_event_id = "ak:event:AVvHap65LnD8zHKvce7Yq8fodmj2dYC4w32MPRABihB9";

    state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageCreate,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "event_id": event_id,
                "message_id": message_id,
                "sender": "did:web:alice",
                "thread_id": "ak:strand:1",
                "content": {"kind": "ak.content.text", "body": "original"}
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageRevise,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "event_id": revision_event_id,
                "target_ref": message_id,
                "content": {"kind": "ak.content.text", "body": "revised"}
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageRedact,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "event_id": "ak:event:AaviAQUPcXQA_m9RNFUvox0-znrutEvE8BkTgEoWNTJx",
                "message_id": message_id,
                "by": "did:web:alice",
                "reason": "wrong room"
            }),
        ),
        &hlc,
    );

    assert!(
        state
            .messages_for_realm("ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb")
            .is_empty()
    );
    assert!(
        state
            .projected_message(revision_event_id, false)
            .unwrap()
            .content
            .is_none()
    );
}
