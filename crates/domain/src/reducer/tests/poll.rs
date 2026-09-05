use super::*;

const REALM_A: &str = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
const REALM_B: &str = "ak:realm:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R";
const POLL_EVENT: &str = "ak:event:AVH4Dy1ng6HIwqHRIemmcRdGF6ErKqNeNOzRpc2sGDV2";
const POLL_ID: &str = "ak:message:AVH4Dy1ng6HIwqHRIemmcRdGF6ErKqNeNOzRpc2sGDV2";
const STRAND_A: &str = "ak:strand:ARkwFWDTPrObvpqVAL9kBsWkK8GrMr5FDO--3PcMFEwU";
const STRAND_B: &str = "ak:strand:AUzgWk6FQOO5CNGEhXKtRw7FKYOAXGqzSVCLuwh5qmkk";
const CIRCLE_A: &str = "ak:circle:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu";
const CIRCLE_B: &str = "ak:circle:AbJ9TrPb-MFmDgVNN0uDVC6CIm3VNDxuUzlM5QBHZ8_Z";

fn seed_strand(state: &mut ProjectionState, strand_id: &str, circle_id: Option<&str>) {
    let now = chrono::Utc::now();
    state.strands.insert(
        strand_id.to_owned(),
        StrandProjection {
            strand_id: strand_id.to_owned(),
            realm_id: REALM_A.to_owned(),
            tracks: crate::reducer::projections::default_strand_tracks(),
            title: "Poll".to_owned(),
            summary: None,
            content: None,
            encrypted_content: None,
            fields: BTreeMap::new(),
            state: ObjectLifecycleState::Active,
            state_changed_at: None,
            stage: None,
            stage_changed_at: None,
            created_by: "ak:did_core:web:alice.example".to_owned(),
            created_at: now,
            history_basis_seals: Vec::new(),
            updated_by: None,
            updated_at: None,
            scope_circle_id: circle_id.map(ToOwned::to_owned),
            schema_refs: Vec::new(),
            schedule_revision_heads: Vec::new(),
        },
    );
}

fn create_poll(state: &mut ProjectionState, hlc: &ServerHlc) {
    create_poll_with_limit(state, hlc, 1);
}

fn create_poll_with_limit(state: &mut ProjectionState, hlc: &ServerHlc, max_selections: u32) {
    if !state.strands.contains_key(STRAND_A) {
        seed_strand(state, STRAND_A, None);
    }
    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::MessageCreate,
            REALM_A,
            serde_json::json!({
                "event_id": POLL_EVENT,
                "strand_id": STRAND_A,
                "track_name": "discussion",
                "content": {
                    "kind": "ak.content.poll",
                    "body": "Choose",
                    "poll": {
                        "kind": "disclosed",
                        "max_selections": max_selections,
                        "answers": [
                            {"id": "yes", "text": {"kind": "ak.content.text", "body": "Yes"}},
                            {"id": "no", "text": {"kind": "ak.content.text", "body": "No"}}
                        ]
                    }
                }
            }),
        ),
        hlc,
    );
    assert!(matches!(effect, ProjectionEffect::MessageCreated(_)));
    assert!(state.poll(POLL_ID).is_some());
}

#[test]
fn poll_reducer_accepts_valid_multi_selection() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("poll-test");
    create_poll_with_limit(&mut state, &hlc, 2);
    assert!(matches!(
        response(&mut state, &hlc, REALM_A, serde_json::json!(["yes", "no"]),),
        ProjectionEffect::Ignored
    ));
    assert_eq!(
        state
            .poll(POLL_ID)
            .unwrap()
            .votes
            .values()
            .next()
            .unwrap()
            .selections,
        BTreeSet::from(["no".to_owned(), "yes".to_owned()])
    );
}

fn response(
    state: &mut ProjectionState,
    hlc: &ServerHlc,
    realm: &str,
    selections: Value,
) -> ProjectionEffect {
    state.apply(&response_operation(realm, selections), hlc)
}

fn response_operation(
    realm: &str,
    selections: Value,
) -> arkret_event_draft::ProjectedEventOperation {
    response_operation_on_strand(realm, STRAND_A, selections)
}

fn response_operation_on_strand(
    realm: &str,
    strand_id: &str,
    selections: Value,
) -> arkret_event_draft::ProjectedEventOperation {
    make_operation(
        arkret_wire::EventKind::MessageCreate,
        realm,
        serde_json::json!({
            "strand_id": strand_id,
            "track_name": "discussion",
            "content": {
                "kind": "ak.content.poll.response",
                "body": "vote",
                "poll_response": {"poll_ref": POLL_ID, "selections": selections}
            }
        }),
    )
}

#[test]
fn poll_reducer_rejects_same_realm_different_circle_scope() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("poll-test");
    seed_strand(&mut state, STRAND_A, Some(CIRCLE_A));
    seed_strand(&mut state, STRAND_B, Some(CIRCLE_B));
    create_poll(&mut state, &hlc);

    let effect = state.apply(
        &response_operation_on_strand(REALM_A, STRAND_B, serde_json::json!(["yes"])),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason } if reason == "poll_ref_cross_scope"
    ));
}

#[test]
fn poll_reducer_accepts_only_exact_scope_known_answers_within_limit() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("poll-test");
    create_poll(&mut state, &hlc);

    assert!(matches!(
        response(&mut state, &hlc, REALM_A, serde_json::json!(["yes"])),
        ProjectionEffect::Ignored
    ));
    let vote = state.poll(POLL_ID).unwrap().votes.values().next().unwrap();
    assert_eq!(vote.selections, BTreeSet::from(["yes".to_owned()]));

    for (realm, selections, reason) in [
        (
            REALM_A,
            serde_json::json!(["unknown"]),
            "poll_selection_unknown",
        ),
        (
            REALM_A,
            serde_json::json!(["yes", "no"]),
            "poll_selection_limit_exceeded",
        ),
        (REALM_B, serde_json::json!(["yes"]), "poll_ref_cross_scope"),
    ] {
        let effect = response(&mut state, &hlc, realm, selections);
        assert!(
            matches!(effect, ProjectionEffect::Rejected { reason: ref actual } if actual == reason)
        );
    }
}

#[test]
fn poll_reducer_rejects_unknown_poll_instead_of_silently_ignoring() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("poll-test");
    let effect = response(&mut state, &hlc, REALM_A, serde_json::json!(["yes"]));
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason } if reason == "poll_ref_unknown"
    ));
}

#[test]
fn poll_reducer_causal_successor_wins_even_with_lower_digest() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("poll-test");
    create_poll(&mut state, &hlc);
    let current_digest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let candidate_digest =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let mut current = response_operation(REALM_A, serde_json::json!(["yes"]));
    current.context.canonical_event_digest = arkret_identifiers::Hash::new(current_digest).unwrap();
    state.apply(&current, &hlc);
    let mut candidate = response_operation(REALM_A, serde_json::json!(["no"]));
    candidate.context.canonical_event_digest =
        arkret_identifiers::Hash::new(candidate_digest).unwrap();
    candidate.context.envelope_causal_refs =
        vec![arkret_identifiers::Hash::new(current_digest).unwrap()];
    state.apply(&candidate, &hlc);

    let vote = state.poll(POLL_ID).unwrap().votes.values().next().unwrap();
    assert_eq!(vote.selections, BTreeSet::from(["no".to_owned()]));
    assert_eq!(vote.source_event_digest, candidate_digest);
}

#[test]
fn poll_reducer_concurrent_digest_order_is_arrival_independent() {
    let hlc = ServerHlc::new("poll-test");
    let mut base = ProjectionState::new();
    create_poll(&mut base, &hlc);
    let low_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let high_digest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let mut low = response_operation(REALM_A, serde_json::json!(["yes"]));
    low.context.canonical_event_digest = arkret_identifiers::Hash::new(low_digest).unwrap();
    let mut high = response_operation(REALM_A, serde_json::json!(["no"]));
    high.context.canonical_event_digest = arkret_identifiers::Hash::new(high_digest).unwrap();

    let mut low_then_high = base.clone();
    low_then_high.apply(&low, &hlc);
    low_then_high.apply(&high, &hlc);
    let mut high_then_low = base;
    high_then_low.apply(&high, &hlc);
    high_then_low.apply(&low, &hlc);

    for state in [&low_then_high, &high_then_low] {
        let vote = state.poll(POLL_ID).unwrap().votes.values().next().unwrap();
        assert_eq!(vote.selections, BTreeSet::from(["no".to_owned()]));
        assert_eq!(vote.source_event_digest, high_digest);
    }
}
