//! Real-database regressions for the frozen timeline window producer.
//!
//! The fixture `AppState` stores through the same Postgres adapter production
//! uses, so these exercise the real projection-order index, the real accepted
//! Event admission path and the real cursor records rather than a stand-in.

use chrono::{DateTime, Utc};

use super::super::tests::{
    ROSTER_ACTOR, ROSTER_CALLER, ROSTER_REALM, canonical_event_record_after,
    canonical_event_record_received_at, insert_projected_membership_at, roster_realm,
    roster_session, store_canonical_event, test_state,
};
use super::*;

fn at(offset: i64) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-09-15T00:00:00.000Z")
        .expect("fixture instant")
        .with_timezone(&Utc)
        + chrono::Duration::seconds(offset)
}

fn filter(limit: u32) -> arkret_models_collaboration::sync_frames::account_subscribe::SyncFilter {
    serde_json::from_value(json!({"timeline_limit": limit})).expect("fixture filter")
}

fn snapshot_cursor() -> arkret_wire::Cursor {
    arkret_wire::Cursor::new(format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()))
        .expect("fixture snapshot cursor")
}

/// A joined caller, a Realm the events belong to, and `count` accepted Events
/// whose projection order is the order they were written in.
async fn fixture(count: u64) -> (AppState, SessionIdentityState, RealmId) {
    let state = test_state();
    state.realm_directory().upsert(roster_realm(false, true));
    insert_projected_membership_at(&state, ROSTER_ACTOR, "join", at(-60));
    insert_projected_membership_at(&state, ROSTER_CALLER, "join", at(-60));
    for seq in 1..=count {
        store_canonical_event(
            &state,
            canonical_event_record_received_at(
                seq,
                arkret_wire::EventKind::MessageCreate,
                json!({"body": format!("window fixture {seq}")}),
                ROSTER_ACTOR,
                at(seq as i64),
                at(seq as i64),
            ),
        )
        .await;
    }
    let session = roster_session(&state, ROSTER_CALLER);
    let realm = RealmId::new(ROSTER_REALM.to_owned()).expect("fixture realm id");
    (state, session, realm)
}

async fn frozen(state: &AppState, realm: &RealmId, window_limit: u32) -> TimelineWindowCursor {
    TimelineWindowCursor {
        window_limit,
        head: state
            .sync()
            .timeline_window_head(realm.as_str())
            .await
            .expect("frozen head"),
        ..TimelineWindowCursor::default()
    }
}

fn ids(segment: &WindowSegment) -> Vec<String> {
    segment
        .timeline
        .events
        .iter()
        .map(|event| event.event_id.to_string())
        .collect()
}

#[tokio::test]
async fn frame_bytes_cut_the_window_into_segments_without_lowering_its_cumulative_limit() {
    let (state, session, realm) = fixture(5).await;
    let filter = filter(5);
    let cursor_token = snapshot_cursor();
    let mut cursor = frozen(&state, &realm, 5).await;

    // Budget for two Events per segment, measured from the fixture itself so
    // the test states a byte fact rather than guessing one.
    let whole = next_segment(
        &state,
        &session,
        &filter,
        &realm,
        &cursor_token,
        &mut frozen(&state, &realm, 5).await,
        usize::MAX,
    )
    .await
    .expect("an unconstrained window delivers in one segment");
    assert_eq!(whole.timeline.events.len(), 5);
    assert!(whole.baseline.as_ref().expect("baseline").complete);
    let two_events = whole.timeline.events[..2]
        .iter()
        .map(|event| {
            arkret_canonical::canonical_json_bytes(event)
                .expect("canonical")
                .len()
                + 1
        })
        .sum::<usize>();

    let mut delivered = Vec::new();
    let mut segments = Vec::new();
    for _ in 0..8 {
        let Some(segment) = next_segment(
            &state,
            &session,
            &filter,
            &realm,
            &cursor_token,
            &mut cursor,
            two_events,
        )
        .await
        else {
            break;
        };
        let complete = segment.baseline.as_ref().expect("baseline").complete;
        delivered.extend(ids(&segment));
        segments.push(segment);
        if complete {
            break;
        }
    }

    // The byte budget decided segmentation only. It never lowered the ceiling,
    // never dropped an owed Event, and never let a short segment complete.
    assert_eq!(segments.len(), 3);
    assert_eq!(
        segments
            .iter()
            .map(|segment| segment.timeline.events.len())
            .collect::<Vec<_>>(),
        vec![2, 2, 1]
    );
    assert_eq!(
        delivered,
        ids(&whole),
        "segmented delivery reproduces the whole window in ascending projection order"
    );
    for (index, segment) in segments.iter().enumerate() {
        let baseline = segment.baseline.as_ref().expect("every segment is frozen");
        assert_eq!(baseline.window_limit, 5, "the ceiling is window-level");
        assert_eq!(baseline.snapshot_cursor, cursor_token);
        assert_eq!(baseline.complete, index == segments.len() - 1);
        // 5.2: window-level fields repeat identically in every segment.
        assert_eq!(segment.timeline.limited, segments[0].timeline.limited);
        assert_eq!(
            segment.timeline.prev_cursor,
            segments[0].timeline.prev_cursor
        );
        assert_eq!(
            segment.timeline.preview_only,
            segments[0].timeline.preview_only
        );
    }
    assert_eq!(cursor.delivered, 5);

    // A response the client never installed is not the next starting point:
    // replaying the same cursor must reproduce the same segment.
    let mut replay = frozen(&state, &realm, 5).await;
    let first = next_segment(
        &state,
        &session,
        &filter,
        &realm,
        &cursor_token,
        &mut replay,
        two_events,
    )
    .await
    .expect("first segment");
    let mut again = frozen(&state, &realm, 5).await;
    let repeated = next_segment(
        &state,
        &session,
        &filter,
        &realm,
        &cursor_token,
        &mut again,
        two_events,
    )
    .await
    .expect("replayed first segment");
    assert_eq!(ids(&first), ids(&repeated));
}

#[tokio::test]
async fn a_window_shorter_than_its_history_reports_one_prev_cursor_for_the_whole_window() {
    let (state, session, realm) = fixture(5).await;
    let filter = filter(2);
    let cursor_token = snapshot_cursor();
    let mut cursor = frozen(&state, &realm, 2).await;

    let first = next_segment(
        &state,
        &session,
        &filter,
        &realm,
        &cursor_token,
        &mut cursor,
        usize::MAX,
    )
    .await
    .expect("a settled window delivers");
    assert_eq!(first.timeline.events.len(), 2);
    assert!(first.timeline.limited, "older readable history exists");
    // 5.2 (b): this producer does not replay historical projections, so a
    // limited window takes the preview fallback rather than publishing a
    // window-start state it cannot stand behind.
    assert_eq!(first.timeline.preview_only, Some(true));
    let prev_cursor = first
        .timeline
        .prev_cursor
        .clone()
        .expect("a limited window points at the history before it");
    assert!(prev_cursor.starts_with("ak:cursor:"));
    // It addresses the boundary before the whole window, which is its floor.
    assert_eq!(
        cursor.floor.as_ref().expect("floor").event_id,
        first.timeline.events[0].event_id.to_string()
    );

    // The same token round-trips as an `ak.self.committed_event.read.scan.v1` `before=`
    // for this Realm: it validates against the digest that path recomputes.
    let target = super::super::cursor::parse_and_validate_events_query_cursor(
        &prev_cursor,
        &state,
        Some(&session),
        &super::super::events_query::realm_history_scan_digest(&realm),
        chrono::Utc::now().timestamp_millis(),
    )
    .await
    .expect("prev_cursor must be a valid backfill cursor for this Realm");
    assert_eq!(
        target.event_id,
        first.timeline.events[0].event_id.to_string()
    );

    // A second generation of the same window repeats the value rather than
    // recomputing a per-segment one.
    let mut segmented = frozen(&state, &realm, 2).await;
    let one_event = arkret_canonical::canonical_json_bytes(&first.timeline.events[0])
        .expect("canonical")
        .len()
        + 1;
    let head = next_segment(
        &state,
        &session,
        &filter,
        &realm,
        &cursor_token,
        &mut segmented,
        one_event,
    )
    .await
    .expect("first of two segments");
    let tail = next_segment(
        &state,
        &session,
        &filter,
        &realm,
        &cursor_token,
        &mut segmented,
        one_event,
    )
    .await
    .expect("second of two segments");
    assert_eq!(head.timeline.events.len(), 1);
    assert_eq!(tail.timeline.events.len(), 1);
    assert_eq!(head.timeline.prev_cursor, tail.timeline.prev_cursor);
    assert_eq!(head.timeline.limited, tail.timeline.limited);
    assert_eq!(head.timeline.preview_only, tail.timeline.preview_only);
    assert!(tail.baseline.as_ref().expect("baseline").complete);
    assert!(!head.baseline.as_ref().expect("baseline").complete);
}

#[tokio::test]
async fn zero_item_windows_complete_explicitly_and_live_increments_carry_no_baseline() {
    let (state, session, realm) = fixture(2).await;
    let cursor_token = snapshot_cursor();

    // `window_limit=0` asks for no items. It still completes explicitly, and it
    // proves nothing about the Realm's history, so it claims neither a gap nor
    // a continuation.
    let zero_filter = filter(0);
    let mut zero = frozen(&state, &realm, 0).await;
    let segment = next_segment(
        &state,
        &session,
        &zero_filter,
        &realm,
        &cursor_token,
        &mut zero,
        usize::MAX,
    )
    .await
    .expect("a zero-item window is delivered, not omitted");
    assert!(segment.timeline.events.is_empty());
    assert!(segment.baseline.as_ref().expect("baseline").complete);
    assert_eq!(segment.baseline.as_ref().expect("baseline").window_limit, 0);
    assert!(!segment.timeline.limited);
    assert!(segment.timeline.prev_cursor.is_none());
    assert!(segment.timeline.preview_only.is_none());

    // An empty Realm is a legitimately empty window with the same shape.
    let empty_realm =
        RealmId::new("ak:realm:AQVZRUJrSSC16EodjmqL6mBFC9TGwv6oxx-sQlJzlvxS".to_owned())
            .expect("fixture realm id");
    let mut empty = frozen(&state, &empty_realm, 20).await;
    assert!(empty.head.is_none());
    let segment = next_segment(
        &state,
        &session,
        &filter(20),
        &empty_realm,
        &cursor_token,
        &mut empty,
        usize::MAX,
    )
    .await
    .expect("an empty Realm still completes its window");
    assert!(segment.timeline.events.is_empty());
    assert!(segment.baseline.as_ref().expect("baseline").complete);

    // A window frozen over both Events completes, and an Event accepted after
    // the freeze sorts above the head: it is a live increment, which carries no
    // `timeline_baseline` and therefore cannot complete or reopen the window.
    let live_filter = filter(20);
    let mut cursor = frozen(&state, &realm, 20).await;
    let window = next_segment(
        &state,
        &session,
        &live_filter,
        &realm,
        &cursor_token,
        &mut cursor,
        usize::MAX,
    )
    .await
    .expect("frozen window");
    assert_eq!(window.timeline.events.len(), 2);
    assert!(window.baseline.as_ref().expect("baseline").complete);
    assert!(
        next_segment(
            &state,
            &session,
            &live_filter,
            &realm,
            &cursor_token,
            &mut cursor,
            usize::MAX,
        )
        .await
        .is_none(),
        "a finished window with nothing new owes nothing"
    );

    store_canonical_event(
        &state,
        canonical_event_record_received_at(
            3,
            arkret_wire::EventKind::MessageCreate,
            json!({"body": "after the freeze"}),
            ROSTER_ACTOR,
            at(3),
            at(3),
        ),
    )
    .await;
    let live = next_segment(
        &state,
        &session,
        &live_filter,
        &realm,
        &cursor_token,
        &mut cursor,
        usize::MAX,
    )
    .await
    .expect("an Event above the frozen head is delivered live");
    assert!(
        live.baseline.is_none(),
        "a live increment must never carry a timeline_baseline"
    );
    assert!(!live.timeline.limited && live.timeline.prev_cursor.is_none());
    assert_eq!(live.timeline.events.len(), 1);
    assert_eq!(
        cursor.delivered, 2,
        "live increments do not count against the frozen window"
    );
}

#[tokio::test]
async fn a_late_predecessor_takes_the_window_off_the_preview_fallback() {
    let state = test_state();
    state.realm_directory().upsert(roster_realm(false, true));
    insert_projected_membership_at(&state, ROSTER_ACTOR, "join", at(-60));
    insert_projected_membership_at(&state, ROSTER_CALLER, "join", at(-60));

    // The root is built first so its successors can name it, and written last so
    // this is a real out-of-order arrival. Until it lands, every row this Realm
    // holds hangs off an edge the Station cannot resolve.
    let root = canonical_event_record_received_at(
        1,
        arkret_wire::EventKind::MessageCreate,
        json!({"body": "late predecessor root"}),
        ROSTER_ACTOR,
        at(1),
        at(1),
    );
    let root_id = arkret_wire::EventId::new(root.event_id.clone()).expect("fixture event id");
    let child = canonical_event_record_after(
        2,
        arkret_wire::EventKind::MessageCreate,
        json!({"body": "late predecessor child"}),
        ROSTER_ACTOR,
        at(2),
        at(2),
        std::slice::from_ref(&root_id),
    );
    let child_id = arkret_wire::EventId::new(child.event_id.clone()).expect("fixture event id");
    let grandchild = canonical_event_record_after(
        3,
        arkret_wire::EventKind::MessageCreate,
        json!({"body": "late predecessor grandchild"}),
        ROSTER_ACTOR,
        at(3),
        at(3),
        std::slice::from_ref(&child_id),
    );
    store_canonical_event(&state, child).await;
    store_canonical_event(&state, grandchild).await;

    let session = roster_session(&state, ROSTER_CALLER);
    let realm = RealmId::new(ROSTER_REALM.to_owned()).expect("fixture realm id");
    let cursor_token = snapshot_cursor();
    let filter = filter(5);
    let segment = next_segment(
        &state,
        &session,
        &filter,
        &realm,
        &cursor_token,
        &mut frozen(&state, &realm, 5).await,
        usize::MAX,
    )
    .await
    .expect("a provisional window is still delivered");
    assert_eq!(segment.timeline.events.len(), 2);
    assert!(!segment.timeline.limited, "the window covers all it holds");
    assert_eq!(
        segment.timeline.preview_only,
        Some(true),
        "5.2 forbids claiming a final order around an edge the Station cannot see"
    );

    store_canonical_event(&state, root).await;

    let settled = next_segment(
        &state,
        &session,
        &filter,
        &realm,
        &cursor_token,
        &mut frozen(&state, &realm, 5).await,
        usize::MAX,
    )
    .await
    .expect("the rebuilt generation delivers");
    assert_eq!(
        ids(&settled),
        vec![
            root_id.to_string(),
            child_id.to_string(),
            settled.timeline.events[2].event_id.to_string()
        ],
        "the late root sorts ahead of the successors it unblocked"
    );
    assert!(
        settled.timeline.preview_only.is_none(),
        "re-resolving the depth takes the window off the preview fallback"
    );
}
