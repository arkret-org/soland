//! Producer for one Realm's frozen timeline window (`client-sync.md` 2.3).
//!
//! The window is the newest `window_limit` accepted Events the caller may see,
//! in the section 6 projection order, frozen at the generation the current
//! detail page minted. Segments walk downward from that frozen head, so Events
//! accepted mid-delivery sort above it and arrive as live increments instead of
//! joining a window already in flight.
//!
//! Nothing here reads a Realm's history: the order index supplies bounded
//! keyset pages, and the scan ceiling below bounds the work even when the
//! newest rows are all invisible to this session.

use arkret_models_collaboration::sync_frames::account_sync::Timeline;
use arkret_models_collaboration::sync_frames::demand_sync::{
    ACCOUNT_SYNC_MAX_TIMELINE_LIMIT, RealmTimelineBaseline,
};
use soland_storage::{TimelineOrderPosition, TimelineWindowCandidate, TimelineWindowCursor};

use super::*;

/// Rows examined per round while looking for visible Events.
///
/// Visibility is per-Event and cannot be pushed into the index, so a window
/// whose newest rows are all filtered out would otherwise walk the Realm. The
/// round ends at this ceiling and resumes from the last examined position, so
/// the work stays bounded without ever concluding a window early.
const SCAN_ROWS_PER_ROUND: usize = 200;

pub(super) struct WindowSegment {
    pub timeline: Timeline,
    /// Absent on a live increment: `client-sync.md` 2.3 makes the presence of
    /// this field the discriminator between frozen-window content and live
    /// delivery, so a live segment must never carry one.
    pub baseline: Option<RealmTimelineBaseline>,
}

/// Deliver the next segment of `realm`'s frozen window.
///
/// Returns `None` when the window is already complete and nothing new is owed,
/// which is what lets a detail turn fall through to a frontier frame instead of
/// re-sending a finished window.
pub(super) async fn next_segment(
    state: &AppState,
    session: &SessionIdentityState,
    filter: &arkret_models_collaboration::sync_frames::client_sync::SyncFilter,
    realm: &RealmId,
    snapshot_cursor: &arkret_wire::Cursor,
    cursor: &mut TimelineWindowCursor,
) -> Option<WindowSegment> {
    if cursor.window_limit == 0 {
        // A caller that asked for no items still gets an explicit zero-item
        // completion: absence of an entry is not an empty window.
        cursor.window_limit = filter
            .effective_timeline_limit()
            .min(ACCOUNT_SYNC_MAX_TIMELINE_LIMIT);
    }
    if cursor.complete {
        return live_segment(state, session, filter, realm, cursor).await;
    }
    let Some(head) = cursor.head.clone() else {
        // The Realm holds no accepted Event at the frozen generation. That is a
        // legitimately empty window, and it completes explicitly.
        cursor.complete = true;
        return Some(WindowSegment {
            timeline: empty_timeline(cursor),
            baseline: Some(baseline_of(snapshot_cursor, cursor)),
        });
    };
    if cursor.delivered >= cursor.window_limit {
        return Some(finish(cursor, Vec::new(), snapshot_cursor));
    }

    let owed = (cursor.window_limit - cursor.delivered) as usize;
    let mut visible: Vec<TimelineWindowCandidate> = Vec::new();
    let mut bound = cursor.last_delivered.clone();
    let mut exhausted = false;
    let mut examined = 0usize;
    let projection = state.projections().snapshot();
    while visible.len() < owed && examined < SCAN_ROWS_PER_ROUND {
        let scan = match state
            .sync()
            .timeline_window_scan(
                realm.as_str(),
                &head,
                bound.as_ref(),
                SCAN_ROWS_PER_ROUND - examined,
            )
            .await
        {
            Ok(scan) => scan,
            Err(error) => {
                tracing::warn!(%error, %realm, "timeline window scan failed");
                return None;
            }
        };
        if scan.candidates.is_empty() {
            exhausted = true;
            break;
        }
        for candidate in scan.candidates {
            examined += 1;
            bound = Some(candidate.position.clone());
            if !kind_allowed(filter, &candidate.kind) {
                continue;
            }
            if !visible_to_session(state, &projection, realm, &candidate, session).await {
                continue;
            }
            visible.push(candidate);
            if visible.len() == owed {
                break;
            }
        }
        if scan.exhausted {
            exhausted = true;
            break;
        }
    }

    cursor.last_delivered = bound;
    cursor.provisional |= visible.iter().any(|candidate| candidate.provisional);
    // Only the frozen generation's own exhaustion completes the window. Hitting
    // the scan ceiling means work remains, and the next round resumes from
    // `last_delivered` rather than declaring the window finished.
    let finished = exhausted || cursor.delivered + visible.len() as u32 >= cursor.window_limit;
    if !finished && visible.is_empty() {
        // Nothing visible this round but the window is not settled: keep the
        // client pending rather than publishing a segment that looks like
        // progress it did not make.
        return Some(segment(cursor, Vec::new(), snapshot_cursor, false));
    }
    if finished {
        // The window is limited when it stopped at its ceiling with rows still
        // below it, not when a single segment ran out of budget.
        cursor.limited = !exhausted;
        Some(finish(cursor, visible, snapshot_cursor))
    } else {
        Some(segment(cursor, visible, snapshot_cursor, false))
    }
}

fn finish(
    cursor: &mut TimelineWindowCursor,
    visible: Vec<TimelineWindowCandidate>,
    snapshot_cursor: &arkret_wire::Cursor,
) -> WindowSegment {
    // Live delivery resumes from the frozen head, so an Event accepted while
    // the window was shipping is delivered exactly once: it was above the head
    // and therefore out of the window, and it is above `live_position` too.
    cursor.live_position.get_or_insert_with(|| {
        cursor
            .head
            .clone()
            .unwrap_or_else(|| TimelineOrderPosition {
                causal_depth: 0,
                hlc: None,
                actor_id: String::new(),
                actor_seq: 0,
                event_id: String::new(),
            })
    });
    segment(cursor, visible, snapshot_cursor, true)
}

/// Deliver Events accepted above the frozen head.
///
/// These carry no `timeline_baseline`, so they can neither complete, reopen nor
/// advance the window; they only install content.
async fn live_segment(
    state: &AppState,
    session: &SessionIdentityState,
    filter: &arkret_models_collaboration::sync_frames::client_sync::SyncFilter,
    realm: &RealmId,
    cursor: &mut TimelineWindowCursor,
) -> Option<WindowSegment> {
    let after = cursor.live_position.clone()?;
    let scan = state
        .sync()
        .timeline_live_scan(realm.as_str(), &after, SCAN_ROWS_PER_ROUND)
        .await
        .inspect_err(|error| tracing::warn!(%error, %realm, "timeline live scan failed"))
        .ok()?;
    if scan.candidates.is_empty() {
        return None;
    }
    let projection = state.projections().snapshot();
    let mut events = Vec::new();
    for candidate in scan.candidates {
        cursor.live_position = Some(candidate.position.clone());
        if !kind_allowed(filter, &candidate.kind)
            || !visible_to_session(state, &projection, realm, &candidate, session).await
        {
            continue;
        }
        push_event(&mut events, candidate);
    }
    if events.is_empty() {
        // The position advanced past rows this session cannot see; there is
        // nothing to install, and an empty live timeline would be noise.
        return None;
    }
    Some(WindowSegment {
        timeline: Timeline {
            events,
            limited: false,
            prev_cursor: None,
            preview_only: None,
            ordered_log_siblings: Vec::new(),
            extra: BTreeMap::new(),
        },
        baseline: None,
    })
}

fn segment(
    cursor: &mut TimelineWindowCursor,
    visible: Vec<TimelineWindowCandidate>,
    snapshot_cursor: &arkret_wire::Cursor,
    complete: bool,
) -> WindowSegment {
    cursor.complete = complete;
    // The scan walks newest first; the wire order is the ascending projection
    // order, so the segment is reversed exactly once, here.
    let mut events = Vec::new();
    for candidate in visible.into_iter().rev() {
        push_event(&mut events, candidate);
    }
    // Count what is actually on the wire. Counting candidates instead would let
    // one undecodable envelope retire a slot the window still owes.
    cursor.delivered = cursor.delivered.saturating_add(events.len() as u32);
    WindowSegment {
        timeline: Timeline {
            events,
            ..empty_timeline(cursor)
        },
        baseline: Some(baseline_of(snapshot_cursor, cursor)),
    }
}

/// An accepted row whose envelope no longer decodes is a storage defect, not a
/// delivery decision: drop it loudly rather than letting it silently shrink a
/// window.
fn push_event(events: &mut Vec<arkret_wire::Event>, candidate: TimelineWindowCandidate) {
    match serde_json::from_value(candidate.envelope) {
        Ok(event) => events.push(event),
        Err(error) => tracing::error!(
            %error,
            event_id = %candidate.position.event_id,
            "accepted Event envelope did not decode for timeline delivery"
        ),
    }
}

fn empty_timeline(cursor: &TimelineWindowCursor) -> Timeline {
    Timeline {
        events: Vec::new(),
        limited: cursor.limited,
        prev_cursor: None,
        // Window-level and identical in every segment (5.2). A provisional
        // depth means 7.3 forbids claiming the order is final, so the window
        // takes the preview fallback instead of publishing a window-start
        // state it cannot stand behind.
        preview_only: (cursor.limited || cursor.provisional).then_some(true),
        ordered_log_siblings: Vec::new(),
        extra: BTreeMap::new(),
    }
}

fn baseline_of(
    snapshot_cursor: &arkret_wire::Cursor,
    cursor: &TimelineWindowCursor,
) -> RealmTimelineBaseline {
    RealmTimelineBaseline {
        snapshot_cursor: snapshot_cursor.clone(),
        window_limit: cursor.window_limit,
        complete: cursor.complete,
    }
}

/// `filter` kind allow/deny trims only the data-plane timeline (2.3); it never
/// reaches the security baseline, invalidations or account channels, which do
/// not pass through here at all.
fn kind_allowed(
    filter: &arkret_models_collaboration::sync_frames::client_sync::SyncFilter,
    kind: &str,
) -> bool {
    if let Some(deny) = &filter.not_event_kinds
        && deny.iter().any(|denied| denied == kind)
    {
        return false;
    }
    match &filter.event_kinds {
        Some(allow) if !allow.is_empty() => allow.iter().any(|allowed| allowed == kind),
        _ => true,
    }
}

async fn visible_to_session(
    state: &AppState,
    projection: &ProjectionState,
    realm: &RealmId,
    candidate: &TimelineWindowCandidate,
    session: &SessionIdentityState,
) -> bool {
    if !crate::routing::spaces::space::realm_event_visible_to_session(
        state,
        realm.as_str(),
        candidate.created_at,
        candidate.sender.as_deref(),
        Some(session),
    )
    .await
    {
        return false;
    }
    super::snapshot::circle_scope_visible_to_session(
        state,
        projection,
        candidate
            .envelope
            .get("scope_ref")
            .and_then(|scope| scope.get("circle_id"))
            .and_then(serde_json::Value::as_str),
        candidate.created_at,
        Some(session),
        candidate.sender.as_deref(),
    )
}
