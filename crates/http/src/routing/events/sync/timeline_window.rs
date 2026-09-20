//! Producer for one Realm's frozen timeline window (`client-sync.md` 2.3).
//!
//! The window is the newest `window_limit` accepted Events the caller may see,
//! in the section 6 projection order, frozen at the generation the current
//! detail page minted. Nothing here reads a Realm's history: the order index
//! supplies bounded keyset pages in both directions, and the scan ceiling below
//! bounds the work even when the newest rows are all invisible to this session.
//!
//! Production runs in two phases because 5.2 makes `limited`, `preview_only`
//! and `prev_cursor` *window-level*: every segment of one generation must carry
//! the same values and the same field presence. None of them can be answered
//! while segments are still being cut, so selection walks down from the frozen
//! head first and settles the window's extent, and only then does delivery walk
//! back up and cut it into byte-sized segments.

use arkret_models_collaboration::sync_frames::account_sync::Timeline;
use arkret_models_collaboration::sync_frames::demand_sync::RealmTimelineBaseline;
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
/// `byte_budget` is what the frame this segment will ride in still has left
/// (`client-sync.md` 2.3 fixed budgets). It decides only how the window is cut,
/// never how much of it is owed: a segment stops at the budget with the
/// remaining Events still owed, and the next round resumes from the same
/// position. `window_limit` is untouched by it.
///
/// Returns `None` when nothing is deliverable this round, which is what lets a
/// detail turn fall through to a frontier frame instead of re-sending a
/// finished window or an empty segment that looks like progress.
pub(super) async fn next_segment(
    state: &AppState,
    session: &SessionIdentityState,
    filter: &arkret_models_collaboration::sync_frames::client_sync::SyncFilter,
    realm: &RealmId,
    snapshot_cursor: &arkret_wire::Cursor,
    cursor: &mut TimelineWindowCursor,
    byte_budget: usize,
) -> Option<WindowSegment> {
    if cursor.complete {
        return live_segment(state, session, filter, realm, cursor, byte_budget).await;
    }
    if !cursor.selection_complete {
        if !select(state, session, filter, realm, cursor).await {
            return None;
        }
        if !cursor.selection_complete {
            // Selection stopped on its own row ceiling. The window's extent is
            // not settled yet, so no segment can carry the window-level fields;
            // the round resumes from `select_bound` instead.
            return None;
        }
    }
    deliver(
        state,
        session,
        filter,
        realm,
        snapshot_cursor,
        cursor,
        byte_budget,
    )
    .await
}

/// Walk down from the frozen head until `window_limit` visible Events are
/// admitted or the readable history runs out, then settle `floor`, `limited`
/// and `prev_cursor` for the whole window.
///
/// Returns `false` only on a storage failure, which leaves the cursor untouched
/// so the next round retries the same position.
async fn select(
    state: &AppState,
    session: &SessionIdentityState,
    filter: &arkret_models_collaboration::sync_frames::client_sync::SyncFilter,
    realm: &RealmId,
    cursor: &mut TimelineWindowCursor,
) -> bool {
    let Some(head) = cursor.head.clone() else {
        // The Realm holds no accepted Event at the frozen generation: a
        // legitimately empty window with no earlier history to point at.
        cursor.selection_complete = true;
        return true;
    };
    if cursor.window_limit == 0 {
        // `window_limit=0` asks for no items. It still completes explicitly and
        // still proves nothing about the Realm's history, so it claims neither
        // a gap nor a continuation: nothing was read.
        cursor.selection_complete = true;
        return true;
    }
    let projection = state.projections().snapshot();
    let mut examined = 0usize;
    let mut exhausted = false;
    while cursor.selected < cursor.window_limit && examined < SCAN_ROWS_PER_ROUND {
        let scan = match state
            .sync()
            .timeline_window_scan(
                realm.as_str(),
                &head,
                cursor.select_bound.as_ref(),
                SCAN_ROWS_PER_ROUND - examined,
            )
            .await
        {
            Ok(scan) => scan,
            Err(error) => {
                tracing::warn!(%error, %realm, "timeline window selection failed");
                return false;
            }
        };
        if scan.candidates.is_empty() {
            exhausted = true;
            break;
        }
        let batch_exhausted = scan.exhausted;
        for candidate in scan.candidates {
            examined += 1;
            cursor.select_bound = Some(candidate.position.clone());
            if !kind_allowed(filter, &candidate.kind)
                || !visible_to_session(state, &projection, realm, &candidate, session).await
            {
                continue;
            }
            cursor.provisional |= candidate.provisional;
            cursor.floor = Some(candidate.position.clone());
            cursor.selected += 1;
            if cursor.selected >= cursor.window_limit {
                break;
            }
        }
        // Exhaustion only settles the window once the batch has been consumed:
        // a batch that filled the window mid-way may still hold older rows.
        if batch_exhausted && cursor.selected < cursor.window_limit {
            exhausted = true;
            break;
        }
    }
    if exhausted {
        // The window reaches the start of this session's readable history, so
        // there is no earlier range and no cursor to fabricate for one.
        cursor.limited = false;
        cursor.selection_complete = true;
        return true;
    }
    if cursor.selected < cursor.window_limit {
        // Scan ceiling, not a settled window. Resume next round.
        return true;
    }
    let floor = cursor
        .floor
        .clone()
        .expect("a window that admitted its ceiling has a floor");
    let Some(limited) = readable_history_below(state, session, filter, realm, &head, &floor).await
    else {
        return false;
    };
    cursor.limited = limited;
    if limited {
        // Addresses the history before the *whole* window, and is minted once
        // so every segment repeats the same token (5.2). It is bound to the
        // plain Realm-scoped scan digest, which is what an
        // `ak.self.committed_event.read.scan.v1` backfill of this Realm recomputes, so
        // the token round-trips as that request's `before=`.
        cursor.prev_cursor = Some(
            super::cursor::sync_token_for_events_query(
                state,
                Some(session),
                &super::events_query::realm_history_scan_digest(realm),
                &floor.event_id,
            )
            .await,
        );
    }
    cursor.selection_complete = true;
    true
}

/// Does this session have readable history below the window's floor?
///
/// Answered with one bounded page rather than a count, because `limited` only
/// claims that an earlier *readable* range exists: content the filter or the
/// authorization removed must not be turned into a backfill invitation. A page
/// that ends on its ceiling without a visible row still reports a gap, because
/// rows do exist there and the backfill query re-applies authorization anyway;
/// what must never happen is claiming history is complete when it is not.
async fn readable_history_below(
    state: &AppState,
    session: &SessionIdentityState,
    filter: &arkret_models_collaboration::sync_frames::client_sync::SyncFilter,
    realm: &RealmId,
    head: &TimelineOrderPosition,
    floor: &TimelineOrderPosition,
) -> Option<bool> {
    let scan = state
        .sync()
        .timeline_window_scan(realm.as_str(), head, Some(floor), SCAN_ROWS_PER_ROUND)
        .await
        .inspect_err(|error| tracing::warn!(%error, %realm, "timeline history probe failed"))
        .ok()?;
    let projection = state.projections().snapshot();
    for candidate in &scan.candidates {
        if kind_allowed(filter, &candidate.kind)
            && visible_to_session(state, &projection, realm, candidate, session).await
        {
            return Some(true);
        }
    }
    Some(!scan.exhausted)
}

/// Walk up from the window floor toward the frozen head, cutting at the frame's
/// remaining bytes.
async fn deliver(
    state: &AppState,
    session: &SessionIdentityState,
    filter: &arkret_models_collaboration::sync_frames::client_sync::SyncFilter,
    realm: &RealmId,
    snapshot_cursor: &arkret_wire::Cursor,
    cursor: &mut TimelineWindowCursor,
    byte_budget: usize,
) -> Option<WindowSegment> {
    let (Some(head), Some(floor)) = (cursor.head.clone(), cursor.floor.clone()) else {
        // A zero-item window completes explicitly: absence of an entry is not
        // an empty window.
        return Some(finish(cursor, Vec::new(), snapshot_cursor));
    };
    if cursor.delivered >= cursor.window_limit {
        return Some(finish(cursor, Vec::new(), snapshot_cursor));
    }
    let owed = (cursor.window_limit - cursor.delivered) as usize;
    let projection = state.projections().snapshot();
    let mut events: Vec<arkret_wire::Event> = Vec::new();
    let mut bytes = 0usize;
    // Advances past rows this segment settled. A row the byte budget turned
    // away is not settled, so the bound stops short of it and the next round
    // reads it again.
    let mut bound = cursor.deliver_bound.clone();
    let mut examined = 0usize;
    let mut exhausted = false;
    let mut out_of_budget = false;
    while events.len() < owed && examined < SCAN_ROWS_PER_ROUND {
        let from = bound.clone().unwrap_or_else(|| floor.clone());
        let scan = match state
            .sync()
            .timeline_ascending_scan(
                realm.as_str(),
                &from,
                bound.is_none(),
                Some(&head),
                SCAN_ROWS_PER_ROUND - examined,
            )
            .await
        {
            Ok(scan) => scan,
            Err(error) => {
                tracing::warn!(%error, %realm, "timeline window delivery scan failed");
                return None;
            }
        };
        if scan.candidates.is_empty() {
            exhausted = true;
            break;
        }
        let batch_exhausted = scan.exhausted;
        for candidate in scan.candidates {
            examined += 1;
            // 2.3 re-decides every row against the receiver's *current* read
            // authorization when the frame is built; a frozen generation never
            // licenses delivering a row the caller may no longer see.
            if !kind_allowed(filter, &candidate.kind)
                || !visible_to_session(state, &projection, realm, &candidate, session).await
            {
                bound = Some(candidate.position.clone());
                continue;
            }
            let position = candidate.position.clone();
            let Some((event, size)) = encoded(candidate) else {
                bound = Some(position);
                continue;
            };
            if bytes.saturating_add(size) > byte_budget {
                out_of_budget = true;
                break;
            }
            bytes += size;
            bound = Some(event.0);
            events.push(event.1);
            if events.len() == owed {
                break;
            }
        }
        if out_of_budget {
            break;
        }
        if batch_exhausted {
            exhausted = true;
            break;
        }
    }
    cursor.deliver_bound = bound;
    // Only the frozen generation's own exhaustion or its cumulative ceiling
    // completes the window. Running out of frame bytes or hitting the scan
    // ceiling means work remains.
    let finished = !out_of_budget
        && (exhausted || cursor.delivered + events.len() as u32 >= cursor.window_limit);
    if finished {
        return Some(finish(cursor, events, snapshot_cursor));
    }
    if events.is_empty() {
        // Nothing to install this round. An empty non-final segment would only
        // repeat the window envelope, so the turn falls through to a frontier
        // frame and resumes from the position just recorded.
        return None;
    }
    Some(segment(cursor, events, snapshot_cursor, false))
}

fn finish(
    cursor: &mut TimelineWindowCursor,
    events: Vec<arkret_wire::Event>,
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
    segment(cursor, events, snapshot_cursor, true)
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
    byte_budget: usize,
) -> Option<WindowSegment> {
    let after = cursor.live_position.clone()?;
    let scan = state
        .sync()
        .timeline_ascending_scan(realm.as_str(), &after, false, None, SCAN_ROWS_PER_ROUND)
        .await
        .inspect_err(|error| tracing::warn!(%error, %realm, "timeline live scan failed"))
        .ok()?;
    if scan.candidates.is_empty() {
        return None;
    }
    let projection = state.projections().snapshot();
    let mut events = Vec::new();
    let mut bytes = 0usize;
    for candidate in scan.candidates {
        let position = candidate.position.clone();
        if !kind_allowed(filter, &candidate.kind)
            || !visible_to_session(state, &projection, realm, &candidate, session).await
        {
            cursor.live_position = Some(position);
            continue;
        }
        let Some((event, size)) = encoded(candidate) else {
            cursor.live_position = Some(position);
            continue;
        };
        if bytes.saturating_add(size) > byte_budget {
            // The rest of the increment rides the next frame; the position is
            // left on the last Event actually installed.
            break;
        }
        bytes += size;
        cursor.live_position = Some(event.0);
        events.push(event.1);
    }
    if events.is_empty() {
        // The position advanced past rows this session cannot see; there is
        // nothing to install, and an empty live timeline would be noise.
        return None;
    }
    Some(WindowSegment {
        timeline: Timeline {
            events,
            ..window_fields(&TimelineWindowCursor::default())
        },
        baseline: None,
    })
}

fn segment(
    cursor: &mut TimelineWindowCursor,
    events: Vec<arkret_wire::Event>,
    snapshot_cursor: &arkret_wire::Cursor,
    complete: bool,
) -> WindowSegment {
    cursor.complete = complete;
    // Count what is actually on the wire. Counting candidates instead would let
    // one undecodable envelope retire a slot the window still owes.
    cursor.delivered = cursor.delivered.saturating_add(events.len() as u32);
    WindowSegment {
        timeline: Timeline {
            events,
            ..window_fields(cursor)
        },
        baseline: Some(baseline_of(snapshot_cursor, cursor)),
    }
}

/// An accepted row whose envelope no longer decodes is a storage defect, not a
/// delivery decision: drop it loudly rather than letting it silently shrink a
/// window. The canonical size travels with the Event so the frame budget counts
/// exactly the bytes the wire will carry, plus the one byte of array
/// punctuation that joins it to its neighbour.
fn encoded(
    candidate: TimelineWindowCandidate,
) -> Option<((TimelineOrderPosition, arkret_wire::Event), usize)> {
    let position = candidate.position;
    let event: arkret_wire::Event = match serde_json::from_value(candidate.envelope) {
        Ok(event) => event,
        Err(error) => {
            tracing::error!(
                %error,
                event_id = %position.event_id,
                "accepted Event envelope did not decode for timeline delivery"
            );
            return None;
        }
    };
    let size = arkret_canonical::canonical_json_bytes(&event)
        .inspect_err(|error| {
            tracing::error!(
                %error,
                event_id = %position.event_id,
                "accepted Event did not canonicalize for timeline delivery"
            )
        })
        .ok()?
        .len()
        + 1;
    Some(((position, event), size))
}

/// The window-level fields of 5.2: identical in every segment of one frozen
/// generation, both in value and in presence.
fn window_fields(cursor: &TimelineWindowCursor) -> Timeline {
    Timeline {
        events: Vec::new(),
        limited: cursor.limited,
        prev_cursor: cursor.prev_cursor.clone(),
        // A provisional depth means 7.3 forbids claiming the order is final,
        // and a limited window means the client is missing the window-start
        // render context. Both take 5.2's (b) fallback: this producer does not
        // replay historical projections, so it never publishes a
        // `state_at_window_start` it cannot stand behind, and it never switches
        // between (a) and (b) mid-window.
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

#[cfg(test)]
mod postgres_tests;
