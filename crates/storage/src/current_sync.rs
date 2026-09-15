//! Private durable account current-window coordinates. These are stored inside
//! authenticated cursor handles, never accepted as a second wire protocol.

use arkret_models_collaboration::sync_frames::current_results::{
    CurrentCoverage, CurrentResultEntry,
};
use arkret_models_collaboration::sync_frames::demand_sync::RealmDetailBaseline;
use arkret_wire::{ActorId, Cursor, EventId, RealmId, StrandId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize)]
pub struct CurrentDetailRequest {
    pub actor_id: ActorId,
    pub realm_id: RealmId,
    pub strand_ids: Option<Vec<StrandId>>,
    pub all_members: bool,
    /// Exact message window chosen by the server, not arbitrary client IDs.
    pub event_ids: Vec<EventId>,
    /// Frozen timeline window shape (`client-sync.md` 2.3). These three fields
    /// decide which Events the window contains, so they belong to the request
    /// context frozen with the generation: raising the ceiling or changing the
    /// content filter changes the window range and MUST mint a new generation
    /// rather than mutate one already in flight. They reach that outcome by
    /// being part of the request digest a stored progress is checked against.
    pub timeline_limit: u32,
    pub event_kinds: Option<Vec<String>>,
    pub not_event_kinds: Option<Vec<String>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CurrentDetailPhase {
    Priority,
    Ordinary,
    Live,
}

/// One position in the `conformance/encoding.md` 7.3 projection order.
///
/// Carried in the cursor handle so a window can resume across rounds without
/// rereading what it already delivered. `hlc` is `None` for a genuine absent
/// HLC and never a substitute value: 7.3 sorts absent last, and any filler
/// would move the Event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimelineOrderPosition {
    pub causal_depth: i64,
    pub hlc: Option<String>,
    pub actor_id: String,
    pub actor_seq: i64,
    pub event_id: String,
}

/// Per-Realm progress of one frozen timeline window (`client-sync.md` 2.3).
///
/// The window is produced in two phases, because 5.2 makes `limited`,
/// `preview_only` and `prev_cursor` *window-level*: every segment of one
/// generation must repeat the same values and the same field presence. None of
/// those can be answered while segments are still being cut, so selection runs
/// first and settles the window's extent, and only then does delivery cut it
/// into byte-sized segments.
///
/// Phase 1 (selection) walks down from `head` and keeps the oldest position it
/// admitted in `floor`; phase 2 (delivery) walks up from `floor` to `head`. The
/// walk is bounded in both directions by the projection-order index, so neither
/// phase ever reads the Realm.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimelineWindowCursor {
    /// Cumulative ceiling across every segment of this generation, frozen from
    /// the request. Constant within a window, which is what stops it from
    /// degenerating into a per-frame limit.
    pub window_limit: u32,
    /// Newest projection-order position at freeze time and the inclusive upper
    /// bound of the whole window. Events accepted afterwards sort above it and
    /// stay out; they reach the client as live increments instead.
    pub head: Option<TimelineOrderPosition>,
    /// Descending selection continuation (exclusive), so a selection split over
    /// rounds never re-examines a row.
    pub select_bound: Option<TimelineOrderPosition>,
    /// Oldest position selection admitted: the window start, and the boundary
    /// `prev_cursor` points at.
    pub floor: Option<TimelineOrderPosition>,
    pub selected: u32,
    pub selection_complete: bool,
    /// Window-level `timeline.limited`: readable history exists below `floor`.
    /// Decided once, when selection closes, and repeated in every segment.
    pub limited: bool,
    /// Window-level `timeline.prev_cursor`, minted once when selection closes
    /// and only when `limited`. It addresses the history before the *whole*
    /// window, never before the current segment.
    pub prev_cursor: Option<String>,
    /// Some Event in this window has a provisional depth, so 7.3 forbids
    /// claiming the order is final; the producer falls back to `preview_only`.
    pub provisional: bool,
    /// Ascending delivery continuation (exclusive), or `None` to start at
    /// `floor` inclusive.
    pub deliver_bound: Option<TimelineOrderPosition>,
    pub delivered: u32,
    pub complete: bool,
    /// Highest position already delivered as a live increment, starting at
    /// `head` when the window completes. Live increments carry no
    /// `timeline_baseline`, never complete or reopen the frozen window, and
    /// continue from here so an Event accepted mid-delivery is delivered once.
    pub live_position: Option<TimelineOrderPosition>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentDetailProgress {
    pub request_digest: String,
    pub snapshot_cursor: Cursor,
    pub cut_revision: i64,
    pub authority_revision: i64,
    pub retained_revision: i64,
    pub expires_at_ms: i64,
    pub coverage: CurrentCoverage,
    pub phase: CurrentDetailPhase,
    pub scan_revision: i64,
    pub scan_selector: String,
    /// Timeline window state of the same frozen generation. `current-results.md`
    /// 4 binds both to one generation, so they share this record and its
    /// `snapshot_cursor`; their completion flags stay independent.
    #[serde(default)]
    pub timeline: TimelineWindowCursor,
}

#[derive(Clone, Debug)]
pub struct CurrentDetailPage {
    pub progress: CurrentDetailProgress,
    pub entries: Vec<CurrentResultEntry>,
    pub baseline: Option<RealmDetailBaseline>,
}

/// One candidate row of a frozen timeline window, before the caller applies
/// per-Event visibility.
///
/// Authorization is not a storage predicate here: history access, Circle scope
/// and redaction need the session and the projection, so the reader returns
/// candidates in projection order and the HTTP layer decides. The scan stays
/// bounded so that decision cannot degenerate into reading the Realm.
#[derive(Clone, Debug)]
pub struct TimelineWindowCandidate {
    pub position: TimelineOrderPosition,
    pub kind: String,
    pub provisional: bool,
    pub envelope: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub sender: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct TimelineWindowScan {
    pub candidates: Vec<TimelineWindowCandidate>,
    /// No further rows exist at or below the requested bound.
    pub exhausted: bool,
    /// The scan stopped on its own row ceiling rather than on exhaustion, so
    /// the caller must continue from the last candidate instead of concluding
    /// the window is finished.
    pub scan_capped: bool,
}

#[derive(Clone, Debug)]
pub enum CurrentDetailOutcome {
    Page(CurrentDetailPage),
    NotFound,
    Unavailable,
}
