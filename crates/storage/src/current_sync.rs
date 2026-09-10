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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CurrentDetailPhase {
    Priority,
    Ordinary,
    Live,
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
}

#[derive(Clone, Debug)]
pub struct CurrentDetailPage {
    pub progress: CurrentDetailProgress,
    pub entries: Vec<CurrentResultEntry>,
    pub baseline: Option<RealmDetailBaseline>,
}

#[derive(Clone, Debug)]
pub enum CurrentDetailOutcome {
    Page(CurrentDetailPage),
    NotFound,
    Unavailable,
}
