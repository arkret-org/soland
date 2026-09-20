//! Private resumable snapshot-and-tail coordinates for account sync.

use std::collections::BTreeMap;

use arkret_wire::{ActorId, CommitStreamHead, CommitStreamRef, Cursor, EventId, RealmId, StrandId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize)]
pub struct CurrentDetailRequest {
    pub actor_id: ActorId,
    pub realm_id: RealmId,
    pub strand_ids: Option<Vec<StrandId>>,
    pub all_members: bool,
    pub event_ids: Vec<EventId>,
    pub timeline_limit: u32,
    pub event_kinds: Option<Vec<String>>,
    pub not_event_kinds: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentDetailProgress {
    pub request_digest: String,
    pub snapshot_cursor: Cursor,
    pub expires_at_ms: i64,
    pub snapshot_id: arkret_wire::RealmSnapshotId,
    pub stream_heads: Vec<CommitStreamHead>,
    /// Next unread position for each independent stream's tail.
    pub next_positions: BTreeMap<CommitStreamRef, u64>,
    pub complete: bool,
}

#[derive(Clone, Debug)]
pub struct CurrentDetailPage {
    pub progress: CurrentDetailProgress,
    pub entries: Vec<arkret_wire::CommittedEventFullView>,
    pub snapshot: Option<arkret_wire::RealmStateSnapshot>,
}

#[derive(Clone, Debug)]
pub enum CurrentDetailOutcome {
    Page(CurrentDetailPage),
    NotFound,
    Unavailable,
}
