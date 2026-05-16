//! Deterministic state reducer for contrix operations.
//!
//! Applies operations to produce projection state using well-known
//! conflict resolution rules:
//! - Scalar fields: Last-Writer-Wins (LWW) by HLC timestamp
//! - Set fields: OR-Set (add-wins with tombstones)
//! - Messages: append-only, revisions form chains
//! - Ordered lists: fractional indexing
//!
//! # Architecture
//!
//! [`ProjectionState::apply`] is a direct match-on-canonical-kind
//! dispatcher to inline projection helpers.
//!
//! The Move/Anchor receive pipeline (`POST /api/v1/moves` /
//! `POST /api/v1/anchors`) routes through [`registry::LatticeKind`] /
//! [`registry::LatticeRegistry`]. Concrete impls live in
//! [`lattice_kinds`]; [`lattice_kinds::build_sdk_cell_registry`] feeds
//! the SDK's `verify_move` / `apply_anchor` pipeline. This is the
//! protocol-canonical path; [`ProjectionState`]'s structured fields
//! (`messages`, `reactions`, `read_markers`, etc.) are an in-memory
//! convenience cache populated from the durable Event-Envelope ingestion
//! path that pre-dates the Move/Anchor model. As Anchor projection lands,
//! the structured fields migrate to a single `cells` map.

pub mod lattice_kinds;
pub mod registry;

use std::collections::{BTreeMap, BTreeSet};

use contrix_sdk::lattice::CellState;
use contrix_sdk::state_res::{CellRegistry, CellStore, StoreError};
use contrix_sdk::{CellRef, Operation, SpaceId};
use serde_json::Value;

use crate::hlc::ServerHlc;

/// In-memory projection state produced by the reducer.
#[derive(Clone, Debug, Default)]
pub struct ProjectionState {
    /// Messages keyed by event_id. LWW by created_at.
    pub messages: BTreeMap<String, MessageState>,
    /// Reactions keyed by (event_id, actor, reaction_key). OR-Set.
    pub reactions: BTreeMap<String, BTreeMap<String, BTreeMap<String, ReactionState>>>,
    /// Read markers keyed by (space_id, actor, scope_id). LWW.
    pub read_markers: BTreeMap<(String, String, String), ReadMarkerState>,
    /// Relations keyed by relation_id. LWW by HLC.
    pub relations: BTreeMap<String, RelationState>,
    /// Structured side-band cache keyed by
    /// `(space_id, actor_did)`. Holds the FSM state value plus `role` /
    /// `joined_at` / `updated_at` side-band data that doesn't fit in the
    /// `cx.component.member.state.v1` FSM cell itself. Reads should go
    /// through helpers like [`ProjectionState::members_of_space`] /
    /// [`ProjectionState::members_in_state`] / [`ProjectionState::member`]
    /// rather than touching this directly.
    ///
    /// Banned and knocking members are derived via `members_in_state`
    /// against the FSM state field, not stored as separate collections.
    pub members: BTreeMap<(String, String), MembershipState>,
    /// Space lifecycle state keyed by space_id.
    pub space_states: BTreeMap<String, SpaceState>,
    /// Redacted event IDs (tombstones). This stays as a flat
    /// fast-lookup index over the parallel [`Self::redaction_cells`] map
    /// — entries sit here whenever the parallel cell is `Some(_)` and are
    /// removed when the cas-register is set back to null (un-redaction).
    pub redactions: BTreeSet<String>,
    /// Parallel `redaction` cells keyed by the target
    /// event_id (subject). Each value is a [`RedactionCellValue`] holding
    /// `{redacted_at, by, reason}` per the spec, or `None` after an
    /// un-redaction. The original message entry in [`Self::messages`] is
    /// left intact so the ordered-log historical entry id is preserved;
    /// the projection layer consults this map at read time and replaces
    /// the payload with the tombstone.
    pub redaction_cells: BTreeMap<String, Option<RedactionCellValue>>,
    /// Per-cell effective state
    /// populated from the Move/Anchor pipeline's `apply_anchor` write-back.
    ///
    /// Keyed by canonical `CellRef` (e.g.
    /// `cx:cell:cx.component.space.read_receipt_policy.v1:<space_id>`).
    /// Each successful apply_anchor (`routing::federation::move_anchor::submit_anchor` or
    /// `crate::anchorer::AnchorerWorker`) calls
    /// [`ProjectionState::reload_cells_from_store`] to refresh this map for
    /// the affected Space. Read handlers query via [`ProjectionState::cell`]
    /// / [`ProjectionState::cell_value`] for cell-keyed state lookups
    /// instead of scanning the durable Event store.
    ///
    /// This map is the canonical source for all cell-driven state in the
    /// Move/Anchor pipeline.
    /// Completed migrations:
    ///   - `read_receipt_policies` (CasRegister) — old BTreeMap deleted; read path uses
    ///     `cell_value`.
    ///   - `memberships` / `banned_members` / `knocking_members` (FSM) — replaced by flat
    ///     `members: BTreeMap<(String, String), MembershipState>` cache + per-actor
    ///     `cx.component.member.state.v1` FSM cell.
    ///   - `space_states` (mixed: ordered-log + cas-register) — kept as structured `space_states`
    ///     side-band cache (server-side `created_at`/`updated_at`/`deleted` flag) BUT every
    ///     `apply_space_lifecycle` now also writes one of: `cx.component.space.create.v1`
    ///     (ordered-log, append) / `cx.component.space.organization.v1` (cas-register, latest
    ///     metadata) / `cx.component.space.destroy.v1` (cas-register, terminal). Helpers:
    ///     `space_create_log` / `space_organization_cell_value` / `space_is_destroyed` query cells
    ///     directly.
    /// Durable-event-only fields (`messages` / `reactions` / `read_markers`
    /// / `relations` / `redactions`) stay structured per spec
    /// (those event kinds have no `cell_family` declaration).
    pub cells: BTreeMap<CellRef, CellState>,
    /// Server-side Place projection — `place_id -> PlaceProjection`.
    /// Maintains the canonical state-machine described in
    /// `contrix-spec/v1/zh/models/common-fields.md §5.1` for cx.place.*
    /// lifecycle events. Used by `event_log::submit_event` to reject
    /// invalid transitions with HTTP 412 before persisting. Reducer
    /// applies cx.place.create / update / parent / archive / restore /
    /// tombstone; mirror table is `projection_places` (durable).
    pub places: BTreeMap<String, PlaceProjection>,
    /// Round 13 — Server-side Flow projection. Mirrors the canonical
    /// state-machine for cx.flow.create / update / archive / restore.
    /// Unlike Place there is no dedicated `cx.flow.tombstone` event;
    /// terminal state is reached via `cx.redaction`. Mirror table is
    /// `projection_flows` (durable).
    pub flows: BTreeMap<String, FlowProjection>,
    /// Round 13 — Server-side Morph projection. Same shape as Flow.
    /// Mirror table is `projection_morphs` (durable).
    pub morphs: BTreeMap<String, MorphProjection>,
    /// Round 15b (2026-05-16) — Server-side Applet registry projection,
    /// keyed by `service_did` (the canonical applet identity per spec
    /// `extensions/applet-integration.md`). Populated by
    /// `cx.applet.registration` (initial registration / re-registration)
    /// and updated by `cx.applet.discovery` (manifest refresh). Used by
    /// `GET /api/v1/admin/applets` admin snapshot. Protocol-session
    /// events (`cx.applet.protocol_session.{start,status}`,
    /// `cx.applet.bridge_error`) are NOT mirrored here — sessions are
    /// ephemeral and the applet bridge state machine lives client-side.
    pub applets: BTreeMap<String, AppletProjection>,
    /// Round 15b — Server-side Agent registry projection, keyed by
    /// `agent_did`. Same shape as `applets`. Populated by
    /// `cx.agent.endpoint`. Protocol-session events for agents
    /// (`cx.agent.protocol_session.{start,status,result}`) are also not
    /// mirrored — see `applets` rationale.
    pub agents: BTreeMap<String, AgentProjection>,
}

/// Server-side Place state cache. Mirrors the `projection_places` table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlaceProjection {
    pub place_id: String,
    pub space_id: String,
    pub kind: String,
    pub title: String,
    pub parent_ref: Option<String>,
    pub rank: Option<String>,
    pub state: PlaceLifecycleState,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PlaceLifecycleState {
    #[default]
    Active,
    Archived,
    Tombstoned,
}

impl PlaceLifecycleState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Archived => "archived",
            Self::Tombstoned => "tombstoned",
        }
    }
}

/// Server-side Flow state cache. Mirrors `projection_flows` table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowProjection {
    pub flow_id: String,
    pub space_id: String,
    pub title: String,
    pub summary: Option<String>,
    pub state: ObjectLifecycleState,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Server-side Morph state cache. Mirrors `projection_morphs` table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MorphProjection {
    pub morph_id: String,
    pub space_id: String,
    pub morph_type: String,
    pub title: Option<String>,
    pub state: ObjectLifecycleState,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Round 15b — Server-side Applet registry entry. Populated by
/// `cx.applet.registration` (creates) and `cx.applet.discovery` (refreshes
/// the manifest). Spec `extensions/applet-integration.md` doesn't pin
/// down a state-machine for applet entries themselves (the bridge state
/// machine is per-session and lives client-side), so this is a simple
/// last-write-wins projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppletProjection {
    /// `service_did` of the applet — canonical identity per spec.
    pub service_did: String,
    pub namespace: String,
    /// Optional snapshot of the most recent `manifest` (from the latest
    /// `cx.applet.discovery` event). `None` if only registration has
    /// landed.
    pub manifest: Option<Value>,
    /// Optional capability list from the latest `cx.applet.registration`.
    pub capabilities: Option<Value>,
    pub registered_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Round 15b — Server-side Agent registry entry. Populated by
/// `cx.agent.endpoint`. Spec `extensions/agent-integration.md` mirrors
/// the applet family shape; same simple last-write-wins semantics.
///
/// Sprint Q1 第二十增量 (B4d): `endpoint_url` is the HTTPS URL the
/// agent runtime listens on. It is OPTIONAL on the wire (older
/// clients + DID-only agents that resolve via did:web service entry
/// won't set it), but when present the reference bridge echoes it
/// back in the `cx.agent.protocol_session.result` envelope's
/// `detail.endpoint_url` so timeline consumers see which endpoint
/// answered the invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentProjection {
    /// `agent_did` — canonical agent identity per spec.
    pub agent_did: String,
    /// Protocol the agent speaks (free-form string per spec event-kind-registry
    /// payload description; no enum enforcement at this layer).
    pub protocol: String,
    /// HTTPS endpoint URL — optional. Reference bridge currently
    /// uses this only as an observability field. Production runtimes
    /// will follow it for outbound dispatch (tracked as B4f in
    /// `_todos.md`).
    pub endpoint_url: Option<String>,
    pub registered_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// State enum shared by Flow and Morph projections (mirrors SDK
/// `contrix_sdk::ObjectState`). Unlike `PlaceLifecycleState` which has a
/// single `Tombstoned` terminal, Flow / Morph distinguish the two terminal
/// kinds `Deleted` (reached via cx.redaction with a delete intent) from
/// `Redacted` (content cleared, audit envelope preserved). Per spec §5.1
/// both are equivalent for state-machine purposes — neither admits any
/// transition out, so the soland reducer reuses one enum.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ObjectLifecycleState {
    #[default]
    Active,
    Archived,
    Deleted,
    Redacted,
}

impl ObjectLifecycleState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Archived => "archived",
            Self::Deleted => "deleted",
            Self::Redacted => "redacted",
        }
    }

    /// Terminal state per spec §5.1: `tombstoned / deleted / redacted` are
    /// equivalent unrecoverable terminals.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Deleted | Self::Redacted)
    }
}

/// Value of the parallel `redaction` cas-register
/// cell on the same subject as the target message cell. Mirrors the spec
/// shape `{redacted_at, by, reason}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactionCellValue {
    pub redacted_at: chrono::DateTime<chrono::Utc>,
    pub by: String,
    pub reason: Option<String>,
}

impl RedactionCellValue {
    /// Render the cas-register payload as JSON for projection / wire emission.
    pub fn to_json(&self) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "redacted_at".to_owned(),
            Value::String(self.redacted_at.to_rfc3339()),
        );
        obj.insert("by".to_owned(), Value::String(self.by.clone()));
        if let Some(reason) = &self.reason {
            obj.insert("reason".to_owned(), Value::String(reason.clone()));
        }
        Value::Object(obj)
    }
}

/// Projection-layer view of a single message cell. The reducer
/// keeps the original [`MessageState`] intact; this view is what callers
/// see at read time after the parallel `redaction` cell is consulted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectedMessageView {
    pub event_id: String,
    pub space_id: String,
    pub sender: String,
    pub thread_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// `Some(content)` for live messages; `None` when a redaction tombstone
    /// is in effect (the projection layer replaced the payload).
    pub content: Option<Value>,
    /// `Some(value)` while the parallel `redaction` cell is set; `None` for
    /// live messages and for messages whose redaction was reverted (cell
    /// set back to null).
    pub redaction: Option<RedactionCellValue>,
}

#[derive(Clone, Debug)]
pub struct MessageState {
    pub event_id: String,
    pub space_id: String,
    pub sender: String,
    pub thread_id: String,
    pub content: Value,
    pub encrypted: bool,
    pub operation_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// If this is a revision, points to the original event_id.
    pub revision_of: Option<String>,
    /// If redacted, the tombstone timestamp.
    pub redacted_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug)]
pub struct ReactionState {
    pub actor: String,
    pub key: String,
    pub active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct ReadMarkerState {
    pub actor: String,
    pub space_id: String,
    pub scope_id: String,
    pub event_id: String,
    pub read_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct RelationState {
    pub relation_id: String,
    pub space_id: String,
    pub relation_kind: String,
    pub from_ref: Option<String>,
    pub to_ref: Option<String>,
    pub fields: BTreeMap<String, Value>,
    pub deleted: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct MembershipState {
    pub member: String,
    pub space_id: String,
    /// Canonical FSM state value (one of `invite` / `join` / `leave` /
    /// `ban` / `knock`). Authoritative source is the
    /// `cx.component.member.state.v1` cell in
    /// [`ProjectionState::cells`]; this field is the structured-cache
    /// mirror updated on every membership transition.
    pub state: String,
    pub role: String,
    pub joined_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct SpaceState {
    pub space_id: String,
    pub owner: Option<String>,
    pub title: Option<String>,
    pub deleted: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// The effect of applying an operation to the projection state.
#[derive(Clone, Debug)]
pub enum ProjectionEffect {
    MessageCreated(MessageState),
    MessageRevised {
        original_id: String,
        revision: MessageState,
    },
    MessageRedacted {
        event_id: String,
    },
    ReactionChanged {
        event_id: String,
        actor: String,
        key: String,
        active: bool,
    },
    ReadMarkerUpdated(ReadMarkerState),
    RelationCreated(RelationState),
    RelationUpdated(RelationState),
    RelationDeleted {
        relation_id: String,
    },
    MembershipChanged {
        space_id: String,
        member: String,
        action: String,
    },
    SpaceLifecycle {
        space_id: String,
        action: String,
    },
    /// Place lifecycle transition accepted; new state is reflected in
    /// `ProjectionState::places` and (when persisted) `projection_places`.
    PlaceLifecycle {
        place_id: String,
        new_state: PlaceLifecycleState,
    },
    /// Round 13 — Flow lifecycle transition accepted. Mirror of
    /// `PlaceLifecycle` for `ProjectionState::flows`.
    FlowLifecycle {
        flow_id: String,
        new_state: ObjectLifecycleState,
    },
    /// Round 13 — Morph lifecycle transition accepted. Same shape as Flow.
    MorphLifecycle {
        morph_id: String,
        new_state: ObjectLifecycleState,
    },
    /// Round 15b — Applet registry projection updated (registration or
    /// discovery). Keyed by the applet's `service_did`.
    AppletProjectionUpdated {
        service_did: String,
    },
    /// Round 15b — Agent registry projection updated (endpoint). Keyed
    /// by the agent's `agent_did`.
    AgentProjectionUpdated {
        agent_did: String,
    },
    /// State-machine rejected the operation per
    /// `common-fields.md §5.1`. Routing layer maps this to HTTP 412
    /// `failed_precondition` with the canonical reason_code.
    Rejected {
        reason: String,
    },
    Ignored,
}

/// Which Place lifecycle transition is being attempted. Used by
/// `apply_place_lifecycle` to share the state-machine guard across the
/// three event kinds.
#[derive(Clone, Copy, Debug)]
enum PlaceLifecycleTransition {
    Archive,
    Restore,
    Tombstone,
}

/// Round 13 — Flow / Morph lifecycle transition picker. Mirror of
/// `PlaceLifecycleTransition` but for the two-event family (no tombstone).
#[derive(Clone, Copy, Debug)]
enum ObjectLifecycleTransition {
    Archive,
    Restore,
}

/// Round 14b — Extract the typed-id object reference from a
/// `cx.redaction` event payload, used by both the reducer
/// (`apply_redaction`) and the preflight
/// (`check_redaction_target_transition`). Returns `None` for redactions
/// that only carry a `target_event_id` (message redaction path), or
/// when no recognised object-ref field is present. The fallbacks
/// `target_object_ref` / `object_ref` mirror SDK `extract_place_id`'s
/// convention for object-level event payloads.
fn redaction_object_ref(operation: &Operation) -> Option<String> {
    operation
        .payload
        .get("object_ref")
        .or_else(|| operation.payload.get("target_object_ref"))
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
}

impl ProjectionState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up a cell's resolved state by its canonical [`CellRef`]. Returns
    /// `None` if the cell hasn't been observed (no anchored Move ever wrote
    /// to it). The returned `CellState` is either `Value(_)` (lattice
    /// resolved successfully) or `Bottom(_)` (concurrent conflict requires
    /// recovery).
    pub fn cell(&self, cell_id: &CellRef) -> Option<&CellState> {
        self.cells.get(cell_id)
    }

    /// Look up the JSON value stored in a cell. Returns `None` for absent
    /// cells AND for cells in `Bottom` state — callers that need to
    /// distinguish (e.g. UI showing "this state is in conflict") should
    /// use [`ProjectionState::cell`] directly.
    pub fn cell_value(&self, cell_id: &CellRef) -> Option<&Value> {
        match self.cells.get(cell_id)? {
            CellState::Value(v) => Some(v),
            CellState::Bottom(_) => None,
        }
    }

    /// Reload the cells map for one Space from the SDK CellStore + apply
    /// each cell's lattice. Called after every successful `apply_anchor`
    /// in the Move/Anchor pipeline (`routing::federation::move_anchor::submit_anchor`
    /// + `crate::anchorer::AnchorerWorker`) to keep this projection cache
    /// in sync with anchored cell state.
    ///
    /// This is the only write path into [`ProjectionState::cells`]; the
    /// durable-Event projection path (`apply()`) does NOT touch cells —
    /// state cells are exclusively a Move/Anchor surface per spec.
    pub fn reload_cells_from_store(
        &mut self,
        space_id: &SpaceId,
        cell_store: &dyn CellStore,
        cell_registry: &dyn CellRegistry,
    ) -> Result<(), StoreError> {
        for cell in cell_store.list_cells(space_id)? {
            let ops = cell_store.anchored_ops_for_cell(space_id, &cell)?;
            let binding = cell_registry
                .resolve(space_id, &cell)
                .map_err(|e| StoreError::Backend(format!("cell registry resolve: {e}")))?;
            let resolved = binding.lattice.join(&cell, &ops);
            self.cells.insert(cell, resolved);
        }
        Ok(())
    }

    /// Apply a single operation and return the effect.
    ///
    /// Direct match-on-canonical-kind dispatch to per-domain helpers. This
    /// replaced the per-kind
    /// `ReducerKind` trait + `ReducerRegistry` apparatus, which added
    /// zero value over inline match dispatch (every per-kind stub was a
    /// thin delegate to a `ProjectionState::apply_*` helper).
    ///
    /// Durable-event projection now probes the lattice registry before
    /// applying these inline caches, so unknown event kinds fail closed.
    pub fn apply(&mut self, operation: &Operation, _hlc: &ServerHlc) -> ProjectionEffect {
        use crate::kinds::*;
        let now = operation.created_at;
        match crate::kinds::canonical_kind_for_operation(operation) {
            Some(CX_MESSAGE_CREATE) => self.apply_message(operation, now),
            Some(CX_MESSAGE_REVISE) => self.apply_message_revise(operation, now),
            Some(CX_MESSAGE_REDACT) | Some(CX_REDACTION) => self.apply_redaction(operation),
            Some(CX_REACTION_ADD) => self.apply_reaction_add(operation, now),
            Some(CX_REACTION_REMOVE) => self.apply_reaction_remove(operation),
            Some(CX_READ_MARKER) => self.apply_read_marker(operation, now),
            Some(CX_RELATION_CREATE) => self.apply_relation_create(operation, now),
            Some(CX_RELATION_UPDATE) => self.apply_relation_update(operation, now, _hlc),
            Some(CX_RELATION_DELETE) => self.apply_relation_delete(operation),
            Some(CX_CONTAINER_MOVE_ITEM) | Some(CX_CONTAINER_REBALANCE) => {
                self.apply_container_position(operation, now)
            }
            Some(CX_MEMBER_STATE) => self.apply_membership(operation, now),
            Some(kind @ (CX_SPACE_CREATE | CX_SPACE_UPDATE | CX_SPACE_DESTROY)) => {
                self.apply_space_lifecycle(operation, now, kind)
            }
            Some(CX_PLACE_CREATE) => self.apply_place_create(operation, now),
            Some(CX_PLACE_UPDATE) => self.apply_place_update(operation, now),
            Some(CX_PLACE_PARENT) => self.apply_place_parent(operation, now),
            Some(CX_PLACE_ARCHIVE) => self.apply_place_lifecycle(
                operation,
                now,
                PlaceLifecycleTransition::Archive,
            ),
            Some(CX_PLACE_RESTORE) => self.apply_place_lifecycle(
                operation,
                now,
                PlaceLifecycleTransition::Restore,
            ),
            Some(CX_PLACE_TOMBSTONE) => self.apply_place_lifecycle(
                operation,
                now,
                PlaceLifecycleTransition::Tombstone,
            ),
            Some(CX_FLOW_CREATE) => self.apply_flow_create(operation, now),
            Some(CX_FLOW_UPDATE) => self.apply_flow_update(operation, now),
            Some(CX_FLOW_ARCHIVE) => self.apply_flow_lifecycle(
                operation,
                now,
                ObjectLifecycleTransition::Archive,
            ),
            Some(CX_FLOW_RESTORE) => self.apply_flow_lifecycle(
                operation,
                now,
                ObjectLifecycleTransition::Restore,
            ),
            Some(CX_FLOW_MOVE) | Some(CX_FLOW_REORDER) => {
                self.apply_flow_position_touch(operation, now)
            }
            Some(
                CX_FLOW_TRACK_DISABLE
                | CX_FLOW_TRACK_ENABLE
                | CX_FLOW_TRACK_SET_PRIMARY
                | CX_FLOW_TRACK_UPDATE,
            ) => self.apply_flow_track_touch(operation, now),
            Some(CX_MORPH_CREATE) => self.apply_morph_create(operation, now),
            Some(CX_MORPH_UPDATE) => self.apply_morph_update(operation, now),
            Some(CX_MORPH_ARCHIVE) => self.apply_morph_lifecycle(
                operation,
                now,
                ObjectLifecycleTransition::Archive,
            ),
            Some(CX_MORPH_RESTORE) => self.apply_morph_lifecycle(
                operation,
                now,
                ObjectLifecycleTransition::Restore,
            ),
            Some(CX_APPLET_REGISTRATION) => self.apply_applet_registration(operation, now),
            Some(CX_APPLET_DISCOVERY) => self.apply_applet_discovery(operation, now),
            Some(CX_AGENT_ENDPOINT) => self.apply_agent_endpoint(operation, now),
            // All cell-state events (cx.space.policy / cx.space.read_receipt_policy /
            // cx.consent.* / cx.member.state / cx.space.* facets) are routed via
            // the Move/Anchor pipeline through `LatticeKind` impls in
            // `lattice_kinds.rs`; the structured ProjectionState fields don't
            // mirror them. `routing/projection.rs::project_read_receipt_policy`
            // handles the read-receipt cache fast path explicitly.
            _ => ProjectionEffect::Ignored,
        }
    }

    /// Apply a batch of operations.
    pub fn apply_batch(
        &mut self,
        operations: &[Operation],
        hlc: &ServerHlc,
    ) -> Vec<ProjectionEffect> {
        operations.iter().map(|op| self.apply(op, hlc)).collect()
    }

    /// Probe the supplied [`LatticeRegistry`] for a `cell_family` that
    /// handles this Operation's canonical kind via `event_kinds()`.
    ///
    /// Behaviour:
    /// - **Hit on a cell-family impl**: routes through the inline `apply_*` helpers (the helpers
    ///   ARE the projection — the registry only validates that the spec maps this event_kind to a
    ///   known cell family, then we trust the inline dispatcher to handle the per-domain effect).
    /// - **No mapping in registry but a known canonical kind**: the kind is durable-Event-only
    ///   (`cx.message.*` / `cx.reaction.*` etc.); fall through to inline `apply()` exactly as
    ///   before. No log noise.
    /// - **Unknown canonical kind**: spec compliance requires us to fail closed — log at `error`
    ///   level and project as `ProjectionEffect:: Ignored` with `bottom = reject` semantics.
    pub fn apply_via_lattice_registry(
        &mut self,
        operation: &Operation,
        hlc: &ServerHlc,
        registry: &registry::LatticeRegistry,
    ) -> ProjectionEffect {
        let kind = match crate::kinds::canonical_kind_for_operation(operation) {
            Some(k) => k,
            None => {
                tracing::error!(
                    object_type = %operation.object_type,
                    operation_id = %operation.operation_id,
                    "lattice registry dispatch: unknown canonical kind for operation; \
                     dropping with bottom (reject)"
                );
                return ProjectionEffect::Ignored;
            }
        };
        if registry.lookup_for_event_kind(kind).is_some() {
            // Canonical hit — log at trace + delegate to inline helpers.
            // The inline helpers and the LatticeRegistry-resolved cell
            // family agree by construction (this whole module has one
            // canonical match arm; the registry just declares which
            // event kinds it owns).
            tracing::trace!(
                event_kind = %kind,
                "lattice registry dispatch: routed through LatticeRegistry"
            );
            self.apply(operation, hlc)
        } else {
            // No cell-family mapping for this kind — durable-Event-only
            // projection (messages / reactions / etc.) goes through the
            // inline cache. This branch is the steady state for the
            // ~10 message-domain kinds.
            self.apply(operation, hlc)
        }
    }

    fn apply_message(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let event_id = operation
            .payload
            .get("event_id")
            .and_then(|v| v.as_str())
            .unwrap_or(operation.operation_id.as_str())
            .to_owned();
        let sender = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let thread_id = operation
            .payload
            .get("thread_id")
            .and_then(|v| v.as_str())
            .unwrap_or(operation.space_id.as_str())
            .to_owned();
        let content = operation
            .payload
            .get("content")
            .cloned()
            .unwrap_or_else(|| operation.payload.clone());
        let encrypted = operation
            .payload
            .get("encrypted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let state = MessageState {
            event_id: event_id.clone(),
            space_id: operation.space_id.to_string(),
            sender,
            thread_id,
            content,
            encrypted,
            operation_id: operation.operation_id.to_string(),
            created_at: now,
            revision_of: None,
            redacted_at: None,
        };
        let effect = ProjectionEffect::MessageCreated(state.clone());
        self.messages.insert(event_id, state);
        effect
    }

    fn apply_message_revise(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let original_id = operation
            .payload
            .get("target_event_id")
            .or_else(|| operation.payload.get("event_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let new_event_id = operation
            .payload
            .get("new_event_id")
            .or_else(|| operation.payload.get("revised_event_id"))
            .and_then(|v| v.as_str())
            .unwrap_or(operation.operation_id.as_str())
            .to_owned();

        if let Some(original) = self.messages.get(&original_id) {
            let mut revised = original.clone();
            revised.event_id = new_event_id.clone();
            revised.revision_of = Some(original_id.clone());
            revised.created_at = now;
            revised.operation_id = operation.operation_id.to_string();
            if let Some(content) = operation.payload.get("content") {
                revised.content = content.clone();
            }
            let effect = ProjectionEffect::MessageRevised {
                original_id: original_id.clone(),
                revision: revised.clone(),
            };
            self.messages.insert(new_event_id, revised);
            effect
        } else {
            // Original not found; treat as a new message
            self.apply_message(operation, now)
        }
    }

    /// Writes a parallel `redaction` cas-register
    /// cell on the same subject as the target message cell, value
    /// `{redacted_at, by, reason}`. The ordered-log historical entry id
    /// (the original [`MessageState`]) is preserved unchanged; the
    /// projection layer at read time consults the redaction cell and
    /// replaces the payload with a tombstone.
    ///
    /// Un-redaction: an `apply_redaction` call whose payload sets
    /// `redaction_value: null` (or the equivalent `unredact: true` flag)
    /// resets the cas-register and removes the tombstone.
    ///
    /// Round 14b: when the payload also carries `object_ref` /
    /// `target_object_ref` naming a `cx:flow:` or `cx:morph:` typed-id,
    /// the redaction additionally flips the corresponding projection's
    /// state to `ObjectLifecycleState::Redacted` per spec common-fields.md
    /// §5.1. Place is intentionally excluded — spec note "Place 没有
    /// redacted" routes Place removal through `cx.place.tombstone` only.
    fn apply_redaction(&mut self, operation: &Operation) -> ProjectionEffect {
        let target = operation
            .payload
            .get("target_event_id")
            .or_else(|| operation.payload.get("target"))
            .or_else(|| operation.payload.get("redacts"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        if target.is_empty() {
            return ProjectionEffect::Ignored;
        }

        // Cas-register set-null path: clears the parallel cell and removes
        // the tombstone. The original MessageState stays intact. Object-ref
        // redactions don't have an un-redact path (terminal state by spec).
        let unredact = operation
            .payload
            .get("redaction_value")
            .map(|v| v.is_null())
            .or_else(|| operation.payload.get("unredact").and_then(|v| v.as_bool()))
            .unwrap_or(false);
        if unredact {
            self.redaction_cells.insert(target.clone(), None);
            self.redactions.remove(&target);
            if let Some(msg) = self.messages.get_mut(&target) {
                msg.redacted_at = None;
            }
            return ProjectionEffect::MessageRedacted { event_id: target };
        }

        // Standard redact path: write the parallel cell + flag the
        // historical entry without removing it.
        let by = operation
            .payload
            .get("by")
            .or_else(|| operation.payload.get("redacted_by"))
            .or_else(|| operation.payload.get("sender"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let reason = operation
            .payload
            .get("reason")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned);
        let cell = RedactionCellValue {
            redacted_at: operation.created_at,
            by,
            reason: reason.clone(),
        };
        self.redaction_cells
            .insert(target.clone(), Some(cell.clone()));
        self.redactions.insert(target.clone());
        if let Some(msg) = self.messages.get_mut(&target) {
            msg.redacted_at = Some(operation.created_at);
        }

        // Round 14b — Flow / Morph object-level redaction. If payload
        // carries an `object_ref` (or fallback `target_object_ref`)
        // naming a typed-id, push the projection to the Redacted terminal
        // state. State-machine guard against terminal source is policed
        // by `check_redaction_target_transition` preflight — by the time
        // the reducer runs here, the source state is known-permissible.
        let updated_by = operation
            .payload
            .get("by")
            .or_else(|| operation.payload.get("redacted_by"))
            .or_else(|| operation.payload.get("sender"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        if let Some(object_ref) = redaction_object_ref(operation) {
            if let Some(flow) = self.flows.get_mut(&object_ref) {
                flow.state = ObjectLifecycleState::Redacted;
                flow.state_changed_at = Some(operation.created_at);
                flow.updated_by.clone_from(&updated_by);
                flow.updated_at = Some(operation.created_at);
                return ProjectionEffect::FlowLifecycle {
                    flow_id: object_ref,
                    new_state: ObjectLifecycleState::Redacted,
                };
            }
            if let Some(morph) = self.morphs.get_mut(&object_ref) {
                morph.state = ObjectLifecycleState::Redacted;
                morph.state_changed_at = Some(operation.created_at);
                morph.updated_by.clone_from(&updated_by);
                morph.updated_at = Some(operation.created_at);
                return ProjectionEffect::MorphLifecycle {
                    morph_id: object_ref,
                    new_state: ObjectLifecycleState::Redacted,
                };
            }
        }

        ProjectionEffect::MessageRedacted { event_id: target }
    }

    fn apply_reaction_add(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let event_id = operation
            .payload
            .get("event_id")
            .or_else(|| operation.payload.get("target_event_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let actor = operation
            .payload
            .get("actor")
            .or_else(|| operation.payload.get("sender"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let key = operation
            .payload
            .get("key")
            .or_else(|| operation.payload.get("reaction"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();

        if event_id.is_empty() || actor.is_empty() || key.is_empty() {
            return ProjectionEffect::Ignored;
        }

        let reaction = ReactionState {
            actor: actor.clone(),
            key: key.clone(),
            active: true,
            created_at: now,
        };
        self.reactions
            .entry(event_id.clone())
            .or_default()
            .entry(actor.clone())
            .or_default()
            .insert(key.clone(), reaction);

        ProjectionEffect::ReactionChanged {
            event_id,
            actor,
            key,
            active: true,
        }
    }

    fn apply_reaction_remove(&mut self, operation: &Operation) -> ProjectionEffect {
        let event_id = operation
            .payload
            .get("event_id")
            .or_else(|| operation.payload.get("target_event_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let actor = operation
            .payload
            .get("actor")
            .or_else(|| operation.payload.get("sender"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let key = operation
            .payload
            .get("key")
            .or_else(|| operation.payload.get("reaction"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();

        if event_id.is_empty() || actor.is_empty() || key.is_empty() {
            return ProjectionEffect::Ignored;
        }

        if let Some(event_reactions) = self.reactions.get_mut(&event_id)
            && let Some(actor_reactions) = event_reactions.get_mut(&actor)
        {
            actor_reactions.remove(&key);
        }

        ProjectionEffect::ReactionChanged {
            event_id,
            actor,
            key,
            active: false,
        }
    }

    fn apply_read_marker(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let actor = operation
            .payload
            .get("actor")
            .or_else(|| operation.payload.get("sender"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let space_id = operation.space_id.to_string();
        let scope_id = operation
            .payload
            .get("scope_id")
            .or_else(|| operation.payload.get("thread_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("_default")
            .to_owned();
        let event_id = operation
            .payload
            .get("event_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();

        if actor.is_empty() {
            return ProjectionEffect::Ignored;
        }

        let marker = ReadMarkerState {
            actor: actor.clone(),
            space_id: space_id.clone(),
            scope_id: scope_id.clone(),
            event_id,
            read_at: now,
        };
        let key = (space_id, actor, scope_id);
        // LWW: only update if newer
        let dominated = self
            .read_markers
            .get(&key)
            .is_some_and(|existing| existing.read_at >= marker.read_at);
        if !dominated {
            self.read_markers.insert(key, marker.clone());
        }
        ProjectionEffect::ReadMarkerUpdated(marker)
    }

    fn apply_relation_create(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let relation_id = operation
            .payload
            .get("relation_id")
            .or_else(|| operation.payload.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or(operation.operation_id.as_str())
            .to_owned();
        let relation_kind = operation
            .payload
            .get("relation_kind")
            .or_else(|| operation.payload.get("kind"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_owned();
        let from_ref = operation
            .payload
            .get("from")
            .or_else(|| operation.payload.get("from_ref"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let to_ref = operation
            .payload
            .get("to")
            .or_else(|| operation.payload.get("to_ref"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let fields = operation
            .payload
            .get("fields")
            .and_then(|v| v.as_object())
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();

        let state = RelationState {
            relation_id: relation_id.clone(),
            space_id: operation.space_id.to_string(),
            relation_kind,
            from_ref,
            to_ref,
            fields,
            deleted: false,
            created_at: now,
            updated_at: now,
        };
        let effect = ProjectionEffect::RelationCreated(state.clone());
        self.relations.insert(relation_id, state);
        effect
    }

    fn apply_relation_update(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        _hlc: &ServerHlc,
    ) -> ProjectionEffect {
        let relation_id = operation
            .payload
            .get("relation_id")
            .or_else(|| operation.payload.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        if relation_id.is_empty() {
            return ProjectionEffect::Ignored;
        }
        // Patch-merge on the existing relation. If the relation does not yet
        // exist locally (out-of-order replication), drop the update — a
        // subsequent gap-fill will replay create + update in order.
        let Some(relation) = self.relations.get_mut(&relation_id) else {
            return ProjectionEffect::Ignored;
        };
        if let Some(kind) = operation
            .payload
            .get("relation_kind")
            .or_else(|| operation.payload.get("kind"))
            .and_then(|v| v.as_str())
        {
            relation.relation_kind = kind.to_owned();
        }
        if let Some(value) = operation
            .payload
            .get("from")
            .or_else(|| operation.payload.get("from_ref"))
        {
            relation.from_ref = value.as_str().map(ToOwned::to_owned);
        }
        if let Some(value) = operation
            .payload
            .get("to")
            .or_else(|| operation.payload.get("to_ref"))
        {
            relation.to_ref = value.as_str().map(ToOwned::to_owned);
        }
        if let Some(fields) = operation.payload.get("fields").and_then(|v| v.as_object()) {
            for (k, v) in fields.iter() {
                if v.is_null() {
                    relation.fields.remove(k);
                } else {
                    relation.fields.insert(k.clone(), v.clone());
                }
            }
        }
        relation.updated_at = now;
        ProjectionEffect::RelationUpdated(relation.clone())
    }

    fn apply_relation_delete(&mut self, operation: &Operation) -> ProjectionEffect {
        let relation_id = operation
            .payload
            .get("relation_id")
            .or_else(|| operation.payload.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();

        if let Some(relation) = self.relations.get_mut(&relation_id) {
            relation.deleted = true;
            relation.updated_at = operation.created_at;
        }
        ProjectionEffect::RelationDeleted { relation_id }
    }

    fn apply_container_position(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let relation_id = operation
            .payload
            .get("relation_id")
            .or_else(|| {
                operation
                    .payload
                    .get("expected_position")
                    .and_then(|value| value.get("relation_id"))
            })
            .and_then(|v| v.as_str())
            .unwrap_or(operation.operation_id.as_str())
            .to_owned();
        let relation_kind = operation
            .payload
            .get("relation_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("contains")
            .to_owned();
        let object_ref = operation
            .payload
            .get("object_ref")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let container_id = operation
            .payload
            .get("to_container_id")
            .or_else(|| operation.payload.get("container_id"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let mut fields = BTreeMap::new();
        if let Some(rank) = operation.payload.get("rank") {
            fields.insert("rank".to_owned(), rank.clone());
        }

        let state = self
            .relations
            .entry(relation_id.clone())
            .or_insert_with(|| RelationState {
                relation_id: relation_id.clone(),
                space_id: operation.space_id.to_string(),
                relation_kind: relation_kind.clone(),
                from_ref: container_id.clone(),
                to_ref: object_ref.clone(),
                fields: BTreeMap::new(),
                deleted: false,
                created_at: now,
                updated_at: now,
            });
        state.relation_kind = relation_kind;
        state.from_ref = container_id;
        state.to_ref = object_ref;
        state.fields.extend(fields);
        state.deleted = false;
        state.updated_at = now;
        ProjectionEffect::RelationCreated(state.clone())
    }

    fn apply_membership(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(new_state) = operation.payload.get("membership").and_then(Value::as_str) else {
            return ProjectionEffect::Ignored;
        };
        if !matches!(new_state, "invite" | "join" | "leave" | "ban" | "knock") {
            return ProjectionEffect::Ignored;
        }
        let member = operation
            .payload
            .get("actor_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let space_id = operation.space_id.to_string();

        if member.is_empty() {
            return ProjectionEffect::Ignored;
        }

        // Side-band data: `role` lives outside the FSM cell and is captured
        // here for the structured cache. `joined_at` is set on the first
        // `join` transition; subsequent transitions preserve the original.
        let role = operation
            .payload
            .get("role")
            .and_then(|v| v.as_str())
            .unwrap_or("member")
            .to_owned();
        let key = (space_id.clone(), member.clone());
        let joined_at = self.members.get(&key).map(|m| m.joined_at).unwrap_or(now);

        // Update the structured cache with side-band + FSM state mirror.
        self.members.insert(
            key.clone(),
            MembershipState {
                member: member.clone(),
                space_id: space_id.clone(),
                state: new_state.to_owned(),
                role,
                joined_at,
                updated_at: now,
            },
        );

        // Synthesize the FSM cell state. Cell ref shape per spec
        // `cx:cell:cx.component.member.state.v1:<actor_did>` — note the
        // cell_subject is `actor_id` (per-actor), not (space_id, actor)
        // composite. The Space scoping is implicit in the CellStore key.
        if let Ok(cell_id) =
            contrix_sdk::CellRef::new(format!("cx:cell:cx.component.member.state.v1:{member}"))
        {
            self.cells.insert(
                cell_id,
                CellState::Value(Value::String(new_state.to_owned())),
            );
        }

        ProjectionEffect::MembershipChanged {
            space_id,
            member,
            action: new_state.to_owned(),
        }
    }

    fn apply_space_lifecycle(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        kind: &'static str,
    ) -> ProjectionEffect {
        // Keep the structured cache and the canonical cells map in sync.
        //
        // Per spec event-kind-registry, each cx.space.* lifecycle event
        // writes a distinct cell family with its own lattice:
        //   cx.space.create  → cx.component.space.create.v1  (ordered-log, singleton)
        //   cx.space.update  → cx.component.space.organization.v1 (cas-register, singleton)
        //   cx.space.destroy → cx.component.space.destroy.v1 (cas-register, singleton)
        //
        // The structured `space_states` field is the side-band cache —
        // keeps `created_at` / `updated_at` server-side timestamps and a
        // simple `deleted` bool that directory/sync consumers
        // already query. Cells map is the protocol-canonical source.
        let action = operation
            .payload
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let space_id = operation.space_id.to_string();
        let owner = operation
            .payload
            .get("owner")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let title = operation
            .payload
            .get("title")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);

        // Structured cache mirror.
        let space = self
            .space_states
            .entry(space_id.clone())
            .or_insert_with(|| SpaceState {
                space_id: space_id.clone(),
                owner: owner.clone(),
                title: title.clone(),
                deleted: false,
                created_at: now,
                updated_at: now,
            });
        let is_destroy = matches!(
            action.as_str(),
            "delete" | "space.delete" | "destroy" | "space.destroy"
        ) || kind == crate::kinds::CX_SPACE_DESTROY;
        if is_destroy {
            space.deleted = true;
        }
        if owner.is_some() {
            space.owner.clone_from(&owner);
        }
        if title.is_some() {
            space.title.clone_from(&title);
        }
        space.updated_at = now;

        // Cells map: synth a CellState::Value per the spec cell family
        // for this canonical kind.
        match kind {
            k if k == crate::kinds::CX_SPACE_CREATE => {
                // ordered-log: append entries. We model the log here as
                // an array of envelopes; each create event appends. For
                // most Spaces there's exactly one create entry, but the
                // spec lattice allows multiple (e.g. spec changes,
                // re-genesis under recovery).
                if let Ok(cell_id) = contrix_sdk::CellRef::new(format!(
                    "cx:cell:cx.component.space.create.v1:{space_id}"
                )) {
                    let entry = serde_json::json!({
                        "owner": owner,
                        "title": title,
                        "created_at": now.to_rfc3339(),
                        "operation_id": operation.operation_id.as_str(),
                    });
                    let new_log = match self.cells.get(&cell_id) {
                        Some(CellState::Value(Value::Array(existing))) => {
                            let mut log = existing.clone();
                            log.push(entry);
                            CellState::Value(Value::Array(log))
                        }
                        _ => CellState::Value(Value::Array(vec![entry])),
                    };
                    self.cells.insert(cell_id, new_log);
                }
            }
            k if k == crate::kinds::CX_SPACE_UPDATE => {
                // cas-register: latest value wins. Composite of
                // owner / title / arbitrary other organization fields
                // pulled from payload (fields the spec evolves can land
                // here without changing soland code).
                if let Ok(cell_id) = contrix_sdk::CellRef::new(format!(
                    "cx:cell:cx.component.space.organization.v1:{space_id}"
                )) {
                    let mut value = serde_json::Map::new();
                    if let Some(o) = owner.as_ref() {
                        value.insert("owner".to_owned(), Value::String(o.clone()));
                    }
                    if let Some(t) = title.as_ref() {
                        value.insert("title".to_owned(), Value::String(t.clone()));
                    }
                    value.insert("updated_at".to_owned(), Value::String(now.to_rfc3339()));
                    self.cells
                        .insert(cell_id, CellState::Value(Value::Object(value)));
                }
            }
            k if k == crate::kinds::CX_SPACE_DESTROY => {
                // cas-register: terminal {destroyed: true, at: ts}.
                if let Ok(cell_id) = contrix_sdk::CellRef::new(format!(
                    "cx:cell:cx.component.space.destroy.v1:{space_id}"
                )) {
                    let value = serde_json::json!({
                        "destroyed": true,
                        "at": now.to_rfc3339(),
                        "operation_id": operation.operation_id.as_str(),
                    });
                    self.cells.insert(cell_id, CellState::Value(value));
                }
            }
            _ => {}
        }

        ProjectionEffect::SpaceLifecycle { space_id, action }
    }

    /// Read-only state-machine preflight for a `cx.place.*` lifecycle
    /// operation. Returns `Err(reason_code)` if the projection's current
    /// Place state forbids the transition per `common-fields.md §5.1`,
    /// else `Ok(())`. Used by `event_log::submit_event` to short-circuit
    /// HTTP admission with a 412 failed_precondition instead of letting
    /// the reducer accept-then-reject after persistence. Unknown Place
    /// (no prior cx.place.create projected) returns Ok — causal /
    /// backfill ordering is allowed; the reducer also tolerates it.
    pub fn check_place_lifecycle_transition(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        use crate::kinds::*;
        let kind = match crate::kinds::canonical_kind_for_operation(operation) {
            Some(k) => k,
            None => return Ok(()),
        };

        // `cx.place.create` is unconditional (only constraint is that no
        // existing place with the same id — but LWW overwrite is fine
        // per the reducer's existing `insert`).
        // `cx.place.update` / `cx.place.parent` require Active source.
        // `cx.place.archive` requires Active.
        // `cx.place.restore` requires Archived.
        // `cx.place.tombstone` requires {Active, Archived}.
        let (allowed_source, reason): (&[PlaceLifecycleState], &'static str) = match kind {
            CX_PLACE_CREATE => return Ok(()),
            CX_PLACE_UPDATE | CX_PLACE_PARENT => {
                (&[PlaceLifecycleState::Active], "place_not_active")
            }
            CX_PLACE_ARCHIVE => (&[PlaceLifecycleState::Active], "place_not_active"),
            CX_PLACE_RESTORE => (&[PlaceLifecycleState::Archived], "place_not_archived"),
            CX_PLACE_TOMBSTONE => (
                &[
                    PlaceLifecycleState::Active,
                    PlaceLifecycleState::Archived,
                ],
                "place_already_terminal",
            ),
            _ => return Ok(()),
        };

        let Some(place_id) = operation.payload.get("place_id").and_then(|v| v.as_str()) else {
            // Missing place_id is a schema-validation problem caught
            // upstream; preflight is not the right place to surface it.
            return Ok(());
        };
        let Some(place) = self.places.get(place_id) else {
            // Unknown — causal / backfill window. Don't block.
            return Ok(());
        };
        if !allowed_source.contains(&place.state) {
            return Err(reason);
        }
        Ok(())
    }

    /// Apply `cx.place.create` — populate the `places` projection from
    /// the wire `object` field. Idempotent: re-create with the same id
    /// overwrites the existing entry per LWW. Spec:
    /// `space-and-place.md §4.2`.
    fn apply_place_create(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(object) = operation.payload.get("object").and_then(|v| v.as_object()) else {
            return ProjectionEffect::Rejected {
                reason: "place_create_missing_object".to_owned(),
            };
        };
        let Some(place_id) = object.get("id").and_then(|v| v.as_str()).map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "place_create_missing_id".to_owned(),
            };
        };
        let kind = object
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let title = object
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let parent_ref = object
            .get("parent_ref")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let rank = object
            .get("rank")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let space_id = object
            .get("space_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| operation.space_id.to_string());
        let created_by = object
            .get("created_by")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .or_else(|| {
                operation
                    .payload
                    .get("sender")
                    .and_then(|v| v.as_str())
                    .map(ToOwned::to_owned)
            })
            .unwrap_or_default();

        let projection = PlaceProjection {
            place_id: place_id.clone(),
            space_id,
            kind,
            title,
            parent_ref,
            rank,
            state: PlaceLifecycleState::Active,
            state_changed_at: None,
            created_by,
            created_at: now,
            updated_by: None,
            updated_at: None,
        };
        self.places.insert(place_id.clone(), projection);

        ProjectionEffect::PlaceLifecycle {
            place_id,
            new_state: PlaceLifecycleState::Active,
        }
    }

    /// Apply `cx.place.update` — patch title / rank / fields on an
    /// existing Place. Per common-fields.md §5.1 ("update on non-active
    /// object MUST fail"): rejects with `place_not_active` if the target
    /// is not in Active state. Unknown Place is tolerated.
    fn apply_place_update(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(place_id) = operation
            .payload
            .get("place_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "place_update_missing_place_id".to_owned(),
            };
        };
        let Some(place) = self.places.get_mut(&place_id) else {
            return ProjectionEffect::Ignored;
        };
        if place.state != PlaceLifecycleState::Active {
            return ProjectionEffect::Rejected {
                reason: "place_not_active".to_owned(),
            };
        }
        let patch = operation.payload.get("patch").and_then(|v| v.as_object());
        if let Some(patch) = patch {
            if let Some(title) = patch.get("title").and_then(|v| v.as_str()) {
                place.title = title.to_owned();
            }
            if let Some(rank) = patch.get("rank").and_then(|v| v.as_str()) {
                place.rank = Some(rank.to_owned());
            }
        }
        place.updated_by = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        place.updated_at = Some(now);
        ProjectionEffect::PlaceLifecycle {
            place_id,
            new_state: place.state,
        }
    }

    /// Apply `cx.place.parent` — update parent_ref. State-machine guard
    /// (`parent on non-active MUST fail`) follows the same rule as
    /// `apply_place_update`.
    fn apply_place_parent(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(place_id) = operation
            .payload
            .get("place_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "place_parent_missing_place_id".to_owned(),
            };
        };
        let parent_ref = operation
            .payload
            .get("parent_ref")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let Some(place) = self.places.get_mut(&place_id) else {
            return ProjectionEffect::Ignored;
        };
        if place.state != PlaceLifecycleState::Active {
            return ProjectionEffect::Rejected {
                reason: "place_not_active".to_owned(),
            };
        }
        place.parent_ref = parent_ref;
        place.updated_by = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        place.updated_at = Some(now);
        ProjectionEffect::PlaceLifecycle {
            place_id,
            new_state: place.state,
        }
    }

    /// Apply a `cx.place.archive` / `cx.place.restore` / `cx.place.tombstone`
    /// event with the canonical state-machine guard from
    /// `common-fields.md §5.1`. Unknown Place (no prior cx.place.create in
    /// the projection) is tolerated — returns `Ignored` so causal /
    /// backfill ordering doesn't get flagged as invalid. Invalid source
    /// state returns `Rejected { reason }` with the spec reason_code;
    /// `event_log::submit_event` maps that to HTTP 412.
    fn apply_place_lifecycle(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        transition: PlaceLifecycleTransition,
    ) -> ProjectionEffect {
        let Some(place_id) = operation
            .payload
            .get("place_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "missing_place_id".to_owned(),
            };
        };

        let Some(place) = self.places.get_mut(&place_id) else {
            // Unknown Place — likely the cx.place.create has not yet
            // been projected (causal / backfill window). Tolerate
            // silently per the spec convention (common-fields.md §5.1
            // "未知对象容忍").
            return ProjectionEffect::Ignored;
        };

        let (allowed_source, target_state, reason_on_invalid) = match transition {
            PlaceLifecycleTransition::Archive => (
                &[PlaceLifecycleState::Active][..],
                PlaceLifecycleState::Archived,
                "place_not_active",
            ),
            PlaceLifecycleTransition::Restore => (
                &[PlaceLifecycleState::Archived][..],
                PlaceLifecycleState::Active,
                "place_not_archived",
            ),
            PlaceLifecycleTransition::Tombstone => (
                &[
                    PlaceLifecycleState::Active,
                    PlaceLifecycleState::Archived,
                ][..],
                PlaceLifecycleState::Tombstoned,
                "place_already_terminal",
            ),
        };

        if !allowed_source.contains(&place.state) {
            return ProjectionEffect::Rejected {
                reason: reason_on_invalid.to_owned(),
            };
        }

        place.state = target_state;
        place.state_changed_at = Some(now);
        place.updated_by = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        place.updated_at = Some(now);

        ProjectionEffect::PlaceLifecycle {
            place_id,
            new_state: target_state,
        }
    }

    // ── Round 13: Flow / Morph projection state machine ──

    /// Read-only state-machine preflight for a `cx.flow.*` lifecycle event.
    /// Mirror of `check_place_lifecycle_transition` — used by
    /// `event_log::submit_event` to short-circuit HTTP admission with 412
    /// failed_precondition. Unknown Flow returns `Ok` (causal/backfill
    /// tolerance per common-fields.md §5.1).
    pub fn check_flow_lifecycle_transition(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        use crate::kinds::*;
        let kind = match crate::kinds::canonical_kind_for_operation(operation) {
            Some(k) => k,
            None => return Ok(()),
        };
        // `cx.flow.create` is unconditional (no current state to validate).
        // `cx.flow.update` requires Active source.
        // `cx.flow.archive` requires Active source.
        // `cx.flow.restore` requires Archived source.
        let (allowed_source, reason): (&[ObjectLifecycleState], &'static str) = match kind {
            CX_FLOW_CREATE => return Ok(()),
            CX_FLOW_UPDATE => (&[ObjectLifecycleState::Active], "flow_not_active"),
            CX_FLOW_ARCHIVE => (&[ObjectLifecycleState::Active], "flow_not_active"),
            CX_FLOW_RESTORE => (&[ObjectLifecycleState::Archived], "flow_not_archived"),
            _ => return Ok(()),
        };
        let Some(flow_id) = operation.payload.get("flow_id").and_then(|v| v.as_str()) else {
            // Missing flow_id is caught upstream by the operation-schema
            // validator; preflight tolerates absence to keep responsibilities
            // separate.
            return Ok(());
        };
        let Some(flow) = self.flows.get(flow_id) else {
            return Ok(());
        };
        if !allowed_source.contains(&flow.state) {
            return Err(reason);
        }
        Ok(())
    }

    /// Round 14b — Read-only preflight for `cx.redaction` events that
    /// target a Flow / Morph via `object_ref`. Per spec common-fields.md
    /// §5.1, redaction is legal only from `active` or `archived` source;
    /// terminal source MUST `failed_precondition` with
    /// `<kind>_already_terminal`. Unknown object tolerated (causal /
    /// backfill window). Place is excluded — spec routes Place removal
    /// through `cx.place.tombstone` only.
    pub fn check_redaction_target_transition(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        if crate::kinds::canonical_kind_for_operation(operation) != Some(crate::kinds::CX_REDACTION)
        {
            return Ok(());
        }
        let Some(object_ref) = redaction_object_ref(operation) else {
            return Ok(());
        };
        if let Some(flow) = self.flows.get(&object_ref) {
            if flow.state.is_terminal() {
                return Err("flow_already_terminal");
            }
            return Ok(());
        }
        if let Some(morph) = self.morphs.get(&object_ref) {
            if morph.state.is_terminal() {
                return Err("morph_already_terminal");
            }
            return Ok(());
        }
        Ok(())
    }

    /// Read-only state-machine preflight for a `cx.morph.*` lifecycle event.
    /// Same shape as `check_flow_lifecycle_transition`.
    pub fn check_morph_lifecycle_transition(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        use crate::kinds::*;
        let kind = match crate::kinds::canonical_kind_for_operation(operation) {
            Some(k) => k,
            None => return Ok(()),
        };
        let (allowed_source, reason): (&[ObjectLifecycleState], &'static str) = match kind {
            CX_MORPH_CREATE => return Ok(()),
            CX_MORPH_UPDATE => (&[ObjectLifecycleState::Active], "morph_not_active"),
            CX_MORPH_ARCHIVE => (&[ObjectLifecycleState::Active], "morph_not_active"),
            CX_MORPH_RESTORE => (&[ObjectLifecycleState::Archived], "morph_not_archived"),
            _ => return Ok(()),
        };
        let Some(morph_id) = operation.payload.get("morph_id").and_then(|v| v.as_str()) else {
            return Ok(());
        };
        let Some(morph) = self.morphs.get(morph_id) else {
            return Ok(());
        };
        if !allowed_source.contains(&morph.state) {
            return Err(reason);
        }
        Ok(())
    }

    /// Apply `cx.flow.create` — populate the `flows` projection from
    /// the wire `object` field. Spec: common-fields.md §5 + flow schema.
    /// Idempotent: re-create with same id overwrites the existing entry
    /// (LWW), but the preflight will accept it since `cx.flow.create` has
    /// no source-state guard.
    fn apply_flow_create(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(object) = operation.payload.get("object").and_then(|v| v.as_object()) else {
            return ProjectionEffect::Rejected {
                reason: "flow_create_missing_object".to_owned(),
            };
        };
        let Some(flow_id) = object.get("id").and_then(|v| v.as_str()).map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "flow_create_missing_id".to_owned(),
            };
        };
        let title = object
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let summary = object
            .get("summary")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let space_id = object
            .get("space_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| operation.space_id.to_string());
        let created_by = object
            .get("created_by")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .or_else(|| {
                operation
                    .payload
                    .get("sender")
                    .and_then(|v| v.as_str())
                    .map(ToOwned::to_owned)
            })
            .unwrap_or_default();

        let projection = FlowProjection {
            flow_id: flow_id.clone(),
            space_id,
            title,
            summary,
            state: ObjectLifecycleState::Active,
            state_changed_at: None,
            created_by,
            created_at: now,
            updated_by: None,
            updated_at: None,
        };
        self.flows.insert(flow_id.clone(), projection);

        ProjectionEffect::FlowLifecycle {
            flow_id,
            new_state: ObjectLifecycleState::Active,
        }
    }

    /// Apply `cx.flow.update` — patch title / summary on an existing Flow.
    /// Spec common-fields.md §5.1: update on non-active object MUST fail
    /// with `flow_not_active`. Unknown Flow tolerated.
    fn apply_flow_update(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(flow_id) = operation
            .payload
            .get("flow_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "flow_update_missing_flow_id".to_owned(),
            };
        };
        let Some(flow) = self.flows.get_mut(&flow_id) else {
            return ProjectionEffect::Ignored;
        };
        if flow.state != ObjectLifecycleState::Active {
            return ProjectionEffect::Rejected {
                reason: "flow_not_active".to_owned(),
            };
        }
        let patch = operation.payload.get("patch").and_then(|v| v.as_object());
        if let Some(patch) = patch {
            if let Some(title) = patch.get("title").and_then(|v| v.as_str()) {
                flow.title = title.to_owned();
            }
            if let Some(summary) = patch.get("summary").and_then(|v| v.as_str()) {
                flow.summary = Some(summary.to_owned());
            }
        }
        flow.updated_by = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        flow.updated_at = Some(now);
        ProjectionEffect::FlowLifecycle {
            flow_id,
            new_state: flow.state,
        }
    }

    /// Apply `cx.flow.archive` / `cx.flow.restore`. Spec
    /// `common-fields.md §5.1`. Unknown Flow tolerated.
    fn apply_flow_lifecycle(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        transition: ObjectLifecycleTransition,
    ) -> ProjectionEffect {
        let Some(flow_id) = operation
            .payload
            .get("flow_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "missing_flow_id".to_owned(),
            };
        };
        let Some(flow) = self.flows.get_mut(&flow_id) else {
            return ProjectionEffect::Ignored;
        };
        let (allowed_source, target_state, reason_on_invalid) = match transition {
            ObjectLifecycleTransition::Archive => (
                &[ObjectLifecycleState::Active][..],
                ObjectLifecycleState::Archived,
                "flow_not_active",
            ),
            ObjectLifecycleTransition::Restore => (
                &[ObjectLifecycleState::Archived][..],
                ObjectLifecycleState::Active,
                "flow_not_archived",
            ),
        };
        if !allowed_source.contains(&flow.state) {
            return ProjectionEffect::Rejected {
                reason: reason_on_invalid.to_owned(),
            };
        }
        flow.state = target_state;
        flow.state_changed_at = Some(now);
        flow.updated_by = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        flow.updated_at = Some(now);
        ProjectionEffect::FlowLifecycle {
            flow_id,
            new_state: target_state,
        }
    }

    /// Round 14d (2026-05-16) — read-only preflight for `cx.flow.track.*`
    /// sub-events. Spec common-fields.md §5.1 update-on-non-active rule:
    /// track mutations are a kind of update; parent Flow MUST be Active
    /// or the admission MUST `failed_precondition` with `flow_not_active`
    /// before persistence. Unknown Flow tolerated (causal / backfill —
    /// matches the lifecycle preflight family). soland's projection
    /// doesn't carry track-level state (FlowProjection has no `tracks`
    /// field by design — SDK is the source of truth client-side); only
    /// the parent Flow's lifecycle state matters here.
    pub fn check_flow_track_transition(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        let kind = match crate::kinds::canonical_kind_for_operation(operation) {
            Some(k) => k,
            None => return Ok(()),
        };
        if !crate::kinds::is_flow_track_kind(kind) {
            return Ok(());
        }
        let Some(flow_id) = operation.payload.get("flow_id").and_then(|v| v.as_str()) else {
            // Missing flow_id is caught by operation-schema validator
            // upstream; preflight tolerates absence (responsibilities split).
            return Ok(());
        };
        let Some(flow) = self.flows.get(flow_id) else {
            return Ok(());
        };
        if flow.state != ObjectLifecycleState::Active {
            return Err("flow_not_active");
        }
        Ok(())
    }

    /// Apply `cx.flow.move` / `cx.flow.reorder` (round 14). These events
    /// don't affect Flow lifecycle state — they write to the
    /// `cx.component.flow.position.v1` cell family on the Move/Anchor
    /// pipeline. The Event-Envelope reducer just bumps `updated_at` /
    /// `updated_by` on the Flow projection so read-after-write sees the
    /// touch. Unknown Flow is tolerated (causal / backfill).
    fn apply_flow_position_touch(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(flow_id) = operation
            .payload
            .get("flow_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "missing_flow_id".to_owned(),
            };
        };
        let Some(flow) = self.flows.get_mut(&flow_id) else {
            return ProjectionEffect::Ignored;
        };
        flow.updated_by = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        flow.updated_at = Some(now);
        ProjectionEffect::FlowLifecycle {
            flow_id,
            new_state: flow.state,
        }
    }

    /// Round 14d (2026-05-16) — Apply `cx.flow.track.*` sub-events
    /// server-side. State guard runs in `check_flow_track_transition`
    /// preflight; by the time this reducer fires, the parent Flow is
    /// known to be Active (or unknown, in which case the touch is a
    /// no-op). The actual track membership lives in SDK reducer's
    /// Flow.tracks; soland's projection just bumps `updated_at` so
    /// read-after-write sees the change. Unknown Flow tolerated.
    fn apply_flow_track_touch(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(flow_id) = operation
            .payload
            .get("flow_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "missing_flow_id".to_owned(),
            };
        };
        let Some(flow) = self.flows.get_mut(&flow_id) else {
            return ProjectionEffect::Ignored;
        };
        // Defence-in-depth: even though check_flow_track_transition
        // gated this at the admission layer, re-check here so direct
        // reducer callers (tests / replay paths that bypass HTTP) still
        // see the spec invariant enforced.
        if flow.state != ObjectLifecycleState::Active {
            return ProjectionEffect::Rejected {
                reason: "flow_not_active".to_owned(),
            };
        }
        flow.updated_by = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        flow.updated_at = Some(now);
        ProjectionEffect::FlowLifecycle {
            flow_id,
            new_state: flow.state,
        }
    }

    /// Apply `cx.morph.create`. Mirror of `apply_flow_create`.
    fn apply_morph_create(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(object) = operation.payload.get("object").and_then(|v| v.as_object()) else {
            return ProjectionEffect::Rejected {
                reason: "morph_create_missing_object".to_owned(),
            };
        };
        let Some(morph_id) = object.get("id").and_then(|v| v.as_str()).map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "morph_create_missing_id".to_owned(),
            };
        };
        let morph_type = object
            .get("morph_type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let title = object
            .get("title")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let space_id = object
            .get("space_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| operation.space_id.to_string());
        let created_by = object
            .get("created_by")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .or_else(|| {
                operation
                    .payload
                    .get("sender")
                    .and_then(|v| v.as_str())
                    .map(ToOwned::to_owned)
            })
            .unwrap_or_default();

        let projection = MorphProjection {
            morph_id: morph_id.clone(),
            space_id,
            morph_type,
            title,
            state: ObjectLifecycleState::Active,
            state_changed_at: None,
            created_by,
            created_at: now,
            updated_by: None,
            updated_at: None,
        };
        self.morphs.insert(morph_id.clone(), projection);

        ProjectionEffect::MorphLifecycle {
            morph_id,
            new_state: ObjectLifecycleState::Active,
        }
    }

    /// Apply `cx.morph.update`. Mirror of `apply_flow_update`.
    fn apply_morph_update(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(morph_id) = operation
            .payload
            .get("morph_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "morph_update_missing_morph_id".to_owned(),
            };
        };
        let Some(morph) = self.morphs.get_mut(&morph_id) else {
            return ProjectionEffect::Ignored;
        };
        if morph.state != ObjectLifecycleState::Active {
            return ProjectionEffect::Rejected {
                reason: "morph_not_active".to_owned(),
            };
        }
        let patch = operation.payload.get("patch").and_then(|v| v.as_object());
        if let Some(patch) = patch {
            if let Some(title) = patch.get("title").and_then(|v| v.as_str()) {
                morph.title = Some(title.to_owned());
            }
            if let Some(morph_type) = patch.get("morph_type").and_then(|v| v.as_str()) {
                morph.morph_type = morph_type.to_owned();
            }
        }
        morph.updated_by = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        morph.updated_at = Some(now);
        ProjectionEffect::MorphLifecycle {
            morph_id,
            new_state: morph.state,
        }
    }

    /// Apply `cx.morph.archive` / `cx.morph.restore`. Mirror of
    /// `apply_flow_lifecycle`.
    fn apply_morph_lifecycle(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        transition: ObjectLifecycleTransition,
    ) -> ProjectionEffect {
        let Some(morph_id) = operation
            .payload
            .get("morph_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "missing_morph_id".to_owned(),
            };
        };
        let Some(morph) = self.morphs.get_mut(&morph_id) else {
            return ProjectionEffect::Ignored;
        };
        let (allowed_source, target_state, reason_on_invalid) = match transition {
            ObjectLifecycleTransition::Archive => (
                &[ObjectLifecycleState::Active][..],
                ObjectLifecycleState::Archived,
                "morph_not_active",
            ),
            ObjectLifecycleTransition::Restore => (
                &[ObjectLifecycleState::Archived][..],
                ObjectLifecycleState::Active,
                "morph_not_archived",
            ),
        };
        if !allowed_source.contains(&morph.state) {
            return ProjectionEffect::Rejected {
                reason: reason_on_invalid.to_owned(),
            };
        }
        morph.state = target_state;
        morph.state_changed_at = Some(now);
        morph.updated_by = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        morph.updated_at = Some(now);
        ProjectionEffect::MorphLifecycle {
            morph_id,
            new_state: target_state,
        }
    }

    /// Round 15b — Apply `cx.applet.registration`. Upserts the
    /// AppletProjection keyed by `service_did`. Re-registration with
    /// the same DID is allowed (replace capabilities + bump
    /// updated_at), matching the spec convention that registration is
    /// idempotent for the same identity.
    fn apply_applet_registration(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(service_did) = operation
            .payload
            .get("service_did")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "applet_registration_missing_service_did".to_owned(),
            };
        };
        let namespace = operation
            .payload
            .get("namespace")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let capabilities = operation.payload.get("capabilities").cloned();
        let existing_manifest = self
            .applets
            .get(&service_did)
            .and_then(|p| p.manifest.clone());
        let registered_at = self
            .applets
            .get(&service_did)
            .map(|p| p.registered_at)
            .unwrap_or(now);
        let projection = AppletProjection {
            service_did: service_did.clone(),
            namespace,
            manifest: existing_manifest,
            capabilities,
            registered_at,
            updated_at: now,
        };
        self.applets.insert(service_did.clone(), projection);
        ProjectionEffect::AppletProjectionUpdated { service_did }
    }

    /// Round 15b — Apply `cx.applet.discovery`. Updates the manifest
    /// on an existing AppletProjection. If the applet hasn't registered
    /// yet (causal / backfill window), creates a stub entry with the
    /// manifest and empty namespace; subsequent registration will fill
    /// in the namespace + capabilities.
    fn apply_applet_discovery(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(service_did) = operation
            .payload
            .get("service_did")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "applet_discovery_missing_service_did".to_owned(),
            };
        };
        let manifest = operation.payload.get("manifest").cloned();
        let entry = self
            .applets
            .entry(service_did.clone())
            .or_insert_with(|| AppletProjection {
                service_did: service_did.clone(),
                namespace: String::new(),
                manifest: None,
                capabilities: None,
                registered_at: now,
                updated_at: now,
            });
        entry.manifest = manifest;
        entry.updated_at = now;
        ProjectionEffect::AppletProjectionUpdated { service_did }
    }

    /// Round 15b — Apply `cx.agent.endpoint`. Upserts the
    /// AgentProjection keyed by `agent_did`.
    ///
    /// Sprint Q1 第二十增量 (B4d): if the payload carries an
    /// `endpoint_url` field it is captured into the projection so the
    /// bridge can echo it back on `protocol_session.result`.
    fn apply_agent_endpoint(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(agent_did) = operation
            .payload
            .get("agent_did")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "agent_endpoint_missing_agent_did".to_owned(),
            };
        };
        let protocol = operation
            .payload
            .get("protocol")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let endpoint_url = operation
            .payload
            .get("endpoint_url")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let registered_at = self
            .agents
            .get(&agent_did)
            .map(|p| p.registered_at)
            .unwrap_or(now);
        let projection = AgentProjection {
            agent_did: agent_did.clone(),
            protocol,
            endpoint_url,
            registered_at,
            updated_at: now,
        };
        self.agents.insert(agent_did.clone(), projection);
        ProjectionEffect::AgentProjectionUpdated { agent_did }
    }

    // ── Query helpers ──

    /// Get all non-redacted messages for a space, sorted by creation time.
    pub fn messages_for_space(&self, space_id: &str) -> Vec<&MessageState> {
        let mut msgs: Vec<_> = self
            .messages
            .values()
            .filter(|m| {
                m.space_id == space_id
                    && self
                        .redaction_cells
                        .get(&m.event_id)
                        .and_then(|cell| cell.as_ref())
                        .is_none()
            })
            .collect();
        msgs.sort_by_key(|a| a.created_at);
        msgs
    }

    /// Get messages for a thread, sorted by creation time.
    pub fn messages_for_thread(&self, thread_id: &str) -> Vec<&MessageState> {
        let mut msgs: Vec<_> = self
            .messages
            .values()
            .filter(|m| {
                m.thread_id == thread_id
                    && self
                        .redaction_cells
                        .get(&m.event_id)
                        .and_then(|cell| cell.as_ref())
                        .is_none()
            })
            .collect();
        msgs.sort_by_key(|a| a.created_at);
        msgs
    }

    /// Projection-layer view of a single message that
    /// consults the parallel `redaction` cell. Returns:
    ///   - `Some(view)` with `content = Some(_)` for live messages (no redaction cell set, or set
    ///     back to null);
    ///   - `Some(view)` with `content = None` + `redaction = Some(_)` when the parallel cell is in
    ///     effect — caller renders the tombstone;
    ///   - `None` if no underlying [`MessageState`] is known.
    ///
    /// The ordered-log historical entry id is preserved unchanged so
    /// federation / sync replay still emits the same `event_id`.
    pub fn projected_message(
        &self,
        event_id: &str,
        viewer_is_author: bool,
    ) -> Option<ProjectedMessageView> {
        let msg = self.messages.get(event_id)?;
        let redaction = self
            .redaction_cells
            .get(event_id)
            .and_then(|cell| cell.as_ref())
            .cloned();
        let content = match (&redaction, viewer_is_author) {
            // No redaction in effect — full payload visible.
            (None, _) => Some(msg.content.clone()),
            // Author keeps the audit-view of the original payload.
            (Some(_), true) => Some(msg.content.clone()),
            // Other members see the tombstone.
            (Some(_), false) => None,
        };
        Some(ProjectedMessageView {
            event_id: msg.event_id.clone(),
            space_id: msg.space_id.clone(),
            sender: msg.sender.clone(),
            thread_id: msg.thread_id.clone(),
            created_at: msg.created_at,
            content,
            redaction,
        })
    }

    /// Get active reactions for an event.
    pub fn reactions_for_event(&self, event_id: &str) -> Vec<&ReactionState> {
        self.reactions
            .get(event_id)
            .map(|by_actor| {
                by_actor
                    .values()
                    .filter_map(|by_key| by_key.values().find(|r| r.active))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get relations for a space, optionally filtered by kind.
    pub fn relations_for_space(&self, space_id: &str, kind: Option<&str>) -> Vec<&RelationState> {
        self.relations
            .values()
            .filter(|r| {
                r.space_id == space_id && !r.deleted && kind.is_none_or(|k| r.relation_kind == k)
            })
            .collect()
    }

    /// Get members of a space currently in `state="join"`.
    /// For state-specific queries use [`members_in_state`].
    pub fn members_of_space(&self, space_id: &str) -> Vec<&MembershipState> {
        self.members_in_state(space_id, "join")
    }

    /// All `MembershipState` entries for a Space whose FSM state matches
    /// `state` (`invite` / `join` / `leave` / `ban` / `knock`).
    pub fn members_in_state(&self, space_id: &str, state: &str) -> Vec<&MembershipState> {
        self.members
            .iter()
            .filter(|((sid, _), m)| sid == space_id && m.state == state)
            .map(|(_, m)| m)
            .collect()
    }

    /// Look up a single `(space_id, actor_did)` member entry.
    pub fn member(&self, space_id: &str, actor_did: &str) -> Option<&MembershipState> {
        self.members
            .get(&(space_id.to_owned(), actor_did.to_owned()))
    }

    /// Read the FSM state of a member directly from the cells map.
    /// Returns `None` if the cell hasn't been written or is in `Bottom`
    /// state. The cell_subject is the actor_did per spec
    /// `cx.component.member.state.v1` cell_family declaration.
    pub fn member_fsm_state(&self, actor_did: &str) -> Option<String> {
        let cell_id =
            contrix_sdk::CellRef::new(format!("cx:cell:cx.component.member.state.v1:{actor_did}"))
                .ok()?;
        self.cell_value(&cell_id)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    }

    // ── Cell-keyed query helpers ──

    /// Read the effective `cx.space.read_receipt_policy` value out of the
    /// cells map. Returns `None` when:
    ///   - the cell has never been written, OR
    ///   - the cell is in `Bottom` state (concurrent conflict needs recovery)
    pub fn read_receipt_policy_cell_value(&self, space_id: &str) -> Option<&Value> {
        let cell_id = contrix_sdk::CellRef::new(format!(
            "cx:cell:cx.component.space.read_receipt_policy.v1:{space_id}"
        ))
        .ok()?;
        self.cell_value(&cell_id)
    }

    // ── Space lifecycle cell helpers ──

    /// Read the effective `cx.component.space.organization.v1` cas-register
    /// value (mutable Space metadata: owner, title, updated_at). Returns
    /// `None` if no `cx.space.update` event has landed for this space, or
    /// if the cell is in `Bottom` (concurrent admin updates require recovery).
    pub fn space_organization_cell_value(&self, space_id: &str) -> Option<&Value> {
        let cell_id = contrix_sdk::CellRef::new(format!(
            "cx:cell:cx.component.space.organization.v1:{space_id}"
        ))
        .ok()?;
        self.cell_value(&cell_id)
    }

    /// Read the `cx.component.space.create.v1` ordered-log entries for the
    /// space's genesis history. Returns `None` for spaces with no create
    /// events (e.g. before first projection) or `Bottom` state.
    pub fn space_create_log(&self, space_id: &str) -> Option<&[Value]> {
        let cell_id =
            contrix_sdk::CellRef::new(format!("cx:cell:cx.component.space.create.v1:{space_id}"))
                .ok()?;
        match self.cells.get(&cell_id)? {
            CellState::Value(Value::Array(entries)) => Some(entries.as_slice()),
            _ => None,
        }
    }

    /// True when the `cx.component.space.destroy.v1` cell has a Value
    /// (any non-Bottom value indicates the destroy commit landed).
    /// Equivalent to checking `space_states[space_id].deleted` but reads
    /// from the protocol-canonical cells map source.
    pub fn space_is_destroyed(&self, space_id: &str) -> bool {
        let Ok(cell_id) =
            contrix_sdk::CellRef::new(format!("cx:cell:cx.component.space.destroy.v1:{space_id}"))
        else {
            return false;
        };
        matches!(self.cells.get(&cell_id), Some(CellState::Value(_)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hlc::ServerHlc;

    fn make_operation(object_type: &str, space_id: &str, payload: Value) -> Operation {
        Operation::create(
            contrix_sdk::OperationId::new(format!("cx:operation:{}", uuid::Uuid::now_v7()))
                .unwrap(),
            contrix_sdk::SpaceId::new(space_id).unwrap(),
            object_type,
            payload,
        )
    }

    #[test]
    fn message_create_and_query() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let op = make_operation(
            crate::kinds::CX_MESSAGE_CREATE,
            "cx:space:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "event_id": "cx:event:01904100-0000-7000-8000-caaa6a15bce1",
                "sender": "did:web:alice",
                "thread_id": "cx:flow:1",
                "content": {"body": "hello"}
            }),
        );
        let effect = state.apply(&op, &hlc);
        assert!(matches!(effect, ProjectionEffect::MessageCreated(_)));

        let msgs = state.messages_for_space("cx:space:01904100-0000-7000-8000-cfc039892036");
        assert_eq!(msgs.len(), 1);
        assert_eq!(
            msgs[0].event_id,
            "cx:event:01904100-0000-7000-8000-caaa6a15bce1"
        );
    }

    #[test]
    fn redaction_hides_message() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");

        state.apply(
            &make_operation(
                crate::kinds::CX_MESSAGE_CREATE,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "event_id": "cx:event:01904100-0000-7000-8000-caaa6a15bce1",
                    "sender": "did:web:alice",
                    "thread_id": "cx:flow:1",
                    "content": {"body": "hello"}
                }),
            ),
            &hlc,
        );
        state.apply(
            &make_operation(
                crate::kinds::CX_MESSAGE_REDACT,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "target_event_id": "cx:event:01904100-0000-7000-8000-caaa6a15bce1",
                    "by": "did:web:alice",
                    "reason": "wrong room"
                }),
            ),
            &hlc,
        );

        assert!(
            state
                .messages_for_space("cx:space:01904100-0000-7000-8000-cfc039892036")
                .is_empty()
        );
        assert!(
            state
                .redactions
                .contains("cx:event:01904100-0000-7000-8000-caaa6a15bce1")
        );
        // The original MessageState is preserved (only the
        // parallel cell + flat redactions index move).
        assert!(
            state
                .messages
                .contains_key("cx:event:01904100-0000-7000-8000-caaa6a15bce1")
        );
        let cell = state
            .redaction_cells
            .get("cx:event:01904100-0000-7000-8000-caaa6a15bce1")
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
                crate::kinds::CX_MESSAGE_CREATE,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "event_id": event_id,
                    "sender": "did:web:alice",
                    "thread_id": "cx:flow:1",
                    "content": {"body": "hello"}
                }),
            ),
            hlc,
        );
    }

    #[test]
    fn mal14_tombstone_visible_to_author() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let event_id = "cx:event:01904100-0000-7000-8000-aaaaaaaaaaa1";
        redact_make_message(&mut state, &hlc, event_id);
        state.apply(
            &make_operation(
                crate::kinds::CX_MESSAGE_REDACT,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "target_event_id": event_id,
                    "by": "did:web:alice",
                    "reason": "rethink",
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
        let event_id = "cx:event:01904100-0000-7000-8000-aaaaaaaaaaa2";
        redact_make_message(&mut state, &hlc, event_id);
        state.apply(
            &make_operation(
                crate::kinds::CX_MESSAGE_REDACT,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
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
        let event_id = "cx:event:01904100-0000-7000-8000-aaaaaaaaaaa3";
        redact_make_message(&mut state, &hlc, event_id);
        // Redact.
        state.apply(
            &make_operation(
                crate::kinds::CX_MESSAGE_REDACT,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
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
                crate::kinds::CX_MESSAGE_REDACT,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
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
        let event_id = "cx:event:01904100-0000-7000-8000-aaaaaaaaaaa4";
        // Pre-create the projected message and let the projection
        // rendering query it once before the redaction lands.
        redact_make_message(&mut state, &hlc, event_id);
        let pre = state.projected_message(event_id, false).unwrap();
        assert!(pre.content.is_some());
        assert!(pre.redaction.is_none());
        // Now a delayed redaction arrives.
        state.apply(
            &make_operation(
                crate::kinds::CX_MESSAGE_REDACT,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
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
                crate::kinds::CX_REACTION_ADD,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "event_id": "cx:event:01904100-0000-7000-8000-caaa6a15bce1",
                    "actor": "did:web:alice",
                    "key": "👍"
                }),
            ),
            &hlc,
        );
        assert_eq!(
            state
                .reactions_for_event("cx:event:01904100-0000-7000-8000-caaa6a15bce1")
                .len(),
            1
        );

        state.apply(
            &make_operation(
                crate::kinds::CX_REACTION_REMOVE,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "event_id": "cx:event:01904100-0000-7000-8000-caaa6a15bce1",
                    "actor": "did:web:alice",
                    "key": "👍"
                }),
            ),
            &hlc,
        );
        assert_eq!(
            state
                .reactions_for_event("cx:event:01904100-0000-7000-8000-caaa6a15bce1")
                .len(),
            0
        );
    }

    #[test]
    fn membership_join_leave() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");

        state.apply(
            &make_operation(
                crate::kinds::CX_MEMBER_STATE,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "actor_id": "did:web:bob",
                    "membership": "join",
                    "role": "member"
                }),
            ),
            &hlc,
        );
        assert_eq!(
            state
                .members_of_space("cx:space:01904100-0000-7000-8000-cfc039892036")
                .len(),
            1
        );

        state.apply(
            &make_operation(
                crate::kinds::CX_MEMBER_STATE,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "actor_id": "did:web:bob",
                    "membership": "leave"
                }),
            ),
            &hlc,
        );
        assert_eq!(
            state
                .members_of_space("cx:space:01904100-0000-7000-8000-cfc039892036")
                .len(),
            0
        );
    }

    #[test]
    fn message_revise_creates_chain() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");

        state.apply(
            &make_operation(
                crate::kinds::CX_MESSAGE_CREATE,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "event_id": "cx:event:01904100-0000-7000-8000-caaa6a15bce1",
                    "sender": "did:web:alice",
                    "thread_id": "cx:flow:1",
                    "content": {"body": "original"}
                }),
            ),
            &hlc,
        );

        state.apply(
            &make_operation(
                crate::kinds::CX_MESSAGE_REVISE,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "target_event_id": "cx:event:01904100-0000-7000-8000-caaa6a15bce1",
                    "new_event_id": "cx:event:01904100-0000-7000-8000-c4daaba541fc",
                    "content": {"body": "revised"}
                }),
            ),
            &hlc,
        );

        let msgs = state.messages_for_space("cx:space:01904100-0000-7000-8000-cfc039892036");
        assert_eq!(msgs.len(), 2); // original + revision
        let revision = msgs
            .iter()
            .find(|m| m.event_id == "cx:event:01904100-0000-7000-8000-c4daaba541fc")
            .unwrap();
        assert_eq!(
            revision.revision_of.as_deref(),
            Some("cx:event:01904100-0000-7000-8000-caaa6a15bce1")
        );
    }

    // ── Cells map tests ──

    #[test]
    fn cell_value_returns_none_for_unwritten_cell() {
        let state = ProjectionState::new();
        let cell_id = contrix_sdk::CellRef::new(
            "cx:cell:cx.component.space.read_receipt_policy.v1:cx:space:01904100-0000-7000-8000-cfc039892036".to_owned(),
        )
        .unwrap();
        assert!(state.cell(&cell_id).is_none());
        assert!(state.cell_value(&cell_id).is_none());
    }

    #[test]
    fn cell_value_returns_none_for_bottom_state() {
        use contrix_sdk::lattice::CellState;
        let mut state = ProjectionState::new();
        let cell_id = contrix_sdk::CellRef::new(
            "cx:cell:cx.component.space.policy.v1:cx:space:01904100-0000-7000-8000-cfc039892036"
                .to_owned(),
        )
        .unwrap();
        // Manually insert a Bottom state — represents concurrent conflict.
        let bottom = contrix_sdk::Bottom {
            kind: contrix_sdk::BottomKind::Conflict,
            cells: vec![cell_id.clone()],
            move_ids: vec![],
            anchor_view: None,
            heads: vec![],
            details: Some(serde_json::json!({"reason": "concurrent set"})),
            escalated_at: None,
        };
        state
            .cells
            .insert(cell_id.clone(), CellState::Bottom(bottom));

        // cell() returns Some(Bottom)
        assert!(matches!(state.cell(&cell_id), Some(CellState::Bottom(_))));
        // cell_value() filters out Bottom.
        assert!(state.cell_value(&cell_id).is_none());
    }

    // ── Membership cache + FSM cell tests ──

    #[test]
    fn membership_join_writes_both_structured_cache_and_fsm_cell() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");

        state.apply(
            &make_operation(
                crate::kinds::CX_MEMBER_STATE,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "actor_id": "did:web:alice",
                    "membership": "join",
                    "role": "admin"
                }),
            ),
            &hlc,
        );

        // Structured cache populated with state="join" + role="admin".
        let m = state
            .member(
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                "did:web:alice",
            )
            .expect("member entry should exist after join");
        assert_eq!(m.state, "join");
        assert_eq!(m.role, "admin");

        // FSM cell populated.
        assert_eq!(
            state.member_fsm_state("did:web:alice").as_deref(),
            Some("join")
        );

        // members_of_space only returns entries in `state="join"`.
        assert_eq!(
            state
                .members_of_space("cx:space:01904100-0000-7000-8000-cfc039892036")
                .len(),
            1
        );
    }

    #[test]
    fn ban_then_invite_round_trips_through_fsm_states() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");

        // join -> ban -> invite — full FSM lifecycle.
        for membership in ["join", "ban"] {
            state.apply(
                &make_operation(
                    crate::kinds::CX_MEMBER_STATE,
                    "cx:space:01904100-0000-7000-8000-cfc039892036",
                    serde_json::json!({
                        "actor_id": "did:web:bob",
                        "membership": membership,
                        "role": "member"
                    }),
                ),
                &hlc,
            );
        }

        // After ban, Bob is in `members_in_state("ban")` and NOT in
        // `members_of_space()` (which filters by `state="join"`).
        assert_eq!(
            state
                .members_in_state("cx:space:01904100-0000-7000-8000-cfc039892036", "ban")
                .len(),
            1
        );
        assert_eq!(
            state
                .members_of_space("cx:space:01904100-0000-7000-8000-cfc039892036")
                .len(),
            0
        );
        assert_eq!(
            state.member_fsm_state("did:web:bob").as_deref(),
            Some("ban")
        );

        // invite returns the actor to the invite state.
        state.apply(
            &make_operation(
                crate::kinds::CX_MEMBER_STATE,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({"actor_id": "did:web:bob", "membership": "invite"}),
            ),
            &hlc,
        );
        assert_eq!(
            state.member_fsm_state("did:web:bob").as_deref(),
            Some("invite")
        );
        assert_eq!(
            state
                .members_in_state("cx:space:01904100-0000-7000-8000-cfc039892036", "ban")
                .len(),
            0
        );
        assert_eq!(
            state
                .members_in_state("cx:space:01904100-0000-7000-8000-cfc039892036", "invite")
                .len(),
            1
        );
    }

    // ── Space lifecycle cache + cell tests ──

    #[test]
    fn space_create_writes_both_structured_cache_and_ordered_log_cell() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        state.apply(
            &make_operation(
                crate::kinds::CX_SPACE_CREATE,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "action": "create",
                    "owner": "did:web:alice",
                    "title": "Test Space",
                }),
            ),
            &hlc,
        );

        // Structured cache populated.
        let space = state
            .space_states
            .get("cx:space:01904100-0000-7000-8000-cfc039892036")
            .expect("space_states entry should exist after create");
        assert_eq!(space.owner.as_deref(), Some("did:web:alice"));
        assert_eq!(space.title.as_deref(), Some("Test Space"));
        assert!(!space.deleted);

        // Ordered-log cell has one entry.
        let log = state
            .space_create_log("cx:space:01904100-0000-7000-8000-cfc039892036")
            .expect("create cell should be a Value(Array)");
        assert_eq!(log.len(), 1);
        assert_eq!(
            log[0].get("owner").and_then(Value::as_str),
            Some("did:web:alice")
        );
    }

    #[test]
    fn space_update_writes_organization_cell_with_cas_register_semantics() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        state.apply(
            &make_operation(
                crate::kinds::CX_SPACE_UPDATE,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "action": "update",
                    "owner": "did:web:alice",
                    "title": "Renamed Space",
                }),
            ),
            &hlc,
        );

        let value = state
            .space_organization_cell_value("cx:space:01904100-0000-7000-8000-cfc039892036")
            .expect("organization cell should resolve to Value");
        assert_eq!(
            value.get("title").and_then(Value::as_str),
            Some("Renamed Space")
        );
        assert_eq!(
            value.get("owner").and_then(Value::as_str),
            Some("did:web:alice")
        );
        // updated_at is a server-side timestamp present on every update.
        assert!(value.get("updated_at").is_some());
    }

    #[test]
    fn space_destroy_writes_destroy_cell_and_marks_cache_deleted() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        // First create...
        state.apply(
            &make_operation(
                crate::kinds::CX_SPACE_CREATE,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({"action": "create", "owner": "did:web:alice"}),
            ),
            &hlc,
        );
        assert!(!state.space_is_destroyed("cx:space:01904100-0000-7000-8000-cfc039892036"));

        // ...then destroy.
        state.apply(
            &make_operation(
                crate::kinds::CX_SPACE_DESTROY,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({"action": "destroy"}),
            ),
            &hlc,
        );

        // Cell-keyed query returns true.
        assert!(state.space_is_destroyed("cx:space:01904100-0000-7000-8000-cfc039892036"));
        // Structured cache mirror agrees.
        let space = state
            .space_states
            .get("cx:space:01904100-0000-7000-8000-cfc039892036")
            .unwrap();
        assert!(space.deleted);
    }

    #[test]
    fn space_create_log_appends_on_repeated_create_events() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        for owner in ["did:web:alice", "did:web:bob"] {
            state.apply(
                &make_operation(
                    crate::kinds::CX_SPACE_CREATE,
                    "cx:space:01904100-0000-7000-8000-cfc039892036",
                    serde_json::json!({"action": "create", "owner": owner}),
                ),
                &hlc,
            );
        }
        let log = state
            .space_create_log("cx:space:01904100-0000-7000-8000-cfc039892036")
            .unwrap();
        assert_eq!(log.len(), 2, "ordered-log should accumulate entries");
    }

    #[test]
    fn space_organization_cell_returns_none_for_uncreated_space() {
        let state = ProjectionState::new();
        assert!(
            state
                .space_organization_cell_value("cx:space:01904100-0000-7000-8000-0f863ed7d6d2")
                .is_none()
        );
        assert!(
            state
                .space_create_log("cx:space:01904100-0000-7000-8000-0f863ed7d6d2")
                .is_none()
        );
        assert!(!state.space_is_destroyed("cx:space:01904100-0000-7000-8000-0f863ed7d6d2"));
    }

    #[test]
    fn knock_state_visible_in_members_in_state_query() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        state.apply(
            &make_operation(
                crate::kinds::CX_MEMBER_STATE,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({"actor_id": "did:web:carol", "membership": "knock"}),
            ),
            &hlc,
        );
        let knockers =
            state.members_in_state("cx:space:01904100-0000-7000-8000-cfc039892036", "knock");
        assert_eq!(knockers.len(), 1);
        assert_eq!(knockers[0].member, "did:web:carol");
        assert_eq!(
            state.member_fsm_state("did:web:carol").as_deref(),
            Some("knock")
        );
    }

    #[test]
    fn read_receipt_policy_cell_value_helper_extracts_canonical_value() {
        use contrix_sdk::lattice::CellState;
        let mut state = ProjectionState::new();
        let cell_id = contrix_sdk::CellRef::new(
            "cx:cell:cx.component.space.read_receipt_policy.v1:cx:space:01904100-0000-7000-8000-cfc039892036".to_owned(),
        )
        .unwrap();
        state.cells.insert(
            cell_id,
            CellState::Value(serde_json::json!({
                "disclosure": "required",
                "visibility": "members",
                "scope_overrides_allowed": false,
            })),
        );
        let value = state
            .read_receipt_policy_cell_value("cx:space:01904100-0000-7000-8000-cfc039892036")
            .expect("policy cell should resolve");
        assert_eq!(
            value.get("disclosure").and_then(Value::as_str),
            Some("required")
        );
        assert_eq!(
            value.get("visibility").and_then(Value::as_str),
            Some("members")
        );
        assert_eq!(
            value
                .get("scope_overrides_allowed")
                .and_then(Value::as_bool),
            Some(false)
        );
    }

    /// End-to-end Place lifecycle through the dispatcher: create →
    /// archive (active → archived) → restore (archived → active) →
    /// tombstone (active → tombstoned). Verifies the projection's
    /// `places` map tracks state transitions correctly and the
    /// effects carry the new state.
    #[test]
    fn place_lifecycle_round_trip() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let space_id = "cx:space:01904100-0000-7000-8000-cfc039892036";
        let place_id = "cx:place:01904100-0000-7000-8000-1fb50799ad42";

        // create
        let create_effect = state.apply(
            &make_operation(
                crate::kinds::CX_PLACE_CREATE,
                space_id,
                serde_json::json!({
                    "object": {
                        "id": place_id,
                        "space_id": space_id,
                        "kind": "board",
                        "title": "Roadmap",
                        "created_by": "did:web:alice.example",
                    }
                }),
            ),
            &hlc,
        );
        assert!(matches!(create_effect, ProjectionEffect::PlaceLifecycle { new_state: PlaceLifecycleState::Active, .. }));
        assert_eq!(state.places[place_id].state, PlaceLifecycleState::Active);

        // archive
        let archive_effect = state.apply(
            &make_operation(
                crate::kinds::CX_PLACE_ARCHIVE,
                space_id,
                serde_json::json!({ "place_id": place_id, "sender": "did:web:alice.example" }),
            ),
            &hlc,
        );
        assert!(matches!(archive_effect, ProjectionEffect::PlaceLifecycle { new_state: PlaceLifecycleState::Archived, .. }));
        assert_eq!(state.places[place_id].state, PlaceLifecycleState::Archived);

        // restore
        let restore_effect = state.apply(
            &make_operation(
                crate::kinds::CX_PLACE_RESTORE,
                space_id,
                serde_json::json!({ "place_id": place_id, "sender": "did:web:alice.example" }),
            ),
            &hlc,
        );
        assert!(matches!(restore_effect, ProjectionEffect::PlaceLifecycle { new_state: PlaceLifecycleState::Active, .. }));
        assert_eq!(state.places[place_id].state, PlaceLifecycleState::Active);

        // tombstone
        let tombstone_effect = state.apply(
            &make_operation(
                crate::kinds::CX_PLACE_TOMBSTONE,
                space_id,
                serde_json::json!({ "place_id": place_id, "sender": "did:web:alice.example" }),
            ),
            &hlc,
        );
        assert!(matches!(tombstone_effect, ProjectionEffect::PlaceLifecycle { new_state: PlaceLifecycleState::Tombstoned, .. }));
        assert_eq!(state.places[place_id].state, PlaceLifecycleState::Tombstoned);
    }

    /// Preflight `check_place_lifecycle_transition` rejects each illegal
    /// transition with the spec-canonical reason_code per
    /// `contrix-spec/v1/zh/models/common-fields.md §5.1`.
    #[test]
    fn place_lifecycle_preflight_rejects_illegal_transitions() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let space_id = "cx:space:01904100-0000-7000-8000-cfc039892036";
        let place_id = "cx:place:01904100-0000-7000-8000-1fb50799ad43";

        // Create the place (Active).
        state.apply(
            &make_operation(
                crate::kinds::CX_PLACE_CREATE,
                space_id,
                serde_json::json!({
                    "object": {
                        "id": place_id,
                        "space_id": space_id,
                        "kind": "list",
                        "title": "Todo",
                        "created_by": "did:web:alice.example",
                    }
                }),
            ),
            &hlc,
        );

        // restore on Active → place_not_archived
        let restore_op = make_operation(
            crate::kinds::CX_PLACE_RESTORE,
            space_id,
            serde_json::json!({ "place_id": place_id }),
        );
        assert_eq!(
            state.check_place_lifecycle_transition(&restore_op),
            Err("place_not_archived")
        );

        // Archive then try archive again → place_not_active
        state.apply(
            &make_operation(
                crate::kinds::CX_PLACE_ARCHIVE,
                space_id,
                serde_json::json!({ "place_id": place_id }),
            ),
            &hlc,
        );
        let archive_op = make_operation(
            crate::kinds::CX_PLACE_ARCHIVE,
            space_id,
            serde_json::json!({ "place_id": place_id }),
        );
        assert_eq!(
            state.check_place_lifecycle_transition(&archive_op),
            Err("place_not_active")
        );

        // Tombstone (legal from Archived).
        state.apply(
            &make_operation(
                crate::kinds::CX_PLACE_TOMBSTONE,
                space_id,
                serde_json::json!({ "place_id": place_id }),
            ),
            &hlc,
        );
        // Now restore on Tombstoned → still place_not_archived.
        let restore_again = make_operation(
            crate::kinds::CX_PLACE_RESTORE,
            space_id,
            serde_json::json!({ "place_id": place_id }),
        );
        assert_eq!(
            state.check_place_lifecycle_transition(&restore_again),
            Err("place_not_archived")
        );
        // Tombstone on Tombstoned → place_already_terminal.
        let tombstone_again = make_operation(
            crate::kinds::CX_PLACE_TOMBSTONE,
            space_id,
            serde_json::json!({ "place_id": place_id }),
        );
        assert_eq!(
            state.check_place_lifecycle_transition(&tombstone_again),
            Err("place_already_terminal")
        );
        // Update on Tombstoned → place_not_active.
        let update_op = make_operation(
            crate::kinds::CX_PLACE_UPDATE,
            space_id,
            serde_json::json!({
                "place_id": place_id,
                "patch": { "title": "Renamed while tombstoned" }
            }),
        );
        assert_eq!(
            state.check_place_lifecycle_transition(&update_op),
            Err("place_not_active")
        );
    }

    /// Preflight is permissive when the Place is unknown — causal /
    /// backfill window. Spec: "未知对象容忍" rule in common-fields §5.1.
    #[test]
    fn place_lifecycle_preflight_tolerates_unknown_place() {
        let state = ProjectionState::new();
        let archive_unknown = make_operation(
            crate::kinds::CX_PLACE_ARCHIVE,
            "cx:space:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({ "place_id": "cx:place:nope-not-here" }),
        );
        assert_eq!(state.check_place_lifecycle_transition(&archive_unknown), Ok(()));
    }

    // ── Round 13: Flow lifecycle state-machine tests ──

    /// End-to-end Flow lifecycle through the dispatcher: create → archive →
    /// restore (no tombstone for Flow per spec). Verifies projection state
    /// transitions correctly and effects carry the new state.
    #[test]
    fn flow_lifecycle_round_trip() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let space_id = "cx:space:01904100-0000-7000-8000-cfc039892036";
        let flow_id = "cx:flow:01904100-0000-7000-8000-1fb50799ad50";

        let create_effect = state.apply(
            &make_operation(
                crate::kinds::CX_FLOW_CREATE,
                space_id,
                serde_json::json!({
                    "object": {
                        "id": flow_id,
                        "space_id": space_id,
                        "title": "Payment refactor",
                        "created_by": "did:web:alice.example",
                    }
                }),
            ),
            &hlc,
        );
        assert!(matches!(
            create_effect,
            ProjectionEffect::FlowLifecycle { new_state: ObjectLifecycleState::Active, .. }
        ));
        assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Active);

        let archive_effect = state.apply(
            &make_operation(
                crate::kinds::CX_FLOW_ARCHIVE,
                space_id,
                serde_json::json!({ "flow_id": flow_id, "sender": "did:web:alice.example" }),
            ),
            &hlc,
        );
        assert!(matches!(
            archive_effect,
            ProjectionEffect::FlowLifecycle { new_state: ObjectLifecycleState::Archived, .. }
        ));
        assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Archived);

        let restore_effect = state.apply(
            &make_operation(
                crate::kinds::CX_FLOW_RESTORE,
                space_id,
                serde_json::json!({ "flow_id": flow_id, "sender": "did:web:alice.example" }),
            ),
            &hlc,
        );
        assert!(matches!(
            restore_effect,
            ProjectionEffect::FlowLifecycle { new_state: ObjectLifecycleState::Active, .. }
        ));
        assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Active);
    }

    /// Preflight `check_flow_lifecycle_transition` rejects illegal
    /// transitions with the spec-canonical reason codes per
    /// `common-fields.md §5.1`.
    #[test]
    fn flow_lifecycle_preflight_rejects_illegal_transitions() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let space_id = "cx:space:01904100-0000-7000-8000-cfc039892036";
        let flow_id = "cx:flow:01904100-0000-7000-8000-1fb50799ad51";

        state.apply(
            &make_operation(
                crate::kinds::CX_FLOW_CREATE,
                space_id,
                serde_json::json!({
                    "object": {
                        "id": flow_id,
                        "space_id": space_id,
                        "title": "Refactor",
                        "created_by": "did:web:alice.example",
                    }
                }),
            ),
            &hlc,
        );

        // restore on Active → flow_not_archived
        let restore_op = make_operation(
            crate::kinds::CX_FLOW_RESTORE,
            space_id,
            serde_json::json!({ "flow_id": flow_id }),
        );
        assert_eq!(
            state.check_flow_lifecycle_transition(&restore_op),
            Err("flow_not_archived")
        );

        // Archive then re-archive → flow_not_active
        state.apply(
            &make_operation(
                crate::kinds::CX_FLOW_ARCHIVE,
                space_id,
                serde_json::json!({ "flow_id": flow_id }),
            ),
            &hlc,
        );
        let archive_again = make_operation(
            crate::kinds::CX_FLOW_ARCHIVE,
            space_id,
            serde_json::json!({ "flow_id": flow_id }),
        );
        assert_eq!(
            state.check_flow_lifecycle_transition(&archive_again),
            Err("flow_not_active")
        );

        // Update on Archived → flow_not_active
        let update_op = make_operation(
            crate::kinds::CX_FLOW_UPDATE,
            space_id,
            serde_json::json!({
                "flow_id": flow_id,
                "patch": { "title": "Edit while archived" }
            }),
        );
        assert_eq!(
            state.check_flow_lifecycle_transition(&update_op),
            Err("flow_not_active")
        );
    }

    #[test]
    fn flow_lifecycle_preflight_tolerates_unknown_flow() {
        let state = ProjectionState::new();
        let archive_unknown = make_operation(
            crate::kinds::CX_FLOW_ARCHIVE,
            "cx:space:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({ "flow_id": "cx:flow:nope-not-here" }),
        );
        assert_eq!(
            state.check_flow_lifecycle_transition(&archive_unknown),
            Ok(())
        );
    }

    // ── Round 13: Morph lifecycle state-machine tests ──

    #[test]
    fn morph_lifecycle_round_trip() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let space_id = "cx:space:01904100-0000-7000-8000-cfc039892036";
        let morph_id = "cx:morph:01904100-0000-7000-8000-1fb50799ad60";

        let create_effect = state.apply(
            &make_operation(
                crate::kinds::CX_MORPH_CREATE,
                space_id,
                serde_json::json!({
                    "object": {
                        "id": morph_id,
                        "space_id": space_id,
                        "morph_type": "task",
                        "title": "Backfill",
                        "created_by": "did:web:alice.example",
                    }
                }),
            ),
            &hlc,
        );
        assert!(matches!(
            create_effect,
            ProjectionEffect::MorphLifecycle { new_state: ObjectLifecycleState::Active, .. }
        ));
        assert_eq!(state.morphs[morph_id].state, ObjectLifecycleState::Active);

        state.apply(
            &make_operation(
                crate::kinds::CX_MORPH_ARCHIVE,
                space_id,
                serde_json::json!({ "morph_id": morph_id }),
            ),
            &hlc,
        );
        assert_eq!(state.morphs[morph_id].state, ObjectLifecycleState::Archived);

        state.apply(
            &make_operation(
                crate::kinds::CX_MORPH_RESTORE,
                space_id,
                serde_json::json!({ "morph_id": morph_id }),
            ),
            &hlc,
        );
        assert_eq!(state.morphs[morph_id].state, ObjectLifecycleState::Active);
    }

    #[test]
    fn morph_lifecycle_preflight_rejects_illegal_transitions() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let space_id = "cx:space:01904100-0000-7000-8000-cfc039892036";
        let morph_id = "cx:morph:01904100-0000-7000-8000-1fb50799ad61";

        state.apply(
            &make_operation(
                crate::kinds::CX_MORPH_CREATE,
                space_id,
                serde_json::json!({
                    "object": {
                        "id": morph_id,
                        "space_id": space_id,
                        "morph_type": "task",
                        "title": "Backfill",
                        "created_by": "did:web:alice.example",
                    }
                }),
            ),
            &hlc,
        );

        // restore on Active → morph_not_archived
        let restore_op = make_operation(
            crate::kinds::CX_MORPH_RESTORE,
            space_id,
            serde_json::json!({ "morph_id": morph_id }),
        );
        assert_eq!(
            state.check_morph_lifecycle_transition(&restore_op),
            Err("morph_not_archived")
        );

        state.apply(
            &make_operation(
                crate::kinds::CX_MORPH_ARCHIVE,
                space_id,
                serde_json::json!({ "morph_id": morph_id }),
            ),
            &hlc,
        );
        let archive_again = make_operation(
            crate::kinds::CX_MORPH_ARCHIVE,
            space_id,
            serde_json::json!({ "morph_id": morph_id }),
        );
        assert_eq!(
            state.check_morph_lifecycle_transition(&archive_again),
            Err("morph_not_active")
        );

        // Update on Archived → morph_not_active
        let update_op = make_operation(
            crate::kinds::CX_MORPH_UPDATE,
            space_id,
            serde_json::json!({
                "morph_id": morph_id,
                "patch": { "title": "Edit blocked" }
            }),
        );
        assert_eq!(
            state.check_morph_lifecycle_transition(&update_op),
            Err("morph_not_active")
        );
    }

    #[test]
    fn morph_lifecycle_preflight_tolerates_unknown_morph() {
        let state = ProjectionState::new();
        let archive_unknown = make_operation(
            crate::kinds::CX_MORPH_ARCHIVE,
            "cx:space:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({ "morph_id": "cx:morph:nope-not-here" }),
        );
        assert_eq!(
            state.check_morph_lifecycle_transition(&archive_unknown),
            Ok(())
        );
    }

    // ── Round 14: Flow position events (move / reorder) ──

    /// `cx.flow.move` / `cx.flow.reorder` touch the Flow projection's
    /// `updated_at` / `updated_by` but do NOT change state. Cell-write
    /// happens on the Move/Anchor pipeline (out of scope here).
    #[test]
    fn flow_position_events_touch_projection_without_changing_state() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let space_id = "cx:space:01904100-0000-7000-8000-cfc039892036";
        let flow_id = "cx:flow:01904100-0000-7000-8000-2fb50799ad50";
        let board_place_id = "cx:place:01904100-0000-7000-8000-c10dc0000001";

        state.apply(
            &make_operation(
                crate::kinds::CX_FLOW_CREATE,
                space_id,
                serde_json::json!({
                    "object": {
                        "id": flow_id,
                        "space_id": space_id,
                        "title": "Launch",
                        "created_by": "did:web:alice.example",
                    }
                }),
            ),
            &hlc,
        );
        let created_state = state.flows[flow_id].state;
        let created_updated_at = state.flows[flow_id].updated_at;
        assert_eq!(created_state, ObjectLifecycleState::Active);
        assert!(created_updated_at.is_none(), "create does not set updated_at");

        // cx.flow.move — state unchanged, updated_at advances.
        let move_effect = state.apply(
            &make_operation(
                crate::kinds::CX_FLOW_MOVE,
                space_id,
                serde_json::json!({
                    "flow_id": flow_id,
                    "board_place_id": board_place_id,
                    "target_place_id": "cx:place:01904100-0000-7000-8000-c10dc0000002",
                    "sender": "did:web:alice.example",
                }),
            ),
            &hlc,
        );
        assert!(matches!(
            move_effect,
            ProjectionEffect::FlowLifecycle { new_state: ObjectLifecycleState::Active, .. }
        ));
        assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Active);
        assert!(state.flows[flow_id].updated_at.is_some(), "move bumps updated_at");
        assert_eq!(
            state.flows[flow_id].updated_by.as_deref(),
            Some("did:web:alice.example")
        );

        // cx.flow.reorder — same family, same effect.
        let reorder_effect = state.apply(
            &make_operation(
                crate::kinds::CX_FLOW_REORDER,
                space_id,
                serde_json::json!({
                    "flow_id": flow_id,
                    "board_place_id": board_place_id,
                    "rank": "a1",
                    "sender": "did:web:alice.example",
                }),
            ),
            &hlc,
        );
        assert!(matches!(
            reorder_effect,
            ProjectionEffect::FlowLifecycle { new_state: ObjectLifecycleState::Active, .. }
        ));
        assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Active);
    }

    /// Unknown Flow tolerated by the position-touch helper, same convention
    /// as the lifecycle helpers (causal / backfill ordering).
    #[test]
    fn flow_position_events_tolerate_unknown_flow() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let effect = state.apply(
            &make_operation(
                crate::kinds::CX_FLOW_MOVE,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "flow_id": "cx:flow:nope-not-here",
                    "board_place_id": "cx:place:01904100-0000-7000-8000-c10dc0000001",
                }),
            ),
            &hlc,
        );
        assert!(matches!(effect, ProjectionEffect::Ignored));
    }

    // ── Round 14b: cx.redaction → Flow / Morph terminal-state push ──

    /// `cx.redaction` carrying `object_ref: cx:flow:...` flips the
    /// FlowProjection state to Redacted (terminal) per spec
    /// common-fields.md §5.1.
    #[test]
    fn redaction_with_flow_object_ref_flips_to_redacted() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let space_id = "cx:space:01904100-0000-7000-8000-cfc039892036";
        let flow_id = "cx:flow:01904100-0000-7000-8000-3fb50799ad50";

        state.apply(
            &make_operation(
                crate::kinds::CX_FLOW_CREATE,
                space_id,
                serde_json::json!({
                    "object": {
                        "id": flow_id,
                        "space_id": space_id,
                        "title": "Sensitive flow",
                        "created_by": "did:web:alice.example",
                    }
                }),
            ),
            &hlc,
        );
        assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Active);

        let effect = state.apply(
            &make_operation(
                crate::kinds::CX_REDACTION,
                space_id,
                serde_json::json!({
                    "target_event_id": "cx:event:01904100-0000-7000-8000-1d10dc000001",
                    "object_ref": flow_id,
                    "by": "did:web:alice.example",
                    "reason": "policy violation",
                }),
            ),
            &hlc,
        );
        assert!(matches!(
            effect,
            ProjectionEffect::FlowLifecycle { new_state: ObjectLifecycleState::Redacted, .. }
        ));
        assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Redacted);
        assert!(state.flows[flow_id].state.is_terminal());
    }

    /// Same for Morph via `object_ref: cx:morph:...`.
    #[test]
    fn redaction_with_morph_object_ref_flips_to_redacted() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let space_id = "cx:space:01904100-0000-7000-8000-cfc039892036";
        let morph_id = "cx:morph:01904100-0000-7000-8000-3fb50799ad60";

        state.apply(
            &make_operation(
                crate::kinds::CX_MORPH_CREATE,
                space_id,
                serde_json::json!({
                    "object": {
                        "id": morph_id,
                        "space_id": space_id,
                        "morph_type": "task",
                        "title": "Sensitive task",
                        "created_by": "did:web:alice.example",
                    }
                }),
            ),
            &hlc,
        );
        let effect = state.apply(
            &make_operation(
                crate::kinds::CX_REDACTION,
                space_id,
                serde_json::json!({
                    "target_event_id": "cx:event:01904100-0000-7000-8000-1d10dc000002",
                    "object_ref": morph_id,
                    "sender": "did:web:alice.example",
                }),
            ),
            &hlc,
        );
        assert!(matches!(
            effect,
            ProjectionEffect::MorphLifecycle { new_state: ObjectLifecycleState::Redacted, .. }
        ));
        assert_eq!(state.morphs[morph_id].state, ObjectLifecycleState::Redacted);
    }

    /// Preflight rejects `cx.redaction` against an already-terminal
    /// Flow with `flow_already_terminal`. Mirror for Morph also covered.
    #[test]
    fn redaction_preflight_rejects_against_already_terminal() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let space_id = "cx:space:01904100-0000-7000-8000-cfc039892036";
        let flow_id = "cx:flow:01904100-0000-7000-8000-3fb50799ad51";
        let morph_id = "cx:morph:01904100-0000-7000-8000-3fb50799ad61";

        // Materialise + redact a Flow once (legal first redaction).
        state.apply(
            &make_operation(
                crate::kinds::CX_FLOW_CREATE,
                space_id,
                serde_json::json!({
                    "object": {
                        "id": flow_id,
                        "space_id": space_id,
                        "title": "Flow",
                        "created_by": "did:web:alice.example",
                    }
                }),
            ),
            &hlc,
        );
        state.apply(
            &make_operation(
                crate::kinds::CX_REDACTION,
                space_id,
                serde_json::json!({
                    "target_event_id": "cx:event:01904100-0000-7000-8000-1d10dc000003",
                    "object_ref": flow_id,
                }),
            ),
            &hlc,
        );
        assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Redacted);

        // Second redaction against the now-Redacted Flow → preflight rejects.
        let second_redact = make_operation(
            crate::kinds::CX_REDACTION,
            space_id,
            serde_json::json!({
                "target_event_id": "cx:event:01904100-0000-7000-8000-1d10dc000004",
                "object_ref": flow_id,
            }),
        );
        assert_eq!(
            state.check_redaction_target_transition(&second_redact),
            Err("flow_already_terminal")
        );

        // Same path for Morph.
        state.apply(
            &make_operation(
                crate::kinds::CX_MORPH_CREATE,
                space_id,
                serde_json::json!({
                    "object": {
                        "id": morph_id,
                        "space_id": space_id,
                        "morph_type": "task",
                        "title": "Task",
                        "created_by": "did:web:alice.example",
                    }
                }),
            ),
            &hlc,
        );
        state.apply(
            &make_operation(
                crate::kinds::CX_REDACTION,
                space_id,
                serde_json::json!({
                    "target_event_id": "cx:event:01904100-0000-7000-8000-1d10dc000005",
                    "object_ref": morph_id,
                }),
            ),
            &hlc,
        );
        let second_morph_redact = make_operation(
            crate::kinds::CX_REDACTION,
            space_id,
            serde_json::json!({
                "target_event_id": "cx:event:01904100-0000-7000-8000-1d10dc000006",
                "object_ref": morph_id,
            }),
        );
        assert_eq!(
            state.check_redaction_target_transition(&second_morph_redact),
            Err("morph_already_terminal")
        );
    }

    // ── Round 14d: Flow track sub-events ──

    /// `cx.flow.track.*` sub-events touch Flow.updated_at but never
    /// flip lifecycle state. Parent Flow must be Active or the touch is
    /// rejected with `flow_not_active` (defence-in-depth in the reducer,
    /// mirroring the admission preflight).
    #[test]
    fn flow_track_events_touch_active_flow_only() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let space_id = "cx:space:01904100-0000-7000-8000-cfc039892036";
        let flow_id = "cx:flow:01904100-0000-7000-8000-4fb50799ad50";

        state.apply(
            &make_operation(
                crate::kinds::CX_FLOW_CREATE,
                space_id,
                serde_json::json!({
                    "object": {
                        "id": flow_id,
                        "space_id": space_id,
                        "title": "Launch",
                        "created_by": "did:web:alice.example",
                    }
                }),
            ),
            &hlc,
        );

        for kind in [
            crate::kinds::CX_FLOW_TRACK_ENABLE,
            crate::kinds::CX_FLOW_TRACK_DISABLE,
            crate::kinds::CX_FLOW_TRACK_UPDATE,
            crate::kinds::CX_FLOW_TRACK_SET_PRIMARY,
        ] {
            let effect = state.apply(
                &make_operation(
                    kind,
                    space_id,
                    serde_json::json!({
                        "flow_id": flow_id,
                        "track_id": "synthesis",
                        "patch": {"profile": "synthesis"},
                        "sender": "did:web:alice.example",
                    }),
                ),
                &hlc,
            );
            assert!(
                matches!(
                    effect,
                    ProjectionEffect::FlowLifecycle {
                        new_state: ObjectLifecycleState::Active,
                        ..
                    }
                ),
                "kind {kind} should touch Active Flow without flipping state"
            );
        }
        assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Active);
        assert!(state.flows[flow_id].updated_at.is_some());
    }

    /// Preflight returns `flow_not_active` when parent Flow is archived
    /// (or any non-Active state). Reducer-level enforcement is also
    /// present as defence-in-depth — both verified here.
    #[test]
    fn flow_track_preflight_rejects_when_flow_archived() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let space_id = "cx:space:01904100-0000-7000-8000-cfc039892036";
        let flow_id = "cx:flow:01904100-0000-7000-8000-4fb50799ad51";

        state.apply(
            &make_operation(
                crate::kinds::CX_FLOW_CREATE,
                space_id,
                serde_json::json!({
                    "object": {
                        "id": flow_id,
                        "space_id": space_id,
                        "title": "Refactor",
                        "created_by": "did:web:alice.example",
                    }
                }),
            ),
            &hlc,
        );
        state.apply(
            &make_operation(
                crate::kinds::CX_FLOW_ARCHIVE,
                space_id,
                serde_json::json!({ "flow_id": flow_id }),
            ),
            &hlc,
        );
        assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Archived);

        // Preflight: enable on archived Flow → flow_not_active.
        let enable_op = make_operation(
            crate::kinds::CX_FLOW_TRACK_ENABLE,
            space_id,
            serde_json::json!({ "flow_id": flow_id, "track_id": "synthesis" }),
        );
        assert_eq!(
            state.check_flow_track_transition(&enable_op),
            Err("flow_not_active")
        );

        // Reducer-level defence: also rejects directly.
        let effect = state.apply(&enable_op, &hlc);
        assert!(matches!(
            effect,
            ProjectionEffect::Rejected { ref reason } if reason == "flow_not_active"
        ));
    }

    /// Unknown Flow tolerated at the preflight (causal / backfill).
    #[test]
    fn flow_track_preflight_tolerates_unknown_flow() {
        let state = ProjectionState::new();
        let enable_op = make_operation(
            crate::kinds::CX_FLOW_TRACK_ENABLE,
            "cx:space:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "flow_id": "cx:flow:nope-not-here",
                "track_id": "synthesis",
            }),
        );
        assert_eq!(state.check_flow_track_transition(&enable_op), Ok(()));
    }

    /// Preflight tolerates redactions against unknown objects (causal /
    /// backfill window) and against missing `object_ref` (message
    /// redaction path).
    #[test]
    fn redaction_preflight_tolerates_unknown_object_or_message_path() {
        let state = ProjectionState::new();
        let space_id = "cx:space:01904100-0000-7000-8000-cfc039892036";
        // Unknown object_ref.
        let unknown = make_operation(
            crate::kinds::CX_REDACTION,
            space_id,
            serde_json::json!({
                "target_event_id": "cx:event:01904100-0000-7000-8000-1d10dc000007",
                "object_ref": "cx:flow:nope-not-here",
            }),
        );
        assert_eq!(state.check_redaction_target_transition(&unknown), Ok(()));
        // Missing object_ref (message redaction path).
        let message_redact = make_operation(
            crate::kinds::CX_REDACTION,
            space_id,
            serde_json::json!({
                "target_event_id": "cx:event:01904100-0000-7000-8000-1d10dc000008",
            }),
        );
        assert_eq!(
            state.check_redaction_target_transition(&message_redact),
            Ok(())
        );
    }
}
