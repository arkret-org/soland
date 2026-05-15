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
    Ignored,
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
        // the tombstone. The original MessageState stays intact.
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
            reason,
        };
        self.redaction_cells
            .insert(target.clone(), Some(cell.clone()));
        self.redactions.insert(target.clone());
        if let Some(msg) = self.messages.get_mut(&target) {
            msg.redacted_at = Some(operation.created_at);
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
}
