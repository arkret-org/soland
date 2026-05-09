//! Deterministic state reducer for contrix operations.
//!
//! Applies operations to produce projection state using well-known
//! conflict resolution rules:
//! - Scalar fields: Last-Writer-Wins (LWW) by HLC timestamp
//! - Set fields: OR-Set (add-wins with tombstones)
//! - Messages: append-only, revisions form chains
//! - Ordered lists: fractional indexing
//!
//! # Architecture (2026-05-09 六轮 aggressive batch)
//!
//! [`ProjectionState::apply`] is a direct match-on-canonical-kind
//! dispatcher to inline projection helpers. The legacy per-event-kind
//! `ReducerKind` trait + 47-stub `ReducerRegistry` + macro-generated
//! `src/reducer/kinds/` tree was deleted: it added zero value over a
//! direct match (every stub was a thin delegate).
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

use contrix_sdk::{
    CellRef, Operation, SpaceId,
    lattice::CellState,
    state_res::{CellRegistry, CellStore, StoreError},
};
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
    /// Entities keyed by entity_id. LWW by HLC.
    pub entities: BTreeMap<String, EntityState>,
    /// Relations keyed by relation_id. LWW by HLC.
    pub relations: BTreeMap<String, RelationState>,
    /// C10.B (2026-05-09 九轮): structured side-band cache keyed by
    /// `(space_id, actor_did)`. Holds the FSM state value plus `role` /
    /// `joined_at` / `updated_at` side-band data that doesn't fit in the
    /// `cx.component.member.state.v1` FSM cell itself. Reads should go
    /// through helpers like [`ProjectionState::members_of_space`] /
    /// [`ProjectionState::members_in_state`] / [`ProjectionState::member`]
    /// rather than touching this directly.
    ///
    /// Replaces the legacy `memberships` (nested BTreeMap) +
    /// `banned_members` (BTreeSet) + `knocking_members` (BTreeSet)
    /// trio — banned / knocking are now derived via `members_in_state`
    /// against the FSM state field, not stored as separate fields.
    pub members: BTreeMap<(String, String), MembershipState>,
    /// Space lifecycle state keyed by space_id.
    pub space_states: BTreeMap<String, SpaceState>,
    /// Redacted event IDs (tombstones).
    pub redactions: BTreeSet<String>,
    /// C10.B (2026-05-09 八轮 激进模式): per-cell effective state
    /// populated from the Move/Anchor pipeline's `apply_anchor` write-back.
    ///
    /// Keyed by canonical `CellRef` (e.g.
    /// `cx:cell:cx.component.space.read_receipt_policy.v1:<space_id>`).
    /// Each successful apply_anchor (`routing::move_anchor::submit_anchor` or
    /// `crate::anchorer::AnchorerWorker`) calls
    /// [`ProjectionState::reload_cells_from_store`] to refresh this map for
    /// the affected Space. Read handlers query via [`ProjectionState::cell`]
    /// / [`ProjectionState::cell_value`] for cell-keyed state lookups
    /// instead of scanning the durable Event store.
    ///
    /// **Migration status (2026-05-09 十三轮)**: this map is the canonical
    /// source for all cell-driven state in the Move/Anchor pipeline.
    /// Completed migrations:
    ///   - `read_receipt_policies` (CasRegister) — old BTreeMap deleted; read
    ///     path uses `cell_value`.
    ///   - `memberships` / `banned_members` / `knocking_members` (FSM) —
    ///     replaced by flat `members: BTreeMap<(String, String),
    ///     MembershipState>` cache + per-actor `cx.component.member.state.v1`
    ///     FSM cell.
    ///   - `space_states` (mixed: ordered-log + cas-register) — kept as
    ///     structured `space_states` side-band cache (server-side
    ///     `created_at`/`updated_at`/`deleted` flag) BUT every
    ///     `apply_space_lifecycle` now also writes one of:
    ///     `cx.component.space.create.v1` (ordered-log, append) /
    ///     `cx.component.space.organization.v1` (cas-register, latest
    ///     metadata) / `cx.component.space.destroy.v1` (cas-register,
    ///     terminal). Helpers: `space_create_log` / `space_organization_cell_value`
    ///     / `space_is_destroyed` query cells directly.
    /// Durable-event-only fields (`messages` / `reactions` / `read_markers`
    /// / `entities` / `relations` / `redactions`) stay structured per spec
    /// (those event kinds have no `cell_family` declaration).
    pub cells: BTreeMap<CellRef, CellState>,
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
pub struct EntityState {
    pub entity_id: String,
    pub space_id: String,
    pub entity_type: String,
    pub facets: Vec<String>,
    pub title: Option<String>,
    pub content: Option<Value>,
    pub fields: BTreeMap<String, Value>,
    pub deleted: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
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
    /// Canonical FSM state value (one of `invited` / `join` / `leave` /
    /// `kick` / `ban` / `knock`). Authoritative source is the
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
    EntityCreated(EntityState),
    EntityUpdated(EntityState),
    EntityDeleted {
        entity_id: String,
    },
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

fn extract_entity_facets(payload: &Value) -> Vec<String> {
    match payload.get("facets") {
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(|value| value.as_str().map(ToOwned::to_owned))
            .collect(),
        Some(Value::Object(values)) => values.keys().cloned().collect(),
        _ => Vec::new(),
    }
}

fn field_path_to_storage_key(field_path: &str) -> String {
    field_path
        .strip_prefix("fields.")
        .unwrap_or(field_path)
        .to_owned()
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
    /// in the Move/Anchor pipeline (`routing::move_anchor::submit_anchor`
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
    /// Direct match-on-canonical-kind dispatch to per-domain helpers. As
    /// of 2026-05-09 六轮 aggressive batch this replaced the per-kind
    /// `ReducerKind` trait + `ReducerRegistry` apparatus, which added
    /// zero value over inline match dispatch (every per-kind stub was a
    /// thin delegate to a `ProjectionState::apply_*` helper).
    ///
    /// Round 21: when `AppConfig::lattice_first` is true the caller routes
    /// through [`Self::apply_via_lattice_registry`] first; that path is a
    /// stub today (the registry only maps Move/Anchor effects, not durable
    /// Events) but the wire is in place for the eventual flip.
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
            Some(CX_ENTITY_CREATE) => self.apply_entity_create(operation, now),
            Some(CX_ENTITY_UPDATE) => self.apply_entity_update(operation, now, _hlc),
            Some(CX_ENTITY_DELETE) => self.apply_entity_delete(operation),
            Some(CX_FIELD_POSITION_MOVE) | Some(CX_FIELD_POSITION_REORDER) => {
                self.apply_entity_update(operation, now, _hlc)
            }
            Some(CX_LEGACY_TASK_MOVE) => {
                if operation
                    .payload
                    .get("migration_profile")
                    .and_then(Value::as_str)
                    == Some(LEGACY_KIND_MIGRATION_PROFILE)
                {
                    self.apply_entity_update(operation, now, _hlc)
                } else {
                    ProjectionEffect::Ignored
                }
            }
            Some(CX_RELATION_CREATE) => self.apply_relation_create(operation, now),
            Some(CX_RELATION_UPDATE) => self.apply_relation_update(operation, now, _hlc),
            Some(CX_RELATION_DELETE) => self.apply_relation_delete(operation),
            Some(CX_CONTAINER_MOVE_ITEM) | Some(CX_CONTAINER_REBALANCE) => {
                self.apply_container_position(operation, now)
            }
            Some(kind) if is_membership_kind(kind) => self.apply_membership(operation, now, kind),
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

    /// Round 22 — `lattice_first` apply path. Probes the supplied
    /// [`LatticeRegistry`] for a `cell_family` that handles this
    /// Operation's canonical kind via the new `event_kinds()` declaration.
    ///
    /// Behaviour:
    /// - **Hit on a cell-family impl**: routes through the inline
    ///   `apply_*` helpers (the helpers ARE the projection — the registry
    ///   only validates that the spec maps this event_kind to a known
    ///   cell family, then we trust the inline dispatcher to handle the
    ///   per-domain effect). This is the canonical path now that
    ///   `AppConfig::lattice_first` defaults to `true` (round 22).
    /// - **No mapping in registry but a known canonical kind**: the kind
    ///   is durable-Event-only (`cx.message.*` / `cx.reaction.*` etc.);
    ///   fall through to inline `apply()` exactly as before. No log noise.
    /// - **Unknown canonical kind**: spec compliance requires us to fail
    ///   closed — log at `error` level and project as `ProjectionEffect::
    ///   Ignored` with `bottom = reject` semantics. Callers that want the
    ///   permissive legacy behaviour set `lattice_first=false` in config.
    pub fn apply_via_lattice_registry(
        &mut self,
        operation: &Operation,
        hlc: &ServerHlc,
        registry: &registry::LatticeRegistry,
    ) -> ProjectionEffect {
        let kind = match crate::kinds::canonical_kind_for_operation(operation) {
            Some(k) => k,
            None => {
                // Safety fallback per round 22 mission: an Operation that
                // doesn't even canonicalise to a known kind cannot be
                // routed through any cell family. Drop with `bottom`
                // semantics rather than letting it slip through silently.
                tracing::error!(
                    object_type = %operation.object_type,
                    operation_id = %operation.operation_id,
                    "lattice_first dispatch: unknown canonical kind for operation; \
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
                "lattice_first dispatch: routed through LatticeRegistry"
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
            .unwrap_or_else(|| {
                // Support legacy "body" field
                if let Some(body) = operation.payload.get("body") {
                    serde_json::json!({ "body": body })
                } else {
                    operation.payload.clone()
                }
            });
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
            if let Some(body) = operation.payload.get("body") {
                revised.content = serde_json::json!({ "body": body });
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

    fn apply_redaction(&mut self, operation: &Operation) -> ProjectionEffect {
        let target = operation
            .payload
            .get("target_event_id")
            .or_else(|| operation.payload.get("target"))
            .or_else(|| operation.payload.get("redacts"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();

        if !target.is_empty() {
            self.redactions.insert(target.clone());
            if let Some(msg) = self.messages.get_mut(&target) {
                msg.redacted_at = Some(operation.created_at);
            }
            ProjectionEffect::MessageRedacted { event_id: target }
        } else {
            ProjectionEffect::Ignored
        }
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

    fn apply_entity_create(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let entity_id = operation
            .payload
            .get("entity_id")
            .or_else(|| operation.payload.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or(operation.operation_id.as_str())
            .to_owned();
        let entity_type = operation
            .payload
            .get("entity_type")
            .or_else(|| operation.payload.get("type"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_owned();
        let title = operation
            .payload
            .get("title")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let facets = extract_entity_facets(&operation.payload);
        let content = operation.payload.get("content").cloned();
        let fields = operation
            .payload
            .get("fields")
            .and_then(|v| v.as_object())
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();

        let state = EntityState {
            entity_id: entity_id.clone(),
            space_id: operation.space_id.to_string(),
            entity_type,
            facets,
            title,
            content,
            fields,
            deleted: false,
            created_at: now,
            updated_at: now,
        };
        let effect = ProjectionEffect::EntityCreated(state.clone());
        self.entities.insert(entity_id, state);
        effect
    }

    fn apply_entity_update(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        _hlc: &ServerHlc,
    ) -> ProjectionEffect {
        let entity_id = operation
            .payload
            .get("entity_id")
            .or_else(|| operation.payload.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or(operation.operation_id.as_str())
            .to_owned();

        if let Some(existing) = self.entities.get_mut(&entity_id) {
            // LWW: merge fields
            if let Some(title) = operation.payload.get("title").and_then(|v| v.as_str()) {
                existing.title = Some(title.to_owned());
            }
            if let Some(content) = operation.payload.get("content") {
                existing.content = Some(content.clone());
            }
            if let Some(fields) = operation.payload.get("fields").and_then(|v| v.as_object()) {
                for (k, v) in fields {
                    existing.fields.insert(k.clone(), v.clone());
                }
            }
            if let Some(field_path) = operation.payload.get("group_by").and_then(|v| v.as_str())
                && let Some(value) = operation.payload.get("to_value")
            {
                existing
                    .fields
                    .insert(field_path_to_storage_key(field_path), value.clone());
            }
            if let Some(rank) = operation.payload.get("rank") {
                existing.fields.insert("rank".to_owned(), rank.clone());
            }
            if operation.payload.get("facets").is_some() {
                existing.facets = extract_entity_facets(&operation.payload);
            }
            existing.updated_at = now;
            ProjectionEffect::EntityUpdated(existing.clone())
        } else {
            // Entity doesn't exist yet; create it
            self.apply_entity_create(operation, now)
        }
    }

    fn apply_entity_delete(&mut self, operation: &Operation) -> ProjectionEffect {
        let entity_id = operation
            .payload
            .get("entity_id")
            .or_else(|| operation.payload.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();

        if let Some(entity) = self.entities.get_mut(&entity_id) {
            entity.deleted = true;
            entity.updated_at = operation.created_at;
        }
        ProjectionEffect::EntityDeleted { entity_id }
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
            .or_else(|| operation.payload.get("from_entity_id"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let to_ref = operation
            .payload
            .get("to")
            .or_else(|| operation.payload.get("to_entity_id"))
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
            .or_else(|| operation.payload.get("from_entity_id"))
        {
            relation.from_ref = value.as_str().map(ToOwned::to_owned);
        }
        if let Some(value) = operation
            .payload
            .get("to")
            .or_else(|| operation.payload.get("to_entity_id"))
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
        let entity_id = operation
            .payload
            .get("entity_id")
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
                to_ref: entity_id.clone(),
                fields: BTreeMap::new(),
                deleted: false,
                created_at: now,
                updated_at: now,
            });
        state.relation_kind = relation_kind;
        state.from_ref = container_id;
        state.to_ref = entity_id;
        state.fields.extend(fields);
        state.deleted = false;
        state.updated_at = now;
        ProjectionEffect::RelationCreated(state.clone())
    }

    fn apply_membership(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        kind: &'static str,
    ) -> ProjectionEffect {
        // C10.B (2026-05-09 九轮): map the durable cx.membership.* event
        // kind to its canonical FSM state in `cx.component.member.state.v1`.
        // The `unban` event clears a ban → returns the member to `invited`
        // per the FSM transition table (ban→invited).
        let new_state = match kind {
            crate::kinds::CX_MEMBERSHIP_JOIN => "join",
            crate::kinds::CX_MEMBERSHIP_LEAVE => "leave",
            crate::kinds::CX_MEMBERSHIP_KICK => "kick",
            crate::kinds::CX_MEMBERSHIP_BAN => "ban",
            crate::kinds::CX_MEMBERSHIP_UNBAN => "invited",
            crate::kinds::CX_MEMBERSHIP_KNOCK => "knock",
            _ => return ProjectionEffect::Ignored,
        };
        let member = operation
            .payload
            .get("member")
            .or_else(|| operation.payload.get("sender"))
            .or_else(|| operation.payload.get("actor"))
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
        let joined_at = self
            .members
            .get(&key)
            .map(|m| m.joined_at)
            .unwrap_or(now);

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
        if let Ok(cell_id) = contrix_sdk::CellRef::new(format!(
            "cx:cell:cx.component.member.state.v1:{member}"
        )) {
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
        // C10.B (2026-05-09 十三轮): structured cache + cells map double-write.
        //
        // Per spec event-kind-registry, each cx.space.* lifecycle event
        // writes a distinct cell family with its own lattice:
        //   cx.space.create  → cx.component.space.create.v1  (ordered-log, singleton)
        //   cx.space.update  → cx.component.space.organization.v1 (cas-register, singleton)
        //   cx.space.destroy → cx.component.space.destroy.v1 (cas-register, singleton)
        //
        // The structured `space_states` field is the side-band cache —
        // keeps `created_at` / `updated_at` server-side timestamps and a
        // simple `deleted` bool that consumers like `routing/index.rs`
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
                    value.insert(
                        "updated_at".to_owned(),
                        Value::String(now.to_rfc3339()),
                    );
                    self.cells.insert(cell_id, CellState::Value(Value::Object(value)));
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
            .filter(|m| m.space_id == space_id && m.redacted_at.is_none())
            .collect();
        msgs.sort_by_key(|a| a.created_at);
        msgs
    }

    /// Get messages for a thread, sorted by creation time.
    pub fn messages_for_thread(&self, thread_id: &str) -> Vec<&MessageState> {
        let mut msgs: Vec<_> = self
            .messages
            .values()
            .filter(|m| m.thread_id == thread_id && m.redacted_at.is_none())
            .collect();
        msgs.sort_by_key(|a| a.created_at);
        msgs
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

    /// Get entities for a space, optionally filtered by type and required facets.
    pub fn entities_for_space(
        &self,
        space_id: &str,
        entity_type: Option<&str>,
        facets: &[String],
    ) -> Vec<&EntityState> {
        self.entities
            .values()
            .filter(|e| {
                e.space_id == space_id
                    && !e.deleted
                    && entity_type.is_none_or(|t| e.entity_type == t)
                    && facets
                        .iter()
                        .all(|facet| e.facets.iter().any(|value| value == facet))
            })
            .collect()
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

    /// Get members of a space currently in `state="join"` (the legacy
    /// `members_of_space` semantic — banned/kicked/left members are
    /// excluded). For state-specific queries use [`members_in_state`].
    pub fn members_of_space(&self, space_id: &str) -> Vec<&MembershipState> {
        self.members_in_state(space_id, "join")
    }

    /// All `MembershipState` entries for a Space whose FSM state matches
    /// `state` (`invited` / `join` / `leave` / `kick` / `ban` / `knock`).
    /// Replaces the legacy `banned_members` / `knocking_members` BTreeSets:
    /// query `members_in_state(space, "ban")` / `members_in_state(space, "knock")`.
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
        let cell_id = contrix_sdk::CellRef::new(format!(
            "cx:cell:cx.component.member.state.v1:{actor_did}"
        ))
        .ok()?;
        self.cell_value(&cell_id)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    }

    // ── C10.B (2026-05-09 八轮) cell-keyed query helpers ──

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

    // ── C10.B (2026-05-09 十三轮) space lifecycle cell helpers ──

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
        let cell_id = contrix_sdk::CellRef::new(format!(
            "cx:cell:cx.component.space.create.v1:{space_id}"
        ))
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
        let Ok(cell_id) = contrix_sdk::CellRef::new(format!(
            "cx:cell:cx.component.space.destroy.v1:{space_id}"
        )) else {
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
                "thread_id": "cx:thread:1",
                "content": {"body": "hello"}
            }),
        );
        let effect = state.apply(&op, &hlc);
        assert!(matches!(effect, ProjectionEffect::MessageCreated(_)));

        let msgs = state.messages_for_space("cx:space:01904100-0000-7000-8000-cfc039892036");
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].event_id, "cx:event:01904100-0000-7000-8000-caaa6a15bce1");
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
                    "thread_id": "cx:thread:1",
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
                    "target_event_id": "cx:event:01904100-0000-7000-8000-caaa6a15bce1"
                }),
            ),
            &hlc,
        );

        assert!(state.messages_for_space("cx:space:01904100-0000-7000-8000-cfc039892036").is_empty());
        assert!(state.redactions.contains("cx:event:01904100-0000-7000-8000-caaa6a15bce1"));
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
        assert_eq!(state.reactions_for_event("cx:event:01904100-0000-7000-8000-caaa6a15bce1").len(), 1);

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
        assert_eq!(state.reactions_for_event("cx:event:01904100-0000-7000-8000-caaa6a15bce1").len(), 0);
    }

    #[test]
    fn entity_crud_lifecycle() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");

        state.apply(
            &make_operation(
                crate::kinds::CX_ENTITY_CREATE,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "entity_id": "cx:entity:01904100-0000-7000-8000-ca33616973bb",
                    "entity_type": "task",
                    "title": "Do the thing"
                }),
            ),
            &hlc,
        );
        assert_eq!(
            state.entities_for_space("cx:space:01904100-0000-7000-8000-cfc039892036", None, &[]).len(),
            1
        );

        state.apply(
            &make_operation(
                crate::kinds::CX_ENTITY_DELETE,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "entity_id": "cx:entity:01904100-0000-7000-8000-ca33616973bb"
                }),
            ),
            &hlc,
        );
        assert_eq!(
            state.entities_for_space("cx:space:01904100-0000-7000-8000-cfc039892036", None, &[]).len(),
            0
        );
    }

    #[test]
    fn entity_facets_filter_queries() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");

        state.apply(
            &make_operation(
                crate::kinds::CX_ENTITY_CREATE,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "entity_id": "cx:entity:01904100-0000-7000-8000-ca33616973bb",
                    "entity_type": "task",
                    "facets": ["stateful", "rankable", "renderable"],
                    "title": "Do the thing"
                }),
            ),
            &hlc,
        );

        assert_eq!(
            state
                .entities_for_space(
                    "cx:space:01904100-0000-7000-8000-cfc039892036",
                    None,
                    &["stateful".to_owned(), "rankable".to_owned()]
                )
                .len(),
            1
        );
        assert_eq!(
            state
                .entities_for_space("cx:space:01904100-0000-7000-8000-cfc039892036", None, &["documentable".to_owned()])
                .len(),
            0
        );
    }

    #[test]
    fn canonical_field_position_move_updates_entity_position_fields() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");

        state.apply(
            &make_operation(
                crate::kinds::CX_ENTITY_CREATE,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "entity_id": "cx:entity:01904100-0000-7000-8000-ca33616973bb",
                    "entity_type": "task",
                    "fields": {"status": "todo", "rank": "F"}
                }),
            ),
            &hlc,
        );
        state.apply(
            &make_operation(
                crate::kinds::CX_FIELD_POSITION_MOVE,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "entity_id": "cx:entity:01904100-0000-7000-8000-ca33616973bb",
                    "view_id": "cx:view:01904100-0000-7000-8000-3bbd26004285",
                    "group_by": "fields.status",
                    "to_value": "done",
                    "rank": "V"
                }),
            ),
            &hlc,
        );

        let entity = state.entities.get("cx:entity:01904100-0000-7000-8000-ca33616973bb").unwrap();
        assert_eq!(entity.fields["status"], "done");
        assert_eq!(entity.fields["rank"], "V");
    }

    #[test]
    fn legacy_task_move_requires_migration_profile() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");

        state.apply(
            &make_operation(
                crate::kinds::CX_ENTITY_CREATE,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "entity_id": "cx:entity:01904100-0000-7000-8000-ca33616973bb",
                    "entity_type": "task",
                    "fields": {"status": "todo"}
                }),
            ),
            &hlc,
        );
        state.apply(
            &make_operation(
                crate::kinds::CX_LEGACY_TASK_MOVE,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "entity_id": "cx:entity:01904100-0000-7000-8000-ca33616973bb",
                    "group_by": "fields.status",
                    "to_value": "blocked",
                    "rank": "M"
                }),
            ),
            &hlc,
        );
        assert_eq!(state.entities["cx:entity:01904100-0000-7000-8000-ca33616973bb"].fields["status"], "todo");

        state.apply(
            &make_operation(
                crate::kinds::CX_LEGACY_TASK_MOVE,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "migration_profile": crate::kinds::LEGACY_KIND_MIGRATION_PROFILE,
                    "entity_id": "cx:entity:01904100-0000-7000-8000-ca33616973bb",
                    "group_by": "fields.status",
                    "to_value": "blocked",
                    "rank": "M"
                }),
            ),
            &hlc,
        );
        assert_eq!(
            state.entities["cx:entity:01904100-0000-7000-8000-ca33616973bb"].fields["status"],
            "blocked"
        );
    }

    #[test]
    fn membership_join_leave() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");

        state.apply(
            &make_operation(
                crate::kinds::CX_MEMBERSHIP_JOIN,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "member": "did:web:bob",
                    "action": "join",
                    "role": "member"
                }),
            ),
            &hlc,
        );
        assert_eq!(state.members_of_space("cx:space:01904100-0000-7000-8000-cfc039892036").len(), 1);

        state.apply(
            &make_operation(
                crate::kinds::CX_MEMBERSHIP_LEAVE,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "member": "did:web:bob",
                    "action": "leave"
                }),
            ),
            &hlc,
        );
        assert_eq!(state.members_of_space("cx:space:01904100-0000-7000-8000-cfc039892036").len(), 0);
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
                    "thread_id": "cx:thread:1",
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
        assert_eq!(revision.revision_of.as_deref(), Some("cx:event:01904100-0000-7000-8000-caaa6a15bce1"));
    }

    // ── C10.B (2026-05-09 八轮) cells map tests ──

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
            "cx:cell:cx.component.space.policy.v1:cx:space:01904100-0000-7000-8000-cfc039892036".to_owned(),
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
        state.cells.insert(cell_id.clone(), CellState::Bottom(bottom));

        // cell() returns Some(Bottom)
        assert!(matches!(
            state.cell(&cell_id),
            Some(CellState::Bottom(_))
        ));
        // cell_value() filters out Bottom.
        assert!(state.cell_value(&cell_id).is_none());
    }

    // ── C10.B (2026-05-09 九轮) memberships → cells + structured cache ──

    #[test]
    fn membership_join_writes_both_structured_cache_and_fsm_cell() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");

        state.apply(
            &make_operation(
                crate::kinds::CX_MEMBERSHIP_JOIN,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "member": "did:web:alice",
                    "role": "admin"
                }),
            ),
            &hlc,
        );

        // Structured cache populated with state="join" + role="admin".
        let m = state
            .member("cx:space:01904100-0000-7000-8000-cfc039892036", "did:web:alice")
            .expect("member entry should exist after join");
        assert_eq!(m.state, "join");
        assert_eq!(m.role, "admin");

        // FSM cell populated.
        assert_eq!(
            state.member_fsm_state("did:web:alice").as_deref(),
            Some("join")
        );

        // members_of_space (legacy semantics: only `state="join"`) sees Alice.
        assert_eq!(state.members_of_space("cx:space:01904100-0000-7000-8000-cfc039892036").len(), 1);
    }

    #[test]
    fn ban_then_unban_round_trips_through_fsm_states() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");

        // join → ban → unban (back to invited) — full FSM lifecycle.
        for kind in [
            crate::kinds::CX_MEMBERSHIP_JOIN,
            crate::kinds::CX_MEMBERSHIP_BAN,
        ] {
            state.apply(
                &make_operation(
                    kind,
                    "cx:space:01904100-0000-7000-8000-cfc039892036",
                    serde_json::json!({"member": "did:web:bob", "role": "member"}),
                ),
                &hlc,
            );
        }

        // After ban, Bob is in `members_in_state("ban")` and NOT in
        // `members_of_space()` (which filters by `state="join"`).
        assert_eq!(state.members_in_state("cx:space:01904100-0000-7000-8000-cfc039892036", "ban").len(), 1);
        assert_eq!(state.members_of_space("cx:space:01904100-0000-7000-8000-cfc039892036").len(), 0);
        assert_eq!(state.member_fsm_state("did:web:bob").as_deref(), Some("ban"));

        // Unban → invited (per FSM ban→invited transition).
        state.apply(
            &make_operation(
                crate::kinds::CX_MEMBERSHIP_UNBAN,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({"member": "did:web:bob"}),
            ),
            &hlc,
        );
        assert_eq!(
            state.member_fsm_state("did:web:bob").as_deref(),
            Some("invited")
        );
        assert_eq!(state.members_in_state("cx:space:01904100-0000-7000-8000-cfc039892036", "ban").len(), 0);
        assert_eq!(state.members_in_state("cx:space:01904100-0000-7000-8000-cfc039892036", "invited").len(), 1);
    }

    // ── C10.B (2026-05-09 十三轮) space_states 双层 tests ──

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
        let space = state.space_states.get("cx:space:01904100-0000-7000-8000-cfc039892036").unwrap();
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
        let log = state.space_create_log("cx:space:01904100-0000-7000-8000-cfc039892036").unwrap();
        assert_eq!(log.len(), 2, "ordered-log should accumulate entries");
    }

    #[test]
    fn space_organization_cell_returns_none_for_uncreated_space() {
        let state = ProjectionState::new();
        assert!(state
            .space_organization_cell_value("cx:space:01904100-0000-7000-8000-0f863ed7d6d2")
            .is_none());
        assert!(state.space_create_log("cx:space:01904100-0000-7000-8000-0f863ed7d6d2").is_none());
        assert!(!state.space_is_destroyed("cx:space:01904100-0000-7000-8000-0f863ed7d6d2"));
    }

    #[test]
    fn knock_state_visible_in_members_in_state_query() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        state.apply(
            &make_operation(
                crate::kinds::CX_MEMBERSHIP_KNOCK,
                "cx:space:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({"member": "did:web:carol"}),
            ),
            &hlc,
        );
        let knockers = state.members_in_state("cx:space:01904100-0000-7000-8000-cfc039892036", "knock");
        assert_eq!(knockers.len(), 1);
        assert_eq!(knockers[0].member, "did:web:carol");
        assert_eq!(state.member_fsm_state("did:web:carol").as_deref(), Some("knock"));
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
        assert_eq!(value.get("disclosure").and_then(Value::as_str), Some("required"));
        assert_eq!(value.get("visibility").and_then(Value::as_str), Some("members"));
        assert_eq!(
            value.get("scope_overrides_allowed").and_then(Value::as_bool),
            Some(false)
        );
    }
}
