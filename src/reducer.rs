//! Deterministic state reducer for contrix operations.
//!
//! Applies operations to produce projection state using well-known
//! conflict resolution rules:
//! - Scalar fields: Last-Writer-Wins (LWW) by HLC timestamp
//! - Set fields: OR-Set (add-wins with tombstones)
//! - Messages: append-only, revisions form chains
//! - Ordered lists: fractional indexing
//!
//! # T1-1 architecture (2026-05-07)
//!
//! Each canonical Contrix event kind is a `Box<dyn ReducerKind>`
//! registered in [`registry::ReducerRegistry`]. Subject derivation
//! follows spec Phase 1's `(space_id, kind, subject?)` model — see
//! [`registry::ReducerKind::subject_for_event`]. The legacy
//! match-on-kind dispatcher in [`ProjectionState::apply`] remains as a
//! thin wrapper that delegates to the registry; its body is one
//! lookup + one trait call.

pub mod kinds;
pub mod registry;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use contrix_sdk::Operation;
use serde_json::Value;

use crate::hlc::ServerHlc;

use self::registry::ReducerRegistry;

/// Canonical reducer registry; built once at first access and reused for
/// the lifetime of the process. T1-1 wires this through
/// [`ProjectionState::apply`].
fn registry() -> &'static ReducerRegistry {
    static REGISTRY: OnceLock<ReducerRegistry> = OnceLock::new();
    REGISTRY.get_or_init(ReducerRegistry::new)
}

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
    /// Memberships keyed by (space_id, member_did). LWW.
    pub memberships: BTreeMap<String, BTreeMap<String, MembershipState>>,
    /// Banned members keyed by space_id. Set per spec event-auth-state-resolution.
    pub banned_members: BTreeMap<String, BTreeSet<String>>,
    /// Knocking members keyed by space_id. Cleared when the actor joins or leaves.
    pub knocking_members: BTreeMap<String, BTreeSet<String>>,
    /// Space lifecycle state keyed by space_id.
    pub space_states: BTreeMap<String, SpaceState>,
    /// Redacted event IDs (tombstones).
    pub redactions: BTreeSet<String>,
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

    /// Apply a single operation and return the effect.
    ///
    /// Dispatch goes through [`registry::ReducerRegistry`]. The registry
    /// owns one [`registry::ReducerKind`] trait object per canonical
    /// kind id; subject derivation (per the spec event-kind-registry's
    /// `cell_subject` declaration) runs before `project()`. Every kind
    /// is registered in [`crate::reducer::kinds`].
    pub fn apply(&mut self, operation: &Operation, hlc: &ServerHlc) -> ProjectionEffect {
        registry().project(operation, self, hlc)
    }

    /// Apply a batch of operations.
    pub fn apply_batch(
        &mut self,
        operations: &[Operation],
        hlc: &ServerHlc,
    ) -> Vec<ProjectionEffect> {
        operations.iter().map(|op| self.apply(op, hlc)).collect()
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
        // Trust the canonical kind we matched on rather than re-deriving from
        // payload — kick/leave/ban/unban/knock are distinct events and must
        // not be collapsed by ad-hoc payload sniffing.
        let action = match kind {
            crate::kinds::CX_MEMBERSHIP_JOIN => "join",
            crate::kinds::CX_MEMBERSHIP_LEAVE => "leave",
            crate::kinds::CX_MEMBERSHIP_KICK => "kick",
            crate::kinds::CX_MEMBERSHIP_BAN => "ban",
            crate::kinds::CX_MEMBERSHIP_UNBAN => "unban",
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
        let role = operation
            .payload
            .get("role")
            .and_then(|v| v.as_str())
            .unwrap_or("member")
            .to_owned();

        if member.is_empty() {
            return ProjectionEffect::Ignored;
        }

        match kind {
            crate::kinds::CX_MEMBERSHIP_LEAVE
            | crate::kinds::CX_MEMBERSHIP_KICK
            | crate::kinds::CX_MEMBERSHIP_BAN => {
                if let Some(space_members) = self.memberships.get_mut(&space_id) {
                    space_members.remove(&member);
                }
                if kind == crate::kinds::CX_MEMBERSHIP_BAN {
                    self.banned_members
                        .entry(space_id.clone())
                        .or_default()
                        .insert(member.clone());
                }
            }
            crate::kinds::CX_MEMBERSHIP_UNBAN => {
                // Lift the ban marker but do NOT auto-rejoin. A subsequent
                // join event is required to add membership back.
                if let Some(banned) = self.banned_members.get_mut(&space_id) {
                    banned.remove(&member);
                }
            }
            crate::kinds::CX_MEMBERSHIP_KNOCK => {
                // Knock records intent to join; it does not add membership.
                self.knocking_members
                    .entry(space_id.clone())
                    .or_default()
                    .insert(member.clone());
            }
            crate::kinds::CX_MEMBERSHIP_JOIN => {
                let membership = MembershipState {
                    member: member.clone(),
                    space_id: space_id.clone(),
                    role,
                    joined_at: now,
                    updated_at: now,
                };
                self.memberships
                    .entry(space_id.clone())
                    .or_default()
                    .insert(member.clone(), membership);
                if let Some(knocking) = self.knocking_members.get_mut(&space_id) {
                    knocking.remove(&member);
                }
            }
            _ => return ProjectionEffect::Ignored,
        }

        ProjectionEffect::MembershipChanged {
            space_id,
            member,
            action: action.to_owned(),
        }
    }

    fn apply_space_lifecycle(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let action = operation
            .payload
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let space_id = operation.space_id.to_string();

        let space = self
            .space_states
            .entry(space_id.clone())
            .or_insert_with(|| SpaceState {
                space_id: space_id.clone(),
                owner: operation
                    .payload
                    .get("owner")
                    .and_then(|v| v.as_str())
                    .map(ToOwned::to_owned),
                title: operation
                    .payload
                    .get("title")
                    .and_then(|v| v.as_str())
                    .map(ToOwned::to_owned),
                deleted: false,
                created_at: now,
                updated_at: now,
            });

        match action.as_str() {
            "delete" | "space.delete" => {
                space.deleted = true;
                space.updated_at = now;
            }
            _ => {
                space.updated_at = now;
            }
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

    /// Get members of a space.
    pub fn members_of_space(&self, space_id: &str) -> Vec<&MembershipState> {
        self.memberships
            .get(space_id)
            .map(|m| m.values().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hlc::ServerHlc;

    fn make_operation(object_type: &str, space_id: &str, payload: Value) -> Operation {
        Operation::create(
            contrix_sdk::OperationId::new(format!("cx:operation:test-{}", uuid::Uuid::new_v4()))
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
            "cx:space:test",
            serde_json::json!({
                "event_id": "cx:event:msg-1",
                "sender": "did:web:alice",
                "thread_id": "cx:thread:1",
                "content": {"body": "hello"}
            }),
        );
        let effect = state.apply(&op, &hlc);
        assert!(matches!(effect, ProjectionEffect::MessageCreated(_)));

        let msgs = state.messages_for_space("cx:space:test");
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].event_id, "cx:event:msg-1");
    }

    #[test]
    fn redaction_hides_message() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");

        state.apply(
            &make_operation(
                crate::kinds::CX_MESSAGE_CREATE,
                "cx:space:test",
                serde_json::json!({
                    "event_id": "cx:event:msg-1",
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
                "cx:space:test",
                serde_json::json!({
                    "target_event_id": "cx:event:msg-1"
                }),
            ),
            &hlc,
        );

        assert!(state.messages_for_space("cx:space:test").is_empty());
        assert!(state.redactions.contains("cx:event:msg-1"));
    }

    #[test]
    fn reaction_or_set_convergence() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");

        state.apply(
            &make_operation(
                crate::kinds::CX_REACTION_ADD,
                "cx:space:test",
                serde_json::json!({
                    "event_id": "cx:event:msg-1",
                    "actor": "did:web:alice",
                    "key": "👍"
                }),
            ),
            &hlc,
        );
        assert_eq!(state.reactions_for_event("cx:event:msg-1").len(), 1);

        state.apply(
            &make_operation(
                crate::kinds::CX_REACTION_REMOVE,
                "cx:space:test",
                serde_json::json!({
                    "event_id": "cx:event:msg-1",
                    "actor": "did:web:alice",
                    "key": "👍"
                }),
            ),
            &hlc,
        );
        assert_eq!(state.reactions_for_event("cx:event:msg-1").len(), 0);
    }

    #[test]
    fn entity_crud_lifecycle() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");

        state.apply(
            &make_operation(
                crate::kinds::CX_ENTITY_CREATE,
                "cx:space:test",
                serde_json::json!({
                    "entity_id": "cx:entity:task-1",
                    "entity_type": "task",
                    "title": "Do the thing"
                }),
            ),
            &hlc,
        );
        assert_eq!(
            state.entities_for_space("cx:space:test", None, &[]).len(),
            1
        );

        state.apply(
            &make_operation(
                crate::kinds::CX_ENTITY_DELETE,
                "cx:space:test",
                serde_json::json!({
                    "entity_id": "cx:entity:task-1"
                }),
            ),
            &hlc,
        );
        assert_eq!(
            state.entities_for_space("cx:space:test", None, &[]).len(),
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
                "cx:space:test",
                serde_json::json!({
                    "entity_id": "cx:entity:task-1",
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
                    "cx:space:test",
                    None,
                    &["stateful".to_owned(), "rankable".to_owned()]
                )
                .len(),
            1
        );
        assert_eq!(
            state
                .entities_for_space("cx:space:test", None, &["documentable".to_owned()])
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
                "cx:space:test",
                serde_json::json!({
                    "entity_id": "cx:entity:task-1",
                    "entity_type": "task",
                    "fields": {"status": "todo", "rank": "F"}
                }),
            ),
            &hlc,
        );
        state.apply(
            &make_operation(
                crate::kinds::CX_FIELD_POSITION_MOVE,
                "cx:space:test",
                serde_json::json!({
                    "entity_id": "cx:entity:task-1",
                    "view_id": "cx:view:board",
                    "group_by": "fields.status",
                    "to_value": "done",
                    "rank": "V"
                }),
            ),
            &hlc,
        );

        let entity = state.entities.get("cx:entity:task-1").unwrap();
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
                "cx:space:test",
                serde_json::json!({
                    "entity_id": "cx:entity:task-1",
                    "entity_type": "task",
                    "fields": {"status": "todo"}
                }),
            ),
            &hlc,
        );
        state.apply(
            &make_operation(
                crate::kinds::CX_LEGACY_TASK_MOVE,
                "cx:space:test",
                serde_json::json!({
                    "entity_id": "cx:entity:task-1",
                    "group_by": "fields.status",
                    "to_value": "blocked",
                    "rank": "M"
                }),
            ),
            &hlc,
        );
        assert_eq!(state.entities["cx:entity:task-1"].fields["status"], "todo");

        state.apply(
            &make_operation(
                crate::kinds::CX_LEGACY_TASK_MOVE,
                "cx:space:test",
                serde_json::json!({
                    "migration_profile": crate::kinds::LEGACY_KIND_MIGRATION_PROFILE,
                    "entity_id": "cx:entity:task-1",
                    "group_by": "fields.status",
                    "to_value": "blocked",
                    "rank": "M"
                }),
            ),
            &hlc,
        );
        assert_eq!(
            state.entities["cx:entity:task-1"].fields["status"],
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
                "cx:space:test",
                serde_json::json!({
                    "member": "did:web:bob",
                    "action": "join",
                    "role": "member"
                }),
            ),
            &hlc,
        );
        assert_eq!(state.members_of_space("cx:space:test").len(), 1);

        state.apply(
            &make_operation(
                crate::kinds::CX_MEMBERSHIP_LEAVE,
                "cx:space:test",
                serde_json::json!({
                    "member": "did:web:bob",
                    "action": "leave"
                }),
            ),
            &hlc,
        );
        assert_eq!(state.members_of_space("cx:space:test").len(), 0);
    }

    #[test]
    fn message_revise_creates_chain() {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");

        state.apply(
            &make_operation(
                crate::kinds::CX_MESSAGE_CREATE,
                "cx:space:test",
                serde_json::json!({
                    "event_id": "cx:event:msg-1",
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
                "cx:space:test",
                serde_json::json!({
                    "target_event_id": "cx:event:msg-1",
                    "new_event_id": "cx:event:msg-1-rev1",
                    "content": {"body": "revised"}
                }),
            ),
            &hlc,
        );

        let msgs = state.messages_for_space("cx:space:test");
        assert_eq!(msgs.len(), 2); // original + revision
        let revision = msgs
            .iter()
            .find(|m| m.event_id == "cx:event:msg-1-rev1")
            .unwrap();
        assert_eq!(revision.revision_of.as_deref(), Some("cx:event:msg-1"));
    }
}
