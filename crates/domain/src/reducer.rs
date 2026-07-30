//! Deterministic state reducer for arkret operations.
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
//! The standard peer-event receive pipeline routes through
//! [`registry::LatticeKind`] / [`registry::LatticeRegistry`]. Concrete impls live in
//! [`lattice_kinds`]; [`lattice_kinds::build_sdk_cell_registry`] feeds
//! the SDK's `verify_move` / `apply_seal` pipeline. This is the
//! protocol-canonical path; [`ProjectionState`]'s structured fields
//! (`messages`, `reactions`, `read_cursors`, etc.) are an in-memory
//! convenience cache populated from the durable Event-Envelope ingestion
//! path. As Seal projection lands, the structured fields migrate to a
//! single `cells` map.

// SOL-07-005: strand/morph/circle/applet/agent `apply_*` reducers (additional
// `impl ProjectionState` blocks) split out of this file.
mod apply_capability;
mod apply_invites;
mod apply_key_backup;
mod apply_member_application;
mod apply_messages;
mod apply_moderation;
mod apply_objects;
mod apply_realm_key;
mod apply_realm_lifecycle;
mod apply_realm_organization;
mod apply_realm_policy;
mod apply_relations;
mod apply_space_container;
pub mod lattice_kinds;
pub mod mls;
pub mod realm_links;
// G3.S2: policy server cell reducer
pub mod realm_policy_server;
pub mod registry;

// Structural split (2026-06-18) — the direct content of this mod file
// (top-level projection types, free helpers, dispatch registry, and the
// `ProjectionState` struct + inline impl) was moved into the sibling
// submodules below. Re-exports keep the `crate::reducer::Xxx` paths and
// the sibling `apply_*` modules' `super::*` access unchanged.
mod capability_derivation;
mod dispatch;
mod effects;
mod message_helpers;
mod patch_helpers;
mod policy_validation;
mod projection_state;
mod projections;

// Shared imports that the inline `impl ProjectionState` blocks (now in the
// sibling `apply_*` / submodules) reach through `use super::*;`. These were
// the original file-scope `use`s before the 2026-06-18 structural split.
use std::collections::{BTreeMap, BTreeSet};

use arkret_event_draft::Operation;
use arkret_identifiers::CellRef;
use arkret_models_collaboration::agent_operations::AgentLifecycleState;
use arkret_models_collaboration::objects::read_receipts::{
    ReadCursorCausalRelation, ReadCursorPosition as ReadCursorPositionWire,
};
use arkret_state::lattice::CellState;
use arkret_wire::ReadCursorScope as ReadScopeWire;
use arkret_wire::cba::ProjectedCellWrite;
use serde_json::Value;

use crate::hlc::ServerHlc;

pub const CHILD_ORDER_CELL_FAMILY: &str = "ak.component.child_order.v1";
pub const READ_CURSOR_CAUSAL_RELATION_CONTEXT: &str = "read_cursor_causal_relation";

fn projection_context_stripped_payload(payload: &Value) -> Value {
    let mut wire_payload = payload.clone();
    if let Some(object) = wire_payload.as_object_mut() {
        for field in [
            "event_id",
            "sender",
            "hlc",
            "executed_by",
            "authorization_ref",
            "seal_ref",
            "seal_basis",
            "preconditions",
            "accepted_event_id",
            "query_grade",
            READ_CURSOR_CAUSAL_RELATION_CONTEXT,
        ] {
            object.remove(field);
        }
    }
    wire_payload
}

// Public projection record types — kept `pub` so the external
// `crate::reducer::Xxx` references resolve exactly as before.
// Free helpers — `pub(crate)` glob re-exports so sibling `apply_*`
// modules keep resolving them by bare name through their `use super::*;`.
// The handful of `pub` items in these modules get an explicit `pub use`
// (which takes priority over the glob for that name).
pub use apply_capability::engine_grant_from_capability_cell_state;
pub(crate) use apply_member_application::MemberApplicationState;
pub use apply_member_application::MemberApplicationView;
pub use capability_derivation::inheritance_allowed_policies;
pub(crate) use capability_derivation::*;
pub(crate) use dispatch::{APPLY_REGISTRY, extract_event_ref_id, upsert_realm_link};
// Dispatch registry — `ApplyFn` + `default_apply_registry` are `pub`
// (out-of-crate tests assert registry coverage). The realm-link / event-ref
// helpers are `pub(crate)` for sibling `apply_*` access.
pub use dispatch::{ApplyFn, default_apply_registry};
pub use effects::{MlsEffect, ProjectionEffect};
pub(crate) use effects::{ObjectLifecycleTransition, SpaceContainerLifecycleTransition};
pub(crate) use message_helpers::*;
pub use message_helpers::{
    message_id_from_event_id, message_id_from_payload_or_event_id, message_redaction_target_ref,
    poll_id_from_content,
};
// Spec T07 fanout window const is `pub`.
pub use patch_helpers::REALM_DESTROY_FANOUT_WINDOW_DAYS;
pub use patch_helpers::morph_document_body;
pub(crate) use patch_helpers::*;
// `validate_join_policy_payload` is `pub` (out-of-module reference).
pub use policy_validation::validate_join_policy_payload;
pub(crate) use policy_validation::*;
pub use projection_state::ProjectionState;
// `space_container_id_from_payload` is private to the crate but used by
// sibling `apply_*` modules via `super::*`.
pub use projections::{
    AgentActionApprovalProjection, AgentActionRequestProjection, AgentActionRequestStatus,
    AppletProjection, CapabilityDerivedState, CircleLifecycleState, CircleMembershipState,
    CircleProjection, DocumentVersionProjection, ErasureReceiptRecord, InviteProjection,
    KeyPackageLifetime, MessageExpiryAnchor, MessageExpiryProjection, MessageExpiryProjectionState,
    MessageState, MlsCommitEpoch, MlsCommitEpochKey, MlsKeyPackage, MlsRemoveObligation,
    MlsRemoveProposal, MlsWelcome, MlsWelcomeQueueKey, MorphProjection, ObjectLifecycleState,
    PendingReplayEntry, PinProjection, PollOptionState, PollState, ProjectedMessageView,
    PushRouteCellValue, PushRouteSubject, ReactionState, ReadMarkerState,
    RealmInheritancePolicyState, RealmLinkState, RealmOrganizationStatementState,
    RealmPolicyServerConfig, RealmPolicyServerHead, RedactionCellValue, RsvpHead, RsvpProjection,
    SidecarProjection, SolandKeyBackupActiveSeries, SolandMembershipState, SolandRealmState,
    SolandRelationState, SpaceContainerLifecycleState, SpaceContainerProjection, StrandProjection,
    StrandWatchProjection, message_expiry_projection_from_value,
    message_expiry_projection_from_value_with_anchor,
};
pub(crate) use projections::{
    CallFsmHead, operation_history_basis_seals, space_container_id_from_payload,
};

#[cfg(test)]
mod tests;
