//! Deterministic state reducer for cokret operations.
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
//! The Move/Seal receive pipeline (`POST /_soland/peer/moves` /
//! `POST /_soland/peer/seals`) routes through [`registry::LatticeKind`] /
//! [`registry::LatticeRegistry`]. Concrete impls live in
//! [`lattice_kinds`]; [`lattice_kinds::build_sdk_cell_registry`] feeds
//! the SDK's `verify_move` / `apply_seal` pipeline. This is the
//! protocol-canonical path; [`ProjectionState`]'s structured fields
//! (`messages`, `reactions`, `read_cursors`, etc.) are an in-memory
//! convenience cache populated from the durable Event-Envelope ingestion
//! path that pre-dates the Move/Seal model. As Seal projection lands,
//! the structured fields migrate to a single `cells` map.

// SOL-07-005: strand/morph/circle/applet/agent `apply_*` reducers (additional
// `impl ProjectionState` blocks) split out of this file.
mod apply_capability;
mod apply_invites;
mod apply_messages;
mod apply_moderation;
mod apply_objects;
mod apply_realm_lifecycle;
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

use cokret_sdk::lattice::CellState;
use cokret_sdk::{AgentLifecycleState, CellRef, Operation};
use serde_json::Value;

use crate::hlc::ServerHlc;
use crate::wire::{ReadCursorPositionWire, ReadScopeWire};

pub const CHILD_ORDER_CELL_FAMILY: &str = "ck.component.child_order.v1";

// Public projection record types — kept `pub` so the external
// `crate::reducer::Xxx` references resolve exactly as before.
// Free helpers — `pub(crate)` glob re-exports so sibling `apply_*`
// modules keep resolving them by bare name through their `use super::*;`.
// The handful of `pub` items in these modules get an explicit `pub use`
// (which takes priority over the glob for that name).
pub(crate) use capability_derivation::*;
pub(crate) use dispatch::{APPLY_REGISTRY, extract_event_ref_id, upsert_realm_link};
// Dispatch registry — `ApplyFn` + `default_apply_registry` are `pub`
// (out-of-crate tests assert registry coverage). The realm-link / event-ref
// helpers are `pub(crate)` for sibling `apply_*` access.
pub use dispatch::{ApplyFn, default_apply_registry};
pub use effects::{MlsEffect, ProjectionEffect};
pub(crate) use effects::{ObjectLifecycleTransition, SpaceContainerLifecycleTransition};
pub(crate) use message_helpers::*;
// Spec T07 fanout window const is `pub`.
pub use patch_helpers::REALM_DESTROY_FANOUT_WINDOW_DAYS;
pub(crate) use patch_helpers::*;
// `validate_join_policy_payload` is `pub` (out-of-module reference).
pub use policy_validation::validate_join_policy_payload;
pub(crate) use policy_validation::*;
pub use projection_state::ProjectionState;
// `space_container_id_from_payload` is private to the crate but used by
// sibling `apply_*` modules via `super::*`.
pub(crate) use projections::space_container_id_from_payload;
pub use projections::{
    AppletProjection, CapabilityDerivedState, ChildScopePolicy, CircleLifecycleState,
    CircleProjection, DocumentVersionProjection, ErasureReceiptRecord, FanoutPeerStatus,
    InviteProjection, KeyPackageLifetime, MessageState, MlsCommitEpoch, MlsCommitEpochKey,
    MlsKeyPackage, MlsRemoveObligation, MlsWelcome, MlsWelcomeQueueKey, MorphProjection,
    ObjectLifecycleState, PinProjection, PollOptionState, PollState, ProjectedMessageView,
    PushRouteCellValue, PushRouteSubject, ReactionState, ReadMarkerState,
    RealmInheritancePolicyState, RealmLinkState, RealmPolicyServerConfig, RedactionCellValue,
    RsvpProjection, SolandAgentProjection, SolandMembershipState, SolandRealmState,
    SolandRelationState, SpaceContainerLifecycleState, SpaceContainerProjection, StrandProjection,
};

#[cfg(test)]
mod tests;
