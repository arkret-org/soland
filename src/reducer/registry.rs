//! ReducerKind trait + canonical kind registry.
//!
//! This is **soland's reducer-internal projection layer**. It drives the
//! local `ProjectionState` from durable Event Envelopes; its
//! `(space_id, kind, subject?)` model is a reducer-internal projection
//! key, not a wire concept. Subject is derived from typed payload fields
//! per the spec event-kind-registry's `cell_subject`. The full
//! Move/Anchor/Lattice runtime (per-cell Lattice join over Anchor
//! frontier) is tracked separately as Tier 2.6 / root C10.B; until that
//! lands, this reducer remains the active projection driver.
//!
//! Design: each canonical Contrix event kind is represented as a
//! `Box<dyn ReducerKind>` registered in `ReducerRegistry`. The dispatcher
//! looks up the trait object by `&'static str` kind id and delegates
//! `subject_for_event` (per-subject projection key derivation) and `project`
//! (state mutation) to it. Component metadata (`component_type` /
//! `component_version` / `criticality`) is exposed via
//! [`ReducerKind::component`] so unknown kinds are handled by their
//! declared criticality.
//!
//! Per-kind impls live in `src/reducer/kinds/<domain>.rs`. Each domain
//! file pulls in the shared `singleton_state_kind!` / `non_state_kind!` /
//! `legacy_membership_kind!` / `consent_kind!` macros from
//! `kinds/mod.rs`.

use std::collections::BTreeMap;

use contrix_sdk::Operation;

use crate::hlc::ServerHlc;
use crate::kinds;
use crate::reducer::{ProjectionEffect, ProjectionState};

/// Cell-cardinality declared by a `ReducerKind` (corresponds to the
/// contrix-spec event-kind-registry's `cell_subject` shape).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateCardinality {
    /// One projection slot per `(space_id, kind)`. Subject is empty.
    Singleton,
    /// One projection slot per `(space_id, kind, subject)`; subject is
    /// derived from the typed payload field declared in the spec
    /// registry's `cell_subject`.
    PerSubject,
    /// Not a state-bearing event — no slot, no subject. The `project`
    /// method is still called to update non-state projection
    /// (e.g. message timeline).
    None,
}

/// Receiver behaviour when an unknown component_type/version is seen
/// (matches the `criticality` field in the contrix-spec registry).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Criticality {
    /// MUST fail closed (schema_violation / soft_fail / quarantine
    /// depending on context).
    Required,
    /// MAY warn and skip; do not advance reducer state for this event.
    Optional,
    /// Silently drop; do not advance reducer state.
    Ignore,
}

/// Stable identification of the logical cell this `ReducerKind` drives.
/// Multiple kinds operating on the same cell (paired kinds, e.g.
/// `cx.capability.grant` + `cx.capability.revoke`) MUST share
/// `component_type` so the reducer treats them as supersedes on the
/// same cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComponentDescriptor {
    /// Stable URI in the `cx.component.<facet-path>.v<n>` namespace.
    pub component_type: &'static str,
    /// Monotonic version within the same `component_type`.
    pub component_version: u32,
    /// Receiver behaviour for unknown component_type/version.
    pub criticality: Criticality,
}

/// Errors a [`ReducerKind`] can raise during subject derivation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReducerKindError {
    /// The event payload is missing a required typed field used to derive
    /// the cell subject (e.g. `payload.actor_id` on `cx.member.state`).
    MissingSubjectField {
        kind: &'static str,
        field: &'static str,
    },
}

impl std::fmt::Display for ReducerKindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReducerKindError::MissingSubjectField { kind, field } => {
                write!(f, "{kind} requires payload.{field}")
            }
        }
    }
}

impl std::error::Error for ReducerKindError {}

/// One canonical Contrix event kind implementation.
///
/// Implementations are stateless trait objects held in
/// [`ReducerRegistry`]; the dispatcher passes `&mut ProjectionState`
/// when a kind needs to mutate projection.
pub trait ReducerKind: Send + Sync {
    /// Stable canonical kind id (e.g. `cx.message.create`).
    fn kind(&self) -> &'static str;

    /// State cardinality for this kind. Used by the dispatcher to decide
    /// whether to derive a subject before keying the projection slot.
    fn cardinality(&self) -> StateCardinality;

    /// Component metadata for forward-compat handling.
    fn component(&self) -> ComponentDescriptor;

    /// Derive the cell subject for an event. Returns:
    ///
    /// - `Ok(None)` for `StateCardinality::Singleton` and
    ///   `StateCardinality::None` (no per-event subject).
    /// - `Ok(Some(subject))` for `StateCardinality::PerSubject` — the
    ///   value derived from the typed payload field.
    /// - `Err(_)` if the typed payload field is missing.
    ///
    /// Default impl returns `Ok(None)` — singleton / non-state kinds get
    /// it for free; per-subject kinds MUST override.
    fn subject_for_event(
        &self,
        _operation: &Operation,
    ) -> Result<Option<String>, ReducerKindError> {
        Ok(None)
    }

    /// Apply the operation to projection state. The dispatcher ensures
    /// `subject_for_event` succeeded before this is called.
    fn project(
        &self,
        operation: &Operation,
        state: &mut ProjectionState,
        hlc: &ServerHlc,
    ) -> ProjectionEffect;
}

/// Canonical-kind registry. Holds one `Box<dyn ReducerKind>` per
/// registered `&'static str` kind id; lookup is `O(log n)` over the
/// `BTreeMap`.
pub struct ReducerRegistry {
    kinds: BTreeMap<&'static str, Box<dyn ReducerKind>>,
}

impl ReducerRegistry {
    /// Build a registry pre-populated with every kind soland's reducer
    /// currently projects, plus stubs for spec kinds whose subject
    /// derivation is wired up but whose `project` method is a no-op
    /// pending T1-3.
    pub fn new() -> Self {
        use crate::reducer::kinds::*;
        let mut registry = Self { kinds: BTreeMap::new() };

        // ── Active projecting kinds (T1-1 migration) ─────────────────
        registry.register(MessageCreate);
        registry.register(MessageRevise);
        registry.register(MessageRedact); // shared slot via redacts target
        registry.register(Redaction); // generic cx.redaction
        registry.register(ReactionAdd);
        registry.register(ReactionRemove);
        registry.register(ReadMarker);
        registry.register(EntityCreate);
        registry.register(EntityUpdate);
        registry.register(EntityDelete);
        registry.register(FieldPositionMove);
        registry.register(FieldPositionReorder);
        registry.register(RelationCreate);
        registry.register(RelationUpdate);
        registry.register(RelationDelete);
        registry.register(ContainerMoveItem);
        registry.register(ContainerRebalance);
        registry.register(MembershipJoin);
        registry.register(MembershipLeave);
        registry.register(MembershipKick);
        registry.register(MembershipBan);
        registry.register(MembershipUnban);
        registry.register(MembershipKnock);
        registry.register(SpaceCreate);
        registry.register(SpaceUpdate);
        registry.register(SpaceDestroy);

        // ── Per-facet space policy state events (T1-3 will land
        //    project() bodies; subject derivation already wired). ────────
        registry.register(SpacePolicy);
        registry.register(SpaceJoinRule);
        registry.register(SpaceHistoryVisibility);
        registry.register(SpaceDiscovery);
        registry.register(SpacePolicyServer);
        registry.register(SpacePolicyComponents);
        registry.register(SpaceHistorySharingPolicy);
        registry.register(SpaceAssetPrivacyPolicy);
        registry.register(SpaceReadReceiptPolicy);
        registry.register(SpaceModerationPolicy);
        registry.register(SpacePlaintextVisibleServices);
        registry.register(SpaceMediaService);
        registry.register(SpaceSchema);
        registry.register(SpaceInheritancePolicy);
        registry.register(SpaceArchive);
        registry.register(SpaceFreeze);
        registry.register(SpaceTombstone);
        // Holder-private consent (cell or-set, see consent-model.md).
        registry.register(ConsentGrant);
        registry.register(ConsentRevoke);
        // Member state: cx.member.state typed kind (active);
        // legacy cx.membership.* kinds above remain the projection path
        // until T1-3 swaps them for cx.member.state.
        registry.register(MemberState);

        registry
    }

    fn register(&mut self, kind: impl ReducerKind + 'static) {
        let id = kind.kind();
        if self.kinds.contains_key(id) {
            panic!("duplicate ReducerKind registration: {id}");
        }
        self.kinds.insert(id, Box::new(kind));
    }

    /// Look up a kind by its canonical id.
    pub fn lookup(&self, kind: &str) -> Option<&dyn ReducerKind> {
        self.kinds.get(kind).map(|boxed| boxed.as_ref())
    }

    /// Number of registered kinds.
    pub fn len(&self) -> usize {
        self.kinds.len()
    }

    /// True when the registry has no kinds (only meaningful for tests).
    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty()
    }

    /// Iterate registered `&'static str` kind ids in canonical sort order.
    pub fn kinds(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.kinds.keys().copied()
    }

    /// Dispatch an operation through the registry: derive subject, then
    /// call `project()`. Returns `Ignored` for kinds that fall outside
    /// the registry (matches the legacy `ProjectionState::apply` fallback).
    pub fn project(
        &self,
        operation: &Operation,
        state: &mut ProjectionState,
        hlc: &ServerHlc,
    ) -> ProjectionEffect {
        let Some(kind) = kinds::canonical_kind_for_operation(operation) else {
            return ProjectionEffect::Ignored;
        };
        let Some(reducer) = self.lookup(kind) else {
            return ProjectionEffect::Ignored;
        };
        // Subject derivation runs before project so a missing required
        // payload field surfaces as an explicit error rather than a silent
        // miss-keyed slot. For T1-1 the result is currently advisory —
        // T1-3 will wire it into the actual slot keying for state events.
        if let Err(err) = reducer.subject_for_event(operation) {
            tracing::warn!(
                kind = kind,
                operation_id = operation.operation_id.as_str(),
                error = %err,
                "reducer subject derivation failed",
            );
            return ProjectionEffect::Ignored;
        }
        reducer.project(operation, state, hlc)
    }
}

impl Default for ReducerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ReducerRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReducerRegistry").field("kind_count", &self.kinds.len()).finish()
    }
}

/// Helper: read an optional string field from `payload`, returning
/// `Some(_)` only if the field is present and a non-empty string. Used by
/// per_subject kinds to derive subject from typed payload fields.
pub(crate) fn optional_payload_string(
    operation: &Operation,
    field: &str,
) -> Option<String> {
    operation
        .payload
        .get(field)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_unique_kinds() {
        let registry = ReducerRegistry::new();
        // Sanity: every registered kind has a non-empty id and a stable
        // ComponentDescriptor; no two share the same kind id (panics in
        // `register` would have caught duplicates already).
        let mut seen = std::collections::HashSet::new();
        for kind_id in registry.kinds() {
            assert!(!kind_id.is_empty(), "empty kind id");
            assert!(seen.insert(kind_id), "duplicate kind id: {kind_id}");
        }
        assert!(registry.len() > 20, "expected ≥ 20 registered kinds");
    }

    #[test]
    fn registry_includes_post_phase_1_5_kinds() {
        let registry = ReducerRegistry::new();
        // Per-facet space split.
        assert!(registry.lookup("cx.space.policy").is_some());
        assert!(registry.lookup("cx.space.media_service").is_some());
        assert!(registry.lookup("cx.space.inheritance_policy").is_some());
        assert!(registry.lookup("cx.space.archive").is_some());
        assert!(registry.lookup("cx.space.tombstone").is_some());
        // Read receipt disclosure policy (spec discovery/read-receipts.md §2.5).
        assert!(registry.lookup("cx.space.read_receipt_policy").is_some());
        // Holder-private consent (cell or-set).
        assert!(registry.lookup("cx.consent.grant").is_some());
        assert!(registry.lookup("cx.consent.revoke").is_some());
        // Move/Anchor/Lattice rebase removed cx.space.host / cx.space.host.transfer
        // (anchorer cell now governs Anchor signing); they MUST NOT be registered.
        assert!(registry.lookup("cx.space.host").is_none());
        assert!(registry.lookup("cx.space.host.transfer").is_none());
    }

    #[test]
    fn registry_rejects_legacy_aggregate_kinds() {
        let registry = ReducerRegistry::new();
        // Spec hard-removed these aggregate kinds; soland MUST NOT register them.
        assert!(registry.lookup("cx.space.policy.set").is_none());
        assert!(registry.lookup("cx.space.lifecycle.set").is_none());
    }
}
