//! Per-cell-family `LatticeKind` registry.
//!
//! This module owns the projection-routing trait in soland.
//! `ProjectionState::apply()` does direct match-on-canonical-kind dispatch to
//! inline projection helpers, and model lookups (subject derivation, lattice
//! resolution, bottom policy) all run through [`LatticeKind`] /
//! [`LatticeRegistry`] in this module.
//!
//! Concrete `LatticeKind` impls live in [`super::lattice_kinds`]; the
//! [`super::lattice_kinds::default_lattice_registry`] factory pre-registers
//! every spec-declared cell family. The Move/Anchor receive pipeline
//! (`POST /api/v1/moves` / `POST /api/v1/anchors`) consults
//! [`super::lattice_kinds::build_sdk_cell_registry`] (an
//! `SDK MemoryCellRegistry`) to drive `verify_move` and `apply_anchor`
//! per-cell-family lattice resolution.
//!
//! Common metadata types ([`StateCardinality`], [`Criticality`],
//! [`ComponentDescriptor`]) are kept here because durable Event projection
//! and the Move/Anchor pipeline both report them.

use std::collections::BTreeMap;

/// Cell-cardinality declared by a [`LatticeKind`] — corresponds to the
/// contrix-spec event-kind-registry's `cell_subject` shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateCardinality {
    /// One projection slot per `(space_id, cell_family)`. Subject empty.
    Singleton,
    /// One projection slot per `(space_id, cell_family, subject)`; subject
    /// is derived from the typed effect-payload field declared in the spec
    /// registry's `cell_subject`.
    PerSubject,
    /// Not a state-bearing event — no slot, no subject.
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

/// Stable identification of the logical cell this [`LatticeKind`] drives.
/// Multiple kinds operating on the same cell (paired kinds, e.g.
/// `cx.capability.grant` + `cx.capability.revoke`) MUST share
/// `component_type` so the receiver treats them as supersedes on the
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

/// Bottom-handling policy for a cell family.
///
/// - `Reject`: when the Lattice's `join` returns a structured `Bottom`, the receiver MUST
///   quarantine the resolved cell and emit `bottom_diagnostics` events. Lattice queries on this
///   cell return `bottom` rather than choosing a winner. This is the v1 default for safety-critical
///   cells (capability, consent, anchorer).
/// - `Expose`: callers are expected to render the multi-value set directly (e.g. UI shows "two
///   concurrent edits, please reconcile" rather than blocking). Suitable for advisory cells (Flow
///   titles, user profile fields).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BottomPolicy {
    Reject,
    Expose,
}

impl BottomPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::Expose => "expose",
        }
    }
}

/// Errors a [`LatticeKind`] can raise during subject derivation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LatticeKindError {
    /// The Move's effects[] is missing the typed field used to derive the
    /// cell subject (e.g. `payload.flow_id` for a flow-position cell).
    MissingSubjectField {
        cell_family: &'static str,
        field: &'static str,
    },
    /// The cell_family declared by a Move effect doesn't match this
    /// `LatticeKind`. The dispatcher MUST route to a different impl.
    UnknownCellFamily {
        observed: String,
        declared: &'static str,
    },
}

impl std::fmt::Display for LatticeKindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSubjectField { cell_family, field } => {
                write!(
                    f,
                    "{cell_family} requires effect field `{field}` for cell subject"
                )
            }
            Self::UnknownCellFamily { observed, declared } => {
                write!(
                    f,
                    "cell_family `{observed}` is not handled by this LatticeKind ({declared})"
                )
            }
        }
    }
}

impl std::error::Error for LatticeKindError {}

/// One canonical Contrix cell-family implementation.
///
/// Each `LatticeKind` owns one `cell_family` (e.g.
/// `cx.component.consent.v1`), declares the lattice algebra that resolves
/// it (one of the six spec-normative lattices), and exposes subject-
/// derivation + post-resolution validation hooks. Move/Anchor receive
/// pipeline iterates anchored Moves, groups effects by `(cell_family,
/// cell_subject)`, and dispatches to the matching `LatticeKind` for
/// per-cell `Lattice::join`.
pub trait LatticeKind: Send + Sync {
    /// Stable cell-family id (e.g. `cx.component.consent.v1`). Move
    /// effects route to this `LatticeKind` when the effect's `cell` ref
    /// has this family path.
    fn cell_family(&self) -> &'static str;

    /// Which of the six normative lattices drives this family. The SDK's
    /// `contrix-lattice` crate provides the runtime impl (`OrSet`,
    /// `CasRegister`, `Counter`, `Fsm`, `MvRegister`, `OrderedLog`).
    fn lattice(&self) -> contrix_sdk::lattice::LatticeKind;

    /// `reject` → quarantine on Bottom (default, safety-critical cells);
    /// `expose` → render multi-value directly (advisory cells).
    fn bottom_policy(&self) -> BottomPolicy {
        BottomPolicy::Reject
    }

    /// Component metadata for extension handling.
    fn component(&self) -> ComponentDescriptor;

    /// Derive the cell subject from a Move effect's typed fields. Returns:
    /// - `Ok(None)` if the cell family is a singleton (one cell per space, e.g.
    ///   `cx.component.space.policy.v1`) — the subject is empty per spec convention.
    /// - `Ok(Some(subject))` for per-subject cells; subject is the typed field value (or composite
    ///   hash for multi-component subjects).
    /// - `Err(_)` if the required typed field is missing on the effect.
    fn subject_for_effect(
        &self,
        _effect_payload: &serde_json::Value,
    ) -> Result<Option<String>, LatticeKindError> {
        Ok(None)
    }

    /// Durable Contrix event kinds (`cx.<facet>.<verb>`) whose
    /// projection feeds **this** cell family. Empty by default — only the
    /// cell families that have a 1:N event-kind → cell-family mapping
    /// declare it (mostly the `cx.space.<facet>` lifecycle cells, the
    /// `cx.message.*` / `cx.reaction.*` projection cells, and the
    /// `cx.consent.*` / `cx.member.*` state cells). The
    /// [`LatticeRegistry`] inverts this declaration into a global event-kind
    /// → `LatticeKind` index used by [`LatticeRegistry::lookup_for_event_kind`]
    /// to drive `ProjectionState::apply_via_lattice_registry`.
    ///
    /// SDK gap: a sibling `event_kinds()` is planned directly on
    /// `contrix_sdk::lattice::LatticeKind`. Once that lands we can
    /// collapse this declaration with the SDK side; until then this
    /// method shadows the spec mapping inside soland.
    fn event_kinds(&self) -> &'static [&'static str] {
        &[]
    }
}

/// Canonical-cell-family registry. Holds one `Box<dyn LatticeKind>` per
/// registered `cell_family` string; lookup is `O(log n)` over a `BTreeMap`.
///
/// The Move/Anchor receive path iterates Anchor frontier Moves, routes
/// each effect to the matching `LatticeKind`, and applies `Lattice::join`
/// over the per-cell anchored ops list.
///
/// The inverted `event_kind -> cell_family` index is built from each impl's
/// [`LatticeKind::event_kinds`] declaration. Durable Events look up the
/// owning cell family before the inline projection dispatcher applies the
/// cache update.
#[derive(Default)]
pub struct LatticeRegistry {
    families: BTreeMap<&'static str, Box<dyn LatticeKind>>,
    /// Inverted index: durable event_kind → cell_family. Filled at
    /// [`Self::register`] time; collisions are tolerated (last-writer-wins,
    /// matching the families map). For most kinds this is a single mapping
    /// (`cx.consent.grant → cx.component.consent.grant.v1`), but space
    /// lifecycle / membership both fan one event into one cell family
    /// each.
    event_kind_index: BTreeMap<&'static str, &'static str>,
}

impl LatticeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a cell-family impl. Subsequent inserts on the same family
    /// id replace the existing impl (last-write-wins).
    pub fn register<K>(&mut self, kind: K)
    where
        K: LatticeKind + 'static,
    {
        // Snapshot the event_kinds declaration BEFORE moving the impl into
        // the families map — the inverted index uses the same `&'static str`
        // entries so lookups are O(log n) without re-borrowing through the
        // boxed trait object.
        let family = kind.cell_family();
        for ek in kind.event_kinds() {
            self.event_kind_index.insert(*ek, family);
        }
        self.families.insert(family, Box::new(kind));
    }

    /// Look up the impl for a cell_family, returning `None` for unknown
    /// families (caller decides Required / Optional / Ignore handling per
    /// the family's `Criticality` declaration).
    pub fn lookup(&self, cell_family: &str) -> Option<&dyn LatticeKind> {
        self.families.get(cell_family).map(|boxed| boxed.as_ref())
    }

    /// Look up the [`LatticeKind`] that owns the given durable
    /// event_kind (e.g. `cx.consent.grant`). Returns `None` for events
    /// that have no cell-family mapping declared (most messaging /
    /// reaction / entity / relation events fall here; those still flow
    /// through the inline durable-Event projection cache).
    pub fn lookup_for_event_kind(&self, event_kind: &str) -> Option<&dyn LatticeKind> {
        let family = self.event_kind_index.get(event_kind)?;
        self.lookup(family)
    }

    /// Number of distinct durable event kinds mapped through the
    /// registry. Used by tests + diagnostic logs.
    pub fn event_kind_mappings(&self) -> usize {
        self.event_kind_index.len()
    }

    /// Number of registered families. Used by tests to confirm migration
    /// progress against the spec's cell-family target.
    pub fn len(&self) -> usize {
        self.families.len()
    }

    pub fn is_empty(&self) -> bool {
        self.families.is_empty()
    }
}

#[cfg(test)]
mod lattice_kind_scaffold_tests {
    use super::*;

    /// Smoke test: a tiny `LatticeKind` impl plugs into the registry and
    /// is reachable by `cell_family` lookup. Confirms the trait shape is
    /// consistent with the SDK's `contrix-lattice` `LatticeKind` enum.
    #[test]
    fn registry_register_and_lookup_works() {
        struct ConsentCell;
        impl LatticeKind for ConsentCell {
            fn cell_family(&self) -> &'static str {
                "cx.component.consent.v1"
            }
            fn lattice(&self) -> contrix_sdk::lattice::LatticeKind {
                contrix_sdk::lattice::LatticeKind::OrSet
            }
            fn bottom_policy(&self) -> BottomPolicy {
                BottomPolicy::Reject
            }
            fn component(&self) -> ComponentDescriptor {
                ComponentDescriptor {
                    component_type: "cx.component.consent.v1",
                    component_version: 1,
                    criticality: Criticality::Required,
                }
            }
        }
        let mut registry = LatticeRegistry::new();
        assert!(registry.is_empty());
        registry.register(ConsentCell);
        assert_eq!(registry.len(), 1);
        let found = registry.lookup("cx.component.consent.v1").unwrap();
        assert_eq!(found.lattice(), contrix_sdk::lattice::LatticeKind::OrSet);
        assert_eq!(found.bottom_policy(), BottomPolicy::Reject);
        assert_eq!(found.bottom_policy().as_str(), "reject");
        assert!(registry.lookup("cx.component.unknown.v1").is_none());
    }

    /// LatticeKindError formats both variants the way log lines + JSON
    /// envelopes downstream consumers expect.
    #[test]
    fn lattice_kind_error_display_is_stable() {
        let err = LatticeKindError::MissingSubjectField {
            cell_family: "cx.component.flow.position.v1",
            field: "flow_id",
        };
        let msg = format!("{err}");
        assert!(msg.contains("cx.component.flow.position.v1"));
        assert!(msg.contains("flow_id"));

        let err = LatticeKindError::UnknownCellFamily {
            observed: "cx.component.unrecognised.v9".to_owned(),
            declared: "cx.component.consent.v1",
        };
        let msg = format!("{err}");
        assert!(msg.contains("cx.component.unrecognised.v9"));
        assert!(msg.contains("cx.component.consent.v1"));
    }
}
