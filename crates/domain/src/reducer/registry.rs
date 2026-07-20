//! Per-cell-family `LatticeKind` registry (SDK re-export shim).
//!
//! The trait + registry types and the spec-normative cell-family
//! bindings moved to `arkret_core::lattice_registry` (SDK-8) so all
//! consumers (soland Move/Seal pipeline, inkson Move pre-check,
//! cotest fixtures) share one canonical registry. This module is a
//! thin re-export shim — existing soland call sites such as
//! `crate::reducer::registry::LatticeKind` keep working without
//! changes.

pub use arkret_lattice_registry::{
    BottomPolicy, ComponentDescriptor, Criticality, LatticeKind, LatticeKindError, LatticeRegistry,
    StateCardinality,
};

#[cfg(test)]
mod lattice_kind_scaffold_tests {
    use super::*;

    /// Smoke test: a tiny `LatticeKind` impl plugs into the registry and
    /// is reachable by `cell_family` lookup. Confirms the SDK trait
    /// surface that soland depends on stays stable.
    #[test]
    fn registry_register_and_lookup_works() {
        struct ConsentCell;
        impl LatticeKind for ConsentCell {
            fn cell_family(&self) -> &'static str {
                "ak.component.consent.v1"
            }
            fn lattice(&self) -> arkret_state::lattice::LatticeKind {
                arkret_state::lattice::LatticeKind::OrSet
            }
            fn bottom_policy(&self) -> BottomPolicy {
                BottomPolicy::Reject
            }
            fn component(&self) -> ComponentDescriptor {
                ComponentDescriptor {
                    component_type: "ak.component.consent.v1",
                    component_version: 1,
                    criticality: Criticality::Required,
                }
            }
        }
        let mut registry = LatticeRegistry::new();
        assert!(registry.is_empty());
        registry.register(ConsentCell);
        assert_eq!(registry.len(), 1);
        let found = registry.lookup("ak.component.consent.v1").unwrap();
        assert_eq!(found.lattice(), arkret_state::lattice::LatticeKind::OrSet);
        assert_eq!(found.bottom_policy(), BottomPolicy::Reject);
        assert_eq!(found.bottom_policy().as_str(), "reject");
        assert!(registry.lookup("ak.component.unknown.v1").is_none());
    }

    #[test]
    fn lattice_kind_error_display_is_stable() {
        let err = LatticeKindError::MissingSubjectField {
            cell_family: "ak.component.strand.position.v1",
            field: "strand_id",
        };
        let msg = format!("{err}");
        assert!(msg.contains("ak.component.strand.position.v1"));
        assert!(msg.contains("strand_id"));

        let err = LatticeKindError::UnknownCellFamily {
            observed: "ak.component.unrecognised.v1".to_owned(),
            declared: "ak.component.consent.v1",
        };
        let msg = format!("{err}");
        assert!(msg.contains("ak.component.unrecognised.v1"));
        assert!(msg.contains("ak.component.consent.v1"));
    }
}
