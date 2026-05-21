//! Concrete `LatticeKind` impls + factory (SDK re-export shim).
//!
//! All `LatticeKind` impls and the [`default_lattice_registry`] /
//! [`build_sdk_cell_registry`] factories moved to
//! `contrix_sdk::lattice_registry` (SDK-8). This module is a thin
//! re-export shim — existing callers
//! (`crate::reducer::lattice_kinds::default_lattice_registry()`,
//! `build_sdk_cell_registry()`) keep working without changes.
//!
//! The artifact drift tests at the bottom stay here because they
//! consult `crate::artifacts::*` which lives in soland.

pub use contrix_sdk::lattice_registry::{
    build_sdk_cell_registry, default_lattice_registry, lattice_bindings_for_sdk_registry,
};

// Re-export the individual cell-family impl structs as well so any
// soland test that referenced them by name (e.g. `ViewCreate`,
// `ViewUpdate`, `ViewReconcile` mentioned in `routing/events/operations.rs`
// comments) continues to compile.
pub use contrix_sdk::lattice_registry::{
    AccountStatus, AnchorerCell, CapabilityDelegate, CapabilityDerived, CapabilityGrant,
    ConsentGrant, CoveredFrontier, CrossSigningPublish, CrossSigningReset, DeviceAuthorized,
    DeviceListUpdate, FlowPosition, MemberState, MimiRoomBinding, MlsEpoch, PlaceParent,
    PolicyRule, ProfileCreate, SessionGrant, SpaceArchive, SpaceAssetPrivacyPolicy, SpaceChild,
    SpaceCreate, SpaceDestroy, SpaceDiscovery, SpaceFreeze, SpaceHistorySharingPolicy,
    SpaceHistoryVisibility, SpaceInheritancePolicy, SpaceJoinRule, SpaceMediaService,
    SpaceModerationPolicy, SpaceOrganization, SpaceParent, SpacePlaintextVisibleServices,
    SpacePolicy, SpacePolicyComponents, SpacePolicyServer, SpaceReadReceiptPolicyLattice,
    SpaceSchema, SpaceTombstone, SpaceUpgrade, ViewCreate, ViewReconcile, ViewUpdate,
};

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use contrix_sdk::lattice::LatticeKind as SdkLatticeKind;
    use contrix_sdk::state_res::BottomMode;

    use super::*;
    /// Drift guard between the SDK-defined cell-family registry and
    /// soland's artifact-registry view of the spec event-kind
    /// registry. Both sources MUST agree on lattice and bottom policy
    /// for every cell family.
    #[test]
    fn artifact_cell_family_lattice_and_bottom_drift_test() {
        let registry = default_lattice_registry();
        for binding in crate::artifacts::cell_family_bindings() {
            let kind = registry
                .lookup(&binding.cell_family)
                .unwrap_or_else(|| panic!("missing artifact cell family {}", binding.cell_family));
            assert_eq!(
                kind.lattice().as_wire_str(),
                binding.lattice,
                "{} lattice drifted from event-kind registry",
                binding.cell_family
            );
            assert_eq!(
                kind.bottom_policy().as_str(),
                binding.bottom,
                "{} bottom policy drifted from event-kind registry",
                binding.cell_family
            );
        }
    }

    /// Drift guard: every active durable `event_kind` declared in the
    /// spec registry maps to the cell family the artifact registry
    /// says it does.
    #[test]
    fn artifact_event_kind_to_family_drift_test() {
        let registry = default_lattice_registry();
        for binding in crate::artifacts::active_durable_cell_bindings() {
            let kind = registry
                .lookup_for_event_kind(&binding.event_kind)
                .unwrap_or_else(|| {
                    panic!(
                        "missing artifact event_kind mapping {} -> {}",
                        binding.event_kind, binding.cell_family
                    )
                });
            assert_eq!(
                kind.cell_family(),
                binding.cell_family,
                "{} event_kind mapped to wrong cell family",
                binding.event_kind
            );
        }
    }

    /// Drift guard: the SDK bulk-registration binding table
    /// ([`lattice_bindings_for_sdk_registry`]) MUST cover every family
    /// the artifact registry knows about, with matching lattice +
    /// bottom mode. This is what drives `build_sdk_cell_registry()` →
    /// `verify_move` / `apply_anchor`.
    #[test]
    fn sdk_lattice_binding_table_covers_artifact_families() {
        let bindings = lattice_bindings_for_sdk_registry()
            .into_iter()
            .map(|(family, lattice, bottom)| (family, (lattice.as_wire_str(), bottom)))
            .collect::<BTreeMap<_, _>>();
        for binding in crate::artifacts::cell_family_bindings() {
            let (lattice, bottom) = bindings
                .get(binding.cell_family.as_str())
                .unwrap_or_else(|| panic!("missing SDK binding for {}", binding.cell_family));
            assert_eq!(*lattice, binding.lattice);
            assert_eq!(
                match bottom {
                    BottomMode::Reject => "reject",
                    BottomMode::Expose => "expose",
                },
                binding.bottom
            );
        }
    }

    /// Sanity: the SDK-defined registry covers every spec-normative
    /// cell family. Locked at 75 after the R1.2 Realm-rename + new
    /// flow-facet families landed in the spec event-kind registry —
    /// see the matching assertion in
    /// `contrix-rust-sdk/crates/sdk/src/lattice_registry.rs` for the
    /// breakdown. Bump deliberately when a new spec family lands.
    #[test]
    fn default_registry_still_covers_every_spec_family() {
        let registry = default_lattice_registry();
        assert_eq!(registry.len(), 71);
    }

    #[test]
    fn sdk_lattice_bindings_include_registry_fix_families() {
        let bindings = lattice_bindings_for_sdk_registry();
        let binding_for = |family: &str| {
            bindings
                .iter()
                .find(|(registered_family, _, _)| *registered_family == family)
                .copied()
                .unwrap_or_else(|| panic!("missing SDK lattice binding for {family}"))
        };

        let (_, publish_kind, publish_bottom) =
            binding_for("cx.component.cross_signing.publish.v1");
        assert_eq!(publish_kind, SdkLatticeKind::CasRegister);
        assert_eq!(publish_bottom, BottomMode::Reject);

        let (_, reset_kind, reset_bottom) = binding_for("cx.component.cross_signing.reset.v1");
        assert_eq!(reset_kind, SdkLatticeKind::OrderedLog);
        assert_eq!(reset_bottom, BottomMode::Reject);
    }
}
