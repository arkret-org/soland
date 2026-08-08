//! Concrete `LatticeKind` impls + factory (SDK re-export shim).
//!
//! All `LatticeKind` impls and the [`default_lattice_registry`] /
//! [`build_sdk_cell_registry`] factories moved to
//! `arkret_lattice_registry` (SDK-8). This module is a thin
//! re-export shim. Existing callers
//! (`crate::reducer::lattice_kinds::default_lattice_registry()`,
//! `build_sdk_cell_registry()`) keep working without changes.

use std::collections::BTreeSet;

use arkret_identifiers::{CellRef, RealmId};
// Re-export the individual cell-family impl structs as well so any
// soland test that referenced them by name (e.g. `ViewCreate`,
// `ViewUpdate`, `ViewReconcile` mentioned in `routing/events/operations.rs`
// comments) continues to compile.
pub use arkret_lattice_registry::{
    AccountStatus, AgentKey, AgentStatus, CallState, CallSummary, CapabilityDerived,
    CapabilityGrant, CircleCreate, CircleMember, CircleTombstone, ConsentGrant, ContactFactLog,
    DeviceAuthorized, DeviceListUpdate, DirectConversationBinding, KeyBackupActiveSeries,
    MemberIdentityLattice as MemberIdentity, MemberState, MimiRoomBinding, MlsEpoch, MorphStage,
    NotaryCell, PolicyRule, ProfileCreate, RealmArchive, RealmAssetPrivacyPolicy, RealmCreate,
    RealmDeliveryBindingPolicy, RealmDestroy, RealmDisappearingPolicy, RealmDiscovery, RealmFreeze,
    RealmHistorySharingPolicy, RealmHistoryVisibility, RealmInheritancePolicy, RealmJoinRule,
    RealmLink, RealmMediaService, RealmModerationPolicy, RealmOrganization,
    RealmPlaintextVisibleServices, RealmPolicy, RealmPolicyBundle, RealmPolicyServer,
    RealmPreviewPolicy, RealmReadReceiptPolicy, RealmReducerProfile, RealmSchema,
    RealmSearchPolicy, RealmTombstone, SpaceParent, StrandPosition, StrandStage, ViewCreate,
    ViewReconcile, ViewUpdate, build_sdk_cell_registry, default_lattice_registry,
    lattice_bindings_for_sdk_registry,
};
use arkret_lattice_registry::{
    ContractRegistryError, ResolvedFsmContract, canonical_fsm_contracts,
    try_build_sdk_cell_registry,
};
use arkret_state::lattice::LatticeKind;
use arkret_state::state::{BottomMode, CellRegistry, MemoryCellRegistry};

/// Closed shared-FSM family count in the canonical v1 contract.
pub const CANONICAL_SHARED_FSM_FAMILY_COUNT: usize = 17;

/// Resolve and validate the one shared SDK registry used by every Soland
/// state-resolution path.
///
/// This is a startup gate, not a second FSM table: family names, states and
/// transitions all come from the SDK's embedded canonical contract.
pub fn try_build_validated_sdk_cell_registry() -> Result<MemoryCellRegistry, ContractRegistryError>
{
    let contracts = canonical_fsm_contracts()?;
    validate_canonical_fsm_exact_closure(&contracts)?;
    let registry = try_build_sdk_cell_registry()?;
    let realm = RealmId::new("ak:realm:AS6APqej-Rh7QFhSceTHVNyMDqcQte46AfERL21Hkt5_".to_owned())
        .map_err(|error| ContractRegistryError::Invalid(error.to_string()))?;
    for contract in &contracts {
        let cell = CellRef::new(format!("ak:cell:{}:startup-probe", contract.cell_family))
            .map_err(|error| ContractRegistryError::Invalid(error.to_string()))?;
        let binding = registry.resolve(&realm, &cell).map_err(|error| {
            ContractRegistryError::Invalid(format!(
                "shared FSM {} is not resolvable at startup: {error}",
                contract.cell_family
            ))
        })?;
        if binding.lattice.kind() != LatticeKind::Fsm || binding.bottom_mode != BottomMode::Reject {
            return Err(ContractRegistryError::Invalid(format!(
                "shared FSM {} resolved with {:?}/{:?}, expected fsm/reject",
                contract.cell_family,
                binding.lattice.kind(),
                binding.bottom_mode
            )));
        }
    }
    Ok(registry)
}

fn validate_canonical_fsm_exact_closure(
    contracts: &[ResolvedFsmContract],
) -> Result<(), ContractRegistryError> {
    if contracts.len() != CANONICAL_SHARED_FSM_FAMILY_COUNT {
        return Err(ContractRegistryError::Invalid(format!(
            "canonical shared FSM closure has {} families, expected {}",
            contracts.len(),
            CANONICAL_SHARED_FSM_FAMILY_COUNT
        )));
    }
    let contract_families = contracts
        .iter()
        .map(|contract| contract.cell_family.as_str())
        .collect::<BTreeSet<_>>();
    if contract_families.len() != contracts.len() {
        return Err(ContractRegistryError::Invalid(
            "canonical shared FSM closure contains duplicate families".to_owned(),
        ));
    }
    if contract_families
        .iter()
        .any(|family| !family.starts_with("ak.component."))
    {
        return Err(ContractRegistryError::Invalid(
            "actor-private or non-component family leaked into shared FSM closure".to_owned(),
        ));
    }
    let binding_families = lattice_bindings_for_sdk_registry()
        .into_iter()
        .filter_map(|(family, kind, _)| (kind == LatticeKind::Fsm).then_some(family))
        .collect::<BTreeSet<_>>();
    if binding_families != contract_families {
        return Err(ContractRegistryError::Invalid(format!(
            "canonical FSM contracts and generated lattice bindings differ: contracts={contract_families:?}, bindings={binding_families:?}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_fsm_startup_gate_is_an_exact_18_family_closure() {
        let contracts = canonical_fsm_contracts().unwrap();
        validate_canonical_fsm_exact_closure(&contracts).unwrap();
        try_build_validated_sdk_cell_registry().unwrap();
    }

    #[test]
    fn canonical_fsm_startup_gate_fails_closed_on_incomplete_or_duplicate_closure() {
        let contracts = canonical_fsm_contracts().unwrap();
        let mut incomplete = contracts.clone();
        incomplete.pop();
        assert!(validate_canonical_fsm_exact_closure(&incomplete).is_err());

        let mut duplicate = contracts;
        duplicate.push(duplicate[0].clone());
        assert!(validate_canonical_fsm_exact_closure(&duplicate).is_err());
    }
}
