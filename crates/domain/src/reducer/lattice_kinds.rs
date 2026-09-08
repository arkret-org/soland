//! Canonical shared-FSM registry resolution for Soland state resolution.
//!
//! The `LatticeKind` impls and the registry factories live in
//! `arkret_lattice_registry` (SDK-8); this module owns the startup gate that
//! validates the canonical FSM closure before any resolution path uses it.

use std::collections::BTreeSet;

use arkret_identifiers::{CellRef, RealmId};
pub use arkret_lattice_registry::default_lattice_registry;
use arkret_lattice_registry::{
    ContractRegistryError, ResolvedFsmContract, canonical_fsm_contracts,
    lattice_bindings_for_sdk_registry, try_build_sdk_cell_registry,
};
use arkret_state::lattice::LatticeKind;
use arkret_state::state::{CellRegistry, EventCellBottom, MemoryCellRegistry};

/// Closed shared-FSM family count in the canonical v1 contract.
///
/// v1 has no protocol-native moderation-appeal FSM, so the appeal family is not
/// one of these.
pub const CANONICAL_SHARED_FSM_FAMILY_COUNT: usize = 18;

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
        if binding.lattice.kind() != LatticeKind::Fsm
            || binding.bottom_mode != EventCellBottom::Reject
        {
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
    fn canonical_fsm_startup_gate_is_an_exact_19_family_closure() {
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

    /// A `LatticeKind` impl plugs into the SDK registry and is reachable by
    /// `cell_family` lookup. Pins the SDK trait surface soland depends on.
    #[test]
    fn registry_register_and_lookup_works() {
        use arkret_lattice_registry::{
            ComponentDescriptor, Criticality, EventCellBottom, LatticeRegistry,
        };

        struct ConsentCell;
        impl arkret_lattice_registry::LatticeKind for ConsentCell {
            fn cell_family(&self) -> &'static str {
                "ak.component.consent.v1"
            }
            fn lattice(&self) -> LatticeKind {
                LatticeKind::OrSet
            }
            fn bottom_policy(&self) -> EventCellBottom {
                EventCellBottom::Reject
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
        assert_eq!(found.lattice(), LatticeKind::OrSet);
        assert_eq!(found.bottom_policy(), EventCellBottom::Reject);
        assert_eq!(found.bottom_policy().as_str(), "reject");
        assert!(registry.lookup("ak.component.unknown.v1").is_none());
    }

    #[test]
    fn lattice_kind_error_display_is_stable() {
        use arkret_lattice_registry::LatticeKindError;

        let err = LatticeKindError::MissingSubjectField {
            cell_family: arkret_wire::CellFamilyId::STRAND_POSITION_V1,
            field: "strand_id",
        };
        let msg = format!("{err}");
        assert!(msg.contains(arkret_wire::CellFamilyId::STRAND_POSITION_V1));
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
