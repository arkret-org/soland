//! Canonical shared state-model registry resolution for Soland.

use std::collections::BTreeSet;

use arkret_identifiers::{CellRef, RealmId};
pub use arkret_lattice_registry::default_cell_family_registry;
use arkret_lattice_registry::{
    ContractRegistryError, ResolvedTransitionContract, canonical_transition_contracts,
    state_model_bindings_for_sdk_registry, try_build_sdk_state_registry,
};
use arkret_state::state::MemoryCellStateRegistry;
use arkret_state::state_model::StateModelKind;

pub const CANONICAL_SHARED_TRANSITION_FAMILY_COUNT: usize = 18;

pub fn try_build_validated_sdk_cell_registry()
-> Result<MemoryCellStateRegistry, ContractRegistryError> {
    let contracts = canonical_transition_contracts()?;
    validate_canonical_transition_exact_closure(&contracts)?;
    let registry = try_build_sdk_state_registry()?;
    let realm = RealmId::new("ak:realm:AS6APqej-Rh7QFhSceTHVNyMDqcQte46AfERL21Hkt5_".to_owned())
        .map_err(|error| ContractRegistryError::Invalid(error.to_string()))?;
    for contract in &contracts {
        let cell = CellRef::new(format!("ak:cell:{}:startup-probe", contract.cell_family))
            .map_err(|error| ContractRegistryError::Invalid(error.to_string()))?;
        let binding = arkret_state::state::CellStateRegistry::resolve(&registry, &realm, &cell)
            .map_err(|error| {
                ContractRegistryError::Invalid(format!(
                    "transition contract {} is not resolvable at startup: {error}",
                    contract.cell_family
                ))
            })?;
        if binding.state_model != StateModelKind::SequencedState
            || binding.domain_transition.is_none()
        {
            return Err(ContractRegistryError::Invalid(format!(
                "transition contract {} did not resolve as sequenced_state with a validator",
                contract.cell_family
            )));
        }
    }
    Ok(registry)
}

fn validate_canonical_transition_exact_closure(
    contracts: &[ResolvedTransitionContract],
) -> Result<(), ContractRegistryError> {
    if contracts.len() != CANONICAL_SHARED_TRANSITION_FAMILY_COUNT {
        return Err(ContractRegistryError::Invalid(format!(
            "canonical transition closure has {} families, expected {}",
            contracts.len(),
            CANONICAL_SHARED_TRANSITION_FAMILY_COUNT
        )));
    }
    let contract_families = contracts
        .iter()
        .map(|contract| contract.cell_family.as_str())
        .collect::<BTreeSet<_>>();
    if contract_families.len() != contracts.len()
        || contract_families
            .iter()
            .any(|family| !family.starts_with("ak.component."))
    {
        return Err(ContractRegistryError::Invalid(
            "canonical transition closure is duplicated or contains a non-component family"
                .to_owned(),
        ));
    }
    let binding_families = state_model_bindings_for_sdk_registry()
        .into_iter()
        .filter_map(|(family, execution, model, ..)| {
            (model == StateModelKind::SequencedState
                && execution == arkret_wire::EventCellExecution::Security)
                .then_some(family)
        })
        .collect::<BTreeSet<_>>();
    if binding_families != contract_families {
        return Err(ContractRegistryError::Invalid(format!(
            "transition contracts and generated state-model bindings differ: contracts={contract_families:?}, bindings={binding_families:?}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_transition_startup_gate_is_exact() {
        let contracts = canonical_transition_contracts().unwrap();
        validate_canonical_transition_exact_closure(&contracts).unwrap();
        try_build_validated_sdk_cell_registry().unwrap();
    }

    #[test]
    fn canonical_transition_startup_gate_rejects_incomplete_or_duplicate_closure() {
        let contracts = canonical_transition_contracts().unwrap();
        let mut incomplete = contracts.clone();
        incomplete.pop();
        assert!(validate_canonical_transition_exact_closure(&incomplete).is_err());

        let mut duplicate = contracts;
        duplicate.push(duplicate[0].clone());
        assert!(validate_canonical_transition_exact_closure(&duplicate).is_err());
    }
}
