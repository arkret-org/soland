//! Canonical shared state-model registry resolution for Soland.

use std::collections::BTreeSet;

use arkret_identifiers::{CellRef, RealmId};
pub use arkret_lattice_registry::default_cell_family_registry;
use arkret_lattice_registry::{
    ContractRegistryError, ResolvedTransitionContract, canonical_transition_contracts,
    state_model_bindings_for_sdk_registry, try_build_sdk_state_registry,
};
use arkret_state::state::MemoryCellStateRegistry;

pub fn try_build_validated_sdk_cell_registry()
-> Result<MemoryCellStateRegistry, ContractRegistryError> {
    let contracts = canonical_transition_contracts()?;
    let registry = try_build_sdk_state_registry()?;
    validate_canonical_transition_exact_closure(&contracts, &registry)?;
    Ok(registry)
}

fn validate_canonical_transition_exact_closure(
    contracts: &[ResolvedTransitionContract],
    registry: &MemoryCellStateRegistry,
) -> Result<(), ContractRegistryError> {
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
    let realm = RealmId::new("ak:realm:AS6APqej-Rh7QFhSceTHVNyMDqcQte46AfERL21Hkt5_".to_owned())
        .map_err(|error| ContractRegistryError::Invalid(error.to_string()))?;
    let mut binding_families = BTreeSet::new();
    for (family, execution, model, value_shape, bottom_policy) in
        state_model_bindings_for_sdk_registry()
    {
        let cell = CellRef::new(format!("ak:cell:{family}:startup-probe"))
            .map_err(|error| ContractRegistryError::Invalid(error.to_string()))?;
        let binding = arkret_state::state::CellStateRegistry::resolve(registry, &realm, &cell)
            .map_err(|error| {
                ContractRegistryError::Invalid(format!(
                    "registered family {family} is not resolvable at startup: {error}"
                ))
            })?;
        if binding.state_model != model
            || binding.model.kind() != model
            || binding.execution != execution
            || binding.value_shape != value_shape
            || binding.bottom_policy != bottom_policy
        {
            return Err(ContractRegistryError::Invalid(format!(
                "registered family {family} differs from its canonical binding"
            )));
        }
        if binding.domain_transition.is_some() {
            binding_families.insert(family);
        }
    }
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
        validate_canonical_transition_exact_closure(
            &contracts,
            &try_build_sdk_state_registry().unwrap(),
        )
        .unwrap();
        try_build_validated_sdk_cell_registry().unwrap();
    }

    #[test]
    fn canonical_transition_startup_gate_rejects_incomplete_or_duplicate_closure() {
        let contracts = canonical_transition_contracts().unwrap();
        let mut incomplete = contracts.clone();
        incomplete.pop();
        assert!(
            validate_canonical_transition_exact_closure(
                &incomplete,
                &try_build_sdk_state_registry().unwrap()
            )
            .is_err()
        );

        let mut duplicate = contracts;
        duplicate.push(duplicate[0].clone());
        assert!(
            validate_canonical_transition_exact_closure(
                &duplicate,
                &try_build_sdk_state_registry().unwrap()
            )
            .is_err()
        );
    }
    #[test]
    fn domain_transitions_are_independent_of_the_state_model() {
        use arkret_state::state::{CellStateRegistry, MemoryCellStateRegistry};
        use arkret_state::state_model::StateModelKind;
        use arkret_wire::CellFamilyId;
        let registry: MemoryCellStateRegistry = try_build_validated_sdk_cell_registry().unwrap();
        let realm = RealmId::new("ak:realm:AS6APqej-Rh7QFhSceTHVNyMDqcQte46AfERL21Hkt5_").unwrap();
        for (family, model, transition) in [
            (
                CellFamilyId::REALM_AUTHORITY_ROOT_V1,
                StateModelKind::SequencedState,
                false,
            ),
            (
                CellFamilyId::CAPABILITY_GRANT_V1,
                StateModelKind::SequencedState,
                false,
            ),
            (
                CellFamilyId::REALM_CREATE_V1,
                StateModelKind::SequencedState,
                false,
            ),
            (
                CellFamilyId::MEMBER_STATE_V1,
                StateModelKind::SequencedState,
                true,
            ),
            (
                CellFamilyId::MORPH_LIFECYCLE_V1,
                StateModelKind::CausalRegister,
                true,
            ),
        ] {
            let cell = CellRef::new(format!("ak:cell:{family}:test")).unwrap();
            let binding = registry.resolve(&realm, &cell).unwrap();
            assert_eq!(binding.state_model, model, "{family}");
            assert_eq!(binding.domain_transition.is_some(), transition, "{family}");
        }
    }
}
