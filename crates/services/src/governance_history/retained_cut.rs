use std::collections::{BTreeMap, BTreeSet};

use arkret_models_collaboration::governance_dependencies::{
    GovernanceDependency, GovernanceDependencySelector, governance_attester_evidence_selectors,
    governance_runtime_dependency_selector_coordinates_for_acquisition,
};
use arkret_models_collaboration::history_key::{
    HistoryGovernanceTraversalIntent, HistoryGovernanceTraversalRetention,
};
use arkret_wire::{Event, EventProof, HistoryEffectiveScope, RealmId, Seal, SealBasis};

use super::HistoryPreparationError;

#[derive(Clone, Debug, PartialEq)]
pub struct PreparedRetainedHistoryCut {
    pub realm_id: RealmId,
    pub target_basis: SealBasis,
    pub replay_seals: Vec<Seal>,
    pub replay_events: Vec<Event>,
    pub checkpoint_dependencies: Vec<GovernanceDependency>,
}

fn frontier(detail: impl Into<String>) -> HistoryPreparationError {
    HistoryPreparationError::FrontierUnavailable(detail.into())
}

pub fn prepare_retained_history_cut(
    effective_scope: &HistoryEffectiveScope,
    receipt_retention: &HistoryGovernanceTraversalRetention,
    traversal: &soland_storage::HistoryTraversalRetentionWrite,
) -> Result<PreparedRetainedHistoryCut, HistoryPreparationError> {
    if traversal.retention != *receipt_retention {
        return Err(frontier(
            "history traversal retention drifted from its receipt",
        ));
    }
    let HistoryGovernanceTraversalIntent::MemberHistoryDelivery {
        trusted_history_base_basis,
        target_basis,
        ..
    } = &traversal.retention.traversal_intent
    else {
        return Err(frontier("history traversal intent is not member delivery"));
    };
    if traversal.pins.len() != traversal.objects.len() {
        return Err(frontier(
            "history traversal pin and retained-object counts differ",
        ));
    }
    let retained_seal_map = traversal
        .pins
        .iter()
        .zip(&traversal.objects)
        .filter_map(|(pin, object)| match (pin, object) {
            (
                soland_storage::HistoryTraversalPin::Seal { seal_id, .. },
                soland_storage::HistoryTraversalRetainedObject::Seal(seal),
            ) if seal.id == *seal_id => Some((seal_id.clone(), seal)),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let retained_seals = traversal
        .pins
        .iter()
        .filter_map(|pin| match pin {
            soland_storage::HistoryTraversalPin::Seal { seal_id, .. } => Some(seal_id.clone()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    if retained_seal_map.len() != retained_seals.len() {
        return Err(frontier(
            "history retained Seal pin and object branches disagree",
        ));
    }
    let base_leaves = trusted_history_base_basis
        .leaves
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut expected_seals = BTreeSet::new();
    let mut pending = target_basis.leaves.clone();
    while let Some(seal_id) = pending.pop() {
        if !expected_seals.insert(seal_id.clone()) {
            continue;
        }
        let seal = retained_seal_map
            .get(&seal_id)
            .ok_or_else(|| frontier("history retained Seal predecessor closure is incomplete"))?;
        if base_leaves.contains(&seal_id) {
            if !seal.predecessor_refs.is_empty() {
                return Err(frontier("history trusted base is not predecessor-free"));
            }
        } else {
            pending.extend(seal.predecessor_refs.iter().cloned());
        }
    }
    if !base_leaves.is_subset(&expected_seals) || retained_seals != expected_seals {
        return Err(frontier(
            "history retained Seal cut is not the exact target-to-base closure",
        ));
    }
    let realm_id = match effective_scope {
        arkret_wire::HistoryEffectiveScope::Realm { realm_id }
        | arkret_wire::HistoryEffectiveScope::Circle { realm_id, .. } => realm_id,
    };
    let retained_events = traversal
        .pins
        .iter()
        .filter_map(|pin| match pin {
            soland_storage::HistoryTraversalPin::ControlEvent { event_digest, .. } => {
                Some(event_digest.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let mut replay_seals = Vec::new();
    let mut replay_events = Vec::new();
    let mut replay_dependencies = Vec::new();
    let mut anchor_events = BTreeSet::new();
    for seal in retained_seal_map.values().filter(|seal| seal.predecessor_refs.is_empty()) {
        let mut unit = Vec::new();
        for digest in &seal.delta {
            let event = traversal.pins.iter().zip(&traversal.objects)
                .find_map(|(pin, object)| match (pin, object) {
                    (soland_storage::HistoryTraversalPin::ControlEvent { event_digest, .. },
                     soland_storage::HistoryTraversalRetainedObject::ControlEvent(event))
                        if event_digest == digest => Some(event.clone()),
                    _ => None,
                })
                .ok_or_else(|| frontier("retained anchor unit is incomplete"))?;
            unit.push((digest.clone(), event));
        }
        let unit = arkret_state::state::deterministic_order(unit)
            .into_iter().map(|(_, event)| event).collect::<Vec<_>>();
        arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit(&unit)
            .map_err(|error| frontier(error.to_string()))?;
        anchor_events.extend(seal.delta.iter().cloned());
    }
    for (pin, object) in traversal.pins.iter().zip(&traversal.objects) {
        let canonical = soland_storage::history_traversal_retained_object_canonical(object)
            .map_err(|error| frontier(error.to_string()))?;
        let (pin_kind, pin_ref, pin_digest) = pin
            .storage_parts()
            .map_err(|error| frontier(error.to_string()))?;
        if canonical.object_kind != pin_kind
            || canonical.object_ref != pin_ref
            || canonical.object_digest != *pin_digest
        {
            return Err(frontier(
                "retained history object bytes no longer match their pin",
            ));
        }
        match (pin, object) {
            (
                soland_storage::HistoryTraversalPin::Seal { seal_id, .. },
                soland_storage::HistoryTraversalRetainedObject::Seal(seal),
            ) => {
                if seal.id != *seal_id
                    || seal
                        .delta
                        .iter()
                        .any(|event_digest| !retained_events.contains(event_digest))
                {
                    return Err(frontier(
                        "retained history Seal bytes or delta are incomplete",
                    ));
                }
                replay_seals.push(seal.clone());
            }
            (
                soland_storage::HistoryTraversalPin::ControlEvent {
                    event_digest,
                    ..
                },
                soland_storage::HistoryTraversalRetainedObject::ControlEvent(event),
            ) => {
                let event_digest_suite = event_digest
                    .digest_suite()
                    .map_err(|error| frontier(error.to_string()))?;
                let actual_event_digest = arkret_wire::Hash::new(
                    event
                        .event_digest_with_digest_suite(event_digest_suite)
                        .map_err(|error| HistoryPreparationError::Invariant(error.to_string()))?,
                )
                .map_err(|error| HistoryPreparationError::Invariant(error.to_string()))?;
                if actual_event_digest != *event_digest {
                    return Err(frontier(
                        "retained Control Event digest does not match its pin",
                    ));
                }
                let context = if anchor_events.contains(event_digest) {
                    arkret_wire::event_envelope::EventSubmitContext::AnchorUnit
                } else {
                    arkret_wire::event_envelope::EventSubmitContext::Standard
                };
                match event.proofs.as_slice() {
                    [EventProof::Producer(_)] => event
                        .validate_for_direct_history_structural_in_context(context)
                        .map_err(|error| frontier(error.to_string()))?,
                    _ => event
                        .validate_for_federation_structural_in_context(
                            context,
                            event_digest_suite,
                        )
                        .map_err(|error| frontier(error.to_string()))?,
                }
                replay_events.push(event.clone());
            }
            (
                soland_storage::HistoryTraversalPin::GovernanceDependency { selector, .. },
                soland_storage::HistoryTraversalRetainedObject::GovernanceDependency(item),
            ) => {
                if item.selector() != selector {
                    return Err(frontier("retained governance dependency selector changed"));
                }
                replay_dependencies.push(item.clone());
            }
            _ => {
                return Err(frontier("retained history pin and object branch mismatch"));
            }
        }
    }
    // Availability is authorized by each Seal's predecessor state, not by a
    // blanket per-Event requirement. Genesis has no predecessor authority and
    // MUST carry no receipts. The caller's complete SDK replay verifies exact
    // receipt bytes/signatures/coverage when that Seal's policy requires them.
    // Proof regimes and closed anchor-unit CBS context were validated above.
    let expected_first_round = governance_runtime_dependency_selector_coordinates_for_acquisition(
        &replay_seals,
        &replay_events,
    )
    .map_err(|error| frontier(error.to_string()))?;
    let selector_key = |selector: &GovernanceDependencySelector| {
        selector
            .canonical_sort_key()
            .map(|(kind, bytes)| (kind.to_owned(), bytes))
            .map_err(|error| frontier(error.to_string()))
    };
    let mut expected_selector_values = expected_first_round;
    let dependency_by_selector = replay_dependencies
        .iter()
        .map(|dependency| Ok((selector_key(dependency.selector())?, dependency)))
        .collect::<Result<BTreeMap<_, _>, HistoryPreparationError>>()?;
    let mut expected_selectors = BTreeSet::new();
    let mut cursor = 0;
    while cursor < expected_selector_values.len() {
        let selector = &expected_selector_values[cursor];
        cursor += 1;
        let key = selector_key(selector)?;
        if !expected_selectors.insert(key.clone()) {
            continue;
        }
        let dependency = dependency_by_selector
            .get(&key)
            .ok_or_else(|| frontier("retained governance dependency closure is incomplete"))?;
        if let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
            authenticated_signer_resolution_evidence,
            ..
        } = dependency
        {
            expected_selector_values.extend(
                governance_attester_evidence_selectors(std::slice::from_ref(
                    authenticated_signer_resolution_evidence,
                ))
                .map_err(|error| frontier(error.to_string()))?,
            );
        }
    }
    let retained_selectors = replay_dependencies
        .iter()
        .map(|dependency| selector_key(dependency.selector()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if !expected_selectors.is_subset(&retained_selectors) {
        return Err(frontier(
            "retained governance replay dependency closure is incomplete",
        ));
    }
    let source_evidence = replay_dependencies
        .iter()
        .filter(|dependency| {
            selector_key(dependency.selector()).is_ok_and(|key| !expected_selectors.contains(&key))
        })
        .collect::<Vec<_>>();
    if source_evidence.iter().any(|dependency| {
        !matches!(
            dependency,
            GovernanceDependency::AuthenticatedSignerResolutionEvidence { .. }
                | GovernanceDependency::MinimalMetadataMlsLeafSignerEvidence { .. }
        )
    }) {
        return Err(frontier(
            "retained traversal contains a surplus non-signer governance dependency",
        ));
    }
    let source_authenticated = source_evidence
        .iter()
        .filter_map(|dependency| match dependency {
            GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                authenticated_signer_resolution_evidence,
                ..
            } => Some(authenticated_signer_resolution_evidence.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let source_attesters = governance_attester_evidence_selectors(&source_authenticated)
        .map_err(|error| frontier(error.to_string()))?;
    if source_attesters
        .iter()
        .map(selector_key)
        .collect::<Result<BTreeSet<_>, _>>()?
        .iter()
        .any(|selector| !retained_selectors.contains(selector))
    {
        return Err(frontier(
            "retained source signer attester dependency closure is incomplete",
        ));
    }
    let checkpoint_dependencies = expected_selectors
        .iter()
        .map(|selector| {
            dependency_by_selector
                .get(selector)
                .map(|dependency| (*dependency).clone())
                .ok_or_else(|| frontier("retained replay dependency disappeared"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    for event in &replay_events {
        arkret_schema::validate_event_wire_schema(event)
            .map_err(|error| frontier(error.to_string()))?;
    }
    Ok(PreparedRetainedHistoryCut {
        realm_id: realm_id.clone(),
        target_basis: target_basis.clone(),
        replay_seals,
        replay_events,
        checkpoint_dependencies,
    })
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::history_key::SelfHistoryTraversalAccess;

    use super::*;

    fn digest(byte: &str) -> arkret_wire::Hash {
        arkret_wire::Hash::new(format!("sha256:{}", byte.repeat(64))).unwrap()
    }

    fn member_retention() -> HistoryGovernanceTraversalRetention {
        let fixture = arkret_schema_conformance::spec_json_artifact(
            "fixtures/history-key-recovery-fixture.json",
        )
        .unwrap();
        serde_json::from_value(fixture["direct_traversal_kat"]["member_retention"].clone()).unwrap()
    }

    fn traversal(
        retention: HistoryGovernanceTraversalRetention,
    ) -> soland_storage::HistoryTraversalRetentionWrite {
        soland_storage::HistoryTraversalRetentionWrite {
            access: soland_storage::HistoryTraversalAccess::SelfAccess(
                SelfHistoryTraversalAccess::RequestReceipt {
                    request_receipt_digest: digest("1"),
                },
            ),
            retention,
            pins: Vec::new(),
            objects: Vec::new(),
        }
    }

    fn scope(retention: &HistoryGovernanceTraversalRetention) -> HistoryEffectiveScope {
        match &retention.traversal_intent {
            HistoryGovernanceTraversalIntent::MemberHistoryDelivery {
                effective_scope, ..
            }
            | HistoryGovernanceTraversalIntent::OrganizationRecoveryArchive {
                effective_scope,
                ..
            } => effective_scope.clone(),
        }
    }

    #[test]
    fn retained_cut_accepts_an_exact_empty_closure() {
        let mut retention = member_retention();
        let HistoryGovernanceTraversalIntent::MemberHistoryDelivery {
            trusted_history_base_basis,
            target_basis,
            ..
        } = &mut retention.traversal_intent
        else {
            unreachable!()
        };
        trusted_history_base_basis.leaves.clear();
        target_basis.leaves.clear();
        let effective_scope = scope(&retention);
        let write = traversal(retention.clone());

        let prepared = prepare_retained_history_cut(&effective_scope, &retention, &write).unwrap();
        assert!(prepared.replay_seals.is_empty());
        assert!(prepared.replay_events.is_empty());
        assert!(prepared.checkpoint_dependencies.is_empty());
    }

    #[test]
    fn retained_cut_rejects_missing_predecessor_and_receipt_drift() {
        let retention = member_retention();
        let effective_scope = scope(&retention);
        let write = traversal(retention.clone());
        assert!(matches!(
            prepare_retained_history_cut(&effective_scope, &retention, &write),
            Err(HistoryPreparationError::FrontierUnavailable(_))
        ));

        let mut drifted_receipt = retention;
        drifted_receipt.traversal_intent_digest = digest("2");
        assert!(matches!(
            prepare_retained_history_cut(&effective_scope, &drifted_receipt, &write),
            Err(HistoryPreparationError::FrontierUnavailable(_))
        ));
    }

    #[test]
    fn retained_cut_rejects_archive_intent() {
        let fixture = arkret_schema_conformance::spec_json_artifact(
            "fixtures/history-key-recovery-fixture.json",
        )
        .unwrap();
        let retention: HistoryGovernanceTraversalRetention = serde_json::from_value(
            fixture["organization_recovery_archive_durable_before_gc_kat"]["replica"]
                ["history_traversal_retention"]
                .clone(),
        )
        .unwrap();
        let effective_scope = scope(&retention);
        let write = traversal(retention.clone());
        assert!(matches!(
            prepare_retained_history_cut(&effective_scope, &retention, &write),
            Err(HistoryPreparationError::FrontierUnavailable(_))
        ));
    }
}
