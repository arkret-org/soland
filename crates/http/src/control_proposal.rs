use std::collections::BTreeSet;

use arkret_identifiers::{Hash, RealmId};
use arkret_models_collaboration::events_payloads::realm::RealmPolicyBundlePayload;
use arkret_wire::{
    AuthoritySetRef, ControlProposalAck, ControlProposalAckKind, ControlProposalAuthorityAck,
    ControlProposalDecision, ControlProposalDecisionPolicy, ControlProposalDeferReason,
    ControlProposalRejectReason, Event, PayloadSignature,
};

use crate::state::AppState;

fn policy_from_realm_policy_bundle(
    realm_id: &RealmId,
    event: &Event,
) -> Result<Option<ControlProposalDecisionPolicy>, String> {
    if event.kind != arkret_wire::EventKind::RealmPolicyBundle {
        return Ok(None);
    }
    let payload: RealmPolicyBundlePayload = serde_json::from_value(serde_json::Value::Object(
        event.payload.clone().into_iter().collect(),
    ))
    .map_err(|error| format!("Realm policy-bundle payload is invalid: {error}"))?;
    if event.realm_id != *realm_id {
        return Err("Realm policy bundle does not bind the proposal Realm".to_owned());
    }
    payload.validate().map_err(|error| error.to_string())?;
    payload
        .control_proposal_decision_policy()
        .map(Some)
        .map_err(|error| error.to_string())
}

pub(crate) async fn control_proposal_policy(
    state: &AppState,
    realm_id: &RealmId,
    submitted_events: &[Event],
) -> Result<ControlProposalDecisionPolicy, String> {
    for event in submitted_events {
        if let Some(policy) = policy_from_realm_policy_bundle(realm_id, event)? {
            return Ok(policy);
        }
    }
    let records = state
        .event_queries()
        .realm_events_newest_first(realm_id.as_str())
        .await
        .map_err(|error| format!("Realm proposal policy is unavailable: {error}"))?;
    if let Some(record) = records
        .into_iter()
        .find(|record| record.kind == arkret_wire::EventKind::RealmPolicyBundle.as_str())
    {
        let event: Event = serde_json::from_value(record.envelope)
            .map_err(|error| format!("canonical Realm policy-bundle Event is invalid: {error}"))?;
        return policy_from_realm_policy_bundle(realm_id, &event)?
            .ok_or_else(|| "canonical Realm policy bundle has the wrong kind".to_owned());
    }
    // Managed-agent PCR genesis has no ordinary bootstrap policy bundle. Its
    // Control Proposal timing therefore uses the protocol defaults.
    Ok(ControlProposalDecisionPolicy::default())
}

pub(crate) fn mint_control_proposal_ack(
    state: &AppState,
    realm_id: RealmId,
    proposal_digest: Hash,
    authority_set_ref: Hash,
    received_at: chrono::DateTime<chrono::Utc>,
    policy: ControlProposalDecisionPolicy,
) -> Result<ControlProposalAck, String> {
    policy.validate().map_err(|error| error.to_string())?;
    let received_at = arkret_canonical::canonical::normalize_timestamp_canonical(received_at);
    let mut authority_ack = ControlProposalAuthorityAck {
        realm_id: realm_id.clone(),
        proposal_digest: proposal_digest.clone(),
        received_at,
        decision_due_at: received_at + policy.decision_window,
        absolute_due_at: received_at + policy.absolute_horizon,
        authority_set_ref: authority_set_ref.clone(),
        signature: PayloadSignature {
            extra: Default::default(),
            verification_method: arkret_wire::DidUrl::new(format!(
                "{}#notary-key",
                state.service_id()
            ))
            .map_err(|error| error.to_string())?,
            payload_digest: Hash::new(format!("sha256:{}", "00".repeat(32)))
                .map_err(|error| error.to_string())?,
            created_at: received_at,
            jws: String::new(),
        },
    };
    let bytes = authority_ack
        .canonical_bytes_for_signature()
        .map_err(|error| error.to_string())?;
    authority_ack.signature.payload_digest = authority_ack
        .authority_ack_digest()
        .map_err(|error| error.to_string())?;
    authority_ack.signature.jws =
        arkret_signatures::jws::sign_jws_ed25519(&bytes, state.notary_signing_key().as_ref())
            .map_err(|error| error.to_string())?;
    let ack = ControlProposalAck {
        kind: ControlProposalAckKind::SignedAck,
        realm_id,
        proposal_digest,
        received_at,
        decision_due_at: received_at + policy.decision_window,
        absolute_due_at: received_at + policy.absolute_horizon,
        defer_count: 0,
        authority_set_ref,
        authority_acks: vec![authority_ack],
    };
    ack.validate_structural(policy)
        .map_err(|error| error.to_string())?;
    Ok(ack)
}

pub(crate) async fn mint_control_proposal_acks(
    state: &AppState,
    realm_id: &RealmId,
    events: &[Event],
    received_at: chrono::DateTime<chrono::Utc>,
    bootstrap_ingress_authority_set_ref: Option<&AuthoritySetRef>,
) -> Result<Vec<ControlProposalAck>, String> {
    let policy = control_proposal_policy(state, realm_id, events).await?;
    let notary_authority_set_ref =
        crate::notary::NotaryWorker::for_service(state.service_id().clone())
            .authority_set_ref_for_events(state, realm_id, events)
            .map_err(|error| error.to_string())?;
    let is_closed_genesis = events
        .first()
        .is_some_and(|event| event.kind == arkret_wire::EventKind::RealmCreate);
    let authority_set_ref = select_control_proposal_ack_authority(
        notary_authority_set_ref,
        bootstrap_ingress_authority_set_ref,
        is_closed_genesis,
    )?;
    events
        .iter()
        .map(|event| {
            let proposal_digest =
                Hash::new(event.event_digest().map_err(|error| error.to_string())?)
                    .map_err(|error| error.to_string())?;
            mint_control_proposal_ack(
                state,
                realm_id.clone(),
                proposal_digest,
                authority_set_ref.clone(),
                received_at,
                policy,
            )
        })
        .collect()
}

pub(crate) async fn verify_control_proposal_ack(
    state: &AppState,
    event: &Event,
    ack: &ControlProposalAck,
    policy: ControlProposalDecisionPolicy,
) -> Result<(), String> {
    ack.validate_structural(policy)
        .map_err(|error| error.to_string())?;
    let worker = crate::notary::NotaryWorker::for_service(state.service_id().clone());
    let Some((profile, authority_set_ref)) = worker
        .current_notary_profile_for_events(state, &ack.realm_id, std::slice::from_ref(event))
        .map_err(|error| error.to_string())?
    else {
        return Err("current proposal authority profile is unavailable".to_owned());
    };
    if ack.authority_set_ref != authority_set_ref {
        return Err("Control Proposal Ack does not bind the current authority profile".to_owned());
    }

    let mut signers = BTreeSet::new();
    for member in &ack.authority_acks {
        let signer_full_id =
            arkret_identity::verification_method_did(&member.signature.verification_method)
                .map_err(|error| error.to_string())?;
        let signer = arkret_wire::project_full_id_to_core_id(&signer_full_id)
            .map_err(|error| error.to_string())?;
        if !signers.insert(signer.clone()) {
            return Err("Control Proposal Ack repeats an authority member".to_owned());
        }
        let bytes = member
            .canonical_bytes_for_signature()
            .map_err(|error| error.to_string())?;
        let device_method = member
            .signature
            .verification_method
            .strip_prefix(&format!("{signer_full_id}#"))
            .is_some_and(|fragment| arkret_identifiers::DeviceId::new(fragment.to_owned()).is_ok());
        if device_method {
            crate::jws_verify::verify_principal_authorized_jws_ed25519_async(
                &bytes,
                &member.signature.jws,
                &member.signature.verification_method,
                signer.as_str(),
                state,
            )
            .await
            .map_err(|error| error.to_string())?;
        } else {
            crate::jws_verify::verify_did_controlled_jws_async(
                &bytes,
                &member.signature.jws,
                &member.signature.verification_method,
                signer_full_id.as_str(),
                state,
            )
            .await?;
        }
    }

    if !profile.proposal_quorum_met(&signers) {
        let delegated_controller = event.executed_by.as_ref().filter(|controller| {
            signers.len() == 1 && signers.iter().any(|signer| signer == *controller)
        });
        let delegated_quorum = if let Some(controller) = delegated_controller {
            let envelope = serde_json::to_value(event)
                .map_err(|error| error.to_string())?
                .as_object()
                .cloned()
                .ok_or_else(|| "delegated Agent Event is not an object".to_owned())?;
            crate::routing::identity::managed_agent_pcr::validate_delegated_agent_envelope(
                state,
                &envelope,
                controller.as_str(),
            )
            .await
            .is_ok()
                && profile.proposal_quorum_met(
                    &event
                        .proofs
                        .iter()
                        .filter_map(|proof| {
                            let (controller, _) = proof.verification_method.rsplit_once('#')?;
                            let full_id =
                                arkret_wire::DidFullId::new(controller.to_owned()).ok()?;
                            let core_id = arkret_wire::project_full_id_to_core_id(&full_id).ok()?;
                            (core_id == event.actor_id).then_some(core_id)
                        })
                        .collect(),
                )
        } else {
            false
        };
        if !delegated_quorum {
            return Err(
                "Control Proposal Ack does not satisfy the current notary quorum".to_owned(),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod control_proposal_ack_quorum_tests {
    use arkret_wire::notary::{ForensicAttribution, NotaryValue};

    use super::*;

    fn did(name: &str) -> arkret_wire::DidCoreId {
        arkret_wire::DidCoreId::new(format!("ak:did_core:web:{name}.example")).unwrap()
    }

    fn full_did(name: &str) -> arkret_wire::DidFullId {
        arkret_wire::DidFullId::new(format!("did:web:{name}.example")).unwrap()
    }

    fn signers(values: &[&str]) -> BTreeSet<arkret_wire::DidCoreId> {
        values.iter().map(|value| did(value)).collect()
    }

    #[test]
    fn threshold_requires_distinct_current_members() {
        let profile = NotaryValue::Threshold {
            threshold: 2,
            members: vec![did("a"), did("b"), did("c")],
            forensic_attribution: ForensicAttribution::QuorumIntersection,
        };
        assert!(profile.proposal_quorum_met(&signers(&["a", "b"])));
        assert!(!profile.proposal_quorum_met(&signers(&["a"])));
        assert!(!profile.proposal_quorum_met(&signers(&["a", "outsider"])));
    }

    #[test]
    fn open_set_ack_is_one_signer_slot_not_a_cross_leaf_quorum() {
        let profile = NotaryValue::OpenSet {
            members: vec![did("a"), did("b")],
        };
        assert!(profile.proposal_quorum_met(&signers(&["a"])));
        assert!(!profile.proposal_quorum_met(&signers(&["a", "b"])));
        assert!(!profile.proposal_quorum_met(&signers(&["outsider"])));
    }

    #[test]
    fn mixed_accepts_primary_or_complete_recovery_set_only() {
        let profile = NotaryValue::Mixed {
            did: full_did("primary"),
            recovery_members: vec![did("recovery-a"), did("recovery-b")],
        };
        assert!(profile.proposal_quorum_met(&signers(&["primary"])));
        assert!(profile.proposal_quorum_met(&signers(&["recovery-a", "recovery-b"])));
        assert!(!profile.proposal_quorum_met(&signers(&["recovery-a"])));
        assert!(!profile.proposal_quorum_met(&signers(&["primary", "recovery-a"])));
    }
}

fn select_control_proposal_ack_authority(
    notary_authority_set_ref: Option<Hash>,
    bootstrap_ingress_authority_set_ref: Option<&AuthoritySetRef>,
    is_closed_genesis: bool,
) -> Result<Hash, String> {
    notary_authority_set_ref
        .or_else(|| {
            is_closed_genesis
                .then(|| {
                    bootstrap_ingress_authority_set_ref
                        .map(|authority| authority.authority_set_digest.clone())
                })
                .flatten()
        })
        .ok_or_else(|| {
            "this service cannot issue the current authority set's Control Proposal Ack".to_owned()
        })
}

pub(crate) fn sign_control_proposal_reject(
    state: &AppState,
    ack: &ControlProposalAck,
    previous_defers: &[ControlProposalDecision],
    notary: &arkret_wire::notary::NotaryValue,
    reason_code: ControlProposalRejectReason,
    decided_at: chrono::DateTime<chrono::Utc>,
) -> Result<ControlProposalDecision, String> {
    let first_member = ack
        .authority_acks
        .first()
        .ok_or_else(|| "Control Proposal Ack has no authority Ack".to_owned())?;
    let validation_policy = ControlProposalDecisionPolicy {
        proposal_intake_sla: arkret_wire::MAX_PROPOSAL_INTAKE_SLA,
        decision_window: first_member.decision_due_at - first_member.received_at,
        absolute_horizon: first_member.absolute_due_at - first_member.received_at,
        max_defers: arkret_wire::MAX_PROPOSAL_DEFERS,
    };
    let current_due_at = previous_defers
        .last()
        .map(ControlProposalDecision::decision_due_at)
        .unwrap_or(ack.decision_due_at);
    let mut decision = ControlProposalDecision::SignedReject {
        realm_id: ack.realm_id.clone(),
        proposal_digest: ack.proposal_digest.clone(),
        proposal_ack_digest: ack
            .proposal_ack_digest()
            .map_err(|error| error.to_string())?,
        decided_at,
        decision_due_at: current_due_at,
        absolute_due_at: ack.absolute_due_at,
        defer_count: u8::try_from(previous_defers.len())
            .map_err(|_| "proposal defer count overflow".to_owned())?,
        reason_code,
        authority_set_ref: ack.authority_set_ref.clone(),
        proofs: vec![PayloadSignature {
            extra: Default::default(),
            verification_method: arkret_wire::DidUrl::new(format!(
                "{}#notary-key",
                state.service_id()
            ))
            .map_err(|error| error.to_string())?,
            payload_digest: Hash::new(format!("sha256:{}", "00".repeat(32)))
                .map_err(|error| error.to_string())?,
            created_at: decided_at,
            jws: String::new(),
        }],
    };
    let bytes = decision
        .canonical_bytes_for_signature()
        .map_err(|error| error.to_string())?;
    let digest = decision
        .decision_digest()
        .map_err(|error| error.to_string())?;
    if let ControlProposalDecision::SignedReject { proofs, .. } = &mut decision {
        proofs[0].payload_digest = digest;
        proofs[0].jws =
            arkret_signatures::jws::sign_jws_ed25519(&bytes, state.notary_signing_key().as_ref())
                .map_err(|error| error.to_string())?;
    }
    decision
        .validate_chain_for_notary(ack, previous_defers, validation_policy, notary)
        .map_err(|error| error.to_string())?;
    Ok(decision)
}

pub(crate) fn sign_control_proposal_defer(
    state: &AppState,
    ack: &ControlProposalAck,
    previous_defers: &[ControlProposalDecision],
    notary: &arkret_wire::notary::NotaryValue,
    reason_code: ControlProposalDeferReason,
    decided_at: chrono::DateTime<chrono::Utc>,
    next_due_at: chrono::DateTime<chrono::Utc>,
    policy: ControlProposalDecisionPolicy,
) -> Result<ControlProposalDecision, String> {
    policy.validate().map_err(|error| error.to_string())?;
    let defer_count = u8::try_from(previous_defers.len())
        .map_err(|_| "proposal defer count overflow".to_owned())?
        .checked_add(1)
        .ok_or_else(|| "proposal defer count overflow".to_owned())?;
    let mut decision = ControlProposalDecision::SignedDefer {
        realm_id: ack.realm_id.clone(),
        proposal_digest: ack.proposal_digest.clone(),
        proposal_ack_digest: ack
            .proposal_ack_digest()
            .map_err(|error| error.to_string())?,
        decided_at,
        decision_due_at: next_due_at,
        absolute_due_at: ack.absolute_due_at,
        defer_count,
        reason_code,
        authority_set_ref: ack.authority_set_ref.clone(),
        proofs: vec![PayloadSignature {
            extra: Default::default(),
            verification_method: arkret_wire::DidUrl::new(format!(
                "{}#notary-key",
                state.service_id()
            ))
            .map_err(|error| error.to_string())?,
            payload_digest: Hash::new(format!("sha256:{}", "00".repeat(32)))
                .map_err(|error| error.to_string())?,
            created_at: decided_at,
            jws: String::new(),
        }],
    };
    let bytes = decision
        .canonical_bytes_for_signature()
        .map_err(|error| error.to_string())?;
    let digest = decision
        .decision_digest()
        .map_err(|error| error.to_string())?;
    if let ControlProposalDecision::SignedDefer { proofs, .. } = &mut decision {
        proofs[0].payload_digest = digest;
        proofs[0].jws =
            arkret_signatures::jws::sign_jws_ed25519(&bytes, state.notary_signing_key().as_ref())
                .map_err(|error| error.to_string())?;
    }
    decision
        .validate_chain_for_notary(ack, previous_defers, policy, notary)
        .map_err(|error| error.to_string())?;
    Ok(decision)
}

#[cfg(test)]
mod tests {
    use arkret_identifiers::Hash;
    use arkret_wire::AuthoritySetRef;

    use super::select_control_proposal_ack_authority;

    fn authority(byte: &str) -> AuthoritySetRef {
        AuthoritySetRef {
            authority_set_id: "ak.authority_set.realm_admission.v1".to_owned(),
            authority_set_digest: Hash::new(format!("sha256:{}", byte.repeat(64)))
                .expect("test digest is valid"),
        }
    }

    #[test]
    fn closed_genesis_can_use_lease_ingress_authority_before_notary_exists() {
        let lease_authority = authority("a");
        assert_eq!(
            select_control_proposal_ack_authority(None, Some(&lease_authority), true).unwrap(),
            lease_authority.authority_set_digest
        );
    }

    #[test]
    fn ordinary_control_move_cannot_use_genesis_ingress_authority() {
        let lease_authority = authority("b");
        assert!(
            select_control_proposal_ack_authority(None, Some(&lease_authority), false).is_err(),
            "non-genesis proposals must fail closed without the effective notary authority"
        );
    }

    #[test]
    fn effective_notary_authority_takes_precedence() {
        let notary_authority = authority("c");
        let lease_authority = authority("d");
        assert_eq!(
            select_control_proposal_ack_authority(
                Some(notary_authority.authority_set_digest.clone()),
                Some(&lease_authority),
                true,
            )
            .unwrap(),
            notary_authority.authority_set_digest
        );
    }
}
