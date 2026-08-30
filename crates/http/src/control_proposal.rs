use std::collections::BTreeSet;

use arkret_identifiers::{Hash, RealmId};
use arkret_models_collaboration::agent_operations::AgentLifecycleState;
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
            verification_method: state.service_verification_method("notary-key")?,
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
    authority_ack.signature.jws = soland_services::identity::sign_ed25519_frozen_notary_jws(
        &bytes,
        &authority_ack.signature.verification_method,
        state.notary_signing_key().as_ref(),
    )?;
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
    digest_suites: &[arkret_canonical::DigestSuite],
    received_at: chrono::DateTime<chrono::Utc>,
    bootstrap_ingress_authority_set_ref: Option<&AuthoritySetRef>,
) -> Result<Vec<ControlProposalAck>, String> {
    if events.len() != digest_suites.len() {
        return Err("Control Proposal Ack input has no exact digest suite per Event".to_owned());
    }
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
        .zip(digest_suites)
        .map(|(event, digest_suite)| {
            let proposal_digest = Hash::new(
                event
                    .event_digest_with_digest_suite(*digest_suite)
                    .map_err(|error| error.to_string())?,
            )
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

/// Verify the delegated-controller Control Proposal Ack of a managed Agent PCR
/// closed genesis.
///
/// `authz/cba-profiles.md` ingress source 1 is the only receipt path this class
/// has: the founding authority is recomputed from the candidate signed create,
/// the current controller device is established by the accepted Agent DID
/// delegation, and the receipt signer is that controller device. A managed
/// Agent PCR freezes the Agent DID as its notary
/// (`identity/key-management.md` section 3.6), and the same section makes the
/// current controller device a delegated notary signer of that PCR, so the
/// receipt signer is deliberately absent from the frozen descriptor set and
/// this judgement MUST NOT run through the frozen-descriptor rail. It also
/// MUST NOT fall back to a service-signed receipt.
pub(crate) async fn managed_agent_pcr_event_matches_accepted_delegation(
    state: &AppState,
    event: &Event,
) -> Result<bool, String> {
    let Some(record) = state
        .agent_pairings()
        .agent(event.actor_id.signing_principal_id().as_str())
        .await
        .map_err(|error| format!("managed Agent delegation lookup failed: {error}"))?
    else {
        return Ok(false);
    };
    let controller_id = arkret_wire::DidCoreId::new(record.controller_id.clone())
        .or_else(|_| {
            arkret_wire::Did::new(record.controller_id.clone())
                .and_then(|did| arkret_wire::project_did_to_core_id(&did))
        })
        .map_err(|error| format!("accepted managed Agent controller is invalid: {error}"))?;
    let controller_actor = arkret_wire::ActorId::hosted_principal(
        controller_id,
        event.actor_id.route_service_id().clone(),
    );
    Ok(record.principal_control_realm_id == event.realm_id.as_str()
        && event.executed_by.as_ref() == Some(&controller_actor)
        && event.authorization_ref.as_deref() == Some(record.controller_authorization_ref.as_str())
        && record.state != AgentLifecycleState::Deactivated)
}

pub(crate) async fn verify_managed_agent_pcr_ack(
    state: &AppState,
    event: &Event,
    ack: &ControlProposalAck,
    policy: ControlProposalDecisionPolicy,
) -> Result<Hash, String> {
    ack.validate_structural(policy)
        .map_err(|error| error.to_string())?;
    let accepted_create = if event.kind == arkret_wire::EventKind::RealmCreate {
        event.clone()
    } else {
        let records = state
            .event_queries()
            .realm_events_newest_first(event.realm_id.as_str())
            .await
            .map_err(|error| format!("managed Agent PCR genesis lookup failed: {error}"))?;
        let mut creates = records
            .into_iter()
            .filter(|record| record.kind == arkret_wire::event_kind_str::REALM_CREATE)
            .map(|record| {
                serde_json::from_value::<Event>(record.envelope).map_err(|error| {
                    format!("accepted managed Agent PCR genesis is invalid: {error}")
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if creates.len() != 1 {
            return Err(format!(
                "managed Agent PCR requires exactly one accepted genesis Event (found {})",
                creates.len()
            ));
        }
        creates.pop().expect("exactly one create")
    };
    let authority = arkret_bootstrap::ManagedAgentPcrGenesisAuthority::from_delegated_create(
        &accepted_create,
        &|event: &Event| {
            arkret_schema::project_registered_cell_writes(
                event,
                arkret_canonical::DigestSuite::Sha256,
            )
            .map_err(|error| error.to_string())
        },
    )
    .map_err(|error| format!("managed Agent PCR genesis authority is invalid: {error}"))?;
    if *authority.realm_id() != event.realm_id
        || authority.agent_id() != &event.actor_id
        || event.executed_by.as_ref() != Some(authority.controller_id())
        || event.authorization_ref.as_deref() != Some(authority.authorization_ref())
        || ack.realm_id != event.realm_id
    {
        return Err("managed Agent PCR Ack does not bind the delegated Event authority".to_owned());
    }
    if ack.authority_set_ref != *authority.authority_set_ref() {
        return Err("managed Agent PCR Ack does not bind the founding authority".to_owned());
    }
    let record = state
        .agent_pairings()
        .agent(authority.agent_id().signing_principal_id().as_str())
        .await
        .map_err(|error| format!("accepted managed Agent delegation is unavailable: {error}"))?
        .ok_or_else(|| "managed Agent PCR has no accepted Agent delegation".to_owned())?;
    let record_controller_id = arkret_wire::DidCoreId::new(record.controller_id.clone())
        .or_else(|_| {
            arkret_wire::Did::new(record.controller_id.clone())
                .and_then(|did| arkret_wire::project_did_to_core_id(&did))
        })
        .map_err(|error| format!("accepted managed Agent controller is invalid: {error}"))?;
    if record.principal_control_realm_id != event.realm_id.as_str()
        || record_controller_id != *authority.controller_id().signing_principal_id()
        || record.controller_authorization_ref.as_str() != authority.authorization_ref()
        || record.state == AgentLifecycleState::Deactivated
    {
        return Err(
            "managed Agent PCR genesis authority differs from the accepted Agent delegation"
                .to_owned(),
        );
    }
    let [member] = ack.authority_acks.as_slice() else {
        return Err(
            "managed Agent PCR Ack requires exactly one delegated controller signature".to_owned(),
        );
    };
    let device_id = member
        .signature
        .verification_method
        .as_str()
        .rsplit_once('#')
        .map(|(_, fragment)| fragment)
        .filter(|fragment| fragment.starts_with("ak:device:"))
        .filter(|fragment| fragment.len() > "ak:device:".len())
        .ok_or_else(|| {
            "managed Agent PCR Ack signer is not a controller device method".to_owned()
        })?;
    if !crate::routing::federation::move_seal::session_device_verification_method_matches(
        authority.controller_id().signing_principal_id().as_str(),
        device_id,
        &member.signature.verification_method,
    ) {
        return Err("managed Agent PCR Ack signer is not the delegated controller".to_owned());
    }
    let device = state
        .identities()
        .find_device(soland_services::identity::FindDeviceQuery {
            actor_id: record.controller_id.clone(),
            device_id: device_id.to_owned(),
        })
        .await
        .map_err(|error| format!("controller device lookup failed: {error}"))?
        .ok_or_else(|| {
            "managed Agent PCR Ack signer is not a registered controller device".to_owned()
        })?;
    let generation = crate::routing::identity::device_generation::current_device_generation(
        state,
        &record.controller_id,
    )
    .await
    .map_err(|error| format!("controller device generation is unavailable: {error}"))?;
    if device.revoked_at.is_some()
        || device.verification_state != "verified"
        || generation.as_ref().is_some_and(|generation| {
            generation.status
                != crate::routing::identity::device_generation::DeviceGenerationStatus::Active
                || device
                    .payload
                    .get("authorized_generation_ref")
                    .and_then(serde_json::Value::as_u64)
                    != Some(generation.current_ref)
        })
    {
        return Err("managed Agent PCR Ack signer is not an active controller device".to_owned());
    }
    let public_key = device
        .payload
        .get("device_public_key")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "controller device signing key is missing".to_owned())?;
    let multibase = public_key
        .strip_prefix("did:key:")
        .ok_or_else(|| "controller device key must be a canonical did:key".to_owned())?;
    let key = arkret_canonical::decode_ed25519_multibase(multibase)
        .map_err(|error| format!("controller device key is invalid: {error}"))?;
    let bytes = member
        .canonical_bytes_for_signature()
        .map_err(|error| error.to_string())?;
    arkret_signatures::Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &member.signature.jws,
            &bytes,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: key.to_vec(),
            },
        )
        .map_err(|error| format!("managed Agent PCR Ack signature is invalid: {error}"))?;
    Ok(authority.authority_set_ref().clone())
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
        .current_notary_value_for_events(state, &ack.realm_id, std::slice::from_ref(event))
        .map_err(|error| error.to_string())?
    else {
        return Err("current proposal authority profile is unavailable".to_owned());
    };
    if ack.authority_set_ref != authority_set_ref {
        return Err("Control Proposal Ack does not bind the current authority profile".to_owned());
    }

    let mut signer_methods = BTreeSet::new();
    for member in &ack.authority_acks {
        if !signer_methods.insert(member.signature.verification_method.clone()) {
            return Err("Control Proposal Ack repeats an authority member".to_owned());
        }
        let bytes = member
            .canonical_bytes_for_signature()
            .map_err(|error| error.to_string())?;
        let descriptor = profile
            .signer_descriptor(&member.signature.verification_method)
            .ok_or_else(|| {
                "Control Proposal Ack signer is absent from the frozen notary value".to_owned()
            })?;
        let frozen_signature = arkret_wire::SealSignature::from(member.signature.clone());
        arkret_signatures::verify_frozen_notary_detached_jws(&frozen_signature, descriptor, &bytes)
            .map_err(|error| error.to_string())?;
    }

    if !profile.proposal_quorum_met(&signer_methods) {
        return Err("Control Proposal Ack does not satisfy the current notary quorum".to_owned());
    }
    Ok(())
}

/// Verify one externally submitted decision against the immutable durable Ack,
/// the exact preceding defer chain and the current proposal authority profile.
/// Every proof is checked against its own canonical transcript; proof-set
/// quorum validation alone never substitutes for cryptographic verification.
pub(crate) async fn verify_control_proposal_decision(
    state: &AppState,
    event: &Event,
    digest_suite: arkret_canonical::DigestSuite,
    ack: &ControlProposalAck,
    previous_decisions: &[ControlProposalDecision],
    decision: &ControlProposalDecision,
    policy: ControlProposalDecisionPolicy,
) -> Result<(), String> {
    let event_digest = Hash::new(
        event
            .event_digest_with_digest_suite(digest_suite)
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if event.realm_id != *decision.realm_id()
        || event_digest != *decision.proposal_digest()
        || ack.realm_id != event.realm_id
        || ack.proposal_digest != event_digest
    {
        return Err("proposal decision does not bind the accepted Event and Ack".to_owned());
    }
    if previous_decisions
        .iter()
        .any(ControlProposalDecision::is_reject)
    {
        return Err("proposal decision chain is already terminal".to_owned());
    }
    verify_control_proposal_ack(state, event, ack, policy).await?;
    let worker = crate::notary::NotaryWorker::for_service(state.service_id().clone());
    let Some((notary, authority_set_ref)) = worker
        .current_notary_value_for_events(state, &event.realm_id, std::slice::from_ref(event))
        .map_err(|error| error.to_string())?
    else {
        return Err("current proposal authority profile is unavailable".to_owned());
    };
    if authority_set_ref != ack.authority_set_ref {
        return Err("proposal decision Ack is outside the current authority profile".to_owned());
    }
    decision
        .validate_chain_for_notary(ack, previous_decisions, policy, &notary)
        .map_err(|error| error.to_string())?;

    let proofs = match decision {
        ControlProposalDecision::SignedReject { proofs, .. }
        | ControlProposalDecision::SignedDefer { proofs, .. } => proofs,
    };
    for proof in proofs {
        let binding = decision
            .proof_binding_bytes(proof)
            .map_err(|error| error.to_string())?;
        let descriptor = notary
            .signer_descriptor(&proof.verification_method)
            .ok_or_else(|| {
                "Control Proposal decision signer is absent from the frozen notary value".to_owned()
            })?;
        let frozen_signature = arkret_wire::SealSignature::from(proof.clone());
        arkret_signatures::verify_frozen_notary_detached_jws(
            &frozen_signature,
            descriptor,
            &binding,
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod control_proposal_ack_quorum_tests {
    use arkret_wire::notary::{ForensicAttribution, NotaryValue};

    use super::*;

    fn signer(name: &str) -> arkret_wire::NotarySignerDescriptor {
        let notary = crate::test_single_signer_notary(&format!("did:web:{name}.example"), 51);
        let NotaryValue::SingleSigner { signer, .. } = notary else {
            unreachable!()
        };
        signer
    }

    fn signers(values: &[&str]) -> BTreeSet<arkret_wire::DidUrl> {
        values
            .iter()
            .map(|value| signer(value).verification_method)
            .collect()
    }

    #[test]
    fn threshold_requires_distinct_current_members() {
        let profile = NotaryValue::Threshold {
            threshold: 2,
            signers: vec![signer("a"), signer("b"), signer("c")],
            forensic_attribution: ForensicAttribution::QuorumIntersection,
        };
        assert!(profile.proposal_quorum_met(&signers(&["a", "b"])));
        assert!(!profile.proposal_quorum_met(&signers(&["a"])));
        assert!(!profile.proposal_quorum_met(&signers(&["a", "outsider"])));
    }

    #[test]
    fn open_set_ack_is_one_signer_slot_not_a_cross_leaf_quorum() {
        let profile = NotaryValue::OpenSet {
            signers: vec![signer("a"), signer("b")],
        };
        assert!(profile.proposal_quorum_met(&signers(&["a"])));
        assert!(!profile.proposal_quorum_met(&signers(&["a", "b"])));
        assert!(!profile.proposal_quorum_met(&signers(&["outsider"])));
    }

    #[test]
    fn mixed_accepts_primary_or_complete_recovery_set_only() {
        let profile = NotaryValue::Mixed {
            signer: signer("primary"),
            recovery_signers: vec![signer("recovery-a"), signer("recovery-b")],
            controller_organization_id: None,
            recovery_controller_organization_ids: Vec::new(),
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
            verification_method: state.service_verification_method("notary-key")?,
            payload_digest: Hash::new(format!("sha256:{}", "00".repeat(32)))
                .map_err(|error| error.to_string())?,
            created_at: decided_at,
            jws: String::new(),
        }],
    };
    let digest = decision
        .decision_digest()
        .map_err(|error| error.to_string())?;
    if let ControlProposalDecision::SignedReject { proofs, .. } = &mut decision {
        proofs[0].payload_digest = digest;
    }
    let bytes = decision
        .canonical_bytes_for_signature()
        .map_err(|error| error.to_string())?;
    if let ControlProposalDecision::SignedReject { proofs, .. } = &mut decision {
        proofs[0].jws = soland_services::identity::sign_ed25519_frozen_notary_jws(
            &bytes,
            &proofs[0].verification_method,
            state.notary_signing_key().as_ref(),
        )?;
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
            verification_method: state.service_verification_method("notary-key")?,
            payload_digest: Hash::new(format!("sha256:{}", "00".repeat(32)))
                .map_err(|error| error.to_string())?,
            created_at: decided_at,
            jws: String::new(),
        }],
    };
    let digest = decision
        .decision_digest()
        .map_err(|error| error.to_string())?;
    if let ControlProposalDecision::SignedDefer { proofs, .. } = &mut decision {
        proofs[0].payload_digest = digest;
    }
    let bytes = decision
        .canonical_bytes_for_signature()
        .map_err(|error| error.to_string())?;
    if let ControlProposalDecision::SignedDefer { proofs, .. } = &mut decision {
        proofs[0].jws = soland_services::identity::sign_ed25519_frozen_notary_jws(
            &bytes,
            &proofs[0].verification_method,
            state.notary_signing_key().as_ref(),
        )?;
    }
    decision
        .validate_chain_for_notary(ack, previous_defers, policy, notary)
        .map_err(|error| error.to_string())?;
    Ok(decision)
}

#[cfg(test)]
mod tests {
    use arkret_identifiers::{Hash, RealmId};
    use arkret_wire::{
        AuthoritySetRef, ControlProposalDecision, ControlProposalDecisionPolicy,
        ControlProposalDeferReason, ControlProposalRejectReason, DidCoreId, NotaryValue,
    };
    use chrono::{Duration, TimeZone, Utc};

    use super::{
        mint_control_proposal_ack, select_control_proposal_ack_authority,
        sign_control_proposal_defer, sign_control_proposal_reject,
    };
    use crate::AppState;

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

    #[test]
    fn proposal_ack_signer_uses_resolved_service_did() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let ack = mint_control_proposal_ack(
            &state,
            RealmId::new("ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K".to_owned())
                .unwrap(),
            Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
            Hash::new(format!("sha256:{}", "2".repeat(64))).unwrap(),
            chrono::Utc::now(),
            ControlProposalDecisionPolicy::default(),
        )
        .expect("service DID must produce a valid proposal Ack signer");

        assert_eq!(
            ack.authority_acks[0].signature.verification_method,
            state.service_verification_method("notary-key").unwrap()
        );
        assert!(
            ack.authority_acks[0]
                .signature
                .verification_method
                .as_str()
                .starts_with("did:")
        );
    }

    #[test]
    fn locally_signed_defer_and_reject_bind_the_final_canonical_decision_digest() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let verification_method = state.service_verification_method("notary-key").unwrap();
        let signing_key = state.notary_signing_key();
        let descriptor = soland_services::identity::ed25519_notary_signer_descriptor(
            DidCoreId::new(state.service_id().clone()).unwrap(),
            verification_method,
            signing_key.verifying_key().as_bytes(),
        )
        .unwrap();
        let notary = NotaryValue::single_signer(descriptor);
        let policy = ControlProposalDecisionPolicy::default();
        let received_at = Utc.with_ymd_and_hms(2026, 8, 25, 0, 0, 0).single().unwrap();
        let ack = mint_control_proposal_ack(
            &state,
            RealmId::new("ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K".to_owned())
                .unwrap(),
            Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
            Hash::new(format!("sha256:{}", "2".repeat(64))).unwrap(),
            received_at,
            policy,
        )
        .unwrap();
        let defer = sign_control_proposal_defer(
            &state,
            &ack,
            &[],
            &notary,
            ControlProposalDeferReason::TemporarilyUnavailable,
            received_at + Duration::seconds(1),
            ack.decision_due_at + policy.decision_window,
            policy,
        )
        .unwrap();
        defer
            .validate_chain_for_notary(&ack, &[], policy, &notary)
            .unwrap();
        let reject = sign_control_proposal_reject(
            &state,
            &ack,
            std::slice::from_ref(&defer),
            &notary,
            ControlProposalRejectReason::SchemaViolation,
            received_at + Duration::seconds(2),
        )
        .unwrap();
        reject
            .validate_chain_for_notary(&ack, std::slice::from_ref(&defer), policy, &notary)
            .unwrap();

        for decision in [&defer, &reject] {
            let proofs = match decision {
                ControlProposalDecision::SignedDefer { proofs, .. }
                | ControlProposalDecision::SignedReject { proofs, .. } => proofs,
            };
            assert_eq!(
                proofs[0].payload_digest,
                decision.decision_digest().unwrap()
            );
            assert!(!proofs[0].jws.is_empty());
        }
    }
}
