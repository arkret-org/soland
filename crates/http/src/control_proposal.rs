use std::collections::BTreeSet;

use arkret_identifiers::{Hash, RealmId};
use arkret_wire::{
    AuthoritySetRef, ControlProposalDecision, ControlProposalDecisionPolicy,
    ControlProposalDeferReason, ControlProposalReceipt, ControlProposalReceiptKind,
    ControlProposalRejectReason, Event, PayloadSignature, ProposalMemberReceipt,
};
use chrono::Duration;
use serde::Deserialize;

use crate::state::AppState;

#[derive(Deserialize)]
struct RealmCreateProposalPolicyPayload {
    object: RealmCreateProposalPolicy,
}

#[derive(Deserialize)]
struct RealmCreateProposalPolicy {
    id: RealmId,
    #[serde(default)]
    receipt_sla_ms: Option<u64>,
    #[serde(default)]
    proposal_decision_window_ms: Option<u64>,
    #[serde(default)]
    proposal_absolute_deadline_ms: Option<u64>,
    #[serde(default)]
    max_proposal_defers: Option<u8>,
}

fn policy_from_realm_create(
    realm_id: &RealmId,
    event: &Event,
) -> Result<Option<ControlProposalDecisionPolicy>, String> {
    if event.kind != arkret_wire::EventKind::REALM_CREATE {
        return Ok(None);
    }
    // A proposal receipt acknowledges ingress before semantic admission. Read
    // only the create-locked decision-policy fields here; full Realm schema
    // validation belongs to admission and must not turn a receipt request into
    // a quorum failure because the payload carries an unrelated extension.
    let payload: RealmCreateProposalPolicyPayload = serde_json::from_value(
        serde_json::Value::Object(event.payload.clone().into_iter().collect()),
    )
    .map_err(|error| format!("Realm create policy payload is invalid: {error}"))?;
    if payload.object.id != *realm_id {
        return Err("Realm create policy does not bind the proposal Realm".to_owned());
    }
    let duration_from_ms = |value: u64, field: &str| {
        i64::try_from(value)
            .map(Duration::milliseconds)
            .map_err(|_| format!("{field} exceeds the signed duration range"))
    };
    let policy = ControlProposalDecisionPolicy {
        receipt_sla: duration_from_ms(
            payload.object.receipt_sla_ms.unwrap_or(86_400_000),
            "receipt_sla_ms",
        )?,
        decision_window: duration_from_ms(
            payload.object.proposal_decision_window_ms.unwrap_or(30_000),
            "proposal_decision_window_ms",
        )?,
        absolute_horizon: duration_from_ms(
            payload
                .object
                .proposal_absolute_deadline_ms
                .unwrap_or(90_000),
            "proposal_absolute_deadline_ms",
        )?,
        max_defers: payload.object.max_proposal_defers.unwrap_or(2),
    };
    policy.validate().map_err(|error| error.to_string())?;
    Ok(Some(policy))
}

pub(crate) async fn control_proposal_policy(
    state: &AppState,
    realm_id: &RealmId,
    submitted_events: &[Event],
) -> Result<ControlProposalDecisionPolicy, String> {
    for event in submitted_events {
        if let Some(policy) = policy_from_realm_create(realm_id, event)? {
            return Ok(policy);
        }
    }
    let records = state
        .event_queries()
        .realm_events_newest_first(realm_id.as_str())
        .await
        .map_err(|error| format!("Realm proposal policy is unavailable: {error}"))?;
    let mut resolved = None;
    for record in records
        .into_iter()
        .filter(|record| record.kind == arkret_wire::EventKind::REALM_CREATE)
    {
        if resolved.is_some() {
            return Err("Realm has more than one canonical create policy".to_owned());
        }
        let event: Event = serde_json::from_value(record.envelope)
            .map_err(|error| format!("canonical Realm create Event is invalid: {error}"))?;
        resolved = policy_from_realm_create(realm_id, &event)?;
    }
    resolved.ok_or_else(|| "Realm has no canonical proposal decision policy".to_owned())
}

pub(crate) fn mint_control_proposal_receipt(
    state: &AppState,
    realm_id: RealmId,
    proposal_digest: Hash,
    authority_set_ref: Hash,
    received_at: chrono::DateTime<chrono::Utc>,
    policy: ControlProposalDecisionPolicy,
) -> Result<ControlProposalReceipt, String> {
    policy.validate().map_err(|error| error.to_string())?;
    let received_at = arkret_canonical::canonical::normalize_timestamp_canonical(received_at);
    let mut member_receipt = ProposalMemberReceipt {
        realm_id: realm_id.clone(),
        proposal_digest: proposal_digest.clone(),
        received_at,
        decision_due_at: received_at + policy.decision_window,
        absolute_due_at: received_at + policy.absolute_horizon,
        authority_set_ref: authority_set_ref.clone(),
        signature: PayloadSignature {
            extra: Default::default(),
            alg: "EdDSA".to_owned(),
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
    let bytes = member_receipt
        .canonical_bytes_for_signature()
        .map_err(|error| error.to_string())?;
    member_receipt.signature.payload_digest = member_receipt
        .member_receipt_digest()
        .map_err(|error| error.to_string())?;
    member_receipt.signature.jws =
        arkret_signatures::jws::sign_jws_ed25519(&bytes, state.notary_signing_key().as_ref())
            .map_err(|error| error.to_string())?;
    let receipt = ControlProposalReceipt {
        kind: ControlProposalReceiptKind::ProposalReceipt,
        realm_id,
        proposal_digest,
        received_at,
        decision_due_at: received_at + policy.decision_window,
        absolute_due_at: received_at + policy.absolute_horizon,
        defer_count: 0,
        authority_set_ref,
        member_receipts: vec![member_receipt],
    };
    receipt
        .validate_structural(policy)
        .map_err(|error| error.to_string())?;
    Ok(receipt)
}

pub(crate) async fn mint_control_proposal_receipts(
    state: &AppState,
    realm_id: &RealmId,
    events: &[Event],
    received_at: chrono::DateTime<chrono::Utc>,
    bootstrap_ingress_authority_set_ref: Option<&AuthoritySetRef>,
) -> Result<Vec<ControlProposalReceipt>, String> {
    let policy = control_proposal_policy(state, realm_id, events).await?;
    let notary_authority_set_ref =
        crate::notary::NotaryWorker::for_service(state.service_id().clone())
            .authority_set_ref_for_events(state, realm_id, events)
            .map_err(|error| error.to_string())?;
    let is_closed_genesis = events
        .first()
        .is_some_and(|event| event.kind == arkret_wire::EventKind::REALM_CREATE);
    let authority_set_ref = select_proposal_receipt_authority(
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
            mint_control_proposal_receipt(
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

pub(crate) async fn verify_control_proposal_receipt(
    state: &AppState,
    event: &Event,
    receipt: &ControlProposalReceipt,
    policy: ControlProposalDecisionPolicy,
) -> Result<(), String> {
    receipt
        .validate_structural(policy)
        .map_err(|error| error.to_string())?;
    let worker = crate::notary::NotaryWorker::for_service(state.service_id().clone());
    let Some((profile, authority_set_ref)) = worker
        .current_notary_profile_for_events(state, &receipt.realm_id, std::slice::from_ref(event))
        .map_err(|error| error.to_string())?
    else {
        return Err("current proposal authority profile is unavailable".to_owned());
    };
    if receipt.authority_set_ref != authority_set_ref {
        return Err("proposal receipt does not bind the current authority profile".to_owned());
    }

    let mut signers = BTreeSet::new();
    for member in &receipt.member_receipts {
        let signer =
            arkret_identity::verification_method_did(&member.signature.verification_method)
                .map_err(|error| error.to_string())?;
        if !signers.insert(signer.clone()) {
            return Err("proposal receipt repeats an authority member".to_owned());
        }
        let bytes = member
            .canonical_bytes_for_signature()
            .map_err(|error| error.to_string())?;
        let device_method = member
            .signature
            .verification_method
            .strip_prefix(&format!("{signer}#"))
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
                signer.as_str(),
                state,
            )
            .await?;
        }
    }

    if !profile.proposal_quorum_met(&signers) {
        let delegated_controller = event
            .executed_by
            .as_ref()
            .filter(|controller| signers.len() == 1 && signers.contains(*controller));
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
                && profile.proposal_quorum_met(&BTreeSet::from([event.actor_id.clone()]))
        } else {
            false
        };
        if !delegated_quorum {
            return Err("proposal receipt does not satisfy the current notary quorum".to_owned());
        }
    }
    Ok(())
}

#[cfg(test)]
mod proposal_receipt_quorum_tests {
    use arkret_wire::notary::{ForensicAttribution, NotaryValue};

    use super::*;

    fn did(name: &str) -> arkret_wire::Did {
        arkret_wire::Did::new(format!("did:web:{name}.example")).unwrap()
    }

    fn signers(values: &[&str]) -> BTreeSet<arkret_wire::Did> {
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
    fn open_set_receipt_is_one_signer_slot_not_a_cross_leaf_quorum() {
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
            did: did("primary"),
            recovery_members: vec![did("recovery-a"), did("recovery-b")],
        };
        assert!(profile.proposal_quorum_met(&signers(&["primary"])));
        assert!(profile.proposal_quorum_met(&signers(&["recovery-a", "recovery-b"])));
        assert!(!profile.proposal_quorum_met(&signers(&["recovery-a"])));
        assert!(!profile.proposal_quorum_met(&signers(&["primary", "recovery-a"])));
    }
}

fn select_proposal_receipt_authority(
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
            "this service cannot issue the current authority set's proposal receipt".to_owned()
        })
}

pub(crate) fn sign_control_proposal_reject(
    state: &AppState,
    receipt: &ControlProposalReceipt,
    previous_defers: &[ControlProposalDecision],
    notary: &arkret_wire::notary::NotaryValue,
    reason_code: ControlProposalRejectReason,
    decided_at: chrono::DateTime<chrono::Utc>,
) -> Result<ControlProposalDecision, String> {
    let first_member = receipt
        .member_receipts
        .first()
        .ok_or_else(|| "proposal receipt has no member receipt".to_owned())?;
    let validation_policy = ControlProposalDecisionPolicy {
        receipt_sla: arkret_wire::MAX_PROPOSAL_RECEIPT_SLA,
        decision_window: first_member.decision_due_at - first_member.received_at,
        absolute_horizon: first_member.absolute_due_at - first_member.received_at,
        max_defers: arkret_wire::MAX_PROPOSAL_DEFERS,
    };
    let current_due_at = previous_defers
        .last()
        .map(ControlProposalDecision::decision_due_at)
        .unwrap_or(receipt.decision_due_at);
    let mut decision = ControlProposalDecision::SignedReject {
        realm_id: receipt.realm_id.clone(),
        proposal_digest: receipt.proposal_digest.clone(),
        receipt_digest: receipt
            .receipt_digest()
            .map_err(|error| error.to_string())?,
        decided_at,
        decision_due_at: current_due_at,
        absolute_due_at: receipt.absolute_due_at,
        defer_count: u8::try_from(previous_defers.len())
            .map_err(|_| "proposal defer count overflow".to_owned())?,
        reason_code,
        authority_set_ref: receipt.authority_set_ref.clone(),
        proofs: vec![PayloadSignature {
            extra: Default::default(),
            alg: "EdDSA".to_owned(),
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
        .validate_chain_for_notary(receipt, previous_defers, validation_policy, notary)
        .map_err(|error| error.to_string())?;
    Ok(decision)
}

pub(crate) fn sign_control_proposal_defer(
    state: &AppState,
    receipt: &ControlProposalReceipt,
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
        realm_id: receipt.realm_id.clone(),
        proposal_digest: receipt.proposal_digest.clone(),
        receipt_digest: receipt
            .receipt_digest()
            .map_err(|error| error.to_string())?,
        decided_at,
        decision_due_at: next_due_at,
        absolute_due_at: receipt.absolute_due_at,
        defer_count,
        reason_code,
        authority_set_ref: receipt.authority_set_ref.clone(),
        proofs: vec![PayloadSignature {
            extra: Default::default(),
            alg: "EdDSA".to_owned(),
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
        .validate_chain_for_notary(receipt, previous_defers, policy, notary)
        .map_err(|error| error.to_string())?;
    Ok(decision)
}

#[cfg(test)]
mod tests {
    use arkret_identifiers::Hash;
    use arkret_wire::AuthoritySetRef;

    use super::select_proposal_receipt_authority;

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
            select_proposal_receipt_authority(None, Some(&lease_authority), true).unwrap(),
            lease_authority.authority_set_digest
        );
    }

    #[test]
    fn ordinary_control_move_cannot_use_genesis_ingress_authority() {
        let lease_authority = authority("b");
        assert!(
            select_proposal_receipt_authority(None, Some(&lease_authority), false).is_err(),
            "non-genesis proposals must fail closed without the effective notary authority"
        );
    }

    #[test]
    fn effective_notary_authority_takes_precedence() {
        let notary_authority = authority("c");
        let lease_authority = authority("d");
        assert_eq!(
            select_proposal_receipt_authority(
                Some(notary_authority.authority_set_digest.clone()),
                Some(&lease_authority),
                true,
            )
            .unwrap(),
            notary_authority.authority_set_digest
        );
    }
}
