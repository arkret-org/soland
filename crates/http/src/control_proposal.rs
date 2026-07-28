use arkret_identifiers::{Hash, RealmId};
use arkret_wire::{
    ControlProposalDecision, ControlProposalDecisionPolicy, ControlProposalDeferReason,
    ControlProposalReceipt, ControlProposalReceiptKind, ControlProposalRejectReason, Event,
    PayloadSignature,
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
    if event.kind != arkret_wire::events::EventKind::REALM_CREATE {
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
        .filter(|record| record.kind == arkret_wire::events::EventKind::REALM_CREATE)
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
    let mut receipt = ControlProposalReceipt {
        kind: ControlProposalReceiptKind::ProposalReceipt,
        realm_id,
        proposal_digest,
        received_at,
        decision_due_at: received_at + policy.decision_window,
        absolute_due_at: received_at + policy.absolute_horizon,
        defer_count: 0,
        authority_set_ref,
        signature: PayloadSignature {
            alg: "EdDSA".to_owned(),
            verification_method: format!("{}#notary-key", state.service_id()),
            payload_digest: Hash::new(format!("sha256:{}", "00".repeat(32)))
                .map_err(|error| error.to_string())?,
            created_at: received_at,
            jws: String::new(),
        },
    };
    let bytes = receipt
        .canonical_bytes_for_signature()
        .map_err(|error| error.to_string())?;
    receipt.signature.payload_digest = receipt
        .receipt_digest()
        .map_err(|error| error.to_string())?;
    receipt.signature.jws =
        arkret_signatures::jws::sign_jws_ed25519(&bytes, state.notary_signing_key().as_ref())
            .map_err(|error| error.to_string())?;
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
) -> Result<Vec<ControlProposalReceipt>, String> {
    let policy = control_proposal_policy(state, realm_id, events).await?;
    let authority_set_ref = crate::notary::NotaryWorker::for_service(state.service_id().clone())
        .authority_set_ref_for_events(state, realm_id, events)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| {
            "this service cannot issue the current authority set's proposal receipt".to_owned()
        })?;
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

pub(crate) fn sign_control_proposal_reject(
    state: &AppState,
    receipt: &ControlProposalReceipt,
    previous_defers: &[ControlProposalDecision],
    reason_code: ControlProposalRejectReason,
    decided_at: chrono::DateTime<chrono::Utc>,
) -> Result<ControlProposalDecision, String> {
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
        signature: PayloadSignature {
            alg: "EdDSA".to_owned(),
            verification_method: format!("{}#notary-key", state.service_id()),
            payload_digest: Hash::new(format!("sha256:{}", "00".repeat(32)))
                .map_err(|error| error.to_string())?,
            created_at: decided_at,
            jws: String::new(),
        },
    };
    let bytes = decision
        .canonical_bytes_for_signature()
        .map_err(|error| error.to_string())?;
    let digest = decision
        .decision_digest()
        .map_err(|error| error.to_string())?;
    if let ControlProposalDecision::SignedReject { signature, .. } = &mut decision {
        signature.payload_digest = digest;
        signature.jws =
            arkret_signatures::jws::sign_jws_ed25519(&bytes, state.notary_signing_key().as_ref())
                .map_err(|error| error.to_string())?;
    }
    decision
        .validate_chain(
            receipt,
            previous_defers,
            ControlProposalDecisionPolicy::protocol_maximum(),
        )
        .map_err(|error| error.to_string())?;
    Ok(decision)
}

pub(crate) fn sign_control_proposal_defer(
    state: &AppState,
    receipt: &ControlProposalReceipt,
    previous_defers: &[ControlProposalDecision],
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
        signature: PayloadSignature {
            alg: "EdDSA".to_owned(),
            verification_method: format!("{}#notary-key", state.service_id()),
            payload_digest: Hash::new(format!("sha256:{}", "00".repeat(32)))
                .map_err(|error| error.to_string())?,
            created_at: decided_at,
            jws: String::new(),
        },
    };
    let bytes = decision
        .canonical_bytes_for_signature()
        .map_err(|error| error.to_string())?;
    let digest = decision
        .decision_digest()
        .map_err(|error| error.to_string())?;
    if let ControlProposalDecision::SignedDefer { signature, .. } = &mut decision {
        signature.payload_digest = digest;
        signature.jws =
            arkret_signatures::jws::sign_jws_ed25519(&bytes, state.notary_signing_key().as_ref())
                .map_err(|error| error.to_string())?;
    }
    decision
        .validate_chain(receipt, previous_defers, policy)
        .map_err(|error| error.to_string())?;
    Ok(decision)
}
