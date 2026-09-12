//! Source projection signatures are issued only for durable committed Events.
use soland_storage::{
    CommittedContactCompletionIntent, ContactCompletionBinding, ContactCompletionIntent,
    ContactCompletionResult,
};

use super::*;

pub(super) async fn resolve_completion(
    state: &AppState,
    binding: &ContactCompletionBinding,
) -> JsonResult<ContactOperationOutcome> {
    materialize_contact_completions(state).await?;
    let result = state
        .persistence()
        .contact_completion_for_request(
            &binding.authenticated_actor,
            &binding.idempotency_key,
            &binding.request_hash,
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .and_then(|state| state.result);
    match result {
        Some(ContactCompletionResult::Accepted { outcome }) => {
            json_ok(ContactOperationOutcome::Accepted { outcome })
        }
        Some(ContactCompletionResult::Rejected { problem }) => {
            Err(AppError::from_frozen_problem(problem))
        }
        None => Err(crate::app_error!(
            TemporarilyUnavailable,
            "Contact command is awaiting confirmed completion"
        )),
    }
}

pub(crate) async fn materialize_contact_completions(state: &AppState) -> Result<(), AppError> {
    let mut after = None;
    loop {
        let ready = state
            .persistence()
            .committed_contact_completion_intents(64, after.as_ref())
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        let Some(last) = ready.last() else {
            break;
        };
        after = Some(last.event_digest.clone());
        // Continue past incomplete histories: one peer's missing evidence must
        // not starve unrelated committed commands behind the first page.
        for item in &ready {
            if let Err(error) = materialize_one(state, item).await {
                tracing::warn!(event_id=%item.intent.event.event_id,error=%error,"Contact committed completion remains pending");
            }
        }
        if ready.len() < 64 {
            break;
        }
    }
    Ok(())
}
async fn materialize_one(
    state: &AppState,
    ready: &CommittedContactCompletionIntent,
) -> Result<(), AppError> {
    let snapshot = state
        .projections()
        .control_proposal_snapshot(&ready.event_digest)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| {
            crate::app_error!(
                TemporarilyUnavailable,
                "Contact command evidence is unavailable"
            )
        })?;
    if snapshot.event.event_id != ready.intent.event.event_id
        || !matches!(snapshot.command_decisions.as_slice(),[decision] if decision.outcome==arkret_wire::CommandOutcome::Committed && decision.seal_id==ready.deciding_seal_id)
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "Contact source signature requires the exact committed command"
        ));
    }
    let outcome = sign_outcome(state, &ready.intent).await?;
    let delivery = if let Some(target) = &ready.intent.delivery {
        let carrier = ready
            .intent
            .delivery_carrier(&outcome)
            .map_err(|error| AppError::internal(error.to_string()))?
            .ok_or_else(|| AppError::internal("Contact delivery intent is absent"))?;
        let row = crate::routing::identity::contact_federation::prepare_peer_contact_carrier(
            state,
            target.contact_address.delivery_station_id().as_str(),
            &carrier,
        )
        .await?
        .ok_or_else(|| AppError::internal("remote Contact completion has no delivery"))?;
        Some(soland_storage::FederationOutboxRecord::pending(
            row.id,
            row.peer_id,
            row.peer_url
                .ok_or_else(|| AppError::internal("Contact delivery route missing"))?,
            row.endpoint,
            row.idempotency_key,
            row.payload_json,
            row.created_at,
        ))
    } else {
        None
    };
    state
        .persistence()
        .finalize_contact_completion_intent(
            ready,
            &ContactCompletionResult::Accepted { outcome },
            delivery.as_ref(),
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(())
}
async fn sign_outcome(
    state: &AppState,
    intent: &ContactCompletionIntent,
) -> Result<ContactAcceptedOutcome, AppError> {
    let mut outcome = intent.outcome.clone();
    match &mut outcome {
        ContactAcceptedOutcome::Request {
            request_acceptance_receipt: receipt,
            ..
        } => {
            receipt.core.accepted_at = now();
            receipt.receipt_digest = receipt
                .computed_core_digest()
                .map_err(|error| AppError::internal(error.to_string()))?;
            receipt.signature = sign_contact_transcript(
                state,
                &receipt
                    .canonical_signing_bytes()
                    .map_err(|error| AppError::internal(error.to_string()))?,
            )?;
        }
        ContactAcceptedOutcome::Response {
            normal_response_acceptance_receipt: receipt,
            lineage,
            current_proof,
            ..
        } => {
            receipt.accepted_at = now();
            receipt.signature = sign_contact_transcript(
                state,
                &receipt
                    .canonical_signing_bytes()
                    .map_err(|error| AppError::internal(error.to_string()))?,
            )?;
            lineage.signature = sign_contact_transcript(
                state,
                &lineage
                    .canonical_signing_bytes()
                    .map_err(|error| AppError::internal(error.to_string()))?,
            )?;
            *current_proof = latest_direction_proof(state, intent, current_proof).await?;
        }
        ContactAcceptedOutcome::Reject {
            reject_acceptance_receipt: receipt,
            ..
        } => {
            receipt.accepted_at = now();
            receipt.signature = sign_contact_transcript(
                state,
                &receipt
                    .canonical_signing_bytes()
                    .map_err(|error| AppError::internal(error.to_string()))?,
            )?;
        }
        ContactAcceptedOutcome::ScopeUpdate {
            lineage,
            current_proof,
            ..
        }
        | ContactAcceptedOutcome::Tombstone {
            lineage,
            current_proof,
            ..
        } => {
            lineage.signature = sign_contact_transcript(
                state,
                &lineage
                    .canonical_signing_bytes()
                    .map_err(|error| AppError::internal(error.to_string()))?,
            )?;
            *current_proof = latest_direction_proof(state, intent, current_proof).await?;
        }
    }
    Ok(outcome)
}
async fn latest_direction_proof(
    state: &AppState,
    intent: &ContactCompletionIntent,
    planned: &ContactCurrentProof,
) -> Result<ContactCurrentProof, AppError> {
    let holder = &intent.event.actor_id;
    let peer = planned.peer.contact_actor_id();
    let record = if let Some(record) = state
        .contacts()
        .contact_any(holder, &peer)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        record
    } else {
        state
            .contacts()
            .contact_any(&peer, holder)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            .ok_or_else(|| {
                crate::app_error!(
                    TemporarilyUnavailable,
                    "Contact source projection is unavailable"
                )
            })?
    };
    let proof = record
        .contact_round_evidence
        .as_ref()
        .filter(|bundle| bundle.contact_round_id == planned.contact_round_id)
        .and_then(|bundle| {
            bundle.current_proofs.iter().find(|proof| {
                proof.peer == planned.peer && proof.issuer_id == state.service_core_id()
            })
        })
        .ok_or_else(|| {
            crate::app_error!(
                TemporarilyUnavailable,
                "Contact current directional head is unavailable"
            )
        })?;
    let snapshot = state
        .projections()
        .control_proposal_snapshot(&proof.head_event_ref.event_digest())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| {
            crate::app_error!(
                TemporarilyUnavailable,
                "Contact current head confirmation is unavailable"
            )
        })?;
    if snapshot.event.event_id != proof.head_event_ref
        || snapshot.event.actor_id != *holder
        || !matches!(snapshot.command_decisions.as_slice(),[decision] if decision.outcome==arkret_wire::CommandOutcome::Committed)
    {
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "Contact local directional history is incomplete"
        ));
    }
    let next = signed_current_proof(
        state,
        planned.contact_round_id.clone(),
        planned.peer.clone(),
        &snapshot.event,
        snapshot
            .event
            .event_id
            .event_digest()
            .digest_suite()
            .map_err(|error| AppError::internal(error.to_string()))?,
    )?;
    if record.status == "tombstoned" && !next.terminal {
        // A remote terminal fence requires its authenticated original lineage;
        // it cannot be reconstructed by signing a local non-terminal head.
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "Contact terminal fence history is incomplete"
        ));
    }
    Ok(next)
}
