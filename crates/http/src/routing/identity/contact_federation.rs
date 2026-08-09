//! Cross-Principal-Server contact fact delivery (spec
//! `contact-and-direct-conversation.md` §2 / §4.1).
//!
//! Contact facts (`ak.contact.requested` / `accepted` / `rejected` /
//! `tombstoned`) are principal-scoped and cross-Realm. When the issuer and the
//! target holder live on different Principal Servers, the issuer-side server
//! federates the signed fact to the target holder's server via
//! `ak.peer.contacts.command.submit` (`POST /_arkret/peer/contacts`); the recipient
//! projects the original signed envelope into the target holder's contact
//! projection without re-signing it.
//!
//! Surfaces:
//! - sender: [`federate_contact_fact`] — enqueue a durable outbound delivery when the addressed
//!   holder is hosted on a configured federation peer.
//! - receiver: [`peer_contacts_submit`] — accept a delivered fact and project it into the local
//!   target holder's contact projection.

use arkret_canonical as canonical;
use arkret_identifiers::{Did, Hash};
use arkret_models_collaboration::contact_operations::{
    ContactBasis, ContactBasisEvidenceBundle, ContactCurrentProof, ContactScope,
    ContactScopeUpdatePayload, GlareConcurrencyAttestation, PeerContactControlKind,
    PeerContactControlReceipt, PeerContactControlReceiptDomain, PeerContactControlSubmitOutcome,
    PeerContactDisposition, PeerContactEventSubmitOutcome, PeerContactMirrorReceipt,
    PeerContactMirrorReceiptDomain, PeerContactSubmitOutcome, PeerContactSubmitRequestBody,
    RequestAcceptanceReceipt,
};
use arkret_models_collaboration::events_payloads::contact::{
    ContactAcceptedPayload, ContactRejectedPayload, ContactRequestedPayload,
    ContactTombstonedPayload,
};
use arkret_models_collaboration::governance::peer_contact::{
    ContactIntroductionEvidence, PeerContactAddress,
};
use arkret_wire::{Base64UrlString, DidUrl, Event, IdempotencyKey, ProtocolSignature};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::Signer as _;
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};
use soland_services::events::ProjectedEvent as ProjectionEventRecord;
use soland_services::identity::ContactRecord;
use uuid::Uuid;

use super::now;
use crate::state::AppState;

const HEADER_SOURCE_SERVICE_ID: &str = "source-service-id";
const CONTACT_MESSAGE_STUB: &str = "[message withheld until contact is accepted]";

pub(crate) fn peer_router() -> Router {
    Router::new().push(Router::with_path("contacts").post(peer_contacts_submit))
}

/// Enqueue the exact typed `ak.peer.contacts.command.submit` carrier for a
/// remote Principal Server. Same-server delivery is a no-op because the local
/// Contact projection was already committed by the self operation.
pub(crate) async fn enqueue_peer_contact_carrier(
    state: &AppState,
    recipient_service_id: &str,
    delivery: &PeerContactSubmitRequestBody,
) -> Result<bool, AppError> {
    let Some(prepared) = prepare_peer_contact_carrier(state, recipient_service_id, delivery)?
    else {
        return Ok(false);
    };
    state
        .federation()
        .enqueue_delivery(
            soland_services::federation::EnqueueFederationDeliveryCommand { delivery: prepared },
        )
        .await
        .map_err(|error| AppError::internal(format!("contact delivery enqueue: {error}")))?;
    Ok(true)
}

pub(crate) fn prepare_peer_contact_carrier(
    state: &AppState,
    recipient_service_id: &str,
    delivery: &PeerContactSubmitRequestBody,
) -> Result<Option<soland_services::events::FederationDelivery>, AppError> {
    if recipient_service_id == state.service_id() {
        return Ok(None);
    }
    let peer_url = crate::routing::federation::federation::peer_url_for_service_id(
        state,
        recipient_service_id,
    )
    .ok_or_else(|| AppError::invalid_param("recipient service is not a configured peer"))?;
    let (idempotency_key, contact_address) = match delivery {
        PeerContactSubmitRequestBody::Request {
            idempotency_key,
            contact_address,
            ..
        }
        | PeerContactSubmitRequestBody::Response {
            idempotency_key,
            contact_address,
            ..
        }
        | PeerContactSubmitRequestBody::Reject {
            idempotency_key,
            contact_address,
            ..
        }
        | PeerContactSubmitRequestBody::ScopeUpdate {
            idempotency_key,
            contact_address,
            ..
        }
        | PeerContactSubmitRequestBody::Tombstone {
            idempotency_key,
            contact_address,
            ..
        }
        | PeerContactSubmitRequestBody::ProofRefresh {
            idempotency_key,
            contact_address,
            ..
        }
        | PeerContactSubmitRequestBody::GlareFinalize {
            idempotency_key,
            contact_address,
            ..
        } => (idempotency_key.as_str(), contact_address),
    };
    if contact_address.recipient_service_id.as_str() != recipient_service_id {
        return Err(AppError::invalid_param(
            "contact_address.recipient_service_id does not match delivery destination",
        ));
    }
    let payload_bytes = canonical::canonical_json_bytes(&delivery)
        .map_err(|error| AppError::internal(format!("contact delivery canonicalize: {error}")))?;
    let payload_json = String::from_utf8(payload_bytes)
        .map_err(|error| AppError::internal(format!("contact delivery utf8: {error}")))?;
    Ok(Some(soland_services::events::FederationDelivery {
        id: Uuid::new_v4().to_string(),
        peer_did: recipient_service_id.to_owned(),
        peer_url: peer_url.trim_end_matches('/').to_owned(),
        endpoint: "/_arkret/peer/contacts".to_owned(),
        idempotency_key: idempotency_key.to_owned(),
        payload_json,
        created_at: now().timestamp(),
    }))
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.contacts.command.submit", tags("identity"))]
#[tracing::instrument(skip_all, fields(op = "ak.peer.contacts.command.submit"))]
async fn peer_contacts_submit(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PeerContactSubmitOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    super::super::events::peer::validate_peer_request(state, req, true).await?;
    let delivery = req
        .parse_json::<PeerContactSubmitRequestBody>()
        .await
        .map_err(|_| AppError::bad_json("invalid ak.peer.contacts.command.submit request body"))?;
    let source_service_id = req
        .headers()
        .get(HEADER_SOURCE_SERVICE_ID)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            super::super::events::peer::schema_violation("source-service-id header is required")
        })?
        .to_owned();
    if let Some(outcome) =
        handle_contact_control_request(state, &delivery, &source_service_id).await?
    {
        return json_ok(outcome);
    }
    let (fact_kind, signed_event, contact_address) = match &delivery {
        PeerContactSubmitRequestBody::Request {
            signed_event,
            request_receipt,
            introduction_evidence,
            contact_address,
            ..
        } => {
            request_receipt.core.validate().map_err(|error| {
                super::super::events::peer::schema_violation(format!(
                    "invalid Contact request receipt: {error}"
                ))
            })?;
            if request_receipt.core.request_event_ref != signed_event.event_id
                || request_receipt.core.holder.subject_id() != &signed_event.actor_id
            {
                return Err(super::super::events::peer::schema_violation(
                    "Contact request receipt does not bind signed_event",
                ));
            }
            validate_contact_introduction_evidence_digest(
                &serde_json::to_value(&signed_event.payload).map_err(|error| {
                    AppError::internal(format!("Contact request payload encode: {error}"))
                })?,
                introduction_evidence,
            )?;
            ("ak.contact.requested", signed_event, contact_address)
        }
        PeerContactSubmitRequestBody::Response {
            signed_event,
            response_receipt,
            contact_address,
            ..
        } => {
            response_receipt
                .request_receipt
                .core
                .validate()
                .map_err(|error| {
                    super::super::events::peer::schema_violation(format!(
                        "invalid Contact response request receipt: {error}"
                    ))
                })?;
            if response_receipt.response_event_ref != signed_event.event_id
                || response_receipt.issuer != signed_event.actor_id
            {
                return Err(super::super::events::peer::schema_violation(
                    "Contact response receipt does not bind signed_event",
                ));
            }
            ("ak.contact.accepted", signed_event, contact_address)
        }
        PeerContactSubmitRequestBody::Reject {
            signed_event,
            reject_receipt,
            contact_address,
            ..
        } => {
            reject_receipt
                .request_receipt
                .core
                .validate()
                .map_err(|error| {
                    super::super::events::peer::schema_violation(format!(
                        "invalid Contact reject request receipt: {error}"
                    ))
                })?;
            if reject_receipt.reject_event_ref != signed_event.event_id
                || reject_receipt.issuer != signed_event.actor_id
            {
                return Err(super::super::events::peer::schema_violation(
                    "Contact reject receipt does not bind signed_event",
                ));
            }
            ("ak.contact.rejected", signed_event, contact_address)
        }
        PeerContactSubmitRequestBody::ScopeUpdate {
            signed_event,
            lineage,
            current_proof,
            contact_address,
            ..
        } => {
            validate_contact_lineage_carrier(signed_event, lineage, current_proof, false)?;
            ("ak.contact.scope.update", signed_event, contact_address)
        }
        PeerContactSubmitRequestBody::Tombstone {
            signed_event,
            lineage,
            current_proof,
            contact_address,
            ..
        } => {
            validate_contact_lineage_carrier(signed_event, lineage, current_proof, true)?;
            ("ak.contact.tombstoned", signed_event, contact_address)
        }
        PeerContactSubmitRequestBody::ProofRefresh { .. }
        | PeerContactSubmitRequestBody::GlareFinalize { .. } => {
            unreachable!("control carrier branches are handled before Event carrier projection")
        }
    };
    if signed_event.kind.as_str() != fact_kind {
        return Err(super::super::events::peer::schema_violation(
            "Contact carrier branch does not match signed_event.kind",
        ));
    }
    let issuer = signed_event.actor_id.as_str().to_owned();
    let subject_id = contact_address.subject_id.as_str().to_owned();
    let recipient_service_id = contact_address.recipient_service_id.as_str();
    if recipient_service_id != state.service_id() {
        return Err(super::super::events::peer::cross_domain_replay(
            "contact_address.recipient_service_id does not match this service",
        ));
    }
    let payload = signed_event.payload.clone();

    // Originating Principal Server of this delivery: the peer end of the
    // projected contact row (the issuer) is hosted there. `validate_peer_request`
    // above already verified this header is a present, well-formed DID, so we
    // record it on the projection as the contact's `peer_service_id` — that is
    // the requester's/accepter's home server, NOT this service. inkson reads it
    // off a pending_incoming row as the `requester_service_id` to address the
    // reverse `respond` delivery back to the originator.
    // Project the issuer's exact signed envelope; peer transport never
    // re-signs or rewrites the Contact fact.
    let outcome = project_delivered_contact_fact(
        state,
        fact_kind,
        &issuer,
        &subject_id,
        &serde_json::to_value(&payload).map_err(|error| {
            AppError::internal(format!("contact payload encode failed: {error}"))
        })?,
        signed_event.event_id.as_str(),
        match &delivery {
            PeerContactSubmitRequestBody::Request {
                request_receipt, ..
            } => Some(request_receipt),
            _ => None,
        },
        Some(&source_service_id),
    )
    .await?;

    super::append_audit_log(
        state,
        Some(&subject_id),
        "peer.contacts.submit",
        json!({
            "fact_kind": fact_kind,
            "issuer": issuer,
            "subject_id": subject_id,
            "status": outcome,
        }),
        outcome,
    )
    .await;
    let disposition = if outcome == "duplicate" {
        PeerContactDisposition::Duplicate
    } else {
        PeerContactDisposition::Accepted
    };
    if matches!(delivery, PeerContactSubmitRequestBody::Request { .. }) {
        let request_digest = contact_control_request_digest(&delivery)?;
        if let Some(replayed) =
            replayed_contact_event_outcome(state, &subject_id, &issuer, &request_digest).await?
        {
            return json_ok(replayed);
        }
    }
    let mirror_receipt = sign_contact_mirror_receipt(state, &delivery, signed_event, disposition)?;
    if matches!(delivery, PeerContactSubmitRequestBody::Request { .. }) {
        persist_request_mirror_receipt(state, &subject_id, &issuer, &mirror_receipt).await?;
        enqueue_glare_finalize_if_ready(state, &subject_id, &issuer).await?;
    }
    let result_kind = match &delivery {
        PeerContactSubmitRequestBody::Request { .. } => {
            arkret_models_collaboration::contact_operations::ContactResultKind::Request
        }
        PeerContactSubmitRequestBody::Response { .. } => {
            arkret_models_collaboration::contact_operations::ContactResultKind::Response
        }
        PeerContactSubmitRequestBody::Reject { .. } => {
            arkret_models_collaboration::contact_operations::ContactResultKind::Reject
        }
        PeerContactSubmitRequestBody::ScopeUpdate { .. } => {
            arkret_models_collaboration::contact_operations::ContactResultKind::ScopeUpdate
        }
        PeerContactSubmitRequestBody::Tombstone { .. } => {
            arkret_models_collaboration::contact_operations::ContactResultKind::Tombstone
        }
        PeerContactSubmitRequestBody::ProofRefresh { .. }
        | PeerContactSubmitRequestBody::GlareFinalize { .. } => unreachable!(),
    };
    let response = PeerContactSubmitOutcome::Event(PeerContactEventSubmitOutcome {
        result_kind,
        status: disposition,
        mirror_receipt,
        current_proof: None,
        retry_after_ms: None,
    });
    if matches!(delivery, PeerContactSubmitRequestBody::Request { .. }) {
        persist_contact_event_outcome(state, &subject_id, &issuer, &response).await?;
    }
    json_ok(response)
}

async fn replayed_contact_event_outcome(
    state: &AppState,
    holder: &str,
    peer: &str,
    request_digest: &Hash,
) -> Result<Option<PeerContactSubmitOutcome>, AppError> {
    let record = state
        .contacts()
        .contact_any(holder, peer)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(record.and_then(|record| {
        record
            .control_outcomes
            .iter()
            .find_map(|outcome| match outcome {
                PeerContactSubmitOutcome::Event(event)
                    if event.mirror_receipt.request_digest == *request_digest =>
                {
                    Some(outcome.clone())
                }
                _ => None,
            })
    }))
}

async fn persist_contact_event_outcome(
    state: &AppState,
    holder: &str,
    peer: &str,
    outcome: &PeerContactSubmitOutcome,
) -> Result<(), AppError> {
    let contacts = state.contacts();
    let mut record = contacts
        .contact_any(holder, peer)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::internal("projected Contact row disappeared"))?;
    let outcome_digest = super::account::canonical_contact_digest(outcome)?;
    let already_stored = record.control_outcomes.iter().any(|stored| {
        super::account::canonical_contact_digest(stored)
            .is_ok_and(|digest| digest == outcome_digest)
    });
    if !already_stored {
        let expected_updated_at = record.updated_at;
        record.control_outcomes.push(outcome.clone());
        advance_contact_revision(&mut record, expected_updated_at);
        save_contact_cas(contacts, expected_updated_at, record).await?;
    }
    Ok(())
}

async fn handle_contact_control_request(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    source_service_id: &str,
) -> Result<Option<PeerContactSubmitOutcome>, AppError> {
    match request {
        PeerContactSubmitRequestBody::ProofRefresh {
            prior_mirror_receipt,
            current_proof,
            contact_address,
            ..
        } => {
            if contact_address.recipient_service_id.as_str() != state.service_id() {
                return Err(super::super::events::peer::cross_domain_replay(
                    "contact_address.recipient_service_id does not match this service",
                ));
            }
            let outcome = finalize_contact_proof_refresh(
                state,
                request,
                source_service_id,
                prior_mirror_receipt,
                current_proof,
                contact_address,
            )
            .await?;
            return Ok(Some(outcome));
        }
        PeerContactSubmitRequestBody::GlareFinalize {
            basis_id,
            basis,
            request_receipts,
            remote_mirror_receipt,
            glare_concurrency_attestation,
            contact_address,
            ..
        } => {
            if contact_address.recipient_service_id.as_str() != state.service_id() {
                return Err(super::super::events::peer::cross_domain_replay(
                    "contact_address.recipient_service_id does not match this service",
                ));
            }
            let outcome = finalize_glare_contact_basis(
                state,
                request,
                source_service_id,
                basis_id,
                basis,
                request_receipts,
                remote_mirror_receipt,
                glare_concurrency_attestation,
                contact_address,
            )
            .await?;
            return Ok(Some(outcome));
        }
        _ => return Ok(None),
    }
}

pub(crate) fn validate_mirror_receipt_cryptography(
    state: &AppState,
    receipt: &PeerContactMirrorReceipt,
    expected_service_id: &str,
    field: &str,
) -> Result<(), AppError> {
    if receipt.issuer.as_str() != expected_service_id
        || receipt.recipient_service_id.as_str() != expected_service_id
        || !matches!(
            receipt.disposition,
            PeerContactDisposition::Accepted | PeerContactDisposition::Duplicate
        )
    {
        return Err(super::super::events::peer::cross_domain_replay(format!(
            "{field} issuer, recipient, or authoritative disposition is invalid"
        )));
    }
    let signing_bytes = receipt
        .canonical_signing_bytes()
        .map_err(|error| AppError::internal(format!("{field} transcript failed: {error}")))?;
    verify_contact_service_signature_bytes(
        state,
        expected_service_id,
        &receipt.signature,
        &signing_bytes,
        field,
    )
}

async fn validate_proof_refresh_evidence(
    state: &AppState,
    source_service_id: &str,
    prior_mirror_receipt: &PeerContactMirrorReceipt,
    current_proof: &ContactCurrentProof,
    contact_address: &PeerContactAddress,
) -> Result<(), AppError> {
    validate_mirror_receipt_cryptography(
        state,
        prior_mirror_receipt,
        state.service_id(),
        "prior_mirror_receipt",
    )?;
    let signing_bytes = current_proof
        .canonical_signing_bytes()
        .map_err(|error| AppError::internal(format!("current_proof transcript failed: {error}")))?;
    verify_contact_service_signature_bytes(
        state,
        source_service_id,
        &current_proof.signature,
        &signing_bytes,
        "current_proof",
    )?;
    if current_proof.terminal
        || current_proof.issuer == contact_address.subject_id
        || current_proof.head_event_ref != prior_mirror_receipt.signed_event_ref
        || current_proof.head_digest != prior_mirror_receipt.signed_event_digest
        || !current_proof
            .accepted_frontier
            .contains(&current_proof.head_event_ref)
        || current_proof.complete_through == 0
        || current_proof.fresh_until <= now()
    {
        return Err(super::super::events::peer::schema_violation(
            "Contact proof-refresh proof does not bind the mirrored immutable fact",
        ));
    }
    let contacts = state
        .contacts()
        .contacts_for_actor(contact_address.subject_id.as_str())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let durable_match = contacts.iter().any(|record| {
        matches!(record.status.as_str(), "accepted" | "pending")
            && record.peer_service_id.as_deref() == Some(source_service_id)
            && record.basis_id.as_deref() == Some(current_proof.basis_id.as_str())
            && (record.request_receipts.iter().any(|stored| {
                stored.core.request_event_ref == current_proof.head_event_ref
                    && stored.core.request_digest == current_proof.head_digest
            }) || (record.requester == current_proof.issuer.as_str()
                && record.target == contact_address.subject_id.as_str()
                && record.request_event_ref.as_deref()
                    == Some(current_proof.head_event_ref.as_str()))
                || (record.target == current_proof.issuer.as_str()
                    && record.requester == contact_address.subject_id.as_str()
                    && record.response_event_ref.as_deref()
                        == Some(current_proof.head_event_ref.as_str())))
    });
    if !durable_match {
        return Err(AppError::new(
            soland_http::error::ErrorCode::FailedPrecondition,
            "proof_refresh durable Contact basis/head evidence is unavailable",
        ));
    }
    Ok(())
}

async fn finalize_contact_proof_refresh(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    source_service_id: &str,
    prior_mirror_receipt: &PeerContactMirrorReceipt,
    current_proof: &ContactCurrentProof,
    contact_address: &PeerContactAddress,
) -> Result<PeerContactSubmitOutcome, AppError> {
    let contacts = state.contacts();
    let mut record = contacts
        .contact_any(
            contact_address.subject_id.as_str(),
            current_proof.issuer.as_str(),
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| {
            AppError::new(
                soland_http::error::ErrorCode::FailedPrecondition,
                "proof-refresh Contact basis is unavailable",
            )
        })?;
    let request_digest = contact_control_request_digest(request)?;
    if let Some(outcome) = replayed_contact_control_outcome(
        &record,
        &request_digest,
        PeerContactControlKind::ProofRefresh,
    ) {
        return Ok(outcome);
    }
    validate_proof_refresh_evidence(
        state,
        source_service_id,
        prior_mirror_receipt,
        current_proof,
        contact_address,
    )
    .await?;
    if record.peer_service_id.as_deref() != Some(source_service_id) {
        return Err(super::super::events::peer::cross_domain_replay(
            "proof-refresh source service does not match durable Contact peer",
        ));
    }
    let mut bundle = record.basis_evidence.clone().ok_or_else(|| {
        AppError::new(
            soland_http::error::ErrorCode::FailedPrecondition,
            "proof-refresh Contact basis evidence is unavailable",
        )
    })?;
    if bundle.basis_id != current_proof.basis_id || bundle.glare_concurrency_attestations.is_none()
    {
        return Err(super::super::events::peer::schema_violation(
            "proof-refresh does not bind the durable glare basis",
        ));
    }
    if bundle.current_proofs.iter().any(|proof| {
        proof.issuer == current_proof.issuer
            && (proof.fresh_until >= current_proof.fresh_until
                || proof.complete_through > current_proof.complete_through)
    }) {
        return Err(super::super::events::peer::schema_violation(
            "proof-refresh must advance the issuer's durable freshness/completeness proof",
        ));
    }
    bundle
        .current_proofs
        .retain(|proof| proof.issuer != current_proof.issuer);
    bundle.current_proofs.push(current_proof.clone());
    bundle.current_proofs.sort_by(|left, right| {
        left.issuer
            .as_str()
            .as_bytes()
            .cmp(right.issuer.as_str().as_bytes())
    });
    let pair_has_both_current_proofs = bundle.current_proofs.len() == 2
        && bundle.current_proofs.iter().all(|proof| {
            proof.basis_id == bundle.basis_id
                && !proof.terminal
                && proof.complete_through > 0
                && proof.fresh_until > now()
        });
    if pair_has_both_current_proofs {
        record.status = "accepted".to_owned();
        record.version = Some(1);
    }
    let expected_updated_at = record.updated_at;
    record.basis_evidence = Some(bundle);
    advance_contact_revision(&mut record, expected_updated_at);
    let result_digest = super::account::canonical_contact_digest(current_proof)?;
    let control_receipt = sign_contact_control_receipt(
        state,
        request,
        PeerContactControlKind::ProofRefresh,
        PeerContactDisposition::Accepted,
        Some(result_digest),
    )?;
    let outcome =
        PeerContactSubmitOutcome::Control(PeerContactControlSubmitOutcome::ProofRefresh {
            status: PeerContactDisposition::Accepted,
            control_receipt,
            current_proof: current_proof.clone(),
        });
    record.control_outcomes.push(outcome.clone());
    save_contact_cas(contacts, expected_updated_at, record).await?;
    Ok(outcome)
}

#[allow(clippy::too_many_arguments)]
fn validate_glare_finalize_evidence(
    state: &AppState,
    source_service_id: &str,
    basis_id: &Hash,
    basis: &ContactBasis,
    request_receipts: &[RequestAcceptanceReceipt; 2],
    remote_mirror_receipt: &PeerContactMirrorReceipt,
    attestation: &GlareConcurrencyAttestation,
    contact_address: &PeerContactAddress,
) -> Result<(), AppError> {
    validate_mirror_receipt_cryptography(
        state,
        remote_mirror_receipt,
        state.service_id(),
        "remote_mirror_receipt",
    )?;
    for (index, receipt) in request_receipts.iter().enumerate() {
        super::account::validate_request_receipt_cryptography(
            state,
            receipt,
            &format!("request_receipts[{index}]"),
        )?;
    }
    if attestation.issuer == contact_address.subject_id
        || attestation.peer != contact_address.subject_id
    {
        return Err(super::super::events::peer::schema_violation(
            "glare_concurrency_attestation participant coordinates are invalid",
        ));
    }
    let signing_bytes = attestation.canonical_signing_bytes().map_err(|error| {
        AppError::internal(format!(
            "glare_concurrency_attestation transcript failed: {error}"
        ))
    })?;
    verify_contact_service_signature_bytes(
        state,
        source_service_id,
        &attestation.signature,
        &signing_bytes,
        "glare_concurrency_attestation",
    )?;

    let mut ordered = request_receipts
        .iter()
        .map(|receipt| {
            Ok((
                receipt.core.request_event_ref.clone(),
                super::account::canonical_contact_digest(receipt)?,
                receipt,
            ))
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    ordered.sort_by(|left, right| left.0.as_str().as_bytes().cmp(right.0.as_str().as_bytes()));
    let [first, second] = ordered.as_slice() else {
        unreachable!("request_receipts is a fixed pair")
    };
    let mut pair = [
        contact_address.subject_id.clone(),
        attestation.issuer.clone(),
    ];
    pair.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
    let expected_basis = ContactBasis::Glare {
        sorted_pair_members: pair,
        requests: [
            arkret_models_collaboration::contact_operations::ContactBasisRequestRef {
                request_event_ref: first.0.clone(),
                request_acceptance_receipt_digest: first.1.clone(),
            },
            arkret_models_collaboration::contact_operations::ContactBasisRequestRef {
                request_event_ref: second.0.clone(),
                request_acceptance_receipt_digest: second.1.clone(),
            },
        ],
    };
    if super::account::canonical_contact_digest(basis)?
        != super::account::canonical_contact_digest(&expected_basis)?
    {
        return Err(super::super::events::peer::schema_violation(
            "glare basis does not match the exact request receipts",
        ));
    }
    if &contact_basis_id(&expected_basis)? != basis_id
        || attestation.request_receipt_digests != [first.1.clone(), second.1.clone()]
        || !attestation.observed_frontier.contains(&first.0)
        || !attestation.observed_frontier.contains(&second.0)
        || attestation.complete_through == 0
    {
        return Err(super::super::events::peer::schema_violation(
            "glare basis/attestation digest or frontier coordinates are invalid",
        ));
    }
    let source_receipt = request_receipts
        .iter()
        .find(|receipt| receipt.core.issuer.as_str() == source_service_id)
        .ok_or_else(|| {
            super::super::events::peer::schema_violation(
                "glare request receipts have no source-service receipt",
            )
        })?;
    let local_receipt = request_receipts
        .iter()
        .find(|receipt| receipt.core.issuer.as_str() == state.service_id())
        .ok_or_else(|| {
            super::super::events::peer::schema_violation(
                "glare request receipts have no local-service counterpart receipt",
            )
        })?;
    if source_receipt.core.holder.subject_id() != &attestation.issuer
        || source_receipt.core.peer.subject_id() != &contact_address.subject_id
        || local_receipt.core.holder.subject_id() != &contact_address.subject_id
        || local_receipt.core.peer.subject_id() != &attestation.issuer
        || remote_mirror_receipt.signed_event_ref != source_receipt.core.request_event_ref
        || remote_mirror_receipt.signed_event_digest != source_receipt.core.request_digest
    {
        return Err(super::super::events::peer::schema_violation(
            "glare receipts, mirror, and participant request coordinates do not cross-bind",
        ));
    }
    Ok(())
}

fn verify_contact_service_signature_bytes(
    state: &AppState,
    expected_service_id: &str,
    signature: &ProtocolSignature,
    signing_bytes: &[u8],
    evidence_field: &str,
) -> Result<(), AppError> {
    let signed_value: Value = serde_json::from_slice(signing_bytes).map_err(|error| {
        AppError::internal(format!(
            "{evidence_field} canonical signing transcript is invalid JSON: {error}"
        ))
    })?;
    super::account::verify_contact_service_signature(
        state,
        expected_service_id,
        signature,
        &signed_value,
        evidence_field,
    )
}

#[allow(clippy::too_many_arguments)]
async fn finalize_glare_contact_basis(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    source_service_id: &str,
    basis_id: &Hash,
    basis: &ContactBasis,
    request_receipts: &[RequestAcceptanceReceipt; 2],
    remote_mirror_receipt: &PeerContactMirrorReceipt,
    remote_attestation: &GlareConcurrencyAttestation,
    contact_address: &PeerContactAddress,
) -> Result<PeerContactSubmitOutcome, AppError> {
    let local_holder = contact_address.subject_id.as_str();
    let remote_holder = remote_attestation.issuer.as_str();
    let contacts = state.contacts();
    let mut record = contacts
        .contact_any(local_holder, remote_holder)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| {
            AppError::new(
                soland_http::error::ErrorCode::FailedPrecondition,
                "glare Contact request slot is unavailable",
            )
        })?;
    let request_digest = contact_control_request_digest(request)?;
    if let Some(outcome) = replayed_contact_control_outcome(
        &record,
        &request_digest,
        PeerContactControlKind::GlareFinalize,
    ) {
        return Ok(outcome);
    }
    validate_glare_finalize_evidence(
        state,
        source_service_id,
        basis_id,
        basis,
        request_receipts,
        remote_mirror_receipt,
        remote_attestation,
        contact_address,
    )?;
    if record.status != "pending" || record.basis_evidence.is_some() {
        return Err(AppError::conflict(
            "Contact request slot is already consumed",
        ));
    }

    let retained_receipts = record.request_receipts.clone();
    let retained = retained_receipts
        .iter()
        .map(super::account::canonical_contact_digest)
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    let submitted = request_receipts
        .iter()
        .map(super::account::canonical_contact_digest)
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    if retained.len() != 2 || retained != submitted {
        return Err(AppError::new(
            soland_http::error::ErrorCode::FailedPrecondition,
            "glare Contact request receipts are not durably complete",
        ));
    }
    let local_request = request_receipts
        .iter()
        .find(|receipt| receipt.core.holder.subject_id().as_str() == local_holder)
        .ok_or_else(|| {
            super::super::events::peer::schema_violation(
                "glare receipts have no local-holder request",
            )
        })?;
    let Some(counterpart_mirror) = record
        .request_mirror_receipts
        .iter()
        .find(|receipt| {
            receipt.issuer.as_str() == source_service_id
                && receipt.signed_event_ref == local_request.core.request_event_ref
                && receipt.signed_event_digest == local_request.core.request_digest
                && matches!(
                    receipt.disposition,
                    PeerContactDisposition::Accepted | PeerContactDisposition::Duplicate
                )
        })
        .cloned()
    else {
        let control_receipt = sign_contact_control_receipt(
            state,
            request,
            PeerContactControlKind::GlareFinalize,
            PeerContactDisposition::Deferred,
            None,
        )?;
        return Ok(PeerContactSubmitOutcome::ControlDeferred(
            arkret_models_collaboration::contact_operations::PeerContactControlDeferredOutcome {
                status: PeerContactDisposition::Deferred,
                request_kind: PeerContactControlKind::GlareFinalize,
                control_receipt,
                retry_after_ms: Some(1_000),
            },
        ));
    };
    validate_mirror_receipt_cryptography(
        state,
        &counterpart_mirror,
        source_service_id,
        "counterpart_mirror_receipt",
    )?;

    let mut observed_frontier = request_receipts
        .iter()
        .map(|receipt| receipt.core.request_event_ref.clone())
        .collect::<Vec<_>>();
    observed_frontier
        .sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
    let ordered_digests: [Hash; 2] = observed_frontier
        .iter()
        .map(|event_ref| {
            request_receipts
                .iter()
                .find(|receipt| &receipt.core.request_event_ref == event_ref)
                .ok_or_else(|| {
                    super::super::events::peer::schema_violation(
                        "glare frontier does not bind exact request receipts",
                    )
                })
                .and_then(super::account::canonical_contact_digest)
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| AppError::internal("glare receipt digest cardinality invalid"))?;
    let complete_through = local_request.core.slot_version;
    let checkpoint = super::account::canonical_contact_digest(&json!({
        "domain": "ak.contact.glare-unconsumed-slot.v1",
        "holder": local_holder,
        "peer": remote_holder,
        "basis_id": basis_id,
        "request_receipt_digests": ordered_digests,
        "observed_frontier": observed_frontier,
        "complete_through": complete_through,
        "slot_state": "pending_unconsumed"
    }))?;
    let observed_at = now();
    let local_issuer = Did::new(local_holder.to_owned())
        .map_err(|error| AppError::internal(format!("local Contact holder invalid: {error}")))?;
    let remote_peer = Did::new(remote_holder.to_owned())
        .map_err(|error| AppError::internal(format!("remote Contact holder invalid: {error}")))?;
    let mut local_attestation = GlareConcurrencyAttestation {
        issuer: local_issuer.clone(),
        peer: remote_peer,
        request_receipt_digests: ordered_digests,
        observed_frontier: observed_frontier.clone(),
        complete_through,
        unconsumed_slot_checkpoint: checkpoint,
        observed_at,
        signature: placeholder_contact_signature(state, observed_at)?,
    };
    local_attestation.signature = sign_contact_evidence_bytes(
        state,
        observed_at,
        &local_attestation
            .canonical_signing_bytes()
            .map_err(|error| {
                AppError::internal(format!(
                    "local glare attestation transcript failed: {error}"
                ))
            })?,
    )?;

    let fresh_until = observed_at + chrono::Duration::minutes(10);
    let mut local_current_proof = ContactCurrentProof {
        basis_id: basis_id.clone(),
        issuer: local_issuer,
        terminal: false,
        head_event_ref: local_request.core.request_event_ref.clone(),
        head_digest: local_request.core.request_digest.clone(),
        accepted_frontier: observed_frontier,
        complete_through,
        fresh_until,
        signature: placeholder_contact_signature(state, observed_at)?,
    };
    local_current_proof.signature = sign_contact_evidence_bytes(
        state,
        observed_at,
        &local_current_proof
            .canonical_signing_bytes()
            .map_err(|error| {
                AppError::internal(format!(
                    "local Contact current proof transcript failed: {error}"
                ))
            })?,
    )?;

    let mut attestations = [remote_attestation.clone(), local_attestation.clone()];
    attestations.sort_by(|left, right| {
        left.issuer
            .as_str()
            .as_bytes()
            .cmp(right.issuer.as_str().as_bytes())
    });
    let previous_terminal_basis_id = request_receipts
        .iter()
        .filter_map(|receipt| receipt.core.previous_terminal_basis_id.clone())
        .next();
    let partial_bundle = ContactBasisEvidenceBundle {
        basis_id: basis_id.clone(),
        previous_terminal_basis_id,
        basis: basis.clone(),
        request_receipts: request_receipts.to_vec(),
        normal_response_receipt: None,
        glare_concurrency_attestations: Some(attestations),
        // The receiver can author only its own current proof here. The peer's
        // proof arrives through the registered proof-refresh carrier; until
        // then this durable bundle remains tentative and cannot authorize a
        // Direct Conversation founding unit.
        current_proofs: vec![local_current_proof.clone()],
    };
    let expected_updated_at = record.updated_at;
    record.basis_id = Some(basis_id.to_string());
    record.basis_evidence = Some(partial_bundle);
    record.updated_at = observed_at.max(expected_updated_at + chrono::Duration::microseconds(1));
    let result_digest = super::account::canonical_contact_digest(&json!({
        "glare_concurrency_attestation": local_attestation,
        "current_proof": local_current_proof,
    }))?;
    let control_receipt = sign_contact_control_receipt(
        state,
        request,
        PeerContactControlKind::GlareFinalize,
        PeerContactDisposition::Accepted,
        Some(result_digest),
    )?;
    let outcome =
        PeerContactSubmitOutcome::Control(PeerContactControlSubmitOutcome::GlareFinalize {
            status: PeerContactDisposition::Accepted,
            control_receipt,
            glare_concurrency_attestation: local_attestation,
            current_proof: Some(local_current_proof),
        });
    record.control_outcomes.push(outcome.clone());
    save_contact_cas(contacts, expected_updated_at, record).await?;
    Ok(outcome)
}

fn contact_control_request_digest(
    request: &PeerContactSubmitRequestBody,
) -> Result<Hash, AppError> {
    Hash::new(
        canonical::canonical_sha256(request)
            .map_err(|error| AppError::internal(format!("Contact control digest: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("Contact control digest invalid: {error}")))
}

fn replayed_contact_control_outcome(
    record: &ContactRecord,
    request_digest: &Hash,
    request_kind: PeerContactControlKind,
) -> Option<PeerContactSubmitOutcome> {
    record.control_outcomes.iter().find_map(|outcome| {
        let receipt = match outcome {
            PeerContactSubmitOutcome::Control(PeerContactControlSubmitOutcome::ProofRefresh {
                control_receipt,
                ..
            }) if request_kind == PeerContactControlKind::ProofRefresh => control_receipt,
            PeerContactSubmitOutcome::Control(PeerContactControlSubmitOutcome::GlareFinalize {
                control_receipt,
                ..
            }) if request_kind == PeerContactControlKind::GlareFinalize => control_receipt,
            _ => return None,
        };
        (receipt.request_digest == *request_digest).then(|| outcome.clone())
    })
}

fn placeholder_contact_signature(
    state: &AppState,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Result<ProtocolSignature, AppError> {
    Ok(ProtocolSignature {
        verification_method: DidUrl::new(
            crate::routing::federation::federation_service_signature_key_id(state.service_id()),
        )
        .map_err(|error| AppError::internal(format!("service key id invalid: {error}")))?,
        created_at,
        jws: Base64UrlString::new("AA".to_owned()).map_err(|error| {
            AppError::internal(format!("signature placeholder invalid: {error}"))
        })?,
    })
}

fn sign_contact_evidence_bytes(
    state: &AppState,
    created_at: chrono::DateTime<chrono::Utc>,
    signing_bytes: &[u8],
) -> Result<ProtocolSignature, AppError> {
    let signature = state.notary_signing_key().sign(signing_bytes);
    Ok(ProtocolSignature {
        verification_method: DidUrl::new(
            crate::routing::federation::federation_service_signature_key_id(state.service_id()),
        )
        .map_err(|error| AppError::internal(format!("service key id invalid: {error}")))?,
        created_at,
        jws: Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature.to_bytes()))
            .map_err(|error| AppError::internal(format!("Contact signature invalid: {error}")))?,
    })
}

fn validate_contact_lineage_carrier(
    event: &Event,
    lineage: &arkret_models_collaboration::contact_operations::ContactLineage,
    current_proof: &arkret_models_collaboration::contact_operations::ContactCurrentProof,
    terminal: bool,
) -> Result<(), AppError> {
    if lineage.event_ref != event.event_id
        || lineage.issuer.subject_id() != &event.actor_id
        || lineage.basis_id != current_proof.basis_id
        || current_proof.head_event_ref != event.event_id
        || terminal != lineage.terminal.unwrap_or(false)
    {
        return Err(super::super::events::peer::schema_violation(
            "Contact lineage/current proof does not bind signed_event",
        ));
    }
    Ok(())
}

fn sign_contact_mirror_receipt(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    event: &Event,
    disposition: PeerContactDisposition,
) -> Result<PeerContactMirrorReceipt, AppError> {
    let request_digest = Hash::new(
        canonical::canonical_sha256(request)
            .map_err(|error| AppError::internal(format!("Contact request digest: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("Contact request digest invalid: {error}")))?;
    let signed_event_digest = Hash::new(
        event
            .event_digest()
            .map_err(|error| AppError::internal(format!("Contact Event digest: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("Contact Event digest invalid: {error}")))?;
    let received_at = now();
    let issuer = Did::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("service DID invalid: {error}")))?;
    let verification_method = DidUrl::new(
        crate::routing::federation::federation_service_signature_key_id(state.service_id()),
    )
    .map_err(|error| AppError::internal(format!("service verification method invalid: {error}")))?;
    let signing_bytes = canonical::canonical_json_bytes(&json!({
        "domain": "ak.peer-contact.mirror-receipt.v1",
        "request_digest": request_digest,
        "signed_event_ref": event.event_id,
        "signed_event_digest": signed_event_digest,
        "disposition": disposition,
        "recipient_service_id": issuer,
        "received_at": arkret_canonical::format_timestamp_canonical(received_at),
        "issuer": issuer,
    }))
    .map_err(|error| AppError::internal(format!("Contact mirror receipt canonicalize: {error}")))?;
    let signature = state.notary_signing_key().sign(&signing_bytes);
    let jws =
        Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature.to_bytes())).map_err(|error| {
            AppError::internal(format!("Contact mirror signature invalid: {error}"))
        })?;
    Ok(PeerContactMirrorReceipt {
        domain: PeerContactMirrorReceiptDomain::V1,
        request_digest,
        signed_event_ref: event.event_id.clone(),
        signed_event_digest,
        disposition,
        recipient_service_id: issuer.clone(),
        received_at,
        issuer,
        signature: ProtocolSignature {
            verification_method,
            created_at: received_at,
            jws,
        },
    })
}

pub(crate) async fn persist_request_mirror_receipt(
    state: &AppState,
    holder: &str,
    peer: &str,
    receipt: &PeerContactMirrorReceipt,
) -> Result<(), AppError> {
    let contacts = state.contacts();
    let mut record = contacts
        .contact_any(holder, peer)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| {
            AppError::new(
                soland_http::error::ErrorCode::FailedPrecondition,
                "Contact request slot is unavailable for mirror receipt",
            )
        })?;
    let binds_retained_request = record.request_receipts.iter().any(|stored| {
        stored.core.request_event_ref == receipt.signed_event_ref
            && stored.core.request_digest == receipt.signed_event_digest
    });
    if !binds_retained_request {
        return Err(super::super::events::peer::schema_violation(
            "mirror receipt does not bind a retained Contact request receipt",
        ));
    }
    let receipt_digest = super::account::canonical_contact_digest(receipt)?;
    let already_stored = record.request_mirror_receipts.iter().any(|stored| {
        super::account::canonical_contact_digest(stored)
            .is_ok_and(|digest| digest == receipt_digest)
    });
    if !already_stored {
        let expected_updated_at = record.updated_at;
        record.request_mirror_receipts.push(receipt.clone());
        advance_contact_revision(&mut record, expected_updated_at);
        save_contact_cas(contacts, expected_updated_at, record).await?;
    }
    Ok(())
}

/// Continue the sender half of the Contact glare protocol from durable state.
///
/// This is deliberately called from both places that can complete the four
/// prerequisite receipts: the inbound reverse-request handler and the durable
/// outbox response handler. Only the holder whose canonically first request
/// Event is retained is allowed to originate `glare_finalize`, so two servers
/// never elect themselves from local arrival order. The idempotency key and
/// signed attestation are derived from the stable persisted row; replay after
/// lease expiry therefore reconstructs byte-identical carrier JSON.
pub(crate) async fn enqueue_glare_finalize_if_ready(
    state: &AppState,
    holder: &str,
    peer: &str,
) -> Result<bool, AppError> {
    let Some(record) = state
        .contacts()
        .contact_any(holder, peer)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    else {
        return Ok(false);
    };
    if record.status != "pending"
        || record.basis_evidence.is_some()
        || record.request_receipts.len() != 2
    {
        return Ok(false);
    }
    let Some(peer_service_id) = record.peer_service_id.as_deref() else {
        return Ok(false);
    };
    let mut receipts = record.request_receipts.clone();
    receipts.sort_by(|left, right| {
        left.core
            .request_event_ref
            .as_str()
            .as_bytes()
            .cmp(right.core.request_event_ref.as_str().as_bytes())
    });
    if receipts[0].core.holder.subject_id().as_str() != holder
        || receipts[0].core.peer.subject_id().as_str() != peer
        || receipts[1].core.holder.subject_id().as_str() != peer
        || receipts[1].core.peer.subject_id().as_str() != holder
    {
        // The other holder is the unique canonical glare initiator, or the
        // retained receipts do not form the exact reverse-request pair.
        return Ok(false);
    }
    let request_receipts: [RequestAcceptanceReceipt; 2] = receipts
        .try_into()
        .map_err(|_| AppError::internal("glare request receipt cardinality invalid"))?;
    let local_request = &request_receipts[0];
    let Some(remote_mirror_receipt) = record
        .request_mirror_receipts
        .iter()
        .find(|receipt| {
            receipt.issuer.as_str() == peer_service_id
                && receipt.signed_event_ref == local_request.core.request_event_ref
                && receipt.signed_event_digest == local_request.core.request_digest
                && matches!(
                    receipt.disposition,
                    PeerContactDisposition::Accepted | PeerContactDisposition::Duplicate
                )
        })
        .cloned()
    else {
        return Ok(false);
    };
    validate_mirror_receipt_cryptography(
        state,
        &remote_mirror_receipt,
        peer_service_id,
        "glare_remote_mirror_receipt",
    )?;

    let (basis_id, basis, receipt_digests) = derive_glare_basis(&request_receipts)?;
    let observed_frontier = request_receipts
        .iter()
        .map(|receipt| receipt.core.request_event_ref.clone())
        .collect::<Vec<_>>();
    let complete_through = local_request.core.slot_version;
    let observed_at = record.updated_at;
    let checkpoint = super::account::canonical_contact_digest(&json!({
        "domain": "ak.contact.glare-unconsumed-slot.v1",
        "holder": holder,
        "peer": peer,
        "basis_id": basis_id,
        "request_receipt_digests": receipt_digests,
        "observed_frontier": observed_frontier,
        "complete_through": complete_through,
        "slot_state": "pending_unconsumed"
    }))?;
    let mut attestation = GlareConcurrencyAttestation {
        issuer: Did::new(holder.to_owned())
            .map_err(|error| AppError::internal(format!("glare holder DID invalid: {error}")))?,
        peer: Did::new(peer.to_owned())
            .map_err(|error| AppError::internal(format!("glare peer DID invalid: {error}")))?,
        request_receipt_digests: receipt_digests,
        observed_frontier,
        complete_through,
        unconsumed_slot_checkpoint: checkpoint,
        observed_at,
        signature: placeholder_contact_signature(state, observed_at)?,
    };
    attestation.signature = sign_contact_evidence_bytes(
        state,
        observed_at,
        &attestation.canonical_signing_bytes().map_err(|error| {
            AppError::internal(format!("glare attestation transcript failed: {error}"))
        })?,
    )?;
    let idempotency_key = IdempotencyKey::new(format!("contact-glare-finalize:{basis_id}"))
        .map_err(|error| AppError::internal(format!("glare idempotency key invalid: {error}")))?;
    let delivery = PeerContactSubmitRequestBody::GlareFinalize {
        idempotency_key,
        basis_id,
        basis,
        request_receipts,
        remote_mirror_receipt,
        glare_concurrency_attestation: attestation,
        contact_address: PeerContactAddress {
            subject_id: Did::new(peer.to_owned()).map_err(|error| {
                AppError::internal(format!("glare recipient DID invalid: {error}"))
            })?,
            recipient_service_id: Did::new(peer_service_id.to_owned()).map_err(|error| {
                AppError::internal(format!("glare recipient service DID invalid: {error}"))
            })?,
            recipient_service_kind: None,
        },
    };
    enqueue_peer_contact_carrier(state, peer_service_id, &delivery).await
}

fn derive_glare_basis(
    request_receipts: &[RequestAcceptanceReceipt; 2],
) -> Result<(Hash, ContactBasis, [Hash; 2]), AppError> {
    let receipt_digests = [
        super::account::canonical_contact_digest(&request_receipts[0])?,
        super::account::canonical_contact_digest(&request_receipts[1])?,
    ];
    let mut pair = [
        request_receipts[0].core.holder.subject_id().clone(),
        request_receipts[1].core.holder.subject_id().clone(),
    ];
    pair.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
    let basis = ContactBasis::Glare {
        sorted_pair_members: pair,
        requests: [
            arkret_models_collaboration::contact_operations::ContactBasisRequestRef {
                request_event_ref: request_receipts[0].core.request_event_ref.clone(),
                request_acceptance_receipt_digest: receipt_digests[0].clone(),
            },
            arkret_models_collaboration::contact_operations::ContactBasisRequestRef {
                request_event_ref: request_receipts[1].core.request_event_ref.clone(),
                request_acceptance_receipt_digest: receipt_digests[1].clone(),
            },
        ],
    };
    let basis_id = contact_basis_id(&basis)?;
    Ok((basis_id, basis, receipt_digests))
}

fn contact_basis_id(basis: &ContactBasis) -> Result<Hash, AppError> {
    #[derive(serde::Serialize)]
    struct BasisDigestTranscript<'a> {
        domain: &'static str,
        #[serde(flatten)]
        basis: &'a ContactBasis,
    }
    super::account::canonical_contact_digest(&BasisDigestTranscript {
        domain: "ak.contact.basis.v1",
        basis,
    })
}

pub(crate) async fn accept_outbound_contact_control_outcome(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    outcome: &PeerContactSubmitOutcome,
    peer_service_id: &str,
) -> Result<(), AppError> {
    match (request, outcome) {
        (
            PeerContactSubmitRequestBody::GlareFinalize {
                basis_id,
                basis,
                request_receipts,
                remote_mirror_receipt,
                glare_concurrency_attestation: local_attestation,
                contact_address,
                ..
            },
            PeerContactSubmitOutcome::Control(PeerContactControlSubmitOutcome::GlareFinalize {
                status,
                control_receipt,
                glare_concurrency_attestation: remote_attestation,
                current_proof: Some(remote_proof),
            }),
        ) if matches!(
            status,
            PeerContactDisposition::Accepted | PeerContactDisposition::Duplicate
        ) =>
        {
            validate_outbound_control_receipt(
                state,
                request,
                control_receipt,
                PeerContactControlKind::GlareFinalize,
                peer_service_id,
                Some(super::account::canonical_contact_digest(&json!({
                    "glare_concurrency_attestation": remote_attestation,
                    "current_proof": remote_proof,
                }))?),
            )?;
            let (derived_basis_id, derived_basis, receipt_digests) =
                derive_glare_basis(request_receipts)?;
            if &derived_basis_id != basis_id
                || serde_json::to_value(&derived_basis)
                    .map_err(|error| AppError::internal(format!("glare basis: {error}")))?
                    != serde_json::to_value(basis)
                        .map_err(|error| AppError::internal(format!("glare basis: {error}")))?
                || remote_attestation.issuer != contact_address.subject_id
                || remote_attestation.peer != local_attestation.issuer
                || remote_attestation.request_receipt_digests != receipt_digests
                || remote_proof.basis_id != *basis_id
                || remote_proof.issuer != contact_address.subject_id
                || remote_proof.terminal
                || remote_proof.fresh_until <= now()
            {
                return Err(super::super::events::peer::schema_violation(
                    "glare finalize outcome does not bind the outbound request",
                ));
            }
            let remote_request = request_receipts
                .iter()
                .find(|receipt| receipt.core.holder.subject_id() == &contact_address.subject_id)
                .ok_or_else(|| {
                    super::super::events::peer::schema_violation(
                        "glare finalize has no remote-holder request receipt",
                    )
                })?;
            if remote_proof.head_event_ref != remote_request.core.request_event_ref
                || remote_proof.head_digest != remote_request.core.request_digest
                || !remote_proof
                    .accepted_frontier
                    .contains(&remote_proof.head_event_ref)
                || remote_attestation.complete_through == 0
                || !remote_attestation
                    .observed_frontier
                    .iter()
                    .all(|event_ref| {
                        request_receipts
                            .iter()
                            .any(|receipt| &receipt.core.request_event_ref == event_ref)
                    })
            {
                return Err(super::super::events::peer::schema_violation(
                    "glare finalize outcome proof/frontier is incomplete",
                ));
            }
            verify_contact_evidence_signature(
                state,
                peer_service_id,
                &remote_attestation.signature,
                &remote_attestation
                    .canonical_signing_bytes()
                    .map_err(|error| {
                        AppError::internal(format!("remote glare attestation transcript: {error}"))
                    })?,
                "remote_glare_attestation",
            )?;
            verify_contact_evidence_signature(
                state,
                peer_service_id,
                &remote_proof.signature,
                &remote_proof.canonical_signing_bytes().map_err(|error| {
                    AppError::internal(format!("remote Contact current proof transcript: {error}"))
                })?,
                "remote_current_proof",
            )?;

            let local_holder = local_attestation.issuer.as_str();
            let remote_holder = contact_address.subject_id.as_str();
            let contacts = state.contacts();
            let mut record = contacts
                .contact_any(local_holder, remote_holder)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .ok_or_else(|| {
                    AppError::new(
                        soland_http::error::ErrorCode::FailedPrecondition,
                        "outbound glare Contact slot is unavailable",
                    )
                })?;
            if record.peer_service_id.as_deref() != Some(peer_service_id) {
                return Err(super::super::events::peer::cross_domain_replay(
                    "glare outcome service does not match durable Contact peer",
                ));
            }
            let local_request = request_receipts
                .iter()
                .find(|receipt| receipt.core.holder.subject_id().as_str() == local_holder)
                .ok_or_else(|| {
                    super::super::events::peer::schema_violation(
                        "glare finalize has no local-holder request receipt",
                    )
                })?;
            let mut bundle = if let Some(bundle) = record.basis_evidence.clone() {
                if bundle.basis_id != *basis_id || bundle.glare_concurrency_attestations.is_none() {
                    return Err(AppError::conflict(
                        "outbound glare outcome conflicts with durable Contact basis",
                    ));
                }
                bundle
            } else {
                let observed_at = now();
                let mut local_proof = ContactCurrentProof {
                    basis_id: basis_id.clone(),
                    issuer: local_attestation.issuer.clone(),
                    terminal: false,
                    head_event_ref: local_request.core.request_event_ref.clone(),
                    head_digest: local_request.core.request_digest.clone(),
                    accepted_frontier: request_receipts
                        .iter()
                        .map(|receipt| receipt.core.request_event_ref.clone())
                        .collect(),
                    complete_through: local_request.core.slot_version,
                    fresh_until: observed_at + chrono::Duration::minutes(10),
                    signature: placeholder_contact_signature(state, observed_at)?,
                };
                local_proof.signature = sign_contact_evidence_bytes(
                    state,
                    observed_at,
                    &local_proof.canonical_signing_bytes().map_err(|error| {
                        AppError::internal(format!("local Contact proof transcript: {error}"))
                    })?,
                )?;
                let mut attestations = [local_attestation.clone(), remote_attestation.clone()];
                attestations.sort_by(|left, right| {
                    left.issuer
                        .as_str()
                        .as_bytes()
                        .cmp(right.issuer.as_str().as_bytes())
                });
                ContactBasisEvidenceBundle {
                    basis_id: basis_id.clone(),
                    previous_terminal_basis_id: request_receipts
                        .iter()
                        .find_map(|receipt| receipt.core.previous_terminal_basis_id.clone()),
                    basis: basis.clone(),
                    request_receipts: request_receipts.to_vec(),
                    normal_response_receipt: None,
                    glare_concurrency_attestations: Some(attestations),
                    current_proofs: vec![local_proof],
                }
            };
            let local_proof = bundle
                .current_proofs
                .iter()
                .find(|proof| proof.issuer.as_str() == local_holder)
                .cloned()
                .ok_or_else(|| {
                    AppError::new(
                        soland_http::error::ErrorCode::FailedPrecondition,
                        "durable local Contact proof is unavailable",
                    )
                })?;
            bundle
                .current_proofs
                .retain(|proof| proof.issuer != remote_proof.issuer);
            bundle.current_proofs.push(remote_proof.clone());
            bundle.current_proofs.sort_by(|left, right| {
                left.issuer
                    .as_str()
                    .as_bytes()
                    .cmp(right.issuer.as_str().as_bytes())
            });
            let outcome_digest = super::account::canonical_contact_digest(outcome)?;
            let outcome_stored = record.control_outcomes.iter().any(|stored| {
                super::account::canonical_contact_digest(stored)
                    .is_ok_and(|digest| digest == outcome_digest)
            });
            if !outcome_stored || record.status != "accepted" {
                let expected_updated_at = record.updated_at;
                record.basis_id = Some(basis_id.to_string());
                record.version = Some(1);
                record.status = "accepted".to_owned();
                record.basis_evidence = Some(bundle);
                if !outcome_stored {
                    record.control_outcomes.push(outcome.clone());
                }
                advance_contact_revision(&mut record, expected_updated_at);
                save_contact_cas(contacts, expected_updated_at, record).await?;
            }

            let proof_digest = super::account::canonical_contact_digest(&local_proof)?;
            let idempotency_key =
                IdempotencyKey::new(format!("contact-proof-refresh:{basis_id}:{proof_digest}"))
                    .map_err(|error| {
                        AppError::internal(format!(
                            "proof-refresh idempotency key invalid: {error}"
                        ))
                    })?;
            let delivery = PeerContactSubmitRequestBody::ProofRefresh {
                idempotency_key,
                prior_mirror_receipt: remote_mirror_receipt.clone(),
                current_proof: local_proof,
                contact_address: contact_address.clone(),
            };
            enqueue_peer_contact_carrier(state, peer_service_id, &delivery).await?;
            Ok(())
        }
        (
            PeerContactSubmitRequestBody::ProofRefresh { current_proof, .. },
            PeerContactSubmitOutcome::Control(PeerContactControlSubmitOutcome::ProofRefresh {
                status,
                control_receipt,
                current_proof: returned_proof,
            }),
        ) if matches!(
            status,
            PeerContactDisposition::Accepted | PeerContactDisposition::Duplicate
        ) =>
        {
            if super::account::canonical_contact_digest(current_proof)?
                != super::account::canonical_contact_digest(returned_proof)?
            {
                return Err(super::super::events::peer::schema_violation(
                    "proof-refresh outcome changed the submitted current proof",
                ));
            }
            validate_outbound_control_receipt(
                state,
                request,
                control_receipt,
                PeerContactControlKind::ProofRefresh,
                peer_service_id,
                Some(super::account::canonical_contact_digest(returned_proof)?),
            )
        }
        _ => Err(super::super::events::peer::schema_violation(
            "Contact control outcome does not match the outbound request branch",
        )),
    }
}

pub(crate) async fn reenqueue_deferred_contact_control(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    deferred: &arkret_models_collaboration::contact_operations::PeerContactControlDeferredOutcome,
    peer_service_id: &str,
) -> Result<(), AppError> {
    let expected_kind = match request {
        PeerContactSubmitRequestBody::GlareFinalize { .. } => PeerContactControlKind::GlareFinalize,
        PeerContactSubmitRequestBody::ProofRefresh { .. } => PeerContactControlKind::ProofRefresh,
        _ => {
            return Err(super::super::events::peer::schema_violation(
                "deferred Contact control outcome names an Event carrier",
            ));
        }
    };
    if deferred.status != PeerContactDisposition::Deferred
        || deferred.request_kind != expected_kind
        || deferred.control_receipt.disposition != PeerContactDisposition::Deferred
        || deferred.control_receipt.result_digest.is_some()
    {
        return Err(super::super::events::peer::schema_violation(
            "deferred Contact control outcome has inconsistent status/kind",
        ));
    }
    let request_digest = contact_control_request_digest(request)?;
    let receipt = &deferred.control_receipt;
    if receipt.request_kind != expected_kind
        || receipt.request_digest != request_digest
        || receipt.issuer.as_str() != peer_service_id
        || receipt.recipient_service_id.as_str() != peer_service_id
    {
        return Err(super::super::events::peer::schema_violation(
            "deferred Contact control receipt does not bind the request",
        ));
    }
    let signing_bytes = contact_control_receipt_signing_bytes(receipt)?;
    verify_contact_evidence_signature(
        state,
        peer_service_id,
        &receipt.signature,
        &signing_bytes,
        "deferred Contact control receipt",
    )?;

    // A semantic response was received, so the next evaluation uses a fresh
    // key. It is deterministically derived from the previous exact body digest
    // so response-loss replay enqueues the same successor intent, while a
    // second deferred response (whose request includes that successor key)
    // advances to another key.
    let next_key = IdempotencyKey::new(format!("contact-control-retry:{request_digest}"))
        .map_err(|error| AppError::internal(format!("Contact retry key invalid: {error}")))?;
    let mut retry = request.clone();
    match &mut retry {
        PeerContactSubmitRequestBody::GlareFinalize {
            idempotency_key, ..
        }
        | PeerContactSubmitRequestBody::ProofRefresh {
            idempotency_key, ..
        } => *idempotency_key = next_key,
        _ => unreachable!("request branch checked above"),
    }
    enqueue_peer_contact_carrier(state, peer_service_id, &retry).await?;
    Ok(())
}

fn validate_outbound_control_receipt(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    receipt: &PeerContactControlReceipt,
    expected_kind: PeerContactControlKind,
    peer_service_id: &str,
    expected_result_digest: Option<Hash>,
) -> Result<(), AppError> {
    let request_digest = contact_control_request_digest(request)?;
    if receipt.request_kind != expected_kind
        || receipt.request_digest != request_digest
        || receipt.disposition == PeerContactDisposition::Deferred
        || receipt.result_digest != expected_result_digest
        || receipt.issuer.as_str() != peer_service_id
        || receipt.recipient_service_id.as_str() != peer_service_id
    {
        return Err(super::super::events::peer::schema_violation(
            "Contact control receipt does not bind the outbound request/result",
        ));
    }
    let signing_bytes = contact_control_receipt_signing_bytes(receipt)?;
    verify_contact_evidence_signature(
        state,
        peer_service_id,
        &receipt.signature,
        &signing_bytes,
        "Contact control receipt",
    )
}

#[derive(serde::Serialize)]
struct ContactControlReceiptSigningTranscript<'a> {
    domain: &'a PeerContactControlReceiptDomain,
    request_kind: PeerContactControlKind,
    request_digest: &'a Hash,
    disposition: PeerContactDisposition,
    #[serde(skip_serializing_if = "Option::is_none")]
    result_digest: Option<&'a Hash>,
    recipient_service_id: &'a Did,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    received_at: chrono::DateTime<chrono::Utc>,
    issuer: &'a Did,
}

fn contact_control_receipt_signing_bytes(
    receipt: &PeerContactControlReceipt,
) -> Result<Vec<u8>, AppError> {
    canonical::canonical_json_bytes(&ContactControlReceiptSigningTranscript {
        domain: &receipt.domain,
        request_kind: receipt.request_kind,
        request_digest: &receipt.request_digest,
        disposition: receipt.disposition,
        result_digest: receipt.result_digest.as_ref(),
        recipient_service_id: &receipt.recipient_service_id,
        received_at: receipt.received_at,
        issuer: &receipt.issuer,
    })
    .map_err(|error| AppError::internal(format!("Contact control receipt transcript: {error}")))
}

fn verify_contact_evidence_signature(
    state: &AppState,
    service_id: &str,
    signature: &ProtocolSignature,
    signing_bytes: &[u8],
    field: &str,
) -> Result<(), AppError> {
    super::account::verify_contact_service_signature_bytes(
        state,
        service_id,
        signature,
        signing_bytes,
        field,
    )
}

fn advance_contact_revision(
    record: &mut ContactRecord,
    expected_updated_at: chrono::DateTime<chrono::Utc>,
) {
    record.updated_at = now().max(expected_updated_at + chrono::Duration::microseconds(1));
}

async fn save_contact_cas(
    contacts: &soland_services::identity::ContactService,
    expected_updated_at: chrono::DateTime<chrono::Utc>,
    record: ContactRecord,
) -> Result<(), AppError> {
    let saved = contacts
        .save_contact_if_updated_at(expected_updated_at, record)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if !saved {
        return Err(AppError::conflict(
            "Contact evidence changed concurrently; replay the exact request",
        ));
    }
    Ok(())
}

fn sign_contact_control_receipt(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    request_kind: PeerContactControlKind,
    disposition: PeerContactDisposition,
    result_digest: Option<Hash>,
) -> Result<PeerContactControlReceipt, AppError> {
    let request_digest = Hash::new(
        canonical::canonical_sha256(request)
            .map_err(|error| AppError::internal(format!("Contact control digest: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("Contact control digest invalid: {error}")))?;
    let received_at = now();
    let issuer = Did::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("service DID invalid: {error}")))?;
    let verification_method = DidUrl::new(
        crate::routing::federation::federation_service_signature_key_id(state.service_id()),
    )
    .map_err(|error| AppError::internal(format!("service verification method invalid: {error}")))?;
    let mut signing_value = json!({
        "domain": "ak.peer-contact.control-receipt.v1",
        "request_kind": request_kind,
        "request_digest": request_digest,
        "disposition": disposition,
        "result_digest": result_digest,
        "recipient_service_id": issuer,
        "received_at": arkret_canonical::format_timestamp_canonical(received_at),
        "issuer": issuer,
    });
    if result_digest.is_none()
        && let Value::Object(fields) = &mut signing_value
    {
        fields.remove("result_digest");
    }
    let signing_bytes = canonical::canonical_json_bytes(&signing_value).map_err(|error| {
        AppError::internal(format!("Contact control receipt canonicalize: {error}"))
    })?;
    let signature = state.notary_signing_key().sign(&signing_bytes);
    let jws =
        Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature.to_bytes())).map_err(|error| {
            AppError::internal(format!("Contact control signature invalid: {error}"))
        })?;
    Ok(PeerContactControlReceipt {
        domain: PeerContactControlReceiptDomain::V1,
        request_kind,
        request_digest,
        disposition,
        result_digest,
        recipient_service_id: issuer.clone(),
        received_at,
        issuer,
        signature: ProtocolSignature {
            verification_method,
            created_at: received_at,
            jws,
        },
    })
}

fn validate_contact_introduction_evidence_digest(
    payload: &Value,
    evidence: &ContactIntroductionEvidence,
) -> Result<(), AppError> {
    let expected = payload
        .get("introduction_evidence_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            super::super::events::peer::schema_violation(
                "contact_requested_payload.introduction_evidence_digest is required",
            )
        })?;
    let canonical = canonical::canonical_json_bytes(evidence).map_err(|error| {
        super::super::events::peer::schema_violation(format!(
            "contact introduction_evidence is not canonical-hashable: {error}"
        ))
    })?;
    let mut transcript = b"ak.contact.introduction-evidence.v1\n".to_vec();
    transcript.extend(canonical);
    let actual = canonical::sha256_digest(transcript);
    if expected != actual {
        return Err(super::super::events::peer::schema_violation(
            "contact_requested_payload.introduction_evidence_digest mismatch",
        ));
    }
    Ok(())
}

async fn should_stub_incoming_contact_message(
    state: &AppState,
    requester: &str,
    target: &str,
    _scope: &str,
) -> Result<bool, AppError> {
    let contacts = state
        .contacts()
        .contacts_for_actor(target)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let accepted_contact = contacts.iter().any(|record| {
        record.status == "accepted"
            && ((record.requester == requester && record.target == target)
                || (record.requester == target && record.target == requester))
    });
    Ok(!accepted_contact)
}

async fn append_stubbed_contact_message_audit(
    state: &AppState,
    target: &str,
    requester: &str,
    scope: &str,
    message: &str,
    contact_event_id: &str,
) {
    super::append_audit_log(
        state,
        Some(target),
        "peer.contacts.message_stubbed",
        json!({
            "requester": requester,
            "target": target,
            "scope": scope,
            "contact_event_id": contact_event_id,
            "message_chars": message.chars().count(),
            "message_digest": canonical::sha256_digest(message.as_bytes()),
        }),
        "accepted",
    )
    .await;
}

async fn append_delivered_contact_fact_projection_event(
    state: &AppState,
    fact_kind: &str,
    issuer: &str,
    payload: &Value,
    contact_event_id: &str,
) {
    let Some(event_kind) = arkret_wire::EventKind::try_new(fact_kind) else {
        tracing::warn!(
            fact_kind,
            "contact fact has no registered EventKind; projection skipped"
        );
        return;
    };
    let mut payload = payload.clone();
    if let Value::Object(object) = &mut payload {
        object
            .entry("event_id".to_owned())
            .or_insert_with(|| Value::String(contact_event_id.to_owned()));
        object.insert(
            "original_issuer".to_owned(),
            Value::String(issuer.to_owned()),
        );
    }
    let realm_id = match crate::routing::identity::principal_control_realm_for_actor(state, issuer)
    {
        Ok(realm_id) => realm_id.into_string(),
        Err(error) => {
            tracing::warn!(%error, issuer, "delivered contact fact issuer PCR unavailable");
            return;
        }
    };
    let _ = crate::routing::events::projection::append_projection_event(
        state,
        ProjectionEventRecord {
            event_id: contact_event_id.to_owned(),
            realm_id,
            event_kind,
            operation_kind: "delivered_contact_fact".to_owned(),
            operation_id: None,
            sender: Some(issuer.to_owned()),
            payload,
            created_at: now(),
            received_at: now(),
        },
    )
    .await;
}

/// Project a delivered contact fact into the local `subject_id`'s contact
/// projection. Returns the receive status (`accepted` / `duplicate`).
async fn project_delivered_contact_fact(
    state: &AppState,
    fact_kind: &str,
    issuer: &str,
    subject_id: &str,
    payload: &Value,
    contact_event_id: &str,
    request_receipt: Option<&RequestAcceptanceReceipt>,
    source_service_id: Option<&str>,
) -> Result<&'static str, AppError> {
    let projected_scopes = granted_scopes(payload);
    let scope = projected_scopes
        .first()
        .cloned()
        .unwrap_or_else(|| "direct_message".to_owned());
    let contacts = state.contacts();
    match fact_kind {
        "ak.contact.requested" => {
            let request_receipt = request_receipt.ok_or_else(|| {
                super::super::events::peer::schema_violation(
                    "Contact request carrier is missing its acceptance receipt",
                )
            })?;
            let request = serde_json::from_value::<ContactRequestedPayload>(payload.clone())
                .map_err(|_| {
                    super::super::events::peer::schema_violation(
                        "invalid ak.contact.requested payload",
                    )
                })?;
            if request.peer.subject_id().as_str() != subject_id {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.requested peer does not match the addressed holder",
                ));
            }
            // requester = issuer, target = subject_id (this holder). Form a
            // pending_incoming row on the target side.
            let raw_message = payload
                .get("message")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let stub_message = raw_message.is_some()
                && should_stub_incoming_contact_message(state, issuer, subject_id, &scope).await?;
            let message = if stub_message {
                Some(CONTACT_MESSAGE_STUB.to_owned())
            } else {
                raw_message.clone()
            };
            if let Some(mut existing) = contacts
                .contact_any(issuer, subject_id)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
            {
                if existing.status == "pending"
                    && existing.request_event_ref.as_deref() == Some(contact_event_id)
                {
                    if !existing.request_receipts.iter().any(|stored| {
                        stored.core.request_event_ref == request_receipt.core.request_event_ref
                            && stored.core.request_digest == request_receipt.core.request_digest
                    }) {
                        let expected_updated_at = existing.updated_at;
                        existing.request_receipts.push(request_receipt.clone());
                        advance_contact_revision(&mut existing, expected_updated_at);
                        save_contact_cas(contacts, expected_updated_at, existing).await?;
                    }
                    return Ok("duplicate");
                }
                if existing.status == "pending"
                    && existing.requester == subject_id
                    && existing.target == issuer
                    && existing.request_event_ref.as_deref() != Some(contact_event_id)
                {
                    // A reverse request may coexist only as an unconsumed
                    // glare candidate. Preserve the original request
                    // orientation and append the exact second source receipt;
                    // founder selection later uses canonical Event-ref order,
                    // never arrival order or DID order.
                    if !existing
                        .request_receipts
                        .iter()
                        .any(|stored| stored.core.request_event_ref.as_str() == contact_event_id)
                    {
                        let expected_updated_at = existing.updated_at;
                        existing.request_receipts.push(request_receipt.clone());
                        existing.granted_to_requester_scopes = projected_scopes.clone();
                        existing.peer_service_id = source_service_id.map(ToOwned::to_owned);
                        advance_contact_revision(&mut existing, expected_updated_at);
                        save_contact_cas(contacts, expected_updated_at, existing).await?;
                    }
                    return Ok("accepted");
                }
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.requested conflicts with the permanent Contact request slot",
                ));
            }
            let contact = ContactRecord {
                requester: issuer.to_owned(),
                target: subject_id.to_owned(),
                basis_id: None,
                version: None,
                granted_to_target_scopes: projected_scopes,
                granted_to_requester_scopes: Vec::new(),
                status: "pending".to_owned(),
                request_event_ref: Some(contact_event_id.to_owned()),
                request_receipts: vec![request_receipt.clone()],
                request_mirror_receipts: Vec::new(),
                basis_evidence: None,
                control_outcomes: Vec::new(),
                response_event_ref: None,
                tombstone_event_ref: None,
                message,
                // Peer end of this pending_incoming row is the remote requester
                // (`issuer`), hosted on the delivering source server. The local
                // holder later uses this as the reverse-delivery target when it
                // responds (inkson's `requester_service_id`).
                peer_service_id: source_service_id.map(ToOwned::to_owned),
                created_at: now(),
                updated_at: now(),
            };
            contacts
                .save_contact(contact)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            if stub_message {
                append_stubbed_contact_message_audit(
                    state,
                    subject_id,
                    issuer,
                    &scope,
                    raw_message.as_deref().unwrap_or_default(),
                    contact_event_id,
                )
                .await;
            }
            append_delivered_contact_fact_projection_event(
                state,
                fact_kind,
                issuer,
                payload,
                contact_event_id,
            )
            .await;
            Ok("accepted")
        }
        "ak.contact.accepted" => {
            let accepted = serde_json::from_value::<ContactAcceptedPayload>(payload.clone())
                .map_err(|_| {
                    super::super::events::peer::schema_violation(
                        "invalid ak.contact.accepted payload",
                    )
                })?;
            if accepted.peer.subject_id().as_str() != subject_id {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.accepted peer does not match the original requester",
                ));
            }
            // Travelling back to the original requester (subject_id). The
            // target (issuer) accepted: flip the requester-side row to accepted
            // and project the issuer -> requester consent grants by their
            // original event refs, so the requester's row surfaces
            // invite_consent_grant_ref / bidirectional scopes without
            // re-minting target-controlled grant facts locally.
            let Some(mut contact) = contacts
                .contact_any(subject_id, issuer)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
            else {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.accepted references no local pending request",
                ));
            };
            if contact.status == "accepted" {
                if contact.response_event_ref.as_deref() == Some(contact_event_id) {
                    return Ok("duplicate");
                }
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.accepted conflicts with the accepted Contact basis",
                ));
            }
            if contact.status != "pending" || contact.request_event_ref.is_none() {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.accepted references a non-pending or unverifiable request",
                ));
            }
            if accepted.request_event_ref.as_str() != contact.request_event_ref.as_deref().unwrap()
            {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.accepted request_id does not match the pending request",
                ));
            }
            contact.granted_to_requester_scopes = granted_scopes(payload);
            contact.basis_id = Some(accepted.basis_id.to_string());
            contact.version = Some(accepted.version);
            contact.status = "accepted".to_owned();
            contact.response_event_ref = Some(contact_event_id.to_owned());
            contact.updated_at = now();
            // Peer end is the remote accepter (`issuer`), hosted on the
            // delivering source server. Record/backfill it so the requester's
            // row can address future invites/responses to the peer's home PS.
            if let Some(source) = source_service_id {
                contact.peer_service_id = Some(source.to_owned());
            }
            contacts
                .save_contact(contact)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            append_delivered_contact_fact_projection_event(
                state,
                fact_kind,
                issuer,
                payload,
                contact_event_id,
            )
            .await;
            Ok("accepted")
        }
        "ak.contact.rejected" => {
            let rejected = serde_json::from_value::<ContactRejectedPayload>(payload.clone())
                .map_err(|_| {
                    super::super::events::peer::schema_violation(
                        "invalid ak.contact.rejected payload",
                    )
                })?;
            if rejected.peer.subject_id().as_str() != subject_id {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.rejected peer does not match the original requester",
                ));
            }
            let Some(mut contact) = contacts
                .contact_any(subject_id, issuer)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
            else {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.rejected references no local pending request",
                ));
            };
            if contact.status == "rejected" {
                if contact.response_event_ref.as_deref() == Some(contact_event_id) {
                    return Ok("duplicate");
                }
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.rejected conflicts with the consumed request slot",
                ));
            }
            if contact.status != "pending" || contact.request_event_ref.is_none() {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.rejected references a non-pending or unverifiable request",
                ));
            }
            if rejected.request_event_ref.as_str() != contact.request_event_ref.as_deref().unwrap()
            {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.rejected request_id does not match the pending request",
                ));
            }
            contact.status = "rejected".to_owned();
            contact.response_event_ref = Some(contact_event_id.to_owned());
            contact.updated_at = now();
            contacts
                .save_contact(contact)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            append_delivered_contact_fact_projection_event(
                state,
                fact_kind,
                issuer,
                payload,
                contact_event_id,
            )
            .await;
            Ok("accepted")
        }
        "ak.contact.scope.update" => {
            let update = serde_json::from_value::<ContactScopeUpdatePayload>(payload.clone())
                .map_err(|_| {
                    super::super::events::peer::schema_violation(
                        "invalid ak.contact.scope.update payload",
                    )
                })?;
            if update.peer.subject_id().as_str() != subject_id {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.scope.update peer does not match the addressed holder",
                ));
            }
            let Some(mut contact) = contacts
                .contact_any(issuer, subject_id)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
            else {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.scope.update references no accepted basis",
                ));
            };
            let predecessor = if contact.requester == issuer {
                contact.request_event_ref.as_deref()
            } else {
                contact.response_event_ref.as_deref()
            };
            if contact.status != "accepted"
                || contact.basis_id.as_deref() != Some(update.basis_id.as_str())
                || contact.version.and_then(|value| value.checked_add(1)) != Some(update.version)
                || predecessor != Some(update.predecessor_event_ref.as_str())
            {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.scope.update lineage CAS mismatch",
                ));
            }
            contact.version = Some(update.version);
            if contact.requester == issuer {
                contact.granted_to_target_scopes = projected_scopes;
                contact.request_event_ref = Some(contact_event_id.to_owned());
            } else {
                contact.granted_to_requester_scopes = projected_scopes;
                contact.response_event_ref = Some(contact_event_id.to_owned());
            }
            contact.updated_at = now();
            contacts
                .save_contact(contact)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            Ok("accepted")
        }
        "ak.contact.tombstoned" => {
            let tombstone = serde_json::from_value::<ContactTombstonedPayload>(payload.clone())
                .map_err(|_| {
                    super::super::events::peer::schema_violation(
                        "invalid ak.contact.tombstoned payload",
                    )
                })?;
            if tombstone.peer.subject_id().as_str() != subject_id {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.tombstoned peer does not match the addressed holder",
                ));
            }
            let Some(mut row) = contacts
                .contact_any(issuer, subject_id)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
            else {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.tombstoned references no Contact basis",
                ));
            };
            if row.status == "tombstoned" {
                if row.tombstone_event_ref.as_deref() == Some(contact_event_id) {
                    return Ok("duplicate");
                }
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.tombstoned conflicts with the terminal Contact basis",
                ));
            }
            let predecessor = if row.requester == issuer {
                row.request_event_ref.as_deref()
            } else {
                row.response_event_ref.as_deref()
            };
            if row.basis_id.as_deref() != Some(tombstone.basis_id.as_str())
                || row.version.and_then(|value| value.checked_add(1)) != Some(tombstone.version)
                || predecessor != Some(tombstone.predecessor_event_ref.as_str())
            {
                return Err(super::super::events::peer::schema_violation(
                    "ak.contact.tombstoned lineage CAS mismatch",
                ));
            }
            row.version = Some(tombstone.version);
            row.status = "tombstoned".to_owned();
            row.tombstone_event_ref = Some(contact_event_id.to_owned());
            row.updated_at = now();
            contacts
                .save_contact(row)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            append_delivered_contact_fact_projection_event(
                state,
                fact_kind,
                issuer,
                payload,
                contact_event_id,
            )
            .await;
            Ok("accepted")
        }
        other => Err(super::super::events::peer::schema_violation(format!(
            "unsupported contact fact_kind {other}"
        ))),
    }
}

fn granted_scopes(payload: &Value) -> Vec<String> {
    payload
        .get("granted_to_peer_scopes")
        .and_then(Value::as_array)
        .map(|scopes| {
            scopes
                .iter()
                .filter_map(Value::as_str)
                .filter(|scope| {
                    serde_json::from_value::<ContactScope>(Value::String((*scope).to_owned()))
                        .is_ok()
                })
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {

    use soland_storage_postgres::Db;

    use super::*;
    use crate::config::{AppConfig, ObjectStorageConfig};

    fn test_config() -> AppConfig {
        AppConfig {
            public_base_url: "http://test".to_owned(),
            object_storage: ObjectStorageConfig::local(std::env::temp_dir()),
            development_mode: true,
            did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
            jws_replay_window_seconds: 0,
            jws_replay_window_per_family: std::collections::BTreeMap::new(),
            seal_compaction_min_age_seconds: 0,
            compaction_min_witnesses: 0,
            compaction_preserve_genesis: false,
            compaction_prune_only_singleton_successors: false,
            trust_domain: "ak:trust_domain:recipient.local".to_owned(),
            ..AppConfig::test_default()
        }
    }

    fn request_receipt(
        holder: &str,
        peer: &str,
        issuer: &str,
        event_ref: &str,
        digest_byte: char,
    ) -> RequestAcceptanceReceipt {
        serde_json::from_value(json!({
            "core": {
                "holder": {"kind": "human", "principal_id": holder},
                "peer": {"kind": "human", "principal_id": peer},
                "slot_version": 1,
                "request_event_ref": event_ref,
                "request_digest": format!("sha256:{}", digest_byte.to_string().repeat(64)),
                "source_checkpoint": format!("sha256:{}", "c".repeat(64)),
                "accepted_at": "2026-08-09T00:00:00.000Z",
                "issuer": issuer
            },
            "receipt_digest": format!("sha256:{}", "d".repeat(64)),
            "signature": {
                "verification_method": format!("{issuer}#federation-signing-key"),
                "created_at": "2026-08-09T00:00:00.000Z",
                "jws": "YWJj"
            }
        }))
        .expect("request receipt fixture")
    }

    /// Cross-PS `ak.contact.requested` delivery: the projected pending_incoming
    /// row on the recipient (target holder) MUST record the *originating*
    /// requester's home Principal Server as `peer_service_id` — the
    /// `source-service-id` of the delivery, NOT the recipient's own service
    /// DID. This is exactly the address inkson reads back as
    /// `requester_service_id` to federate the reverse `respond` delivery.
    #[tokio::test]
    async fn delivered_request_records_originating_peer_service_id() {
        let state = AppState::new(test_config(), Db { pool: None });
        let requester = "did:web:remote-alice.example"; // issuer, on source PS
        let target = "did:web:local-bob.example"; // subject_id, this holder
        let source_service_id = "did:web:remote.local"; // requester's home PS

        let payload = json!({
            "peer": {"kind": "human", "principal_id": target},
            "granted_to_peer_scopes": ["direct_message"],
            "introduction_evidence_digest": format!("sha256:{}", "a".repeat(64)),
            "message": "hi from across the federation",
        });
        let request_event_ref = "ak:event:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
        let request_receipt: RequestAcceptanceReceipt = serde_json::from_value(json!({
            "core": {
                "holder": {"kind": "human", "principal_id": requester},
                "peer": {"kind": "human", "principal_id": target},
                "slot_version": 1,
                "request_event_ref": request_event_ref,
                "request_digest": format!("sha256:{}", "b".repeat(64)),
                "source_checkpoint": format!("sha256:{}", "c".repeat(64)),
                "accepted_at": "2026-08-09T00:00:00.000Z",
                "issuer": source_service_id
            },
            "receipt_digest": format!("sha256:{}", "d".repeat(64)),
            "signature": {
                "verification_method": format!("{source_service_id}#federation-signing-key"),
                "created_at": "2026-08-09T00:00:00.000Z",
                "jws": "YWJj"
            }
        }))
        .expect("request receipt fixture");

        let outcome = project_delivered_contact_fact(
            &state,
            "ak.contact.requested",
            requester,
            target,
            &payload,
            request_event_ref,
            Some(&request_receipt),
            Some(source_service_id),
        )
        .await
        .expect("delivered request projects");
        assert_eq!(outcome, "accepted");

        let record = state
            .contacts()
            .contact_any(requester, target)
            .await
            .expect("contact store lookup")
            .expect("pending_incoming row was projected");

        assert_eq!(
            record.peer_service_id.as_deref(),
            Some(source_service_id),
            "peer_service_id must be the originating requester's PS, not the recipient's own \
             service_id ({})",
            state.service_id(),
        );
        assert_eq!(
            record.request_event_ref.as_deref(),
            Some("ak:event:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"),
        );
        assert_ne!(
            record.peer_service_id.as_deref(),
            Some(state.service_id().as_str()),
            "peer_service_id must not point at this recipient service",
        );
    }

    #[test]
    fn glare_basis_and_initiator_are_independent_of_arrival_order() {
        let alice = request_receipt(
            "did:web:alice.example",
            "did:web:bob.example",
            "did:web:alice-service.example",
            "ak:event:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N",
            'a',
        );
        let bob = request_receipt(
            "did:web:bob.example",
            "did:web:alice.example",
            "did:web:bob-service.example",
            "ak:event:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5",
            'b',
        );
        let mut first_arrival = [bob.clone(), alice.clone()];
        first_arrival.sort_by(|left, right| {
            left.core
                .request_event_ref
                .as_str()
                .cmp(right.core.request_event_ref.as_str())
        });
        let mut reverse_arrival = [alice, bob];
        reverse_arrival.sort_by(|left, right| {
            left.core
                .request_event_ref
                .as_str()
                .cmp(right.core.request_event_ref.as_str())
        });
        let (left_id, left_basis, _) = derive_glare_basis(&first_arrival).unwrap();
        let (right_id, right_basis, _) = derive_glare_basis(&reverse_arrival).unwrap();
        assert_eq!(left_id, right_id);
        assert_eq!(
            serde_json::to_value(left_basis).unwrap(),
            serde_json::to_value(right_basis).unwrap()
        );
        assert_eq!(
            first_arrival[0].core.holder.subject_id().as_str(),
            "did:web:alice.example",
            "requests[0] issuer is the sole mechanical glare initiator"
        );
    }

    #[tokio::test]
    async fn glare_finalize_cas_has_one_concurrent_winner() {
        let state = AppState::new(test_config(), Db { pool: None });
        let now = chrono::Utc::now();
        let record = ContactRecord {
            requester: "did:web:alice.example".to_owned(),
            target: "did:web:bob.example".to_owned(),
            basis_id: None,
            version: None,
            granted_to_target_scopes: vec!["direct_message".to_owned()],
            granted_to_requester_scopes: vec!["direct_message".to_owned()],
            status: "pending".to_owned(),
            request_event_ref: None,
            request_receipts: Vec::new(),
            request_mirror_receipts: Vec::new(),
            basis_evidence: None,
            control_outcomes: Vec::new(),
            response_event_ref: None,
            tombstone_event_ref: None,
            message: None,
            peer_service_id: Some("did:web:bob-service.example".to_owned()),
            created_at: now,
            updated_at: now,
        };
        state.contacts().save_contact(record.clone()).await.unwrap();
        let mut winner = record.clone();
        winner.basis_id = Some(format!("sha256:{}", "1".repeat(64)));
        winner.updated_at += chrono::Duration::microseconds(1);
        let mut loser = record;
        loser.basis_id = Some(format!("sha256:{}", "2".repeat(64)));
        loser.updated_at += chrono::Duration::microseconds(1);

        assert!(
            state
                .contacts()
                .save_contact_if_updated_at(now, winner)
                .await
                .unwrap()
        );
        assert!(
            !state
                .contacts()
                .save_contact_if_updated_at(now, loser)
                .await
                .unwrap(),
            "the stale concurrent finalize cannot overwrite the first CAS winner"
        );
    }

    #[tokio::test]
    async fn pending_glare_receipts_survive_restart_without_coordinate_rederivation() {
        let config = test_config();
        let state = AppState::new(config.clone(), Db { pool: None });
        let first = request_receipt(
            "did:web:alice.example",
            "did:web:bob.example",
            "did:web:alice-service.example",
            "ak:event:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N",
            'a',
        );
        let second = request_receipt(
            "did:web:bob.example",
            "did:web:alice.example",
            "did:web:bob-service.example",
            "ak:event:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5",
            'b',
        );
        let now = chrono::Utc::now();
        state
            .contacts()
            .save_contact(ContactRecord {
                requester: "did:web:alice.example".to_owned(),
                target: "did:web:bob.example".to_owned(),
                basis_id: None,
                version: None,
                granted_to_target_scopes: vec!["direct_message".to_owned()],
                granted_to_requester_scopes: vec!["direct_message".to_owned()],
                status: "pending".to_owned(),
                request_event_ref: Some(first.core.request_event_ref.to_string()),
                request_receipts: vec![first.clone(), second.clone()],
                request_mirror_receipts: Vec::new(),
                basis_evidence: None,
                control_outcomes: Vec::new(),
                response_event_ref: None,
                tombstone_event_ref: None,
                message: None,
                peer_service_id: Some("did:web:bob-service.example".to_owned()),
                created_at: now,
                updated_at: now,
            })
            .await
            .unwrap();
        let persistence = state.test_persistence();
        drop(state);
        let restarted = AppState::new_with_persistence(config, Db { pool: None }, persistence);
        restarted.hydrate().await.unwrap();
        let row = restarted
            .contacts()
            .contact_any("did:web:alice.example", "did:web:bob.example")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.request_receipts.len(), 2);
        assert_eq!(
            serde_json::to_value(&row.request_receipts[0].core).unwrap(),
            serde_json::to_value(&first.core).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&row.request_receipts[1].core).unwrap(),
            serde_json::to_value(&second.core).unwrap()
        );
        assert_eq!(
            row.peer_service_id.as_deref(),
            Some("did:web:bob-service.example")
        );
    }

    #[test]
    fn control_response_loss_replays_only_the_exact_request_digest() {
        let exact = Hash::new(format!("sha256:{}", "7".repeat(64))).unwrap();
        let outcome: PeerContactSubmitOutcome = serde_json::from_value(json!({
            "result_kind": "proof_refresh",
            "status": "accepted",
            "control_receipt": {
                "domain": "ak.peer-contact.control-receipt.v1",
                "request_kind": "proof_refresh",
                "request_digest": exact.clone(),
                "disposition": "accepted",
                "result_digest": format!("sha256:{}", "8".repeat(64)),
                "recipient_service_id": "did:web:bob-service.example",
                "received_at": "2026-08-09T00:00:00.000Z",
                "issuer": "did:web:bob-service.example",
                "signature": {
                    "verification_method": "did:web:bob-service.example#federation-signing-key",
                    "created_at": "2026-08-09T00:00:00.000Z",
                    "jws": "YWJj"
                }
            },
            "current_proof": {
                "basis_id": format!("sha256:{}", "9".repeat(64)),
                "issuer": "did:web:alice.example",
                "terminal": false,
                "head_event_ref": "ak:event:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N",
                "head_digest": format!("sha256:{}", "a".repeat(64)),
                "accepted_frontier": ["ak:event:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N"],
                "complete_through": 1,
                "fresh_until": "2026-08-09T00:10:00Z",
                "signature": {
                    "verification_method": "did:web:alice-service.example#federation-signing-key",
                    "created_at": "2026-08-09T00:00:00.000Z",
                    "jws": "YWJj"
                }
            }
        }))
        .unwrap();
        let record = ContactRecord {
            requester: "did:web:alice.example".to_owned(),
            target: "did:web:bob.example".to_owned(),
            basis_id: None,
            version: None,
            granted_to_target_scopes: Vec::new(),
            granted_to_requester_scopes: Vec::new(),
            status: "pending".to_owned(),
            request_event_ref: None,
            request_receipts: Vec::new(),
            request_mirror_receipts: Vec::new(),
            basis_evidence: None,
            control_outcomes: vec![outcome.clone()],
            response_event_ref: None,
            tombstone_event_ref: None,
            message: None,
            peer_service_id: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        assert!(
            replayed_contact_control_outcome(&record, &exact, PeerContactControlKind::ProofRefresh)
                .is_some()
        );
        let different = Hash::new(format!("sha256:{}", "6".repeat(64))).unwrap();
        assert!(
            replayed_contact_control_outcome(
                &record,
                &different,
                PeerContactControlKind::ProofRefresh
            )
            .is_none(),
            "different request bytes cannot reuse the response-loss outcome"
        );
    }
}
