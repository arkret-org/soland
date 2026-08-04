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
    ContactBasis, ContactCurrentProof, ContactScope, ContactScopeUpdatePayload,
    GlareConcurrencyAttestation, PeerContactControlDeferredOutcome, PeerContactControlKind,
    PeerContactControlReceipt, PeerContactControlReceiptDomain, PeerContactDisposition,
    PeerContactEventSubmitOutcome, PeerContactMirrorReceipt, PeerContactMirrorReceiptDomain,
    PeerContactSubmitOutcome, PeerContactSubmitRequestBody, RequestAcceptanceReceipt,
};
use arkret_models_collaboration::events_payloads::contact::{
    ContactAcceptedPayload, ContactRejectedPayload, ContactRequestedPayload,
    ContactTombstonedPayload,
};
use arkret_models_collaboration::governance::peer_contact::{
    ContactIntroductionEvidence, PeerContactAddress,
};
use arkret_wire::{Base64UrlString, DidUrl, Event, ProtocolSignature};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Duration;
use ed25519_dalek::Signer as _;
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};
use soland_services::events::ProjectedEvent as ProjectionEventRecord;
use soland_services::identity::ContactRecord;

use super::now;
use crate::state::AppState;

const HEADER_SOURCE_SERVICE_ID: &str = "source-service-id";
const CONTACT_MESSAGE_STUB: &str = "[message withheld until contact is accepted]";

pub(crate) fn peer_router() -> Router {
    Router::new().push(Router::with_path("contacts").post(peer_contacts_submit))
}

/// Issuer-side: federate a signed contact fact to `subject_id`'s home
/// Principal Server (`recipient_service_id`). Returns `Ok(false)` (no-op)
/// when `recipient_service_id` is this service (same-server request handled
/// locally) or when the deployment does not list the peer; `Ok(true)` when a
/// durable outbound delivery was enqueued.
///
/// `fact_kind` is one of the `ak.contact.*` kinds. `fact_payload` carries the
/// projection fields the recipient needs (requester/target/scope/message/
/// granted_scopes/consent grant refs). The fact is wrapped in a dev-proof
/// Event scoped to the issuer's Principal Control Realm so it is a
/// real signed contact fact the recipient can project as the original
/// envelope (spec §2).
pub(crate) async fn enqueue_peer_contact_carrier(
    state: &AppState,
    recipient_service_id: &str,
    delivery: &PeerContactSubmitRequestBody,
) -> Result<bool, AppError> {
    if recipient_service_id == state.service_id() {
        return Ok(false);
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
    crate::routing::federation::outbox::enqueue_outbound(
        state,
        &peer_url,
        recipient_service_id,
        "/_arkret/peer/contacts",
        idempotency_key,
        &payload_json,
    )
    .await
    .map_err(|error| AppError::internal(format!("contact delivery enqueue: {error}")))?;
    Ok(true)
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
    let mirror_receipt = sign_contact_mirror_receipt(state, &delivery, signed_event, disposition)?;
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
    json_ok(PeerContactSubmitOutcome::Event(
        PeerContactEventSubmitOutcome {
            result_kind,
            status: disposition,
            mirror_receipt,
            current_proof: None,
            retry_after_ms: None,
        },
    ))
}

async fn handle_contact_control_request(
    state: &AppState,
    request: &PeerContactSubmitRequestBody,
    source_service_id: &str,
) -> Result<Option<PeerContactSubmitOutcome>, AppError> {
    let (kind, address) = match request {
        PeerContactSubmitRequestBody::ProofRefresh {
            prior_mirror_receipt,
            current_proof,
            contact_address,
            ..
        } => {
            validate_proof_refresh_evidence(
                state,
                source_service_id,
                prior_mirror_receipt,
                current_proof,
                contact_address,
            )
            .await?;
            (PeerContactControlKind::ProofRefresh, contact_address)
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
            validate_glare_finalize_evidence(
                state,
                source_service_id,
                basis_id,
                basis,
                request_receipts,
                remote_mirror_receipt,
                glare_concurrency_attestation,
                contact_address,
            )?;
            (PeerContactControlKind::GlareFinalize, contact_address)
        }
        _ => return Ok(None),
    };
    if address.recipient_service_id.as_str() != state.service_id() {
        return Err(super::super::events::peer::cross_domain_replay(
            "contact_address.recipient_service_id does not match this service",
        ));
    }

    // Control carriers never smuggle an unsigned state transition. Until the
    // referenced proof/receipt frontier is locally complete, acknowledge the
    // durable request as deferred and require an exact replay after dependency
    // reconciliation.
    let control_receipt =
        sign_contact_control_receipt(state, request, kind, PeerContactDisposition::Deferred, None)?;
    Ok(Some(PeerContactSubmitOutcome::ControlDeferred(
        PeerContactControlDeferredOutcome {
            status: PeerContactDisposition::Deferred,
            request_kind: kind,
            control_receipt,
            retry_after_ms: Some(1_000),
        },
    )))
}

fn unsigned_contact_evidence<T: serde::Serialize>(
    evidence: &T,
    field: &str,
) -> Result<Value, AppError> {
    let mut value = serde_json::to_value(evidence)
        .map_err(|error| AppError::internal(format!("{field} serialize failed: {error}")))?;
    value
        .as_object_mut()
        .ok_or_else(|| AppError::internal(format!("{field} must be a JSON object")))?
        .remove("signature");
    Ok(value)
}

fn validate_mirror_receipt_cryptography(
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
    super::account::verify_contact_service_signature(
        state,
        expected_service_id,
        &receipt.signature,
        &unsigned_contact_evidence(receipt, field)?,
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
    super::account::verify_contact_service_signature(
        state,
        source_service_id,
        &current_proof.signature,
        &unsigned_contact_evidence(current_proof, "current_proof")?,
        "current_proof",
    )?;
    if current_proof.issuer == contact_address.subject_id
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
        record.status == "accepted"
            && record.peer_service_id.as_deref() == Some(source_service_id)
            && record.basis_id.as_deref() == Some(current_proof.basis_id.as_str())
            && ((record.requester == current_proof.issuer.as_str()
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
    super::account::verify_contact_service_signature(
        state,
        source_service_id,
        &attestation.signature,
        &unsigned_contact_evidence(attestation, "glare_concurrency_attestation")?,
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
    let expected_basis = json!({
        "kind": "glare",
        "sorted_pair_members": pair,
        "requests": [
            {"request_event_ref": first.0, "request_acceptance_receipt_digest": first.1},
            {"request_event_ref": second.0, "request_acceptance_receipt_digest": second.1},
        ],
    });
    if serde_json::to_value(basis)
        .map_err(|error| AppError::internal(format!("Contact basis serialize: {error}")))?
        != expected_basis
    {
        return Err(super::super::events::peer::schema_violation(
            "glare basis does not match the exact request receipts",
        ));
    }
    let mut basis_preimage = expected_basis;
    basis_preimage
        .as_object_mut()
        .expect("glare basis is an object")
        .insert("domain".to_owned(), json!("ak.contact.basis.v1"));
    if &super::account::canonical_contact_digest(&basis_preimage)? != basis_id
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

async fn accept_delivered_direct_binding(
    state: &AppState,
    event: &Event,
    subject_id: &str,
    source_service_id: Option<&str>,
    signer_key_evidence: &[arkret_wire::event_envelope::FederatedDeviceSigningKeyEvidence],
) -> Result<&'static str, AppError> {
    for evidence in signer_key_evidence {
        crate::routing::events::event_log::validate_federated_device_signing_key_evidence(
            state, evidence,
        )
        .await
        .map_err(|error| {
            super::super::events::peer::schema_violation(format!(
                "invalid direct binding signer authorization evidence: {error}"
            ))
        })?;
    }
    let payload: arkret_models_collaboration::events_payloads::device_identity::DirectConversationBoundPayload =
        serde_json::from_value(serde_json::to_value(&event.payload).map_err(|error| {
            AppError::internal(format!("direct binding payload encode failed: {error}"))
        })?)
        .map_err(|_| {
            super::super::events::peer::schema_violation(
                "invalid ak.direct_conversation.bound payload",
            )
        })?;
    let issuer = event.actor_id.as_str();
    if issuer == subject_id
        || !payload
            .participants_unordered
            .iter()
            .any(|participant| participant.as_str() == issuer)
        || !payload
            .participants_unordered
            .iter()
            .any(|participant| participant.as_str() == subject_id)
    {
        return Err(super::super::events::peer::schema_violation(
            "direct binding issuer and contact subject must be its two participants",
        ));
    }
    let contact = state
        .contacts()
        .contact_any(issuer, subject_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| {
            super::super::events::peer::schema_violation(
                "direct binding references no accepted local contact",
            )
        })?;
    if contact.status != "accepted"
        || source_service_id.is_none()
        || contact.peer_service_id.as_deref() != source_service_id
    {
        return Err(super::super::events::peer::schema_violation(
            "direct binding source service does not match the accepted contact",
        ));
    }

    // Realm Events and the principal-scoped binding travel on independent
    // durable federation rails. A binding may legitimately arrive first; make
    // that condition retryable instead of permanently dead-lettering a valid
    // signed fact as a schema error.
    let referenced_events = payload
        .member_event_refs
        .iter()
        .chain(std::iter::once(&payload.main_strand_create_ref))
        .chain(std::iter::once(&payload.mls_genesis_event_ref))
        .chain(std::iter::once(&payload.mls_commit_event_ref))
        .chain(std::iter::once(&payload.mls_welcome_event_ref));
    for event_ref in referenced_events {
        let available = state
            .event_queries()
            .canonical_event(event_ref.as_str())
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            .is_some();
        if !available {
            tracing::warn!(
                target: "soland_http::error",
                realm_id = %payload.realm_id,
                event_ref = %event_ref,
                "direct binding dependency is not canonical yet"
            );
            return Err(AppError::new(
                soland_http::error::ErrorCode::TemporarilyUnavailable,
                "direct binding dependencies have not arrived yet",
            )
            .with_status(StatusCode::SERVICE_UNAVAILABLE)
            .with_wire_code("direct_binding_dependencies_pending"));
        }
    }

    let created_at = now();
    let federation_device_id = "federation:contact-binding";
    let session = soland_services::identity::SessionIdentityState {
        token_hash: format!("peer-contact-binding:{}", event.event_id),
        actor: issuer.to_owned(),
        device_id: federation_device_id.to_owned(),
        audience: state.service_id().clone(),
        session_public_key: None,
        agent_session: None,
        expires_at: created_at + Duration::minutes(5),
        created_at,
        revoked_at: None,
    };
    let envelope = serde_json::to_value(event)
        .map_err(|error| AppError::internal(format!("direct binding encode failed: {error}")))?;
    let admission = crate::routing::events::event_log::InternalEventAdmission::peer_direct_binding(
        event.realm_id.to_string(),
        issuer,
        federation_device_id,
        subject_id,
        signer_key_evidence.to_vec(),
    );
    let parsed = crate::routing::events::event_log::validate_event_envelope_with_context(
        state,
        &session,
        &envelope,
        &[],
        Some(&admission),
    )
    .await
    .map_err(|error| {
        super::super::events::peer::schema_violation(format!(
            "direct binding Event rejected: {} ({})",
            error.message, error.code
        ))
    })?;
    let operation =
        crate::routing::events::event_log::projection_operation_from_event(&parsed, &envelope)
            .ok_or_else(|| {
                super::super::events::peer::schema_violation(
                    "direct binding Event cannot be projected",
                )
            })?;
    super::account::validate_direct_binding_operation(state, &operation)
        .await
        .map_err(super::super::events::peer::schema_violation)?;

    if let Some(existing) = state
        .event_queries()
        .canonical_event(&parsed.event_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        if existing.canonical_digest != parsed.canonical_digest {
            return Err(super::super::events::peer::schema_violation(
                "direct binding Event id collides with different canonical bytes",
            ));
        }
        return Ok("duplicate");
    }
    state
        .event_queries()
        .store_canonical_event(soland_services::events::CanonicalEventRecord {
            event_id: parsed.event_id,
            actor_id: parsed.actor_id,
            actor_seq: parsed.actor_seq,
            realm_id: Some(parsed.realm_id),
            kind: parsed.kind,
            schema_id: parsed.schema_id,
            canonical_digest: parsed.canonical_digest,
            canonical_bytes: parsed.canonical_bytes,
            envelope,
            received_at: created_at,
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    super::account::project_canonical_direct_binding(state, &operation).await;
    Ok("accepted")
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
    let evidence_value = serde_json::to_value(evidence).map_err(|error| {
        super::super::events::peer::schema_violation(format!(
            "contact introduction_evidence is not serializable: {error}"
        ))
    })?;
    let actual = canonical::canonical_sha256(&evidence_value).map_err(|error| {
        super::super::events::peer::schema_violation(format!(
            "contact introduction_evidence is not canonical-hashable: {error}"
        ))
    })?;
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
    let _ = crate::routing::events::projection::append_projection_event(
        state,
        ProjectionEventRecord {
            event_id: contact_event_id.to_owned(),
            realm_id: soland_services::identity::principal_control_realm_for_did(issuer),
            event_kind: fact_kind.to_owned(),
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
            if let Some(existing) = contacts
                .contact_any(issuer, subject_id)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
            {
                if existing.status == "pending"
                    && existing.request_event_ref.as_deref() == Some(contact_event_id)
                {
                    return Ok("duplicate");
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
            "granted_to_peer_scopes": ["direct_message"],
            "message": "hi from across the federation",
        });

        let outcome = project_delivered_contact_fact(
            &state,
            "ak.contact.requested",
            requester,
            target,
            &payload,
            "ak:event:0196419b-0000-7000-8000-000000000001",
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
            Some("ak:event:0196419b-0000-7000-8000-000000000001"),
        );
        assert_ne!(
            record.peer_service_id.as_deref(),
            Some(state.service_id().as_str()),
            "peer_service_id must not point at this recipient service",
        );
    }
}
