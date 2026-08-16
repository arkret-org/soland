//! Ingress receipt minting for a first durable publication.
//!
//! `authz/offline-publication.md` §2: a receipt is signed proof that a
//! policy-accepted ingress received one Event digest while its lease was still
//! valid. It proves arrival and nothing more — not that the Event passed the
//! reducer, entered a projection, was seen by a peer, or reached Seal finality.
//!
//! Two rules shape every function here:
//!
//! * §2.1 — an idempotent retry of the same Event canonical bytes MUST return the ORIGINAL receipt.
//!   Re-signing with a fresh `received_at` would silently widen a revocation window that is already
//!   fixed, so the store is first-writer-wins and callers use whatever it returns, never their own
//!   freshly minted candidate.
//! * §2 — the proof `created_at` MUST equal `received_at` verbatim, and `issued_at <= received_at
//!   <= expires_at` is the revocation boundary.

use arkret_wire::offline_publication::{AuthorizationLease, IngressReceipt};
use arkret_wire::primitives::{PayloadProof, proof_kind};

use super::*;

pub(in crate::routing) async fn validate_authorization_lease_for_event(
    state: &AppState,
    session: Option<&SessionRecord>,
    event: &arkret_wire::Event,
    lease: &AuthorizationLease,
) -> Result<(), SubmitOneError> {
    if let Some(session) = session
        && lease.device_id.as_str() != session.device_id
    {
        return Err(SubmitOneError::new(
            StatusCode::FORBIDDEN,
            "authorization_lease_device_mismatch",
            "authorization lease device_id does not match the authenticated session",
        ));
    }
    let expected_risk = arkret_schema::capability_action(&lease.action).map_or(
        arkret_wire::RiskTier::High,
        |descriptor| match descriptor.risk_tier {
            arkret_schema::CapabilityRiskTier::Low => arkret_wire::RiskTier::Low,
            arkret_schema::CapabilityRiskTier::Medium => arkret_wire::RiskTier::Medium,
            arkret_schema::CapabilityRiskTier::High => arkret_wire::RiskTier::High,
        },
    );
    let action_covers_kind = arkret_schema::capability_action(&lease.action)
        .is_some_and(|descriptor| descriptor.target_event_kinds.contains(&event.kind.as_str()))
        || (lease.action == event.kind.as_str() && expected_risk == arkret_wire::RiskTier::High);
    if !action_covers_kind || lease.risk_tier != expected_risk {
        return Err(SubmitOneError::new(
            StatusCode::FORBIDDEN,
            "authorization_lease_action_mismatch",
            "authorization lease action/risk does not cover the Event kind",
        ));
    }
    match &lease.basis_ref {
        arkret_wire::LeaseBasisRef::Seal(seal) if event.seal_ref.as_ref() == Some(seal) => {}
        arkret_wire::LeaseBasisRef::Joined(basis) if event.seal_basis.as_ref() == Some(basis) => {}
        arkret_wire::LeaseBasisRef::AnchorUnit(_) => {
            // The complete ordered-unit binding is checked once at the batch
            // boundary by validate_anchor_unit_lease_bindings.
        }
        _ => {
            return Err(SubmitOneError::new(
                StatusCode::FORBIDDEN,
                "authorization_lease_basis_mismatch",
                "authorization lease basis does not match the signed Event",
            ));
        }
    }

    for proof in &lease.proofs {
        let issuer = arkret_identity::verification_method_did(&proof.verification_method).map_err(
            |error| {
                SubmitOneError::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    format!("authorization lease issuer is invalid: {error}"),
                )
            },
        )?;
        let required_audience = issuer.as_str();
        let audience_covers_service = match proof.audience.as_ref() {
            Some(arkret_wire::Audience::Single(value)) => value == required_audience,
            Some(arkret_wire::Audience::Multiple(values)) => {
                values.iter().any(|value| value == required_audience)
            }
            None => false,
        };
        if !audience_covers_service {
            return Err(SubmitOneError::new(
                StatusCode::FORBIDDEN,
                "invalid_proof",
                "authorization lease proof audience does not cover its issuer service",
            ));
        }
        let expected_source_digest =
            arkret_canonical::canonical_sha256(&lease.basis_ref).map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("authorization lease authority basis digest failed: {error}"),
                )
            })?;
        if lease.authority_set_ref.authority_set_id
            != arkret_wire::AuthoritySetId::REALM_ADMISSION_V1
            || lease.authority_set_policy.source.source_digest.as_str() != expected_source_digest
            || lease.authority_set_policy.scope_ref != event.scope_ref
        {
            return Err(SubmitOneError::new(
                StatusCode::FORBIDDEN,
                "authorization_lease_authority_mismatch",
                "authorization lease authority-set reference is not valid for its issuer and basis",
            ));
        }
        let binding = lease.proof_binding_bytes(proof).map_err(|error| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                format!("authorization lease proof binding is invalid: {error}"),
            )
        })?;
        verify_service_publication_proof(
            state,
            &binding,
            &proof.jws,
            &proof.verification_method,
            issuer.as_str(),
        )
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::FORBIDDEN,
                "invalid_proof",
                format!("authorization lease issuer proof is invalid: {error}"),
            )
        })?;
    }
    Ok(())
}

pub(super) async fn validate_ingress_receipt_proofs(
    state: &AppState,
    receipts: &[IngressReceipt],
) -> Result<(), SubmitOneError> {
    for receipt in receipts {
        for proof in &receipt.proofs {
            let issuer = arkret_identity::verification_method_did(&proof.verification_method)
                .map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::BAD_REQUEST,
                        "invalid_proof",
                        format!("ingress receipt issuer is invalid: {error}"),
                    )
                })?;
            let issuer_service_id =
                arkret_wire::project_full_id_to_core_id(&issuer).map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::BAD_REQUEST,
                        "invalid_proof",
                        format!("ingress receipt issuer cannot be projected: {error}"),
                    )
                })?;
            if issuer_service_id != receipt.service_id {
                return Err(SubmitOneError::new(
                    StatusCode::FORBIDDEN,
                    "invalid_proof",
                    "ingress receipt signer does not match receipt service_id",
                ));
            }
            let binding = receipt.proof_binding_bytes(proof).map_err(|error| {
                SubmitOneError::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    format!("ingress receipt proof binding is invalid: {error}"),
                )
            })?;
            verify_service_publication_proof(
                state,
                &binding,
                &proof.jws,
                &proof.verification_method,
                issuer.as_str(),
            )
            .await
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::FORBIDDEN,
                    "invalid_proof",
                    format!("ingress receipt proof is invalid: {error}"),
                )
            })?;
        }
    }
    Ok(())
}

async fn verify_service_publication_proof(
    state: &AppState,
    binding: &[u8],
    jws: &str,
    verification_method: &str,
    issuer: &str,
) -> Result<(), String> {
    crate::jws_verify::validate_verification_method_controller(issuer, verification_method)?;
    let cached_key = state
        .federation_peer_verification_method_key(verification_method)
        .or_else(|| state.federation_peer_verifying_key(issuer));
    if let Some(key) = cached_key {
        return arkret_signatures::Ed25519DetachedJwsVerifier::new()
            .verify_detached_jws(
                jws,
                binding,
                &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                    bytes: key.to_bytes().to_vec(),
                },
            )
            .map_err(|error| error.to_string());
    }
    crate::jws_verify::verify_did_controlled_jws_async(
        binding,
        jws,
        verification_method,
        issuer,
        state,
    )
    .await
}

/// Mint this service's ingress receipt for `parsed`, store it first-writer-wins
/// and return the STORED record.
///
/// The returned receipt is the one that goes back on
/// `EventsSubmitOutcome.ingress_receipts[]` and the one a later federation
/// submission transports. When the digest was already receipted, that earlier
/// receipt is returned unchanged.
pub(super) async fn mint_and_store_ingress_receipt(
    state: &AppState,
    parsed: &ValidatedEventEnvelope,
    lease: &AuthorizationLease,
    received_at: chrono::DateTime<chrono::Utc>,
) -> Result<IngressReceipt, SubmitOneError> {
    let record = build_ingress_receipt_record(state, parsed, lease, received_at)?;
    let stored = state
        .event_queries()
        .store_publication_evidence(record)
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("publication evidence store unavailable: {error}"),
            )
        })?;
    Ok(stored.ingress_receipt)
}

/// Build publication evidence without persisting it. Closed atomic Event units
/// pass the returned records into the same storage transaction as the Events.
pub(super) fn build_ingress_receipt_record(
    state: &AppState,
    parsed: &ValidatedEventEnvelope,
    lease: &AuthorizationLease,
    received_at: chrono::DateTime<chrono::Utc>,
) -> Result<soland_services::events::PublicationEvidenceRecord, SubmitOneError> {
    let event_digest =
        arkret_identifiers::Hash::new(parsed.canonical_digest.clone()).map_err(|error| {
            publication_reject(format!("Event canonical digest is invalid: {error}"))
        })?;
    // The revocation boundary. An Event whose lease had already expired when it
    // arrived never gets a receipt, and therefore can never be federated.
    if !lease.covers_instant(received_at) {
        return Err(SubmitOneError::new(
            StatusCode::PRECONDITION_FAILED,
            "authorization_lease_expired",
            "authorization lease does not cover the time this Event was received",
        ));
    }
    let receipt = sign_ingress_receipt(state, &event_digest, lease, received_at)?;
    Ok(soland_services::events::PublicationEvidenceRecord {
        event_digest: parsed.canonical_digest.clone(),
        realm_id: parsed.realm_id.to_string(),
        authorization_lease: lease.clone(),
        ingress_receipt: receipt,
    })
}

/// Build and sign one receipt with this service's notary key.
///
/// The proof is a detached JWS over `receipt.proof_binding_bytes(&proof)` —
/// the same `publication_binding_bytes` shape a verifier reconstructs, whose
/// fixed `ak.ingress-receipt-proof-v1` context keeps the signature from being
/// replayed as a lease proof or an Event proof. `verification_method` is
/// `<service_id>#notary-key`, the durable key this service publishes in its DID
/// document.
fn sign_ingress_receipt(
    state: &AppState,
    event_digest: &arkret_identifiers::Hash,
    lease: &AuthorizationLease,
    received_at: chrono::DateTime<chrono::Utc>,
) -> Result<IngressReceipt, SubmitOneError> {
    let receipt_id = arkret_identifiers::ReceiptId::new(crate::ids::generate("receipt"))
        .map_err(|error| publication_reject(format!("minted receipt_id is invalid: {error}")))?;
    let service_id = arkret_identifiers::DidCoreId::new(state.service_id().clone())
        .map_err(|error| publication_reject(format!("service_id is not a DID: {error}")))?;
    let verification_method = arkret_wire::DidUrl::new(format!(
        "{}#notary-key",
        state.service_resolution_commitment().full_id
    ))
    .map_err(|error| {
        publication_reject(format!(
            "service notary verification method is invalid: {error}"
        ))
    })?;
    let mut receipt = IngressReceipt {
        receipt_id,
        event_digest: event_digest.clone(),
        authorization_lease_id: lease.authorization_lease_id.clone(),
        received_at,
        service_id,
        // The receipt is checked against the same accepted authority-set policy
        // the lease cited: `offline-publication.md` §1/§2 make
        // `{authority_set_id, authority_set_digest}` one closed object shared by
        // every CBA authority/quorum scenario, and inventing a second symbol
        // here would leave a verifier no way to resolve it from the basis.
        authority_set_ref: lease.authority_set_ref.clone(),
        proofs: Vec::new(),
    };
    // `receipt_digest` covers the receipt with `proofs` removed, so it has to be
    // taken before the proof is attached.
    let receipt_digest = receipt
        .receipt_digest()
        .map_err(|error| publication_reject(format!("receipt digest failed: {error}")))?;
    let mut proof = PayloadProof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        verification_method,
        payload_digest: receipt_digest,
        // §2 — verbatim equality, not "close enough": a retry that re-stamped
        // this would move the revocation boundary.
        created_at: received_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: String::new(),
    };
    let binding_bytes = receipt
        .proof_binding_bytes(&proof)
        .map_err(|error| publication_reject(format!("receipt proof binding failed: {error}")))?;
    proof.jws = arkret_signatures::jws::sign_jws_ed25519(
        &binding_bytes,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|error| publication_reject(format!("receipt proof signing failed: {error}")))?;
    receipt.proofs = vec![proof];
    receipt
        .validate_structural()
        .map_err(|error| publication_reject(format!("minted receipt is not valid: {error}")))?;
    receipt
        .validate_against_lease(lease, event_digest)
        .map_err(|error| {
            publication_reject(format!("minted receipt does not bind its lease: {error}"))
        })?;
    Ok(receipt)
}

/// Publication evidence that arrived on a federation submission, keyed by the
/// Event id it covers.
#[derive(Clone, Debug)]
pub(super) struct InboundPublicationEvidence {
    pub(super) event_digest: String,
    pub(super) realm_id: String,
    pub(super) authorization_lease: AuthorizationLease,
    pub(super) ingress_receipts: Vec<IngressReceipt>,
}

/// Persist federated publication evidence exactly as it arrived.
///
/// `offline-publication.md` §2.1 — a receipt proves the digest reached a
/// policy-accepted ingress inside the lease window. This service was not that
/// ingress, so it MUST NOT mint a replacement: doing so would re-stamp
/// `received_at` with a local first-sight time and widen an already fixed
/// revocation window. Storing the transported receipt verbatim is what lets the
/// Event be re-federated onward later.
///
/// `EventFederationSubmission::validate_structural` has already bound every
/// receipt to this lease and this exact digest, so the first one is a valid
/// representative of the set.
///
/// Best-effort: the Event is already accepted, and a failed evidence write only
/// costs a later onward federation, so it degrades to a warning rather than
/// unwinding an accepted commit.
pub(super) async fn store_inbound_publication_evidence(
    state: &AppState,
    evidence: &InboundPublicationEvidence,
) {
    let Some(receipt) = evidence.ingress_receipts.first() else {
        tracing::warn!(
            event_digest = %evidence.event_digest,
            "federated Event carried no ingress receipt; it cannot be re-federated"
        );
        return;
    };
    let record = soland_services::events::PublicationEvidenceRecord {
        event_digest: evidence.event_digest.clone(),
        realm_id: evidence.realm_id.clone(),
        authorization_lease: evidence.authorization_lease.clone(),
        ingress_receipt: receipt.clone(),
    };
    if let Err(error) = state
        .event_queries()
        .store_publication_evidence(record)
        .await
    {
        tracing::warn!(
            %error,
            event_digest = %evidence.event_digest,
            "failed to store transported publication evidence"
        );
    }
}

fn publication_reject(message: String) -> SubmitOneError {
    SubmitOneError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", message)
}

/// Validate the client-supplied publication wrapper before anything is minted.
///
/// `offline-publication.md` §2.1 puts lease verification ahead of receipt
/// issuance: this service must not sign arrival evidence for a submission whose
/// lease is structurally invalid or does not bind the Event it travels with.
pub(super) fn validate_initial_submission_in_context(
    submission: &arkret_wire::EventInitialSubmission,
    context: arkret_wire::EventSubmitContext,
) -> Result<(), SubmitOneError> {
    submission
        .validate_structural_in_context(context)
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("initial publication wrapper is invalid: {error}"),
            )
        })
}
