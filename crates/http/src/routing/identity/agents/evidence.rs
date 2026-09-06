//! Agent signer evidence is a closed current/historical protocol.
//!
//! Soland must not reconstruct either branch from old projection rows. Until
//! all signed snapshot, controller-account gate, lifecycle witness and
//! historical admission-receipt inputs are available, evidence production and
//! federation admission fail closed.

use std::time::Duration;

use arkret_models_collaboration::governance_dependencies::{
    GovernanceDependency, GovernanceDependencySelector,
};
use arkret_models_identity::AuthenticatedSignerResolutionEvidence;
use arkret_models_identity::agent_signer_evidence::{
    AGENT_KEY_COMPONENT, AGENT_STATUS_COMPONENT, AgentAdmissionEvidence, AgentAuthorityState,
    AgentAuthorityStateEvidence, AgentAuthorityStateLease, AgentAuthorizationEvidence,
    AgentAuthorizationStateWitness, AgentAuthorizationStatus, AgentCurrentObservation,
    AgentDetachedJws, AgentEvidenceOuterAttestation, AgentHistoricalEvidenceOuterAttestation,
    AgentKeyCellEntry, AgentLifecycleProvenance, AgentLifecycleStatus, AgentLifecycleWitness,
    AgentSignerEvidence, AgentSignerEvidenceQueryFailure, AgentSignerEvidenceQueryFailureReason,
    AgentSignerEvidenceQueryOutcome, AgentSignerEvidenceQueryRequestBody,
    AgentSignerEvidenceQuerySelector, ControllerAccountGateAttestation,
    ControllerAccountGateAttestationIssueOutcome, ControllerAccountGateAttestationIssueRequestBody,
    CurrentAgentSignerEvidence,
};
use arkret_signatures::proof::PublicKeyMaterial;
use arkret_wire::{
    CellRef, DidCoreId, Event, EventId, Hash, NonEmptyString, NotarySig, RealmId, RequestId,
    SchemaId, Seal,
};
use salvo::oapi::extract::JsonBody;

use super::*;

#[salvo::oapi::endpoint(
    operation_id = "ak.self.agent_signer_evidence.read.resolve",
    tags("identity")
)]
pub(super) async fn query_agent_signer_evidence(
    aa: AuthArgs,
    body: JsonBody<AgentSignerEvidenceQueryRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentSignerEvidenceQueryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    body.validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if !crate::routing::realm_has_member(
        state,
        body.realm_id.as_str(),
        &crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?
            .to_string(),
    )
    .await
    {
        return Err(AppError::not_found("Agent signer evidence is unavailable"));
    }
    let request = body.clone();
    let mut evidence = Vec::with_capacity(body.queries.len());
    let mut failures = Vec::with_capacity(body.queries.len());
    for selector in body.queries {
        if let Err(reason) = reserve_evidence_challenge(state, &selector).await {
            failures.push(AgentSignerEvidenceQueryFailure { selector, reason });
            continue;
        }
        match current_authenticated_agent_signer_evidence(state, &selector).await {
            Ok((root, dependencies)) => {
                persist_agent_signer_evidence_closure(state, &root, &dependencies).await?;
                evidence.push(root);
            }
            Err(reason) => failures.push(AgentSignerEvidenceQueryFailure { selector, reason }),
        }
    }
    let outcome = AgentSignerEvidenceQueryOutcome {
        evidence_items: evidence,
        failures: (!failures.is_empty()).then_some(failures),
    };
    outcome
        .validate_for_request(&request)
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(outcome)
}

pub(crate) async fn current_agent_signer_evidence(
    state: &AppState,
    selector: &AgentSignerEvidenceQuerySelector,
) -> Result<CurrentAgentSignerEvidence, AgentSignerEvidenceQueryFailureReason> {
    let gate = preflight_controller_gate(state, selector).await?;
    produce_current_agent_signer_evidence(state, selector, gate).await
}

pub(crate) async fn freeze_current_agent_signer_evidence(
    state: &AppState,
    selector: &AgentSignerEvidenceQuerySelector,
) -> Result<(arkret_wire::SignerEvidenceRef, Hash), AppError> {
    let (root, dependencies) = current_authenticated_agent_signer_evidence(state, selector)
        .await
        .map_err(|reason| AppError::internal(format!("{reason:?}")))?;
    persist_agent_signer_evidence_closure(state, &root, &dependencies).await?;
    let digest = root
        .canonical_sha256_digest()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let reference = root
        .evidence_ref()
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok((reference, digest))
}

pub(crate) async fn current_authenticated_agent_signer_evidence(
    state: &AppState,
    selector: &AgentSignerEvidenceQuerySelector,
) -> Result<
    (
        AuthenticatedSignerResolutionEvidence,
        Vec<AuthenticatedSignerResolutionEvidence>,
    ),
    AgentSignerEvidenceQueryFailureReason,
> {
    if let AgentSignerEvidenceQuerySelector::HistoricalEvent {
        agent_id,
        verification_method,
        event_id,
        receiver_id,
    } = selector
    {
        return historical_authenticated_agent_signer_evidence(
            state,
            soland_storage::HistoricalAgentSignerEvidenceKey {
                agent_id: agent_id.clone(),
                verification_method: verification_method.clone(),
                event_id: event_id.clone(),
                receiver_id: receiver_id.clone(),
            },
        )
        .await;
    }
    let current = current_agent_signer_evidence(state, selector).await?;
    let agent_signer_evidence = AgentSignerEvidence::from(current);
    let AgentSignerEvidence::CurrentAdmission {
        admission_evidence,
        current_observation,
        ..
    } = &agent_signer_evidence
    else {
        unreachable!("current evidence producer returned a historical branch")
    };
    let binding = &admission_evidence
        .agent_authority_state_evidence
        .state
        .signing_key_binding;
    let gate = &admission_evidence.controller_account_gate_attestation;
    let local_service_evidence = current_service_signer_evidence(state).await?;
    let controller_evidence = current_controller_signer_evidence(
        state,
        &binding.controller_principal_id,
        &binding.controller_proof.verification_method,
        &local_service_evidence,
    )
    .await?;
    let account_authority_evidence =
        fetch_service_signer_evidence(state, &gate.authority_id, None, None, chrono::Utc::now())
            .await?;
    // The current branch is also the standard cold-recipient federation
    // branch.  When the verifier is a foreign recipient Station, retain its
    // authenticated Service evidence in the closure instead of requiring the
    // verifier to be this Agent Authority itself.
    let receiver_evidence =
        if current_observation.verifier_id == *local_service_evidence.signer_id() {
            local_service_evidence.clone()
        } else {
            fetch_service_signer_evidence(
                state,
                &current_observation.verifier_id,
                None,
                None,
                chrono::Utc::now(),
            )
            .await?
        };
    let root = arkret::build_agent_signer_resolution_evidence(
        agent_signer_evidence,
        &local_service_evidence,
        &controller_evidence,
        &account_authority_evidence,
        &receiver_evidence,
    )
    .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let mut dependencies = Vec::new();
    let mut digests = std::collections::BTreeSet::new();
    for evidence in [
        local_service_evidence,
        controller_evidence,
        account_authority_evidence,
        receiver_evidence,
    ] {
        let digest = evidence
            .canonical_sha256_digest()
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
        if digests.insert(digest) {
            dependencies.push(evidence);
        }
    }
    Ok((root, dependencies))
}

pub(crate) async fn issue_current_authenticated_agent_signer_evidence(
    state: &AppState,
    selector: &AgentSignerEvidenceQuerySelector,
) -> Result<
    (
        AuthenticatedSignerResolutionEvidence,
        Vec<AuthenticatedSignerResolutionEvidence>,
    ),
    AgentSignerEvidenceQueryFailureReason,
> {
    reserve_evidence_challenge(state, selector).await?;
    let (root, dependencies) = current_authenticated_agent_signer_evidence(state, selector).await?;
    persist_agent_signer_evidence_closure(state, &root, &dependencies)
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    Ok((root, dependencies))
}

async fn historical_authenticated_agent_signer_evidence(
    state: &AppState,
    key: soland_storage::HistoricalAgentSignerEvidenceKey,
) -> Result<
    (
        AuthenticatedSignerResolutionEvidence,
        Vec<AuthenticatedSignerResolutionEvidence>,
    ),
    AgentSignerEvidenceQueryFailureReason,
> {
    let store = state.persistence().governance_dependency_store();
    let item = store
        .get_historical_agent_signer_evidence(&key)
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?
        .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
        authenticated_signer_resolution_evidence: root,
        ..
    } = item
    else {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    };
    let AuthenticatedSignerResolutionEvidence::Agent {
        signer_id,
        verification_method,
        agent_signer_evidence,
        ..
    } = root.as_ref()
    else {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    };
    let AgentSignerEvidence::HistoricalEvent {
        event_admission_receipt,
        ..
    } = agent_signer_evidence.as_ref()
    else {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    };
    if signer_id != &key.agent_id
        || verification_method != &key.verification_method
        || event_admission_receipt.event_id != key.event_id
        || event_admission_receipt.receiver_id != key.receiver_id
    {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    }
    root.validate_attester_binding()
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;

    let mut dependencies = Vec::new();
    let mut pending =
        arkret_models_collaboration::governance_dependencies::governance_attester_evidence_selectors(
            std::slice::from_ref(&root),
        )
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let mut resolved = std::collections::BTreeSet::new();
    while let Some(dependency_selector) = pending.pop() {
        let selector_bytes = arkret_canonical::canonical_json_bytes(&dependency_selector)
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
        if !resolved.insert(selector_bytes) {
            continue;
        }
        if resolved.len() > 64 {
            return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
        }
        let dependency = store
            .get_unscoped_signer_evidence(&dependency_selector)
            .await
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?
            .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
        let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
            selector: stored_selector,
            authenticated_signer_resolution_evidence,
        } = dependency
        else {
            return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
        };
        if stored_selector != dependency_selector {
            return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
        }
        authenticated_signer_resolution_evidence
            .validate_attester_binding()
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
        pending.extend(
            arkret_models_collaboration::governance_dependencies::governance_attester_evidence_selectors(
                std::slice::from_ref(&authenticated_signer_resolution_evidence),
            )
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?,
        );
        dependencies.push(*authenticated_signer_resolution_evidence);
    }
    Ok((*root, dependencies))
}

async fn current_service_signer_evidence(
    state: &AppState,
) -> Result<AuthenticatedSignerResolutionEvidence, AgentSignerEvidenceQueryFailureReason> {
    let resolution =
        crate::routing::system::service_resolution::current_authenticated_service_resolution(state)
            .await
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let service_id = resolution
        .service_resolution_record
        .record
        .service_id
        .clone();
    arkret_identity::service_signer_evidence_from_authenticated_resolution(
        resolution,
        &service_id,
        chrono::Utc::now(),
    )
    .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)
}

async fn current_controller_signer_evidence(
    state: &AppState,
    controller_principal_id: &DidCoreId,
    verification_method: &arkret_wire::DidUrl,
    attester: &AuthenticatedSignerResolutionEvidence,
) -> Result<AuthenticatedSignerResolutionEvidence, AgentSignerEvidenceQueryFailureReason> {
    let station_id = attester.signer_id().clone();
    let authority = arkret_wire::AccountId::new(controller_principal_id.clone(), station_id);
    let (public_resolution, normalized_did_document) =
        crate::routing::system::principal_resolution::current_public_principal_resolution(
            state, &authority,
        )
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let evidence = AuthenticatedSignerResolutionEvidence::Principal {
        signer_id: controller_principal_id.clone(),
        verification_method: verification_method.clone(),
        public_resolution,
        normalized_did_document,
        attester_signer_evidence_ref: attester
            .evidence_ref()
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?,
    };
    evidence
        .validate_attester_binding()
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    Ok(evidence)
}

/// Retain a peer service resolution as a signer-evidence leaf.
///
/// `at` is the instant the retained resolution is judged against and MUST be
/// the same instant the eventual verifier uses: `Utc::now()` for the current
/// branch, and the receipt `accepted_at` for a historical Agent root
/// (`zh/identity/key-management.md` §historical branch). Judging a historical
/// leaf at `now` would publish a root that its own verifier evaluates at
/// `accepted_at` and may reject, which is unrecoverable once the selector
/// tuple is taken.
pub(crate) async fn fetch_service_signer_evidence(
    state: &AppState,
    service_id: &DidCoreId,
    base_url: Option<&str>,
    verification_method: Option<&arkret_wire::DidUrl>,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<AuthenticatedSignerResolutionEvidence, AgentSignerEvidenceQueryFailureReason> {
    // A private Account Authority shares its owning Station's service history.
    // Its gate-account origin is not a public service-resolution endpoint.
    let resolution = if service_id == &state.service_core_id() {
        crate::routing::system::service_resolution::current_authenticated_service_resolution(state)
            .await
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?
    } else {
        let resolved_base;
        let base_url = match base_url.filter(|value| !value.trim().is_empty()) {
            Some(base_url) => base_url,
            None => {
                resolved_base = crate::routing::federation::resolved_peer_base_url(
                    state,
                    service_id.as_str(),
                    arkret_wire::ServiceKind::Station.as_str(),
                    false,
                )
                .await
                .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
                &resolved_base
            }
        };
        let path = arkret_models_identity::canonical_service_current_record_path(service_id);
        let target = format!("{}{}", base_url.trim_end_matches('/'), path);
        let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
            &target,
            "Agent signer evidence service resolution",
            state.config().development_mode,
            Duration::from_secs(10),
        )
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
        let response = client
            .get(url)
            .header(
                "arkret-operation",
                arkret_wire::ServiceOperationId::OPEN_SERVICE_READ_RESOLUTION_V1,
            )
            .send()
            .await
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
        if !response.status().is_success() {
            return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
        }
        let body = response
            .bytes()
            .await
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
        if body.len() > 1024 * 1024 {
            return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
        }
        serde_json::from_slice(&body)
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?
    };
    match verification_method {
        Some(method) => {
            arkret_identity::service_signer_evidence_for_method_from_authenticated_resolution(
                resolution,
                service_id,
                method.clone(),
                at,
            )
        }
        None => arkret_identity::service_signer_evidence_from_authenticated_resolution(
            resolution, service_id, at,
        ),
    }
    .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)
}

pub(crate) async fn materialize_historical_agent_signer_evidence(
    state: &AppState,
    receipt: arkret_models_identity::agent_signer_evidence::AgentEventAdmissionReceipt,
    receiver_base_url: &str,
) -> Result<(), AppError> {
    let store = state.persistence().governance_dependency_store();
    if let Some(materialized) = store
        .get_historical_agent_signer_evidence(&soland_storage::HistoricalAgentSignerEvidenceKey {
            agent_id: receipt.agent_id.clone(),
            verification_method: receipt.verification_method.clone(),
            event_id: receipt.event_id.clone(),
            receiver_id: receipt.receiver_id.clone(),
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        return replayed_historical_agent_signer_evidence(materialized, &receipt);
    }
    let original_selector = GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
        content_digest: receipt
            .producer_signer_resolution_evidence_ref
            .content_digest()
            .map_err(|error| AppError::internal(error.to_string()))?,
    };
    let original_item = store
        .get_unscoped_signer_evidence(&original_selector)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::internal("origin-frozen Agent signer evidence is missing"))?;
    let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
        authenticated_signer_resolution_evidence: original_root,
        ..
    } = original_item
    else {
        return Err(AppError::internal(
            "origin-frozen signer dependency has the wrong kind",
        ));
    };
    if original_root
        .evidence_ref()
        .map_err(|error| AppError::internal(error.to_string()))?
        != receipt.producer_signer_resolution_evidence_ref
    {
        return Err(AppError::internal(
            "receipt producer evidence ref does not resolve byte-exactly",
        ));
    }
    let AuthenticatedSignerResolutionEvidence::Agent {
        signer_id,
        verification_method,
        agent_signer_evidence,
        attester_signer_evidence_ref,
        controller_signer_evidence_ref,
        account_authority_signer_evidence_ref,
        ..
    } = *original_root
    else {
        return Err(AppError::internal(
            "receipt producer evidence is not an Agent CurrentAdmission root",
        ));
    };
    let AgentSignerEvidence::CurrentAdmission {
        schema,
        admission_evidence,
        transparency,
        ..
    } = *agent_signer_evidence
    else {
        return Err(AppError::internal(
            "receipt producer evidence is not an Agent CurrentAdmission root",
        ));
    };
    if signer_id != receipt.agent_id || verification_method != receipt.verification_method {
        return Err(AppError::internal(
            "receipt Agent identity does not match the frozen producer evidence",
        ));
    }
    async fn dependency_by_ref(
        store: &dyn soland_storage::GovernanceDependencyStore,
        evidence_ref: &arkret_wire::SignerEvidenceRef,
    ) -> Result<AuthenticatedSignerResolutionEvidence, AppError> {
        let content_digest = evidence_ref
            .content_digest()
            .map_err(|error| AppError::internal(error.to_string()))?;
        let item = store
            .get_unscoped_signer_evidence(
                &GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                    content_digest,
                },
            )
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            .ok_or_else(|| AppError::internal("Agent signer dependency is missing"))?;
        let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
            authenticated_signer_resolution_evidence,
            ..
        } = item
        else {
            return Err(AppError::internal(
                "Agent signer dependency has the wrong kind",
            ));
        };
        Ok(*authenticated_signer_resolution_evidence)
    }
    let authority_evidence = dependency_by_ref(store, &attester_signer_evidence_ref).await?;
    let controller_evidence = dependency_by_ref(store, &controller_signer_evidence_ref).await?;
    let account_authority_evidence =
        dependency_by_ref(store, &account_authority_signer_evidence_ref).await?;
    let receipt_method =
        arkret_signatures::agent_evidence::historical_receipt_verification_method(&receipt)
            .map_err(|reason| AppError::internal(reason.as_str()))?;
    let receiver_evidence = fetch_service_signer_evidence(
        state,
        &receipt.receiver_id,
        Some(receiver_base_url),
        Some(&receipt_method),
        receipt.accepted_at,
    )
    .await
    .map_err(|reason| AppError::internal(format!("{reason:?}")))?;
    let AuthenticatedSignerResolutionEvidence::Service {
        authenticated_resolution,
        ..
    } = &receiver_evidence
    else {
        return Err(AppError::internal(
            "receiver signer evidence is not authenticated service evidence",
        ));
    };
    let historical_document = arkret_identity::authenticated_service_document_at(
        authenticated_resolution,
        &receipt.receiver_id,
        receipt.accepted_at,
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    let receiver_key = arkret_identity::jws::resolve_ed25519_pubkey_from_document(
        &historical_document,
        receipt_method.as_str(),
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    arkret_signatures::agent_evidence::verify_agent_event_admission_receipt(
        &receipt,
        &PublicKeyMaterial::Ed25519Raw {
            bytes: receiver_key.to_bytes().to_vec(),
        },
    )
    .map_err(|reason| AppError::internal(reason.as_str()))?;
    let attested_at = chrono::Utc::now();
    let mut historical = AgentSignerEvidence::HistoricalEvent {
        schema,
        admission_evidence,
        event_admission_receipt: receipt,
        outer_attestation: AgentHistoricalEvidenceOuterAttestation {
            domain: non_empty(arkret_wire::DomainSeparationId::AGENT_SIGNER_EVIDENCE_V1)
                .map_err(|reason| AppError::internal(format!("{reason:?}")))?,
            core_digest: Hash::new(format!("sha256:{}", "00".repeat(32)))
                .map_err(|error| AppError::internal(error.to_string()))?,
            source_id: authority_evidence.signer_id().clone(),
            verification_method: authority_evidence.verification_method().clone(),
            attested_at,
            proof: empty_proof().map_err(|reason| AppError::internal(format!("{reason:?}")))?,
        },
        transparency,
    };
    arkret_signatures::agent_evidence::sign_agent_historical_evidence_outer_attestation(
        &mut historical,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    let historical_root = arkret::build_agent_signer_resolution_evidence(
        historical,
        &authority_evidence,
        &controller_evidence,
        &account_authority_evidence,
        &receiver_evidence,
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    persist_agent_signer_evidence_closure(
        state,
        &historical_root,
        &[
            authority_evidence,
            controller_evidence,
            account_authority_evidence,
            receiver_evidence,
        ],
    )
    .await
}

/// Decide the outcome of a second consumption of one already materialized
/// selector tuple.
///
/// The Agent Authority signs a fresh outer attestation on every attempt, so
/// re-running materialization derives a different canonical root digest for
/// byte-identical inputs: the new digest cannot take the stored tuple, and the
/// tuple would answer `duplicate_conflict` forever. `zh/sync/federation.md`
/// §4.1.1 makes the same tuple carrying the same receipt an exact replay, so it
/// resolves here as a no-op against the stored root. A stored tuple carrying a
/// different receipt stays a real conflict with zero overwrite; the receipt
/// binds the producer evidence pair, so receipt equality also settles the
/// frozen `admission_evidence` the root was built from.
fn replayed_historical_agent_signer_evidence(
    materialized: GovernanceDependency,
    receipt: &arkret_models_identity::agent_signer_evidence::AgentEventAdmissionReceipt,
) -> Result<(), AppError> {
    let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
        authenticated_signer_resolution_evidence,
        ..
    } = materialized
    else {
        return Err(AppError::internal(
            "materialized historical Agent signer evidence has the wrong kind",
        ));
    };
    let AuthenticatedSignerResolutionEvidence::Agent {
        agent_signer_evidence,
        ..
    } = *authenticated_signer_resolution_evidence
    else {
        return Err(AppError::internal(
            "materialized historical Agent signer evidence has the wrong kind",
        ));
    };
    let AgentSignerEvidence::HistoricalEvent {
        event_admission_receipt,
        ..
    } = *agent_signer_evidence
    else {
        return Err(AppError::internal(
            "materialized historical Agent signer evidence has the wrong kind",
        ));
    };
    if event_admission_receipt != *receipt {
        return Err(AppError::conflict(
            "duplicate_conflict: historical Agent signer evidence tuple differs",
        ));
    }
    Ok(())
}

async fn persist_agent_signer_evidence_closure(
    state: &AppState,
    root: &AuthenticatedSignerResolutionEvidence,
    dependencies: &[AuthenticatedSignerResolutionEvidence],
) -> Result<(), AppError> {
    let store = state.persistence().governance_dependency_store();
    // Dependency CAS objects are immutable. Publish every leaf first and the
    // selector-indexed root last, so a crash can leave only harmless orphan
    // leaves and can never expose a root whose recursive closure is missing.
    for evidence in dependencies.iter().chain(std::iter::once(root)) {
        let content_digest = evidence
            .canonical_sha256_digest()
            .map_err(|error| AppError::internal(error.to_string()))?;
        let item = GovernanceDependency::AuthenticatedSignerResolutionEvidence {
            selector: GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                content_digest,
            },
            authenticated_signer_resolution_evidence: Box::new(evidence.clone()),
        };
        store
            .put_unscoped_signer_evidence_exact(item)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
    }
    Ok(())
}

async fn reserve_evidence_challenge(
    state: &AppState,
    selector: &AgentSignerEvidenceQuerySelector,
) -> Result<(), AgentSignerEvidenceQueryFailureReason> {
    let AgentSignerEvidenceQuerySelector::CurrentAdmission {
        agent_id,
        challenge,
        ..
    } = selector
    else {
        return Ok(());
    };
    let key = format!("agent-signer-evidence:{}", challenge.as_str());
    let persistence = state.persistence();
    let authenticated_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        agent_id.clone(),
        state.service_core_id(),
    ));
    if persistence
        .scoped_idempotency_record(
            &authenticated_actor,
            "ak.self.agent_signer_evidence.read.resolve",
            &key,
        )
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?
        .is_some()
    {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    }
    let marker = uuid::Uuid::now_v7().to_string();
    let request_hash = canonical_digest(selector)?.to_string();
    let now = chrono::Utc::now();
    persistence
        .record_idempotency(&soland_storage::IdempotencyRecord {
            authenticated_actor: authenticated_actor.clone(),
            operation_id: "ak.self.agent_signer_evidence.read.resolve".to_owned(),
            idempotency_key: key.clone(),
            request_hash,
            response_status: 201,
            response_body: serde_json::json!({"reservation": marker}),
            created_at: now,
            expires_at: now + chrono::Duration::minutes(5),
        })
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let winner = persistence
        .scoped_idempotency_record(
            &authenticated_actor,
            "ak.self.agent_signer_evidence.read.resolve",
            &key,
        )
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?
        .and_then(|record| {
            record
                .response_body
                .get("reservation")
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned)
        });
    if winner.as_deref() != Some(marker.as_str()) {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    }
    Ok(())
}

/// Resolve and independently verify the Account Authority-owned controller
/// gate before any Agent-PCR snapshot assembly. The remaining signed
/// Seal/state witness assembly still fails closed below until all exact
/// projection inputs are present.
async fn preflight_controller_gate(
    state: &AppState,
    selector: &AgentSignerEvidenceQuerySelector,
) -> Result<ControllerAccountGateAttestation, AgentSignerEvidenceQueryFailureReason> {
    let AgentSignerEvidenceQuerySelector::CurrentAdmission { agent_id, .. } = selector else {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    };
    let agent = state
        .agent_pairings()
        .agent(agent_id.as_str())
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?
        .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let principal_id = DidCoreId::new(agent.controller_principal_id)
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let destination_id = crate::routing::events::peer::trusted_account_authority_id(state)
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let source_id = DidCoreId::new(state.service_id().clone())
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let account_authority_url = state
        .config()
        .account_authority_url
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let target = format!(
        "{}/_arkret/gate/account/controller-gate-attestations",
        account_authority_url.trim_end_matches('/')
    );
    let request_id = RequestId::new(format!("ak:request:{}", uuid::Uuid::now_v7()))
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let request = ControllerAccountGateAttestationIssueRequestBody {
        request_id: request_id.clone(),
        principal_id: principal_id.clone(),
        agent_authority_id: source_id.clone(),
        agent_authority_resolution:
            crate::routing::system::service_resolution::current_authenticated_service_resolution(
                state,
            )
            .await
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?,
    };
    let body = arkret_canonical::canonical_json_bytes(&request)
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &target,
        "controller account gate",
        state.config().development_mode,
        Duration::from_secs(10),
    )
    .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/json"),
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "content-digest",
        &crate::routing::federation::outbox::content_digest_header_value(&body),
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "source-service-id",
        source_id.as_str(),
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "destination-service-id",
        destination_id.as_str(),
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "arkret-operation-id",
        arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_CONTROLLER_GATE_ATTESTATION_V1,
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "arkret-operation",
        arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_CONTROLLER_GATE_ATTESTATION_V1,
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "arkret-request-id",
        request_id.as_str(),
    );
    let headers = crate::routing::federation::outbox::rfc9421_sign_controller_gate_request(
        state, headers, &target,
    );
    let response = client
        .post(url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    if !response.status().is_success() {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    }
    let response = response
        .bytes()
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    if response.len() > 1024 * 1024 {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    }
    let outcome: ControllerAccountGateAttestationIssueOutcome =
        serde_json::from_slice(&response)
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    if outcome.request_id != request_id
        || outcome.controller_account_gate_attestation.principal_id != principal_id
        || outcome.controller_account_gate_attestation.authority_id != destination_id
    {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    }
    let gate = outcome.controller_account_gate_attestation;
    let authority_key =
        crate::jws_verify::resolve_ed25519_pubkey_async(state, gate.verification_method.as_str())
            .await
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    arkret_signatures::agent_evidence::verify_controller_account_gate_attestation(
        &gate,
        &principal_id,
        &destination_id,
        &PublicKeyMaterial::Ed25519Raw {
            bytes: authority_key.to_bytes().to_vec(),
        },
        chrono::Utc::now(),
    )
    .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    Ok(gate)
}

async fn produce_current_agent_signer_evidence(
    state: &AppState,
    selector: &AgentSignerEvidenceQuerySelector,
    gate: ControllerAccountGateAttestation,
) -> Result<CurrentAgentSignerEvidence, AgentSignerEvidenceQueryFailureReason> {
    let AgentSignerEvidenceQuerySelector::CurrentAdmission {
        agent_id,
        verification_method,
        operation_id,
        request_digest,
        verifier_id,
        audience,
        challenge,
    } = selector
    else {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    };
    let now = chrono::Utc::now();
    let agent = state
        .agent_pairings()
        .agent(agent_id.as_str())
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?
        .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    if agent.state != arkret_models_collaboration::agent_operations::AgentLifecycleState::Active {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentAuthorizationInactive);
    }
    let runtime = agent
        .runtime_bindings()
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?
        .active_binding
        .ok_or(AgentSignerEvidenceQueryFailureReason::AgentAuthorizationInactive)?;
    if runtime.verification_method != *verification_method
        || runtime.signing_key_binding.agent_id != *agent_id
        || runtime.signing_key_binding.agent_key_authorize_event_id != runtime.authorized_event_ref
    {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    }
    if runtime
        .signing_key_binding
        .expires_at
        .is_some_and(|expires_at| expires_at <= now)
    {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentAuthorizationInactive);
    }
    let realm_id = RealmId::new(agent.principal_control_realm_id.clone())
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let authorize_event = accepted_event(state, &runtime.authorized_event_ref).await?;
    let payload =
        arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload::try_from(
            &authorize_event,
        )
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let binding_digest = arkret_signatures::agent_evidence::agent_signing_key_binding_digest(
        &runtime.signing_key_binding,
    )
    .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let agent_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        agent_id.clone(),
        state.service_core_id().clone(),
    ));
    if authorize_event.realm_id != realm_id
        || authorize_event.actor_id != agent_actor
        || payload.verification_method != *verification_method
        || payload.public_key_digest != runtime.public_key_digest
        || payload.signing_key_binding_digest != binding_digest
        || payload.key_id != runtime.signing_key_binding.agent_key_id
    {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    }
    let key_seal = covering_seal(state, &authorize_event).await?;
    let key_cell_ref = arkret_signatures::agent_evidence::agent_authorization_cell_ref(
        agent_id,
        &runtime.signing_key_binding.agent_key_id,
    )
    .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let (key_value, _key_heads, key_proof) =
        witnessed_cell(state, &realm_id, &key_seal, &key_cell_ref).await?;
    let key_value: Vec<AgentKeyCellEntry> = serde_json::from_value(key_value)
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;

    let lifecycle = accepted_current_lifecycle(state, &agent, agent_id, &realm_id).await?;
    let lifecycle_seal = covering_seal(state, &lifecycle.event).await?;
    let lifecycle_cell_ref = lifecycle_cell_ref(&agent_actor)?;
    let (lifecycle_value, lifecycle_heads, lifecycle_proof) =
        witnessed_cell(state, &realm_id, &lifecycle_seal, &lifecycle_cell_ref).await?;
    let lifecycle_value: AgentLifecycleStatus = serde_json::from_value(lifecycle_value)
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    if lifecycle_value != AgentLifecycleStatus::Active {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentAuthorizationInactive);
    }

    let frontier =
        crate::routing::identity::agent_pcr::agent_event_seal_head(state, realm_id.as_str())
            .await
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?
            .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let closure = state
        .projections()
        .seal_closure(std::slice::from_ref(&frontier.id))
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    if !closure.contains(&key_seal.id) || !closure.contains(&lifecycle_seal.id) {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    }
    let mut seal_lineage = Vec::with_capacity(closure.len());
    for seal_id in closure {
        seal_lineage.push(
            state
                .projections()
                .seal_by_id(&seal_id)
                .await
                .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?
                .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?,
        );
    }
    seal_lineage.sort_by_key(|seal| seal.notary_seq);

    let service_id =
        arkret_wire::project_did_to_core_id(&state.service_resolution_commitment().did)
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let (_, authority_method) = state
        .current_service_receipt_binding()
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let key_seal_id = key_seal.id.clone();
    let lifecycle_seal_id = lifecycle_seal.id.clone();
    let core = AgentAuthorityState {
        authority_id: service_id.clone(),
        principal_control_realm_id: realm_id,
        frontier_seal_id: frontier.id.clone(),
        frontier_state_root: frontier.state_root.clone(),
        signing_key_binding: runtime.signing_key_binding.clone(),
        authorization: AgentAuthorizationEvidence {
            status: AgentAuthorizationStatus::Active,
            authorized_event_id: runtime.authorized_event_ref.clone(),
            accepted_seal_id: key_seal.id.clone(),
            accepted_at: key_seal.sealed_at,
            not_before: runtime.signing_key_binding.issued_at,
            expires_at: runtime.signing_key_binding.expires_at,
            transition_event_id: None,
            transition_seal_id: None,
        },
        key_state_witness: AgentAuthorizationStateWitness {
            component: non_empty(AGENT_KEY_COMPONENT)?,
            agent_id: agent_id.clone(),
            authorization_event_id: runtime.authorized_event_ref,
            seal_id: key_seal.id.clone(),
            state_root: key_seal.state_root.clone(),
            seal: key_seal,
            cell_ref: key_cell_ref,
            cell_value: key_value,
            leaf_digest: key_proof.leaf_digest,
            leaf_index: key_proof.leaf_index,
            leaf_count: key_proof.leaf_count,
            inclusion_proof: key_proof.inclusion_proof,
        },
        key_transition_witness: None,
        agent_lifecycle_witness: AgentLifecycleWitness {
            component: non_empty(AGENT_STATUS_COMPONENT)?,
            agent_id: agent_id.clone(),
            status: AgentLifecycleStatus::Active,
            provenance: lifecycle.provenance,
            accepted_status_event: lifecycle.event,
            seal_id: lifecycle_seal.id.clone(),
            state_root: lifecycle_seal.state_root.clone(),
            seal: lifecycle_seal,
            cell_ref: lifecycle_cell_ref,
            cell_value: lifecycle_value,
            // `ak.component.agent.status.v1` is an `fsm`, so its section 6.2.1
            // leaf hashes the head set; a verifier cannot rebuild `leaf_digest`
            // from the settled status alone.
            cell_heads: lifecycle_heads
                .iter()
                .map(|head| {
                    Ok(arkret_models_identity::AgentLifecycleHead {
                        event_id: arkret_wire::EventId::from_event_digest(&head.move_id).map_err(
                            |_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing,
                        )?,
                        value: serde_json::from_value(head.value.clone()).map_err(|_| {
                            AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing
                        })?,
                    })
                })
                .collect::<Result<Vec<_>, AgentSignerEvidenceQueryFailureReason>>()?,
            leaf_digest: lifecycle_proof.leaf_digest,
            leaf_index: lifecycle_proof.leaf_index,
            leaf_count: lifecycle_proof.leaf_count,
            inclusion_proof: lifecycle_proof.inclusion_proof,
        },
        seal_lineages: seal_lineage,
    };
    let state_digest = canonical_digest(&core)?;
    let expires_at = now + chrono::Duration::minutes(2);
    let mut authority_state_evidence = AgentAuthorityStateEvidence {
        state: core,
        state_digest: state_digest.clone(),
        lease: AgentAuthorityStateLease {
            authority_kind: non_empty("agent_authority")?,
            authority_id: service_id.clone(),
            verification_method: authority_method.clone(),
            state_digest: state_digest.clone(),
            issued_at: now,
            expires_at,
            proof: empty_proof()?,
        },
    };
    arkret_signatures::agent_evidence::sign_agent_authority_state_lease(
        &mut authority_state_evidence.lease,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let admission_evidence_digest =
        arkret_signatures::agent_evidence::agent_admission_evidence_digest(
            &authority_state_evidence,
            &gate,
        )
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let gate_digest = canonical_digest(&gate)?;
    let admission_evidence = AgentAdmissionEvidence {
        agent_authority_state_evidence: authority_state_evidence,
        controller_account_gate_attestation: gate,
        admission_evidence_digest,
    };
    let mut evidence = AgentSignerEvidence::CurrentAdmission {
        schema: non_empty(SchemaId::AGENT_SIGNER_EVIDENCE_V1)?,
        admission_evidence,
        current_observation: AgentCurrentObservation {
            operation_id: operation_id.clone(),
            request_digest: request_digest.clone(),
            verifier_id: verifier_id.clone(),
            audience_id: audience.clone(),
            challenge: challenge.clone(),
            agent_authority_state_digest: state_digest,
            agent_key_seal_id: key_seal_id,
            agent_status_seal_id: lifecycle_seal_id,
            controller_gate_attestation_digest: gate_digest,
            evaluated_at: now,
            expires_at,
        },
        outer_attestation: AgentEvidenceOuterAttestation {
            domain: non_empty(arkret_wire::DomainSeparationId::AGENT_SIGNER_EVIDENCE_V1)?,
            core_digest: Hash::new(format!("sha256:{}", "00".repeat(32)))
                .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?,
            source_id: service_id,
            verification_method: authority_method,
            issued_at: now,
            expires_at,
            proof: empty_proof()?,
        },
        transparency: None,
    };
    arkret_signatures::agent_evidence::sign_agent_evidence_outer_attestation(
        &mut evidence,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    verify_current_evidence(state, &evidence, selector, now).await?;
    match evidence {
        AgentSignerEvidence::CurrentAdmission {
            schema,
            admission_evidence,
            current_observation,
            outer_attestation,
            transparency,
        } => Ok(CurrentAgentSignerEvidence {
            schema,
            admission_evidence,
            current_observation,
            outer_attestation,
            transparency,
        }),
        AgentSignerEvidence::HistoricalEvent { .. } => unreachable!(),
    }
}

struct AcceptedLifecycle {
    event: Event,
    provenance: AgentLifecycleProvenance,
}

async fn accepted_event(
    state: &AppState,
    event_id: &EventId,
) -> Result<Event, AgentSignerEvidenceQueryFailureReason> {
    let record = state
        .event_queries()
        .canonical_event(event_id.as_str())
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?
        .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let event: Event = serde_json::from_value(record.envelope)
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    if event.event_id != *event_id {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    }
    Ok(event)
}

async fn covering_seal(
    state: &AppState,
    event: &Event,
) -> Result<Seal, AgentSignerEvidenceQueryFailureReason> {
    let digest_suite = arkret::signed_event_digest_claim(event)
        .and_then(|digest| digest.digest_suite().map_err(Into::into))
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let digest = Hash::new(
        event
            .event_digest_with_digest_suite(digest_suite)
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?,
    )
    .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    state
        .projections()
        .seal_covering_event(&digest)
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?
        .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)
}

async fn witnessed_cell(
    state: &AppState,
    realm_id: &RealmId,
    seal: &Seal,
    cell: &NonEmptyString,
) -> Result<
    (
        serde_json::Value,
        Vec<arkret_state::lattice::cas_register::CasHead>,
        arkret_state::StateInclusionProof,
    ),
    AgentSignerEvidenceQueryFailureReason,
> {
    let cell = CellRef::new(cell.as_str().to_owned())
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let effective = state
        .projections()
        .effective_state_at(std::slice::from_ref(&seal.id), realm_id)
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let value = effective
        .get(&cell)
        .and_then(|value| match value {
            arkret_state::lattice::CellState::Value(value) => Some(value.clone()),
            arkret_state::lattice::CellState::Bottom(_) => None,
        })
        .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let digest_suite = state
        .projections()
        .seal_digest_suites(seal)
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?
        .seal_digest_suite;
    // The branch is over the governance `state_root`, so a causal register in
    // this view needs its head half to hash the leaf shape spec section 6.2.1
    // defines. `fsm` is one since section 9.3.1.5, which is why the head set
    // travels with the witness rather than being rebuilt from the value.
    let cas_heads = state
        .projections()
        .effective_cas_heads_at(std::slice::from_ref(&seal.id), realm_id)
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let proof = arkret_state::state_inclusion_proof(
        arkret_state::GovernanceView::new(&effective, &cas_heads),
        &cell,
        digest_suite,
    )
    .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let heads = cas_heads.get(&cell).cloned().unwrap_or_default();
    Ok((value, heads, proof))
}

fn lifecycle_cell_ref(
    agent_actor_id: &arkret_wire::ActorId,
) -> Result<NonEmptyString, AgentSignerEvidenceQueryFailureReason> {
    if agent_actor_id.as_account_id().is_none() {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    }
    let canonical_actor = agent_actor_id
        .canonical_key()
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let subject = arkret_wire::composite_subject(&[canonical_actor.as_str()])
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    non_empty(&format!("ak:cell:{AGENT_STATUS_COMPONENT}:{subject}"))
}

async fn accepted_current_lifecycle(
    state: &AppState,
    agent: &soland_services::identity::AgentPairingState,
    agent_id: &DidCoreId,
    realm_id: &RealmId,
) -> Result<AcceptedLifecycle, AgentSignerEvidenceQueryFailureReason> {
    let agent_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        agent_id.clone(),
        state.service_core_id().clone(),
    ));
    let records = state
        .event_queries()
        .accepted_events()
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let mut events = records
        .into_iter()
        .filter_map(|record| serde_json::from_value::<Event>(record.envelope).ok())
        .filter(|event| {
            event.realm_id == *realm_id
                && event.actor_id == agent_actor
                && matches!(
                    event.kind,
                    arkret_wire::EventKind::RealmCreate
                        | arkret_wire::EventKind::SelfAgentPause
                        | arkret_wire::EventKind::SelfAgentResume
                        | arkret_wire::EventKind::SelfAgentDeactivate
                )
        })
        .collect::<Vec<_>>();
    events.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    let event = events
        .last()
        .cloned()
        .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let provenance = match event.kind {
        arkret_wire::EventKind::RealmCreate => {
            let provision = agent
                .provision_event_refs
                .as_ref()
                .and_then(|refs| refs.get("provision_event_id"))
                .and_then(serde_json::Value::as_str)
                .and_then(|value| EventId::new(value.to_owned()).ok())
                .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
            AgentLifecycleProvenance::DelegatedPcrGenesis {
                realm_create_event_id: event.event_id.clone(),
                agent_provision_event_id: provision,
            }
        }
        arkret_wire::EventKind::SelfAgentResume => {
            let predecessor = events
                .iter()
                .rev()
                .skip(1)
                .find(|candidate| candidate.kind == arkret_wire::EventKind::SelfAgentPause)
                .map(|candidate| candidate.event_id.clone())
                .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
            AgentLifecycleProvenance::ResumeAccepted {
                resume_event_id: event.event_id.clone(),
                predecessor_pause_event_id: predecessor,
            }
        }
        _ => return Err(AgentSignerEvidenceQueryFailureReason::AgentAuthorizationInactive),
    };
    Ok(AcceptedLifecycle { event, provenance })
}

fn non_empty(value: &str) -> Result<NonEmptyString, AgentSignerEvidenceQueryFailureReason> {
    NonEmptyString::new(value.to_owned())
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)
}

fn empty_proof() -> Result<AgentDetachedJws, AgentSignerEvidenceQueryFailureReason> {
    Ok(AgentDetachedJws {
        kind: non_empty("detached_jws")?,
        jws: non_empty("pending")?,
    })
}

fn canonical_digest(
    value: &impl serde::Serialize,
) -> Result<Hash, AgentSignerEvidenceQueryFailureReason> {
    let digest = crate::util::canonical_digest(value)
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    Hash::new(digest).map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)
}

async fn verify_current_evidence(
    state: &AppState,
    evidence: &AgentSignerEvidence,
    selector: &AgentSignerEvidenceQuerySelector,
    observed_at: chrono::DateTime<chrono::Utc>,
) -> Result<[u8; 32], AgentSignerEvidenceQueryFailureReason> {
    let AgentSignerEvidence::CurrentAdmission {
        admission_evidence,
        current_observation: _,
        outer_attestation,
        ..
    } = evidence
    else {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    };
    let AgentSignerEvidenceQuerySelector::CurrentAdmission {
        agent_id,
        verification_method,
        operation_id,
        request_digest,
        verifier_id,
        audience,
        challenge,
    } = selector
    else {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    };
    let snapshot = &admission_evidence.agent_authority_state_evidence;
    let binding = &snapshot.state.signing_key_binding;
    if binding.agent_id != *agent_id || binding.verification_method != *verification_method {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    }
    let controller_device_id = binding
        .controller_proof
        .verification_method
        .as_str()
        .rsplit_once('#')
        .and_then(|(_, fragment)| arkret_wire::DeviceId::new(fragment.to_owned()).ok())
        .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let controller_account = arkret_wire::AccountId::new(
        binding.controller_principal_id.clone(),
        state.service_core_id().clone(),
    );
    let controller_key =
        crate::jws_verify::resolve_principal_authorized_device_key_with_account_authority_async(
            binding.controller_proof.verification_method.as_str(),
            &controller_account,
            &controller_device_id,
            state,
        )
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let authority_key = crate::jws_verify::resolve_ed25519_pubkey_async(
        state,
        outer_attestation.verification_method.as_str(),
    )
    .await
    .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let gate = &admission_evidence.controller_account_gate_attestation;
    let trusted_account_authority =
        crate::routing::events::peer::trusted_account_authority_id(state)
            .await
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    if gate.authority_id != trusted_account_authority {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    }
    let account_authority_key =
        crate::jws_verify::resolve_ed25519_pubkey_async(state, gate.verification_method.as_str())
            .await
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let controller_material = PublicKeyMaterial::Ed25519Raw {
        bytes: controller_key.to_bytes().to_vec(),
    };
    let authority_material = PublicKeyMaterial::Ed25519Raw {
        bytes: authority_key.to_bytes().to_vec(),
    };
    let account_authority_material = PublicKeyMaterial::Ed25519Raw {
        bytes: account_authority_key.to_bytes().to_vec(),
    };
    let mut seal_keys = std::collections::BTreeMap::new();
    for seal in &snapshot.state.seal_lineages {
        for method in seal_signature_methods(seal) {
            if seal_keys.contains_key(method.as_str()) {
                continue;
            }
            let key = if method == &binding.controller_proof.verification_method {
                controller_key
            } else {
                crate::jws_verify::resolve_ed25519_pubkey_async(state, method.as_str())
                    .await
                    .map_err(|_| {
                        AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing
                    })?
            };
            seal_keys.insert(method.as_str().to_owned(), key);
        }
    }
    let verify_seal = |seal: &Seal| verify_seal_with_keys(seal, &seal_keys);
    let verify_lifecycle = |witness: &AgentLifecycleWitness| validate_lifecycle_witness(witness);
    let binding_digest =
        arkret_signatures::agent_evidence::agent_signing_key_binding_digest(binding)
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let agent_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        agent_id.clone(),
        state.service_core_id().clone(),
    ));
    let state_context = arkret_signatures::agent_evidence::AgentEvidenceStateVerificationContext {
        signer_id: agent_id,
        signer_actor_id: &agent_actor,
        agent_key_id: &binding.agent_key_id,
        controller_principal_id: &binding.controller_principal_id,
        agent_key_authorize_event_id: &binding.agent_key_authorize_event_id,
        authorize_public_key_digest: &binding.public_key_digest,
        authorize_signing_key_binding_digest: &binding_digest,
        verify_seal_signature: &verify_seal,
        verify_lifecycle_reducer: &verify_lifecycle,
    };
    let verified_state = arkret_signatures::agent_evidence::verify_agent_evidence_state(
        admission_evidence,
        &state_context,
    )
    .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let common = arkret_signatures::agent_evidence::AgentEvidenceCommonContext {
        signer_id: agent_id,
        agent_key_id: &binding.agent_key_id,
        controller_principal_id: &binding.controller_principal_id,
        verification_method,
        agent_key_authorize_event_id: &binding.agent_key_authorize_event_id,
        authorize_public_key_digest: &binding.public_key_digest,
        authorize_signing_key_binding_digest: &binding_digest,
        expected_authority_id: &snapshot.state.authority_id,
        expected_authority_verification_method: &outer_attestation.verification_method,
        expected_account_authority_id: &gate.authority_id,
        expected_account_authority_verification_method: &gate.verification_method,
        controller_public_key: &controller_material,
        authority_public_key: &authority_material,
        account_authority_public_key: &account_authority_material,
        verified_state: &verified_state,
        require_transparency: false,
        transparency_verified: false,
        now: observed_at,
    };
    let context = arkret_signatures::agent_evidence::CurrentAgentSignerEvidenceValidationContext {
        common,
        operation_id,
        request_digest,
        verifier_id,
        audience,
        challenge,
    };
    match arkret_signatures::agent_evidence::validate_current_agent_signer_evidence(
        Some(evidence),
        &context,
    ) {
        arkret_signatures::agent_evidence::AgentSignerEvidenceVerdict::Verified(key) => {
            Ok(*key.key())
        }
        arkret_signatures::agent_evidence::AgentSignerEvidenceVerdict::Unresolved(_)
        | arkret_signatures::agent_evidence::AgentSignerEvidenceVerdict::Rejected(_) => {
            Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)
        }
    }
}

fn seal_signature_methods(seal: &Seal) -> Vec<&arkret_wire::DidUrl> {
    match &seal.notary_signature {
        NotarySig::Single(signature) => vec![&signature.verification_method],
        NotarySig::Multi(multi) => multi
            .signatures
            .iter()
            .map(|signature| &signature.verification_method)
            .collect(),
    }
}

fn verify_seal_with_keys(
    seal: &Seal,
    keys: &std::collections::BTreeMap<String, ed25519_dalek::VerifyingKey>,
) -> Result<(), arkret_signatures::agent_evidence::AgentEvidenceRejectedReason> {
    use arkret_signatures::agent_evidence::AgentEvidenceRejectedReason;
    let bytes = seal
        .canonical_bytes_for_id()
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let digest = Hash::new(arkret_canonical::sha256_digest(&bytes))
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let verify = |signature: &arkret_wire::SealSignature| {
        let key = keys
            .get(signature.verification_method.as_str())
            .ok_or(AgentEvidenceRejectedReason::SigningKeyMismatch)?;
        if signature.payload_digest != digest {
            return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
        }
        arkret_signatures::Ed25519DetachedJwsVerifier::new()
            .verify_detached_jws(
                &signature.jws,
                &bytes,
                &PublicKeyMaterial::Ed25519Raw {
                    bytes: key.to_bytes().to_vec(),
                },
            )
            .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)
    };
    match &seal.notary_signature {
        NotarySig::Single(signature) => verify(signature),
        NotarySig::Multi(multi) if !multi.signatures.is_empty() => {
            multi.signatures.iter().try_for_each(verify)
        }
        NotarySig::Multi(_) => Err(AgentEvidenceRejectedReason::SigningKeyMismatch),
    }
}

fn validate_lifecycle_witness(
    witness: &AgentLifecycleWitness,
) -> Result<(), arkret_signatures::agent_evidence::AgentEvidenceRejectedReason> {
    use arkret_signatures::agent_evidence::AgentEvidenceRejectedReason;
    let actor = witness
        .accepted_status_event
        .actor_id
        .as_account_id()
        .ok_or(AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let canonical_actor = witness
        .accepted_status_event
        .actor_id
        .canonical_key()
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let lifecycle_subject = arkret_wire::composite_subject(&[canonical_actor.as_str()])
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let lifecycle_cell_ref = format!("ak:cell:{AGENT_STATUS_COMPONENT}:{lifecycle_subject}");
    if witness
        .accepted_status_event
        .actor_id
        .signing_principal_id()
        != &witness.agent_id
        || actor.principal_id != witness.agent_id
        || witness.cell_ref.as_str() != lifecycle_cell_ref
        || witness.accepted_status_event.realm_id != witness.seal.realm_id
        || witness.status != AgentLifecycleStatus::Active
    {
        return Err(AgentEvidenceRejectedReason::AuthorizationInactive);
    }
    match &witness.provenance {
        AgentLifecycleProvenance::DelegatedPcrGenesis {
            realm_create_event_id,
            ..
        } if witness.accepted_status_event.kind == arkret_wire::EventKind::RealmCreate
            && witness.accepted_status_event.event_id == *realm_create_event_id =>
        {
            Ok(())
        }
        AgentLifecycleProvenance::ResumeAccepted {
            resume_event_id, ..
        } if witness.accepted_status_event.kind == arkret_wire::EventKind::SelfAgentResume
            && witness.accepted_status_event.event_id == *resume_event_id =>
        {
            Ok(())
        }
        _ => Err(AgentEvidenceRejectedReason::SigningKeyMismatch),
    }
}
