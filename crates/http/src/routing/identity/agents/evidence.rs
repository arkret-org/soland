//! Agent signer evidence is a closed current/historical protocol.
//!
//! Current statements are reusable within their independent validity windows.
//! Historical evidence retains the origin-frozen statements and exact durable
//! acceptance, with all signer dependencies addressed by content.

use std::time::Duration;

use arkret_models_collaboration::governance_dependencies::{
    GovernanceDependency, GovernanceDependencySelector,
};
use arkret_models_identity::AuthenticatedSignerResolutionEvidence;
use arkret_models_identity::agent_signer_evidence::{
    AGENT_KEY_COMPONENT, AGENT_STATUS_COMPONENT, AgentAdmissionEvidence, AgentAuthorityState,
    AgentAuthorityStateEvidence, AgentAuthorityStateLease, AgentAuthorizationEvidence,
    AgentAuthorizationStateWitness, AgentAuthorizationStatus, AgentDetachedJws, AgentKeyCellEntry,
    AgentLifecycleProvenance, AgentLifecycleStatus, AgentLifecycleWitness, AgentSignerEvidence,
    AgentSignerEvidenceQueryFailure, AgentSignerEvidenceQueryFailureReason,
    AgentSignerEvidenceQueryOutcome, AgentSignerEvidenceQueryRequestBody,
    AgentSignerEvidenceQuerySelector, ControllerAccountGateAttestation,
    ControllerAccountGateAttestationIssueOutcome, ControllerAccountGateAttestationIssueRequestBody,
    CurrentAgentSignerEvidence,
};
use arkret_signatures::proof::PublicKeyMaterial;
use arkret_wire::{
    CellRef, DidCoreId, Event, EventId, Hash, NonEmptyString, RealmId, RequestId, SchemaId, Seal,
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
    let requester =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let requester_is_member =
        crate::routing::realm_has_member(state, body.realm_id.as_str(), &requester.to_string())
            .await;
    if state
        .realms()
        .realm_metadata(body.realm_id.as_str())
        .await
        .ok()
        .flatten()
        .is_none_or(|realm| realm.minimal_metadata_realm)
    {
        return Err(AppError::not_found("Agent signer evidence is unavailable"));
    }
    let request = body.clone();
    let mut evidence = Vec::with_capacity(body.queries.len());
    let mut failures = Vec::with_capacity(body.queries.len());
    for selector in body.queries {
        let visible = match &selector {
            AgentSignerEvidenceQuerySelector::CurrentAdmission { agent_id, .. } => {
                let signer = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    agent_id.clone(),
                    state.service_core_id(),
                ));
                requester_is_member
                    && crate::routing::realm_has_member(
                        state,
                        request.realm_id.as_str(),
                        &signer.to_string(),
                    )
                    .await
            }
            AgentSignerEvidenceQuerySelector::HistoricalEvent { event_id, .. } => {
                match state
                    .event_queries()
                    .canonical_event(event_id.as_str())
                    .await
                    .ok()
                    .flatten()
                {
                    Some(record)
                        if record.realm_id.as_deref() == Some(request.realm_id.as_str()) =>
                    {
                        crate::routing::events::event_log::event_visible_to_session(
                            state, &record, &session,
                        )
                        .await
                    }
                    _ => false,
                }
            }
        };
        if !visible {
            failures.push(AgentSignerEvidenceQueryFailure {
                selector,
                reason: AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing,
            });
            continue;
        }

        match current_authenticated_agent_signer_evidence(state, &selector).await {
            Ok((root, _dependencies)) => {
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
    let (root, _) = current_authenticated_agent_signer_evidence(state, selector).await?;
    let AuthenticatedSignerResolutionEvidence::Agent {
        agent_signer_evidence,
        ..
    } = root
    else {
        unreachable!()
    };
    match *agent_signer_evidence {
        AgentSignerEvidence::CurrentAdmission {
            schema,
            admission_evidence,
            transparency,
        } => Ok(CurrentAgentSignerEvidence {
            schema,
            admission_evidence,
            transparency,
        }),
        AgentSignerEvidence::HistoricalEvent { .. } => {
            Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)
        }
    }
}

async fn assemble_current_agent_signer_evidence(
    state: &AppState,
    selector: &AgentSignerEvidenceQuerySelector,
) -> Result<CurrentAgentSignerEvidence, AgentSignerEvidenceQueryFailureReason> {
    let gate = preflight_controller_gate(state, selector)
        .await
        .map_err(|reason| {
            tracing::warn!(
                ?reason,
                "Agent current evidence controller gate unavailable"
            );
            reason
        })?;
    produce_current_agent_signer_evidence(state, selector, gate)
        .await
        .map_err(|reason| {
            tracing::warn!(?reason, "Agent current evidence state assembly failed");
            reason
        })
}

pub(crate) async fn freeze_current_agent_signer_evidence(
    state: &AppState,
    selector: &AgentSignerEvidenceQuerySelector,
) -> Result<(arkret_wire::SignerEvidenceRef, Hash), AppError> {
    let (root, _dependencies) = current_authenticated_agent_signer_evidence(state, selector)
        .await
        .map_err(|reason| AppError::internal(format!("{reason:?}")))?;
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
    let current = assemble_current_agent_signer_evidence(state, selector)
        .await
        .map_err(|reason| {
            tracing::warn!(?reason, "Agent current signed state assembly failed");
            reason
        })?;
    let agent_signer_evidence = AgentSignerEvidence::from(current);
    let AgentSignerEvidence::CurrentAdmission {
        admission_evidence, ..
    } = &agent_signer_evidence
    else {
        unreachable!("current evidence producer returned a historical branch")
    };
    let gate = &admission_evidence.controller_account_gate_attestation;
    let local_service_evidence =
        current_service_signer_evidence(state)
            .await
            .map_err(|reason| {
                tracing::warn!(
                    ?reason,
                    "Agent current evidence local Service closure failed"
                );
                reason
            })?;
    let account_authority_evidence = fetch_service_signer_evidence(
        state,
        &gate.authority_id,
        None,
        Some(&gate.verification_method),
        gate.issued_at,
    )
    .await
    .map_err(|reason| {
        tracing::warn!(
            ?reason,
            "Agent current evidence Account Authority closure failed"
        );
        reason
    })?;
    let root = arkret::build_agent_signer_resolution_evidence(
        agent_signer_evidence,
        &local_service_evidence,
        &account_authority_evidence,
        None,
    )
    .map_err(|error| {
        tracing::warn!(%error, "Agent current evidence root binding failed");
        AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing
    })?;
    let mut dependencies = Vec::new();
    let mut digests = std::collections::BTreeSet::new();
    for evidence in [
        local_service_evidence,
        account_authority_evidence,
    ] {
        let digest = evidence
            .canonical_sha256_digest()
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
        if digests.insert(digest) {
            dependencies.push(evidence);
        }
    }
    let dependencies = complete_agent_signer_evidence_dependencies(state, &root, dependencies)
        .await
        .map_err(|reason| {
            tracing::warn!(
                ?reason,
                "Agent current signer dependency closure is incomplete"
            );
            reason
        })?;
    let context_key = (root.signer_id().clone(), root.verification_method().clone());
    let previous = state
        .agent_evidence_cache
        .verified_contexts
        .lock()
        .get(&context_key)
        .cloned();
    let proof_dependencies = dependencies
        .iter()
        .map(|dependency| {
            Ok(
                GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                    selector: GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                        content_digest: dependency.canonical_sha256_digest()?,
                    },
                    authenticated_signer_resolution_evidence: Box::new(dependency.clone()),
                },
            )
        })
        .collect::<Result<Vec<_>, arkret_wire::WireError>>()
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let trust_root = std::sync::Arc::new(root.clone());
    let trust_dependencies = std::sync::Arc::new(proof_dependencies.clone());
    let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        root.signer_id().clone(),
        state.service_core_id(),
    ));
    let verified = arkret::verify_agent_current_context(
        &actor,
        root.verification_method(),
        &root,
        &proof_dependencies,
        chrono::Utc::now(),
        previous.as_ref(),
        move |request| {
            let root = trust_root.clone();
            let dependencies = trust_dependencies.clone();
            Box::pin(
                async move { arkret::verify_agent_portable_trust(request, &root, &dependencies) },
            )
        },
    )
    .await
    .map_err(|error| {
        tracing::warn!(%error, "Agent authority portable verification failed");
        AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing
    })?;
    persist_agent_signer_evidence_closure(state, &root, &dependencies)
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    {
        let mut contexts = state.agent_evidence_cache.verified_contexts.lock();
        if contexts.len() >= 4096 {
            contexts.pop_first();
        }
        contexts.insert(context_key, verified);

    }
    Ok((root, dependencies))
}

pub(crate) async fn historical_authenticated_agent_signer_evidence(
    state: &AppState,
    key: soland_storage::HistoricalAgentSignerEvidenceKey,
) -> Result<
    (
        AuthenticatedSignerResolutionEvidence,
        Vec<AuthenticatedSignerResolutionEvidence>,
    ),
    AgentSignerEvidenceQueryFailureReason,
> {
    if key.receiver_id == state.service_core_id() {
        let event = accepted_event(state, &key.event_id).await?;
        let admission =
            arkret_models_identity::agent_signer_evidence::AgentEventAdmission::StationAdmission {
                accepted_event: event,
            };
        let admission = if admission.receiver_id().ok().as_ref() == Some(&key.receiver_id) {
            admission
        } else {
            let record = state
                .persistence()
                .idempotency_record(
                    &key.receiver_id,
                    &format!(
                        "agent-event-admission-receipt:{}:{}",
                        key.event_id, key.receiver_id
                    ),
                )
                .await
                .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?
                .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
            let receipt = serde_json::from_value(record.response_body)
                .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
            arkret_models_identity::agent_signer_evidence::AgentEventAdmission::ReceiverReceipt {
                receipt,
            }
        };
        materialize_historical_agent_signer_evidence(state, admission, "")
            .await
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    }
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
        event_admission, ..
    } = agent_signer_evidence.as_ref()
    else {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    };
    if signer_id != &key.agent_id
        || verification_method != &key.verification_method
        || event_admission.event_id() != &key.event_id
        || event_admission.receiver_id().ok().as_ref() != Some(&key.receiver_id)
    {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    }
    root.validate_attester_binding()
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;

    let dependencies =
        complete_agent_signer_evidence_dependencies(state, &root, Vec::new()).await?;
    Ok((*root, dependencies))
}

async fn complete_agent_signer_evidence_dependencies(
    state: &AppState,
    root: &AuthenticatedSignerResolutionEvidence,
    initial: Vec<AuthenticatedSignerResolutionEvidence>,
) -> Result<Vec<AuthenticatedSignerResolutionEvidence>, AgentSignerEvidenceQueryFailureReason> {
    use arkret_models_collaboration::governance_dependencies::governance_attester_evidence_selectors;
    let missing = AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing;
    let store = state.persistence().governance_dependency_store();
    let AuthenticatedSignerResolutionEvidence::Agent {
        agent_signer_evidence,
        ..
    } = root
    else {
        return Err(missing);
    };
    let (AgentSignerEvidence::CurrentAdmission {
        admission_evidence, ..
    }
    | AgentSignerEvidence::HistoricalEvent {
        admission_evidence, ..
    }) = agent_signer_evidence.as_ref();
    let proof_realm = &admission_evidence
        .agent_authority_state_evidence
        .state
        .principal_control_realm_id;
    let mut by_digest = std::collections::BTreeMap::new();
    for evidence in initial {
        by_digest.insert(
            evidence.canonical_sha256_digest().map_err(|_| missing)?,
            evidence,
        );
    }
    let mut pending =
        governance_attester_evidence_selectors(std::slice::from_ref(root)).map_err(|_| missing)?;
    let mut resolved = std::collections::BTreeSet::new();
    while let Some(selector) = pending.pop() {
        let GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence { content_digest } =
            &selector
        else {
            return Err(missing);
        };
        if !resolved.insert(content_digest.clone()) {
            continue;
        }
        if resolved.len() > 64 {
            return Err(missing);
        }
        if !by_digest.contains_key(content_digest) {
            let dependency = store
                .get_unscoped_signer_evidence(&selector)
                .await
                .map_err(|_| missing)?;
            let dependency = match dependency {
                Some(dependency) => dependency,
                None => {
                    let dependency = store
                        .get(proof_realm, &selector)
                        .await
                        .map_err(|_| missing)?
                        .ok_or(missing)?;
                    store
                        .put_unscoped_signer_evidence_exact(dependency.clone())
                        .await
                        .map_err(|_| missing)?;
                    dependency
                }
            };
            let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                selector: stored_selector,
                authenticated_signer_resolution_evidence,
            } = dependency
            else {
                return Err(missing);
            };
            if stored_selector != selector
                || authenticated_signer_resolution_evidence
                    .canonical_sha256_digest()
                    .map_err(|_| missing)?
                    != *content_digest
            {
                return Err(missing);
            }
            by_digest.insert(
                content_digest.clone(),
                *authenticated_signer_resolution_evidence,
            );
        }
        let evidence = by_digest.get(content_digest).ok_or(missing)?;
        evidence.validate_attester_binding().map_err(|_| missing)?;
        pending.extend(
            governance_attester_evidence_selectors(std::slice::from_ref(evidence))
                .map_err(|_| missing)?,
        );
    }
    Ok(by_digest.into_values().collect())
}

async fn current_service_signer_evidence(
    state: &AppState,
) -> Result<AuthenticatedSignerResolutionEvidence, AgentSignerEvidenceQueryFailureReason> {
    let resolution =
        crate::routing::system::service_resolution::current_authenticated_service_resolution(state)
            .await
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let service_id = resolution.service_id.clone();
    let (_, method) = state
        .current_service_receipt_binding()
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    arkret_identity::service_signer_evidence_for_method_from_authenticated_resolution(
        resolution,
        &service_id,
        method,
        chrono::Utc::now(),
    )
    .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)
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
        let path = arkret_models_identity::canonical_service_resolution_path(service_id);
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
        None => {
            let document =
                arkret_identity::authenticated_service_document_at(&resolution, service_id, at)
                    .map_err(|_| {
                        AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing
                    })?;
            let methods: Vec<_> = document
                .verification_methods
                .keys()
                .filter_map(|value| {
                    let method = arkret_wire::DidUrl::new(value.clone()).ok()?;
                    arkret_identity::validate_verification_method_relationship(
                        &document,
                        &method,
                        &document.id,
                        arkret_identity::DidVerificationRelationship::AssertionMethod,
                    )
                    .ok()?;
                    Some(method)
                })
                .collect();
            if methods.len() != 1 {
                return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
            }
            arkret_identity::service_signer_evidence_for_method_from_authenticated_resolution(
                resolution,
                service_id,
                methods[0].clone(),
                at,
            )
        }
    }
    .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)
}

/// Classify the actual signing principal from the origin-frozen root, including
/// Agent execution on another actor's behalf.
pub(crate) async fn event_has_agent_signer(
    state: &AppState,
    event: &Event,
) -> Result<bool, String> {
    let admission = event
        .proofs
        .iter()
        .find_map(arkret_wire::EventProof::as_station_admission)
        .ok_or_else(|| "accepted Event omitted its Station admission".to_owned())?;
    let Some(reference) = &admission.producer_signer_resolution_evidence_ref else {
        return Ok(false);
    };
    let selector = GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
        content_digest: reference
            .content_digest()
            .map_err(|error| error.to_string())?,
    };
    let origin =
        arkret_models_identity::agent_signer_evidence::AgentEventAdmission::StationAdmission {
            accepted_event: event.clone(),
        }
        .receiver_id()
        .map_err(|error| error.to_string())?;
    let dependency = retain_origin_signer_dependency(state, event, &origin, &selector).await?;
    let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
        authenticated_signer_resolution_evidence: root,
        ..
    } = dependency
    else {
        return Err("origin signer dependency has wrong kind".to_owned());
    };
    if root.evidence_ref().map_err(|error| error.to_string())? != *reference
        || root.verification_method() != &admission.producer_verification_method
        || root.signer_id()
            != event
                .executed_by
                .as_ref()
                .unwrap_or(&event.actor_id)
                .signing_principal_id()
    {
        return Err("origin-frozen signer identity mismatch".to_owned());
    }
    if !matches!(*root, AuthenticatedSignerResolutionEvidence::Agent { .. }) {
        return Ok(false);
    }
    let mut pending = arkret_models_collaboration::governance_dependencies::governance_attester_evidence_selectors(
        std::slice::from_ref(root.as_ref()),
    ).map_err(|error| error.to_string())?;
    pending.push(
        GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
            content_digest: admission
                .signer_resolution_evidence_ref
                .content_digest()
                .map_err(|error| error.to_string())?,
        },
    );
    let mut seen = std::collections::BTreeSet::new();
    while let Some(selector) = pending.pop() {
        let GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence { content_digest } =
            &selector
        else {
            return Err("Agent signer dependency has wrong selector kind".to_owned());
        };
        if !seen.insert(content_digest.clone()) {
            continue;
        }
        if seen.len() > 64 {
            return Err("Agent signer dependency closure exceeds its limit".to_owned());
        }
        let dependency = retain_origin_signer_dependency(state, event, &origin, &selector).await?;
        let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
            authenticated_signer_resolution_evidence: leaf,
            ..
        } = dependency
        else {
            return Err("Agent signer dependency has wrong kind".to_owned());
        };
        pending.extend(arkret_models_collaboration::governance_dependencies::governance_attester_evidence_selectors(
            std::slice::from_ref(leaf.as_ref()),
        ).map_err(|error| error.to_string())?);
    }
    Ok(true)
}

async fn retain_origin_signer_dependency(
    state: &AppState,
    event: &Event,
    origin: &DidCoreId,
    selector: &GovernanceDependencySelector,
) -> Result<GovernanceDependency, String> {
    let store = state.persistence().governance_dependency_store();
    if let Some(item) = store
        .get_unscoped_signer_evidence(selector)
        .await
        .map_err(|error| error.to_string())?
    {
        return Ok(item);
    }
    let item = if let Some(item) = store
        .get(&event.realm_id, selector)
        .await
        .map_err(|error| error.to_string())?
    {
        item
    } else {
        if origin == &state.service_core_id() {
            return Err("origin-frozen signer evidence is missing".to_owned());
        }
        let request = arkret_models_collaboration::governance_dependencies::PeerGovernanceDependencyResolveRequest {
            realm_id: event.realm_id.clone(), selectors: vec![selector.clone()], byte_limit: 8 * 1024 * 1024, history_traversal_access: None,
        };
        let outcome =
            crate::routing::federation::rhrk_acquisition::fetch_peer_governance_dependencies(
                state, origin, &request,
            )
            .await
            .map_err(|error| error.to_string())?;
        outcome
            .validate_for_peer_request(&request)
            .map_err(|error| error.to_string())?;
        let [item] = outcome.items.as_slice() else {
            return Err("origin-frozen signer evidence is missing".to_owned());
        };
        item.clone()
    };
    let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
        selector: actual_selector,
        authenticated_signer_resolution_evidence: evidence,
    } = &item
    else {
        return Err("origin signer dependency has wrong kind".to_owned());
    };
    let expected = GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
        content_digest: evidence
            .canonical_sha256_digest()
            .map_err(|error| error.to_string())?,
    };
    if actual_selector != selector || expected != *selector {
        return Err("origin signer dependency digest mismatch".to_owned());
    }
    store
        .put_unscoped_signer_evidence_exact(item.clone())
        .await
        .map_err(|error| error.to_string())?;
    Ok(item)
}

pub(crate) async fn materialize_historical_agent_signer_evidence(
    state: &AppState,
    event_admission: arkret_models_identity::agent_signer_evidence::AgentEventAdmission,
    receiver_base_url: &str,
) -> Result<(), AppError> {
    let invalid = |error: arkret_wire::WireError| AppError::internal(error.to_string());
    let agent_id = event_admission.agent_id().clone();
    let expected_method = event_admission
        .verification_method()
        .map_err(invalid)?
        .clone();
    let event_id = event_admission.event_id().clone();
    let receiver_id = event_admission.receiver_id().map_err(invalid)?;
    let accepted_at = event_admission.receiver_accepted_at().map_err(invalid)?;
    let producer_ref = event_admission
        .producer_signer_resolution_evidence_ref()
        .map_err(invalid)?
        .clone();
    let accepted = accepted_event(state, &event_id)
        .await
        .map_err(|_| AppError::internal("historical Agent Event is missing"))?;
    let origin =
        arkret_models_identity::agent_signer_evidence::AgentEventAdmission::StationAdmission {
            accepted_event: accepted,
        };
    if event_admission.realm_id() != origin.realm_id()
        || event_admission.agent_id() != origin.agent_id()
        || event_admission.verification_method().map_err(invalid)?
            != origin.verification_method().map_err(invalid)?
        || event_admission.producer_accepted_at().map_err(invalid)?
            != origin.producer_accepted_at().map_err(invalid)?
        || &producer_ref
            != origin
                .producer_signer_resolution_evidence_ref()
                .map_err(invalid)?
    {
        return Err(AppError::internal(
            "historical Agent acceptance differs from the stored Event",
        ));
    }
    match &event_admission {
        arkret_models_identity::agent_signer_evidence::AgentEventAdmission::StationAdmission {
            ..
        } if event_admission.station_admission().map_err(invalid)?
            != origin.station_admission().map_err(invalid)? =>
        {
            return Err(AppError::internal(
                "historical Agent acceptance differs from the original Station proof",
            ));
        }
        arkret_models_identity::agent_signer_evidence::AgentEventAdmission::ReceiverReceipt {
            ..
        } if receiver_id == origin.receiver_id().map_err(invalid)?
            && accepted_at == origin.receiver_accepted_at().map_err(invalid)? =>
        {
            return Err(AppError::internal(
                "same-Station acceptance must reuse its original admission",
            ));
        }
        _ => {}
    }
    let store = state.persistence().governance_dependency_store();
    if let Some(materialized) = store
        .get_historical_agent_signer_evidence(&soland_storage::HistoricalAgentSignerEvidenceKey {
            agent_id: agent_id.clone(),
            verification_method: expected_method.clone(),
            event_id: event_id.clone(),
            receiver_id: receiver_id.clone(),
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        return replayed_historical_agent_signer_evidence(materialized, &event_admission);
    }
    let original_selector = GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
        content_digest: producer_ref
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
        != producer_ref
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
    if signer_id != agent_id || verification_method != expected_method {
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
    let account_authority_evidence =
        dependency_by_ref(store, &account_authority_signer_evidence_ref).await?;
    let receipt_method =
        arkret_signatures::agent_evidence::historical_admission_verification_method(
            &event_admission,
        )
        .map_err(|reason| AppError::internal(reason.as_str()))?;
    let receiver_evidence = match &event_admission {
        arkret_models_identity::agent_signer_evidence::AgentEventAdmission::StationAdmission {
            ..
        } => {
            dependency_by_ref(
                store,
                &event_admission
                    .station_admission()
                    .map_err(invalid)?
                    .signer_resolution_evidence_ref,
            )
            .await?
        }
        arkret_models_identity::agent_signer_evidence::AgentEventAdmission::ReceiverReceipt {
            ..
        } => fetch_service_signer_evidence(
            state,
            &receiver_id,
            (!receiver_base_url.is_empty()).then_some(receiver_base_url),
            Some(&receipt_method),
            accepted_at,
        )
        .await
        .map_err(|reason| AppError::internal(format!("{reason:?}")))?,
    };
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
        &receiver_id,
        accepted_at,
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    let receiver_key = arkret_identity::jws::resolve_ed25519_pubkey_from_document(
        &historical_document,
        receipt_method.as_str(),
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    let receiver_material = PublicKeyMaterial::Ed25519Raw {
        bytes: receiver_key.to_bytes().to_vec(),
    };
    match &event_admission {
        arkret_models_identity::agent_signer_evidence::AgentEventAdmission::ReceiverReceipt {
            receipt,
        } => {
            arkret_signatures::agent_evidence::verify_agent_event_admission_receipt(
                receipt,
                &receiver_material,
            )
            .map_err(|reason| AppError::internal(reason.as_str()))?;
        }
        arkret_models_identity::agent_signer_evidence::AgentEventAdmission::StationAdmission {
            accepted_event,
        } => {
            let suite = accepted_event
                .event_id
                .event_digest()
                .digest_suite()
                .map_err(|error| AppError::internal(error.to_string()))?;
            accepted_event
                .validate_station_admission_binding(suite)
                .map_err(invalid)?;
            let proof = event_admission.station_admission().map_err(invalid)?;
            arkret_signatures::Ed25519DetachedJwsVerifier::new()
                .verify_detached_jws(
                    &proof.jws,
                    &proof.canonical_binding_bytes().map_err(invalid)?,
                    &receiver_material,
                )
                .map_err(|error| AppError::internal(error.to_string()))?;
        }
    }
    let historical = AgentSignerEvidence::HistoricalEvent {
        schema,
        admission_evidence,
        event_admission,
        transparency,
    };
    let historical_root = arkret::build_agent_signer_resolution_evidence(
        historical,
        &authority_evidence,
        &account_authority_evidence,
        Some(&receiver_evidence),
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    persist_agent_signer_evidence_closure(
        state,
        &historical_root,
        &[
            authority_evidence,
                account_authority_evidence,
            receiver_evidence,
        ],
    )
    .await
}

/// Replaying one durable acceptance preserves the exact historical root.
fn replayed_historical_agent_signer_evidence(
    materialized: GovernanceDependency,
    expected_admission: &arkret_models_identity::agent_signer_evidence::AgentEventAdmission,
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
        event_admission, ..
    } = *agent_signer_evidence
    else {
        return Err(AppError::internal(
            "materialized historical Agent signer evidence has the wrong kind",
        ));
    };
    let same_acceptance = match (&event_admission, expected_admission) {
        (
            arkret_models_identity::agent_signer_evidence::AgentEventAdmission::StationAdmission {
                accepted_event: stored,
            },
            arkret_models_identity::agent_signer_evidence::AgentEventAdmission::StationAdmission {
                accepted_event: expected,
            },
        ) => {
            let suite = stored
                .event_id
                .event_digest()
                .digest_suite()
                .map_err(|error| AppError::internal(error.to_string()))?;
            expected
                .validate_station_admission_binding(suite)
                .map_err(|error| AppError::internal(error.to_string()))?;
            stored.event_digest_with_digest_suite(suite).ok()
                == expected.event_digest_with_digest_suite(suite).ok()
                && event_admission.station_admission().ok()
                    == expected_admission.station_admission().ok()
        }
        _ => event_admission == *expected_admission,
    };
    if !same_acceptance {
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
    if state.account_lifecycle_state(principal_id.as_str()) != "active" {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentAuthorizationInactive);
    }
    let destination_id = crate::routing::events::peer::trusted_account_authority_id(state)
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let source_id = DidCoreId::new(state.service_id().clone())
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let slot = state.agent_evidence_cache.gate_slot(
        (
            source_id.clone(),
            destination_id.clone(),
            principal_id.clone(),
        ),
        chrono::Utc::now(),
    );
    let mut cached_gate = slot.lock().await;
    if let Some(gate) = cached_gate.as_ref()
        && gate.issued_at <= chrono::Utc::now()
        && chrono::Utc::now() < gate.expires_at
    {
        return Ok(gate.clone());
    }
    *cached_gate = None;
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
        tracing::warn!(status = %response.status(), "Agent evidence controller gate request failed");
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
    *cached_gate = Some(gate.clone());
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
    let pcr_genesis_event = accepted_event(state, &realm_id.event_id()).await?;
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

    let frontier =
        crate::routing::identity::agent_pcr::agent_event_seal_head(state, realm_id.as_str())
            .await
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?
            .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let lifecycle_seal = frontier.clone();
    let lifecycle_cell_ref = lifecycle_cell_ref(&agent_actor)?;
    let (lifecycle_value, lifecycle_heads, lifecycle_proof) =
        witnessed_cell(state, &realm_id, &lifecycle_seal, &lifecycle_cell_ref).await?;
    let lifecycle_value: AgentLifecycleStatus = serde_json::from_value(lifecycle_value)
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    if lifecycle_value != AgentLifecycleStatus::Active {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentAuthorizationInactive);
    }
    let lifecycle =
        accepted_current_lifecycle(state, &agent_actor, &realm_id, &lifecycle_heads).await?;

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
    let core = AgentAuthorityState {
        authority_id: service_id.clone(),
        principal_control_realm_id: realm_id,
        frontier_seal_id: frontier.id.clone(),
        frontier_state_root: frontier.state_root.clone(),
        pcr_genesis_event,
        key_authorization_event: authorize_event,
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
    let mut expires_at = now + chrono::Duration::seconds(300);
    if let Some(binding_expiry) = core.signing_key_binding.expires_at {
        expires_at = expires_at.min(binding_expiry);
    }
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
    {
        let mut leases = state.agent_evidence_cache.state_leases.lock();
        leases.retain(|_, lease| lease.expires_at > now);
        let key = (state_digest.clone(), authority_method.clone());
        if let Some(lease) = leases.get(&key)
            && lease.issued_at <= now
            && now < lease.expires_at
            && lease.expires_at <= expires_at
        {
            authority_state_evidence.lease = lease.clone();
        } else {
            arkret_signatures::agent_evidence::sign_agent_authority_state_lease(
                &mut authority_state_evidence.lease,
                state.notary_signing_key().as_ref(),
            )
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
            if leases.len() >= 4096 {
                leases.pop_first();
            }
            leases.insert(key, authority_state_evidence.lease.clone());
        }
    }
    let admission_evidence_digest =
        arkret_signatures::agent_evidence::agent_admission_evidence_digest(
            &authority_state_evidence,
            &gate,
        )
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let admission_evidence = AgentAdmissionEvidence {
        agent_authority_state_evidence: authority_state_evidence,
        controller_account_gate_attestation: gate,
        admission_evidence_digest,
    };
    let evidence = AgentSignerEvidence::CurrentAdmission {
        schema: non_empty(SchemaId::AGENT_SIGNER_EVIDENCE_V1)?,
        admission_evidence,
        transparency: None,
    };
    match evidence {
        AgentSignerEvidence::CurrentAdmission {
            schema,
            admission_evidence,
            transparency,
        } => Ok(CurrentAgentSignerEvidence {
            schema,
            admission_evidence,
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
    agent_actor: &arkret_wire::ActorId,
    realm_id: &RealmId,
    heads: &[arkret_state::lattice::cas_register::CasHead],
) -> Result<AcceptedLifecycle, AgentSignerEvidenceQueryFailureReason> {
    let missing = AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing;
    if heads.is_empty()
        || heads
            .iter()
            .any(|head| head.value != serde_json::json!("active"))
    {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentAuthorizationInactive);
    }
    // Every active head is authoritative. Choose a stable representative by
    // content identity, never by caller-controlled timestamps or arrival order.
    let event_id = heads
        .iter()
        .map(|head| EventId::from_event_digest(&head.move_id).map_err(|_| missing))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .min()
        .ok_or(missing)?;
    let event = accepted_event(state, &event_id).await?;
    if event.realm_id != *realm_id || event.actor_id != *agent_actor {
        return Err(missing);
    }
    let provenance = match event.kind {
        arkret_wire::EventKind::RealmCreate => AgentLifecycleProvenance::DelegatedPcrGenesis {
            realm_create_event_id: event.event_id.clone(),
        },
        arkret_wire::EventKind::SelfAgentResume => AgentLifecycleProvenance::ResumeAccepted {
            resume_event_id: event.event_id.clone(),
        },
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
