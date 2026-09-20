//! Agent signer evidence is a closed current/historical protocol.
//!
//! Current statements are reusable within their independent validity windows.
//! Historical evidence retains producer-frozen statements and applicable
//! authorization closures, with all signer dependencies addressed by content.

use std::time::Duration;

use arkret_models_collaboration::governance_dependencies::{
    GovernanceDependency, GovernanceDependencySelector,
};
use arkret_models_identity::AuthenticatedSignerResolutionEvidence;
use arkret_models_identity::agent_signer_evidence::{
    AGENT_KEY_COMPONENT, AGENT_STATUS_COMPONENT, AgentAdmissionEvidence, AgentAuthorityState,
    AgentAuthorityStateAttestation, AgentAuthorityStateEvidence, AgentAuthorizationEvidence,
    AgentAuthorizationStateWitness, AgentAuthorizationStatus, AgentDetachedJws, AgentKeyCellEntry,
    AgentLifecycleProvenance, AgentLifecycleStatus, AgentLifecycleWitness, AgentSignerEvidence,
    ControllerAccountGateAttestation, ControllerAccountGateIssuanceInput,
    ControllerAccountGateIssuanceResult, CurrentAgentSignerEvidence,
    StationSigningKey,
};
use arkret_signatures::proof::PublicKeyMaterial;
use arkret_wire::{
    CellRef, DidCoreId, Event, EventId, Hash, NonEmptyString, RealmId, RequestId, SchemaId, Seal,
};

use super::*;

#[derive(Clone, Debug)]
pub(crate) enum AgentSignerEvidenceQuerySelector {
    CurrentAdmission {
        actor: arkret_wire::ActorId,
        verification_method: arkret_wire::DidUrl,
    },
    HistoricalEvent {
        actor: arkret_wire::ActorId,
        verification_method: arkret_wire::DidUrl,
        event_id: arkret_wire::EventId,
    },
}

impl AgentSignerEvidenceQuerySelector {
    pub(crate) fn actor(&self) -> &arkret_wire::ActorId {
        match self {
            Self::CurrentAdmission { actor, .. } | Self::HistoricalEvent { actor, .. } => actor,
        }
    }

    pub(crate) fn verification_method(&self) -> &arkret_wire::DidUrl {
        match self {
            Self::CurrentAdmission {
                verification_method,
                ..
            }
            | Self::HistoricalEvent {
                verification_method,
                ..
            } => verification_method,
        }
    }
}

/// Internal acquisition diagnostics; self APIs expose only uniform unavailable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AgentEvidenceAcquisitionFailure {
    AgentSignerEvidenceMissing,
    AgentAuthorizationInactive,
}

async fn verify_retained_agent_trust(
    state: &AppState,
    request: arkret::AgentHistoricalTrustRequest<'_>,
    root: &AuthenticatedSignerResolutionEvidence,
    dependencies: &[GovernanceDependency],
) -> arkret_wire::Result<()> {
    match request {
        arkret::AgentHistoricalTrustRequest::AuthorizationClosure(seal_id) => {
            let seal = state
                .projections()
                .seal_by_id(seal_id)
                .await
                .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?
                .ok_or_else(|| {
                    arkret_wire::WireError::Protocol(
                        "Agent authorization closure Seal is unavailable".to_owned(),
                    )
                })?;
            let expected_realm = match root {
                AuthenticatedSignerResolutionEvidence::Agent {
                    agent_signer_evidence,
                    ..
                } => {
                    &agent_signer_evidence
                        .admission_evidence()
                        .agent_authority_state_evidence
                        .state
                        .principal_control_realm_id
                }
                _ => {
                    return Err(arkret_wire::WireError::Protocol(
                        "Agent authorization closure requires Agent evidence".to_owned(),
                    ));
                }
            };
            if &seal.realm_id != expected_realm {
                return Err(arkret_wire::WireError::Protocol(
                    "Agent authorization closure belongs to another Realm".to_owned(),
                ));
            }
            seal.validate_id(seal.state_root.digest_suite()?)?;
            Ok(())
        }
        request => arkret::verify_agent_portable_trust(request, root, dependencies),
    }
}

/// Verify portable roots on the Station before reducing them to a self result.
pub(crate) async fn verified_station_agent_key(
    state: &AppState,
    selector: &AgentSignerEvidenceQuerySelector,
    root: &AuthenticatedSignerResolutionEvidence,
    dependencies: &[AuthenticatedSignerResolutionEvidence],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<StationSigningKey, AppError> {
    let invalid = || AppError::not_found("Agent signer evidence unavailable");
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
        .map_err(|_| invalid())?;
    let trust_root = std::sync::Arc::new(root.clone());
    let trust_dependencies = std::sync::Arc::new(proof_dependencies.clone());
    let (bytes, authorization_ref) = match selector {
        AgentSignerEvidenceQuerySelector::CurrentAdmission {
            actor,
            verification_method,
        } => {
            let verified = arkret::verify_agent_current_context(
                actor,
                verification_method,
                root,
                &proof_dependencies,
                now,
                None,
                move |request| {
                    let root = trust_root.clone();
                    let dependencies = trust_dependencies.clone();
                    let state = state.clone();
                    Box::pin(async move {
                        verify_retained_agent_trust(&state, request, &root, &dependencies).await
                    })
                },
            )
            .await
            .map_err(|_| invalid())?;
            (
                *verified.key().key(),
                verified.key().authorization_ref().clone(),
            )
        }
        AgentSignerEvidenceQuerySelector::HistoricalEvent {
            actor,
            verification_method,
            event_id,
        } => {
            let event = accepted_event(state, event_id)
                .await
                .map_err(|_| invalid())?;
            if event.executed_by.as_ref().unwrap_or(&event.actor_id) != actor {
                return Err(invalid());
            }
            let AuthenticatedSignerResolutionEvidence::Agent {
                agent_signer_evidence,
                ..
            } = root
            else {
                return Err(invalid());
            };
            let AgentSignerEvidence::HistoricalEvent {
                admission_evidence, ..
            } = agent_signer_evidence.as_ref()
            else {
                return Err(invalid());
            };
            let Some(producer) = event.producer_proof.as_ref() else {
                return Err(invalid());
            };
            if &producer.verification_method != verification_method {
                return Err(invalid());
            }
            let material = arkret::verify_agent_historical_event_key(
                &event,
                root,
                &proof_dependencies,
                move |request| {
                    let root = trust_root.clone();
                    let dependencies = trust_dependencies.clone();
                    let state = state.clone();
                    Box::pin(async move {
                        verify_retained_agent_trust(&state, request, &root, &dependencies).await
                    })
                },
            )
            .await
            .map_err(|_| invalid())?;
            (
                material.ed25519_bytes().map_err(|_| invalid())?,
                admission_evidence
                    .agent_authority_state_evidence
                    .state
                    .key_authorization_event
                    .event_id
                    .clone(),
            )
        }
    };
    let key = StationSigningKey {
        actor: selector.actor().clone(),
        verification_method: selector.verification_method().clone(),
        public_key_b64u: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            bytes,
        ))
        .map_err(|_| invalid())?,
        authorization_ref,
    };
    key.validate().map_err(|_| invalid())?;
    Ok(key)
}

pub(crate) async fn current_agent_signer_evidence(
    state: &AppState,
    selector: &AgentSignerEvidenceQuerySelector,
) -> Result<CurrentAgentSignerEvidence, AgentEvidenceAcquisitionFailure> {
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
            Err(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)
        }
    }
}

async fn assemble_current_agent_signer_evidence(
    state: &AppState,
    selector: &AgentSignerEvidenceQuerySelector,
    frozen_agent: Option<&AgentPrincipalRecord>,
) -> Result<CurrentAgentSignerEvidence, AgentEvidenceAcquisitionFailure> {
    let gate = preflight_controller_gate(state, selector)
        .await
        .map_err(|reason| {
            tracing::warn!(
                ?reason,
                "Agent current evidence controller gate unavailable"
            );
            reason
        })?;
    produce_current_agent_signer_evidence(state, selector, gate, frozen_agent)
        .await
        .map_err(|reason| {
            tracing::warn!(?reason, "Agent current evidence state assembly failed");
            reason
        })
}

pub(crate) fn current_agent_evidence_delivery(
    actor: arkret_wire::ActorId,
    verification_method: arkret_wire::DidUrl,
    root: &AuthenticatedSignerResolutionEvidence,
    dependencies: Vec<AuthenticatedSignerResolutionEvidence>,
) -> Result<
    (
        arkret_wire::SignerEvidenceRef,
        arkret_models_collaboration::current_signer_evidence::CurrentSignerEvidence,
    ),
    AppError,
> {
    let reference =
        arkret::signer_evidence_ref(root).map_err(|error| AppError::internal(error.to_string()))?;
    let compact = arkret_models_collaboration::current_signer_evidence::CompactAgentSignerResolutionEvidence::from_full(root, &[])
        .map_err(|error| AppError::internal(error.to_string()))?;
    let delivery =
        arkret_models_collaboration::current_signer_evidence::CurrentSignerEvidence::Agent {
            actor,
            verification_method,
            authenticated_signer_evidence: compact,
            dependencies,
        };
    let (hydrated_root, _) = delivery
        .hydrate_complete_agent()
        .map_err(|error| AppError::internal(error.to_string()))?;
    if hydrated_root != *root
        || arkret::signer_evidence_ref(&hydrated_root)
            .map_err(|error| AppError::internal(error.to_string()))?
            != reference
    {
        return Err(AppError::internal(
            "Agent signer evidence delivery does not reproduce its frozen root",
        ));
    }
    Ok((reference, delivery))
}

pub(crate) async fn current_authenticated_agent_signer_evidence(
    state: &AppState,
    selector: &AgentSignerEvidenceQuerySelector,
) -> Result<
    (
        AuthenticatedSignerResolutionEvidence,
        Vec<AuthenticatedSignerResolutionEvidence>,
    ),
    AgentEvidenceAcquisitionFailure,
> {
    current_authenticated_agent_signer_evidence_for_record(state, selector, None).await
}

pub(crate) async fn current_authenticated_agent_signer_evidence_for_record(
    state: &AppState,
    selector: &AgentSignerEvidenceQuerySelector,
    frozen_agent: Option<&AgentPrincipalRecord>,
) -> Result<
    (
        AuthenticatedSignerResolutionEvidence,
        Vec<AuthenticatedSignerResolutionEvidence>,
    ),
    AgentEvidenceAcquisitionFailure,
> {
    if let AgentSignerEvidenceQuerySelector::HistoricalEvent {
        actor,
        verification_method,
        event_id,
    } = selector
    {
        return historical_authenticated_agent_signer_evidence(
            state,
            actor,
            verification_method,
            event_id,
        )
        .await;
    }
    let current = assemble_current_agent_signer_evidence(state, selector, frozen_agent)
        .await
        .map_err(|reason| {
            tracing::warn!(?reason, "Agent current signed state assembly failed");
            reason
        })?;
    let activation_evidence =
        frozen_agent
            .is_some()
            .then(|| AgentSignerEvidence::HistoricalEvent {
                schema: current.schema.clone(),
                admission_evidence: current.admission_evidence.clone(),
                authorization_closure_refs: Vec::new(),
                transparency: current.transparency.clone(),
            });
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
    let current_root = arkret::build_agent_signer_evidence(
        agent_signer_evidence,
        &local_service_evidence,
        &account_authority_evidence,
    )
    .map_err(|error| {
        tracing::warn!(%error, "Agent current evidence root binding failed");
        AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing
    })?;
    let activation_root = activation_evidence
        .map(|evidence| {
            arkret::build_agent_signer_evidence(
                evidence,
                &local_service_evidence,
                &account_authority_evidence,
            )
        })
        .transpose()
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    let mut dependencies = Vec::new();
    let mut digests = std::collections::BTreeSet::new();
    for evidence in [local_service_evidence, account_authority_evidence] {
        let digest = evidence
            .canonical_sha256_digest()
            .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
        if digests.insert(digest) {
            dependencies.push(evidence);
        }
    }
    let dependencies =
        complete_agent_signer_evidence_dependencies(state, &current_root, dependencies)
            .await
            .map_err(|reason| {
                tracing::warn!(
                    ?reason,
                    "Agent current signer dependency closure is incomplete"
                );
                reason
            })?;
    let context_key = (
        current_root.signer_id().clone(),
        current_root.verification_method().clone(),
    );
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
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    let trust_root = std::sync::Arc::new(current_root.clone());
    let trust_dependencies = std::sync::Arc::new(proof_dependencies.clone());
    let actor = selector.actor().clone();
    let verified = arkret::verify_agent_current_context(
        &actor,
        current_root.verification_method(),
        &current_root,
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
        AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing
    })?;
    let root = activation_root.unwrap_or(current_root);
    persist_agent_signer_evidence_closure(state, &root, &dependencies)
        .await
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
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
    actor: &arkret_wire::ActorId,
    verification_method: &arkret_wire::DidUrl,
    event_id: &arkret_wire::EventId,
) -> Result<
    (
        AuthenticatedSignerResolutionEvidence,
        Vec<AuthenticatedSignerResolutionEvidence>,
    ),
    AgentEvidenceAcquisitionFailure,
> {
    let event = accepted_event(state, event_id).await?;
    if event.executed_by.as_ref().unwrap_or(&event.actor_id) != actor {
        return Err(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing);
    }
    let Some(producer) = event.producer_proof.as_ref() else {
        return Err(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing);
    };
    if &producer.verification_method != verification_method {
        return Err(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing);
    }
    let selector = GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
        content_digest: producer
            .signer_resolution_evidence_ref
            .as_ref()
            .ok_or(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?
            .content_digest()
            .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?,
    };
    let store = state.persistence().governance_dependency_store();
    let item = store
        .get_unscoped_signer_evidence(&selector)
        .await
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?
        .ok_or(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
        authenticated_signer_resolution_evidence: root,
        ..
    } = item
    else {
        return Err(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing);
    };
    let AuthenticatedSignerResolutionEvidence::Agent {
        signer_id,
        verification_method,
        agent_signer_evidence,
        ..
    } = root.as_ref()
    else {
        return Err(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing);
    };
    let AgentSignerEvidence::HistoricalEvent { .. } = agent_signer_evidence.as_ref() else {
        return Err(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing);
    };
    if signer_id != actor.signing_principal_id()
        || root.verification_method() != verification_method
        || root
            .evidence_ref()
            .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?
            != *producer
                .signer_resolution_evidence_ref
                .as_ref()
                .ok_or(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?
    {
        return Err(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing);
    }
    root.validate_attester_binding()
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;

    let dependencies =
        complete_agent_signer_evidence_dependencies(state, &root, Vec::new()).await?;
    Ok((*root, dependencies))
}

async fn complete_agent_signer_evidence_dependencies(
    state: &AppState,
    root: &AuthenticatedSignerResolutionEvidence,
    initial: Vec<AuthenticatedSignerResolutionEvidence>,
) -> Result<Vec<AuthenticatedSignerResolutionEvidence>, AgentEvidenceAcquisitionFailure> {
    use arkret_models_collaboration::governance_dependencies::governance_attester_evidence_selectors;
    let missing = AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing;
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

pub(crate) async fn verified_historical_agent_event_key(
    state: &AppState,
    event: &Event,
    root: &AuthenticatedSignerResolutionEvidence,
) -> Result<[u8; 32], String> {
    if !matches!(
        root,
        AuthenticatedSignerResolutionEvidence::Agent {
            agent_signer_evidence,
            ..
        } if matches!(agent_signer_evidence.as_ref(), AgentSignerEvidence::HistoricalEvent { .. })
    ) {
        return Err("ordinary Agent Event requires historical signer evidence".to_owned());
    }
    let dependencies = complete_agent_signer_evidence_dependencies(state, root, Vec::new())
        .await
        .map_err(|_| "Agent signer evidence dependency closure is incomplete".to_owned())?;
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
        .map_err(|error| error.to_string())?;
    let trust_root = std::sync::Arc::new(root.clone());
    let trust_dependencies = std::sync::Arc::new(proof_dependencies.clone());
    let trust_state = state.clone();
    let material = arkret::verify_agent_historical_event_key(
        event,
        root,
        &proof_dependencies,
        move |request| {
            let root = trust_root.clone();
            let dependencies = trust_dependencies.clone();
            let state = trust_state.clone();
            Box::pin(async move {
                verify_retained_agent_trust(&state, request, &root, &dependencies).await
            })
        },
    )
    .await
    .map_err(|error| error.to_string())?;
    material.ed25519_bytes().map_err(|error| error.to_string())
}

async fn current_service_signer_evidence(
    state: &AppState,
) -> Result<AuthenticatedSignerResolutionEvidence, AgentEvidenceAcquisitionFailure> {
    let resolution =
        crate::routing::system::service_resolution::current_authenticated_service_resolution(state)
            .await
            .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    let service_id = resolution.service_id.clone();
    let (_, method) = state
        .current_service_receipt_binding()
        .await
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    arkret_identity::service_signer_evidence_for_method_from_authenticated_resolution(
        resolution,
        &service_id,
        method,
        chrono::Utc::now(),
    )
    .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)
}

pub(crate) async fn retain_current_service_signer_evidence_ref(
    state: &AppState,
    signed_at: chrono::DateTime<chrono::Utc>,
) -> Result<arkret_wire::SignerEvidenceRef, AppError> {
    let resolution =
        crate::routing::system::service_resolution::current_authenticated_service_resolution(state)
            .await?;
    let service_id = resolution.service_id.clone();
    let (_, verification_method) = state
        .current_service_receipt_binding()
        .await
        .map_err(AppError::internal)?;
    let evidence =
        arkret_identity::service_signer_evidence_for_method_from_authenticated_resolution(
            resolution,
            &service_id,
            verification_method,
            signed_at,
        )
        .map_err(|error| AppError::internal(error.to_string()))?;
    let reference = arkret::signer_evidence_ref(&evidence)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let content_digest = evidence
        .canonical_sha256_digest()
        .map_err(|error| AppError::internal(error.to_string()))?;
    state
        .persistence()
        .governance_dependency_store()
        .put_unscoped_signer_evidence_exact(
            GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                selector: GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                    content_digest,
                },
                authenticated_signer_resolution_evidence: Box::new(evidence),
            },
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(reference)
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
) -> Result<AuthenticatedSignerResolutionEvidence, AgentEvidenceAcquisitionFailure> {
    // A private Account Authority shares its owning Station's service history.
    // Its gate-account origin is not a public service-resolution endpoint.
    let resolution = if service_id == &state.service_core_id() {
        crate::routing::system::service_resolution::current_authenticated_service_resolution(state)
            .await
            .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?
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
                .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
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
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
        let response = client
            .get(url)
            .header(
                "arkret-operation",
                arkret_wire::ServiceOperationId::OPEN_SERVICE_READ_RESOLUTION_V1,
            )
            .send()
            .await
            .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
        if !response.status().is_success() {
            return Err(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing);
        }
        let body = response
            .bytes()
            .await
            .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
        if body.len() > 1024 * 1024 {
            return Err(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing);
        }
        serde_json::from_slice(&body)
            .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?
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
                    .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
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
                return Err(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing);
            }
            arkret_identity::service_signer_evidence_for_method_from_authenticated_resolution(
                resolution,
                service_id,
                methods[0].clone(),
                at,
            )
        }
    }
    .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)
}

/// Classify the actual signing principal from its retained producer evidence, including
/// Agent execution on another actor's behalf.
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
) -> Result<ControllerAccountGateAttestation, AgentEvidenceAcquisitionFailure> {
    let AgentSignerEvidenceQuerySelector::CurrentAdmission { actor, .. } = selector else {
        return Err(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing);
    };
    let account = actor
        .as_account_id()
        .ok_or(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    if account.station_id != state.service_core_id() {
        return Err(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing);
    }
    let agent_id = &account.principal_id;
    let agent = state
        .agent_pairings()
        .agent(agent_id.as_str())
        .await
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?
        .ok_or(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    let principal_id = DidCoreId::new(agent.controller_principal_id)
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    if state.account_lifecycle_state(principal_id.as_str()) != "active" {
        return Err(AgentEvidenceAcquisitionFailure::AgentAuthorizationInactive);
    }
    let destination_id = crate::routing::events::peer::trusted_account_authority_id(state)
        .await
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    let source_id = DidCoreId::new(state.service_id().clone())
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
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
    let channel = crate::routing::events::peer::registered_internal_authority_channel(state)
        .await
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    let target = channel.controller_gate_url();
    let request_id = RequestId::new(format!("ak:request:{}", uuid::Uuid::now_v7()))
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    let request = ControllerAccountGateIssuanceInput {
        request_id: request_id.clone(),
        principal_id: principal_id.clone(),
        agent_authority_id: source_id.clone(),
    };
    let body = arkret_canonical::canonical_json_bytes(&request)
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        target,
        "controller account gate",
        state.config().development_mode,
        Duration::from_secs(10),
    )
    .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    // This product-private adapter runs on the deployment-internal authenticated
    // channel, and the Agent same-server
    // invariant means it has no external calling branch. The channel credential
    // is the complete authentication contract: it replaces the RFC 9421 request
    // signature, and the request carries no service-resolution carrier.
    //
    // Every plaintext proxy on this link is part of the trusted deployment TCB;
    // with no peer registered the call fails closed rather than falling back to
    // an unauthenticated or self-asserted identity.
    //
    // The fixed call site supplies the destination. No redundant
    // service-identity or trust-domain headers are sent. §2.5.1 forbids the
    // `Content-Digest` that existed only for the removed request signature.
    //
    // The *response* attestation is unaffected: it keeps its own signature, its
    // DID assertion authorization and its TTL, and is verified below, because it
    // leaves this relationship and enters the external Agent evidence chain.
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/json"),
    );
    let authorization =
        reqwest::header::HeaderValue::from_str(&format!("Bearer {}", channel.credential()))
            .map(|mut value| {
                value.set_sensitive(true);
                value
            })
            .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    headers.insert(reqwest::header::AUTHORIZATION, authorization);
    let response = client
        .post(url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    if !response.status().is_success() {
        tracing::warn!(status = %response.status(), "Agent evidence controller gate request failed");
        return Err(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing);
    }
    let response = response
        .bytes()
        .await
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    if response.len() > 1024 * 1024 {
        return Err(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing);
    }
    let outcome: ControllerAccountGateIssuanceResult =
        serde_json::from_slice(&response)
            .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    if outcome.request_id != request_id
        || outcome.controller_account_gate_attestation.principal_id != principal_id
        || outcome.controller_account_gate_attestation.authority_id != destination_id
    {
        return Err(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing);
    }
    let gate = outcome.controller_account_gate_attestation;
    let authority_key =
        crate::jws_verify::resolve_ed25519_pubkey_async(state, gate.verification_method.as_str())
            .await
            .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    arkret_signatures::agent_evidence::verify_controller_account_gate_attestation(
        &gate,
        &principal_id,
        &destination_id,
        &PublicKeyMaterial::Ed25519Raw {
            bytes: authority_key.to_bytes().to_vec(),
        },
        chrono::Utc::now(),
    )
    .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    *cached_gate = Some(gate.clone());
    Ok(gate)
}

async fn produce_current_agent_signer_evidence(
    state: &AppState,
    selector: &AgentSignerEvidenceQuerySelector,
    gate: ControllerAccountGateAttestation,
    frozen_agent: Option<&AgentPrincipalRecord>,
) -> Result<CurrentAgentSignerEvidence, AgentEvidenceAcquisitionFailure> {
    let AgentSignerEvidenceQuerySelector::CurrentAdmission {
        actor,
        verification_method,
    } = selector
    else {
        return Err(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing);
    };
    let account = actor
        .as_account_id()
        .ok_or(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    if account.station_id != state.service_core_id() {
        return Err(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing);
    }
    let agent_id = &account.principal_id;
    let now = chrono::Utc::now();
    let loaded_agent;
    let agent = match frozen_agent {
        Some(agent) => agent,
        None => {
            loaded_agent = state
                .agent_pairings()
                .agent(agent_id.as_str())
                .await
                .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?
                .ok_or(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
            &loaded_agent
        }
    };
    if agent.state != arkret_models_collaboration::agent_operations::AgentLifecycleState::Active {
        return Err(AgentEvidenceAcquisitionFailure::AgentAuthorizationInactive);
    }
    let runtime = agent
        .runtime_bindings()
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?
        .active_binding
        .ok_or(AgentEvidenceAcquisitionFailure::AgentAuthorizationInactive)?;
    let authorized_key =
        arkret_models_identity::agent_signer_evidence::AgentAuthorizedSigningKey::from_event(
            &runtime.key_authorization_event,
        )
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    if runtime.verification_method != *verification_method
        || authorized_key.agent_id != *agent_id
        || authorized_key.agent_key_authorize_event_id != runtime.authorized_event_ref
    {
        return Err(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing);
    }
    if authorized_key
        .expires_at
        .is_some_and(|expires_at| expires_at <= now)
    {
        return Err(AgentEvidenceAcquisitionFailure::AgentAuthorizationInactive);
    }
    let realm_id = RealmId::new(agent.principal_control_realm_id.clone())
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    let pcr_genesis_event = accepted_event(state, &realm_id.event_id()).await?;
    let authorize_event = accepted_event(state, &runtime.authorized_event_ref).await?;
    let payload =
        arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload::try_from(
            &authorize_event,
        )
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    let agent_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        agent_id.clone(),
        state.service_core_id().clone(),
    ));
    if authorize_event.realm_id != realm_id
        || authorize_event.actor_id != agent_actor
        || payload.verification_method != *verification_method
        || authorized_key.public_key_digest != runtime.public_key_digest
        || authorize_event.payload != runtime.key_authorization_event.payload
        || payload.key_id != authorized_key.agent_key_id
    {
        return Err(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing);
    }
    let key_seal = covering_seal(state, &authorize_event).await?;
    let key_cell_ref = arkret_signatures::agent_evidence::agent_authorization_cell_ref(
        agent_id,
        &authorized_key.agent_key_id,
    )
    .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    let (key_value, _key_revision, key_proof) =
        witnessed_cell(state, &realm_id, &key_seal, &key_cell_ref).await?;
    let key_value: Vec<AgentKeyCellEntry> = serde_json::from_value(key_value)
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;

    let frontier =
        crate::routing::identity::agent_pcr::agent_event_seal_head(state, realm_id.as_str())
            .await
            .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?
            .ok_or(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    let lifecycle_seal = frontier.clone();
    let lifecycle_cell_ref = lifecycle_cell_ref(&agent_actor)?;
    let (lifecycle_value, lifecycle_revision, lifecycle_proof) =
        witnessed_cell(state, &realm_id, &lifecycle_seal, &lifecycle_cell_ref).await?;
    let lifecycle_value: AgentLifecycleStatus = serde_json::from_value(lifecycle_value)
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    if lifecycle_value != AgentLifecycleStatus::Active {
        return Err(AgentEvidenceAcquisitionFailure::AgentAuthorizationInactive);
    }
    let lifecycle =
        accepted_current_lifecycle(state, &agent_actor, &realm_id, &lifecycle_revision).await?;

    let closure = state
        .projections()
        .seal_basis_closure(std::slice::from_ref(&frontier.id))
        .await
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    if !closure.contains(&key_seal.id) || !closure.contains(&lifecycle_seal.id) {
        return Err(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing);
    }
    let mut seal_lineage = Vec::with_capacity(closure.len());
    for seal_id in closure {
        seal_lineage.push(
            state
                .projections()
                .seal_by_id(&seal_id)
                .await
                .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?
                .ok_or(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?,
        );
    }
    seal_lineage.sort_by_key(|seal| seal.notary_seq);

    let mut delegated_signers = std::collections::BTreeMap::new();
    for seal in &seal_lineage {
        let signer = state
            .persistence()
            .governance_dependency_store()
            .agent_seal_signer(&seal.id)
            .await
            .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
        if let Some(signer) = signer {
            if let Some(previous) =
                delegated_signers.insert(signer.verification_method.clone(), signer.clone())
                && previous != signer
            {
                return Err(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing);
            }
        }
    }

    let service_id =
        arkret_wire::project_did_to_core_id(&state.service_resolution_commitment().did)
            .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    let (_, authority_method) = state
        .current_service_receipt_binding()
        .await
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    let core = AgentAuthorityState {
        authority_id: service_id.clone(),
        principal_control_realm_id: realm_id,
        pcr_genesis_event,
        key_authorization_event: authorize_event,
        frontier_seal_id: frontier.id.clone(),
        frontier_state_root: frontier.state_root.clone(),
        authorization: AgentAuthorizationEvidence {
            status: AgentAuthorizationStatus::Active,
            authorized_event_id: runtime.authorized_event_ref.clone(),
            accepted_seal_id: key_seal.id.clone(),
            accepted_at: key_seal.sealed_at,
            not_before: authorized_key.issued_at,
            expires_at: authorized_key.expires_at,
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
            leaf_digest: lifecycle_proof.leaf_digest,
            leaf_index: lifecycle_proof.leaf_index,
            leaf_count: lifecycle_proof.leaf_count,
            inclusion_proof: lifecycle_proof.inclusion_proof,
        },
        seal_lineages: seal_lineage,
        accepted_delegated_notary_signers: delegated_signers.into_values().collect(),
    };
    let state_digest = canonical_digest(&core)?;
    let mut expires_at = now + chrono::Duration::seconds(300);
    if let Some(binding_expiry) = core.authorization.expires_at {
        expires_at = expires_at.min(binding_expiry);
    }
    let mut authority_state_evidence = AgentAuthorityStateEvidence {
        state: core,
        state_digest: state_digest.clone(),
        attestation: AgentAuthorityStateAttestation {
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
        let mut attestations = state.agent_evidence_cache.state_attestations.lock();
        attestations.retain(|_, attestation| attestation.expires_at > now);
        let key = (state_digest.clone(), authority_method.clone());
        if let Some(attestation) = attestations.get(&key)
            && attestation.issued_at <= now
            && now < attestation.expires_at
            && attestation.expires_at <= expires_at
        {
            authority_state_evidence.attestation = attestation.clone();
        } else {
            arkret_signatures::agent_evidence::sign_agent_authority_state_attestation(
                &mut authority_state_evidence.attestation,
                state.notary_signing_key().as_ref(),
            )
            .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
            if attestations.len() >= 4096 {
                attestations.pop_first();
            }
            attestations.insert(key, authority_state_evidence.attestation.clone());
        }
    }
    let admission_evidence_digest =
        arkret_signatures::agent_evidence::agent_admission_evidence_digest(
            &authority_state_evidence,
            &gate,
        )
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
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
) -> Result<Event, AgentEvidenceAcquisitionFailure> {
    let record = state
        .event_queries()
        .canonical_event(event_id.as_str())
        .await
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?
        .ok_or(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    let event: Event = serde_json::from_value(record.envelope)
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    if event.event_id != *event_id {
        return Err(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing);
    }
    Ok(event)
}

async fn covering_seal(
    state: &AppState,
    event: &Event,
) -> Result<Seal, AgentEvidenceAcquisitionFailure> {
    let digest_suite = arkret::signed_event_digest_claim(event)
        .and_then(|digest| digest.digest_suite().map_err(Into::into))
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    let digest = Hash::new(
        event
            .event_digest_with_digest_suite(digest_suite)
            .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?,
    )
    .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    state
        .projections()
        .seal_covering_event(&digest)
        .await
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?
        .ok_or(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)
}

async fn witnessed_cell(
    state: &AppState,
    realm_id: &RealmId,
    seal: &Seal,
    cell: &NonEmptyString,
) -> Result<
    (
        serde_json::Value,
        EventId,
        arkret_state::StateInclusionProof,
    ),
    AgentEvidenceAcquisitionFailure,
> {
    let cell = CellRef::new(cell.as_str().to_owned())
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    let effective = state
        .projections()
        .effective_state_at(std::slice::from_ref(&seal.id), realm_id)
        .await
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    let Some(arkret_state::state_model::ResolvedCellState::Sequenced(sequenced)) =
        effective.get(&cell)
    else {
        return Err(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing);
    };
    let value = sequenced.value.clone();
    let revision_event_id = sequenced.revision_event_id.clone();
    let digest_suite = state
        .projections()
        .seal_digest_suites(seal)
        .await
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?
        .seal_digest_suite;
    let proof = arkret_state::state_inclusion_proof(
        arkret_state::GovernanceView::new(&effective),
        &cell,
        digest_suite,
    )
    .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    Ok((value, revision_event_id, proof))
}

pub(super) fn lifecycle_cell_ref(
    agent_actor_id: &arkret_wire::ActorId,
) -> Result<NonEmptyString, AgentEvidenceAcquisitionFailure> {
    if agent_actor_id.as_account_id().is_none() {
        return Err(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing);
    }
    let canonical_actor = agent_actor_id
        .canonical_key()
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    let subject = arkret_wire::composite_subject(&[canonical_actor.as_str()])
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    non_empty(&format!("ak:cell:{AGENT_STATUS_COMPONENT}:{subject}"))
}

async fn accepted_current_lifecycle(
    state: &AppState,
    agent_actor: &arkret_wire::ActorId,
    realm_id: &RealmId,
    revision_event_id: &EventId,
) -> Result<AcceptedLifecycle, AgentEvidenceAcquisitionFailure> {
    let event = accepted_event(state, revision_event_id).await?;
    if event.realm_id != *realm_id || event.actor_id != *agent_actor {
        return Err(AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing);
    }
    let provenance = match event.kind {
        arkret_wire::EventKind::RealmCreate => AgentLifecycleProvenance::DelegatedPcrGenesis {
            realm_create_event_id: event.event_id.clone(),
        },
        arkret_wire::EventKind::SelfAgentResume => AgentLifecycleProvenance::ResumeAccepted {
            resume_event_id: event.event_id.clone(),
        },
        _ => return Err(AgentEvidenceAcquisitionFailure::AgentAuthorizationInactive),
    };
    Ok(AcceptedLifecycle { event, provenance })
}

fn non_empty(value: &str) -> Result<NonEmptyString, AgentEvidenceAcquisitionFailure> {
    NonEmptyString::new(value.to_owned())
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)
}

fn empty_proof() -> Result<AgentDetachedJws, AgentEvidenceAcquisitionFailure> {
    Ok(AgentDetachedJws {
        kind: non_empty("detached_jws")?,
        jws: non_empty("pending")?,
    })
}

fn canonical_digest(
    value: &impl serde::Serialize,
) -> Result<Hash, AgentEvidenceAcquisitionFailure> {
    let digest = crate::util::canonical_digest(value)
        .map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)?;
    Hash::new(digest).map_err(|_| AgentEvidenceAcquisitionFailure::AgentSignerEvidenceMissing)
}
