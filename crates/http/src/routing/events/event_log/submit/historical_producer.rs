use arkret_models_collaboration::governance_dependencies::{
    GovernanceDependency, GovernanceDependencySelector,
};
use arkret_models_identity::AuthenticatedSignerResolutionEvidence;

use super::*;

/// Copy every exact original source into the accepted Event's transaction.
/// This is retention only; source authentication must have succeeded earlier.
pub(super) async fn retained_historical_producer_dependencies(
    state: &AppState,
    root: &arkret_wire::SignerEvidenceRef,
) -> Result<Vec<GovernanceDependency>, String> {
    let mut pending = vec![root.clone()];
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    while let Some(reference) = pending.pop() {
        if !seen.insert(reference.clone()) {
            continue;
        }
        if seen.len() > 64 {
            return Err("historical producer dependency closure exceeds 64 items".to_owned());
        }
        let evidence = retained_evidence(state, &reference).await?;
        for selector in arkret_models_collaboration::governance_dependencies::governance_attester_evidence_selectors(std::slice::from_ref(&evidence)).map_err(|error| error.to_string())? {
            let GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence { content_digest } = selector else { return Err("historical producer source has another dependency kind".to_owned()); };
            pending.push(arkret_wire::SignerEvidenceRef::new(format!("ak:signer_evidence:{content_digest}")).map_err(|error| error.to_string())?);
        }
        result.push(
            GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                selector: GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                    content_digest: reference
                        .content_digest()
                        .map_err(|error| error.to_string())?,
                },
                authenticated_signer_resolution_evidence: Box::new(evidence),
            },
        );
    }
    Ok(result)
}

async fn retained_evidence(
    state: &AppState,
    reference: &arkret_wire::SignerEvidenceRef,
) -> Result<AuthenticatedSignerResolutionEvidence, String> {
    let selector = GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
        content_digest: reference
            .content_digest()
            .map_err(|error| error.to_string())?,
    };
    let dependency = state
        .persistence()
        .governance_dependency_store()
        .get_unscoped_signer_evidence(&selector)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| {
            "dependency_missing: historical producer source original material is unavailable"
                .to_owned()
        })?;
    let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
        authenticated_signer_resolution_evidence: evidence,
        ..
    } = dependency
    else {
        return Err("historical producer source resolved to another dependency kind".to_owned());
    };
    if &evidence.evidence_ref().map_err(|error| error.to_string())? != reference {
        return Err(
            "historical producer source bytes do not match their signed reference".to_owned(),
        );
    }
    Ok(*evidence)
}

pub(crate) async fn verify_historical_producer(
    state: &AppState,
    event: &Event,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<arkret::historical_producer::VerifiedHistoricalEventProducer, String> {
    let Some(proof) = event.producer_proof.as_ref() else {
        return Err("ordinary Event needs exactly one producer proof".to_owned());
    };
    let reference = proof
        .signer_resolution_evidence_ref
        .as_ref()
        .ok_or_else(|| "ordinary Event proof omits signer evidence".to_owned())?;
    let root = retained_evidence(state, reference).await?;
    let signer = event.executed_by.as_ref().unwrap_or(&event.actor_id);
    let source = match &root {
        AuthenticatedSignerResolutionEvidence::AccountDeviceControl {
            pcr_genesis_event_ref,
            history_event_refs,
            history_seal_refs,
            ..
        } => {
            let history_suite = pcr_genesis_event_ref
                .event_digest()
                .digest_suite()
                .map_err(|error| {
                    format!("Control signer PCR genesis digest suite is invalid: {error}")
                })?;
            let mut events = Vec::with_capacity(history_event_refs.len());
            for event_ref in history_event_refs {
                let event_digest = event_ref.event_digest();
                let retained = state
                    .projections()
                    .control_event_by_digest(&event_digest)
                    .await
                    .map_err(|error| {
                        format!(
                            "dependency_missing: Control signer history Event lookup failed: {error}"
                        )
                    })?
                    .ok_or_else(|| {
                        format!(
                            "dependency_missing: Control signer history Event {event_ref} is unavailable"
                        )
                    })?;
                if &retained.event_id != event_ref {
                    return Err(
                        "Control signer history Event bytes differ from their exact reference"
                            .to_owned(),
                    );
                }
                events.push(retained);
            }
            let mut seals = Vec::with_capacity(history_seal_refs.len());
            for seal_ref in history_seal_refs {
                let retained = state
                    .projections()
                    .seal_by_id(seal_ref)
                    .await
                    .map_err(|error| {
                        format!(
                            "dependency_missing: Control signer history Seal lookup failed: {error}"
                        )
                    })?
                    .ok_or_else(|| {
                        format!(
                            "dependency_missing: Control signer history Seal {seal_ref} is unavailable"
                        )
                    })?;
                if &retained.id != seal_ref {
                    return Err(
                        "Control signer history Seal bytes differ from their exact reference"
                            .to_owned(),
                    );
                }
                seals.push(retained);
            }
            arkret::historical_producer::AuthenticatedHistoricalProducerSource::authenticate_account_device_control(
                reference,
                signer,
                &root,
                &seals,
                &events,
                history_suite,
            )
            .map_err(|error| {
                format!("historical Control producer source authentication failed: {error}")
            })?
        }
        _ => {
            let dependencies = match &root {
                AuthenticatedSignerResolutionEvidence::Principal {
                    attester_signer_evidence_ref,
                    ..
                }
                | AuthenticatedSignerResolutionEvidence::AccountDevice {
                    attester_signer_evidence_ref,
                    ..
                } => vec![retained_evidence(state, attester_signer_evidence_ref).await?],
                _ => Vec::new(),
            };
            arkret::historical_producer::AuthenticatedHistoricalProducerSource::authenticate(
                reference,
                signer,
                &root,
                &dependencies,
                event.created_at,
            )
            .map_err(|error| format!("historical producer source authentication failed: {error}"))?
        }
    };
    let producer = source
        .verify_event(event, digest_suite)
        .map_err(|error| error.to_string())?;
    Ok(producer)
}
