use std::collections::{BTreeMap, BTreeSet};

use arkret_identifiers::{CellRef, Did, EventId, Hash, RealmId};
use arkret_models_collaboration::agent_signer_evidence::{
    AGENT_KEY_COMPONENT, AgentAuthorizationAdmission, AgentAuthorizationEvidence,
    AgentAuthorizationStateWitness, AgentAuthorizationStatus, AgentAuthorizationTransitionWitness,
    AgentSignerEvidence, AgentSignerEvidenceBundle, AgentSignerEvidenceQueryFailure,
    AgentSignerEvidenceQueryFailureReason, AgentSignerEvidenceQueryOutcome,
    AgentSignerEvidenceQueryRequestBodyBody, AgentSignerEvidenceQuerySelector,
    AgentSigningKeyBinding,
};
use arkret_state::lattice::CellState;
use arkret_wire::{DidUrl, Event, NonEmptyString, NotarySig, SchemaId, Seal};
use chrono::{DateTime, Duration, Utc};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::Value;
use soland_http::error::{AppError, ErrorCode};
use soland_http::result::{JsonResult, json_ok};
use soland_services::events::CanonicalEventRecord;

use super::{AuthArgs, now};
use crate::state::AppState;

const FRESHNESS_LIFETIME: Duration = Duration::minutes(2);

pub(crate) struct AgentAuthorizationAdmissionSnapshot {
    pub authorization_event_id: EventId,
    pub accepted_frontier: NonEmptyString,
}

/// Capture the Agent PCR authorization frontier used at Event admission.
/// Callers place this receipt only in transport `unsigned` metadata, so the
/// producer Event's canonical bytes remain unchanged.
pub(crate) async fn authorization_admission_snapshot(
    state: &AppState,
    agent_id: &str,
    verification_method: &str,
) -> Option<AgentAuthorizationAdmissionSnapshot> {
    let record = state.agent_pairings().agent(agent_id).await.ok()??;
    if record.authorized_verification_method.as_deref() != Some(verification_method) {
        return None;
    }
    let authorization_event_id = EventId::new(record.authorized_event_ref?).ok()?;
    let pcr_id = RealmId::new(record.principal_control_realm_id).ok()?;
    let head = unique_realm_head(state, &pcr_id).ok()?;
    Some(AgentAuthorizationAdmissionSnapshot {
        authorization_event_id,
        accepted_frontier: NonEmptyString::new(head.id.as_str().to_owned()).ok()?,
    })
}

struct WitnessMaterial {
    seal: Seal,
    cell_ref: CellRef,
    cell_value: Value,
    leaf_digest: Hash,
    leaf_index: u64,
    leaf_count: u64,
    inclusion_proof: Vec<Hash>,
}

struct AuthorizationTransition {
    status: AgentAuthorizationStatus,
    event: CanonicalEventRecord,
    key_id: NonEmptyString,
    witness: WitnessMaterial,
}

#[endpoint(
    operation_id = "ak.self.agent_signer_evidence.query.resolve",
    summary = "Query portable Native Agent signer evidence",
    tags("agents")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent_signer_evidence.query.resolve"))]
pub(super) async fn query_agent_signer_evidence(
    aa: AuthArgs,
    body: JsonBody<AgentSignerEvidenceQueryRequestBodyBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentSignerEvidenceQueryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let request = body.into_inner();
    let realm_id = request.realm_id.as_str();
    let realm = state
        .realms()
        .realm_metadata(realm_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("not found"))?;
    if realm.minimal_metadata_realm {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "Agent signer evidence is forbidden in minimal-metadata Realms",
        )
        .with_wire_code("agent_signer_evidence_forbidden"));
    }
    if !crate::routing::spaces::space::realm_has_member(state, realm_id, &session.actor).await {
        return Err(AppError::not_found("not found"));
    }
    let realm_events = state
        .event_queries()
        .realm_events_newest_first(realm_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;

    let mut evidence = Vec::new();
    let mut failures = Vec::new();
    for selector in request.queries {
        if !realm_contains_matching_agent_event(&realm_events, &selector) {
            failures.push(query_failure(
                selector,
                AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing,
            ));
            continue;
        }
        match build_evidence(state, &selector).await {
            Ok(Some(value)) => evidence.push(value),
            Ok(None) => failures.push(query_failure(
                selector,
                AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing,
            )),
            Err(reason) => failures.push(query_failure(selector, reason)),
        }
    }

    json_ok(AgentSignerEvidenceQueryOutcome {
        evidence,
        failures: (!failures.is_empty()).then_some(failures),
    })
}

fn query_failure(
    selector: AgentSignerEvidenceQuerySelector,
    reason: AgentSignerEvidenceQueryFailureReason,
) -> AgentSignerEvidenceQueryFailure {
    AgentSignerEvidenceQueryFailure { selector, reason }
}

pub(crate) async fn build_evidence(
    state: &AppState,
    selector: &AgentSignerEvidenceQuerySelector,
) -> Result<Option<AgentSignerEvidence>, AgentSignerEvidenceQueryFailureReason> {
    let record = state
        .agent_pairings()
        .agent(selector.agent_id.as_str())
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceStale)?
        .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let pcr_id = RealmId::new(record.principal_control_realm_id.clone())
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let mut events = state
        .event_queries()
        .canonical_events_for_realm_actor(pcr_id.as_str(), selector.agent_id.as_str())
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceStale)?;
    events.sort_by(|left, right| {
        left.received_at
            .cmp(&right.received_at)
            .then_with(|| left.actor_seq.cmp(&right.actor_seq))
            .then_with(|| left.event_id.cmp(&right.event_id))
    });

    let authorization_event = select_authorization_event(&events, selector, &record)
        .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let binding = binding_for_event(authorization_event, &record)
        .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    if binding.agent_id != selector.agent_id
        || binding.verification_method != selector.verification_method
        || binding.agent_key_authorize_event_id.as_str() != authorization_event.event_id
        || !authorization_payload_matches_binding(authorization_event, &binding)
    {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    }

    let head = unique_realm_head(state, &pcr_id)?;
    let seals = head_lineage(state, &pcr_id, &head)?;
    let authorization_witness = find_event_witness(
        state,
        &pcr_id,
        &seals,
        &binding.agent_id,
        &binding.agent_key_id,
        binding.agent_key_authorize_event_id.as_str(),
    )?
    .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let transition = find_transition(
        state,
        &pcr_id,
        &seals,
        &events,
        authorization_event,
        &binding,
    )?;
    let issued_now = now();
    let expired_before_transition = binding.expires_at.is_some_and(|expires_at| {
        expires_at <= issued_now
            && transition
                .as_ref()
                .is_none_or(|transition| expires_at <= transition.event.received_at)
    });
    let status = if expired_before_transition {
        AgentAuthorizationStatus::Expired
    } else {
        transition
            .as_ref()
            .map_or(AgentAuthorizationStatus::Active, |transition| {
                transition.status
            })
    };

    if let Some(frontier) = selector.event_accepted_frontier.as_ref() {
        let positions = seal_positions(&seals);
        let Some(event_position) = positions.get(frontier.as_str()).copied() else {
            return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceStale);
        };
        let authorization_position = positions
            .get(authorization_witness.seal.id.as_str())
            .copied()
            .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceStale)?;
        let transition_position = transition
            .as_ref()
            .and_then(|transition| positions.get(transition.witness.seal.id.as_str()).copied());
        if event_position < authorization_position
            || transition_position.is_some_and(|position| event_position >= position)
        {
            return Err(AgentSignerEvidenceQueryFailureReason::AgentAuthorizationInactive);
        }
    }

    let freshness_attestation =
        arkret_signatures::agent_evidence::build_agent_evidence_freshness_attestation(
            Did::new(state.service_id().clone())
                .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceStale)?,
            NonEmptyString::new(head.id.as_str().to_owned())
                .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceStale)?,
            issued_now,
            issued_now + FRESHNESS_LIFETIME,
            DidUrl::new(format!("{}#notary-key", state.service_id()))
                .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceStale)?,
            state.notary_signing_key().as_ref(),
        )
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceStale)?;

    let accepted_frontier = NonEmptyString::new(authorization_witness.seal.id.as_str().to_owned())
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceStale)?;
    let (valid_until_frontier, transition_event_id, transition_witness) =
        if expired_before_transition {
            (None, None, None)
        } else if let Some(transition) = transition {
            let frontier = NonEmptyString::new(transition.witness.seal.id.as_str().to_owned())
                .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceStale)?;
            let event_id = EventId::new(transition.event.event_id.clone())
                .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceStale)?;
            let witness = transition_witness(
                &selector.agent_id,
                &binding.agent_key_authorize_event_id,
                &event_id,
                transition.key_id,
                frontier.clone(),
                transition.witness,
            )?;
            (Some(frontier), Some(event_id), Some(witness))
        } else {
            (None, None, None)
        };

    Ok(Some(AgentSignerEvidence {
        schema: NonEmptyString::new(SchemaId::AGENT_SIGNER_EVIDENCE_V1.to_owned())
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceStale)?,
        signing_key_binding: binding.clone(),
        authorization: AgentAuthorizationEvidence {
            status,
            authorized_event_id: binding.agent_key_authorize_event_id.clone(),
            accepted_frontier: accepted_frontier.clone(),
            accepted_at: authorization_event.received_at,
            valid_from_frontier: accepted_frontier.clone(),
            not_before: binding.issued_at,
            valid_until_frontier,
            expires_at: binding.expires_at,
            transition_event_id,
        },
        state_witness: authorization_state_witness(
            &selector.agent_id,
            &binding.agent_key_authorize_event_id,
            accepted_frontier,
            authorization_witness,
        )?,
        transition_witness,
        seal_lineage: seals,
        freshness_attestation,
        transparency: None,
    }))
}

pub(crate) async fn signer_evidence_bundle_for_events(
    state: &AppState,
    events: &[Event],
) -> Option<AgentSignerEvidenceBundle> {
    let mut selectors = BTreeMap::new();
    for event in events {
        if event.applet_id.is_some() {
            continue;
        }
        let Some(admission) = event
            .unsigned
            .get("agent_authorization_admission")
            .cloned()
            .and_then(|value| serde_json::from_value::<AgentAuthorizationAdmission>(value).ok())
        else {
            continue;
        };
        let signer = event.executed_by.as_ref().unwrap_or(&event.actor_id);
        if signer != &admission.agent_id
            || !event
                .proofs
                .iter()
                .any(|proof| proof.verification_method == admission.verification_method.as_str())
        {
            continue;
        }
        let key = (
            admission.agent_id.as_str().to_owned(),
            admission.verification_method.as_str().to_owned(),
            admission.authorization_event_id.as_str().to_owned(),
            admission.accepted_frontier.as_str().to_owned(),
        );
        selectors
            .entry(key)
            .or_insert(AgentSignerEvidenceQuerySelector {
                agent_id: admission.agent_id,
                verification_method: admission.verification_method,
                agent_key_authorize_event_id: Some(admission.authorization_event_id),
                event_accepted_frontier: Some(admission.accepted_frontier),
            });
    }

    let mut evidence = Vec::new();
    for selector in selectors.into_values().take(256) {
        if let Ok(Some(item)) = build_evidence(state, &selector).await {
            evidence.push(item);
        }
    }
    if evidence.is_empty() {
        return None;
    }
    Some(AgentSignerEvidenceBundle {
        schema: NonEmptyString::new(SchemaId::AGENT_SIGNER_EVIDENCE_BUNDLE_V1.to_owned()).ok()?,
        evidence,
    })
}

pub(crate) async fn verify_federated_signer_evidence(
    state: &AppState,
    evidence: &AgentSignerEvidence,
    event: &Event,
    now: DateTime<Utc>,
) -> Result<[u8; 32], String> {
    use arkret_signatures::Ed25519DetachedJwsVerifier;
    use arkret_signatures::agent_evidence::{
        AgentSignerEvidenceValidationContext, AgentSignerEvidenceVerdict,
        agent_signing_key_binding_digest, validate_agent_signer_evidence,
        verify_agent_evidence_freshness_attestation, verify_agent_signing_key_binding,
    };

    if event.applet_id.is_some() {
        return Err("Applet Events cannot use Native Agent signer evidence".to_owned());
    }
    let admission = event
        .unsigned
        .get("agent_authorization_admission")
        .cloned()
        .and_then(|value| serde_json::from_value::<AgentAuthorizationAdmission>(value).ok())
        .ok_or_else(|| "Agent Event omitted its authorization admission receipt".to_owned())?;
    let binding = &evidence.signing_key_binding;
    let signer = event.executed_by.as_ref().unwrap_or(&event.actor_id);
    if signer != &admission.agent_id
        || signer != &binding.agent_id
        || admission.verification_method != binding.verification_method
        || admission.authorization_event_id != binding.agent_key_authorize_event_id
        || !event
            .proofs
            .iter()
            .any(|proof| proof.verification_method == binding.verification_method.as_str())
    {
        return Err("Agent signer evidence does not match the transported Event".to_owned());
    }

    let controller_material =
        resolve_evidence_public_key(state, binding.controller_proof.verification_method.as_str())
            .await?;
    let binding_digest =
        agent_signing_key_binding_digest(binding).map_err(|error| format!("{error:?}"))?;
    verify_agent_signing_key_binding(
        binding,
        &binding.agent_id,
        &binding.agent_key_id,
        &binding.controller_id,
        &binding.verification_method,
        &binding.agent_key_authorize_event_id,
        &binding.public_key_digest,
        &binding_digest,
        &controller_material,
    )
    .map_err(|error| format!("Agent signing-key binding rejected: {error:?}"))?;

    let freshness = &evidence.freshness_attestation;
    let source_material =
        resolve_evidence_public_key(state, freshness.source_proof.verification_method.as_str())
            .await?;
    verify_agent_evidence_freshness_attestation(freshness, &source_material)
        .map_err(|error| format!("Agent evidence freshness rejected: {error:?}"))?;

    let allowed_seal_signers = [
        freshness.source_service_id.as_str(),
        binding.controller_id.as_str(),
    ];
    for seal in &evidence.seal_lineage {
        let canonical = seal
            .canonical_bytes_for_id()
            .map_err(|error| format!("Agent evidence Seal is invalid: {error}"))?;
        let expected_digest = Hash::new(arkret_canonical::sha256_digest(&canonical))
            .map_err(|error| format!("Agent evidence Seal digest is invalid: {error}"))?;
        let signatures = match &seal.notary_signature {
            NotarySig::Single(signature) => vec![signature],
            NotarySig::Multi(multi) if !multi.signatures.is_empty() => {
                multi.signatures.iter().collect()
            }
            NotarySig::Multi(_) | NotarySig::Threshold(_) => {
                return Err("Agent evidence Seal has unsupported signatures".to_owned());
            }
        };
        for signature in signatures {
            let controller = signature
                .verification_method
                .split_once('#')
                .map_or(signature.verification_method.as_str(), |(did, _)| did);
            if signature.alg != "EdDSA"
                || signature.payload_digest != expected_digest
                || !allowed_seal_signers.contains(&controller)
            {
                return Err("Agent evidence Seal signature binding is invalid".to_owned());
            }
            let material =
                resolve_evidence_public_key(state, &signature.verification_method).await?;
            Ed25519DetachedJwsVerifier::new()
                .verify_detached_jws(&signature.jws, &canonical, &material)
                .map_err(|error| format!("Agent evidence Seal signature rejected: {error}"))?;
        }
    }

    let context = AgentSignerEvidenceValidationContext {
        signer_id: &admission.agent_id,
        agent_key_id: &binding.agent_key_id,
        authorization_realm_id: &evidence.state_witness.seal.realm_id,
        controller_id: &binding.controller_id,
        verification_method: &admission.verification_method,
        agent_key_authorize_event_id: &admission.authorization_event_id,
        authorize_public_key_digest: &binding.public_key_digest,
        authorize_signing_key_binding_digest: &binding_digest,
        event_accepted_frontier: &admission.accepted_frontier,
        event_accepted_at: admission.accepted_at,
        now,
        controller_public_key: &controller_material,
        seal_lineage_signatures_verified: true,
        freshness_signature_verified: true,
        require_transparency: false,
        transparency_verified: false,
    };
    match validate_agent_signer_evidence(Some(evidence), &context) {
        AgentSignerEvidenceVerdict::Verified(verified) => Ok(verified.key),
        AgentSignerEvidenceVerdict::Rejected(reason) => {
            Err(format!("Agent signer evidence rejected: {reason:?}"))
        }
        AgentSignerEvidenceVerdict::Unresolved(reason) => {
            Err(format!("Agent signer evidence unresolved: {reason:?}"))
        }
    }
}

async fn resolve_evidence_public_key(
    state: &AppState,
    verification_method: &str,
) -> Result<arkret_signatures::PublicKeyMaterial, String> {
    let (controller, fragment) = verification_method
        .split_once('#')
        .ok_or_else(|| "evidence verification method has no DID fragment".to_owned())?;
    if let Ok(device_id) = arkret_identifiers::DeviceId::new(fragment.to_owned()) {
        let controller_id = Did::new(controller.to_owned())
            .map_err(|error| format!("evidence controller DID is invalid: {error}"))?;
        let evidence = crate::jws_verify::federated_device_signing_key_evidence(
            state,
            &controller_id,
            &device_id,
            verification_method,
        )
        .await?;
        let multibase = evidence
            .device_signing_key
            .as_str()
            .strip_prefix("did:key:")
            .ok_or_else(|| "evidence device key is not Ed25519 did:key".to_owned())?;
        return Ok(arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
            value: multibase.to_owned(),
        });
    }
    let key = crate::jws_verify::resolve_ed25519_pubkey_async(state, verification_method).await?;
    Ok(arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: key.to_bytes().to_vec(),
    })
}

fn realm_contains_matching_agent_event(
    events: &[CanonicalEventRecord],
    selector: &AgentSignerEvidenceQuerySelector,
) -> bool {
    events.iter().any(|event| {
        if event.envelope.get("applet_id").is_some() {
            return false;
        }
        let signer = event
            .envelope
            .get("executed_by")
            .and_then(Value::as_str)
            .unwrap_or(event.actor_id.as_str());
        signer == selector.agent_id.as_str() && {
            let admission = event
                .envelope
                .pointer("/unsigned/agent_authorization_admission")
                .cloned()
                .and_then(|value| {
                    serde_json::from_value::<AgentAuthorizationAdmission>(value).ok()
                });
            admission.is_some_and(|admission| {
                admission.agent_id == selector.agent_id
                    && admission.verification_method == selector.verification_method
                    && selector
                        .agent_key_authorize_event_id
                        .as_ref()
                        .is_none_or(|event_id| event_id == &admission.authorization_event_id)
                    && selector
                        .event_accepted_frontier
                        .as_ref()
                        .is_none_or(|frontier| frontier == &admission.accepted_frontier)
            })
        }
    })
}

fn select_authorization_event<'a>(
    events: &'a [CanonicalEventRecord],
    selector: &AgentSignerEvidenceQuerySelector,
    record: &soland_services::identity::AgentPairingState,
) -> Option<&'a CanonicalEventRecord> {
    let event_id = selector
        .agent_key_authorize_event_id
        .as_ref()
        .map(EventId::as_str)
        .or(record.authorized_event_ref.as_deref())?;
    events.iter().find(|event| {
        event.event_id == event_id && event.kind == arkret_wire::EventKind::AGENT_KEY_AUTHORIZE
    })
}

fn binding_for_event(
    event: &CanonicalEventRecord,
    record: &soland_services::identity::AgentPairingState,
) -> Option<AgentSigningKeyBinding> {
    let from_event = event
        .envelope
        .get("unsigned")
        .and_then(|unsigned| unsigned.get("agent_signing_key_binding"))
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok());
    from_event.or_else(|| {
        (record.authorized_event_ref.as_deref() == Some(event.event_id.as_str()))
            .then(|| record.authorized_signing_key_binding.clone())
            .flatten()
    })
}

fn authorization_payload_matches_binding(
    event: &CanonicalEventRecord,
    binding: &AgentSigningKeyBinding,
) -> bool {
    let Some(payload) = event.envelope.get("payload") else {
        return false;
    };
    let binding_digest =
        arkret_signatures::agent_evidence::agent_signing_key_binding_digest(binding).ok();
    payload.get("agent_id").and_then(Value::as_str) == Some(binding.agent_id.as_str())
        && payload.get("key_id").and_then(Value::as_str) == Some(binding.agent_key_id.as_str())
        && payload.get("verification_method").and_then(Value::as_str)
            == Some(binding.verification_method.as_str())
        && payload.get("public_key_digest").and_then(Value::as_str)
            == Some(binding.public_key_digest.as_str())
        && payload
            .get("signing_key_binding_digest")
            .and_then(Value::as_str)
            == binding_digest.as_ref().map(|digest| digest.as_str())
}

fn unique_realm_head(
    state: &AppState,
    realm_id: &RealmId,
) -> Result<Seal, AgentSignerEvidenceQueryFailureReason> {
    let leaves = state
        .projections()
        .realm_seal_leaves(realm_id)
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceStale)?;
    if leaves.len() != 1 {
        return Err(if leaves.is_empty() {
            AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing
        } else {
            AgentSignerEvidenceQueryFailureReason::AgentAuthorizationConflicted
        });
    }
    state
        .projections()
        .seal_by_id(&leaves[0])
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceStale)?
        .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceStale)
}

fn head_lineage(
    state: &AppState,
    realm_id: &RealmId,
    head: &Seal,
) -> Result<Vec<Seal>, AgentSignerEvidenceQueryFailureReason> {
    let mut pending = vec![head.id.clone()];
    let mut seen = BTreeSet::new();
    let mut seals = Vec::new();
    while let Some(seal_id) = pending.pop() {
        if !seen.insert(seal_id.clone()) {
            continue;
        }
        let seal = state
            .projections()
            .seal_by_id(&seal_id)
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceStale)?
            .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceStale)?;
        if seal.realm_id != *realm_id {
            return Err(AgentSignerEvidenceQueryFailureReason::AgentAuthorizationConflicted);
        }
        pending.extend(seal.predecessor_refs.iter().cloned());
        seals.push(seal);
    }
    seals.sort_by(|left, right| {
        left.notary_seq
            .cmp(&right.notary_seq)
            .then_with(|| left.sealed_at.cmp(&right.sealed_at))
            .then_with(|| left.id.as_str().cmp(right.id.as_str()))
    });
    Ok(seals)
}

fn seal_positions(seals: &[Seal]) -> BTreeMap<&str, usize> {
    seals
        .iter()
        .enumerate()
        .map(|(index, seal)| (seal.id.as_str(), index))
        .collect()
}

fn find_event_witness(
    state: &AppState,
    realm_id: &RealmId,
    seals: &[Seal],
    agent_id: &Did,
    key_id: &NonEmptyString,
    event_id: &str,
) -> Result<Option<WitnessMaterial>, AgentSignerEvidenceQueryFailureReason> {
    let cell_ref_wire =
        arkret_signatures::agent_evidence::agent_authorization_cell_ref(agent_id, key_id)
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let cell_ref = CellRef::new(cell_ref_wire.as_str().to_owned())
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    for seal in seals {
        let cells = state
            .projections()
            .effective_state_at(std::slice::from_ref(&seal.id), realm_id)
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentAuthorizationConflicted)?;
        let Some(cell_state) = cells.get(&cell_ref) else {
            continue;
        };
        let CellState::Value(cell_value) = cell_state else {
            return Err(AgentSignerEvidenceQueryFailureReason::AgentAuthorizationConflicted);
        };
        if !value_contains_string(cell_value, event_id) {
            continue;
        }
        let computed_root = arkret_state::compute_state_root(&cells)
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceStale)?;
        if computed_root != seal.state_root {
            return Err(AgentSignerEvidenceQueryFailureReason::AgentAuthorizationConflicted);
        }
        let proof = arkret_state::state_inclusion_proof(&cells, &cell_ref)
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceStale)?;
        return Ok(Some(WitnessMaterial {
            seal: seal.clone(),
            cell_ref,
            cell_value: cell_value.clone(),
            leaf_digest: proof.leaf_digest,
            leaf_index: proof.leaf_index,
            leaf_count: proof.leaf_count,
            inclusion_proof: proof.inclusion_proof,
        }));
    }
    Ok(None)
}

fn find_transition(
    state: &AppState,
    realm_id: &RealmId,
    seals: &[Seal],
    events: &[CanonicalEventRecord],
    authorization_event: &CanonicalEventRecord,
    binding: &AgentSigningKeyBinding,
) -> Result<Option<AuthorizationTransition>, AgentSignerEvidenceQueryFailureReason> {
    let mut candidates = Vec::new();
    for event in events.iter().filter(|event| {
        event.received_at > authorization_event.received_at
            || (event.received_at == authorization_event.received_at
                && event.event_id > authorization_event.event_id)
    }) {
        let Some(payload) = event.envelope.get("payload") else {
            continue;
        };
        let (status, transition_key_id) = if event.kind
            == arkret_wire::EventKind::AGENT_KEY_AUTHORIZE
            && payload
                .get("supersedes")
                .and_then(Value::as_array)
                .is_some_and(|supersedes| {
                    supersedes.iter().any(|superseded| {
                        superseded
                            .get("authorized_event_ref")
                            .and_then(Value::as_str)
                            == Some(authorization_event.event_id.as_str())
                    })
                }) {
            (
                AgentAuthorizationStatus::Superseded,
                payload.get("key_id").and_then(Value::as_str),
            )
        } else if event.kind == arkret_wire::EventKind::AGENT_KEY_REVOKE
            && payload.get("key_id").and_then(Value::as_str) == Some(binding.agent_key_id.as_str())
        {
            (
                AgentAuthorizationStatus::Revoked,
                Some(binding.agent_key_id.as_str()),
            )
        } else {
            continue;
        };
        let Some(transition_key_id) =
            transition_key_id.and_then(|value| NonEmptyString::new(value.to_owned()).ok())
        else {
            continue;
        };
        let Some(witness) = find_event_witness(
            state,
            realm_id,
            seals,
            &binding.agent_id,
            &transition_key_id,
            &event.event_id,
        )?
        else {
            continue;
        };
        candidates.push(AuthorizationTransition {
            status,
            event: event.clone(),
            key_id: transition_key_id,
            witness,
        });
    }
    candidates.sort_by(|left, right| {
        left.witness
            .seal
            .notary_seq
            .cmp(&right.witness.seal.notary_seq)
            .then_with(|| {
                left.witness
                    .seal
                    .sealed_at
                    .cmp(&right.witness.seal.sealed_at)
            })
            .then_with(|| left.event.event_id.cmp(&right.event.event_id))
    });
    Ok(candidates.into_iter().next())
}

fn authorization_state_witness(
    agent_id: &Did,
    authorization_event_id: &EventId,
    accepted_frontier: NonEmptyString,
    material: WitnessMaterial,
) -> Result<AgentAuthorizationStateWitness, AgentSignerEvidenceQueryFailureReason> {
    Ok(AgentAuthorizationStateWitness {
        component: NonEmptyString::new(AGENT_KEY_COMPONENT.to_owned())
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceStale)?,
        agent_id: agent_id.clone(),
        authorization_event_id: authorization_event_id.clone(),
        accepted_frontier,
        seal_id: material.seal.id.clone(),
        state_root: material.seal.state_root.clone(),
        seal: material.seal,
        cell_ref: NonEmptyString::new(material.cell_ref.as_str().to_owned())
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceStale)?,
        cell_value: material.cell_value,
        leaf_digest: material.leaf_digest,
        leaf_index: material.leaf_index,
        leaf_count: material.leaf_count,
        inclusion_proof: material.inclusion_proof,
    })
}

fn transition_witness(
    agent_id: &Did,
    authorization_event_id: &EventId,
    transition_event_id: &EventId,
    transition_key_id: NonEmptyString,
    accepted_frontier: NonEmptyString,
    material: WitnessMaterial,
) -> Result<AgentAuthorizationTransitionWitness, AgentSignerEvidenceQueryFailureReason> {
    Ok(AgentAuthorizationTransitionWitness {
        component: NonEmptyString::new(AGENT_KEY_COMPONENT.to_owned())
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceStale)?,
        agent_id: agent_id.clone(),
        authorization_event_id: authorization_event_id.clone(),
        transition_event_id: transition_event_id.clone(),
        transition_key_id,
        accepted_frontier,
        seal_id: material.seal.id.clone(),
        state_root: material.seal.state_root.clone(),
        seal: material.seal,
        cell_ref: NonEmptyString::new(material.cell_ref.as_str().to_owned())
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceStale)?,
        cell_value: material.cell_value,
        leaf_digest: material.leaf_digest,
        leaf_index: material.leaf_index,
        leaf_count: material.leaf_count,
        inclusion_proof: material.inclusion_proof,
    })
}

fn value_contains_string(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(value) => value == expected,
        Value::Array(values) => values
            .iter()
            .any(|value| value_contains_string(value, expected)),
        Value::Object(values) => values
            .values()
            .any(|value| value_contains_string(value, expected)),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use serde_json::json;

    use super::*;

    fn selector() -> AgentSignerEvidenceQuerySelector {
        serde_json::from_value(json!({
            "agent_id": "did:web:agent.example",
            "verification_method": "did:web:agent.example#runtime-1",
            "agent_key_authorize_event_id":
                "ak:event:01964137-0000-7000-8000-000000000001",
            "event_accepted_frontier": "ak:seal:01964137-0000-7000-8000-000000000002"
        }))
        .unwrap()
    }

    fn event(actor_id: &str, executed_by: Option<&str>) -> CanonicalEventRecord {
        let mut envelope = json!({
            "actor_id": actor_id,
            "unsigned": {
                "agent_authorization_admission": {
                    "agent_id": "did:web:agent.example",
                    "verification_method": "did:web:agent.example#runtime-1",
                    "authorization_event_id":
                        "ak:event:01964137-0000-7000-8000-000000000001",
                    "accepted_frontier":
                        "ak:seal:01964137-0000-7000-8000-000000000002",
                    "accepted_at": "2026-07-25T00:01:00.000Z"
                }
            }
        });
        if let Some(executed_by) = executed_by {
            envelope["executed_by"] = Value::String(executed_by.to_owned());
        }
        CanonicalEventRecord {
            event_id: "ak:event:01964137-0000-7000-8000-000000000003".to_owned(),
            actor_id: actor_id.to_owned(),
            actor_seq: 1,
            realm_id: Some("ak:realm:01964137-0000-7000-8000-000000000004".to_owned()),
            kind: arkret_wire::EventKind::MESSAGE_CREATE.to_owned(),
            schema_id: "ak.schema.event.v1".to_owned(),
            canonical_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            canonical_bytes: Vec::new(),
            envelope,
            received_at: Utc::now(),
        }
    }

    #[test]
    fn shared_context_matches_native_and_delegated_agent_events() {
        let selector = selector();
        assert!(realm_contains_matching_agent_event(
            &[event("did:web:agent.example", None)],
            &selector,
        ));
        assert!(realm_contains_matching_agent_event(
            &[event(
                "did:web:controller.example",
                Some("did:web:agent.example"),
            )],
            &selector,
        ));
        assert!(!realm_contains_matching_agent_event(
            &[event(
                "did:web:controller.example",
                Some("did:web:other-agent.example"),
            )],
            &selector,
        ));
    }
}
