//! Native Agent signer evidence is a closed current/historical protocol.
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
    AGENT_KEY_COMPONENT, AGENT_STATUS_COMPONENT, AgentAdmissionEvidence, AgentAuthoritySnapshot,
    AgentAuthoritySnapshotCore, AgentAuthorizationEvidence, AgentAuthorizationStateWitness,
    AgentAuthorizationStatus, AgentCurrentObservation, AgentDetachedJws,
    AgentEvidenceOuterAttestation, AgentKeyCellEntry, AgentLifecycleProvenance,
    AgentLifecycleStatus, AgentLifecycleWitness, AgentSignerEvidence,
    AgentSignerEvidenceQueryFailure, AgentSignerEvidenceQueryFailureReason,
    AgentSignerEvidenceQueryOutcome, AgentSignerEvidenceQueryRequestBody,
    AgentSignerEvidenceQuerySelector, AgentSnapshotLease, ControllerAccountGateAttestation,
    ControllerAccountGateAttestationIssueOutcome, ControllerAccountGateAttestationIssueRequestBody,
    CurrentAgentSignerEvidence,
};
use arkret_signatures::proof::PublicKeyMaterial;
use arkret_wire::{
    CellRef, DidCoreId, Event, EventId, Hash, NonEmptyString, NotarySig, RealmId, RequestId,
    SchemaId, Seal,
};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;

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
    if !crate::routing::realm_has_member(state, body.realm_id.as_str(), &session.actor).await {
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
        evidence,
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

async fn current_authenticated_agent_signer_evidence(
    state: &AppState,
    selector: &AgentSignerEvidenceQuerySelector,
) -> Result<
    (
        AuthenticatedSignerResolutionEvidence,
        Vec<AuthenticatedSignerResolutionEvidence>,
    ),
    AgentSignerEvidenceQueryFailureReason,
> {
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
        .agent_authority_snapshot
        .core
        .signing_key_binding;
    let gate = &admission_evidence.controller_account_gate_attestation;
    let local_service_evidence = current_service_signer_evidence(state).await?;
    let controller_evidence = current_controller_signer_evidence(
        state,
        &binding.controller_id,
        &binding.controller_proof.verification_method,
        &local_service_evidence,
    )
    .await?;
    let account_authority_evidence = fetch_service_signer_evidence(
        state,
        &gate.authority_service_id,
        state.config().account_authority_url.as_deref(),
    )
    .await?;
    let receiver_evidence =
        if current_observation.verifier_id == *local_service_evidence.signer_id() {
            local_service_evidence.clone()
        } else {
            return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
        };
    let root = arkret::build_native_agent_signer_resolution_evidence(
        agent_signer_evidence,
        &local_service_evidence,
        &controller_evidence,
        &account_authority_evidence,
        &receiver_evidence,
    )
    .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    Ok((
        root,
        vec![
            local_service_evidence,
            controller_evidence,
            account_authority_evidence,
            receiver_evidence,
        ],
    ))
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
    controller_id: &DidCoreId,
    verification_method: &arkret_wire::DidUrl,
    attester: &AuthenticatedSignerResolutionEvidence,
) -> Result<AuthenticatedSignerResolutionEvidence, AgentSignerEvidenceQueryFailureReason> {
    let principal_server_id = attester.signer_id().clone();
    let authority =
        arkret_wire::PrincipalAuthorityKey::new(controller_id.clone(), principal_server_id);
    let (public_resolution, normalized_did_document) =
        crate::routing::system::principal_resolution::current_public_principal_resolution(
            state, &authority,
        )
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let evidence = AuthenticatedSignerResolutionEvidence::Principal {
        signer_id: controller_id.clone(),
        verification_method: verification_method.clone(),
        public_resolution,
        normalized_did_document,
        attester_signer_evidence_ref: attester
            .evidence_ref()
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?,
        attester_signer_evidence_digest: attester
            .canonical_sha256_digest()
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?,
    };
    evidence
        .validate_attester_binding()
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    Ok(evidence)
}

async fn fetch_service_signer_evidence(
    state: &AppState,
    service_id: &DidCoreId,
    base_url: Option<&str>,
) -> Result<AuthenticatedSignerResolutionEvidence, AgentSignerEvidenceQueryFailureReason> {
    let base_url = base_url
        .filter(|value| !value.trim().is_empty())
        .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
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
    let resolution = serde_json::from_slice(&body)
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    arkret_identity::service_signer_evidence_from_authenticated_resolution(
        resolution,
        service_id,
        chrono::Utc::now(),
    )
    .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)
}

async fn persist_agent_signer_evidence_closure(
    state: &AppState,
    root: &AuthenticatedSignerResolutionEvidence,
    dependencies: &[AuthenticatedSignerResolutionEvidence],
) -> Result<(), AppError> {
    let store = state.persistence().governance_dependency_store();
    for evidence in std::iter::once(root).chain(dependencies) {
        let content_digest = evidence
            .canonical_sha256_digest()
            .map_err(|error| AppError::internal(error.to_string()))?;
        let item = GovernanceDependency::AuthenticatedSignerResolutionEvidence {
            selector: GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                content_digest,
            },
            authenticated_signer_resolution_evidence: evidence.clone(),
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
    if persistence
        .idempotency_record(agent_id.as_str(), &key)
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
            principal_id: agent_id.as_str().to_owned(),
            idempotency_key: key.clone(),
            service_id: state.service_id().clone(),
            request_hash,
            response_status: 201,
            response_body: serde_json::json!({"reservation": marker}),
            created_at: now,
            expires_at: now + chrono::Duration::minutes(5),
        })
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let winner = persistence
        .idempotency_record(agent_id.as_str(), &key)
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
    let principal_id = DidCoreId::new(agent.controller_id)
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let destination_service_id =
        crate::routing::events::peer::trusted_account_authority_service_id(state)
            .await
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let source_service_id = DidCoreId::new(state.service_id().clone())
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
        agent_authority_service_id: source_service_id.clone(),
        agent_authority_service_resolution:
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
        source_service_id.as_str(),
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "destination-service-id",
        destination_service_id.as_str(),
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "arkret-operation-id",
        arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_CONTROLLER_GATE_ATTESTATION,
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
        || outcome
            .controller_account_gate_attestation
            .authority_service_id
            != destination_service_id
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
        &destination_service_id,
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
    if authorize_event.realm_id != realm_id
        || authorize_event.actor_id != *agent_id
        || payload.verification_method != *verification_method
        || payload.public_key_digest != runtime.public_key_digest
        || payload.signing_key_binding_digest != binding_digest
        || payload.key_id != runtime.signing_key_binding.agent_key_id
    {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    }
    let key_seal = covering_seal(state, &authorize_event)?;
    let key_cell_ref = arkret_signatures::agent_evidence::agent_authorization_cell_ref(
        agent_id,
        &runtime.signing_key_binding.agent_key_id,
    )
    .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let (key_value, key_proof) = witnessed_cell(state, &realm_id, &key_seal, &key_cell_ref)?;
    let key_value: Vec<AgentKeyCellEntry> = serde_json::from_value(key_value)
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;

    let lifecycle = accepted_current_lifecycle(state, &agent, agent_id, &realm_id).await?;
    let lifecycle_seal = covering_seal(state, &lifecycle.event)?;
    let lifecycle_cell_ref = lifecycle_cell_ref(agent_id)?;
    let (lifecycle_value, lifecycle_proof) =
        witnessed_cell(state, &realm_id, &lifecycle_seal, &lifecycle_cell_ref)?;
    let lifecycle_value: AgentLifecycleStatus = serde_json::from_value(lifecycle_value)
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    if lifecycle_value != AgentLifecycleStatus::Active {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentAuthorizationInactive);
    }

    let frontier = crate::routing::identity::managed_agent_pcr::managed_agent_event_seal_head(
        state,
        realm_id.as_str(),
    )
    .await
    .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?
    .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let closure = state
        .projections()
        .seal_closure(std::slice::from_ref(&frontier.id))
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    if !closure.contains(&key_seal.id) || !closure.contains(&lifecycle_seal.id) {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    }
    let mut seal_lineage = closure
        .into_iter()
        .map(|seal_id| {
            state
                .projections()
                .seal_by_id(&seal_id)
                .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?
                .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)
        })
        .collect::<Result<Vec<_>, _>>()?;
    seal_lineage.sort_by_key(|seal| seal.notary_seq);

    let service_id = DidCoreId::from(
        arkret_wire::project_full_id_to_core_id(&state.service_resolution_commitment().full_id)
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?,
    );
    let (_, authority_method) = state
        .current_service_receipt_binding()
        .await
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let key_seal_id = key_seal.id.clone();
    let lifecycle_seal_id = lifecycle_seal.id.clone();
    let core = AgentAuthoritySnapshotCore {
        authority_service_id: service_id.clone(),
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
            controller_id: runtime.signing_key_binding.controller_id.clone(),
            status: AgentLifecycleStatus::Active,
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
        seal_lineage,
    };
    let snapshot_digest = canonical_digest(&core)?;
    let expires_at = now + chrono::Duration::minutes(2);
    let mut snapshot = AgentAuthoritySnapshot {
        core,
        snapshot_digest: snapshot_digest.clone(),
        lease: AgentSnapshotLease {
            authority_kind: non_empty("agent_authority")?,
            authority_service_id: service_id.clone(),
            verification_method: authority_method.clone(),
            snapshot_digest: snapshot_digest.clone(),
            issued_at: now,
            expires_at,
            proof: empty_proof()?,
        },
    };
    arkret_signatures::agent_evidence::sign_agent_snapshot_lease(
        &mut snapshot.lease,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    #[derive(serde::Serialize)]
    struct AdmissionCore<'a> {
        agent_authority_snapshot: &'a AgentAuthoritySnapshot,
        controller_account_gate_attestation: &'a ControllerAccountGateAttestation,
    }
    let admission_evidence_digest = canonical_digest(&AdmissionCore {
        agent_authority_snapshot: &snapshot,
        controller_account_gate_attestation: &gate,
    })?;
    let gate_digest = canonical_digest(&gate)?;
    let admission_evidence = AgentAdmissionEvidence {
        agent_authority_snapshot: snapshot,
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
            audience: audience.clone(),
            challenge: challenge.clone(),
            agent_snapshot_digest: snapshot_digest,
            agent_key_seal_id: key_seal_id,
            agent_status_seal_id: lifecycle_seal_id,
            controller_gate_attestation_digest: gate_digest,
            evaluated_at: now,
            expires_at,
        },
        outer_attestation: AgentEvidenceOuterAttestation {
            domain: non_empty("ak.agent-signer-evidence.v1")?,
            core_digest: Hash::new(format!("sha256:{}", "00".repeat(32)))
                .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?,
            source_service_id: service_id,
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

fn covering_seal(
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
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?
        .ok_or(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)
}

fn witnessed_cell(
    state: &AppState,
    realm_id: &RealmId,
    seal: &Seal,
    cell: &NonEmptyString,
) -> Result<
    (serde_json::Value, arkret_state::StateInclusionProof),
    AgentSignerEvidenceQueryFailureReason,
> {
    let cell = CellRef::new(cell.as_str().to_owned())
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let effective = state
        .projections()
        .effective_state_at(std::slice::from_ref(&seal.id), realm_id)
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
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?
        .seal_digest_suite;
    let proof = arkret_state::state_inclusion_proof(&effective, &cell, digest_suite)
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    Ok((value, proof))
}

fn lifecycle_cell_ref(
    agent_id: &DidCoreId,
) -> Result<NonEmptyString, AgentSignerEvidenceQueryFailureReason> {
    let subject = arkret_wire::composite_subject(&[agent_id.as_str()])
        .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    non_empty(&format!("ak:cell:{AGENT_STATUS_COMPONENT}:{subject}"))
}

async fn accepted_current_lifecycle(
    state: &AppState,
    agent: &soland_services::identity::AgentPairingState,
    agent_id: &DidCoreId,
    realm_id: &RealmId,
) -> Result<AcceptedLifecycle, AgentSignerEvidenceQueryFailureReason> {
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
                && event.actor_id == *agent_id
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
    Hash::new(
        arkret_canonical::canonical_sha256(value)
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?,
    )
    .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)
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
    let snapshot = &admission_evidence.agent_authority_snapshot;
    let binding = &snapshot.core.signing_key_binding;
    if binding.agent_id != *agent_id || binding.verification_method != *verification_method {
        return Err(AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing);
    }
    let controller_key = crate::jws_verify::resolve_ed25519_pubkey_async(
        state,
        binding.controller_proof.verification_method.as_str(),
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
        crate::routing::events::peer::trusted_account_authority_service_id(state)
            .await
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    if gate.authority_service_id != trusted_account_authority {
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
    for seal in &snapshot.core.seal_lineage {
        for method in seal_signature_methods(seal) {
            if seal_keys.contains_key(method.as_str()) {
                continue;
            }
            let key = crate::jws_verify::resolve_ed25519_pubkey_async(state, method.as_str())
                .await
                .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
            seal_keys.insert(method.as_str().to_owned(), key);
        }
    }
    let verify_seal = |seal: &Seal| verify_seal_with_keys(seal, &seal_keys);
    let verify_lifecycle = |witness: &AgentLifecycleWitness| validate_lifecycle_witness(witness);
    let binding_digest =
        arkret_signatures::agent_evidence::agent_signing_key_binding_digest(binding)
            .map_err(|_| AgentSignerEvidenceQueryFailureReason::AgentSignerEvidenceMissing)?;
    let state_context = arkret_signatures::agent_evidence::AgentEvidenceStateVerificationContext {
        signer_id: agent_id,
        agent_key_id: &binding.agent_key_id,
        controller_id: &binding.controller_id,
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
        controller_id: &binding.controller_id,
        verification_method,
        agent_key_authorize_event_id: &binding.agent_key_authorize_event_id,
        authorize_public_key_digest: &binding.public_key_digest,
        authorize_signing_key_binding_digest: &binding_digest,
        expected_authority_service_id: &snapshot.core.authority_service_id,
        expected_authority_verification_method: &outer_attestation.verification_method,
        expected_account_authority_service_id: &gate.authority_service_id,
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
    if witness.accepted_status_event.actor_id != witness.agent_id
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
