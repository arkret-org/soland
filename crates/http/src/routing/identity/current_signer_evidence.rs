//! Reusable current signer evidence proxy and peer authority endpoint.

use std::collections::BTreeMap;
use std::time::Duration;

use arkret_models_collaboration::{
    CompactAgentSignerResolutionEvidence, CurrentSignerEvidence, CurrentSignerEvidenceQueryOutcome,
    CurrentSignerEvidenceQueryRequestBody, CurrentSignerEvidenceResponseCore,
    CurrentSignerEvidenceSelector,
};
use arkret_models_identity::{
    CurrentSignerKeyOutcome, HistoricalAgentSignerKeyOutcome, SignerEvidenceResolvedStatus,
    SignerEvidenceUnavailableStatus, SignerKeyQueryOutcome, SignerKeyQuerySelector,
    SignerKeysQueryOutcome, SignerKeysQueryRequestBody, UnavailableSignerKeyOutcome,
};
use arkret_wire::DidCoreId;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};

use super::AuthArgs;
use super::agents::evidence::AgentSignerEvidenceQuerySelector;
use crate::state::AppState;

const PEER_PATH: &str = "/_arkret/peer/current-signer-evidence/query";

pub(crate) fn self_router() -> Router {
    Router::with_path("signer-keys/query").post(self_query)
}

pub(crate) fn peer_router() -> Router {
    Router::with_path("current-signer-evidence/query").post(peer_query)
}

#[salvo::oapi::endpoint(operation_id = "ak.self.signer_keys.read.resolve", tags("identity"))]
async fn self_query(
    aa: AuthArgs,
    body: JsonBody<SignerKeysQueryRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SignerKeysQueryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    body.validate().map_err(self_request_error)?;
    let actor = super::session_actor::validated_session_actor(state, &session).await?;
    if actor.as_account_id() != Some(&body.recipient_account_id)
        || body.recipient_account_id.station_id != state.service_core_id()
    {
        return Err(AppError::not_found(
            "current signer evidence is unavailable",
        ));
    }
    json_ok(resolve_self_signer_keys(state, &session, &body).await?)
}

pub(crate) fn self_request_error(error: arkret_wire::WireError) -> AppError {
    AppError::from_rejection(
        match error.error_code() {
            Some(arkret_wire::ErrorCode::PayloadTooLarge) => {
                arkret_wire::ErrorCode::PayloadTooLarge
            }
            _ => arkret_wire::ErrorCode::SchemaViolation,
        },
        error.to_string(),
    )
}
pub(crate) fn self_result_error(error: arkret_wire::WireError) -> AppError {
    AppError::from_rejection(
        match error.error_code() {
            Some(arkret_wire::ErrorCode::LimitExceeded) => arkret_wire::ErrorCode::LimitExceeded,
            _ => arkret_wire::ErrorCode::SchemaViolation,
        },
        error.to_string(),
    )
}

pub(crate) async fn resolve_self_signer_keys(
    state: &AppState,
    session: &soland_services::identity::SessionIdentityState,
    body: &SignerKeysQueryRequestBody,
) -> Result<SignerKeysQueryOutcome, AppError> {
    body.validate().map_err(self_request_error)?;
    let requester = arkret_wire::ActorId::account(body.recipient_account_id.clone());
    let requester_is_member =
        crate::routing::realm_has_member(state, body.realm_id.as_str(), &requester.to_string())
            .await;
    let ordinary = state
        .realms()
        .realm_metadata(body.realm_id.as_str())
        .await
        .ok()
        .flatten()
        .is_some_and(|realm| !realm.minimal_metadata_realm);
    let mut results = Vec::with_capacity(body.queries.len());
    for selector in &body.queries {
        let visible = ordinary
            && match selector.event_id() {
                Some(event_id) => match state
                    .event_queries()
                    .canonical_event(event_id.as_str())
                    .await
                    .ok()
                    .flatten()
                {
                    Some(record) if record.realm_id.as_deref() == Some(body.realm_id.as_str()) => {
                        crate::routing::events::event_log::event_visible_to_session(
                            state, &record, session,
                        )
                        .await
                    }
                    _ => false,
                },
                None => {
                    requester_is_member
                        && crate::routing::realm_has_member(
                            state,
                            body.realm_id.as_str(),
                            &selector.actor().to_string(),
                        )
                        .await
                }
            };
        let resolved = if visible {
            match selector {
                SignerKeyQuerySelector::CurrentAccountDevice(current) => {
                    let Some(account_id) = current.actor.as_account_id().cloned() else {
                        results.push(unavailable_signer_key(selector));
                        continue;
                    };
                    current_key_result(
                        state,
                        body,
                        selector,
                        CurrentSignerEvidenceSelector::AccountDevice {
                            account_id,
                            device_id: current.device_id.clone(),
                        },
                    )
                    .await
                }
                SignerKeyQuerySelector::CurrentAgent(current) => {
                    current_key_result(
                        state,
                        body,
                        selector,
                        CurrentSignerEvidenceSelector::Agent {
                            actor: current.actor.clone(),
                            verification_method: current.verification_method.clone(),
                        },
                    )
                    .await
                }
                SignerKeyQuerySelector::HistoricalAgent(historical) => {
                    historical_agent_key_result(state, historical).await
                }
                SignerKeyQuerySelector::HistoricalAccountDevice(_) => None,
            }
        } else {
            None
        };
        results.push(resolved.unwrap_or_else(|| unavailable_signer_key(selector)));
    }
    let outcome = SignerKeysQueryOutcome {
        request_id: body.request_id.clone(),
        realm_id: body.realm_id.clone(),
        recipient_account_id: body.recipient_account_id.clone(),
        results,
    };
    outcome
        .validate_for_request(body)
        .map_err(self_result_error)?;
    Ok(outcome)
}

fn unavailable_signer_key(selector: &SignerKeyQuerySelector) -> SignerKeyQueryOutcome {
    SignerKeyQueryOutcome::Unavailable(UnavailableSignerKeyOutcome {
        selector: selector.clone(),
        status: SignerEvidenceUnavailableStatus::Unavailable,
    })
}

async fn current_key_result(
    state: &AppState,
    body: &SignerKeysQueryRequestBody,
    selector: &SignerKeyQuerySelector,
    peer_selector: CurrentSignerEvidenceSelector,
) -> Option<SignerKeyQueryOutcome> {
    let target = peer_selector.route_service_id().clone();
    let peer_request = CurrentSignerEvidenceQueryRequestBody {
        request_id: body.request_id.clone(),
        realm_id: body.realm_id.clone(),
        recipient_account_id: body.recipient_account_id.clone(),
        queries: vec![peer_selector.clone()],
        known_agent_state_digests: Vec::new(),
        known_signer_evidence_refs: Vec::new(),
    };
    let outcome = if target == state.service_core_id() {
        issue_authority_outcome(state, &peer_request, state.service_core_id()).await
    } else {
        proxy_peer_query(state, &peer_request, &target).await
    }
    .ok()?;
    outcome.validate_transport_for_request(&peer_request).ok()?;
    for item in &outcome.response.evidences {
        if item.selector() == peer_selector {
            let key = self_key_from_peer_item(state, &peer_request, item)
                .await
                .ok()?;
            return Some(SignerKeyQueryOutcome::Current(CurrentSignerKeyOutcome {
                selector: selector.clone(),
                status: SignerEvidenceResolvedStatus::Resolved,
                key,
                checked_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
            }));
        }
    }
    None
}

async fn historical_agent_key_result(
    state: &AppState,
    historical: &arkret_models_identity::HistoricalAgentSelector,
) -> Option<SignerKeyQueryOutcome> {
    let selector = AgentSignerEvidenceQuerySelector::HistoricalEvent {
        actor: historical.actor.clone(),
        verification_method: historical.verification_method.clone(),
        event_id: historical.event_id.clone(),
        receiver_id: state.service_core_id(),
    };
    let (root, dependencies) =
        super::agents::evidence::current_authenticated_agent_signer_evidence(state, &selector)
            .await
            .ok()?;
    let key = super::agents::evidence::verified_station_agent_key(
        state,
        &selector,
        &root,
        &dependencies,
        chrono::Utc::now(),
    )
    .await
    .ok()?;
    let arkret_models_identity::AuthenticatedSignerResolutionEvidence::Agent {
        agent_signer_evidence,
        ..
    } = &root
    else {
        return None;
    };
    let arkret_models_identity::AgentSignerEvidence::HistoricalEvent {
        event_admission, ..
    } = agent_signer_evidence.as_ref()
    else {
        return None;
    };
    Some(SignerKeyQueryOutcome::HistoricalAgent(
        HistoricalAgentSignerKeyOutcome {
            selector: historical.clone(),
            status: SignerEvidenceResolvedStatus::Resolved,
            key,
            accepted_at: event_admission.producer_accepted_at().ok()?,
            signer_evidence_ref: root.evidence_ref().ok()?,
        },
    ))
}

async fn self_key_from_peer_item(
    state: &AppState,
    request: &CurrentSignerEvidenceQueryRequestBody,
    item: &CurrentSignerEvidence,
) -> Result<arkret_models_identity::StationSigningKey, AppError> {
    let invalid = || AppError::not_found("current signer evidence unavailable");
    match item {
        CurrentSignerEvidence::Agent {
            actor,
            verification_method,
            ..
        } => {
            let (root, dependencies) = item
                .hydrate_agent(request, &BTreeMap::new(), &[])
                .map_err(|_| invalid())?;
            super::agents::evidence::verified_station_agent_key(
                state,
                &AgentSignerEvidenceQuerySelector::CurrentAdmission {
                    actor: actor.clone(),
                    verification_method: verification_method.clone(),
                },
                &root,
                &dependencies,
                chrono::Utc::now(),
            )
            .await
        }
        CurrentSignerEvidence::AccountDevice {
            account_id,
            device_id: _,
            device_projection_attestation,
            signer_evidence_ref,
        } => {
            let document =
                current_device_projection_document(state, device_projection_attestation).await?;
            use arkret_models_collaboration::governance_dependencies::{
                GovernanceDependency, GovernanceDependencySelector,
                PeerGovernanceDependencyResolveRequestBody,
            };
            let selector = GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                content_digest: signer_evidence_ref
                    .content_digest()
                    .map_err(|_| invalid())?,
            };
            let store = state.persistence().governance_dependency_store();
            let dependency = if let Some(item) = store
                .get_unscoped_signer_evidence(&selector)
                .await
                .map_err(|_| invalid())?
            {
                item
            } else {
                let query = PeerGovernanceDependencyResolveRequestBody {
                    realm_id: request.realm_id.clone(),
                    selectors: vec![selector],
                    byte_limit: 1024 * 1024,
                    history_traversal_access: None,
                };
                let response = crate::routing::federation::rhrk_acquisition::fetch_peer_governance_dependencies(state, &account_id.station_id, &query).await.map_err(|_| invalid())?;
                response
                    .validate_for_peer_request(&query)
                    .map_err(|_| invalid())?;
                response.items.into_iter().next().ok_or_else(invalid)?
            };
            let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                authenticated_signer_resolution_evidence: root,
                ..
            } = dependency
            else {
                return Err(invalid());
            };
            device_self_result_key(item, &root, &document, chrono::Utc::now())
                .map_err(|_| invalid())
        }
    }
}

pub(super) async fn current_device_projection_document(
    state: &AppState,
    attestation: &arkret_models_crypto::DeviceProjectionAttestation,
) -> Result<arkret_identity::DidDocument, AppError> {
    let unavailable = || AppError::not_found("current signer evidence is unavailable");
    let did =
        arkret_identity::verification_method_did(attestation.proof.verification_method.as_str())
            .map_err(|_| unavailable())?;
    if arkret_wire::project_did_to_core_id(&did).map_err(|_| unavailable())?
        != attestation.attestation.account_id.station_id
    {
        return Err(unavailable());
    }
    let current = state
        .dids()
        .resolve_current_service_did(&did)
        .await
        .map_err(|_| unavailable())?;
    Ok(current.document)
}

/// The self handler reduces a peer device item only after signature and exact
/// reference/Account/device bindings have all passed together.
fn device_self_result_key(
    item: &CurrentSignerEvidence,
    root: &arkret_models_identity::AuthenticatedSignerResolutionEvidence,
    document: &arkret_identity::DidDocument,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<arkret_models_identity::StationSigningKey, String> {
    let CurrentSignerEvidence::AccountDevice {
        account_id,
        device_id,
        device_projection_attestation: attestation,
        signer_evidence_ref,
    } = item
    else {
        return Err("not a device item".to_owned());
    };
    if &attestation.attestation.account_id != account_id
        || &attestation.attestation.device_id != device_id
    {
        return Err("device item identity mismatch".to_owned());
    }
    verify_current_device_projection(attestation, document, now)?;
    root.validate_attester_binding()
        .map_err(|e| e.to_string())?;
    if root.evidence_ref().map_err(|e| e.to_string())? != *signer_evidence_ref {
        return Err("device root reference mismatch".to_owned());
    }
    let arkret_models_identity::AuthenticatedSignerResolutionEvidence::AccountDevice {
        signer_id,
        verification_method,
        device_projection_attestation: projected,
        ..
    } = root
    else {
        return Err("not a device root".to_owned());
    };
    if signer_id != &account_id.principal_id || projected != attestation {
        return Err("device root identity mismatch".to_owned());
    }
    let public = attestation
        .attestation
        .device_signing_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or("device public key is not did:key")?;
    let bytes = arkret_canonical::decode_ed25519_multibase(public).map_err(|e| e.to_string())?;
    let key = arkret_models_identity::StationSigningKey {
        actor: arkret_wire::ActorId::account(account_id.clone()),
        verification_method: verification_method.clone(),
        public_key_b64u: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            bytes,
        ))
        .map_err(|e| e.to_string())?,
        authorization_ref: attestation.attestation.device_authorize_event_id.clone(),
    };
    key.validate().map_err(|e| e.to_string())?;
    Ok(key)
}

pub(super) fn verify_current_device_projection(
    attestation: &arkret_models_crypto::DeviceProjectionAttestation,
    document: &arkret_identity::DidDocument,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), String> {
    let method = &attestation.proof.verification_method;
    let did = arkret_identity::verification_method_did(method.as_str())
        .map_err(|error| error.to_string())?;
    if document.id != did
        || arkret_wire::project_did_to_core_id(&did).map_err(|error| error.to_string())?
            != attestation.attestation.account_id.station_id
    {
        return Err("device projection issuer mismatch".to_owned());
    }
    arkret_identity::validate_verification_method_relationship(
        document,
        method,
        &did,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(|error| error.to_string())?;
    let key = arkret_identity::jws::resolve_ed25519_pubkey_from_document(document, method.as_str())
        .map_err(|error| error.to_string())?;
    arkret_signatures::device_projection::verify_device_projection_attestation(
        attestation,
        &key,
        now,
    )
    .map_err(|error| error.to_string())
}

#[salvo::oapi::endpoint(
    operation_id = "ak.peer.current_signer_evidence.read.resolve",
    tags("identity")
)]
async fn peer_query(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CurrentSignerEvidenceQueryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    crate::routing::events::peer::validate_peer_request(state, req, true).await?;
    let source = req
        .headers()
        .get("source-service-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| DidCoreId::new(value.to_owned()).ok())
        .ok_or_else(|| AppError::not_found("current signer evidence is unavailable"))?;
    let body = req
        .parse_json::<CurrentSignerEvidenceQueryRequestBody>()
        .await
        .map_err(|_| AppError::json_invalid("invalid current signer evidence request"))?;
    body.validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if body.recipient_account_id.station_id != source {
        return json_ok(query_outcome(&body, Vec::new()));
    }
    json_ok(issue_authority_outcome(state, &body, source).await?)
}

async fn issue_authority_outcome(
    state: &AppState,
    request: &CurrentSignerEvidenceQueryRequestBody,
    verifier_id: DidCoreId,
) -> Result<CurrentSignerEvidenceQueryOutcome, AppError> {
    let visible = disclosure_context_is_current(state, request, &verifier_id).await;
    if !visible {
        tracing::warn!(realm_id = %request.realm_id, "current signer evidence disclosure gate rejected request");
    }
    let mut evidence = Vec::new();
    if visible {
        for selector in &request.queries {
            if let Some(item) = issue_selector(state, request, selector).await? {
                evidence.push(item);
            }
        }
    }
    Ok(query_outcome(request, evidence))
}

fn query_outcome(
    request: &CurrentSignerEvidenceQueryRequestBody,
    evidences: Vec<CurrentSignerEvidence>,
) -> CurrentSignerEvidenceQueryOutcome {
    CurrentSignerEvidenceQueryOutcome {
        response: CurrentSignerEvidenceResponseCore {
            request_id: request.request_id.clone(),
            realm_id: request.realm_id.clone(),
            recipient_account_id: request.recipient_account_id.clone(),
            evidences,
        },
    }
}

async fn disclosure_context_is_current(
    state: &AppState,
    request: &CurrentSignerEvidenceQueryRequestBody,
    verifier_id: &DidCoreId,
) -> bool {
    if verifier_id != &request.recipient_account_id.station_id
        || !matches!(
            request.target_station_id(),
            Ok(target) if target == &state.service_core_id()
        )
    {
        return false;
    }
    if state
        .realms()
        .realm_metadata(request.realm_id.as_str())
        .await
        .ok()
        .flatten()
        .is_none_or(|record| record.minimal_metadata_realm)
    {
        return false;
    }
    let recipient = arkret_wire::ActorId::account(request.recipient_account_id.clone());
    if !crate::routing::realm_has_member(state, request.realm_id.as_str(), &recipient.to_string())
        .await
    {
        return false;
    }
    for selector in &request.queries {
        if !crate::routing::realm_has_member(
            state,
            request.realm_id.as_str(),
            &selector.actor_id().to_string(),
        )
        .await
        {
            return false;
        }
    }
    true
}

async fn issue_selector(
    state: &AppState,
    request: &CurrentSignerEvidenceQueryRequestBody,
    selector: &CurrentSignerEvidenceSelector,
) -> Result<Option<CurrentSignerEvidence>, AppError> {
    match selector {
        CurrentSignerEvidenceSelector::AccountDevice {
            account_id,
            device_id,
        } => {
            let facet = super::device_signing::resolve_device_signing_directory_facet(
                state,
                account_id.principal_id.as_str(),
                device_id.as_str(),
            )
            .await;
            let record = super::keys::attested_device_record(
                state,
                account_id,
                device_id,
                facet,
                BTreeMap::new(),
            )
            .await?;
            Ok(record.map(|record| CurrentSignerEvidence::AccountDevice {
                signer_evidence_ref: record.signer_evidence_ref,
                account_id: account_id.clone(),
                device_id: device_id.clone(),
                device_projection_attestation: record.device_projection_attestation,
            }))
        }
        CurrentSignerEvidenceSelector::Agent {
            actor,
            verification_method,
        } => {
            let selector = AgentSignerEvidenceQuerySelector::CurrentAdmission {
                actor: actor.clone(),
                verification_method: verification_method.clone(),
            };
            match super::agents::evidence::current_authenticated_agent_signer_evidence(
                state, &selector,
            )
            .await
            {
                Ok((root, dependencies)) => {
                    let compact = CompactAgentSignerResolutionEvidence::from_full(
                        &root,
                        &request.known_agent_state_digests,
                    )
                    .map_err(|error| AppError::internal(error.to_string()))?;
                    let mut missing = Vec::new();
                    for dependency in dependencies {
                        let reference = dependency
                            .evidence_ref()
                            .map_err(|error| AppError::internal(error.to_string()))?;
                        if !request.known_signer_evidence_refs.contains(&reference) {
                            missing.push(dependency);
                        }
                    }
                    Ok(Some(CurrentSignerEvidence::Agent {
                        actor: actor.clone(),
                        verification_method: verification_method.clone(),
                        authenticated_signer_evidence: compact,
                        dependencies: missing,
                    }))
                }
                Err(reason) => {
                    tracing::warn!(
                        ?reason,
                        "current Agent Signal evidence unavailable at authority"
                    );
                    Ok(None)
                }
            }
        }
    }
}

async fn proxy_peer_query(
    state: &AppState,
    request: &CurrentSignerEvidenceQueryRequestBody,
    target_id: &DidCoreId,
) -> Result<CurrentSignerEvidenceQueryOutcome, AppError> {
    let route = crate::routing::federation::resolved_peer_target(
        state,
        target_id.as_str(),
        "station",
        false,
    )
    .await
    .map_err(|_| AppError::not_found("current signer evidence is unavailable"))?;
    let target = format!("{}{}", route.base_url.trim_end_matches('/'), PEER_PATH);
    let body = arkret_canonical::canonical_json_bytes(request)
        .map_err(|error| AppError::internal(format!("canonical evidence request: {error}")))?;
    let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &target,
        "current signer evidence peer query",
        state.config().development_mode,
        Duration::from_secs(10),
    )
    .map_err(|_| AppError::not_found("current signer evidence is unavailable"))?;
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "content-digest",
        &crate::routing::federation::outbox::content_digest_header_value(&body),
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "source-service-id",
        state.service_id(),
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "destination-service-id",
        target_id.as_str(),
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "source-trust-domain",
        state.config().trust_domain.as_str(),
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "destination-trust-domain",
        &route.trust_domain,
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "arkret-operation",
        "ak.peer.current_signer_evidence.read.resolve.v1",
    );
    let headers = crate::routing::federation::outbox::rfc9421_sign(state, headers, "POST", &target);
    let response = client
        .post(url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|_| AppError::not_found("current signer evidence is unavailable"))?;
    if !response.status().is_success() {
        return Err(AppError::not_found(
            "current signer evidence is unavailable",
        ));
    }
    let mut response = response;
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| AppError::not_found("current signer evidence unavailable"))?
    {
        if bytes.len().saturating_add(chunk.len()) > 1024 * 1024 {
            return Err(AppError::from_rejection(
                arkret_wire::ErrorCode::LimitExceeded,
                "peer signer response exceeds budget",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| AppError::not_found("current signer evidence is unavailable"))
}

#[cfg(test)]
mod tests {
    fn signed_device_projection() -> (
        arkret_models_crypto::DeviceProjectionAttestation,
        arkret_identity::DidDocument,
        chrono::DateTime<chrono::Utc>,
        [u8; 32],
    ) {
        let station_did = arkret_wire::Did::new("did:web:projection-station.example").unwrap();
        let method = arkret_wire::DidUrl::new(format!("{station_did}#assertion")).unwrap();
        let account = arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:projection-principal.example").unwrap(),
            arkret_wire::project_did_to_core_id(&station_did).unwrap(),
        );
        let device =
            arkret_wire::DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap();
        let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[43u8; 32]);
        let public_key = arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase(
            signing_key.verifying_key().as_bytes(),
        );
        let attestation = arkret_signatures::device_projection::sign_device_projection_attestation(
            arkret_models_crypto::DeviceProjectionAttestationCore {
                account_id: account.clone(),
                device_id: device.clone(),
                device_signing_key_did: arkret_wire::DidKey::new(format!("did:key:{public_key}"))
                    .unwrap(),
                hpke_key: arkret_wire::NonEmptyString::new("hpke-test").unwrap(),
                device_authorize_event_id: arkret_wire::EventId::new(
                    "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e",
                )
                .unwrap(),
                authorized_generation_ref: 7,
                device_status: arkret_models_crypto::DeviceStatus::Active,
                attested_at: now,
                expires_at: now + chrono::Duration::minutes(5),
            },
            method.clone(),
            &signing_key,
        )
        .unwrap();
        let document: arkret_identity::DidDocument = serde_json::from_value(serde_json::json!({
            "id": station_did,
            "verificationMethod": [{
                "id": method,
                "controller": station_did,
                "type": "Multikey",
                "publicKeyMultibase": public_key
            }]
        }))
        .unwrap();
        (
            attestation,
            document,
            now,
            signing_key.verifying_key().to_bytes(),
        )
    }

    fn self_device_fixture() -> (
        super::CurrentSignerEvidence,
        arkret_models_identity::AuthenticatedSignerResolutionEvidence,
        arkret_identity::DidDocument,
        chrono::DateTime<chrono::Utc>,
        [u8; 32],
    ) {
        let (attestation, mut document, now, bytes) = signed_device_projection();
        document.raw_properties.insert(
            "assertionMethod".to_owned(),
            serde_json::json!(["#assertion"]),
        );
        let core = &attestation.attestation;
        let root = arkret_models_identity::AuthenticatedSignerResolutionEvidence::AccountDevice {
            signer_id: core.account_id.principal_id.clone(),
            verification_method: arkret_wire::DidUrl::new(format!(
                "did:web:projection-principal.example#{}",
                core.device_id
            ))
            .unwrap(),
            device_projection_attestation: attestation.clone(),
            attester_signer_evidence_ref: arkret_wire::SignerEvidenceRef::new(format!(
                "ak:signer_evidence:sha256:{}",
                "a".repeat(64)
            ))
            .unwrap(),
        };
        let item = super::CurrentSignerEvidence::AccountDevice {
            account_id: core.account_id.clone(),
            device_id: core.device_id.clone(),
            device_projection_attestation: attestation,
            signer_evidence_ref: root.evidence_ref().unwrap(),
        };
        (item, root, document, now, bytes)
    }

    #[test]
    fn self_device_result_verifies_real_signature_before_extracting_exact_key() {
        let (item, root, document, now, expected) = self_device_fixture();
        let key = super::device_self_result_key(&item, &root, &document, now).unwrap();
        assert_eq!(
            arkret_canonical::base64url_decode(key.public_key_b64u.as_str()).unwrap(),
            expected
        );
        assert_eq!(&key.verification_method, root.verification_method());
        assert!(
            super::device_self_result_key(
                &item,
                &root,
                &document,
                now + chrono::Duration::minutes(5)
            )
            .is_err()
        );
        let mut wrong_document = document.clone();
        let another_key = ed25519_dalek::SigningKey::from_bytes(&[57u8; 32]);
        let encoded = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            another_key.verifying_key().as_bytes(),
        );
        let mut json = serde_json::to_value(&wrong_document).unwrap();
        json["verificationMethod"][0]["publicKeyMultibase"] = serde_json::json!(encoded);
        wrong_document = serde_json::from_value(json).unwrap();
        assert!(super::device_self_result_key(&item, &root, &wrong_document, now).is_err());
    }

    #[test]
    fn self_device_result_rejects_forged_projection_and_cross_station_root() {
        let (mut item, mut root, document, now, _) = self_device_fixture();
        if let arkret_models_identity::AuthenticatedSignerResolutionEvidence::AccountDevice {
            device_projection_attestation,
            ..
        } = &mut root
        {
            device_projection_attestation
                .attestation
                .authorized_generation_ref += 1;
        }
        if let super::CurrentSignerEvidence::AccountDevice {
            device_projection_attestation,
            signer_evidence_ref,
            ..
        } = &mut item
        {
            device_projection_attestation
                .attestation
                .authorized_generation_ref += 1;
            *signer_evidence_ref = root.evidence_ref().unwrap();
        }
        // The modified root reference matches: rejection must still reach the
        // original real signature instead of treating a hash as authority.
        assert!(super::device_self_result_key(&item, &root, &document, now).is_err());
        let (mut item, root, document, now, _) = self_device_fixture();
        if let super::CurrentSignerEvidence::AccountDevice { account_id, .. } = &mut item {
            account_id.station_id =
                arkret_wire::DidCoreId::new("ak:did_core:web:other.example").unwrap();
        }
        assert!(super::device_self_result_key(&item, &root, &document, now).is_err());
        let (item, mut root, document, now, _) = self_device_fixture();
        if let arkret_models_identity::AuthenticatedSignerResolutionEvidence::AccountDevice {
            verification_method,
            ..
        } = &mut root
        {
            *verification_method =
                arkret_wire::DidUrl::new("did:web:other.example#wrong-device").unwrap();
        }
        assert!(super::device_self_result_key(&item, &root, &document, now).is_err());
    }

    #[test]
    fn current_device_projection_requires_origin_assertion_key_and_valid_signature() {
        let (attestation, mut document, now, _) = signed_device_projection();
        assert!(super::verify_current_device_projection(&attestation, &document, now).is_err());
        document.raw_properties.insert(
            "assertionMethod".to_owned(),
            serde_json::json!(["#another-key"]),
        );
        assert!(super::verify_current_device_projection(&attestation, &document, now).is_err());
        document.raw_properties.insert(
            "assertionMethod".to_owned(),
            serde_json::json!(["#assertion"]),
        );
        assert!(super::verify_current_device_projection(&attestation, &document, now).is_ok());
        assert!(
            super::verify_current_device_projection(
                &attestation,
                &document,
                now + chrono::Duration::minutes(5)
            )
            .is_err()
        );
        let mut tampered = attestation.clone();
        tampered.attestation.authorized_generation_ref += 1;
        assert!(super::verify_current_device_projection(&tampered, &document, now).is_err());
        let mut foreign = attestation;
        foreign.attestation.account_id.station_id =
            arkret_wire::DidCoreId::new("ak:did_core:web:foreign.example").unwrap();
        assert!(super::verify_current_device_projection(&foreign, &document, now).is_err());
    }
}
