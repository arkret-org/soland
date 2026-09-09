//! Request-bound current signer evidence proxy and peer authority endpoint.

use std::collections::BTreeMap;
use std::time::Duration;

use arkret_models_collaboration::{
    CURRENT_SIGNER_EVIDENCE_MAX_LIFETIME_SECONDS, CurrentSignerEvidenceItem,
    CurrentSignerEvidenceQueryOutcome, CurrentSignerEvidenceQueryRequestBody,
    CurrentSignerEvidenceResponseCore, CurrentSignerEvidenceSelector,
};
use arkret_models_identity::agent_signer_evidence::AgentSignerEvidenceQuerySelector;
use arkret_wire::DidCoreId;
use chrono::Utc;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};

use super::{AuthArgs, now};
use crate::state::AppState;

const PEER_PATH: &str = "/_arkret/peer/current-signer-evidence/query";

pub(crate) fn self_router() -> Router {
    Router::with_path("current-signer-evidence/query").post(self_query)
}

pub(crate) fn peer_router() -> Router {
    Router::with_path("current-signer-evidence/query").post(peer_query)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.current_signer_evidence.read.resolve",
    tags("identity")
)]
async fn self_query(
    aa: AuthArgs,
    body: JsonBody<CurrentSignerEvidenceQueryRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CurrentSignerEvidenceQueryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    body.validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let actor = super::session_actor::validated_session_actor(state, &session).await?;
    if actor.as_account_id() != Some(&body.recipient_account_id)
        || body.recipient_account_id.station_id != state.service_core_id()
    {
        return Err(AppError::not_found(
            "current signer evidence is unavailable",
        ));
    }
    let target = body
        .target_station_id()
        .map_err(|error| AppError::param_invalid(error.to_string()))?
        .clone();
    let outcome = if target == state.service_core_id() {
        issue_authority_outcome(state, &body, state.service_core_id()).await?
    } else {
        proxy_peer_query(state, &body, &target).await?
    };
    outcome
        .validate_for_request(&body, Utc::now())
        .map_err(|error| {
            AppError::internal(format!("authority returned invalid evidence: {error}"))
        })?;
    let key = crate::jws_verify::resolve_ed25519_pubkey_async(
        state,
        outcome.proof.verification_method.as_str(),
    )
    .await
    .map_err(|_| AppError::not_found("current signer evidence is unavailable"))?;
    arkret_signatures::current_signer_evidence::verify_current_signer_evidence_outcome(
        &outcome,
        &key,
        Utc::now(),
    )
    .map_err(|_| AppError::not_found("current signer evidence is unavailable"))?;
    json_ok(outcome)
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
        return json_ok(opaque_empty_outcome(state, &body).await?);
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
            if let Some(item) = issue_selector(state, request, selector, &verifier_id).await? {
                evidence.push(item);
            }
        }
    }
    signed_outcome(state, request, evidence)
}

async fn opaque_empty_outcome(
    state: &AppState,
    request: &CurrentSignerEvidenceQueryRequestBody,
) -> Result<CurrentSignerEvidenceQueryOutcome, AppError> {
    signed_outcome(state, request, Vec::new())
}

fn signed_outcome(
    state: &AppState,
    request: &CurrentSignerEvidenceQueryRequestBody,
    mut evidences: Vec<CurrentSignerEvidenceItem>,
) -> Result<CurrentSignerEvidenceQueryOutcome, AppError> {
    let issued_at = now();
    // Never extend an already-expired inner authorization to make the outer
    // response look live.  Opaque omission preserves the same response shape
    // as every other unavailable/unauthorized selector.
    evidences.retain(|item| evidence_item_expiry(item).is_some_and(|expiry| expiry > issued_at));
    let mut expires_at =
        issued_at + chrono::Duration::seconds(CURRENT_SIGNER_EVIDENCE_MAX_LIFETIME_SECONDS);
    for item in &evidences {
        // The retain above established that every item has a live expiry.
        expires_at = expires_at.min(evidence_item_expiry(item).expect("retained live evidence"));
    }
    let response = CurrentSignerEvidenceResponseCore {
        request_id: request.request_id.clone(),
        realm_id: request.realm_id.clone(),
        operation_id: request.operation_id,
        request_digest: request.request_digest.clone(),
        recipient_account_id: request.recipient_account_id.clone(),
        challenge: request.challenge.clone(),
        issuer_id: state.service_core_id(),
        issued_at,
        expires_at,
        evidences,
    };
    let verification_method = state
        .service_verification_method("notary-key")
        .map_err(|error| AppError::internal(format!("service notary method: {error}")))?;
    let outcome = arkret_signatures::current_signer_evidence::sign_current_signer_evidence_outcome(
        response,
        verification_method,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|error| AppError::internal(format!("sign current signer evidence: {error}")))?;
    Ok(outcome)
}

fn evidence_item_expiry(item: &CurrentSignerEvidenceItem) -> Option<chrono::DateTime<Utc>> {
    match item {
        CurrentSignerEvidenceItem::AccountDevice {
            device_projection_attestation,
            ..
        } => Some(device_projection_attestation.attestation.expires_at),
        CurrentSignerEvidenceItem::Agent {
            authenticated_signer_evidence,
            ..
        } => match authenticated_signer_evidence {
            arkret_models_identity::AuthenticatedSignerResolutionEvidence::Agent {
                agent_signer_evidence,
                ..
            } => match agent_signer_evidence.as_ref() {
                arkret_models_identity::agent_signer_evidence::AgentSignerEvidence::CurrentAdmission {
                    outer_attestation,
                    ..
                } => Some(outer_attestation.expires_at),
                arkret_models_identity::agent_signer_evidence::AgentSignerEvidence::HistoricalEvent {
                    ..
                } => None,
            },
            _ => None,
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
    verifier_id: &DidCoreId,
) -> Result<Option<CurrentSignerEvidenceItem>, AppError> {
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
            Ok(
                record.map(|record| CurrentSignerEvidenceItem::AccountDevice {
                    signer_evidence_ref: record.signer_evidence_ref,
                    account_id: account_id.clone(),
                    device_id: device_id.clone(),
                    device_projection_attestation: record.device_projection_attestation,
                }),
            )
        }
        CurrentSignerEvidenceSelector::Agent {
            actor,
            verification_method,
        } => {
            let selector = AgentSignerEvidenceQuerySelector::CurrentAdmission {
                agent_id: actor.signing_principal_id().clone(),
                verification_method: verification_method.clone(),
                operation_id: request
                    .agent_observation_operation_id()
                    .map_err(|error| AppError::internal(error.to_string()))?,
                request_digest: request.request_digest.clone(),
                verifier_id: verifier_id.clone(),
                audience: request.recipient_account_id.principal_id.clone(),
                challenge: request.challenge.clone(),
            };
            match super::agents::evidence::issue_current_authenticated_agent_signer_evidence(
                state, &selector,
            )
            .await
            {
                Ok((root, dependencies)) => Ok(Some(CurrentSignerEvidenceItem::Agent {
                    actor: actor.clone(),
                    verification_method: verification_method.clone(),
                    authenticated_signer_evidence: root,
                    dependencies,
                })),
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
    let bytes = response
        .bytes()
        .await
        .map_err(|_| AppError::not_found("current signer evidence is unavailable"))?;
    if bytes.len() > 1024 * 1024 {
        return Err(AppError::not_found(
            "current signer evidence is unavailable",
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| AppError::not_found("current signer evidence is unavailable"))
}
