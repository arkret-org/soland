//! Reusable current signer evidence proxy and peer authority endpoint.

use std::collections::BTreeMap;
use std::time::Duration;

use arkret_models_collaboration::{
    CompactAgentSignerResolutionEvidence, CurrentSignerEvidenceItem,
    CurrentSignerEvidenceQueryOutcome, CurrentSignerEvidenceQueryRequestBody,
    CurrentSignerEvidenceResponseCore, CurrentSignerEvidenceSelector,
};
use arkret_models_identity::agent_signer_evidence::AgentSignerEvidenceQuerySelector;
use arkret_wire::DidCoreId;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};

use super::AuthArgs;
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
        .validate_transport_for_request(&body)
        .map_err(|error| {
            AppError::internal(format!("authority returned invalid evidence: {error}"))
        })?;
    if target != state.service_core_id() {
        validate_remote_device_projections(state, &outcome).await?;
    }
    json_ok(outcome)
}

async fn validate_remote_device_projections(
    state: &AppState,
    outcome: &CurrentSignerEvidenceQueryOutcome,
) -> Result<(), AppError> {
    for item in &outcome.response.evidences {
        let CurrentSignerEvidenceItem::AccountDevice {
            account_id,
            device_id,
            device_projection_attestation: attestation,
            ..
        } = item
        else {
            continue;
        };
        let unavailable = || AppError::not_found("current signer evidence is unavailable");
        if &attestation.attestation.account_id != account_id
            || &attestation.attestation.device_id != device_id
        {
            return Err(unavailable());
        }
        let method = &attestation.proof.verification_method;
        let did =
            arkret_identity::verification_method_did(method.as_str()).map_err(|_| unavailable())?;
        if arkret_wire::project_did_to_core_id(&did).map_err(|_| unavailable())?
            != account_id.station_id
        {
            return Err(unavailable());
        }
        let current = state
            .dids()
            .resolve_current_service_did(&did)
            .await
            .map_err(|_| unavailable())?;
        verify_current_device_projection(attestation, &current.document, chrono::Utc::now())
            .map_err(|_| unavailable())?;
    }
    Ok(())
}

fn verify_current_device_projection(
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
    evidences: Vec<CurrentSignerEvidenceItem>,
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
                    Ok(Some(CurrentSignerEvidenceItem::Agent {
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

#[cfg(test)]
mod tests {
    #[test]
    fn current_device_projection_requires_origin_assertion_key_and_valid_signature() {
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
        let mut document: arkret_identity::DidDocument =
            serde_json::from_value(serde_json::json!({
                "id": station_did,
                "verificationMethod": [{
                    "id": method,
                    "controller": station_did,
                    "type": "Multikey",
                    "publicKeyMultibase": public_key
                }]
            }))
            .unwrap();
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
