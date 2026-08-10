use arkret_models_discovery::ServiceDescribe;
use arkret_models_identity::service_identity::CanonicalServiceUrl;
use arkret_models_identity::{
    AuthenticatedServiceResolution, DidDocument, ResolutionDidBindingEvidenceKind,
    ResolutionDidBindingEvidenceReceipt, ResolutionDidBindingMethodProof,
    ResolutionDidBindingMethodProofKind, ResolutionMethodEvidenceBoundary,
    ResolutionMethodHistoryEvidence, ServiceResolutionRecord, ServiceResolutionRecordCore,
};
use arkret_wire::{DidUrl, Hash, ServiceId};
use chrono::{Duration, Utc};
use salvo::oapi::extract::PathParam;
use salvo::prelude::*;
use soland_http::error::{AppError, ErrorCode};

use crate::state::AppState;
use crate::{JsonResult, json_ok};

const RESOLUTION_REFRESH_SECONDS: i64 = 300;
const RESOLUTION_TTL_SECONDS: i64 = 600;
const MAX_RESOLUTION_CAS_ATTEMPTS: usize = 8;

pub(super) fn open_router() -> Router {
    Router::with_path("services/{service_id}/resolution").get(open_service_resolution)
}

fn canonical_digest(value: &impl serde::Serialize) -> Result<Hash, AppError> {
    Hash::new(
        arkret_canonical::canonical_sha256(value)
            .map_err(|error| AppError::internal(format!("canonical digest failed: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("canonical digest is invalid: {error}")))
}

pub(crate) fn service_ids(state: &AppState) -> Result<(ServiceId, arkret_wire::FullId), AppError> {
    let commitment = state.service_resolution_commitment();
    let core = arkret_wire::project_full_id_to_core_id(&commitment.full_id).map_err(|error| {
        AppError::new(
            ErrorCode::ServiceIdentityUnavailable,
            format!("service FullId cannot be projected: {error}"),
        )
    })?;
    Ok((ServiceId::from(core), commitment.full_id.clone()))
}

fn current_record_url(state: &AppState, service_id: &ServiceId) -> Result<String, AppError> {
    let base = canonical_base_url(state)?;
    Ok(format!(
        "{base}_arkret/open/services/{}/resolution",
        percent_encode_path_segment(service_id.as_str())
    ))
}

fn canonical_base_url(state: &AppState) -> Result<String, AppError> {
    let url = CanonicalServiceUrl::canonicalize(&state.config().public_base_url)
        .map_err(|error| AppError::internal(format!("public base URL is invalid: {error}")))?;
    if !state.config().development_mode {
        url.require_https().map_err(|error| {
            AppError::new(ErrorCode::ServiceIdentityConflict, error.to_string())
        })?;
    }
    Ok(url.to_string())
}

fn percent_encode_path_segment(value: &str) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            write!(&mut encoded, "%{byte:02X}").expect("writing to a String cannot fail");
        }
    }
    encoded
}

fn route_binding_digest(description: &ServiceDescribe) -> Result<Hash, AppError> {
    #[derive(serde::Serialize)]
    struct RouteBindingProjection<'a> {
        service_id: &'a ServiceId,
        service_kind: &'a arkret_wire::ServiceKind,
        service_resolution: &'a arkret_models_identity::ResolutionCommitment,
        http_json_base_url: String,
    }

    let binding_base = description
        .supported_bindings
        .iter()
        .find(|binding| binding.kind == arkret_wire::BindingKind::HttpJson)
        .and_then(|binding| binding.base_url.as_deref())
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::ServiceIdentityConflict,
                "ServiceDescribe has no http_json base URL",
            )
        })?;
    let http_json_base_url = CanonicalServiceUrl::canonicalize(binding_base)
        .map_err(|error| {
            AppError::new(
                ErrorCode::ServiceIdentityConflict,
                format!("ServiceDescribe http_json base URL is invalid: {error}"),
            )
        })?
        .to_string();
    canonical_digest(&RouteBindingProjection {
        service_id: &description.service_id,
        service_kind: &description.service_kind,
        service_resolution: &description.service_resolution,
        http_json_base_url,
    })
}

fn webvh_resolution_event_ref(log_head_digest: &str) -> Result<String, AppError> {
    let digest = log_head_digest.strip_prefix("sha256:").ok_or_else(|| {
        AppError::new(
            ErrorCode::ServiceIdentityConflict,
            "service WebVH log head is not a sha256 digest",
        )
    })?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppError::new(
            ErrorCode::ServiceIdentityConflict,
            "service WebVH log head is not a 32-byte hex digest",
        ));
    }
    Ok(format!(
        "did-webvh-entry-sha256:{}",
        digest.to_ascii_lowercase()
    ))
}

pub(crate) fn service_assertion_method(
    state: &AppState,
    stored: &arkret_identity::service_identity::StoredServiceIdentity,
) -> Result<DidUrl, AppError> {
    let expected_multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        state.notary_verifying_key().as_bytes(),
    );
    let method = stored
        .did_document
        .verification_method
        .iter()
        .find(|method| {
            method.public_key_multibase == expected_multibase
                && stored.did_document.assertion_method.contains(&method.id)
        })
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::ServiceIdentityUnavailable,
                "runtime signer is not a current service assertion method",
            )
        })?;
    DidUrl::new(method.id.clone())
        .map_err(|error| AppError::internal(format!("service assertion method invalid: {error}")))
}

pub(crate) async fn ensure_current_record(
    state: &AppState,
    description: &ServiceDescribe,
) -> Result<ServiceResolutionRecord, AppError> {
    let (service_id, full_id) = service_ids(state)?;
    let commitment = state.service_resolution_commitment();
    if description.service_id != service_id || description.service_resolution != *commitment {
        return Err(AppError::new(
            ErrorCode::ServiceIdentityConflict,
            "ServiceDescribe does not carry the runtime service resolution commitment",
        ));
    }
    let stored = state
        .stored_service_identity()
        .await
        .map_err(|error| AppError::new(ErrorCode::ServiceIdentityUnavailable, error))?;
    if stored.identity.service_id != service_id
        || stored.identity.full_id != full_id
        || stored.identity.version_id != commitment.version_id
        || stored.registration_receipt.log_head_digest != commitment.method_history_head
    {
        return Err(AppError::new(
            ErrorCode::ServiceIdentityConflict,
            "durable service identity does not match the runtime resolution commitment",
        ));
    }
    let describe_digest = route_binding_digest(description)?;
    let base_url = canonical_base_url(state)?;
    let record_url = current_record_url(state, &service_id)?;
    let now = chrono::DateTime::<Utc>::from_timestamp_millis(Utc::now().timestamp_millis())
        .ok_or_else(|| AppError::internal("current service resolution timestamp is invalid"))?;

    for _ in 0..MAX_RESOLUTION_CAS_ATTEMPTS {
        let current = state
            .current_signed_service_resolution()
            .await
            .map_err(|error| {
                AppError::internal(format!("service resolution lookup failed: {error}"))
            })?;
        if let Some(record) = current.as_ref()
            && record.record.service_id == service_id
            && record.record.full_id == full_id
            && record.record.method_history_head == commitment.method_history_head
            && record.record.version_id == commitment.version_id
            && record.record.current_record_url == record_url
            && record.record.base_url == base_url
            && record.record.describe_digest == describe_digest
            && record.record.refresh_after > now
            && record.record.expires_at > now
        {
            return Ok(record.clone());
        }
        if current.as_ref().is_some_and(|record| {
            record.record.service_id != service_id || record.record.full_id != full_id
        }) {
            return Err(AppError::new(
                ErrorCode::ServiceIdentityConflict,
                "durable service resolution belongs to another service identity",
            ));
        }
        let predecessor_digest = current.as_ref().map(canonical_digest).transpose()?;
        let record_sequence = current
            .as_ref()
            .map_or(0, |record| record.record.record_sequence.saturating_add(1));
        let core = ServiceResolutionRecordCore {
            service_id: service_id.clone(),
            service_kind: arkret_wire::ServiceKind::PrincipalServer
                .as_str()
                .to_owned(),
            full_id: full_id.clone(),
            method_history_head: commitment.method_history_head.clone(),
            version_id: commitment.version_id.clone(),
            resolution_event_ref: webvh_resolution_event_ref(
                &stored.registration_receipt.log_head_digest,
            )?,
            record_sequence,
            previous_record_digest: predecessor_digest.clone(),
            current_record_url: record_url.clone(),
            base_url: base_url.clone(),
            describe_digest: describe_digest.clone(),
            issued_at: now,
            refresh_after: now + Duration::seconds(RESOLUTION_REFRESH_SECONDS),
            expires_at: now + Duration::seconds(RESOLUTION_TTL_SECONDS),
        };
        let record = arkret_signatures::service_resolution::sign_service_resolution_record(
            core,
            service_assertion_method(state, &stored)?,
            state.notary_signing_key().as_ref(),
        )
        .map_err(|error| {
            AppError::internal(format!("service resolution signing failed: {error}"))
        })?;
        if state
            .compare_and_set_signed_service_resolution(predecessor_digest.as_ref(), record.clone())
            .await
            .map_err(|error| {
                AppError::internal(format!("service resolution persist failed: {error}"))
            })?
        {
            return Ok(record);
        }
    }
    Err(AppError::new(
        ErrorCode::CasConflict,
        "service resolution changed concurrently",
    ))
}

pub(crate) async fn authenticated_current_resolution(
    state: &AppState,
    description: &ServiceDescribe,
) -> Result<AuthenticatedServiceResolution, AppError> {
    let record = ensure_current_record(state, description).await?;
    let stored = state
        .stored_service_identity()
        .await
        .map_err(|error| AppError::new(ErrorCode::ServiceIdentityUnavailable, error))?;
    let normalized_did_document: DidDocument = serde_json::from_value(
        serde_json::to_value(&stored.did_document)
            .map_err(|error| AppError::internal(format!("service DID encode failed: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("service DID normalize failed: {error}")))?;
    let document_digest = arkret_identity::document_canonical_digest(&normalized_did_document)
        .map_err(|error| AppError::internal(format!("service DID digest failed: {error}")))?;
    let witness_proofs_digest = canonical_digest(&Vec::<serde_json::Value>::new())?;
    let commitment = state.service_resolution_commitment();
    let boundary = ResolutionMethodEvidenceBoundary {
        from_method_history_head: commitment.method_history_head.clone(),
        from_version_id: commitment.version_id.clone(),
        to_method_history_head: commitment.method_history_head.clone(),
        to_version_id: commitment.version_id.clone(),
    };
    let method_history_evidence = ResolutionMethodHistoryEvidence::WebvhLog {
        adapter_version: "did:webvh:1.0".to_owned(),
        boundary,
        evidence: ResolutionDidBindingEvidenceReceipt {
            kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
            method: "webvh".to_owned(),
            document_digest,
            method_proofs: vec![ResolutionDidBindingMethodProof {
                kind: ResolutionDidBindingMethodProofKind::WebvhLog,
                history_head: commitment.method_history_head.clone(),
                witnesses: Vec::new(),
                witness_proofs_digest,
            }],
        },
    };
    let authenticated = AuthenticatedServiceResolution {
        service_resolution_record: record,
        method_history_evidence,
        normalized_did_document,
    };
    let (service_id, _) = service_ids(state)?;
    arkret_signatures::service_resolution::verify_authenticated_service_resolution(
        &authenticated,
        &service_id,
        Utc::now(),
    )
    .map_err(|error| {
        AppError::internal(format!("produced service resolution is invalid: {error}"))
    })?;
    Ok(authenticated)
}

#[salvo::oapi::endpoint(operation_id = "ak.open.service.read.resolution", tags("identity"))]
async fn open_service_resolution(
    service_id: PathParam<String>,
    depot: &mut Depot,
) -> JsonResult<ServiceResolutionRecord> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let requested = ServiceId::new(service_id.into_inner())
        .map_err(|_| AppError::not_found("service resolution not found"))?;
    let (current, _) = service_ids(state)?;
    if requested != current {
        return Err(AppError::not_found("service resolution not found"));
    }
    let description = super::describe::build_server_description(state);
    json_ok(ensure_current_record(state, &description).await?)
}
