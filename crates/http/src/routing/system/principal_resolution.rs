use arkret_models_identity::{
    DidDocument, PrincipalResolutionEvidence, PrincipalResolutionProjection,
    ResolutionDidBindingEvidenceKind, ResolutionDidBindingEvidenceReceipt,
    ResolutionDidBindingMethodProof, ResolutionDidBindingMethodProofKind,
    ResolutionMethodEvidenceBoundary, ResolutionMethodHistoryEvidence,
};
use arkret_wire::{DidCoreId, DidFullId, Hash, PrincipalAuthorityKey};
use salvo::oapi::extract::{PathParam, QueryParam};
use salvo::prelude::*;
use soland_http::error::{AppError, ErrorCode};
use soland_services::identity::PinnedDidVersionStatus;

use crate::state::AppState;
use crate::{JsonResult, json_ok};

pub(super) fn open_router() -> Router {
    Router::with_path("principals/{principal_id}/resolution").get(open_principal_resolution)
}

#[salvo::oapi::endpoint(operation_id = "ak.open.identity.read.resolution", tags("identity"))]
async fn open_principal_resolution(
    principal_id: PathParam<String>,
    principal_server_id: QueryParam<String, true>,
    depot: &mut Depot,
) -> JsonResult<PrincipalResolutionEvidence> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let principal_id = DidCoreId::new(principal_id.into_inner())
        .map_err(|_| AppError::not_found("principal resolution not found"))?;
    let principal_server_id = DidCoreId::new(principal_server_id.into_inner())
        .map_err(|_| AppError::param_invalid("invalid principal_server_id"))?;
    let authority = PrincipalAuthorityKey::new(principal_id.clone(), principal_server_id);
    let record = state
        .persistence()
        .principal_resolution_by_authority_key(&authority)
        .await
        .map_err(|error| AppError::internal(format!("principal resolution store failed: {error}")))?
        .ok_or_else(|| AppError::not_found("principal resolution not found"))?;
    if record.authority_key != authority {
        return Err(AppError::not_found("principal resolution not found"));
    }

    let method_history_evidence =
        principal_method_history_evidence(state, &record.projection).await?;
    let evidence = PrincipalResolutionEvidence {
        principal_id,
        authority,
        current_resolution: record.projection,
        method_history_evidence: Some(method_history_evidence),
    };
    evidence.validate_authority_binding().map_err(|error| {
        AppError::internal(format!(
            "principal resolution authority binding is invalid: {error}"
        ))
    })?;
    json_ok(evidence)
}

async fn principal_method_history_evidence(
    state: &AppState,
    projection: &PrincipalResolutionProjection,
) -> Result<ResolutionMethodHistoryEvidence, AppError> {
    let full_id = DidFullId::new(projection.full_id.to_string()).map_err(|error| {
        AppError::internal(format!("stored principal full_id is invalid: {error}"))
    })?;
    let boundary = ResolutionMethodEvidenceBoundary {
        from_method_history_head: projection.method_history_head.clone(),
        from_version_id: projection.version_id.clone(),
        to_method_history_head: projection.method_history_head.clone(),
        to_version_id: projection.version_id.clone(),
    };
    match full_id.method() {
        "webvh" => {
            let history_head =
                Hash::new(projection.method_history_head.clone()).map_err(|error| {
                    AppError::internal(format!(
                        "stored did:webvh method-history head is invalid: {error}"
                    ))
                })?;
            let pinned = state
                .dids()
                .resolve_pinned_webvh_state(&full_id, &projection.version_id, &history_head)
                .await
                .map_err(|error| {
                    AppError::new(
                        ErrorCode::TemporarilyUnavailable,
                        format!("current principal did:webvh history is unverifiable: {error}"),
                    )
                })?;
            if pinned.status != PinnedDidVersionStatus::Current {
                return Err(AppError::new(
                    ErrorCode::TemporarilyUnavailable,
                    "principal did:webvh commitment is not the current verified method head",
                ));
            }
            let document: DidDocument =
                serde_json::from_value(pinned.document).map_err(|error| {
                    AppError::internal(format!(
                        "resolved principal DID document is invalid: {error}"
                    ))
                })?;
            let document_digest = canonical_document_digest(&document)?;
            let witness_proofs_digest = canonical_digest(&Vec::<serde_json::Value>::new())?;
            Ok(ResolutionMethodHistoryEvidence::WebvhLog {
                adapter_version: "did:webvh:1.0".to_owned(),
                boundary,
                evidence: ResolutionDidBindingEvidenceReceipt {
                    kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                    method: "webvh".to_owned(),
                    document_digest,
                    method_proofs: vec![ResolutionDidBindingMethodProof {
                        kind: ResolutionDidBindingMethodProofKind::WebvhLog,
                        history_head: projection.method_history_head.clone(),
                        witnesses: Vec::new(),
                        witness_proofs_digest,
                    }],
                },
            })
        }
        "web" | "key" => {
            let resolved = state.dids().resolve_did(&full_id).await.map_err(|error| {
                AppError::new(
                    ErrorCode::TemporarilyUnavailable,
                    format!("current principal DID document is unverifiable: {error}"),
                )
            })?;
            let document: DidDocument =
                serde_json::from_value(serde_json::to_value(resolved).map_err(|error| {
                    AppError::internal(format!("resolved principal DID encode failed: {error}"))
                })?)
                .map_err(|error| {
                    AppError::internal(format!(
                        "resolved principal DID document is invalid: {error}"
                    ))
                })?;
            let document_digest = canonical_document_digest(&document)?;
            let evidence = ResolutionDidBindingEvidenceReceipt {
                kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                method: full_id.method().to_owned(),
                document_digest,
                method_proofs: Vec::new(),
            };
            if full_id.method() == "web" {
                validate_did_web_coordinates(projection, &evidence.document_digest)?;
                Ok(ResolutionMethodHistoryEvidence::DidWebDocument {
                    adapter_version: "did:web:1".to_owned(),
                    boundary,
                    evidence,
                })
            } else {
                validate_did_key_coordinates(projection, &projection.full_id)?;
                Ok(ResolutionMethodHistoryEvidence::DidKeyExpansion {
                    adapter_version: "did:key:1".to_owned(),
                    boundary,
                    evidence,
                })
            }
        }
        method => Err(AppError::new(
            ErrorCode::TemporarilyUnavailable,
            format!("principal DID method {method:?} has no active resolution evidence adapter"),
        )),
    }
}

fn canonical_document_digest(document: &DidDocument) -> Result<Hash, AppError> {
    canonical_digest(document)
}

fn canonical_digest(value: &impl serde::Serialize) -> Result<Hash, AppError> {
    Hash::new(
        arkret_canonical::canonical_sha256(value)
            .map_err(|error| AppError::internal(format!("canonical digest failed: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("canonical digest is invalid: {error}")))
}

fn validate_did_web_coordinates(
    projection: &PrincipalResolutionProjection,
    document_digest: &Hash,
) -> Result<(), AppError> {
    validate_synthetic_coordinates(
        projection,
        document_digest,
        "synthetic-jcs-sha256:",
        "did:web",
    )
}

fn validate_did_key_coordinates(
    projection: &PrincipalResolutionProjection,
    full_id: &DidFullId,
) -> Result<(), AppError> {
    let digest = Hash::new(arkret_canonical::sha256_digest(full_id.as_str().as_bytes()))
        .map_err(|error| AppError::internal(format!("did:key digest is invalid: {error}")))?;
    validate_synthetic_coordinates(projection, &digest, "synthetic-full-id-sha256:", "did:key")
}

fn validate_synthetic_coordinates(
    projection: &PrincipalResolutionProjection,
    digest: &Hash,
    version_prefix: &str,
    method: &str,
) -> Result<(), AppError> {
    let hex = digest
        .as_str()
        .strip_prefix("sha256:")
        .ok_or_else(|| AppError::internal("canonical SHA-256 digest lost its suite prefix"))?;
    if projection.method_history_head != digest.as_str()
        || projection.version_id != format!("{version_prefix}{hex}")
    {
        return Err(AppError::new(
            ErrorCode::TemporarilyUnavailable,
            format!("stored {method} commitment does not match the active adapter"),
        ));
    }
    Ok(())
}
