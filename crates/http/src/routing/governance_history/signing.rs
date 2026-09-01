//! Signing and canonicalization helpers for governance-history responses.

use super::*;

pub(super) fn sign_history_response_record(
    state: &AppState,
    sequence: u64,
    cursor: String,
    sent_at: chrono::DateTime<chrono::Utc>,
    source_record: HistoryKeyResponseSendRequest,
    manifest_admission: HistoryManifestAdmission,
    release_service_signer_evidence: &GovernanceDependency,
) -> Result<HistoryKeyResponseRecord, AppError> {
    let verification_method = history_service_verification_method(state)?;
    let (release_service_signer_evidence_ref, release_service_signer_evidence_digest) =
        history_release_service_signer_evidence_coordinates(release_service_signer_evidence)?;
    let temporary = HistoryKeyResponseRecord {
        sequence,
        cursor: cursor.clone(),
        record_digest: zero_sha256_hash()?,
        sent_at,
        release_attestation: None,
        manifest_admission: Some(manifest_admission.clone()),
        release_service_signer_evidence_ref: release_service_signer_evidence_ref.clone(),
        release_service_signer_evidence_digest: release_service_signer_evidence_digest.clone(),
        service_proof: placeholder_history_proof(verification_method.clone(), sent_at)?,
        source_record: source_record.clone(),
    };
    let record_digest = temporary
        .response_record_digest()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let record = HistoryKeyResponseRecord::build_signed_proof(
        verification_method,
        sent_at,
        |service_proof| HistoryKeyResponseRecord {
            sequence,
            cursor: cursor.clone(),
            record_digest: record_digest.clone(),
            sent_at,
            release_attestation: None,
            manifest_admission: Some(manifest_admission.clone()),
            release_service_signer_evidence_ref: release_service_signer_evidence_ref.clone(),
            release_service_signer_evidence_digest: release_service_signer_evidence_digest.clone(),
            service_proof,
            source_record: source_record.clone(),
        },
        |binding| history_service_jws(state, binding),
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    record
        .validate()
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(record)
}

pub(super) fn sign_history_chunk_response_record(
    state: &AppState,
    sequence: u64,
    cursor: String,
    sent_at: chrono::DateTime<chrono::Utc>,
    source_record: HistoryKeyResponseSendRequest,
    release_attestation: HistoryReleaseAttestation,
    release_service_signer_evidence: &GovernanceDependency,
) -> Result<HistoryKeyResponseRecord, AppError> {
    let verification_method = history_service_verification_method(state)?;
    let (release_service_signer_evidence_ref, release_service_signer_evidence_digest) =
        history_release_service_signer_evidence_coordinates(release_service_signer_evidence)?;
    let temporary = HistoryKeyResponseRecord {
        sequence,
        cursor: cursor.clone(),
        record_digest: zero_sha256_hash()?,
        sent_at,
        release_attestation: Some(release_attestation.clone()),
        manifest_admission: None,
        release_service_signer_evidence_ref: release_service_signer_evidence_ref.clone(),
        release_service_signer_evidence_digest: release_service_signer_evidence_digest.clone(),
        service_proof: placeholder_history_proof(verification_method.clone(), sent_at)?,
        source_record: source_record.clone(),
    };
    let record_digest = temporary
        .response_record_digest()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let record = HistoryKeyResponseRecord::build_signed_proof(
        verification_method,
        sent_at,
        |service_proof| HistoryKeyResponseRecord {
            sequence,
            cursor: cursor.clone(),
            record_digest: record_digest.clone(),
            sent_at,
            release_attestation: Some(release_attestation.clone()),
            manifest_admission: None,
            release_service_signer_evidence_ref: release_service_signer_evidence_ref.clone(),
            release_service_signer_evidence_digest: release_service_signer_evidence_digest.clone(),
            service_proof,
            source_record: source_record.clone(),
        },
        |binding| history_service_jws(state, binding),
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    record
        .validate()
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(record)
}

pub(super) async fn current_history_release_service_signer_evidence(
    state: &AppState,
    signed_at: chrono::DateTime<chrono::Utc>,
) -> Result<GovernanceDependency, AppError> {
    let resolution =
        crate::routing::system::service_resolution::current_authenticated_service_resolution(state)
            .await?;
    let service_id = resolution
        .service_resolution_record
        .record
        .service_id
        .clone();
    let evidence = arkret_identity::service_signer_evidence_from_authenticated_resolution(
        resolution,
        &service_id,
        signed_at,
    )
    .map_err(|error| {
        AppError::new(
            ErrorCode::ServiceIdentityUnavailable,
            format!("history release service signer evidence is unavailable: {error}"),
        )
    })?;
    let content_digest = evidence
        .canonical_sha256_digest()
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(
        GovernanceDependency::AuthenticatedSignerResolutionEvidence {
            selector: GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                content_digest,
            },
            authenticated_signer_resolution_evidence: Box::new(evidence),
        },
    )
}

pub(super) fn history_release_service_signer_evidence_coordinates(
    dependency: &GovernanceDependency,
) -> Result<(arkret_wire::SignerEvidenceRef, arkret_wire::Hash), AppError> {
    let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
        selector:
            GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence { content_digest },
        authenticated_signer_resolution_evidence,
    } = dependency
    else {
        return Err(AppError::internal(
            "history release signer evidence is not service-kind",
        ));
    };
    let evidence = authenticated_signer_resolution_evidence.as_ref();
    if !matches!(
        evidence,
        arkret_models_identity::AuthenticatedSignerResolutionEvidence::Service { .. }
    ) {
        return Err(AppError::internal(
            "history release signer evidence is not service-kind",
        ));
    }
    if evidence
        .canonical_sha256_digest()
        .map_err(|error| AppError::internal(error.to_string()))?
        != *content_digest
    {
        return Err(AppError::internal(
            "history release signer evidence digest drifted after reservation",
        ));
    }
    let evidence_ref = evidence
        .evidence_ref()
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok((evidence_ref, content_digest.clone()))
}

pub(super) fn history_response_signer_dependencies(
    mut source_dependencies: Vec<GovernanceDependency>,
    release_dependency: &GovernanceDependency,
) -> Result<Vec<GovernanceDependency>, AppError> {
    if let Some(existing) = source_dependencies
        .iter()
        .find(|dependency| dependency.selector() == release_dependency.selector())
    {
        if existing != release_dependency {
            return Err(AppError::conflict(
                "history signer evidence digest is bound to different bytes",
            ));
        }
    } else {
        source_dependencies.push(release_dependency.clone());
    }
    source_dependencies.sort_by(|left, right| {
        left.selector()
            .canonical_sort_key()
            .expect("validated history signer selector")
            .cmp(
                &right
                    .selector()
                    .canonical_sort_key()
                    .expect("validated history signer selector"),
            )
    });
    Ok(source_dependencies)
}

pub(super) fn sign_history_response_receipt(
    state: &AppState,
    record: &HistoryKeyResponseRecord,
    source_record_digest: arkret_wire::Hash,
    manifest_admission_digest: arkret_wire::Hash,
    release_attestation_digest: Option<arkret_wire::Hash>,
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> Result<HistoryKeyResponseSendReceipt, AppError> {
    let verification_method = history_service_verification_method(state)?;
    let temporary = HistoryKeyResponseSendReceipt {
        response_id: record.source_record.response_id.clone(),
        source_record_digest: source_record_digest.clone(),
        record_digest: record.record_digest.clone(),
        sequence: record.sequence,
        accepted_at,
        manifest_admission_digest: manifest_admission_digest.clone(),
        release_attestation_digest: release_attestation_digest.clone(),
        receipt_digest: zero_sha256_hash()?,
        service_proof: placeholder_history_proof(verification_method.clone(), accepted_at)?,
    };
    let receipt_digest = temporary
        .send_receipt_digest()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let receipt = HistoryKeyResponseSendReceipt::build_signed_proof(
        verification_method,
        accepted_at,
        |service_proof| HistoryKeyResponseSendReceipt {
            response_id: record.source_record.response_id.clone(),
            source_record_digest: source_record_digest.clone(),
            record_digest: record.record_digest.clone(),
            sequence: record.sequence,
            accepted_at,
            manifest_admission_digest: manifest_admission_digest.clone(),
            release_attestation_digest: release_attestation_digest.clone(),
            receipt_digest: receipt_digest.clone(),
            service_proof,
        },
        |binding| history_service_jws(state, binding),
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    receipt
        .validate()
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(receipt)
}

pub(super) fn history_service_verification_method(
    state: &AppState,
) -> Result<arkret_wire::DidUrl, AppError> {
    state
        .service_verification_method("notary-key")
        .map_err(|error| AppError::internal(error.to_string()))
}

pub(super) fn placeholder_history_proof(
    verification_method: arkret_wire::DidUrl,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Result<arkret_wire::PayloadProof, AppError> {
    Ok(arkret_wire::PayloadProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method,
        payload_digest: zero_sha256_hash()?,
        created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: String::new(),
    })
}

pub(super) fn history_service_jws(state: &AppState, binding: &[u8]) -> arkret_wire::Result<String> {
    arkret_signatures::jws::sign_jws_ed25519(binding, state.notary_signing_key().as_ref())
        .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))
}

pub(super) fn zero_sha256_hash() -> Result<arkret_wire::Hash, AppError> {
    arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))
        .map_err(|error| AppError::internal(error.to_string()))
}
