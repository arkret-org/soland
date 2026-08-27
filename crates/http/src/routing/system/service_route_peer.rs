use arkret_models_identity::{
    ServiceResolutionArtifactKey, ServiceResolutionPublishAckCore, ServiceResolutionPublishOutcome,
    ServiceResolutionPublishRequest, ServiceResolutionResolveOutcome,
    ServiceResolutionResolveRequest, ServiceRouteHandoverState,
};
use arkret_wire::{DidCoreId, DidFullId, Hash};
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier as _};
use salvo::http::StatusCode;
use salvo::prelude::*;
use soland_http::error::{AppError, ErrorCode};
use soland_http::result::{JsonResult, json_ok};
use soland_storage::{
    ServiceResolutionForkEvidence, ServiceResolutionMirrorCommit, ServiceResolutionMirrorEntry,
};

use crate::state::AppState;

const MAX_PUBLISH_CANONICAL_BYTES: usize = 65_536;
const MAX_RESOLVE_CANONICAL_BYTES: usize = 262_144;
const MAX_RESOLVE_RECORDS: usize = 32;

pub(super) fn router() -> Router {
    Router::with_path("service-resolution")
        .push(Router::with_path("publish").post(peer_publish))
        .push(Router::with_path("resolve").query(peer_resolve))
}

#[salvo::oapi::endpoint(
    operation_id = "ak.peer.service_resolution.command.publish",
    tags("identity")
)]
async fn peer_publish(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ServiceResolutionPublishOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    crate::routing::events::peer::validate_peer_request(state, req, true).await?;
    let source = required_service_id(req, "source-service-id")?;
    let idempotency_key = required_header(req, "idempotency-key")?;
    let request = parse_json::<ServiceResolutionPublishRequest>(req).await?;
    if canonical_size(&request)? > MAX_PUBLISH_CANONICAL_BYTES {
        return Err(limit_exceeded(
            "service resolution publish body exceeds 64 KiB",
        ));
    }
    if idempotency_key != request.request_id.as_str() {
        return Err(duplicate_conflict("Idempotency-Key must equal request_id"));
    }
    let artifact_key = request.validate().map_err(protocol_violation)?;
    let target = artifact_service_id(&artifact_key);
    if !crate::routing::events::peer::peer_route_visibility(
        state,
        source.as_str(),
        request.realm_id.as_str(),
        target.as_str(),
    )
    .await?
    {
        return Err(AppError::capability_denied("peer route visibility denied"));
    }
    verify_target_artifact(state, &request, target).await?;

    let now = Utc::now();
    let request_digest = request.canonical_digest().map_err(protocol_violation)?;
    let (receiver, _) = super::service_resolution::service_ids(state)?;
    let stored = state
        .stored_service_identity()
        .await
        .map_err(AppError::internal)?;
    let ack = arkret_signatures::service_resolution::sign_service_resolution_publish_ack(
        ServiceResolutionPublishAckCore {
            request_id: request.request_id.clone(),
            source_service_id: source.clone(),
            receiver_service_id: receiver,
            realm_id: request.realm_id.clone(),
            request_digest: request_digest.clone(),
            artifact_key: artifact_key.clone(),
            artifact_digest: request.artifact_digest.clone(),
            accepted_at: now,
        },
        super::service_resolution::service_assertion_method(state, &stored)?,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|error| AppError::internal(error.to_string()))?;

    let committed = state
        .persistence()
        .commit_service_route_mirror(ServiceResolutionMirrorEntry {
            source_service_id: source,
            realm_id: request.realm_id.clone(),
            request_id: request.request_id.clone(),
            request_digest,
            artifact_key,
            artifact_digest: request.artifact_digest.clone(),
            request: request.clone(),
            ack: ack.clone(),
            accepted_at: now,
        })
        .await
        .map_err(route_service_error)?;
    let durable_ack = match committed {
        ServiceResolutionMirrorCommit::Stored(ack) | ServiceResolutionMirrorCommit::Replay(ack) => {
            ack
        }
        ServiceResolutionMirrorCommit::TransportConflict => {
            return Err(duplicate_conflict(
                "request_id is already bound to other bytes",
            ));
        }
        ServiceResolutionMirrorCommit::ArtifactConflict { .. } => {
            return Err(duplicate_conflict(
                "artifact key is already bound to other bytes",
            ));
        }
        ServiceResolutionMirrorCommit::SequenceConflict { accepted_digest } => {
            quarantine_sequence_conflict(state, &request, accepted_digest, now).await?;
            return Err(blinded_not_found());
        }
        ServiceResolutionMirrorCommit::SequenceRejected => return Err(blinded_not_found()),
    };
    // `commit_service_route_mirror` stores the artifact, monotonic floor/notice
    // state, and exact ACK on one lock/transaction. Returning the ACK earlier
    // would permit a crash to retain replay authority without its safety floor.
    json_ok(ServiceResolutionPublishOutcome { ack: durable_ack })
}

#[salvo::oapi::endpoint(
    operation_id = "ak.peer.service_resolution.read.resolve",
    tags("identity")
)]
async fn peer_resolve(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ServiceResolutionResolveOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    if req.headers().contains_key("idempotency-key") {
        return Err(protocol_violation("resolve forbids Idempotency-Key"));
    }
    crate::routing::events::peer::validate_peer_request(state, req, true).await?;
    let source = required_service_id(req, "source-service-id")?;
    let request = parse_json::<ServiceResolutionResolveRequest>(req).await?;
    request.validate_bounds().map_err(protocol_violation)?;
    if !crate::routing::events::peer::peer_route_visibility(
        state,
        source.as_str(),
        request.realm_id.as_str(),
        request.target_service_id.as_str(),
    )
    .await?
    {
        return Err(AppError::capability_denied("peer route visibility denied"));
    }
    if state
        .persistence()
        .service_route_is_quarantined(&request.target_service_id, &request.target_service_kind)
        .await
        .map_err(route_service_error)?
    {
        return Err(blinded_not_found());
    }
    let record_limit = request
        .max_records
        .map_or(MAX_RESOLVE_RECORDS, |v| v as usize);
    let response_limit = request
        .max_response_bytes
        .map_or(MAX_RESOLVE_CANONICAL_BYTES, |v| v as usize);
    let mut records = state
        .persistence()
        .service_route_successors(
            &source,
            &request.realm_id,
            &request.target_service_id,
            &request.target_service_kind,
            request.known_record_sequence,
            record_limit.saturating_add(1),
        )
        .await
        .map_err(route_service_error)?;
    let has_more = records.len() > record_limit;
    records.truncate(record_limit);
    let mut sequence = request.known_record_sequence;
    let mut predecessor = request.known_record_digest.clone();
    for record in &records {
        if record.record.record_sequence != sequence + 1
            || record.record.previous_record_digest.as_ref() != Some(&predecessor)
        {
            return Err(blinded_not_found());
        }
        sequence = record.record.record_sequence;
        predecessor = digest(record)?;
    }
    let mut notice = state
        .persistence()
        .latest_service_route_notice(
            &source,
            &request.realm_id,
            &request.target_service_id,
            &request.target_service_kind,
        )
        .await
        .map_err(route_service_error)?;
    if notice.as_ref().is_some_and(|notice| {
        notice.notice.state == ServiceRouteHandoverState::Cancelled
            || notice.notice.expires_at <= Utc::now()
            || notice.notice.from_record_sequence != sequence
            || notice.notice.from_record_digest != predecessor
            || request
                .known_notice_digest
                .as_ref()
                .is_some_and(|known| digest(notice).as_ref().ok() == Some(known))
    }) {
        notice = None;
    }
    if records.is_empty() && notice.is_none() {
        return Err(blinded_not_found());
    }
    let mut outcome = ServiceResolutionResolveOutcome {
        successor_records: records,
        handover_notice: notice,
        has_more,
    };
    while canonical_size(&outcome)? > response_limit {
        if outcome.successor_records.pop().is_none() {
            return Err(limit_exceeded(
                "one route artifact exceeds max_response_bytes",
            ));
        }
        outcome.has_more = true;
    }
    if outcome.successor_records.is_empty() && outcome.has_more {
        return Err(blinded_not_found());
    }
    outcome
        .validate_chain(&request)
        .map_err(|_| blinded_not_found())?;
    json_ok(outcome)
}

async fn quarantine_sequence_conflict(
    state: &AppState,
    request: &ServiceResolutionPublishRequest,
    accepted_digest: Hash,
    now: chrono::DateTime<Utc>,
) -> Result<(), AppError> {
    let (service_id, service_kind, family, key) =
        if let Some(record) = request.service_resolution_record.as_ref() {
            (
                record.record.service_id.clone(),
                record.record.service_kind.clone(),
                "service_resolution_record",
                record.record.record_sequence.to_string(),
            )
        } else if let Some(notice) = request.service_route_handover_notice.as_ref() {
            (
                notice.notice.service_id.clone(),
                notice.notice.service_kind.clone(),
                "service_route_handover_notice",
                format!(
                    "{}:{}",
                    notice.notice.handover_id, notice.notice.notice_revision
                ),
            )
        } else {
            return Err(protocol_violation("publish must contain one artifact"));
        };
    state
        .persistence()
        .quarantine_service_route_fork(ServiceResolutionForkEvidence {
            service_id,
            service_kind,
            artifact_family: family.to_owned(),
            artifact_key: key,
            accepted_digest,
            conflicting_digest: request.artifact_digest.clone(),
            evidence: serde_json::json!({"request_id": request.request_id}),
            quarantined_at: now,
        })
        .await
        .map_err(route_service_error)
}

async fn verify_target_artifact(
    state: &AppState,
    request: &ServiceResolutionPublishRequest,
    expected: &DidCoreId,
) -> Result<(), AppError> {
    let (proof, bytes, full_id, method_history_head, issued_at, expires_at) =
        if let Some(record) = request.service_resolution_record.as_ref() {
            if record.record.service_id != *expected
                || record.record.issued_at > record.record.refresh_after
                || record.record.refresh_after >= record.record.expires_at
                || record.proof.created_at != record.record.issued_at
            {
                return Err(protocol_violation(
                    "invalid service resolution record boundary",
                ));
            }
            (
                &record.proof,
                record.proof_signing_bytes().map_err(protocol_violation)?,
                record.record.full_id.clone(),
                Some(record.record.method_history_head.as_str()),
                record.record.issued_at,
                record.record.expires_at,
            )
        } else if let Some(notice) = request.service_route_handover_notice.as_ref() {
            validate_notice_candidate(notice)?;
            let bare = proof_bare_full_id(&notice.proof.verification_method)?;
            (
                &notice.proof,
                notice.proof_signing_bytes().map_err(protocol_violation)?,
                bare,
                None,
                notice.notice.issued_at,
                notice.notice.expires_at,
            )
        } else {
            return Err(protocol_violation("publish must contain one artifact"));
        };
    if Utc::now() >= expires_at
        || proof.created_at != issued_at
        || arkret_wire::project_full_id_to_core_id(&full_id).map_err(protocol_violation)?
            != *expected
    {
        return Err(protocol_violation(
            "artifact proof target or freshness mismatch",
        ));
    }
    let proof_full = proof_bare_full_id(&proof.verification_method)?;
    if proof_full != full_id {
        return Err(protocol_violation(
            "proof verification method is not based on artifact full_id",
        ));
    }

    // A federation transport key authenticates only the peer connection. The
    // target route assertion is third-party authority material and therefore
    // MUST resolve through the registered DID adapter and the exact method in
    // the target's verified document. Unsupported/stale history fails closed;
    // there is deliberately no transport-key fallback.
    let did = DidFullId::new(full_id.as_str().to_owned()).map_err(protocol_violation)?;
    let resolved = crate::jws_verify::resolve_ed25519_verification_key_for_did_fresh(
        state,
        &did,
        proof.verification_method.as_str(),
    )
    .await
    .map_err(|error| {
        AppError::capability_denied(format!("target DID verification unavailable: {error}"))
    })?;
    if method_history_head.is_some_and(|declared| declared != resolved.key_log_head.as_str()) {
        return Err(AppError::capability_denied(
            "target route method history head does not match verified DID history",
        ));
    }
    let signature_bytes =
        arkret_canonical::base64url_decode(proof.jws.as_str()).map_err(protocol_violation)?;
    let signature = Signature::from_slice(&signature_bytes).map_err(protocol_violation)?;
    resolved
        .public_key
        .verify(&bytes, &signature)
        .map_err(|_| AppError::capability_denied("invalid target route proof"))
}

fn proof_bare_full_id(method: &arkret_wire::DidUrl) -> Result<DidFullId, AppError> {
    let bare = method
        .as_str()
        .split_once('#')
        .map_or(method.as_str(), |(bare, _)| bare);
    DidFullId::new(bare.to_owned()).map_err(protocol_violation)
}

fn artifact_service_id(key: &ServiceResolutionArtifactKey) -> &DidCoreId {
    match key {
        ServiceResolutionArtifactKey::ServiceResolutionRecord { service_id, .. }
        | ServiceResolutionArtifactKey::ServiceRouteHandoverNotice { service_id, .. } => service_id,
    }
}

fn validate_notice_candidate(
    notice: &arkret_models_identity::ServiceRouteHandoverNotice,
) -> Result<(), AppError> {
    if notice.notice.state == ServiceRouteHandoverState::Cancelled {
        return Ok(());
    }
    let base = notice
        .notice
        .candidate_base_url
        .as_deref()
        .ok_or_else(|| protocol_violation("scheduled notice omits candidate_base_url"))?;
    let base = arkret_models_identity::service_identity::CanonicalServiceUrl::canonicalize(base)
        .map_err(protocol_violation)?
        .to_string();
    let expected = format!(
        "{base}_arkret/open/services/{}/resolution",
        percent_encode_path_segment(notice.notice.service_id.as_str())
    );
    if notice.notice.candidate_record_url.as_deref() != Some(expected.as_str()) {
        return Err(protocol_violation(
            "candidate_record_url is not mechanically derived from candidate_base_url",
        ));
    }
    Ok(())
}

fn percent_encode_path_segment(value: &str) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            write!(&mut encoded, "%{byte:02X}").expect("writing to String cannot fail");
        }
    }
    encoded
}

fn digest(value: &impl serde::Serialize) -> Result<Hash, AppError> {
    Hash::new(arkret_canonical::canonical_sha256(value).map_err(protocol_violation)?)
        .map_err(protocol_violation)
}

fn canonical_size(value: &impl serde::Serialize) -> Result<usize, AppError> {
    arkret_canonical::canonical_json_bytes(value)
        .map(|bytes| bytes.len())
        .map_err(protocol_violation)
}

async fn parse_json<T: serde::de::DeserializeOwned>(req: &mut Request) -> Result<T, AppError> {
    req.parse_json::<T>()
        .await
        .map_err(|_| protocol_violation("invalid service resolution JSON body"))
}

fn required_service_id(req: &Request, name: &'static str) -> Result<DidCoreId, AppError> {
    DidCoreId::new(required_header(req, name)?).map_err(protocol_violation)
}

fn required_header(req: &Request, name: &'static str) -> Result<String, AppError> {
    req.headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| protocol_violation(format!("required header {name} missing")))
}

fn protocol_violation(error: impl std::fmt::Display) -> AppError {
    AppError::param_invalid(error.to_string())
        .with_status(StatusCode::BAD_REQUEST)
        .with_wire_code("schema_violation")
}

fn duplicate_conflict(message: impl Into<String>) -> AppError {
    AppError::conflict(message).with_wire_code("duplicate_conflict")
}

fn limit_exceeded(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::LimitExceeded, message)
}

fn blinded_not_found() -> AppError {
    AppError::not_found("not found")
}

fn route_service_error(error: soland_services::ServiceError) -> AppError {
    AppError::internal(format!("service route persistence: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_invisible_gap_and_fork_share_one_blinded_wire_error() {
        for _reason in ["unknown", "invisible", "not-held", "gap", "fork"] {
            let error = blinded_not_found();
            assert_eq!(error.http_status(), StatusCode::NOT_FOUND);
            assert_eq!(error.wire_code(), "not_found");
            assert_eq!(error.message.as_ref(), "not found");
        }
    }
}
