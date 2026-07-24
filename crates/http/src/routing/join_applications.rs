//! Profile-private join-application HTTP carrier.
//!
//! These records are deliberately kept out of Realm Event history. The
//! handlers validate signed receipts, apply the private workflow atomically
//! through the persistence port, and mirror only the minimum authorization
//! state into the in-process reducer projection.

use std::collections::BTreeSet;

use arkret_identifiers::RealmId;
use arkret_models_collaboration::governance::join_policy::{
    JoinApplicationAuditOutcome, JoinApplicationCancelRequest, JoinApplicationEntry,
    JoinApplicationGetOutcome, JoinApplicationListOutcome, JoinApplicationMutationOutcome,
    JoinApplicationPrivateBody, JoinApplicationReviewRequest, JoinApplicationStatus,
    JoinApplicationSubmitRequest, join_application_revision_digest,
};
use arkret_wire::Hash;
use chrono::{Duration, Utc};
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde::Serialize;
use serde_json::json;
use soland_services::ServiceError;
use soland_services::join_applications::{
    JoinApplicationCommand, JoinApplicationCommandOutcome, JoinApplicationMutation,
    JoinApplicationRecord,
};
use soland_http::error::{AppError, ErrorCode};
use soland_http::result::{JsonResult, json_ok};

use super::AuthArgs;
use crate::state::AppState;

const REVIEW_ACTION_FALLBACK: &str = "ak.realm.join.review";
const AUDIT_READ_ACTION: &str = "ak.audit.query";
const MAX_IDEMPOTENCY_KEY_LEN: usize = 255;

pub(crate) fn router() -> Router {
    Router::with_path("{realm_id}/join-applications")
        .get(list_join_applications)
        .post(submit_join_application)
        .push(
            Router::with_path("{application_ref}")
                .get(get_join_application)
                .push(Router::with_path("reviews").post(review_join_application))
                .push(Router::with_path("cancel").post(cancel_join_application))
                .push(Router::with_path("audit").get(list_join_application_audit)),
        )
}

fn require_enabled(state: &AppState) -> Result<(), AppError> {
    if state.settings().candidate_join_policy_enabled {
        Ok(())
    } else {
        Err(AppError::unsupported_feature(
            "candidate join-policy profile is disabled",
        ))
    }
}

fn idempotency_key(req: &Request) -> Result<String, AppError> {
    let value = req
        .headers()
        .get("Idempotency-Key")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::missing_param("Idempotency-Key header is required"))?
        .trim();
    if value.is_empty() || value.len() > MAX_IDEMPOTENCY_KEY_LEN {
        return Err(AppError::invalid_param(
            "Idempotency-Key must contain 1 to 255 characters",
        ));
    }
    Ok(value.to_owned())
}

fn parse_application_ref(value: String) -> Result<Hash, AppError> {
    Hash::new(value).map_err(|error| AppError::invalid_param(error.to_string()))
}

fn schema_error(error: impl std::fmt::Display) -> AppError {
    AppError::new(ErrorCode::SchemaViolation, error.to_string())
}

fn proof_error(error: impl std::fmt::Display) -> AppError {
    failed_precondition(
        "proof_invalid",
        "join application receipt proof or digest is invalid",
    )
    .with_private_detail(error.to_string())
}

fn failed_precondition(reason_code: &str, message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::FailedPrecondition, message).with_reason_code(reason_code)
}

fn projection_error(reason: &'static str) -> AppError {
    match reason {
        "capability_denied" => AppError::new(
            ErrorCode::ReviewerCapabilityRevoked,
            "reviewer capability is not active",
        ),
        "ttl_expired" => failed_precondition("ttl_expired", "join application has expired"),
        "gate_check_failed" => {
            failed_precondition("gate_check_failed", "join application gate check failed")
        }
        other => failed_precondition(other, "join application precondition failed"),
    }
}

fn service_error(error: ServiceError) -> AppError {
    let detail = error.detail().to_owned();
    match error {
        ServiceError::NotFound(_) => AppError::not_found("join application not found"),
        ServiceError::Conflict(_) if detail.contains("duplicate_conflict") => {
            AppError::new(ErrorCode::DuplicateConflict, "Idempotency-Key conflict")
        }
        ServiceError::Conflict(_) if detail.contains("ttl_expired") => {
            failed_precondition("ttl_expired", "join application has expired")
        }
        ServiceError::Conflict(_) => failed_precondition(
            "failed_precondition",
            "join application precondition failed",
        )
        .with_private_detail(detail),
        ServiceError::SchemaViolation(_) => AppError::new(
            ErrorCode::SchemaViolation,
            "join application schema violation",
        )
        .with_private_detail(detail),
        ServiceError::Database(_) | ServiceError::Internal(_) => AppError::internal(detail),
    }
}

async fn verify_receipt_proof(
    state: &AppState,
    binding: Vec<u8>,
    jws: &str,
    verification_method: &str,
    actor: &str,
) -> Result<(), AppError> {
    let result = if state.config().development_mode {
        crate::jws_verify::verify_jws_shape(&binding, jws, verification_method, actor)
    } else {
        crate::jws_verify::verify_jws_ed25519_async(
            &binding,
            jws,
            verification_method,
            actor,
            state,
        )
        .await
    };
    result.map_err(|detail| {
        failed_precondition("proof_invalid", "join application receipt proof is invalid")
            .with_private_detail(detail)
    })
}

fn request_hash(body: &impl Serialize) -> Result<String, AppError> {
    arkret_canonical::canonical_sha256(body).map_err(|error| AppError::internal(error.to_string()))
}

fn command_record(
    outcome: JoinApplicationCommandOutcome,
) -> Result<(JoinApplicationRecord, serde_json::Value), AppError> {
    match outcome {
        JoinApplicationCommandOutcome::Applied {
            response_body,
            record,
        }
        | JoinApplicationCommandOutcome::Replay {
            response_body,
            record,
        } => Ok((record, response_body)),
        JoinApplicationCommandOutcome::IdempotencyConflict => Err(AppError::new(
            ErrorCode::DuplicateConflict,
            "Idempotency-Key was already used with a different request",
        )),
    }
}

fn response_from_value(
    record: JoinApplicationRecord,
    response_body: serde_json::Value,
) -> Result<(JoinApplicationRecord, JoinApplicationMutationOutcome), AppError> {
    let response = serde_json::from_value(response_body)
        .map_err(|error| AppError::internal(format!("stored response is invalid: {error}")))?;
    Ok((record, response))
}

#[handler]
async fn submit_join_application(
    aa: AuthArgs,
    realm_id: PathParam<RealmId>,
    body: JsonBody<JoinApplicationSubmitRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<JoinApplicationMutationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_enabled(state)?;
    let session = aa.authenticated_session(state, req).await?;
    let idempotency_key = idempotency_key(req)?;
    let realm_id = realm_id.into_inner();
    let body = body.into_inner();
    body.receipt.validate().map_err(proof_error)?;
    body.private_body.validate().map_err(schema_error)?;
    if body.private_body.canonical_digest().map_err(schema_error)?
        != body.receipt.private_body_digest
    {
        return Err(proof_error("private body digest mismatch"));
    }
    if body.receipt.realm_id != realm_id || body.receipt.applicant_did.as_str() != session.actor {
        return Err(failed_precondition(
            "proof_invalid",
            "receipt actor or realm does not match the request",
        ));
    }
    verify_receipt_proof(
        state,
        body.receipt
            .canonical_proof_binding_bytes()
            .map_err(proof_error)?,
        &body.receipt.proof.jws,
        &body.receipt.proof.verification_method,
        body.receipt.applicant_did.as_str(),
    )
    .await?;

    if let JoinApplicationPrivateBody::ServerProtected {
        answers,
        gate_proofs,
        ..
    } = &body.private_body
    {
        let digest = join_application_revision_digest(
            answers,
            gate_proofs,
            &body.receipt.policy_version_digest,
        )
        .map_err(schema_error)?;
        if digest != body.receipt.application_revision_digest {
            return Err(failed_precondition(
                "proof_invalid",
                "application revision digest does not match the private body",
            ));
        }
    }

    let snapshot = state.projections().snapshot();
    let admission = snapshot
        .check_private_join_application(&body.receipt, &body.private_body)
        .map_err(projection_error)?;
    if let JoinApplicationPrivateBody::ReviewerEnvelope {
        encryption_envelope,
    } = &body.private_body
    {
        let action = snapshot
            .realm_join_policy_review_capability(realm_id.as_str())
            .unwrap_or_else(|| REVIEW_ACTION_FALLBACK.to_owned());
        let mut recipients = BTreeSet::new();
        for recipient in &encryption_envelope.recipients {
            if recipient.recipient_hpke_kid.is_empty()
                || recipient.enc.is_empty()
                || recipient.wrapped_key.is_empty()
                || !recipients.insert((
                    recipient.reviewer_did.as_str(),
                    recipient.device_id.as_str(),
                ))
                || !snapshot.issuer_has_projected_capability(
                    recipient.reviewer_did.as_str(),
                    realm_id.as_str(),
                    &action,
                    realm_id.as_str(),
                )
            {
                return Err(failed_precondition(
                    "gate_check_failed",
                    "reviewer encryption recipient is not eligible",
                ));
            }
        }
    }

    let expires_at = body.receipt.submitted_at + admission.application_ttl;
    let record = JoinApplicationRecord {
        application_ref: body.receipt.application_receipt_digest.clone(),
        receipt: body.receipt.clone(),
        private_body: body.private_body.clone(),
        status: JoinApplicationStatus::AwaitingReview,
        applicant_visibility: admission.applicant_visibility,
        expires_at,
        reviews: Vec::new(),
        required_accept_refs: Vec::new(),
        superseded_by: None,
        cancel_receipt: None,
        invite_consumed: false,
        audit_entries: Vec::new(),
        updated_at: body.receipt.submitted_at,
    };
    let command = JoinApplicationCommand {
        principal_id: session.actor,
        idempotency_key,
        request_hash: request_hash(&body)?,
        idempotency_expires_at: expires_at + Duration::days(7),
        mutation: JoinApplicationMutation::Submit {
            record: Box::new(record),
            max_open_applications: admission.max_open_applications,
            cooldown_after_reject_seconds: admission.cooldown_after_reject.num_seconds(),
        },
    };
    let (record, response_body) = command_record(
        state
            .join_applications()
            .execute(command)
            .await
            .map_err(service_error)?,
    )?;
    let (record, response) = response_from_value(record, response_body)?;
    state
        .projections()
        .install_join_application_record(&record);
    json_ok(response)
}

#[handler]
async fn review_join_application(
    aa: AuthArgs,
    realm_id: PathParam<RealmId>,
    application_ref: PathParam<String>,
    body: JsonBody<JoinApplicationReviewRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<JoinApplicationMutationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_enabled(state)?;
    let session = aa.authenticated_session(state, req).await?;
    let idempotency_key = idempotency_key(req)?;
    let realm_id = realm_id.into_inner();
    let application_ref = parse_application_ref(application_ref.into_inner())?;
    let body = body.into_inner();
    body.receipt.validate().map_err(proof_error)?;
    if body.receipt.realm_id != realm_id
        || body.receipt.application_ref != application_ref
        || body.receipt.reviewer_did.as_str() != session.actor
    {
        return Err(failed_precondition(
            "proof_invalid",
            "review receipt actor or path binding does not match the request",
        ));
    }
    verify_receipt_proof(
        state,
        body.receipt
            .canonical_proof_binding_bytes()
            .map_err(proof_error)?,
        &body.receipt.proof.jws,
        &body.receipt.proof.verification_method,
        body.receipt.reviewer_did.as_str(),
    )
    .await?;
    let accept_threshold = state
        .projections()
        .snapshot()
        .check_private_join_application_review(&body.receipt)
        .map_err(projection_error)?;
    let existing = state
        .join_applications()
        .get(realm_id.as_str(), application_ref.as_str(), Utc::now())
        .await
        .map_err(service_error)?
        .ok_or_else(|| AppError::not_found("join application not found"))?;
    let command = JoinApplicationCommand {
        principal_id: session.actor,
        idempotency_key,
        request_hash: request_hash(&body)?,
        idempotency_expires_at: existing.expires_at + Duration::days(7),
        mutation: JoinApplicationMutation::Review {
            realm_id: realm_id.as_str().to_owned(),
            application_ref: application_ref.clone(),
            receipt: body.receipt,
            accept_threshold,
        },
    };
    let (record, response_body) = command_record(
        state
            .join_applications()
            .execute(command)
            .await
            .map_err(service_error)?,
    )?;
    let (record, response) = response_from_value(record, response_body)?;
    state
        .projections()
        .install_join_application_record(&record);
    json_ok(response)
}

#[handler]
async fn cancel_join_application(
    aa: AuthArgs,
    realm_id: PathParam<RealmId>,
    application_ref: PathParam<String>,
    body: JsonBody<JoinApplicationCancelRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<JoinApplicationMutationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_enabled(state)?;
    let session = aa.authenticated_session(state, req).await?;
    let idempotency_key = idempotency_key(req)?;
    let realm_id = realm_id.into_inner();
    let application_ref = parse_application_ref(application_ref.into_inner())?;
    let body = body.into_inner();
    body.receipt.validate().map_err(proof_error)?;
    if body.receipt.realm_id != realm_id
        || body.receipt.application_ref != application_ref
        || body.receipt.cancelled_by.as_str() != session.actor
    {
        return Err(failed_precondition(
            "proof_invalid",
            "cancel receipt actor or path binding does not match the request",
        ));
    }
    verify_receipt_proof(
        state,
        body.receipt
            .canonical_proof_binding_bytes()
            .map_err(proof_error)?,
        &body.receipt.proof.jws,
        &body.receipt.proof.verification_method,
        body.receipt.cancelled_by.as_str(),
    )
    .await?;
    let existing = state
        .join_applications()
        .get(realm_id.as_str(), application_ref.as_str(), Utc::now())
        .await
        .map_err(service_error)?
        .ok_or_else(|| AppError::not_found("join application not found"))?;
    if existing.receipt.applicant_did.as_str() != session.actor {
        return Err(AppError::not_found("join application not found"));
    }
    let command = JoinApplicationCommand {
        principal_id: session.actor,
        idempotency_key,
        request_hash: request_hash(&body)?,
        idempotency_expires_at: existing.expires_at + Duration::days(7),
        mutation: JoinApplicationMutation::Cancel {
            realm_id: realm_id.as_str().to_owned(),
            application_ref: application_ref.clone(),
            receipt: body.receipt,
        },
    };
    let (record, response_body) = command_record(
        state
            .join_applications()
            .execute(command)
            .await
            .map_err(service_error)?,
    )?;
    let (record, response) = response_from_value(record, response_body)?;
    state
        .projections()
        .install_join_application_record(&record);
    json_ok(response)
}

fn viewer_context(state: &AppState, realm_id: &RealmId, actor: &str) -> (bool, bool, bool) {
    let snapshot = state.projections().snapshot();
    let review_action = snapshot
        .realm_join_policy_review_capability(realm_id.as_str())
        .unwrap_or_else(|| REVIEW_ACTION_FALLBACK.to_owned());
    let reviewer = snapshot.issuer_has_projected_capability(
        actor,
        realm_id.as_str(),
        &review_action,
        realm_id.as_str(),
    );
    let audit_reader = snapshot.issuer_has_projected_capability(
        actor,
        realm_id.as_str(),
        AUDIT_READ_ACTION,
        realm_id.as_str(),
    );
    let member = snapshot
        .member(realm_id.as_str(), actor)
        .is_some_and(|membership| membership.state == "join");
    (reviewer, audit_reader, member)
}

fn application_entry(
    record: &JoinApplicationRecord,
    actor: &str,
    reviewer: bool,
) -> (JoinApplicationEntry, bool) {
    let applicant = record.receipt.applicant_did.as_str() == actor;
    let body_visible = reviewer
        || applicant
        || record.applicant_visibility == "public"
        || (record.applicant_visibility == "members_after_join"
            && matches!(
                record.status,
                JoinApplicationStatus::Accepted | JoinApplicationStatus::Consumed
            ));
    (
        JoinApplicationEntry {
            application_ref: record.application_ref.clone(),
            realm_id: record.receipt.realm_id.clone(),
            applicant_did: record.receipt.applicant_did.clone(),
            application_revision_digest: record.receipt.application_revision_digest.clone(),
            policy_version_digest: record.receipt.policy_version_digest.clone(),
            submitted_at: record.receipt.submitted_at,
            status: record.status.clone(),
            private_body: body_visible.then(|| record.private_body.clone()),
            application_pending: (!body_visible).then_some(true),
            latest_review_ref: record
                .reviews
                .last()
                .map(|review| review.review_receipt_digest.clone()),
        },
        body_visible,
    )
}

async fn audit_body_read(
    state: &AppState,
    record: &JoinApplicationRecord,
    actor: &str,
) -> Result<(), AppError> {
    state
        .join_applications()
        .append_read_audit(
            record.receipt.realm_id.as_str(),
            record.application_ref.as_str(),
            actor,
            Utc::now(),
        )
        .await
        .map_err(service_error)?;
    super::append_audit_log(
        state,
        Some(actor),
        "ak.audit.accessed",
        json!({
            "realm_id": record.receipt.realm_id,
            "application_ref": record.application_ref,
            "resource_kind": "join_application_private_body",
        }),
        "success",
    )
    .await;
    Ok(())
}

#[handler]
async fn list_join_applications(
    aa: AuthArgs,
    realm_id: PathParam<RealmId>,
    cursor: QueryParam<String, false>,
    limit: QueryParam<u16, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<JoinApplicationListOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_enabled(state)?;
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let cursor = cursor.into_inner();
    let limit = limit.into_inner().unwrap_or(50);
    if !(1..=200).contains(&limit) {
        return Err(AppError::invalid_param("limit must be in 1..=200"));
    }
    let (reviewer, _, member) = viewer_context(state, &realm_id, &session.actor);
    let mut records = state
        .join_applications()
        .list(realm_id.as_str(), Utc::now())
        .await
        .map_err(service_error)?;
    records.sort_by(|left, right| left.application_ref.cmp(&right.application_ref));
    let mut visible = records
        .into_iter()
        .filter(|record| {
            reviewer || member || record.receipt.applicant_did.as_str() == session.actor
        })
        .filter(|record| {
            cursor
                .as_deref()
                .is_none_or(|cursor| record.application_ref.as_str() > cursor)
        })
        .collect::<Vec<_>>();
    let has_more = visible.len() > usize::from(limit);
    visible.truncate(usize::from(limit));
    let next_cursor = has_more
        .then(|| {
            visible
                .last()
                .map(|record| record.application_ref.to_string())
        })
        .flatten();
    let mut applications = Vec::with_capacity(visible.len());
    for record in visible {
        let (entry, body_visible) = application_entry(&record, &session.actor, reviewer);
        if body_visible {
            audit_body_read(state, &record, &session.actor).await?;
        }
        applications.push(entry);
    }
    json_ok(JoinApplicationListOutcome {
        realm_id,
        viewer_is_reviewer: reviewer,
        applications,
        next_cursor,
    })
}

#[handler]
async fn get_join_application(
    aa: AuthArgs,
    realm_id: PathParam<RealmId>,
    application_ref: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<JoinApplicationGetOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_enabled(state)?;
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let application_ref = parse_application_ref(application_ref.into_inner())?;
    let record = state
        .join_applications()
        .get(realm_id.as_str(), application_ref.as_str(), Utc::now())
        .await
        .map_err(service_error)?
        .ok_or_else(|| AppError::not_found("join application not found"))?;
    let (reviewer, ..) = viewer_context(state, &realm_id, &session.actor);
    if !reviewer && record.receipt.applicant_did.as_str() != session.actor {
        return Err(AppError::not_found("join application not found"));
    }
    let (application, body_visible) = application_entry(&record, &session.actor, reviewer);
    if body_visible {
        audit_body_read(state, &record, &session.actor).await?;
    }
    json_ok(JoinApplicationGetOutcome { application })
}

#[handler]
async fn list_join_application_audit(
    aa: AuthArgs,
    realm_id: PathParam<RealmId>,
    application_ref: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<JoinApplicationAuditOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_enabled(state)?;
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let application_ref = parse_application_ref(application_ref.into_inner())?;
    let record = state
        .join_applications()
        .get(realm_id.as_str(), application_ref.as_str(), Utc::now())
        .await
        .map_err(service_error)?
        .ok_or_else(|| AppError::not_found("join application not found"))?;
    let (reviewer, audit_reader, _) = viewer_context(state, &realm_id, &session.actor);
    if !reviewer && !audit_reader && record.receipt.applicant_did.as_str() != session.actor {
        return Err(AppError::not_found("join application not found"));
    }
    json_ok(JoinApplicationAuditOutcome {
        realm_id,
        application_ref,
        entries: record.audit_entries,
    })
}

