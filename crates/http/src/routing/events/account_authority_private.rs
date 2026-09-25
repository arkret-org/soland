use arkret_wire::{
    AuthorityCommitStatus, AuthorityRejectionStatus, AuthoritySubmitOutcome,
    AuthoritySubmitRequest, EventAdmissionSubmission,
};
use salvo::prelude::*;
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};
use soland_services::ServiceErrorKind;
use soland_services::authority_commit::AuthorityEventAdmissionOutcome;

use crate::state::AppState;

/// Admit a single Event delivered by this deployment's Account Authority.
///
/// The adapter delegates to the injected authority application, whose
/// queue+commit persistence call is one transaction. It therefore returns an
/// accepted result only after the exact `Event` and its signed `RealmCommit`
/// are durably visible together.
#[handler]
#[tracing::instrument(skip_all, fields(op = "soland.account_authority.events.admit"))]
pub(super) async fn admit_event(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AuthoritySubmitOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    super::peer::authenticate_account_authority_private_request(state, req)?;

    let submission = req
        .parse_json::<EventAdmissionSubmission>()
        .await
        .map_err(|_| AppError::json_invalid("invalid private Event admission body"))?;
    submission
        .validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let idempotency_key = req
        .headers()
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::param_invalid("Idempotency-Key is required"))?;
    if idempotency_key != submission.event.event_id.as_str() {
        return Err(AppError::conflict(
            "Idempotency-Key must equal the submitted event_id",
        ));
    }

    let verification_method = state
        .service_verification_method("notary-key")
        .map_err(AppError::internal)?;
    if submission.event.kind == arkret_wire::EventKind::DeviceAuthorize {
        let outcome = accepted_device_outcome(
            state
                .authority_commits()
                .admit_accepted_device_authorization(
                    &submission.event,
                    &state.service_core_id(),
                    verification_method,
                    state.notary_signing_key().as_ref(),
                    chrono::Utc::now(),
                )
                .await,
        );
        outcome
            .validate_for_request(&AuthoritySubmitRequest::Event(submission))
            .map_err(|error| AppError::internal(error.to_string()))?;
        return json_ok(outcome);
    }
    let admission = state
        .authority_commits()
        .admit_event(
            &submission.event,
            &state.service_core_id(),
            verification_method,
            state.notary_signing_key().as_ref(),
            chrono::Utc::now(),
        )
        .await;
    let outcome = match admission {
        Ok(AuthorityEventAdmissionOutcome::Committed(commit)) => AuthoritySubmitOutcome::Accepted {
            status: AuthorityCommitStatus::Committed,
            commit,
        },
        Ok(AuthorityEventAdmissionOutcome::Duplicate(commit)) => AuthoritySubmitOutcome::Accepted {
            status: AuthorityCommitStatus::Duplicate,
            commit,
        },
        Ok(AuthorityEventAdmissionOutcome::NotCurrentAuthority) => {
            AuthoritySubmitOutcome::Rejected {
                status: AuthorityRejectionStatus::Rejected,
                reason_code: "authority_mismatch".to_owned(),
            }
        }
        Err(error) => match error.kind() {
            ServiceErrorKind::Conflict
                if error.conflict_code()
                    == Some(soland_storage::ConflictCode::FailedPrecondition) =>
            {
                return Err(AppError::new(
                    arkret_wire::ErrorCode::FailedPrecondition,
                    error.detail(),
                ));
            }
            ServiceErrorKind::Conflict => return Err(AppError::conflict(error.detail())),
            ServiceErrorKind::SchemaViolation => {
                return Err(AppError::param_invalid(error.detail()));
            }
            ServiceErrorKind::UnsupportedEventKind => {
                return Err(AppError::new(
                    arkret_wire::ErrorCode::UnsupportedEventKind,
                    error.detail(),
                ));
            }
            ServiceErrorKind::NotFound
            | ServiceErrorKind::Database
            | ServiceErrorKind::Internal => {
                tracing::warn!(error = %error, "atomic Account Authority Event admission unavailable");
                AuthoritySubmitOutcome::Rejected {
                    status: AuthorityRejectionStatus::RetryableUnavailable,
                    reason_code: "authority_transaction_unavailable".to_owned(),
                }
            }
        },
    };
    outcome
        .validate_for_request(&AuthoritySubmitRequest::Event(submission))
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(outcome)
}

/// The Account Authority abandons a frozen pairing admission only on a
/// terminal `rejected` outcome, so every refusal the accepted-device unit
/// decides from durable PCR state or from the Event itself is terminal and
/// carries its registered reason; a lost head race or an unavailable store is
/// retryable and leaves the reservation in place.
fn accepted_device_outcome(
    admission: soland_services::ServiceResult<AuthorityEventAdmissionOutcome>,
) -> AuthoritySubmitOutcome {
    use soland_storage::ConflictCode;

    let rejected = |reason_code: &str| AuthoritySubmitOutcome::Rejected {
        status: AuthorityRejectionStatus::Rejected,
        reason_code: reason_code.to_owned(),
    };
    let retryable = || AuthoritySubmitOutcome::Rejected {
        status: AuthorityRejectionStatus::RetryableUnavailable,
        reason_code: "authority_transaction_unavailable".to_owned(),
    };
    match admission {
        Ok(AuthorityEventAdmissionOutcome::Committed(commit)) => AuthoritySubmitOutcome::Accepted {
            status: AuthorityCommitStatus::Committed,
            commit,
        },
        Ok(AuthorityEventAdmissionOutcome::Duplicate(commit)) => AuthoritySubmitOutcome::Accepted {
            status: AuthorityCommitStatus::Duplicate,
            commit,
        },
        Ok(AuthorityEventAdmissionOutcome::NotCurrentAuthority) => rejected("authority_mismatch"),
        Err(error) => match error.kind() {
            ServiceErrorKind::SchemaViolation => rejected(ConflictCode::SchemaViolation.as_str()),
            ServiceErrorKind::Conflict => match error.conflict_code() {
                Some(
                    code @ (ConflictCode::DeviceRevoked
                    | ConflictCode::DeviceRevocationPending
                    | ConflictCode::DeviceGenerationFenced
                    | ConflictCode::DeviceUnauthorized
                    | ConflictCode::SignatureInvalid
                    | ConflictCode::SchemaViolation
                    | ConflictCode::EventIdDigestMismatch
                    | ConflictCode::DuplicateConflict
                    | ConflictCode::FailedPrecondition),
                ) => rejected(code.as_str()),
                _ => {
                    tracing::warn!(error = %error, "accepted-device admission lost its PCR cut");
                    retryable()
                }
            },
            ServiceErrorKind::UnsupportedEventKind
            | ServiceErrorKind::NotFound
            | ServiceErrorKind::Database
            | ServiceErrorKind::Internal => {
                tracing::warn!(error = %error, "accepted-device admission unavailable");
                retryable()
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use soland_storage::ConflictCode;

    use super::*;

    fn conflict(
        code: ConflictCode,
    ) -> soland_services::ServiceResult<AuthorityEventAdmissionOutcome> {
        Err(soland_services::ServiceError::Conflict(format!(
            "{code}: diagnostic"
        )))
    }

    #[test]
    fn accepted_device_refusals_are_terminal_and_races_are_retryable() {
        for code in [
            ConflictCode::DeviceRevoked,
            ConflictCode::DeviceRevocationPending,
            ConflictCode::DeviceGenerationFenced,
            ConflictCode::SignatureInvalid,
            ConflictCode::DuplicateConflict,
        ] {
            assert_eq!(
                accepted_device_outcome(conflict(code)),
                AuthoritySubmitOutcome::Rejected {
                    status: AuthorityRejectionStatus::Rejected,
                    reason_code: code.as_str().to_owned(),
                }
            );
        }
        for retryable in [
            conflict(ConflictCode::CasConflict),
            Err(soland_services::ServiceError::Database("down".to_owned())),
        ] {
            assert!(matches!(
                accepted_device_outcome(retryable),
                AuthoritySubmitOutcome::Rejected {
                    status: AuthorityRejectionStatus::RetryableUnavailable,
                    ..
                }
            ));
        }
        assert_eq!(
            accepted_device_outcome(Ok(AuthorityEventAdmissionOutcome::NotCurrentAuthority)),
            AuthoritySubmitOutcome::Rejected {
                status: AuthorityRejectionStatus::Rejected,
                reason_code: "authority_mismatch".to_owned(),
            }
        );
    }

    #[test]
    fn private_adapter_is_not_a_protocol_operation() {
        let source = include_str!("account_authority_private.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production section");
        assert!(!source.contains("oapi::endpoint"));
        assert!(!source.contains("Arkret-Operation"));
        assert!(source.contains(".authority_commits()") && source.contains(".admit_event("));
        assert!(source.contains(".admit_accepted_device_authorization("));
        assert!(source.contains("authority_transaction_unavailable"));
    }
}
