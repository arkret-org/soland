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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_adapter_is_not_a_protocol_operation() {
        let source = include_str!("account_authority_private.rs");
        assert!(!source.contains("oapi::endpoint"));
        assert!(!source.contains("Arkret-Operation"));
        assert!(source.contains("authority_commits().admit_event"));
        assert!(source.contains("authority_transaction_unavailable"));
    }
}
