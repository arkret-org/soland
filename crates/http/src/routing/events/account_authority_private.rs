use arkret_wire::{
    AuthorityCommitStatus, AuthorityRejectionStatus, AuthoritySubmitOutcome,
    AuthoritySubmitRequest, EventCommitSubmission,
};
use salvo::prelude::*;
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};

use crate::state::AppState;

/// Admit a single Event delivered by this deployment's Account Authority.
///
/// The private adapter can already close exact duplicate retries from the
/// committed store. A new Event is rejected retryably until the authority
/// transaction/signing application is wired into `AppState`; it must never be
/// acknowledged without a durable `RealmCommit`.
#[tracing::instrument(skip_all, fields(op = "soland.account_authority.events.admit"))]
pub(super) async fn admit_event(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AuthoritySubmitOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    super::peer::authenticate_account_authority_private_request(state, req)?;

    let submission = req
        .parse_json::<EventCommitSubmission>()
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

    if let Some(record) = state
        .persistence()
        .committed_event(&submission.event.event_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        if record.event != submission.event {
            return Err(AppError::conflict(
                "event_id is already committed with different canonical content",
            ));
        }
        let outcome = AuthoritySubmitOutcome::Accepted {
            status: AuthorityCommitStatus::Duplicate,
            commit: record.commit,
        };
        outcome
            .validate_for_request(&AuthoritySubmitRequest::Event(submission))
            .map_err(|error| AppError::internal(error.to_string()))?;
        return json_ok(outcome);
    }

    json_ok(AuthoritySubmitOutcome::Rejected {
        status: AuthorityRejectionStatus::RetryableUnavailable,
        reason_code: "authority_transaction_unavailable".to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_adapter_is_not_a_protocol_operation() {
        let source = include_str!("account_authority_private.rs");
        assert!(!source.contains("oapi::endpoint"));
        assert!(!source.contains("Arkret-Operation"));
        assert!(source.contains("authority_transaction_unavailable"));
    }
}
