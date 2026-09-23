//! Agent membership cascade admission boundary.
//!
//! The current SDK carries an exact set of producer-signed
//! `EventAdmissionSubmission`s. The retired Cell/Seal writer cannot commit
//! the controller transition, every Agent transition, cleanup intent,
//! RealmCommits and current membership effects in one authority transaction.

use arkret_models_collaboration::governance::agent_membership_cascade::{
    AgentMembershipCascadeOutcome, AgentMembershipCascadeSubmission,
};
use salvo::http::StatusCode;

use super::{AppState, SessionRecord, SubmitOneError};

pub(in crate::routing) async fn submit_agent_membership_cascade(
    _state: &AppState,
    _session: &SessionRecord,
    submission: AgentMembershipCascadeSubmission,
) -> Result<AgentMembershipCascadeOutcome, SubmitOneError> {
    submission.validate().map_err(|error| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("invalid Agent membership cascade: {error}"),
        )
    })?;
    Err(SubmitOneError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "service_unavailable",
        "Agent membership cascade awaits exact-set atomic Event/RealmCommit/current admission",
    ))
}
