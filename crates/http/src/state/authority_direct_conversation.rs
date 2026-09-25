//! Direct Conversation admission on the governing Station.
//!
//! `contact-and-direct-conversation.md` sections 5.5 and 8.4. The founder's
//! current Station admits the caller-authored four-Event founding unit through
//! the self events union; after founding, every write to the Realm is first
//! judged by the profile admission table at the accepting cut. This module is
//! the serving side of both: it authenticates the founder's four producers,
//! signs the four Commits and relays the table's closed refusal as the
//! `{status="rejected",reason_code}` Event outcome.

use arkret_models_collaboration::authority_commit::{
    AggregateAcceptanceStatus, DirectConversationFoundingAcceptanceOutcome,
    DirectConversationFoundingUnitSubmission,
};
use arkret_wire::{AuthorityRejectionStatus, AuthoritySubmitOutcome, Event};
use chrono::Utc;
use soland_services::identity::SessionIdentityState;
use soland_services::{ServiceError, ServiceResult};
use soland_storage::{ConflictCode, DirectConversationAdmissionCut, SelfProducerCommitGuard};

use super::AppState;

/// The closed Event outcome for a table refusal, or the refusal as an error
/// when the code is not one of the seven mapped reasons.
pub(super) fn direct_conversation_refusal(
    code: ConflictCode,
) -> ServiceResult<AuthoritySubmitOutcome> {
    match code.direct_conversation_admission_reason() {
        Some(reason_code) => Ok(AuthoritySubmitOutcome::Rejected {
            status: AuthorityRejectionStatus::Rejected,
            reason_code: reason_code.to_owned(),
        }),
        None => Err(ServiceError::Conflict(format!(
            "{}: the Direct Conversation profile refuses this Event",
            code.as_str()
        ))),
    }
}

/// The closed outcome for a table refusal raised inside an accepting
/// transaction; any other error passes through unchanged.
pub(super) fn relay_direct_conversation_refusal(
    error: ServiceError,
) -> ServiceResult<AuthoritySubmitOutcome> {
    match error.conflict_code() {
        Some(code) if code.direct_conversation_admission_reason().is_some() => {
            direct_conversation_refusal(code)
        }
        _ => Err(error),
    }
}

/// Judge an Event this Station has no admission unit for. A Direct
/// Conversation Realm's table still answers first, in registered precedence;
/// otherwise the Event keeps its `unsupported` refusal.
pub(super) async fn refuse_unadmitted_event(
    state: &AppState,
    event: &Event,
    unsupported: ServiceError,
) -> ServiceResult<AuthoritySubmitOutcome> {
    match state
        .authority_commits()
        .direct_conversation_admission(event)
        .await?
    {
        DirectConversationAdmissionCut::Refused(code) => direct_conversation_refusal(code),
        DirectConversationAdmissionCut::NotDirectConversation
        | DirectConversationAdmissionCut::Passed => Err(unsupported),
    }
}

/// `direct_conversation_founding_unit_submission` on the self events union.
///
/// The Station never re-authors or reorders the four Events; it only verifies
/// their producers, signs the four consecutive Commits and hands the unit to
/// the one transaction that claims the founder's slot and reads the founding
/// authority at its cut.
pub(super) async fn submit_self_direct_conversation_founding(
    state: &AppState,
    session: &SessionIdentityState,
    request: DirectConversationFoundingUnitSubmission,
) -> ServiceResult<DirectConversationFoundingAcceptanceOutcome> {
    request.validate().map_err(|error| {
        ServiceError::Conflict(format!(
            "{}: {error}",
            ConflictCode::DirectConversationFoundingUnitInvalid.as_str()
        ))
    })?;
    let mut guards = Vec::with_capacity(4);
    for submitted in &request.events {
        guards.push(
            super::authority_producer_validation::verify_self_event_producer(
                state,
                session,
                &submitted.event,
            )
            .await?,
        );
    }
    let guards: [SelfProducerCommitGuard; 4] = guards
        .try_into()
        .map_err(|_| ServiceError::internal("four founding producer guards expected"))?;
    let genesis = &request.events[0].event;
    let authority = soland_storage::CurrentRealmAuthority {
        realm_id: arkret_wire::RealmId::from_event_id(&genesis.event_id),
        generation: 0,
        service_id: state.service_core_id(),
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
            genesis.event_id.clone(),
        ),
        last_handoff_ref: None,
    };
    let method = arkret_wire::DidUrl::new(
        crate::routing::federation::federation_service_signature_key_id(
            state.service_did().as_str(),
        ),
    )
    .map_err(|error| ServiceError::Internal(error.to_string()))?;
    let committed_at = Utc::now();
    let unit = state
        .authority_commits()
        .prepare_direct_conversation_founding_unit(
            request.clone(),
            &authority,
            method,
            state.notary_signing_key().as_ref(),
            committed_at,
        )?;
    let (status, commits) = match state
        .authority_commits()
        .admit_self_direct_conversation_founding_unit(&unit, &guards, committed_at)
        .await?
    {
        soland_storage::DirectConversationFoundingCommitOutcome::Committed(commits) => {
            (AggregateAcceptanceStatus::Committed, commits)
        }
        soland_storage::DirectConversationFoundingCommitOutcome::Duplicate(commits) => {
            (AggregateAcceptanceStatus::Duplicate, commits)
        }
    };
    let outcome = DirectConversationFoundingAcceptanceOutcome {
        unit_kind: request.unit_kind,
        status,
        commits,
    };
    outcome
        .validate()
        .map_err(|error| ServiceError::Internal(error.to_string()))?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_seven_table_reasons_are_closed_rejected_outcomes_and_others_stay_errors() {
        let mapped = [
            ConflictCode::DirectConversationBindingInvalid,
            ConflictCode::DirectConversationTerminalForbidden,
            ConflictCode::DirectConversationMemberCountInvalid,
            ConflictCode::DirectConversationThirdPartyMemberForbidden,
            ConflictCode::DirectConversationInviteForbidden,
            ConflictCode::DirectConversationRootMaskViolation,
            ConflictCode::DirectConversationParticipantAuthorityDenied,
        ];
        for code in mapped {
            let outcome = direct_conversation_refusal(code).unwrap();
            assert_eq!(
                serde_json::to_value(&outcome).unwrap(),
                serde_json::json!({"status":"rejected","reason_code":code.as_str()})
            );
            let relayed = relay_direct_conversation_refusal(ServiceError::Conflict(format!(
                "{}: refused at the accepting cut",
                code.as_str()
            )))
            .unwrap();
            assert_eq!(relayed, outcome);
        }
        for code in [
            ConflictCode::DirectConversationSpaceForbidden,
            ConflictCode::DirectConversationFoundingUnitInvalid,
            ConflictCode::DirectConversationSlotAlreadyCommitted,
            ConflictCode::CapabilityDenied,
        ] {
            assert!(direct_conversation_refusal(code).is_err());
            let error = ServiceError::Conflict(format!("{}: refused", code.as_str()));
            assert_eq!(
                relay_direct_conversation_refusal(error)
                    .unwrap_err()
                    .conflict_code(),
                Some(code)
            );
        }
    }
}
