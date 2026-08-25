//! Replay-derived governance-history state.

use arkret_state::direct_traversal::{HistoryJoinEpochSubject, derive_history_join_epoch};

use super::*;

pub(super) fn replay_derived_history_join_epoch(
    state: &AppState,
    request_record: &soland_storage::HistoryRequestRecord,
) -> Result<u64, AppError> {
    let traversal = request_record
        .write
        .local_traversal
        .as_ref()
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FrontierUnavailable,
                "history join epoch requires the local retained cut",
            )
        })?;
    let HistoryGovernanceTraversalIntent::MemberHistoryDelivery { mls_group_id, .. } =
        &traversal.retention.traversal_intent
    else {
        return Err(AppError::new(
            ErrorCode::FrontierUnavailable,
            "history join epoch has no member-delivery intent",
        ));
    };
    let request = &request_record.write.request;
    let mut retained_events = Vec::new();
    for pin in &traversal.pins {
        let soland_storage::HistoryTraversalPin::ControlEvent { event_digest, .. } = pin else {
            continue;
        };
        retained_events.push(
            state
                .projections()
                .control_event_by_digest(event_digest)
                .map_err(|error| AppError::internal(error.to_string()))?
                .ok_or_else(|| {
                    AppError::new(
                        ErrorCode::FrontierUnavailable,
                        "retained history Control Event is unavailable",
                    )
                })?,
        );
    }
    derive_history_join_epoch(
        &retained_events,
        &HistoryJoinEpochSubject {
            mls_group_id: arkret_wire::MlsGroupId::new(mls_group_id.clone()).map_err(|error| {
                AppError::new(ErrorCode::FrontierUnavailable, error.to_string())
            })?,
            requester_actor_id: request.requester_actor_id.clone(),
            authorization_incarnation: request.requester_authorization_incarnation.clone(),
        },
    )
    .map_err(|error| AppError::new(ErrorCode::FrontierUnavailable, error.to_string()))
}
