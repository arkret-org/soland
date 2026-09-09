//! Replay-derived governance-history state.

use super::*;

pub(super) async fn replay_derived_history_join_epoch(
    state: &AppState,
    request_record: &soland_storage::HistoryRequestRecord,
) -> Result<u64, AppError> {
    let traversal = request_record
        .write
        .local_traversal
        .as_ref()
        .ok_or_else(|| {
            crate::app_error!(
                FrontierUnavailable,
                "history join epoch requires the local retained cut",
            )
        })?;
    let HistoryGovernanceTraversalIntent::MemberHistoryDelivery {
        target_basis,
        mls_group_id,
        ..
    } = &traversal.retention.traversal_intent
    else {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "history join epoch has no member-delivery intent",
        ));
    };
    let request = &request_record.write.request;
    if request
        .effective_scope
        .canonical_mls_group_id()
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?
        != *mls_group_id
    {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "retained history group differs from its scope"
        ));
    }
    let mut retained_events = Vec::new();
    for pin in &traversal.pins {
        let soland_storage::HistoryTraversalPin::ControlEvent { event_digest, .. } = pin else {
            continue;
        };
        retained_events.push(
            state
                .projections()
                .control_event_by_digest(event_digest)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .ok_or_else(|| {
                    crate::app_error!(
                        FrontierUnavailable,
                        "retained history Control Event is unavailable",
                    )
                })?,
        );
    }
    let (membership, epoch) = state
        .projections()
        .member_history_at_verified_basis(
            &request.effective_scope,
            &request.requester_actor_id,
            target_basis,
            &retained_events,
        )
        .await
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    if membership.incarnation() != &request.requester_authorization_incarnation {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "retained history membership differs from its request"
        ));
    }
    epoch.ok_or_else(|| {
        crate::app_error!(
            FrontierUnavailable,
            "history membership is ready; MLS lineage is pending"
        )
    })
}
