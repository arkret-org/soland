use arkret_models_collaboration::event_query::{
    EventDeliveryStatusOutcome, EventDeliveryStatusRequestBody,
};

use super::*;

pub(in crate::routing::events) fn router() -> Router {
    Router::new()
        .push(Router::with_path("events/delivery-status").query(event_delivery_status))
        .push(
            Router::with_path("committed-events/subscribe")
                .get(super::super::sync::events_subscribe),
        )
        .push(Router::with_path("events").post(crate::routing::authority_commit::submit_self))
        .push(Router::with_path("committed-events/{event_id}").get(get_committed_event))
}

#[salvo::oapi::endpoint(operation_id = "ak.self.committed_event.resource.get", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.committed_event.resource.get.v1"))]
async fn get_committed_event(
    aa: AuthArgs,
    event_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CommittedEventView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let event_id = EventId::new(event_id.into_inner())
        .map_err(|_| AppError::not_found("committed event not found"))?;
    let Some(record) = state
        .event_queries()
        .canonical_event(event_id.as_str())
        .await
        .ok()
        .flatten()
    else {
        return withheld_chain_node(state, &session, &event_id).await;
    };
    if !event_visible_to_session(state, &record, &session).await {
        return Err(AppError::not_found("committed event not found"));
    }
    let committed = state
        .persistence()
        .committed_event(&event_id)
        .await
        .map_err(|error| AppError::internal(format!("committed Event lookup failed: {error}")))?
        .ok_or_else(|| AppError::not_found("committed event not found"))?;
    refuse_pending_replica(state, &committed.commit.realm_id).await?;
    let view = CommittedEventView::Full(CommittedEventFullView {
        commit: committed.commit,
        event: committed.event,
    });
    view.validate_shape().map_err(|error| {
        AppError::internal(format!("durable committed Event view is invalid: {error}"))
    })?;
    json_ok(view)
}

/// A member Station's held Realm stream that is still pending its bootstrap
/// anchor serves no local read (`federation.md` §4.1.1).
async fn refuse_pending_replica(state: &AppState, realm_id: &RealmId) -> Result<(), AppError> {
    let anchor = state
        .authority_commits()
        .replica_stream_anchor(realm_id)
        .await
        .map_err(|error| AppError::internal(format!("replica anchor lookup failed: {error}")))?;
    if anchor.is_some_and(|anchor| anchor.anchored_head.is_none()) {
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "the held Realm stream is pending its bootstrap anchor",
        ));
    }
    Ok(())
}

/// A withheld chain node a member Station holds is read only as the withheld
/// branch, by a member the Station hosts in its Realm (`federation.md`
/// §4.1.1).
async fn withheld_chain_node(
    state: &AppState,
    session: &SessionRecord,
    event_id: &EventId,
) -> JsonResult<CommittedEventView> {
    let commit = state
        .authority_commits()
        .committed_chain_node(event_id)
        .await
        .map_err(|error| AppError::internal(format!("chain node lookup failed: {error}")))?
        .ok_or_else(|| AppError::not_found("committed event not found"))?;
    let caller =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)
            .map_err(|_| AppError::not_found("committed event not found"))?;
    if !crate::routing::realm_has_member(state, commit.realm_id.as_str(), &caller.to_string()).await
    {
        return Err(AppError::not_found("committed event not found"));
    }
    json_ok(CommittedEventView::Withheld(
        arkret_wire::CommittedEventWithheldView {
            commit,
            event_disclosure: arkret_wire::EventDisclosure {
                status: arkret_wire::EventDisclosureStatus::Withheld,
            },
        },
    ))
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.events.read.delivery_status.v1"))]
async fn event_delivery_status(
    aa: AuthArgs,
    body: JsonBody<EventDeliveryStatusRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventDeliveryStatusOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    super::super::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_EVENTS_READ_DELIVERY_STATUS_V1,
    )?;
    let body = body.into_inner();
    let event_id = body.event_id.as_str();
    let record = state
        .event_queries()
        .canonical_event(event_id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| AppError::not_found("event not found"))?;
    if !event_visible_to_session(state, &record, &session).await {
        return Err(AppError::not_found("event not found"));
    }
    let deliveries = state
        .federation()
        .deliveries_for_event(event_id)
        .await
        .map_err(|error| {
            AppError::internal(format!("Event delivery status unavailable: {error}"))
        })?;
    let mut targets = BTreeMap::new();
    for delivery in deliveries {
        let Some(mut target) =
            soland_services::federation::event_delivery_target_status(&delivery, event_id)
                .map_err(|error| AppError::internal(error.to_string()))?
        else {
            continue;
        };
        let binding =
            delivery.delivery.realm_fanout.as_ref().ok_or_else(|| {
                AppError::internal("projected Realm fanout target lost its binding")
            })?;
        let can_read_service_id = caller_can_read_delivery_target_service(
            state,
            &session,
            binding,
            delivery.delivery.peer_id.as_str(),
        )
        .await;
        if can_read_service_id {
            target.service_id = Some(delivery.delivery.peer_id.clone());
        }
        if targets.insert(target.target_id.clone(), target).is_some() {
            return Err(AppError::internal(
                "duplicate durable Realm fanout target for one Event",
            ));
        }
    }
    let targets = targets.into_values().collect::<Vec<_>>();
    let outcome = EventDeliveryStatusOutcome {
        event_id: body.event_id,
        targets,
    };
    outcome
        .validate()
        .map_err(|error| AppError::internal(format!("invalid Event delivery status: {error}")))?;
    json_ok(outcome)
}

async fn caller_can_read_delivery_target_service(
    state: &AppState,
    session: &SessionRecord,
    binding: &soland_services::federation::RealmFanoutBinding,
    recipient_id: &str,
) -> bool {
    for witness in &binding.authority_witnesses {
        let member_key = witness.member_id.to_string();
        let witness_is_current = state
            .projections()
            .snapshot()
            .member(&binding.realm_id, &member_key)
            .is_some_and(|member| {
                member.state == "join"
                    && witness.member_id.route_service_id().as_str() == recipient_id
                    && member.membership_event_ref.as_deref()
                        == Some(witness.membership_event_ref.as_str())
            });
        if !witness_is_current {
            continue;
        }
        let Ok(Some(membership_event)) = state
            .event_queries()
            .canonical_event(&witness.membership_event_ref)
            .await
        else {
            continue;
        };
        if !event_visible_to_session(state, &membership_event, session).await {
            continue;
        }
        return true;
    }
    false
}
