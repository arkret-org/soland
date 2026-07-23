use std::collections::BTreeSet;

use arkret_event_draft::Operation;
use arkret_identifiers::OperationId;
use soland_application::events::ProjectedEvent as ProjectionEventRecord;
use soland_application::operation_semantics as kinds;

use super::*;
use crate::state::AppState;

pub async fn append_projection_event(
    state: &AppState,
    event: ProjectionEventRecord,
) -> soland_application::ApplicationResult<soland_application::events::ProjectedEventAppendResult> {
    state
        .event_query_application()
        .append_projected_event(event)
        .await
}

pub async fn persist_and_publish_projection_event(
    state: &AppState,
    event: ProjectionEventRecord,
) -> soland_application::ApplicationResult<soland_application::events::ProjectedEventAppendResult> {
    let outcome = append_projection_event(state, event.clone()).await?;
    if outcome == soland_application::events::ProjectedEventAppendResult::Inserted {
        let _ = state.publish_event_notification(crate::state::EventNotification::event(
            event.realm_id.clone(),
            event.event_id.clone(),
            projection_event_json(&event),
        ));
    }
    Ok(outcome)
}

pub async fn projected_event_page(
    state: &AppState,
    realm_id: &str,
    cursor: Option<&str>,
    limit: usize,
) -> anyhow::Result<Option<ProjectedEventPage>> {
    let realm_ids = BTreeSet::from([realm_id.to_owned()]);
    projected_event_page_for_realms(state, &realm_ids, cursor, limit).await
}

pub async fn projected_event_page_for_realms(
    state: &AppState,
    realm_ids: &BTreeSet<String>,
    cursor: Option<&str>,
    limit: usize,
) -> anyhow::Result<Option<ProjectedEventPage>> {
    projected_event_page_for_realms_through(state, realm_ids, cursor, None, limit).await
}

pub async fn projected_event_replay_upper_bound(
    state: &AppState,
    realm_ids: &BTreeSet<String>,
    cursor: &str,
) -> anyhow::Result<Option<String>> {
    let events = ordered_projected_events_for_realms(state, realm_ids).await?;
    let start = events
        .iter()
        .position(|event| event.event_id == cursor)
        .map(|index| index + 1)
        .ok_or_else(|| anyhow::anyhow!("invalid_cursor: cursor not found"))?;
    Ok(events
        .get(start..)
        .and_then(|events| events.last())
        .map(|event| event.event_id.clone()))
}

pub async fn projected_event_page_for_realms_through(
    state: &AppState,
    realm_ids: &BTreeSet<String>,
    cursor: Option<&str>,
    upper_bound_event_id: Option<&str>,
    limit: usize,
) -> anyhow::Result<Option<ProjectedEventPage>> {
    let events = ordered_projected_events_for_realms(state, realm_ids).await?;
    if events.is_empty() {
        return Ok(None);
    }
    let redacted = {
        let projection = state.projection_application().snapshot();
        redaction_target_event_ids_from_events(&events, &projection)
    };
    let start = if let Some(cursor) = cursor {
        events
            .iter()
            .position(|event| event.event_id == cursor)
            .map(|index| index + 1)
            .ok_or_else(|| anyhow::anyhow!("invalid_cursor: cursor not found"))?
    } else {
        0
    };
    let end = match upper_bound_event_id {
        Some(upper_bound) => events
            .iter()
            .position(|event| event.event_id == upper_bound)
            .map(|index| index + 1)
            .ok_or_else(|| anyhow::anyhow!("invalid_cursor: replay upper bound not found"))?,
        None => events.len(),
    };
    if end < start {
        return Err(anyhow::anyhow!(
            "invalid_cursor: replay upper bound precedes cursor"
        ));
    }
    let mut page_items = events
        .into_iter()
        .skip(start)
        .take(end - start)
        .filter(|event| event_is_visible(event, &redacted))
        .take(limit.saturating_add(1))
        .collect::<Vec<_>>();
    {
        let projection = state.projection_application().snapshot();
        for event in &mut page_items {
            tombstone_projection_event_for_erased_actor(&projection, event);
            tombstone_projection_event_for_message_redaction(&projection, event);
            stub_projection_event_for_message_expiry(&projection, event, now());
            stub_pin_projection_event_for_invisible_target(&projection, event);
        }
    }
    for event in &mut page_items {
        if let Some(tombstone) = retention_tombstone_for_event(state, &event.event_id) {
            tombstone_projection_event_for_retention(event, &tombstone);
        }
    }
    let has_more = page_items.len() > limit;
    if has_more {
        page_items.truncate(limit);
    }
    let next_cursor = if has_more {
        page_items.last().map(|event| event.event_id.clone())
    } else {
        None
    };
    Ok(Some(ProjectedEventPage {
        items: page_items,
        next_cursor,
        has_more,
    }))
}

async fn ordered_projected_events_for_realms(
    state: &AppState,
    realm_ids: &BTreeSet<String>,
) -> anyhow::Result<Vec<ProjectionEventRecord>> {
    let mut events = state
        .event_query_application()
        .projected_events()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|event| realm_ids.contains(&event.realm_id))
        .collect::<Vec<_>>();
    if events.is_empty() {
        return Ok(events);
    }
    events.sort_by(|left, right| {
        left.received_at
            .cmp(&right.received_at)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    Ok(events)
}

pub struct FederationIngestResult {
    pub accepted: Vec<OperationId>,
    pub rejected: Vec<arkret_models_collaboration::http_bodies::EventsSubmitRejectedItem>,
}

fn federation_rejection(
    operation_id: &OperationId,
    reason_code: impl Into<String>,
    detail: Option<String>,
) -> arkret_models_collaboration::http_bodies::EventsSubmitRejectedItem {
    arkret_models_collaboration::http_bodies::EventsSubmitRejectedItem {
        id: operation_id.to_string(),
        reason_code: reason_code.into(),
        detail,
    }
}

pub async fn ingest_federation_operations(
    state: &AppState,
    origin: &str,
    operations: Vec<Operation>,
) -> FederationIngestResult {
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    let profile_gate =
        match crate::routing::federation::federation::federation_profile_intersection_for_peer(
            state, origin, None,
        )
        .await
        {
            Ok(gate) => gate,
            Err(rejection) => {
                rejected.extend(operations.iter().map(|operation| {
                    federation_rejection(
                        &operation.operation_id,
                        rejection.code,
                        Some(rejection.message.clone()),
                    )
                }));
                return FederationIngestResult { accepted, rejected };
            }
        };
    for operation in operations {
        let operation_id = operation.operation_id.clone();
        if state
            .federation_application()
            .has_operation(operation_id.as_str())
            .await
            .unwrap_or(false)
        {
            accepted.push(operation_id);
            continue;
        }
        let _active_series_guards =
            crate::routing::events::operations::lock_active_series_operations(
                std::slice::from_ref(&operation),
            )
            .await;
        if operation.validate_payload_object().is_err() {
            rejected.push(federation_rejection(&operation_id, "invalid_payload", None));
            continue;
        }
        if let Err(rejection) = profile_gate.enforce_operation(&operation) {
            rejected.push(federation_rejection(
                &operation_id,
                rejection.code,
                Some(rejection.message),
            ));
            continue;
        }
        if let Err(message) = validate_operation_semantics(state, std::slice::from_ref(&operation))
        {
            rejected.push(federation_rejection(
                &operation_id,
                "invalid_semantics",
                Some(message.to_owned()),
            ));
            continue;
        }
        if let Err(message) =
            validate_content_encryption_floor(state, std::slice::from_ref(&operation)).await
        {
            rejected.push(federation_rejection(
                &operation_id,
                message,
                Some(message.to_owned()),
            ));
            continue;
        }
        if let Err(message) =
            validate_operation_policy(state, std::slice::from_ref(&operation)).await
        {
            let (_, code) =
                crate::routing::events::operations::operation_policy_reason_code(message);
            rejected.push(federation_rejection(
                &operation_id,
                code,
                Some(message.to_owned()),
            ));
            continue;
        }
        if let Err(error) = state
            .federation_application()
            .append_operation(operation.clone())
            .await
        {
            tracing::error!(%error, "failed to persist federation operation");
            rejected.push(federation_rejection(
                &operation_id,
                "persistence_error",
                Some(error.to_string()),
            ));
            continue;
        }
        project_federation_operation(state, origin, &operation).await;
        accepted.push(operation_id);
    }
    FederationIngestResult { accepted, rejected }
}

pub async fn project_federation_operation(state: &AppState, origin: &str, operation: &Operation) {
    ensure_projected_realm(state, origin, operation).await;
    if kinds::operation_is_message_create(operation) {
        project_federated_message(state, origin, operation).await;
    } else if kinds::operation_is_invite_create(operation) {
        project_invite_create_operation(state, origin, operation).await;
    } else if kinds::operation_is_invite_third_party(operation) {
        project_invite_third_party_operation(state, operation).await;
    } else if kinds::operation_is_invite_claim(operation) {
        project_invite_claim_operation(state, operation).await;
    } else if kinds::canonical_kind_string(operation) == "ak.invite.accept" {
        project_invite_accept_operation(state, origin, operation).await;
    } else if kinds::canonical_kind_string(operation)
        == arkret_wire::events::EventKind::INVITE_CANCEL
    {
        project_invite_cancel_operation(state, origin, operation).await;
    } else if kinds::canonical_kind_string(operation)
        == arkret_wire::events::EventKind::INVITE_REVOKE
    {
        project_invite_revoke_operation(state, origin, operation).await;
    } else if kinds::operation_is_membership(operation)
        || kinds::operation_is_realm_lifecycle(operation)
    {
        project_membership_operation(state, origin, operation).await;
    }
    // Also apply to the deterministic reducer.
    let reducer_effect = Some(
        state
            .projection_application()
            .apply_via_lattice_registry(operation, state.hlc()),
    );
    if let Some(effect) = reducer_effect {
        mirror_mls_effect_to_persistence(state, origin, "", operation, &effect).await;
    }
    let _ = append_projection_event(
        state,
        projection_event_from_operation(operation, Some(origin)),
    )
    .await;
}

pub async fn accept_local_operations(
    state: &AppState,
    actor: &str,
    operations: &[Operation],
) -> Result<(), &'static str> {
    let _active_series_guards =
        crate::routing::events::operations::lock_active_series_operations(operations).await;
    validate_operation_semantics(state, operations)?;
    validate_content_encryption_floor(state, operations).await?;
    validate_operation_policy(state, operations).await?;
    project_accepted_operations(state, actor, operations).await;
    Ok(())
}

pub async fn accept_trusted_sidecar_circle_operation(
    state: &AppState,
    controller: &str,
    sidecar_id: &arkret_identifiers::SidecarId,
    operation: &Operation,
) -> Result<(), &'static str> {
    let _active_series_guards = crate::routing::events::operations::lock_active_series_operations(
        std::slice::from_ref(operation),
    )
    .await;
    validate_operation_semantics(state, std::slice::from_ref(operation))?;
    validate_content_encryption_floor(state, std::slice::from_ref(operation)).await?;
    crate::routing::events::operations::validate_trusted_sidecar_circle_operation(
        state, operation, controller, sidecar_id,
    )
    .await?;
    project_accepted_operations(state, controller, std::slice::from_ref(operation)).await;
    Ok(())
}

pub async fn accept_trusted_sidecar_create_operation(
    state: &AppState,
    controller: &str,
    backing_circle_id: &arkret_identifiers::CircleId,
    operation: &Operation,
) -> Result<(), &'static str> {
    let _active_series_guards = crate::routing::events::operations::lock_active_series_operations(
        std::slice::from_ref(operation),
    )
    .await;
    validate_operation_semantics(state, std::slice::from_ref(operation))?;
    crate::routing::events::operations::validate_trusted_sidecar_create_operation(
        operation,
        controller,
        backing_circle_id,
    )?;
    project_accepted_operations(state, controller, std::slice::from_ref(operation)).await;
    Ok(())
}

pub async fn accept_trusted_sidecar_member_operation(
    state: &AppState,
    controller: &str,
    operation: &Operation,
) -> Result<(), &'static str> {
    let _active_series_guards = crate::routing::events::operations::lock_active_series_operations(
        std::slice::from_ref(operation),
    )
    .await;
    validate_operation_semantics(state, std::slice::from_ref(operation))?;
    validate_content_encryption_floor(state, std::slice::from_ref(operation)).await?;
    crate::routing::events::operations::validate_trusted_sidecar_member_operation(
        state, operation, controller,
    )
    .await?;
    project_trusted_sidecar_member_operation(state, controller, operation).await;
    Ok(())
}

pub async fn persist_projected_operation(
    state: &AppState,
    origin: &str,
    operation: &Operation,
) -> anyhow::Result<()> {
    state
        .event_query_application()
        .persist_projected_operation(origin, operation)
        .await
        .map_err(Into::into)
}
