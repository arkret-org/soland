use std::collections::BTreeSet;

use arkret_event_draft::Operation;
use soland_services::events::ProjectedEvent as ProjectionEventRecord;

use super::*;
use crate::state::AppState;

pub async fn append_projection_event(
    state: &AppState,
    event: ProjectionEventRecord,
) -> soland_services::ServiceResult<soland_services::events::ProjectedEventAppendResult> {
    state.event_queries().append_projected_event(event).await
}

pub async fn persist_and_publish_projection_event(
    state: &AppState,
    event: ProjectionEventRecord,
) -> soland_services::ServiceResult<soland_services::events::ProjectedEventAppendResult> {
    let outcome = append_projection_event(state, event.clone()).await?;
    if outcome == soland_services::events::ProjectedEventAppendResult::Inserted {
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
        let projection = state.projections().snapshot();
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
        let projection = state.projections().snapshot();
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
    let mut events = Vec::new();
    for realm_id in realm_ids {
        events.extend(
            state
                .event_queries()
                .projected_events_for_realm(realm_id)
                .await?,
        );
    }
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

pub async fn accept_local_operations(
    state: &AppState,
    actor: &str,
    operations: &[Operation],
) -> Result<(), &'static str> {
    accept_local_operations_with_policy_context(
        state, actor, operations, operations, operations, false,
    )
    .await
}

async fn accept_local_operations_with_policy_context(
    state: &AppState,
    actor: &str,
    operations: &[Operation],
    policy_operations: &[Operation],
    projection_operations: &[Operation],
    persist_before_projection: bool,
) -> Result<(), &'static str> {
    let _active_series_guards =
        crate::routing::events::operations::lock_active_series_operations(operations).await;
    {
        let projection = state.projections().snapshot();
        for operation in operations {
            projection.check_move_preconditions(operation)?;
        }
    }
    validate_operation_semantics(state, operations)?;
    validate_content_encryption_floor(state, operations).await?;
    validate_operation_policy(state, policy_operations).await?;
    let mut inserted_events = Vec::new();
    if persist_before_projection {
        for operation in projection_operations {
            let event = projection_event_from_operation(operation, Some(actor));
            if append_projection_event(state, event.clone())
                .await
                .map_err(|_| "projection_event_persistence_failed")?
                == soland_services::events::ProjectedEventAppendResult::Inserted
            {
                inserted_events.push(event);
            }
        }
    }
    project_accepted_operations(state, actor, projection_operations).await;
    for event in inserted_events {
        let _ = state.publish_event_notification(crate::state::EventNotification::event(
            event.realm_id.clone(),
            event.event_id.clone(),
            projection_event_json(&event),
        ));
    }
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
        .event_queries()
        .persist_projected_operation(origin, operation)
        .await
        .map_err(Into::into)
}
