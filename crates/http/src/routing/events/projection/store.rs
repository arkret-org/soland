use std::collections::BTreeSet;

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

pub async fn projected_event_page_for_realms(
    state: &AppState,
    realm_ids: &BTreeSet<String>,
    cursor: Option<&str>,
    limit: usize,
) -> anyhow::Result<Option<ProjectedEventPage>> {
    projected_event_page_for_realms_through(state, realm_ids, cursor, None, limit).await
}

pub async fn projected_event_page_for_realms_in_direction(
    state: &AppState,
    realm_ids: &BTreeSet<String>,
    cursor: Option<&str>,
    limit: usize,
    backward: bool,
) -> anyhow::Result<Option<ProjectedEventPage>> {
    if !backward {
        return projected_event_page_for_realms(state, realm_ids, cursor, limit).await;
    }

    let events = ordered_projected_events_for_realms(state, realm_ids).await?;
    if events.is_empty() {
        return Ok(None);
    }
    let durable_redactions = {
        let projection = state.projections().snapshot();
        message_redactions_from_events(&events, &projection)
    };
    let end = if let Some(cursor) = cursor {
        events
            .iter()
            .position(|event| event.event_id == cursor)
            .ok_or_else(|| anyhow::anyhow!("invalid_cursor: cursor not found"))?
    } else {
        events.len()
    };
    let mut page_items = events
        .into_iter()
        .take(end)
        .rev()
        .filter(|event| event_is_visible(event))
        .take(limit.saturating_add(1))
        .collect::<Vec<_>>();
    {
        let projection = state.projections().snapshot();
        for event in &mut page_items {
            tombstone_projection_event_for_erased_actor(&projection, event);
            tombstone_projection_event_for_message_redaction(
                &projection,
                &durable_redactions,
                event,
            );
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
    let next_cursor = has_more
        .then(|| page_items.last().map(|event| event.event_id.clone()))
        .flatten();
    Ok(Some(ProjectedEventPage {
        items: page_items,
        next_cursor,
        has_more,
    }))
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
    let durable_redactions = {
        let projection = state.projections().snapshot();
        message_redactions_from_events(&events, &projection)
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
        .filter(|event| event_is_visible(event))
        .take(limit.saturating_add(1))
        .collect::<Vec<_>>();
    {
        let projection = state.projections().snapshot();
        for event in &mut page_items {
            tombstone_projection_event_for_erased_actor(&projection, event);
            tombstone_projection_event_for_message_redaction(
                &projection,
                &durable_redactions,
                event,
            );
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
