use std::collections::BTreeSet;

use arkret_sdk::{Operation, OperationId};
use soland_domain::kinds;
use soland_storage::ProjectionEventRecord;

use super::*;
use crate::state::AppState;

pub async fn append_projection_event(
    state: &AppState,
    event: ProjectionEventRecord,
) -> soland_storage::PersistenceResult<soland_storage::ProjectionEventAppendOutcome> {
    state.projection_events_store().append(event).await
}

pub async fn persist_and_publish_projection_event(
    state: &AppState,
    event: ProjectionEventRecord,
) -> soland_storage::PersistenceResult<soland_storage::ProjectionEventAppendOutcome> {
    let outcome = append_projection_event(state, event.clone()).await?;
    if outcome == soland_storage::ProjectionEventAppendOutcome::Inserted {
        let _ = state
            .event_broadcast
            .send(crate::state::EventNotification::event(
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
        let projection = state.projection.lock();
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
        let projection = state.projection.lock();
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
        .projection_events_store()
        .snapshot_all()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|event| realm_ids.contains(&event.realm_id))
        .collect::<Vec<_>>();
    let loaded_realms = events
        .iter()
        .map(|event| event.realm_id.clone())
        .collect::<BTreeSet<_>>();
    for realm_id in realm_ids.difference(&loaded_realms) {
        events.extend(load_projected_events_from_pg(state, realm_id).await?);
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

pub async fn load_projected_events_from_pg(
    state: &AppState,
    realm_id: &str,
) -> anyhow::Result<Vec<ProjectionEventRecord>> {
    let Some(pool) = state.db.pool.as_ref() else {
        return Ok(Vec::new());
    };
    soland_storage_postgres::load_projected_events_from_pg(pool, realm_id)
        .await
        .map_err(Into::into)
}

pub struct FederationIngestResult {
    pub accepted: Vec<OperationId>,
    pub rejected: Vec<arkret_sdk::EventsSubmitRejectedItem>,
}

fn federation_rejection(
    operation_id: &OperationId,
    reason_code: impl Into<String>,
    detail: Option<String>,
) -> arkret_sdk::EventsSubmitRejectedItem {
    arkret_sdk::EventsSubmitRejectedItem {
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
            .federation_operations_store()
            .contains(operation_id.as_str())
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
            .federation_operations_store()
            .append(operation.clone())
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
        == arkret_sdk::events::EventKind::INVITE_CANCEL
    {
        project_invite_cancel_operation(state, origin, operation).await;
    } else if kinds::canonical_kind_string(operation)
        == arkret_sdk::events::EventKind::INVITE_REVOKE
    {
        project_invite_revoke_operation(state, origin, operation).await;
    } else if kinds::operation_is_membership(operation)
        || kinds::operation_is_realm_lifecycle(operation)
    {
        project_membership_operation(state, origin, operation).await;
    }
    // Also apply to the deterministic reducer.
    let reducer_effect = {
        let mut proj = state.projection.lock();
        Some(apply_via_lattice_registry(state, &mut proj, operation))
    };
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
    operation: &Operation,
) -> Result<(), &'static str> {
    let _active_series_guards = crate::routing::events::operations::lock_active_series_operations(
        std::slice::from_ref(operation),
    )
    .await;
    validate_operation_semantics(state, std::slice::from_ref(operation))?;
    validate_content_encryption_floor(state, std::slice::from_ref(operation)).await?;
    crate::routing::events::operations::validate_trusted_sidecar_circle_operation(
        state, operation, controller,
    )
    .await?;
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
    let Some(pool) = state.db.pool.as_ref() else {
        return Ok(());
    };
    let event_type = soland_domain::kinds::canonical_kind_string(operation);
    let is_message_create = soland_domain::kinds::operation_is_message_create(operation);
    let is_membership_or_realm_lifecycle = soland_domain::kinds::operation_is_membership(operation)
        || soland_domain::kinds::operation_is_realm_lifecycle(operation);
    soland_storage_postgres::persist_projected_operation_to_pg(
        pool,
        origin,
        operation,
        &event_type,
        is_message_create,
        is_membership_or_realm_lifecycle,
    )
    .await
    .map_err(Into::into)
}
