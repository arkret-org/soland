use arkret_sdk::{Operation, OperationId};
use serde_json::{Value, json};

use super::*;
use crate::kinds;
use crate::state::{AppState, ProjectionEventRecord};

pub async fn append_projection_event(state: &AppState, event: ProjectionEventRecord) {
    let store = state.persistence.projection_events();
    let exists = store
        .snapshot_all()
        .await
        .map(|known| known.iter().any(|record| record.event_id == event.event_id))
        .unwrap_or(false);
    if exists {
        return;
    }
    if let Err(error) = store.append(event).await {
        tracing::warn!(%error, "failed to persist projection event");
    }
}

pub async fn projected_event_page(
    state: &AppState,
    realm_id: &str,
    cursor: Option<&str>,
    limit: usize,
) -> anyhow::Result<Option<ProjectedEventPage>> {
    let mut events = state
        .persistence
        .projection_events()
        .snapshot_all()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|event| event.realm_id == realm_id)
        .collect::<Vec<_>>();
    if events.is_empty() {
        events = load_projected_events_from_pg(state, realm_id).await?;
    }
    if events.is_empty() {
        return Ok(None);
    }
    events.sort_by(|left, right| {
        left.received_at
            .cmp(&right.received_at)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
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
    let mut page_items = events
        .into_iter()
        .skip(start)
        .filter(|event| event_is_visible(event, &redacted))
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

pub async fn load_projected_events_from_pg(
    state: &AppState,
    realm_id: &str,
) -> anyhow::Result<Vec<ProjectionEventRecord>> {
    let Some(pool) = state.db.pool.as_ref() else {
        return Ok(Vec::new());
    };
    crate::persistence::load_projected_events_from_pg(pool, realm_id)
        .await
        .map_err(Into::into)
}

pub struct FederationIngestResult {
    pub accepted: Vec<OperationId>,
    pub rejected: Vec<Value>,
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
                    json!({
                        "operation_id": operation.operation_id.clone(),
                        "reason": rejection.code,
                        "message": rejection.message.clone(),
                    })
                }));
                return FederationIngestResult { accepted, rejected };
            }
        };
    for operation in operations {
        let operation_id = operation.operation_id.clone();
        if state
            .persistence
            .federation_operations()
            .contains(operation_id.as_str())
            .await
            .unwrap_or(false)
        {
            accepted.push(operation_id);
            continue;
        }
        if operation.validate_payload_object().is_err() {
            rejected.push(json!({
                "operation_id": operation_id,
                "reason": "invalid_payload",
            }));
            continue;
        }
        if let Err(rejection) = profile_gate.enforce_operation(&operation) {
            rejected.push(json!({
                "operation_id": operation_id,
                "reason": rejection.code,
                "message": rejection.message,
            }));
            continue;
        }
        if let Err(message) = validate_operation_semantics(state, std::slice::from_ref(&operation))
        {
            rejected.push(json!({
                "operation_id": operation_id,
                "reason": "invalid_semantics",
                "message": message,
            }));
            continue;
        }
        if let Err(message) =
            validate_content_encryption_floor(state, std::slice::from_ref(&operation)).await
        {
            rejected.push(json!({
                "operation_id": operation_id,
                "reason": message,
                "message": message,
            }));
            continue;
        }
        if let Err(message) =
            validate_operation_policy(state, std::slice::from_ref(&operation)).await
        {
            let (_, code) =
                crate::routing::events::operations::operation_policy_reason_code(message);
            rejected.push(json!({
                "operation_id": operation_id,
                "reason": code,
                "message": message,
            }));
            continue;
        }
        if let Err(error) = state
            .persistence
            .federation_operations()
            .append(operation.clone())
            .await
        {
            tracing::error!(%error, "failed to persist federation operation");
            rejected.push(json!({
                "operation_id": operation_id,
                "reason": "persistence_error",
                "message": error.to_string(),
            }));
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
    } else if kinds::canonical_kind_string(operation) == arkret_sdk::events::kinds::INVITE_CANCEL {
        project_invite_cancel_operation(state, origin, operation).await;
    } else if kinds::canonical_kind_string(operation) == arkret_sdk::events::kinds::INVITE_REVOKE {
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
    append_projection_event(
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
    validate_operation_semantics(state, operations)?;
    validate_content_encryption_floor(state, operations).await?;
    validate_operation_policy(state, operations).await?;
    project_accepted_operations(state, actor, operations).await;
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
    crate::persistence::persist_projected_operation_to_pg(pool, origin, operation)
        .await
        .map_err(Into::into)
}
