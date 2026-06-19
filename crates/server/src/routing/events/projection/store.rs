use cokret_sdk::{Operation, OperationId};
use diesel::sql_query;
use diesel::sql_types::{Jsonb, Nullable, Text, Timestamptz, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use serde_json::{Value, json};

use super::*;
use crate::state::{AppState, ProjectionEventRecord};
use crate::{ids, kinds};

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
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    let redacted = redaction_targets_from_events(&events);
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
    if let Ok(projection) = state.projection.lock() {
        for event in &mut page_items {
            tombstone_projection_event_for_erased_actor(&projection, event);
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
    let mut conn = pool.get().await?;
    let realm_id_uuid = ids::typed_uuid_part_or_panic(realm_id);
    let rows = sql_query(
        "SELECT id AS event_id, realm_id, event_type AS event_kind, 'event' AS operation_type, operation_id, sender_id AS sender, payload, created_at \
         FROM events WHERE realm_id = $1 \
         UNION ALL \
         SELECT id AS event_id, realm_id, event_type AS event_kind, 'state' AS operation_type, operation_id, sender_id AS sender, payload, created_at \
         FROM space_state_events WHERE realm_id = $1 \
         ORDER BY created_at ASC, event_id ASC",
    )
    .bind::<SqlUuid, _>(realm_id_uuid)
    .load::<ProjectionEventRow>(&mut *conn).await?;
    Ok(rows
        .into_iter()
        .map(|row| ProjectionEventRecord {
            event_id: ids::format_typed_uuid("event", &row.event_id),
            realm_id: ids::format_typed_uuid("realm", &row.realm_id),
            event_kind: row.event_kind,
            operation_type: row.operation_type,
            operation_id: row
                .operation_id
                .as_ref()
                .map(|u| ids::format_typed_uuid("operation", u)),
            sender: row.sender,
            payload: row.payload,
            created_at: row.created_at,
        })
        .collect())
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
    } else if kinds::canonical_kind_string(operation) == "ck.invite.accept" {
        project_invite_accept_operation(state, origin, operation).await;
    } else if kinds::operation_is_membership(operation)
        || kinds::operation_is_realm_lifecycle(operation)
    {
        project_membership_operation(state, origin, operation).await;
    }
    // Also apply to the deterministic reducer.
    let reducer_effect = state
        .projection
        .lock()
        .ok()
        .map(|mut proj| apply_via_lattice_registry(state, &mut proj, operation));
    if let Some(effect) = reducer_effect {
        mirror_mls_effect_to_persistence(state, operation, &effect).await;
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
    let mut conn = pool.get().await?;
    let event_type = kinds::canonical_kind_string(operation);
    if kinds::operation_is_message_create(operation) {
        let event_id = operation
            .payload
            .get("event_id")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| {
                let op_uuid = ids::typed_uuid_part_or_panic(operation.operation_id.as_str());
                ids::format_typed_uuid("event", &op_uuid)
            });
        let sender = operation
            .payload
            .get("sender")
            .and_then(|value| value.as_str())
            .unwrap_or(origin);
        let thread_id = operation
            .payload
            .get("thread_id")
            .and_then(|value| value.as_str());
        let event_id_uuid = ids::typed_uuid_part_or_panic(&event_id);
        let realm_id_uuid = ids::typed_uuid_part_or_panic(operation.realm_id.as_str());
        let operation_id_uuid = ids::typed_uuid_part_or_panic(operation.operation_id.as_str());
        sql_query(
                "INSERT INTO events (id, realm_id, event_type, sender_id, thread_id, operation_id, payload, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind::<SqlUuid, _>(event_id_uuid)
            .bind::<SqlUuid, _>(realm_id_uuid)
            .bind::<Text, _>(&event_type)
            .bind::<Nullable<Text>, _>(Some(sender))
            .bind::<Nullable<Text>, _>(thread_id)
            .bind::<Nullable<SqlUuid>, _>(Some(operation_id_uuid))
            .bind::<Jsonb, _>(&operation.payload)
            .bind::<Timestamptz, _>(operation.created_at)
            .execute(&mut *conn).await?;
    } else if kinds::operation_is_membership(operation)
        || kinds::operation_is_realm_lifecycle(operation)
    {
        let title = operation_realm_title(operation);
        let title_for_insert = title.unwrap_or_else(|| operation.realm_id.as_str());
        let summary = operation_realm_summary(operation);
        let discoverability = operation_realm_discoverability(operation).unwrap_or_else(|| {
            if operation
                .payload
                .get("public")
                .and_then(|value| value.as_bool())
                .unwrap_or(false)
            {
                "public"
            } else {
                "invite_only"
            }
        });
        let realm_id_uuid = ids::typed_uuid_part_or_panic(operation.realm_id.as_str());
        let operation_id_uuid = ids::typed_uuid_part_or_panic(operation.operation_id.as_str());
        if title.is_some() {
            sql_query(
                    "INSERT INTO spaces (id, title, summary, owner_id, discoverability, payload, created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $7) \
                     ON CONFLICT (id) DO UPDATE SET title = EXCLUDED.title, summary = COALESCE(EXCLUDED.summary, spaces.summary), updated_at = EXCLUDED.updated_at",
                )
                .bind::<SqlUuid, _>(realm_id_uuid)
                .bind::<Text, _>(title_for_insert)
                .bind::<Nullable<Text>, _>(summary)
                .bind::<Nullable<Text>, _>(Some(origin))
                .bind::<Text, _>(discoverability)
                .bind::<Jsonb, _>(&operation.payload)
                .bind::<Timestamptz, _>(operation.created_at)
                .execute(&mut *conn).await?;
        } else {
            sql_query(
                    "INSERT INTO spaces (id, title, summary, owner_id, discoverability, payload, created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $7) \
                     ON CONFLICT (id) DO UPDATE SET summary = COALESCE(EXCLUDED.summary, spaces.summary), updated_at = EXCLUDED.updated_at",
                )
                .bind::<SqlUuid, _>(realm_id_uuid)
                .bind::<Text, _>(title_for_insert)
                .bind::<Nullable<Text>, _>(summary)
                .bind::<Nullable<Text>, _>(Some(origin))
                .bind::<Text, _>(discoverability)
                .bind::<Jsonb, _>(&operation.payload)
                .bind::<Timestamptz, _>(operation.created_at)
                .execute(&mut *conn).await?;
        }

        if let Some(member) = operation
            .payload
            .get("actor_id")
            .and_then(|value| value.as_str())
        {
            let membership = operation
                .payload
                .get("membership")
                .and_then(|value| value.as_str())
                .unwrap_or("join");
            sql_query(
                    "INSERT INTO space_members (id, realm_id, actor_id, membership, payload, joined_at, left_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, CASE WHEN $4 = 'join' THEN $6 ELSE NULL END, CASE WHEN $4 <> 'join' THEN $6 ELSE NULL END, $6) \
                     ON CONFLICT (realm_id, actor_id) DO UPDATE SET membership = EXCLUDED.membership, payload = EXCLUDED.payload, left_at = EXCLUDED.left_at, updated_at = EXCLUDED.updated_at",
                )
                .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::now_v7())
                .bind::<SqlUuid, _>(realm_id_uuid)
                .bind::<Text, _>(member)
                .bind::<Text, _>(membership)
                .bind::<Jsonb, _>(&operation.payload)
                .bind::<Timestamptz, _>(operation.created_at)
                .execute(&mut *conn).await?;
        }

        // The DB column matches the canonical projection-cell key
        // model: `(realm_id, event_type, subject)` identifies the cell.
        // The space_state_events row reuses the operation_id as its primary
        // key — same UUID, different typed wire form (operation vs event).
        sql_query(
                "INSERT INTO space_state_events (id, realm_id, event_type, subject, sender_id, operation_id, payload, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $1, $6, $7) \
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind::<SqlUuid, _>(operation_id_uuid)
            .bind::<SqlUuid, _>(realm_id_uuid)
            .bind::<Text, _>(&event_type)
            .bind::<Text, _>(
                operation
                    .payload
                    .get("member")
                    .and_then(|value| value.as_str())
                    .unwrap_or(""),
            )
            .bind::<Nullable<Text>, _>(Some(origin))
            .bind::<Jsonb, _>(&operation.payload)
            .bind::<Timestamptz, _>(operation.created_at)
            .execute(&mut *conn).await?;
    }
    Ok(())
}
