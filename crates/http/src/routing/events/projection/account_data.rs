use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_models_collaboration::objects::read_receipts::ReadCursorCausalRelation;
use arkret_models_collaboration::sync_frames::account_sync::{
    ActorPrivateAccountDataOperation, ActorPrivateAccountDataUpdate, ActorPrivateDeviceUpdate,
    ActorPrivateReadCursorUpdate, DeviceMessageSender,
};
use serde_json::Value;
use soland_services::identity::{AccountDataCasOutcome, AccountDataState};
use soland_services::operation_semantics as kinds;

use crate::routing::identity::device_messages::fanout_actor_private_update;
use crate::state::AppState;

/// Project a `ak.realm.read_receipt_policy` (post-R1.2; was
/// `ak.space.read_receipt_policy`) durable-event into
/// `ProjectionState::cells` as a synthesized CasRegister value at the
/// canonical cell
/// `ak:cell:ak.component.realm.read_receipt_policy.v1:<realm_id>`.
/// This unifies the read path with the Move/Seal pipeline: both durable-
/// event ingestion AND Move/Seal `apply_seal` write to the same cells
/// map, so `routing::events::effective_read_receipt_policy_for_realm`
/// queries one source.
///
/// Cas-register semantics: the projection writer wins-by-arrival here
/// (we don't have HLC ordering on synthesized values yet); for full
/// cas-register conflict semantics writes should go through Move/Seal.
pub fn project_read_receipt_policy(state: &AppState, operation: &Operation) {
    let realm_id = operation.realm_id.clone();
    let policy: arkret_models_collaboration::objects::read_receipts::ReadReceiptPolicy =
        match serde_json::from_value(operation.payload.clone()) {
            Ok(policy) => policy,
            Err(_) => return,
        };

    // Synthesize a CellState::Value at the canonical cell ref. This lets
    // the cells-map fast-path serve reads without scanning the durable
    // Event store on every fanout.
    let cell_id = match arkret_identifiers::CellRef::new(format!(
        "ak:cell:ak.component.realm.read_receipt_policy.v1:{}",
        realm_id.as_str()
    )) {
        Ok(c) => c,
        Err(_) => return,
    };
    let value = match serde_json::to_value(policy) {
        Ok(value) => value,
        Err(_) => return,
    };
    state.projections().cache_cell(cell_id, value);
}

pub(super) fn actor_private_read_cursor_matches_origin(
    origin: &str,
    source_device_id: &str,
    operation: &Operation,
) -> bool {
    if kinds::canonical_kind(operation) != arkret_wire::EventKind::ReadCursorAdvance
        || source_device_id.is_empty()
    {
        return true;
    }
    let actor_matches = operation
        .payload
        .get("actor_id")
        .cloned()
        .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value).ok())
        .is_some_and(|actor_id| {
            actor_id == operation.context.sender
                && actor_id.signing_principal_id().as_str() == origin
        });
    let device_matches = operation
        .payload
        .get("device_id")
        .and_then(Value::as_str)
        .is_none_or(|device_id| device_id == source_device_id);
    if !actor_matches || !device_matches {
        tracing::warn!(
            origin,
            source_device_id,
            operation_id = %operation.operation_id,
            "ak.read_cursor.advance actor/device does not match accepted event origin"
        );
        return false;
    }
    true
}

pub(super) async fn read_cursor_reducer_context_operation(
    state: &AppState,
    operation: &Operation,
) -> Option<Operation> {
    if kinds::canonical_kind(operation) != arkret_wire::EventKind::ReadCursorAdvance {
        return None;
    }
    let actor_id =
        serde_json::from_value::<arkret_wire::ActorId>(operation.payload.get("actor_id")?.clone())
            .ok()?;
    let read_scope: arkret_wire::ReadCursorScope =
        serde_json::from_value(operation.payload.get("read_scope")?.clone()).ok()?;
    let candidate_event_id = operation
        .payload
        .get("position")?
        .get("event_id")?
        .as_str()?;
    let current_event_id = {
        let projection = state.projections().snapshot();
        projection
            .read_cursors
            .values()
            .find(|marker| {
                marker.actor_id == actor_id
                    && marker.realm_id.as_str() == operation.realm_id.as_str()
                    && marker.read_scope == read_scope
            })
            .map(|marker| marker.position.event_id.to_string())
    }?;
    let relation = match state.event_queries().canonical_events().await {
        Ok(records) => soland_services::events::read_cursor_causal_relation(
            &records,
            &current_event_id,
            candidate_event_id,
        ),
        Err(error) => {
            tracing::warn!(
                %error,
                current_event_id,
                candidate_event_id,
                "read cursor causal closure lookup failed; preserving current projection"
            );
            ReadCursorCausalRelation::Undecidable
        }
    };
    let relation = match relation {
        ReadCursorCausalRelation::CandidateDominatesCurrent => "candidate_dominates_current",
        ReadCursorCausalRelation::CurrentDominatesCandidate => "current_dominates_candidate",
        ReadCursorCausalRelation::Concurrent => "concurrent",
        ReadCursorCausalRelation::Undecidable => "undecidable",
    };
    let mut contextual = operation.clone();
    contextual.payload[crate::routing::events::READ_CURSOR_CAUSAL_RELATION_CONTEXT] =
        Value::String(relation.to_owned());
    Some(contextual)
}

pub(super) async fn project_account_data_set(
    state: &AppState,
    origin: &str,
    source_device_id: &str,
    operation: &Operation,
) {
    let Some(account_data_key) = operation
        .payload
        .get("key")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return;
    };
    let Some(account_id) = operation.context.sender.as_account_id() else {
        return;
    };
    // This projection and its device fanout belong to the local Account. A
    // foreign accepted Event cannot borrow a same-principal local directory.
    if account_id.station_id != state.service_core_id() {
        return;
    }
    let owner = operation.context.sender.to_string();
    let Some(expected_revision) = operation
        .payload
        .get("expected_revision")
        .and_then(Value::as_u64)
    else {
        tracing::warn!(
            owner,
            account_data_key,
            "account_data Event missing expected_revision"
        );
        return;
    };
    let Some(revision) = expected_revision.checked_add(1) else {
        tracing::warn!(owner, account_data_key, "account_data revision exhausted");
        return;
    };
    let tombstone = operation
        .payload
        .get("tombstone")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let content = if tombstone {
        Value::Null
    } else {
        let Some(content) = operation
            .payload
            .get("body")
            .or_else(|| operation.payload.get("encrypted_payload"))
            .cloned()
        else {
            return;
        };
        content
    };
    let record = AccountDataState {
        actor_id: owner.to_owned(),
        account_data_key: account_data_key.to_owned(),
        revision,
        payload: content,
        tombstone,
        updated_at: operation.created_at,
    };
    let applied = match state
        .account_data()
        .compare_and_set(record.clone(), expected_revision)
        .await
    {
        Ok(AccountDataCasOutcome::Applied(applied)) => applied,
        Ok(AccountDataCasOutcome::Conflict(current)) => {
            tracing::warn!(
                owner,
                account_data_key,
                expected_revision,
                current_revision = current.as_ref().map_or(0, |value| value.revision),
                "rejected stale account_data Event projection"
            );
            return;
        }
        Err(error) => {
            tracing::warn!(%error, owner, account_data_key, "failed to project account_data from event");
            return;
        }
    };
    if !source_device_id.is_empty() && origin == account_id.principal_id.as_str() {
        let Ok(sender_device_id) = arkret_identifiers::DeviceId::new(source_device_id.to_owned())
        else {
            tracing::warn!(
                owner,
                source_device_id,
                "actor-private account-data fanout source is not a DeviceId"
            );
            return;
        };
        let sender = DeviceMessageSender::Device {
            sender_account_id: account_id.clone(),
            sender_device_id,
        };
        let content = ActorPrivateAccountDataUpdate {
            operation: if tombstone {
                ActorPrivateAccountDataOperation::Delete
            } else {
                ActorPrivateAccountDataOperation::Put
            },
            account_data_key: account_data_key.to_owned(),
            revision: applied.revision,
            content: (!tombstone).then_some(applied.payload.clone()),
            updated_at: applied.updated_at,
        };
        let update = if account_data_key == arkret_wire::AccountDataKey::ACCOUNT_BLOCKLIST {
            ActorPrivateDeviceUpdate::Blocklist {
                sender,
                content,
                created_at: applied.updated_at,
            }
        } else {
            ActorPrivateDeviceUpdate::AccountData {
                sender,
                content,
                created_at: applied.updated_at,
            }
        };
        fanout_actor_private_update(state, account_id.principal_id.as_str(), update).await;
    }
}

pub(super) async fn fanout_projection_effect_private_update(
    state: &AppState,
    origin: &str,
    source_device_id: &str,
    effect: &soland_services::projection::ProjectionEffectView,
) {
    let soland_services::projection::ProjectionEffectView::ReadMarkerUpdated(marker) = effect
    else {
        return;
    };
    if source_device_id.is_empty() || marker.actor_id.signing_principal_id().as_str() != origin {
        return;
    }
    fanout_actor_private_update(
        state,
        marker.actor_id.signing_principal_id().as_str(),
        ActorPrivateDeviceUpdate::ReadCursor {
            sender: DeviceMessageSender::Device {
                sender_account_id: match marker.actor_id.as_account_id() {
                    Some(account_id) => account_id.clone(),
                    None => return,
                },
                sender_device_id: marker.device_id.clone(),
            },
            content: ActorPrivateReadCursorUpdate {
                schema: arkret_wire::SchemaId::READ_CURSOR_UPDATE_V1.to_owned(),
                actor_id: marker.actor_id.clone(),
                device_id: marker.device_id.clone(),
                realm_id: marker.realm_id.clone(),
                read_scope: marker.read_scope.clone(),
                position: marker.position.clone(),
                updated_at: marker.updated_at,
            },
            created_at: marker.updated_at,
        },
    )
    .await;
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[tokio::test]
    async fn account_data_projection_uses_the_exact_local_actor_cas_key() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let principal = arkret_wire::DidCoreId::new("ak:did_core:web:holder.example").unwrap();
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            state.service_core_id(),
        ));
        let actor_key = actor.to_string();
        let foreign = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        ));
        let mut operation = arkret_event_draft::test_support::raw_projected_operation(
            arkret_wire::OperationId::new("ak:operation:01904100-0000-7000-8000-000000000002")
                .unwrap(),
            arkret_wire::RealmId::new("ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K")
                .unwrap(),
            arkret_wire::EventKind::AccountDataSet.as_str(),
            json!({"key": "ak.dnd_schedule", "expected_revision": 0, "body": {"opaque": "first"}}),
        );
        operation.context.sender = actor.clone();
        project_account_data_set(&state, principal.as_str(), "", &operation).await;
        let first = state
            .account_data()
            .entry(&actor_key, "ak.dnd_schedule")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.revision, 1);
        assert!(
            state
                .account_data()
                .entry(principal.as_str(), "ak.dnd_schedule")
                .await
                .unwrap()
                .is_none()
        );

        operation.payload["expected_revision"] = json!(1);
        operation.payload["body"] = json!({"opaque": "foreign"});
        operation.context.sender = foreign.clone();
        project_account_data_set(&state, principal.as_str(), "", &operation).await;
        assert!(
            state
                .account_data()
                .entry(&foreign.to_string(), "ak.dnd_schedule")
                .await
                .unwrap()
                .is_none()
        );
        operation.context.sender = actor;
        operation.payload["body"] = json!({"opaque": "second"});
        project_account_data_set(&state, principal.as_str(), "", &operation).await;
        let second = state
            .account_data()
            .entry(&actor_key, "ak.dnd_schedule")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.revision, 2);
        operation.payload["body"] = json!({"opaque": "stale"});
        project_account_data_set(&state, principal.as_str(), "", &operation).await;
        assert_eq!(
            state
                .account_data()
                .entry(&actor_key, "ak.dnd_schedule")
                .await
                .unwrap()
                .unwrap()
                .payload,
            second.payload
        );
        assert_eq!(
            state
                .account_data()
                .entries_for_actor(&actor_key)
                .await
                .unwrap()
                .len(),
            1
        );
    }
}
