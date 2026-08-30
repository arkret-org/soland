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
        .and_then(Value::as_str)
        .is_some_and(|actor_id| actor_id == origin);
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
    let actor_id = operation.payload.get("actor_id")?.as_str()?;
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
                marker.actor_id.signing_principal_id().as_str() == actor_id
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
    let owner = operation
        .payload
        .get("holder_id")
        .and_then(Value::as_str)
        .unwrap_or(origin);
    if owner != origin && origin != state.service_id() {
        tracing::warn!(
            owner,
            origin,
            account_data_key,
            "ak.account_data.set holder_id does not match accepted operation origin"
        );
        return;
    }
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
    if !source_device_id.is_empty() {
        let Ok(sender_device_id) = arkret_identifiers::DeviceId::new(source_device_id.to_owned())
        else {
            tracing::warn!(
                owner,
                source_device_id,
                "actor-private account-data fanout source is not a DeviceId"
            );
            return;
        };
        let sender = DeviceMessageSender::Device { sender_device_id };
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
        fanout_actor_private_update(state, owner, update).await;
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
                sender_device_id: marker.device_id.clone(),
            },
            content: ActorPrivateReadCursorUpdate {
                schema: arkret_wire::SchemaId::READ_CURSOR_V1.to_owned(),
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
