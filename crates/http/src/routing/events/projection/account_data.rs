use arkret_event_draft::Operation;
use serde_json::{Value, json};
use soland_services::identity::AccountDataState;
use soland_services::operation_semantics as kinds;

use crate::routing::identity::device_messages::{
    ACCOUNT_DATA_UPDATE_TYPE, BLOCKLIST_UPDATE_TYPE, READ_MARKER_UPDATE_TYPE,
    fanout_actor_private_update,
};
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

fn account_data_update_type(account_data_key: &str) -> &'static str {
    if account_data_key == "ak.account.blocklist" {
        BLOCKLIST_UPDATE_TYPE
    } else {
        ACCOUNT_DATA_UPDATE_TYPE
    }
}

pub(super) fn actor_private_read_cursor_matches_origin(
    origin: &str,
    source_device_id: &str,
    operation: &Operation,
) -> bool {
    if kinds::canonical_kind_string(operation)
        != arkret_wire::events::EventKind::READ_CURSOR_ADVANCE
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
        .get("owner")
        .and_then(Value::as_str)
        .unwrap_or(origin);
    if owner != origin && origin != state.service_id() {
        tracing::warn!(
            owner,
            origin,
            account_data_key,
            "ak.account_data.set owner does not match accepted operation origin"
        );
        return;
    }
    if operation
        .payload
        .get("tombstone")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        if let Err(error) = state
            .account_data()
            .delete_entry(owner, account_data_key)
            .await
        {
            tracing::warn!(%error, owner, account_data_key, "failed to tombstone account_data from event");
            return;
        }
        if !source_device_id.is_empty() {
            fanout_actor_private_update(
                state,
                owner,
                source_device_id,
                account_data_update_type(account_data_key),
                json!({
                    "operation": "delete",
                    "account_data_key": account_data_key,
                    "deleted_at": operation.created_at,
                }),
            )
            .await;
        }
        return;
    }
    let Some(content) = operation
        .payload
        .get("body")
        .or_else(|| operation.payload.get("encrypted_payload"))
        .or_else(|| operation.payload.get("encrypted_content"))
        .cloned()
    else {
        return;
    };
    let record = AccountDataState {
        actor_id: owner.to_owned(),
        account_data_key: account_data_key.to_owned(),
        payload: content,
        updated_at: operation.created_at,
    };
    if let Err(error) = state.account_data().save_entry(record.clone()).await {
        tracing::warn!(%error, owner, account_data_key, "failed to project account_data from event");
        return;
    }
    if !source_device_id.is_empty() {
        fanout_actor_private_update(
            state,
            owner,
            source_device_id,
            account_data_update_type(account_data_key),
            json!({
                "operation": "put",
                "account_data_key": account_data_key,
                "content": record.payload.clone(),
                "updated_at": record.updated_at,
            }),
        )
        .await;
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
    if source_device_id.is_empty() || marker.actor_id != origin {
        return;
    }
    let origin_device = if marker.device_id.is_empty() {
        source_device_id
    } else {
        marker.device_id.as_str()
    };
    fanout_actor_private_update(
        state,
        &marker.actor_id,
        origin_device,
        READ_MARKER_UPDATE_TYPE,
        json!({
            "schema": "ak.schema.read_cursor.v1",
            "actor_id": marker.actor_id.clone(),
            "device_id": origin_device,
            "realm_id": marker.realm_id.clone(),
            "read_scope": marker.read_scope.clone(),
            "position": marker.position.clone(),
            "updated_at": marker.updated_at,
        }),
    )
    .await;
}
