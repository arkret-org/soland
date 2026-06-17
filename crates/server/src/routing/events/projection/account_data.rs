use cokret_sdk::Operation;
use serde_json::{Value, json};

use super::*;
use crate::kinds;
use crate::routing::identity::device_messages::{
    ACCOUNT_DATA_UPDATE_TYPE, BLOCKLIST_UPDATE_TYPE, READ_MARKER_UPDATE_TYPE,
    fanout_actor_private_update,
};
use crate::state::{AccountDataRecord, AppState};

/// Project a `ck.realm.read_receipt_policy` (post-R1.2; was
/// `ck.space.read_receipt_policy`) durable-event into
/// `ProjectionState::cells` as a synthesized CasRegister value at the
/// canonical cell
/// `ck:cell:ck.component.realm.read_receipt_policy.v1:<realm_id>`.
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
    let payload = match operation.payload.as_object() {
        Some(payload) => payload,
        None => return,
    };
    let disclosure = payload
        .get("disclosure")
        .and_then(|v| v.as_str())
        .unwrap_or("optional")
        .to_owned();
    let visibility = payload
        .get("visibility")
        .and_then(|v| v.as_str())
        .unwrap_or("members")
        .to_owned();
    let scope_overrides_allowed = payload
        .get("scope_overrides_allowed")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    // Synthesize a CellState::Value at the canonical cell ref. This lets
    // the cells-map fast-path serve reads without scanning the durable
    // Event store on every fanout.
    let cell_id = match cokret_sdk::CellRef::new(format!(
        "ck:cell:ck.component.realm.read_receipt_policy.v1:{}",
        realm_id.as_str()
    )) {
        Ok(c) => c,
        Err(_) => return,
    };
    let value = serde_json::json!({
        "disclosure": disclosure,
        "visibility": visibility,
        "scope_overrides_allowed": scope_overrides_allowed,
    });
    if let Ok(mut proj) = state.projection.lock() {
        proj.cells
            .insert(cell_id, cokret_sdk::lattice::CellState::Value(value));
    }
}

fn account_data_update_type(data_type: &str) -> &'static str {
    if matches!(
        data_type,
        "ck.account.blocklist" | "ck.account.blocklist.v1"
    ) {
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
    if kinds::canonical_kind_string(operation) != kinds::CK_READ_MARKER
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
            "ck.read_cursor.advance actor/device does not match accepted event origin"
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
    let Some(data_type) = operation
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
    if owner != origin {
        tracing::warn!(
            owner,
            origin,
            data_type,
            "ck.account_data.set owner does not match accepted operation origin"
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
            .persistence
            .account_data()
            .delete(owner, data_type)
            .await
        {
            tracing::warn!(%error, owner, data_type, "failed to tombstone account_data from event");
            return;
        }
        if !source_device_id.is_empty() {
            fanout_actor_private_update(
                state,
                owner,
                source_device_id,
                account_data_update_type(data_type),
                json!({
                    "operation": "delete",
                    "data_type": data_type,
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
    let record = AccountDataRecord {
        actor: owner.to_owned(),
        data_type: data_type.to_owned(),
        payload: content,
        updated_at: operation.created_at,
    };
    if let Err(error) = state.persistence.account_data().put(&record).await {
        tracing::warn!(%error, owner, data_type, "failed to project account_data from event");
        return;
    }
    if !source_device_id.is_empty() {
        fanout_actor_private_update(
            state,
            owner,
            source_device_id,
            account_data_update_type(data_type),
            json!({
                "operation": "put",
                "data_type": data_type,
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
    effect: &crate::reducer::ProjectionEffect,
) {
    let crate::reducer::ProjectionEffect::ReadMarkerUpdated(marker) = effect else {
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
            "schema": "ck.schema.read_cursor.v1",
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
