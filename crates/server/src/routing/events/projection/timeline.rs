use arkret_sdk::Operation;

use super::*;
use crate::kinds;
use crate::state::ProjectionEventRecord;

pub fn projection_event_from_operation(
    operation: &Operation,
    sender_fallback: Option<&str>,
) -> ProjectionEventRecord {
    let event_id = operation_event_id(operation);
    ProjectionEventRecord {
        event_id,
        realm_id: operation.realm_id.to_string(),
        event_kind: kinds::canonical_kind_string(operation),
        operation_type: operation_type_string(operation),
        operation_id: Some(operation.operation_id.to_string()),
        sender: operation
            .payload
            .get("sender")
            .and_then(|value| value.as_str())
            .or(sender_fallback)
            .map(ToOwned::to_owned),
        payload: operation.payload.clone(),
        created_at: operation.created_at,
        received_at: now(),
    }
}
