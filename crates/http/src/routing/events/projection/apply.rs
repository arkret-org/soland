//! Reducer context for accepted MemberState Events.
//!
//! The old post-accept Cell/Seal projection publisher has no production caller.
//! Formal Event/RealmCommit admission owns durable effects and publication.

use arkret_event_draft::ProjectedEventOperation as Operation;
use serde_json::Value;

/// Receiver time is reducer context, never a producer payload field. Preserve
/// the accepted Event unchanged and apply the timestamp only to a local clone.
pub(crate) fn accepted_member_state_reducer_operation(operation: &Operation) -> Operation {
    let mut contextual = operation.clone();
    let received_at = contextual
        .payload
        .get("event_received_at")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc));
    if let Some(payload) = contextual.payload.as_object_mut() {
        payload.remove("event_received_at");
    }
    if let Some(received_at) = received_at {
        contextual.created_at = received_at;
    }
    contextual
}

#[cfg(test)]
mod tests {
    use arkret_identifiers::{OperationId, RealmId};
    use serde_json::json;

    use super::*;

    #[test]
    fn member_state_receiver_time_stays_outside_closed_payload() {
        let mut operation = arkret_event_draft::test_support::raw_projected_operation(
            OperationId::new("ak:operation:01904100-0000-7000-8000-000000000602").unwrap(),
            RealmId::new("ak:realm:AeMdjqxM9dnJ8ik-DD-XWcNeb1liwy0eVEWHTvxfesqr").unwrap(),
            arkret_wire::EventKind::MemberState,
            json!({
                "member_id": "ak:did_core:web:bob.example",
                "membership": "join"
            }),
        );
        operation.payload["event_received_at"] = json!("2026-09-23T00:00:02.000Z");
        let original_time = operation.created_at;
        let contextual = accepted_member_state_reducer_operation(&operation);
        assert!(contextual.payload.get("event_received_at").is_none());
        assert!(operation.payload.get("event_received_at").is_some());
        assert_ne!(contextual.created_at, original_time);
        assert_eq!(
            contextual.created_at.to_rfc3339(),
            "2026-09-23T00:00:02+00:00"
        );
    }
}
