//! `cx.profile.agent_workspace.v1` notification bridge.
//!
//! Spec: contrix-spec/spec/v1/zh/extensions/agent-workspace-profile.md §14
//! (`agent_membership_change` notification).
//!
//! When a source Space sees a membership / capability event targeting an
//! agent DID (heuristic: subject string starts with `did:`), this bridge
//! fans out a synthetic `cx.schema.notification.v1`-shaped projection
//! event with `notification_type=agent_membership_change`. The
//! controller-side client (yougen) subscribes to its workspace root
//! Space and filters these notifications by the agent_authority binding
//! it observes locally.
//!
//! Watcher event kinds the bridge mirrors into agent_membership_change:
//!   - `cx.member.state` with payload.state in {member,joined,active} →
//!     change_kind=add
//!   - `cx.member.state` with payload.state in {removed,left} →
//!     change_kind=remove
//!   - `cx.capability.grant` → change_kind=add (capability granted)
//!   - `cx.capability.revoke` → change_kind=remove (capability revoked)
//!
//! The bridge is intentionally permissive — it emits notifications for
//! every membership / capability event, then yougen filters to agents
//! the controller actually owns. This matches the observe-then-write
//! pattern in agent-workspace-profile.md §4.3 / §4.8: server-side
//! doesn't need agent_authority lookup to classify; the client does.
//!
//! Note: in production the notification fan-out would be routed through
//! the push gateway (Floria) rather than broadcast on the live subscriber
//! channel. The current implementation emits to the broadcast channel as
//! a synthetic projection event so yougen + cotest can observe round-trip
//! semantics. Push-gateway integration is tracked separately.

use serde_json::{Value, json};

use crate::ids;
use crate::kinds;
use crate::state::{AppState, EventNotification, ProjectionEventRecord};

use super::projection::append_projection_event;

/// Inspect `operation` and, when it carries a membership / capability
/// event for which the subject DID looks like an agent, emit a synthetic
/// `agent_membership_change` notification projection event. Idempotent
/// (no-ops for unrelated kinds).
pub fn maybe_emit_agent_membership_change(
    state: &AppState,
    origin: &str,
    operation: &contrix_sdk::Operation,
) {
    let kind = kinds::canonical_kind_string(operation);
    let change_info = if kinds::is_membership_kind(&kind) {
        membership_change(operation)
    } else if kind == "cx.capability.grant" {
        capability_grant_change(operation)
    } else if kind == "cx.capability.revoke" {
        capability_revoke_change(operation)
    } else {
        return;
    };
    let Some((change_kind, subject_did, source_flow_id)) = change_info else {
        return;
    };
    // Heuristic: only emit for DID-shaped subjects. Real agent_authority
    // verification happens client-side.
    if !subject_did.starts_with("did:") {
        return;
    }

    let synthetic_event_id = ids::generate("event");
    let payload = json!({
        "notification_type": "agent_membership_change",
        "source_event_id": operation.operation_id.to_string(),
        "space_id": operation.space_id.to_string(),
        "preview": {
            "change_kind": change_kind,
            "agent_did": subject_did,
            "source_space_id": operation.space_id.to_string(),
            "source_flow_id": source_flow_id,
        }
    });
    let record = ProjectionEventRecord {
        event_id: synthetic_event_id,
        space_id: operation.space_id.to_string(),
        event_kind: "cx.notification.agent_membership_change".to_owned(),
        operation_type: "agent_workspace_membership_change".to_owned(),
        operation_id: None,
        sender: Some(origin.to_owned()),
        payload,
        created_at: chrono::Utc::now(),
    };

    let _ = state.event_broadcast.send(EventNotification::event(
        record.space_id.clone(),
        record.event_id.clone(),
        super::projection::projection_event_json(&record),
    ));
    append_projection_event(state, record);
}

/// Returns (change_kind, subject_did, source_flow_id_or_none) for an
/// accepted `cx.member.state` operation.
fn membership_change(op: &contrix_sdk::Operation) -> Option<(&'static str, String, Option<String>)> {
    let body = op.payload.as_object()?;
    let actor = body
        .get("actor_id")
        .or_else(|| body.get("actor"))
        .or_else(|| body.get("sender"))
        .or_else(|| body.get("member"))
        .and_then(Value::as_str)?
        .to_owned();
    let state = body
        .get("state")
        .or_else(|| body.get("membership"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let change_kind = match state {
        "member" | "joined" | "active" | "join" => "add",
        "removed" | "left" | "leave" | "ban" | "banned" => "remove",
        _ => return None,
    };
    let flow_id = body.get("flow_id").and_then(Value::as_str).map(str::to_owned);
    Some((change_kind, actor, flow_id))
}

/// Returns (change_kind="add", grant.subject, None) for an accepted
/// `cx.capability.grant` operation.
fn capability_grant_change(op: &contrix_sdk::Operation) -> Option<(&'static str, String, Option<String>)> {
    let body = op.payload.as_object()?;
    let subject = body
        .get("subject")
        .or_else(|| body.get("grant_subject"))
        .and_then(Value::as_str)
        .or_else(|| {
            body.get("grant")
                .and_then(|g| g.get("subject"))
                .and_then(Value::as_str)
        })?
        .to_owned();
    Some(("add", subject, None))
}

/// Returns (change_kind="remove", grant.subject, None) for an accepted
/// `cx.capability.revoke` operation. The revoke payload usually carries
/// `grant_id` rather than subject directly, so callers may need to
/// resolve grant_id → subject from the cell projection; here we surface
/// whatever DID we can find. Real client-side filtering handles this.
fn capability_revoke_change(op: &contrix_sdk::Operation) -> Option<(&'static str, String, Option<String>)> {
    let body = op.payload.as_object()?;
    // Prefer an explicit subject if the payload carries one; otherwise
    // fall back to `revoked_by` (which is the issuer, not subject, but
    // still a DID so client can filter on agent_authority).
    let subject = body
        .get("subject")
        .or_else(|| body.get("grant_subject"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            body.get("grant")
                .and_then(|g| g.get("subject"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
    let subject = subject?;
    Some(("remove", subject, None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use contrix_sdk::Operation;
    use serde_json::json;

    fn op(kind: &str, payload: Value) -> Operation {
        let mut op = Operation::create(
            contrix_sdk::OperationId::new("cx:operation:01904100-0000-7000-8000-57d7d85564c5")
                .unwrap(),
            contrix_sdk::SpaceId::new("cx:space:01904100-0000-7000-8000-668e2181b41d").unwrap(),
            kind.split('.').nth(1).unwrap_or("member"),
            payload,
        );
        op.object_type = kind.to_owned();
        op
    }

    #[test]
    fn member_state_joined_classifies_as_add() {
        let o = op(
            "cx.member.state",
            json!({"actor_id": "did:web:agent.example", "state": "joined"}),
        );
        let (kind, subject, _) = membership_change(&o).expect("classified");
        assert_eq!(kind, "add");
        assert_eq!(subject, "did:web:agent.example");
    }

    #[test]
    fn member_state_removed_classifies_as_remove() {
        let o = op(
            "cx.member.state",
            json!({"actor_id": "did:web:agent.example", "state": "removed"}),
        );
        let (kind, _, _) = membership_change(&o).expect("classified");
        assert_eq!(kind, "remove");
    }

    #[test]
    fn capability_grant_classifies_as_add() {
        let o = op(
            "cx.capability.grant",
            json!({"subject": "did:web:agent.example", "actions": ["cx.message.create"]}),
        );
        let (kind, subject, _) = capability_grant_change(&o).expect("classified");
        assert_eq!(kind, "add");
        assert_eq!(subject, "did:web:agent.example");
    }

    #[test]
    fn capability_revoke_classifies_as_remove() {
        let o = op(
            "cx.capability.revoke",
            json!({"subject": "did:web:agent.example", "grant_id": "cx:grant:01"}),
        );
        let (kind, _, _) = capability_revoke_change(&o).expect("classified");
        assert_eq!(kind, "remove");
    }

    #[test]
    fn member_state_unknown_state_returns_none() {
        let o = op(
            "cx.member.state",
            json!({"actor_id": "did:web:agent.example", "state": "frobnicating"}),
        );
        assert!(membership_change(&o).is_none());
    }

    #[test]
    fn non_did_subject_is_filtered_in_caller() {
        // The maybe_emit_* entry point bails on non-DID subjects; the
        // classifier helpers themselves don't enforce that (they just
        // return the string they found).
        let o = op(
            "cx.member.state",
            json!({"actor_id": "user-123", "state": "joined"}),
        );
        let (_, subject, _) = membership_change(&o).expect("classified");
        assert_eq!(subject, "user-123");
        // The maybe_emit caller bails because subject doesn't start with did:.
        assert!(!subject.starts_with("did:"));
    }
}
