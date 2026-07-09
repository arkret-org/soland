use super::*;

pub(super) async fn validate_agent_interop_session_writer_policy(
    state: &AppState,
    operations: &[Operation],
    operation: &Operation,
) -> Result<(), &'static str> {
    let Some(kind) = kinds::canonical_kind_for_operation(operation) else {
        return Ok(());
    };
    if !matches!(
        kind,
        arkret_sdk::events::kinds::AGENT_INTEROP_SESSION_STATUS
            | arkret_sdk::events::kinds::AGENT_INTEROP_SESSION_RESULT
    ) {
        return Ok(());
    }
    let Some(session_id) = agent_interop_session_id_from_payload(&operation.payload) else {
        return Err("interop_session_writer_unauthorized");
    };
    let Some(actor) = operation.actor() else {
        return Err("interop_session_writer_unauthorized");
    };
    let actor = actor.as_str();
    if agent_interop_session_start_actor(state, operations, operation.realm_id.as_str(), session_id)
        .await
        .as_deref()
        == Some(actor)
    {
        return Ok(());
    }
    if agent_interop_session_delegate_allows(state, operation, actor, session_id) {
        return Ok(());
    }
    Err("interop_session_writer_unauthorized")
}

pub(super) fn agent_interop_session_id_from_payload(payload: &Value) -> Option<&str> {
    payload
        .get("session_id")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("ak:agent_interop_session:"))
}

pub(super) async fn agent_interop_session_start_actor(
    state: &AppState,
    operations: &[Operation],
    realm_id: &str,
    session_id: &str,
) -> Option<String> {
    if let Some(actor) = operations.iter().find_map(|candidate| {
        (kinds::canonical_kind_for_operation(candidate)
            == Some(arkret_sdk::events::kinds::AGENT_INTEROP_SESSION_START)
            && candidate.realm_id.as_str() == realm_id
            && agent_interop_session_id_from_payload(&candidate.payload) == Some(session_id))
        .then(|| candidate.actor().map(|did| did.to_string()))
        .flatten()
    }) {
        return Some(actor);
    }
    state
        .persistence
        .events()
        .snapshot_all()
        .await
        .ok()?
        .iter()
        .find_map(|record| {
            if record.kind != arkret_sdk::events::kinds::AGENT_INTEROP_SESSION_START {
                return None;
            }
            if record.realm_id.as_deref() != Some(realm_id) {
                return None;
            }
            let payload = record.envelope.get("payload").unwrap_or(&record.envelope);
            if agent_interop_session_id_from_payload(payload) != Some(session_id) {
                return None;
            }
            Some(record.actor_id.clone())
        })
}

pub(super) fn agent_interop_session_delegate_allows(
    state: &AppState,
    operation: &Operation,
    actor: &str,
    session_id: &str,
) -> bool {
    let actions = agent_interop_session_delegate_actions(operation);
    if actions.is_empty() {
        return false;
    }
    state
        .authz
        .grants_for_subject(actor, operation.realm_id.as_str())
        .iter()
        .any(|grant| {
            let action_allowed = grant
                .actions
                .iter()
                .any(|action| actions.contains(&action.as_str()));
            let resource_allowed =
                crate::authz::resource_matches(&grant.resource, operation.realm_id.as_str())
                    || crate::authz::resource_matches(&grant.resource, session_id);
            let has_blocking_decision = grant.constraints.iter().any(|constraint| {
                matches!(
                    constraint,
                    crate::authz::Constraint::Decision {
                        decision: crate::authz::GrantDecisionVerdict::Deny
                            | crate::authz::GrantDecisionVerdict::Quarantine
                            | crate::authz::GrantDecisionVerdict::RequireReview
                    }
                )
            });
            let session_allowed = grant.constraints.iter().any(|constraint| {
                matches!(
                    constraint,
                    crate::authz::Constraint::AllowedSessionIds { allowed_session_ids }
                        if allowed_session_ids.iter().any(|allowed| allowed.as_ref() == session_id)
                )
            });
            action_allowed && resource_allowed && !has_blocking_decision && session_allowed
        })
}

pub(super) fn agent_interop_session_delegate_actions(
    operation: &Operation,
) -> &'static [&'static str] {
    let cancelled = operation.payload.get("status").and_then(Value::as_str) == Some("cancelled");
    match kinds::canonical_kind_for_operation(operation) {
        Some(arkret_sdk::events::kinds::AGENT_INTEROP_SESSION_STATUS) if cancelled => {
            &["ck.agent.interop_session.cancel"]
        }
        Some(arkret_sdk::events::kinds::AGENT_INTEROP_SESSION_STATUS) => {
            &["ck.agent.interop_session.stream_status"]
        }
        Some(arkret_sdk::events::kinds::AGENT_INTEROP_SESSION_RESULT) if cancelled => {
            &["ck.agent.interop_session.cancel"]
        }
        Some(arkret_sdk::events::kinds::AGENT_INTEROP_SESSION_RESULT) => {
            &["ck.agent.interop_session.attach_artifact"]
        }
        _ => &[],
    }
}
