use super::*;
const REALM: &str = "ck:realm:01904100-0000-7000-8000-cfc039892036";
const AGENT: &str = "did:web:agent.example";
const REQUEST: &str = "ck:agent-action-request:01904100-0000-7000-8000-cfc039892037";

fn agent_endpoint() -> Operation {
    make_operation(
        crate::kinds::CK_AGENT_ENDPOINT,
        REALM,
        serde_json::json!({
            "agent_id": AGENT,
            "protocol": "echo",
            "endpoints": [{
                "protocol": "https-json",
                "endpoint_url": "https://agent.example/runtime"
            }]
        }),
    )
}

fn action_request(request_id: &str) -> Operation {
    make_operation(
        crate::kinds::CK_AGENT_ACTION_REQUEST,
        REALM,
        serde_json::json!({
            "agent_principal_id": AGENT,
            "request_id": request_id
        }),
    )
}

fn action_approve(request_id: &str) -> Operation {
    make_operation(
        crate::kinds::CK_AGENT_ACTION_APPROVE,
        REALM,
        serde_json::json!({ "request_id": request_id }),
    )
}

fn pause_agent() -> Operation {
    make_operation(
        crate::kinds::CK_AGENT_PAUSE,
        REALM,
        serde_json::json!({
            "agent_principal_id": AGENT,
            "status_changed_at": "2026-06-19T00:00:00Z"
        }),
    )
}

fn resume_agent() -> Operation {
    make_operation(
        crate::kinds::CK_AGENT_RESUME,
        REALM,
        serde_json::json!({
            "agent_principal_id": AGENT,
            "status_changed_at": "2026-06-19T00:01:00Z"
        }),
    )
}

fn deactivate_agent() -> Operation {
    make_operation(
        crate::kinds::CK_AGENT_DEACTIVATE,
        REALM,
        serde_json::json!({
            "agent_principal_id": AGENT,
            "status_changed_at": "2026-06-19T00:02:00Z"
        }),
    )
}

#[test]
fn pause_revokes_endpoint_and_pending_action_requests() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    state.apply(&agent_endpoint(), &hlc);
    assert!(state.agents.contains_key(AGENT));

    state.apply(&action_request(REQUEST), &hlc);
    assert_eq!(
        state.agent_action_requests[REQUEST].status,
        AgentActionRequestStatus::Pending
    );

    let effect = state.apply(&pause_agent(), &hlc);
    assert!(matches!(
        effect,
        ProjectionEffect::AgentLifecycleProjected {
            agent_principal_id,
            new_state: AgentLifecycleState::Paused,
        } if agent_principal_id == AGENT
    ));
    assert!(!state.agents.contains_key(AGENT));
    let request = &state.agent_action_requests[REQUEST];
    assert_eq!(request.status, AgentActionRequestStatus::Cancelled);
    assert_eq!(request.cancel_reason.as_deref(), Some("agent_paused"));
    assert!(request.resolved_at.is_some());
    assert!(request.resolution_event_id.is_some());
}

#[test]
fn lifecycle_state_blocks_endpoint_reregistration_until_resume() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    state.apply(&pause_agent(), &hlc);
    let paused_effect = state.apply(&agent_endpoint(), &hlc);
    assert!(matches!(
        paused_effect,
        ProjectionEffect::Rejected { reason } if reason == "agent_paused"
    ));

    state.apply(&resume_agent(), &hlc);
    let active_effect = state.apply(&agent_endpoint(), &hlc);
    assert!(matches!(
        active_effect,
        ProjectionEffect::AgentProjectionUpdated { agent_id } if agent_id == AGENT
    ));
    assert!(state.agents.contains_key(AGENT));

    state.apply(&deactivate_agent(), &hlc);
    assert!(!state.agents.contains_key(AGENT));
    let deactivated_effect = state.apply(&agent_endpoint(), &hlc);
    assert!(matches!(
        deactivated_effect,
        ProjectionEffect::Rejected { reason } if reason == "agent_deactivated"
    ));
}

#[test]
fn lifecycle_state_blocks_new_action_requests() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    state.apply(&pause_agent(), &hlc);
    let paused_effect = state.apply(&action_request(REQUEST), &hlc);
    assert!(matches!(
        paused_effect,
        ProjectionEffect::Rejected { reason } if reason == "agent_paused"
    ));
    assert!(!state.agent_action_requests.contains_key(REQUEST));

    state.apply(&resume_agent(), &hlc);
    state.apply(&deactivate_agent(), &hlc);
    let deactivated_effect = state.apply(&action_request(REQUEST), &hlc);
    assert!(matches!(
        deactivated_effect,
        ProjectionEffect::Rejected { reason } if reason == "agent_deactivated"
    ));
    assert!(!state.agent_action_requests.contains_key(REQUEST));
}

#[test]
fn approved_action_request_is_not_cancelled_by_lifecycle() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    state.apply(&action_request(REQUEST), &hlc);
    state.apply(&action_approve(REQUEST), &hlc);
    assert_eq!(
        state.agent_action_requests[REQUEST].status,
        AgentActionRequestStatus::Approved
    );

    state.apply(&pause_agent(), &hlc);
    let request = &state.agent_action_requests[REQUEST];
    assert_eq!(request.status, AgentActionRequestStatus::Approved);
    assert!(request.cancel_reason.is_none());
}
