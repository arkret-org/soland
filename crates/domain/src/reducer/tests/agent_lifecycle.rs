use super::*;
const REALM: &str = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
const AGENT: &str = "ak:did_core:web:agent.example";
const CONTROLLER: &str = "ak:did_core:web:controller.example";
const REQUEST: &str = "ak:agent-action-request:01904100-0000-7000-8000-cfc039892037";

fn agent_operation(kind: arkret_wire::EventKind, payload: serde_json::Value) -> Operation {
    let mut operation = make_operation(kind, REALM, payload);
    operation.context.sender = account_actor(AGENT);
    operation
}

fn action_request(request_id: &str) -> Operation {
    agent_operation(
        arkret_wire::EventKind::AgentActionRequest,
        serde_json::json!({
            "agent_id": AGENT,
            "controller_account_id": arkret_wire::AccountId::new(
                arkret_identifiers::DidCoreId::new(CONTROLLER).unwrap(),
                arkret_identifiers::DidCoreId::new(CONTROLLER).unwrap(),
            ),
            "request_id": request_id
        }),
    )
}

fn action_approve(request_id: &str) -> Operation {
    let mut operation = agent_operation(
        arkret_wire::EventKind::AgentActionApprove,
        serde_json::json!({
            "approval_id": "ak:agent-approval:01904100-0000-7000-8000-cfc039892038",
            "request_id": request_id,
            "agent_id": AGENT,
            "proposed_action": "ak.message.create",
            "target": { "kind": "realm", "realm_id": REALM },
            "approved_payload_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "approval_nonce": "nonce-01904100",
            "approved_at": "2026-06-19T00:00:10.000Z",
            "expires_at": "2026-06-19T00:10:10.000Z"
        }),
    );
    operation.context.sender = account_actor(CONTROLLER);
    operation
}

fn pause_agent() -> Operation {
    agent_operation(
        arkret_wire::EventKind::SelfAgentPause,
        serde_json::json!({
            "status_changed_at": "2026-06-19T00:00:00.000Z"
        }),
    )
}

fn resume_agent() -> Operation {
    agent_operation(
        arkret_wire::EventKind::SelfAgentResume,
        serde_json::json!({
            "status_changed_at": "2026-06-19T00:01:00.000Z"
        }),
    )
}

fn deactivate_agent() -> Operation {
    agent_operation(
        arkret_wire::EventKind::SelfAgentDeactivate,
        serde_json::json!({
            "status_changed_at": "2026-06-19T00:02:00.000Z"
        }),
    )
}

#[test]
fn pause_cancels_pending_action_requests() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    state.apply(&action_request(REQUEST), &hlc);
    assert_eq!(
        state.agent_action_requests[REQUEST].status,
        AgentActionRequestStatus::Pending
    );

    let effect = state.apply(&pause_agent(), &hlc);
    assert!(matches!(
        effect,
        ProjectionEffect::AgentLifecycleProjected {
            agent_id,
            new_state: AgentLifecycleState::Paused,
        } if agent_id == AGENT
    ));
    let request = &state.agent_action_requests[REQUEST];
    assert_eq!(request.status, AgentActionRequestStatus::Cancelled);
    assert_eq!(request.cancel_reason.as_deref(), Some("agent_paused"));
    assert!(request.resolved_at.is_some());
    assert!(request.resolution_event_id.is_some());
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
    let approval = request.approval.as_ref().expect("approval projection");
    assert_eq!(approval.approval_nonce, "nonce-01904100");
    assert_eq!(approval.proposed_action, "ak.message.create");
    assert!(request.cancel_reason.is_none());
}

#[test]
fn action_resolution_requires_the_complete_controller_account() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    state.apply(&action_request(REQUEST), &hlc);
    let mut approval = action_approve(REQUEST);
    approval.context.sender = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_identifiers::DidCoreId::new(CONTROLLER).unwrap(),
        arkret_identifiers::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
    ));
    let effect = state.apply(&approval, &hlc);

    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { reason }
            if reason == "agent_action_resolution_controller_mismatch"
    ));
    assert_eq!(
        state.agent_action_requests[REQUEST].status,
        AgentActionRequestStatus::Pending
    );
}
