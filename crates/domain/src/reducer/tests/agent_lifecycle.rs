use super::*;
const REALM: &str = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
const AGENT: &str = "ak:did_core:web:agent.example";
const CONTROLLER: &str = "ak:did_core:web:controller.example";
const REQUEST: &str = "ak:agent-action-request:01904100-0000-7000-8000-cfc039892037";

/// Assert an Operation was rejected for exactly `expected`, printing the real
/// effect when it was not. A bare `matches!` here hides the reason that makes
/// the failure diagnosable.
#[track_caller]
fn expect_rejected(effect: ProjectionEffect, expected: &str) {
    match effect {
        ProjectionEffect::Rejected { reason } => assert_eq!(reason, expected),
        other => panic!("expected Rejected({expected}), got {other:?}"),
    }
}

/// Assert a private Agent Event was accepted under `expected` kind.
#[track_caller]
fn expect_agent_event_accepted(effect: ProjectionEffect, expected: arkret_wire::EventKind) {
    match effect {
        ProjectionEffect::AgentPrivateEventAccepted { kind, .. } => assert_eq!(kind, expected),
        other => panic!("expected {expected} to be accepted, got {other:?}"),
    }
}

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
            "approved_event_id": "ak:event:AbuDfbb-uv82LvhWbTydj5wUDvzph0PSFjJTtTJxq7P5",
            "approval_nonce": "nonce-01904100",
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
fn pause_suspends_pending_requests_and_resume_restores_them() {
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
    assert_eq!(request.status, AgentActionRequestStatus::AwaitingResume);
    assert!(request.cancel_reason.is_none());
    assert!(request.resolved_at.is_none());
    assert!(request.resolution_event_id.is_none());
    state.apply(&resume_agent(), &hlc);
    assert_eq!(
        state.agent_action_requests[REQUEST].status,
        AgentActionRequestStatus::Pending
    );
    state.apply(&pause_agent(), &hlc);
    state.apply(&deactivate_agent(), &hlc);
    assert_eq!(
        state.agent_action_requests[REQUEST].status,
        AgentActionRequestStatus::Cancelled
    );
}

#[test]
fn lifecycle_state_blocks_new_action_requests() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    state.apply(&pause_agent(), &hlc);
    let paused_effect = state.apply(&action_request(REQUEST), &hlc);
    expect_rejected(paused_effect, "agent_paused");
    assert!(!state.agent_action_requests.contains_key(REQUEST));

    state.apply(&resume_agent(), &hlc);
    state.apply(&deactivate_agent(), &hlc);
    let deactivated_effect = state.apply(&action_request(REQUEST), &hlc);
    expect_rejected(deactivated_effect, "agent_deactivated");
    assert!(!state.agent_action_requests.contains_key(REQUEST));
}

#[test]
fn approved_action_request_is_not_cancelled_by_lifecycle() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    expect_agent_event_accepted(
        state.apply(&action_request(REQUEST), &hlc),
        arkret_wire::EventKind::AgentActionRequest,
    );
    expect_agent_event_accepted(
        state.apply(&action_approve(REQUEST), &hlc),
        arkret_wire::EventKind::AgentActionApprove,
    );
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

    expect_rejected(effect, "agent_action_resolution_controller_mismatch");
    assert_eq!(
        state.agent_action_requests[REQUEST].status,
        AgentActionRequestStatus::Pending
    );
}
