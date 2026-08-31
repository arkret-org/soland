use super::{
    FederationOutboxOutcome, FederationOutboxState, FederationOutboxTransition,
    classify_federation_outbox_completion,
};

#[test]
fn frontier_failure_window_and_confirmed_evidence_are_distinct() {
    use super::*;
    let peer = DidCoreId::new("ak:did_core:web:peer.example").unwrap();
    let mut record = None;
    for attempt in 1..=3 {
        let next =
            frontier_exchange_failure_record(record, "realm", &peer, "network_error", attempt);
        assert_eq!(next.consecutive_failures, attempt as i32);
        assert_eq!(
            next.status,
            if attempt == 3 {
                "peer_stale"
            } else {
                "healthy"
            }
        );
        record = Some(next);
    }
    let success = frontier_exchange_success_record(record, "realm", &peer, "remote-scope-root", 4);
    assert_eq!(success.status, "healthy");
    assert_eq!(success.consecutive_failures, 0);
    assert_eq!(
        success.last_frontier_root.as_deref(),
        Some("remote-scope-root")
    );
    for reason in ["witness_disagreement", "fork_quarantine"] {
        let evidence =
            frontier_exchange_failure_record(Some(success.clone()), "realm", &peer, reason, 5);
        assert_eq!(evidence.status, "peer_stale");
        assert_eq!(evidence.consecutive_failures, 0);
        let ordinary =
            frontier_exchange_failure_record(Some(evidence), "realm", &peer, "network_error", 6);
        assert_eq!(ordinary.last_error.as_deref(), Some(reason));
        let success =
            frontier_exchange_success_record(Some(ordinary), "realm", &peer, "equal-root", 7);
        assert_eq!(
            success.status, "peer_stale",
            "root equality cannot resolve evidence"
        );
        assert_eq!(success.last_error.as_deref(), Some(reason));
        assert_eq!(success.consecutive_failures, 0);
    }
    let forged =
        frontier_exchange_failure_record(None, "realm", &peer, "event_id_digest_mismatch", 8);
    assert_eq!(forged.status, "healthy");
    assert_eq!(forged.consecutive_failures, 1);
}

fn transition(outcome: FederationOutboxOutcome) -> FederationOutboxTransition {
    FederationOutboxTransition {
        id: "outbox-1".to_owned(),
        lease_token: "lease-1".to_owned(),
        attempts: 2,
        semantic_attempts: 1,
        last_http_status: None,
        last_error_code: None,
        last_response_excerpt: None,
        observed_at: 42,
        outcome,
    }
}

#[test]
fn completion_projects_retry_and_terminal_fields_once() {
    let retry = classify_federation_outbox_completion(
        false,
        &transition(FederationOutboxOutcome::Retry {
            next_attempt_at: 99,
        }),
    )
    .unwrap();
    assert_eq!(retry.state, FederationOutboxState::Pending);
    assert_eq!(retry.next_attempt_at, 99);
    assert_eq!(retry.completed_at, None);
    assert_eq!(retry.policy_version, None);

    let suppressed = classify_federation_outbox_completion(
        false,
        &transition(FederationOutboxOutcome::PolicySuppressed {
            policy_version: "policy-v2".to_owned(),
        }),
    )
    .unwrap();
    assert_eq!(suppressed.state, FederationOutboxState::PolicySuppressed);
    assert_eq!(suppressed.next_attempt_at, 42);
    assert_eq!(suppressed.completed_at, Some(42));
    assert_eq!(suppressed.policy_version.as_deref(), Some("policy-v2"));
}

#[test]
fn completion_rejects_outcomes_from_the_other_lifecycle() {
    let direct_route_failure = classify_federation_outbox_completion(
        false,
        &transition(FederationOutboxOutcome::RouteUnavailable {
            next_attempt_at: 99,
        }),
    );
    assert!(direct_route_failure.is_err());

    let realm_route_retry = classify_federation_outbox_completion(
        true,
        &transition(FederationOutboxOutcome::RouteUnavailable {
            next_attempt_at: 99,
        }),
    );
    assert!(realm_route_retry.is_ok());

    let direct_policy_suppression = classify_federation_outbox_completion(
        false,
        &transition(FederationOutboxOutcome::PolicySuppressed {
            policy_version: "policy-v2".to_owned(),
        }),
    );
    assert!(direct_policy_suppression.is_ok());

    let realm_policy_suppression = classify_federation_outbox_completion(
        true,
        &transition(FederationOutboxOutcome::PolicySuppressed {
            policy_version: "policy-v2".to_owned(),
        }),
    );
    assert!(realm_policy_suppression.is_err());
}
