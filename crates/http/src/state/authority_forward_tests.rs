use arkret_wire::{AuthorityCommitStatus, AuthorityRejectionStatus, RealmId, ScopeRef};

use super::*;
use crate::routing::federation::outbox::PeerSubmitResponse;

fn forwarded_request(seed: u8) -> PeerAuthoritySubmitRequest {
    let realm_id = RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [seed; 32],
    ));
    let mut event = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::RealmProfile.as_str(),
        ScopeRef::Realm { realm_id },
        DidCoreId::new("ak:did_core:web:relay-producer.example").unwrap(),
        DidCoreId::new("ak:did_core:web:relay-forwarder.example").unwrap(),
        serde_json::json!({"name": format!("relay {seed}")}),
        chrono::DateTime::parse_from_rfc3339("2026-09-25T09:59:00.000Z")
            .unwrap()
            .with_timezone(&Utc),
    )
    .unwrap();
    crate::test_event::attach_structural_only_producer_proof(
        &mut event,
        arkret_wire::DidUrl::new("did:web:relay-producer.example#key-1").unwrap(),
    );
    PeerAuthoritySubmitRequest::AuthorityForwardEvent(
        PeerAuthorityForwardEventRequest::new(EventAdmissionSubmission::new(event), None, None)
            .unwrap(),
    )
}

fn commit_for(request: &PeerAuthoritySubmitRequest) -> arkret_wire::RealmCommit {
    let PeerAuthoritySubmitRequest::AuthorityForwardEvent(request) = request else {
        unreachable!("fixture forwards one ordinary Event")
    };
    let event = &request.event_submission.event;
    let at = event.created_at;
    arkret_wire::RealmCommit {
        commit_id: arkret_wire::RealmCommitId::from_digest([0x33; 32]),
        realm_id: event.realm_id.clone(),
        stream_ref: arkret_wire::CommitStreamRef::from_scope(
            &event.scope_ref,
            Some(event.realm_id.clone()),
        )
        .unwrap(),
        stream_position: 4,
        previous_commit_ref: Some(arkret_wire::RealmCommitId::from_digest([0x32; 32])),
        event_ref: event.event_id.clone(),
        governance_generation: 0,
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
            event.realm_id.event_id(),
        ),
        committed_at: at,
        signature: arkret_wire::DetachedObjectSignature {
            context: arkret_wire::DetachedSignatureContext::RealmCommit,
            signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
            verification_method: arkret_wire::DidUrl::new("did:web:governance.example#notary-key")
                .unwrap(),
            signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap(),
            created_at: at,
            sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
        },
    }
}

fn answer(status: u16, body: serde_json::Value) -> PeerSubmitResponse {
    PeerSubmitResponse {
        status,
        body: serde_json::to_vec(&body).unwrap(),
    }
}

fn forward_outcome(outcome: AuthoritySubmitOutcome) -> serde_json::Value {
    serde_json::to_value(PeerAuthoritySubmitOutcome::AuthorityForward(
        arkret_models_collaboration::authority_commit::PeerAuthorityForwardOutcome {
            branch: arkret_models_collaboration::authority_commit::AuthorityForwardBranch::AuthorityForward,
            outcome,
        },
    ))
    .unwrap()
}

/// The governance Station's refusal as it is rendered on the wire.
fn problem(code: &str, reason: Option<&str>) -> serde_json::Value {
    let mut problem = arkret_wire::Problem::from_code(code, "refused by governance");
    if let Some(reason) = reason {
        problem = problem.with_extension("reason_code", serde_json::json!(reason));
    }
    serde_json::to_value(problem).unwrap()
}

#[test]
fn relayed_governance_refusals_keep_their_registered_codes() {
    let request = forwarded_request(0x41);
    for code in [
        "device_revoked",
        "device_revocation_pending",
        "device_generation_fenced",
        "device_unauthorized",
        "signature_invalid",
        "failed_precondition",
        "epoch_mismatch",
    ] {
        let error =
            relay_governance_response(&request, answer(409, problem(code, None))).unwrap_err();
        assert_eq!(
            error.conflict_code().map(ConflictCode::as_str),
            Some(code),
            "{error:?}"
        );
    }
    // A registered reason travels with its code, so a relayed pending
    // key-access Commit is still distinguishable from a plain precondition.
    assert_eq!(
        relay_governance_response(
            &request,
            answer(
                409,
                problem("failed_precondition", Some("epoch_update_required"))
            )
        )
        .unwrap_err()
        .conflict_code(),
        Some(ConflictCode::EpochUpdateRequired)
    );
    assert!(matches!(
        relay_governance_response(&request, answer(422, problem("schema_violation", None))),
        Err(ServiceError::SchemaViolation(_))
    ));
    for (status, body) in [
        (500, problem("internal_error", None)),
        (409, serde_json::json!({"code": "device_revoked"})),
    ] {
        assert_eq!(
            relay_governance_response(&request, answer(status, body))
                .unwrap_err()
                .conflict_code(),
            Some(ConflictCode::TemporarilyUnavailable)
        );
    }
}

#[test]
fn relayed_outcome_must_cover_the_forwarded_event() {
    let request = forwarded_request(0x42);
    let commit = commit_for(&request);
    let accepted = AuthoritySubmitOutcome::Accepted {
        status: AuthorityCommitStatus::Committed,
        commit: commit.clone(),
    };
    assert_eq!(
        relay_governance_response(&request, answer(200, forward_outcome(accepted.clone())))
            .unwrap(),
        accepted
    );
    let rejected = AuthoritySubmitOutcome::Rejected {
        status: AuthorityRejectionStatus::Rejected,
        reason_code: "capability_denied".to_owned(),
    };
    assert_eq!(
        relay_governance_response(&request, answer(200, forward_outcome(rejected.clone())))
            .unwrap(),
        rejected
    );
    let other = commit_for(&forwarded_request(0x43));
    let foreign = AuthoritySubmitOutcome::Accepted {
        status: AuthorityCommitStatus::Committed,
        commit: other,
    };
    assert_eq!(
        relay_governance_response(&request, answer(200, forward_outcome(foreign)))
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::TemporarilyUnavailable),
        "a Commit for another Event is never relayed as this forward's outcome"
    );
}
