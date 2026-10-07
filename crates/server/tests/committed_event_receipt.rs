//! Non-governance receipt of committed Events (federation §3), following
//! `ak.vector.federation.non_governance_receiver_trusts_governance_commit.v1`.
//!
//! The receiver is a real Station over PostgreSQL that hosts one Account with
//! an accepted PCR genesis. The Realm is governed elsewhere: a verified
//! genesis/handoff chain from Station A to Station B. A foreign human device
//! producer key comes from its actual accepted Origin PCR source, carried as
//! an immutable fact bound by the true Gov Commit. Every rejection writes nothing.

use arkret_canonical::DigestSuite;
use arkret_wire::{DidCoreId, DidUrl, Event, EventKind, RealmCommit, ScopeRef};
use chrono::{Duration, Utc};
use soland_http::state::AppState;
use soland_services::ServiceError;
use soland_services::committed_receipt::{
    CommitContinuity, ReceivedProducer, verify_committed_event_receipt_with_fact,
};
use soland_test_support::AppStateTestExt as _;
use soland_test_support::device_authorization_history::sign_event;
use soland_test_support::governance_authority::{GovernanceChain, GovernanceSigner};
use soland_test_support::pcr_genesis::PcrGenesisFixture;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn method(did: &str, fragment: &str) -> DidUrl {
    DidUrl::new(format!("{did}#{fragment}")).unwrap()
}

fn unsigned_event(
    chain: &GovernanceChain,
    kind: EventKind,
    principal: DidCoreId,
    station: DidCoreId,
    name: &str,
) -> Event {
    arkret_wire::test_support::raw_event_at(
        kind.as_str(),
        ScopeRef::Realm {
            realm_id: chain.realm_id.clone(),
        },
        principal,
        station,
        serde_json::json!({ "name": name }),
        Utc::now() - Duration::seconds(1),
    )
    .unwrap()
}

async fn receive(
    receiver: &AppState,
    chain: &GovernanceChain,
    event: &Event,
    commit: &RealmCommit,
    continuity: CommitContinuity<'_>,
    fact: Option<&arkret_models_collaboration::authority_commit::HumanHistoricalSignerFact>,
) -> Result<ReceivedProducer, ServiceError> {
    let store = receiver.test_persistence();
    let fact = fact.cloned().map(Into::into);
    verify_committed_event_receipt_with_fact(
        store.device_revocations(),
        event,
        commit,
        continuity,
        &chain.authority,
        &chain.keys,
        &receiver.service_core_id(),
        DigestSuite::Sha256,
        fact.as_ref(),
    )
    .await
}

fn refusal_code(result: Result<ReceivedProducer, ServiceError>) -> String {
    match result.expect_err("the receipt must be refused") {
        ServiceError::SchemaViolation(_) => "schema_violation".to_owned(),
        error => error
            .conflict_code()
            .map(|code| code.as_str().to_owned())
            .unwrap_or_else(|| format!("{error:?}")),
    }
}

async fn assert_nothing_written(receiver: &AppState, event: &Event) {
    let store = receiver.test_persistence();
    let commits = store.authority_commits();
    assert!(
        commits
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        commits
            .queued_event(&event.event_id)
            .await
            .unwrap()
            .is_none()
    );
}

fn seal_fact(
    chain: &GovernanceChain,
    event: &Event,
    source: &arkret_models_collaboration::authority_commit::HumanHistoricalSignerFact,
    signer: GovernanceSigner,
) -> (
    RealmCommit,
    arkret_models_collaboration::authority_commit::HumanHistoricalSignerFact,
) {
    let mut fact = source.clone();
    fact.event_id = event.event_id.clone();
    let mut commit = chain.commit_next(event, signer);
    commit.producer_signer_fact_digest = Some(fact.digest().unwrap());
    (chain.seal(commit, signer), fact)
}

#[test]
fn non_governance_receiver_verifies_original_human_fact_and_legacy_is_unavailable() {
    runtime().block_on(async {
        let receiver = soland_test_support::app_state_with_postgres_governance(
            soland_test_support::app_config(),
        );
        let mut origin_config = soland_test_support::app_config();
        origin_config.public_base_url = "https://remote-station.example".to_owned();
        let origin = soland_test_support::app_state_with_postgres_governance(origin_config);
        assert_ne!(origin.service_core_id(), receiver.service_core_id());
        let foreign_pcr = PcrGenesisFixture::new(origin.service_did());
        foreign_pcr
            .admit(&origin)
            .await
            .expect("actual original foreign PCR acceptance");
        let hosted = PcrGenesisFixture::new(receiver.service_did());
        hosted
            .admit(&receiver)
            .await
            .expect("actual hosted PCR acceptance");
        let chain = GovernanceChain::new();
        let held = CommitContinuity::After(&chain.head);
        let produced =
            |fixture: &PcrGenesisFixture, kind: EventKind, name: &str, seed: [u8; 32]| {
                sign_event(
                    unsigned_event(
                        &chain,
                        kind,
                        fixture.history.account.principal_id.clone(),
                        fixture.history.account.station_id.clone(),
                        name,
                    ),
                    fixture.history.device_verification_method.clone(),
                    seed,
                )
            };
        let replica = produced(
            &foreign_pcr,
            EventKind::RealmProfile,
            "replicated",
            foreign_pcr.history.founding_device_signing_seed,
        );
        let source = origin
            .test_persistence()
            .authority_commits()
            .prepare_human_signer_fact(&replica, Utc::now())
            .await
            .unwrap()
            .unwrap();
        let (commit, fact) = seal_fact(&chain, &replica, &source, GovernanceSigner::CurrentStation);
        assert_eq!(
            receive(&receiver, &chain, &replica, &commit, held, Some(&fact))
                .await
                .unwrap(),
            ReceivedProducer::GovernanceCommittedHumanDevice
        );
        // This is the shared standalone receipt verifier, not proof that the
        // external Invite delivery wire has carried the fact yet.
        let invite = produced(
            &foreign_pcr,
            EventKind::InviteCreate,
            "invite",
            foreign_pcr.history.founding_device_signing_seed,
        );
        let (invite_commit, invite_fact) =
            seal_fact(&chain, &invite, &source, GovernanceSigner::CurrentStation);
        assert_eq!(
            receive(
                &receiver,
                &chain,
                &invite,
                &invite_commit,
                CommitContinuity::Standalone,
                Some(&invite_fact)
            )
            .await
            .unwrap(),
            ReceivedProducer::GovernanceCommittedHumanDevice
        );
        let local = produced(
            &hosted,
            EventKind::RealmProfile,
            "hosted",
            hosted.history.founding_device_signing_seed,
        );
        let local_source = receiver
            .test_persistence()
            .authority_commits()
            .prepare_human_signer_fact(&local, Utc::now())
            .await
            .unwrap()
            .unwrap();
        let (local_commit, local_fact) = seal_fact(
            &chain,
            &local,
            &local_source,
            GovernanceSigner::CurrentStation,
        );
        let ReceivedProducer::HostedHumanDevice(producer) = receive(
            &receiver,
            &chain,
            &local,
            &local_commit,
            held,
            Some(&local_fact),
        )
        .await
        .unwrap() else {
            panic!("complete local Account is bound by frozen original fact");
        };
        assert_eq!(producer.account_id, hosted.history.account);
        assert_eq!(producer.device_id, hosted.history.founding_device_id);
        for event in [&replica, &local] {
            let legacy = chain.commit_next(event, GovernanceSigner::CurrentStation);
            assert_eq!(
                refusal_code(receive(&receiver, &chain, event, &legacy, held, None).await),
                "temporarily_unavailable"
            );
            assert_nothing_written(&receiver, event).await;
        }
        let mut digest_mismatch = replica.clone();
        digest_mismatch
            .producer_proof
            .as_mut()
            .unwrap()
            .event_digest = invite.event_id.event_digest();
        let mut bad_fragment = replica.clone();
        bad_fragment
            .producer_proof
            .as_mut()
            .unwrap()
            .verification_method = method(
            &foreign_pcr.history.did.to_string(),
            "ak:device:not-a-device-id",
        );
        let mut wrong_projection = replica.clone();
        wrong_projection
            .producer_proof
            .as_mut()
            .unwrap()
            .verification_method = method(
            "did:web:mallory.example",
            foreign_pcr.history.founding_device_id.as_str(),
        );
        let mut tampered = commit.clone();
        tampered.committed_at += Duration::seconds(1);
        let wrong_governor = chain.seal(commit.clone(), GovernanceSigner::GenesisStation);
        let mut gap = commit.clone();
        gap.stream_position += 1;
        let gap = chain.seal(gap, GovernanceSigner::CurrentStation);
        let mut fork = commit.clone();
        fork.previous_commit_ref = Some(chain.head.previous_commit_ref.clone().unwrap());
        let fork = chain.seal(fork, GovernanceSigner::CurrentStation);
        let key_mismatch = produced(
            &hosted,
            EventKind::RealmProfile,
            "wrong device key",
            [0x77; 32],
        );
        let (wrong_key_commit, wrong_key_fact) = seal_fact(
            &chain,
            &key_mismatch,
            &local_source,
            GovernanceSigner::CurrentStation,
        );
        let cases = vec![
            (
                "proof_event_digest_mismatch",
                digest_mismatch,
                commit.clone(),
                fact.clone(),
                "signature_invalid",
            ),
            (
                "fragment_differs_from_device_id",
                bad_fragment,
                commit.clone(),
                fact.clone(),
                "signature_invalid",
            ),
            (
                "verification_method_projection_differs_from_signer",
                wrong_projection,
                commit.clone(),
                fact.clone(),
                "signature_invalid",
            ),
            (
                "governance_commit_signature_invalid",
                replica.clone(),
                tampered,
                fact.clone(),
                "signature_invalid",
            ),
            (
                "commit_signed_by_non_current_governance_station",
                replica.clone(),
                wrong_governor,
                fact.clone(),
                "signature_invalid",
            ),
            (
                "commit_binds_another_event",
                replica.clone(),
                invite_commit,
                fact.clone(),
                "signature_invalid",
            ),
            (
                "predecessor_not_held",
                replica.clone(),
                gap,
                fact.clone(),
                "dependency_missing",
            ),
            (
                "previous_commit_ref_is_not_the_held_head",
                replica.clone(),
                fork,
                fact.clone(),
                "failed_precondition",
            ),
            (
                "local_account_producer_key_mismatch",
                key_mismatch,
                wrong_key_commit,
                wrong_key_fact,
                "signature_invalid",
            ),
        ];
        for (name, event, commit, fact, expected) in cases {
            assert_eq!(
                refusal_code(receive(&receiver, &chain, &event, &commit, held, Some(&fact)).await),
                expected,
                "{name}"
            );
            assert_nothing_written(&receiver, &event).await;
        }
        // Every leaf is authenticated by the first governance digest. Even
        // using the same key with another historical revision is not a substitute.
        let mut substitutions = Vec::new();
        let mut changed = fact.clone();
        changed.key.revision.stream_position += 1;
        substitutions.push(changed);
        let mut changed = fact.clone();
        changed.key.governance_generation += 1;
        substitutions.push(changed);
        let mut changed = fact.clone();
        changed.accepted_at += Duration::seconds(1);
        substitutions.push(changed);
        let mut changed = fact.clone();
        changed.key.authorization_ref.stream_position += 1;
        substitutions.push(changed);
        for changed in substitutions {
            assert_eq!(
                refusal_code(
                    receive(&receiver, &chain, &replica, &commit, held, Some(&changed)).await
                ),
                "signature_invalid"
            );
            assert_nothing_written(&receiver, &replica).await;
        }
    });
}
