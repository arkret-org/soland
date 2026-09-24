//! Non-governance receipt of committed Events (federation §3), following
//! `ak.vector.federation.non_governance_receiver_trusts_governance_commit.v1`.
//!
//! The receiver is a real Station over PostgreSQL that hosts one Account with
//! an accepted PCR genesis. The Realm is governed elsewhere: a verified
//! genesis/handoff chain from Station A to Station B. A foreign human device
//! producer is never resolved: the Station holds no directory entry for it,
//! so any key lookup would refuse. Every rejection writes nothing.

use arkret_canonical::DigestSuite;
use arkret_wire::{
    Did, DidCoreId, DidUrl, Event, EventKind, RealmCommit, ScopeRef, project_did_to_core_id,
};
use chrono::{Duration, Utc};
use soland_http::state::AppState;
use soland_services::ServiceError;
use soland_services::committed_receipt::{
    CommitContinuity, ReceivedProducer, verify_committed_event_receipt,
};
use soland_test_support::AppStateTestExt as _;
use soland_test_support::device_authorization_history::sign_event;
use soland_test_support::governance_authority::{GovernanceChain, GovernanceSigner};
use soland_test_support::pcr_genesis::PcrGenesisFixture;

const FOREIGN_DID: &str = "did:web:remote-alice.example";
const FOREIGN_STATION_DID: &str = "did:web:remote-station.example";
const FOREIGN_DEVICE: &str = "ak:device:0196419b-0000-7000-8000-00000000c0a1";
const FOREIGN_SEED: [u8; 32] = [0x61; 32];

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn core_id(did: &str) -> DidCoreId {
    project_did_to_core_id(&Did::new(did).unwrap()).unwrap()
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

/// A Realm-profile Event produced by a human device of an Account on another
/// Station, signed under `method`.
fn foreign(chain: &GovernanceChain, name: &str, method: DidUrl) -> Event {
    sign_event(
        unsigned_event(
            chain,
            EventKind::RealmProfile,
            core_id(FOREIGN_DID),
            core_id(FOREIGN_STATION_DID),
            name,
        ),
        method,
        FOREIGN_SEED,
    )
}

fn foreign_device(chain: &GovernanceChain, name: &str) -> Event {
    foreign(chain, name, method(FOREIGN_DID, FOREIGN_DEVICE))
}

async fn receive(
    receiver: &AppState,
    chain: &GovernanceChain,
    event: &Event,
    commit: &RealmCommit,
    continuity: CommitContinuity<'_>,
) -> Result<ReceivedProducer, ServiceError> {
    let store = receiver.test_persistence();
    verify_committed_event_receipt(
        store.device_revocations(),
        event,
        commit,
        continuity,
        &chain.authority,
        &chain.keys,
        &receiver.service_core_id(),
        DigestSuite::Sha256,
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

#[test]
fn non_governance_receiver_trusts_the_governance_commit() {
    runtime().block_on(async {
        let receiver = soland_test_support::app_state_with_postgres_governance(
            soland_test_support::app_config(),
        );
        let hosted = PcrGenesisFixture::new(receiver.service_did());
        hosted.admit(&receiver).await.expect("accepted PCR genesis");
        let chain = GovernanceChain::new();
        let held = CommitContinuity::After(&chain.head);

        // foreign_human_producer_replica_stored: no key is resolved; the
        // verified governance Commit is the commitment to its authorization.
        let replica = foreign_device(&chain, "replicated");
        let commit = chain.commit_next(&replica, GovernanceSigner::CurrentStation);
        assert_eq!(
            receive(&receiver, &chain, &replica, &commit, held)
                .await
                .expect("a foreign human replica is stored"),
            ReceivedProducer::GovernanceCommittedHumanDevice
        );

        // foreign_human_invite_delivery_verified: an invite is received
        // outside any held stream and only binds its `invite_commit`.
        let invite = sign_event(
            unsigned_event(
                &chain,
                EventKind::InviteCreate,
                core_id(FOREIGN_DID),
                core_id(FOREIGN_STATION_DID),
                "invite",
            ),
            method(FOREIGN_DID, FOREIGN_DEVICE),
            FOREIGN_SEED,
        );
        let invite_commit = chain.commit_next(&invite, GovernanceSigner::CurrentStation);
        assert_eq!(
            receive(
                &receiver,
                &chain,
                &invite,
                &invite_commit,
                CommitContinuity::Standalone
            )
            .await
            .expect("a foreign human invite is verified"),
            ReceivedProducer::GovernanceCommittedHumanDevice
        );

        // local_account_producer_verified_against_local_pcr
        let account = hosted.history.account.clone();
        let hosted_event = |name: &str, seed: [u8; 32]| {
            sign_event(
                unsigned_event(
                    &chain,
                    EventKind::RealmProfile,
                    account.principal_id.clone(),
                    account.station_id.clone(),
                    name,
                ),
                hosted.history.device_verification_method.clone(),
                seed,
            )
        };
        let local = hosted_event("hosted", hosted.history.founding_device_signing_seed);
        let local_commit = chain.commit_next(&local, GovernanceSigner::CurrentStation);
        let ReceivedProducer::HostedHumanDevice(producer) =
            receive(&receiver, &chain, &local, &local_commit, held)
                .await
                .expect("a hosted producer verifies under its local PCR key")
        else {
            panic!("a hosted Account device is verified against local PCR");
        };
        assert_eq!(producer.account_id, account);
        assert_eq!(producer.device_id, hosted.history.founding_device_id);

        let mut digest_mismatch = foreign_device(&chain, "digest");
        digest_mismatch
            .producer_proof
            .as_mut()
            .unwrap()
            .event_digest = replica.event_id.event_digest();
        let mut tampered = chain.commit_next(&replica, GovernanceSigner::CurrentStation);
        tampered.committed_at += Duration::seconds(1);
        let unbound = chain.commit_next(&invite, GovernanceSigner::CurrentStation);
        let mut gap = chain.commit_next(&replica, GovernanceSigner::CurrentStation);
        gap.stream_position += 1;
        let gap = chain.seal(gap, GovernanceSigner::CurrentStation);
        let mut fork = chain.commit_next(&replica, GovernanceSigner::CurrentStation);
        fork.previous_commit_ref = Some(fork.commit_id.clone());
        let fork = chain.seal(fork, GovernanceSigner::CurrentStation);
        let key_mismatch = hosted_event("hosted, other key", [0x77; 32]);

        let cases: Vec<(&str, Event, Option<RealmCommit>, &str)> = vec![
            (
                "proof_event_digest_mismatch",
                digest_mismatch,
                None,
                "signature_invalid",
            ),
            (
                "fragment_differs_from_device_id",
                foreign(
                    &chain,
                    "fragment",
                    method(FOREIGN_DID, "ak:device:not-a-device-id"),
                ),
                None,
                "signature_invalid",
            ),
            (
                "verification_method_projection_differs_from_signer",
                foreign(
                    &chain,
                    "projection",
                    method("did:web:mallory.example", FOREIGN_DEVICE),
                ),
                None,
                "signature_invalid",
            ),
            (
                "governance_commit_signature_invalid",
                replica.clone(),
                Some(tampered),
                "signature_invalid",
            ),
            (
                "commit_signed_by_non_current_governance_station",
                replica.clone(),
                Some(chain.commit_next(&replica, GovernanceSigner::GenesisStation)),
                "signature_invalid",
            ),
            (
                "commit_binds_another_event",
                replica.clone(),
                Some(unbound),
                "signature_invalid",
            ),
            (
                "predecessor_not_held",
                replica.clone(),
                Some(gap),
                "dependency_missing",
            ),
            (
                "previous_commit_ref_is_not_the_held_head",
                replica.clone(),
                Some(fork),
                "failed_precondition",
            ),
            (
                "local_account_producer_key_mismatch",
                key_mismatch,
                None,
                "signature_invalid",
            ),
        ];
        for (name, event, commit, expected) in cases {
            let commit = commit
                .unwrap_or_else(|| chain.commit_next(&event, GovernanceSigner::CurrentStation));
            let result = receive(&receiver, &chain, &event, &commit, held).await;
            assert_eq!(refusal_code(result), expected, "variant {name}");
            assert_nothing_written(&receiver, &event).await;
        }
    });
}
