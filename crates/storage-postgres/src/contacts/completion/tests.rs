//! Real PostgreSQL proof that Contact completion finalization is exactly-once
//! under concurrent workers, idempotent on exact replay after the staged plan
//! has been replaced by its terminal result, and still fails closed on any
//! different plan, commit reference, result, or delivery.

use arkret_models_collaboration::contact_operations::{
    ContactAcceptedOutcome, ContactPeer, ContactProducerSigner, RequestAcceptanceReceipt,
};
use arkret_models_collaboration::governance::peer_contact::{
    ContactIntroductionEvidence, PeerContactAddress,
};
use arkret_models_identity::ServiceResolutionCarrier;
use arkret_wire::{
    AccountId, CommitStreamRef, CommittedEventRef, DidCoreId, DidUrl, Event, EventId,
    ProtocolSignature, RealmCommitId, RealmId, ScopeRef,
};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;
use soland_storage::{
    ContactCompletionAction, ContactCompletionDraft, ContactDeliveryTarget, FederationOutboxRecord,
};

use super::*;
use crate::test_database::TestDatabase;

const STATION: &str = "ak:did_core:web:contact-station.example";
const PEER_STATION: &str = "ak:did_core:web:contact-peer-station.example";
const RECEIPT_METHOD: &str = "did:web:contact-station.example#receipt";

#[derive(Clone)]
struct Fixture {
    ready: CommittedContactCompletionIntent,
    result: ContactCompletionResult,
    delivery: Option<FederationOutboxRecord>,
}

fn core(value: &str) -> DidCoreId {
    DidCoreId::new(value).unwrap()
}

fn human(local: &str, station: &str) -> ContactPeer {
    ContactPeer::Human {
        account_id: AccountId::new(
            core(&format!("ak:did_core:web:{local}.example")),
            core(station),
        ),
    }
}

fn hash(fill: char) -> arkret_wire::Hash {
    arkret_wire::Hash::new(format!("sha256:{}", fill.to_string().repeat(64))).unwrap()
}

fn base() -> DateTime<Utc> {
    "2026-09-20T00:00:00Z".parse().unwrap()
}

/// One structurally bound request Event carrying its producer proof.
fn request_event(holder: &ContactPeer, peer: &ContactPeer, realm_id: &RealmId) -> Event {
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        arkret_wire::EventKind::ContactRequested.as_str(),
        ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        holder.contact_actor_id(),
        json!({
            "peer": peer,
            "granted_to_peer_scopes": ["direct_message"],
            "introduction_evidence_digest": hash('e'),
        }),
        base(),
    )
    .unwrap();
    let digest = event.event_id.event_digest();
    event.producer_proof = Some(arkret_wire::ProducerEventProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: DidUrl::new("did:web:contact-holder.example#key").unwrap(),
        event_digest: digest.clone(),
        created_at: base(),
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: arkret_wire::test_support::structural_only_detached_jws(&digest),
    });
    event
}

/// Sign the request receipt the way the completion worker does: the
/// signature records its own signing instant, so two signings differ.
fn request_result(
    intent: &ContactCompletionIntent,
    signed_at: DateTime<Utc>,
) -> ContactCompletionResult {
    let key = SigningKey::from_bytes(&[41_u8; 32]);
    let receipt =
        RequestAcceptanceReceipt::sign_with(intent.request_receipt_core().unwrap(), |bytes| {
            Ok(ProtocolSignature {
                verification_method: DidUrl::new(RECEIPT_METHOD).unwrap(),
                created_at: signed_at,
                jws: arkret_canonical::base64url_encode(key.sign(bytes).to_bytes()),
            })
        })
        .unwrap();
    ContactCompletionResult::Accepted {
        outcome: ContactAcceptedOutcome::Request {
            operation_id: intent.plan.operation_id.clone(),
            request_acceptance_receipt: receipt,
        },
    }
}

/// A confirmed Contact request whose peer is served by this Station
/// (`remote == false`, no delivery) or by another Station (`remote == true`,
/// one federation delivery).
fn fixture(remote: bool) -> Fixture {
    let holder = human("contact-holder", STATION);
    let peer = human("contact-peer", if remote { PEER_STATION } else { STATION });
    let realm_id = RealmId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [5_u8; 32],
    ));
    let event = request_event(&holder, &peer, &realm_id);
    let target = ContactDeliveryTarget {
        contact_address: PeerContactAddress::for_recipient(
            peer.clone(),
            ServiceResolutionCarrier::ResolutionUrl {
                resolution_url: "https://contact-peer-station.example/.well-known/resolution"
                    .to_owned(),
            },
        ),
        introduction_evidence: Some(ContactIntroductionEvidence::SharedRealm {
            realm_id: realm_id.clone(),
            requester_member_ref: EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [6_u8; 32],
            ),
            target_member_ref: EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [7_u8; 32],
            ),
        }),
        idempotency_key: arkret_wire::IdempotencyKey::new("contact-delivery-1").unwrap(),
    };
    let producer = ContactProducerSigner::direct(
        DidUrl::new("did:web:contact-holder.example#key").unwrap(),
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            SigningKey::from_bytes(&[23_u8; 32])
                .verifying_key()
                .to_bytes(),
        ))
        .unwrap(),
    )
    .unwrap();
    let mut intent = ContactCompletionDraft {
        event: event.clone(),
        operation_id: arkret_wire::ProtocolOperationId::new(
            "ak:operation:ak.self.contact.command.commit",
        )
        .unwrap(),
        holder: holder.clone(),
        action: ContactCompletionAction::Request {
            slot_version: 1,
            slot_predecessor: None,
        },
        response_binding: ContactCompletionBinding {
            authenticated_actor: holder.contact_actor_id(),
            idempotency_key: "contact-commit-1".to_owned(),
            request_hash: hash('a').as_str().to_owned(),
        },
        target,
        local_mirror_target: None,
    }
    .bind_producer(producer)
    .unwrap();
    intent
        .freeze_acceptance_time(base() + Duration::seconds(1))
        .unwrap();
    assert_eq!(intent.requires_delivery(), remote);
    let result = request_result(&intent, base() + Duration::seconds(2));
    let delivery = remote.then(|| {
        let ContactCompletionResult::Accepted { outcome } = &result else {
            unreachable!()
        };
        FederationOutboxRecord::pending(
            "contact-outbox-1".to_owned(),
            core(PEER_STATION),
            "https://contact-peer-station.example".to_owned(),
            "/_arkret/peer/contacts".to_owned(),
            intent.plan.target.idempotency_key.as_str().to_owned(),
            serde_json::to_string(&intent.finalized_carrier(outcome).unwrap()).unwrap(),
            base().timestamp_millis(),
        )
    });
    let committed_ref = CommittedEventRef {
        event_id: event.event_id.clone(),
        commit_id: RealmCommitId::from_digest(arkret_canonical::sha256_bytes(b"contact-commit")),
        stream_ref: CommitStreamRef::Realm { realm_id },
        stream_position: 7,
    };
    Fixture {
        ready: CommittedContactCompletionIntent {
            event_digest: event.event_id.event_digest(),
            committed_ref,
            intent,
        },
        result,
        delivery,
    }
}

async fn stage(pool: &PgPool, fixture: &Fixture) {
    let mut conn = pg_conn(pool).await.unwrap();
    stage_in_transaction(
        &mut conn,
        &fixture.ready.committed_ref,
        &fixture.ready.intent,
    )
    .await
    .unwrap();
    // Exactly what the worker queue reads back.
    let queued = confirmed(pool, 16, None).await.unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].event_digest, fixture.ready.event_digest);
}

async fn run(pool: &PgPool, fixture: &Fixture) -> PersistenceResult<bool> {
    finalize(
        pool,
        &fixture.ready,
        &fixture.result,
        fixture.delivery.as_ref(),
    )
    .await
}

#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

async fn count(pool: &PgPool, query: &str) -> i64 {
    let mut conn = pg_conn(pool).await.unwrap();
    sql_query(query)
        .get_result::<Count>(&mut *conn)
        .await
        .unwrap()
        .count
}

/// The single terminal state every accepted path must leave behind.
async fn assert_terminal_once(pool: &PgPool, fixture: &Fixture) {
    let mut conn = pg_conn(pool).await.unwrap();
    let row = sql_query(format!(
        "SELECT {COLUMNS} FROM contact_completion_intents WHERE event_digest=$1"
    ))
    .bind::<Text, _>(fixture.ready.event_digest.as_str())
    .get_result::<CompletionRow>(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert!(row.intent.is_none());
    assert_eq!(
        row.result,
        Some(serde_json::to_value(&fixture.result).unwrap())
    );
    assert!(confirmed(pool, 16, None).await.unwrap().is_empty());
    assert_eq!(
        count(
            pool,
            "SELECT count(*) AS count FROM idempotency_keys \
             WHERE operation_id='ak.self.contact.command.commit'"
        )
        .await,
        1
    );
    let delivered = count(
        pool,
        "SELECT count(*) AS count FROM contact_completion_intents c \
         JOIN federation_outbox o ON o.id=c.delivery_outbox_id",
    )
    .await;
    assert_eq!(delivered, i64::from(fixture.delivery.is_some()));
    assert_eq!(
        count(pool, "SELECT count(*) AS count FROM federation_outbox").await,
        i64::from(fixture.delivery.is_some())
    );
}

/// Hold the staged row's lock until both workers are queued on it, then
/// release it so the two finalizations genuinely contend for the same row.
async fn race(remote: bool) {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let fixture = fixture(remote);
    stage(&pool, &fixture).await;

    let mut holder = pg_conn(&pool).await.unwrap();
    sql_query("BEGIN").execute(&mut *holder).await.unwrap();
    sql_query(
        "SELECT event_digest FROM contact_completion_intents WHERE event_digest=$1 FOR UPDATE",
    )
    .bind::<Text, _>(fixture.ready.event_digest.as_str())
    .execute(&mut *holder)
    .await
    .unwrap();
    let release = async {
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(20);
        loop {
            let waiting = count(
                &pool,
                "SELECT count(*) AS count FROM pg_stat_activity \
                 WHERE datname=current_database() AND wait_event_type='Lock'",
            )
            .await;
            if waiting >= 2 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "both Contact workers must block on the staged row"
            );
            tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
        }
        sql_query("COMMIT").execute(&mut *holder).await.unwrap();
    };
    let (first, second, ()) = tokio::join!(run(&pool, &fixture), run(&pool, &fixture), release);
    let mut applied = vec![
        first.expect("first concurrent worker"),
        second.expect("second concurrent worker"),
    ];
    applied.sort_unstable();
    assert_eq!(
        applied,
        [false, true],
        "exactly one worker applies the result"
    );
    assert_terminal_once(&pool, &fixture).await;
}

#[tokio::test]
async fn concurrent_workers_finalize_local_completion_exactly_once() {
    race(false).await;
}

#[tokio::test]
async fn concurrent_workers_finalize_delivered_completion_exactly_once() {
    race(true).await;
}

#[tokio::test]
async fn sequential_exact_replay_after_terminal_is_idempotent() {
    for remote in [false, true] {
        let database = TestDatabase::lease().await;
        let pool = database.pool();
        let fixture = fixture(remote);
        stage(&pool, &fixture).await;
        assert!(run(&pool, &fixture).await.unwrap());
        for _ in 0..2 {
            assert!(
                !run(&pool, &fixture)
                    .await
                    .expect("exact replay after terminal"),
                "an exact replay never re-applies the terminal result"
            );
        }
        assert_terminal_once(&pool, &fixture).await;
    }
}

#[tokio::test]
async fn different_completion_after_terminal_still_conflicts() {
    for remote in [false, true] {
        let database = TestDatabase::lease().await;
        let pool = database.pool();
        let fixture = fixture(remote);
        stage(&pool, &fixture).await;
        assert!(run(&pool, &fixture).await.unwrap());

        // A differently signed result for the same plan cannot replace the
        // first durable terminal result.
        let mut resigned = fixture.clone();
        resigned.result = request_result(&fixture.ready.intent, base() + Duration::seconds(3));
        if let (Some(delivery), ContactCompletionResult::Accepted { outcome }) =
            (resigned.delivery.as_mut(), &resigned.result)
        {
            delivery.payload_json =
                serde_json::to_string(&fixture.ready.intent.finalized_carrier(outcome).unwrap())
                    .unwrap();
        }
        // A different staged plan for the same Event and result.
        let mut replanned = fixture.clone();
        replanned.ready.intent.plan.local_mirror_target = Some("mirror-elsewhere".to_owned());
        // A different authority commit for the same Event.
        let mut recommitted = fixture.clone();
        recommitted.ready.committed_ref.stream_position += 1;
        let mut cases = vec![
            (
                "resigned result",
                resigned,
                "terminal result cannot be replaced",
            ),
            (
                "different plan",
                replanned,
                "does not bind the exact committed Event",
            ),
            (
                "different commit",
                recommitted,
                "does not bind the exact committed Event",
            ),
        ];
        if remote {
            // Same result, but a delivery whose bytes differ from the durable outbox row.
            let mut redelivered = fixture.clone();
            redelivered.delivery.as_mut().unwrap().payload_json = "{}".to_owned();
            cases.push((
                "different delivery",
                redelivered,
                "idempotency key binds different bytes",
            ));
        }
        for (name, case, expected) in cases {
            let error = run(&pool, &case)
                .await
                .expect_err("a different completion after terminal must fail closed");
            assert!(
                error.to_string().contains(expected),
                "{name} (remote={remote}) failed for the wrong reason: {error}"
            );
        }
        assert_terminal_once(&pool, &fixture).await;
    }
}
