//! Second-member admission and committed-replication fanout on real
//! PostgreSQL.
//!
//! * The governance Station admits `ak.member.state` only at its same-cut FSM, writer and join-rule
//!   decision, and plans the committed-replication fanout of every Realm-stream Event from the
//!   joined set that Event produced (`federation.md` §4.1.1), in the Event's own transaction.
//! * A member Station stores exact source replicas: the hosted member's own verified `join` opens
//!   its held Realm stream, later Commits must directly follow it, and gaps, forks and unheld
//!   streams are refused with zero writes.

#[path = "support/ordinary_realm.rs"]
mod ordinary_realm;

use arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest;
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel_async::RunQueryDsl;
use ordinary_realm::{
    STATION, bootstrap_unit_with_join_rule, founder, message_payload, next_request,
    next_request_for_actor,
};
use soland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, CommittedReplica, CommittedReplicaOutcome,
    ConflictCode, CurrentRealmAuthority, EventCommitRequest, EventCommitUnitOfWork,
    OrdinaryRealmBootstrapCommitUnit, RealmFanoutAuthorityWitness,
};
use soland_storage_postgres::test_database::TestDatabase;
use soland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgPool};

const MEMBER_STATION: &str = "ak:did_core:web:member-station.example";

fn member_station() -> arkret_wire::DidCoreId {
    arkret_wire::DidCoreId::new(MEMBER_STATION).unwrap()
}

fn remote_member(label: &str) -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(format!("ak:did_core:web:{label}.example")).unwrap(),
        member_station(),
    ))
}

fn founder_actor() -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        founder(),
        arkret_wire::DidCoreId::new(STATION).unwrap(),
    ))
}

/// A membership payload. Every call carries its own audit reason, so two
/// requests for the same transition are distinct Events.
fn membership(
    realm_id: &arkret_wire::RealmId,
    member: &arkret_wire::ActorId,
    state: &str,
) -> serde_json::Value {
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    serde_json::json!({
        "realm_id": realm_id,
        "member_id": member,
        "membership": state,
        "reason": format!("fixture transition {sequence}"),
    })
}

/// The request as the guarded unit sends it: carrying its exact source
/// submission so a remote joined member can be owed the Event.
fn sourced(mut request: EventCommitRequest) -> EventCommitRequest {
    request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        request.authority_commit.event.clone(),
    ));
    request
}

fn membership_request(
    previous: &AuthorityCommitTransaction,
    writer: arkret_wire::ActorId,
    member: &arkret_wire::ActorId,
    state: &str,
) -> EventCommitRequest {
    sourced(next_request_for_actor(
        previous,
        arkret_wire::EventKind::MemberState,
        writer,
        membership(&previous.event.realm_id, member, state),
        previous.commit.committed_at,
    ))
}

async fn admit(pool: &PgPool, seed: &str, join_rule: &str) -> OrdinaryRealmBootstrapCommitUnit {
    let unit = bootstrap_unit_with_join_rule(seed, join_rule);
    unit.validate().unwrap();
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .expect("admit ordinary Realm bootstrap");
    unit
}

#[derive(diesel::QueryableByName)]
struct OutboxRow {
    #[diesel(sql_type = Text)]
    peer_id: String,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Text)]
    endpoint: String,
    #[diesel(sql_type = Text)]
    payload_json: String,
    #[diesel(sql_type = Jsonb)]
    realm_fanout: serde_json::Value,
    #[diesel(sql_type = BigInt)]
    linked: i64,
}

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[derive(diesel::QueryableByName)]
struct MembershipRow {
    #[diesel(sql_type = Text)]
    membership: String,
}

async fn fanout_rows(pool: &PgPool, request: &EventCommitRequest) -> Vec<OutboxRow> {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT o.peer_id, o.state, o.endpoint, o.payload_json, o.realm_fanout, \
         (SELECT count(*) FROM event_federation_outbox l WHERE l.outbox_id = o.id) AS linked \
         FROM federation_outbox o WHERE o.idempotency_key = $1 ORDER BY o.peer_id",
    )
    .bind::<Text, _>(format!(
        "realm-fanout:{}",
        request.authority_commit.commit.commit_id
    ))
    .load::<OutboxRow>(&mut *conn)
    .await
    .unwrap()
}

async fn outbox_count(pool: &PgPool) -> i64 {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT count(*) AS count FROM federation_outbox")
        .get_result::<CountRow>(&mut *conn)
        .await
        .unwrap()
        .count
}

async fn member_state(
    pool: &PgPool,
    realm_id: &arkret_wire::RealmId,
    member: &arkret_wire::ActorId,
) -> Option<String> {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT membership FROM member_state_current_results WHERE realm_id=$1 AND member_id=$2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(member.to_string())
    .load::<MembershipRow>(&mut *conn)
    .await
    .unwrap()
    .pop()
    .map(|row| row.membership)
}

/// The one intent the Event owes the member Station, with exactly the
/// expected frozen bases and an exact source-submission body.
fn assert_owed(
    rows: &[OutboxRow],
    request: &EventCommitRequest,
    witnesses: &[(&arkret_wire::ActorId, &arkret_wire::EventId)],
) {
    assert_eq!(rows.len(), 1, "one intent per distinct remote Station");
    let row = &rows[0];
    assert_eq!(row.peer_id, MEMBER_STATION);
    assert_eq!(row.state, "pending_route");
    assert_eq!(row.endpoint, "/_arkret/peer/events");
    assert_eq!(row.linked, 1);
    let body: PeerAuthoritySubmitRequest = serde_json::from_str(&row.payload_json).unwrap();
    body.validate().unwrap();
    let PeerAuthoritySubmitRequest::CommittedReplication(body) = body else {
        panic!("Realm fanout must use the committed_replication branch");
    };
    assert_eq!(body.replications.len(), 1);
    assert_eq!(
        body.replications[0].event_submission,
        request.realm_fanout_source.clone().unwrap()
    );
    assert_eq!(
        body.replications[0].source_commit,
        request.authority_commit.commit
    );
    assert!(
        !row.payload_json.contains("fanout_authorization_basis")
            && !row.payload_json.contains("authority_witnesses"),
        "the frozen basis stays in sender metadata"
    );
    let frozen: Vec<RealmFanoutAuthorityWitness> =
        serde_json::from_value(row.realm_fanout["authority_witnesses"].clone()).unwrap();
    let expected: Vec<_> = witnesses
        .iter()
        .map(|(member, event_id)| RealmFanoutAuthorityWitness {
            member_id: (*member).clone(),
            membership_event_ref: event_id.to_string(),
        })
        .collect();
    assert_eq!(frozen, expected);
}

/// A remote account enters a public Realm by its own `join`; every later
/// Realm Event is owed to its Station with the membership that authorizes it,
/// a plaintext Message only when the Station may read plaintext, and a
/// member who leaves stops authorizing the intent.
#[tokio::test]
async fn remote_joined_target_set_and_fanout_basis_commit_with_the_event() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let unit = admit(&pool, "fanout-public", "public").await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let last = unit.transactions.last().unwrap();
    let alice = remote_member("fanout-alice");
    let bob = remote_member("fanout-bob");

    let alice_join = membership_request(last, alice.clone(), &alice, "join");
    let outcome = uow.commit_event(alice_join.clone()).await.unwrap();
    assert_eq!(outcome.outbox_inserted, 1);
    assert_eq!(
        member_state(&pool, &realm_id, &alice).await.as_deref(),
        Some("join")
    );
    let alice_ref = alice_join.authority_commit.event.event_id.clone();
    assert_owed(
        &fanout_rows(&pool, &alice_join).await,
        &alice_join,
        &[(&alice, &alice_ref)],
    );

    let at = last.commit.committed_at;
    let strand = sourced(next_request(
        &alice_join.authority_commit,
        arkret_wire::EventKind::StrandCreate,
        &founder(),
        serde_json::json!({"object": {
            "schema":"ak.schema.strand.v1",
            "realm_id":realm_id,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Fanout discussion"},
            "state":"active",
            "created_by":founder_actor(),
            "created_at":at,
        }}),
        at,
    ));
    uow.commit_event(strand.clone()).await.unwrap();
    assert_owed(
        &fanout_rows(&pool, &strand).await,
        &strand,
        &[(&alice, &alice_ref)],
    );
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let default = sourced(next_request(
        &strand.authority_commit,
        arkret_wire::EventKind::RealmSetDefaultStrand,
        &founder(),
        serde_json::json!({
            "realm_id": realm_id,
            "strand_id": strand_id,
            "expected_default_strand_id": null,
        }),
        at,
    ));
    uow.commit_event(default.clone()).await.unwrap();

    // The member Station is not a private plaintext service of this Realm:
    // it may not hold the plaintext body, so no intent is planned.
    let message = sourced(next_request(
        &default.authority_commit,
        arkret_wire::EventKind::MessageCreate,
        &founder(),
        message_payload(&strand_id, "plaintext stays on the governance Station"),
        at,
    ));
    let outcome = uow.commit_event(message.clone()).await.unwrap();
    assert_eq!(outcome.outbox_inserted, 0);
    assert!(fanout_rows(&pool, &message).await.is_empty());

    // A second member on the same Station adds a basis to one intent.
    let bob_join = membership_request(&message.authority_commit, bob.clone(), &bob, "join");
    uow.commit_event(bob_join.clone()).await.unwrap();
    let bob_ref = bob_join.authority_commit.event.event_id.clone();
    let mut expected = vec![(&alice, &alice_ref), (&bob, &bob_ref)];
    expected.sort_by_key(|(member, _)| member.to_string());
    assert_owed(&fanout_rows(&pool, &bob_join).await, &bob_join, &expected);

    // After Alice leaves by her own Control Event, only Bob authorizes it.
    let alice_leave =
        membership_request(&bob_join.authority_commit, alice.clone(), &alice, "leave");
    uow.commit_event(alice_leave.clone()).await.unwrap();
    assert_eq!(
        member_state(&pool, &realm_id, &alice).await.as_deref(),
        Some("leave")
    );
    assert_owed(
        &fanout_rows(&pool, &alice_leave).await,
        &alice_leave,
        &[(&bob, &bob_ref)],
    );

    // Bob leaves: nobody on the member Station is joined, so nothing is owed.
    let bob_leave = membership_request(&alice_leave.authority_commit, bob.clone(), &bob, "leave");
    let outcome = uow.commit_event(bob_leave.clone()).await.unwrap();
    assert_eq!(outcome.outbox_inserted, 0);
}

fn assert_code(error: &soland_storage::PersistenceError, code: ConflictCode) {
    assert_eq!(error.conflict_code(), Some(code), "{error}");
}

/// An Event owed to a remote Station cannot commit without the exact source
/// submission its fanout carries.
#[tokio::test]
async fn an_event_owed_to_a_remote_station_needs_its_source_submission() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let unit = admit(&pool, "fanout-unsourced", "public").await;
    let alice = remote_member("unsourced-alice");
    let join = membership_request(
        unit.transactions.last().unwrap(),
        alice.clone(),
        &alice,
        "join",
    );
    let mut unsourced = join.clone();
    unsourced.realm_fanout_source = None;
    let outbox = outbox_count(&pool).await;
    uow.commit_event(unsourced).await.unwrap_err();
    assert_eq!(outbox_count(&pool).await, outbox);
    assert!(
        PgAuthorityCommitStore { pool: pool.clone() }
            .committed_event(&join.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    uow.commit_event(join).await.unwrap();
}

fn governance_authority(unit: &OrdinaryRealmBootstrapCommitUnit) -> CurrentRealmAuthority {
    unit.transactions[0].expected_authority.clone()
}

fn replica(
    unit: &OrdinaryRealmBootstrapCommitUnit,
    request: &EventCommitRequest,
    opens_stream: bool,
) -> CommittedReplica {
    CommittedReplica {
        local_service_id: member_station(),
        authority: governance_authority(unit),
        event: request.authority_commit.event.clone(),
        commit: request.authority_commit.commit.clone(),
        opens_stream,
        received_at: request.authority_commit.commit.committed_at,
    }
}

/// The member Station opens its held Realm stream with its member's own join
/// and then stores only direct successors while that member is joined.
#[tokio::test]
async fn committed_replication_persists_exact_source_bytes_and_remote_authority() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    // The governance Station's cut is built but never admitted here: this
    // database is the member Station.
    let unit = bootstrap_unit_with_join_rule("replica-public", "public");
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let last = unit.transactions.last().unwrap();
    let alice = remote_member("replica-alice");
    let join = membership_request(last, alice.clone(), &alice, "join");

    // A non-join Event cannot open the stream.
    let early = sourced(next_request(
        last,
        arkret_wire::EventKind::RealmProfile,
        &founder(),
        serde_json::json!({"name":"Renamed"}),
        last.commit.committed_at,
    ));
    let error = store
        .install_committed_replica(&replica(&unit, &early, false))
        .await
        .unwrap_err();
    assert_code(&error, ConflictCode::DependencyMissing);

    assert_eq!(
        store
            .install_committed_replica(&replica(&unit, &join, true))
            .await
            .unwrap(),
        CommittedReplicaOutcome::Stored
    );
    assert_eq!(
        store
            .install_committed_replica(&replica(&unit, &join, true))
            .await
            .unwrap(),
        CommittedReplicaOutcome::Duplicate
    );
    let held = store
        .committed_event(&join.authority_commit.event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(held.commit, join.authority_commit.commit);
    assert_eq!(held.event, join.authority_commit.event);
    assert_eq!(
        member_state(&pool, &realm_id, &alice).await.as_deref(),
        Some("join")
    );
    let authority = store.current_authority(&realm_id).await.unwrap().unwrap();
    assert_eq!(authority, governance_authority(&unit));

    let next = sourced(next_request(
        &join.authority_commit,
        arkret_wire::EventKind::RealmProfile,
        &founder(),
        serde_json::json!({"name":"Replicated"}),
        last.commit.committed_at,
    ));
    // A different Commit at the held position is a fork, not a successor.
    let mut fork = next.clone();
    fork.authority_commit.commit.stream_position = join.authority_commit.commit.stream_position;
    fork.authority_commit.commit.previous_commit_ref = last.commit.previous_commit_ref.clone();
    let error = store
        .install_committed_replica(&replica(&unit, &fork, false))
        .await
        .unwrap_err();
    assert_code(&error, ConflictCode::ForkQuarantine);
    // A Commit after an unheld one is a missing dependency.
    let after_next = sourced(next_request(
        &next.authority_commit,
        arkret_wire::EventKind::RealmProfile,
        &founder(),
        serde_json::json!({"name":"Too early"}),
        last.commit.committed_at,
    ));
    let error = store
        .install_committed_replica(&replica(&unit, &after_next, false))
        .await
        .unwrap_err();
    assert_code(&error, ConflictCode::DependencyMissing);
    assert!(
        store
            .committed_event(&after_next.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );

    assert_eq!(
        store
            .install_committed_replica(&replica(&unit, &next, false))
            .await
            .unwrap(),
        CommittedReplicaOutcome::Stored
    );
    assert_eq!(
        store
            .install_committed_replica(&replica(&unit, &after_next, false))
            .await
            .unwrap(),
        CommittedReplicaOutcome::Stored
    );

    // Once Alice has left, the member Station hosts nobody who may hold
    // further Events.
    let leave = membership_request(&after_next.authority_commit, alice.clone(), &alice, "leave");
    store
        .install_committed_replica(&replica(&unit, &leave, false))
        .await
        .unwrap();
    let later = sourced(next_request(
        &leave.authority_commit,
        arkret_wire::EventKind::RealmProfile,
        &founder(),
        serde_json::json!({"name":"Unowed"}),
        last.commit.committed_at,
    ));
    let error = store
        .install_committed_replica(&replica(&unit, &later, false))
        .await
        .unwrap_err();
    assert_code(&error, ConflictCode::CapabilityDenied);
}

/// A remote authority record never names this Station, never goes back a
/// generation and never forks one.
#[tokio::test]
async fn remote_authority_records_only_move_forward() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = bootstrap_unit_with_join_rule("remote-authority", "public");
    let authority = governance_authority(&unit);
    store
        .record_remote_authority(&authority, &member_station())
        .await
        .unwrap();
    store
        .record_remote_authority(&authority, &member_station())
        .await
        .unwrap();
    assert!(
        store
            .record_remote_authority(&authority, &authority.service_id)
            .await
            .is_err()
    );
    let mut forked = authority.clone();
    forked.service_id =
        arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
    let error = store
        .record_remote_authority(&forked, &member_station())
        .await
        .unwrap_err();
    assert_code(&error, ConflictCode::ForkQuarantine);
    assert_eq!(
        store
            .current_authority(&authority.realm_id)
            .await
            .unwrap()
            .unwrap(),
        authority
    );
}

/// Before every send the frozen basis is rechecked at the current accepted
/// cut: the intent stays owed while one frozen member is still joined by the
/// same membership Event, and is no longer owed once that member left.
#[tokio::test]
async fn fanout_basis_revalidation_cancels_after_member_leave() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let unit = admit(&pool, "fanout-revalidation", "public").await;
    let local = arkret_wire::DidCoreId::new(STATION).unwrap();
    let alice = remote_member("revalidation-alice");
    let join = membership_request(
        unit.transactions.last().unwrap(),
        alice.clone(),
        &alice,
        "join",
    );
    uow.commit_event(join.clone()).await.unwrap();
    let event = &join.authority_commit.event;
    let basis = vec![RealmFanoutAuthorityWitness {
        member_id: alice.clone(),
        membership_event_ref: event.event_id.to_string(),
    }];
    let now = chrono::Utc::now();
    assert!(
        store
            .realm_fanout_still_owed(event, &local, &member_station(), &basis, now)
            .await
            .unwrap()
    );
    // Another Station is never owed an intent frozen for this one, and a
    // basis naming another membership Event does not authorize it.
    let elsewhere = arkret_wire::DidCoreId::new("ak:did_core:web:elsewhere.example").unwrap();
    assert!(
        !store
            .realm_fanout_still_owed(event, &local, &elsewhere, &basis, now)
            .await
            .unwrap()
    );
    let stale = vec![RealmFanoutAuthorityWitness {
        member_id: alice.clone(),
        membership_event_ref: unit.transactions.last().unwrap().event.event_id.to_string(),
    }];
    assert!(
        !store
            .realm_fanout_still_owed(event, &local, &member_station(), &stale, now)
            .await
            .unwrap()
    );

    let leave = membership_request(&join.authority_commit, alice.clone(), &alice, "leave");
    uow.commit_event(leave).await.unwrap();
    assert!(
        !store
            .realm_fanout_still_owed(event, &local, &member_station(), &basis, now)
            .await
            .unwrap(),
        "every frozen basis is gone once the member left"
    );
}

/// A member Station refuses a replica whose predecessor it does not hold, a
/// Commit forking its held head, and any replica once no member it hosts is
/// joined, each with zero writes.
#[tokio::test]
async fn committed_replication_rejects_broken_predecessor_and_no_local_member() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = bootstrap_unit_with_join_rule("replica-negative", "public");
    let last = unit.transactions.last().unwrap();
    let alice = remote_member("replica-negative-alice");
    let join = membership_request(last, alice.clone(), &alice, "join");
    let at = last.commit.committed_at;
    let profile = |previous: &AuthorityCommitTransaction, name: &str| {
        sourced(next_request(
            previous,
            arkret_wire::EventKind::RealmProfile,
            &founder(),
            serde_json::json!({ "name": name }),
            at,
        ))
    };
    // Nothing is held yet: only the hosted member's own join opens the stream.
    let first = profile(last, "Before join");
    assert_code(
        &store
            .install_committed_replica(&replica(&unit, &first, false))
            .await
            .unwrap_err(),
        ConflictCode::DependencyMissing,
    );
    store
        .install_committed_replica(&replica(&unit, &join, true))
        .await
        .unwrap();
    let next = profile(&join.authority_commit, "Next");
    let after = profile(&next.authority_commit, "After");
    assert_code(
        &store
            .install_committed_replica(&replica(&unit, &after, false))
            .await
            .unwrap_err(),
        ConflictCode::DependencyMissing,
    );
    let mut broken = next.clone();
    broken.authority_commit.commit.previous_commit_ref = last.commit.previous_commit_ref.clone();
    assert_code(
        &store
            .install_committed_replica(&replica(&unit, &broken, false))
            .await
            .unwrap_err(),
        ConflictCode::ForkQuarantine,
    );
    for refused in [&first, &after, &broken] {
        assert!(
            store
                .committed_event(&refused.authority_commit.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
    }
    store
        .install_committed_replica(&replica(&unit, &next, false))
        .await
        .unwrap();
    let leave = membership_request(&next.authority_commit, alice.clone(), &alice, "leave");
    store
        .install_committed_replica(&replica(&unit, &leave, false))
        .await
        .unwrap();
    let unowed = profile(&leave.authority_commit, "Unowed");
    assert_code(
        &store
            .install_committed_replica(&replica(&unit, &unowed, false))
            .await
            .unwrap_err(),
        ConflictCode::CapabilityDenied,
    );
}
