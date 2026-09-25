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

async fn assert_refused(
    pool: &PgPool,
    uow: &PgEventCommitUnitOfWork,
    request: EventCommitRequest,
    code: ConflictCode,
) {
    let outbox = outbox_count(pool).await;
    let error = uow.commit_event(request.clone()).await.unwrap_err();
    assert_code(&error, code);
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    assert!(
        store
            .committed_event(&request.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none(),
        "a refused membership Event is not committed"
    );
    assert_eq!(
        outbox_count(pool).await,
        outbox,
        "a refusal plans no fanout"
    );
}

/// Real PostgreSQL: only the listed FSM edges by their listed writers are
/// admitted -- self entry under an open join rule, self leave, and a kick or
/// ban by a joined member the same-cut evaluator admits for `ak.member.state`
/// (the root controller, or a holder of an active `ak.realm.admin` grant) --
/// and every refusal writes nothing.
#[tokio::test]
async fn member_state_join_leave_and_kick_follow_join_rule_and_capability() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let alice = remote_member("fsm-alice");
    let bob = remote_member("fsm-bob");

    // An invite-only Realm has no self entry.
    let invite = admit(&pool, "fsm-invite", "invite").await;
    let last = invite.transactions.last().unwrap();
    assert_refused(
        &pool,
        &uow,
        membership_request(last, alice.clone(), &alice, "join"),
        ConflictCode::GateCheckFailed,
    )
    .await;
    assert_refused(
        &pool,
        &uow,
        membership_request(last, alice.clone(), &alice, "knock"),
        ConflictCode::GateCheckFailed,
    )
    .await;

    let public = admit(&pool, "fsm-public", "public").await;
    let last = public.transactions.last().unwrap();
    // Even the Realm root controller cannot enter someone else.
    assert_refused(
        &pool,
        &uow,
        membership_request(last, founder_actor(), &alice, "join"),
        ConflictCode::CapabilityDenied,
    )
    .await;
    let alice_join = membership_request(last, alice.clone(), &alice, "join");
    uow.commit_event(alice_join.clone()).await.unwrap();
    // `join -> join` is not an edge.
    assert_refused(
        &pool,
        &uow,
        membership_request(&alice_join.authority_commit, alice.clone(), &alice, "join"),
        ConflictCode::FailedPrecondition,
    )
    .await;
    let bob_join = membership_request(&alice_join.authority_commit, bob.clone(), &bob, "join");
    uow.commit_event(bob_join.clone()).await.unwrap();
    // A member without `ak.realm.admin` cannot ban or remove another.
    assert_refused(
        &pool,
        &uow,
        membership_request(&bob_join.authority_commit, alice.clone(), &bob, "ban"),
        ConflictCode::CapabilityDenied,
    )
    .await;
    assert_refused(
        &pool,
        &uow,
        membership_request(&bob_join.authority_commit, alice.clone(), &bob, "leave"),
        ConflictCode::CapabilityDenied,
    )
    .await;
    // The root controller holds every action and bans Bob.
    let ban = membership_request(&bob_join.authority_commit, founder_actor(), &bob, "ban");
    uow.commit_event(ban.clone()).await.unwrap();
    let realm_id = public.transactions[0].event.realm_id.clone();
    assert_eq!(
        member_state(&pool, &realm_id, &bob).await.as_deref(),
        Some("ban")
    );
    // Bob cannot lift his own ban, and a banned member cannot rejoin.
    assert_refused(
        &pool,
        &uow,
        membership_request(&ban.authority_commit, bob.clone(), &bob, "leave"),
        ConflictCode::CapabilityDenied,
    )
    .await;
    assert_refused(
        &pool,
        &uow,
        membership_request(&ban.authority_commit, bob.clone(), &bob, "join"),
        ConflictCode::FailedPrecondition,
    )
    .await;

    // A grant of `ak.realm.admin` from the root lets Alice remove Carol; once
    // the root revokes it, the same Alice is refused at the next cut.
    let carol = remote_member("fsm-carol");
    let carol_join = membership_request(&ban.authority_commit, carol.clone(), &carol, "join");
    uow.commit_event(carol_join.clone()).await.unwrap();
    let root_event_ref = realm_root_event_ref(&pool, &realm_id).await;
    let admin_grant = grant_request(
        &carol_join.authority_commit,
        &alice,
        &["ak.realm.admin"],
        &root_event_ref,
    );
    uow.commit_event(admin_grant.clone()).await.unwrap();
    let kick = membership_request(
        &admin_grant.authority_commit,
        alice.clone(),
        &carol,
        "leave",
    );
    uow.commit_event(kick.clone()).await.unwrap();
    assert_eq!(
        member_state(&pool, &realm_id, &carol).await.as_deref(),
        Some("leave")
    );
    let revoke = sourced(next_request_for_actor(
        &kick.authority_commit,
        arkret_wire::EventKind::CapabilityRevoke,
        founder_actor(),
        serde_json::json!({
            "grant_id": arkret_wire::GrantId::from_event_id(
                &admin_grant.authority_commit.event.event_id
            ),
            "expected_revision": {
                "commit_id": admin_grant.authority_commit.commit.commit_id,
                "stream_position": admin_grant.authority_commit.commit.stream_position,
            },
        }),
        kick.authority_commit.commit.committed_at,
    ));
    uow.commit_event(revoke.clone()).await.unwrap();
    assert_refused(
        &pool,
        &uow,
        membership_request(&revoke.authority_commit, alice.clone(), &carol, "ban"),
        ConflictCode::CapabilityDenied,
    )
    .await;
    // Alice leaves by her own Event, and a member who left holds no
    // administration even with the Realm's grants restored.
    let alice_leave = membership_request(&revoke.authority_commit, alice.clone(), &alice, "leave");
    uow.commit_event(alice_leave.clone()).await.unwrap();
    assert_eq!(
        member_state(&pool, &realm_id, &alice).await.as_deref(),
        Some("leave")
    );
    // A distinct grant body: the first grant's exact Event is already committed.
    let regrant = grant_request(
        &alice_leave.authority_commit,
        &alice,
        &["ak.realm.admin", "ak.message.create"],
        &root_event_ref,
    );
    uow.commit_event(regrant.clone()).await.unwrap();
    assert_refused(
        &pool,
        &uow,
        membership_request(&regrant.authority_commit, alice.clone(), &carol, "ban"),
        ConflictCode::CapabilityDenied,
    )
    .await;
}

async fn realm_root_event_ref(pool: &PgPool, realm_id: &arkret_wire::RealmId) -> String {
    #[derive(diesel::QueryableByName)]
    struct RootRow {
        #[diesel(sql_type = Text)]
        authority_event_ref: String,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT authority_event_ref FROM realm_authority_root_current_results WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<RootRow>(&mut *conn)
    .await
    .unwrap()
    .authority_event_ref
}

/// The root controller's grant of `actions` over the whole Realm to
/// `subject`, sequenced after `previous`.
fn grant_request(
    previous: &AuthorityCommitTransaction,
    subject: &arkret_wire::ActorId,
    actions: &[&str],
    root_event_ref: &str,
) -> EventCommitRequest {
    let realm_id = previous.event.realm_id.clone();
    let at = previous.commit.committed_at;
    sourced(next_request_for_actor(
        previous,
        arkret_wire::EventKind::CapabilityGrant,
        founder_actor(),
        serde_json::json!({
            "grant": {
                "schema": "ak.schema.capability.v1",
                "realm_id": realm_id,
                "issuer_id": founder_actor(),
                "subject": subject,
                "actions": actions,
                "resources": [{"kind": "realm", "realm_id": realm_id}],
                "issuer_authority_refs": [{
                    "kind": "realm_root",
                    "realm_id": realm_id,
                    "authority_event_ref": root_event_ref,
                    "authority_generation": 0
                }],
                "issued_at": arkret_canonical::format_timestamp_canonical(at),
            }
        }),
        at,
    ))
}

#[derive(Debug, PartialEq, Eq)]
struct AcceptState {
    events: i64,
    lifecycle: Vec<(String, serde_json::Value, String)>,
    live_target: Vec<(String, serde_json::Value, String)>,
    members: Vec<(String, serde_json::Value, String)>,
}

/// Every row an `ak.invite.accept` may write, with its covering Commit.
async fn accept_state(pool: &PgPool, realm_id: &arkret_wire::RealmId) -> AcceptState {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Text)]
        subject: String,
        #[diesel(sql_type = Jsonb)]
        value: serde_json::Value,
        #[diesel(sql_type = Text)]
        current_commit_id: String,
    }
    let mut conn = pool.get().await.unwrap();
    let events =
        diesel::sql_query("SELECT count(*) AS count FROM canonical_events WHERE realm_id=$1")
            .bind::<Text, _>(realm_id.as_str())
            .get_result::<CountRow>(&mut *conn)
            .await
            .unwrap()
            .count;
    let mut families = Vec::new();
    for sql in [
        "SELECT invite_id AS subject, value, current_commit_id \
         FROM invite_lifecycle_current_results WHERE realm_id=$1 ORDER BY invite_id",
        "SELECT invitee_account_id AS subject, value, current_commit_id \
         FROM invite_live_target_current_results WHERE realm_id=$1 ORDER BY invitee_account_id",
        "SELECT member_id AS subject, value, current_commit_id \
         FROM member_state_current_results WHERE realm_id=$1 ORDER BY member_id",
    ] {
        families.push(
            diesel::sql_query(sql)
                .bind::<Text, _>(realm_id.as_str())
                .load::<Row>(&mut *conn)
                .await
                .unwrap()
                .into_iter()
                .map(|row| (row.subject, row.value, row.current_commit_id))
                .collect::<Vec<_>>(),
        );
    }
    let members = families.pop().unwrap();
    let live_target = families.pop().unwrap();
    let lifecycle = families.pop().unwrap();
    AcceptState {
        events,
        lifecycle,
        live_target,
        members,
    }
}

fn invite_create_request(
    previous: &AuthorityCommitTransaction,
    invitee: &arkret_wire::AccountId,
) -> EventCommitRequest {
    let at = previous.commit.committed_at;
    sourced(next_request_for_actor(
        previous,
        arkret_wire::EventKind::InviteCreate,
        founder_actor(),
        serde_json::json!({
            "invitee_account_id": invitee,
            "introduction_evidence_digest": format!("sha256:{}", "a".repeat(64)),
            "expires_at": arkret_canonical::format_timestamp_canonical(
                at + chrono::TimeDelta::days(7)
            ),
        }),
        at,
    ))
}

/// An `ak.invite.accept` by `actor` of the Invite `create` opened, created
/// `offset_ms` after the head it extends so that retries are distinct Events.
fn accept_request(
    previous: &AuthorityCommitTransaction,
    actor: &arkret_wire::ActorId,
    create: &EventCommitRequest,
    previous_state: &str,
    invitee: Option<&arkret_wire::AccountId>,
    offset_ms: i64,
) -> EventCommitRequest {
    let mut payload = serde_json::json!({
        "invite_id": arkret_wire::InviteId::from_event_id(&create.authority_commit.event.event_id),
        "previous_state": previous_state,
    });
    if let Some(invitee) = invitee {
        payload["invitee_account_id"] = serde_json::to_value(invitee).unwrap();
    }
    sourced(next_request_for_actor(
        previous,
        arkret_wire::EventKind::InviteAccept,
        actor.clone(),
        payload,
        previous.commit.committed_at + chrono::TimeDelta::milliseconds(offset_ms),
    ))
}

async fn assert_accept_refused(
    pool: &PgPool,
    uow: &PgEventCommitUnitOfWork,
    request: EventCommitRequest,
    code: ConflictCode,
) {
    let realm_id = request.authority_commit.event.realm_id.clone();
    let before = accept_state(pool, &realm_id).await;
    assert_refused(pool, uow, request, code).await;
    assert_eq!(accept_state(pool, &realm_id).await, before);
}

/// Real PostgreSQL: the directed invitee's `ak.invite.accept` moves the Invite
/// `pending -> accepted`, releases its live-target slot and moves its own
/// member row `leave -> join`, all on the accepting Commit. Another actor, a
/// payload invitee other than the stored one, a stale `previous_state` and a
/// second accept of the terminal Invite are refused with zero writes; after
/// leaving, the same account joins again through a fresh Invite.
#[tokio::test]
async fn invite_accept_joins_member_atomically_and_second_accept_is_rejected() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let unit = admit(&pool, "accept-invite", "invite").await;
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let bob = remote_member("accept-bob");
    let bob_account = bob.as_account_id().unwrap().clone();
    let carol = remote_member("accept-carol");
    let carol_account = carol.as_account_id().unwrap().clone();

    let create = invite_create_request(unit.transactions.last().unwrap(), &bob_account);
    uow.commit_event(create.clone()).await.unwrap();
    let head = &create.authority_commit;
    for (request, code) in [
        // Only the invitee accepts, even with the invitee's exact payload.
        (
            accept_request(head, &carol, &create, "pending", Some(&bob_account), 1),
            ConflictCode::FailedPrecondition,
        ),
        // The payload invitee must match the stored one in both directions.
        (
            accept_request(head, &carol, &create, "pending", Some(&carol_account), 2),
            ConflictCode::InviteDirectedInviteeMismatch,
        ),
        (
            accept_request(head, &bob, &create, "pending", None, 3),
            ConflictCode::InviteDirectedInviteeMismatch,
        ),
        // The declared pre-state is compared with the frozen register.
        (
            accept_request(head, &bob, &create, "claimed", Some(&bob_account), 4),
            ConflictCode::FailedPrecondition,
        ),
    ] {
        assert_accept_refused(&pool, &uow, request, code).await;
    }
    assert_eq!(member_state(&pool, &realm_id, &bob).await, None);

    let accept = accept_request(head, &bob, &create, "pending", Some(&bob_account), 5);
    uow.commit_event(accept.clone()).await.unwrap();
    let accept_commit = accept.authority_commit.commit.commit_id.to_string();
    let invite_id = arkret_wire::InviteId::from_event_id(&create.authority_commit.event.event_id);
    let state = accept_state(&pool, &realm_id).await;
    assert_eq!(
        state.lifecycle,
        vec![(
            invite_id.to_string(),
            serde_json::json!("accepted"),
            accept_commit.clone()
        )]
    );
    assert_eq!(
        state.live_target,
        vec![(
            String::from_utf8(arkret_canonical::canonical_json_bytes(&bob_account).unwrap())
                .unwrap(),
            serde_json::Value::Null,
            accept_commit.clone()
        )]
    );
    assert!(state.members.contains(&(
        bob.to_string(),
        serde_json::json!({"membership": "join"}),
        accept_commit.clone()
    )));

    // `accepted` is terminal: a second accept is refused before any write.
    assert_accept_refused(
        &pool,
        &uow,
        accept_request(
            &accept.authority_commit,
            &bob,
            &create,
            "pending",
            Some(&bob_account),
            6,
        ),
        ConflictCode::InviteAlreadyTerminal,
    )
    .await;

    // After leaving, Bob returns only through a fresh Invite.
    let leave = membership_request(&accept.authority_commit, bob.clone(), &bob, "leave");
    uow.commit_event(leave.clone()).await.unwrap();
    let reinvite = invite_create_request(&leave.authority_commit, &bob_account);
    uow.commit_event(reinvite.clone()).await.unwrap();
    let rejoin = accept_request(
        &reinvite.authority_commit,
        &bob,
        &reinvite,
        "pending",
        Some(&bob_account),
        7,
    );
    uow.commit_event(rejoin.clone()).await.unwrap();
    assert_eq!(
        member_state(&pool, &realm_id, &bob).await.as_deref(),
        Some("join")
    );
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

fn scan_request(
    realm_id: &arkret_wire::RealmId,
    direction: arkret_wire::StreamScanDirection,
    limit: u16,
) -> arkret_wire::StreamScanRequest {
    arkret_wire::StreamScanRequest {
        realm_id: realm_id.clone(),
        stream_ref: arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
        direction,
        limit,
    }
}

async fn scanned(
    store: &PgAuthorityCommitStore,
    request: arkret_wire::StreamScanRequest,
    account: &arkret_wire::ActorId,
) -> soland_storage::AccountStreamScan {
    store
        .scan_stream_for_account(
            &request,
            account.as_account_id().unwrap(),
            &arkret_wire::DidCoreId::new(STATION).unwrap(),
        )
        .await
        .unwrap()
}

fn page(scan: soland_storage::AccountStreamScan) -> arkret_wire::StreamScanOutcome {
    match scan {
        soland_storage::AccountStreamScan::Page(page) => page,
        other => panic!("expected a proved page, got {other:?}"),
    }
}

/// Each row's position and whether its Event is disclosed in full.
fn rows(page: &arkret_wire::StreamScanOutcome) -> Vec<(u64, bool)> {
    page.committed_events
        .iter()
        .map(|item| {
            (
                item.commit().stream_position,
                matches!(item, arkret_wire::CommittedEventView::Full(_)),
            )
        })
        .collect()
}

/// Real PostgreSQL: under `since_join` a second member's readable interval
/// starts at its own join Commit (`membership_join`, decision 0108 §1045),
/// with the founder still reading from genesis (`stream_start`); pages stop
/// at the floor without truncation, other members' Events of kinds not
/// disclosed to every member are withheld on their Commit, the stream list
/// names the same floor, a member who left reads nothing and a rejoin moves
/// the floor to the new join.
#[tokio::test]
async fn account_stream_scan_serves_joined_member_from_its_join_commit() {
    use arkret_wire::StreamScanDirection::{After, Before};

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let unit = admit(&pool, "scan-joined-member", "public").await;
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let last = unit.transactions.last().unwrap();
    let at = last.commit.committed_at;
    let bob = remote_member("scan-bob");

    let strand = sourced(next_request(
        last,
        arkret_wire::EventKind::StrandCreate,
        &founder(),
        serde_json::json!({"object": {
            "schema":"ak.schema.strand.v1",
            "realm_id":realm_id,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Scan discussion"},
            "state":"active",
            "created_by":founder_actor(),
            "created_at":at,
        }}),
        at,
    ));
    uow.commit_event(strand.clone()).await.unwrap();
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
    let join = membership_request(&default.authority_commit, bob.clone(), &bob, "join");
    uow.commit_event(join.clone()).await.unwrap();
    // A joined member without a grant cannot write a Message.
    assert_refused(
        &pool,
        &uow,
        sourced(next_request_for_actor(
            &join.authority_commit,
            arkret_wire::EventKind::MessageCreate,
            bob.clone(),
            message_payload(&strand_id, "not yet"),
            at,
        )),
        ConflictCode::CapabilityDenied,
    )
    .await;
    let root_event_ref = realm_root_event_ref(&pool, &realm_id).await;
    let grant = grant_request(
        &join.authority_commit,
        &bob,
        &["ak.message.create"],
        &root_event_ref,
    );
    uow.commit_event(grant.clone()).await.unwrap();
    let bob_message = sourced(next_request_for_actor(
        &grant.authority_commit,
        arkret_wire::EventKind::MessageCreate,
        bob.clone(),
        message_payload(&strand_id, "hello from the second member"),
        at,
    ));
    uow.commit_event(bob_message.clone()).await.unwrap();
    let founder_message = sourced(next_request(
        &bob_message.authority_commit,
        arkret_wire::EventKind::MessageCreate,
        &founder(),
        message_payload(&strand_id, "welcome"),
        at,
    ));
    uow.commit_event(founder_message.clone()).await.unwrap();

    let join_position = join.authority_commit.commit.stream_position;
    let floor = arkret_wire::ReadableFloor {
        oldest_position: join_position,
        floor_commit_id: join.authority_commit.commit.commit_id.clone(),
        floor_reason: arkret_wire::ReadableFloorReason::MembershipJoin,
    };
    let forward = page(scanned(&store, scan_request(&realm_id, After(None), 10), &bob).await);
    assert_eq!(forward.readable_floor.as_ref(), Some(&floor));
    assert!(!forward.truncated);
    assert_eq!(
        rows(&forward),
        vec![
            (join_position, true),
            (join_position + 1, false),
            (join_position + 2, true),
            (join_position + 3, true),
        ],
        "own join and Message and the founder's Message in full; the grant withheld"
    );
    // A cursor below the floor still starts at the floor.
    let below = page(scanned(&store, scan_request(&realm_id, After(Some(2)), 1), &bob).await);
    assert_eq!(rows(&below), vec![(join_position, true)]);
    assert!(below.truncated);
    // Backfill stops at the floor without reporting truncation.
    let backfill = page(
        scanned(
            &store,
            scan_request(&realm_id, Before(Some(join_position + 1)), 5),
            &bob,
        )
        .await,
    );
    assert_eq!(rows(&backfill), vec![(join_position, true)]);
    assert!(!backfill.truncated);
    assert_eq!(backfill.readable_floor.as_ref(), Some(&floor));
    let newest = page(scanned(&store, scan_request(&realm_id, Before(None), 2), &bob).await);
    assert_eq!(
        rows(&newest),
        vec![(join_position + 3, true), (join_position + 2, true)]
    );
    assert!(newest.truncated);

    // The founder's interval still starts at the genesis Commit.
    let founder_page = page(
        scanned(
            &store,
            scan_request(&realm_id, After(None), 50),
            &founder_actor(),
        )
        .await,
    );
    assert_eq!(
        founder_page
            .readable_floor
            .as_ref()
            .map(|floor| (floor.oldest_position, floor.floor_reason)),
        Some((0, arkret_wire::ReadableFloorReason::StreamStart))
    );
    assert_eq!(
        founder_page.committed_events.len() as u64,
        join_position + 4
    );
    assert!(rows(&founder_page).iter().all(|(_, full)| *full));

    // The stream list names the same floor.
    let listed = store
        .list_realm_streams_for_account(
            &realm_id,
            bob.as_account_id().unwrap(),
            &arkret_wire::DidCoreId::new(STATION).unwrap(),
        )
        .await
        .unwrap();
    let soland_storage::AccountRealmStreamList::Listed(streams) = listed else {
        panic!("a joined member's stream list is proved, got {listed:?}");
    };
    assert_eq!(streams.len(), 1);
    assert_eq!(streams[0].readable_floor.as_ref(), Some(&floor));

    // A member who left has no readable interval; a rejoin reads only from
    // the new join.
    let leave = membership_request(
        &founder_message.authority_commit,
        bob.clone(),
        &bob,
        "leave",
    );
    uow.commit_event(leave.clone()).await.unwrap();
    assert_eq!(
        scanned(&store, scan_request(&realm_id, After(None), 10), &bob).await,
        soland_storage::AccountStreamScan::NotAuthorized
    );
    let rejoin = membership_request(&leave.authority_commit, bob.clone(), &bob, "join");
    uow.commit_event(rejoin.clone()).await.unwrap();
    let rejoined = page(scanned(&store, scan_request(&realm_id, After(None), 10), &bob).await);
    assert_eq!(
        rejoined.readable_floor,
        Some(arkret_wire::ReadableFloor {
            oldest_position: rejoin.authority_commit.commit.stream_position,
            floor_commit_id: rejoin.authority_commit.commit.commit_id.clone(),
            floor_reason: arkret_wire::ReadableFloorReason::MembershipJoin,
        })
    );
    assert_eq!(
        rows(&rejoined),
        vec![(rejoin.authority_commit.commit.stream_position, true)]
    );
}
