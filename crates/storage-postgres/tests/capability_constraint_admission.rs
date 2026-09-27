//! Capability Grant constraints at the accepting transaction on real
//! PostgreSQL (`authz/constraint-schema.md` §8.1, §15.4, §16;
//! `authz/capabilities.md` §3.2; `models/realm-and-space.md` §2.6.0).
//!
//! * A hard rate quota a grant carries is reserved with the Event it admits: the Event over the
//!   quota is refused with zero writes, and an exact retry of an admitted Event counts once.
//! * A `deny` constraint of any effective grant refuses the Event even when another grant alone
//!   would allow it.
//! * A temporal recurrence outside its window leaves the grant unsatisfied.
//! * An archived Realm admits only its exemption set.
//! * The Realm authority row lock is the cut's dependency lock: a revocation committed while an
//!   admission waits for that lock is observed by it.

#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use diesel::sql_types::{BigInt, Text};
use diesel_async::{RunQueryDsl, SimpleAsyncConnection};
use ordinary_realm::{
    STATION, bootstrap_unit_with_join_rule, founder, message_payload, next_request,
};
use soland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, ConflictCode, EventCommitRequest,
    EventCommitUnitOfWork,
};
use soland_storage_postgres::test_database::TestDatabase;
use soland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgPool};

fn local(label: &str) -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(format!("ak:did_core:web:{label}.example")).unwrap(),
        arkret_wire::DidCoreId::new(STATION).unwrap(),
    ))
}

fn founder_actor() -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        founder(),
        arkret_wire::DidCoreId::new(STATION).unwrap(),
    ))
}

fn by(
    previous: &AuthorityCommitTransaction,
    kind: arkret_wire::EventKind,
    actor: &arkret_wire::ActorId,
    payload: serde_json::Value,
) -> EventCommitRequest {
    ordinary_realm::next_request_for_actor(
        previous,
        kind,
        actor.clone(),
        payload,
        previous.commit.committed_at,
    )
}

/// An open Realm with an active default discussion Strand and a joined
/// `member`.
struct Discussion {
    realm_id: arkret_wire::RealmId,
    strand_id: arkret_wire::StrandId,
    root_event_ref: String,
    head: EventCommitRequest,
}

async fn discussion(pool: &PgPool, seed: &str, member: &arkret_wire::ActorId) -> Discussion {
    let unit = bootstrap_unit_with_join_rule(seed, "public");
    unit.validate().unwrap();
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .expect("admit ordinary Realm bootstrap");
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let last = unit.transactions.last().unwrap();
    let at = last.commit.committed_at;
    let realm_id = last.event.realm_id.clone();
    let strand = next_request(
        last,
        arkret_wire::EventKind::StrandCreate,
        &founder(),
        serde_json::json!({"object": {
            "schema":"ak.schema.strand.v1",
            "realm_id":realm_id,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Constraint discussion"},
            "state":"active",
            "created_by":founder_actor(),
            "created_at":at,
        }}),
        at,
    );
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let default = next_request(
        &strand.authority_commit,
        arkret_wire::EventKind::RealmSetDefaultStrand,
        &founder(),
        serde_json::json!({
            "realm_id": realm_id,
            "strand_id": strand_id,
            "expected_default_strand_id": null,
        }),
        at,
    );
    uow.commit_event(default.clone()).await.unwrap();
    let join = by(
        &default.authority_commit,
        arkret_wire::EventKind::MemberState,
        member,
        serde_json::json!({
            "realm_id": realm_id,
            "member_id": member,
            "membership": "join",
            "reason": "fixture join",
        }),
    );
    uow.commit_event(join.clone()).await.unwrap();
    let root_event_ref = root_event_ref(pool, &realm_id).await;
    Discussion {
        realm_id,
        strand_id,
        root_event_ref,
        head: join,
    }
}

async fn root_event_ref(pool: &PgPool, realm_id: &arkret_wire::RealmId) -> String {
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
/// `subject` with `constraints`.
fn grant(
    discussion: &Discussion,
    previous: &AuthorityCommitTransaction,
    subject: &arkret_wire::ActorId,
    actions: &[&str],
    constraints: serde_json::Value,
) -> EventCommitRequest {
    let realm_id = &discussion.realm_id;
    let mut payload = serde_json::json!({
            "grant": {
                "schema": "ak.schema.capability.v1",
                "realm_id": realm_id,
                "issuer_id": founder_actor(),
                "subject": subject,
                "actions": actions,
                "resources": [{"kind": "realm", "realm_id": realm_id}],
                "constraints": constraints,
                "issuer_authority_refs": [{
                    "kind": "realm_root",
                    "realm_id": realm_id,
                    "authority_event_ref": discussion.root_event_ref,
                    "authority_generation": 0
                }],
                "issued_at": arkret_canonical::format_timestamp_canonical(
                    previous.commit.committed_at
                ),
            }
    });
    if constraints.as_array().is_some_and(Vec::is_empty) {
        payload["grant"]
            .as_object_mut()
            .unwrap()
            .remove("constraints");
    }
    by(
        previous,
        arkret_wire::EventKind::CapabilityGrant,
        &founder_actor(),
        payload,
    )
}

fn message(
    discussion: &Discussion,
    previous: &AuthorityCommitTransaction,
    author: &arkret_wire::ActorId,
    body: &str,
) -> EventCommitRequest {
    by(
        previous,
        arkret_wire::EventKind::MessageCreate,
        author,
        message_payload(&discussion.strand_id, body),
    )
}

async fn assert_refused(
    pool: &PgPool,
    uow: &PgEventCommitUnitOfWork,
    request: EventCommitRequest,
    code: ConflictCode,
) {
    let error = uow.commit_event(request.clone()).await.unwrap_err();
    assert_eq!(error.conflict_code(), Some(code), "{error}");
    assert!(
        PgAuthorityCommitStore { pool: pool.clone() }
            .committed_event(&request.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none(),
        "a refused Event is not committed"
    );
}

async fn quota_consumed(pool: &PgPool) -> i64 {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = BigInt)]
        consumed: i64,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT COALESCE(SUM(consumed),0)::bigint AS consumed FROM capability_quota_counters",
    )
    .get_result::<Row>(&mut *conn)
    .await
    .unwrap()
    .consumed
}

#[tokio::test]
async fn a_rate_quota_is_reserved_with_the_event_it_admits() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let alice = local("quota-alice");
    let discussion = discussion(&pool, "quota-realm", &alice).await;
    let quota = grant(
        &discussion,
        &discussion.head.authority_commit,
        &alice,
        &["ak.message.create"],
        serde_json::json!([{
            "constraint_kind": "quota",
            "constraint_subkind": "rate",
            "effect": "allow",
            "max_operations": 1,
            "period": "P1D",
            "constraint_scope": "per_realm"
        }]),
    );
    uow.commit_event(quota.clone()).await.unwrap();
    let first = message(&discussion, &quota.authority_commit, &alice, "first");
    uow.commit_event(first.clone()).await.unwrap();
    assert_eq!(quota_consumed(&pool).await, 1);
    // An exact retry of the admitted Event does not count again.
    uow.commit_event(first.clone()).await.unwrap();
    assert_eq!(quota_consumed(&pool).await, 1);
    assert_refused(
        &pool,
        &uow,
        message(&discussion, &first.authority_commit, &alice, "second"),
        ConflictCode::RateLimited,
    )
    .await;
    assert_eq!(quota_consumed(&pool).await, 1);
    // The root controller's owner aggregate owes no quota.
    uow.commit_event(message(
        &discussion,
        &first.authority_commit,
        &founder_actor(),
        "owner",
    ))
    .await
    .unwrap();
    assert_eq!(quota_consumed(&pool).await, 1);
}

#[tokio::test]
async fn a_deny_constraint_of_any_grant_refuses_and_recurrence_bounds_a_grant() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let alice = local("deny-alice");
    let discussion = discussion(&pool, "deny-realm", &alice).await;
    let open = grant(
        &discussion,
        &discussion.head.authority_commit,
        &alice,
        &["ak.message.create"],
        serde_json::json!([]),
    );
    uow.commit_event(open.clone()).await.unwrap();
    let hello = message(&discussion, &open.authority_commit, &alice, "hello");
    uow.commit_event(hello.clone()).await.unwrap();
    let denying = grant(
        &discussion,
        &hello.authority_commit,
        &alice,
        &["ak.message.create"],
        serde_json::json!([{
            "constraint_kind": "scope_limitation",
            "effect": "deny",
            "denied_strand_ids": [discussion.strand_id]
        }]),
    );
    uow.commit_event(denying.clone()).await.unwrap();
    assert_refused(
        &pool,
        &uow,
        message(&discussion, &denying.authority_commit, &alice, "denied"),
        ConflictCode::CapabilityDenied,
    )
    .await;

    // Bob's only grant is valid on a weekday hour the accepting commit is
    // not in: its window is never satisfied.
    let bob = local("deny-bob");
    let bob_join = by(
        &denying.authority_commit,
        arkret_wire::EventKind::MemberState,
        &bob,
        serde_json::json!({
            "realm_id": discussion.realm_id,
            "member_id": bob,
            "membership": "join",
            "reason": "fixture join",
        }),
    );
    uow.commit_event(bob_join.clone()).await.unwrap();
    let committed_at = bob_join.authority_commit.commit.committed_at;
    let closed_hour = (committed_at + chrono::TimeDelta::hours(12))
        .format("%H:00")
        .to_string();
    let closed_end = (committed_at + chrono::TimeDelta::hours(13))
        .format("%H:00")
        .to_string();
    let windowed = grant(
        &discussion,
        &bob_join.authority_commit,
        &bob,
        &["ak.message.create"],
        serde_json::json!([{
            "constraint_kind": "temporal",
            "constraint_subkind": "window",
            "effect": "allow",
            "recurrence": {
                "frequency": "daily",
                "window_start": closed_hour,
                "window_end": closed_end,
                "timezone": "UTC"
            }
        }]),
    );
    uow.commit_event(windowed.clone()).await.unwrap();
    assert_refused(
        &pool,
        &uow,
        message(&discussion, &windowed.authority_commit, &bob, "off hours"),
        ConflictCode::CapabilityDenied,
    )
    .await;
}

#[tokio::test]
async fn an_archived_realm_admits_only_its_exemption_set() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let alice = local("archive-alice");
    let discussion = discussion(&pool, "archive-realm", &alice).await;
    let admin = grant(
        &discussion,
        &discussion.head.authority_commit,
        &alice,
        &["ak.message.create"],
        serde_json::json!([]),
    );
    uow.commit_event(admin.clone()).await.unwrap();
    let archive = by(
        &admin.authority_commit,
        arkret_wire::EventKind::RealmArchive,
        &founder_actor(),
        serde_json::json!({"reason": "fixture archive"}),
    );
    uow.commit_event(archive.clone()).await.unwrap();
    assert_refused(
        &pool,
        &uow,
        message(&discussion, &archive.authority_commit, &alice, "archived"),
        ConflictCode::RealmFrozen,
    )
    .await;
    assert_refused(
        &pool,
        &uow,
        grant(
            &discussion,
            &archive.authority_commit,
            &alice,
            &["ak.realm.admin"],
            serde_json::json!([]),
        ),
        ConflictCode::RealmFrozen,
    )
    .await;
    // Revocation is in the exemption set.
    let revoke = by(
        &archive.authority_commit,
        arkret_wire::EventKind::CapabilityRevoke,
        &founder_actor(),
        serde_json::json!({
            "grant_id": arkret_wire::GrantId::from_event_id(&admin.authority_commit.event.event_id),
            "expected_revision": {
                "commit_id": admin.authority_commit.commit.commit_id,
                "stream_position": admin.authority_commit.commit.stream_position,
            },
        }),
    );
    uow.commit_event(revoke.clone()).await.unwrap();
    let restore = by(
        &revoke.authority_commit,
        arkret_wire::EventKind::RealmRestore,
        &founder_actor(),
        serde_json::json!({"reason": "fixture restore"}),
    );
    uow.commit_event(restore.clone()).await.unwrap();
    uow.commit_event(message(
        &discussion,
        &restore.authority_commit,
        &founder_actor(),
        "restored",
    ))
    .await
    .unwrap();
}

#[tokio::test]
async fn an_admission_waiting_on_the_realm_lock_observes_a_concurrent_revocation() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let alice = local("lock-alice");
    let discussion = discussion(&pool, "lock-realm", &alice).await;
    let writer = grant(
        &discussion,
        &discussion.head.authority_commit,
        &alice,
        &["ak.message.create"],
        serde_json::json!([]),
    );
    uow.commit_event(writer.clone()).await.unwrap();
    let grant_id = arkret_wire::GrantId::from_event_id(&writer.authority_commit.event.event_id);

    // A concurrent Realm-stream writer holds the authority row lock and
    // closes the grant inside its still-open transaction.
    let mut holder = pool.get().await.unwrap();
    holder.batch_execute("BEGIN").await.unwrap();
    diesel::sql_query("SELECT realm_id FROM realm_authorities WHERE realm_id=$1 FOR UPDATE")
        .bind::<Text, _>(discussion.realm_id.as_str())
        .execute(&mut *holder)
        .await
        .unwrap();
    diesel::sql_query(
        "UPDATE capability_grant_current_results \
         SET status='revoked',value=jsonb_set(value,'{status}','\"revoked\"') \
         WHERE realm_id=$1 AND grant_id=$2",
    )
    .bind::<Text, _>(discussion.realm_id.as_str())
    .bind::<Text, _>(grant_id.as_str())
    .execute(&mut *holder)
    .await
    .unwrap();

    let waiting = message(&discussion, &writer.authority_commit, &alice, "racing");
    let event_id = waiting.authority_commit.event.event_id.clone();
    let task_pool = pool.clone();
    let admission = tokio::spawn(async move {
        PgEventCommitUnitOfWork::new(task_pool)
            .commit_event(waiting)
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(
        !admission.is_finished(),
        "the admission waits for the Realm authority lock"
    );
    holder.batch_execute("COMMIT").await.unwrap();
    let error = admission.await.unwrap().unwrap_err();
    assert_eq!(
        error.conflict_code(),
        Some(ConflictCode::CapabilityDenied),
        "{error}"
    );
    assert!(
        PgAuthorityCommitStore { pool: pool.clone() }
            .committed_event(&event_id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn strand_patch_exact_resource_and_field_grant_are_decided_at_the_pg_cut() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let member = local("strand-field-editor");
    let discussion = discussion(&pool, "strand-field-grant-cut", &member).await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let mut permission = grant(
        &discussion,
        &discussion.head.authority_commit,
        &member,
        &["ak.strand.update"],
        serde_json::json!([{
            "constraint_kind":"field_access",
            "effect":"allow",
            "allowed_write_fields":["metadata.title"]
        }]),
    );
    permission
        .authority_commit
        .event
        .payload
        .get_mut("grant")
        .unwrap()["resources"] = serde_json::json!([arkret_wire::WireResourceSelector::strand(
        discussion.realm_id.clone(),
        discussion.strand_id.clone()
    )]);
    ordinary_realm::reseal(&mut permission.authority_commit.event);
    permission = ordinary_realm::request_for_event(
        &discussion.head.authority_commit,
        permission.authority_commit.event,
        discussion.head.authority_commit.commit.committed_at,
    );
    uow.commit_event(permission.clone()).await.unwrap();
    let allowed = by(
        &permission.authority_commit,
        arkret_wire::EventKind::StrandUpdate,
        &member,
        serde_json::json!({
            "target_ref": discussion.strand_id,
            "patch":{"metadata.title":{"$op":"set","value":"Authorized title"}}
        }),
    );
    uow.commit_event(allowed.clone()).await.unwrap();
    let before = PgAuthorityCommitStore { pool: pool.clone() }
        .realm_state_snapshot_material(&discussion.realm_id)
        .await
        .unwrap()
        .unwrap();
    for payload in [
        serde_json::json!({
            "target_ref":discussion.strand_id,
            "patch":{"metadata.summary":{"$op":"set","value":"Unpermitted field"}}
        }),
        serde_json::json!({
            "target_ref":arkret_wire::StrandId::from_event_id(&permission.authority_commit.event.event_id),
            "patch":{"metadata.title":{"$op":"set","value":"Unpermitted target"}}
        }),
    ] {
        let refused = by(
            &allowed.authority_commit,
            arkret_wire::EventKind::StrandUpdate,
            &member,
            payload,
        );
        #[derive(diesel::QueryableByName, Debug, PartialEq)]
        struct Counts {
            #[diesel(sql_type = BigInt)]
            events: i64,
            #[diesel(sql_type = BigInt)]
            commits: i64,
        }
        let mut conn = pool.get().await.unwrap();
        let query = "SELECT (SELECT COUNT(*) FROM canonical_events WHERE realm_id=$1) AS events, \
                     (SELECT COUNT(*) FROM realm_commits WHERE realm_id=$1) AS commits";
        let counts: Counts = diesel::sql_query(query)
            .bind::<Text, _>(discussion.realm_id.as_str())
            .get_result(&mut conn)
            .await
            .unwrap();
        assert_refused(&pool, &uow, refused, ConflictCode::CapabilityDenied).await;
        let after_counts: Counts = diesel::sql_query(query)
            .bind::<Text, _>(discussion.realm_id.as_str())
            .get_result(&mut conn)
            .await
            .unwrap();
        assert_eq!(counts, after_counts);
        assert_eq!(
            PgAuthorityCommitStore { pool: pool.clone() }
                .realm_state_snapshot_material(&discussion.realm_id)
                .await
                .unwrap()
                .unwrap(),
            before,
        );
    }
}
