//! `ak.strand.update` advances its target value at the accepted RealmCommit cut.
//! Every rejected update leaves the Event, Commit and current value untouched.

#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel_async::RunQueryDsl;
use ordinary_realm::{founder, next_request, open_discussion};
use serde_json::{Value, json};
use soland_storage::{AuthorityCommitStore, EventCommitUnitOfWork};
use soland_storage_postgres::PgEventCommitUnitOfWork;
use soland_storage_postgres::test_database::TestDatabase;

#[derive(diesel::QueryableByName, Debug, PartialEq)]
struct Current {
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct Count {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

async fn current(
    pool: &soland_storage_postgres::PgPool,
    strand_id: &arkret_wire::StrandId,
) -> Current {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT current_commit_id,current_stream_position,value \
         FROM strand_current_results WHERE strand_id=$1",
    )
    .bind::<Text, _>(strand_id.as_str())
    .get_result(&mut conn)
    .await
    .unwrap()
}

async fn realm_counts(
    pool: &soland_storage_postgres::PgPool,
    realm_id: &arkret_wire::RealmId,
) -> (i64, i64) {
    let mut conn = pool.get().await.unwrap();
    let events: Count =
        diesel::sql_query("SELECT COUNT(*) AS count FROM canonical_events WHERE realm_id=$1")
            .bind::<Text, _>(realm_id.as_str())
            .get_result(&mut conn)
            .await
            .unwrap();
    let commits: Count =
        diesel::sql_query("SELECT COUNT(*) AS count FROM realm_commits WHERE realm_id=$1")
            .bind::<Text, _>(realm_id.as_str())
            .get_result(&mut conn)
            .await
            .unwrap();
    (events.count, commits.count)
}

fn digest(value: &Value) -> String {
    arkret_canonical::sha256_digest(arkret_canonical::canonical_json_bytes(value).unwrap())
}

#[tokio::test]
async fn strand_update_current_cas_and_rejection_are_one_pg_cut() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let discussion = open_discussion(&pool, "strand-update-current-cas").await;
    let realm_id = discussion.head.authority_commit.event.realm_id.clone();
    let at = discussion.head.authority_commit.commit.committed_at;
    let before = current(&pool, &discussion.strand_id).await;
    let baseline = realm_counts(&pool, &realm_id).await;

    let accepted = next_request(
        &discussion.head.authority_commit,
        arkret_wire::EventKind::StrandUpdate,
        &founder(),
        json!({
            "target_ref": discussion.strand_id,
            "expected_state_digest": digest(&before.value),
            "patch": {"metadata.title": {"$op":"set", "value":"Accepted title"}},
        }),
        at,
    );
    let outcome = uow.commit_event(accepted.clone()).await.unwrap();
    assert!(outcome.event_inserted);
    let after = current(&pool, &discussion.strand_id).await;
    assert_eq!(after.value["metadata"]["title"], "Accepted title");
    let store = soland_storage_postgres::PgAuthorityCommitStore { pool: pool.clone() };
    let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        founder(),
        ordinary_realm::station(),
    ));
    let (_, list) = store
        .object_projection_lists_for_actor(&realm_id, &actor, false)
        .await
        .unwrap()
        .unwrap();
    let listed = list
        .strands
        .iter()
        .find(|row| row.strand_id == discussion.strand_id)
        .unwrap();
    assert_eq!(listed.title.as_deref(), Some("Accepted title"));
    assert!(listed.is_default);
    let outsider = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:read-outsider.example").unwrap(),
        ordinary_realm::station(),
    ));
    assert!(
        store
            .object_projection_lists_for_actor(&realm_id, &outsider, false)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        after.current_commit_id,
        accepted.authority_commit.commit.commit_id.as_str()
    );
    assert_eq!(
        after.current_stream_position,
        accepted.authority_commit.commit.stream_position as i64
    );
    assert_eq!(
        realm_counts(&pool, &realm_id).await,
        (baseline.0 + 1, baseline.1 + 1)
    );

    // Updating the already disclosed Strand family must keep member bootstrap
    // available, with the accepted value and its exact current revision.
    let account = arkret_wire::AccountId::new(founder(), ordinary_realm::station());
    let snapshot = soland_storage_postgres::account_snapshot_material(&pool, &realm_id, &account)
        .await
        .unwrap()
        .unwrap();
    assert!(snapshot.current_state_entries.iter().any(|entry| matches!(
        entry,
        arkret_wire::TypedCurrentResult::Value { selector: arkret_wire::CurrentSelector::Strand { strand_id }, revision, value, .. }
            if strand_id == &discussion.strand_id
                && revision.commit_id.as_str() == after.current_commit_id
                && revision.stream_position == after.current_stream_position as u64
                && value == &after.value
    )));

    let duplicate = uow.commit_event(accepted.clone()).await.unwrap();
    assert!(!duplicate.event_inserted);
    assert_eq!(current(&pool, &discussion.strand_id).await, after);
    assert_eq!(
        realm_counts(&pool, &realm_id).await,
        (baseline.0 + 1, baseline.1 + 1)
    );

    let head = &accepted.authority_commit;
    let stale = next_request(
        head,
        arkret_wire::EventKind::StrandUpdate,
        &founder(),
        json!({
            "target_ref": discussion.strand_id,
            "expected_state_digest": digest(&before.value),
            "patch": {"metadata.title": {"$op":"set", "value":"Stale title"}},
        }),
        at,
    );
    let unknown = next_request(
        head,
        arkret_wire::EventKind::StrandUpdate,
        &founder(),
        json!({
            "target_ref": arkret_wire::StrandId::from_event_id(&accepted.authority_commit.event.event_id),
            "patch": {"metadata.title": {"$op":"set", "value":"Unknown title"}},
        }),
        at,
    );
    let forbidden = next_request(
        head,
        arkret_wire::EventKind::StrandUpdate,
        &founder(),
        json!({
            "target_ref": discussion.strand_id,
            "patch": {"stage": {"$op":"set", "value":"done"}},
        }),
        at,
    );
    let not_joined = next_request(
        head,
        arkret_wire::EventKind::StrandUpdate,
        &arkret_wire::DidCoreId::new("ak:did_core:web:strand-update-outsider.example").unwrap(),
        json!({
            "target_ref": discussion.strand_id,
            "patch": {"metadata.title": {"$op":"set", "value":"Unauthorized title"}},
        }),
        at,
    );
    for (request, reason) in [
        (stale, "expected_state_digest"),
        (unknown, "target is absent"),
        (forbidden, "forbidden"),
        (not_joined, "capability_denied"),
    ] {
        let error = uow.commit_event(request).await.unwrap_err().to_string();
        assert!(error.contains(reason), "{error}");
        assert_eq!(current(&pool, &discussion.strand_id).await, after);
        assert_eq!(
            realm_counts(&pool, &realm_id).await,
            (baseline.0 + 1, baseline.1 + 1)
        );
    }
}

#[tokio::test]
async fn strand_update_calendar_profile_requires_ref_and_subtree_together() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let discussion = open_discussion(&pool, "strand-update-calendar-pair").await;
    let realm_id = discussion.head.authority_commit.event.realm_id.clone();
    let at = discussion.head.authority_commit.commit.committed_at;
    let schedule = json!({
        "start": "2026-06-22",
        "end": "2026-06-23",
        "timezone": "UTC",
        "tzdb_version": "2025b",
        "all_day": true,
        "status": "confirmed"
    });
    let accepted = next_request(
        &discussion.head.authority_commit,
        arkret_wire::EventKind::StrandUpdate,
        &founder(),
        json!({
            "target_ref": discussion.strand_id,
            "patch": {
                "schema_refs": {"$op":"set", "value":["ak.schema.calendar_event.v1"]},
                "metadata.fields.calendar": {"$op":"set", "value":schedule},
            },
        }),
        at,
    );
    uow.commit_event(accepted.clone()).await.unwrap();
    let confirmed = current(&pool, &discussion.strand_id).await;
    assert_eq!(
        confirmed.value["schema_refs"],
        json!(["ak.schema.calendar_event.v1"])
    );
    assert_eq!(confirmed.value["metadata"]["fields"]["calendar"], schedule);
    let counts = realm_counts(&pool, &realm_id).await;

    let unpaired = next_request(
        &accepted.authority_commit,
        arkret_wire::EventKind::StrandUpdate,
        &founder(),
        json!({
            "target_ref": discussion.strand_id,
            "patch": {"schema_refs": {"$op":"unset"}},
        }),
        at,
    );
    let error = uow.commit_event(unpaired).await.unwrap_err().to_string();
    assert!(error.contains("calendar_activation_mismatch"), "{error}");
    assert_eq!(current(&pool, &discussion.strand_id).await, confirmed);
    assert_eq!(realm_counts(&pool, &realm_id).await, counts);
}
