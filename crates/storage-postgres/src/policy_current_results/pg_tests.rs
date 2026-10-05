//! Imported accepted-history fixtures exercise the real PostgreSQL CAS boundary.
use diesel::sql_types::{Binary, Nullable};
use serde_json::json;

use super::*;
use crate::test_database::TestDatabase;

fn realm() -> arkret_wire::RealmId {
    event(EventKind::RealmCreate, json!({}), 0).realm_id
}

fn policy(revision: Option<CurrentRevision>, agent: bool) -> PolicySetStatePayload {
    let mut value = json!({
        "policy_id":"ak:policy:0198ff00-0000-7000-8000-000000000001",
        "value": {
            "schema":"ak.schema.policy.v1", "id":"ak:policy:0198ff00-0000-7000-8000-000000000001",
            "realm_id":realm(), "policy_kind": if agent { "agent" } else { "access" },
            "rules":[{"rule_id":"allow", "kind":"action", "effect":"allow", "actions":["ak.message.create"]}],
            "default_effect":"allow", "created_by":{"kind":"account", "account_id":{
                "principal_id":"ak:did_core:web:controller.example", "station_id":"ak:did_core:web:station.example"
            }}, "created_at":"2026-10-05T12:00:00.000Z"
        }
    });
    if agent {
        value["expected_revision"] = json!(revision);
    }
    serde_json::from_value(value).unwrap()
}

fn event(kind: EventKind, payload: Value, position: u64) -> Event {
    arkret_wire::test_support::raw_event_at(
        kind.as_str(),
        if kind == EventKind::RealmCreate {
            arkret_wire::ScopeRef::RealmGenesis
        } else {
            arkret_wire::ScopeRef::Realm { realm_id: realm() }
        },
        "ak:did_core:web:controller.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
        payload,
        chrono::DateTime::parse_from_rfc3339("2026-10-05T12:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
            + chrono::TimeDelta::seconds(position as i64),
    )
    .unwrap()
}

fn commit(event: &Event, position: u64) -> RealmCommit {
    RealmCommit {
        producer_signer_fact_digest: None,
        commit_id: arkret_wire::RealmCommitId::from_digest([position as u8 + 80; 32]),
        realm_id: event.realm_id.clone(),
        stream_ref: CommitStreamRef::Realm {
            realm_id: event.realm_id.clone(),
        },
        stream_position: position,
        previous_commit_ref: position
            .checked_sub(1)
            .map(|p| arkret_wire::RealmCommitId::from_digest([p as u8 + 80; 32])),
        event_ref: event.event_id.clone(),
        governance_generation: 0,
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
            event.event_id.clone(),
        ),
        committed_at: event.created_at,
        signature: arkret_wire::DetachedObjectSignature {
            context: arkret_wire::DetachedSignatureContext::RealmCommit,
            signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
            verification_method: arkret_wire::DidUrl::new("did:web:station.example#authority")
                .unwrap(),
            signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "aa".repeat(32))).unwrap(),
            created_at: event.created_at,
            sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl").unwrap(),
        },
    }
}

fn revision(commit: &RealmCommit) -> CurrentRevision {
    CurrentRevision {
        commit_id: commit.commit_id.clone(),
        stream_position: commit.stream_position,
    }
}

async fn insert_history(conn: &mut AsyncPgConnection, event: &Event, commit: &RealmCommit) {
    sql_query("INSERT INTO canonical_events(id,digest_suite,digest,actor_id,realm_id,scope_ref,kind,canonical_bytes,envelope,state,committed_at) VALUES($1,1,$2,$3,$4,$5,$6,$7,$8,'committed',$9)")
        .bind::<Binary,_>(event.event_id.token_bytes().to_vec()).bind::<Binary,_>(event.event_id.digest_bytes().to_vec())
        .bind::<Text,_>(event.actor_id.to_string()).bind::<Text,_>(event.realm_id.as_str())
        .bind::<Jsonb,_>(json!(event.scope_ref)).bind::<Text,_>(event.kind.as_str())
        .bind::<Binary,_>(arkret_canonical::canonical_json_bytes(event).unwrap()).bind::<Jsonb,_>(json!(event))
        .bind::<Timestamptz,_>(commit.committed_at).execute(&mut *conn).await.unwrap();
    sql_query("INSERT INTO realm_commits(commit_id,realm_id,stream_key,stream_ref,stream_position,previous_commit_ref,event_pk,governance_generation,commit_json,committed_at) SELECT $1,$2,$3,$4,$5,$6,pk,0,$7,$8 FROM canonical_events WHERE id=$9")
        .bind::<Text,_>(commit.commit_id.as_str()).bind::<Text,_>(commit.realm_id.as_str())
        .bind::<Text,_>(arkret_canonical::canonical_json_string(&commit.stream_ref).unwrap())
        .bind::<Jsonb,_>(json!(commit.stream_ref)).bind::<BigInt,_>(commit.stream_position as i64)
        .bind::<Nullable<Text>,_>(commit.previous_commit_ref.as_ref().map(|id|id.as_str()))
        .bind::<Jsonb,_>(json!(commit)).bind::<Timestamptz,_>(commit.committed_at)
        .bind::<Binary,_>(event.event_id.token_bytes().to_vec()).execute(&mut *conn).await.unwrap();
}

async fn seed_genesis(conn: &mut AsyncPgConnection) {
    sql_query("INSERT INTO realm_authorities(realm_id,generation,service_id,authority_ref) VALUES($1,0,'ak:did_core:web:station.example','{}')")
        .bind::<Text,_>(realm().as_str()).execute(&mut *conn).await.unwrap();
    let genesis = event(EventKind::RealmCreate, json!({}), 0);
    insert_history(conn, &genesis, &commit(&genesis, 0)).await;
}

async fn check(
    conn: &mut AsyncPgConnection,
    payload: &PolicySetStatePayload,
    position: u64,
) -> PersistenceResult<()> {
    let candidate = event(EventKind::PolicySet, json!(payload), position);
    check_policy_cas_in_connection(conn, &candidate, &commit(&candidate, position), payload).await
}

#[tokio::test]
async fn first_write_needs_a_complete_held_prefix_and_rolls_back_without_effects() {
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    sql_query("BEGIN").execute(&mut conn).await.unwrap();
    seed_genesis(&mut conn).await;
    let payload = policy(None, true);
    check(&mut conn, &payload, 1).await.unwrap();
    sql_query("INSERT INTO realm_commits(commit_id,realm_id,stream_key,stream_ref,stream_position,previous_commit_ref,event_pk,governance_generation,commit_json,committed_at) VALUES('opaque-sibling',$1,'sibling','{\"kind\":\"circle\"}',0,NULL,NULL,0,'{}',now())")
        .bind::<Text,_>(realm().as_str()).execute(&mut conn).await.unwrap();
    assert!(check(&mut conn, &payload, 1).await.is_err());
    sql_query("DELETE FROM realm_commits WHERE commit_id='opaque-sibling'")
        .execute(&mut conn)
        .await
        .unwrap();
    assert!(check(&mut conn, &payload, 2).await.is_err());
    let candidate = event(EventKind::PolicySet, json!(payload), 1);
    let mut wrong_predecessor = commit(&candidate, 1);
    wrong_predecessor.previous_commit_ref = Some(arkret_wire::RealmCommitId::from_digest([99; 32]));
    assert!(
        check_policy_cas_in_connection(&mut conn, &candidate, &wrong_predecessor, &payload)
            .await
            .is_err()
    );
    sql_query("UPDATE realm_commits SET event_pk=NULL WHERE stream_position=0")
        .execute(&mut conn)
        .await
        .unwrap();
    assert!(check(&mut conn, &payload, 1).await.is_err());
    sql_query("ROLLBACK").execute(&mut conn).await.unwrap();
    let absent = sql_query("SELECT NOT EXISTS(SELECT 1 FROM policy_current_results) AND NOT EXISTS(SELECT 1 FROM realm_commits) AS present")
        .get_result::<Present>(&mut conn).await.unwrap();
    assert!(absent.present);
}

#[tokio::test]
async fn exact_revision_last_accepted_row_and_terminal_policy_binding_are_required() {
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    sql_query("BEGIN").execute(&mut conn).await.unwrap();
    seed_genesis(&mut conn).await;
    let first = policy(None, true);
    let accepted = event(EventKind::PolicySet, json!(first), 1);
    let basis = commit(&accepted, 1);
    insert_history(&mut conn, &accepted, &basis).await;
    commit_in_connection(&mut conn, &accepted, &basis)
        .await
        .unwrap();
    let exact = policy(Some(revision(&basis)), true);
    check(&mut conn, &exact, 2).await.unwrap();
    sql_query("UPDATE policy_current_results SET realm_id='foreign-realm'")
        .execute(&mut conn)
        .await
        .unwrap();
    assert!(check(&mut conn, &exact, 2).await.is_err());
    sql_query("UPDATE policy_current_results SET realm_id=$1")
        .bind::<Text, _>(realm().as_str())
        .execute(&mut conn)
        .await
        .unwrap();
    assert!(check(&mut conn, &policy(None, true), 2).await.is_err());
    let mut wrong = exact.clone();
    wrong
        .expected_revision
        .as_mut()
        .unwrap()
        .as_mut()
        .unwrap()
        .stream_position = 0;
    assert!(check(&mut conn, &wrong, 2).await.is_err());
    wrong = exact.clone();
    wrong
        .expected_revision
        .as_mut()
        .unwrap()
        .as_mut()
        .unwrap()
        .commit_id = arkret_wire::RealmCommitId::from_digest([99; 32]);
    assert!(check(&mut conn, &wrong, 2).await.is_err());
    let other_family = policy(None, false);
    assert!(check(&mut conn, &other_family, 2).await.is_err());
    let rebound = event(EventKind::PolicySet, json!(other_family), 2);
    assert!(
        commit_in_connection(&mut conn, &rebound, &commit(&rebound, 2))
            .await
            .is_err()
    );
    sql_query(
        "UPDATE policy_current_results SET value=jsonb_set(value,'{default_effect}','\"deny\"')",
    )
    .execute(&mut conn)
    .await
    .unwrap();
    assert!(check(&mut conn, &exact, 2).await.is_err());
    sql_query("DELETE FROM policy_current_results")
        .execute(&mut conn)
        .await
        .unwrap();
    assert!(check(&mut conn, &policy(None, true), 2).await.is_err());
    assert!(check(&mut conn, &other_family, 2).await.is_err());
    sql_query("ROLLBACK").execute(&mut conn).await.unwrap();
}

#[tokio::test]
async fn exact_accepted_retry_does_not_recheck_the_later_current_revision() {
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    sql_query("BEGIN").execute(&mut conn).await.unwrap();
    seed_genesis(&mut conn).await;
    let first = policy(None, true);
    let accepted = event(EventKind::PolicySet, json!(first), 1);
    let basis = commit(&accepted, 1);
    insert_history(&mut conn, &accepted, &basis).await;
    commit_in_connection(&mut conn, &accepted, &basis)
        .await
        .unwrap();
    let next = policy(Some(revision(&basis)), true);
    let accepted_next = event(EventKind::PolicySet, json!(next), 2);
    let next_commit = commit(&accepted_next, 2);
    insert_history(&mut conn, &accepted_next, &next_commit).await;
    commit_in_connection(&mut conn, &accepted_next, &next_commit)
        .await
        .unwrap();
    check_policy_cas_in_connection(&mut conn, &accepted, &basis, &first)
        .await
        .unwrap();
    let later_candidate = commit(&accepted, 3);
    check_policy_cas_in_connection(&mut conn, &accepted, &later_candidate, &first)
        .await
        .unwrap();
    let mut changed_event = accepted.clone();
    changed_event.created_at += chrono::TimeDelta::milliseconds(1);
    assert!(
        check_policy_cas_in_connection(&mut conn, &changed_event, &basis, &first)
            .await
            .is_err()
    );
    sql_query("ROLLBACK").execute(&mut conn).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_stale_editor_observes_the_winners_revision_after_the_lock() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let mut winner = pool.get().await.unwrap();
    seed_genesis(&mut winner).await;
    let first = policy(None, true);
    let accepted = event(EventKind::PolicySet, json!(first), 1);
    let basis = commit(&accepted, 1);
    insert_history(&mut winner, &accepted, &basis).await;
    commit_in_connection(&mut winner, &accepted, &basis)
        .await
        .unwrap();
    let update = policy(Some(revision(&basis)), true);
    sql_query("BEGIN").execute(&mut winner).await.unwrap();
    check(&mut winner, &update, 2).await.unwrap();
    let pool = pool.clone();
    let stale = update.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let reader = tokio::spawn(async move {
        let mut conn = pool.get().await.unwrap();
        sql_query("BEGIN").execute(&mut conn).await.unwrap();
        started_tx.send(()).unwrap();
        let result = check(&mut conn, &stale, 3).await;
        sql_query("ROLLBACK").execute(&mut conn).await.unwrap();
        result
    });
    started_rx.await.unwrap();
    let next = event(EventKind::PolicySet, json!(update), 2);
    let next_commit = commit(&next, 2);
    insert_history(&mut winner, &next, &next_commit).await;
    commit_in_connection(&mut winner, &next, &next_commit)
        .await
        .unwrap();
    sql_query("COMMIT").execute(&mut winner).await.unwrap();
    let error = tokio::time::timeout(std::time::Duration::from_secs(10), reader)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(
        error.to_string().contains("expected_revision differs"),
        "{error}"
    );
    let latest = sql_query("SELECT realm_id,current_commit_id,current_stream_position,current_event_id,value FROM policy_current_results")
        .get_result::<PolicyRevisionRow>(&mut winner).await.unwrap();
    assert_eq!(latest.current_commit_id, next_commit.commit_id.as_str());
}
