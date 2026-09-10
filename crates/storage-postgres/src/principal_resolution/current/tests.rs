use diesel_async::AsyncConnection;
use serde_json::json;
use soland_storage::{CanonicalEventRecord, EventStore};

use super::*;

#[tokio::test]
async fn current_cell_ignores_async_cache_and_requires_live_exact_source() {
    let db = crate::test_database::TestDatabase::lease().await;
    let pool = db.pool();
    let account = AccountId::new(
        "ak:did_core:web:principal.example".parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    );
    assert_eq!(
        read(&pool, &account).await.unwrap(),
        CurrentPrincipalRead::Missing
    );
    let time = chrono::DateTime::parse_from_rfc3339("2026-09-10T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let commitment = json!({"did":"did:web:principal.example","method_history_head":"accepted-method-head","version_id":"1"});
    let event = arkret_wire::test_support::raw_event_for_actor_at(
        "ak.realm.create",
        ScopeRef::RealmGenesis,
        arkret_wire::ActorId::account(account.clone()),
        1,
        "000000000001-0000-00000000".parse().unwrap(),
        json!({"object":{"purpose":"principal_control","initial_resolution":commitment}}),
        time,
    )
    .unwrap();
    let realm = event.realm_id.clone();
    let record = CanonicalEventRecord {
        event_id: event.event_id.to_string(),
        actor_id: event.actor_id.canonical_key().unwrap(),
        actor_seq: 1,
        realm_id: Some(realm.to_string()),
        kind: event.kind.as_str().to_owned(),
        schema_id: arkret_wire::SchemaId::EVENT_V1.to_owned(),
        digest_suite: arkret_canonical::DigestSuite::Sha256,
        canonical_digest: event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap(),
        canonical_bytes: arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap())
            .unwrap(),
        envelope: serde_json::to_value(&event).unwrap(),
        received_at: time,
    };
    crate::PgEventStore { pool: pool.clone() }
        .put(record)
        .await
        .unwrap();
    let projection = PrincipalResolutionProjection {
        did: "did:web:principal.example".parse().unwrap(),
        method_history_head: "accepted-method-head".into(),
        version_id: "1".into(),
        resolution_event_ref: event.event_id.to_string(),
        updated_at: time,
    };
    assert_eq!(
        event.realm_id, realm,
        "fixture Realm must be its canonical genesis Realm"
    );
    let _: Event = serde_json::from_value(serde_json::to_value(&event).unwrap())
        .expect("fixture accepted Event roundtrip");
    assert!(source_matches(&event, &projection));
    let mut conn = pg_conn(&pool).await.unwrap();
    // Intentionally corrupt only the asynchronous cache fields. The immutable
    // creation coordinates and accepted current result are the read authority.
    sql_query("INSERT INTO principal_resolutions(principal_id,station_id,pcr_realm_id,genesis_event_id,current_event_id,projection,updated_at) VALUES($1,$2,$3,$4,'stale-index','{}',now())")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str()).bind::<Text,_>(realm.as_str()).bind::<Text,_>(event.event_id.as_str()).execute(&mut *conn).await.unwrap();
    assert_eq!(
        read(&pool, &account).await.unwrap(),
        CurrentPrincipalRead::Unavailable
    );
    let selector = CurrentSelector {
        scope_ref: ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        cell_id: "ak:cell:ak.component.identity.resolution.v1:null"
            .parse()
            .unwrap(),
    };
    let entry=CurrentResultEntry::try_from_json(json!({"selector":selector,"target":{"kind":"realm"},"revision":1,"result":{"status":"value","value":projection}})).unwrap();
    sql_query("INSERT INTO current_result_heads(realm_id,selector_key,revision,target_kind,target_key,payload) VALUES($1,$2,1,'realm','',$3)")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(selector.canonical_key().unwrap()).bind::<Jsonb,_>(serde_json::to_value(entry).unwrap()).execute(&mut *conn).await.unwrap();
    sql_query("INSERT INTO governance_current_ready(realm_id,ready,revision) VALUES($1,TRUE,1)")
        .bind::<Text, _>(realm.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
    let source = accepted(&mut conn, &event.event_id, &realm)
        .await
        .map_err(crate::PgTransactionError::into_persistence)
        .unwrap()
        .expect("accepted genesis source");
    validate_principal_resolution_record(&PrincipalResolutionRecord {
        account_id: account.clone(),
        pcr_realm_id: realm.clone(),
        genesis_event: source.clone(),
        current_event: source,
        projection: projection.clone(),
    })
    .expect("fixture account binding");
    let round=sql_query("SELECT payload,TRUE AS ready,now() AS observed_at FROM current_result_heads WHERE realm_id=$1 AND selector_key=$2")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(selector.canonical_key().unwrap()).get_result::<Current>(&mut *conn).await.unwrap();
    let entry = CurrentResultEntry::try_from_json(round.payload)
        .expect("database current result roundtrip");
    let CurrentOutcome::Value { value } = entry.result() else {
        panic!("scalar result");
    };
    let _: PrincipalResolutionProjection =
        serde_json::from_value(value.as_json().clone()).expect("typed projection roundtrip");
    assert!(
        matches!(read(&pool,&account).await.unwrap(),CurrentPrincipalRead::Ready{projection:p,..} if p==projection)
    );
    let mut other = account.clone();
    other.station_id = "ak:did_core:web:other.example".parse().unwrap();
    assert_eq!(
        read(&pool, &other).await.unwrap(),
        CurrentPrincipalRead::Missing
    );
    sql_query("UPDATE governance_current_ready SET ready=FALSE WHERE realm_id=$1")
        .bind::<Text, _>(realm.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
    assert_eq!(
        read(&pool, &account).await.unwrap(),
        CurrentPrincipalRead::Unavailable
    );
    sql_query("UPDATE governance_current_ready SET ready=TRUE WHERE realm_id=$1")
        .bind::<Text, _>(realm.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
    let mut replacement = event.digest_payload().unwrap();
    replacement["payload"]["object"]["initial_resolution"]["version_id"] = json!("replacement");
    let replacement = arkret_canonical::canonical_json_bytes(&replacement).unwrap();
    conn.transaction::<(), crate::PgTransactionError, _>(async |conn| {
        crate::events::admit_collision_winner(
            conn,
            &event.event_id.token_bytes(),
            Some(realm.as_str()),
            &replacement,
            time.timestamp_millis(),
        )
        .await?;
        Ok(())
    })
    .await
    .map_err(crate::PgTransactionError::into_persistence)
    .unwrap();
    assert_eq!(
        read(&pool, &account).await.unwrap(),
        CurrentPrincipalRead::Unavailable
    );
    sql_query("UPDATE canonical_events SET envelope=$2,state='quarantined' WHERE id=$1")
        .bind::<Binary, _>(event.event_id.token_bytes().to_vec())
        .bind::<Jsonb, _>(serde_json::to_value(event).unwrap())
        .execute(&mut *conn)
        .await
        .unwrap();
    assert_eq!(
        read(&pool, &account).await.unwrap(),
        CurrentPrincipalRead::Unavailable
    );
}
