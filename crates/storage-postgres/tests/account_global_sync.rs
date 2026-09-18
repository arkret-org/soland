mod support;
use deadpool::managed::Pool;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use soland_storage::{AccountDataCasResult, AccountDataRecord, AccountDataStore, SyncCursorStore};
use soland_storage_postgres::{Db, PgAccountDataStore, PgPool, PgSyncCursorStore};

async fn pool() -> PgPool {
    let url = support::contract_database_url();
    support::ensure_contract_database(&url).await;
    Db::connect(Some(&url), Default::default()).await.unwrap();
    Pool::builder(AsyncDieselConnectionManager::new(&url))
        .build()
        .unwrap()
}
async fn put(store: &PgAccountDataStore, actor: &str, key: &str, revision: u64, deleted: bool) {
    let row = AccountDataRecord {
        actor: actor.into(),
        account_data_key: key.into(),
        revision,
        payload: serde_json::json!({"revision":revision}),
        tombstone: deleted,
        updated_at: chrono::Utc::now(),
    };
    assert!(matches!(
        store.compare_and_set(&row, revision - 1).await.unwrap(),
        AccountDataCasResult::Applied(_)
    ));
}
#[tokio::test]
async fn account_global_snapshot_is_frozen_and_changes_are_page_bounded() {
    let pool = pool().await;
    let cas = PgAccountDataStore { pool: pool.clone() };
    let sync = PgSyncCursorStore { pool };
    let actor = format!("global-sync-{}", uuid::Uuid::now_v7());
    for n in 0..103 {
        put(&cas, &actor, &format!("key:{n:03}"), 1, false).await;
    }
    let (_, cut) = sync.account_sync_watermarks().await.unwrap();
    let first = sync
        .account_global_page(&actor, "station_cas", cut, "", None, 100)
        .await
        .unwrap();
    assert_eq!(first.len(), 100);
    assert_eq!(first[99].item_key, "key:099");
    put(&cas, &actor, "key:100", 2, false).await;
    put(&cas, &actor, "key:101", 2, true).await;
    let second = sync
        .account_global_page(&actor, "station_cas", cut, "key:099", None, 100)
        .await
        .unwrap();
    assert_eq!(second.len(), 3);
    assert_eq!(second[0].payload["revision"], 1);
    assert!(!second[1].deleted);
    let latest = sync.account_global_watermark().await.unwrap();
    let changes = sync
        .account_global_page(&actor, "station_cas", latest, "", Some(cut), 1)
        .await
        .unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].item_key, "key:100");
    let last = sync
        .account_global_page(
            &actor,
            "station_cas",
            latest,
            "",
            Some(changes[0].revision),
            100,
        )
        .await
        .unwrap();
    assert_eq!(last.len(), 1);
    assert!(last[0].deleted);
    assert!(
        sync.account_global_page("another-actor", "station_cas", latest, "", None, 100)
            .await
            .unwrap()
            .is_empty()
    );
}

async fn insert_source(
    pool: &PgPool,
    actor: &str,
    realm: Option<&str>,
    kind: &str,
    payload: serde_json::Value,
) -> arkret_wire::EventId {
    use diesel::sql_types::{Binary, Jsonb, Nullable, Text};
    use diesel_async::RunQueryDsl;
    let digest = arkret_canonical::sha256_bytes(uuid::Uuid::now_v7().as_bytes());
    let mut token = [0u8; 33];
    token[0] = 1;
    token[1..].copy_from_slice(&digest);
    let id = arkret_wire::EventId::new(soland_storage::ids::format_event_id(&token)).unwrap();
    let envelope = serde_json::json!({"event_id":id,"actor_id":serde_json::from_str::<serde_json::Value>(actor).unwrap(),"payload":payload});
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("INSERT INTO canonical_events(id,digest_suite,digest,actor_id,actor_seq,realm_id,kind,schema_id,canonical_bytes,envelope) VALUES($1,1,$2,$3,1,$4,$5,'test', $6,$7)")
        .bind::<Binary,_>(token.to_vec()).bind::<Binary,_>(digest.to_vec()).bind::<Text,_>(actor)
        .bind::<Nullable<Text>,_>(realm).bind::<Text,_>(kind).bind::<Binary,_>(b"fixture".to_vec())
        .bind::<Jsonb,_>(envelope).execute(&mut *conn).await.unwrap();
    id
}

#[tokio::test]
async fn holder_current_event_changes_only_with_successful_cas_and_withdrawal_resets_it() {
    use diesel::sql_types::Binary;
    use diesel_async::RunQueryDsl;
    let pool = pool().await;
    let cas = PgAccountDataStore { pool: pool.clone() };
    let sync = PgSyncCursorStore { pool: pool.clone() };
    let actor = serde_json::json!({"kind":"account","account_id":{"principal_id":format!("ak:did_core:web:{}.example",uuid::Uuid::now_v7()),"station_id":"ak:did_core:web:station.example"}}).to_string();
    let key = "ak.dnd_schedule";
    let first = insert_source(
        &pool,
        &actor,
        None,
        "ak.account_data.set",
        serde_json::json!({"key":key,"expected_revision":0,"body":{"v":1}}),
    )
    .await;
    let before = sync.account_global_watermark().await.unwrap();
    assert!(
        sync.account_global_page(&actor, "account_data_events", before, "", None, 100)
            .await
            .unwrap()
            .is_empty()
    );
    let mut row = AccountDataRecord {
        actor: actor.clone(),
        account_data_key: key.into(),
        revision: 1,
        payload: serde_json::json!({"v":1}),
        tombstone: false,
        updated_at: chrono::Utc::now(),
    };
    assert!(matches!(
        cas.compare_and_set_holder_event(&row, 0, &first)
            .await
            .unwrap(),
        AccountDataCasResult::Applied(_)
    ));
    let second = insert_source(
        &pool,
        &actor,
        None,
        "ak.account_data.set",
        serde_json::json!({"key":key,"expected_revision":1,"body":{"v":2}}),
    )
    .await;
    row.revision = 2;
    row.payload = serde_json::json!({"v":2});
    assert!(matches!(
        cas.compare_and_set_holder_event(&row, 1, &second)
            .await
            .unwrap(),
        AccountDataCasResult::Applied(_)
    ));
    let cut = sync.account_global_watermark().await.unwrap();
    row.revision = 1;
    row.payload = serde_json::json!({"v":1});
    assert!(matches!(
        cas.compare_and_set_holder_event(&row, 0, &first)
            .await
            .unwrap(),
        AccountDataCasResult::Conflict(_)
    ));
    let late = insert_source(
        &pool,
        &actor,
        None,
        "ak.account_data.set",
        serde_json::json!({"key":key,"expected_revision":0,"body":{"v":9}}),
    )
    .await;
    row.payload = serde_json::json!({"v":9});
    assert!(matches!(
        cas.compare_and_set_holder_event(&row, 0, &late)
            .await
            .unwrap(),
        AccountDataCasResult::Conflict(_)
    ));
    // The clock is Station-wide, and other tests legitimately publish for
    // different accounts concurrently. A failed CAS must leave this account's
    // register and change stream untouched, rather than freeze that clock.
    let after_conflicts = sync.account_global_watermark().await.unwrap();
    assert!(
        sync.account_global_page(
            &actor,
            "account_data_events",
            after_conflicts,
            "",
            Some(cut),
            100,
        )
        .await
        .unwrap()
        .is_empty(),
        "conflicting or late source must not publish an account change"
    );
    let current = cas.get(&actor, key).await.unwrap().unwrap();
    assert_eq!(current.revision, 2);
    assert_eq!(current.payload, serde_json::json!({"v":2}));
    let page = sync
        .account_global_page(&actor, "account_data_events", cut, "", None, 100)
        .await
        .unwrap();
    assert_eq!(
        page[0].payload["value"]["event_id"],
        serde_json::json!(second)
    );
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("UPDATE canonical_events SET state='quarantined' WHERE id=$1")
        .bind::<Binary, _>(second.token_bytes().to_vec())
        .execute(&mut *conn)
        .await
        .unwrap();
    let now = sync.account_global_watermark().await.unwrap();
    let changes = sync
        .account_global_page(&actor, "account_data_events", now, "", Some(cut), 100)
        .await
        .unwrap();
    assert_eq!(changes[0].payload["source"], "invalidated");
    assert!(changes[0].deleted);
    let old = sync
        .account_global_page(&actor, "account_data_events", cut, "", None, 100)
        .await
        .unwrap();
    assert!(
        old[0].deleted,
        "frozen baseline must not revive withdrawn source"
    );
    assert!(
        cas.get(&actor, key).await.is_err(),
        "withdrawn current content must not be returned by get"
    );
}

#[tokio::test]
async fn device_station_is_bound_only_by_identity_and_rejects_rebinding() {
    use diesel_async::{RunQueryDsl, SimpleAsyncConnection};
    let pool = pool().await;
    let mut conn = pool.get().await.unwrap();
    // Isolate ownership without changing the shared contract database's identity.
    conn.batch_execute("CREATE TEMP TABLE device_inventory_station (singleton boolean PRIMARY KEY CHECK(singleton), station_id text UNIQUE NOT NULL); CREATE TRIGGER immutable_owner BEFORE UPDATE ON device_inventory_station FOR EACH ROW EXECUTE FUNCTION public.immutable_device_inventory_station(); CREATE TEMP TABLE service_identity (id text PRIMARY KEY, identity jsonb NOT NULL); CREATE TRIGGER bind_owner BEFORE INSERT OR UPDATE ON service_identity FOR EACH ROW EXECUTE FUNCTION public.bind_device_inventory_station(); CREATE TEMP TABLE devices (id text PRIMARY KEY, station_id text NOT NULL DEFAULT public.current_device_inventory_station() REFERENCES device_inventory_station(station_id));").await.unwrap();
    assert!(
        diesel::sql_query("INSERT INTO devices(id) VALUES('before')")
            .execute(&mut *conn)
            .await
            .is_err()
    );
    conn.batch_execute(r#"INSERT INTO service_identity VALUES('singleton','{"identity":{"service_id":"ak:did_core:web:local.example"}}'); INSERT INTO devices(id) VALUES('after'); UPDATE service_identity SET identity=identity;"#).await.unwrap();
    assert!(diesel::sql_query(r#"UPDATE service_identity SET identity='{"identity":{"service_id":"ak:did_core:web:foreign.example"}}'"#).execute(&mut *conn).await.is_err());
    assert!(
        diesel::sql_query(
            "INSERT INTO devices(id,station_id) VALUES('foreign','ak:did_core:web:foreign.example')"
        )
        .execute(&mut *conn)
        .await
        .is_err()
    );
}

#[derive(diesel::QueryableByName)]
struct Visible {
    #[diesel(sql_type=diesel::sql_types::Bool)]
    visible: bool,
}
async fn visible(pool: &PgPool, recipient: &str, owner: &str) -> bool {
    use diesel_async::RunQueryDsl;
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT COALESCE(account_device_interest_visible($1,$2),FALSE) AS visible")
        .bind::<diesel::sql_types::Text, _>(recipient)
        .bind::<diesel::sql_types::Text, _>(owner)
        .get_result::<Visible>(&mut *conn)
        .await
        .unwrap()
        .visible
}
#[tokio::test]
async fn device_interest_requires_exact_actor_current_membership_and_nonminimal_create() {
    use diesel_async::RunQueryDsl;
    let pool = pool().await;
    let account = |principal: &str, station: &str| {
        serde_json::json!({"kind":"account","account_id":{"principal_id":principal,"station_id":station}}).to_string()
    };
    let principal = format!("ak:did_core:web:{}.example", uuid::Uuid::now_v7());
    let recipient = account(&principal, "ak:did_core:web:local.example");
    let peer = account(
        "ak:did_core:web:peer.example",
        "ak:did_core:web:remote.example",
    );
    let same_principal_other_station = account(
        "ak:did_core:web:peer.example",
        "ak:did_core:web:other.example",
    );
    for minimal in [true, false] {
        let realm = format!("ak:realm:test-{}", uuid::Uuid::now_v7());
        let mut conn = pool.get().await.unwrap();
        for actor in [&recipient, &peer] {
            diesel::sql_query("INSERT INTO account_summary_current(actor_key,realm_id,revision,membership,available) VALUES($1,$2,1,'join',TRUE)")
                .bind::<diesel::sql_types::Text,_>(actor).bind::<diesel::sql_types::Text,_>(&realm).execute(&mut *conn).await.unwrap();
        }
        assert!(
            !visible(&pool, &recipient, &peer).await,
            "missing accepted create must fail closed"
        );
        let schemas = if minimal {
            serde_json::json!(["ak.profile.mls.minimal_metadata_realm.v1"])
        } else {
            serde_json::json!(["ak.schema.realm.v1"])
        };
        let create_id = insert_source(
            &pool,
            &recipient,
            Some(&realm),
            "ak.realm.create",
            serde_json::json!({"object":{"schema_refs":schemas}}),
        )
        .await;
        assert_eq!(visible(&pool, &recipient, &peer).await, !minimal);
        if !minimal {
            // Establish the authorized interest, then revoke only Create. No
            // additional Seal/summary mutation may be required for left_ids.
            diesel::sql_query("SELECT refresh_account_device_interest($1,$2)")
                .bind::<diesel::sql_types::Text, _>(&recipient)
                .bind::<diesel::sql_types::Text, _>(&peer)
                .execute(&mut *conn)
                .await
                .unwrap();
            let sync = PgSyncCursorStore { pool: pool.clone() };
            let cut = sync.account_global_watermark().await.unwrap();
            diesel::sql_query("UPDATE canonical_events SET state='quarantined' WHERE id=$1")
                .bind::<diesel::sql_types::Binary, _>(create_id.token_bytes().to_vec())
                .execute(&mut *conn)
                .await
                .unwrap();
            let now = sync.account_global_watermark().await.unwrap();
            let delta = sync
                .account_global_page(&recipient, "device_lists", now, "", Some(cut), 100)
                .await
                .unwrap();
            assert!(
                delta.iter().any(|row| row.item_key == peer && row.deleted),
                "Create withdrawal must emit durable left without a Seal"
            );
        }
        assert!(!visible(&pool, &recipient, &same_principal_other_station).await);
        diesel::sql_query("UPDATE account_summary_current SET available=FALSE WHERE realm_id=$1")
            .bind::<diesel::sql_types::Text, _>(&realm)
            .execute(&mut *conn)
            .await
            .unwrap();
        assert!(!visible(&pool, &recipient, &peer).await);
    }
    assert!(visible(&pool, &recipient, &recipient).await);
}

#[derive(diesel::QueryableByName)]
struct Station {
    #[diesel(sql_type=diesel::sql_types::Text)]
    station: String,
}
#[derive(diesel::QueryableByName)]
struct Count {
    #[diesel(sql_type=diesel::sql_types::BigInt)]
    count: i64,
}
#[tokio::test]
async fn racing_holder_cas_accepts_only_one_event_and_publishes_only_its_source() {
    use diesel_async::RunQueryDsl;
    use soland_storage::EventCommitUnitOfWork;
    let pool = pool().await;
    let mut conn = pool.get().await.unwrap();
    let station=diesel::sql_query("SELECT COALESCE(current_device_inventory_station(),'ak:did_core:web:storage-contract.example') AS station").get_result::<Station>(&mut *conn).await.unwrap().station;
    diesel::sql_query("INSERT INTO service_identity(id,identity) VALUES('self',jsonb_build_object('identity',jsonb_build_object('service_id',$1))) ON CONFLICT(id) DO NOTHING").bind::<diesel::sql_types::Text,_>(&station).execute(&mut *conn).await.unwrap();
    let principal = arkret_wire::DidCoreId::new(format!(
        "ak:did_core:web:cas-{}.example",
        uuid::Uuid::now_v7()
    ))
    .unwrap();
    let station = arkret_wire::DidCoreId::new(station).unwrap();
    let realm = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(uuid::Uuid::now_v7().as_bytes()),
    ));
    let now = chrono::Utc::now();
    // Both writers claim the Realm stream's genesis position, so the authority
    // commit is the mutual exclusion the racing holders contend on.
    let authority = soland_storage::CurrentRealmAuthority {
        realm_id: realm.clone(),
        generation: 0,
        service_id: station.clone(),
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
            arkret_identifiers::EventIdentityKey::new(realm.digest_suite_code(), realm.digest_bytes())
                .event_id(),
        ),
        last_handoff_ref: None,
    };
    soland_storage::AuthorityCommitStore::install_genesis_authority(
        &soland_storage_postgres::PgAuthorityCommitStore { pool: pool.clone() },
        &authority,
    )
    .await
    .unwrap();
    let make = |value| {
        let mut event=arkret_wire::test_support::raw_event_at("ak.account_data.set",arkret_wire::ScopeRef::Realm{realm_id:realm.clone()},principal.clone(),station.clone(),serde_json::json!({"key":"ak.dnd_schedule","expected_revision":0,"body":{"value":value}}),now).unwrap();
        let event_digest = arkret_wire::Hash::new(
            event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        event.proofs = vec![arkret_wire::ProducerEventProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: arkret_wire::DidUrl::new(format!(
                "did:{}#cas-device",
                principal.as_str().strip_prefix("ak:did_core:").unwrap()
            ))
            .unwrap(),
            event_digest: event_digest.clone(),
            created_at: arkret_canonical::normalize_timestamp_canonical(now),
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: arkret_wire::test_support::structural_only_detached_jws(&event_digest),
        }];
        let record = soland_storage::CanonicalEventRecord {
            event_id: event.event_id.to_string(),
            actor_id: event.actor_id.to_string(),
            realm_id: Some(realm.to_string()),
            kind: event.kind.to_string(),
            schema_id: "schemas/event-payload.schema.json#/$defs/account_data_set_payload".into(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
            canonical_digest: event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
            canonical_bytes: arkret_canonical::canonical_json_bytes(
                &event.digest_payload().unwrap(),
            )
            .unwrap(),
            envelope: serde_json::to_value(&event).unwrap(),
            received_at: now,
        };
        soland_storage::EventCommitRequest {
            authority_commit: soland_storage::AuthorityCommitTransaction {
                expected_authority: authority.clone(),
                commit: arkret_wire::RealmCommit {
                    commit_id: arkret_wire::RealmCommitId::from_digest(
                        arkret_canonical::sha256_bytes(event.event_id.as_str().as_bytes()),
                    ),
                    realm_id: realm.clone(),
                    stream_ref: arkret_wire::CommitStreamRef::Realm {
                        realm_id: realm.clone(),
                    },
                    stream_position: 0,
                    previous_commit_ref: None,
                    event_ref: event.event_id.clone(),
                    governance_generation: 0,
                    authority_ref: authority.authority_ref.clone(),
                    committed_at: now,
                    signature: arkret_wire::DetachedObjectSignature {
                        context: arkret_wire::DetachedSignatureContext::RealmCommit,
                        signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                        verification_method: arkret_wire::DidUrl::new(format!(
                            "did:{}#authority",
                            station.as_str().strip_prefix("ak:did_core:").unwrap()
                        ))
                        .unwrap(),
                        signed_digest: event_digest,
                        created_at: now,
                        sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
                    },
                },
                event,
                mls_state: None,
                welcomes: Vec::new(),
            },
            event: record,
            device_pairing_authorization: None,
            contact_projection: None,
            consent_projection: None,
            device_revocation_transition: None,
            device_revocation_gate: None,
            projections: vec![],
            idempotency: None,
            outbox: vec![],
        }
    };
    let a = make(1);
    let b = make(2);
    let actor = a.event.actor_id.clone();
    let a_id = a.event.event_id.clone();
    let b_id = b.event.event_id.clone();
    let first = soland_storage_postgres::PgEventCommitUnitOfWork::new(pool.clone());
    let second = soland_storage_postgres::PgEventCommitUnitOfWork::new(pool.clone());
    let (a_result, b_result) = tokio::join!(first.commit_event(a), second.commit_event(b));
    assert_ne!(
        a_result.is_ok(),
        b_result.is_ok(),
        "{a_result:?} / {b_result:?}"
    );
    let rejected_error = a_result
        .as_ref()
        .err()
        .or_else(|| b_result.as_ref().err())
        .unwrap();
    // The Realm stream position is the durable compare-and-set the racing
    // holders contend on, so the loser fails on stream ordering rather than on
    // an unrelated error.
    assert!(
        rejected_error.to_string().contains("stream_position"),
        "{rejected_error}"
    );
    let rejected = if a_result.is_err() { a_id } else { b_id };
    let rejected_count = diesel::sql_query(
        "SELECT count(*) AS count FROM canonical_events WHERE envelope->>'event_id'=$1",
    )
    .bind::<diesel::sql_types::Text, _>(&rejected)
    .get_result::<Count>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(
        rejected_count.count, 0,
        "failed CAS must roll back even accepted Event insertion"
    );
    let sync = PgSyncCursorStore { pool };
    let cut = sync.account_global_watermark().await.unwrap();
    let page = sync
        .account_global_page(&actor, "account_data_events", cut, "", None, 100)
        .await
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_ne!(page[0].payload["value"]["event_id"], rejected);
}
