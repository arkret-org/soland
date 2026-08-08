use soland_storage::contract_tests::{
    EventCommitContractStores, assert_atomic_batch_outbox_rollback_contract,
    assert_control_proposal_authority_ack_store_contract,
    assert_event_commit_unit_of_work_contract, assert_federation_outbox_store_contract,
    assert_idempotency_store_contract, assert_last_resort_claim_ledger_contract,
    assert_mls_keypackage_retirement_contract, assert_organization_registration_store_contract,
};
use soland_storage::{
    AccountDataCasResult, AccountDataRecord, AccountDataStore, MlsKeyPackageStore,
    PeerKeyPackageClaimLedgerRecord, PeerKeyPackageClaimLedgerWriteResult,
};
use soland_storage_postgres::{
    Db, PgAccountDataStore, PgControlProposalAuthorityAckStore, PgEventCommitUnitOfWork,
    PgEventStore, PgFederationOutboxStore, PgIdempotencyStore, PgMlsKeyPackageStore,
    PgOrganizationRegistrationStore, PgPool, PgProjectionEventStore,
};

static TEST_POOL: tokio::sync::OnceCell<Option<PgPool>> = tokio::sync::OnceCell::const_new();

/// These contracts share one database and several of them exercise
/// row/advisory locking (`lock_organization`, the event-commit unit of work).
/// Running them concurrently against a single pool intermittently starves a
/// connection and surfaces as `Database("connection closed")` or a spurious
/// conflict, so each case holds this guard for its duration.
static DB_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn test_pool() -> Option<PgPool> {
    TEST_POOL
        .get_or_init(|| async { Db::from_env().await.expect("initialize test database").pool })
        .await
        .clone()
}

fn event_derived_realm_id(seed: &[u8]) -> String {
    let event_id = arkret_identifiers::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(seed),
    );
    arkret_identifiers::RealmId::from_event_id(&event_id).to_string()
}

#[tokio::test]
async fn postgres_adapter_satisfies_shared_idempotency_contract_when_configured() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let store = PgIdempotencyStore { pool };
    let namespace = format!("postgres-contract-{}", uuid::Uuid::now_v7());
    assert_idempotency_store_contract(&store, &namespace).await;
}

#[tokio::test]
async fn postgres_adapter_satisfies_control_proposal_authority_ack_contract_when_configured() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let store = PgControlProposalAuthorityAckStore { pool };
    let namespace = format!("postgres-control-proposal-ack-{}", uuid::Uuid::now_v7());
    assert_control_proposal_authority_ack_store_contract(&store, &namespace).await;
}

#[tokio::test]
async fn postgres_adapter_satisfies_shared_event_commit_contract_when_configured() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let unit_of_work = PgEventCommitUnitOfWork::new(pool.clone());
    let events = PgEventStore { pool: pool.clone() };
    let projections = PgProjectionEventStore { pool: pool.clone() };
    let idempotency = PgIdempotencyStore { pool: pool.clone() };
    let outbox = PgFederationOutboxStore { pool };
    let namespace = format!("postgres-event-commit-{}", uuid::Uuid::now_v7());
    assert_event_commit_unit_of_work_contract(
        EventCommitContractStores {
            unit_of_work: &unit_of_work,
            events: &events,
            projections: &projections,
            idempotency: &idempotency,
            outbox: &outbox,
        },
        &namespace,
    )
    .await;
}

#[tokio::test]
async fn postgres_event_commit_indexes_basis_free_control_anchor_when_configured() {
    use diesel::sql_types::Text;
    use diesel::{QueryableByName, sql_query};
    use diesel_async::RunQueryDsl;
    use soland_storage::{CanonicalEventRecord, EventCommitRequest, EventCommitUnitOfWork};

    #[derive(QueryableByName)]
    struct CountRow {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        value: i64,
    }

    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let now = chrono::Utc::now();
    let actor_id = arkret_identifiers::Did::new(format!(
        "did:web:managed-anchor-{}.example",
        uuid::Uuid::now_v7()
    ))
    .unwrap();
    let realm_id = arkret_identifiers::principal_control_realm_id(actor_id.as_str());
    let event = arkret_wire::Event::new_with_derived_id_at(
        arkret_wire::EventKind::REALM_CREATE,
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        actor_id,
        0,
        arkret_identifiers::Hlc::new("019c00000000-0000-aabbccdd").unwrap(),
        serde_json::json!({"object": {"fields": {"purpose": "principal_control"}}}),
        now,
    )
    .unwrap();
    let event_id = event.event_id.clone();
    assert!(event.seal_basis.is_none());
    let proposal_digest = arkret_identifiers::Hash::new(event.event_digest().unwrap()).unwrap();
    let authority_set_ref =
        arkret_identifiers::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap();
    let ack = arkret_wire::ControlProposalAck {
        kind: arkret_wire::ControlProposalAckKind::SignedAck,
        realm_id: realm_id.clone(),
        proposal_digest: proposal_digest.clone(),
        received_at: now,
        decision_due_at: now + chrono::Duration::hours(1),
        absolute_due_at: now + chrono::Duration::hours(2),
        defer_count: 0,
        authority_set_ref: authority_set_ref.clone(),
        authority_acks: Vec::new(),
    };
    let envelope = serde_json::to_value(&event).unwrap();
    let canonical_bytes =
        arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(EventCommitRequest {
            event: CanonicalEventRecord {
                event_id: event_id.to_string(),
                actor_id: event.actor_id.to_string(),
                actor_seq: 0,
                realm_id: Some(realm_id.to_string()),
                kind: arkret_wire::EventKind::REALM_CREATE.to_owned(),
                schema_id: "ak.schema.realm.v1".to_owned(),
                canonical_digest: proposal_digest.to_string(),
                canonical_bytes,
                envelope,
                received_at: now,
            },
            control_proposal_ack: Some(ack),
            self_principal_pcr_device_authorized: false,
            projections: Vec::new(),
            idempotency: None,
            outbox: Vec::new(),
        })
        .await
        .expect("commit basis-free Control anchor with its Control Proposal Ack");

    let mut conn = pool.get().await.unwrap();
    let count =
        sql_query("SELECT COUNT(*) AS value FROM state_control_events WHERE event_digest = $1")
            .bind::<Text, _>(proposal_digest.as_str())
            .get_result::<CountRow>(&mut *conn)
            .await
            .unwrap()
            .value;
    assert_eq!(
        count, 1,
        "basis-free Control anchor must enter pending index"
    );
}

#[tokio::test]
async fn postgres_hash_collision_commits_quarantine_evidence_before_returning_conflict() {
    use diesel::sql_types::{BigInt, Binary, SmallInt, Text};
    use diesel::{QueryableByName, sql_query};
    use diesel_async::RunQueryDsl;
    use soland_storage::{
        CanonicalEventRecord, EventBatchCommitRequest, EventCommitRequest, EventCommitUnitOfWork,
        EventStore, FederationOutboxStore, PersistenceError, ids,
    };

    #[derive(QueryableByName)]
    struct PkRow {
        #[diesel(sql_type = BigInt)]
        pk: i64,
    }
    #[derive(QueryableByName)]
    struct StateRow {
        #[diesel(sql_type = Text)]
        state: String,
    }
    #[derive(QueryableByName)]
    struct CountRow {
        #[diesel(sql_type = BigInt)]
        value: i64,
    }

    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let preimage = b"validated-digest-preimage".to_vec();
    let digest = arkret_canonical::sha256_bytes(&preimage);
    let mut id = [0_u8; ids::EVENT_ID_BYTES];
    id[0] = 0x01;
    id[1..].copy_from_slice(&digest);
    let event_id = ids::format_event_id(&id);
    let canonical_digest = ids::format_event_digest(0x01, &digest).unwrap();
    let now = chrono::Utc::now();
    let realm_id = event_derived_realm_id(b"postgres-collision-contract-realm");
    let actor_id = format!("did:web:collision-{}.example", uuid::Uuid::now_v7());
    let incoming = CanonicalEventRecord {
        event_id: event_id.clone(),
        actor_id: actor_id.clone(),
        actor_seq: 0,
        realm_id: Some(realm_id.clone()),
        kind: "ak.test.data".to_owned(),
        schema_id: "arkret://events/test/v1".to_owned(),
        canonical_digest: canonical_digest.clone(),
        canonical_bytes: preimage,
        envelope: serde_json::json!({"variant": "incoming", "proofs": [{"jws": "full-evidence"}]}),
        received_at: now,
    };
    let mut conn = pool.get().await.unwrap();
    let realm_identity = ids::realm_identity_parts(&realm_id).unwrap();
    let realm_pk = sql_query(
        "INSERT INTO canonical_realms \
         (id, derivation_class, digest_suite, digest, wire_id) \
         VALUES ($1, $2, $3, $4, $5) RETURNING pk",
    )
    .bind::<Binary, _>(realm_identity.id.to_vec())
    .bind::<SmallInt, _>(i16::from(realm_identity.derivation_class))
    .bind::<SmallInt, _>(i16::from(realm_identity.digest_suite))
    .bind::<Binary, _>(realm_identity.digest.to_vec())
    .bind::<Text, _>(&realm_id)
    .get_result::<PkRow>(&mut conn)
    .await
    .unwrap()
    .pk;
    let event_pk = sql_query(
        "INSERT INTO canonical_events \
         (id, digest_suite, digest, actor_id, actor_seq, realm_id, realm_pk, kind, schema_id, canonical_bytes, envelope, received_at) \
         VALUES ($1, 1, $2, $3, 0, $4, $5, $6, $7, $8, $9, $10) RETURNING pk",
    )
    .bind::<Binary, _>(id.to_vec())
    .bind::<Binary, _>(digest.to_vec())
    .bind::<Text, _>(&actor_id)
    .bind::<Text, _>(&realm_id)
    .bind::<BigInt, _>(realm_pk)
    .bind::<Text, _>(&incoming.kind)
    .bind::<Text, _>(&incoming.schema_id)
    .bind::<Binary, _>(b"hypothetical-colliding-preimage".to_vec())
    .bind::<diesel::sql_types::Jsonb, _>(serde_json::json!({"variant": "accepted"}))
    .bind::<diesel::sql_types::Timestamptz, _>(now)
    .get_result::<PkRow>(&mut conn)
    .await
    .unwrap()
    .pk;
    sql_query(
        "INSERT INTO projection_events \
         (event_pk, realm_pk, realm_id, event_kind, operation_kind, payload, created_at, received_at) \
         VALUES ($1, $2, $3, $4, 'test', '{}'::jsonb, $5, $5)",
    )
    .bind::<BigInt, _>(event_pk)
    .bind::<BigInt, _>(realm_pk)
    .bind::<Text, _>(&realm_id)
    .bind::<Text, _>(&incoming.kind)
    .bind::<diesel::sql_types::Timestamptz, _>(now)
    .execute(&mut conn)
    .await
    .unwrap();
    let outbox_id = format!("collision-outbox:{}", uuid::Uuid::now_v7());
    sql_query(
        "INSERT INTO federation_outbox \
         (id, event_pk, peer_id, peer_url, endpoint, idempotency_key, payload_json, next_attempt_at, created_at) \
         VALUES ($1, $2, 'did:web:peer.example', 'https://peer.example', '/events', $1, '{}', 0, 0)",
    )
    .bind::<Text, _>(&outbox_id)
    .bind::<BigInt, _>(event_pk)
    .execute(&mut conn)
    .await
    .unwrap();
    drop(conn);

    let store = PgEventStore { pool: pool.clone() };
    let error = store.put(incoming.clone()).await.unwrap_err();
    assert!(
        matches!(error, PersistenceError::Conflict(reason) if reason == "event_hash_collision")
    );
    assert!(store.get(&event_id).await.unwrap().is_none());
    assert_eq!(store.collision_variants(&event_id).await.unwrap().len(), 2);

    let mut conn = pool.get().await.unwrap();
    let projections =
        sql_query("SELECT COUNT(*) AS value FROM projection_events WHERE event_pk = $1")
            .bind::<BigInt, _>(event_pk)
            .get_result::<CountRow>(&mut conn)
            .await
            .unwrap()
            .value;
    assert_eq!(projections, 0, "unsealed projection must be withdrawn");
    sql_query(
        "INSERT INTO state_control_events \
         (event_digest, realm_id, event_json, sealed_by, sealed_at) \
         VALUES ($1, $2, '{}'::jsonb, 'ak:seal:test', $3)",
    )
    .bind::<Text, _>(&canonical_digest)
    .bind::<Text, _>(&realm_id)
    .bind::<diesel::sql_types::Timestamptz, _>(now)
    .execute(&mut conn)
    .await
    .unwrap();
    sql_query(
        "INSERT INTO projection_events \
         (event_pk, realm_pk, realm_id, event_kind, operation_kind, payload, created_at, received_at) \
         VALUES ($1, $2, $3, $4, 'sealed-test', '{}'::jsonb, $5, $5)",
    )
    .bind::<BigInt, _>(event_pk)
    .bind::<BigInt, _>(realm_pk)
    .bind::<Text, _>(&realm_id)
    .bind::<Text, _>(&incoming.kind)
    .bind::<diesel::sql_types::Timestamptz, _>(now)
    .execute(&mut conn)
    .await
    .unwrap();
    drop(conn);

    let repeated = store.put(incoming.clone()).await.unwrap_err();
    assert!(
        matches!(repeated, PersistenceError::Conflict(reason) if reason == "event_hash_collision")
    );
    assert_eq!(store.collision_variants(&event_id).await.unwrap().len(), 2);

    let prefix_preimage = b"batch-prefix-must-not-land".to_vec();
    let prefix_digest = arkret_canonical::sha256_bytes(&prefix_preimage);
    let mut prefix_id_bytes = [0_u8; ids::EVENT_ID_BYTES];
    prefix_id_bytes[0] = 0x01;
    prefix_id_bytes[1..].copy_from_slice(&prefix_digest);
    let prefix_id = ids::format_event_id(&prefix_id_bytes);
    let prefix = CanonicalEventRecord {
        event_id: prefix_id.clone(),
        canonical_digest: ids::format_event_digest(0x01, &prefix_digest).unwrap(),
        canonical_bytes: prefix_preimage,
        envelope: serde_json::json!({"prefix": true}),
        ..incoming.clone()
    };
    let batch_error = PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event_batch(EventBatchCommitRequest {
            events: vec![
                EventCommitRequest {
                    event: prefix,
                    control_proposal_ack: None,
                    self_principal_pcr_device_authorized: false,
                    projections: Vec::new(),
                    idempotency: None,
                    outbox: Vec::new(),
                },
                EventCommitRequest {
                    event: incoming,
                    control_proposal_ack: None,
                    self_principal_pcr_device_authorized: false,
                    projections: Vec::new(),
                    idempotency: None,
                    outbox: Vec::new(),
                },
            ],
            applet_ghosts: None,
        })
        .await
        .unwrap_err();
    assert!(
        matches!(batch_error, PersistenceError::Conflict(reason) if reason == "event_hash_collision")
    );
    assert!(!store.contains(&prefix_id).await.unwrap());

    let mut conn = pool.get().await.unwrap();
    let state = sql_query("SELECT state FROM canonical_events WHERE pk = $1")
        .bind::<BigInt, _>(event_pk)
        .get_result::<StateRow>(&mut conn)
        .await
        .unwrap()
        .state;
    assert_eq!(state, "quarantined");
    let projections =
        sql_query("SELECT COUNT(*) AS value FROM projection_events WHERE event_pk = $1")
            .bind::<BigInt, _>(event_pk)
            .get_result::<CountRow>(&mut conn)
            .await
            .unwrap()
            .value;
    assert_eq!(
        projections, 1,
        "accepted sealed history must survive repeated collision quarantine"
    );
    let outbox = PgFederationOutboxStore { pool };
    let delivery = outbox.get(&outbox_id).await.unwrap().unwrap();
    assert_eq!(
        delivery.last_error_code.as_deref(),
        Some("witness_disagreement")
    );
}

#[tokio::test]
async fn postgres_adapter_rolls_atomic_batches_back_with_their_outbox_when_configured() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let events = PgEventStore { pool: pool.clone() };
    let outbox = PgFederationOutboxStore { pool };
    let namespace = format!("postgres-batch-outbox-{}", uuid::Uuid::now_v7());
    assert_atomic_batch_outbox_rollback_contract(&events, &outbox, &namespace).await;
}

#[tokio::test]
async fn postgres_adapter_satisfies_shared_federation_outbox_contract_when_configured() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let store = PgFederationOutboxStore { pool };
    let namespace = format!("postgres-federation-outbox-{}", uuid::Uuid::now_v7());
    assert_federation_outbox_store_contract(&store, &namespace).await;
}

#[tokio::test]
async fn postgres_adapter_satisfies_mls_keypackage_retirement_contract_when_configured() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let namespace = format!("postgres-retirement-{}", uuid::Uuid::now_v7());
    let store = PgMlsKeyPackageStore { pool: pool.clone() };
    assert_mls_keypackage_retirement_contract(&store, &namespace).await;

    let restarted_store = PgMlsKeyPackageStore { pool };
    let retired_id = format!("{namespace}-keypackage-published");
    let replayed = restarted_store
        .get(&retired_id)
        .await
        .expect("reload retired KeyPackage after store restart")
        .expect("retired KeyPackage survives store restart");
    assert_eq!(replayed.claimed_by_mls_group_id.as_deref(), Some("retired"));
}

#[tokio::test]
async fn postgres_adapter_satisfies_last_resort_claim_ledger_contract_when_configured() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let namespace = format!("postgres-last-resort-{}", uuid::Uuid::now_v7());
    let store = PgMlsKeyPackageStore { pool: pool.clone() };
    assert_last_resort_claim_ledger_contract(&store, &namespace).await;

    let restarted_store = PgMlsKeyPackageStore { pool };
    let claim_request_id = format!("local-last-resort:{namespace}-01");
    let replayed = restarted_store
        .get_peer_claim(&format!("did:web:{namespace}.example"), &claim_request_id)
        .await
        .expect("reload last-resort ledger after store restart")
        .expect("last-resort ledger survives store restart");
    assert_eq!(replayed.claim_request_id, claim_request_id);
    assert_eq!(replayed.state, "last_resort_claimed");

    let concurrent = PeerKeyPackageClaimLedgerRecord {
        source_service_id: format!("did:web:{namespace}.example"),
        claim_request_id: format!("local-last-resort:{namespace}-concurrent"),
        request_digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            .to_owned(),
        state: "last_resort_claimed".to_owned(),
        outcome: Some(serde_json::json!({"response": {"claims": ["concurrent"]}})),
        consume_receipt: None,
        terminal_receipt: None,
        keypackage_id: Some(format!("{namespace}-keypackage-last-resort")),
        claim_expires_at_unix_ms: None,
        expires_at: i64::MAX,
        updated_at: 10,
    };
    let first_writer = PgMlsKeyPackageStore {
        pool: restarted_store.pool.clone(),
    };
    let second_writer = PgMlsKeyPackageStore {
        pool: restarted_store.pool.clone(),
    };
    let (first_result, second_result) = tokio::join!(
        first_writer.record_peer_claim_terminal(&concurrent),
        second_writer.record_peer_claim_terminal(&concurrent)
    );
    let results = [
        first_result.expect("first concurrent ledger writer"),
        second_result.expect("second concurrent ledger writer"),
    ];
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, PeerKeyPackageClaimLedgerWriteResult::Inserted))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| {
                matches!(
                    result,
                    PeerKeyPackageClaimLedgerWriteResult::Existing(existing)
                        if **existing == concurrent
                )
            })
            .count(),
        1
    );
}

#[tokio::test]
async fn postgres_adapter_satisfies_organization_registration_contract_when_configured() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let store = PgOrganizationRegistrationStore::new(pool);
    let namespace = format!(
        "postgres-organization-registration-{}",
        uuid::Uuid::now_v7()
    );
    assert_organization_registration_store_contract(&store, &namespace).await;
}

#[tokio::test]
async fn postgres_account_data_cas_treats_an_absent_key_as_revision_zero_when_configured() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let store = PgAccountDataStore { pool };
    let key = format!("client.postgres-cas.{}", uuid::Uuid::now_v7());
    let actor = "did:web:postgres-cas.example";
    let invalid_create = AccountDataRecord {
        actor: actor.to_owned(),
        account_data_key: key.clone(),
        revision: 8,
        payload: serde_json::json!({"value": "must-not-land"}),
        tombstone: false,
        updated_at: chrono::Utc::now(),
    };
    assert!(matches!(
        store.compare_and_set(&invalid_create, 7).await.unwrap(),
        AccountDataCasResult::Conflict(None)
    ));
    assert!(store.get(actor, &key).await.unwrap().is_none());

    let created = AccountDataRecord {
        actor: actor.to_owned(),
        account_data_key: key.clone(),
        revision: 1,
        payload: serde_json::json!({"value": 1}),
        tombstone: false,
        updated_at: chrono::Utc::now(),
    };
    assert!(matches!(
        store.compare_and_set(&created, 0).await.unwrap(),
        AccountDataCasResult::Applied(record) if record.revision == 1
    ));
    assert!(matches!(
        store.compare_and_set(&created, 0).await.unwrap(),
        AccountDataCasResult::Conflict(Some(record)) if record.revision == 1
    ));
}
