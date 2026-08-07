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
    let event_id =
        arkret_identifiers::EventId::new(format!("ak:event:{}", uuid::Uuid::now_v7())).unwrap();
    let realm_id =
        arkret_identifiers::RealmId::new(format!("ak:realm:{}", uuid::Uuid::now_v7())).unwrap();
    let actor_id = arkret_identifiers::Did::new(format!(
        "did:web:managed-anchor-{}.example",
        uuid::Uuid::now_v7()
    ))
    .unwrap();
    let event = arkret_wire::Event::new_with_id_at(
        event_id.clone(),
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
    assert!(event.seal_basis.is_none());
    let proposal_digest = arkret_identifiers::Hash::new(event.event_digest().unwrap()).unwrap();
    let authority_set_ref =
        arkret_identifiers::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap();
    let member = arkret_wire::ControlProposalAuthorityAck {
        realm_id: realm_id.clone(),
        proposal_digest: proposal_digest.clone(),
        received_at: now,
        decision_due_at: now + chrono::Duration::hours(1),
        absolute_due_at: now + chrono::Duration::hours(2),
        authority_set_ref: authority_set_ref.clone(),
        signature: arkret_wire::PayloadSignature {
            verification_method: arkret_wire::DidUrl::new(
                "did:web:controller.example#device-1".to_owned(),
            )
            .unwrap(),
            payload_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "b".repeat(64)))
                .unwrap(),
            created_at: now,
            jws: "eyJhbGciOiJFZDI1NTE5In0..AQ".to_owned(),
            extra: Default::default(),
        },
    };
    let ack = arkret_wire::ControlProposalAck::from_authority_acks(
        vec![member],
        arkret_wire::ControlProposalDecisionPolicy::default(),
    )
    .unwrap();
    let envelope = serde_json::to_value(&event).unwrap();
    let canonical_bytes = arkret_canonical::canonical_json_bytes(&envelope).unwrap();
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
