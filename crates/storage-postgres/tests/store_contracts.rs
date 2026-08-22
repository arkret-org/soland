use soland_storage::contract_tests::{
    ConsentCommitContractStores, DeviceRevocationSealSettlementStores, EventCommitContractStores,
    assert_atomic_batch_outbox_rollback_contract,
    assert_atomic_control_event_governance_dependency_contract,
    assert_consent_projection_commit_contract,
    assert_control_proposal_authority_ack_store_contract,
    assert_device_message_snapshot_guard_contract,
    assert_device_revocation_seal_settlement_contract, assert_event_commit_unit_of_work_contract,
    assert_federation_outbox_store_contract, assert_governance_unscoped_signer_evidence_contract,
    assert_idempotency_store_contract, assert_last_resort_claim_ledger_contract,
    assert_mimi_consent_correlation_store_contract, assert_mls_keypackage_retirement_contract,
    assert_organization_registration_store_contract,
    assert_service_route_handover_plan_store_contract,
};
use soland_storage::{
    AccountDataCasResult, AccountDataRecord, AccountDataStore, MlsKeyPackageStore,
    PeerKeyPackageClaimLedgerRecord, PeerKeyPackageClaimLedgerWriteResult,
};
use soland_storage_postgres::{
    Db, PgAccountDataStore, PgContactStore, PgControlProposalAuthorityAckStore,
    PgDeviceInventoryStore, PgDeviceMessageStore, PgEventCommitUnitOfWork, PgEventStore,
    PgFederationOutboxStore, PgGovernanceDependencyStore, PgIdempotencyStore,
    PgInviteReceivePolicyStore, PgMimiConsentCorrelationStore, PgMlsKeyPackageStore,
    PgOrganizationRegistrationStore, PgPool, PgProjectionEventStore,
    PgServiceRouteHandoverPlanStore,
};

#[tokio::test]
async fn postgres_adapter_guards_repair_device_snapshots_atomically_when_configured() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let inventory = PgDeviceInventoryStore { pool: pool.clone() };
    let messages = PgDeviceMessageStore { pool };
    let namespace = format!("postgres-repair-snapshot-{}", uuid::Uuid::now_v7());
    assert_device_message_snapshot_guard_contract(&inventory, &messages, &namespace).await;
}

#[tokio::test]
async fn postgres_adapter_satisfies_service_route_handover_plan_contract_when_configured() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let store = PgServiceRouteHandoverPlanStore { pool };
    // The plan slot is keyed by service id, so each run needs its own core to
    // stay independent of whatever a previous case left behind.
    let service_id = arkret_wire::DidCoreId::new(format!(
        "ak:did_core:webvh:z{}",
        uuid::Uuid::now_v7().simple()
    ))
    .unwrap();
    assert_service_route_handover_plan_store_contract(&store, &service_id).await;
}

static TEST_POOL: tokio::sync::OnceCell<Option<PgPool>> = tokio::sync::OnceCell::const_new();

/// These contracts share one database and several of them exercise
/// row/advisory locking (`lock_organization`, the event-commit unit of work).
/// Running them concurrently against a single pool intermittently starves a
/// connection and surfaces as `Database("connection closed")` or a spurious
/// conflict, so each case holds this guard for its duration.
static DB_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn test_pool() -> Option<PgPool> {
    TEST_POOL
        .get_or_init(|| async {
            Db::connect(
                std::env::var("DATABASE_URL").ok().as_deref(),
                Default::default(),
            )
            .await
            .expect("initialize test database")
            .pool
        })
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
async fn postgres_adapter_satisfies_unscoped_signer_evidence_contract_when_configured() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let store = PgGovernanceDependencyStore { pool };
    let namespace = format!("postgres-unscoped-signer-{}", uuid::Uuid::now_v7());
    assert_governance_unscoped_signer_evidence_contract(&store, &namespace).await;
}

#[tokio::test]
async fn postgres_adapter_commits_control_event_governance_dependencies_atomically_when_configured()
{
    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let events = PgEventStore { pool: pool.clone() };
    let dependencies = PgGovernanceDependencyStore { pool };
    let namespace = format!("postgres-control-event-governance-{}", uuid::Uuid::now_v7());
    assert_atomic_control_event_governance_dependency_contract(&events, &dependencies, &namespace)
        .await;
}

#[tokio::test]
async fn postgres_adapter_satisfies_mimi_consent_correlation_contract_when_configured() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let store = PgMimiConsentCorrelationStore { pool };
    let namespace = format!("postgres-mimi-consent-{}", uuid::Uuid::now_v7());
    assert_mimi_consent_correlation_store_contract(&store, &namespace).await;
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
    let outbox = PgFederationOutboxStore { pool: pool.clone() };
    let device_pairings = soland_storage_postgres::PgDevicePairingStore { pool: pool.clone() };
    let contacts = PgContactStore { pool: pool.clone() };
    let invite_policies = PgInviteReceivePolicyStore { pool: pool.clone() };
    let namespace = format!("postgres-event-commit-{}", uuid::Uuid::now_v7());
    assert_event_commit_unit_of_work_contract(
        EventCommitContractStores {
            unit_of_work: &unit_of_work,
            events: &events,
            projections: &projections,
            idempotency: &idempotency,
            outbox: &outbox,
            device_pairings: &device_pairings,
            contacts: &contacts,
            invite_policies: &invite_policies,
        },
        &namespace,
    )
    .await;
}

#[tokio::test]
async fn postgres_adapter_satisfies_shared_consent_projection_commit_contract_when_configured() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let unit_of_work = PgEventCommitUnitOfWork::new(pool.clone());
    let events = PgEventStore { pool: pool.clone() };
    let consent_cells = soland_storage_postgres::PgConsentCellStore { pool: pool.clone() };
    let account_data = PgAccountDataStore { pool: pool.clone() };
    let namespace = format!("pg-consent-commit-{}", uuid::Uuid::now_v7());
    assert_consent_projection_commit_contract(
        ConsentCommitContractStores {
            unit_of_work: &unit_of_work,
            events: &events,
            consent_cells: &consent_cells,
            account_data: &account_data,
        },
        &namespace,
    )
    .await;
}

#[tokio::test]
async fn postgres_adapter_settles_sealed_device_revocations_when_configured() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let cell_registry: std::sync::Arc<dyn arkret_state::state::CellRegistry> = std::sync::Arc::new(
        soland_domain::reducer::lattice_kinds::try_build_validated_sdk_cell_registry()
            .expect("validated SDK cell registry"),
    );
    let stores =
        soland_storage_postgres::build_state_resolution_stores(Some(pool.clone()), cell_registry);
    let unit_of_work = PgEventCommitUnitOfWork::new(pool.clone());
    let revocations = soland_storage_postgres::PgDeviceRevocationStore { pool };
    let namespace = format!("pgrevseal{}", uuid::Uuid::now_v7().simple());
    assert_device_revocation_seal_settlement_contract(
        DeviceRevocationSealSettlementStores {
            unit_of_work: &unit_of_work,
            revocations: &revocations,
            control_events: stores.control_event_store.as_ref(),
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
    let actor_full_id = arkret_identifiers::DidFullId::new(format!(
        "did:web:managed-anchor-{}.example",
        uuid::Uuid::now_v7()
    ))
    .unwrap();
    let actor_id = arkret_wire::project_full_id_to_core_id(&actor_full_id)
        .map(arkret_identifiers::DidCoreId::from)
        .unwrap();
    // A genesis scope names no Realm; the Realm id is derived from this
    // Event's own id, so the fixture reads it back after construction.
    let event = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::RealmCreate.as_str(),
        arkret_wire::ScopeRef::RealmGenesis,
        actor_id,
        arkret_identifiers::DidCoreId::from(
            arkret_wire::project_full_id_to_core_id(
                &arkret_identifiers::DidFullId::new("did:web:service.example".to_owned()).unwrap(),
            )
            .unwrap(),
        ),
        0,
        arkret_identifiers::Hlc::new("019c00000000-0000-aabbccdd").unwrap(),
        serde_json::json!({"object": {"fields": {"purpose": "principal_control"}}}),
        now,
    )
    .unwrap();
    let event_id = event.event_id.clone();
    let realm_id = event.realm_id.clone();
    assert!(event.seal_basis.is_none());
    let proposal_digest = arkret_identifiers::Hash::new(
        event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap(),
    )
    .unwrap();
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
            governance_dependencies: Vec::new(),
            device_pairing_authorization: None,
            contact_projection: None,
            consent_projection: None,
            event: CanonicalEventRecord {
                event_id: event_id.to_string(),
                actor_id: event.actor_id.to_string(),
                actor_seq: 0,
                realm_id: Some(realm_id.to_string()),
                kind: arkret_wire::EventKind::RealmCreate.as_str().to_owned(),
                schema_id: "ak.schema.realm.v1".to_owned(),
                digest_suite: arkret_canonical::DigestSuite::Sha256,
                canonical_digest: proposal_digest.to_string(),
                canonical_bytes,
                envelope,
                received_at: now,
            },
            control_proposal_ingress: Some(
                arkret_state::state::store::ControlProposalIngress::AckRequired(ack),
            ),
            device_revocation_transition: None,
            device_revocation_gate: None,
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
    // The colliding event, its realm row and the quarantine evidence all stay
    // in the database by design, so every run needs its own identities or a
    // rerun collides with the previous run's residue.
    let run_id = uuid::Uuid::now_v7();
    let preimage = format!("validated-digest-preimage-{run_id}").into_bytes();
    let digest = arkret_canonical::sha256_bytes(&preimage);
    let mut id = [0_u8; ids::EVENT_ID_BYTES];
    id[0] = 0x01;
    id[1..].copy_from_slice(&digest);
    let event_id = ids::format_event_id(&id);
    let canonical_digest = ids::format_event_digest(0x01, &digest).unwrap();
    let now = chrono::Utc::now();
    let realm_id =
        event_derived_realm_id(format!("postgres-collision-contract-realm-{run_id}").as_bytes());
    let actor_id = format!("did:web:collision-{run_id}.example");
    let incoming = CanonicalEventRecord {
        event_id: event_id.clone(),
        actor_id: actor_id.clone(),
        actor_seq: 0,
        realm_id: Some(realm_id.clone()),
        kind: "ak.test.data".to_owned(),
        schema_id: "arkret://events/test/v1".to_owned(),
        digest_suite: arkret_canonical::DigestSuite::Sha256,
        canonical_digest: canonical_digest.clone(),
        canonical_bytes: preimage,
        envelope: serde_json::json!({"variant": "incoming", "proofs": [{"jws": "full-evidence"}]}),
        received_at: now,
    };
    let mut conn = pool.get().await.unwrap();
    let realm_identity = ids::realm_identity_parts(&realm_id).unwrap();
    let realm_pk = sql_query(
        "INSERT INTO canonical_realms \
         (id, digest_suite, digest, wire_id) \
         VALUES ($1, $2, $3, $4) RETURNING pk",
    )
    .bind::<Binary, _>(realm_identity.id.to_vec())
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
         (id, peer_id, peer_url, endpoint, idempotency_key, payload_json, next_attempt_at, created_at) \
         VALUES ($1, 'did:web:peer.example', 'https://peer.example', '/events', $1, '{}', 0, 0)",
    )
    .bind::<Text, _>(&outbox_id)
    .execute(&mut conn)
    .await
    .unwrap();
    sql_query("INSERT INTO event_federation_outbox (event_pk, outbox_id) VALUES ($1, $2)")
        .bind::<BigInt, _>(event_pk)
        .bind::<Text, _>(&outbox_id)
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
         (event_digest, digest_suite, realm_id, event_json, ingress_class) \
         VALUES ($1, 'sha256', $2, '{}'::jsonb, '{\"class\":\"ack_required\"}'::jsonb)",
    )
    .bind::<Text, _>(&canonical_digest)
    .bind::<Text, _>(&realm_id)
    .execute(&mut conn)
    .await
    .unwrap();
    sql_query(
        "INSERT INTO state_seals \
         (id, digest_suite, realm_id, seal_id_preimage_bytes, accepted_seal_bytes, seal_json, predecessor_refs, is_genesis) \
         VALUES ('ak:seal:test', 'sha256', $1, decode('00', 'hex'), decode('00', 'hex'), \
                 '{}'::jsonb, '[]'::jsonb, true)",
    )
    .bind::<Text, _>(&realm_id)
    .execute(&mut conn)
    .await
    .unwrap();
    sql_query(
        "INSERT INTO state_seal_control_events \
         (seal_id, realm_id, event_digest, delta_index, accepted_event_bytes_digest, \
          accepted_event_bytes, sealed_at, decision_overdue) \
         VALUES ('ak:seal:test', $1, $2, 0, $2, decode('00', 'hex'), $3, false)",
    )
    .bind::<Text, _>(&realm_id)
    .bind::<Text, _>(&canonical_digest)
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
                    governance_dependencies: Vec::new(),
                    device_pairing_authorization: None,
                    contact_projection: None,
                    consent_projection: None,
                    event: prefix,
                    control_proposal_ingress: None,
                    device_revocation_transition: None,
                    device_revocation_gate: None,
                    projections: Vec::new(),
                    idempotency: None,
                    outbox: Vec::new(),
                },
                EventCommitRequest {
                    governance_dependencies: Vec::new(),
                    device_pairing_authorization: None,
                    contact_projection: None,
                    consent_projection: None,
                    event: incoming,
                    control_proposal_ingress: None,
                    device_revocation_transition: None,
                    device_revocation_gate: None,
                    projections: Vec::new(),
                    idempotency: None,
                    outbox: Vec::new(),
                },
            ],
            applet_ghosts: None,
            agent_membership_cascade: None,
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

// ── S2 durable-ingress atomicity negatives ───────────────────────────────────
//
// A Control Move commits as one indivisible triple: the accepted Event row,
// its Control Proposal Ack (for the Ack-required class), and the pending
// `state_control_events` row. These cases prove against a real database that
// no partial shape — Event-only, Ack-only, pending-only — can be committed,
// and that a replay under a different ingress class is a Conflict.

mod control_move_ingress_negatives {
    use diesel::sql_types::{BigInt, Binary, Jsonb, Text};
    use diesel::{QueryableByName, sql_query};
    use diesel_async::RunQueryDsl;
    use soland_storage::{CanonicalEventRecord, EventCommitRequest, EventCommitUnitOfWork, ids};
    use soland_storage_postgres::PgEventCommitUnitOfWork;

    use super::{DB_GUARD, test_pool};

    #[derive(QueryableByName)]
    struct CountRow {
        #[diesel(sql_type = BigInt)]
        value: i64,
    }

    struct ControlAnchorFixture {
        event: arkret_wire::Event,
        realm_id: arkret_identifiers::RealmId,
        proposal_digest: arkret_identifiers::Hash,
        ack: arkret_wire::ControlProposalAck,
        canonical_bytes: Vec<u8>,
    }

    /// A basis-free genesis anchor (a Control Move), built exactly as the
    /// positive anchor-commit case above does.
    fn control_anchor_fixture(seed: &str) -> ControlAnchorFixture {
        let now = chrono::Utc::now();
        let actor_full_id = arkret_identifiers::DidFullId::new(format!(
            "did:web:ingress-negative-{seed}-{}.example",
            uuid::Uuid::now_v7()
        ))
        .unwrap();
        let actor_id = arkret_wire::project_full_id_to_core_id(&actor_full_id)
            .map(arkret_identifiers::DidCoreId::from)
            .unwrap();
        // A genesis scope names no Realm; the Realm id is derived from this
        // Event's own id, so the fixture reads it back after construction.
        // Anything the commit path re-parses from the envelope resolves the
        // same id, which is what the Ack must bind.
        let event = arkret_wire::test_support::raw_event_at(
            arkret_wire::EventKind::RealmCreate.as_str(),
            arkret_wire::ScopeRef::RealmGenesis,
            actor_id,
            arkret_identifiers::DidCoreId::from(
                arkret_wire::project_full_id_to_core_id(
                    &arkret_identifiers::DidFullId::new("did:web:service.example".to_owned())
                        .unwrap(),
                )
                .unwrap(),
            ),
            0,
            arkret_identifiers::Hlc::new("019c00000000-0000-aabbccdd").unwrap(),
            serde_json::json!({"object": {"fields": {"purpose": "principal_control"}}}),
            now,
        )
        .unwrap();
        let realm_id = event.realm_id.clone();
        let digest_suite = arkret_canonical::DigestSuite::Sha256;
        let proposal_digest = arkret_identifiers::Hash::new(
            event.event_digest_with_digest_suite(digest_suite).unwrap(),
        )
        .unwrap();
        let authority_set_ref =
            arkret_identifiers::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap();
        // The durable ingress path validates the aggregate Ack's protocol
        // bounds, so the fixture needs one well-formed authority Ack: its
        // signature digest must cover the member's canonical bytes, though the
        // JWS itself is not verified at admission.
        let mut authority_ack = arkret_wire::ControlProposalAuthorityAck {
            realm_id: realm_id.clone(),
            proposal_digest: proposal_digest.clone(),
            received_at: now,
            decision_due_at: now + chrono::Duration::hours(1),
            absolute_due_at: now + chrono::Duration::hours(2),
            authority_set_ref: authority_set_ref.clone(),
            signature: arkret_wire::PayloadSignature {
                verification_method: arkret_wire::DidUrl::new(
                    "did:web:authority.example#notary-1".to_owned(),
                )
                .unwrap(),
                payload_digest: authority_set_ref.clone(),
                created_at: now,
                jws: "fixture-jws".to_owned(),
                extra: Default::default(),
            },
        };
        authority_ack.signature.payload_digest = authority_ack.authority_ack_digest().unwrap();
        let ack = arkret_wire::ControlProposalAck {
            kind: arkret_wire::ControlProposalAckKind::SignedAck,
            realm_id: realm_id.clone(),
            proposal_digest: proposal_digest.clone(),
            received_at: now,
            decision_due_at: now + chrono::Duration::hours(1),
            absolute_due_at: now + chrono::Duration::hours(2),
            defer_count: 0,
            authority_set_ref,
            authority_acks: vec![authority_ack],
        };
        let canonical_bytes =
            arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
        ControlAnchorFixture {
            event,
            realm_id,
            proposal_digest,
            ack,
            canonical_bytes,
        }
    }

    impl ControlAnchorFixture {
        fn commit_request(
            &self,
            ingress: Option<arkret_state::state::store::ControlProposalIngress>,
        ) -> EventCommitRequest {
            EventCommitRequest {
                governance_dependencies: Vec::new(),
                device_pairing_authorization: None,
                contact_projection: None,
                consent_projection: None,
                event: CanonicalEventRecord {
                    event_id: self.event.event_id.to_string(),
                    actor_id: self.event.actor_id.to_string(),
                    actor_seq: 0,
                    realm_id: Some(self.realm_id.to_string()),
                    kind: arkret_wire::EventKind::RealmCreate.as_str().to_owned(),
                    schema_id: "ak.schema.realm.v1".to_owned(),
                    digest_suite: arkret_canonical::DigestSuite::Sha256,
                    canonical_digest: self.proposal_digest.to_string(),
                    canonical_bytes: self.canonical_bytes.clone(),
                    envelope: serde_json::to_value(&self.event).unwrap(),
                    received_at: chrono::Utc::now(),
                },
                control_proposal_ingress: ingress,
                device_revocation_transition: None,
                device_revocation_gate: None,
                projections: Vec::new(),
                idempotency: None,
                outbox: Vec::new(),
            }
        }

        async fn canonical_event_rows(&self, pool: &soland_storage_postgres::PgPool) -> i64 {
            let identity = ids::validated_event_identity_parts(
                self.event.event_id.as_str(),
                self.proposal_digest.as_str(),
                &self.canonical_bytes,
            )
            .unwrap();
            let mut conn = pool.get().await.unwrap();
            sql_query("SELECT COUNT(*) AS value FROM canonical_events WHERE id = $1")
                .bind::<Binary, _>(identity.id.to_vec())
                .get_result::<CountRow>(&mut *conn)
                .await
                .unwrap()
                .value
        }

        async fn pending_rows(&self, pool: &soland_storage_postgres::PgPool) -> i64 {
            let mut conn = pool.get().await.unwrap();
            sql_query("SELECT COUNT(*) AS value FROM state_control_events WHERE event_digest = $1")
                .bind::<Text, _>(self.proposal_digest.as_str())
                .get_result::<CountRow>(&mut *conn)
                .await
                .unwrap()
                .value
        }
    }

    /// Event-only: a Control Move presented without its durable ingress
    /// classification commits nothing at all.
    #[tokio::test]
    async fn postgres_control_move_without_ingress_commits_nothing_when_configured() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let _db_guard = DB_GUARD.lock().await;
        let fixture = control_anchor_fixture("event-only");

        let error = PgEventCommitUnitOfWork::new(pool.clone())
            .commit_event(fixture.commit_request(None))
            .await
            .expect_err("a Control Move without ingress classification must be rejected");
        assert!(
            error
                .to_string()
                .contains("missing its durable ingress classification"),
            "unexpected rejection: {error}"
        );
        assert_eq!(fixture.canonical_event_rows(&pool).await, 0);
        assert_eq!(fixture.pending_rows(&pool).await, 0);
    }

    /// Ack-only: an Ack that does not bind the Control Move's digest commits
    /// nothing at all.
    #[tokio::test]
    async fn postgres_control_move_with_unbound_ack_commits_nothing_when_configured() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let _db_guard = DB_GUARD.lock().await;
        let fixture = control_anchor_fixture("ack-only");
        let mut ack = fixture.ack.clone();
        ack.proposal_digest =
            arkret_identifiers::Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap();

        let error = PgEventCommitUnitOfWork::new(pool.clone())
            .commit_event(fixture.commit_request(Some(
                arkret_state::state::store::ControlProposalIngress::AckRequired(ack),
            )))
            .await
            .expect_err("an Ack that does not bind the Control Move must be rejected");
        assert!(
            error
                .to_string()
                .contains("Control Proposal Ack does not bind"),
            "unexpected rejection: {error}"
        );
        assert_eq!(fixture.canonical_event_rows(&pool).await, 0);
        assert_eq!(fixture.pending_rows(&pool).await, 0);
    }

    /// Pending-only: when the pending-row leg cannot land (a conflicting
    /// durable row for the same digest), the accepted-Event leg rolls back
    /// with it; the pre-existing row is left untouched.
    #[tokio::test]
    async fn postgres_control_move_pending_conflict_rolls_back_the_event_when_configured() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let _db_guard = DB_GUARD.lock().await;
        let fixture = control_anchor_fixture("pending-only");
        {
            let mut conn = pool.get().await.unwrap();
            sql_query(
                "INSERT INTO state_control_events \
                 (event_digest, realm_id, event_json, control_proposal_ack, ingress_class) \
                 VALUES ($1, $2, $3, NULL, $4)",
            )
            .bind::<Text, _>(fixture.proposal_digest.as_str())
            .bind::<Text, _>(fixture.realm_id.as_str())
            .bind::<Jsonb, _>(serde_json::json!({"variant": "conflicting-canonical-bytes"}))
            .bind::<Jsonb, _>(serde_json::json!({"class": "ack_required"}))
            .execute(&mut *conn)
            .await
            .unwrap();
        }

        let error = PgEventCommitUnitOfWork::new(pool.clone())
            .commit_event(fixture.commit_request(Some(
                arkret_state::state::store::ControlProposalIngress::AckRequired(
                    fixture.ack.clone(),
                ),
            )))
            .await
            .expect_err("a pending-row conflict must reject the whole commit");
        assert!(
            error.to_string().contains("duplicate_conflict"),
            "unexpected rejection: {error}"
        );
        assert_eq!(
            fixture.canonical_event_rows(&pool).await,
            0,
            "the Event row must roll back with its failed pending leg"
        );
        assert_eq!(fixture.pending_rows(&pool).await, 1);
        let mut conn = pool.get().await.unwrap();
        let ackless = sql_query(
            "SELECT COUNT(*) AS value FROM state_control_events \
             WHERE event_digest = $1 AND control_proposal_ack IS NULL",
        )
        .bind::<Text, _>(fixture.proposal_digest.as_str())
        .get_result::<CountRow>(&mut *conn)
        .await
        .unwrap()
        .value;
        assert_eq!(ackless, 1, "the conflicting row must not absorb the Ack");
    }

    /// Class mismatch: the first admission's ingress class is part of the
    /// durable basis; replaying the same digest under the other class is a
    /// Conflict, while a byte-identical replay stays idempotent.
    #[tokio::test(flavor = "multi_thread")]
    async fn postgres_control_move_ingress_class_mismatch_is_conflict_when_configured() {
        use arkret_state::state::store::{
            AcklessSelfPrincipalIngress, ControlProposalIngress, StoreError,
        };

        let Some(pool) = test_pool().await else {
            return;
        };
        let _db_guard = DB_GUARD.lock().await;
        let fixture = control_anchor_fixture("class-mismatch");
        let stores = soland_storage_postgres::build_state_resolution_stores(
            Some(pool),
            std::sync::Arc::new(arkret_state::state::MemoryCellRegistry::default()),
        );

        stores
            .control_event_store
            .put_pending_with_ingress(
                &fixture.event,
                &ControlProposalIngress::AckRequired(fixture.ack.clone()),
                arkret_canonical::DigestSuite::Sha256,
            )
            .unwrap();
        let ackless = ControlProposalIngress::AcklessSelfPrincipal(AcklessSelfPrincipalIngress {
            device_id: "ak:device:fixture".to_owned(),
            device_authorize_event_id: "ak:event:fixture".to_owned(),
            device_generation_ref: 1,
            seal_basis_digest: "sha256:fixture".to_owned(),
        });
        assert!(
            matches!(
                stores.control_event_store.put_pending_with_ingress(
                    &fixture.event,
                    &ackless,
                    arkret_canonical::DigestSuite::Sha256,
                ),
                Err(StoreError::Conflict(_))
            ),
            "an Ack-required Move cannot be replayed as Ack-less"
        );
        stores
            .control_event_store
            .put_pending_with_ingress(
                &fixture.event,
                &ControlProposalIngress::AckRequired(fixture.ack.clone()),
                arkret_canonical::DigestSuite::Sha256,
            )
            .expect("the byte-identical class and Ack remain idempotent");
    }
}
