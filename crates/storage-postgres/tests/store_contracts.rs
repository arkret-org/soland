use soland_storage::contract_tests::{
    AppletFormalCommitContractStores, ConsentCommitContractStores,
    DeviceRevocationSealSettlementStores, EventCommitContractStores,
    assert_applet_formal_commit_transaction_contract, assert_atomic_batch_outbox_rollback_contract,
    assert_atomic_control_event_governance_dependency_contract,
    assert_consent_projection_commit_contract,
    assert_control_proposal_authority_ack_store_contract,
    assert_device_message_snapshot_guard_contract,
    assert_device_revocation_seal_settlement_contract, assert_event_commit_unit_of_work_contract,
    assert_federation_outbox_store_contract, assert_governance_unscoped_signer_evidence_contract,
    assert_idempotency_store_contract, assert_last_resort_claim_ledger_contract,
    assert_mimi_consent_correlation_store_contract, assert_mls_keypackage_retirement_contract,
    assert_organization_registration_store_contract, minimal_history_signer_evidence,
};
use soland_storage::{
    AccountDataCasResult, AccountDataRecord, AccountDataStore, AccountNotificationDeltaWrite,
    AgentPrincipalRecord, AgentStore, AppletAuthoringPreviewRecord, AppletStore,
    GovernanceDependencySource, GovernanceDependencyStore, GovernanceDependencyWrite,
    MlsKeyPackageStore, NotificationStore, PeerKeyPackageClaimLedgerRecord,
    PeerKeyPackageClaimLedgerWriteResult,
};
use soland_storage_postgres::{
    Db, PgAccountDataStore, PgAgentStore, PgAppletStore, PgContactStore,
    PgControlProposalAuthorityAckStore, PgDeviceInventoryStore, PgDeviceMessageStore,
    PgEventCommitUnitOfWork, PgEventStore, PgFederationOutboxStore, PgGovernanceDependencyStore,
    PgIdempotencyStore, PgInviteReceivePolicyStore, PgMimiConsentCorrelationStore,
    PgMlsKeyPackageStore, PgNotificationStore, PgOrganizationRegistrationStore, PgPool,
    PgProjectionEventStore,
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

static TEST_POOL: tokio::sync::OnceCell<Option<PgPool>> = tokio::sync::OnceCell::const_new();

/// These contracts share one database and several of them exercise
/// row/advisory locking (`lock_organization`, the event-commit unit of work).
/// Running them concurrently against a single pool intermittently starves a
/// connection and surfaces as `Database("connection closed")` or a spurious
/// conflict, so each case holds this guard for its duration.
static DB_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(diesel::QueryableByName)]
struct TimestampRow {
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    value: chrono::DateTime<chrono::Utc>,
}

#[derive(diesel::QueryableByName)]
struct LedgerCountRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    value: i64,
}

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

fn franking_event_request(
    realm_id: &arkret_identifiers::RealmId,
    actor_id: arkret_wire::DidCoreId,
    station_id: &arkret_wire::DidCoreId,
    marker: u64,
    kind: &str,
    payload: serde_json::Value,
    received_at: chrono::DateTime<chrono::Utc>,
) -> soland_storage::EventCommitRequest {
    let event = arkret_wire::test_support::raw_event_at(
        kind,
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        actor_id.clone(),
        station_id.clone(),
        0,
        arkret_identifiers::Hlc::new(format!("019f00000000-{marker:04x}-aabbccdd")).unwrap(),
        payload,
        received_at,
    )
    .unwrap();
    let canonical_digest = event
        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    let canonical_bytes =
        arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
    soland_storage::EventCommitRequest {
        governance_dependencies: Vec::new(),
        membership_compensation_evidence: None,
        device_pairing_authorization: None,
        contact_projection: None,
        consent_projection: None,
        event: soland_storage::CanonicalEventRecord {
            event_id: event.event_id.to_string(),
            actor_id: actor_id.to_string(),
            actor_seq: 0,
            realm_id: Some(realm_id.to_string()),
            kind: kind.to_owned(),
            schema_id: "ak.schema.franking_fixture.v1".to_owned(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
            canonical_digest,
            canonical_bytes,
            envelope: serde_json::to_value(event).unwrap(),
            received_at,
        },
        control_proposal_ingress: None,
        device_revocation_transition: None,
        device_revocation_gate: None,
        projections: Vec::new(),
        idempotency: None,
        outbox: Vec::new(),
    }
}

#[tokio::test]
async fn postgres_franking_nonce_ledger_is_bounded_atomic_and_restart_stable_when_configured() {
    use diesel::sql_types::{BigInt, Text, Timestamptz};
    use diesel_async::RunQueryDsl;
    use soland_storage::{
        EventBatchCommitRequest, EventCommitUnitOfWork, EventStore, FrankingReplayNonceCommit,
        PersistenceError,
    };

    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let realm_id = arkret_identifiers::RealmId::new(event_derived_realm_id(
        format!("franking-ledger:{}", uuid::Uuid::now_v7()).as_bytes(),
    ))
    .unwrap();
    let received_by =
        arkret_wire::DidCoreId::new("ak:did_core:web:franking-ledger.example".to_owned()).unwrap();
    let make_request =
        |marker: u64, replay_nonce: &str, consumed_at: chrono::DateTime<chrono::Utc>| {
            let actor_id = arkret_wire::DidCoreId::new(format!(
                "ak:did_core:web:franking-reporter-{marker}.example"
            ))
            .unwrap();
            let event = franking_event_request(
                &realm_id,
                actor_id,
                &received_by,
                marker,
                arkret_wire::EventKind::SelfModerationReport.as_str(),
                serde_json::json!({
                    "franking_proof": {
                        "received_by": received_by.as_str(),
                        "replay_nonce": replay_nonce,
                    }
                }),
                consumed_at,
            );
            let event_id = event.event.event_id.clone();
            (
                event,
                FrankingReplayNonceCommit {
                    realm_id: realm_id.to_string(),
                    received_by: received_by.clone(),
                    replay_nonce: replay_nonce.to_owned(),
                    report_event_id: event_id,
                    consumed_at,
                },
            )
        };
    let commit = |event, nonce| EventBatchCommitRequest {
        events: vec![event],
        agent_approval_nonce: None,
        franking_replay_nonce: Some(nonce),
        applet_record: None,
        applet_authoring_preview: None,
        agent_membership_cascade: None,
    };
    let consumed_at =
        chrono::DateTime::from_timestamp_micros(chrono::Utc::now().timestamp_micros()).unwrap();
    let replay_nonce = "shared_nonce_0123456789";
    let (first_event, first_nonce) = make_request(1, replay_nonce, consumed_at);
    let first_event_id = first_event.event.event_id.clone();
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event_batch(commit(first_event, first_nonce))
        .await
        .unwrap();

    // Treat the successful write above as a lost response: reconstruct the
    // adapter and retry the same durable nonce with a competing Event.
    let (replay_event, replay_commit) =
        make_request(2, replay_nonce, consumed_at + chrono::TimeDelta::seconds(1));
    let replay_event_id = replay_event.event.event_id.clone();
    let replay_error = PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event_batch(commit(replay_event, replay_commit))
        .await
        .unwrap_err();
    assert!(matches!(
        replay_error,
        PersistenceError::Conflict(reason) if reason == "duplicate_conflict"
    ));
    let event_store = PgEventStore { pool: pool.clone() };
    assert!(event_store.contains(&first_event_id).await.unwrap());
    assert!(!event_store.contains(&replay_event_id).await.unwrap());

    let expires_at = soland_storage::franking_replay_nonce_expires_at(consumed_at).unwrap();
    let mut conn = pool.get().await.unwrap();
    let stored_expiry = diesel::sql_query(
        "SELECT expires_at AS value FROM moderation_franking_replay_nonces \
         WHERE realm_id = $1 AND received_by = $2 AND replay_nonce = $3",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(received_by.as_str())
    .bind::<Text, _>(replay_nonce)
    .get_result::<TimestampRow>(&mut conn)
    .await
    .unwrap()
    .value;
    assert_eq!(stored_expiry, expires_at);

    let (just_before_event, just_before_nonce) = make_request(
        5,
        replay_nonce,
        expires_at - chrono::TimeDelta::microseconds(1),
    );
    let just_before_event_id = just_before_event.event.event_id.clone();
    let just_before_error = PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event_batch(commit(just_before_event, just_before_nonce))
        .await
        .unwrap_err();
    assert!(matches!(
        just_before_error,
        PersistenceError::Conflict(reason) if reason == "duplicate_conflict"
    ));
    assert!(!event_store.contains(&just_before_event_id).await.unwrap());

    let (at_expiry_event, at_expiry_nonce) = make_request(6, replay_nonce, expires_at);
    let at_expiry_event_id = at_expiry_event.event.event_id.clone();
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event_batch(commit(at_expiry_event, at_expiry_nonce))
        .await
        .unwrap();
    assert!(event_store.contains(&at_expiry_event_id).await.unwrap());

    diesel::sql_query(
        "INSERT INTO moderation_franking_replay_nonces \
         (realm_id, received_by, replay_nonce, report_event_id, consumed_at, expires_at) \
         VALUES ($1, $2, 'expired_nonce_0123456789', $3, $4, $5)",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(received_by.as_str())
    .bind::<Text, _>(format!("expired-report-{}", uuid::Uuid::now_v7()))
    .bind::<Timestamptz, _>(consumed_at - chrono::TimeDelta::hours(25))
    .bind::<Timestamptz, _>(consumed_at - chrono::TimeDelta::hours(1))
    .execute(&mut conn)
    .await
    .unwrap();
    drop(conn);
    let (after_expiry_event, after_expiry_nonce) = make_request(
        3,
        "after_expiry_nonce_0123456789",
        consumed_at + chrono::TimeDelta::seconds(2),
    );
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event_batch(commit(after_expiry_event, after_expiry_nonce))
        .await
        .unwrap();
    let mut conn = pool.get().await.unwrap();
    let expired_count = diesel::sql_query(
        "SELECT COUNT(*) AS value FROM moderation_franking_replay_nonces \
         WHERE replay_nonce = 'expired_nonce_0123456789'",
    )
    .get_result::<LedgerCountRow>(&mut conn)
    .await
    .unwrap()
    .value;
    assert_eq!(expired_count, 0);

    diesel::sql_query(
        "DELETE FROM moderation_franking_replay_nonces \
         WHERE realm_id = $1 AND received_by = $2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(received_by.as_str())
    .execute(&mut conn)
    .await
    .unwrap();
    diesel::sql_query(
        "INSERT INTO moderation_franking_replay_nonces \
         (realm_id, received_by, replay_nonce, report_event_id, consumed_at, expires_at) \
         SELECT $1, $2, 'capacity_nonce_' || n, 'capacity_report_' || n, $3, $4 \
         FROM generate_series(1, $5) AS n",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(received_by.as_str())
    .bind::<Timestamptz, _>(consumed_at)
    .bind::<Timestamptz, _>(expires_at)
    .bind::<BigInt, _>(
        i64::try_from(soland_storage::LOCAL_FRANKING_REPLAY_NONCE_MAX_ACTIVE_PER_SCOPE).unwrap(),
    )
    .execute(&mut conn)
    .await
    .unwrap();
    drop(conn);
    let (overflow_event, overflow_nonce) = make_request(
        4,
        "overflow_nonce_0123456789",
        consumed_at + chrono::TimeDelta::seconds(3),
    );
    let overflow_event_id = overflow_event.event.event_id.clone();
    let overflow_error = PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event_batch(commit(overflow_event, overflow_nonce))
        .await
        .unwrap_err();
    assert!(matches!(
        overflow_error,
        PersistenceError::Conflict(reason) if reason == "duplicate_conflict"
    ));
    assert!(!event_store.contains(&overflow_event_id).await.unwrap());
    let mut conn = pool.get().await.unwrap();
    let active_count = diesel::sql_query(
        "SELECT COUNT(*) AS value FROM moderation_franking_replay_nonces \
         WHERE realm_id = $1 AND received_by = $2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(received_by.as_str())
    .get_result::<LedgerCountRow>(&mut conn)
    .await
    .unwrap()
    .value;
    assert_eq!(
        active_count,
        i64::try_from(soland_storage::LOCAL_FRANKING_REPLAY_NONCE_MAX_ACTIVE_PER_SCOPE).unwrap()
    );
}

#[tokio::test]
async fn postgres_franking_target_proof_fault_and_restart_contract_when_configured() {
    use soland_storage::{
        EventBatchCommitRequest, EventCommitUnitOfWork, EventStore, PersistenceError,
    };

    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let realm_id = arkret_identifiers::RealmId::new(event_derived_realm_id(
        format!("franking-target-proof:{}", uuid::Uuid::now_v7()).as_bytes(),
    ))
    .unwrap();
    let received_by =
        arkret_wire::DidCoreId::new("ak:did_core:web:franking-service.example".to_owned()).unwrap();
    let created_at =
        chrono::DateTime::from_timestamp_micros(chrono::Utc::now().timestamp_micros()).unwrap();
    let target = franking_event_request(
        &realm_id,
        arkret_wire::DidCoreId::new("ak:did_core:web:franking-sender.example".to_owned()).unwrap(),
        &received_by,
        100,
        arkret_wire::EventKind::MessageCreate.as_str(),
        serde_json::json!({"encrypted_content": {"ciphertext": "fixture"}}),
        created_at,
    );
    let target_event_id = target.event.event_id.clone();
    let mut proof = franking_event_request(
        &realm_id,
        received_by.clone(),
        &received_by,
        101,
        arkret_wire::EventKind::ModerationFrankingProof.as_str(),
        serde_json::json!({"event_id": target_event_id}),
        created_at,
    );
    let proof_event_id = proof.event.event_id.clone();
    let clean_schema_id = proof.event.schema_id.clone();
    proof.event.schema_id.push('\0');
    let failing_batch = EventBatchCommitRequest {
        events: vec![target.clone(), proof.clone()],
        agent_approval_nonce: None,
        franking_replay_nonce: None,
        applet_record: None,
        applet_authoring_preview: None,
        agent_membership_cascade: None,
    };

    let database_error = PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event_batch(failing_batch)
        .await
        .unwrap_err();
    assert!(matches!(database_error, PersistenceError::Database(_)));
    let event_store = PgEventStore { pool: pool.clone() };
    assert!(!event_store.contains(&target_event_id).await.unwrap());
    assert!(!event_store.contains(&proof_event_id).await.unwrap());
    assert!(
        event_store
            .franking_proofs_for_target(realm_id.as_str(), &received_by, &target_event_id)
            .await
            .unwrap()
            .is_empty(),
        "a database error while inserting the proof must roll back its target prefix"
    );

    proof.event.schema_id = clean_schema_id;
    let clean_batch = EventBatchCommitRequest {
        events: vec![target, proof],
        agent_approval_nonce: None,
        franking_replay_nonce: None,
        applet_record: None,
        applet_authoring_preview: None,
        agent_membership_cascade: None,
    };
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event_batch(clean_batch.clone())
        .await
        .unwrap();

    // Model a lost success response by reconstructing the adapter without
    // carrying the first outcome into the retry. This is not a process-kill
    // claim; it proves only the durable retry boundary.
    let retry = PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event_batch(clean_batch)
        .await
        .unwrap();
    assert_eq!(retry, soland_storage::EventCommitOutcome::default());
    assert_eq!(
        event_store
            .franking_proofs_for_target(realm_id.as_str(), &received_by, &target_event_id)
            .await
            .unwrap()
            .len(),
        1,
        "restart retry must not materialize a second proof Event"
    );
}

#[tokio::test]
async fn postgres_agent_store_accepts_spec_managed_agent_binding_when_configured() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let store = PgAgentStore { pool: pool.clone() };
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let scid = format!("zTest{suffix}");
    let agent_id = format!("ak:did_core:webvh:{scid}");
    let did = format!("did:webvh:{scid}:agent.example");
    let now = chrono::DateTime::from_timestamp_micros(chrono::Utc::now().timestamp_micros())
        .expect("timestamp round-trip");
    let record = AgentPrincipalRecord::new(
        agent_id.clone(),
        "ak:did_core:web:controller.example".to_owned(),
        event_derived_realm_id(agent_id.as_bytes()),
        arkret_wire::DidUrl::new(format!("{did}#managed-controller")).unwrap(),
        arkret_models_collaboration::agent_operations::AgentLifecycleState::Active,
        now,
    );

    store
        .put(record.clone())
        .await
        .expect("spec-valid managed Agent binding must persist");
    assert_eq!(store.get(&agent_id).await.unwrap(), Some(record));

    use diesel::sql_types::Text;
    use diesel_async::RunQueryDsl;
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("DELETE FROM agent_principals WHERE id = $1")
        .bind::<Text, _>(&agent_id)
        .execute(&mut *conn)
        .await
        .unwrap();
}

#[tokio::test]
async fn postgres_agent_table_rejects_mismatched_did_and_core_agent_ids_when_configured() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let agent_id = format!("ak:did_core:webvh:zLeft{suffix}");
    let authorization_ref = format!("did:webvh:zRight{suffix}:agent.example#managed-controller");
    let realm_id = event_derived_realm_id(agent_id.as_bytes());
    let now = chrono::DateTime::from_timestamp_micros(chrono::Utc::now().timestamp_micros())
        .expect("timestamp round-trip");

    use diesel::sql_types::{Text, Timestamptz};
    use diesel_async::RunQueryDsl;
    let mut conn = pool.get().await.unwrap();
    let error = diesel::sql_query(
        "INSERT INTO agent_principals \
         (id, controller_id, principal_control_realm_id, controller_authorization_ref, \
          created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $5)",
    )
    .bind::<Text, _>(&agent_id)
    .bind::<Text, _>("ak:did_core:web:controller.example")
    .bind::<Text, _>(&realm_id)
    .bind::<Text, _>(&authorization_ref)
    .bind::<Timestamptz, _>(now)
    .execute(&mut *conn)
    .await
    .expect_err("database must reject a DID that projects to a different Agent core id");
    assert!(
        error
            .to_string()
            .contains("agent_principals_controller_authorization_ref_check"),
        "{error}"
    );
}

fn event_derived_realm_id(seed: &[u8]) -> String {
    let event_id = arkret_identifiers::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(seed),
    );
    arkret_identifiers::RealmId::from_event_id(&event_id).to_string()
}

#[derive(diesel::QueryableByName)]
struct ScheduleCountRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    value: i64,
}

async fn control_seal_schedule_row_count(pool: &PgPool, realm_id: Option<&str>) -> i64 {
    use diesel::sql_types::{Nullable, Text};
    use diesel_async::RunQueryDsl;

    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT COUNT(*) AS value FROM state_control_seal_schedule \
         WHERE ($1::text IS NULL OR realm_id = $1)",
    )
    .bind::<Nullable<Text>, _>(realm_id)
    .get_result::<ScheduleCountRow>(&mut *conn)
    .await
    .unwrap()
    .value
}

async fn prioritize_control_seal_schedule_test_realm(pool: &PgPool, realm_id: &str) {
    use diesel::sql_types::Text;
    use diesel_async::RunQueryDsl;

    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "WITH priority AS ( \
           SELECT GREATEST(COALESCE(MIN(next_attempt_at_ms), 0), -9223372036854775807) - 1 AS at_ms \
           FROM state_control_seal_schedule WHERE realm_id <> $1 \
         ) \
         UPDATE state_control_seal_schedule schedule \
         SET next_attempt_at_ms = priority.at_ms, first_pending_at_ms = priority.at_ms \
         FROM priority WHERE schedule.realm_id = $1",
    )
    .bind::<Text, _>(realm_id)
    .execute(&mut *conn)
    .await
    .unwrap();
}

async fn cleanup_control_schedule_test_actor(pool: &PgPool, actor_id: &str) {
    use diesel::sql_types::Text;
    use diesel_async::RunQueryDsl;

    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "DELETE FROM governance_dependency_edges edge USING state_control_events event \
         WHERE edge.event_digest = event.event_digest AND edge.realm_id = event.realm_id \
           AND event.event_json->>'actor_id' = $1",
    )
    .bind::<Text, _>(actor_id)
    .execute(&mut *conn)
    .await
    .unwrap();
    diesel::sql_query(
        "DELETE FROM state_control_seal_schedule schedule USING state_control_events event \
         WHERE schedule.realm_id = event.realm_id AND event.event_json->>'actor_id' = $1",
    )
    .bind::<Text, _>(actor_id)
    .execute(&mut *conn)
    .await
    .unwrap();
    diesel::sql_query("DELETE FROM state_control_events WHERE event_json->>'actor_id' = $1")
        .bind::<Text, _>(actor_id)
        .execute(&mut *conn)
        .await
        .unwrap();
    diesel::sql_query("DELETE FROM canonical_events WHERE actor_id = $1")
        .bind::<Text, _>(actor_id)
        .execute(&mut *conn)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn postgres_control_seal_schedule_fences_generation_expiry_and_repair_when_configured() {
    use arkret_state::state::store::{AcklessSelfPrincipalIngress, ControlProposalIngress};
    use arkret_state::state::{ControlSealAttemptCompletion, ControlSealAttemptOutcome};
    use diesel::sql_types::Text;
    use diesel_async::RunQueryDsl;

    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let realm_id = arkret_identifiers::RealmId::new(event_derived_realm_id(
        format!("control-seal-schedule:{}", uuid::Uuid::now_v7()).as_bytes(),
    ))
    .unwrap();
    let mut cleanup_conn = pool.get().await.unwrap();
    diesel::sql_query("DELETE FROM state_control_seal_schedule WHERE realm_id = $1")
        .bind::<Text, _>(realm_id.as_str())
        .execute(&mut *cleanup_conn)
        .await
        .unwrap();
    diesel::sql_query("DELETE FROM state_control_events WHERE realm_id = $1")
        .bind::<Text, _>(realm_id.as_str())
        .execute(&mut *cleanup_conn)
        .await
        .unwrap();
    drop(cleanup_conn);
    let stores = soland_storage_postgres::build_state_resolution_stores(
        Some(pool.clone()),
        std::sync::Arc::new(arkret_state::state::MemoryCellRegistry::default()),
    );
    let ingress = ControlProposalIngress::AcklessSelfPrincipal(AcklessSelfPrincipalIngress {
        device_id: "ak:device:schedule-contract".to_owned(),
        device_authorize_event_id: "ak:event:schedule-contract".to_owned(),
        device_generation_ref: 1,
        seal_basis_digest: format!("sha256:{}", "a".repeat(64)),
    });
    let (first_event, _) = seal_dependency_contract_event(&realm_id, "schedule-first");
    stores
        .control_event_store
        .put_pending_with_ingress(
            &first_event,
            &ingress,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
    prioritize_control_seal_schedule_test_realm(&pool, realm_id.as_str()).await;
    let now_ms = chrono::Utc::now().timestamp_millis().saturating_add(1_000);
    let claim_store = stores.control_event_store.clone();
    let first_claim = tokio::task::spawn_blocking(move || {
        claim_store.claim_due_control_seal_realms("worker-a", now_ms, now_ms + 1_000, 1)
    })
    .await
    .expect("coordinator-style blocking claim task")
    .unwrap()
    .pop()
    .unwrap();
    assert_eq!(first_claim.generation, 1);

    stores
        .control_event_store
        .put_pending_with_ingress(
            &first_event,
            &ingress,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
    assert_eq!(
        stores
            .control_event_store
            .complete_control_seal_attempt(
                &first_claim,
                &ControlSealAttemptOutcome::SigningFailed,
                now_ms,
            )
            .unwrap(),
        ControlSealAttemptCompletion::Applied,
        "an idempotent Event replay must not bump generation"
    );
    prioritize_control_seal_schedule_test_realm(&pool, realm_id.as_str()).await;
    let second_claim = stores
        .control_event_store
        .claim_due_control_seal_realms("worker-a", now_ms + 1_000, now_ms + 2_000, 1)
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(second_claim.generation, 1);

    let (second_event, _) = seal_dependency_contract_event(&realm_id, "schedule-second");
    stores
        .control_event_store
        .put_pending_with_ingress(
            &second_event,
            &ingress,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
    prioritize_control_seal_schedule_test_realm(&pool, realm_id.as_str()).await;
    assert_eq!(
        stores
            .control_event_store
            .complete_control_seal_attempt(
                &second_claim,
                &ControlSealAttemptOutcome::SigningFailed,
                now_ms + 1_001,
            )
            .unwrap(),
        ControlSealAttemptCompletion::ReleasedNewGeneration
    );
    let third_claim = stores
        .control_event_store
        .claim_due_control_seal_realms("worker-a", now_ms + 1_001, now_ms + 1_101, 1)
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(third_claim.generation, 2);
    let active_stats = stores
        .control_event_store
        .control_seal_schedule_stats(now_ms + 1_100)
        .unwrap();
    assert!(active_stats.pending >= 1);
    assert!(active_stats.claimed >= 1);
    let expired_stats = stores
        .control_event_store
        .control_seal_schedule_stats(now_ms + 1_101)
        .unwrap();
    assert!(expired_stats.eligible >= 1);
    assert!(expired_stats.expired_claims >= 1);
    let reclaimed = stores
        .control_event_store
        .claim_due_control_seal_realms("worker-b", now_ms + 1_101, now_ms + 2_000, 1)
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(reclaimed.fence, third_claim.fence + 1);
    assert_eq!(
        stores
            .control_event_store
            .complete_control_seal_attempt(
                &third_claim,
                &ControlSealAttemptOutcome::ProgressPublished,
                now_ms + 1_102,
            )
            .unwrap(),
        ControlSealAttemptCompletion::StaleClaim
    );

    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("DELETE FROM state_control_seal_schedule WHERE realm_id = $1")
        .bind::<Text, _>(realm_id.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    let mut repair_inserted = 0;
    for repair_round in 0..2 {
        repair_inserted += stores
            .control_event_store
            .repair_control_seal_schedule(now_ms + 1_200 + repair_round, 4_096)
            .unwrap()
            .inserted;
        if control_seal_schedule_row_count(&pool, Some(realm_id.as_str())).await == 1 {
            break;
        }
    }
    assert!(repair_inserted >= 1);
    assert_eq!(
        control_seal_schedule_row_count(&pool, Some(realm_id.as_str())).await,
        1
    );
    let mut cleanup_conn = pool.get().await.unwrap();
    diesel::sql_query("DELETE FROM state_control_seal_schedule WHERE realm_id = $1")
        .bind::<Text, _>(realm_id.as_str())
        .execute(&mut *cleanup_conn)
        .await
        .unwrap();
    diesel::sql_query("DELETE FROM state_control_events WHERE realm_id = $1")
        .bind::<Text, _>(realm_id.as_str())
        .execute(&mut *cleanup_conn)
        .await
        .unwrap();
}

fn seal_dependency_contract_event(
    realm_id: &arkret_identifiers::RealmId,
    marker: &str,
) -> (arkret_wire::Event, arkret_identifiers::Hash) {
    let actor = arkret_wire::project_did_to_core_id(
        &arkret_wire::Did::new("did:web:seal-dependency-holder.example".to_owned()).unwrap(),
    )
    .unwrap();
    let event = arkret_wire::test_support::raw_event_at(
        "ak.test.control",
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        actor.clone(),
        actor,
        0,
        arkret_wire::Hlc::new("019f00000000-0000-00000001").unwrap(),
        serde_json::json!({"marker": marker}),
        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
    )
    .unwrap();
    let digest =
        arkret_state::state::control_event_digest(&event, arkret_canonical::DigestSuite::Sha256)
            .unwrap();
    (event, digest)
}

fn seal_dependency_contract_availability(
    event: &arkret_wire::Event,
    marker: &str,
) -> arkret_models_collaboration::governance_dependencies::GovernanceDependency {
    use arkret_models_collaboration::governance_dependencies::{
        GovernanceDependency, GovernanceDependencySelector,
    };

    let created_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let evidence_digest = arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(format!(
        "seal-dependency-evidence:{marker}"
    )))
    .unwrap();
    let mut receipt = arkret_wire::AvailabilityReceipt {
        realm_id: event.realm_id.clone(),
        event_id: event.event_id.clone(),
        bytes_digest: arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(format!(
            "seal-dependency-event-bytes:{marker}"
        )))
        .unwrap(),
        holder_id: event.actor_id.signing_principal_id().clone(),
        retention_expires_at: created_at + chrono::Duration::days(1),
        holder_signer_evidence_ref: arkret_wire::SignerEvidenceRef::new(format!(
            "ak:signer_evidence:{}",
            evidence_digest.as_str()
        ))
        .unwrap(),
        holder_signer_evidence_digest: evidence_digest,
        signature: arkret_wire::PayloadProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: arkret_wire::DidUrl::new(
                "did:web:seal-dependency-holder.example#key-1".to_owned(),
            )
            .unwrap(),
            payload_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
                .unwrap(),
            created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "eyJhbGciOiJFZDI1NTE5In0..AQ".to_owned(),
        },
    };
    receipt.signature.payload_digest = arkret_identifiers::Hash::new(arkret_canonical::digest(
        arkret_canonical::DigestSuite::Sha256,
        receipt.canonical_signature_payload_bytes().unwrap(),
    ))
    .unwrap();
    let content_digest = receipt
        .full_receipt_digest(|bytes| {
            Ok(arkret_identifiers::Hash::new(arkret_canonical::digest(
                arkret_canonical::DigestSuite::Sha256,
                bytes,
            ))?)
        })
        .unwrap();
    GovernanceDependency::AvailabilityReceipt {
        selector: GovernanceDependencySelector::AvailabilityReceipt { content_digest },
        availability_receipt: receipt,
    }
}

fn seal_dependency_contract_digest(
    dependency: &arkret_models_collaboration::governance_dependencies::GovernanceDependency,
) -> arkret_identifiers::Hash {
    let arkret_models_collaboration::governance_dependencies::GovernanceDependency::AvailabilityReceipt {
        selector:
            arkret_models_collaboration::governance_dependencies::GovernanceDependencySelector::AvailabilityReceipt {
                content_digest,
            },
        ..
    } = dependency
    else {
        panic!("contract dependency is an AvailabilityReceipt");
    };
    content_digest.clone()
}

fn seal_dependency_contract_seal(
    realm_id: &arkret_identifiers::RealmId,
    predecessor_refs: Vec<arkret_identifiers::SealId>,
    delta: arkret_identifiers::Hash,
    covered: &std::collections::BTreeSet<arkret_identifiers::Hash>,
    availability_digest: arkret_identifiers::Hash,
) -> arkret_wire::Seal {
    let root =
        arkret_state::state::control_event_set_root(covered, arkret_canonical::DigestSuite::Sha256)
            .unwrap();
    let state_root =
        arkret_state::state::compute_state_root(
            &std::collections::BTreeMap::<
                arkret_identifiers::CellRef,
                arkret_state::lattice::CellState,
            >::new(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
    let mut seal = arkret_wire::Seal {
        id: arkret_identifiers::SealId::new(format!("ak:seal:sha256:{}", "0".repeat(64))).unwrap(),
        realm_id: realm_id.clone(),
        predecessor_refs,
        delta: vec![delta],
        control_event_set_root: root.clone(),
        state_root,
        completeness_root: root,
        notary_seq: 0,
        data_view_root: None,
        data_event_set_root: None,
        availability_receipt_digests: vec![availability_digest],
        covered_event_digests: Vec::new(),
        previous_state_root: None,
        previous_digest_algorithm: None,
        notary_signature: arkret_wire::NotarySig::Single(arkret_wire::SealSignature {
            verification_method: arkret_wire::DidUrl::new(
                "did:web:seal-dependency-holder.example#notary-key".to_owned(),
            )
            .unwrap(),
            payload_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
                .unwrap(),
            jws: "eyJhbGciOiJFZDI1NTE5In0..AQ".to_owned(),
        }),
        sealed_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
        hlc: arkret_wire::Hlc::new("019f00000000-0000-00000002").unwrap(),
    };
    seal.id = seal
        .derive_id(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    seal
}

#[derive(diesel::QueryableByName)]
struct SealDependencyAtomicCounts {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    seals: i64,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    cell_ops: i64,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    sealed_markers: i64,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    dependency_objects: i64,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    dependency_edges: i64,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    data_event_manifests: i64,
}

async fn seal_dependency_atomic_counts(
    pool: &PgPool,
    seal_id: &arkret_identifiers::SealId,
    object_digest: &arkret_identifiers::Hash,
) -> SealDependencyAtomicCounts {
    use diesel::sql_types::Text;
    use diesel_async::RunQueryDsl;

    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT \
           (SELECT COUNT(*) FROM state_seals WHERE id = $1) AS seals, \
           (SELECT COUNT(*) FROM state_cell_ops WHERE seal_id = $1) AS cell_ops, \
           (SELECT COUNT(*) FROM state_seal_control_events WHERE seal_id = $1) AS sealed_markers, \
           (SELECT COUNT(*) FROM governance_dependency_objects WHERE object_digest = $2) AS dependency_objects, \
           (SELECT COUNT(*) FROM governance_dependency_edges WHERE seal_id = $1) AS dependency_edges, \
           (SELECT COUNT(*) FROM state_seal_data_event_manifests WHERE seal_id = $1) AS data_event_manifests",
    )
    .bind::<Text, _>(seal_id.as_str())
    .bind::<Text, _>(object_digest.as_str())
    .get_result(&mut conn)
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn postgres_event_seal_commit_retains_dependencies_at_the_frontier_cas_boundary_when_configured()
 {
    use arkret_models_collaboration::governance_dependencies::{
        GovernanceDependency, GovernanceDependencySelector,
    };
    use arkret_state::state::store::{AcklessSelfPrincipalIngress, ControlProposalIngress};
    use soland_storage::{
        GovernanceDependencySource, GovernanceDependencyStore, GovernanceDependencyWrite,
    };

    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let registry: std::sync::Arc<dyn arkret_state::state::CellRegistry> = std::sync::Arc::new(
        soland_domain::reducer::lattice_kinds::try_build_validated_sdk_cell_registry()
            .expect("validated SDK cell registry"),
    );
    let stores =
        soland_storage_postgres::build_state_resolution_stores(Some(pool.clone()), registry);
    let dependency_store = PgGovernanceDependencyStore { pool: pool.clone() };
    let realm_id = arkret_identifiers::RealmId::new(event_derived_realm_id(
        format!("seal-dependency-atomic:{}", uuid::Uuid::now_v7()).as_bytes(),
    ))
    .unwrap();
    let ingress = ControlProposalIngress::AcklessSelfPrincipal(AcklessSelfPrincipalIngress {
        device_id: "ak:device:01904100-0000-7000-8000-000000000001".to_owned(),
        device_authorize_event_id: format!("ak:event:{}", "b".repeat(43)),
        device_generation_ref: 1,
        seal_basis_digest: format!("sha256:{}", "c".repeat(64)),
    });

    let (genesis_event, genesis_digest) =
        seal_dependency_contract_event(&realm_id, "genesis-success");
    stores
        .control_event_store
        .put_pending_with_ingress(
            &genesis_event,
            &ingress,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
    let genesis_dependency =
        seal_dependency_contract_availability(&genesis_event, "genesis-success");
    let genesis_object_digest = seal_dependency_contract_digest(&genesis_dependency);
    let genesis_covered = [genesis_digest.clone()]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    let mut genesis_seal = seal_dependency_contract_seal(
        &realm_id,
        Vec::new(),
        genesis_digest.clone(),
        &genesis_covered,
        genesis_object_digest.clone(),
    );
    let genesis_manifest =
        [arkret_identifiers::Hash::new(format!("sha256:{}", "d".repeat(64))).unwrap()]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
    genesis_seal.data_event_set_root = Some(
        arkret_state::event_digest_set_root(
            &genesis_manifest,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap(),
    );
    genesis_seal.id = genesis_seal
        .derive_id(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    let genesis_write = GovernanceDependencyWrite {
        realm_id: realm_id.clone(),
        source: GovernanceDependencySource::Seal(genesis_seal.id.clone()),
        edge_index: 0,
        item: genesis_dependency.clone(),
    };
    assert!(
        stores
            .event_seal_committer
            .commit_if_frontier(
                &genesis_seal,
                arkret_canonical::DigestSuite::Sha256,
                &[],
                &[],
                &genesis_covered,
                &genesis_manifest,
                std::slice::from_ref(&genesis_write),
            )
            .unwrap()
    );
    let committed =
        seal_dependency_atomic_counts(&pool, &genesis_seal.id, &genesis_object_digest).await;
    assert_eq!(committed.seals, 1);
    assert_eq!(committed.cell_ops, 0);
    assert_eq!(committed.sealed_markers, 1);
    assert_eq!(committed.dependency_objects, 1);
    assert_eq!(committed.dependency_edges, 1);
    assert_eq!(committed.data_event_manifests, 1);
    assert_eq!(
        stores
            .event_seal_committer
            .data_event_leaf_manifest(&genesis_seal.id)
            .unwrap(),
        Some(genesis_manifest.clone())
    );
    let restarted = soland_storage_postgres::build_state_resolution_stores(
        Some(pool.clone()),
        stores.cell_registry.clone(),
    );
    assert_eq!(
        restarted
            .event_seal_committer
            .data_event_leaf_manifest(&genesis_seal.id)
            .unwrap(),
        Some(genesis_manifest.clone()),
        "a reconstructed PostgreSQL adapter must return the byte-identical frozen manifest"
    );
    assert_eq!(
        stores
            .control_event_store
            .covering_seals(&genesis_digest)
            .unwrap(),
        vec![genesis_seal.id.clone()]
    );
    assert_eq!(
        dependency_store
            .list_for_source(
                &realm_id,
                &GovernanceDependencySource::Seal(genesis_seal.id.clone()),
            )
            .await
            .unwrap(),
        vec![soland_storage::GovernanceDependencyEdgeRecord {
            edge_index: 0,
            item: genesis_dependency.clone(),
        }]
    );

    assert!(
        stores
            .event_seal_committer
            .commit_if_frontier(
                &genesis_seal,
                arkret_canonical::DigestSuite::Sha256,
                &[],
                &[],
                &genesis_covered,
                &genesis_manifest,
                std::slice::from_ref(&genesis_write),
            )
            .unwrap(),
        "an exact retry must observe the same complete dependency set"
    );
    let replay_mismatch =
        seal_dependency_contract_availability(&genesis_event, "exact-retry-mismatch");
    let replay_mismatch_digest = seal_dependency_contract_digest(&replay_mismatch);
    let replay_error = stores
        .event_seal_committer
        .commit_if_frontier(
            &genesis_seal,
            arkret_canonical::DigestSuite::Sha256,
            &[],
            &[],
            &genesis_covered,
            &genesis_manifest,
            &[GovernanceDependencyWrite {
                realm_id: realm_id.clone(),
                source: GovernanceDependencySource::Seal(genesis_seal.id.clone()),
                edge_index: 0,
                item: replay_mismatch,
            }],
        )
        .unwrap_err();
    assert!(
        replay_error
            .to_string()
            .contains("different governance dependencies")
    );
    let replay_counts =
        seal_dependency_atomic_counts(&pool, &genesis_seal.id, &replay_mismatch_digest).await;
    assert_eq!(replay_counts.dependency_objects, 0);
    assert_eq!(replay_counts.dependency_edges, 1);

    for failure in ["realm", "source", "index", "object"] {
        let marker = format!("binding-failure-{failure}");
        let (event, event_digest) = seal_dependency_contract_event(&realm_id, &marker);
        stores
            .control_event_store
            .put_pending_with_ingress(&event, &ingress, arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        let mut dependency = seal_dependency_contract_availability(&event, &marker);
        if failure == "object" {
            let GovernanceDependency::AvailabilityReceipt { selector, .. } = &mut dependency else {
                unreachable!();
            };
            *selector = GovernanceDependencySelector::AvailabilityReceipt {
                content_digest: arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(
                    format!("invalid-object:{marker}"),
                ))
                .unwrap(),
            };
        }
        let object_digest = seal_dependency_contract_digest(&dependency);
        let covered = [genesis_digest.clone(), event_digest.clone()]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        let seal = seal_dependency_contract_seal(
            &realm_id,
            vec![genesis_seal.id.clone()],
            event_digest.clone(),
            &covered,
            object_digest.clone(),
        );
        let mut write = GovernanceDependencyWrite {
            realm_id: realm_id.clone(),
            source: GovernanceDependencySource::Seal(seal.id.clone()),
            edge_index: 0,
            item: dependency,
        };
        match failure {
            "realm" => {
                write.realm_id = arkret_identifiers::RealmId::new(event_derived_realm_id(
                    format!("wrong-realm:{marker}").as_bytes(),
                ))
                .unwrap();
            }
            "source" => {
                write.source = GovernanceDependencySource::ControlEvent(event_digest.clone());
            }
            "index" => write.edge_index = 1,
            "object" => {}
            _ => unreachable!(),
        }
        stores
            .event_seal_committer
            .commit_if_frontier(
                &seal,
                arkret_canonical::DigestSuite::Sha256,
                std::slice::from_ref(&genesis_seal.id),
                &[],
                &covered,
                &std::collections::BTreeSet::new(),
                &[write],
            )
            .unwrap_err();
        let counts = seal_dependency_atomic_counts(&pool, &seal.id, &object_digest).await;
        assert_eq!(counts.seals, 0, "{failure} failure leaked a Seal");
        assert_eq!(counts.cell_ops, 0, "{failure} failure leaked cell ops");
        assert_eq!(
            counts.sealed_markers, 0,
            "{failure} failure leaked a sealed marker"
        );
        assert_eq!(
            counts.dependency_objects, 0,
            "{failure} failure leaked a dependency object"
        );
        assert_eq!(
            counts.dependency_edges, 0,
            "{failure} failure leaked a dependency edge"
        );
        assert_eq!(
            counts.data_event_manifests, 0,
            "{failure} failure leaked a DataEvent manifest"
        );
        assert!(
            stores
                .control_event_store
                .covering_seals(&event_digest)
                .unwrap()
                .is_empty()
        );
    }

    let (cas_event, cas_digest) = seal_dependency_contract_event(&realm_id, "cas-loss");
    stores
        .control_event_store
        .put_pending_with_ingress(&cas_event, &ingress, arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    let cas_dependency = seal_dependency_contract_availability(&cas_event, "cas-loss");
    let cas_object_digest = seal_dependency_contract_digest(&cas_dependency);
    let cas_covered = [genesis_digest, cas_digest.clone()]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    let cas_seal = seal_dependency_contract_seal(
        &realm_id,
        vec![genesis_seal.id.clone()],
        cas_digest.clone(),
        &cas_covered,
        cas_object_digest.clone(),
    );
    let cas_write = GovernanceDependencyWrite {
        realm_id,
        source: GovernanceDependencySource::Seal(cas_seal.id.clone()),
        edge_index: 0,
        item: cas_dependency,
    };
    let root_mismatch_manifest =
        [arkret_identifiers::Hash::new(format!("sha256:{}", "e".repeat(64))).unwrap()]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
    let root_mismatch = stores
        .event_seal_committer
        .commit_if_frontier(
            &cas_seal,
            arkret_canonical::DigestSuite::Sha256,
            &[],
            &[],
            &cas_covered,
            &root_mismatch_manifest,
            std::slice::from_ref(&cas_write),
        )
        .unwrap_err();
    assert!(
        root_mismatch
            .to_string()
            .contains("data_event_set_root mismatch")
    );
    let root_mismatch_counts =
        seal_dependency_atomic_counts(&pool, &cas_seal.id, &cas_object_digest).await;
    assert_eq!(root_mismatch_counts.seals, 0);
    assert_eq!(root_mismatch_counts.data_event_manifests, 0);
    assert!(
        !stores
            .event_seal_committer
            .commit_if_frontier(
                &cas_seal,
                arkret_canonical::DigestSuite::Sha256,
                &[],
                &[],
                &cas_covered,
                &std::collections::BTreeSet::new(),
                &[cas_write],
            )
            .unwrap()
    );
    let cas_counts = seal_dependency_atomic_counts(&pool, &cas_seal.id, &cas_object_digest).await;
    assert_eq!(cas_counts.seals, 0);
    assert_eq!(cas_counts.cell_ops, 0);
    assert_eq!(cas_counts.sealed_markers, 0);
    assert_eq!(cas_counts.dependency_objects, 0);
    assert_eq!(cas_counts.dependency_edges, 0);
    assert_eq!(cas_counts.data_event_manifests, 0);
    assert!(
        stores
            .control_event_store
            .covering_seals(&cas_digest)
            .unwrap()
            .is_empty()
    );

    use diesel::sql_types::Text;
    use diesel_async::RunQueryDsl;
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("DELETE FROM state_seal_data_event_manifests WHERE seal_id = $1")
        .bind::<Text, _>(genesis_seal.id.as_str())
        .execute(&mut conn)
        .await
        .unwrap();
    let missing_manifest_retry = stores
        .event_seal_committer
        .commit_if_frontier(
            &genesis_seal,
            arkret_canonical::DigestSuite::Sha256,
            &[],
            &[],
            &genesis_covered,
            &genesis_manifest,
            std::slice::from_ref(&genesis_write),
        )
        .unwrap_err();
    assert!(
        missing_manifest_retry
            .to_string()
            .contains("different or missing DataEvent leaf manifest")
    );
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
async fn postgres_account_notification_upsert_and_remove_stream_as_typed_deltas_when_configured() {
    use diesel::{QueryableByName, sql_query};
    use diesel_async::RunQueryDsl;

    #[derive(QueryableByName)]
    struct AccountNotificationStorageRow {
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
        notification_kind: Option<String>,
        #[diesel(sql_type = diesel::sql_types::Text)]
        projection_action: String,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Jsonb>)]
        projection_data: Option<serde_json::Value>,
    }

    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let store = PgNotificationStore { pool: pool.clone() };
    let run_id = uuid::Uuid::now_v7();
    let notification_uuid = uuid::Uuid::now_v7();
    let notification_id =
        arkret_wire::NotificationId::new(format!("ak:notification:{notification_uuid}")).unwrap();
    let controller_account_pk = soland_storage::AccountPk(1);
    let recipient_actor_id = arkret_wire::ActorId::hosted_principal(
        arkret_wire::DidCoreId::new(format!("ak:did_core:web:notification-{run_id}.example"))
            .unwrap(),
        arkret_wire::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
    );
    let recipient_id =
        arkret_wire::DidCoreId::new(format!("ak:did_core:web:controller-{run_id}.example"))
            .unwrap();
    let artifact_id = format!("agent_runtime_approval:{run_id}");
    let approval_request_id = arkret_wire::OpaqueLocalId::new(artifact_id.clone()).unwrap();
    let agent_id =
        arkret_wire::DidCoreId::new(format!("ak:did_core:web:agent-{run_id}.example")).unwrap();
    let timestamp = |value: &str| {
        chrono::DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&chrono::Utc)
    };

    let upsert = |expires_at: &str| {
        arkret_models_collaboration::sync_frames::account_sync::NotificationDelta::try_new(
            notification_id.clone(),
            arkret_models_collaboration::sync_frames::account_sync::NotificationDeltaAction::Upsert,
            Some(
                arkret_models_collaboration::sync_frames::account_sync::NotificationData::AgentRuntimeApproval(
                    arkret_models_collaboration::sync_frames::account_sync::AgentRuntimeApprovalNotificationData {
                        approval_request_id: approval_request_id.clone(),
                        agent_id: agent_id.clone(),
                        requested_at: timestamp("2026-08-26T10:00:00.000Z"),
                        expires_at: timestamp(expires_at),
                    },
                ),
            ),
        )
        .unwrap()
    };
    let write = |delta| AccountNotificationDeltaWrite {
        delta,
        recipient_actor_id: recipient_actor_id.clone(),
        controller_account_pk,
        recipient_id: recipient_id.clone(),
        source_account_artifact_id: artifact_id.clone(),
    };

    store
        .put_account_delta(write(upsert("2026-08-26T10:15:00.000Z")))
        .await
        .unwrap();
    let inserted = store
        .list_for_account(&controller_account_pk, recipient_id.as_str(), None)
        .await
        .unwrap();
    assert_eq!(inserted.len(), 1);
    assert_eq!(
        inserted[0].record.delta.action,
        arkret_models_collaboration::sync_frames::account_sync::NotificationDeltaAction::Upsert
    );
    assert!(
        store
            .list_for_recipient(recipient_id.as_str())
            .await
            .unwrap()
            .is_empty(),
        "account-private deltas must not enter the generic Event notification projection"
    );
    let mut conn = pool.get().await.unwrap();
    let stored = sql_query(
        "SELECT notification_kind, projection_action, projection_data \
         FROM notifications WHERE id = $1",
    )
    .bind::<diesel::sql_types::Uuid, _>(notification_uuid)
    .get_result::<AccountNotificationStorageRow>(&mut *conn)
    .await
    .unwrap();
    assert!(stored.notification_kind.is_none());
    assert_eq!(stored.projection_action, "upsert");
    assert!(
        stored
            .projection_data
            .as_ref()
            .is_some_and(|data| data.get("kind").is_none())
    );
    drop(conn);
    let inserted_position = inserted[0].projection_position;

    store
        .put_account_delta(write(upsert("2026-08-26T10:20:00.000Z")))
        .await
        .unwrap();
    let updated = store
        .list_for_account(
            &controller_account_pk,
            recipient_id.as_str(),
            Some(inserted_position),
        )
        .await
        .unwrap();
    assert_eq!(updated.len(), 1);
    assert!(updated[0].projection_position > inserted_position);
    assert_eq!(
        updated[0]
            .record
            .delta
            .agent_runtime_approval()
            .unwrap()
            .expires_at,
        timestamp("2026-08-26T10:20:00.000Z")
    );
    let updated_position = updated[0].projection_position;

    let removal =
        arkret_models_collaboration::sync_frames::account_sync::NotificationDelta::try_new(
            notification_id,
            arkret_models_collaboration::sync_frames::account_sync::NotificationDeltaAction::Remove,
            Some(
                arkret_models_collaboration::sync_frames::account_sync::NotificationData::AgentRuntimeApprovalRemoval(
                    arkret_models_collaboration::sync_frames::account_sync::AgentRuntimeApprovalNotificationRemovalData {
                        reason: arkret_models_collaboration::sync_frames::account_sync::AgentRuntimeApprovalRemovalReason::Approved,
                    },
                ),
            ),
        )
        .unwrap();
    store.put_account_delta(write(removal)).await.unwrap();
    let removed = store
        .list_for_account(
            &controller_account_pk,
            recipient_id.as_str(),
            Some(updated_position),
        )
        .await
        .unwrap();
    assert_eq!(removed.len(), 1);
    assert_eq!(
        removed[0].record.delta.action,
        arkret_models_collaboration::sync_frames::account_sync::NotificationDeltaAction::Remove
    );
    assert!(removed[0].record.delta.agent_runtime_approval().is_none());
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
async fn postgres_adapter_retains_seal_dependencies_before_seal_publication_when_configured() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let store = PgGovernanceDependencyStore { pool };
    let namespace = format!(
        "postgres-prepublish-seal-dependency-{}",
        uuid::Uuid::now_v7()
    );
    let realm_id = arkret_wire::RealmId::new(event_derived_realm_id(namespace.as_bytes())).unwrap();
    let seal_id = arkret_wire::SealId::new(format!(
        "ak:seal:sha256:{}",
        arkret_canonical::sha256_hex(namespace.as_bytes())
    ))
    .unwrap();
    let source = GovernanceDependencySource::Seal(seal_id);
    let item = minimal_history_signer_evidence(&namespace);

    store
        .put_exact(GovernanceDependencyWrite {
            realm_id: realm_id.clone(),
            source: source.clone(),
            edge_index: 0,
            item: item.clone(),
        })
        .await
        .expect("retain dependency before its candidate Seal is published");

    let retained = store
        .list_for_source(&realm_id, &source)
        .await
        .expect("read pre-published Seal dependency");
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].item, item);
}

#[tokio::test]
async fn postgres_adapter_commits_control_event_governance_dependencies_and_control_seal_schedule_atomically_when_configured()
 {
    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let events = PgEventStore { pool: pool.clone() };
    let dependencies = PgGovernanceDependencyStore { pool: pool.clone() };
    let namespace = format!("postgres-control-event-governance-{}", uuid::Uuid::now_v7());
    let before = control_seal_schedule_row_count(&pool, None).await;
    assert_atomic_control_event_governance_dependency_contract(&events, &dependencies, &namespace)
        .await;
    assert_eq!(
        control_seal_schedule_row_count(&pool, None).await,
        before + 1,
        "the PgEventStore Control Event path must atomically create its schedule row"
    );
    cleanup_control_schedule_test_actor(&pool, &format!("ak:did_core:web:{namespace}.example"))
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
async fn postgres_adapter_satisfies_formal_applet_commit_transaction_contract_when_configured() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let unit_of_work = PgEventCommitUnitOfWork::new(pool.clone());
    let events = PgEventStore { pool: pool.clone() };
    let applets = PgAppletStore { pool };
    let namespace = format!("postgres-formal-applet-{}", uuid::Uuid::now_v7().simple());
    assert_applet_formal_commit_transaction_contract(
        AppletFormalCommitContractStores {
            unit_of_work: &unit_of_work,
            events: &events,
            applets: &applets,
        },
        &namespace,
    )
    .await;
}

#[tokio::test]
async fn postgres_applet_authoring_preview_has_one_durable_exact_winner_when_configured() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let _db_guard = DB_GUARD.lock().await;
    let store = PgAppletStore { pool };
    let subject_key = format!("applet-preview:{}", uuid::Uuid::now_v7());
    let now = chrono::Utc::now();
    let candidate = |basis: &str, request: &str, issued_at: chrono::DateTime<chrono::Utc>| {
        AppletAuthoringPreviewRecord {
            subject_key: subject_key.clone(),
            basis_digest: basis.to_owned(),
            request_digest: request.to_owned(),
            signed_request: serde_json::json!({"request": request}),
            issued_at,
            expires_at: issued_at + chrono::Duration::minutes(5),
        }
    };
    let first = candidate("basis-a", "request-a", now);
    assert_eq!(
        store
            .issue_authoring_preview(first.clone())
            .await
            .unwrap()
            .signed_request,
        first.signed_request
    );
    assert_eq!(
        store
            .issue_authoring_preview(candidate(
                "basis-a",
                "request-a-new-signature",
                now + chrono::Duration::seconds(1),
            ))
            .await
            .unwrap()
            .request_digest,
        "request-a"
    );
    assert_eq!(
        store
            .issue_authoring_preview(candidate(
                "basis-b",
                "request-b",
                now + chrono::Duration::seconds(2),
            ))
            .await
            .unwrap()
            .request_digest,
        "request-b"
    );
    assert_eq!(
        store
            .issue_authoring_preview(candidate(
                "basis-b",
                "request-b-reissued",
                now + chrono::Duration::minutes(7),
            ))
            .await
            .unwrap()
            .request_digest,
        "request-b-reissued"
    );
    assert_eq!(
        store
            .current_authoring_preview(&subject_key)
            .await
            .unwrap()
            .unwrap()
            .request_digest,
        "request-b-reissued"
    );
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

#[tokio::test(flavor = "multi_thread")]
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
async fn postgres_event_commit_indexes_basis_free_control_anchor_and_control_seal_schedule_when_configured()
 {
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
    let actor_did = arkret_identifiers::Did::new(format!(
        "did:web:managed-anchor-{}.example",
        uuid::Uuid::now_v7()
    ))
    .unwrap();
    let actor_id = arkret_wire::project_did_to_core_id(&actor_did).unwrap();
    // A genesis scope names no Realm; the Realm id is derived from this
    // Event's own id, so the fixture reads it back after construction.
    let event = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::RealmCreate.as_str(),
        arkret_wire::ScopeRef::RealmGenesis,
        actor_id,
        arkret_wire::project_did_to_core_id(
            &arkret_identifiers::Did::new("did:web:service.example".to_owned()).unwrap(),
        )
        .unwrap(),
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
            membership_compensation_evidence: None,
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
    drop(conn);
    assert_eq!(
        control_seal_schedule_row_count(&pool, Some(realm_id.as_str())).await,
        1,
        "the event commit unit of work must atomically create its schedule row"
    );
    let mut cleanup_conn = pool.get().await.unwrap();
    sql_query("DELETE FROM state_control_seal_schedule WHERE realm_id = $1")
        .bind::<Text, _>(realm_id.as_str())
        .execute(&mut *cleanup_conn)
        .await
        .unwrap();
    sql_query("DELETE FROM state_control_events WHERE event_digest = $1")
        .bind::<Text, _>(proposal_digest.as_str())
        .execute(&mut *cleanup_conn)
        .await
        .unwrap();
    sql_query("DELETE FROM canonical_events WHERE actor_id = $1")
        .bind::<Text, _>(event.actor_id.to_string())
        .execute(&mut *cleanup_conn)
        .await
        .unwrap();
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
    let actor_id = format!("ak:did_core:web:collision-{run_id}.example");
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
         VALUES ($1, 'ak:did_core:web:peer.example', 'https://peer.example', '/events', $1, '{}', 0, 0)",
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
                    membership_compensation_evidence: None,
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
                    membership_compensation_evidence: None,
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
            agent_approval_nonce: None,
            franking_replay_nonce: None,
            applet_record: None,
            applet_authoring_preview: None,
            agent_membership_cascade: None,
        })
        .await
        .unwrap_err();
    assert!(
        matches!(batch_error, PersistenceError::Conflict(ref reason) if reason == "event_hash_collision"),
        "unexpected collision batch rejection: {batch_error:?}"
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
    let accounts = soland_storage_postgres::PgAccountStore { pool: pool.clone() };
    assert_mls_keypackage_retirement_contract(&store, &accounts, &namespace).await;

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
    let accounts = soland_storage_postgres::PgAccountStore { pool: pool.clone() };
    assert_last_resort_claim_ledger_contract(&store, &accounts, &namespace).await;

    let restarted_store = PgMlsKeyPackageStore { pool };
    let claim_request_id = format!("local-last-resort:{namespace}-01");
    let replayed = restarted_store
        .get_peer_claim(&format!("did:web:{namespace}.example"), &claim_request_id)
        .await
        .expect("reload last-resort ledger after store restart")
        .expect("last-resort ledger survives store restart");
    assert_eq!(replayed.claim_request_id, claim_request_id);
    assert_eq!(replayed.state, "consumed");
    assert_eq!(
        replayed.consume_receipt,
        Some(serde_json::json!({"receipt": "first-writer"}))
    );
    let expired = restarted_store
        .get_peer_claim(
            &format!("did:web:{namespace}.example"),
            &format!("local-last-resort:{namespace}-02"),
        )
        .await
        .expect("reload expired last-resort ledger after store restart")
        .expect("expired last-resort ledger survives store restart");
    assert_eq!(expired.state, "expired");
    assert!(expired.outcome.is_some());
    assert!(expired.consume_receipt.is_none());

    let delayed = restarted_store
        .get_peer_claim(
            &format!("did:web:{namespace}.example"),
            &format!("local-last-resort:{namespace}-03"),
        )
        .await
        .expect("reload delayed consumed source mirror after restart")
        .expect("delayed consumed source mirror survives restart");
    assert_eq!(delayed.state, "consumed");
    assert_eq!(delayed.key_package_use, "last_resort");
    assert_eq!(
        delayed.consume_receipt,
        Some(serde_json::json!({"receipt": "signed-before-deadline"}))
    );

    let terminal = restarted_store
        .get_peer_claim(
            &format!("did:web:{namespace}.example"),
            &format!("local-last-resort:{namespace}-04"),
        )
        .await
        .expect("reload terminal source mirror after restart")
        .expect("terminal source mirror survives restart");
    assert_eq!(terminal.state, "revoked");
    assert_eq!(terminal.key_package_use, "last_resort");
    assert_eq!(
        terminal.terminal_receipt,
        Some(serde_json::json!({"receipt": "terminal"}))
    );
    assert!(
        restarted_store
            .get_peer_claim(
                &format!("did:web:{namespace}.example"),
                &format!("local-last-resort:{namespace}-05"),
            )
            .await
            .expect("check rejected fractional-deadline claim")
            .is_none()
    );

    let concurrent = PeerKeyPackageClaimLedgerRecord {
        source_id: format!("ak:did_core:web:{namespace}.example"),
        claim_request_id: format!("local-last-resort:{namespace}-concurrent"),
        request_digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            .to_owned(),
        key_package_use: "last_resort".to_owned(),
        state: "last_resort_claimed".to_owned(),
        outcome: Some(serde_json::json!({"response": {"claims": ["concurrent"]}})),
        consume_receipt: None,
        terminal_receipt: None,
        keypackage_id: Some(format!("{namespace}-keypackage-last-resort")),
        claim_expires_at_unix_ms: Some(20_000),
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

    use super::{
        DB_GUARD, cleanup_control_schedule_test_actor, control_seal_schedule_row_count, test_pool,
    };

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
        let actor_did = arkret_identifiers::Did::new(format!(
            "did:web:ingress-negative-{seed}-{}.example",
            uuid::Uuid::now_v7()
        ))
        .unwrap();
        let actor_id = arkret_wire::project_did_to_core_id(&actor_did).unwrap();
        // A genesis scope names no Realm; the Realm id is derived from this
        // Event's own id, so the fixture reads it back after construction.
        // Anything the commit path re-parses from the envelope resolves the
        // same id, which is what the Ack must bind.
        let event = arkret_wire::test_support::raw_event_at(
            arkret_wire::EventKind::RealmCreate.as_str(),
            arkret_wire::ScopeRef::RealmGenesis,
            actor_id,
            arkret_wire::project_did_to_core_id(
                &arkret_identifiers::Did::new("did:web:service.example".to_owned()).unwrap(),
            )
            .unwrap(),
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
                membership_compensation_evidence: None,
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
                 (event_digest, digest_suite, realm_id, event_json, control_proposal_ack, ingress_class) \
                 VALUES ($1, $2, $3, $4, NULL, $5)",
            )
            .bind::<Text, _>(fixture.proposal_digest.as_str())
            .bind::<Text, _>(arkret_canonical::DigestSuite::Sha256.as_str())
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
    async fn postgres_control_move_ingress_class_mismatch_and_control_seal_schedule_when_configured()
     {
        use arkret_state::state::store::{
            AcklessSelfPrincipalIngress, ControlProposalIngress, StoreError,
        };

        let Some(pool) = test_pool().await else {
            return;
        };
        let _db_guard = DB_GUARD.lock().await;
        let fixture = control_anchor_fixture("class-mismatch");
        let stores = soland_storage_postgres::build_state_resolution_stores(
            Some(pool.clone()),
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
        assert_eq!(
            control_seal_schedule_row_count(&pool, Some(fixture.realm_id.as_str())).await,
            1,
            "the state ControlEventStore path must atomically create its schedule row"
        );
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
        cleanup_control_schedule_test_actor(&pool, &fixture.event.actor_id.to_string()).await;
    }
}
