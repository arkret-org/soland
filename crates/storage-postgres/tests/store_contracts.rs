mod support;

use soland_storage::contract_tests::{
    AppletFormalCommitContractStores, ConsentCommitContractStores,
    DeviceRevocationSealSettlementStores, EventCommitContractStores,
    assert_account_localpart_remove_contract, assert_applet_formal_commit_transaction_contract,
    assert_atomic_batch_outbox_rollback_contract,
    assert_atomic_control_event_governance_dependency_contract,
    assert_consent_projection_commit_contract,
    assert_control_proposal_authority_ack_store_contract,
    assert_device_message_snapshot_guard_contract,
    assert_device_revocation_seal_settlement_contract, assert_event_commit_unit_of_work_contract,
    assert_federation_outbox_store_contract, assert_governance_unscoped_signer_evidence_contract,
    assert_idempotency_store_contract, assert_invite_new_source_ledger_contract,
    assert_last_resort_claim_ledger_contract, assert_mimi_consent_correlation_store_contract,
    assert_mls_keypackage_retirement_contract, assert_organization_registration_store_contract,
    minimal_history_signer_evidence,
};
use soland_storage::{
    AccountDataCasResult, AccountDataRecord, AccountDataStore, AccountNotificationDeltaWrite,
    AgentPrincipalRecord, AgentStore, AppletAuthoringPreviewRecord, AppletStore,
    GovernanceDependencySource, GovernanceDependencyStore, GovernanceDependencyWrite,
    MlsKeyPackageStore, NotificationStore, PeerKeyPackageClaimLedgerRecord,
    PeerKeyPackageClaimLedgerWriteResult,
};
use soland_storage_postgres::{
    Db, PgAccountDataStore, PgAccountLocalpartStore, PgAccountStore, PgAgentStore, PgAppletStore,
    PgContactStore, PgControlProposalAuthorityAckStore, PgDeviceInventoryStore,
    PgDeviceMessageStore, PgEventCommitUnitOfWork, PgEventStore, PgFederationOutboxStore,
    PgGovernanceDependencyStore, PgIdempotencyStore, PgInviteNewSourceLedgerStore,
    PgInviteReceivePolicyStore, PgMimiConsentCorrelationStore, PgMlsKeyPackageStore,
    PgNotificationStore, PgOrganizationRegistrationStore, PgPool, PgProjectionEventStore,
};

#[tokio::test]
async fn postgres_audit_regression_satisfies_account_localpart_remove_contract() {
    let pool = test_pool().await;
    let _db_guard = DB_GUARD.lock().await;
    let accounts = PgAccountStore { pool: pool.clone() };
    let localparts = PgAccountLocalpartStore { pool };
    assert_account_localpart_remove_contract(
        &accounts,
        &localparts,
        &format!("postgres-{}", uuid::Uuid::now_v7().simple()),
    )
    .await;
}

#[tokio::test]
async fn postgres_adapter_guards_repair_device_snapshots_atomically() {
    let pool = test_pool().await;
    let _db_guard = DB_GUARD.lock().await;
    // This contract bypasses runtime bootstrap, so install its trusted local
    // inventory owner explicitly before exercising device writes.
    {
        use diesel_async::RunQueryDsl;
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,'ak:did_core:web:storage-contract.example') ON CONFLICT(singleton) DO NOTHING")
            .execute(&mut *conn).await.unwrap();
    }
    let inventory = PgDeviceInventoryStore { pool: pool.clone() };
    let messages = PgDeviceMessageStore { pool };
    let namespace = format!("postgres-repair-snapshot-{}", uuid::Uuid::now_v7());
    assert_device_message_snapshot_guard_contract(&inventory, &messages, &namespace).await;
}

static TEST_POOL: tokio::sync::OnceCell<PgPool> = tokio::sync::OnceCell::const_new();

async fn put_pending_control_singleton(
    store: &dyn arkret_state::state::ControlEventStore,
    event: &arkret_wire::Event,
    ingress: &arkret_state::state::store::ControlProposalIngress,
    digest_suite: arkret_canonical::DigestSuite,
) -> arkret_state::state::StoreResult<Vec<arkret_wire::Hash>> {
    store
        .put_pending_unit_with_ingress(&[arkret_state::state::ControlUnitIngressMember {
            event: event.clone(),
            digest_suite,
            ingress: ingress.clone(),
        }])
        .await
}

#[tokio::test]
async fn postgres_notification_relay_delivers_large_payload_by_committed_reference() {
    use diesel::sql_query;
    use diesel_async::RunQueryDsl;
    use soland_storage_postgres::{load_event_notification, publish_event_notification};
    use tokio_postgres::{AsyncMessage, NoTls};

    let pool = test_pool().await;
    let _db_guard = DB_GUARD.lock().await;
    let (client, mut connection) =
        tokio_postgres::connect(&support::contract_database_url(), NoTls)
            .await
            .unwrap();
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
    let listener = tokio::spawn(async move {
        while let Some(message) = std::future::poll_fn(|cx| connection.poll_message(cx)).await {
            if let AsyncMessage::Notification(notification) = message.unwrap() {
                sender.send(notification.payload().to_owned()).unwrap();
            }
        }
    });
    client
        .batch_execute("LISTEN soland_event_notifications")
        .await
        .unwrap();
    let payload = serde_json::json!({"welcome": "x".repeat(32_768)}).to_string();
    let id = publish_event_notification(&pool, &payload).await.unwrap();
    let reference = tokio::time::timeout(std::time::Duration::from_secs(5), receiver.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reference, id.to_string());
    assert_eq!(reference.len(), 36);
    assert_eq!(
        load_event_notification(&pool, id).await.unwrap(),
        Some(payload.clone())
    );
    // Another subscriber can read the same record; delivery is not a destructive dequeue.
    assert_eq!(
        load_event_notification(&pool, id).await.unwrap(),
        Some(payload)
    );
    assert_eq!(
        load_event_notification(&pool, uuid::Uuid::now_v7())
            .await
            .unwrap(),
        None
    );

    let mut conn = pool.get().await.unwrap();
    sql_query(
        "UPDATE event_notification_relay SET created_at = NOW() - INTERVAL '2 days' WHERE id = $1",
    )
    .bind::<diesel::sql_types::Uuid, _>(id)
    .execute(&mut *conn)
    .await
    .unwrap();
    let current = publish_event_notification(&pool, "current").await.unwrap();
    assert_eq!(load_event_notification(&pool, id).await.unwrap(), None);
    assert_eq!(
        load_event_notification(&pool, current).await.unwrap(),
        Some("current".into())
    );
    listener.abort();
}

#[tokio::test]
async fn postgres_frontier_evidence_survives_restart_and_concurrent_success() {
    use soland_storage::FederationFrontierExchangeStore;
    use soland_storage_postgres::PgFederationFrontierExchangeStore;
    let pool = test_pool().await;
    let _db_guard = DB_GUARD.lock().await;
    let realm = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [0x93; 32],
    ));
    let peer = arkret_wire::DidCoreId::new(format!(
        "ak:did_core:web:frontier-{}.example",
        uuid::Uuid::new_v4()
    ))
    .unwrap();
    let store = PgFederationFrontierExchangeStore { pool: pool.clone() };
    for attempt in 1..=3 {
        let record = store
            .record_failure(realm.as_str(), &peer, "network_error", attempt)
            .await
            .unwrap();
        assert_eq!(
            record.status,
            if attempt == 3 {
                "peer_stale"
            } else {
                "healthy"
            }
        );
    }
    let reopened = PgFederationFrontierExchangeStore { pool: pool.clone() };
    assert_eq!(
        reopened
            .get(realm.as_str(), &peer)
            .await
            .unwrap()
            .unwrap()
            .status,
        "peer_stale"
    );
    assert_eq!(
        reopened
            .record_success(realm.as_str(), &peer, "remote-root", 4)
            .await
            .unwrap()
            .status,
        "healthy"
    );
    // The cell subject is the disputed position alone, so both overflow
    // evidence shapes at one position key the same confirmed-evidence row.
    let subject =
        arkret_models_collaboration::events_payloads::ForkResolutionSubject::EventSiblingPosition {
            actor_id: arkret_wire::ActorId::service(peer.clone()),
            actor_seq: 9,
        };
    let evidence_scope_key = subject.cell_subject_key().unwrap();
    let evidence_record = soland_storage::FederationFrontierConfirmedEvidenceRecord {
        realm_id: realm.to_string(),
        peer_id: peer.clone(),
        evidence_scope_key: evidence_scope_key.to_string(),
        reason: "fork_quarantine".to_owned(),
        evidence_scope: serde_json::to_value(&subject).unwrap(),
        observed_at: 5,
        local_resolution_kind: None,
        local_resolution_digest: None,
        local_normalized_at: None,
        peer_alignment_digest: None,
        peer_aligned_at: None,
    };
    let (evidence, success) = tokio::join!(
        store.record_confirmed_evidence(&evidence_record),
        reopened.record_success(realm.as_str(), &peer, "another-scope-root", 6),
    );
    evidence.unwrap();
    success.unwrap();
    let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:checkpoint-user.example").unwrap(),
        arkret_wire::DidCoreId::new("ak:did_core:web:checkpoint-station.example").unwrap(),
    ));
    store
        .put_reduction_checkpoint(&soland_storage::FederationFrontierReductionCheckpoint {
            realm_id: realm.to_string(),
            peer_id: peer.clone(),
            remote_snapshot_digest: "sha256:remote-snapshot".to_owned(),
            actor_set_digest: "sha256:actor-set".to_owned(),
            actor_id: actor.clone(),
            cursor: Some("opaque-cursor".to_owned()),
            updated_at: 7,
        })
        .await
        .unwrap();
    let restarted = PgFederationFrontierExchangeStore { pool };
    let record = restarted.get(realm.as_str(), &peer).await.unwrap().unwrap();
    assert_eq!(record.status, "peer_stale");
    assert_eq!(record.last_error.as_deref(), Some("fork_quarantine"));
    assert_eq!(
        restarted
            .unresolved_confirmed_evidence(realm.as_str(), &peer)
            .await
            .unwrap(),
        vec![evidence_record.clone()]
    );
    assert!(
        !restarted
            .resolve_confirmed_evidence_for_peer(
                realm.as_str(),
                &peer,
                "sha256:wrong-scope",
                "fork_resolution_event",
                &format!("sha256:{}", "3".repeat(64)),
                7,
            )
            .await
            .unwrap()
    );
    assert_eq!(
        restarted
            .record_success(realm.as_str(), &peer, "ordinary-success", 8)
            .await
            .unwrap()
            .status,
        "peer_stale"
    );
    // A second peer holding the same disputed scope is untouched: alignment is
    // proved one peer at a time, so clearing this one says nothing about that
    // one.
    let other_peer = arkret_wire::DidCoreId::new(format!(
        "ak:did_core:web:frontier-peer-b-{}.example",
        uuid::Uuid::new_v4()
    ))
    .unwrap();
    restarted
        .record_confirmed_evidence(&soland_storage::FederationFrontierConfirmedEvidenceRecord {
            peer_id: other_peer.clone(),
            ..evidence_record.clone()
        })
        .await
        .unwrap();
    restarted
        .record_local_normalization(
            &soland_storage::FederationFrontierResolutionRecord {
                realm_id: realm.to_string(),
                cell_subject_key: evidence_scope_key.to_string(),
                subject: serde_json::to_value(&subject).unwrap(),
                verdict: serde_json::json!({"kind": "void_all"}),
                conflict_evidence_digest: format!("sha256:{}", "2".repeat(64)),
                resolution_event_digest: format!("sha256:{}", "3".repeat(64)),
                normalized_at: 9,
            },
            &soland_storage::FederationForkNormalizationScope::SiblingPosition {
                actor_id: arkret_wire::ActorId::service(peer.clone()).to_string(),
                actor_seq: 9,
                winner_event_id: None,
            },
        )
        .await
        .unwrap();
    assert!(
        restarted
            .resolve_confirmed_evidence_for_peer(
                realm.as_str(),
                &peer,
                evidence_scope_key.as_str(),
                "fork_resolution_event",
                &format!("sha256:{}", "3".repeat(64)),
                9,
            )
            .await
            .unwrap()
    );
    assert_eq!(
        restarted
            .unresolved_confirmed_evidence(realm.as_str(), &other_peer)
            .await
            .unwrap()
            .len(),
        1,
        "another peer aligning must not clear this peer"
    );
    // Replay is visibly idempotent rather than a second transition.
    assert!(
        !restarted
            .resolve_confirmed_evidence_for_peer(
                realm.as_str(),
                &peer,
                evidence_scope_key.as_str(),
                "fork_resolution_event",
                &format!("sha256:{}", "3".repeat(64)),
                10,
            )
            .await
            .unwrap()
    );
    assert_eq!(
        restarted
            .get(realm.as_str(), &peer)
            .await
            .unwrap()
            .unwrap()
            .status,
        "healthy"
    );
    assert!(
        !restarted
            .record_peer_alignment(
                realm.as_str(),
                &peer,
                "sha256:wrong-scope",
                &format!("sha256:{}", "4".repeat(64)),
                10,
            )
            .await
            .unwrap()
    );
    assert!(
        !restarted
            .record_peer_alignment(
                realm.as_str(),
                &peer,
                evidence_scope_key.as_str(),
                &format!("sha256:{}", "4".repeat(64)),
                11,
            )
            .await
            .unwrap()
    );
    assert_eq!(
        restarted
            .get(realm.as_str(), &peer)
            .await
            .unwrap()
            .unwrap()
            .status,
        "healthy"
    );
    let checkpoint = restarted
        .reduction_checkpoint(realm.as_str(), &peer)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(checkpoint.actor_id, actor);
    assert_eq!(checkpoint.cursor.as_deref(), Some("opaque-cursor"));
    restarted
        .clear_reduction_checkpoint(realm.as_str(), &peer)
        .await
        .unwrap();
    assert!(
        restarted
            .reduction_checkpoint(realm.as_str(), &peer)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn postgres_structured_projection_and_invite_identities_round_trip() {
    use arkret_wire::{AccountId, ActorId, DidCoreId};
    use soland_storage::{
        CircleProjectionStore, MorphProjectionStore, RealmInviteStore,
        SpaceContainerProjectionStore, StrandProjectionStore,
    };
    let pool = test_pool().await;
    let _db_guard = DB_GUARD.lock().await;
    let principal = DidCoreId::new("ak:did_core:web:projection-alice.example").unwrap();
    let account = AccountId::new(
        principal.clone(),
        DidCoreId::new("ak:did_core:web:station-a.example").unwrap(),
    );
    let other_account = AccountId::new(
        principal,
        DidCoreId::new("ak:did_core:web:station-b.example").unwrap(),
    );
    let author = ActorId::account(account.clone()).to_string();
    let other_author = ActorId::account(other_account.clone()).to_string();
    let service =
        ActorId::service(DidCoreId::new("ak:did_core:web:notary.example").unwrap()).to_string();
    let realm_id = "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP";
    let now = chrono::DateTime::parse_from_rfc3339("2026-08-31T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    // New adapters read only PostgreSQL; there is no in-memory projection cache.
    macro_rules! round_trip {
        ($adapter:ident, $record:expr, $id:ident) => {{
            let mut record = $record;
            soland_storage_postgres::$adapter { pool: pool.clone() }
                .put(&record)
                .await
                .unwrap();
            let reopened = soland_storage_postgres::$adapter { pool: pool.clone() };
            assert_eq!(reopened.get(&record.$id).await.unwrap().unwrap(), record);
            assert!(
                reopened
                    .list_for_realm(realm_id)
                    .await
                    .unwrap()
                    .contains(&record)
            );
            for updated_by in [Some(other_author.clone()), Some(service.clone()), None] {
                record.updated_by = updated_by;
                reopened.put(&record).await.unwrap();
                assert_eq!(reopened.get(&record.$id).await.unwrap().unwrap(), record);
                assert!(reopened.snapshot_all().await.unwrap().contains(&record));
            }
            record.created_by = "ak:did_core:web:unbound.example".into();
            assert!(
                reopened.put(&record).await.is_err(),
                "scalar bylines must fail closed"
            );
        }};
    }
    round_trip!(
        PgSpaceContainerProjectionStore,
        soland_storage::SpaceContainerProjectionRecord {
            container_space_id: "ak:space:AeJsr0sf3TZ_Cuzj2uLddhd-O-Cywvdj8ypnqpVG8zim".into(),
            kind: "navigation".into(),
            title: "identity persistence".into(),
            fields: Default::default(),
            scope_circle_id: None,
            child_scope_policy: None,
            child_scope_policy_scope_circle_id: None,
            parent_ref: None,
            rank: None,
            history_basis_seals: vec![],
            realm_id: realm_id.into(),
            state: "active".into(),
            state_changed_at: None,
            created_by: author.clone(),
            created_at: now,
            updated_by: None,
            updated_at: Some(now),
        },
        container_space_id
    );
    round_trip!(
        PgStrandProjectionStore,
        soland_storage::StrandProjectionRecord {
            strand_id: "ak:strand:AeJsr0sf3TZ_Cuzj2uLddhd-O-Cywvdj8ypnqpVG8zim".into(),
            tracks: Default::default(),
            title: "identity persistence".into(),
            summary: None,
            content: Some(serde_json::json!({"text":"test"})),
            encrypted_content: None,
            fields: Default::default(),
            schema_refs: vec!["ak.schema.calendar_event.v1".to_owned()],
            scope_circle_id: None,
            history_basis_seals: vec![],
            realm_id: realm_id.into(),
            state: "active".into(),
            state_changed_at: None,
            stage: None,
            stage_changed_at: None,
            created_by: author.clone(),
            created_at: now,
            updated_by: None,
            updated_at: Some(now),
        },
        strand_id
    );
    round_trip!(
        PgMorphProjectionStore,
        soland_storage::MorphProjectionRecord {
            morph_id: "ak:morph:AeJsr0sf3TZ_Cuzj2uLddhd-O-Cywvdj8ypnqpVG8zim".into(),
            scope_circle_id: None,
            morph_kind: "document".into(),
            title: None,
            fields: serde_json::json!({}),
            schema_refs: serde_json::json!([]),
            facets: serde_json::json!({}),
            versions: serde_json::json!([]),
            content: Some(serde_json::json!({"text":"test"})),
            encrypted_content: None,
            history_basis_seals: vec![],
            realm_id: realm_id.into(),
            state: "active".into(),
            state_changed_at: None,
            stage: None,
            stage_changed_at: None,
            created_by: author.clone(),
            created_at: now,
            updated_by: None,
            updated_at: Some(now),
        },
        morph_id
    );
    round_trip!(
        PgCircleProjectionStore,
        soland_storage::CircleProjectionRecord {
            circle_id: "ak:circle:AeJsr0sf3TZ_Cuzj2uLddhd-O-Cywvdj8ypnqpVG8zim".into(),
            profile_ref: None,
            title: "identity persistence".into(),
            summary: None,
            display: serde_json::json!({}),
            directory_visibility: "members".into(),
            join_rule: "invite".into(),
            history_access: "since_join".into(),
            content_encryption_floor: None,
            metadata_encryption_floor: None,
            encryption_profile: "none".into(),
            content_scheme: None,
            mls_group_ref: None,
            durability_policy: None,
            realm_id: realm_id.into(),
            state: "active".into(),
            state_changed_at: None,
            created_by: author.clone(),
            created_at: now,
            updated_by: None,
            updated_at: Some(now),
        },
        circle_id
    );

    let invites = soland_storage_postgres::PgRealmInviteStore { pool: pool.clone() };
    let record = soland_storage::RealmInviteRecord {
        invite_id: "ak:invite:AeJsr0sf3TZ_Cuzj2uLddhd-O-Cywvdj8ypnqpVG8zim".into(),
        realm_id: realm_id.into(),
        inviter_id: account.to_string(),
        invitee_id: Some(other_account.to_string()),
        introduction_evidence_digest: None,
        third_party_invite: None,
        invite_token: String::new(),
        status: "pending".into(),
        claim_nonces: Default::default(),
        expires_at: None,
        created_at: now,
        updated_at: None,
    };
    invites.put(record.clone()).await.unwrap();
    let reopened = soland_storage_postgres::PgRealmInviteStore { pool };
    let found = reopened.get(&record.invite_id).await.unwrap().unwrap();
    assert_eq!(found.inviter_id, record.inviter_id);
    assert_eq!(found.invitee_id, record.invitee_id);
    assert_ne!(Some(&found.inviter_id), found.invitee_id.as_ref());
    assert!(
        reopened
            .snapshot_all()
            .await
            .unwrap()
            .iter()
            .any(|invite| invite.invite_id == record.invite_id)
    );
    let mut invalid = record;
    invalid.inviter_id = "ak:did_core:web:unbound.example".into();
    assert!(reopened.put(invalid).await.is_err());
}

#[tokio::test]
async fn postgres_key_backup_identity_and_series_round_trip() {
    use arkret_wire::{AccountId, ActorId, DidCoreId};
    use soland_storage::{KeyBackupStore, PersistenceError};
    use soland_storage_postgres::PgKeyBackupStore;
    let pool = test_pool().await;
    let _db_guard = DB_GUARD.lock().await;
    let principal = DidCoreId::new(format!(
        "ak:did_core:web:backup-{}.example",
        uuid::Uuid::now_v7().simple()
    ))
    .unwrap();
    let actor = |station| {
        ActorId::account(AccountId::new(
            principal.clone(),
            DidCoreId::new(station).unwrap(),
        ))
    };
    let actor_a = actor("ak:did_core:web:station-a.example");
    let actor_b = actor("ak:did_core:web:station-b.example");
    let series_id = format!("ak:backup_series:{}", uuid::Uuid::now_v7());
    let mut records = Vec::new();
    for actor_id in [&actor_a, &actor_b] {
        let backup_id = format!("ak:backup:{}", uuid::Uuid::now_v7());
        let payload = backup_page_envelope(&backup_id, actor_id, &series_id, 0);
        PgKeyBackupStore { pool: pool.clone() }
            .put(backup_id.clone(), payload.clone())
            .await
            .unwrap();
        records.push((backup_id, payload));
    }
    let reopened = PgKeyBackupStore { pool };
    for ((backup_id, payload), actor_id) in records.iter().zip([&actor_a, &actor_b]) {
        assert_eq!(
            reopened.get(backup_id).await.unwrap().as_ref(),
            Some(payload)
        );
        assert_eq!(
            reopened
                .list_for_actor(&actor_id.to_string())
                .await
                .unwrap(),
            vec![payload.clone()]
        );
    }
    let duplicate_id = format!("ak:backup:{}", uuid::Uuid::now_v7());
    let mut duplicate = records[0].1.clone();
    duplicate["backup_id"] = duplicate_id.clone().into();
    assert!(matches!(
        reopened.put(duplicate_id, duplicate).await,
        Err(PersistenceError::Conflict(_))
    ));
    let mut invalid = records[0].1.clone();
    invalid["actor_id"] = principal.to_string().into();
    assert!(reopened.put(records[0].0.clone(), invalid).await.is_err());
    assert!(reopened.list_for_actor(principal.as_str()).await.is_err());
    assert_eq!(
        reopened.get(&records[0].0).await.unwrap().as_ref(),
        Some(&records[0].1)
    );
}

fn backup_page_envelope(
    id: &str,
    actor: &arkret_wire::ActorId,
    series: &str,
    seq: u64,
) -> serde_json::Value {
    serde_json::json!({
        "backup_id":id, "actor_id":actor, "backup_kind":"secret_storage", "backup_version":"kb_1",
        "created_at":"2026-09-09T00:00:00.000Z", "series_id":series, "series_seq":seq,
        "encryption":{"recipient_method":"secret_storage_key", "recipient_key_ref":"backup-key", "aead":{"name":"xchacha20_poly1305", "nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
        "domain_separation":{"subdomain":"arkret.secret_storage.v1"},
        "contents":[{"item_kind":"recovery_key_share", "secret_id":"share"}],
        "ciphertext":"AAAA", "ciphertext_digest":"sha256:709e80c88487a2411e1ee4dfb9f22a861492d20c4765150c0c794abd70f8147c"
    })
}

#[tokio::test]
async fn postgres_key_backup_pages_are_ordered_bounded_and_revisioned() {
    use soland_storage::{KeyBackupListPosition, KeyBackupListQuery, KeyBackupStore};
    use soland_storage_postgres::PgKeyBackupStore;
    let pool = test_pool().await;
    let _guard = DB_GUARD.lock().await;
    let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(format!(
            "ak:did_core:web:page-{}.example",
            uuid::Uuid::now_v7().simple()
        ))
        .unwrap(),
        arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    ));
    let series = format!("ak:backup_series:{}", uuid::Uuid::now_v7());
    let store = PgKeyBackupStore { pool: pool.clone() };
    let mut ids = Vec::new();
    for seq in 0..5 {
        let id = format!("ak:backup:{}", uuid::Uuid::now_v7());
        let mut body = backup_page_envelope(&id, &actor, &series, seq);
        body["ciphertext"] = "A".repeat(100_000).into();
        store.put(id.clone(), body).await.unwrap();
        ids.push(id);
    }
    let mut query = KeyBackupListQuery {
        actor_id: actor.to_string(),
        backup_kind: Some("secret_storage".into()),
        series_id: Some(series.clone()),
        after: None,
        limit: 2,
    };
    let first = store.list_page(&query).await.unwrap();
    assert_eq!(first.revision, 5);
    assert_eq!(first.payloads.len(), 2);
    assert!(!first.byte_limited);
    assert_eq!(first.payloads[0]["series_seq"], 0);
    assert_eq!(first.payloads[1]["series_seq"], 1);
    assert!(
        first
            .payloads
            .iter()
            .all(|row| row.get("ciphertext").is_none())
    );
    query.after = Some(KeyBackupListPosition {
        backup_kind: "secret_storage".into(),
        series_id: series,
        series_seq: 1,
        backup_id: ids[1].clone(),
    });
    let reopened = PgKeyBackupStore { pool: pool.clone() };
    reopened.get(&ids[0]).await.unwrap();
    let second = reopened.list_page(&query).await.unwrap();
    assert_eq!(second.revision, first.revision);
    assert_eq!(second.payloads[0]["series_seq"], 2);
    assert_eq!(second.payloads[1]["series_seq"], 3);
    reopened.delete(&ids[4]).await.unwrap();
    assert_eq!(reopened.list_page(&query).await.unwrap().revision, 6);
    let mut replacement = reopened.get(&ids[3]).await.unwrap().unwrap();
    replacement["contents"][0]["secret_id"] = "s".repeat(910_000).into();
    reopened.put(ids[3].clone(), replacement).await.unwrap();
    let bounded = reopened.list_page(&query).await.unwrap();
    assert_eq!(bounded.revision, 7);
    assert!(bounded.byte_limited);
    assert_eq!(bounded.payloads.len(), 1);
    query.limit = 202;
    assert!(reopened.list_page(&query).await.is_err());
}

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

async fn test_pool() -> PgPool {
    TEST_POOL
        .get_or_init(|| async {
            let url = support::contract_database_url();
            support::ensure_contract_database(&url).await;
            Db::connect(Some(&url), Default::default())
                .await
                .expect("initialize test database")
                .pool
                .expect("a configured URL always yields a pool")
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
        mls_public_producer: None,
        mls_public_genesis: None,
        mls_frontier_leaves: None,
        replicated: false,
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
async fn postgres_mls_frontier_input_commits_atomically_and_survives_adapter_restart() {
    use diesel::sql_types::{Binary, Text};
    use diesel_async::RunQueryDsl;
    use soland_storage::{EventCommitUnitOfWork, EventStore};

    let pool = test_pool().await;
    let _db_guard = DB_GUARD.lock().await;
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let realm_id = arkret_identifiers::RealmId::new(event_derived_realm_id(
        format!("mls-frontier-input:{}", uuid::Uuid::now_v7()).as_bytes(),
    ))
    .unwrap();
    let station = arkret_wire::DidCoreId::new("ak:did_core:web:mls-input.example").unwrap();
    let actor = arkret_wire::DidCoreId::new("ak:did_core:web:mls-author.example").unwrap();
    // Storage owns atomic evidence retention. HTTP admission separately verifies
    // this input against the signed binding and the exact accepted basis.
    let mut request = franking_event_request(
        &realm_id,
        actor,
        &station,
        107,
        arkret_wire::EventKind::MlsGenesis.as_str(),
        serde_json::json!({}),
        now,
    );
    let event: arkret_wire::Event = serde_json::from_value(request.event.envelope.clone()).unwrap();
    let leaves = vec![arkret_wire::mls_transition::MlsSecurityFrontierLeaf {
        leaf_index: 0,
        actor_id: event.actor_id.clone(),
        credential_ref: arkret_wire::NonEmptyString::new("device-a").unwrap(),
    }];
    request.mls_frontier_leaves = Some(leaves.clone());
    let policy = arkret_wire::ControlProposalDecisionPolicy::default();
    let mut ack = arkret_wire::ControlProposalAuthorityAck {
        realm_id: realm_id.clone(),
        proposal_digest: arkret_wire::Hash::new(request.event.canonical_digest.clone()).unwrap(),
        received_at: now,
        decision_due_at: now + policy.decision_window,
        absolute_due_at: now + policy.absolute_horizon,
        authority_set_ref: arkret_wire::Hash::new(format!("sha256:{}", "aa".repeat(32))).unwrap(),
        signature: arkret_wire::PayloadSignature {
            verification_method: arkret_wire::DidUrl::new("did:web:mls-input.example#authority")
                .unwrap(),
            payload_digest: arkret_wire::Hash::new(format!("sha256:{}", "00".repeat(32))).unwrap(),
            created_at: now,
            jws: "e30..c2ln".to_owned(),
        },
    };
    ack.signature.payload_digest = ack.authority_ack_digest().unwrap();
    request.control_proposal_ingress = Some(
        arkret_state::state::store::ControlProposalIngress::AckRequired(
            arkret_wire::ControlProposalAck::from_authority_acks(vec![ack], policy).unwrap(),
        ),
    );
    let event_id = request.event.event_id.clone();
    let store = PgEventStore { pool: pool.clone() };
    let mut missing = request.clone();
    missing.mls_frontier_leaves = None;
    assert!(
        PgEventCommitUnitOfWork::new(pool.clone())
            .commit_event(missing)
            .await
            .is_err()
    );
    assert!(!store.contains(&event_id).await.unwrap());
    assert!(
        store
            .mls_frontier_leaves(&event_id)
            .await
            .unwrap()
            .is_none()
    );
    // Fail after inserting both canonical Event and leaf input: all rows roll back.
    let mut no_ingress = request.clone();
    no_ingress.control_proposal_ingress = None;
    assert!(
        PgEventCommitUnitOfWork::new(pool.clone())
            .commit_event(no_ingress)
            .await
            .is_err()
    );
    assert!(!store.contains(&event_id).await.unwrap());
    assert!(
        store
            .mls_frontier_leaves(&event_id)
            .await
            .unwrap()
            .is_none()
    );
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(request.clone())
        .await
        .unwrap();
    let restarted = PgEventStore { pool: pool.clone() };
    assert_eq!(
        restarted.mls_frontier_leaves(&event_id).await.unwrap(),
        Some(leaves.clone())
    );
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(request.clone())
        .await
        .unwrap();
    let mut conflicting = request;
    conflicting.mls_frontier_leaves.as_mut().unwrap()[0].credential_ref =
        arkret_wire::NonEmptyString::new("device-b").unwrap();
    assert!(
        PgEventCommitUnitOfWork::new(pool.clone())
            .commit_event(conflicting)
            .await
            .is_err()
    );
    assert_eq!(
        restarted.mls_frontier_leaves(&event_id).await.unwrap(),
        Some(leaves)
    );
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("UPDATE canonical_events SET state = $1 WHERE id = $2")
        .bind::<Text, _>("quarantined")
        .bind::<Binary, _>(
            soland_storage::ids::parse_event_id(&event_id)
                .unwrap()
                .to_vec(),
        )
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    assert!(
        restarted
            .mls_frontier_leaves(&event_id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn postgres_franking_nonce_ledger_is_bounded_atomic_and_restart_stable() {
    use diesel::sql_types::{BigInt, Text, Timestamptz};
    use diesel_async::RunQueryDsl;
    use soland_storage::{
        EventBatchCommitRequest, EventCommitUnitOfWork, EventStore, FrankingReplayNonceCommit,
        PersistenceError,
    };

    let pool = test_pool().await;
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
         SELECT $1, $2, 'capacity_nonce_' || n, 'capacity_report_' || $1 || '_' || n, $3, $4 \
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
async fn postgres_franking_target_proof_fault_and_restart_contract() {
    use soland_storage::{
        EventBatchCommitRequest, EventCommitUnitOfWork, EventStore, PersistenceError,
    };

    let pool = test_pool().await;
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
async fn postgres_agent_store_accepts_spec_agent_binding() {
    let pool = test_pool().await;
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
        .expect("spec-valid Agent binding must persist");
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
async fn postgres_agent_table_rejects_mismatched_did_and_core_agent_ids() {
    let pool = test_pool().await;
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
         (id, controller_principal_id, principal_control_realm_id, controller_authorization_ref, \
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
async fn postgres_control_seal_schedule_fences_generation_expiry_and_repair() {
    use arkret_state::state::store::{AcklessSelfPrincipalIngress, ControlProposalIngress};
    use arkret_state::state::{ControlSealAttemptCompletion, ControlSealAttemptOutcome};
    use diesel::sql_types::Text;
    use diesel_async::RunQueryDsl;

    let pool = test_pool().await;
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
        std::sync::Arc::new(arkret_state::state::MemoryCellStateRegistry::default()),
    );
    let ingress = ControlProposalIngress::AcklessSelfPrincipal(AcklessSelfPrincipalIngress {
        device_id: "ak:device:schedule-contract".to_owned(),
        device_authorize_event_id: "ak:event:schedule-contract".to_owned(),
        device_generation_ref: 1,
        seal_basis_digest: format!("sha256:{}", "a".repeat(64)),
    });
    let (first_event, _) = seal_dependency_contract_event(&realm_id, "schedule-first");
    put_pending_control_singleton(
        stores.control_event_store.as_ref(),
        &first_event,
        &ingress,
        arkret_canonical::DigestSuite::Sha256,
    )
    .await
    .unwrap();
    prioritize_control_seal_schedule_test_realm(&pool, realm_id.as_str()).await;
    let now_ms = chrono::Utc::now().timestamp_millis().saturating_add(1_000);
    let first_claim = stores
        .control_event_store
        .claim_due_control_seal_realms("worker-a", now_ms, now_ms + 1_000, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(first_claim.generation, 1);
    assert!(!first_claim.isolate_candidates);

    let first_cursor = first_event.event_id.event_digest();
    assert!(
        stores
            .control_event_store
            .advance_control_seal_scan(&first_claim, Some(&first_cursor), now_ms)
            .await
            .unwrap()
    );
    assert!(
        !stores
            .control_event_store
            .advance_control_seal_scan(&first_claim, None, now_ms + 1_000)
            .await
            .unwrap()
    );

    put_pending_control_singleton(
        stores.control_event_store.as_ref(),
        &first_event,
        &ingress,
        arkret_canonical::DigestSuite::Sha256,
    )
    .await
    .unwrap();
    assert_eq!(
        stores
            .control_event_store
            .complete_control_seal_attempt(
                &first_claim,
                &ControlSealAttemptOutcome::SigningFailed,
                now_ms,
            )
            .await
            .unwrap(),
        ControlSealAttemptCompletion::Applied,
        "an idempotent Event replay must not bump generation"
    );
    prioritize_control_seal_schedule_test_realm(&pool, realm_id.as_str()).await;
    let second_claim = stores
        .control_event_store
        .claim_due_control_seal_realms("worker-a", now_ms + 1_000, now_ms + 2_000, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(second_claim.generation, 1);
    assert_eq!(second_claim.scan_cursor, Some(first_cursor.clone()));
    assert!(second_claim.isolate_candidates);
    assert!(
        !stores
            .control_event_store
            .advance_control_seal_scan(&first_claim, None, now_ms + 1_000)
            .await
            .unwrap()
    );

    let (second_event, _) = seal_dependency_contract_event(&realm_id, "schedule-second");
    put_pending_control_singleton(
        stores.control_event_store.as_ref(),
        &second_event,
        &ingress,
        arkret_canonical::DigestSuite::Sha256,
    )
    .await
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
            .await
            .unwrap(),
        ControlSealAttemptCompletion::ReleasedNewGeneration
    );
    let third_claim = stores
        .control_event_store
        .claim_due_control_seal_realms("worker-a", now_ms + 1_001, now_ms + 1_101, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(third_claim.generation, 2);
    let active_stats = stores
        .control_event_store
        .control_seal_schedule_stats(now_ms + 1_100)
        .await
        .unwrap();
    assert!(active_stats.pending >= 1);
    assert!(active_stats.claimed >= 1);
    let expired_stats = stores
        .control_event_store
        .control_seal_schedule_stats(now_ms + 1_101)
        .await
        .unwrap();
    assert!(expired_stats.eligible >= 1);
    assert!(expired_stats.expired_claims >= 1);
    let reclaimed = stores
        .control_event_store
        .claim_due_control_seal_realms("worker-b", now_ms + 1_101, now_ms + 2_000, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(reclaimed.fence, third_claim.fence + 1);
    assert!(reclaimed.isolate_candidates);
    assert_eq!(
        stores
            .control_event_store
            .complete_control_seal_attempt(
                &third_claim,
                &ControlSealAttemptOutcome::ProgressPublished,
                now_ms + 1_102,
            )
            .await
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
            .await
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
        holder_service_id: event.actor_id.route_service_id().clone(),
        retention_expires_at: created_at + chrono::Duration::days(1),
        holder_signer_evidence_ref: arkret_wire::SignerEvidenceRef::new(format!(
            "ak:signer_evidence:{}",
            evidence_digest.as_str()
        ))
        .unwrap(),
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
    predecessor_ref: Option<arkret_identifiers::SealId>,
    delta: arkret_identifiers::Hash,
    covered: &std::collections::BTreeSet<arkret_identifiers::Hash>,
    availability_digest: arkret_identifiers::Hash,
) -> arkret_wire::Seal {
    let root =
        arkret_state::state::control_event_set_root(covered, arkret_canonical::DigestSuite::Sha256)
            .unwrap();
    let state_root = arkret_state::state::compute_state_root(
        arkret_state::GovernanceView::new(&std::collections::BTreeMap::new()),
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let command_result = arkret_wire::SealCommandOutcome::committed(
        delta.clone(),
        vec![delta.clone()],
        Vec::new(),
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let mut seal = arkret_wire::Seal {
        id: arkret_identifiers::SealId::new(format!("ak:seal:sha256:{}", "0".repeat(64))).unwrap(),
        realm_id: realm_id.clone(),
        predecessor_ref,
        delta: vec![delta],
        control_event_set_root: root.clone(),
        state_root,
        notary_seq: 0,
        availability_receipt_digests: vec![availability_digest],
        covered_event_digests: Vec::new(),
        previous_state_root: None,
        previous_digest_algorithm: None,
        notary_signature: arkret_wire::MultiSignature {
            kind: arkret_wire::MultiSigKind::MultiSig,
            signatures: vec![arkret_wire::SealSignature {
                verification_method: arkret_wire::DidUrl::new(
                    "did:web:seal-dependency-holder.example#notary-key".to_owned(),
                )
                .unwrap(),
                payload_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
                    .unwrap(),
                jws: "eyJhbGciOiJFZDI1NTE5In0..AQ".to_owned(),
            }],
            view: 0,
        },
        sealed_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
        hlc: arkret_wire::Hlc::new("019f00000000-0000-00000002").unwrap(),
        configuration_ref: arkret_wire::EventId::new(format!("ak:event:A{}", "a".repeat(42)))
            .unwrap(),
        command_results: vec![command_result],
        authorization_closures: Vec::new(),
        existence_anchors: Vec::new(),
        transaction_records: Vec::new(),
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
    effective_state_checkpoints: i64,
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
           (SELECT COUNT(*) FROM state_seal_effective_checkpoints WHERE seal_id = $1) AS effective_state_checkpoints",
    )
    .bind::<Text, _>(seal_id.as_str())
    .bind::<Text, _>(object_digest.as_str())
    .get_result(&mut conn)
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn postgres_event_seal_commit_retains_dependencies_at_the_frontier_cas_boundary() {
    use arkret_models_collaboration::governance_dependencies::{
        GovernanceDependency, GovernanceDependencySelector,
    };
    use arkret_state::state::store::{AcklessSelfPrincipalIngress, ControlProposalIngress};
    use soland_storage::{
        GovernanceDependencySource, GovernanceDependencyStore, GovernanceDependencyWrite,
    };

    let pool = test_pool().await;
    let _db_guard = DB_GUARD.lock().await;
    let registry: std::sync::Arc<dyn arkret_state::state::CellStateRegistry> = std::sync::Arc::new(
        soland_domain::reducer::state_model_kinds::try_build_validated_sdk_cell_registry()
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
    put_pending_control_singleton(
        stores.control_event_store.as_ref(),
        &genesis_event,
        &ingress,
        arkret_canonical::DigestSuite::Sha256,
    )
    .await
    .unwrap();
    let genesis_dependency =
        seal_dependency_contract_availability(&genesis_event, "genesis-success");
    assert_eq!(
        stores
            .control_event_store
            .list_pending_units_for_notary(&realm_id, None, 1)
            .await
            .unwrap()
            .len(),
        1
    );
    let genesis_object_digest = seal_dependency_contract_digest(&genesis_dependency);
    let genesis_covered = [genesis_digest.clone()]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    let genesis_seal = seal_dependency_contract_seal(
        &realm_id,
        None,
        genesis_digest.clone(),
        &genesis_covered,
        genesis_object_digest.clone(),
    );
    let genesis_write = GovernanceDependencyWrite {
        realm_id: realm_id.clone(),
        source: GovernanceDependencySource::Seal(genesis_seal.id.clone()),
        edge_index: 0,
        item: genesis_dependency.clone(),
    };
    assert!(
        stores
            .event_seal_committer
            .commit_if_head(
                &genesis_seal,
                arkret_canonical::DigestSuite::Sha256,
                None,
                &[],
                &genesis_covered,
                std::slice::from_ref(&genesis_write),
            )
            .await
            .unwrap()
    );
    let committed =
        seal_dependency_atomic_counts(&pool, &genesis_seal.id, &genesis_object_digest).await;
    assert_eq!(committed.seals, 1);
    assert_eq!(committed.cell_ops, 0);
    assert_eq!(committed.sealed_markers, 1);
    assert_eq!(committed.dependency_objects, 1);
    assert_eq!(committed.dependency_edges, 1);
    assert_eq!(committed.effective_state_checkpoints, 1);
    let restarted = soland_storage_postgres::build_state_resolution_stores(
        Some(pool.clone()),
        stores.cell_registry.clone(),
    );
    assert!(
        restarted
            .control_event_store
            .list_pending_units_for_notary(&realm_id, None, 1)
            .await
            .unwrap()
            .is_empty(),
        "accepted coverage must remove pending work durably"
    );
    let checkpoint = restarted
        .event_seal_committer
        .effective_state_checkpoint(&genesis_seal.id)
        .await
        .unwrap()
        .expect("accepted Seal checkpoint survives adapter reconstruction");
    assert_eq!(checkpoint.realm_id, realm_id);
    assert_eq!(checkpoint.seal_id, genesis_seal.id);
    assert_eq!(checkpoint.covered_event_digests, genesis_covered);
    assert_eq!(
        checkpoint.covered_seal_ids,
        [genesis_seal.id.clone()].into_iter().collect()
    );
    assert!(checkpoint.state.is_empty());
    assert_eq!(
        stores
            .control_event_store
            .covering_seals(&genesis_digest)
            .await
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
            .commit_if_head(
                &genesis_seal,
                arkret_canonical::DigestSuite::Sha256,
                None,
                &[],
                &genesis_covered,
                std::slice::from_ref(&genesis_write),
            )
            .await
            .unwrap(),
        "an exact retry must observe the same complete dependency set"
    );
    let replay_mismatch =
        seal_dependency_contract_availability(&genesis_event, "exact-retry-mismatch");
    let replay_mismatch_digest = seal_dependency_contract_digest(&replay_mismatch);
    let replay_error = stores
        .event_seal_committer
        .commit_if_head(
            &genesis_seal,
            arkret_canonical::DigestSuite::Sha256,
            None,
            &[],
            &genesis_covered,
            &[GovernanceDependencyWrite {
                realm_id: realm_id.clone(),
                source: GovernanceDependencySource::Seal(genesis_seal.id.clone()),
                edge_index: 0,
                item: replay_mismatch,
            }],
        )
        .await
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
        put_pending_control_singleton(
            stores.control_event_store.as_ref(),
            &event,
            &ingress,
            arkret_canonical::DigestSuite::Sha256,
        )
        .await
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
            Some(genesis_seal.id.clone()),
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
                write.source = GovernanceDependencySource::Event(event_digest.clone());
            }
            "index" => write.edge_index = 1,
            "object" => {}
            _ => unreachable!(),
        }
        stores
            .event_seal_committer
            .commit_if_head(
                &seal,
                arkret_canonical::DigestSuite::Sha256,
                Some(&genesis_seal.id),
                &[],
                &covered,
                &[write],
            )
            .await
            .unwrap_err();
        let counts = seal_dependency_atomic_counts(&pool, &seal.id, &object_digest).await;
        assert_eq!(counts.seals, 0, "{failure} failure leaked a Seal");
        assert!(
            stores
                .control_event_store
                .list_pending_units_for_notary(&realm_id, None, 1024)
                .await
                .unwrap()
                .iter()
                .flat_map(|unit| &unit.members)
                .any(|pending| pending.event.event_id == event.event_id),
            "{failure} rollback lost pending work"
        );
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
            counts.effective_state_checkpoints, 0,
            "{failure} failure leaked an effective-state checkpoint"
        );
        assert!(
            stores
                .control_event_store
                .covering_seals(&event_digest)
                .await
                .unwrap()
                .is_empty()
        );
    }

    let (cas_event, cas_digest) = seal_dependency_contract_event(&realm_id, "cas-loss");
    put_pending_control_singleton(
        stores.control_event_store.as_ref(),
        &cas_event,
        &ingress,
        arkret_canonical::DigestSuite::Sha256,
    )
    .await
    .unwrap();
    let cas_dependency = seal_dependency_contract_availability(&cas_event, "cas-loss");
    let cas_object_digest = seal_dependency_contract_digest(&cas_dependency);
    let cas_covered = [genesis_digest, cas_digest.clone()]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    let cas_seal = seal_dependency_contract_seal(
        &realm_id,
        Some(genesis_seal.id.clone()),
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
    let stale_basis = stores
        .event_seal_committer
        .commit_if_head(
            &cas_seal,
            arkret_canonical::DigestSuite::Sha256,
            None,
            &[],
            &cas_covered,
            std::slice::from_ref(&cas_write),
        )
        .await
        .unwrap_err();
    assert!(
        stale_basis
            .to_string()
            .contains("predecessor_ref does not match")
    );
    let stale_basis_counts =
        seal_dependency_atomic_counts(&pool, &cas_seal.id, &cas_object_digest).await;
    assert_eq!(stale_basis_counts.seals, 0);
    assert_eq!(stale_basis_counts.effective_state_checkpoints, 0);
    assert!(
        stores
            .control_event_store
            .covering_seals(&cas_digest)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn postgres_rejected_command_unit_is_terminal_atomically_and_never_coverage() {
    use arkret_state::state::store::{
        AcklessSelfPrincipalIngress, ControlProposalIngress, ControlUnitIngressMember,
    };
    let pool = test_pool().await;
    let _db_guard = DB_GUARD.lock().await;
    let registry = std::sync::Arc::new(
        soland_domain::reducer::state_model_kinds::try_build_validated_sdk_cell_registry().unwrap(),
    );
    let stores =
        soland_storage_postgres::build_state_resolution_stores(Some(pool.clone()), registry);
    let suite = arkret_canonical::DigestSuite::Sha256;
    let realm_id = arkret_identifiers::RealmId::new(event_derived_realm_id(
        format!("rejected-unit:{}", uuid::Uuid::now_v7()).as_bytes(),
    ))
    .unwrap();
    let ingress = ControlProposalIngress::AcklessSelfPrincipal(AcklessSelfPrincipalIngress {
        device_id: "ak:device:01904100-0000-7000-8000-000000000001".to_owned(),
        device_authorize_event_id: format!("ak:event:{}", "b".repeat(43)),
        device_generation_ref: 1,
        seal_basis_digest: format!("sha256:{}", "c".repeat(64)),
    });
    let (genesis_event, genesis_digest) = seal_dependency_contract_event(&realm_id, "genesis");
    put_pending_control_singleton(
        stores.control_event_store.as_ref(),
        &genesis_event,
        &ingress,
        suite,
    )
    .await
    .unwrap();
    let covered = [genesis_digest.clone()].into_iter().collect();
    let mut genesis = seal_dependency_contract_seal(
        &realm_id,
        None,
        genesis_digest.clone(),
        &covered,
        genesis_digest,
    );
    genesis.availability_receipt_digests.clear();
    genesis.id = genesis.derive_id(suite).unwrap();
    assert!(
        stores
            .event_seal_committer
            .commit_if_head(&genesis, suite, None, &[], &covered, &[])
            .await
            .unwrap()
    );

    // An atomic self-leave may have 257 members, exceeding the old Event page.
    let members = (0..257)
        .map(|index| ControlUnitIngressMember {
            event: seal_dependency_contract_event(&realm_id, &format!("unit-{index}")).0,
            ingress: ingress.clone(),
            digest_suite: suite,
        })
        .collect::<Vec<_>>();
    let digests = stores
        .control_event_store
        .put_pending_unit_with_ingress(&members)
        .await
        .unwrap();
    let page = stores
        .control_event_store
        .list_pending_units_for_notary(&realm_id, None, 1)
        .await
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].members.len(), 257);
    assert!(
        stores
            .control_event_store
            .list_pending_units_for_notary(&realm_id, Some(&digests[128]), 1)
            .await
            .unwrap()
            .is_empty()
    );
    let reason = arkret_wire::ReasonCode::CallStateTransitionInvalid;
    let mut rejected = genesis.clone();
    rejected.predecessor_ref = Some(genesis.id.clone());
    rejected.notary_seq = 1;
    rejected.delta.clear();
    rejected.command_results = vec![
        arkret_wire::SealCommandOutcome::rejected(
            digests[0].clone(),
            digests.clone(),
            reason.clone(),
            suite,
        )
        .unwrap(),
    ];
    rejected.id = rejected.derive_id(suite).unwrap();
    assert!(
        stores
            .event_seal_committer
            .commit_if_head(&rejected, suite, None, &[], &covered, &[])
            .await
            .is_err()
    );
    assert_eq!(
        stores
            .control_event_store
            .list_pending_units_for_notary(&realm_id, None, 1)
            .await
            .unwrap()[0]
            .members
            .len(),
        257
    );
    assert!(
        stores
            .event_seal_committer
            .commit_if_head(&rejected, suite, Some(&genesis.id), &[], &covered, &[])
            .await
            .unwrap()
    );
    let restarted = soland_storage_postgres::build_state_resolution_stores(
        Some(pool),
        stores.cell_registry.clone(),
    );
    assert!(
        restarted
            .control_event_store
            .list_pending_units_for_notary(&realm_id, None, 1)
            .await
            .unwrap()
            .is_empty()
    );
    for (index, digest) in digests.iter().enumerate() {
        assert!(
            restarted
                .control_event_store
                .covering_seals(digest)
                .await
                .unwrap()
                .is_empty()
        );
        let snapshot = restarted
            .control_event_store
            .control_proposal_snapshot(digest)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.command_decisions.len(), 1);
        let decision = &snapshot.command_decisions[0];
        assert_eq!(decision.seal_id, rejected.id);
        assert_eq!(decision.command_index, 0);
        assert_eq!(decision.member_index, index as u32);
        assert_eq!(decision.outcome, arkret_wire::CommandOutcome::Rejected);
        assert_eq!(decision.reason_code.as_ref(), Some(&reason));
    }
}

#[tokio::test]
async fn postgres_adapter_satisfies_shared_idempotency_contract() {
    let pool = test_pool().await;
    let _db_guard = DB_GUARD.lock().await;
    let store = PgIdempotencyStore { pool };
    let namespace = format!("postgres-contract-{}", uuid::Uuid::now_v7());
    assert_idempotency_store_contract(&store, &namespace).await;
}

#[tokio::test]
async fn postgres_account_notification_upsert_and_remove_stream_as_typed_deltas() {
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

    let pool = test_pool().await;
    let _db_guard = DB_GUARD.lock().await;
    let store = PgNotificationStore { pool: pool.clone() };
    let run_id = uuid::Uuid::now_v7();
    let notification_uuid = uuid::Uuid::now_v7();
    let notification_id =
        arkret_wire::NotificationId::new(format!("ak:notification:{notification_uuid}")).unwrap();
    let controller_account_pk = soland_storage::AccountPk(1);
    let recipient_actor_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(format!("ak:did_core:web:notification-{run_id}.example"))
            .unwrap(),
        arkret_wire::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
    ));
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
            arkret_models_collaboration::objects::read_receipts::NotificationIdentity::AgentApproval(
                notification_id.clone(),
            ),
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
            arkret_models_collaboration::objects::read_receipts::NotificationIdentity::AgentApproval(
                notification_id,
            ),
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
async fn postgres_adapter_satisfies_unscoped_signer_evidence_contract() {
    let pool = test_pool().await;
    let _db_guard = DB_GUARD.lock().await;
    let store = PgGovernanceDependencyStore { pool };
    let namespace = format!("postgres-unscoped-signer-{}", uuid::Uuid::now_v7());
    assert_governance_unscoped_signer_evidence_contract(&store, &namespace).await;
}

#[tokio::test]
async fn postgres_adapter_retains_seal_dependencies_before_seal_publication() {
    let pool = test_pool().await;
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
async fn postgres_adapter_commits_control_event_governance_dependencies_and_control_seal_schedule_atomically()
 {
    let pool = test_pool().await;
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
async fn postgres_adapter_satisfies_mimi_consent_correlation_contract() {
    let pool = test_pool().await;
    let _db_guard = DB_GUARD.lock().await;
    let store = PgMimiConsentCorrelationStore { pool };
    let namespace = format!("postgres-mimi-consent-{}", uuid::Uuid::now_v7());
    assert_mimi_consent_correlation_store_contract(&store, &namespace).await;
}

#[tokio::test]
async fn postgres_adapter_satisfies_control_proposal_authority_ack_contract() {
    let pool = test_pool().await;
    let _db_guard = DB_GUARD.lock().await;
    let store = PgControlProposalAuthorityAckStore { pool };
    let namespace = format!("postgres-control-proposal-ack-{}", uuid::Uuid::now_v7());
    assert_control_proposal_authority_ack_store_contract(&store, &namespace).await;
}

#[tokio::test]
async fn postgres_adapter_satisfies_shared_event_commit_contract() {
    let pool = test_pool().await;
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
async fn postgres_adapter_satisfies_formal_applet_commit_transaction_contract() {
    let pool = test_pool().await;
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
async fn postgres_applet_authoring_preview_has_one_durable_exact_winner() {
    let pool = test_pool().await;
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
async fn postgres_adapter_satisfies_shared_consent_projection_commit_contract() {
    let pool = test_pool().await;
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
async fn postgres_adapter_settles_sealed_device_revocations() {
    use diesel::sql_types::Text;
    use diesel::{QueryableByName, sql_query};
    use diesel_async::RunQueryDsl;
    use soland_storage::DeviceRevocationStore;

    let pool = test_pool().await;
    let _db_guard = DB_GUARD.lock().await;
    let cell_registry: std::sync::Arc<dyn arkret_state::state::CellStateRegistry> =
        std::sync::Arc::new(
            soland_domain::reducer::state_model_kinds::try_build_validated_sdk_cell_registry()
                .expect("validated SDK cell registry"),
        );
    let stores =
        soland_storage_postgres::build_state_resolution_stores(Some(pool.clone()), cell_registry);
    let unit_of_work = PgEventCommitUnitOfWork::new(pool.clone());
    let revocations = soland_storage_postgres::PgDeviceRevocationStore { pool: pool.clone() };
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

    #[derive(QueryableByName)]
    struct ProposalRow {
        #[diesel(sql_type = Text)]
        proposal_digest: String,
    }
    let mut conn = pool.get().await.unwrap();
    let original =
        sql_query("SELECT proposal_digest FROM device_revocation_targets WHERE principal_id = $1")
            .bind::<Text, _>(format!("ak:did_core:web:{namespace}.example"))
            .get_result::<ProposalRow>(&mut conn)
            .await
            .unwrap();
    let expected = revocations
        .target_for_proposal(&original.proposal_digest)
        .await
        .unwrap()
        .unwrap();
    let damaged_digest = arkret_canonical::canonical_sha256(&namespace).unwrap();
    let damaged_event_id = arkret_wire::EventId::from_event_digest(
        &arkret_wire::Hash::new(damaged_digest.clone()).unwrap(),
    )
    .unwrap();
    // Inject damaged persistence alongside the valid target. This is a fault
    // fixture, never a second admitted or accepted canonical Event.
    sql_query(
        "INSERT INTO state_control_events \
         (event_digest, digest_suite, realm_id, event_json, control_proposal_ack, ingress_class, command_unit_event_digests) \
         SELECT $1, digest_suite, realm_id, event_json, '{}'::jsonb, ingress_class, jsonb_build_array($1) \
         FROM state_control_events WHERE event_digest = $2",
    )
    .bind::<Text, _>(&damaged_digest)
    .bind::<Text, _>(&original.proposal_digest)
    .execute(&mut conn)
    .await
    .unwrap();
    sql_query(
        "INSERT INTO device_revocation_targets \
         (proposal_digest, principal_id, station_id, device_id, target_device_authorize_event_id, \
          target_device_generation_ref, proposal_event_id, accepted_at, acceptance_seq, control_proposal_ack) \
         SELECT $1, principal_id, station_id, device_id, target_device_authorize_event_id, \
          target_device_generation_ref, $2, accepted_at, acceptance_seq + 1, '{}'::jsonb \
         FROM device_revocation_targets WHERE proposal_digest = $3",
    )
    .bind::<Text, _>(&damaged_digest)
    .bind::<Text, _>(damaged_event_id.as_str())
    .bind::<Text, _>(&original.proposal_digest)
    .execute(&mut conn)
    .await
    .unwrap();
    drop(conn);
    let exact = revocations
        .target_for_proposal(&original.proposal_digest)
        .await;
    let damaged = revocations.target_for_proposal(&damaged_digest).await;
    let all = revocations.list_targets(&expected.selector).await;
    let mut conn = pool.get().await.unwrap();
    sql_query("DELETE FROM device_revocation_targets WHERE proposal_digest = $1")
        .bind::<Text, _>(&damaged_digest)
        .execute(&mut conn)
        .await
        .unwrap();
    sql_query("DELETE FROM state_control_events WHERE event_digest = $1")
        .bind::<Text, _>(&damaged_digest)
        .execute(&mut conn)
        .await
        .unwrap();
    assert_eq!(exact.unwrap(), Some(expected));
    assert!(
        damaged.is_err(),
        "the corrupt target itself must fail closed"
    );
    assert!(
        all.is_err(),
        "a complete generation read must expose corruption"
    );
}

#[tokio::test]
async fn postgres_event_commit_indexes_basis_free_control_anchor_and_control_seal_schedule() {
    use diesel::sql_types::Text;
    use diesel::{QueryableByName, sql_query};
    use diesel_async::RunQueryDsl;
    use soland_storage::{
        CanonicalEventRecord, EventCommitRequest, EventCommitUnitOfWork, EventStore,
    };

    #[derive(QueryableByName)]
    struct CountRow {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        value: i64,
    }

    let pool = test_pool().await;
    let _db_guard = DB_GUARD.lock().await;
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
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
    let decision_policy = arkret_wire::ControlProposalDecisionPolicy::default();
    let mut authority_ack = arkret_wire::ControlProposalAuthorityAck {
        realm_id: realm_id.clone(),
        proposal_digest: proposal_digest.clone(),
        received_at: now,
        decision_due_at: now + decision_policy.decision_window,
        absolute_due_at: now + decision_policy.absolute_horizon,
        authority_set_ref: authority_set_ref.clone(),
        signature: arkret_wire::PayloadSignature {
            verification_method: arkret_wire::DidUrl::new(
                "did:web:service.example#authority-1".to_owned(),
            )
            .unwrap(),
            payload_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            created_at: now,
            jws: "e30..c2ln".to_owned(),
        },
    };
    authority_ack.signature.payload_digest = authority_ack.authority_ack_digest().unwrap();
    let ack =
        arkret_wire::ControlProposalAck::from_authority_acks(vec![authority_ack], decision_policy)
            .unwrap();
    let envelope = serde_json::to_value(&event).unwrap();
    let canonical_bytes =
        arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(EventCommitRequest {
            mls_public_producer: None,
            mls_public_genesis: None,
            mls_frontier_leaves: None,
            replicated: false,
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
                arkret_state::state::store::ControlProposalIngress::AckRequired(ack.clone()),
            ),
            device_revocation_transition: None,
            device_revocation_gate: None,
            projections: Vec::new(),
            idempotency: None,
            outbox: Vec::new(),
        })
        .await
        .expect("commit basis-free Control anchor with its Control Proposal Ack");

    assert_eq!(
        PgEventStore { pool: pool.clone() }
            .control_proposal_ack_for_digest(proposal_digest.as_str())
            .await
            .expect("read the durable Control Proposal Ack by proposal digest"),
        Some(ack),
        "federation backfill must recover the exact durable Ack"
    );

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

/// The closed exemption to whole-group quarantine.
///
/// `operations-sync.md` section 12 quarantines every variant of a colliding
/// identity until a verdict arrives, and then stops: an accepted
/// `canonical_winner` settles the identity, so a redelivered variant is
/// evidence to keep, not grounds to reopen it. This walks all three arrivals
/// that can follow a verdict — the winner, the loser, and anything at all after
/// `void_all` — because the failure mode is silent: each one that
/// requarantines undoes the verdict and puts the Realm back where it was.
#[tokio::test]
async fn postgres_settled_collision_admits_the_winner_and_refuses_the_rest() {
    use diesel::sql_types::{BigInt, Binary, SmallInt, Text};
    use diesel::{QueryableByName, sql_query};
    use diesel_async::RunQueryDsl;
    use soland_storage::{
        CanonicalEventRecord, EventStore, FederationFrontierExchangeStore, PersistenceError, ids,
    };
    use soland_storage_postgres::PgFederationFrontierExchangeStore;

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

    async fn stored_event_state(pool: &PgPool, event_pk: i64) -> String {
        let mut conn = pool.get().await.unwrap();
        sql_query("SELECT state FROM canonical_events WHERE pk = $1")
            .bind::<BigInt, _>(event_pk)
            .get_result::<StateRow>(&mut conn)
            .await
            .unwrap()
            .state
    }

    let pool = test_pool().await;
    let _db_guard = DB_GUARD.lock().await;
    let events = PgEventStore { pool: pool.clone() };
    let federation = PgFederationFrontierExchangeStore { pool: pool.clone() };
    let now = chrono::Utc::now();
    // The admission timestamp is the covering Seal's, so it is deliberately not
    // `now`: a Station that only ever held the loser has to land on the same
    // value as one that held the winner all along.
    let sealed_at = chrono::DateTime::from_timestamp_millis(
        (now - chrono::Duration::hours(5)).timestamp_millis(),
    )
    .unwrap();

    // Every arrival below is a real preimage of its own identity — only the
    // arriving record is revalidated against the digest — while the row already
    // in the table carries the other variant's bytes. That is exactly the state
    // a Station is in when it admitted one variant of a collision and never saw
    // the other, and it is the only way to stage a collision without one.
    let run_id = uuid::Uuid::now_v7();
    let realm_id =
        event_derived_realm_id(format!("postgres-settled-collision-realm-{run_id}").as_bytes());
    let actor_id = format!("ak:did_core:web:settled-collision-{run_id}.example");
    let mut conn = pool.get().await.unwrap();
    let realm_identity = ids::realm_identity_parts(&realm_id).unwrap();
    let realm_pk = sql_query(
        "INSERT INTO canonical_realms (id, digest_suite, digest, wire_id) \
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

    // Three independent identities, one per arrival being exercised.
    let mut staged = Vec::new();
    for (index, resident_bytes) in [
        // 0: the Station holds the loser and the winner arrives.
        br#"{"variant":"resident-loser"}"#.to_vec(),
        // 1: the Station holds the winner and the loser arrives.
        br#"{"variant":"resident-winner"}"#.to_vec(),
        // 2: `void_all`, and any variant arrives.
        br#"{"variant":"resident-voided"}"#.to_vec(),
    ]
    .into_iter()
    .enumerate()
    {
        let preimage = format!(r#"{{"arriving":"{run_id}","slot":{index}}}"#).into_bytes();
        let digest = arkret_canonical::sha256_bytes(&preimage);
        let mut id = [0_u8; ids::EVENT_ID_BYTES];
        id[0] = 0x01;
        id[1..].copy_from_slice(&digest);
        let event_id = ids::format_event_id(&id);
        let event_pk = sql_query(
            "INSERT INTO canonical_events \
             (id, digest_suite, digest, actor_id, actor_seq, realm_id, realm_pk, kind, schema_id, \
              canonical_bytes, envelope, received_at) \
             VALUES ($1, 1, $2, $3, $4, $5, $6, 'ak.test.data', 'arkret://events/test/v1', \
                     $7, $8, $9) RETURNING pk",
        )
        .bind::<Binary, _>(id.to_vec())
        .bind::<Binary, _>(digest.to_vec())
        .bind::<Text, _>(&actor_id)
        .bind::<BigInt, _>(20 + index as i64)
        .bind::<Text, _>(&realm_id)
        .bind::<BigInt, _>(realm_pk)
        .bind::<Binary, _>(resident_bytes.clone())
        .bind::<diesel::sql_types::Jsonb, _>(
            serde_json::json!({"proofs": [{"jws": "already-verified"}], "variant": "resident"}),
        )
        .bind::<diesel::sql_types::Timestamptz, _>(now)
        .get_result::<PkRow>(&mut conn)
        .await
        .unwrap()
        .pk;
        staged.push((
            event_id.clone(),
            event_pk,
            resident_bytes,
            CanonicalEventRecord {
                event_id,
                actor_id: actor_id.clone(),
                actor_seq: 20 + index as u64,
                realm_id: Some(realm_id.clone()),
                kind: "ak.test.data".to_owned(),
                schema_id: "arkret://events/test/v1".to_owned(),
                digest_suite: arkret_canonical::DigestSuite::Sha256,
                canonical_digest: ids::format_event_digest(0x01, &digest).unwrap(),
                canonical_bytes: preimage,
                envelope: serde_json::json!({"variant": "arriving"}),
                received_at: now,
            },
        ));
    }
    drop(conn);

    // The verdicts. Slot 0 names the arriving bytes, slot 1 names the bytes
    // already resident, slot 2 voids the identity outright.
    for (index, (event_id, _, resident_bytes, arriving)) in staged.iter().enumerate() {
        let winner_canonical_bytes = match index {
            0 => Some(arriving.canonical_bytes.clone()),
            1 => Some(resident_bytes.clone()),
            _ => None,
        };
        let subject =
            arkret_models_collaboration::events_payloads::ForkResolutionSubject::EventIdCollision {
                event_id: arkret_wire::EventId::new(event_id.clone()).unwrap(),
            };
        federation
            .record_local_normalization(
                &soland_storage::FederationFrontierResolutionRecord {
                    realm_id: realm_id.clone(),
                    cell_subject_key: subject.cell_subject_key().unwrap().to_string(),
                    subject: serde_json::to_value(&subject).unwrap(),
                    verdict: match index {
                        2 => serde_json::json!({"kind": "void_all"}),
                        _ => serde_json::json!({"kind": "canonical_winner", "winner_index": 0}),
                    },
                    conflict_evidence_digest: format!("sha256:{}", "6".repeat(64)),
                    resolution_event_digest: format!("sha256:{}", "7".repeat(64)),
                    normalized_at: 30 + index as i64,
                },
                &soland_storage::FederationForkNormalizationScope::EventIdCollision {
                    event_id: event_id.clone(),
                    winner_sealed_at_ms: winner_canonical_bytes
                        .is_some()
                        .then(|| sealed_at.timestamp_millis()),
                    winner_canonical_bytes,
                },
            )
            .await
            .unwrap();
    }

    // Slot 0: the verdict already admitted the winner when it was recorded, so
    // redelivering the same bytes is an ordinary replay rather than a conflict.
    let (event_id, event_pk, resident_bytes, arriving) = &staged[0];
    events.put(arriving.clone()).await.unwrap();
    let admitted = events
        .get(event_id)
        .await
        .unwrap()
        .expect("the winner is the accepted variant of a settled identity");
    assert_eq!(admitted.canonical_bytes, arriving.canonical_bytes);
    assert_eq!(
        admitted.received_at, sealed_at,
        "the admitted Event is timestamped from the covering Seal, not a local clock",
    );
    assert_eq!(
        admitted.envelope.get("proofs"),
        Some(&serde_json::json!([{"jws": "already-verified"}])),
        "both variants bind the same event_digest, so the proofs this Station already \
         verified for the identity carry over instead of being re-derived",
    );
    assert_eq!(
        events
            .collision_variants(event_id)
            .await
            .unwrap()
            .iter()
            .map(|variant| variant.canonical_bytes.clone())
            .collect::<Vec<_>>(),
        vec![resident_bytes.clone()],
        "the displaced loser is retained as a forensic variant",
    );
    assert_eq!(stored_event_state(&pool, *event_pk).await, "accepted");

    // Slot 1: the loser arrives at a Station holding the winner. Refused, kept,
    // and the accepted row is left exactly as the verdict left it.
    let (event_id, event_pk, resident_bytes, arriving) = &staged[1];
    let error = events.put(arriving.clone()).await.unwrap_err();
    assert!(
        matches!(error, PersistenceError::Conflict(reason) if reason == "event_hash_collision"),
        "a settled identity still refuses a second preimage",
    );
    assert_eq!(
        events
            .get(event_id)
            .await
            .unwrap()
            .expect("the winner stays readable")
            .canonical_bytes,
        resident_bytes.clone(),
    );
    assert_eq!(
        events.collision_variants(event_id).await.unwrap().len(),
        1,
        "the refused loser is retained as a forensic variant",
    );
    assert_eq!(
        stored_event_state(&pool, *event_pk).await,
        "accepted",
        "a settled identity is not requarantined by a redelivered loser",
    );

    // Slot 2: after `void_all` the identity has no accepted variant here, and
    // an arrival must not revive it.
    let (event_id, event_pk, _, arriving) = &staged[2];
    let error = events.put(arriving.clone()).await.unwrap_err();
    assert!(
        matches!(error, PersistenceError::Conflict(reason) if reason == "event_hash_collision")
    );
    assert!(
        events.get(event_id).await.unwrap().is_none(),
        "void_all leaves the identity with no accepted variant",
    );
    assert_eq!(
        stored_event_state(&pool, *event_pk).await,
        "accepted",
        "void_all is enforced by the read surface, not by requarantining the row",
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

    let pool = test_pool().await;
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
         (event_digest, digest_suite, realm_id, event_json, ingress_class, command_unit_event_digests) \
         VALUES ($1, 'sha256', $2, '{}'::jsonb, '{\"class\":\"ack_required\"}'::jsonb, jsonb_build_array($1))",
    )
    .bind::<Text, _>(&canonical_digest)
    .bind::<Text, _>(&realm_id)
    .execute(&mut conn)
    .await
    .unwrap();
    let seal_id = format!("ak:seal:test:{}", uuid::Uuid::now_v7().simple());
    sql_query(
        "INSERT INTO state_seals \
         (id, digest_suite, realm_id, seal_id_preimage_bytes, accepted_seal_bytes, seal_json, predecessor_ref, is_genesis) \
         VALUES ($1, 'sha256', $2, decode('00', 'hex'), decode('00', 'hex'), \
                 '{}'::jsonb, NULL, true)",
    )
    .bind::<Text, _>(&seal_id)
    .bind::<Text, _>(&realm_id)
    .execute(&mut conn)
    .await
    .unwrap();
    sql_query(
        "INSERT INTO state_seal_control_events \
         (seal_id, realm_id, event_digest, command_index, member_index, outcome, reason_code, accepted_event_bytes_digest, \
          accepted_event_bytes, sealed_at, decision_overdue) \
         VALUES ($1, $2, $3, 0, 0, 'committed', NULL, $3, decode('00', 'hex'), $4, false)",
    )
    .bind::<Text, _>(&seal_id)
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
                    mls_public_producer: None,
                    mls_public_genesis: None,
                    mls_frontier_leaves: None,
                    replicated: false,
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
                    mls_public_producer: None,
                    mls_public_genesis: None,
                    mls_frontier_leaves: None,
                    replicated: false,
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
async fn postgres_adapter_rolls_atomic_batches_back_with_their_outbox() {
    let pool = test_pool().await;
    let _db_guard = DB_GUARD.lock().await;
    let events = PgEventStore { pool: pool.clone() };
    let outbox = PgFederationOutboxStore { pool };
    let namespace = format!("postgres-batch-outbox-{}", uuid::Uuid::now_v7());
    assert_atomic_batch_outbox_rollback_contract(&events, &outbox, &namespace).await;
}

#[tokio::test]
async fn postgres_adapter_satisfies_shared_federation_outbox_contract() {
    let pool = test_pool().await;
    let _db_guard = DB_GUARD.lock().await;
    let store = PgFederationOutboxStore { pool };
    let namespace = format!("postgres-federation-outbox-{}", uuid::Uuid::now_v7());
    assert_federation_outbox_store_contract(&store, &namespace).await;
}

#[tokio::test]
async fn postgres_adapter_satisfies_mls_keypackage_retirement_contract() {
    let pool = test_pool().await;
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
async fn postgres_adapter_satisfies_last_resort_claim_ledger_contract() {
    let pool = test_pool().await;
    let _db_guard = DB_GUARD.lock().await;
    let namespace = format!("postgres-last-resort-{}", uuid::Uuid::now_v7());
    let store = PgMlsKeyPackageStore { pool: pool.clone() };
    let accounts = soland_storage_postgres::PgAccountStore { pool: pool.clone() };
    assert_last_resort_claim_ledger_contract(&store, &accounts, &namespace).await;

    let restarted_store = PgMlsKeyPackageStore { pool };
    let claim_request_id = format!("local-last-resort:{namespace}-01");
    let replayed = restarted_store
        .get_peer_claim(
            &format!("ak:did_core:web:{namespace}.example"),
            &claim_request_id,
        )
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
            &format!("ak:did_core:web:{namespace}.example"),
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
            &format!("ak:did_core:web:{namespace}.example"),
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
            &format!("ak:did_core:web:{namespace}.example"),
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
                &format!("ak:did_core:web:{namespace}.example"),
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
async fn postgres_adapter_satisfies_organization_registration_contract() {
    let pool = test_pool().await;
    let _db_guard = DB_GUARD.lock().await;
    let store = PgOrganizationRegistrationStore::new(pool);
    let namespace = format!(
        "postgres-organization-registration-{}",
        uuid::Uuid::now_v7()
    );
    assert_organization_registration_store_contract(&store, &namespace).await;
}

#[tokio::test]
async fn postgres_account_data_cas_treats_an_absent_key_as_revision_zero() {
    let pool = test_pool().await;
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
        DB_GUARD, cleanup_control_schedule_test_actor, control_seal_schedule_row_count,
        put_pending_control_singleton, test_pool,
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
                mls_public_producer: None,
                mls_public_genesis: None,
                mls_frontier_leaves: None,
                replicated: false,
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
    async fn postgres_control_move_without_ingress_commits_nothing() {
        let pool = test_pool().await;
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
    async fn postgres_control_move_with_unbound_ack_commits_nothing() {
        let pool = test_pool().await;
        let _db_guard = DB_GUARD.lock().await;
        let fixture = control_anchor_fixture("ack-only");
        let mut ack = fixture.ack.clone();
        // Repoint the whole aggregate, members included. Moving only the
        // envelope's digest would trip the SDK's aggregate-consistency check
        // first and never reach the binding check this case exists for.
        let unbound_digest =
            arkret_identifiers::Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap();
        ack.proposal_digest = unbound_digest.clone();
        for member in &mut ack.authority_acks {
            member.proposal_digest = unbound_digest.clone();
            member.signature.payload_digest = member.authority_ack_digest().unwrap();
        }

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
    async fn postgres_control_move_pending_conflict_rolls_back_the_event() {
        let pool = test_pool().await;
        let _db_guard = DB_GUARD.lock().await;
        let fixture = control_anchor_fixture("pending-only");
        {
            let mut conn = pool.get().await.unwrap();
            sql_query(
                "INSERT INTO state_control_events \
                 (event_digest, digest_suite, realm_id, event_json, control_proposal_ack, ingress_class, command_unit_event_digests) \
                 VALUES ($1, $2, $3, $4, NULL, $5, jsonb_build_array($1))",
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
    async fn postgres_control_move_ingress_class_mismatch_and_control_seal_schedule() {
        use arkret_state::state::store::{
            AcklessSelfPrincipalIngress, ControlProposalIngress, StoreError,
        };

        let pool = test_pool().await;
        let _db_guard = DB_GUARD.lock().await;
        let fixture = control_anchor_fixture("class-mismatch");
        let stores = soland_storage_postgres::build_state_resolution_stores(
            Some(pool.clone()),
            std::sync::Arc::new(arkret_state::state::MemoryCellStateRegistry::default()),
        );

        put_pending_control_singleton(
            stores.control_event_store.as_ref(),
            &fixture.event,
            &ControlProposalIngress::AckRequired(fixture.ack.clone()),
            arkret_canonical::DigestSuite::Sha256,
        )
        .await
        .unwrap();
        let snapshot = stores
            .control_event_store
            .control_proposal_snapshot(&fixture.proposal_digest)
            .await
            .unwrap()
            .expect("the durable Control proposal snapshot must be readable");
        assert!(matches!(
            snapshot.ingress_class,
            arkret_state::state::store::ControlProposalIngressClass::AckRequired
        ));
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
                put_pending_control_singleton(
                    stores.control_event_store.as_ref(),
                    &fixture.event,
                    &ackless,
                    arkret_canonical::DigestSuite::Sha256,
                )
                .await,
                Err(StoreError::Conflict(_))
            ),
            "an Ack-required Move cannot be replayed as Ack-less"
        );
        put_pending_control_singleton(
            stores.control_event_store.as_ref(),
            &fixture.event,
            &ControlProposalIngress::AckRequired(fixture.ack.clone()),
            arkret_canonical::DigestSuite::Sha256,
        )
        .await
        .expect("the byte-identical class and Ack remain idempotent");
        cleanup_control_schedule_test_actor(&pool, &fixture.event.actor_id.to_string()).await;
    }
}

#[tokio::test]
async fn postgres_retention_policy_preserves_full_actor_after_reopen() {
    use arkret_wire::{AccountId, ActorId, DidCoreId};
    use soland_storage::{RetentionPolicyRecord, RetentionPolicyStore};
    use soland_storage_postgres::PgRetentionPolicyStore;
    let pool = test_pool().await;
    let _guard = DB_GUARD.lock().await;
    let store = PgRetentionPolicyStore { pool: pool.clone() };
    let principal = DidCoreId::new("ak:did_core:web:retention-author.example").unwrap();
    let realm = format!("retention-roundtrip-{}", uuid::Uuid::now_v7());
    for station in [
        "ak:did_core:web:station-a.example",
        "ak:did_core:web:station-b.example",
    ] {
        let author = ActorId::account(AccountId::new(
            principal.clone(),
            DidCoreId::new(station).unwrap(),
        ));
        let record = RetentionPolicyRecord {
            realm_id: realm.clone(),
            ttl_seconds: 86_400,
            updated_by: author.clone(),
            updated_at: chrono::Utc::now(),
        };
        store.put(&record).await.unwrap();
        let reopened = PgRetentionPolicyStore { pool: pool.clone() };
        let loaded = reopened.get(&realm).await.unwrap().unwrap();
        assert_eq!(loaded.updated_by, author);
        assert_eq!(loaded.ttl_seconds, 86_400);
        let snapshot = reopened.snapshot_all().await.unwrap();
        assert_eq!(
            snapshot
                .iter()
                .find(|r| r.realm_id == realm)
                .unwrap()
                .updated_by,
            author
        );
    }
}

#[tokio::test]
async fn postgres_adapter_satisfies_invite_new_source_ledger_contract() {
    let pool = test_pool().await;
    let _db_guard = DB_GUARD.lock().await;
    let ledger = PgInviteNewSourceLedgerStore { pool: pool.clone() };
    let accounts = PgAccountStore { pool };
    let namespace = format!("postgres-invite-new-source-{}", uuid::Uuid::now_v7());
    assert_invite_new_source_ledger_contract(&ledger, &accounts, &namespace).await;
}

/// A fresh Realm per run so the `(realm_id, cell_subject_key)` normalization
/// key is never carried over from an earlier execution against the same
/// database.
fn fork_normalization_realm() -> arkret_wire::RealmId {
    let mut seed = [0_u8; 32];
    seed[..16].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
    arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        seed,
    ))
}

fn fork_normalization_actor() -> arkret_wire::ActorId {
    arkret_wire::ActorId::service(
        arkret_wire::DidCoreId::new(format!(
            "ak:did_core:web:fork-{}.example",
            uuid::Uuid::now_v7().simple()
        ))
        .unwrap(),
    )
}

/// One sibling at an exact position. `marker` is what makes the canonical
/// bytes — and therefore the Event identity — distinct.
fn fork_sibling_record(
    realm: &arkret_wire::RealmId,
    actor_id: &str,
    actor_seq: u64,
    marker: &str,
    received_at: chrono::DateTime<chrono::Utc>,
) -> soland_storage::CanonicalEventRecord {
    use soland_storage::ids;
    let canonical_bytes =
        format!("{}|{actor_id}|{actor_seq}|{marker}", realm.as_str()).into_bytes();
    let digest = arkret_canonical::sha256_bytes(&canonical_bytes);
    let mut id = [0_u8; ids::EVENT_ID_BYTES];
    id[0] = 0x01;
    id[1..].copy_from_slice(&digest);
    soland_storage::CanonicalEventRecord {
        event_id: ids::format_event_id(&id),
        actor_id: actor_id.to_owned(),
        actor_seq,
        realm_id: Some(realm.to_string()),
        kind: "ak.test.data".to_owned(),
        schema_id: "arkret://events/test/v1".to_owned(),
        digest_suite: arkret_canonical::DigestSuite::Sha256,
        canonical_digest: ids::format_event_digest(0x01, &digest).unwrap(),
        canonical_bytes,
        envelope: serde_json::json!({"marker": marker}),
        received_at,
    }
}

async fn fork_projection_append(
    projections: &PgProjectionEventStore,
    record: &soland_storage::CanonicalEventRecord,
) {
    use soland_storage::ProjectionEventStore;
    projections
        .append(soland_storage::ProjectionEventRecord {
            event_id: record.event_id.clone(),
            realm_id: record.realm_id.clone().unwrap(),
            event_kind: record.kind.clone(),
            operation_kind: "fork-normalization-test".to_owned(),
            operation_id: None,
            sender: None,
            payload: serde_json::json!({}),
            created_at: record.received_at,
            received_at: record.received_at,
        })
        .await
        .unwrap();
}

/// Pin one Event's canonical bytes under a Seal, the way an accepted Seal does.
async fn fork_seal_pin(pool: &PgPool, record: &soland_storage::CanonicalEventRecord) {
    use diesel::sql_query;
    use diesel::sql_types::{Binary, Text, Timestamptz};
    use diesel_async::RunQueryDsl;
    let realm_id = record.realm_id.clone().unwrap();
    let seal_id = format!("ak:seal:test:{}", uuid::Uuid::now_v7().simple());
    let mut conn = pool.get().await.unwrap();
    sql_query(
        "INSERT INTO state_control_events \
         (event_digest, digest_suite, realm_id, event_json, ingress_class, command_unit_event_digests) \
         VALUES ($1, 'sha256', $2, '{}'::jsonb, '{\"class\":\"ack_required\"}'::jsonb, jsonb_build_array($1))",
    )
    .bind::<Text, _>(&record.canonical_digest)
    .bind::<Text, _>(&realm_id)
    .execute(&mut conn)
    .await
    .unwrap();
    sql_query(
        "INSERT INTO state_seals \
         (id, digest_suite, realm_id, seal_id_preimage_bytes, accepted_seal_bytes, seal_json, \
          predecessor_ref, is_genesis) \
         VALUES ($1, 'sha256', $2, decode('00', 'hex'), decode('00', 'hex'), \
                 '{}'::jsonb, NULL, true)",
    )
    .bind::<Text, _>(&seal_id)
    .bind::<Text, _>(&realm_id)
    .execute(&mut conn)
    .await
    .unwrap();
    sql_query(
        "INSERT INTO state_seal_control_events \
         (seal_id, realm_id, event_digest, command_index, member_index, outcome, reason_code, accepted_event_bytes_digest, \
          accepted_event_bytes, sealed_at, decision_overdue) \
         VALUES ($1, $2, $3, 0, 0, 'committed', NULL, $3, $4, $5, false)",
    )
    .bind::<Text, _>(&seal_id)
    .bind::<Text, _>(&realm_id)
    .bind::<Text, _>(&record.canonical_digest)
    .bind::<Binary, _>(&record.canonical_bytes)
    .bind::<Timestamptz, _>(record.received_at)
    .execute(&mut conn)
    .await
    .unwrap();
}

/// A `canonical_winner` verdict has to leave exactly the winner readable —
/// through every accepted read, not just the one the alignment challenge uses.
///
/// `sync/federation.md` §4.5.3 phase one. `PgEventStore` is the only
/// `EventStore` there is, so these are the contract tests for it.
#[tokio::test]
async fn postgres_fork_resolution_canonical_winner_leaves_exactly_the_winner_readable() {
    use diesel::sql_types::{Binary, Text};
    use diesel::{QueryableByName, sql_query};
    use diesel_async::RunQueryDsl;
    use soland_storage::{EventStore, FederationFrontierExchangeStore, ProjectionEventStore, ids};
    use soland_storage_postgres::PgFederationFrontierExchangeStore;

    #[derive(QueryableByName)]
    struct ValueCountRow {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        value: i64,
    }
    #[derive(QueryableByName)]
    struct SealedBytesRow {
        #[diesel(sql_type = Binary)]
        accepted_event_bytes: Vec<u8>,
    }

    let pool = test_pool().await;
    let _db_guard = DB_GUARD.lock().await;
    let events = PgEventStore { pool: pool.clone() };
    let projections = PgProjectionEventStore { pool: pool.clone() };
    let federation = PgFederationFrontierExchangeStore { pool: pool.clone() };
    let now = chrono::Utc::now();
    let realm = fork_normalization_realm();
    let actor_id = fork_normalization_actor();
    let actor = actor_id.to_string();

    let earlier = fork_sibling_record(&realm, &actor, 3, "earlier", now);
    let winner = fork_sibling_record(&realm, &actor, 4, "winner", now);
    let loser_sealed = fork_sibling_record(&realm, &actor, 4, "loser-sealed", now);
    let loser_plain = fork_sibling_record(&realm, &actor, 4, "loser-plain", now);
    for record in [&earlier, &winner, &loser_sealed, &loser_plain] {
        events.put(record.clone()).await.unwrap();
        fork_projection_append(&projections, record).await;
    }
    // The losing sibling is one an earlier Seal already pinned. Normalization
    // must not touch those bytes: the verdict governs what is read now, not
    // what a Seal committed to then.
    fork_seal_pin(&pool, &loser_sealed).await;

    assert_eq!(
        events
            .list_at_realm_actor_position(realm.as_str(), &actor, 4, 65)
            .await
            .unwrap()
            .len(),
        3,
        "the disputed position starts with every sibling readable"
    );

    let subject =
        arkret_models_collaboration::events_payloads::ForkResolutionSubject::EventSiblingPosition {
            actor_id: actor_id.clone(),
            actor_seq: 4,
        };
    federation
        .record_local_normalization(
            &soland_storage::FederationFrontierResolutionRecord {
                realm_id: realm.to_string(),
                cell_subject_key: subject.cell_subject_key().unwrap().to_string(),
                subject: serde_json::to_value(&subject).unwrap(),
                verdict: serde_json::json!({
                    "kind": "canonical_winner",
                    "winner_event_id": winner.event_id,
                }),
                conflict_evidence_digest: format!("sha256:{}", "2".repeat(64)),
                resolution_event_digest: format!("sha256:{}", "3".repeat(64)),
                normalized_at: 1,
            },
            &soland_storage::FederationForkNormalizationScope::SiblingPosition {
                actor_id: actor.clone(),
                actor_seq: 4,
                winner_event_id: Some(winner.event_id.clone()),
            },
        )
        .await
        .unwrap();

    // 1. The exact-position read the sibling-positions disclosure handler makes is now the verdict
    //    itself: precisely one element.
    assert_eq!(
        events
            .list_at_realm_actor_position(realm.as_str(), &actor, 4, 65)
            .await
            .unwrap()
            .into_iter()
            .map(|record| record.event_id)
            .collect::<Vec<_>>(),
        vec![winner.event_id.clone()],
    );
    // 2. Ordinary reads agree, because they are the same projection.
    assert!(events.get(&loser_sealed.event_id).await.unwrap().is_none());
    assert!(!events.contains(&loser_plain.event_id).await.unwrap());
    assert!(events.get(&winner.event_id).await.unwrap().is_some());
    // 3. So does the actor chain the published frontier is built from: the losers are gone, the
    //    untouched position 3 is not.
    assert_eq!(
        events
            .list_for_realm_actor(realm.as_str(), &actor)
            .await
            .unwrap()
            .into_iter()
            .map(|record| record.event_id)
            .collect::<Vec<_>>(),
        vec![earlier.event_id.clone(), winner.event_id.clone()],
    );
    assert_eq!(events.max_actor_seq(&actor).await.unwrap(), Some(4));
    // 4. And so does the reducer's input.
    let mut projected = projections
        .snapshot_realm(realm.as_str())
        .await
        .unwrap()
        .into_iter()
        .map(|record| record.event_id)
        .collect::<Vec<_>>();
    projected.sort();
    let mut expected = vec![earlier.event_id.clone(), winner.event_id.clone()];
    expected.sort();
    assert_eq!(projected, expected);

    // 5. Nothing was deleted. The rows, the projection rows and the bytes the Seal pinned are all
    //    still exactly where they were.
    let mut conn = pool.get().await.unwrap();
    let retained = sql_query(
        "SELECT COUNT(*) AS value FROM canonical_events \
         WHERE realm_id = $1 AND actor_id = $2 AND actor_seq = 4",
    )
    .bind::<Text, _>(realm.as_str())
    .bind::<Text, _>(&actor)
    .get_result::<ValueCountRow>(&mut conn)
    .await
    .unwrap()
    .value;
    assert_eq!(
        retained, 3,
        "normalization must not delete adjudicated bytes"
    );
    let loser_id = ids::parse_event_id(&loser_plain.event_id).unwrap().to_vec();
    let retained_projection = sql_query(
        "SELECT COUNT(*) AS value FROM projection_events projected \
         JOIN canonical_events parent ON parent.pk = projected.event_pk \
         WHERE parent.id = $1",
    )
    .bind::<Binary, _>(loser_id)
    .get_result::<ValueCountRow>(&mut conn)
    .await
    .unwrap()
    .value;
    assert_eq!(
        retained_projection, 1,
        "an adjudicated sibling leaves the reducer's input without losing its row"
    );
    let sealed = sql_query(
        "SELECT accepted_event_bytes FROM state_seal_control_events WHERE event_digest = $1",
    )
    .bind::<Text, _>(&loser_sealed.canonical_digest)
    .get_result::<SealedBytesRow>(&mut conn)
    .await
    .unwrap()
    .accepted_event_bytes;
    assert_eq!(
        sealed, loser_sealed.canonical_bytes,
        "historic Seal bytes survive the verdict verbatim"
    );
}

/// A `void_all` verdict has to empty the position exactly, and keep it empty.
///
/// `event-and-patch.md` §2.6 makes the position final: the actor's chain stops
/// at the last accepted sequence, and a variant that shows up afterwards must
/// not reopen the subject as a fresh first-seen winner.
#[tokio::test]
async fn postgres_fork_resolution_void_all_empties_the_position_and_keeps_it_empty() {
    use diesel::sql_types::Text;
    use diesel::{QueryableByName, sql_query};
    use diesel_async::RunQueryDsl;
    use soland_storage::{EventStore, FederationFrontierExchangeStore};
    use soland_storage_postgres::PgFederationFrontierExchangeStore;

    #[derive(QueryableByName)]
    struct ValueCountRow {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        value: i64,
    }

    let pool = test_pool().await;
    let _db_guard = DB_GUARD.lock().await;
    let events = PgEventStore { pool: pool.clone() };
    let federation = PgFederationFrontierExchangeStore { pool: pool.clone() };
    let now = chrono::Utc::now();
    let realm = fork_normalization_realm();
    let actor_id = fork_normalization_actor();
    let actor = actor_id.to_string();

    let kept = fork_sibling_record(&realm, &actor, 5, "kept", now);
    let voided_a = fork_sibling_record(&realm, &actor, 6, "voided-a", now);
    let voided_b = fork_sibling_record(&realm, &actor, 6, "voided-b", now);
    for record in [&kept, &voided_a, &voided_b] {
        events.put(record.clone()).await.unwrap();
    }
    assert_eq!(events.max_actor_seq(&actor).await.unwrap(), Some(6));

    let subject =
        arkret_models_collaboration::events_payloads::ForkResolutionSubject::EventSiblingPosition {
            actor_id: actor_id.clone(),
            actor_seq: 6,
        };
    federation
        .record_local_normalization(
            &soland_storage::FederationFrontierResolutionRecord {
                realm_id: realm.to_string(),
                cell_subject_key: subject.cell_subject_key().unwrap().to_string(),
                subject: serde_json::to_value(&subject).unwrap(),
                verdict: serde_json::json!({"kind": "void_all"}),
                conflict_evidence_digest: format!("sha256:{}", "4".repeat(64)),
                resolution_event_digest: format!("sha256:{}", "5".repeat(64)),
                normalized_at: 2,
            },
            &soland_storage::FederationForkNormalizationScope::SiblingPosition {
                actor_id: actor.clone(),
                actor_seq: 6,
                winner_event_id: None,
            },
        )
        .await
        .unwrap();

    assert!(
        events
            .list_at_realm_actor_position(realm.as_str(), &actor, 6, 65)
            .await
            .unwrap()
            .is_empty(),
        "void_all reads back as the empty set, which is what alignment compares against"
    );
    assert_eq!(
        events
            .list_for_realm_actor(realm.as_str(), &actor)
            .await
            .unwrap()
            .into_iter()
            .map(|record| record.event_id)
            .collect::<Vec<_>>(),
        vec![kept.event_id.clone()],
    );
    assert_eq!(
        events.max_actor_seq(&actor).await.unwrap(),
        Some(5),
        "the authoring chain stops at the last position that survived"
    );

    // A variant that arrives after the verdict is excluded on arrival. The
    // subtraction keys on the position, not on the ids the verdict happened to
    // have seen, so `void_all` cannot be reopened by a late first-seen sibling.
    let late = fork_sibling_record(&realm, &actor, 6, "late", now);
    events.put(late.clone()).await.unwrap();
    assert!(
        events
            .list_at_realm_actor_position(realm.as_str(), &actor, 6, 65)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(events.get(&late.event_id).await.unwrap().is_none());
    assert_eq!(events.max_actor_seq(&actor).await.unwrap(), Some(5));

    let mut conn = pool.get().await.unwrap();
    let retained = sql_query(
        "SELECT COUNT(*) AS value FROM canonical_events \
         WHERE realm_id = $1 AND actor_id = $2 AND actor_seq = 6",
    )
    .bind::<Text, _>(realm.as_str())
    .bind::<Text, _>(&actor)
    .get_result::<ValueCountRow>(&mut conn)
    .await
    .unwrap()
    .value;
    assert_eq!(retained, 3, "voided variants are retained, not deleted");
}

/// A collision verdict can only be applied on complete canonical bytes.
///
/// Two variants of one full hash are indistinguishable by id, so the verdict
/// compares preimages. It does not merely subtract: `event-auth-state-resolution.md`
/// section 6.3.3 point 3 makes an accepted `canonical_winner` the admission
/// authority for the winner's bytes, so the Station that happens to hold the
/// loser adopts the winner rather than being left unable to answer for that
/// identity at all. A verdict from another Realm still governs nothing here.
#[tokio::test]
async fn postgres_fork_resolution_collision_verdict_admits_the_winning_preimage() {
    use diesel::sql_types::{BigInt, Binary, SmallInt, Text, Timestamptz};
    use diesel::{QueryableByName, sql_query};
    use diesel_async::RunQueryDsl;
    use soland_storage::{EventStore, FederationFrontierExchangeStore, ids};
    use soland_storage_postgres::PgFederationFrontierExchangeStore;

    #[derive(QueryableByName)]
    struct RealmPkRow {
        #[diesel(sql_type = BigInt)]
        pk: i64,
    }

    let pool = test_pool().await;
    let _db_guard = DB_GUARD.lock().await;
    let events = PgEventStore { pool: pool.clone() };
    let federation = PgFederationFrontierExchangeStore { pool: pool.clone() };
    let now = chrono::Utc::now();
    let realm = fork_normalization_realm();
    let actor_id = fork_normalization_actor();
    let actor = actor_id.to_string();

    let mut conn = pool.get().await.unwrap();
    let realm_identity = ids::realm_identity_parts(realm.as_str()).unwrap();
    let realm_pk = sql_query(
        "INSERT INTO canonical_realms (id, digest_suite, digest, wire_id) \
         VALUES ($1, $2, $3, $4) RETURNING pk",
    )
    .bind::<Binary, _>(realm_identity.id.to_vec())
    .bind::<SmallInt, _>(i16::from(realm_identity.digest_suite))
    .bind::<Binary, _>(realm_identity.digest.to_vec())
    .bind::<Text, _>(realm.as_str())
    .get_result::<RealmPkRow>(&mut conn)
    .await
    .unwrap()
    .pk;

    // Two identities, each holding one of a colliding pair. The rows are
    // written directly because no real preimage pair collides on SHA-256; the
    // stored bytes deliberately differ from the identity's digest preimage,
    // which is exactly the state a Station is in when it admitted one variant
    // and never saw the other.
    let winning_preimage = br#"{"kind":"ak.test.data","note":"winner"}"#.to_vec();
    let losing_preimage = br#"{"kind":"ak.test.data","note":"loser"}"#.to_vec();
    // The admission timestamp is the covering Seal's, so it is deliberately not
    // `now`: a Station that only ever held the loser has to land on the same
    // value as one that held the winner all along.
    let winner_sealed_at = chrono::DateTime::from_timestamp_millis(
        (now - chrono::Duration::hours(3)).timestamp_millis(),
    )
    .unwrap();
    let mut identities = Vec::new();
    for (index, stored_bytes) in [&losing_preimage, &winning_preimage, &losing_preimage]
        .into_iter()
        .enumerate()
    {
        let digest =
            arkret_canonical::sha256_bytes(format!("{}|collision|{index}", realm.as_str()));
        let mut id = [0_u8; ids::EVENT_ID_BYTES];
        id[0] = 0x01;
        id[1..].copy_from_slice(&digest);
        sql_query(
            "INSERT INTO canonical_events \
             (id, digest_suite, digest, actor_id, actor_seq, realm_id, realm_pk, kind, schema_id, \
              canonical_bytes, envelope, received_at) \
             VALUES ($1, 1, $2, $3, $4, $5, $6, 'ak.test.data', 'arkret://events/test/v1', \
                     $7, '{}'::jsonb, $8)",
        )
        .bind::<Binary, _>(id.to_vec())
        .bind::<Binary, _>(digest.to_vec())
        .bind::<Text, _>(&actor)
        .bind::<BigInt, _>(10 + index as i64)
        .bind::<Text, _>(realm.as_str())
        .bind::<BigInt, _>(realm_pk)
        .bind::<Binary, _>(stored_bytes.clone())
        .bind::<Timestamptz, _>(now)
        .execute(&mut conn)
        .await
        .unwrap();
        identities.push(ids::format_event_id(&id));
    }
    drop(conn);

    // A collision group can span Realms. The third identity is adjudicated by
    // another Realm's recovery authority, which has no say over this Realm's
    // projection (`event-auth-state-resolution.md` section 6.3.3).
    let foreign_realm = fork_normalization_realm();
    for (index, event_id) in identities.iter().enumerate() {
        let realm_of_verdict = if index == 2 { &foreign_realm } else { &realm };
        let subject =
            arkret_models_collaboration::events_payloads::ForkResolutionSubject::EventIdCollision {
                event_id: arkret_wire::EventId::new(event_id.clone()).unwrap(),
            };
        federation
            .record_local_normalization(
                &soland_storage::FederationFrontierResolutionRecord {
                    realm_id: realm_of_verdict.to_string(),
                    cell_subject_key: subject.cell_subject_key().unwrap().to_string(),
                    subject: serde_json::to_value(&subject).unwrap(),
                    verdict: serde_json::json!({
                        "kind": "canonical_winner",
                        "winner_index": 0,
                    }),
                    conflict_evidence_digest: format!("sha256:{}", "6".repeat(64)),
                    resolution_event_digest: format!("sha256:{}", "7".repeat(64)),
                    normalized_at: 3 + index as i64,
                },
                &soland_storage::FederationForkNormalizationScope::EventIdCollision {
                    event_id: event_id.clone(),
                    winner_canonical_bytes: Some(winning_preimage.clone()),
                    winner_sealed_at_ms: Some(winner_sealed_at.timestamp_millis()),
                },
            )
            .await
            .unwrap();
    }

    let admitted = events
        .get(&identities[0])
        .await
        .unwrap()
        .expect("the verdict admits the winner on the Station that held the loser");
    assert_eq!(
        admitted.canonical_bytes, winning_preimage,
        "an accepted canonical_winner is the admission authority for the winner's bytes",
    );
    assert_eq!(
        admitted.received_at, winner_sealed_at,
        "the admitted Event is timestamped from the covering Seal, not a local clock",
    );
    assert_eq!(
        events
            .collision_variants(&identities[0])
            .await
            .unwrap()
            .iter()
            .map(|variant| variant.canonical_bytes.clone())
            .collect::<Vec<_>>(),
        vec![losing_preimage.clone()],
        "the displaced loser is retained as a forensic variant",
    );
    assert_eq!(
        events
            .get(&identities[1])
            .await
            .unwrap()
            .expect("the winning preimage stays readable")
            .canonical_bytes,
        winning_preimage,
    );
    assert_eq!(
        events
            .get(&identities[2])
            .await
            .unwrap()
            .expect("another Realm's verdict must not rewrite this Realm's variant")
            .canonical_bytes,
        losing_preimage,
    );
}
