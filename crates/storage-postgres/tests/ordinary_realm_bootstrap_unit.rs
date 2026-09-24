mod support;

use arkret_models_collaboration::authority_commit::{
    OrdinaryRealmBootstrapUnitKind, OrdinaryRealmBootstrapUnitSubmission,
    SelfAuthoritySubmitRequest,
};
use diesel::sql_types::{BigInt, Text};
use diesel_async::RunQueryDsl;
use sha2::{Digest as _, Sha256};
use soland_services::{hydration::HydrationProjectionAdapter, projection::ProjectionService};
use soland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, CurrentRealmAuthority,
    OrdinaryRealmBootstrapCommitOutcome, OrdinaryRealmBootstrapCommitUnit, SelfProducerCommitGuard,
};
use soland_storage_postgres::{Db, PgAuthorityCommitStore, test_database::TestDatabase};

struct BootstrapHydrationAdapter;

impl HydrationProjectionAdapter for BootstrapHydrationAdapter {
    fn operation_from_canonical_record(
        &self,
        record: &soland_services::events::AcceptedEvent,
    ) -> Option<arkret_event_draft::ProjectedEventOperation> {
        let event = serde_json::from_value::<arkret_wire::Event>(record.envelope.clone()).ok()?;
        let mut hasher = Sha256::new();
        hasher.update(b"ak:operation:soland-event-projection:v1:");
        hasher.update(record.event_id.as_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        bytes[6] = (bytes[6] & 0x0f) | 0x70;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let operation_id = arkret_identifiers::OperationId::new(format!(
            "ak:operation:{}",
            uuid::Uuid::from_bytes(bytes)
        ))
        .ok()?;
        arkret_event_draft::ProjectedEventOperation::from_accepted_event(
            operation_id,
            arkret_wire::OperationKind::Create,
            None,
            &event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .ok()
    }
}

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

async fn authority_root_count(
    pool: &soland_storage_postgres::PgPool,
    realm_id: &arkret_wire::RealmId,
) -> i64 {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT COUNT(*) AS count FROM realm_authority_root_current_results WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<CountRow>(&mut *conn)
    .await
    .unwrap()
    .count
}

async fn bootstrap_singleton_count(
    pool: &soland_storage_postgres::PgPool,
    realm_id: &arkret_wire::RealmId,
) -> i64 {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT COUNT(*) AS count FROM realm_bootstrap_current_results WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<CountRow>(&mut *conn)
    .await
    .unwrap()
    .count
}

async fn source_outbox_count(
    pool: &soland_storage_postgres::PgPool,
    realm_id: &arkret_wire::RealmId,
) -> i64 {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT COUNT(*) AS count FROM event_federation_outbox o \
         JOIN canonical_events e ON e.pk=o.event_pk WHERE e.realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<CountRow>(&mut *conn)
    .await
    .unwrap()
    .count
}

fn event(
    kind: arkret_wire::EventKind,
    scope_ref: arkret_wire::ScopeRef,
    actor: &arkret_wire::DidCoreId,
    station: &arkret_wire::DidCoreId,
    payload: serde_json::Value,
    at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::Event {
    let mut event = arkret_wire::test_support::raw_event_at(
        kind.as_str(),
        scope_ref,
        actor.clone(),
        station.clone(),
        payload,
        at,
    )
    .unwrap();
    let digest = arkret_wire::Hash::new(
        event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap(),
    )
    .unwrap();
    event.producer_proof = Some(arkret_wire::ProducerEventProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: arkret_wire::DidUrl::new("did:web:bootstrap-actor.example#key")
            .unwrap(),
        event_digest: digest.clone(),
        created_at: arkret_canonical::normalize_timestamp_canonical(at),
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: arkret_wire::test_support::structural_only_detached_jws(&digest),
    });
    event
}

fn signature(
    station: &arkret_wire::DidCoreId,
    at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::DetachedObjectSignature {
    let did = station.as_str().replace("ak:did_core:", "did:");
    arkret_wire::DetachedObjectSignature {
        context: arkret_wire::DetachedSignatureContext::RealmCommit,
        signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
        verification_method: arkret_wire::DidUrl::new(format!("{did}#authority")).unwrap(),
        signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap(),
        created_at: at,
        sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
    }
}

fn unit() -> OrdinaryRealmBootstrapCommitUnit {
    let at = chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis())
        .unwrap();
    let actor = arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-actor.example").unwrap();
    let station = arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap();
    let genesis = event(
        arkret_wire::EventKind::RealmCreate,
        arkret_wire::ScopeRef::RealmGenesis,
        &actor,
        &station,
        serde_json::json!({"object":{
            "schema":"ak.schema.realm_genesis.v1",
            "purpose":"collaboration",
            "genesis_salt":"X-kS8-uBvWQ_iuRqO7Rsv0WGBjZG2S2wJ533Tk2SJJ4",
            "trust_domain":"ak:trust_domain:bootstrap.example",
            "security_class":"high_assurance",
            "governance_station_id":station,
            "initial_join_rule":"invite",
            "initial_history_access":"since_join",
            "initial_discoverability":"invite_only"
        }}),
        at,
    );
    let realm_id = genesis.realm_id.clone();
    let mut events = vec![genesis];
    let creator = events[0].actor_id.clone();
    for kind in [
        arkret_wire::EventKind::RealmProfile,
        arkret_wire::EventKind::RealmPolicyBundle,
        arkret_wire::EventKind::RealmJoinRule,
        arkret_wire::EventKind::RealmHistoryAccess,
        arkret_wire::EventKind::RealmDiscovery,
        arkret_wire::EventKind::MemberState,
    ]
    .into_iter()
    {
        let payload = match kind {
            arkret_wire::EventKind::RealmProfile => serde_json::json!({"name":"Test Realm"}),
            arkret_wire::EventKind::RealmPolicyBundle => serde_json::json!({"policy_revision":1,"federation_policy":"closed"}),
            arkret_wire::EventKind::RealmJoinRule => serde_json::json!({"value":"invite"}),
            arkret_wire::EventKind::RealmHistoryAccess => {
                serde_json::json!({"from":null,"to":"since_join"})
            }
            arkret_wire::EventKind::RealmDiscovery => {
                serde_json::json!({"value":{"discoverability":"invite_only"}})
            }
            arkret_wire::EventKind::MemberState => {
                serde_json::json!({"member_id":creator,"membership":"join"})
            }
            _ => unreachable!(),
        };
        events.push(event(
            kind,
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            &actor,
            &station,
            payload,
            at,
        ));
    }
    let authority = CurrentRealmAuthority {
        realm_id: realm_id.clone(),
        generation: 0,
        service_id: station.clone(),
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
            events[0].event_id.clone(),
        ),
        last_handoff_ref: None,
    };
    let mut previous = None;
    let transactions = events
        .iter()
        .enumerate()
        .map(|(index, event)| {
            let commit_id = arkret_wire::RealmCommitId::from_digest(
                arkret_canonical::sha256_bytes(format!("{}:{index}", event.event_id).as_bytes()),
            );
            let transaction = AuthorityCommitTransaction {
                expected_authority: authority.clone(),
                event: event.clone(),
                commit: arkret_wire::RealmCommit {
                    commit_id: commit_id.clone(),
                    realm_id: realm_id.clone(),
                    stream_ref: arkret_wire::CommitStreamRef::Realm {
                        realm_id: realm_id.clone(),
                    },
                    stream_position: index as u64,
                    previous_commit_ref: previous.clone(),
                    event_ref: event.event_id.clone(),
                    governance_generation: 0,
                    authority_ref: authority.authority_ref.clone(),
                    committed_at: at,
                    signature: signature(&station, at),
                },
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: 0,
            };
            previous = Some(commit_id);
            transaction
        })
        .collect();
    let submission = OrdinaryRealmBootstrapUnitSubmission {
        unit_kind: OrdinaryRealmBootstrapUnitKind::OrdinaryRealmBootstrap,
        idempotency_key: arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap(),
        events: events
            .into_iter()
            .map(arkret_wire::EventAdmissionSubmission::new)
            .collect(),
    };
    let exact_request_body = serde_json::to_vec(
        &SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(submission.clone()),
    )
    .unwrap();
    OrdinaryRealmBootstrapCommitUnit {
        submission,
        exact_request_body,
        transactions,
    }
}

#[tokio::test]
async fn ordinary_bootstrap_failure_rolls_back_every_event_then_exact_replay_returns_same_commits()
{
    let url = support::contract_database_url();
    support::ensure_contract_database(&url).await;
    let pool = Db::connect(Some(&url), Default::default())
        .await
        .unwrap()
        .pool
        .unwrap();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit();
    unit.validate().unwrap();
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let first_event_id = unit.transactions[0].event.event_id.clone();
    let at = unit.transactions[0].commit.committed_at;

    let producer = unit.transactions[0].event.actor_id.as_account_id().unwrap();
    let first_commit = &unit.transactions[0].commit;
    let unaccepted_guard =
        SelfProducerCommitGuard::HumanDevice(soland_storage::DeviceRevocationGateSelector {
            principal_id: producer.principal_id.clone(),
            station_id: producer.station_id.clone(),
            device_id: "key".to_owned(),
            authorization_ref: arkret_wire::CommittedEventRef {
                event_id: first_event_id.clone(),
                commit_id: first_commit.commit_id.clone(),
                stream_ref: first_commit.stream_ref.clone(),
                stream_position: first_commit.stream_position,
            },
        });
    assert!(
        store
            .admit_self_ordinary_realm_bootstrap_unit(&unit, &[], at)
            .await
            .is_err()
    );
    assert!(
        store
            .admit_self_ordinary_realm_bootstrap_unit(
                &unit,
                &vec![unaccepted_guard; unit.transactions.len()],
                at,
            )
            .await
            .is_err()
    );
    assert!(store.current_authority(&realm_id).await.unwrap().is_none());
    assert_eq!(authority_root_count(&pool, &realm_id).await, 0);
    assert_eq!(bootstrap_singleton_count(&pool, &realm_id).await, 0);
    assert_eq!(source_outbox_count(&pool, &realm_id).await, 0);

    let mut failing = unit.clone();
    failing.transactions[1].commit.signature.verification_method =
        arkret_wire::DidUrl::new("did:web:wrong-station.example#authority").unwrap();
    assert!(
        store
            .admit_ordinary_realm_bootstrap_unit(&failing, at)
            .await
            .is_err()
    );
    assert!(store.current_authority(&realm_id).await.unwrap().is_none());
    assert_eq!(authority_root_count(&pool, &realm_id).await, 0);
    assert_eq!(bootstrap_singleton_count(&pool, &realm_id).await, 0);
    assert_eq!(source_outbox_count(&pool, &realm_id).await, 0);
    assert!(store.realm_state_snapshot_material(&realm_id).await.unwrap().is_none());
    for transaction in &unit.transactions {
        assert!(store.queued_event(&transaction.event.event_id).await.unwrap().is_none());
        assert!(store.committed_event(&transaction.event.event_id).await.unwrap().is_none());
    }

    let accepted = store
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let OrdinaryRealmBootstrapCommitOutcome::Committed(commits) = accepted else {
        panic!("first unit must commit");
    };
    assert_eq!(commits.len(), 7);
    for (position, commit) in commits.iter().enumerate() {
        assert_eq!(commit.stream_position, position as u64);
        assert_eq!(
            commit.previous_commit_ref.as_ref(),
            position
                .checked_sub(1)
                .map(|previous| &commits[previous].commit_id)
        );
    }
    assert_eq!(authority_root_count(&pool, &realm_id).await, 1);
    assert_eq!(bootstrap_singleton_count(&pool, &realm_id).await, 5);
    // The only member of this closed founding unit is the creator, whose
    // AccountId names the governing Station. The remote target set is empty.
    assert_eq!(source_outbox_count(&pool, &realm_id).await, 0);
    let snapshot = store
        .realm_state_snapshot_material(&realm_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.current_state_entries.len(), 8);
    assert_eq!(
        snapshot.retention_and_history_floor.history_access,
        arkret_wire::HistoryAccess::SinceJoin
    );
    for selector in [
        arkret_wire::CurrentSelector::RealmGenesis,
        arkret_wire::CurrentSelector::RealmAuthorityRoot,
        arkret_wire::CurrentSelector::RealmProfile,
        arkret_wire::CurrentSelector::RealmPolicyBundle,
        arkret_wire::CurrentSelector::RealmJoinRule,
        arkret_wire::CurrentSelector::RealmHistoryAccess,
        arkret_wire::CurrentSelector::RealmDiscovery,
        arkret_wire::CurrentSelector::MemberState {
            actor_id: unit.transactions[0].event.actor_id.clone(),
        },
    ] {
        assert!(snapshot.current_state_entries.iter().any(|entry| {
            matches!(entry, arkret_wire::TypedCurrentResult::Value { selector: found, .. } if found == &selector)
        }));
    }
    assert!(
        store
            .committed_event(&first_event_id)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        store
            .admit_ordinary_realm_bootstrap_unit(&unit, at)
            .await
            .unwrap(),
        OrdinaryRealmBootstrapCommitOutcome::Duplicate(commits),
    );
    let mut changed = unit;
    changed.exact_request_body.push(b' ');
    assert!(
        store
            .admit_ordinary_realm_bootstrap_unit(&changed, at)
            .await
            .is_err()
    );
    assert_eq!(authority_root_count(&pool, &realm_id).await, 1);
    assert_eq!(bootstrap_singleton_count(&pool, &realm_id).await, 5);
    assert_eq!(source_outbox_count(&pool, &realm_id).await, 0);
}

#[tokio::test]
async fn confirmed_bootstrap_recovers_after_postcommit_projection_install_is_lost() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit();
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let creator = unit.transactions[0].event.actor_id.clone();
    let at = unit.transactions[0].commit.committed_at;

    // Simulate a process failure in the postcommit window: the authority
    // transaction is durable, but no process-local projection is installed.
    assert!(matches!(
        store
            .admit_ordinary_realm_bootstrap_unit(&unit, at)
            .await
            .unwrap(),
        OrdinaryRealmBootstrapCommitOutcome::Committed(_)
    ));
    let fresh_process = ProjectionService::new("bootstrap-restart-test");
    assert!(
        fresh_process
            .snapshot()
            .realm_create_log(realm_id.as_str())
            .is_none()
    );

    let persistence = soland_storage_postgres::PgPersistenceStore::new(pool.clone());
    fresh_process
        .hydrate_from_persistence(&persistence, &BootstrapHydrationAdapter, [realm_id.clone()])
        .await
        .unwrap();
    let restored = fresh_process.snapshot();
    assert_eq!(
        restored.realm_create_log(realm_id.as_str()).unwrap().len(),
        1
    );
    assert_eq!(
        restored.realm_profile_value(realm_id.as_str()),
        Some(&serde_json::json!({"name":"Test Realm"}))
    );
    assert_eq!(
        restored.realm_policy_bundle_value(realm_id.as_str()),
        Some(&serde_json::json!({"policy_revision":1,"federation_policy":"closed"}))
    );
    assert_eq!(
        restored.realm_default_join_rule(realm_id.as_str()),
        "invite"
    );
    assert_eq!(
        restored.realm_history_access(realm_id.as_str()).as_deref(),
        Some("since_join")
    );
    assert!(
        restored
            .member(realm_id.as_str(), &creator.to_string())
            .is_some()
    );
    assert_eq!(source_outbox_count(&pool, &realm_id).await, 0);

    // Rebuilding a second process from the same Commit prefix must be exact.
    let second_process = ProjectionService::new("bootstrap-second-restart-test");
    second_process
        .hydrate_from_persistence(&persistence, &BootstrapHydrationAdapter, [realm_id.clone()])
        .await
        .unwrap();
    let second = second_process.snapshot();
    assert_eq!(
        second.realm_create_log(realm_id.as_str()),
        restored.realm_create_log(realm_id.as_str())
    );
    assert_eq!(
        second.realm_profile_value(realm_id.as_str()),
        restored.realm_profile_value(realm_id.as_str())
    );
    assert_eq!(
        second.realm_history_access(realm_id.as_str()),
        restored.realm_history_access(realm_id.as_str())
    );
}
