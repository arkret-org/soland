mod support;

use arkret_models_collaboration::authority_commit::{
    OrdinaryRealmBootstrapUnitKind, OrdinaryRealmBootstrapUnitSubmission,
    SelfAuthoritySubmitRequest,
};
use diesel::sql_types::{BigInt, Text};
use diesel_async::RunQueryDsl;
use sha2::{Digest as _, Sha256};
use soland_services::hydration::HydrationProjectionAdapter;
use soland_services::projection::ProjectionService;
use soland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, CurrentRealmAuthority, EventCommitRequest,
    EventCommitUnitOfWork, OrdinaryRealmBootstrapCommitOutcome, OrdinaryRealmBootstrapCommitUnit,
    SelfProducerCommitGuard,
};
use soland_storage_postgres::test_database::TestDatabase;
use soland_storage_postgres::{
    Db, PgAuthorityCommitStore, PgEventCommitUnitOfWork, single_member_bootstrap_snapshot_material,
};

#[tokio::test]
async fn single_member_bootstrap_disclosure_requires_the_complete_accepted_cut() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit();
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let creator = unit.transactions[0]
        .event
        .actor_id
        .as_account_id()
        .unwrap()
        .clone();
    let stranger = arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        creator.station_id.clone(),
    );
    let at = unit.transactions[0].commit.committed_at;
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let material = single_member_bootstrap_snapshot_material(&pool, &realm_id, &creator)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(material.current_state_entries.len(), 8);
    assert!(
        single_member_bootstrap_snapshot_material(&pool, &realm_id, &stranger)
            .await
            .is_err()
    );

    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO relation_current_results \
         (realm_id,domain_key,domain,relation_id,state,current_commit_id,current_stream_position,value,updated_at) \
         VALUES ($1,'injected','{}'::jsonb,'ak:relation:test','active',$2,6, \
                 '{\"id\":\"ak:relation:test\",\"state\":\"active\"}'::jsonb,now())",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(unit.transactions[6].commit.commit_id.as_str())
    .execute(&mut conn).await.unwrap();
    assert!(
        single_member_bootstrap_snapshot_material(&pool, &realm_id, &creator)
            .await
            .is_err()
    );
    diesel::sql_query("DELETE FROM relation_current_results WHERE realm_id=$1")
        .bind::<Text, _>(realm_id.as_str())
        .execute(&mut conn)
        .await
        .unwrap();
    drop(conn);

    let strand = strand_create_request(&unit);
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    uow.commit_event(strand.clone()).await.unwrap();
    assert!(
        single_member_bootstrap_snapshot_material(&pool, &realm_id, &creator)
            .await
            .is_err()
    );
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let default = set_default_strand_request(&strand, &strand_id, None);
    uow.commit_event(default).await.unwrap();
    let material = single_member_bootstrap_snapshot_material(&pool, &realm_id, &creator)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(material.current_state_entries.len(), 10);
}

async fn issuance_count(
    pool: &soland_storage_postgres::PgPool,
    realm_id: &arkret_wire::RealmId,
) -> i64 {
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = BigInt)]
        count: i64,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT count(*) AS count FROM realm_state_snapshot_issuances issued \
         JOIN realm_state_snapshots snapshot ON snapshot.snapshot_id = issued.snapshot_id \
         WHERE snapshot.realm_id = $1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<Count>(&mut conn)
    .await
    .unwrap()
    .count
}

/// Real PostgreSQL: `/head` issuance materializes, checks tenure, signs,
/// and archives in one cut; by-ref returns the exact object only while the
/// read cut still re-proves the Account's disclosure.
#[tokio::test]
async fn account_snapshot_issuance_is_same_cut_and_by_ref_rechecks_disclosure() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit();
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let creator = unit.transactions[0]
        .event
        .actor_id
        .as_account_id()
        .unwrap()
        .clone();
    let stranger = arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        creator.station_id.clone(),
    );
    let at = unit.transactions[0].commit.committed_at;
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let issuer = store
        .current_authority(&realm_id)
        .await
        .unwrap()
        .unwrap()
        .service_id;
    let other_station = arkret_wire::DidCoreId::new("ak:did_core:web:elsewhere.example").unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let method = arkret_wire::DidUrl::new("did:web:station.example#notary-key").unwrap();
    let sign = |material: &soland_storage::RealmStateSnapshotMaterial| {
        soland_services::authority_commit::build_signed_realm_state_snapshot(
            material,
            method.clone(),
            &key,
            chrono::Utc::now(),
        )
        .map_err(|error| soland_storage::PersistenceError::Internal(error.to_string()))
    };
    let tamper = |material: &soland_storage::RealmStateSnapshotMaterial| {
        let mut partial = material.clone();
        partial.current_state_entries.pop();
        sign(&partial)
    };

    // No tenure, no complete disclosure, or a signer that alters the proved
    // material: nothing is issued.
    assert!(matches!(
        store
            .issue_realm_state_snapshot_for_account(&realm_id, &creator, &other_station, &sign)
            .await,
        Err(soland_storage::PersistenceError::SchemaViolation(_))
    ));
    assert!(
        store
            .issue_realm_state_snapshot_for_account(&realm_id, &stranger, &issuer, &sign)
            .await
            .is_err()
    );
    assert!(matches!(
        store
            .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &tamper)
            .await,
        Err(soland_storage::PersistenceError::Internal(_))
    ));
    assert_eq!(issuance_count(&pool, &realm_id).await, 0);

    let first = store
        .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &sign)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.current_state_entries.len(), 8);
    assert_eq!(issuance_count(&pool, &realm_id).await, 1);
    let unsigned = arkret_canonical::unsigned_value(&first, &["signature"]).unwrap();
    arkret_signatures::detached_object::verify_detached_object_signature(
        &first.signature,
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmSnapshot,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: key.verifying_key().to_bytes().to_vec(),
        },
    )
    .unwrap();
    let by_ref = |account: arkret_wire::AccountId,
                  realm: arkret_wire::RealmId,
                  id: arkret_wire::RealmSnapshotId,
                  station: arkret_wire::DidCoreId| {
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        async move {
            store
                .issued_realm_state_snapshot(&realm, &account, &id, &station)
                .await
        }
    };
    let exact = by_ref(
        creator.clone(),
        realm_id.clone(),
        first.snapshot_id.clone(),
        issuer.clone(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&exact).unwrap(),
        arkret_canonical::canonical_json_bytes(&first).unwrap(),
    );
    assert!(
        by_ref(
            stranger.clone(),
            realm_id.clone(),
            first.snapshot_id.clone(),
            issuer.clone()
        )
        .await
        .unwrap()
        .is_none()
    );
    let other_realm = unit_with_plaintext_service().transactions[0]
        .event
        .realm_id
        .clone();
    assert!(
        by_ref(
            creator.clone(),
            other_realm,
            first.snapshot_id.clone(),
            issuer.clone()
        )
        .await
        .unwrap()
        .is_none()
    );
    assert!(
        by_ref(
            creator.clone(),
            realm_id.clone(),
            first.snapshot_id.clone(),
            other_station.clone()
        )
        .await
        .is_err()
    );

    // A later cut issues a new exact object; the earlier one stays exactly
    // readable while the Account's join revision is unchanged.
    let strand = strand_create_request(&unit);
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    uow.commit_event(strand.clone()).await.unwrap();
    assert!(
        store
            .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &sign)
            .await
            .is_err()
    );
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    uow.commit_event(set_default_strand_request(&strand, &strand_id, None))
        .await
        .unwrap();
    let second = store
        .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &sign)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second.current_state_entries.len(), 10);
    assert_ne!(second.snapshot_id, first.snapshot_id);
    assert_eq!(issuance_count(&pool, &realm_id).await, 2);
    assert_eq!(
        by_ref(
            creator.clone(),
            realm_id.clone(),
            first.snapshot_id.clone(),
            issuer.clone()
        )
        .await
        .unwrap(),
        Some(first.clone()),
    );
    // The Realm-wide anchor ignores Account-issued disclosures.
    assert_eq!(store.latest_snapshot(&realm_id).await.unwrap(), None);

    // Read-time recheck: once the Account's membership revision changes,
    // neither exact object is disclosable, and restoring it re-admits them.
    let mut conn = pool.get().await.unwrap();
    let member = arkret_wire::ActorId::account(creator.clone()).to_string();
    diesel::sql_query(
        "UPDATE member_state_current_results SET membership='leave', \
         value='{\"membership\":\"leave\"}'::jsonb WHERE realm_id=$1 AND member_id=$2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(&member)
    .execute(&mut conn)
    .await
    .unwrap();
    for id in [&first.snapshot_id, &second.snapshot_id] {
        assert!(matches!(
            by_ref(
                creator.clone(),
                realm_id.clone(),
                id.clone(),
                issuer.clone()
            )
            .await,
            Err(soland_storage::PersistenceError::SchemaViolation(_))
        ));
    }
    diesel::sql_query(
        "UPDATE member_state_current_results SET membership='join', \
         value='{\"membership\":\"join\"}'::jsonb WHERE realm_id=$1 AND member_id=$2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(&member)
    .execute(&mut conn)
    .await
    .unwrap();
    assert!(
        by_ref(
            creator.clone(),
            realm_id.clone(),
            second.snapshot_id.clone(),
            issuer.clone()
        )
        .await
        .unwrap()
        .is_some()
    );

    // Once another Station governs the Realm, this Station can neither
    // re-prove the earlier object nor issue a new one.
    diesel::sql_query("UPDATE realm_authorities SET service_id=$2 WHERE realm_id=$1")
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(other_station.as_str())
        .execute(&mut conn)
        .await
        .unwrap();
    assert!(
        by_ref(
            creator.clone(),
            realm_id.clone(),
            second.snapshot_id.clone(),
            issuer.clone()
        )
        .await
        .is_err()
    );
    assert!(
        store
            .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &sign)
            .await
            .is_err()
    );
    assert_eq!(issuance_count(&pool, &realm_id).await, 2);
}

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

fn rebind_authorization_ref(
    request: &mut EventCommitRequest,
    authorization_event_id: &arkret_wire::EventId,
) {
    let event = &mut request.authority_commit.event;
    event.authorization_ref = Some(arkret_wire::AuthorizationRef::from(
        authorization_event_id.clone(),
    ));
    let preimage =
        arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
    event.event_id = arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(&preimage),
    );
    let digest = arkret_wire::Hash::new(
        event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap(),
    )
    .unwrap();
    let proof = event.producer_proof.as_mut().unwrap();
    proof.event_digest = digest.clone();
    proof.jws = arkret_wire::test_support::structural_only_detached_jws(&digest);
    request.authority_commit.commit.event_ref = event.event_id.clone();
    request.authority_commit.commit.commit_id = arkret_wire::RealmCommitId::from_digest(
        arkret_canonical::sha256_bytes(format!("message:{}", event.event_id).as_bytes()),
    );
    request.event.event_id = event.event_id.to_string();
    request.event.envelope = serde_json::to_value(&*event).unwrap();
    request.event.canonical_bytes = preimage;
    request.event.canonical_digest = event
        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    request.projections[0].event_id = event.event_id.to_string();
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
    let at =
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
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
            arkret_wire::EventKind::RealmPolicyBundle => {
                serde_json::json!({"policy_revision":1,"federation_policy":"closed"})
            }
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

fn unit_with_plaintext_service() -> OrdinaryRealmBootstrapCommitUnit {
    let mut unit = unit();
    let first = &unit.transactions[0];
    let realm_id = first.event.realm_id.clone();
    let account = first.event.actor_id.as_account_id().unwrap();
    let station = first.expected_authority.service_id.clone();
    let at = first.commit.committed_at;
    let event = event(
        arkret_wire::EventKind::RealmPlaintextVisibleServices,
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        &account.principal_id,
        &station,
        serde_json::json!({"services":[{
            "service_id":station,
            "service_kind":"station",
            "data_classes":["message_content"],
            "purposes":["test"],
            "visibility":"private_plaintext"
        }]}),
        at,
    );
    let mut transaction = unit.transactions[6].clone();
    transaction.event = event.clone();
    transaction.commit.event_ref = event.event_id.clone();
    transaction.commit.commit_id = arkret_wire::RealmCommitId::from_digest(
        arkret_canonical::sha256_bytes(format!("plaintext:{}", event.event_id).as_bytes()),
    );
    transaction.commit.previous_commit_ref = Some(unit.transactions[5].commit.commit_id.clone());
    unit.transactions[6].commit.stream_position = 7;
    unit.transactions[6].commit.previous_commit_ref = Some(transaction.commit.commit_id.clone());
    unit.transactions.insert(6, transaction);
    unit.submission
        .events
        .insert(6, arkret_wire::EventAdmissionSubmission::new(event));
    unit.exact_request_body = serde_json::to_vec(
        &SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(unit.submission.clone()),
    )
    .unwrap();
    unit
}

fn strand_create_request(unit: &OrdinaryRealmBootstrapCommitUnit) -> EventCommitRequest {
    let previous = unit.transactions.last().unwrap();
    let realm_id = previous.event.realm_id.clone();
    let actor = previous.event.actor_id.clone();
    let station = previous.expected_authority.service_id.clone();
    let principal = actor.as_account_id().unwrap().principal_id.clone();
    let at = previous.commit.committed_at;
    let event = event(
        arkret_wire::EventKind::StrandCreate,
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        &principal,
        &station,
        serde_json::json!({"object": {
            "schema":"ak.schema.strand.v1",
            "realm_id":realm_id,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Restart test"},
            "state":"active",
            "created_by":actor,
            "created_at":at,
        }}),
        at,
    );
    let commit = arkret_wire::RealmCommit {
        commit_id: arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            format!("strand:{}", event.event_id).as_bytes(),
        )),
        realm_id: realm_id.clone(),
        stream_ref: arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
        stream_position: previous.commit.stream_position + 1,
        previous_commit_ref: Some(previous.commit.commit_id.clone()),
        event_ref: event.event_id.clone(),
        governance_generation: 0,
        authority_ref: previous.expected_authority.authority_ref.clone(),
        committed_at: at,
        signature: signature(&station, at),
    };
    let canonical_bytes =
        arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
    let canonical_digest = event
        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    let envelope = serde_json::to_value(&event).unwrap();
    let projection = soland_storage::ProjectionEventRecord {
        event_id: event.event_id.to_string(),
        realm_id: realm_id.to_string(),
        event_kind: event.kind.as_str().to_owned(),
        operation_kind: "create".to_owned(),
        operation_id: None,
        sender: Some(event.actor_id.to_string()),
        payload: serde_json::to_value(&event.payload).unwrap(),
        created_at: event.created_at,
        received_at: at,
    };
    let record = soland_storage::CanonicalEventRecord {
        event_id: event.event_id.to_string(),
        actor_id: event.actor_id.to_string(),
        realm_id: Some(realm_id.to_string()),
        kind: event.kind.as_str().to_owned(),
        schema_id: arkret_wire::SchemaId::EVENT_V1.to_owned(),
        digest_suite: arkret_canonical::DigestSuite::Sha256,
        canonical_digest,
        canonical_bytes,
        envelope,
        received_at: at,
    };
    EventCommitRequest {
        authority_commit: AuthorityCommitTransaction {
            expected_authority: previous.expected_authority.clone(),
            event,
            commit,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        },
        self_producer_guard: None,
        event: record,
        parent_membership_admission: None,
        device_pairing_authorization: None,
        contact_projection: None,
        agent_draft_pending_intent: None,
        actor_private_account_data: None,
        consent_projection: None,
        device_revocation_transition: None,
        device_revocation_gate: None,
        projections: vec![projection],
        idempotency: None,
        outbox: Vec::new(),
    }
}

fn set_default_strand_request(
    previous: &EventCommitRequest,
    strand_id: &arkret_wire::StrandId,
    expected: Option<&arkret_wire::StrandId>,
) -> EventCommitRequest {
    let mut request = previous.clone();
    let previous_commit = &previous.authority_commit.commit;
    let previous_event = &previous.authority_commit.event;
    let realm_id = previous_event.realm_id.clone();
    let actor = previous_event.actor_id.as_account_id().unwrap();
    let event = event(
        arkret_wire::EventKind::RealmSetDefaultStrand,
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        &actor.principal_id,
        &actor.station_id,
        serde_json::json!({
            "realm_id": realm_id,
            "strand_id": strand_id,
            "expected_default_strand_id": expected,
        }),
        previous_commit.committed_at,
    );
    request.authority_commit.event = event.clone();
    request.authority_commit.commit.event_ref = event.event_id.clone();
    request.authority_commit.commit.commit_id = arkret_wire::RealmCommitId::from_digest(
        arkret_canonical::sha256_bytes(format!("default:{}", event.event_id).as_bytes()),
    );
    request.authority_commit.commit.stream_position = previous_commit.stream_position + 1;
    request.authority_commit.commit.previous_commit_ref = Some(previous_commit.commit_id.clone());
    request.event.event_id = event.event_id.to_string();
    request.event.kind = event.kind.as_str().to_owned();
    request.event.envelope = serde_json::to_value(&event).unwrap();
    request.event.canonical_bytes =
        arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
    request.event.canonical_digest = event
        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    request.projections[0].event_id = event.event_id.to_string();
    request.projections[0].event_kind = event.kind.as_str().to_owned();
    request.projections[0].payload = serde_json::to_value(&event.payload).unwrap();
    request
}

fn message_create_request(
    previous: &EventCommitRequest,
    strand_id: &arkret_wire::StrandId,
    body: &str,
) -> EventCommitRequest {
    let mut request = previous.clone();
    let previous_commit = &previous.authority_commit.commit;
    let previous_event = &previous.authority_commit.event;
    let realm_id = previous_event.realm_id.clone();
    let actor = previous_event.actor_id.as_account_id().unwrap();
    let event = event(
        arkret_wire::EventKind::MessageCreate,
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        &actor.principal_id,
        &actor.station_id,
        serde_json::json!({
            "strand_id":strand_id,
            "track_name":"discussion",
            "content":{"kind":"ak.content.text","body":body,"format":"plain"}
        }),
        previous_commit.committed_at,
    );
    request.authority_commit.event = event.clone();
    request.authority_commit.commit.event_ref = event.event_id.clone();
    request.authority_commit.commit.commit_id = arkret_wire::RealmCommitId::from_digest(
        arkret_canonical::sha256_bytes(format!("message:{}", event.event_id).as_bytes()),
    );
    request.authority_commit.commit.stream_position = previous_commit.stream_position + 1;
    request.authority_commit.commit.previous_commit_ref = Some(previous_commit.commit_id.clone());
    request.event.event_id = event.event_id.to_string();
    request.event.kind = event.kind.as_str().to_owned();
    request.event.envelope = serde_json::to_value(&event).unwrap();
    request.event.canonical_bytes =
        arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
    request.event.canonical_digest = event
        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    request.projections[0].event_id = event.event_id.to_string();
    request.projections[0].event_kind = event.kind.as_str().to_owned();
    request.projections[0].payload = serde_json::to_value(&event.payload).unwrap();
    request
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
    assert!(
        store
            .realm_state_snapshot_material(&realm_id)
            .await
            .unwrap()
            .is_none()
    );
    for transaction in &unit.transactions {
        assert!(
            store
                .queued_event(&transaction.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .committed_event(&transaction.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
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

#[tokio::test]
async fn strand_create_writes_registered_current_result_and_rejects_remote_unplanned_target() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let bootstrap_store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit();
    let at = unit.transactions[0].commit.committed_at;
    bootstrap_store
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let request = strand_create_request(&unit);
    let strand_id = arkret_wire::StrandId::from_event_id(&request.authority_commit.event.event_id);
    let outcome = uow.commit_event(request.clone()).await.unwrap();
    assert!(outcome.event_inserted);
    assert_eq!(outcome.projections_inserted, 1);
    assert_eq!(outcome.outbox_inserted, 0);
    let snapshot = bootstrap_store
        .realm_state_snapshot_material(&unit.transactions[0].event.realm_id)
        .await
        .unwrap()
        .unwrap();
    assert!(snapshot.current_state_entries.iter().any(|entry| {
        matches!(entry, arkret_wire::TypedCurrentResult::Value {
            selector: arkret_wire::CurrentSelector::Strand { strand_id: found },
            source_stream_ref,
            revision,
            value,
        } if found == &strand_id
            && source_stream_ref == &request.authority_commit.commit.stream_ref
            && revision.commit_id == request.authority_commit.commit.commit_id
            && value.get("id") == Some(&serde_json::json!(strand_id))
            && value.get("state") == Some(&serde_json::json!("active")))
    }));
    assert_eq!(
        source_outbox_count(&pool, &unit.transactions[0].event.realm_id).await,
        0
    );
    let restarted = ProjectionService::new("strand-current-restart-test");
    restarted
        .hydrate_from_persistence(
            &soland_storage_postgres::PgPersistenceStore::new(pool.clone()),
            &BootstrapHydrationAdapter,
            [unit.transactions[0].event.realm_id.clone()],
        )
        .await
        .unwrap();
    assert!(
        restarted
            .snapshot()
            .strands
            .contains_key(strand_id.as_str())
    );

    // A confirmed remote joined member makes an empty source target set
    // false. Inject that current row at a valid RealmCommit basis, then prove
    // the next Strand Event/Commit/current result all roll back together.
    let remote = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:remote.example").unwrap(),
        arkret_wire::DidCoreId::new("ak:did_core:web:remote-station.example").unwrap(),
    ));
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO member_state_current_results \
         (realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,'join',$3,$4,$5,$6)",
    )
    .bind::<Text, _>(unit.transactions[0].event.realm_id.as_str())
    .bind::<Text, _>(serde_json::to_string(&remote).unwrap())
    .bind::<Text, _>(unit.transactions[6].commit.commit_id.as_str())
    .bind::<BigInt, _>(unit.transactions[6].commit.stream_position as i64)
    .bind::<diesel::sql_types::Jsonb, _>(serde_json::json!({"membership":"join"}))
    .bind::<diesel::sql_types::Timestamptz, _>(at)
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    let mut denied = strand_create_request(&unit);
    // Rebuild the Event from a distinct valid create payload instead of
    // mutating a signed transcript: a new title yields a new Event-derived id.
    let mut object = serde_json::to_value(&denied.authority_commit.event.payload).unwrap();
    object["object"]["metadata"]["title"] = serde_json::json!("Denied Strand");
    denied.authority_commit.event = event(
        arkret_wire::EventKind::StrandCreate,
        arkret_wire::ScopeRef::Realm {
            realm_id: unit.transactions[0].event.realm_id.clone(),
        },
        &unit.transactions[0]
            .event
            .actor_id
            .as_account_id()
            .unwrap()
            .principal_id,
        &unit.transactions[0].expected_authority.service_id,
        object,
        at,
    );
    denied.authority_commit.commit.event_ref = denied.authority_commit.event.event_id.clone();
    denied.authority_commit.commit.commit_id = arkret_wire::RealmCommitId::from_digest(
        arkret_canonical::sha256_bytes(denied.authority_commit.event.event_id.as_str().as_bytes()),
    );
    denied.authority_commit.commit.previous_commit_ref =
        Some(request.authority_commit.commit.commit_id.clone());
    denied.authority_commit.commit.stream_position += 1;
    denied.event.event_id = denied.authority_commit.event.event_id.to_string();
    denied.event.envelope = serde_json::to_value(&denied.authority_commit.event).unwrap();
    denied.event.canonical_bytes = arkret_canonical::canonical_json_bytes(
        &denied.authority_commit.event.digest_payload().unwrap(),
    )
    .unwrap();
    denied.event.canonical_digest = denied
        .authority_commit
        .event
        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    denied.projections[0].event_id = denied.authority_commit.event.event_id.to_string();
    denied.projections[0].payload =
        serde_json::to_value(&denied.authority_commit.event.payload).unwrap();
    assert!(uow.commit_event(denied.clone()).await.is_err());
    assert!(
        bootstrap_store
            .committed_event(&denied.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    let snapshot = bootstrap_store
        .realm_state_snapshot_material(&unit.transactions[0].event.realm_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        snapshot
            .current_state_entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry,
                    arkret_wire::TypedCurrentResult::Value {
                        selector: arkret_wire::CurrentSelector::Strand { .. },
                        ..
                    }
                )
            })
            .count(),
        1
    );
}

#[tokio::test]
async fn default_strand_writes_exact_current_at_commit_and_rejects_dangling_and_stale_pointer() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit();
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let strand = strand_create_request(&unit);
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let missing = arkret_wire::StrandId::from_event_id(&unit.transactions[0].event.event_id);
    let dangling = set_default_strand_request(&strand, &missing, None);
    assert!(uow.commit_event(dangling.clone()).await.is_err());
    assert!(
        store
            .committed_event(&dangling.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );

    let request = set_default_strand_request(&strand, &strand_id, None);
    let outcome = uow.commit_event(request.clone()).await.unwrap();
    assert!(outcome.event_inserted);
    assert_eq!(outcome.projections_inserted, 1);
    assert_eq!(outcome.outbox_inserted, 0);
    let realm_id = &unit.transactions[0].event.realm_id;
    let snapshot = store
        .realm_state_snapshot_material(realm_id)
        .await
        .unwrap()
        .unwrap();
    assert!(snapshot.current_state_entries.iter().any(|entry| {
        matches!(entry, arkret_wire::TypedCurrentResult::Value {
            selector: arkret_wire::CurrentSelector::RealmSetDefaultStrand,
            source_stream_ref,
            revision,
            value,
        } if source_stream_ref == &request.authority_commit.commit.stream_ref
            && revision.commit_id == request.authority_commit.commit.commit_id
            && value == &serde_json::json!({"default_strand_id": strand_id}))
    }));
    assert_eq!(source_outbox_count(&pool, realm_id).await, 0);
    let restarted = ProjectionService::new("default-strand-current-restart-test");
    restarted
        .hydrate_from_persistence(
            &soland_storage_postgres::PgPersistenceStore::new(pool.clone()),
            &BootstrapHydrationAdapter,
            [realm_id.clone()],
        )
        .await
        .unwrap();
    assert_eq!(
        restarted
            .snapshot()
            .realm_states
            .get(realm_id.as_str())
            .and_then(|realm| realm.default_strand_id.as_deref()),
        Some(strand_id.as_str())
    );

    let stale = set_default_strand_request(&request, &strand_id, Some(&missing));
    assert!(uow.commit_event(stale.clone()).await.is_err());
    assert!(
        store
            .committed_event(&stale.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    let snapshot_after = store
        .realm_state_snapshot_material(realm_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        snapshot.current_state_entries,
        snapshot_after.current_state_entries
    );
    assert_eq!(source_outbox_count(&pool, realm_id).await, 0);
}

#[tokio::test]
async fn local_plain_text_message_writes_exact_revision_and_rejects_missing_strand() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit_with_plaintext_service();
    unit.validate().unwrap();
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let strand = strand_create_request(&unit);
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let default = set_default_strand_request(&strand, &strand_id, None);
    uow.commit_event(default.clone()).await.unwrap();

    let missing = arkret_wire::StrandId::from_event_id(&unit.transactions[0].event.event_id);
    let denied = message_create_request(&default, &missing, "missing target");
    assert!(uow.commit_event(denied.clone()).await.is_err());
    assert!(
        store
            .committed_event(&denied.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );

    let mut wrong_ref = message_create_request(&default, &strand_id, "wrong authorization ref");
    rebind_authorization_ref(&mut wrong_ref, &unit.transactions[6].event.event_id);
    assert!(uow.commit_event(wrong_ref.clone()).await.is_err());
    assert!(
        store
            .committed_event(&wrong_ref.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );

    let request = message_create_request(&default, &strand_id, "hello");
    let outcome = uow.commit_event(request.clone()).await.unwrap();
    assert!(outcome.event_inserted);
    assert_eq!(outcome.projections_inserted, 1);
    assert_eq!(outcome.outbox_inserted, 0);
    let message_id =
        arkret_wire::MessageId::from_event_id(&request.authority_commit.event.event_id);
    let realm_id = &unit.transactions[0].event.realm_id;
    let snapshot = store
        .realm_state_snapshot_material(realm_id)
        .await
        .unwrap()
        .unwrap();
    assert!(snapshot.current_state_entries.iter().any(|entry| {
        matches!(entry, arkret_wire::TypedCurrentResult::Value {
            selector: arkret_wire::CurrentSelector::MessageRevision { message_id: found },
            source_stream_ref,
            revision,
            value,
        } if found == &message_id
            && source_stream_ref == &request.authority_commit.commit.stream_ref
            && revision.commit_id == request.authority_commit.commit.commit_id
            && value == &serde_json::to_value(&request.authority_commit.event.payload).unwrap())
    }));
    let restarted = ProjectionService::new("message-current-restart-test");
    restarted
        .hydrate_from_persistence(
            &soland_storage_postgres::PgPersistenceStore::new(pool.clone()),
            &BootstrapHydrationAdapter,
            [realm_id.clone()],
        )
        .await
        .unwrap();
    assert!(
        restarted
            .snapshot()
            .messages
            .contains_key(request.authority_commit.event.event_id.as_str())
    );
    assert_eq!(source_outbox_count(&pool, realm_id).await, 0);

    // A newly joined remote account makes the empty federation target set
    // false. The next Message must leave no Event, Commit or revision row.
    let remote = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:message-remote.example").unwrap(),
        arkret_wire::DidCoreId::new("ak:did_core:web:message-remote-station.example").unwrap(),
    ));
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO member_state_current_results \
         (realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,'join',$3,$4,$5,$6)",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(remote.to_string())
    .bind::<Text, _>(unit.transactions.last().unwrap().commit.commit_id.as_str())
    .bind::<BigInt, _>(unit.transactions.last().unwrap().commit.stream_position as i64)
    .bind::<diesel::sql_types::Jsonb, _>(serde_json::json!({"membership":"join"}))
    .bind::<diesel::sql_types::Timestamptz, _>(unit.transactions[0].commit.committed_at)
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    let remote_denied = message_create_request(&request, &strand_id, "remote denied");
    assert!(uow.commit_event(remote_denied.clone()).await.is_err());
    assert!(
        store
            .committed_event(&remote_denied.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    let snapshot_after = store
        .realm_state_snapshot_material(realm_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        snapshot_after
            .current_state_entries
            .iter()
            .filter(|entry| matches!(
                entry,
                arkret_wire::TypedCurrentResult::Value {
                    selector: arkret_wire::CurrentSelector::MessageRevision { .. },
                    ..
                }
            ))
            .count(),
        1
    );
    assert_eq!(source_outbox_count(&pool, realm_id).await, 0);

    // A current row whose covering Commit vanished cannot silently disappear
    // from a snapshot (an INNER JOIN previously caused that data loss).
    let nonexistent = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        b"missing-message-covering-commit",
    ));
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE message_revision_current_results SET current_commit_id=$1 WHERE message_id=$2",
    )
    .bind::<Text, _>(nonexistent.as_str())
    .bind::<Text, _>(message_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert!(store.realm_state_snapshot_material(realm_id).await.is_err());
}

/// Real PostgreSQL: a handoff that rewrites the governing row while `/head`
/// waits on its share lock aborts the issuance cut with SQLSTATE 40001. It
/// must surface as the registered retryable `temporarily_unavailable` conflict
/// with nothing archived, never as an unclassified database fault.
#[tokio::test]
async fn snapshot_issuance_racing_a_handoff_is_retryable_unavailability() {
    use diesel_async::SimpleAsyncConnection as _;

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit();
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let creator = unit.transactions[0]
        .event
        .actor_id
        .as_account_id()
        .unwrap()
        .clone();
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let issuer = store
        .current_authority(&realm_id)
        .await
        .unwrap()
        .unwrap()
        .service_id;

    // The competing handoff holds the governing row before issuance starts.
    let mut handoff = pool.get().await.unwrap();
    handoff
        .batch_execute(&format!(
            "BEGIN; UPDATE realm_authorities SET service_id='ak:did_core:web:successor.example', \
             updated_at=now() WHERE realm_id='{}'",
            realm_id.as_str()
        ))
        .await
        .unwrap();

    let racing = tokio::spawn({
        let pool = pool.clone();
        let realm_id = realm_id.clone();
        let creator = creator.clone();
        let issuer = issuer.clone();
        async move {
            let store = PgAuthorityCommitStore { pool };
            let key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
            let method = arkret_wire::DidUrl::new("did:web:station.example#notary-key").unwrap();
            let sign = |material: &soland_storage::RealmStateSnapshotMaterial| {
                soland_services::authority_commit::build_signed_realm_state_snapshot(
                    material,
                    method.clone(),
                    &key,
                    chrono::Utc::now(),
                )
                .map_err(|error| soland_storage::PersistenceError::Internal(error.to_string()))
            };
            store
                .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &sign)
                .await
        }
    });

    // Commit the handoff only once issuance is provably parked on the lock.
    #[derive(diesel::QueryableByName)]
    struct Waiting {
        #[diesel(sql_type = BigInt)]
        waiting: i64,
    }
    let mut probe = pool.get().await.unwrap();
    let mut parked = false;
    for _ in 0..200 {
        let waiting = diesel::sql_query(
            "SELECT count(*) AS waiting FROM pg_stat_activity \
             WHERE datname = current_database() AND wait_event_type = 'Lock' \
               AND query LIKE '%FROM realm_authorities%FOR SHARE%'",
        )
        .get_result::<Waiting>(&mut probe)
        .await
        .unwrap()
        .waiting;
        if waiting == 1 {
            parked = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(parked, "issuance never waited on the governing row lock");
    handoff.batch_execute("COMMIT").await.unwrap();

    let error = racing.await.unwrap().unwrap_err();
    assert_eq!(
        error.conflict_code(),
        Some(soland_storage::ConflictCode::TemporarilyUnavailable),
        "{error}"
    );
    assert_eq!(issuance_count(&pool, &realm_id).await, 0);
}

async fn reservation_count(pool: &soland_storage_postgres::PgPool) -> i64 {
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = BigInt)]
        count: i64,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT count(*) AS count FROM realm_state_snapshot_window_reservations")
        .get_result::<Count>(&mut conn)
        .await
        .unwrap()
        .count
}

/// Real PostgreSQL, decision 0101: an Account window over the Realm stream
/// names a `window_start_basis` only when an exact snapshot already issued to
/// that Account sits at its anchor and is reserved for the window's
/// consumable period; otherwise a limited stream is `preview_only`. The
/// reservation keeps the by-ref read alive through retention GC, and losing
/// the guarantee (disclosure or expiry) withdraws the basis.
#[tokio::test]
async fn account_window_basis_reserves_exact_issued_snapshot_or_is_preview_only() {
    use arkret_models_collaboration::sync_frames::account_sync::StreamWindowAnchorKind;
    use soland_storage::{AccountRealmWindowRequest, SyncCursorStore as _};

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let cursors = soland_storage_postgres::PgSyncCursorStore { pool: pool.clone() };
    let unit = unit();
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let creator = unit.transactions[0]
        .event
        .actor_id
        .as_account_id()
        .unwrap()
        .clone();
    let stranger = arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        creator.station_id.clone(),
    );
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let issuer = store
        .current_authority(&realm_id)
        .await
        .unwrap()
        .unwrap()
        .service_id;
    let stream_ref = arkret_wire::CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let method = arkret_wire::DidUrl::new("did:web:station.example#notary-key").unwrap();
    let sign = |material: &soland_storage::RealmStateSnapshotMaterial| {
        soland_services::authority_commit::build_signed_realm_state_snapshot(
            material,
            method.clone(),
            &key,
            chrono::Utc::now(),
        )
        .map_err(|error| soland_storage::PersistenceError::Internal(error.to_string()))
    };
    let now_ms = chrono::Utc::now().timestamp_millis();
    let window_ttl = 300_000;
    let request = |account: &arkret_wire::AccountId, limit: u32| AccountRealmWindowRequest {
        realm_id: realm_id.clone(),
        account: account.clone(),
        issuer: issuer.clone(),
        window_limit: limit,
        window_cursor: format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()),
        expires_at_ms: now_ms + window_ttl,
        now_ms,
        byte_budget: 7 * 1024 * 1024,
    };
    let positions = |window: &soland_storage::AccountRealmWindow| {
        window
            .committed_events
            .iter()
            .map(|view| match view {
                arkret_wire::CommittedEventView::Full(full) => full.commit.stream_position,
                arkret_wire::CommittedEventView::Withheld(_) => panic!("withheld window row"),
            })
            .collect::<Vec<_>>()
    };

    // Whole readable history fits: not limited, so no basis is needed.
    let full = store
        .freeze_account_realm_window(&request(&creator, 10))
        .await
        .unwrap()
        .unwrap();
    assert!(!full.window.limited && full.window.complete);
    assert_eq!(full.window.preview_only, None);
    assert!(full.window.window_start_basis.is_none());
    assert_eq!(positions(&full), (0..=6).collect::<Vec<_>>());
    assert_eq!(full.window.next_position, 7);
    assert_eq!(
        full.window.head_commit_ref,
        unit.transactions[6].commit.commit_id
    );

    // Limited, and no snapshot was ever issued at the anchor.
    let unbacked = store
        .freeze_account_realm_window(&request(&creator, 2))
        .await
        .unwrap()
        .unwrap();
    assert!(unbacked.window.limited);
    assert_eq!(unbacked.window.preview_only, Some(true));
    assert!(unbacked.window.window_start_basis.is_none());
    assert_eq!(positions(&unbacked), vec![5, 6]);

    // `/head` at position 6, then two more Commits.
    let at_six = store
        .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &sign)
        .await
        .unwrap()
        .unwrap();
    let strand = strand_create_request(&unit);
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    uow.commit_event(set_default_strand_request(&strand, &strand_id, None))
        .await
        .unwrap();

    // Another Account can neither freeze nor be handed the creator's object.
    assert!(
        store
            .freeze_account_realm_window(&request(&stranger, 2))
            .await
            .is_err()
    );

    let backed_request = request(&creator, 2);
    let backed = store
        .freeze_account_realm_window(&backed_request)
        .await
        .unwrap()
        .unwrap();
    assert!(backed.window.limited && backed.window.complete);
    assert_eq!(backed.window.preview_only, None);
    assert_eq!(positions(&backed), vec![7, 8]);
    let basis = backed.window.window_start_basis.clone().unwrap();
    assert_eq!(
        basis.anchor_kind,
        StreamWindowAnchorKind::AfterCommittedPrefix
    );
    assert_eq!(basis.anchor_position, Some(6));
    assert_eq!(
        basis.anchor_commit_ref.as_ref(),
        Some(&unit.transactions[6].commit.commit_id)
    );
    assert_eq!(basis.snapshot_ref, at_six.snapshot_id);
    assert_eq!(basis.governance_generation, 0);
    assert!(basis.accepted_dependency_refs.is_none());
    assert_eq!(reservation_count(&pool).await, 1);

    // The anchor must be exact: position 7 has no issued snapshot.
    let off_by_one = store
        .freeze_account_realm_window(&request(&creator, 1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(off_by_one.window.preview_only, Some(true));
    assert!(off_by_one.window.window_start_basis.is_none());
    assert_eq!(reservation_count(&pool).await, 1);

    // The reserved basis is re-readable for the window only.
    let reread = |cursor: String, at: i64| {
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        let (realm_id, creator, stream_ref, issuer) = (
            realm_id.clone(),
            creator.clone(),
            stream_ref.clone(),
            issuer.clone(),
        );
        async move {
            store
                .account_window_basis(&realm_id, &creator, &cursor, &stream_ref, &issuer, at)
                .await
                .unwrap()
        }
    };
    assert_eq!(
        reread(backed_request.window_cursor.clone(), now_ms).await,
        Some(basis.clone())
    );
    assert_eq!(
        reread(
            format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()),
            now_ms
        )
        .await,
        None
    );
    assert_eq!(
        reread(backed_request.window_cursor.clone(), now_ms + window_ttl).await,
        None
    );

    // Losing disclosure withdraws the guarantee; restoring it re-admits it.
    let mut conn = pool.get().await.unwrap();
    let member = arkret_wire::ActorId::account(creator.clone()).to_string();
    for membership in ["leave", "join"] {
        diesel::sql_query(
            "UPDATE member_state_current_results SET membership=$3, \
             value=jsonb_build_object('membership', $3::text) WHERE realm_id=$1 AND member_id=$2",
        )
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(&member)
        .bind::<Text, _>(membership)
        .execute(&mut conn)
        .await
        .unwrap();
        let expected = (membership == "join").then(|| basis.clone());
        assert_eq!(
            reread(backed_request.window_cursor.clone(), now_ms).await,
            expected
        );
    }

    // A private handoff anchor that was never issued to any Account.
    let handoff_anchor = {
        let mut material = store
            .realm_state_snapshot_material(&realm_id)
            .await
            .unwrap()
            .unwrap();
        material.current_state_entries.clear();
        soland_services::authority_commit::build_signed_realm_state_snapshot(
            &material,
            method.clone(),
            &key,
            chrono::Utc::now() - chrono::Duration::hours(3),
        )
        .unwrap()
    };
    diesel::sql_query(
        "INSERT INTO realm_state_snapshots \
         (snapshot_id, realm_id, governance_generation, snapshot_json, created_at) \
         VALUES ($1,$2,0,$3,$4)",
    )
    .bind::<Text, _>(handoff_anchor.snapshot_id.as_str())
    .bind::<Text, _>(realm_id.as_str())
    .bind::<diesel::sql_types::Jsonb, _>(serde_json::to_value(&handoff_anchor).unwrap())
    .bind::<diesel::sql_types::Timestamptz, _>(handoff_anchor.created_at)
    .execute(&mut conn)
    .await
    .unwrap();

    // Age the reserved issuance past the unreserved retention and add an
    // unreserved, equally old one at head 8.
    let at_eight = store
        .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &sign)
        .await
        .unwrap()
        .unwrap();
    diesel::sql_query(
        "UPDATE realm_state_snapshot_issuances SET issued_at = now() - interval '2 hours'",
    )
    .execute(&mut conn)
    .await
    .unwrap();
    // RESTRICT: nothing may delete a reserved issuance, even outside GC.
    assert!(
        diesel::sql_query("DELETE FROM realm_state_snapshot_issuances WHERE snapshot_id=$1")
            .bind::<Text, _>(at_six.snapshot_id.as_str())
            .execute(&mut conn)
            .await
            .is_err()
    );
    let by_ref = |id: arkret_wire::RealmSnapshotId| {
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        let (realm_id, creator, issuer) = (realm_id.clone(), creator.clone(), issuer.clone());
        async move {
            store
                .issued_realm_state_snapshot(&realm_id, &creator, &id, &issuer)
                .await
                .unwrap()
        }
    };

    // Sweep while the window is consumable: the reserved basis survives, the
    // old unreserved issuance goes, the never-issued anchor is untouched.
    cursors.prune_expired(now_ms).await.unwrap();
    assert_eq!(
        by_ref(at_six.snapshot_id.clone()).await,
        Some(at_six.clone())
    );
    assert_eq!(by_ref(at_eight.snapshot_id.clone()).await, None);
    assert_eq!(issuance_count(&pool, &realm_id).await, 1);
    assert_eq!(
        reread(backed_request.window_cursor.clone(), now_ms).await,
        Some(basis.clone())
    );

    // A fresh unreserved issuance is inside its retention and survives.
    let fresh = store
        .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &sign)
        .await
        .unwrap()
        .unwrap();
    cursors.prune_expired(now_ms).await.unwrap();
    assert_eq!(by_ref(fresh.snapshot_id.clone()).await, Some(fresh.clone()));

    // After the consumable deadline the reservation and the aged object are
    // reclaimed together; the by-ref read and the basis are gone.
    cursors.prune_expired(now_ms + window_ttl).await.unwrap();
    assert_eq!(reservation_count(&pool).await, 0);
    assert_eq!(by_ref(at_six.snapshot_id.clone()).await, None);
    assert_eq!(
        reread(backed_request.window_cursor.clone(), now_ms).await,
        None
    );
    assert_eq!(by_ref(fresh.snapshot_id.clone()).await, Some(fresh.clone()));
    assert_eq!(issuance_count(&pool, &realm_id).await, 1);
    assert_eq!(
        store.latest_snapshot(&realm_id).await.unwrap(),
        Some(handoff_anchor)
    );

    // A new limited window over the reclaimed anchor is preview only.
    let reclaimed = store
        .freeze_account_realm_window(&request(&creator, 2))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reclaimed.window.preview_only, Some(true));
    assert!(reclaimed.window.window_start_basis.is_none());
}
