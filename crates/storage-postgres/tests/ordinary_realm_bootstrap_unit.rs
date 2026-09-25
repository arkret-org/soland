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
    Db, PgAuthorityCommitStore, PgEventCommitUnitOfWork, account_snapshot_material,
};

#[tokio::test]
async fn founder_disclosure_covers_every_accepted_cut_of_disclosed_kinds() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    // Plain-text messages need the Station in the plaintext-services facet.
    let unit = unit_with_plaintext_service();
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
    let material = account_snapshot_material(&pool, &realm_id, &creator)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(material.current_state_entries.len(), 9);
    assert!(material.current_state_entries.iter().any(|entry| matches!(
        entry,
        arkret_wire::TypedCurrentResult::Value {
            selector: arkret_wire::CurrentSelector::RealmPlaintextVisibleServices,
            ..
        }
    )));
    assert!(
        account_snapshot_material(&pool, &realm_id, &stranger)
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
        account_snapshot_material(&pool, &realm_id, &creator)
            .await
            .is_err()
    );
    diesel::sql_query("DELETE FROM relation_current_results WHERE realm_id=$1")
        .bind::<Text, _>(realm_id.as_str())
        .execute(&mut conn)
        .await
        .unwrap();
    drop(conn);

    // Every accepted cut is disclosed, not a closed chain of fixed length:
    // a Strand without a default pointer, then the pointer, then messages.
    let strand = strand_create_request(&unit);
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    uow.commit_event(strand.clone()).await.unwrap();
    let material = account_snapshot_material(&pool, &realm_id, &creator)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(material.current_state_entries.len(), 10);
    assert_eq!(material.visible_stream_heads[0].stream_position, 8);
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let default = set_default_strand_request(&strand, &strand_id, None);
    uow.commit_event(default.clone()).await.unwrap();
    let material = account_snapshot_material(&pool, &realm_id, &creator)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(material.current_state_entries.len(), 11);
    let first = message_create_request(&default, &strand_id, "first");
    uow.commit_event(first.clone()).await.unwrap();
    let second = message_create_request(&first, &strand_id, "second");
    uow.commit_event(second.clone()).await.unwrap();
    let material = account_snapshot_material(&pool, &realm_id, &creator)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(material.current_state_entries.len(), 13);
    assert_eq!(material.visible_stream_heads[0].stream_position, 11);
    assert_eq!(
        material.retention_and_history_floor.stream_floors[0].oldest_position,
        0
    );
    for request in [&first, &second] {
        let message_id =
            arkret_wire::MessageId::from_event_id(&request.authority_commit.event.event_id);
        let commit = &request.authority_commit.commit;
        assert!(material.current_state_entries.iter().any(|entry| matches!(
            entry,
            arkret_wire::TypedCurrentResult::Value {
                selector: arkret_wire::CurrentSelector::MessageRevision { message_id: found },
                revision,
                ..
            } if found == &message_id
                && revision.commit_id == commit.commit_id
                && revision.stream_position == commit.stream_position
        )));
    }
    // The founder stays the only one who may receive the cut.
    assert!(
        account_snapshot_material(&pool, &realm_id, &stranger)
            .await
            .is_err()
    );
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
    let unit = unit_with_plaintext_service();
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
    assert_eq!(first.current_state_entries.len(), 9);
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
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let default = set_default_strand_request(&strand, &strand_id, None);
    uow.commit_event(default.clone()).await.unwrap();
    uow.commit_event(message_create_request(&default, &strand_id, "hello"))
        .await
        .unwrap();
    let second = store
        .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &sign)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second.current_state_entries.len(), 12);
    assert_eq!(second.visible_stream_heads[0].stream_position, 10);
    assert_ne!(second.snapshot_id, first.snapshot_id);
    assert_eq!(issuance_count(&pool, &realm_id).await, 2);
    // A cut carrying a message row is re-provable by reference.
    assert_eq!(
        by_ref(
            creator.clone(),
            realm_id.clone(),
            second.snapshot_id.clone(),
            issuer.clone()
        )
        .await
        .unwrap(),
        Some(second.clone()),
    );
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
            arkret_wire::EventKind::RealmProfile => {
                serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":"Test Realm"})
            }
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
        forwarded_producer_evidence: None,
        event: record,
        parent_membership_admission: None,
        contact_projection: None,
        agent_draft_pending_intent: None,
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
        Some(&serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":"Test Realm"}))
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
        delivered_head: None,
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
        .freeze_account_realm_window(&request(&creator, 10), &sign)
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
        .freeze_account_realm_window(&request(&creator, 2), &sign)
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
            .freeze_account_realm_window(&request(&stranger, 2), &sign)
            .await
            .is_err()
    );

    let backed_request = request(&creator, 2);
    let backed = store
        .freeze_account_realm_window(&backed_request, &sign)
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
    assert_eq!(basis.anchor_position, 6);
    assert_eq!(
        basis.anchor_commit_ref,
        unit.transactions[6].commit.commit_id
    );
    assert_eq!(basis.snapshot_ref, at_six.snapshot_id);
    assert_eq!(basis.governance_generation, 0);
    assert!(basis.accepted_dependency_refs.is_none());
    assert_eq!(reservation_count(&pool).await, 1);

    // The anchor must be exact: position 7 has no issued snapshot.
    let off_by_one = store
        .freeze_account_realm_window(&request(&creator, 1), &sign)
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
        .freeze_account_realm_window(&request(&creator, 2), &sign)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reclaimed.window.preview_only, Some(true));
    assert!(reclaimed.window.window_start_basis.is_none());
}

fn scan_request(
    realm_id: &arkret_wire::RealmId,
    direction: arkret_wire::StreamScanDirection,
    limit: u16,
) -> arkret_wire::StreamScanRequest {
    arkret_wire::StreamScanRequest {
        realm_id: realm_id.clone(),
        stream_ref: arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
        direction,
        limit,
    }
}

fn scanned_page(scan: soland_storage::AccountStreamScan) -> arkret_wire::StreamScanOutcome {
    match scan {
        soland_storage::AccountStreamScan::Page(page) => page,
        other => panic!("expected a proved page, got {other:?}"),
    }
}

fn positions(page: &arkret_wire::StreamScanOutcome) -> Vec<u64> {
    page.committed_events
        .iter()
        .map(|item| item.commit().stream_position)
        .collect()
}

#[tokio::test]
async fn account_stream_scan_serves_only_the_proved_sole_founder_interval() {
    use arkret_wire::StreamScanDirection::{After, Before};
    use soland_storage::AccountStreamScan;

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
    let station = arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap();
    let stranger = arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        creator.station_id.clone(),
    );
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let genesis_commit = unit.transactions[0].commit.commit_id.clone();
    let scan = |request: arkret_wire::StreamScanRequest, account: arkret_wire::AccountId| {
        let store = store.clone();
        let station = station.clone();
        async move {
            store
                .scan_stream_for_account(&request, &account, &station)
                .await
                .unwrap()
        }
    };

    // Forward pages walk the whole founding chain, bound to the genesis floor.
    let first = scanned_page(scan(scan_request(&realm_id, After(None), 3), creator.clone()).await);
    assert_eq!(positions(&first), [0, 1, 2]);
    assert!(first.truncated);
    let floor = first
        .readable_floor
        .clone()
        .expect("the lower end carries its floor");
    assert_eq!(floor.oldest_position, 0);
    assert_eq!(floor.floor_commit_id, genesis_commit);
    assert_eq!(
        floor.floor_reason,
        arkret_wire::ReadableFloorReason::StreamStart
    );
    let second =
        scanned_page(scan(scan_request(&realm_id, After(Some(2)), 3), creator.clone()).await);
    assert_eq!(positions(&second), [3, 4, 5]);
    assert!(second.truncated);
    let last =
        scanned_page(scan(scan_request(&realm_id, After(Some(5)), 3), creator.clone()).await);
    assert_eq!(positions(&last), [6]);
    assert!(!last.truncated);
    let mut previous = None;
    for (index, item) in first
        .committed_events
        .iter()
        .chain(&second.committed_events)
        .chain(&last.committed_events)
        .enumerate()
    {
        let arkret_wire::CommittedEventView::Full(view) = item else {
            panic!("the founder's own rows are disclosed in full");
        };
        assert_eq!(view.commit, unit.transactions[index].commit);
        assert_eq!(view.event, unit.transactions[index].event);
        assert_eq!(view.commit.previous_commit_ref, previous);
        previous = Some(view.commit.commit_id.clone());
    }
    let beyond =
        scanned_page(scan(scan_request(&realm_id, After(Some(6)), 3), creator.clone()).await);
    assert!(beyond.committed_events.is_empty() && !beyond.truncated);

    // Backward backfill stops at the floor without reporting truncation.
    let newest =
        scanned_page(scan(scan_request(&realm_id, Before(None), 2), creator.clone()).await);
    assert_eq!(positions(&newest), [6, 5]);
    assert!(newest.truncated);
    let oldest =
        scanned_page(scan(scan_request(&realm_id, Before(Some(2)), 5), creator.clone()).await);
    assert_eq!(positions(&oldest), [1, 0]);
    assert!(!oldest.truncated);
    assert_eq!(oldest.readable_floor, Some(floor));

    // No readable interval: another Account, or a Realm not governed here.
    assert_eq!(
        scan(scan_request(&realm_id, After(None), 3), stranger.clone()).await,
        AccountStreamScan::NotAuthorized
    );
    let unknown = arkret_wire::RealmId::from_event_id(&unit.transactions[1].event.event_id);
    assert_eq!(
        scan(scan_request(&unknown, After(None), 3), creator.clone()).await,
        AccountStreamScan::NotAuthorized
    );
    // Authorized in principle, but not provable here: another issuer, a
    // Circle stream, or a second membership row.
    let other_station =
        arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
    assert!(matches!(
        store
            .scan_stream_for_account(
                &scan_request(&realm_id, After(None), 3),
                &creator,
                &other_station
            )
            .await
            .unwrap(),
        AccountStreamScan::Unproved(_)
    ));
    let mut circle = scan_request(&realm_id, After(None), 3);
    circle.stream_ref = arkret_wire::CommitStreamRef::Circle {
        realm_id: realm_id.clone(),
        circle_id: arkret_wire::CircleId::new(
            "ak:circle:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0".to_owned(),
        )
        .unwrap(),
    };
    assert!(matches!(
        scan(circle, creator.clone()).await,
        AccountStreamScan::Unproved(_)
    ));
    let stranger_actor = arkret_wire::ActorId::account(stranger.clone()).to_string();
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO member_state_current_results \
         (realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) \
         VALUES ($1,$2,'knock',$3,6,'{\"membership\":\"knock\"}'::jsonb,now())",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(&stranger_actor)
    .bind::<Text, _>(unit.transactions[6].commit.commit_id.as_str())
    .execute(&mut conn)
    .await
    .unwrap();
    assert!(matches!(
        scan(scan_request(&realm_id, After(None), 3), creator.clone()).await,
        AccountStreamScan::Unproved(_)
    ));
    assert_eq!(
        scan(scan_request(&realm_id, After(None), 3), stranger.clone()).await,
        AccountStreamScan::NotAuthorized
    );
    diesel::sql_query(
        "DELETE FROM member_state_current_results WHERE realm_id=$1 AND member_id=$2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(&stranger_actor)
    .execute(&mut conn)
    .await
    .unwrap();
    // A founder who left no longer has a readable interval.
    diesel::sql_query(
        "UPDATE member_state_current_results \
         SET membership='leave', value='{\"membership\":\"leave\"}'::jsonb WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .execute(&mut conn)
    .await
    .unwrap();
    assert_eq!(
        scan(scan_request(&realm_id, After(None), 3), creator.clone()).await,
        AccountStreamScan::NotAuthorized
    );
}

/// Real PostgreSQL: the Account Realm detail carries the frozen window, its
/// rows, and the typed current of the same proved cut. The basis reservation
/// expires exactly at the window's consumable deadline, which is the deadline
/// the Account cursor that carries the window is bounded by.
#[tokio::test]
async fn account_window_carries_same_cut_current_and_reservation_deadline() {
    use soland_storage::AccountRealmWindowRequest;

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
    let head_material = account_snapshot_material(&pool, &realm_id, &creator)
        .await
        .unwrap()
        .unwrap();

    let now_ms = chrono::Utc::now().timestamp_millis();
    let request = AccountRealmWindowRequest {
        realm_id: realm_id.clone(),
        account: creator.clone(),
        issuer: issuer.clone(),
        window_limit: 2,
        window_cursor: format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()),
        expires_at_ms: now_ms + soland_storage::MAX_ACCOUNT_WINDOW_RESERVATION_MS,
        now_ms,
        byte_budget: 7 * 1024 * 1024,
        delivered_head: None,
    };
    let backed = store
        .freeze_account_realm_window(&request, &sign)
        .await
        .unwrap()
        .unwrap();
    let basis = backed.window.window_start_basis.clone().unwrap();
    assert_eq!(basis.snapshot_ref, at_six.snapshot_id);
    assert_eq!(backed.window.next_position, 9);
    assert_eq!(
        backed.current_state_entries,
        head_material.current_state_entries
    );
    assert_eq!(
        backed.governance_generation,
        head_material.governance_generation
    );
    #[derive(diesel::QueryableByName)]
    struct Deadline {
        #[diesel(sql_type = BigInt)]
        expires_at_ms: i64,
    }
    let mut conn = pool.get().await.unwrap();
    let reserved = diesel::sql_query(
        "SELECT expires_at_ms FROM realm_state_snapshot_window_reservations \
         WHERE window_cursor=$1",
    )
    .bind::<Text, _>(&request.window_cursor)
    .get_result::<Deadline>(&mut conn)
    .await
    .unwrap();
    assert_eq!(reserved.expires_at_ms, request.expires_at_ms);

    // A preview-only window still carries the same-cut current: current
    // never depends on the window start.
    let preview = store
        .freeze_account_realm_window(
            &AccountRealmWindowRequest {
                window_limit: 1,
                window_cursor: format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()),
                ..request.clone()
            },
            &sign,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(preview.window.preview_only, Some(true));
    assert_eq!(
        preview.current_state_entries,
        head_material.current_state_entries
    );
    // A consumable deadline beyond the cursor's lifetime is refused whole.
    assert!(
        store
            .freeze_account_realm_window(
                &AccountRealmWindowRequest {
                    expires_at_ms: now_ms + soland_storage::MAX_ACCOUNT_WINDOW_RESERVATION_MS + 1,
                    window_cursor: format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()),
                    ..request.clone()
                },
                &sign
            )
            .await
            .is_err()
    );
}

/// Real PostgreSQL: a founder Realm (with the plaintext-services facet that
/// plain-text messages require) grows past the product's 20-row window with a
/// message tail. The window over the last 21 Commits names the snapshot
/// issued at the default-Strand head as its basis; its
/// same-cut current and a fresh head both carry one `message_revision` row
/// per message, and that head is re-provable by reference. A window whose
/// anchor was never issued is preview only.
#[tokio::test]
async fn message_tail_window_beyond_twenty_commits_names_the_issued_anchor() {
    use soland_storage::AccountRealmWindowRequest;

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit_with_plaintext_service();
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
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let strand = strand_create_request(&unit);
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let mut previous = set_default_strand_request(&strand, &strand_id, None);
    uow.commit_event(previous.clone()).await.unwrap();
    let at_nine = store
        .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &sign)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(at_nine.visible_stream_heads[0].stream_position, 9);
    for index in 0..21 {
        let message = message_create_request(&previous, &strand_id, &format!("message {index}"));
        uow.commit_event(message.clone()).await.unwrap();
        previous = message;
    }
    let head_material = account_snapshot_material(&pool, &realm_id, &creator)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head_material.visible_stream_heads[0].stream_position, 30);
    assert_eq!(head_material.current_state_entries.len(), 32);
    assert_eq!(
        head_material
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
        21
    );

    let now_ms = chrono::Utc::now().timestamp_millis();
    let request = AccountRealmWindowRequest {
        realm_id: realm_id.clone(),
        account: creator.clone(),
        issuer: issuer.clone(),
        window_limit: 21,
        window_cursor: format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()),
        expires_at_ms: now_ms + soland_storage::MAX_ACCOUNT_WINDOW_RESERVATION_MS,
        now_ms,
        byte_budget: 7 * 1024 * 1024,
        delivered_head: None,
    };
    let backed = store
        .freeze_account_realm_window(&request, &sign)
        .await
        .unwrap()
        .unwrap();
    let basis = backed.window.window_start_basis.clone().unwrap();
    assert_eq!(basis.snapshot_ref, at_nine.snapshot_id);
    assert_eq!(basis.anchor_position, 9);
    assert_eq!(backed.window.preview_only, None);
    assert_eq!(backed.window.next_position, 31);
    assert_eq!(backed.committed_events.len(), 21);
    assert_eq!(backed.committed_events[0].commit().stream_position, 10);
    assert_eq!(
        backed.current_state_entries,
        head_material.current_state_entries
    );

    let unanchored = store
        .freeze_account_realm_window(
            &AccountRealmWindowRequest {
                window_limit: 20,
                window_cursor: format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()),
                ..request.clone()
            },
            &sign,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unanchored.window.preview_only, Some(true));
    assert!(unanchored.window.window_start_basis.is_none());

    let at_head = store
        .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &sign)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        at_head.current_state_entries,
        head_material.current_state_entries
    );
    assert_eq!(
        store
            .issued_realm_state_snapshot(&realm_id, &creator, &at_head.snapshot_id, &issuer)
            .await
            .unwrap(),
        Some(at_head),
    );

    // Live delta: two more messages after the delivered head 30 arrive as a
    // window of exactly those two Commits, on the snapshot the earlier
    // freeze issued at its own head; a delivered head that is not an
    // accepted ancestor falls back to the last `window_limit` Commits.
    let delivered = arkret_wire::CommitStreamHead {
        stream_ref: backed.window.stream_ref.clone(),
        stream_position: backed.window.next_position - 1,
        commit_id: backed.window.head_commit_ref.clone(),
    };
    for index in 0..2 {
        let message = message_create_request(&previous, &strand_id, &format!("live {index}"));
        uow.commit_event(message.clone()).await.unwrap();
        previous = message;
    }
    let delta = store
        .freeze_account_realm_window(
            &AccountRealmWindowRequest {
                delivered_head: Some(delivered.clone()),
                window_cursor: format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()),
                ..request.clone()
            },
            &sign,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(delta.window.preview_only, None);
    assert_eq!(delta.window.next_position, 33);
    assert_eq!(
        delta
            .committed_events
            .iter()
            .map(|row| row.commit().stream_position)
            .collect::<Vec<_>>(),
        vec![31, 32]
    );
    let delta_basis = delta.window.window_start_basis.clone().unwrap();
    assert_eq!(delta_basis.anchor_position, 30);
    assert_eq!(delta_basis.anchor_commit_ref, delivered.commit_id);
    let delta_anchor = store
        .issued_realm_state_snapshot(&realm_id, &creator, &delta_basis.snapshot_ref, &issuer)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(delta_anchor.visible_stream_heads, vec![delivered.clone()]);
    let forged = store
        .freeze_account_realm_window(
            &AccountRealmWindowRequest {
                delivered_head: Some(arkret_wire::CommitStreamHead {
                    commit_id: arkret_wire::RealmCommitId::from_digest([0x7f; 32]),
                    ..delivered
                }),
                window_cursor: format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()),
                ..request.clone()
            },
            &sign,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(forged.committed_events.len(), 21);
    assert_eq!(forged.committed_events[0].commit().stream_position, 12);
}

fn message_redact_request(
    previous: &EventCommitRequest,
    message_id: &arkret_wire::MessageId,
) -> EventCommitRequest {
    let mut request = previous.clone();
    let previous_commit = &previous.authority_commit.commit;
    let previous_event = &previous.authority_commit.event;
    let realm_id = previous_event.realm_id.clone();
    let actor = previous_event.actor_id.as_account_id().unwrap();
    let event = event(
        arkret_wire::EventKind::MessageRedact,
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        &actor.principal_id,
        &actor.station_id,
        serde_json::json!({ "message_id": message_id }),
        previous_commit.committed_at,
    );
    request.authority_commit.event = event.clone();
    request.authority_commit.commit.event_ref = event.event_id.clone();
    request.authority_commit.commit.commit_id = arkret_wire::RealmCommitId::from_digest(
        arkret_canonical::sha256_bytes(format!("redact:{}", event.event_id).as_bytes()),
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

async fn account_issuance_count(
    pool: &soland_storage_postgres::PgPool,
    realm_id: &arkret_wire::RealmId,
) -> i64 {
    issuance_count(pool, realm_id).await
}

/// Real PostgreSQL (0441): repeated `/head` reads and window freezes at one
/// cut reuse the object already issued for it; issuances at distinct heads
/// that no window reserves are trimmed to the per-Account cap, newest kept;
/// and live reservations on one stream stop at their cap, after which a
/// limited window is preview only instead of evicting a live guarantee. A
/// retried freeze returns the same rows on the same basis, and another
/// Account can never read a window basis through the creator's cursor.
#[tokio::test]
async fn issued_snapshots_and_window_reservations_stay_within_their_caps() {
    use soland_storage::{AccountRealmWindowRequest, SyncCursorStore as _};

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let cursors = soland_storage_postgres::PgSyncCursorStore { pool: pool.clone() };
    let unit = unit_with_plaintext_service();
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
    let head = || {
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        let (realm_id, creator, issuer) = (realm_id.clone(), creator.clone(), issuer.clone());
        let sign = &sign;
        async move {
            store
                .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, sign)
                .await
                .unwrap()
                .unwrap()
        }
    };
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

    // Same cut: every `/head` and every whole-history freeze reuses one object.
    let first = head().await;
    for _ in 0..4 {
        assert_eq!(head().await, first);
    }
    let now_ms = chrono::Utc::now().timestamp_millis();
    let window_ttl = 300_000;
    let request = |limit: u32, delivered_head: Option<arkret_wire::CommitStreamHead>| {
        AccountRealmWindowRequest {
            realm_id: realm_id.clone(),
            account: creator.clone(),
            issuer: issuer.clone(),
            window_limit: limit,
            window_cursor: format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()),
            expires_at_ms: now_ms + window_ttl,
            now_ms,
            byte_budget: 7 * 1024 * 1024,
            delivered_head,
        }
    };
    for _ in 0..4 {
        let whole = store
            .freeze_account_realm_window(&request(20, None), &sign)
            .await
            .unwrap()
            .unwrap();
        assert!(!whole.window.limited);
    }
    assert_eq!(account_issuance_count(&pool, &realm_id).await, 1);
    assert_eq!(reservation_count(&pool).await, 0);

    // Twelve distinct heads, each read once through `/head`, keep only the
    // newest eight unreserved issuances.
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let strand = strand_create_request(&unit);
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let mut previous = set_default_strand_request(&strand, &strand_id, None);
    uow.commit_event(previous.clone()).await.unwrap();
    let mut issued = Vec::new();
    for index in 0..12 {
        let message = message_create_request(&previous, &strand_id, &format!("head {index}"));
        uow.commit_event(message.clone()).await.unwrap();
        previous = message;
        issued.push(head().await);
    }
    let cap = soland_storage::MAX_UNRESERVED_ISSUED_SNAPSHOTS_PER_ACCOUNT_REALM;
    assert_eq!(account_issuance_count(&pool, &realm_id).await, cap);
    assert_eq!(by_ref(first.snapshot_id.clone()).await, None);
    for (index, snapshot) in issued.iter().enumerate() {
        let expected = (index >= issued.len() - cap as usize).then(|| snapshot.clone());
        assert_eq!(by_ref(snapshot.snapshot_id.clone()).await, expected);
    }

    // A live delta after the newest issued head: every retry of the same
    // request freezes the same rows on the same basis until the live
    // reservations reach their cap; then the window is preview only, and no
    // retry issues another object.
    let latest = issued.last().unwrap().clone();
    let delivered = latest.visible_stream_heads[0].clone();
    let message = message_create_request(&previous, &strand_id, "live");
    uow.commit_event(message.clone()).await.unwrap();
    let reservation_cap = soland_storage::MAX_LIVE_WINDOW_RESERVATIONS_PER_ACCOUNT_STREAM;
    let mut reference = None;
    let mut creator_cursor = None;
    for _ in 0..reservation_cap {
        let retry = request(20, Some(delivered.clone()));
        let window = store
            .freeze_account_realm_window(&retry, &sign)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(window.window.preview_only, None);
        let basis = window.window.window_start_basis.clone().unwrap();
        assert_eq!(basis.snapshot_ref, latest.snapshot_id);
        let rows = serde_json::to_value(&window.committed_events).unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 1);
        assert_eq!(*reference.get_or_insert_with(|| rows.clone()), rows);
        creator_cursor.get_or_insert(retry.window_cursor);
    }
    assert_eq!(reservation_count(&pool).await, reservation_cap);
    let over = store
        .freeze_account_realm_window(&request(20, Some(delivered.clone())), &sign)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(over.window.preview_only, Some(true));
    assert!(over.window.window_start_basis.is_none());
    assert_eq!(
        serde_json::to_value(&over.committed_events).unwrap(),
        reference.unwrap()
    );
    assert_eq!(reservation_count(&pool).await, reservation_cap);
    // The first freeze issued the new head once; the reserved anchor is
    // outside the unreserved cap.
    assert_eq!(account_issuance_count(&pool, &realm_id).await, cap + 1);

    // The basis is bound to the Account that froze the window.
    let creator_cursor = creator_cursor.unwrap();
    for account in [&stranger, &creator] {
        let basis = store
            .account_window_basis(
                &realm_id,
                account,
                &creator_cursor,
                &stream_ref,
                &issuer,
                now_ms,
            )
            .await
            .unwrap();
        assert_eq!(basis.is_some(), account == &creator);
    }

    // Once the reservations lapse the cap frees, and the retained anchor
    // backs a live delta again.
    cursors.prune_expired(now_ms + window_ttl).await.unwrap();
    assert_eq!(reservation_count(&pool).await, 0);
    let renewed = store
        .freeze_account_realm_window(
            &AccountRealmWindowRequest {
                expires_at_ms: now_ms + 2 * window_ttl,
                now_ms: now_ms + window_ttl,
                ..request(20, Some(delivered.clone()))
            },
            &sign,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        renewed.window.window_start_basis.unwrap().snapshot_ref,
        latest.snapshot_id
    );
}

/// Real PostgreSQL: the Account stream scan applies the committed-event
/// disclosure decision. A retention-expired Message and a redacted Message
/// keep their Commit slot as the withheld branch, so the page is still one
/// contiguous verifiable chain, while the redaction itself is disclosed in
/// full. A signed cut can no longer carry the expired content: `/head` and
/// the window refuse the cut and the earlier issued object is withdrawn
/// from by-ref reads.
#[tokio::test]
async fn account_scan_withholds_expired_and_redacted_messages_on_their_commits() {
    use arkret_wire::StreamScanDirection::After;
    use soland_storage::AccountRealmWindowRequest;

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit_with_plaintext_service();
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
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let strand = strand_create_request(&unit);
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let default = set_default_strand_request(&strand, &strand_id, None);
    uow.commit_event(default.clone()).await.unwrap();
    let expired = message_create_request(&default, &strand_id, "expired");
    uow.commit_event(expired.clone()).await.unwrap();
    let redacted = message_create_request(&expired, &strand_id, "redacted");
    uow.commit_event(redacted.clone()).await.unwrap();
    let kept = message_create_request(&redacted, &strand_id, "kept");
    uow.commit_event(kept.clone()).await.unwrap();
    let before = store
        .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &sign)
        .await
        .unwrap()
        .unwrap();

    let redacted_message =
        arkret_wire::MessageId::new(redacted.authority_commit.event.event_id.as_str().replacen(
            "ak:event:",
            "ak:message:",
            1,
        ))
        .unwrap();
    let redaction = message_redact_request(&kept, &redacted_message);
    uow.commit_event(redaction.clone()).await.unwrap();
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO retention_tombstones \
         (event_id, realm_id, reason, policy_ttl_seconds, expired_at, tombstoned_at) \
         SELECT id, realm_id, 'retention_policy.ttl', 60, now(), now() \
         FROM canonical_events WHERE envelope->>'event_id' = $1",
    )
    .bind::<Text, _>(expired.authority_commit.event.event_id.as_str())
    .execute(&mut conn)
    .await
    .unwrap();

    let page = scanned_page(
        store
            .scan_stream_for_account(
                &scan_request(&realm_id, After(None), 100),
                &creator,
                &issuer,
            )
            .await
            .unwrap(),
    );
    let last = redaction.authority_commit.commit.stream_position;
    assert_eq!(positions(&page), (0..=last).collect::<Vec<_>>());
    assert!(!page.truncated);
    for (index, item) in page.committed_events.iter().enumerate() {
        if index > 0 {
            assert_eq!(
                item.commit().previous_commit_ref.as_ref(),
                Some(&page.committed_events[index - 1].commit().commit_id)
            );
        }
        let withheld = [&expired, &redacted]
            .iter()
            .any(|request| request.authority_commit.commit.commit_id == item.commit().commit_id);
        match item {
            arkret_wire::CommittedEventView::Withheld(view) => {
                assert!(
                    withheld,
                    "unexpected withheld row {}",
                    view.commit.stream_position
                );
            }
            arkret_wire::CommittedEventView::Full(view) => {
                assert!(!withheld, "disclosed row {}", view.commit.stream_position);
                assert_eq!(view.event.event_id, view.commit.event_ref);
            }
        }
    }

    // No signed cut may carry the expired content any more.
    assert!(
        store
            .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &sign)
            .await
            .is_err()
    );
    let now_ms = chrono::Utc::now().timestamp_millis();
    assert!(
        store
            .freeze_account_realm_window(
                &AccountRealmWindowRequest {
                    realm_id: realm_id.clone(),
                    account: creator.clone(),
                    issuer: issuer.clone(),
                    window_limit: 2,
                    window_cursor: format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()),
                    expires_at_ms: now_ms + 300_000,
                    now_ms,
                    byte_budget: 7 * 1024 * 1024,
                    delivered_head: None,
                },
                &sign,
            )
            .await
            .is_err()
    );
    assert!(matches!(
        store
            .issued_realm_state_snapshot(&realm_id, &creator, &before.snapshot_id, &issuer)
            .await,
        Err(soland_storage::PersistenceError::SchemaViolation(_))
    ));
}

#[tokio::test]
async fn peer_stream_scan_refuses_non_hosting_peers_and_never_serves_an_unproved_interval() {
    use arkret_wire::StreamScanDirection::After;
    use soland_storage::AccountStreamScan;

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
    let station = arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap();
    let remote = arkret_wire::DidCoreId::new("ak:did_core:web:remote-station.example").unwrap();
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let scan = |request: arkret_wire::StreamScanRequest, peer: arkret_wire::DidCoreId| {
        let store = store.clone();
        let station = station.clone();
        async move {
            store
                .scan_stream_for_peer(&request, &peer, &station)
                .await
                .unwrap()
        }
    };

    // A peer hosting no joined member has no replication right, even though
    // the founding stream is fully readable by its local founder.
    assert_eq!(
        scan(scan_request(&realm_id, After(None), 3), remote.clone()).await,
        AccountStreamScan::NotAuthorized
    );
    // A Realm not governed here is refused without enumerating it.
    let unknown = arkret_wire::RealmId::from_event_id(&unit.transactions[1].event.event_id);
    assert_eq!(
        scan(
            scan_request(&unknown, After(None), 3),
            creator.station_id.clone()
        )
        .await,
        AccountStreamScan::NotAuthorized
    );

    // A peer hosting a joined member may hold a right, but its join floor,
    // history access and disclosure are not proved: fail closed, no page.
    let remote_member = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:remote-member.example").unwrap(),
        remote.clone(),
    ))
    .to_string();
    let mut conn = pool.get().await.unwrap();
    for membership in ["knock", "join"] {
        diesel::sql_query(
            "INSERT INTO member_state_current_results \
             (realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) \
             VALUES ($1,$2,$3,$4,6,jsonb_build_object('membership',$3::text),now()) \
             ON CONFLICT (realm_id,member_id) DO UPDATE SET membership=EXCLUDED.membership, \
             value=EXCLUDED.value",
        )
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(&remote_member)
        .bind::<Text, _>(membership)
        .bind::<Text, _>(unit.transactions[6].commit.commit_id.as_str())
        .execute(&mut conn)
        .await
        .unwrap();
        let decision = scan(scan_request(&realm_id, After(None), 3), remote.clone()).await;
        if membership == "join" {
            assert!(
                matches!(decision, AccountStreamScan::Unproved(_)),
                "{decision:?}"
            );
        } else {
            // A knock is not a joined member and grants nothing.
            assert_eq!(decision, AccountStreamScan::NotAuthorized);
        }
    }
    // The same holds for a Circle stream and for a Station that lost tenure.
    let mut circle = scan_request(&realm_id, After(None), 3);
    circle.stream_ref = arkret_wire::CommitStreamRef::Circle {
        realm_id: realm_id.clone(),
        circle_id: arkret_wire::CircleId::new(
            "ak:circle:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0".to_owned(),
        )
        .unwrap(),
    };
    assert!(matches!(
        scan(circle, remote.clone()).await,
        AccountStreamScan::Unproved(_)
    ));
    let other_station =
        arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
    assert!(matches!(
        store
            .scan_stream_for_peer(
                &scan_request(&realm_id, After(None), 3),
                &remote,
                &other_station
            )
            .await
            .unwrap(),
        AccountStreamScan::Unproved(_)
    ));
}

fn moderation_report_request(
    previous: &EventCommitRequest,
    reporter: &arkret_wire::DidCoreId,
    payload: serde_json::Value,
) -> EventCommitRequest {
    realm_self_event_request(
        previous,
        reporter,
        arkret_wire::EventKind::SelfModerationReport,
        payload,
    )
}

fn realm_self_event_request(
    previous: &EventCommitRequest,
    reporter: &arkret_wire::DidCoreId,
    kind: arkret_wire::EventKind,
    payload: serde_json::Value,
) -> EventCommitRequest {
    let mut request = previous.clone();
    let previous_commit = &previous.authority_commit.commit;
    let realm_id = previous.authority_commit.event.realm_id.clone();
    let station = previous
        .authority_commit
        .expected_authority
        .service_id
        .clone();
    let event = event(
        kind,
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        reporter,
        &station,
        payload,
        previous_commit.committed_at,
    );
    request.authority_commit.event = event.clone();
    request.authority_commit.commit.event_ref = event.event_id.clone();
    request.authority_commit.commit.commit_id = arkret_wire::RealmCommitId::from_digest(
        arkret_canonical::sha256_bytes(format!("report:{}", event.event_id).as_bytes()),
    );
    request.authority_commit.commit.stream_position = previous_commit.stream_position + 1;
    request.authority_commit.commit.previous_commit_ref = Some(previous_commit.commit_id.clone());
    request.event.event_id = event.event_id.to_string();
    request.event.actor_id = event.actor_id.to_string();
    request.event.kind = event.kind.as_str().to_owned();
    request.event.envelope = serde_json::to_value(&event).unwrap();
    request.event.canonical_bytes =
        arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
    request.event.canonical_digest = event
        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    request.projections[0].event_id = event.event_id.to_string();
    request.projections[0].event_kind = event.kind.as_str().to_owned();
    request.projections[0].sender = Some(event.actor_id.to_string());
    request.projections[0].payload = serde_json::to_value(&event.payload).unwrap();
    request
}

fn report_payload(
    realm_id: &arkret_wire::RealmId,
    target_ref: &str,
    reporter: &arkret_wire::DidCoreId,
) -> serde_json::Value {
    serde_json::json!({
        "realm_id": realm_id,
        "target_ref": target_ref,
        "report_reason_code": "spam",
        "reporter_id": reporter,
        "provenance": "self"
    })
}

fn franking_nonce(
    request: &EventCommitRequest,
    received_by: &arkret_wire::DidCoreId,
    replay_nonce: &str,
) -> soland_storage::EventBatchCommitRequest {
    soland_storage::EventBatchCommitRequest {
        events: vec![request.clone()],
        franking_replay_nonce: Some(soland_storage::FrankingReplayNonceCommit {
            realm_id: request.authority_commit.event.realm_id.to_string(),
            received_by: received_by.clone(),
            replay_nonce: replay_nonce.to_owned(),
            report_event_id: request.authority_commit.event.event_id.to_string(),
            consumed_at: request.authority_commit.commit.committed_at,
        }),
        applet_record: None,
        applet_authoring_preview: None,
        agent_membership_cascade: None,
    }
}

async fn report_row_count(pool: &soland_storage_postgres::PgPool) -> i64 {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT COUNT(*) AS count FROM moderation_report_current_results")
        .get_result::<CountRow>(&mut *conn)
        .await
        .unwrap()
        .count
}

async fn franking_nonce_count(pool: &soland_storage_postgres::PgPool) -> i64 {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT COUNT(*) AS count FROM moderation_franking_replay_nonces")
        .get_result::<CountRow>(&mut *conn)
        .await
        .unwrap()
        .count
}

/// Real PostgreSQL: the reporter-signed self moderation report commits with its
/// Station-signed RealmCommit, the exact `moderation_report` current row and
/// the consumed franking nonce in one transaction; every refusal (absent
/// target, non-member reporter, facade provenance, Circle scope, reused nonce,
/// divergent bytes for an accepted Event id, unplanned remote target) leaves
/// zero Event, Commit, current, nonce and outbox writes.
#[tokio::test]
async fn self_moderation_report_commits_exact_current_and_refuses_with_zero_writes() {
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
    let message = message_create_request(&default, &strand_id, "reported");
    uow.commit_event(message.clone()).await.unwrap();
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let reporter = message
        .authority_commit
        .event
        .actor_id
        .signing_principal_id()
        .clone();
    let target = message.authority_commit.event.event_id.to_string();
    let station = message
        .authority_commit
        .expected_authority
        .service_id
        .clone();

    let assert_zero_writes = async |request: &EventCommitRequest, reports: i64, nonces: i64| {
        assert!(
            store
                .committed_event(&request.authority_commit.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(report_row_count(&pool).await, reports);
        assert_eq!(franking_nonce_count(&pool).await, nonces);
        assert_eq!(source_outbox_count(&pool, &realm_id).await, 0);
    };

    // An absent target is the single anti-oracle not_found.
    let absent = arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(b"absent-report-target"),
    );
    let denied = moderation_report_request(
        &message,
        &reporter,
        report_payload(&realm_id, absent.as_str(), &reporter),
    );
    let error = uow.commit_event(denied.clone()).await.unwrap_err();
    assert!(
        matches!(error, soland_storage::PersistenceError::NotFound(_)),
        "{error}"
    );
    assert_zero_writes(&denied, 0, 0).await;

    // A reporter that is not a confirmed joined member cannot see the target.
    let outsider = arkret_wire::DidCoreId::new("ak:did_core:web:report-outsider.example").unwrap();
    let denied = moderation_report_request(
        &message,
        &outsider,
        report_payload(&realm_id, &target, &outsider),
    );
    assert!(matches!(
        uow.commit_event(denied.clone()).await.unwrap_err(),
        soland_storage::PersistenceError::NotFound(_)
    ));
    assert_zero_writes(&denied, 0, 0).await;

    // MIMI facade provenance has its own ingress and never enters this unit.
    let mut facade = report_payload(&realm_id, &target, &reporter);
    facade["provenance"] = serde_json::json!("mimi_facade");
    facade["source_provider_id"] = serde_json::json!("ak:did_core:web:mimi-provider.example");
    let denied = moderation_report_request(&message, &reporter, facade);
    let error = uow.commit_event(denied.clone()).await.unwrap_err();
    assert!(error.to_string().contains("directly authored"), "{error}");
    assert_zero_writes(&denied, 0, 0).await;

    // A Circle effective scope does not match a Realm-scope target.
    let mut circle = report_payload(&realm_id, &target, &reporter);
    circle["effective_scope"] = serde_json::json!({
        "kind": "circle",
        "realm_id": realm_id,
        "circle_id": arkret_wire::CircleId::from_event_id(&message.authority_commit.event.event_id),
    });
    let denied = moderation_report_request(&message, &reporter, circle);
    assert!(matches!(
        uow.commit_event(denied.clone()).await.unwrap_err(),
        soland_storage::PersistenceError::NotFound(_)
    ));
    assert_zero_writes(&denied, 0, 0).await;

    // Accepted: Event, Commit, exact current row and the consumed nonce.
    let mut framed = report_payload(&realm_id, &target, &reporter);
    framed["franking_proof"] = serde_json::json!({
        "realm_id": realm_id,
        "event_id": target,
        "received_by": station,
        "verification_method": "did:web:bootstrap-station.example#notary-key",
        "received_at": message.authority_commit.commit.committed_at,
        "replay_nonce": "report-nonce-0000000001",
        "signature": "c2lnbmF0dXJl"
    });
    let report = moderation_report_request(&message, &reporter, framed);
    let outcome = uow
        .commit_event_batch(franking_nonce(&report, &station, "report-nonce-0000000001"))
        .await
        .unwrap();
    assert!(outcome.event_inserted);
    assert_eq!(outcome.outbox_inserted, 0);
    let committed = store
        .committed_event(&report.authority_commit.event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(committed.event, report.authority_commit.event);
    assert_eq!(committed.commit, report.authority_commit.commit);
    #[derive(diesel::QueryableByName)]
    struct ReportRow {
        #[diesel(sql_type = Text)]
        current_commit_id: String,
        #[diesel(sql_type = BigInt)]
        current_stream_position: i64,
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        value: serde_json::Value,
    }
    let mut conn = pool.get().await.unwrap();
    let row = diesel::sql_query(
        "SELECT current_commit_id,current_stream_position,value \
         FROM moderation_report_current_results WHERE report_event_id=$1 AND realm_id=$2",
    )
    .bind::<Text, _>(report.authority_commit.event.event_id.as_str())
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<ReportRow>(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert_eq!(
        row.current_commit_id,
        report.authority_commit.commit.commit_id.as_str()
    );
    assert_eq!(
        row.current_stream_position,
        report.authority_commit.commit.stream_position as i64
    );
    assert_eq!(
        row.value,
        serde_json::to_value(&report.authority_commit.event.payload).unwrap()
    );
    assert_eq!(report_row_count(&pool).await, 1);
    assert_eq!(franking_nonce_count(&pool).await, 1);
    // The Realm snapshot cut still materializes after the report Commit.
    store
        .realm_state_snapshot_material(&realm_id)
        .await
        .unwrap()
        .unwrap();

    // The same Event id with different canonical bytes is refused and the
    // accepted Event is not rewritten.
    let mut divergent = report.clone();
    let proof = divergent
        .authority_commit
        .event
        .producer_proof
        .as_mut()
        .unwrap();
    proof.created_at = proof.created_at + chrono::Duration::seconds(1);
    divergent.event.envelope = serde_json::to_value(&divergent.authority_commit.event).unwrap();
    let error = uow.commit_event(divergent).await.unwrap_err();
    assert!(
        error.to_string().contains("event_hash_collision"),
        "{error}"
    );
    assert_eq!(
        store
            .committed_event(&report.authority_commit.event.event_id)
            .await
            .unwrap()
            .unwrap()
            .event,
        report.authority_commit.event
    );
    assert_eq!(report_row_count(&pool).await, 1);

    // A second report that reuses the consumed franking nonce is refused.
    let mut reused = report_payload(&realm_id, &target, &reporter);
    reused["report_reason_code"] = serde_json::json!("harassment");
    reused["franking_proof"] = report.authority_commit.event.payload["franking_proof"].clone();
    let denied = moderation_report_request(&report, &reporter, reused);
    let error = uow
        .commit_event_batch(franking_nonce(&denied, &station, "report-nonce-0000000001"))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("duplicate_conflict"), "{error}");
    assert_zero_writes(&denied, 1, 1).await;

    // A Realm-target report without evidence is accepted at the next position.
    let realm_report = moderation_report_request(
        &report,
        &reporter,
        report_payload(&realm_id, realm_id.as_str(), &reporter),
    );
    uow.commit_event(realm_report.clone()).await.unwrap();
    assert_eq!(report_row_count(&pool).await, 2);

    // A newly joined remote account makes the empty source outbox false.
    let remote = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:report-remote.example").unwrap(),
        arkret_wire::DidCoreId::new("ak:did_core:web:report-remote-station.example").unwrap(),
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
    let mut remote_payload = report_payload(&realm_id, &target, &reporter);
    remote_payload["report_reason_code"] = serde_json::json!("illegal");
    let denied = moderation_report_request(&realm_report, &reporter, remote_payload);
    let error = uow.commit_event(denied.clone()).await.unwrap_err();
    assert!(
        error.to_string().contains("remote delivery target set"),
        "{error}"
    );
    assert_zero_writes(&denied, 2, 1).await;
}

/// Real PostgreSQL: a committed moderation report is moderator-only, so the
/// founder disclosure refuses the whole cut
/// instead of signing a snapshot that omits or discloses it.
#[tokio::test]
async fn moderation_report_row_refuses_the_founder_disclosure_cut() {
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
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let strand = strand_create_request(&unit);
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let default = set_default_strand_request(&strand, &strand_id, None);
    uow.commit_event(default.clone()).await.unwrap();
    assert_eq!(
        account_snapshot_material(&pool, &realm_id, &creator)
            .await
            .unwrap()
            .unwrap()
            .current_state_entries
            .len(),
        10
    );

    let report = moderation_report_request(
        &default,
        &creator.principal_id,
        report_payload(&realm_id, strand_id.as_str(), &creator.principal_id),
    );
    uow.commit_event(report).await.unwrap();
    assert_eq!(report_row_count(&pool).await, 1);
    let error = account_snapshot_material(&pool, &realm_id, &creator)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("outside the disclosure subset"),
        "{error}"
    );
}

async fn event_row_count(pool: &soland_storage_postgres::PgPool, event_id: &str) -> i64 {
    let token = soland_storage::ids::parse_event_id(event_id).unwrap();
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT COUNT(*) AS count FROM canonical_events WHERE id=$1")
        .bind::<diesel::sql_types::Binary, _>(token.to_vec())
        .get_result::<CountRow>(&mut *conn)
        .await
        .unwrap()
        .count
}

/// Real PostgreSQL: two self reports built on the same Realm-stream head race
/// concurrently. Exactly one commits; the other loses the head CAS and answers
/// the registered retryable `temporarily_unavailable` (authority-commit-log.md
/// §4 `retryable_unavailable`) with zero Event, Commit, current and outbox
/// writes. The exact same Event then commits once rebuilt on the new head.
#[tokio::test]
async fn concurrent_self_reports_on_one_stream_head_leave_one_winner_and_a_retryable_loser() {
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
    let default = set_default_strand_request(&strand, &strand_id, None);
    uow.commit_event(default.clone()).await.unwrap();
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let reporter = default
        .authority_commit
        .event
        .actor_id
        .signing_principal_id()
        .clone();
    let first = moderation_report_request(
        &default,
        &reporter,
        report_payload(&realm_id, strand_id.as_str(), &reporter),
    );
    let mut second_payload = report_payload(&realm_id, realm_id.as_str(), &reporter);
    second_payload["report_reason_code"] = serde_json::json!("harassment");
    let second = moderation_report_request(&default, &reporter, second_payload.clone());
    assert_eq!(
        first.authority_commit.commit.stream_position,
        second.authority_commit.commit.stream_position
    );

    let first_uow = PgEventCommitUnitOfWork::new(pool.clone());
    let second_uow = PgEventCommitUnitOfWork::new(pool.clone());
    let (first_result, second_result) = tokio::join!(
        first_uow.commit_event(first.clone()),
        second_uow.commit_event(second.clone())
    );
    let (winner, loser, error) = match (first_result, second_result) {
        (Ok(_), Err(error)) => (&first, &second, error),
        (Err(error), Ok(_)) => (&second, &first, error),
        (first, second) => panic!(
            "expected exactly one winner: first ok={} second ok={}",
            first.is_ok(),
            second.is_ok()
        ),
    };
    assert_eq!(
        error.conflict_code(),
        Some(soland_storage::ConflictCode::TemporarilyUnavailable),
        "{error}"
    );
    assert_eq!(
        soland_services::ServiceError::from(error).conflict_code(),
        Some(soland_storage::ConflictCode::TemporarilyUnavailable)
    );
    let committed = store
        .committed_event(&winner.authority_commit.event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(committed.commit, winner.authority_commit.commit);
    assert!(
        store
            .committed_event(&loser.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        event_row_count(&pool, loser.authority_commit.event.event_id.as_str()).await,
        0
    );
    assert_eq!(report_row_count(&pool).await, 1);
    assert_eq!(source_outbox_count(&pool, &realm_id).await, 0);

    // Exact retry: the same signed Event, ordered by the Station on the new head.
    let retried = moderation_report_request(
        winner,
        &reporter,
        serde_json::to_value(&loser.authority_commit.event.payload).unwrap(),
    );
    assert_eq!(retried.authority_commit.event, loser.authority_commit.event);
    uow.commit_event(retried.clone()).await.unwrap();
    assert_eq!(report_row_count(&pool).await, 2);
    assert_eq!(
        store
            .committed_event(&loser.authority_commit.event.event_id)
            .await
            .unwrap()
            .unwrap()
            .commit
            .stream_position,
        winner.authority_commit.commit.stream_position + 1
    );
}

/// Real PostgreSQL: the moderation queue is a same-cut View over the
/// `moderation_report` family. The Realm root controller sees every report as
/// a closed `moderation-queue-item` with the retyped id, the exact payload and
/// the accepting Commit time; any other caller sees nothing; the full Realm
/// snapshot material carries each report under its registered selector; the
/// committed decisions fold item status from moderation_state; and a same-cut
/// moderation grant makes its subject a moderator of the queue.
#[tokio::test]
async fn moderation_queue_view_derives_from_the_report_family_at_one_cut() {
    use arkret_models_collaboration::governance::moderation_queue::ModerationQueueItem;
    use soland_storage::ModerationStore as _;

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let queue = soland_storage_postgres::PgModerationStore { pool: pool.clone() };
    let unit = unit();
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
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let controller = default.authority_commit.event.actor_id.clone();
    let reporter = controller.signing_principal_id().clone();
    let stranger = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:queue-stranger.example").unwrap(),
        controller.as_account_id().unwrap().station_id.clone(),
    ));

    let items = |read: Vec<ModerationQueueItem>| read;
    assert!(items(queue.queue_view_for_actor(&controller, None).await.unwrap()).is_empty());

    let first = moderation_report_request(
        &default,
        &reporter,
        report_payload(&realm_id, strand_id.as_str(), &reporter),
    );
    uow.commit_event(first.clone()).await.unwrap();
    let mut second_payload = report_payload(&realm_id, realm_id.as_str(), &reporter);
    second_payload["report_reason_code"] = serde_json::json!("harassment");
    let second = moderation_report_request(&first, &reporter, second_payload);
    uow.commit_event(second.clone()).await.unwrap();
    assert_eq!(queue.report_count().await.unwrap(), 2);

    let view = items(queue.queue_view_for_actor(&controller, None).await.unwrap());
    assert_eq!(view.len(), 2);
    for (item, request) in view.iter().zip([&first, &second]) {
        let value = serde_json::to_value(item).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "id": request
                    .authority_commit
                    .event
                    .event_id
                    .as_str()
                    .replacen("ak:event:", "ak:moderation_queue_item:", 1),
                "report": serde_json::to_value(&request.authority_commit.event.payload).unwrap(),
                "status": "submitted",
                "visibility": "plaintext_evidence",
                "created_at": arkret_canonical::format_timestamp_canonical(
                    request.authority_commit.commit.committed_at
                ),
            })
        );
    }
    assert_eq!(
        items(
            queue
                .queue_view_for_actor(&controller, Some(&realm_id))
                .await
                .unwrap()
        )
        .len(),
        2
    );
    let other_realm = arkret_wire::RealmId::from_event_id(&strand.authority_commit.event.event_id);
    assert!(
        items(
            queue
                .queue_view_for_actor(&controller, Some(&other_realm))
                .await
                .unwrap()
        )
        .is_empty()
    );
    assert!(items(queue.queue_view_for_actor(&stranger, None).await.unwrap()).is_empty());

    let material = store
        .realm_state_snapshot_material(&realm_id)
        .await
        .unwrap()
        .unwrap();
    for request in [&first, &second] {
        let selector = arkret_wire::CurrentSelector::ModerationReport {
            event_id: request.authority_commit.event.event_id.clone(),
        };
        let entry = material
            .current_state_entries
            .iter()
            .find(|entry| {
                matches!(entry, arkret_wire::TypedCurrentResult::Value { selector: found, .. } if found == &selector)
            })
            .expect("snapshot material carries the report row");
        let arkret_wire::TypedCurrentResult::Value {
            source_stream_ref,
            revision,
            value,
            ..
        } = entry
        else {
            unreachable!();
        };
        assert_eq!(
            source_stream_ref,
            &request.authority_commit.commit.stream_ref
        );
        assert_eq!(
            revision.commit_id,
            request.authority_commit.commit.commit_id
        );
        assert_eq!(
            value,
            &serde_json::to_value(&request.authority_commit.event.payload).unwrap()
        );
    }

    // A dismiss naming the first report resolves exactly that item and is
    // recorded as one assertion of the report's moderation_state.
    let dismiss = realm_self_event_request(
        &second,
        &reporter,
        arkret_wire::EventKind::ModerationDecision,
        serde_json::json!({
            "target_ref": first.authority_commit.event.event_id,
            "decision": "dismiss",
            "issuer_id": reporter,
            "request_canonical_digest": format!("sha256:{}", "00".repeat(32)),
        }),
    );
    uow.commit_event(dismiss.clone()).await.unwrap();
    let statuses = |view: Vec<ModerationQueueItem>| {
        view.iter()
            .map(|item| serde_json::to_value(&item.status).unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        statuses(queue.queue_view_for_actor(&controller, None).await.unwrap()),
        [
            serde_json::json!("resolved"),
            serde_json::json!("submitted")
        ]
    );
    assert!(items(queue.queue_view_for_actor(&stranger, None).await.unwrap()).is_empty());

    // An issuer without a same-cut moderation capability writes nothing.
    let stranger_principal = stranger.signing_principal_id().clone();
    let unauthorized = realm_self_event_request(
        &dismiss,
        &stranger_principal,
        arkret_wire::EventKind::ModerationDecision,
        serde_json::json!({
            "target_ref": second.authority_commit.event.event_id,
            "decision": "dismiss",
            "issuer_id": stranger_principal,
            "request_canonical_digest": format!("sha256:{}", "01".repeat(32)),
        }),
    );
    assert!(uow.commit_event(unauthorized.clone()).await.is_err());
    assert!(
        store
            .committed_event(&unauthorized.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(moderation_state_rows(&pool).await, 1);

    // A require_review on the second report's target, committed after that
    // report, resolves it too.
    let review = realm_self_event_request(
        &dismiss,
        &reporter,
        arkret_wire::EventKind::ModerationDecision,
        serde_json::json!({
            "target_ref": realm_id,
            "decision": "require_review",
            "issuer_id": reporter,
            "request_canonical_digest": format!("sha256:{}", "02".repeat(32)),
        }),
    );
    uow.commit_event(review.clone()).await.unwrap();
    assert_eq!(
        statuses(queue.queue_view_for_actor(&controller, None).await.unwrap()),
        [serde_json::json!("resolved"), serde_json::json!("resolved")]
    );

    // A lift is compare-and-set on the durable moderation_state revision and
    // appends an assertion; it never removes the decision nor reopens items.
    let lift = |previous: &EventCommitRequest,
                stream_position: u64,
                commit_id: &arkret_wire::RealmCommitId| {
        realm_self_event_request(
            previous,
            &reporter,
            arkret_wire::EventKind::ModerationDecisionLift,
            serde_json::json!({
                "target_ref": realm_id,
                "decision_ref": review.authority_commit.event.event_id,
                "expected_revision": {
                    "commit_id": commit_id,
                    "stream_position": stream_position,
                },
            }),
        )
    };
    let stale = lift(&review, 0, &dismiss.authority_commit.commit.commit_id);
    let refusal = uow.commit_event(stale.clone()).await.unwrap_err();
    assert_eq!(
        refusal.conflict_code(),
        Some(soland_storage::ConflictCode::CasConflict),
        "{refusal:?}"
    );
    let current = lift(
        &review,
        review.authority_commit.commit.stream_position,
        &review.authority_commit.commit.commit_id,
    );
    uow.commit_event(current.clone()).await.unwrap();
    let material = store
        .realm_state_snapshot_material(&realm_id)
        .await
        .unwrap()
        .unwrap();
    let selector = arkret_wire::CurrentSelector::ModerationState {
        target_ref: realm_id.to_string(),
    };
    let Some(arkret_wire::TypedCurrentResult::Value {
        revision, value, ..
    }) = material.current_state_entries.iter().find(|entry| {
        matches!(entry, arkret_wire::TypedCurrentResult::Value { selector: found, .. } if found == &selector)
    })
    else {
        panic!("snapshot material carries the moderation_state row");
    };
    assert_eq!(
        revision.commit_id,
        current.authority_commit.commit.commit_id
    );
    let tags = value["assertions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["tag_id"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let mut expected = vec![
        format!("{}:0", review.authority_commit.event.event_id),
        format!("{}:0", current.authority_commit.event.event_id),
    ];
    expected.sort();
    assert_eq!(tags, expected);
    assert_eq!(
        statuses(queue.queue_view_for_actor(&controller, None).await.unwrap()),
        [serde_json::json!("resolved"), serde_json::json!("resolved")]
    );

    // The root controller grants the decision action on this Realm: the
    // grantee is a moderator of the queue at the same cut.
    let root_event_ref = realm_root_authority_event_ref(&pool, &realm_id).await;
    let grant = realm_self_event_request(
        &current,
        &reporter,
        arkret_wire::EventKind::CapabilityGrant,
        serde_json::json!({
            "grant": {
                "schema": "ak.schema.capability.v1",
                "realm_id": realm_id,
                "issuer_id": controller,
                "subject": stranger,
                "actions": ["ak.moderation.decision"],
                "resources": [{"kind": "realm", "realm_id": realm_id}],
                "issuer_authority_refs": [{
                    "kind": "realm_root",
                    "realm_id": realm_id,
                    "authority_event_ref": root_event_ref,
                    "authority_generation": 0
                }],
                "issued_at": arkret_canonical::format_timestamp_canonical(
                    current.authority_commit.commit.committed_at
                ),
            }
        }),
    );
    uow.commit_event(grant).await.unwrap();
    assert_eq!(
        items(queue.queue_view_for_actor(&stranger, None).await.unwrap()).len(),
        2
    );
}

async fn moderation_state_rows(pool: &soland_storage_postgres::PgPool) -> i64 {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT COUNT(*) AS count FROM moderation_state_current_results")
        .get_result::<CountRow>(&mut *conn)
        .await
        .unwrap()
        .count
}

async fn realm_root_authority_event_ref(
    pool: &soland_storage_postgres::PgPool,
    realm_id: &arkret_wire::RealmId,
) -> String {
    #[derive(diesel::QueryableByName)]
    struct RootRow {
        #[diesel(sql_type = Text)]
        authority_event_ref: String,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT authority_event_ref FROM realm_authority_root_current_results WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<RootRow>(&mut *conn)
    .await
    .unwrap()
    .authority_event_ref
}

/// Real PostgreSQL: the exact self reads decide visibility, generation, head
/// and row on one governing cut. Non-members, unknown Realms and foreign
/// watchers collapse to not-found; a provable Realm-scope row is answered;
/// everything this Station cannot prove fails closed instead of being
/// inferred from absence.
#[tokio::test]
async fn self_current_reads_answer_only_the_provable_cut() {
    use arkret_models_collaboration::exact_current_results::{
        ExactCurrentResultEntry, ExactCurrentResultsReadOutcome, ExactCurrentResultsReadRequestBody,
    };
    use arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentRequestBody;
    use soland_storage::{AccountRealmStreamList, MediaServiceAnchorRead, SelfExactCurrentRead};

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
    let station = arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap();
    let other_station =
        arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
    let stranger = arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        creator.station_id.clone(),
    );
    let unknown = arkret_wire::RealmId::from_event_id(&unit.transactions[1].event.event_id);
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let head = &unit.transactions[6].commit;

    // Streams: the sole founder sees the Realm stream with its genesis floor.
    let AccountRealmStreamList::Listed(rows) = store
        .list_realm_streams_for_account(&realm_id, &creator, &station)
        .await
        .unwrap()
    else {
        panic!("the founding Realm stream is listable");
    };
    assert_eq!(
        rows,
        vec![arkret_wire::RealmStreamRow {
            stream_ref: arkret_wire::CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
            head_commit_ref: head.commit_id.clone(),
            next_position: 7,
            readable_floor: Some(arkret_wire::ReadableFloor {
                oldest_position: 0,
                floor_commit_id: unit.transactions[0].commit.commit_id.clone(),
                floor_reason: arkret_wire::ReadableFloorReason::StreamStart,
            }),
        }]
    );
    for (realm, account) in [(&realm_id, &stranger), (&unknown, &creator)] {
        assert_eq!(
            store
                .list_realm_streams_for_account(realm, account, &station)
                .await
                .unwrap(),
            AccountRealmStreamList::NotVisible
        );
    }
    assert!(matches!(
        store
            .list_realm_streams_for_account(&realm_id, &creator, &other_station)
            .await
            .unwrap(),
        AccountRealmStreamList::Unproved(_)
    ));

    // Exact Relation read: no row is never inferred as never_written.
    let domain = serde_json::json!({
        "domain_kind":"tuple",
        "relation_kind":"references",
        "from_ref":"ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4",
        "to_ref":"ak:strand:AQdknt9AByYY2gb16KB093xeB4J8b02mTEd4Mt8z2rO-"
    });
    let relation_request = |realm: &arkret_wire::RealmId| {
        serde_json::from_value::<ExactCurrentResultsReadRequestBody>(serde_json::json!({
            "realm_id": realm,
            "selector": {"kind":"relation","primary_conflict_domain": domain},
        }))
        .unwrap()
    };
    let exact = |request: ExactCurrentResultsReadRequestBody,
                 account: arkret_wire::AccountId,
                 issuer: arkret_wire::DidCoreId| {
        let store = store.clone();
        async move {
            store
                .exact_current_result_for_account(&request, &account, &issuer)
                .await
                .unwrap()
        }
    };
    assert!(matches!(
        exact(
            relation_request(&realm_id),
            creator.clone(),
            station.clone()
        )
        .await,
        SelfExactCurrentRead::Unresolved(_)
    ));
    let relation_id = "ak:relation:AcFfzgdHkT6eFkto1gjLaKniVuMXx9sD0GKQwk8BXykz";
    let value = serde_json::json!({
        "schema":"ak.schema.relation.v1",
        "id":relation_id,
        "realm_id":realm_id,
        "effective_scope":{"kind":"realm","realm_id":realm_id},
        "relation_kind":"references",
        "from_ref":"ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4",
        "to_ref":"ak:strand:AQdknt9AByYY2gb16KB093xeB4J8b02mTEd4Mt8z2rO-",
        "state":"active",
        "created_by":unit.transactions[0].event.actor_id,
        "created_at":"2026-09-21T00:00:00.000Z"
    });
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO relation_current_results \
         (realm_id,domain_key,domain,relation_id,state,current_commit_id,current_stream_position,\
          value,updated_at) VALUES ($1,$2,$3,$4,'active',$5,6,$6,now())",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(arkret_canonical::canonical_json_string(&domain).unwrap())
    .bind::<diesel::sql_types::Jsonb, _>(&domain)
    .bind::<Text, _>(relation_id)
    .bind::<Text, _>(head.commit_id.as_str())
    .bind::<diesel::sql_types::Jsonb, _>(&value)
    .execute(&mut conn)
    .await
    .unwrap();
    let SelfExactCurrentRead::Answer(ExactCurrentResultsReadOutcome::Present {
        realm_id: answered_realm,
        governance_generation,
        effective_stream_head,
        entry: ExactCurrentResultEntry::Relation(entry),
    }) = exact(
        relation_request(&realm_id),
        creator.clone(),
        station.clone(),
    )
    .await
    else {
        panic!("a Realm-scope Relation row is answered present");
    };
    assert_eq!(answered_realm, realm_id);
    assert_eq!(governance_generation, 0);
    assert_eq!(effective_stream_head.commit_id, head.commit_id);
    assert_eq!(effective_stream_head.stream_position, 6);
    assert_eq!(entry.revision.commit_id, head.commit_id);
    assert_eq!(entry.revision.stream_position, 6);
    assert_eq!(entry.source_stream_ref, effective_stream_head.stream_ref);
    // Non-members and unknown Realms cannot distinguish present from absent.
    assert!(matches!(
        exact(
            relation_request(&realm_id),
            stranger.clone(),
            station.clone()
        )
        .await,
        SelfExactCurrentRead::NotFound
    ));
    assert!(matches!(
        exact(relation_request(&unknown), creator.clone(), station.clone()).await,
        SelfExactCurrentRead::NotFound
    ));
    assert!(matches!(
        exact(
            relation_request(&realm_id),
            creator.clone(),
            other_station.clone()
        )
        .await,
        SelfExactCurrentRead::Unresolved(_)
    ));
    let moderation =
        serde_json::from_value::<ExactCurrentResultsReadRequestBody>(serde_json::json!({
            "realm_id": realm_id,
            "selector": {"kind":"moderation_state","target_ref": relation_id},
        }))
        .unwrap();
    // No decision ever named the target: nothing a lift could consume, and
    // never_written is Relation-only.
    assert!(matches!(
        exact(moderation, creator.clone(), station.clone()).await,
        SelfExactCurrentRead::NotFound
    ));

    // Strand watch: only the watcher itself, only a known Strand.
    let watch = |watcher: &arkret_wire::AccountId| StrandWatchCurrentRequestBody {
        realm_id: realm_id.clone(),
        strand_id: arkret_wire::StrandId::new(
            "ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4".to_owned(),
        )
        .unwrap(),
        watcher_actor_id: arkret_wire::ActorId::account(watcher.clone()),
    };
    for (request, account) in [(watch(&stranger), &creator), (watch(&creator), &creator)] {
        assert!(matches!(
            store
                .strand_watch_current_for_account(&request, account, &station)
                .await
                .unwrap(),
            SelfExactCurrentRead::NotFound
        ));
    }

    // Media service: no accepted assignment in the visible Realm.
    for account in [&creator, &stranger] {
        assert_eq!(
            store
                .media_service_anchor_for_account(&realm_id, account, &station)
                .await
                .unwrap(),
            MediaServiceAnchorRead::NotFound
        );
    }

    // A second joined member makes the founder's floor unprovable.
    let second_member = arkret_wire::ActorId::account(stranger.clone()).to_string();
    diesel::sql_query(
        "INSERT INTO member_state_current_results \
         (realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) \
         VALUES ($1,$2,'join',$3,6,'{\"membership\":\"join\"}'::jsonb,now())",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(&second_member)
    .bind::<Text, _>(head.commit_id.as_str())
    .execute(&mut conn)
    .await
    .unwrap();
    assert!(matches!(
        store
            .list_realm_streams_for_account(&realm_id, &creator, &station)
            .await
            .unwrap(),
        AccountRealmStreamList::Unproved(_)
    ));
}
