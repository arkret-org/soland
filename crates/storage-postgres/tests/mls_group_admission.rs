//! Real PostgreSQL: `ak.mls.genesis` and `ak.mls.commit` install the
//! `mls_group` typed current, the public MLS state and every Welcome in the
//! transaction that commits their Event and RealmCommit, and every refusal
//! leaves zero writes (encryption-and-audit.md §2.2, §2.4.1, §5.1;
//! client-sync.md §10.1).

#[path = "../../test-support/src/device_authorization_history.rs"]
#[allow(dead_code)]
mod device_authorization_history;
#[path = "support/ordinary_realm.rs"]
mod ordinary_realm;
#[path = "../../test-support/src/pcr_genesis.rs"]
#[allow(dead_code)]
mod pcr_genesis;
mod support;

use arkret_models_crypto::{MlsCommitEnvelope, MlsCommitPayload, MlsGovernanceBindingPayload};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::RunQueryDsl;
use soland_storage::{
    AuthorityCommitStore, ConflictCode, DeviceMessageStore, DeviceRevocationGateSelector,
    DeviceRevocationStore, EventCommitRequest, EventCommitUnitOfWork, IdentityStoreRegistry,
    MlsGroupCurrentStore, MlsInstalledBase, MlsKeyPackageStore, MlsStateInstallation,
    MlsWelcomeClaimLedgerKey, RecipientQueueSelector, VerifiedMlsWelcome,
};
use soland_storage_postgres::test_database::TestDatabase;
use soland_storage_postgres::{
    PgAuthorityCommitStore, PgDeviceMessageStore, PgEventCommitUnitOfWork, PgMlsGroupCurrentStore,
    PgPool,
};

fn realm_scope(realm_id: &arkret_wire::RealmId) -> arkret_wire::ScopeRef {
    arkret_wire::ScopeRef::Realm {
        realm_id: realm_id.clone(),
    }
}

fn blob(seed: char) -> String {
    format!("ak:blob:sha256:{}", seed.to_string().repeat(64))
}

fn genesis_payload(
    realm_id: &arkret_wire::RealmId,
    at: chrono::DateTime<chrono::Utc>,
) -> serde_json::Value {
    serde_json::json!({
        "cipher_suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "group_info_ref": blob('3'),
        "ratchet_tree_ref": blob('4'),
        "governance_binding":
            MlsGovernanceBindingPayload::realm(realm_id.clone(), None, 0, 0, 0).unwrap(),
        "created_at": arkret_canonical::format_timestamp_canonical(at),
    })
}

fn commit_payload(
    realm_id: &arkret_wire::RealmId,
    base: &arkret_wire::EventId,
    previous_epoch: u64,
    revision: u64,
    commit_bytes: &[u8],
) -> serde_json::Value {
    let binding = MlsGovernanceBindingPayload::realm(
        realm_id.clone(),
        Some(base.clone()),
        previous_epoch,
        previous_epoch + 1,
        revision,
    )
    .unwrap();
    let envelope = MlsCommitEnvelope {
        group_id: binding.mls_group_id().unwrap(),
        epoch: previous_epoch + 1,
        commit: arkret_wire::base64url::base64url_encode(commit_bytes),
        commit_digest: arkret_wire::Hash::new(arkret_canonical::sha256_digest(commit_bytes))
            .unwrap(),
        ratchet_tree: None,
    };
    serde_json::to_value(MlsCommitPayload::new(base.clone(), revision, &envelope, binding).unwrap())
        .unwrap()
}

fn with_installation(
    mut request: EventCommitRequest,
    base: Option<(&arkret_wire::EventId, u64)>,
    epoch: u64,
) -> EventCommitRequest {
    let scope = request.authority_commit.event.scope_ref.clone();
    // A joined member hosted by another Station receives the Commit Event,
    // never its Welcomes, through committed replication.
    request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        request.authority_commit.event.clone(),
    ));
    request.authority_commit.mls_state = Some(MlsStateInstallation {
        effective_scope: scope,
        base: base.map(|(reference, epoch)| MlsInstalledBase {
            current_mls_commit_event_ref: reference.clone(),
            epoch,
        }),
        epoch,
        public_state: format!("public-state-{epoch}").into_bytes(),
        genesis_blobs: Vec::new(),
    });
    request
}

fn welcome(
    commit: &EventCommitRequest,
    recipient: &DeviceRevocationGateSelector,
    claim_id: &str,
) -> arkret_wire::MlsWelcomeDelivery {
    let event = &commit.authority_commit.event;
    arkret_wire::MlsWelcomeDelivery {
        welcome_id: arkret_wire::MlsWelcomeDeliveryId::new(format!(
            "ak:mls_welcome_delivery:{}",
            uuid::Uuid::now_v7()
        ))
        .unwrap(),
        realm_id: event.realm_id.clone(),
        effective_scope: event.scope_ref.clone(),
        commit_event_ref: event.event_id.clone(),
        recipient_actor_id: recipient_actor(recipient),
        recipient_endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
            device_id: arkret_wire::DeviceId::new(recipient.device_id.clone()).unwrap(),
        },
        keypackage_claim_ref: arkret_wire::KeypackageClaimId::new(claim_id.to_owned()).unwrap(),
        ciphertext_b64: arkret_wire::Base64UrlString::new("V2VsY29tZQ".to_owned()).unwrap(),
        producer_proof: arkret_wire::DetachedObjectSignature {
            context: arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
            signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
            verification_method: event
                .producer_proof
                .as_ref()
                .unwrap()
                .verification_method
                .clone(),
            signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "5".repeat(64))).unwrap(),
            created_at: commit.authority_commit.commit.committed_at,
            sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
        },
    }
}

fn recipient_actor(recipient: &DeviceRevocationGateSelector) -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        recipient.principal_id.clone(),
        recipient.station_id.clone(),
    ))
}

fn claim_id() -> String {
    format!("ak:keypackage_claim:{}", uuid::Uuid::now_v7())
}

/// One live claim ledger row as the claim service leaves it after a
/// successful same-Station claim.
async fn live_claim(pool: &PgPool, station: &str, claim_id: &str) -> MlsWelcomeClaimLedgerKey {
    let key = MlsWelcomeClaimLedgerKey {
        source_id: station.to_owned(),
        claim_request_id: uuid::Uuid::now_v7().simple().to_string(),
        request_digest: format!("sha256:{}", "6".repeat(64)),
    };
    let now = chrono::Utc::now();
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO peer_keypackage_claims \
         (source_id,claim_request_id,request_digest,key_package_use,keypackage_id,outcome, \
          terminal_receipt,consume_receipt,claim_expires_at_unix_ms,expires_at,state,updated_at) \
         VALUES ($1,$2,$3,'single_use',NULL,$4,NULL,NULL,$5,$6,'claimed',$7)",
    )
    .bind::<Text, _>(&key.source_id)
    .bind::<Text, _>(&key.claim_request_id)
    .bind::<Text, _>(&key.request_digest)
    .bind::<Jsonb, _>(serde_json::json!({"claims": [{"claim_id": claim_id}]}))
    .bind::<BigInt, _>(now.timestamp_millis() + 3_600_000)
    .bind::<BigInt, _>(now.timestamp() + 86_400)
    .bind::<BigInt, _>(now.timestamp())
    .execute(&mut *conn)
    .await
    .unwrap();
    key
}

/// The recipient joins the Realm as an Invite acceptance would leave it.
async fn join(pool: &PgPool, head: &EventCommitRequest, member: &arkret_wire::ActorId) {
    let basis = &head.authority_commit;
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO member_state_current_results \
         (realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,'join',$3,$4,$5,$6)",
    )
    .bind::<Text, _>(basis.event.realm_id.as_str())
    .bind::<Text, _>(member.to_string())
    .bind::<Text, _>(basis.commit.commit_id.as_str())
    .bind::<BigInt, _>(basis.commit.stream_position as i64)
    .bind::<Jsonb, _>(serde_json::json!({"membership":"join"}))
    .bind::<Timestamptz, _>(basis.commit.committed_at)
    .execute(&mut *conn)
    .await
    .unwrap();
}

async fn local_station(pool: &PgPool) -> arkret_wire::DidCoreId {
    #[derive(diesel::QueryableByName)]
    struct Station {
        #[diesel(sql_type = Text)]
        station_id: String,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO device_inventory_station(singleton,station_id) \
         VALUES(TRUE,'ak:did_core:web:mls-admission.example') ON CONFLICT(singleton) DO NOTHING",
    )
    .execute(&mut *conn)
    .await
    .unwrap();
    diesel::sql_query("SELECT station_id FROM device_inventory_station WHERE singleton")
        .get_result::<Station>(&mut *conn)
        .await
        .unwrap()
        .station_id
        .parse()
        .unwrap()
}

/// This Station as the governance Station of every fixture Realm, so an
/// account it hosts is a local member of those Realms.
async fn governing_station(pool: &PgPool) -> arkret_wire::DidCoreId {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
        .bind::<Text, _>(ordinary_realm::STATION)
        .execute(&mut *conn)
        .await
        .unwrap();
    ordinary_realm::station()
}

async fn welcome_count(pool: &PgPool) -> i64 {
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = BigInt)]
        count: i64,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT COUNT(*) AS count FROM mls_welcome_deliveries")
        .get_result::<Count>(&mut *conn)
        .await
        .unwrap()
        .count
}

/// `request` is refused with `code`; its Event, RealmCommit, group current
/// and Welcomes are all absent.
async fn assert_zero_write_refusal(
    pool: &PgPool,
    request: &EventCommitRequest,
    code: ConflictCode,
) {
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let groups = PgMlsGroupCurrentStore { pool: pool.clone() };
    let scope = &request.authority_commit.event.scope_ref;
    let before = groups.current(scope).await.unwrap();
    let welcomes = welcome_count(pool).await;
    let error = uow.commit_event(request.clone()).await.unwrap_err();
    assert_eq!(error.conflict_code(), Some(code), "{error}");
    assert!(
        PgAuthorityCommitStore { pool: pool.clone() }
            .committed_event(&request.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(groups.current(scope).await.unwrap(), before);
    assert_eq!(welcome_count(pool).await, welcomes);
}

/// Genesis creates the `mls_group` current at its Commit; a second Genesis
/// is `mls_activation_irreversible`. A Commit merges epoch, current ref and
/// covered revision over the exact base; a stale base or an uncovered
/// key-access revision is `governance_binding_mismatch`, and a non-member
/// committer is `capability_denied`, each with zero writes.
#[tokio::test]
async fn mls_genesis_and_commit_install_the_group_at_their_commits() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = ordinary_realm::open_discussion(&pool, "mls-group-admission").await;
    let realm_id = discussion.realm_id();
    let scope = realm_scope(&realm_id);
    let founder = ordinary_realm::founder();
    let at = discussion.committed_at();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let groups = PgMlsGroupCurrentStore { pool: pool.clone() };

    let genesis = with_installation(
        ordinary_realm::next_request(
            &discussion.head.authority_commit,
            arkret_wire::EventKind::MlsGenesis,
            &founder,
            genesis_payload(&realm_id, at),
            at,
        ),
        None,
        0,
    );
    uow.commit_event(genesis.clone()).await.unwrap();
    let genesis_ref = genesis.authority_commit.event.event_id.clone();
    let installed = groups.current(&scope).await.unwrap().unwrap();
    assert_eq!(
        installed.value,
        arkret_wire::MlsGroupCurrent {
            effective_scope: scope.clone(),
            genesis_event_ref: genesis_ref.clone(),
            current_mls_commit_event_ref: genesis_ref.clone(),
            epoch: 0,
            current_key_access_revision: 0,
            covered_key_access_revision: 0,
            public_tree_ref: arkret_wire::BlobRef::new(blob('4')).unwrap(),
        }
    );
    assert_eq!(
        installed.current_commit_id,
        genesis.authority_commit.commit.commit_id
    );
    assert_eq!(installed.public_state, b"public-state-0");

    let second_genesis = with_installation(
        ordinary_realm::next_request(
            &genesis.authority_commit,
            arkret_wire::EventKind::MlsGenesis,
            &founder,
            genesis_payload(&realm_id, at + chrono::TimeDelta::seconds(1)),
            at + chrono::TimeDelta::seconds(1),
        ),
        None,
        0,
    );
    assert_zero_write_refusal(
        &pool,
        &second_genesis,
        ConflictCode::MlsActivationIrreversible,
    )
    .await;

    let uncovered = with_installation(
        ordinary_realm::next_request(
            &genesis.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &founder,
            commit_payload(&realm_id, &genesis_ref, 0, 1, b"uncovered"),
            at,
        ),
        Some((&genesis_ref, 0)),
        1,
    );
    assert_zero_write_refusal(&pool, &uncovered, ConflictCode::GovernanceBindingMismatch).await;

    let outsider = arkret_wire::DidCoreId::new("ak:did_core:web:mls-outsider.example").unwrap();
    let foreign = with_installation(
        ordinary_realm::next_request(
            &genesis.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &outsider,
            commit_payload(&realm_id, &genesis_ref, 0, 0, b"foreign"),
            at,
        ),
        Some((&genesis_ref, 0)),
        1,
    );
    assert_zero_write_refusal(&pool, &foreign, ConflictCode::CapabilityDenied).await;

    let commit = with_installation(
        ordinary_realm::next_request(
            &genesis.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &founder,
            commit_payload(&realm_id, &genesis_ref, 0, 0, b"first"),
            at,
        ),
        Some((&genesis_ref, 0)),
        1,
    );
    uow.commit_event(commit.clone()).await.unwrap();
    let advanced = groups.current(&scope).await.unwrap().unwrap();
    assert_eq!(advanced.value.epoch, 1);
    assert_eq!(
        advanced.value.current_mls_commit_event_ref,
        commit.authority_commit.event.event_id
    );
    assert_eq!(advanced.value.genesis_event_ref, genesis_ref);
    assert_eq!(
        advanced.current_commit_id,
        commit.authority_commit.commit.commit_id
    );
    assert_eq!(advanced.public_state, b"public-state-1");

    let stale = with_installation(
        ordinary_realm::next_request(
            &commit.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &founder,
            commit_payload(&realm_id, &genesis_ref, 0, 0, b"stale"),
            at,
        ),
        Some((&genesis_ref, 0)),
        1,
    );
    assert_zero_write_refusal(&pool, &stale, ConflictCode::GovernanceBindingMismatch).await;
}

/// A Commit and its Welcome commit together; a full recipient queue rolls the
/// whole Commit back; a reused claim is `duplicate_conflict`; the queued
/// Welcome is read and ACKed only by its exact endpoint and becomes
/// unreadable once that endpoint's device is revoked.
#[tokio::test]
async fn mls_commit_welcome_queue_is_atomic_exact_endpoint_and_revocation_gated() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let station = local_station(&pool).await;
    let persistence = soland_storage_postgres::PgPersistenceStore::new(pool.clone());
    let mut source = pcr_genesis::PcrGenesisFixture::new(
        device_authorization_history::did_web_station(&station),
    );
    let recipient = source
        .admit_founding_device(&persistence)
        .await
        .expect("accepted recipient device");
    let second_device = source
        .admit_accepted_device(&persistence, [41; 32])
        .await
        .expect("accepted second recipient device");

    let discussion = ordinary_realm::open_discussion(&pool, "mls-welcome-queue").await;
    let realm_id = discussion.realm_id();
    let founder = ordinary_realm::founder();
    let at = discussion.committed_at();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let genesis = with_installation(
        ordinary_realm::next_request(
            &discussion.head.authority_commit,
            arkret_wire::EventKind::MlsGenesis,
            &founder,
            genesis_payload(&realm_id, at),
            at,
        ),
        None,
        0,
    );
    uow.commit_event(genesis.clone()).await.unwrap();
    let genesis_ref = genesis.authority_commit.event.event_id.clone();

    let first_claim = claim_id();
    let first_key = live_claim(&pool, station.as_str(), &first_claim).await;
    let mut commit = with_installation(
        ordinary_realm::next_request(
            &genesis.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &founder,
            commit_payload(&realm_id, &genesis_ref, 0, 0, b"add"),
            at,
        ),
        Some((&genesis_ref, 0)),
        1,
    );
    commit.authority_commit.welcomes = vec![VerifiedMlsWelcome {
        delivery: welcome(&commit, &recipient, &first_claim),
        claim: Some(first_key.clone()),
    }];
    commit.authority_commit.recipient_queue_capacity = 1;
    assert_zero_write_refusal(&pool, &commit, ConflictCode::FailedPrecondition).await;
    join(&pool, &discussion.head, &recipient_actor(&recipient)).await;
    uow.commit_event(commit.clone()).await.unwrap();
    assert_eq!(welcome_count(&pool).await, 1);
    let commit_ref = commit.authority_commit.event.event_id.clone();
    // decision 0121: the queueing transaction binds the claim to its Welcome.
    let queued = &commit.authority_commit.welcomes[0].delivery;
    assert_eq!(
        soland_storage_postgres::PgMlsKeyPackageStore { pool: pool.clone() }
            .get_claim_welcome_binding(&first_claim)
            .await
            .unwrap(),
        Some(soland_storage::MlsWelcomeClaimBinding {
            claim_id: first_claim.clone(),
            source_id: first_key.source_id.clone(),
            claim_request_id: first_key.claim_request_id.clone(),
            welcome_id: queued.welcome_id.to_string(),
            welcome_digest: queued.durable_receipt_digest().unwrap().to_string(),
            commit_event_ref: commit_ref.to_string(),
        })
    );

    let second_claim = claim_id();
    let second_key = live_claim(&pool, station.as_str(), &second_claim).await;
    let mut full = with_installation(
        ordinary_realm::next_request(
            &commit.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &founder,
            commit_payload(&realm_id, &commit_ref, 1, 0, b"full"),
            at,
        ),
        Some((&commit_ref, 1)),
        2,
    );
    full.authority_commit.welcomes = vec![VerifiedMlsWelcome {
        delivery: welcome(&full, &recipient, &second_claim),
        claim: Some(second_key),
    }];
    full.authority_commit.recipient_queue_capacity = 1;
    assert_zero_write_refusal(&pool, &full, ConflictCode::RecipientQueueAtCapacity).await;

    let mut reused = with_installation(
        ordinary_realm::next_request(
            &commit.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &founder,
            commit_payload(&realm_id, &commit_ref, 1, 0, b"reused"),
            at,
        ),
        Some((&commit_ref, 1)),
        2,
    );
    reused.authority_commit.welcomes = vec![VerifiedMlsWelcome {
        delivery: welcome(&reused, &recipient, &first_claim),
        claim: Some(first_key),
    }];
    reused.authority_commit.recipient_queue_capacity = 10;
    assert_zero_write_refusal(&pool, &reused, ConflictCode::DuplicateConflict).await;

    let queue = PgDeviceMessageStore { pool: pool.clone() };
    let endpoint = |device: &DeviceRevocationGateSelector| RecipientQueueSelector::HumanDevice {
        recipient: device.principal_id.to_string(),
        device_id: device.device_id.clone(),
    };
    let listed = queue
        .list_recipient_deliveries(&endpoint(&recipient), 0, 10)
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert!(matches!(
        &listed[0].delivery,
        arkret_models_collaboration::device_messages::RecipientDelivery::MlsWelcome { mls_welcome }
            if mls_welcome.keypackage_claim_ref.as_str() == first_claim
    ));
    assert!(
        queue
            .list_recipient_deliveries(&endpoint(&second_device.authorization), 0, 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        queue
            .issue_recipient_ack_token(&endpoint(&second_device.authorization), listed[0].position)
            .await
            .unwrap()
            .is_none()
    );
    let token = queue
        .issue_recipient_ack_token(&endpoint(&recipient), listed[0].position)
        .await
        .unwrap()
        .expect("the exact endpoint ACKs its own Welcome");
    assert!(
        queue
            .ack_recipient_with_token(&endpoint(&second_device.authorization), &token)
            .await
            .unwrap()
            .is_none_or(|count| count == 0)
    );
    assert_eq!(
        queue
            .list_recipient_deliveries(&endpoint(&recipient), 0, 10)
            .await
            .unwrap()
            .len(),
        1
    );

    persistence
        .device_revocations()
        .commit_revocation(&soland_storage::DeviceRevocationTransition {
            selector: recipient.clone(),
            revoke_ref: arkret_wire::CommittedEventRef {
                event_id: arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [0x52; 32],
                ),
                commit_id: arkret_wire::RealmCommitId::from_digest([0x53; 32]),
                stream_ref: recipient.authorization_ref.stream_ref.clone(),
                stream_position: recipient.authorization_ref.stream_position + 10,
            },
            committed_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
    assert!(
        queue
            .list_recipient_deliveries(&endpoint(&recipient), 0, 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        queue
            .ack_recipient_with_token(&endpoint(&recipient), &token)
            .await
            .unwrap()
            .is_none()
    );
}

/// One MLS ciphertext Message body frozen at `epoch` over `group_state_ref`.
fn ciphertext_message(
    strand_id: &arkret_wire::StrandId,
    epoch: u64,
    group_state_ref: &arkret_wire::EventId,
) -> serde_json::Value {
    serde_json::json!({
        "strand_id": strand_id,
        "track_name": "discussion",
        "encrypted_content": arkret_models_crypto::EncryptedEnvelope {
            version: "1.0".to_owned(),
            content_type: "application/vnd.arkret.message+json".to_owned(),
            encryption_context: arkret_models_crypto::EncryptedEnvelopeEncryptionContext::standard(
                epoch,
                group_state_ref.clone(),
            ),
            ciphertext: "Y2lwaGVydGV4dA".to_owned(),
        },
    })
}

/// A Message by the account of `device`, signed by that device and guarded
/// by its exact revocation-gate selector as the self submit preflight pins it.
fn device_message(
    previous: &soland_storage::AuthorityCommitTransaction,
    device: &DeviceRevocationGateSelector,
    payload: serde_json::Value,
) -> EventCommitRequest {
    let mut request = ordinary_realm::next_request_for_actor(
        previous,
        arkret_wire::EventKind::MessageCreate,
        recipient_actor(device),
        payload,
        previous.commit.committed_at,
    );
    let event = &mut request.authority_commit.event;
    event.producer_proof.as_mut().unwrap().verification_method = arkret_wire::DidUrl::new(format!(
        "did:{}#{}",
        device
            .principal_id
            .as_str()
            .strip_prefix("ak:did_core:")
            .unwrap(),
        device.device_id
    ))
    .unwrap();
    request.event.envelope = serde_json::to_value(&*event).unwrap();
    request.self_producer_guard = Some(soland_storage::SelfProducerCommitGuard::HumanDevice(
        device.clone(),
    ));
    request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        request.authority_commit.event.clone(),
    ));
    request
}

/// The Realm root's grant of `ak.message.create` to `subject`.
async fn grant_message_create(
    pool: &PgPool,
    previous: &soland_storage::AuthorityCommitTransaction,
    subject: &arkret_wire::ActorId,
) -> EventCommitRequest {
    #[derive(diesel::QueryableByName)]
    struct Root {
        #[diesel(sql_type = Text)]
        authority_event_ref: String,
    }
    let realm_id = previous.event.realm_id.clone();
    let root = {
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query(
            "SELECT authority_event_ref FROM realm_authority_root_current_results WHERE realm_id=$1",
        )
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<Root>(&mut *conn)
        .await
        .unwrap()
        .authority_event_ref
    };
    let founder = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        ordinary_realm::founder(),
        ordinary_realm::station(),
    ));
    let at = previous.commit.committed_at;
    let grant = ordinary_realm::next_request(
        previous,
        arkret_wire::EventKind::CapabilityGrant,
        &ordinary_realm::founder(),
        serde_json::json!({
            "grant": {
                "schema": "ak.schema.capability.v1",
                "realm_id": realm_id,
                "issuer_id": founder,
                "subject": subject,
                "actions": ["ak.message.create"],
                "resources": [{"kind": "realm", "realm_id": realm_id}],
                "issuer_authority_refs": [{
                    "kind": "realm_root",
                    "realm_id": realm_id,
                    "authority_event_ref": root,
                    "authority_generation": 0
                }],
                "issued_at": arkret_canonical::format_timestamp_canonical(at),
            }
        }),
        at,
    );
    PgEventCommitUnitOfWork::new(pool.clone())
        .commit_event(grant.clone())
        .await
        .unwrap();
    grant
}

/// encryption-and-audit.md §2.5.2 and §2.4.1: the send gate decides the
/// actual signer's endpoint authorization at the cut it reads the current
/// `mls_group`. A revoked device's ciphertext -- even frozen at a stale epoch
/// -- is `device_revoked`, while the same account's other device and another
/// member keep sending at the current epoch; plaintext into the activated
/// scope is `mls_activation_required` and a stale epoch `epoch_mismatch`. The
/// revocation never advances the key-access revision, and each refusal
/// writes nothing.
#[tokio::test]
async fn the_send_gate_refuses_a_revoked_device_at_the_mls_group_cut() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let station = governing_station(&pool).await;
    let persistence = soland_storage_postgres::PgPersistenceStore::new(pool.clone());
    let mut source = pcr_genesis::PcrGenesisFixture::new(
        device_authorization_history::did_web_station(&station),
    );
    let revoked = source
        .admit_founding_device(&persistence)
        .await
        .expect("accepted founding device");
    let active = source
        .admit_accepted_device(&persistence, [43; 32])
        .await
        .expect("accepted second device")
        .authorization;

    let discussion = ordinary_realm::open_discussion(&pool, "mls-send-gate").await;
    let realm_id = discussion.realm_id();
    let scope = realm_scope(&realm_id);
    let founder = ordinary_realm::founder();
    let at = discussion.committed_at();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let groups = PgMlsGroupCurrentStore { pool: pool.clone() };
    join(&pool, &discussion.head, &recipient_actor(&revoked)).await;
    let grant = grant_message_create(
        &pool,
        &discussion.head.authority_commit,
        &recipient_actor(&revoked),
    )
    .await;
    let genesis = with_installation(
        ordinary_realm::next_request(
            &grant.authority_commit,
            arkret_wire::EventKind::MlsGenesis,
            &founder,
            genesis_payload(&realm_id, at),
            at,
        ),
        None,
        0,
    );
    uow.commit_event(genesis.clone()).await.unwrap();
    let genesis_ref = genesis.authority_commit.event.event_id.clone();
    let commit = with_installation(
        ordinary_realm::next_request(
            &genesis.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            &founder,
            commit_payload(&realm_id, &genesis_ref, 0, 0, b"epoch-one"),
            at,
        ),
        Some((&genesis_ref, 0)),
        1,
    );
    uow.commit_event(commit.clone()).await.unwrap();
    let commit_ref = commit.authority_commit.event.event_id.clone();
    let before = groups.current(&scope).await.unwrap().unwrap();
    assert_eq!(before.value.epoch, 1);

    persistence
        .device_revocations()
        .commit_revocation(&soland_storage::DeviceRevocationTransition {
            selector: revoked.clone(),
            revoke_ref: arkret_wire::CommittedEventRef {
                event_id: arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [0x54; 32],
                ),
                commit_id: arkret_wire::RealmCommitId::from_digest([0x55; 32]),
                stream_ref: revoked.authorization_ref.stream_ref.clone(),
                stream_position: revoked.authorization_ref.stream_position + 10,
            },
            committed_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
    let strand = &discussion.strand_id;
    for payload in [
        ciphertext_message(strand, 0, &genesis_ref),
        ciphertext_message(strand, 1, &commit_ref),
    ] {
        assert_zero_write_refusal(
            &pool,
            &device_message(&commit.authority_commit, &revoked, payload),
            ConflictCode::DeviceRevoked,
        )
        .await;
    }
    assert_eq!(groups.current(&scope).await.unwrap().unwrap(), before);

    let plaintext = ordinary_realm::next_request(
        &commit.authority_commit,
        arkret_wire::EventKind::MessageCreate,
        &founder,
        ordinary_realm::message_payload(strand, "plaintext after activation"),
        at,
    );
    assert_zero_write_refusal(&pool, &plaintext, ConflictCode::MlsActivationRequired).await;
    let stale = ordinary_realm::next_request(
        &commit.authority_commit,
        arkret_wire::EventKind::MessageCreate,
        &founder,
        ciphertext_message(strand, 0, &genesis_ref),
        at,
    );
    assert_zero_write_refusal(&pool, &stale, ConflictCode::EpochMismatch).await;

    let sibling = device_message(
        &commit.authority_commit,
        &active,
        ciphertext_message(strand, 1, &commit_ref),
    );
    uow.commit_event(sibling.clone()).await.unwrap();
    let member = ordinary_realm::next_request(
        &sibling.authority_commit,
        arkret_wire::EventKind::MessageCreate,
        &founder,
        ciphertext_message(strand, 1, &commit_ref),
        at,
    );
    uow.commit_event(member).await.unwrap();
    let after = groups.current(&scope).await.unwrap().unwrap();
    assert_eq!(
        after.value, before.value,
        "no revocation advances the group"
    );
}

/// A Welcome to a device of `member` on another Station.
fn remote_welcome(
    commit: &EventCommitRequest,
    member: &arkret_wire::ActorId,
) -> VerifiedMlsWelcome {
    let recipient = DeviceRevocationGateSelector {
        principal_id: member.signing_principal_id().clone(),
        station_id: member.route_service_id().clone(),
        device_id: format!("ak:device:{}", uuid::Uuid::now_v7()),
        authorization_ref: arkret_wire::CommittedEventRef {
            event_id: commit.authority_commit.event.event_id.clone(),
            commit_id: commit.authority_commit.commit.commit_id.clone(),
            stream_ref: commit.authority_commit.commit.stream_ref.clone(),
            stream_position: commit.authority_commit.commit.stream_position,
        },
    };
    VerifiedMlsWelcome {
        delivery: welcome(commit, &recipient, &claim_id()),
        claim: None,
    }
}

async fn replication_payloads(
    pool: &PgPool,
    commit: &EventCommitRequest,
) -> Vec<(String, serde_json::Value)> {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Text)]
        peer_id: String,
        #[diesel(sql_type = Text)]
        payload_json: String,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT peer_id,payload_json FROM federation_outbox WHERE idempotency_key=$1 \
         ORDER BY peer_id",
    )
    .bind::<Text, _>(format!(
        "realm-fanout:{}",
        commit.authority_commit.commit.commit_id
    ))
    .load::<Row>(&mut *conn)
    .await
    .unwrap()
    .into_iter()
    .map(|row| {
        (
            row.peer_id,
            serde_json::from_str(&row.payload_json).unwrap(),
        )
    })
    .collect()
}

/// encryption-and-audit.md §2.2 "跨站 recipient": the governance Station
/// verifies everything but the claim of a Welcome whose recipient another
/// Station hosts and writes it, in submission order, into the Commit's
/// committed-replication intent to exactly that Station, next to the local
/// recipient's queued Welcome; a Station without a joined recipient receives
/// no Welcome, and a remote recipient that is no current joined member
/// refuses the whole Commit with zero writes.
#[tokio::test]
async fn a_remote_recipient_welcome_rides_the_commit_replication_intent() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let station = governing_station(&pool).await;
    let persistence = soland_storage_postgres::PgPersistenceStore::new(pool.clone());
    let local = pcr_genesis::PcrGenesisFixture::new(device_authorization_history::did_web_station(
        &station,
    ))
    .admit_founding_device(&persistence)
    .await
    .expect("accepted local recipient device");
    let discussion = ordinary_realm::open_discussion(&pool, "mls-remote-welcome").await;
    let realm_id = discussion.realm_id();
    let founder = ordinary_realm::founder();
    let at = discussion.committed_at();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let remote_station = "ak:did_core:web:mls-member-station.example";
    let other_station = "ak:did_core:web:mls-other-station.example";
    let member = |label: &str, station: &str| {
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(format!("ak:did_core:web:{label}.example")).unwrap(),
            arkret_wire::DidCoreId::new(station).unwrap(),
        ))
    };
    let (first, second, bystander) = (
        member("mls-remote-first", remote_station),
        member("mls-remote-second", remote_station),
        member("mls-remote-bystander", other_station),
    );
    for joined in [&first, &second, &bystander, &recipient_actor(&local)] {
        join(&pool, &discussion.head, joined).await;
    }
    let genesis = with_installation(
        ordinary_realm::next_request(
            &discussion.head.authority_commit,
            arkret_wire::EventKind::MlsGenesis,
            &founder,
            genesis_payload(&realm_id, at),
            at,
        ),
        None,
        0,
    );
    uow.commit_event(genesis.clone()).await.unwrap();
    let genesis_ref = genesis.authority_commit.event.event_id.clone();

    let add = |bytes: &[u8]| {
        with_installation(
            ordinary_realm::next_request(
                &genesis.authority_commit,
                arkret_wire::EventKind::MlsCommit,
                &founder,
                commit_payload(&realm_id, &genesis_ref, 0, 0, bytes),
                at,
            ),
            Some((&genesis_ref, 0)),
            1,
        )
    };
    let mut stranger = add(b"stranger");
    stranger.authority_commit.welcomes = vec![remote_welcome(
        &stranger,
        &member("mls-remote-stranger", remote_station),
    )];
    stranger.authority_commit.recipient_queue_capacity = 4;
    assert_zero_write_refusal(&pool, &stranger, ConflictCode::FailedPrecondition).await;
    assert!(replication_payloads(&pool, &stranger).await.is_empty());

    let mut commit = add(b"cross-station add");
    let local_claim = claim_id();
    let local_key = live_claim(&pool, station.as_str(), &local_claim).await;
    let mut welcomes = vec![
        remote_welcome(&commit, &first),
        VerifiedMlsWelcome {
            delivery: welcome(&commit, &local, &local_claim),
            claim: Some(local_key),
        },
        remote_welcome(&commit, &second),
    ];
    welcomes.sort_by(|left, right| left.delivery.welcome_id.cmp(&right.delivery.welcome_id));
    commit.authority_commit.welcomes = welcomes.clone();
    commit.authority_commit.recipient_queue_capacity = 4;
    uow.commit_event(commit.clone()).await.unwrap();
    assert_eq!(
        welcome_count(&pool).await,
        1,
        "only the local Welcome is queued"
    );

    let payloads = replication_payloads(&pool, &commit).await;
    assert_eq!(
        payloads
            .iter()
            .map(|(peer, _)| peer.as_str())
            .collect::<Vec<_>>(),
        [remote_station, other_station]
    );
    let item = |payload: &serde_json::Value| payload["replications"][0].clone();
    assert!(item(&payloads[1].1).get("welcomes").is_none());
    let expected = welcomes
        .iter()
        .filter(|welcome| welcome.claim.is_none())
        .map(|welcome| serde_json::to_value(&welcome.delivery).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        item(&payloads[0].1)["welcomes"],
        serde_json::json!(expected)
    );
    let request: arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest =
        serde_json::from_value(payloads[0].1.clone()).unwrap();
    request.validate().unwrap();
}
