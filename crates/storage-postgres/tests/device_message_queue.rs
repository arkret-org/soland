//! Real PostgreSQL proof that the human DeviceMessage queue persists exactly
//! the closed `DeviceMessageEnvelope` it serves, and fails closed on any other
//! stored shape instead of repairing it.
//!
//! Requires `SOLAND_TEST_DATABASE_URL` or `DATABASE_URL`; the lease gives each
//! case an isolated, freshly migrated database.

#[path = "../../test-support/src/device_authorization_history.rs"]
#[allow(dead_code)]
mod device_authorization_history;
#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;
#[path = "../../test-support/src/pcr_genesis.rs"]
#[allow(dead_code)]
mod pcr_genesis;

use arkret_models_collaboration::device_messages::RecipientDelivery;
use chrono::{Duration, Utc};
use diesel::sql_query;
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel_async::RunQueryDsl;
use soland_storage::contract_tests::test_device_message_envelope;
use soland_storage::{
    DeviceMessageBatchCommitOutcome, DeviceMessageBatchInspection, DeviceMessageBatchItemRecord,
    DeviceMessageBatchRecord, DeviceMessageIntentRecord, DeviceMessageRecord, DeviceMessageStore,
    DeviceRevocationGateSelector, PersistenceError, RecipientQueueSelector,
};
use soland_storage_postgres::test_database::TestDatabase;
use soland_storage_postgres::{Db, PgDeviceMessageStore, PgPool};

const STATION: &str = "ak:did_core:web:device-message-queue.example";

/// Two devices of one account, both accepted by the Station: the founding
/// device through the PCR genesis unit, the second through the registered
/// `accepted_device` unit on the founding device's approval.
async fn two_device_authorities(
    pool: &PgPool,
) -> (DeviceRevocationGateSelector, DeviceRevocationGateSelector) {
    let devices = two_device_history(pool).await;
    (devices.founding, devices.second)
}

/// The accepted history behind [`two_device_authorities`], with its founding
/// device key still available to author further Events.
struct TwoDeviceHistory {
    history: device_authorization_history::DeviceHistoryFixture,
    founding: DeviceRevocationGateSelector,
    second: DeviceRevocationGateSelector,
}

async fn two_device_history(pool: &PgPool) -> TwoDeviceHistory {
    let mut conn = pool.get().await.unwrap();
    sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
        .bind::<Text, _>(STATION)
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    let persistence = soland_storage_postgres::PgPersistenceStore::new(pool.clone());
    let mut fixture = pcr_genesis::PcrGenesisFixture::new(
        device_authorization_history::did_web_station(&STATION.parse().unwrap()),
    );
    let founding = fixture
        .admit_founding_device(&persistence)
        .await
        .expect("accepted PCR genesis");
    let second = fixture
        .admit_accepted_device(&persistence, [97; 32])
        .await
        .expect("accepted second device")
        .authorization;
    TwoDeviceHistory {
        history: fixture.history,
        founding,
        second,
    }
}

fn message(
    sender: &DeviceRevocationGateSelector,
    recipient: &DeviceRevocationGateSelector,
    envelope: arkret_models_collaboration::device_messages::DeviceMessageEnvelope,
) -> DeviceMessageRecord {
    DeviceMessageRecord {
        idempotency_key: format!("queue-{}", uuid::Uuid::now_v7()),
        sender: sender.principal_id.to_string(),
        recipient: recipient.principal_id.to_string(),
        device_id: recipient.device_id.clone(),
        recipient_device_authorization: recipient.clone(),
        position: 0,
        envelope,
    }
}

fn batch(namespace: &str, message: DeviceMessageRecord) -> DeviceMessageBatchRecord {
    let expires_at = Utc::now() + Duration::days(1);
    DeviceMessageBatchRecord {
        request_key: format!("request:{namespace}"),
        request_digest: format!("sha256:{namespace}"),
        idempotency_expires_at: expires_at,
        per_device_queue_capacity: 100,
        target_snapshot_guard: None,
        device_revocation_gate: None,
        sender_agent_guard: None,
        items: vec![DeviceMessageBatchItemRecord {
            message_key: format!("{namespace}:message"),
            intent_digest: format!("{namespace}:intent"),
            idempotency_expires_at: expires_at,
            message: Some(message),
        }],
    }
}

fn intents(batch: &DeviceMessageBatchRecord) -> Vec<DeviceMessageIntentRecord> {
    batch
        .items
        .iter()
        .map(|item| DeviceMessageIntentRecord {
            message_key: item.message_key.clone(),
            intent_digest: item.intent_digest.clone(),
        })
        .collect()
}

fn human(recipient: &DeviceRevocationGateSelector) -> RecipientQueueSelector {
    RecipientQueueSelector::HumanDevice {
        recipient: recipient.principal_id.to_string(),
        device_id: recipient.device_id.clone(),
    }
}

async fn queue_row_count(pool: &PgPool) -> i64 {
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = BigInt)]
        count: i64,
    }
    let mut conn = pool.get().await.unwrap();
    sql_query("SELECT COUNT(*) AS count FROM device_messages")
        .get_result::<Count>(&mut *conn)
        .await
        .unwrap()
        .count
}

/// A selector counts only as the Station accepted it. A genuinely signed
/// authorize Event the Station never committed, an older Commit of the same
/// PCR cited for the founding device, and the founding authorization claimed
/// at another Station are each refused by the queue's device gate and leave
/// no row; the Station's PCR status admits only the accepted device.
#[tokio::test]
async fn queue_refuses_device_authorizations_the_station_did_not_accept() {
    use arkret_models_collaboration::events_payloads::{
        DeviceAuthorizationBindingKind, DeviceOrPrincipalRef,
    };
    use soland_storage::DeviceRevocationStore;

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let mut conn = pool.get().await.unwrap();
    sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
        .bind::<Text, _>(STATION)
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    let mut fixture = pcr_genesis::PcrGenesisFixture::new(
        device_authorization_history::did_web_station(&STATION.parse().unwrap()),
    );
    let founding = fixture
        .admit_founding_device(&soland_storage_postgres::PgPersistenceStore::new(
            pool.clone(),
        ))
        .await
        .expect("accepted PCR genesis");

    let unaccepted_device =
        arkret_wire::DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
    let payload = device_authorization_history::possession_with(
        &fixture.history.account,
        device_authorization_history::DeviceAuthorizationSpec {
            device_id: unaccepted_device.clone(),
            signing_seed: [98; 32],
            hpke_seed: [99; 32],
            authorized_by: DeviceOrPrincipalRef::DeviceId(
                fixture.history.founding_device_id.clone(),
            ),
            not_before: fixture.history.events[1].created_at,
            expires_at: None,
            binding: DeviceAuthorizationBindingKind::AcceptedDevice,
            authorized_generation_ref: 1,
            applet_id: None,
        },
    );
    let authorize = fixture.history.event(
        arkret_wire::EventKind::DeviceAuthorize,
        serde_json::to_value(payload).unwrap(),
    );
    fixture.history.append(vec![authorize.clone()]);
    let uncommitted = fixture.history.commits.last().unwrap();
    let unaccepted = DeviceRevocationGateSelector {
        device_id: unaccepted_device.to_string(),
        authorization_ref: arkret_wire::CommittedEventRef {
            event_id: authorize.event_id.clone(),
            commit_id: uncommitted.commit_id.clone(),
            stream_ref: uncommitted.stream_ref.clone(),
            stream_position: uncommitted.stream_position,
        },
        ..founding.clone()
    };
    let create = &fixture.history.commits[0];
    let superseded = DeviceRevocationGateSelector {
        authorization_ref: arkret_wire::CommittedEventRef {
            event_id: create.event_ref.clone(),
            commit_id: create.commit_id.clone(),
            stream_ref: create.stream_ref.clone(),
            stream_position: create.stream_position,
        },
        ..founding.clone()
    };
    let foreign = DeviceRevocationGateSelector {
        station_id: "ak:did_core:web:foreign-station.example".parse().unwrap(),
        ..founding.clone()
    };

    // The Station's PCR status admits the founding device only.
    let status = soland_storage_postgres::PgDeviceRevocationStore { pool: pool.clone() };
    let account = fixture.history.account.clone();
    let at = Utc::now();
    assert_eq!(
        status
            .pcr_device_admission(&account, &fixture.history.founding_device_id, at)
            .await
            .unwrap(),
        arkret_wire::DeviceRevocationAdmissionDecision::Allow
    );
    let unaccepted_status = status
        .pcr_device_admission(&account, &unaccepted_device, at)
        .await;
    assert!(
        !matches!(
            unaccepted_status,
            Ok(arkret_wire::DeviceRevocationAdmissionDecision::Allow)
        ),
        "a device without an accepted authorization is not admitted: {unaccepted_status:?}"
    );

    let store = PgDeviceMessageStore { pool: pool.clone() };
    for (label, recipient) in [
        ("unaccepted", &unaccepted),
        ("superseded", &superseded),
        ("foreign", &foreign),
    ] {
        let envelope = test_device_message_envelope(&founding, recipient, Utc::now());
        let outcome = store
            .commit_batch(batch(label, message(&founding, recipient, envelope)))
            .await;
        assert!(
            !matches!(outcome, Ok(DeviceMessageBatchCommitOutcome::Stored(_))),
            "{label} recipient authorization must not be queued: {outcome:?}"
        );
    }
    assert_eq!(queue_row_count(&pool).await, 0);

    // The accepted selector itself is queued: the refusals above are the
    // gate's, not a broken fixture's.
    let envelope = test_device_message_envelope(&founding, &founding, Utc::now());
    assert!(matches!(
        store
            .commit_batch(batch("accepted", message(&founding, &founding, envelope)))
            .await
            .unwrap(),
        DeviceMessageBatchCommitOutcome::Stored(_)
    ));
    assert_eq!(queue_row_count(&pool).await, 1);
}

#[tokio::test]
async fn postgres_device_message_queue_round_trips_closed_envelope_across_restart() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let (device_a, device_b) = two_device_authorities(&pool).await;
    let store = PgDeviceMessageStore { pool: pool.clone() };

    let envelope = test_device_message_envelope(&device_a, &device_b, Utc::now());
    let expected = serde_json::to_value(&envelope).unwrap();
    let batch = batch("round-trip", message(&device_a, &device_b, envelope));
    assert!(matches!(
        store.commit_batch(batch.clone()).await.unwrap(),
        DeviceMessageBatchCommitOutcome::Stored(_)
    ));

    // A fresh pool behaves like a restarted process attaching to the same
    // database: both queue readers decode the identical closed envelope.
    drop(store);
    drop(pool);
    let restarted = Db::connect(Some(database.url()), Default::default())
        .await
        .unwrap()
        .pool
        .unwrap();
    let store = PgDeviceMessageStore {
        pool: restarted.clone(),
    };
    let listed = store
        .list_after(
            &device_b.principal_id.to_string(),
            &device_b.device_id,
            0,
            10,
        )
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(serde_json::to_value(&listed[0].envelope).unwrap(), expected);
    let deliveries = store
        .list_recipient_deliveries(&human(&device_b), 0, 10)
        .await
        .unwrap();
    assert_eq!(deliveries.len(), 1);
    let RecipientDelivery::DeviceMessage { device_message } = &deliveries[0].delivery else {
        panic!("human queue served a non-DeviceMessage delivery");
    };
    assert_eq!(serde_json::to_value(device_message).unwrap(), expected);
    assert!(
        store
            .list_recipient_deliveries(&human(&device_a), 0, 10)
            .await
            .unwrap()
            .is_empty(),
        "another device of the same account sees nothing"
    );
    assert!(matches!(
        store.commit_batch(batch).await.unwrap(),
        DeviceMessageBatchCommitOutcome::Duplicate(_)
    ));
    assert_eq!(queue_row_count(&restarted).await, 1);
}

#[tokio::test]
async fn postgres_device_message_queue_rejects_unbound_envelopes_with_zero_writes() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let (device_a, device_b) = two_device_authorities(&pool).await;
    let store = PgDeviceMessageStore { pool: pool.clone() };

    // Envelope addressed to device A stored under device B's queue row.
    let misaddressed = batch(
        "misaddressed",
        message(
            &device_a,
            &device_b,
            test_device_message_envelope(&device_a, &device_a, Utc::now()),
        ),
    );
    // sent_at that is not the canonical millisecond wire value.
    let mut sub_millisecond = test_device_message_envelope(&device_a, &device_b, Utc::now());
    sub_millisecond.sent_at += Duration::microseconds(1);
    let sub_millisecond = batch(
        "sub-millisecond",
        message(&device_a, &device_b, sub_millisecond),
    );
    for rejected in [misaddressed, sub_millisecond] {
        let error = store.commit_batch(rejected.clone()).await.unwrap_err();
        assert!(
            matches!(error, PersistenceError::SchemaViolation(_)),
            "unexpected error {error:?}"
        );
        assert!(matches!(
            store
                .inspect_batch(
                    &rejected.request_key,
                    &rejected.request_digest,
                    &intents(&rejected)
                )
                .await
                .unwrap(),
            DeviceMessageBatchInspection::Fresh { .. }
        ));
    }
    let append_error = store
        .append(
            None,
            message(
                &device_a,
                &device_b,
                test_device_message_envelope(&device_a, &device_a, Utc::now()),
            ),
            100,
        )
        .await
        .unwrap_err();
    assert!(matches!(append_error, PersistenceError::SchemaViolation(_)));
    assert_eq!(queue_row_count(&pool).await, 0);
}

#[tokio::test]
async fn postgres_device_message_queue_fails_closed_on_target_shaped_row() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let (device_a, device_b) = two_device_authorities(&pool).await;
    let store = PgDeviceMessageStore { pool: pool.clone() };

    // The pre-fix send path persisted the request target plus a sender branch,
    // without recipient_account_id / recipient_device_id / sent_at. Such a row
    // must never be repaired into an envelope while serving reads.
    let envelope = test_device_message_envelope(&device_a, &device_b, Utc::now());
    let mut target_shaped = serde_json::to_value(&envelope).unwrap();
    let object = target_shaped.as_object_mut().unwrap();
    for member in ["recipient_account_id", "recipient_device_id", "sent_at"] {
        object.remove(member);
    }
    let mut conn = pool.get().await.unwrap();
    sql_query(
        "INSERT INTO device_messages \
         (id, idempotency_key, sender, recipient, device_id, position, content, created_at, \
          recipient_device_authorization) \
         VALUES ($1, 'target-shaped', $2, $3, $4, nextval('public.recipient_delivery_position_seq'), \
                 $5, $6, $7)",
    )
    .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::new_v4())
    .bind::<Text, _>(device_a.principal_id.as_str())
    .bind::<Text, _>(device_b.principal_id.as_str())
    .bind::<Text, _>(&device_b.device_id)
    .bind::<Jsonb, _>(&target_shaped)
    .bind::<diesel::sql_types::Timestamptz, _>(envelope.sent_at)
    .bind::<Jsonb, _>(serde_json::to_value(&device_b).unwrap())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);

    assert!(
        store
            .list_recipient_deliveries(&human(&device_b), 0, 10)
            .await
            .is_err()
    );
    assert!(matches!(
        store
            .list_after(
                &device_b.principal_id.to_string(),
                &device_b.device_id,
                0,
                10
            )
            .await
            .unwrap_err(),
        PersistenceError::SchemaViolation(_)
    ));
}

/// An Agent-sent batch rechecks the sending endpoint's committed key
/// authorization in the queue transaction: an authorization that is not the
/// Agent's committed, single active current key refuses the whole batch and
/// writes neither ledger nor queue rows.
#[tokio::test]
async fn postgres_agent_sender_without_current_authorization_writes_nothing() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let (device_a, device_b) = two_device_authorities(&pool).await;
    let store = PgDeviceMessageStore { pool: pool.clone() };

    let agent_id = arkret_wire::DidCoreId::new("ak:did_core:web:queue-agent.example").unwrap();
    let verification_method =
        arkret_wire::DidUrl::new("did:web:queue-agent.example#agent").unwrap();
    let authorization_ref = device_a.authorization_ref.clone();
    let mut envelope = test_device_message_envelope(&device_a, &device_b, Utc::now());
    envelope.sender = arkret_models_collaboration::device_messages::DeviceMessageSender::Agent {
        sender_agent_id: agent_id.clone(),
        sender_agent_verification_method: verification_method.clone(),
        sender_agent_key_authorize_event_id: authorization_ref.event_id.clone(),
    };
    let mut refused = batch("agent-sender", message(&device_a, &device_b, envelope));
    refused.sender_agent_guard = Some(soland_storage::AgentEndpointGuard {
        pcr_realm_id: authorization_ref.stream_ref.realm_id().clone(),
        agent_id,
        authorization_ref,
        verification_method,
    });
    assert!(matches!(
        store.commit_batch(refused.clone()).await.unwrap(),
        DeviceMessageBatchCommitOutcome::SenderAgentUnauthorized
    ));
    assert_eq!(queue_row_count(&pool).await, 0);
    assert!(matches!(
        store
            .inspect_batch(
                &refused.request_key,
                &refused.request_digest,
                &intents(&refused)
            )
            .await
            .unwrap(),
        DeviceMessageBatchInspection::Fresh { .. }
    ));
}

const AGENT_DID: &str = "did:web:queue-agent.example";
const STATION_AUTHORITY_SEED: [u8; 32] = [90; 32];
const AGENT_RUNTIME_SEED: [u8; 32] = [91; 32];

/// An Agent whose PCR genesis and `ak.agent.key.authorize` are signed by the
/// controller's accepted device and admitted through the Station's atomic
/// Event committer. That committer signs each `RealmCommit` and projects the
/// `agent_status` / `agent_key` current results in the same transaction, so
/// the queue's endpoint recheck reads exactly what a production commit wrote.
struct CommittedAgent {
    authority: soland_services::authority_commit::AuthorityCommitApplication,
    store: soland_storage_postgres::PgAuthorityCommitStore,
    controller: device_authorization_history::DeviceHistoryFixture,
    station: arkret_wire::DidCoreId,
    agent_account: arkret_wire::AccountId,
    pcr_realm_id: arkret_wire::RealmId,
    verification_method: arkret_wire::DidUrl,
    key_id: arkret_wire::NonEmptyString,
    authorization_ref: arkret_wire::CommittedEventRef,
}

impl CommittedAgent {
    async fn provision(pool: &PgPool) -> (Self, DeviceRevocationGateSelector) {
        use arkret_models_collaboration::events_payloads::agent::{
            AgentKeyApprovalEvidence, AgentKeyApprovalEvidenceKind, AgentKeyAuthorizePayload,
        };
        use soland_storage::ActorProfileStore as _;

        let TwoDeviceHistory {
            history: controller,
            second: recipient,
            ..
        } = two_device_history(pool).await;
        let authority = soland_services::authority_commit::AuthorityCommitApplication::new(
            soland_services::persistence::PersistenceHandle::new(std::sync::Arc::new(
                soland_storage_postgres::PgPersistenceStore::new(pool.clone()),
            )),
            100,
        );
        let store = soland_storage_postgres::PgAuthorityCommitStore { pool: pool.clone() };
        let station: arkret_wire::DidCoreId = STATION.parse().unwrap();
        let agent_did = arkret_wire::Did::new(AGENT_DID).unwrap();
        let agent_id = arkret_wire::project_did_to_core_id(&agent_did).unwrap();
        let agent_account = arkret_wire::AccountId::new(agent_id.clone(), station.clone());
        let at = chrono::DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap();
        let create = arkret_bootstrap::build_agent_pcr_create_payload(
            arkret_bootstrap::AgentPcrCreatePayloadInput {
                agent_id: agent_id.clone(),
                governance_station_id: station.clone(),
                initial_resolution: arkret_models_identity::ResolutionCommitment {
                    did: agent_did,
                    method_history_head: format!("sha256:{}", "8".repeat(64)),
                    version_id: "1-QmQueueAgent".to_owned(),
                },
                genesis_salt: arkret_wire::GenesisSalt::new(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                )
                .unwrap(),
                trust_domain: arkret_wire::TrustDomainId::new("ak:trust_domain:example.net")
                    .unwrap(),
                initial_join_rule: arkret_wire::JoinRule::Closed,
                initial_history_access: arkret_wire::HistoryAccess::SinceJoin,
                initial_discoverability: arkret_wire::Discoverability::Secret,
            },
        )
        .unwrap();
        let genesis = controller_signed(
            &controller,
            &agent_account,
            arkret_wire::EventKind::RealmCreate,
            arkret_wire::ScopeRef::RealmGenesis,
            serde_json::to_value(&create).unwrap(),
            at,
        );
        let pcr_realm_id = genesis.realm_id.clone();
        // The controller provisions the Agent in its own PCR, forward-declaring
        // the genesis it froze; the genesis is then its own submission.
        let provision = device_authorization_history::sign_event(
            arkret_wire::test_support::raw_event_at(
                arkret_wire::EventKind::AgentProvision.as_str(),
                arkret_wire::ScopeRef::Realm {
                    realm_id: controller.events[0].realm_id.clone(),
                },
                controller.account.principal_id.clone(),
                controller.account.station_id.clone(),
                serde_json::json!({
                    "schema": "ak.schema.agent_provision.v1",
                    "agent_id": agent_id,
                    "controller_principal_id": controller.account.principal_id,
                    "principal_control_realm_id": pcr_realm_id,
                    "controller_authorization_ref": format!("{AGENT_DID}#managed-controller"),
                    "agent_slug": "queue-agent",
                    "accountability_scope": "agent_operator",
                    "requested_scope_digest": format!("sha256:{}", "9".repeat(64)),
                    "selector_visibility": "private",
                    "created_at": arkret_canonical::format_timestamp_canonical(at)
                }),
                at,
            )
            .unwrap(),
            controller.device_verification_method.clone(),
            controller.founding_device_signing_seed,
        );
        let profiles = soland_storage_postgres::PgActorProfileStore { pool: pool.clone() };
        let committed_at = Utc::now();
        profiles
            .admit_agent_provision(soland_storage::AgentProvisionAdmissionWrite {
                commit: authority
                    .prepare_self_event_transaction(
                        &provision,
                        &station,
                        station_method(&station),
                        &ed25519_dalek::SigningKey::from_bytes(&STATION_AUTHORITY_SEED),
                        committed_at,
                    )
                    .await
                    .unwrap(),
                queued_at: committed_at,
            })
            .await
            .unwrap();
        let committed_at = Utc::now();
        profiles
            .admit_agent_pcr_genesis(soland_storage::AgentPcrGenesisAdmissionWrite {
                commit: authority
                    .prepare_genesis_transaction(
                        &genesis,
                        &station,
                        station_method(&station),
                        &ed25519_dalek::SigningKey::from_bytes(&STATION_AUTHORITY_SEED),
                        committed_at,
                    )
                    .unwrap(),
                queued_at: committed_at,
            })
            .await
            .unwrap();

        let runtime = ed25519_dalek::SigningKey::from_bytes(&AGENT_RUNTIME_SEED);
        let verification_method =
            arkret_wire::DidUrl::new(format!("{AGENT_DID}#agent-runtime")).unwrap();
        let key_id = arkret_wire::NonEmptyString::new(verification_method.as_str()).unwrap();
        let send = arkret_wire::ServiceOperationId::SELF_DEVICE_MESSAGES_COMMAND_SEND_V1;
        let payload = AgentKeyAuthorizePayload {
            agent_id,
            key_id: key_id.clone(),
            verification_method: verification_method.clone(),
            public_key: arkret_models_collaboration::governance::agent_artifacts::PublicKey {
                kty: arkret_wire::NonEmptyString::new("OKP").unwrap(),
                kid: key_id.clone(),
                algorithm: arkret_wire::NonEmptyString::new("Ed25519").unwrap(),
                key: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                    runtime.verifying_key().as_bytes(),
                ))
                .unwrap(),
                key_digest: None,
            },
            accountable_principal_id: controller.account.principal_id.clone(),
            agent_key_scope: serde_json::from_value(serde_json::json!({
                "actions": [send],
                "resources": [{"kind": "operation", "operation": send}],
            }))
            .unwrap(),
            audience: vec![station.to_string()],
            issued_at: at,
            expires_at: None,
            approval_evidence: AgentKeyApprovalEvidence {
                kind: AgentKeyApprovalEvidenceKind::PairingRequest,
                evidence_ref: None,
                request_canonical_digest: Some(
                    arkret_wire::Hash::new(arkret_canonical::sha256_digest(
                        b"queue-agent-pairing-request",
                    ))
                    .unwrap(),
                ),
                pairing_request_id: Some(
                    arkret_wire::OpaqueLocalId::new(format!(
                        "agent_pairing_request:{}",
                        uuid::Uuid::now_v7()
                    ))
                    .unwrap(),
                ),
                approved_by: Some(controller.account.principal_id.clone()),
            },
            supersedes: Vec::new(),
            revocation_check_ref: None,
            runtime_attestation: None,
        };
        let authorize = controller_signed(
            &controller,
            &agent_account,
            arkret_wire::EventKind::AgentKeyAuthorize,
            arkret_wire::ScopeRef::Realm {
                realm_id: pcr_realm_id.clone(),
            },
            serde_json::to_value(&payload).unwrap(),
            at,
        );
        let commit = admit(&authority, &store, &station, &authorize).await;
        let authorization_ref = arkret_wire::CommittedEventRef {
            event_id: authorize.event_id.clone(),
            commit_id: commit.commit_id,
            stream_ref: commit.stream_ref,
            stream_position: commit.stream_position,
        };
        let agent = Self {
            authority,
            store,
            controller,
            station,
            agent_account,
            pcr_realm_id,
            verification_method,
            key_id,
            authorization_ref,
        };
        (agent, recipient)
    }

    fn sender(&self) -> arkret_models_collaboration::device_messages::DeviceMessageSender {
        arkret_models_collaboration::device_messages::DeviceMessageSender::Agent {
            sender_agent_id: self.agent_account.principal_id.clone(),
            sender_agent_verification_method: self.verification_method.clone(),
            sender_agent_key_authorize_event_id: self.authorization_ref.event_id.clone(),
        }
    }

    fn guard(&self) -> soland_storage::AgentEndpointGuard {
        soland_storage::AgentEndpointGuard {
            pcr_realm_id: self.pcr_realm_id.clone(),
            agent_id: self.agent_account.principal_id.clone(),
            authorization_ref: self.authorization_ref.clone(),
            verification_method: self.verification_method.clone(),
        }
    }

    /// One controller-executed Event in the Agent PCR, admitted at the head.
    async fn commit(&self, kind: arkret_wire::EventKind, payload: serde_json::Value) {
        let at = chrono::DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap();
        let event = controller_signed(
            &self.controller,
            &self.agent_account,
            kind,
            arkret_wire::ScopeRef::Realm {
                realm_id: self.pcr_realm_id.clone(),
            },
            payload,
            at,
        );
        admit(&self.authority, &self.store, &self.station, &event).await;
    }

    async fn revoke_key(&self) {
        let payload = arkret_models_collaboration::events_payloads::agent::AgentKeyRevokePayload {
            agent_id: self.agent_account.principal_id.clone(),
            key_id: self.key_id.clone(),
            revoked_by: self.controller.account.principal_id.clone(),
            revoked_at: chrono::DateTime::from_timestamp_millis(Utc::now().timestamp_millis())
                .unwrap(),
            reason: None,
        };
        self.commit(
            arkret_wire::EventKind::AgentKeyRevoke,
            serde_json::to_value(payload).unwrap(),
        )
        .await;
    }

    async fn pause(&self) {
        let payload = arkret_models_collaboration::events_payloads::agent::AgentPausePayload {
            transition: "pause".to_owned(),
            previous_status: "active".to_owned(),
            status_changed_at: chrono::DateTime::from_timestamp_millis(
                Utc::now().timestamp_millis(),
            )
            .unwrap(),
            reason: None,
        };
        self.commit(
            arkret_wire::EventKind::SelfAgentPause,
            serde_json::to_value(payload).unwrap(),
        )
        .await;
    }

    async fn status(&self) -> serde_json::Value {
        let result = self
            .authority
            .current_agent_result(
                &self.pcr_realm_id,
                &arkret_wire::CurrentSelector::AgentStatus {
                    agent_id: self.agent_account.principal_id.clone(),
                },
            )
            .await
            .unwrap()
            .expect("committed Agent PCR genesis projects agent_status");
        let arkret_wire::TypedCurrentResult::Value { value, .. } = result else {
            panic!("agent_status current result carries no value");
        };
        value
    }
}

/// A controller-executed Agent Event: the Agent account is the actor, the
/// controller account executes it under the managed-controller delegation,
/// and the controller's accepted device signs the producer proof.
fn controller_signed(
    controller: &device_authorization_history::DeviceHistoryFixture,
    agent_account: &arkret_wire::AccountId,
    kind: arkret_wire::EventKind,
    scope_ref: arkret_wire::ScopeRef,
    payload: serde_json::Value,
    at: chrono::DateTime<Utc>,
) -> arkret_wire::Event {
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        kind.as_str(),
        scope_ref,
        arkret_wire::ActorId::account(agent_account.clone()),
        payload,
        at,
    )
    .unwrap();
    event.executed_by = Some(arkret_wire::ActorId::account(controller.account.clone()));
    event.authorization_ref = Some(
        arkret_wire::DidUrl::new(format!("{AGENT_DID}#managed-controller"))
            .unwrap()
            .into(),
    );
    device_authorization_history::sign_event(
        event,
        controller.device_verification_method.clone(),
        controller.founding_device_signing_seed,
    )
}

fn station_method(station: &arkret_wire::DidCoreId) -> arkret_wire::DidUrl {
    arkret_wire::DidUrl::new(format!(
        "{}#authority",
        device_authorization_history::did_web_station(station)
    ))
    .unwrap()
}

/// Commit one Agent PCR control Event at the stream head through the
/// Station's Agent control unit with a Station-signed `RealmCommit`.
async fn admit(
    authority: &soland_services::authority_commit::AuthorityCommitApplication,
    store: &soland_storage_postgres::PgAuthorityCommitStore,
    station: &arkret_wire::DidCoreId,
    event: &arkret_wire::Event,
) -> arkret_wire::RealmCommit {
    use soland_storage::ActorProfileStore as _;

    let committed_at = Utc::now();
    let transaction = authority
        .prepare_self_event_transaction(
            event,
            station,
            station_method(station),
            &ed25519_dalek::SigningKey::from_bytes(&STATION_AUTHORITY_SEED),
            committed_at,
        )
        .await
        .unwrap();
    let outcome = soland_storage_postgres::PgActorProfileStore {
        pool: store.pool.clone(),
    }
    .admit_agent_control_event(soland_storage::AgentControlAdmissionWrite {
        commit: transaction,
        queued_at: committed_at,
    })
    .await
    .unwrap();
    let soland_storage::AgentControlAdmissionOutcome::Committed(commit) = outcome else {
        panic!("the governing Station commits the Agent Event");
    };
    commit
}

/// An Agent-sent envelope for `recipient` and its batch, keyed exactly like
/// the send surface: the message identity is `(sender_agent_id,
/// device_message_id)` and the intent digest covers every sender-chosen member.
fn agent_batch(
    agent: &CommittedAgent,
    request: &str,
    recipient: &DeviceRevocationGateSelector,
    envelope: arkret_models_collaboration::device_messages::DeviceMessageEnvelope,
) -> DeviceMessageBatchRecord {
    let expires_at = Utc::now() + Duration::days(1);
    let message_key = arkret_canonical::canonical_sha256(&serde_json::json!({
        "sender_agent_id": agent.agent_account.principal_id,
        "device_message_id": envelope.device_message_id,
    }))
    .unwrap();
    let mut intent = serde_json::to_value(&envelope).unwrap();
    intent.as_object_mut().unwrap().remove("sent_at");
    let intent_digest = arkret_canonical::canonical_sha256(&intent).unwrap();
    DeviceMessageBatchRecord {
        request_key: format!("request:{request}"),
        request_digest: arkret_canonical::canonical_sha256(&serde_json::json!([
            request,
            intent_digest
        ]))
        .unwrap(),
        idempotency_expires_at: expires_at,
        per_device_queue_capacity: 100,
        target_snapshot_guard: None,
        device_revocation_gate: None,
        sender_agent_guard: Some(agent.guard()),
        items: vec![DeviceMessageBatchItemRecord {
            message_key,
            intent_digest,
            idempotency_expires_at: expires_at,
            message: Some(DeviceMessageRecord {
                idempotency_key: format!("queue-{request}"),
                sender: agent.agent_account.principal_id.to_string(),
                recipient: recipient.principal_id.to_string(),
                device_id: recipient.device_id.clone(),
                recipient_device_authorization: recipient.clone(),
                position: 0,
                envelope,
            }),
        }],
    }
}

fn agent_envelope(
    agent: &CommittedAgent,
    recipient: &DeviceRevocationGateSelector,
) -> arkret_models_collaboration::device_messages::DeviceMessageEnvelope {
    let mut envelope = test_device_message_envelope(recipient, recipient, Utc::now());
    envelope.sender = agent.sender();
    envelope
}

/// The success path of an Agent sender whose key authorization is the
/// committed, single active current key of an active Agent: the envelope is
/// queued once, an exact replay returns the stored outcome, another request
/// for the same `(sender_agent_id, device_message_id)` neither re-queues nor
/// may change its intent, and a restarted process serves the same envelope.
#[tokio::test]
async fn postgres_agent_sender_with_committed_key_authorization_enqueues_idempotently() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let (agent, recipient) = CommittedAgent::provision(&pool).await;
    assert_eq!(agent.status().await, serde_json::json!("active"));
    let store = PgDeviceMessageStore { pool: pool.clone() };

    let envelope = agent_envelope(&agent, &recipient);
    let expected = serde_json::to_value(&envelope).unwrap();
    let sent = agent_batch(&agent, "agent-first", &recipient, envelope.clone());
    let message_key = sent.items[0].message_key.clone();
    let DeviceMessageBatchCommitOutcome::Stored(outcomes) =
        store.commit_batch(sent.clone()).await.unwrap()
    else {
        panic!("a current Agent endpoint enqueues its envelope");
    };
    assert_eq!(outcomes.get(&message_key), Some(&true));
    assert_eq!(queue_row_count(&pool).await, 1);

    // Exact replay of the same request returns the recorded outcome.
    let DeviceMessageBatchCommitOutcome::Duplicate(replayed) =
        store.commit_batch(sent.clone()).await.unwrap()
    else {
        panic!("an exact replay is a duplicate");
    };
    assert_eq!(replayed, outcomes);

    // A different request carrying the same logical message is absorbed by
    // the message ledger instead of queueing a second copy.
    let retried = agent_batch(&agent, "agent-retry", &recipient, envelope.clone());
    assert_eq!(retried.items[0].message_key, message_key);
    let DeviceMessageBatchCommitOutcome::Stored(retried_outcomes) =
        store.commit_batch(retried).await.unwrap()
    else {
        panic!("a retried logical message resolves to its recorded outcome");
    };
    assert_eq!(retried_outcomes.get(&message_key), Some(&true));
    assert_eq!(queue_row_count(&pool).await, 1);

    // The same identity with another intent conflicts and writes nothing.
    let mut altered = envelope.clone();
    altered.kind = arkret_wire::ProtocolKind::new("ak.test.device_message_altered").unwrap();
    let conflicting = agent_batch(&agent, "agent-altered", &recipient, altered);
    assert_eq!(conflicting.items[0].message_key, message_key);
    assert!(matches!(
        store.commit_batch(conflicting.clone()).await.unwrap(),
        DeviceMessageBatchCommitOutcome::MessageConflict { .. }
    ));
    assert!(matches!(
        store
            .inspect_batch(
                &conflicting.request_key,
                &conflicting.request_digest,
                &intents(&conflicting)
            )
            .await
            .unwrap(),
        DeviceMessageBatchInspection::MessageConflict { .. }
    ));
    assert_eq!(queue_row_count(&pool).await, 1);

    drop(store);
    drop(pool);
    let restarted = Db::connect(Some(database.url()), Default::default())
        .await
        .unwrap()
        .pool
        .unwrap();
    let store = PgDeviceMessageStore {
        pool: restarted.clone(),
    };
    let deliveries = store
        .list_recipient_deliveries(&human(&recipient), 0, 10)
        .await
        .unwrap();
    assert_eq!(deliveries.len(), 1);
    let RecipientDelivery::DeviceMessage { device_message } = &deliveries[0].delivery else {
        panic!("human queue served a non-DeviceMessage delivery");
    };
    assert_eq!(serde_json::to_value(device_message).unwrap(), expected);
    assert!(matches!(
        store.commit_batch(sent).await.unwrap(),
        DeviceMessageBatchCommitOutcome::Duplicate(_)
    ));
    assert_eq!(queue_row_count(&restarted).await, 1);
}

/// A committed `ak.agent.key.revoke` removes the only active authorization:
/// the endpoint that just sent successfully is refused in the queue
/// transaction and the refused batch writes neither ledger nor queue rows.
#[tokio::test]
async fn postgres_agent_sender_after_committed_key_revoke_writes_nothing() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let (agent, recipient) = CommittedAgent::provision(&pool).await;
    let store = PgDeviceMessageStore { pool: pool.clone() };
    let before = agent_batch(
        &agent,
        "before-revoke",
        &recipient,
        agent_envelope(&agent, &recipient),
    );
    assert!(matches!(
        store.commit_batch(before).await.unwrap(),
        DeviceMessageBatchCommitOutcome::Stored(_)
    ));

    agent.revoke_key().await;
    let refused = agent_batch(
        &agent,
        "after-revoke",
        &recipient,
        agent_envelope(&agent, &recipient),
    );
    assert!(matches!(
        store.commit_batch(refused.clone()).await.unwrap(),
        DeviceMessageBatchCommitOutcome::SenderAgentUnauthorized
    ));
    assert_eq!(queue_row_count(&pool).await, 1);
    assert!(matches!(
        store
            .inspect_batch(
                &refused.request_key,
                &refused.request_digest,
                &intents(&refused)
            )
            .await
            .unwrap(),
        DeviceMessageBatchInspection::Fresh { .. }
    ));
}

/// A committed Agent pause leaves the key authorization in place but the
/// Agent is no longer active, so its endpoint is refused with zero writes.
#[tokio::test]
async fn postgres_paused_agent_sender_writes_nothing() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let (agent, recipient) = CommittedAgent::provision(&pool).await;
    let store = PgDeviceMessageStore { pool: pool.clone() };
    let before = agent_batch(
        &agent,
        "before-pause",
        &recipient,
        agent_envelope(&agent, &recipient),
    );
    assert!(matches!(
        store.commit_batch(before).await.unwrap(),
        DeviceMessageBatchCommitOutcome::Stored(_)
    ));

    agent.pause().await;
    assert_eq!(agent.status().await, serde_json::json!("paused"));
    let refused = agent_batch(
        &agent,
        "after-pause",
        &recipient,
        agent_envelope(&agent, &recipient),
    );
    assert!(matches!(
        store.commit_batch(refused.clone()).await.unwrap(),
        DeviceMessageBatchCommitOutcome::SenderAgentUnauthorized
    ));
    assert_eq!(queue_row_count(&pool).await, 1);
    assert!(matches!(
        store
            .inspect_batch(
                &refused.request_key,
                &refused.request_digest,
                &intents(&refused)
            )
            .await
            .unwrap(),
        DeviceMessageBatchInspection::Fresh { .. }
    ));
}

/// The Agent's current key and the MLS group are read at the same accepting
/// cut. Revocation wins over a stale ciphertext epoch and both refuse writes.
#[tokio::test]
async fn postgres_agent_message_send_gate_checks_epoch_and_current_key() {
    use soland_storage::{
        AuthorityCommitStore as _, EventCommitUnitOfWork as _, MlsGroupCurrentStore as _,
    };

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let (agent, _recipient) = CommittedAgent::provision(&pool).await;
    let discussion = ordinary_realm::open_discussion(&pool, "agent-send-gate").await;
    let realm_id = discussion.realm_id();
    let scope = arkret_wire::ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let at = discussion.committed_at();
    let uow = soland_storage_postgres::PgEventCommitUnitOfWork::new(pool.clone());
    // Seed only the prerequisite member current for this send-gate test.
    // Agent controller-binding admission is a separate production cut.
    let mut conn = pool.get().await.unwrap();
    sql_query(
        "INSERT INTO member_state_current_results \
         (realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,'join',$3,$4,$5,NOW())",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(arkret_wire::ActorId::account(agent.agent_account.clone()).to_string())
    .bind::<Text, _>(discussion.head.authority_commit.commit.commit_id.as_str())
    .bind::<BigInt, _>(discussion.head.authority_commit.commit.stream_position as i64)
    .bind::<Jsonb, _>(serde_json::json!({"membership":"join"}))
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    let mut genesis = ordinary_realm::next_request(
        &discussion.head.authority_commit,
        arkret_wire::EventKind::MlsGenesis,
        &ordinary_realm::founder(),
        serde_json::json!({
            "cipher_suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            "group_info_ref": format!("ak:blob:sha256:{}", "3".repeat(64)),
            "ratchet_tree_ref": format!("ak:blob:sha256:{}", "4".repeat(64)),
            "governance_binding": arkret_models_crypto::MlsGovernanceBindingPayload::realm(
                realm_id.clone(),
                None,
                0,
                0,
                0,
            )
            .unwrap(),
            "created_at": arkret_canonical::format_timestamp_canonical(at),
        }),
        at,
    );
    genesis.authority_commit.mls_state = Some(soland_storage::MlsStateInstallation {
        effective_scope: scope.clone(),
        base: None,
        epoch: 0,
        public_state: b"public-state-0".to_vec(),
        member_principals: Default::default(),
        consumed_proposals: Vec::new(),
        genesis_blobs: Vec::new(),
    });
    genesis.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        genesis.authority_commit.event.clone(),
    ));
    uow.commit_event(genesis.clone()).await.unwrap();
    // Seed the independently governed capability prerequisite so this case
    // exercises Message admission and its MLS cut rather than grant issuance.
    let grant_id = "ak:grant:AcFfzgdHkT6eFkto1gjLaKniVuMXx9sD0GKQwk8BXykz";
    let root = serde_json::json!({
        "kind": "realm_root",
        "realm_id": realm_id,
        "authority_event_ref": discussion.unit.transactions[0].event.event_id,
        "authority_generation": 0,
    });
    let grant = serde_json::json!({
        "id": grant_id,
        "schema": "ak.schema.capability.v1",
        "realm_id": realm_id,
        "issuer_id": discussion.unit.transactions[0].event.actor_id,
        "subject": arkret_wire::ActorId::account(agent.agent_account.clone()),
        "actions": ["ak.message.create"],
        "resources": [{"kind":"realm", "realm_id":realm_id}],
        "issuer_authority_refs": [root.clone()],
        "authority_depth": 1,
        "authority_root_refs": [root],
        "issued_at": arkret_canonical::format_timestamp_canonical(at),
        "status": "active",
    });
    let mut conn = pool.get().await.unwrap();
    sql_query(
        "INSERT INTO capability_grant_current_results \
         (realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,current_stream_position,value,updated_at) \
         VALUES($1,$2,'active',$3,$4,$5,$6,$7,NOW())",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(grant_id)
    .bind::<Text, _>(
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x44; 32])
            .to_string(),
    )
    .bind::<Text, _>(genesis.authority_commit.commit.commit_id.as_str())
    .bind::<Jsonb, _>(serde_json::json!({"kind":"realm", "realm_id": realm_id}))
    .bind::<BigInt, _>(genesis.authority_commit.commit.stream_position as i64)
    .bind::<Jsonb, _>(grant)
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    let groups = soland_storage_postgres::PgMlsGroupCurrentStore { pool: pool.clone() };
    let before = groups.current(&scope).await.unwrap().unwrap();

    // The Agent's ciphertext is frozen at an epoch the scope never had.
    let mut request = ordinary_realm::next_request_for_actor(
        &genesis.authority_commit,
        arkret_wire::EventKind::MessageCreate,
        arkret_wire::ActorId::account(agent.agent_account.clone()),
        serde_json::json!({
            "strand_id": discussion.strand_id,
            "track_name": "discussion",
            "encrypted_content": arkret_models_crypto::EncryptedEnvelope {
                version: "1.0".to_owned(),
                content_type: "application/vnd.arkret.message+json".to_owned(),
                encryption_context:
                    arkret_models_crypto::EncryptedEnvelopeEncryptionContext::standard(
                        7,
                        genesis.authority_commit.event.event_id.clone(),
                    ),
                ciphertext: "Y2lwaGVydGV4dA".to_owned(),
            },
        }),
        at,
    );
    let event = &mut request.authority_commit.event;
    event.producer_proof.as_mut().unwrap().verification_method = agent.verification_method.clone();
    request.event.envelope = serde_json::to_value(&*event).unwrap();
    request.self_producer_guard = Some(soland_storage::SelfProducerCommitGuard::Agent {
        pcr_realm_id: agent.pcr_realm_id.clone(),
        agent_id: agent.agent_account.principal_id.clone(),
        authorization_ref: agent.authorization_ref.clone(),
        verification_method: agent.verification_method.clone(),
    });
    request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        request.authority_commit.event.clone(),
    ));

    let current = uow.commit_event(request.clone()).await.unwrap_err();
    assert_eq!(
        current.conflict_code(),
        Some(soland_storage::ConflictCode::EpochMismatch),
        "{current}"
    );

    let mut accepted = ordinary_realm::next_request_for_actor(
        &genesis.authority_commit,
        arkret_wire::EventKind::MessageCreate,
        arkret_wire::ActorId::account(agent.agent_account.clone()),
        serde_json::json!({
            "strand_id": discussion.strand_id,
            "track_name": "discussion",
            "encrypted_content": arkret_models_crypto::EncryptedEnvelope {
                version: "1.0".to_owned(),
                content_type: "application/vnd.arkret.message+json".to_owned(),
                encryption_context:
                    arkret_models_crypto::EncryptedEnvelopeEncryptionContext::standard(
                        0,
                        genesis.authority_commit.event.event_id.clone(),
                    ),
                ciphertext: "Y2lwaGVydGV4dA".to_owned(),
            },
        }),
        at,
    );
    let accepted_event = &mut accepted.authority_commit.event;
    accepted_event
        .producer_proof
        .as_mut()
        .unwrap()
        .verification_method = agent.verification_method.clone();
    accepted.event.envelope = serde_json::to_value(&*accepted_event).unwrap();
    accepted.self_producer_guard = request.self_producer_guard.clone();
    accepted.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        accepted.authority_commit.event.clone(),
    ));
    uow.commit_event(accepted.clone()).await.unwrap();
    assert!(
        soland_storage_postgres::PgAuthorityCommitStore { pool: pool.clone() }
            .committed_event(&accepted.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_some()
    );

    agent.revoke_key().await;
    let revoked = uow.commit_event(request.clone()).await.unwrap_err();
    assert_eq!(
        revoked.conflict_code(),
        Some(soland_storage::ConflictCode::CapabilityDenied),
        "{revoked}"
    );
    assert!(
        soland_storage_postgres::PgAuthorityCommitStore { pool: pool.clone() }
            .committed_event(&request.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(groups.current(&scope).await.unwrap().unwrap(), before);
}
