//! Real PostgreSQL proof that the human DeviceMessage queue persists exactly
//! the closed `DeviceMessageEnvelope` it serves, and fails closed on any other
//! stored shape instead of repairing it.
//!
//! Requires `SOLAND_TEST_DATABASE_URL` or `DATABASE_URL`; the lease gives each
//! case an isolated, freshly migrated database.

#[path = "../../test-support/src/device_authorization_history.rs"]
mod device_history_fixture;

use arkret_models_collaboration::device_messages::RecipientDelivery;
use chrono::{Duration, Utc};
use diesel::sql_query;
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel_async::RunQueryDsl;
use soland_storage::contract_tests::test_device_message_envelope;
use soland_storage::{
    DeviceInventoryStore, DeviceMessageBatchCommitOutcome, DeviceMessageBatchInspection,
    DeviceMessageBatchItemRecord, DeviceMessageBatchRecord, DeviceMessageIntentRecord,
    DeviceMessageRecord, DeviceMessageStore, DeviceRevocationGateSelector, PersistenceError,
    RecipientQueueSelector,
};
use soland_storage_postgres::test_database::TestDatabase;
use soland_storage_postgres::{Db, PgDeviceInventoryStore, PgDeviceMessageStore, PgPool};

const STATION: &str = "ak:did_core:web:device-message-queue.example";

/// Two accepted devices of one account, seeded from genuinely signed history.
async fn two_device_authorities(
    pool: &PgPool,
) -> (DeviceRevocationGateSelector, DeviceRevocationGateSelector) {
    let source = two_device_history(pool).await;
    let mut selectors = source.gate_selectors().into_iter();
    (selectors.next().unwrap(), selectors.next().unwrap())
}

/// The signed history behind [`two_device_authorities`], with its founding
/// device key still available to author further Events.
async fn two_device_history(pool: &PgPool) -> device_history_fixture::DeviceHistoryFixture {
    let mut conn = pool.get().await.unwrap();
    sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
        .bind::<Text, _>(STATION)
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    let mut source = device_history_fixture::DeviceHistoryFixture::new(
        device_history_fixture::did_web_station(&STATION.parse().unwrap()),
    );
    let second = source.event(
        arkret_wire::EventKind::DeviceAuthorize,
        serde_json::to_value(device_history_fixture::possession(
            &source.account,
            2,
            arkret_models_collaboration::events_payloads::DeviceAuthorizationBindingKind::AcceptedDevice,
        ))
        .unwrap(),
    );
    source.append(vec![second]);
    let inventory = PgDeviceInventoryStore { pool: pool.clone() };
    for device in source.device_inventory_records() {
        inventory.seed_test_record(&device).await.unwrap();
    }
    source
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
    controller: device_history_fixture::DeviceHistoryFixture,
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

        let controller = two_device_history(pool).await;
        let recipient = controller.gate_selectors().pop().unwrap();
        let authority = soland_services::authority_commit::AuthorityCommitApplication::new(
            soland_services::persistence::PersistenceHandle::new(std::sync::Arc::new(
                soland_storage_postgres::PgPersistenceStore::new(pool.clone()),
            )),
            100,
        );
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
        authority
            .install_genesis_authority(&soland_storage::CurrentRealmAuthority {
                realm_id: pcr_realm_id.clone(),
                generation: 0,
                service_id: station.clone(),
                authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    genesis.event_id.clone(),
                ),
                last_handoff_ref: None,
            })
            .await
            .unwrap();
        admit(&authority, &station, &genesis).await;

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
        let commit = admit(&authority, &station, &authorize).await;
        let authorization_ref = arkret_wire::CommittedEventRef {
            event_id: authorize.event_id.clone(),
            commit_id: commit.commit_id,
            stream_ref: commit.stream_ref,
            stream_position: commit.stream_position,
        };
        let agent = Self {
            authority,
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
        admit(&self.authority, &self.station, &event).await;
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
    controller: &device_history_fixture::DeviceHistoryFixture,
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
    device_history_fixture::sign_event(
        event,
        controller.device_verification_method.clone(),
        controller.founding_device_signing_seed,
    )
}

/// Admit `event` through the Station's atomic Event committer, which signs
/// the covering `RealmCommit` with the Station authority key.
async fn admit(
    authority: &soland_services::authority_commit::AuthorityCommitApplication,
    station: &arkret_wire::DidCoreId,
    event: &arkret_wire::Event,
) -> arkret_wire::RealmCommit {
    let method = arkret_wire::DidUrl::new(format!(
        "{}#authority",
        device_history_fixture::did_web_station(station)
    ))
    .unwrap();
    let outcome = authority
        .admit_event(
            event,
            station,
            method,
            &ed25519_dalek::SigningKey::from_bytes(&STATION_AUTHORITY_SEED),
            Utc::now(),
        )
        .await
        .unwrap();
    let soland_services::authority_commit::AuthorityEventAdmissionOutcome::Committed(commit) =
        outcome
    else {
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
