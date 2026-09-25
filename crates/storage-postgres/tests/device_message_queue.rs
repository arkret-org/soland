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
    let mut selectors = source.gate_selectors().into_iter();
    (selectors.next().unwrap(), selectors.next().unwrap())
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
