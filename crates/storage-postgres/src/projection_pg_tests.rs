//! Actual projection persistence must preserve idempotency across PG precision.

#[path = "../tests/support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use soland_storage::{ProjectionEventAppendOutcome, ProjectionEventRecord, ProjectionEventStore};

use super::PgProjectionEventStore;

#[tokio::test]
async fn submicrosecond_receipt_roundtrip_preserves_exact_projection_retry() {
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let discussion =
        ordinary_realm::open_human_discussion(&pool, &uuid::Uuid::now_v7().to_string()).await;
    let event = &discussion.unit.transactions[0].event;
    let received_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now())
        + chrono::TimeDelta::nanoseconds(123_456);
    let record = ProjectionEventRecord {
        event_id: event.event_id.to_string(),
        realm_id: event.realm_id.to_string(),
        event_kind: event.kind.as_str().to_owned(),
        operation_kind: "create".to_owned(),
        operation_id: None,
        sender: Some(event.actor_id.to_string()),
        payload: serde_json::to_value(&event.payload).unwrap(),
        created_at: event.created_at,
        received_at,
    };
    let store = PgProjectionEventStore { pool };
    assert_eq!(
        store.append(record.clone()).await.unwrap(),
        ProjectionEventAppendOutcome::Inserted
    );
    let stored = store.get(&record.event_id).await.unwrap().unwrap();
    assert_eq!(stored.created_at, event.created_at);
    assert_eq!(
        stored.received_at,
        arkret_canonical::normalize_timestamp_canonical(received_at)
    );
    assert_ne!(stored.received_at, received_at);
    assert_eq!(
        store.append(record.clone()).await.unwrap(),
        ProjectionEventAppendOutcome::AlreadyExists
    );
    let mut changed = record;
    changed.received_at += chrono::TimeDelta::milliseconds(1);
    assert!(matches!(
        store.append(changed).await,
        Err(soland_storage::PersistenceError::Conflict(reason))
            if reason.starts_with("duplicate_conflict:")
    ));
}
