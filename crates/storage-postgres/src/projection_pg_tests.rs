//! Actual projection persistence must preserve idempotency across PG precision.

#[path = "../tests/support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use soland_storage::{ProjectionEventAppendOutcome, ProjectionEventRecord, ProjectionEventStore};

use super::PgProjectionEventStore;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hydration_does_not_overwrite_a_concurrent_realm_projection() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Mutex, mpsc};
    use std::time::Duration;

    use soland_services::hydration::HydrationProjectionAdapter;
    use soland_services::projection::ProjectionService;

    struct PausingAdapter {
        first: AtomicBool,
        entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: Mutex<mpsc::Receiver<()>>,
    }
    impl HydrationProjectionAdapter for PausingAdapter {
        fn operation_from_canonical_record(
            &self,
            record: &soland_services::events::AcceptedEvent,
        ) -> Option<arkret_event_draft::ProjectedEventOperation> {
            if self.first.swap(false, Ordering::SeqCst) {
                self.entered
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .send(())
                    .unwrap();
                tokio::task::block_in_place(|| self.release.lock().unwrap().recv().unwrap());
            }
            let event: arkret_wire::Event = serde_json::from_value(record.envelope.clone()).ok()?;
            arkret_event_draft::ProjectedEventOperation::from_accepted_event(
                arkret_wire::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
                    .ok()?,
                arkret_wire::OperationKind::Create,
                None,
                &event,
                record.digest_suite,
            )
            .ok()
        }
    }
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    ordinary_realm::open_human_discussion(&pool, &uuid::Uuid::now_v7().to_string()).await;
    let persistence = crate::PgPersistenceStore::new(pool);
    let service = ProjectionService::new("hydration-concurrency");
    let rebuilding = service.clone();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let adapter = PausingAdapter {
        first: AtomicBool::new(true),
        entered: Mutex::new(Some(entered_tx)),
        release: Mutex::new(release_rx),
    };
    let hydration = tokio::spawn(async move {
        rebuilding
            .hydrate_from_persistence(&persistence, &adapter, [])
            .await
    });
    entered_rx.await.unwrap();
    let writing = service.clone();
    let (started_tx, started_rx) = mpsc::channel();
    let (written_tx, written_rx) = mpsc::channel();
    let writer = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        let now = chrono::Utc::now();
        assert!(writing.reconcile_realm_owner(
            "concurrent-realm",
            "concurrent-owner",
            false,
            now,
            now
        ));
        written_tx.send(()).unwrap();
    });
    let blocked = tokio::task::block_in_place(|| {
        started_rx.recv().unwrap();
        written_rx.recv_timeout(Duration::from_millis(500)).is_err()
    });
    release_tx.send(()).unwrap();
    let result = hydration.await.unwrap();
    writer.join().unwrap();
    result.unwrap();
    assert!(
        blocked,
        "a projection writer escaped the in-progress hydration cut"
    );
    assert_eq!(
        service
            .snapshot()
            .realm_states
            .get("concurrent-realm")
            .unwrap()
            .owner
            .as_deref(),
        Some("concurrent-owner")
    );
}

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
