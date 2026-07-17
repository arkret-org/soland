use soland_storage::contract_tests::{
    EventCommitContractStores, assert_event_commit_unit_of_work_contract,
    assert_idempotency_store_contract,
};
use soland_storage_postgres::{
    Db, PgEventCommitUnitOfWork, PgEventStore, PgFederationOutboxStore, PgIdempotencyStore, PgPool,
    PgProjectionEventStore,
};

static TEST_POOL: tokio::sync::OnceCell<Option<PgPool>> = tokio::sync::OnceCell::const_new();

async fn test_pool() -> Option<PgPool> {
    TEST_POOL
        .get_or_init(|| async { Db::from_env().await.expect("initialize test database").pool })
        .await
        .clone()
}

#[tokio::test]
async fn postgres_adapter_satisfies_shared_idempotency_contract_when_configured() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let store = PgIdempotencyStore { pool };
    let namespace = format!("postgres-contract-{}", uuid::Uuid::now_v7());
    assert_idempotency_store_contract(&store, &namespace).await;
}

#[tokio::test]
async fn postgres_adapter_satisfies_shared_event_commit_contract_when_configured() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let unit_of_work = PgEventCommitUnitOfWork::new(pool.clone());
    let events = PgEventStore { pool: pool.clone() };
    let projections = PgProjectionEventStore { pool: pool.clone() };
    let idempotency = PgIdempotencyStore { pool: pool.clone() };
    let outbox = PgFederationOutboxStore { pool };
    let namespace = format!("postgres-event-commit-{}", uuid::Uuid::now_v7());
    assert_event_commit_unit_of_work_contract(
        EventCommitContractStores {
            unit_of_work: &unit_of_work,
            events: &events,
            projections: &projections,
            idempotency: &idempotency,
            outbox: &outbox,
        },
        &namespace,
    )
    .await;
}
