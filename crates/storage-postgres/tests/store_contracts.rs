use soland_storage::contract_tests::assert_idempotency_store_contract;
use soland_storage_postgres::{Db, PgIdempotencyStore};

#[tokio::test]
async fn postgres_adapter_satisfies_shared_idempotency_contract_when_configured() {
    let db = Db::from_env().await.expect("initialize test database");
    let Some(pool) = db.pool else {
        return;
    };
    let store = PgIdempotencyStore { pool };
    let namespace = format!("postgres-contract-{}", uuid::Uuid::now_v7());
    assert_idempotency_store_contract(&store, &namespace).await;
}
