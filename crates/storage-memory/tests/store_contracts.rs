use soland_storage::PersistenceStore;
use soland_storage::contract_tests::assert_idempotency_store_contract;
use soland_storage_memory::SolandMemoryPersistenceStore;

#[tokio::test]
async fn memory_adapter_satisfies_shared_idempotency_contract() {
    let store = SolandMemoryPersistenceStore::new();
    assert_idempotency_store_contract(store.idempotency_keys(), "memory-contract").await;
}
