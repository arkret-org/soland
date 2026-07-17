use soland_storage::contract_tests::{
    EventCommitContractStores, assert_event_commit_unit_of_work_contract,
    assert_idempotency_store_contract,
};
use soland_storage::{
    EventProjectionStoreRegistry, FederationGovernanceStoreRegistry, SyncStoreRegistry,
};
use soland_storage_memory::SolandMemoryPersistenceStore;

#[tokio::test]
async fn memory_adapter_satisfies_shared_idempotency_contract() {
    let store = SolandMemoryPersistenceStore::new();
    assert_idempotency_store_contract(store.idempotency_keys(), "memory-contract").await;
}

#[tokio::test]
async fn memory_adapter_satisfies_shared_event_commit_contract() {
    let store = SolandMemoryPersistenceStore::new();
    assert_event_commit_unit_of_work_contract(
        EventCommitContractStores {
            unit_of_work: &store,
            events: store.events(),
            projections: store.projection_events(),
            idempotency: store.idempotency_keys(),
            outbox: store.federation_outbox(),
        },
        "memory-event-commit",
    )
    .await;
}
