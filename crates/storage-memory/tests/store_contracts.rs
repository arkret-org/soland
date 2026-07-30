use soland_storage::contract_tests::{
    EventCommitContractStores, assert_event_commit_unit_of_work_contract,
    assert_idempotency_store_contract, assert_last_resort_claim_ledger_contract,
    assert_mls_keypackage_retirement_contract, assert_proposal_member_receipt_store_contract,
};
use soland_storage::{
    AccountDataCasResult, AccountDataRecord, EventProjectionStoreRegistry,
    FederationGovernanceStoreRegistry, IdentityStoreRegistry, MlsAgentStoreRegistry,
    SyncStoreRegistry,
};
use soland_storage_memory::SolandMemoryPersistenceStore;

#[tokio::test]
async fn memory_adapter_satisfies_shared_idempotency_contract() {
    let store = SolandMemoryPersistenceStore::new();
    assert_idempotency_store_contract(store.idempotency_keys(), "memory-contract").await;
}

#[tokio::test]
async fn memory_adapter_satisfies_proposal_member_receipt_contract() {
    let store = SolandMemoryPersistenceStore::new();
    assert_proposal_member_receipt_store_contract(
        store.proposal_member_receipts(),
        "memory-contract",
    )
    .await;
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

#[tokio::test]
async fn memory_adapter_satisfies_mls_keypackage_retirement_contract() {
    let store = SolandMemoryPersistenceStore::new();
    assert_mls_keypackage_retirement_contract(store.mls_key_packages(), "memory-retirement").await;
}

#[tokio::test]
async fn memory_adapter_satisfies_last_resort_claim_ledger_contract() {
    let store = SolandMemoryPersistenceStore::new();
    assert_last_resort_claim_ledger_contract(store.mls_key_packages(), "memory-last-resort").await;
}

fn account_data_record(
    key: &str,
    revision: u64,
    tombstone: bool,
    payload: serde_json::Value,
) -> AccountDataRecord {
    AccountDataRecord {
        actor: "did:web:alice.example".to_owned(),
        account_data_key: key.to_owned(),
        revision,
        payload,
        tombstone,
        updated_at: chrono::Utc::now(),
    }
}

#[tokio::test]
async fn account_data_cas_preserves_revision_high_water_and_rejects_stale_writers() {
    let store = SolandMemoryPersistenceStore::new();
    let account_data = store.account_data();
    let key = "client.example.scalar";

    let created = account_data_record(key, 1, false, serde_json::json!({"value": 1}));
    assert!(matches!(
        account_data.compare_and_set(&created, 0).await.unwrap(),
        AccountDataCasResult::Applied(record) if record.revision == 1
    ));

    let stale = account_data_record(key, 1, false, serde_json::json!({"value": "stale"}));
    assert!(matches!(
        account_data.compare_and_set(&stale, 0).await.unwrap(),
        AccountDataCasResult::Conflict(Some(record))
            if record.revision == 1 && record.payload == serde_json::json!({"value": 1})
    ));

    let updated = account_data_record(key, 2, false, serde_json::json!({"value": 2}));
    assert!(matches!(
        account_data.compare_and_set(&updated, 1).await.unwrap(),
        AccountDataCasResult::Applied(record) if record.revision == 2
    ));
}

#[tokio::test]
async fn account_data_concurrent_delete_and_update_apply_exactly_once() {
    let store = SolandMemoryPersistenceStore::new();
    let account_data = store.account_data();
    let key = "client.example.race";
    let created = account_data_record(key, 1, false, serde_json::json!({"value": 1}));
    account_data.compare_and_set(&created, 0).await.unwrap();

    let deleted = account_data_record(key, 2, true, serde_json::Value::Null);
    let updated = account_data_record(key, 2, false, serde_json::json!({"value": 2}));
    let (delete_result, update_result) = tokio::join!(
        account_data.compare_and_set(&deleted, 1),
        account_data.compare_and_set(&updated, 1)
    );
    let outcomes = [delete_result.unwrap(), update_result.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, AccountDataCasResult::Applied(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, AccountDataCasResult::Conflict(Some(_))))
            .count(),
        1
    );
    assert_eq!(
        account_data
            .get("did:web:alice.example", key)
            .await
            .unwrap()
            .unwrap()
            .revision,
        2
    );
}

#[tokio::test]
async fn account_data_tombstone_is_hidden_but_remains_the_cas_high_water_mark() {
    let store = SolandMemoryPersistenceStore::new();
    let account_data = store.account_data();
    let key = "client.example.deleted";
    let created = account_data_record(key, 1, false, serde_json::json!({"value": 1}));
    account_data.compare_and_set(&created, 0).await.unwrap();

    let tombstone = account_data_record(key, 2, true, serde_json::Value::Null);
    account_data.compare_and_set(&tombstone, 1).await.unwrap();
    assert!(
        account_data
            .list_for_actor("did:web:alice.example")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        account_data
            .compare_and_set(
                &account_data_record(key, 2, false, serde_json::json!({"value": "stale"})),
                1,
            )
            .await
            .unwrap(),
        AccountDataCasResult::Conflict(Some(record))
            if record.revision == 2 && record.tombstone
    ));

    let recreated = account_data_record(key, 3, false, serde_json::json!({"value": 3}));
    assert!(matches!(
        account_data.compare_and_set(&recreated, 2).await.unwrap(),
        AccountDataCasResult::Applied(record)
            if record.revision == 3 && !record.tombstone
    ));
}
