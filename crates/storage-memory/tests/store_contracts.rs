use soland_storage::contract_tests::{
    ConsentCommitContractStores, DeviceRevocationSealSettlementStores, EventCommitContractStores,
    assert_account_status_replica_decision_table_contract,
    assert_atomic_batch_outbox_rollback_contract, assert_consent_projection_commit_contract,
    assert_control_proposal_authority_ack_store_contract, assert_device_key_store_contract,
    assert_device_message_snapshot_guard_contract,
    assert_device_revocation_seal_settlement_contract, assert_event_commit_unit_of_work_contract,
    assert_federation_outbox_store_contract, assert_governance_unscoped_signer_evidence_contract,
    assert_idempotency_store_contract, assert_last_resort_claim_ledger_contract,
    assert_member_identity_store_contract, assert_message_store_contract,
    assert_mimi_consent_correlation_store_contract, assert_mls_keypackage_retirement_contract,
    assert_one_time_key_store_contract, assert_realm_meta_store_contract,
    assert_service_route_handover_plan_store_contract,
};
use soland_storage::{
    AccountDataCasResult, AccountDataRecord, EventProjectionStoreRegistry,
    FederationGovernanceStoreRegistry, IdentityStoreRegistry, MlsAgentStoreRegistry,
    ResolutionStoreRegistry, SyncStoreRegistry,
};
use soland_storage_memory::SolandMemoryPersistenceStore;

#[tokio::test]
async fn memory_adapter_guards_repair_device_snapshots_atomically() {
    let store = SolandMemoryPersistenceStore::new();
    assert_device_message_snapshot_guard_contract(
        store.devices(),
        store.device_messages(),
        "memory-repair-snapshot",
    )
    .await;
}

#[tokio::test]
async fn memory_adapter_satisfies_account_status_replica_decision_table_contract() {
    let store = SolandMemoryPersistenceStore::new();
    assert_account_status_replica_decision_table_contract(
        store.account_status_replicas(),
        "memory-account-status",
    )
    .await;
}

#[tokio::test]
async fn memory_adapter_satisfies_shared_idempotency_contract() {
    let store = SolandMemoryPersistenceStore::new();
    assert_idempotency_store_contract(store.idempotency_keys(), "memory-contract").await;
}

#[tokio::test]
async fn memory_adapter_satisfies_unscoped_signer_evidence_contract() {
    let store = SolandMemoryPersistenceStore::new();
    assert_governance_unscoped_signer_evidence_contract(
        store.governance_dependencies(),
        "memory-unscoped-signer-evidence",
    )
    .await;
}

#[tokio::test]
async fn memory_adapter_satisfies_mimi_consent_correlation_contract() {
    let store = SolandMemoryPersistenceStore::new();
    assert_mimi_consent_correlation_store_contract(
        store.mimi_consent_correlations(),
        "memory-mimi-consent",
    )
    .await;
}

#[tokio::test]
async fn memory_adapter_satisfies_control_proposal_authority_ack_contract() {
    let store = SolandMemoryPersistenceStore::new();
    assert_control_proposal_authority_ack_store_contract(
        store.control_proposal_authority_acks(),
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
            device_pairings: store.device_pairings(),
            contacts: store.contacts(),
            invite_policies: store.invite_receive_policies(),
        },
        "memory-event-commit",
    )
    .await;
}

#[tokio::test]
async fn memory_adapter_satisfies_shared_consent_projection_commit_contract() {
    let store = SolandMemoryPersistenceStore::new();
    assert_consent_projection_commit_contract(
        ConsentCommitContractStores {
            unit_of_work: &store,
            events: store.events(),
            consent_cells: store.consent_cells(),
            account_data: store.account_data(),
        },
        "memory-consent-commit",
    )
    .await;
}

#[tokio::test]
async fn memory_adapter_settles_sealed_device_revocations_from_control_events() {
    let store = SolandMemoryPersistenceStore::new();
    let control_events =
        std::sync::Arc::new(arkret_state::state::MemoryControlEventStore::default());
    store
        .device_revocations()
        .bind_control_event_store(control_events.clone());
    assert_device_revocation_seal_settlement_contract(
        DeviceRevocationSealSettlementStores {
            unit_of_work: &store,
            revocations: store.device_revocations(),
            control_events: control_events.as_ref(),
        },
        "memory-device-revocation-seal",
    )
    .await;
}

#[tokio::test]
async fn memory_adapter_rolls_atomic_batches_back_with_their_outbox() {
    let store = SolandMemoryPersistenceStore::new();
    assert_atomic_batch_outbox_rollback_contract(
        store.events(),
        store.federation_outbox(),
        "memory-batch-outbox",
    )
    .await;
}

#[tokio::test]
async fn memory_adapter_satisfies_shared_federation_outbox_contract() {
    let store = SolandMemoryPersistenceStore::new();
    assert_federation_outbox_store_contract(store.federation_outbox(), "memory-federation-outbox")
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

#[tokio::test]
async fn memory_adapter_satisfies_service_route_handover_plan_contract() {
    let store = SolandMemoryPersistenceStore::new();
    let service_id =
        arkret_wire::DidCoreId::new("ak:did_core:webvh:zCXaWSDv1afiBoxDX5sVBU5an").unwrap();
    assert_service_route_handover_plan_store_contract(store.service_route_plans(), &service_id)
        .await;
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

#[tokio::test]
async fn memory_adapter_satisfies_realm_meta_store_contract() {
    let store = SolandMemoryPersistenceStore::new();
    assert_realm_meta_store_contract(store.realm_meta(), "memory-realm-meta").await;
}

#[tokio::test]
async fn memory_adapter_satisfies_message_store_contract() {
    let store = SolandMemoryPersistenceStore::new();
    assert_message_store_contract(store.messages(), "memory-messages").await;
}

#[tokio::test]
async fn memory_adapter_satisfies_device_key_store_contract() {
    let store = SolandMemoryPersistenceStore::new();
    assert_device_key_store_contract(store.device_keys(), "memory-device-keys").await;
}

#[tokio::test]
async fn memory_adapter_satisfies_one_time_key_store_contract() {
    let store = SolandMemoryPersistenceStore::new();
    assert_one_time_key_store_contract(store.one_time_keys(), "memory-one-time-keys").await;
}

#[tokio::test]
async fn memory_adapter_satisfies_member_identity_store_contract() {
    let store = SolandMemoryPersistenceStore::new();
    assert_member_identity_store_contract(store.member_identity(), "memory-member-identity").await;
}
