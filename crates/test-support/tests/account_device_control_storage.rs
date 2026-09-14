use std::collections::BTreeSet;
use std::sync::Arc;

use arkret_canonical::DigestSuite;
use arkret_state::state::ControlUnitIngressMember;
use arkret_state::state::store::{AcklessSelfPrincipalIngress, ControlProposalIngress};
use diesel::sql_types::{BigInt, Text};
use diesel::{QueryableByName, sql_query};
use diesel_async::RunQueryDsl;
use soland_storage::{ConfirmedDeviceControlProjection, DeviceInventoryStore};
use soland_storage_postgres::test_database::TestDatabase;
use soland_storage_postgres::{
    PgDeviceInventoryStore, StateResolutionStores, build_state_resolution_stores,
};
use soland_test_support::device_authorization_history::DeviceHistoryFixture;

async fn configure_station(
    pool: &soland_storage_postgres::PgPool,
    station: &arkret_wire::DidCoreId,
) {
    let mut conn = pool.get().await.unwrap();
    // A prior interrupted failure-injection test may leave schema DDL behind;
    // the leased-database reset clears rows, not ad-hoc constraints.
    sql_query("ALTER TABLE devices DROP CONSTRAINT IF EXISTS reject_atomic_projection")
        .execute(&mut *conn)
        .await
        .unwrap();
    sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
        .bind::<Text, _>(station.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
}

async fn seed_seal(
    stores: &StateResolutionStores,
    source: &DeviceHistoryFixture,
    seal_index: usize,
) {
    let seal = &source.seals[seal_index];
    for result in &seal.command_results {
        let members = result
            .unit_event_digests
            .iter()
            .map(|digest| ControlUnitIngressMember {
                event: source
                    .events
                    .iter()
                    .find(|event| event.event_id.event_digest() == *digest)
                    .unwrap()
                    .clone(),
                digest_suite: DigestSuite::Sha256,
                ingress: ControlProposalIngress::AcklessSelfPrincipal(
                    AcklessSelfPrincipalIngress {
                        device_id: source.founding_device_id.to_string(),
                        device_authorize_event_id: source.events[1].event_id.to_string(),
                        device_generation_ref: 1,
                        seal_basis_digest: format!("sha256:{}", "a".repeat(64)),
                    },
                ),
            })
            .collect::<Vec<_>>();
        stores
            .control_event_store
            .put_pending_unit_with_ingress(&members)
            .await
            .unwrap();
    }
}

fn projection(source: &DeviceHistoryFixture) -> ConfirmedDeviceControlProjection {
    ConfirmedDeviceControlProjection::from_verified_history(
        source.verify().unwrap(),
        &source.registration_anchor,
        &source.seals,
        &source.events,
        DigestSuite::Sha256,
    )
    .unwrap()
}

async fn commit(
    stores: &StateResolutionStores,
    source: &DeviceHistoryFixture,
    seal_index: usize,
    projection: &ConfirmedDeviceControlProjection,
) -> arkret_state::state::StoreResult<bool> {
    let seal = &source.seals[seal_index];
    let covered = source.seals[..=seal_index]
        .iter()
        .flat_map(|seal| {
            seal.covered_event_digests
                .iter()
                .chain(seal.delta.iter())
                .cloned()
        })
        .collect::<BTreeSet<_>>();
    stores
        .event_seal_committer
        .commit_if_head(
            seal,
            DigestSuite::Sha256,
            seal.predecessor_ref.as_ref(),
            &source.sealed_ops[seal_index],
            &covered,
            &[],
            Some(projection),
        )
        .await
}

#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type = BigInt)]
    value: i64,
}

async fn count(pool: &soland_storage_postgres::PgPool, table: &str) -> i64 {
    let mut conn = pool.get().await.unwrap();
    sql_query(format!("SELECT COUNT(*) AS value FROM {table}"))
        .get_result::<Count>(&mut *conn)
        .await
        .unwrap()
        .value
}

fn root_ref(projection: &ConfirmedDeviceControlProjection) -> arkret_wire::SignerEvidenceRef {
    let arkret_models_collaboration::governance_dependencies::GovernanceDependency::AuthenticatedSignerResolutionEvidence {
        authenticated_signer_resolution_evidence,
        ..
    } = &projection.roots()[0]
    else {
        unreachable!("Control projection roots are signer evidence")
    };
    authenticated_signer_resolution_evidence
        .evidence_ref()
        .unwrap()
}

fn stores(pool: &soland_storage_postgres::PgPool) -> StateResolutionStores {
    build_state_resolution_stores(
        Some(pool.clone()),
        Arc::new(arkret_lattice_registry::try_build_sdk_state_registry().unwrap()),
    )
}

#[tokio::test]
async fn seal_commit_atomically_installs_fixed_root_and_preserves_it_after_revoke() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let station = arkret_wire::DidCoreId::new("ak:did_core:web:atomic-device.example").unwrap();
    configure_station(&pool, &station).await;
    let mut source = DeviceHistoryFixture::new(station);
    let first = projection(&source);
    let stores = stores(&pool);
    seed_seal(&stores, &source, 0).await;
    assert!(commit(&stores, &source, 0, &first).await.unwrap());

    let authorization = first.history().authorizations()[0].clone();
    let original_root = root_ref(&first);
    let inventory = PgDeviceInventoryStore { pool: pool.clone() };
    let active = inventory
        .get(
            source.account.principal_id.as_str(),
            source.founding_device_id.as_str(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        active.payload["confirmed_seal_id"],
        serde_json::json!(authorization.confirmed_seal())
    );
    assert_eq!(
        active.payload["signer_resolution_evidence_ref"],
        serde_json::json!(original_root)
    );
    assert_eq!(count(&pool, "state_seals").await, 1);
    assert_eq!(count(&pool, "governance_unscoped_signer_evidence").await, 1);
    assert_eq!(count(&pool, "device_history_projections").await, 1);
    assert_eq!(count(&pool, "state_seal_control_events").await, 2);

    let revoke = source.event(
        arkret_wire::EventKind::DeviceRevoke,
        serde_json::json!({
            "device_id": source.founding_device_id,
            "revoked_by": source.founding_device_id,
            "revoked_at": "2026-09-12T00:00:00.000Z",
            "reason": "user_requested"
        }),
    );
    source.append(vec![revoke]);
    let successor = projection(&source);
    seed_seal(&stores, &source, 1).await;
    assert!(commit(&stores, &source, 1, &successor).await.unwrap());
    let revoked = inventory
        .get(
            source.account.principal_id.as_str(),
            source.founding_device_id.as_str(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(revoked.verification_state, "unverified");
    assert_eq!(
        revoked.payload["confirmed_seal_id"],
        serde_json::json!(authorization.confirmed_seal())
    );
    assert_eq!(
        revoked.payload["signer_resolution_evidence_ref"],
        serde_json::json!(original_root)
    );
    assert_eq!(count(&pool, "governance_unscoped_signer_evidence").await, 1);
}

#[tokio::test]
async fn exact_retry_does_not_repair_a_missing_root() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let station = arkret_wire::DidCoreId::new("ak:did_core:web:retry-device.example").unwrap();
    configure_station(&pool, &station).await;
    let source = DeviceHistoryFixture::new(station);
    let projection = projection(&source);
    let stores = stores(&pool);
    seed_seal(&stores, &source, 0).await;
    assert!(commit(&stores, &source, 0, &projection).await.unwrap());
    {
        let mut conn = pool.get().await.unwrap();
        sql_query("UPDATE governance_unscoped_signer_evidence SET object_json='{}'::jsonb")
            .execute(&mut *conn)
            .await
            .unwrap();
    }
    assert!(
        commit(&stores, &source, 0, &projection)
            .await
            .unwrap_err()
            .to_string()
            .contains("missing or differs")
    );
    assert_eq!(
        count(&pool, "governance_unscoped_signer_evidence").await,
        1,
        "an exact retry must not overwrite a divergent root"
    );
    {
        let mut conn = pool.get().await.unwrap();
        sql_query("DELETE FROM governance_unscoped_signer_evidence")
            .execute(&mut *conn)
            .await
            .unwrap();
    }
    assert!(
        commit(&stores, &source, 0, &projection)
            .await
            .unwrap_err()
            .to_string()
            .contains("missing or differs")
    );
    assert_eq!(count(&pool, "governance_unscoped_signer_evidence").await, 0);
}

#[tokio::test]
async fn exact_retry_does_not_repair_a_missing_device_mapping() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let station = arkret_wire::DidCoreId::new("ak:did_core:web:retry-mapping.example").unwrap();
    configure_station(&pool, &station).await;
    let source = DeviceHistoryFixture::new(station);
    let projection = projection(&source);
    let stores = stores(&pool);
    seed_seal(&stores, &source, 0).await;
    assert!(commit(&stores, &source, 0, &projection).await.unwrap());
    {
        let mut conn = pool.get().await.unwrap();
        sql_query("DELETE FROM devices")
            .execute(&mut *conn)
            .await
            .unwrap();
    }
    assert!(
        commit(&stores, &source, 0, &projection)
            .await
            .unwrap_err()
            .to_string()
            .contains("device Control mapping")
    );
    assert_eq!(count(&pool, "devices").await, 0);
}

#[tokio::test]
async fn mapping_failure_rolls_back_root_seal_and_decisions() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let station = arkret_wire::DidCoreId::new("ak:did_core:web:rollback-device.example").unwrap();
    configure_station(&pool, &station).await;
    let source = DeviceHistoryFixture::new(station);
    let projection = projection(&source);
    let stores = stores(&pool);
    seed_seal(&stores, &source, 0).await;
    {
        let mut conn = pool.get().await.unwrap();
        sql_query("ALTER TABLE devices DROP CONSTRAINT IF EXISTS reject_atomic_projection")
            .execute(&mut *conn)
            .await
            .unwrap();
        sql_query("ALTER TABLE devices ADD CONSTRAINT reject_atomic_projection CHECK(FALSE)")
            .execute(&mut *conn)
            .await
            .unwrap();
    }
    assert!(commit(&stores, &source, 0, &projection).await.is_err());
    assert_eq!(count(&pool, "state_seals").await, 0);
    assert_eq!(count(&pool, "governance_unscoped_signer_evidence").await, 0);
    assert_eq!(count(&pool, "device_history_projections").await, 0);
    assert_eq!(count(&pool, "state_seal_control_events").await, 0);
    {
        let mut conn = pool.get().await.unwrap();
        sql_query("ALTER TABLE devices DROP CONSTRAINT reject_atomic_projection")
            .execute(&mut *conn)
            .await
            .unwrap();
    }
}
