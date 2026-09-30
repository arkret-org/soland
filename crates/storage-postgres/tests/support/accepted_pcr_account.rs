//! An accepted PCR and founding device for an exact Account fixture.
//! No display Profile is required by capability-grant admission.

use arkret_wire::{ActorId, Did};
use diesel::sql_types::Text;
use diesel_async::RunQueryDsl;
use soland_storage_postgres::{PgPersistenceStore, PgPool};

pub async fn accepted_pcr_account(pool: &PgPool, station_did: Did) -> ActorId {
    let fixture = crate::pcr_genesis::PcrGenesisFixture::new(station_did);
    let mut conn = pool.get().await.expect("test database connection");
    diesel::sql_query(
        "INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1) \
         ON CONFLICT(singleton) DO NOTHING",
    )
    .bind::<Text, _>(fixture.history.account.station_id.as_str())
    .execute(&mut *conn)
    .await
    .expect("hosted Station device inventory");
    drop(conn);
    let persistence = PgPersistenceStore::new(pool.clone());
    fixture
        .admit_founding_device(&persistence)
        .await
        .expect("accepted PCR founding device");
    ActorId::account(fixture.history.account.clone())
}
