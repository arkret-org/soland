use chrono::{DateTime, Utc};
use diesel::{ExpressionMethods, QueryDsl, SelectableHelper};

use super::{
    DevicePairingRecord, DevicePairingRow, DevicePairingStore, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, RunQueryDsl, async_trait, pg_conn,
};
use crate::schema::device_pairings;

pub struct PgDevicePairingStore {
    pub pool: PgPool,
}

#[async_trait]
impl DevicePairingStore for PgDevicePairingStore {
    async fn put(&self, record: DevicePairingRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = DevicePairingRow::from(record);
        diesel::insert_into(device_pairings::table)
            .values(&row)
            .on_conflict(device_pairings::device_pairing_request_id)
            .do_update()
            .set(&row)
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::database)
    }

    async fn get_by_request_id(
        &self,
        device_pairing_request_id: &str,
    ) -> PersistenceResult<Option<DevicePairingRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        device_pairings::table
            .find(device_pairing_request_id)
            .select(DevicePairingRow::as_select())
            .first::<DevicePairingRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)
            .map(|record| record.map(Into::into))
    }

    async fn delete_expired_before(&self, cutoff: DateTime<Utc>) -> PersistenceResult<u64> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        diesel::delete(device_pairings::table.filter(device_pairings::expires_at.le(cutoff)))
            .execute(&mut *conn)
            .await
            .map(|rows| rows as u64)
            .map_err(PersistenceError::database)
    }
}
