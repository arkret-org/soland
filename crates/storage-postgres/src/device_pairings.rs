use chrono::{DateTime, Utc};
use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl, SelectableHelper};

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
            .map_err(PersistenceError::database)?
            .map(DevicePairingRecord::try_from)
            .transpose()
    }

    async fn get_by_pairing_code(
        &self,
        pairing_code: &str,
    ) -> PersistenceResult<Option<DevicePairingRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        device_pairings::table
            .filter(device_pairings::pairing_code.eq(pairing_code))
            .select(DevicePairingRow::as_select())
            .first::<DevicePairingRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
            .map(DevicePairingRecord::try_from)
            .transpose()
    }

    async fn finalize(
        &self,
        device_pairing_request_id: &str,
        account_id: &arkret_wire::AccountId,
        target_proof: serde_json::Value,
        finalized_at: DateTime<Utc>,
    ) -> PersistenceResult<DevicePairingRecord> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let account_key = account_id.to_string();
        // One statement carries the whole contract: the transition fires only
        // from `staged`, and an exact retry matches the already finalized row
        // so it returns unchanged instead of re-attaching a second proof.
        let updated = diesel::update(
            device_pairings::table
                .find(device_pairing_request_id)
                .filter(device_pairings::expires_at.gt(finalized_at))
                .filter(
                    device_pairings::state
                        .eq("staged")
                        .or(device_pairings::state
                            .eq("ready_for_claim")
                            .and(device_pairings::account_id.eq(account_key.clone()))
                            .and(device_pairings::target_proof.eq(target_proof.clone()))),
                ),
        )
        .set((
            device_pairings::state.eq("ready_for_claim"),
            device_pairings::account_id.eq(account_key),
            device_pairings::target_proof.eq(target_proof),
        ))
        .returning(DevicePairingRow::as_returning())
        .get_result::<DevicePairingRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        updated
            .ok_or_else(|| {
                PersistenceError::NotFound("device pairing request is not finalizable".to_owned())
            })
            .and_then(DevicePairingRecord::try_from)
    }

    async fn get_terminal(&self, request_id: &str) -> PersistenceResult<Option<serde_json::Value>> {
        #[derive(diesel::QueryableByName)]
        struct Row {
            #[diesel(sql_type = diesel::sql_types::Jsonb)]
            terminal_record: serde_json::Value,
        }
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        diesel::sql_query(
            "SELECT terminal_record FROM device_pairing_outcomes WHERE request_id = $1",
        )
        .bind::<diesel::sql_types::Text, _>(request_id)
        .get_result::<Row>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(|r| r.terminal_record))
        .map_err(PersistenceError::database)
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
