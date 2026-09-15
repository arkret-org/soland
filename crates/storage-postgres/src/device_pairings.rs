use chrono::{DateTime, Utc};
use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl, SelectableHelper};

use super::{
    AsyncConnection, DevicePairingRecord, DevicePairingRow, DevicePairingStore, OptionalExtension,
    PersistenceError, PersistenceResult, PgPool, PgTransactionError, RunQueryDsl, async_trait,
    pg_conn,
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
        let request_id = device_pairing_request_id.to_owned();
        // `device-lifecycle.md` 2.1.1 step 2 requires the one-way transition and
        // the supersession of every other approvable record of the same account
        // to land in the same durable transaction, so no instant exposes two
        // simultaneously approvable requests for one `AccountId`.
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            // The pre-state decides whether this call performs the transition or
            // replays an exact retry. Reading it under the row lock is what keeps
            // an exact retry from superseding a second time.
            let previous_state = device_pairings::table
                .find(&request_id)
                .select(device_pairings::state)
                .for_update()
                .first::<String>(&mut *conn)
                .await
                .optional()
                .map_err(PersistenceError::database)?;
            // One statement carries the whole contract: the transition fires only
            // from `staged`, and an exact retry matches the already finalized row
            // so it returns unchanged instead of re-attaching a second proof.
            let updated = diesel::update(
                device_pairings::table
                    .find(&request_id)
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
                device_pairings::account_id.eq(account_key.clone()),
                device_pairings::target_proof.eq(target_proof),
            ))
            .returning(DevicePairingRow::as_returning())
            .get_result::<DevicePairingRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
            let updated = updated.ok_or_else(|| {
                PersistenceError::NotFound("device pairing request is not finalizable".to_owned())
            })?;
            if previous_state.as_deref() == Some("staged") {
                // The supersession key is the `AccountId` alone: a refreshed
                // pairing page reusing the same candidate key and an entirely new
                // device retire the previous code identically. `authorized` rows
                // are excluded by the state predicate, so an already accepted
                // record is never rewritten retroactively, and a `staged` row
                // cannot match because it carries no account. The row is flipped
                // rather than deleted: the tombstone keeps the retired code
                // unusable and unmintable until its own `expires_at` elapses.
                diesel::update(
                    device_pairings::table
                        .filter(device_pairings::account_id.eq(account_key))
                        .filter(device_pairings::state.eq("ready_for_claim"))
                        .filter(device_pairings::device_pairing_request_id.ne(request_id.as_str())),
                )
                .set(device_pairings::state.eq("expired"))
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
            }
            Ok(updated)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
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

#[cfg(test)]
mod tests {
    use soland_storage::contract_tests::assert_device_pairing_finalize_supersession_contract;

    use super::*;

    /// Each run claims fresh identifiers: the shared contract database retains
    /// tombstones, and `pairing_code` is unique across every retained row.
    fn unique_namespace() -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is after the unix epoch")
            .as_nanos();
        format!("pg-pairing-{nanos}")
    }

    #[tokio::test]
    async fn finalize_retires_every_other_approvable_request_of_the_same_account() {
        let pool = crate::test_database::contract_pool().await;
        let store = PgDevicePairingStore { pool };
        assert_device_pairing_finalize_supersession_contract(&store, &unique_namespace()).await;
    }
}
