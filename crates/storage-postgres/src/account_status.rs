use arkret_models_collaboration::account_lifecycle::{AccountStatusReceipt, AccountStatusRecord};
use soland_storage::classify_account_status_replica_append;

use super::{
    AccountStatusReplicaAppend, AccountStatusReplicaStore, AsyncConnection, BigInt, Jsonb,
    OptionalExtension, PersistenceError, PersistenceResult, PgPool, PgTransactionError,
    QueryableByName, RunQueryDsl, Text, async_trait, pg_conn, sql_query,
};

/// The durable replica head for one `(account_authority_id, account_id)` pair:
/// the accepted record and the receipt that acknowledged it.
type ReplicaHead = (AccountStatusRecord, AccountStatusReceipt);

pub struct PgAccountStatusReplicaStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct RecordRow {
    #[diesel(sql_type = Jsonb)]
    record: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    receipt: serde_json::Value,
}

fn decode_record(row: &RecordRow) -> PersistenceResult<AccountStatusRecord> {
    serde_json::from_value(row.record.clone()).map_err(|error| {
        PersistenceError::Internal(format!("stored account-status record is invalid: {error}"))
    })
}

fn decode_receipt(row: &RecordRow) -> PersistenceResult<AccountStatusReceipt> {
    serde_json::from_value(row.receipt.clone()).map_err(|error| {
        PersistenceError::Internal(format!("stored account-status receipt is invalid: {error}"))
    })
}

fn encode_account_id(account: &arkret_wire::AccountId) -> PersistenceResult<serde_json::Value> {
    serde_json::to_value(account).map_err(|error| {
        PersistenceError::Internal(format!("account identity cannot be encoded: {error}"))
    })
}

#[async_trait]
impl AccountStatusReplicaStore for PgAccountStatusReplicaStore {
    async fn append(
        &self,
        record: &AccountStatusRecord,
        receipt: &AccountStatusReceipt,
    ) -> PersistenceResult<AccountStatusReplicaAppend> {
        receipt.validate_for_record(record).map_err(|error| {
            PersistenceError::SchemaViolation(format!(
                "account-status record/receipt pair is invalid: {error}"
            ))
        })?;
        let mut conn = pg_conn(&self.pool).await?;
        let record = record.clone();
        let receipt = receipt.clone();
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let authority = record.account_authority_id.to_string();
            let account = encode_account_id(&record.account_id)?;
            let lock_key = format!("account-status:{authority}:{}", record.account_id);
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(&lock_key)
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;

            let head = sql_query(
                "SELECT record, receipt FROM account_status_replica_records \
                 WHERE account_authority_id = $1 AND account_id = $2 \
                 ORDER BY status_seq DESC LIMIT 1",
            )
            .bind::<Text, _>(&authority)
            .bind::<Jsonb, _>(&account)
            .get_result::<RecordRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
            .map(|row| -> PersistenceResult<ReplicaHead> {
                Ok((decode_record(&row)?, decode_receipt(&row)?))
            })
            .transpose()?;

            if let Some(outcome) = classify_account_status_replica_append(&record, head.as_ref()) {
                return Ok(outcome);
            }

            sql_query(
                "INSERT INTO account_status_replica_records \
                 (account_authority_id, account_id, status_seq, record_id, record, receipt) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind::<Text, _>(&authority)
            .bind::<Jsonb, _>(&account)
            .bind::<BigInt, _>(i64::try_from(record.status_seq).map_err(|_| {
                PersistenceError::SchemaViolation(
                    "account-status sequence exceeds PostgreSQL bigint".to_owned(),
                )
            })?)
            .bind::<Text, _>(record.account_status_record_id.as_str())
            .bind::<Jsonb, _>(serde_json::to_value(&record).map_err(|error| {
                PersistenceError::Internal(format!(
                    "account-status record cannot be encoded: {error}"
                ))
            })?)
            .bind::<Jsonb, _>(serde_json::to_value(&receipt).map_err(|error| {
                PersistenceError::Internal(format!(
                    "account-status receipt cannot be encoded: {error}"
                ))
            })?)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            Ok(AccountStatusReplicaAppend::Accepted(receipt))
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn current(
        &self,
        account_authority_id: &str,
        account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<AccountStatusRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT record, receipt FROM account_status_replica_records \
             WHERE account_authority_id = $1 AND account_id = $2 \
             ORDER BY status_seq DESC LIMIT 1",
        )
        .bind::<Text, _>(account_authority_id)
        .bind::<Jsonb, _>(encode_account_id(account_id)?)
        .get_result::<RecordRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(|row| decode_record(&row))
        .transpose()
    }

    async fn resolve(
        &self,
        account_authority_id: &str,
        account_id: &arkret_wire::AccountId,
        from_status_seq: u64,
        limit: u16,
    ) -> PersistenceResult<Vec<AccountStatusRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT record, receipt FROM account_status_replica_records \
             WHERE account_authority_id = $1 AND account_id = $2 AND status_seq >= $3 \
             ORDER BY status_seq ASC LIMIT $4",
        )
        .bind::<Text, _>(account_authority_id)
        .bind::<Jsonb, _>(encode_account_id(account_id)?)
        .bind::<BigInt, _>(i64::try_from(from_status_seq).map_err(|_| {
            PersistenceError::SchemaViolation(
                "account-status sequence exceeds PostgreSQL bigint".to_owned(),
            )
        })?)
        .bind::<BigInt, _>(i64::from(limit))
        .load::<RecordRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter().map(|row| decode_record(&row)).collect()
    }

    async fn erasure_pending(&self, limit: u16) -> PersistenceResult<Vec<AccountStatusRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT record, receipt FROM account_status_replica_records \
             WHERE record #>> '{status}' = 'erasure_pending' \
             ORDER BY accepted_at, account_authority_id, account_id, status_seq LIMIT $1",
        )
        .bind::<BigInt, _>(i64::from(limit))
        .load::<RecordRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter().map(|row| decode_record(&row)).collect()
    }

    async fn receipt(
        &self,
        account_authority_id: &str,
        account_id: &arkret_wire::AccountId,
        status_seq: u64,
    ) -> PersistenceResult<Option<AccountStatusReceipt>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT record, receipt FROM account_status_replica_records \
             WHERE account_authority_id = $1 AND account_id = $2 AND status_seq = $3",
        )
        .bind::<Text, _>(account_authority_id)
        .bind::<Jsonb, _>(encode_account_id(account_id)?)
        .bind::<BigInt, _>(i64::try_from(status_seq).map_err(|_| {
            PersistenceError::SchemaViolation(
                "account-status sequence exceeds PostgreSQL bigint".to_owned(),
            )
        })?)
        .get_result::<RecordRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(|row| decode_receipt(&row))
        .transpose()
    }
}

#[cfg(test)]
mod tests {
    use soland_storage::contract_tests::assert_account_status_replica_decision_table_contract;

    use super::*;

    /// Follows the gating convention of `tests/store_contracts.rs`: the
    /// PostgreSQL contracts run only when `DATABASE_URL` points at a migrated
    /// database and are skipped otherwise.
    async fn test_pool() -> Option<PgPool> {
        crate::Db::connect(
            std::env::var("DATABASE_URL").ok().as_deref(),
            Default::default(),
        )
        .await
        .expect("initialize test database")
        .pool
    }

    /// Each run claims a fresh account so the shared database cannot leak a
    /// durable head between runs.
    fn unique_namespace() -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is after the unix epoch")
            .as_nanos();
        format!("postgres-account-status-{nanos}")
    }

    #[tokio::test]
    async fn postgres_adapter_satisfies_account_status_decision_table_when_configured() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let store = PgAccountStatusReplicaStore { pool };
        assert_account_status_replica_decision_table_contract(&store, &unique_namespace()).await;
    }
}
