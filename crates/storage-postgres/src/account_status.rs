use arkret_models_collaboration::account_lifecycle::{AccountStatusReceipt, AccountStatusRecord};
use arkret_models_collaboration::objects::account_status::AccountStatus;

use super::{
    AccountStatusReplicaAppend, AccountStatusReplicaConflictKind, AccountStatusReplicaStore,
    AsyncConnection, BigInt, Jsonb, OptionalExtension, PersistenceError, PersistenceResult, PgPool,
    PgTransactionError, QueryableByName, RunQueryDsl, Text, async_trait, pg_conn, sql_query,
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

/// Classifies an already transport- and proof-verified submission against the
/// durable replica head, which the account-status replica decision table
/// declares to be the only comparison baseline. Rows are evaluated top to
/// bottom and the first match wins. `None` means the submission is admitted and
/// the caller must perform the advancing write; every other outcome classifies
/// the submission with zero replica, receipt and outbox writes.
fn classify(
    record: &AccountStatusRecord,
    head: Option<&ReplicaHead>,
) -> Option<AccountStatusReplicaAppend> {
    let Some((head_record, head_receipt)) = head else {
        // genesis_gap: an absent head requires the genesis record first.
        if record.status_seq > 1 {
            return Some(AccountStatusReplicaAppend::DependencyMissing {
                current_record: None,
                required_status_seq: 1,
            });
        }
        // genesis_admission.
        return None;
    };
    // binding_version_rollback is evaluated before every sequence row so a
    // rolled-back binding can never be written by the advance branch.
    if record.binding_version < head_record.binding_version {
        return Some(conflict(
            head_record,
            AccountStatusReplicaConflictKind::BindingRollback,
        ));
    }
    if record.status_seq == head_record.status_seq + 1 {
        // fork_predecessor_mismatch, otherwise advance.
        if record.previous_account_status_record_id.as_ref()
            != Some(&head_record.account_status_record_id)
        {
            return Some(conflict(
                head_record,
                AccountStatusReplicaConflictKind::Fork,
            ));
        }
        return admission_conflict(record, head_record).map(|kind| conflict(head_record, kind));
    }
    if record.status_seq == head_record.status_seq {
        // duplicate is the terminal ack only when the head already is the
        // submitted record; a different record at the head sequence forks.
        return Some(
            if record.account_status_record_id == head_record.account_status_record_id {
                AccountStatusReplicaAppend::Duplicate(head_receipt.clone())
            } else {
                conflict(head_record, AccountStatusReplicaConflictKind::Fork)
            },
        );
    }
    if record.status_seq < head_record.status_seq {
        // stale is unconditional. How much history this receiver still retains
        // for the submitted sequence is a local retention decision and must not
        // turn a below-head submission into a duplicate.
        return Some(AccountStatusReplicaAppend::Stale {
            current_record: head_record.clone(),
        });
    }
    // sequence_gap.
    Some(AccountStatusReplicaAppend::DependencyMissing {
        current_record: Some(head_record.clone()),
        required_status_seq: head_record.status_seq + 1,
    })
}

fn conflict(
    head: &AccountStatusRecord,
    kind: AccountStatusReplicaConflictKind,
) -> AccountStatusReplicaAppend {
    AccountStatusReplicaAppend::Conflict {
        current_record: Some(head.clone()),
        kind,
    }
}

/// Admission guards that refine the `advance` row: the submission is the exact
/// successor of the head, and these checks reject a successor whose binding or
/// status transition the receiver must not durably record.
fn admission_conflict(
    record: &AccountStatusRecord,
    head: &AccountStatusRecord,
) -> Option<AccountStatusReplicaConflictKind> {
    if record.binding_version == head.binding_version
        && (record.principal_authority != head.principal_authority
            || record.principal_control_realm_id != head.principal_control_realm_id)
    {
        return Some(AccountStatusReplicaConflictKind::Fork);
    }
    if head.status == AccountStatus::ErasurePending {
        return Some(AccountStatusReplicaConflictKind::ErasurePendingTerminal);
    }
    (!head.status.can_transition_to(record.status))
        .then_some(AccountStatusReplicaConflictKind::TransitionInvalid)
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
            let account = record.account_id.to_string();
            let lock_key = format!("account-status:{authority}:{account}");
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
            .bind::<Text, _>(&account)
            .get_result::<RecordRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
            .map(|row| -> PersistenceResult<ReplicaHead> {
                Ok((decode_record(&row)?, decode_receipt(&row)?))
            })
            .transpose()?;

            if let Some(outcome) = classify(&record, head.as_ref()) {
                return Ok(outcome);
            }

            sql_query(
                "INSERT INTO account_status_replica_records \
                 (account_authority_id, account_id, status_seq, record_id, record, receipt) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind::<Text, _>(&authority)
            .bind::<Text, _>(&account)
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
        account_id: &str,
    ) -> PersistenceResult<Option<AccountStatusRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT record, receipt FROM account_status_replica_records \
             WHERE account_authority_id = $1 AND account_id = $2 \
             ORDER BY status_seq DESC LIMIT 1",
        )
        .bind::<Text, _>(account_authority_id)
        .bind::<Text, _>(account_id)
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
        account_id: &str,
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
        .bind::<Text, _>(account_id)
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
        account_id: &str,
        status_seq: u64,
    ) -> PersistenceResult<Option<AccountStatusReceipt>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT record, receipt FROM account_status_replica_records \
             WHERE account_authority_id = $1 AND account_id = $2 AND status_seq = $3",
        )
        .bind::<Text, _>(account_authority_id)
        .bind::<Text, _>(account_id)
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
