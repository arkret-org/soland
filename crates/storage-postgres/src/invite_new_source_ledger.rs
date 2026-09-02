use arkret_wire::AccountId;
use arkret_wire::receive_policy::EffectiveNewSourceQuota;
use diesel_async::AsyncConnection;

use super::{
    BigInt, InviteNewSourceLedgerStore, NewSourceAdmission, PersistenceError, PersistenceResult,
    PgPool, PgTransactionError, QueryableByName, RunQueryDsl, Text, Timestamptz, Utc, async_trait,
    pg_conn, sql_query,
};

pub struct PgInviteNewSourceLedgerStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct CountsRow {
    #[diesel(sql_type = BigInt)]
    rate: i64,
    #[diesel(sql_type = BigInt)]
    total: i64,
}

#[derive(QueryableByName)]
struct SeenRow {
    #[diesel(sql_type = BigInt)]
    seen: i64,
}

#[async_trait]
impl InviteNewSourceLedgerStore for PgInviteNewSourceLedgerStore {
    async fn admit_new_source(
        &self,
        holder: &AccountId,
        source_digest: &str,
        now: chrono::DateTime<Utc>,
        quota: &EffectiveNewSourceQuota,
    ) -> PersistenceResult<NewSourceAdmission> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let principal_id = holder.principal_id.as_str().to_owned();
        let station_id = holder.station_id.as_str().to_owned();
        let source_digest = source_digest.to_owned();
        let quota = *quota;
        // The whole prune -> membership -> count -> append sequence runs inside
        // one transaction behind a per-holder advisory lock. Without the lock
        // two concurrent first contacts could both read an under-quota ledger
        // and both be admitted, which `consent-model.md` section 6.1.1.4
        // forbids in any interleaving.
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let lock_key = format!("invite-new-source-ledger:{principal_id}:{station_id}");
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(&lock_key)
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;

            let retention_floor = now - chrono::Duration::seconds(quota.retention_seconds as i64);
            let window_floor = now - chrono::Duration::seconds(quota.window_seconds as i64);

            // Step 1: expired rows are physically removed, so the ledger stays
            // bounded by the deployment's retention-window ceiling.
            sql_query(
                "DELETE FROM invite_new_source_ledgers l USING accounts a \
                 WHERE l.account_pk = a.pk AND a.principal_id = $1 AND a.station_id = $2 \
                 AND l.first_admitted_at <= $3",
            )
            .bind::<Text, _>(&principal_id)
            .bind::<Text, _>(&station_id)
            .bind::<Timestamptz, _>(retention_floor)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;

            // Step 2: an already-admitted source is not charged again and is
            // deliberately not re-timestamped.
            let seen = sql_query(
                "SELECT count(*) AS seen FROM invite_new_source_ledgers l \
                 JOIN accounts a ON a.pk = l.account_pk \
                 WHERE a.principal_id = $1 AND a.station_id = $2 AND l.source_digest = $3",
            )
            .bind::<Text, _>(&principal_id)
            .bind::<Text, _>(&station_id)
            .bind::<Text, _>(&source_digest)
            .get_result::<SeenRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            if seen.seen > 0 {
                return Ok(NewSourceAdmission::Seen);
            }

            // Step 3: both sliding windows are counted from the timestamps
            // themselves, so no rotating window state has to be kept.
            let counts = sql_query(
                "SELECT count(*) FILTER (WHERE l.first_admitted_at > $3) AS rate, \
                 count(*) AS total FROM invite_new_source_ledgers l \
                 JOIN accounts a ON a.pk = l.account_pk \
                 WHERE a.principal_id = $1 AND a.station_id = $2",
            )
            .bind::<Text, _>(&principal_id)
            .bind::<Text, _>(&station_id)
            .bind::<Timestamptz, _>(window_floor)
            .get_result::<CountsRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            let rate = u64::try_from(counts.rate).unwrap_or(u64::MAX);
            let total = u64::try_from(counts.total).unwrap_or(u64::MAX);
            if rate >= quota.new_sources_per_window || total >= quota.new_sources_per_retention {
                // Step 4: a denied source MUST NOT be written, or the next
                // window would treat it as already seen.
                return Ok(NewSourceAdmission::Denied);
            }

            let written = sql_query(
                "INSERT INTO invite_new_source_ledgers (account_pk, source_digest, first_admitted_at) \
                 SELECT pk, $3, $4 FROM accounts WHERE principal_id = $1 AND station_id = $2 \
                 ON CONFLICT (account_pk, source_digest) DO NOTHING",
            )
            .bind::<Text, _>(&principal_id)
            .bind::<Text, _>(&station_id)
            .bind::<Text, _>(&source_digest)
            .bind::<Timestamptz, _>(now)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            if written != 1 {
                return Err(PersistenceError::Conflict(
                    "invite new-source ledger holder account does not exist".to_owned(),
                )
                .into());
            }
            Ok(NewSourceAdmission::Admitted)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn delete_for_holder(&self, holder: &AccountId) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "DELETE FROM invite_new_source_ledgers l USING accounts a \
             WHERE l.account_pk = a.pk AND a.principal_id = $1 AND a.station_id = $2",
        )
        .bind::<Text, _>(holder.principal_id.as_str())
        .bind::<Text, _>(holder.station_id.as_str())
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn retained_source_count(&self, holder: &AccountId) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(
            "SELECT count(*) AS seen FROM invite_new_source_ledgers l \
             JOIN accounts a ON a.pk = l.account_pk \
             WHERE a.principal_id = $1 AND a.station_id = $2",
        )
        .bind::<Text, _>(holder.principal_id.as_str())
        .bind::<Text, _>(holder.station_id.as_str())
        .get_result::<SeenRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        Ok(usize::try_from(row.seen).unwrap_or(usize::MAX))
    }
}
