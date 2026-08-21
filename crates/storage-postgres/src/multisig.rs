use super::{
    Array, BTreeMap, BigInt, ClaimSeqRow, Integer, Jsonb, MultisigPendingRecord,
    MultisigPendingStore, Nullable, OptionalExtension, PersistenceError, PersistenceResult, PgPool,
    QueryableByName, RunQueryDsl, Text, Timestamptz, Value, async_trait, partials_to_jsonb,
    pg_conn, sql_query,
};
pub struct PgMultisigPendingStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct MultisigPendingRow {
    #[diesel(sql_type = Text)]
    seal_id: String,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    digest_suite: String,
    #[diesel(sql_type = Integer)]
    threshold_k: i32,
    #[diesel(sql_type = Integer)]
    threshold_n: i32,
    #[diesel(sql_type = Array<Text>)]
    members: Vec<String>,
    #[diesel(sql_type = Text)]
    canonical_b64: String,
    #[diesel(sql_type = Jsonb)]
    partials: Value,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Text>)]
    claimed_by_node_id: Option<String>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    claimed_until: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = BigInt)]
    claim_seq: i64,
}
fn multisig_pending_record(row: MultisigPendingRow) -> PersistenceResult<MultisigPendingRecord> {
    let partials = match row.partials {
        Value::Object(map) => map.into_iter().collect(),
        _ => BTreeMap::new(),
    };
    Ok(MultisigPendingRecord {
        seal_id: row.seal_id,
        realm_id: row.realm_id,
        digest_suite: arkret_canonical::digest_suite(&row.digest_suite).map_err(|error| {
            PersistenceError::Internal(format!("stored multisig digest_suite is invalid: {error}"))
        })?,
        threshold_k: row.threshold_k as u32,
        threshold_n: row.threshold_n as u32,
        members: row.members,
        canonical_b64: row.canonical_b64,
        partials,
        created_at: row.created_at,
        expires_at: row.expires_at,
        claimed_by_node_id: row.claimed_by_node_id,
        claimed_until: row.claimed_until,
        claim_seq: row.claim_seq,
    })
}
#[async_trait]
impl MultisigPendingStore for PgMultisigPendingStore {
    async fn upsert(&self, record: MultisigPendingRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        crate::realm_identity::ensure_realm_pk(&mut conn, &record.realm_id).await?;
        sql_query(
            "INSERT INTO multisig_pending \
             (seal_id, realm_id, digest_suite, threshold_k, threshold_n, members, canonical_b64, partials, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (seal_id) DO UPDATE SET \
                realm_id = EXCLUDED.realm_id, \
                digest_suite = EXCLUDED.digest_suite, \
                threshold_k = EXCLUDED.threshold_k, \
                threshold_n = EXCLUDED.threshold_n, \
                members = EXCLUDED.members, \
                canonical_b64 = EXCLUDED.canonical_b64, \
                expires_at = EXCLUDED.expires_at",
        )
        .bind::<Text, _>(&record.seal_id)
        .bind::<Text, _>(&record.realm_id)
        .bind::<Text, _>(record.digest_suite.as_str())
        .bind::<Integer, _>(record.threshold_k as i32)
        .bind::<Integer, _>(record.threshold_n as i32)
        .bind::<Array<Text>, _>(&record.members)
        .bind::<Text, _>(&record.canonical_b64)
        .bind::<Jsonb, _>(partials_to_jsonb(&record.partials))
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.expires_at)
        .execute(&mut *conn).await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn get(&self, seal_id: &str) -> PersistenceResult<Option<MultisigPendingRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(
            "SELECT seal_id, realm_id, digest_suite, threshold_k, threshold_n, members, canonical_b64, \
             partials, created_at, expires_at, claimed_by_node_id, claimed_until, claim_seq \
             FROM multisig_pending WHERE seal_id = $1",
        )
        .bind::<Text, _>(seal_id)
        .get_result::<MultisigPendingRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(multisig_pending_record).transpose()
    }

    async fn add_partial(
        &self,
        seal_id: &str,
        signer_did: &str,
        partial: Value,
    ) -> PersistenceResult<MultisigPendingRecord> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "UPDATE multisig_pending \
             SET partials = jsonb_set(partials, ARRAY[$2]::text[], $3, true) \
             WHERE seal_id = $1",
        )
        .bind::<Text, _>(seal_id)
        .bind::<Text, _>(signer_did)
        .bind::<Jsonb, _>(&partial)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        self.get(seal_id)
            .await
            .map_err(PersistenceError::database)?
            .ok_or_else(|| {
                PersistenceError::NotFound(format!("multisig_pending row {seal_id} not found"))
            })
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<MultisigPendingRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT seal_id, realm_id, digest_suite, threshold_k, threshold_n, members, canonical_b64, \
             partials, created_at, expires_at, claimed_by_node_id, claimed_until, claim_seq \
             FROM multisig_pending WHERE realm_id = $1 \
             ORDER BY created_at ASC",
        )
        .bind::<Text, _>(realm_id)
        .load::<MultisigPendingRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter().map(multisig_pending_record).collect()
    }

    async fn delete(&self, seal_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM multisig_pending WHERE seal_id = $1")
            .bind::<Text, _>(seal_id)
            .execute(&mut *conn)
            .await
            .map(|n| n > 0)
            .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MultisigPendingRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT seal_id, realm_id, digest_suite, threshold_k, threshold_n, members, canonical_b64, \
             partials, created_at, expires_at, claimed_by_node_id, claimed_until, claim_seq \
             FROM multisig_pending ORDER BY created_at ASC",
        )
        .load::<MultisigPendingRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter().map(multisig_pending_record).collect()
    }

    async fn try_claim(
        &self,
        seal_id: &str,
        node_id: &str,
        now: chrono::DateTime<chrono::Utc>,
        claimed_until: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<(bool, i64)> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        // Atomic claim: only succeed when the row is unclaimed or its
        // existing lease has expired. Bumps `claim_seq` on every
        // successful claim and `RETURNING` the new value so the watchdog
        // can use it as a fencing token for the subsequent
        // `delete_with_fence` / `renew_claim`.
        let updated: Option<ClaimSeqRow> = sql_query(
            "UPDATE multisig_pending \
             SET claimed_by_node_id = $2, claimed_until = $4, \
                 claim_seq = claim_seq + 1 \
             WHERE seal_id = $1 \
               AND (claimed_by_node_id IS NULL \
                    OR claimed_until IS NULL \
                    OR claimed_until <= $3) \
             RETURNING claim_seq",
        )
        .bind::<Text, _>(seal_id)
        .bind::<Text, _>(node_id)
        .bind::<Timestamptz, _>(now)
        .bind::<Timestamptz, _>(claimed_until)
        .get_result::<ClaimSeqRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;

        if let Some(row) = updated {
            Ok((true, row.claim_seq))
        } else {
            // No row was updated; surface the current `claim_seq` so callers
            // can log it for diagnostics. Lookup is best-effort — a missing
            // row reports `0`.
            let cur: Option<ClaimSeqRow> =
                sql_query("SELECT claim_seq FROM multisig_pending WHERE seal_id = $1")
                    .bind::<Text, _>(seal_id)
                    .get_result::<ClaimSeqRow>(&mut *conn)
                    .await
                    .optional()
                    .map_err(PersistenceError::database)?;
            Ok((false, cur.map(|r| r.claim_seq).unwrap_or(0)))
        }
    }

    async fn release_claim(&self, seal_id: &str, node_id: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "UPDATE multisig_pending \
             SET claimed_by_node_id = NULL, claimed_until = NULL \
             WHERE seal_id = $1 AND claimed_by_node_id = $2",
        )
        .bind::<Text, _>(seal_id)
        .bind::<Text, _>(node_id)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn delete_with_fence(
        &self,
        seal_id: &str,
        node_id: &str,
        claim_seq: i64,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "DELETE FROM multisig_pending \
             WHERE seal_id = $1 \
               AND claimed_by_node_id = $2 \
               AND claim_seq = $3",
        )
        .bind::<Text, _>(seal_id)
        .bind::<Text, _>(node_id)
        .bind::<BigInt, _>(claim_seq)
        .execute(&mut *conn)
        .await
        .map(|n| n > 0)
        .map_err(PersistenceError::database)
    }

    async fn renew_claim(
        &self,
        seal_id: &str,
        node_id: &str,
        claim_seq: i64,
        new_claimed_until: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "UPDATE multisig_pending \
             SET claimed_until = $4 \
             WHERE seal_id = $1 \
               AND claimed_by_node_id = $2 \
               AND claim_seq = $3",
        )
        .bind::<Text, _>(seal_id)
        .bind::<Text, _>(node_id)
        .bind::<BigInt, _>(claim_seq)
        .bind::<Timestamptz, _>(new_claimed_until)
        .execute(&mut *conn)
        .await
        .map(|n| n > 0)
        .map_err(PersistenceError::database)
    }
}
