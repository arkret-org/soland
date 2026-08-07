use diesel_async::AsyncConnection;

use super::{
    BigInt, Binary, Bool, Jsonb, MlsCommitEpochAdvance, MlsCommitEpochRecord, MlsCommitGenesis,
    MlsCommitStore, MlsKeyPackageClaim, MlsKeyPackageClaimTarget, MlsKeyPackageRow,
    MlsKeyPackageStore, MlsWelcomeRecord, MlsWelcomeStore, Nullable, OptionalExtension,
    PeerKeyPackageClaimAttempt, PeerKeyPackageClaimAttemptResult, PeerKeyPackageClaimLedgerRecord,
    PeerKeyPackageClaimLedgerWriteResult, PersistenceError, PersistenceResult, PgPool,
    PgTransactionError, QueryableByName, RunQueryDsl, SqlUuid, Text, Uuid, Value, async_trait,
    db_ssk_generation, json_string_array, mls_effective_scope_parts, pg_conn, sql_query,
};
pub struct PgMlsKeyPackageStore {
    pub pool: PgPool,
}
pub struct PgMlsWelcomeStore {
    pub pool: PgPool,
}
pub struct PgMlsCommitStore {
    pub pool: PgPool,
}
#[async_trait]
impl MlsKeyPackageStore for PgMlsKeyPackageStore {
    async fn put(&self, record: &MlsKeyPackageRow) -> PersistenceResult<bool> {
        record.lifecycle().map_err(|error| {
            PersistenceError::SchemaViolation(format!(
                "invalid MLS KeyPackage lifecycle before insert: {error}"
            ))
        })?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let ssk_generation = db_ssk_generation(record.ssk_generation)?;
        let inserted = sql_query(
            "INSERT INTO mls_key_packages \
             (id, keypackage_ref, keypackage_digest, actor_id, device_id, key_package_bytes, \
              capabilities, capabilities_digest, device_signature, last_resort, \
              last_resort_realm_id, lifetime_not_before, lifetime_not_after, \
              claimed_by_mls_group_id, ssk_generation, device_authorize_event_id, agent_key_authorize_event_id, claimed_at, \
              claim_expires_at_unix_ms, consumed_at, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<Text, _>(&record.id)
        .bind::<Text, _>(&record.keypackage_ref)
        .bind::<Text, _>(&record.keypackage_digest)
        .bind::<Text, _>(&record.actor_id)
        .bind::<Text, _>(&record.device_id)
        .bind::<Binary, _>(&record.key_package_bytes)
        .bind::<Jsonb, _>(serde_json::json!(record.capabilities))
        .bind::<Text, _>(&record.capabilities_digest)
        .bind::<Jsonb, _>(&record.device_signature)
        .bind::<Bool, _>(record.last_resort)
        .bind::<Nullable<Text>, _>(&record.last_resort_realm_id)
        .bind::<BigInt, _>(record.lifetime_not_before)
        .bind::<BigInt, _>(record.lifetime_not_after)
        .bind::<Nullable<Text>, _>(&record.claimed_by_mls_group_id)
        .bind::<Nullable<BigInt>, _>(ssk_generation)
        .bind::<Nullable<Text>, _>(&record.device_authorize_event_id)
        .bind::<Nullable<Text>, _>(&record.agent_key_authorize_event_id)
        .bind::<Nullable<BigInt>, _>(record.claimed_at)
        .bind::<Nullable<BigInt>, _>(record.claim_expires_at_unix_ms)
        .bind::<Nullable<BigInt>, _>(record.consumed_at)
        .bind::<BigInt, _>(record.created_at)
        .execute(&mut *conn)
        .await.map_err(PersistenceError::database)?;
        Ok(inserted > 0)
    }

    async fn get(&self, id: &str) -> PersistenceResult<Option<MlsKeyPackageRow>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id, keypackage_ref, keypackage_digest, actor_id, device_id, \
             key_package_bytes, capabilities, capabilities_digest, device_signature, \
             last_resort, last_resort_realm_id, lifetime_not_before, lifetime_not_after, \
             claimed_by_mls_group_id, ssk_generation, device_authorize_event_id, agent_key_authorize_event_id, claimed_at, \
             claim_expires_at_unix_ms, consumed_at, created_at \
             FROM mls_key_packages WHERE id = $1",
        )
        .bind::<Text, _>(id)
        .get_result::<MlsKeyPackagePgRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(validated_keypackage_row)
        .transpose()
    }

    async fn get_by_ref(
        &self,
        keypackage_ref: &str,
    ) -> PersistenceResult<Option<MlsKeyPackageRow>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id, keypackage_ref, keypackage_digest, actor_id, device_id, \
             key_package_bytes, capabilities, capabilities_digest, device_signature, \
             last_resort, last_resort_realm_id, lifetime_not_before, lifetime_not_after, \
             claimed_by_mls_group_id, ssk_generation, device_authorize_event_id, agent_key_authorize_event_id, claimed_at, \
             claim_expires_at_unix_ms, consumed_at, created_at \
             FROM mls_key_packages WHERE keypackage_ref = $1",
        )
        .bind::<Text, _>(keypackage_ref)
        .get_result::<MlsKeyPackagePgRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(validated_keypackage_row)
        .transpose()
    }

    async fn try_claim(
        &self,
        claim: MlsKeyPackageClaim<'_>,
    ) -> PersistenceResult<Option<MlsKeyPackageRow>> {
        let MlsKeyPackageClaim {
            id,
            target,
            intended_realm_id,
            ssk_generation,
            device_authorize_event_id,
            agent_key_authorize_event_id,
            claimed_at,
            claim_expires_at_unix_ms,
        } = claim;
        const REVOKED_CLAIM_SENTINEL: &str = "revoked";
        let group_id = match target {
            MlsKeyPackageClaimTarget::Group(group_id) => group_id,
            MlsKeyPackageClaimTarget::Retire => "retired",
            MlsKeyPackageClaimTarget::Revoke => REVOKED_CLAIM_SENTINEL,
        };
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let ssk_generation = db_ssk_generation(ssk_generation)?;
        sql_query(
            "UPDATE mls_key_packages \
             SET claimed_by_mls_group_id = CASE WHEN last_resort AND $2 NOT IN ('revoked', 'retired') THEN claimed_by_mls_group_id ELSE $2 END, \
                 last_resort_realm_id = CASE WHEN last_resort AND $2 NOT IN ('revoked', 'retired') THEN COALESCE(last_resort_realm_id, $3) ELSE last_resort_realm_id END, \
                 ssk_generation = COALESCE($4, ssk_generation), \
                 device_authorize_event_id = COALESCE($5, device_authorize_event_id), \
                 agent_key_authorize_event_id = COALESCE($6, agent_key_authorize_event_id), \
                 claimed_at = CASE WHEN $2 IN ('revoked', 'retired') THEN NULL WHEN last_resort THEN claimed_at ELSE $7 END, \
                 claim_expires_at_unix_ms = CASE WHEN $2 IN ('revoked', 'retired') THEN NULL WHEN last_resort THEN claim_expires_at_unix_ms ELSE $8 END, \
                 consumed_at = NULL \
             WHERE id = $1 \
               AND (claimed_by_mls_group_id IS NULL OR claimed_by_mls_group_id NOT IN ('revoked', 'retired')) \
               AND (($2 = 'retired' AND NOT last_resort AND claimed_by_mls_group_id IS NULL) \
                    OR ($2 <> 'retired' AND (claimed_by_mls_group_id IS NULL \
                    OR claimed_by_mls_group_id = $2 \
                    OR (last_resort AND $2 <> 'revoked')))) \
               AND ($4 IS NULL OR ssk_generation = $4) \
               AND ($5 IS NULL OR device_authorize_event_id = $5) \
               AND ($6 IS NULL OR agent_key_authorize_event_id = $6) \
               AND ($2 IN ('revoked', 'retired') OR (lifetime_not_after > $7 \
                    AND ($8 IS NULL OR ($8 > $7 * 1000 AND $8 <= lifetime_not_after * 1000)))) \
               AND ((NOT last_resort) OR $2 = 'revoked' OR (last_resort_realm_id IS NULL AND $3 IS NOT NULL) OR last_resort_realm_id = $3) \
             RETURNING id, keypackage_ref, keypackage_digest, actor_id, device_id, \
             key_package_bytes, capabilities, capabilities_digest, device_signature, \
             last_resort, last_resort_realm_id, lifetime_not_before, lifetime_not_after, \
             claimed_by_mls_group_id, ssk_generation, device_authorize_event_id, agent_key_authorize_event_id, claimed_at, \
             claim_expires_at_unix_ms, consumed_at, created_at",
        )
        .bind::<Text, _>(id)
        .bind::<Text, _>(group_id)
        .bind::<Nullable<Text>, _>(intended_realm_id)
        .bind::<Nullable<BigInt>, _>(ssk_generation)
        .bind::<Nullable<Text>, _>(device_authorize_event_id)
        .bind::<Nullable<Text>, _>(agent_key_authorize_event_id)
        .bind::<BigInt, _>(claimed_at)
        .bind::<Nullable<BigInt>, _>(claim_expires_at_unix_ms)
        .get_result::<MlsKeyPackagePgRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(validated_keypackage_row)
        .transpose()
    }

    async fn consume_claim(
        &self,
        id: &str,
        mls_group_id: &str,
        consumed_at: i64,
        peer_consume_receipt: Option<&Value>,
    ) -> PersistenceResult<Option<MlsKeyPackageRow>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let row = sql_query(
                "UPDATE mls_key_packages \
             SET consumed_at = $3 \
             WHERE id = $1 AND NOT last_resort \
               AND claimed_by_mls_group_id = $2 \
               AND consumed_at IS NULL \
               AND (claim_expires_at_unix_ms IS NULL OR claim_expires_at_unix_ms > $3 * 1000) \
             RETURNING id, keypackage_ref, keypackage_digest, actor_id, device_id, \
             key_package_bytes, capabilities, capabilities_digest, device_signature, \
             last_resort, last_resort_realm_id, lifetime_not_before, lifetime_not_after, \
             claimed_by_mls_group_id, ssk_generation, device_authorize_event_id, agent_key_authorize_event_id, claimed_at, \
             claim_expires_at_unix_ms, consumed_at, created_at",
                )
                .bind::<Text, _>(id)
                .bind::<Text, _>(mls_group_id)
                .bind::<BigInt, _>(consumed_at)
                .get_result::<MlsKeyPackagePgRow>(conn)
                .await
                .optional()
                .map_err(PersistenceError::database)?;
            let Some(row) = row else {
                return Ok(None);
            };
            if let Some(receipt) = peer_consume_receipt {
                let updated = sql_query(
                    "UPDATE peer_keypackage_claims \
                     SET state = 'consumed', consume_receipt = $2, updated_at = $3 \
                     WHERE keypackage_id = $1 AND state = 'claimed'",
                )
                .bind::<Text, _>(id)
                .bind::<Jsonb, _>(receipt)
                .bind::<BigInt, _>(consumed_at)
                .execute(conn)
                .await
                .map_err(PersistenceError::database)?;
                if updated > 1 {
                    return Err(PersistenceError::Internal(
                        "multiple peer claim ledgers reference one KeyPackage".to_owned(),
                    )
                    .into());
                }
            }
            Ok(Some(validated_keypackage_row(row)?))
        })
        .await
        .map_err(|error| error.into_persistence())
    }

    async fn get_peer_claim(
        &self,
        source_service_id: &str,
        claim_request_id: &str,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        load_peer_claim(&mut conn, source_service_id, claim_request_id).await
    }

    async fn try_claim_peer(
        &self,
        attempt: PeerKeyPackageClaimAttempt<'_>,
    ) -> PersistenceResult<PeerKeyPackageClaimAttemptResult> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let ssk_generation = db_ssk_generation(attempt.ssk_generation)?;
        let source_service_id = attempt.ledger.source_service_id.clone();
        let claim_request_id = attempt.ledger.claim_request_id.clone();
        let result = conn
            .transaction::<_, PgTransactionError, _>(async move |conn| {
                if let Some(existing) = load_peer_claim(
                    conn,
                    &attempt.ledger.source_service_id,
                    &attempt.ledger.claim_request_id,
                )
                .await?
                {
                    return Ok(PeerKeyPackageClaimAttemptResult::Existing(Box::new(existing)));
                }
                let claimed = sql_query(
                    "UPDATE mls_key_packages \
                 SET claimed_by_mls_group_id = $2, claimed_at = $6, claim_expires_at_unix_ms = $7, consumed_at = NULL \
                 WHERE id = $1 \
                   AND NOT last_resort \
                   AND claimed_by_mls_group_id IS NULL \
                   AND ($3 IS NULL OR ssk_generation = $3) \
                   AND ($4 IS NULL OR device_authorize_event_id = $4) \
                   AND ($5 IS NULL OR agent_key_authorize_event_id = $5) \
                   AND lifetime_not_after > $6 \
                   AND $7 > $6 * 1000 AND $7 <= lifetime_not_after * 1000 \
                 RETURNING id, keypackage_ref, keypackage_digest, actor_id, device_id, \
                 key_package_bytes, capabilities, capabilities_digest, device_signature, \
                 last_resort, last_resort_realm_id, lifetime_not_before, lifetime_not_after, \
                 claimed_by_mls_group_id, ssk_generation, device_authorize_event_id, agent_key_authorize_event_id, claimed_at, \
                 claim_expires_at_unix_ms, consumed_at, created_at",
                )
                .bind::<Text, _>(attempt.keypackage_id)
                .bind::<Text, _>(attempt.mls_group_id)
                .bind::<Nullable<BigInt>, _>(ssk_generation)
                .bind::<Nullable<Text>, _>(attempt.device_authorize_event_id)
                .bind::<Nullable<Text>, _>(attempt.agent_key_authorize_event_id)
                .bind::<BigInt, _>(attempt.claimed_at)
                .bind::<BigInt, _>(attempt.claim_expires_at_unix_ms)
                .get_result::<MlsKeyPackagePgRow>(conn)
                .await
                .optional()
                .map_err(PersistenceError::database)?;
                let Some(claimed) = claimed else {
                    return Ok(PeerKeyPackageClaimAttemptResult::KeyPackageUnavailable);
                };
                insert_peer_claim_strict(conn, attempt.ledger).await?;
                Ok(PeerKeyPackageClaimAttemptResult::Claimed(Box::new(
                    validated_keypackage_row(claimed)?,
                )))
            })
            .await;
        match result {
            Ok(result) => Ok(result),
            Err(error) => {
                if let Some(existing) = self
                    .get_peer_claim(&source_service_id, &claim_request_id)
                    .await?
                {
                    Ok(PeerKeyPackageClaimAttemptResult::Existing(Box::new(
                        existing,
                    )))
                } else {
                    Err(error.into_persistence())
                }
            }
        }
    }

    async fn record_peer_claim_terminal(
        &self,
        record: &PeerKeyPackageClaimLedgerRecord,
    ) -> PersistenceResult<PeerKeyPackageClaimLedgerWriteResult> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let inserted = insert_peer_claim(&mut conn, record)
            .await
            .map_err(PersistenceError::database)?;
        if inserted > 0 {
            return Ok(PeerKeyPackageClaimLedgerWriteResult::Inserted);
        }
        let existing = load_peer_claim(
            &mut conn,
            &record.source_service_id,
            &record.claim_request_id,
        )
        .await?
        .ok_or_else(|| {
            PersistenceError::Internal(
                "peer KeyPackage claim ledger conflict row disappeared".to_owned(),
            )
        })?;
        Ok(PeerKeyPackageClaimLedgerWriteResult::Existing(Box::new(
            existing,
        )))
    }

    async fn attach_peer_claim_terminal_receipt(
        &self,
        source_service_id: &str,
        claim_request_id: &str,
        request_digest: &str,
        terminal_receipt: &Value,
        updated_at: i64,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "UPDATE peer_keypackage_claims \
             SET terminal_receipt = $4, updated_at = $5 \
             WHERE source_service_id = $1 AND claim_request_id = $2 \
               AND request_digest = $3 AND state IN ('expired', 'revoked') \
             RETURNING source_service_id, claim_request_id, request_digest, keypackage_id, \
               outcome, terminal_receipt, consume_receipt, claim_expires_at_unix_ms, \
               expires_at, state, updated_at",
        )
        .bind::<Text, _>(source_service_id)
        .bind::<Text, _>(claim_request_id)
        .bind::<Text, _>(request_digest)
        .bind::<Jsonb, _>(terminal_receipt)
        .bind::<BigInt, _>(updated_at)
        .get_result::<PeerKeyPackageClaimPgRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(PeerKeyPackageClaimLedgerRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn revoke_expired_peer_claims(&self, now_unix_ms: i64) -> PersistenceResult<Vec<String>> {
        #[derive(QueryableByName)]
        struct RevokedKeyPackageId {
            #[diesel(sql_type = Text)]
            id: String,
        }

        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let rows = sql_query(
                "WITH expired AS ( \
                   SELECT source_service_id, claim_request_id, keypackage_id \
                   FROM peer_keypackage_claims \
                   WHERE state = 'claimed' AND claim_expires_at_unix_ms <= $1 \
                 ), revoked AS ( \
                   UPDATE mls_key_packages kp \
                   SET claimed_by_mls_group_id = 'revoked', \
                       claimed_at = NULL, \
                       claim_expires_at_unix_ms = NULL \
                   FROM expired e \
                   WHERE kp.id = e.keypackage_id AND kp.consumed_at IS NULL \
                     AND kp.claimed_by_mls_group_id <> 'revoked' \
                   RETURNING kp.id \
                 ) \
                 UPDATE peer_keypackage_claims ledger \
                 SET state = 'revoked', updated_at = $1 / 1000 \
                 FROM expired e, revoked r \
                 WHERE ledger.source_service_id = e.source_service_id \
                   AND ledger.claim_request_id = e.claim_request_id \
                   AND e.keypackage_id = r.id \
                 RETURNING r.id",
            )
            .bind::<BigInt, _>(now_unix_ms)
            .load::<RevokedKeyPackageId>(conn)
            .await
            .map_err(PersistenceError::database)?;
            Ok(rows.into_iter().map(|row| row.id).collect())
        })
        .await
        .map_err(|error| error.into_persistence())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MlsKeyPackageRow>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id, keypackage_ref, keypackage_digest, actor_id, device_id, \
             key_package_bytes, capabilities, capabilities_digest, device_signature, \
             last_resort, last_resort_realm_id, lifetime_not_before, lifetime_not_after, \
             claimed_by_mls_group_id, ssk_generation, device_authorize_event_id, agent_key_authorize_event_id, claimed_at, \
             claim_expires_at_unix_ms, consumed_at, created_at \
             FROM mls_key_packages ORDER BY created_at ASC, id ASC",
        )
        .load::<MlsKeyPackagePgRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(validated_keypackage_row)
        .collect()
    }

    async fn list_claimed_by_group(
        &self,
        mls_group_id: &str,
    ) -> PersistenceResult<Vec<MlsKeyPackageRow>> {
        if matches!(mls_group_id, "revoked" | "retired") {
            return Ok(Vec::new());
        }
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id, keypackage_ref, keypackage_digest, actor_id, device_id, \
             key_package_bytes, capabilities, capabilities_digest, device_signature, \
             last_resort, last_resort_realm_id, lifetime_not_before, lifetime_not_after, \
             claimed_by_mls_group_id, ssk_generation, device_authorize_event_id, agent_key_authorize_event_id, claimed_at, \
             claim_expires_at_unix_ms, consumed_at, created_at \
             FROM mls_key_packages WHERE claimed_by_mls_group_id = $1 \
             ORDER BY claimed_at ASC NULLS FIRST, id ASC",
        )
        .bind::<Text, _>(mls_group_id)
        .load::<MlsKeyPackagePgRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(validated_keypackage_row)
        .collect()
    }
}

async fn insert_peer_claim(
    conn: &mut diesel_async::AsyncPgConnection,
    record: &PeerKeyPackageClaimLedgerRecord,
) -> Result<usize, diesel::result::Error> {
    sql_query(
        "INSERT INTO peer_keypackage_claims \
         (source_service_id, claim_request_id, request_digest, keypackage_id, outcome, terminal_receipt, consume_receipt, claim_expires_at_unix_ms, expires_at, state, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
         ON CONFLICT (source_service_id, claim_request_id) DO NOTHING",
    )
    .bind::<Text, _>(&record.source_service_id)
    .bind::<Text, _>(&record.claim_request_id)
    .bind::<Text, _>(&record.request_digest)
    .bind::<Nullable<Text>, _>(&record.keypackage_id)
    .bind::<Nullable<Jsonb>, _>(&record.outcome)
    .bind::<Nullable<Jsonb>, _>(&record.terminal_receipt)
    .bind::<Nullable<Jsonb>, _>(&record.consume_receipt)
    .bind::<Nullable<BigInt>, _>(record.claim_expires_at_unix_ms)
    .bind::<BigInt, _>(record.expires_at)
    .bind::<Text, _>(&record.state)
    .bind::<BigInt, _>(record.updated_at)
    .execute(conn)
    .await
}

async fn insert_peer_claim_strict(
    conn: &mut diesel_async::AsyncPgConnection,
    record: &PeerKeyPackageClaimLedgerRecord,
) -> Result<(), diesel::result::Error> {
    sql_query(
        "INSERT INTO peer_keypackage_claims \
         (source_service_id, claim_request_id, request_digest, keypackage_id, outcome, terminal_receipt, consume_receipt, claim_expires_at_unix_ms, expires_at, state, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind::<Text, _>(&record.source_service_id)
    .bind::<Text, _>(&record.claim_request_id)
    .bind::<Text, _>(&record.request_digest)
    .bind::<Nullable<Text>, _>(&record.keypackage_id)
    .bind::<Nullable<Jsonb>, _>(&record.outcome)
    .bind::<Nullable<Jsonb>, _>(&record.terminal_receipt)
    .bind::<Nullable<Jsonb>, _>(&record.consume_receipt)
    .bind::<Nullable<BigInt>, _>(record.claim_expires_at_unix_ms)
    .bind::<BigInt, _>(record.expires_at)
    .bind::<Text, _>(&record.state)
    .bind::<BigInt, _>(record.updated_at)
    .execute(conn)
    .await
    .map(|_| ())
}

async fn load_peer_claim(
    conn: &mut diesel_async::AsyncPgConnection,
    source_service_id: &str,
    claim_request_id: &str,
) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>> {
    sql_query(
        "SELECT source_service_id, claim_request_id, request_digest, keypackage_id, outcome, terminal_receipt, consume_receipt, claim_expires_at_unix_ms, expires_at, state, updated_at \
         FROM peer_keypackage_claims \
         WHERE source_service_id = $1 AND claim_request_id = $2",
    )
    .bind::<Text, _>(source_service_id)
    .bind::<Text, _>(claim_request_id)
    .get_result::<PeerKeyPackageClaimPgRow>(conn)
    .await
    .optional()
    .map(|row| row.map(PeerKeyPackageClaimLedgerRecord::from))
    .map_err(PersistenceError::database)
}
#[async_trait]
impl MlsWelcomeStore for PgMlsWelcomeStore {
    async fn enqueue(&self, record: &MlsWelcomeRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO mls_welcomes \
             (id, mls_group_id, recipient_actor_id, recipient_device_id, welcome_bytes, \
              key_package_id, epoch, commit_ref, governance_binding, enqueued_at, delivered_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<Text, _>(&record.id)
        .bind::<Text, _>(&record.group_id)
        .bind::<Text, _>(&record.recipient_actor_id)
        .bind::<Text, _>(&record.recipient_device_id)
        .bind::<Binary, _>(&record.welcome_bytes)
        .bind::<Text, _>(&record.key_package_id)
        .bind::<BigInt, _>(
            i64::try_from(record.epoch).map_err(|_| {
                PersistenceError::Internal("MLS Welcome epoch exceeds i64".to_owned())
            })?,
        )
        .bind::<Nullable<Text>, _>(&record.commit_ref)
        .bind::<Jsonb, _>(&record.governance_binding)
        .bind::<BigInt, _>(record.enqueued_at)
        .bind::<Nullable<BigInt>, _>(record.delivered_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        Ok(())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MlsWelcomeRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id, mls_group_id, recipient_actor_id, recipient_device_id, welcome_bytes, \
             key_package_id, epoch, commit_ref, governance_binding, enqueued_at, delivered_at \
             FROM mls_welcomes ORDER BY enqueued_at ASC, id ASC",
        )
        .load::<MlsWelcomeRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(MlsWelcomeRecord::from).collect())
        .map_err(PersistenceError::database)
    }
}
#[async_trait]
impl MlsCommitStore for PgMlsCommitStore {
    async fn get(
        &self,
        effective_scope: &Value,
        group_id: &str,
    ) -> PersistenceResult<Option<MlsCommitEpochRecord>> {
        let scope = mls_effective_scope_parts(effective_scope)?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id, mls_group_id, effective_scope, epoch, leader_actor_id, creator_device_id, \
             genesis_event_ref, governance_binding, accepted_commit_ref, committed_at, frontier_contested \
             FROM mls_commits \
             WHERE effective_scope_kind = $1 \
               AND realm_id = $2 \
               AND circle_id IS NOT DISTINCT FROM $3 \
               AND mls_group_id = $4",
        )
        .bind::<Text, _>(&scope.kind)
        .bind::<Text, _>(&scope.realm_id)
        .bind::<Nullable<Text>, _>(&scope.circle_id)
        .bind::<Text, _>(group_id)
        .get_result::<MlsCommitEpochRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(MlsCommitEpochRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn initialize_genesis(
        &self,
        genesis: MlsCommitGenesis<'_>,
    ) -> PersistenceResult<Option<MlsCommitEpochRecord>> {
        let MlsCommitGenesis {
            effective_scope,
            group_id,
            leader_actor_id,
            creator_device_id,
            genesis_event_ref,
            governance_binding,
            committed_at,
        } = genesis;
        let scope = mls_effective_scope_parts(effective_scope)?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO mls_commits \
             (id, effective_scope_kind, realm_id, circle_id, effective_scope, mls_group_id, epoch, leader_actor_id, creator_device_id, genesis_event_ref, governance_binding, accepted_commit_ref, committed_at, frontier_contested) \
             VALUES ($1, $2, $3, $4, $5, $6, 0, $7, $8, $9, $10, NULL, $11, false) \
             ON CONFLICT DO NOTHING \
             RETURNING id, mls_group_id, effective_scope, epoch, leader_actor_id, creator_device_id, genesis_event_ref, governance_binding, accepted_commit_ref, committed_at, frontier_contested",
        )
        .bind::<SqlUuid, _>(Uuid::now_v7())
        .bind::<Text, _>(&scope.kind)
        .bind::<Text, _>(&scope.realm_id)
        .bind::<Nullable<Text>, _>(&scope.circle_id)
        .bind::<Jsonb, _>(effective_scope)
        .bind::<Text, _>(group_id)
        .bind::<Text, _>(leader_actor_id)
        .bind::<Text, _>(creator_device_id)
        .bind::<Text, _>(genesis_event_ref)
        .bind::<Jsonb, _>(governance_binding)
        .bind::<BigInt, _>(committed_at)
        .get_result::<MlsCommitEpochRow>(&mut *conn).await
        .optional()
        .map(|row| row.map(MlsCommitEpochRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn try_bump(
        &self,
        expected_prev_epoch: u64,
        advance: MlsCommitEpochAdvance<'_>,
    ) -> PersistenceResult<Option<MlsCommitEpochRecord>> {
        let scope = mls_effective_scope_parts(advance.effective_scope)?;
        let expected_epoch = i64::try_from(expected_prev_epoch)
            .map_err(|_| PersistenceError::Internal("MLS epoch exceeds i64".to_owned()))?;
        let next_epoch = expected_prev_epoch
            .checked_add(1)
            .and_then(|epoch| i64::try_from(epoch).ok())
            .ok_or_else(|| PersistenceError::Internal("MLS epoch overflow".to_owned()))?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "UPDATE mls_commits SET \
               epoch = $6, \
               leader_actor_id = $7, \
                governance_binding = $8, \
                accepted_commit_ref = $9, \
                committed_at = $10, \
               frontier_contested = false \
             WHERE effective_scope_kind = $1 \
               AND realm_id = $2 \
               AND circle_id IS NOT DISTINCT FROM $3 \
               AND mls_group_id = $4 \
               AND epoch = $5 \
              RETURNING id, mls_group_id, effective_scope, epoch, leader_actor_id, creator_device_id, genesis_event_ref, governance_binding, accepted_commit_ref, committed_at, frontier_contested",
        )
        .bind::<Text, _>(&scope.kind)
        .bind::<Text, _>(&scope.realm_id)
        .bind::<Nullable<Text>, _>(&scope.circle_id)
        .bind::<Text, _>(advance.group_id)
        .bind::<BigInt, _>(expected_epoch)
        .bind::<BigInt, _>(next_epoch)
        .bind::<Text, _>(advance.leader_actor_id)
        .bind::<Jsonb, _>(advance.governance_binding)
        .bind::<Text, _>(advance.accepted_commit_ref)
        .bind::<BigInt, _>(advance.committed_at)
        .get_result::<MlsCommitEpochRow>(&mut *conn).await
        .optional()
        .map(|row| row.map(MlsCommitEpochRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn mark_frontier_contested(
        &self,
        effective_scope: &Value,
        group_id: &str,
        epoch: u64,
    ) -> PersistenceResult<Option<MlsCommitEpochRecord>> {
        let scope = mls_effective_scope_parts(effective_scope)?;
        let epoch = i64::try_from(epoch)
            .map_err(|_| PersistenceError::Internal("MLS epoch exceeds i64".to_owned()))?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "UPDATE mls_commits SET frontier_contested = true \
             WHERE effective_scope_kind = $1 \
               AND realm_id = $2 \
               AND circle_id IS NOT DISTINCT FROM $3 \
               AND mls_group_id = $4 \
               AND epoch = $5 \
              RETURNING id, mls_group_id, effective_scope, epoch, leader_actor_id, creator_device_id, genesis_event_ref, governance_binding, accepted_commit_ref, committed_at, frontier_contested",
        )
        .bind::<Text, _>(&scope.kind)
        .bind::<Text, _>(&scope.realm_id)
        .bind::<Nullable<Text>, _>(&scope.circle_id)
        .bind::<Text, _>(group_id)
        .bind::<BigInt, _>(epoch)
        .get_result::<MlsCommitEpochRow>(&mut *conn).await
        .optional()
        .map(|row| row.map(MlsCommitEpochRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MlsCommitEpochRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id, mls_group_id, effective_scope, epoch, leader_actor_id, creator_device_id, genesis_event_ref, governance_binding, accepted_commit_ref, committed_at, frontier_contested \
             FROM mls_commits ORDER BY effective_scope_kind ASC, realm_id ASC, circle_id ASC, mls_group_id ASC",
        )
        .load::<MlsCommitEpochRow>(&mut *conn).await
        .map(|rows| rows.into_iter().map(MlsCommitEpochRecord::from).collect())
        .map_err(PersistenceError::database)
    }
}
#[derive(QueryableByName)]
struct MlsKeyPackagePgRow {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Text)]
    keypackage_ref: String,
    #[diesel(sql_type = Text)]
    keypackage_digest: String,
    #[diesel(sql_type = Text)]
    actor_id: String,
    #[diesel(sql_type = Text)]
    device_id: String,
    #[diesel(sql_type = Binary)]
    key_package_bytes: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    capabilities: Value,
    #[diesel(sql_type = Text)]
    capabilities_digest: String,
    #[diesel(sql_type = Jsonb)]
    device_signature: Value,
    #[diesel(sql_type = Bool)]
    last_resort: bool,
    #[diesel(sql_type = Nullable<Text>)]
    last_resort_realm_id: Option<String>,
    #[diesel(sql_type = BigInt)]
    lifetime_not_before: i64,
    #[diesel(sql_type = BigInt)]
    lifetime_not_after: i64,
    #[diesel(sql_type = Nullable<Text>)]
    claimed_by_mls_group_id: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    ssk_generation: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    device_authorize_event_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    agent_key_authorize_event_id: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    claimed_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    claim_expires_at_unix_ms: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    consumed_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    created_at: i64,
}

#[derive(QueryableByName)]
struct PeerKeyPackageClaimPgRow {
    #[diesel(sql_type = Text)]
    source_service_id: String,
    #[diesel(sql_type = Text)]
    claim_request_id: String,
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = Nullable<Text>)]
    keypackage_id: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    outcome: Option<Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    terminal_receipt: Option<Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    consume_receipt: Option<Value>,
    #[diesel(sql_type = Nullable<BigInt>)]
    claim_expires_at_unix_ms: Option<i64>,
    #[diesel(sql_type = BigInt)]
    expires_at: i64,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = BigInt)]
    updated_at: i64,
}

impl From<PeerKeyPackageClaimPgRow> for PeerKeyPackageClaimLedgerRecord {
    fn from(row: PeerKeyPackageClaimPgRow) -> Self {
        Self {
            source_service_id: row.source_service_id,
            claim_request_id: row.claim_request_id,
            request_digest: row.request_digest,
            keypackage_id: row.keypackage_id,
            outcome: row.outcome,
            terminal_receipt: row.terminal_receipt,
            consume_receipt: row.consume_receipt,
            claim_expires_at_unix_ms: row.claim_expires_at_unix_ms,
            expires_at: row.expires_at,
            state: row.state,
            updated_at: row.updated_at,
        }
    }
}
impl From<MlsKeyPackagePgRow> for MlsKeyPackageRow {
    fn from(row: MlsKeyPackagePgRow) -> Self {
        Self {
            id: row.id,
            keypackage_ref: row.keypackage_ref,
            keypackage_digest: row.keypackage_digest,
            actor_id: row.actor_id,
            device_id: row.device_id,
            key_package_bytes: row.key_package_bytes,
            capabilities: json_string_array(row.capabilities),
            capabilities_digest: row.capabilities_digest,
            device_signature: row.device_signature,
            last_resort: row.last_resort,
            last_resort_realm_id: row.last_resort_realm_id,
            lifetime_not_before: row.lifetime_not_before,
            lifetime_not_after: row.lifetime_not_after,
            claimed_by_mls_group_id: row.claimed_by_mls_group_id,
            ssk_generation: row
                .ssk_generation
                .and_then(|generation| u64::try_from(generation).ok())
                .filter(|generation| *generation >= 1),
            device_authorize_event_id: row.device_authorize_event_id,
            agent_key_authorize_event_id: row.agent_key_authorize_event_id,
            claimed_at: row.claimed_at,
            claim_expires_at_unix_ms: row.claim_expires_at_unix_ms,
            consumed_at: row.consumed_at,
            created_at: row.created_at,
        }
    }
}

fn validated_keypackage_row(row: MlsKeyPackagePgRow) -> PersistenceResult<MlsKeyPackageRow> {
    let row = MlsKeyPackageRow::from(row);
    row.lifecycle().map_err(|error| {
        PersistenceError::SchemaViolation(format!(
            "stored MLS KeyPackage lifecycle is invalid: {error}"
        ))
    })?;
    Ok(row)
}
#[derive(QueryableByName)]
struct MlsWelcomeRow {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Text)]
    mls_group_id: String,
    #[diesel(sql_type = Text)]
    recipient_actor_id: String,
    #[diesel(sql_type = Text)]
    recipient_device_id: String,
    #[diesel(sql_type = Binary)]
    welcome_bytes: Vec<u8>,
    #[diesel(sql_type = Text)]
    key_package_id: String,
    #[diesel(sql_type = BigInt)]
    epoch: i64,
    #[diesel(sql_type = Nullable<Text>)]
    commit_ref: Option<String>,
    #[diesel(sql_type = Jsonb)]
    governance_binding: Value,
    #[diesel(sql_type = BigInt)]
    enqueued_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    delivered_at: Option<i64>,
}
impl From<MlsWelcomeRow> for MlsWelcomeRecord {
    fn from(row: MlsWelcomeRow) -> Self {
        Self {
            id: row.id,
            group_id: row.mls_group_id,
            recipient_actor_id: row.recipient_actor_id,
            recipient_device_id: row.recipient_device_id,
            welcome_bytes: row.welcome_bytes,
            key_package_id: row.key_package_id,
            epoch: row.epoch.max(0) as u64,
            commit_ref: row.commit_ref,
            governance_binding: row.governance_binding,
            enqueued_at: row.enqueued_at,
            delivered_at: row.delivered_at,
        }
    }
}
#[derive(QueryableByName)]
struct MlsCommitEpochRow {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = Text)]
    mls_group_id: String,
    #[diesel(sql_type = Jsonb)]
    effective_scope: Value,
    #[diesel(sql_type = BigInt)]
    epoch: i64,
    #[diesel(sql_type = Text)]
    leader_actor_id: String,
    #[diesel(sql_type = Text)]
    creator_device_id: String,
    #[diesel(sql_type = Text)]
    genesis_event_ref: String,
    #[diesel(sql_type = Jsonb)]
    governance_binding: Value,
    #[diesel(sql_type = Nullable<Text>)]
    accepted_commit_ref: Option<String>,
    #[diesel(sql_type = BigInt)]
    committed_at: i64,
    #[diesel(sql_type = Bool)]
    frontier_contested: bool,
}
impl From<MlsCommitEpochRow> for MlsCommitEpochRecord {
    fn from(row: MlsCommitEpochRow) -> Self {
        Self {
            id: row.id,
            group_id: row.mls_group_id,
            effective_scope: row.effective_scope,
            epoch: row.epoch.max(0) as u64,
            leader_actor_id: row.leader_actor_id,
            creator_device_id: row.creator_device_id,
            genesis_event_ref: row.genesis_event_ref,
            governance_binding: row.governance_binding,
            accepted_commit_ref: row.accepted_commit_ref,
            committed_at: row.committed_at,
            frontier_contested: row.frontier_contested,
        }
    }
}
