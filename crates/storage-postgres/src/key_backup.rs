use super::{
    Binary, Integer, JsonPayloadRow, Jsonb, KeyBackupDeleteChallengeRecord, KeyBackupStore,
    Nullable, OptionalExtension, PersistenceError, PersistenceResult, PgPool, QueryableByName,
    RunQueryDsl, Text, Timestamptz, Utc, Value, async_trait, ids, pg_conn, sql_query, sql_types,
};

#[derive(QueryableByName)]
struct KeyBackupDeleteChallengeRow {
    #[diesel(sql_type = Text)]
    challenge_id: String,
    #[diesel(sql_type = Text)]
    principal_id: arkret_identifiers::DidCoreId,
    #[diesel(sql_type = Text)]
    station_id: arkret_identifiers::DidCoreId,
    #[diesel(sql_type = Text)]
    backup_id: String,
    #[diesel(sql_type = Text)]
    request_id: String,
    #[diesel(sql_type = Jsonb)]
    challenge: Value,
    #[diesel(sql_type = Timestamptz)]
    issued_at: chrono::DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    consumed_at: Option<chrono::DateTime<Utc>>,
}

impl From<KeyBackupDeleteChallengeRow> for KeyBackupDeleteChallengeRecord {
    fn from(row: KeyBackupDeleteChallengeRow) -> Self {
        Self {
            challenge_id: row.challenge_id,
            account_id: arkret_wire::AccountId::new(row.principal_id, row.station_id),
            backup_id: row.backup_id,
            request_id: row.request_id,
            challenge: row.challenge,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
            consumed_at: row.consumed_at,
        }
    }
}

const DELETE_CHALLENGE_COLUMNS: &str = "challenge_id, principal_id, station_id, backup_id, request_id, challenge, issued_at, expires_at, consumed_at";
/// SOL-02-004 — classify a `key_backups` INSERT failure. A unique violation on
/// `key_backups_series_seq_key` means a concurrent successor PUT already
/// claimed this `(actor_id, series_id, series_seq)` tuple; surface it as a
/// [`PersistenceError::Conflict`] so the receive path can reject the loser of
/// the race with the §7.6 `series_seq_not_monotonic` wire code instead of a
/// generic 5xx. Every other diesel error stays a `Database` error.
fn map_key_backup_put_error(error: diesel::result::Error) -> PersistenceError {
    use diesel::result::{DatabaseErrorKind, Error as DieselError};
    if let DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, info) = &error {
        let constraint = info.constraint_name().unwrap_or_default();
        if constraint.is_empty() || constraint == "key_backups_series_seq_key" {
            return PersistenceError::Conflict(format!(
                "series_seq_not_monotonic: {}",
                info.message()
            ));
        }
    }
    PersistenceError::database(error)
}
pub struct PgKeyBackupStore {
    pub pool: PgPool,
}
#[async_trait]
impl KeyBackupStore for PgKeyBackupStore {
    async fn put(&self, backup_id: String, payload: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let extract_str = |key: &str| -> Option<String> {
            payload
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        };
        let actor_id = payload
            .get("actor_id")
            .cloned()
            .ok_or_else(|| PersistenceError::database("key backup actor_id is missing"))
            .and_then(|value| {
                serde_json::from_value::<arkret_wire::ActorId>(value)
                    .map_err(|_| PersistenceError::database("key backup actor_id is invalid"))
            })?
            .to_string();
        let device_id = extract_str("device_id");
        let scheme = extract_str("scheme").or_else(|| extract_str("algorithm"));
        let version: i32 = payload
            .get("version")
            .and_then(Value::as_i64)
            .map(|v| v.clamp(i32::MIN as i64, i32::MAX as i64) as i32)
            .unwrap_or(0);
        // base64-decoded key material lives in `key_material_encrypted` if the
        // caller already provided raw bytes via a `bytes_b64` field. Otherwise
        // the encrypted material stays in the JSONB envelope.
        let key_material: Option<Vec<u8>> = payload
            .get("key_material_encrypted_b64")
            .and_then(Value::as_str)
            .and_then(|s| {
                use base64::Engine as _;
                use base64::engine::general_purpose::STANDARD;
                STANDARD.decode(s).ok()
            });
        sql_query(
            "INSERT INTO key_backups \
             (id, actor_id, device_id, scheme, version, key_material_encrypted, payload, created_at, last_accessed_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NULL) \
             ON CONFLICT (id) DO UPDATE SET \
                actor_id = EXCLUDED.actor_id, \
                device_id = EXCLUDED.device_id, \
                scheme = EXCLUDED.scheme, \
                version = EXCLUDED.version, \
                key_material_encrypted = EXCLUDED.key_material_encrypted, \
                payload = EXCLUDED.payload",
        )
        .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(&backup_id))
        .bind::<Text, _>(&actor_id)
        .bind::<Nullable<Text>, _>(&device_id)
        .bind::<Nullable<Text>, _>(&scheme)
        .bind::<Integer, _>(version)
        .bind::<Nullable<Binary>, _>(key_material.as_deref())
        .bind::<Jsonb, _>(&payload)
        .execute(&mut *conn).await
        .map(|_| ())
        .map_err(map_key_backup_put_error)
    }

    async fn get(&self, backup_id: &str) -> PersistenceResult<Option<Value>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        // last_accessed_at side-effect on read is informational; failure here
        // must not crash the get path.
        let _ = sql_query("UPDATE key_backups SET last_accessed_at = NOW() WHERE id = $1")
            .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(backup_id))
            .execute(&mut *conn)
            .await;
        sql_query("SELECT payload FROM key_backups WHERE id = $1")
            .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(backup_id))
            .get_result::<JsonPayloadRow>(&mut *conn)
            .await
            .optional()
            .map(|row| row.map(|r| r.payload))
            .map_err(PersistenceError::database)
    }

    async fn delete(&self, backup_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM key_backups WHERE id = $1")
            .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(backup_id))
            .execute(&mut *conn)
            .await
            .map(|n| n > 0)
            .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("SELECT payload FROM key_backups ORDER BY created_at ASC, id ASC")
            .load::<JsonPayloadRow>(&mut *conn)
            .await
            .map(|rows| rows.into_iter().map(|r| r.payload).collect())
            .map_err(PersistenceError::database)
    }

    async fn list_for_actor(&self, actor_id: &str) -> PersistenceResult<Vec<Value>> {
        let actor_id = serde_json::from_str::<arkret_wire::ActorId>(actor_id)
            .map_err(|_| PersistenceError::database("key backup actor selector is invalid"))?
            .to_string();
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT payload FROM key_backups WHERE actor_id = $1 ORDER BY created_at ASC, id ASC",
        )
        .bind::<Text, _>(actor_id)
        .load::<JsonPayloadRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(|r| r.payload).collect())
        .map_err(PersistenceError::database)
    }

    async fn issue_delete_challenge(
        &self,
        record: KeyBackupDeleteChallengeRecord,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<KeyBackupDeleteChallengeRecord> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        // The row is unique on `(principal_id, station_id, backup_id, request_id)`, and the
        // `DO UPDATE ... WHERE` guard only replaces it once the held challenge
        // is consumed or expired. So this statement mints a challenge exactly
        // when §7.8.1 says a new one is due, and returns no row exactly when a
        // still-valid one is held.
        let issued = sql_query(format!(
            "INSERT INTO key_backup_delete_challenges ({DELETE_CHALLENGE_COLUMNS}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL) ON CONFLICT (principal_id, station_id, backup_id, request_id) DO UPDATE SET challenge_id = EXCLUDED.challenge_id, challenge = EXCLUDED.challenge, issued_at = EXCLUDED.issued_at, expires_at = EXCLUDED.expires_at, consumed_at = NULL WHERE key_backup_delete_challenges.consumed_at IS NOT NULL OR key_backup_delete_challenges.expires_at <= $9 RETURNING {DELETE_CHALLENGE_COLUMNS}"
        ))
        .bind::<Text, _>(&record.challenge_id)
        .bind::<Text, _>(&record.account_id.principal_id)
        .bind::<Text, _>(&record.account_id.station_id)
        .bind::<Text, _>(&record.backup_id)
        .bind::<Text, _>(&record.request_id)
        .bind::<Jsonb, _>(&record.challenge)
        .bind::<Timestamptz, _>(record.issued_at)
        .bind::<Timestamptz, _>(record.expires_at)
        .bind::<Timestamptz, _>(now)
        .get_result::<KeyBackupDeleteChallengeRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        if let Some(issued) = issued {
            return Ok(KeyBackupDeleteChallengeRecord::from(issued));
        }
        // No row came back, so a still-valid challenge is held for this triple.
        // Returning it is the contract, not an error: §7.8.1 requires the same
        // `request_id` to keep receiving the same challenge while it is valid,
        // so a client retrying the issue call does not invalidate the challenge
        // it is already signing.
        sql_query(format!(
            "SELECT {DELETE_CHALLENGE_COLUMNS} FROM key_backup_delete_challenges WHERE principal_id = $1 AND station_id = $2 AND backup_id = $3 AND request_id = $4"
        ))
        .bind::<Text, _>(&record.account_id.principal_id)
        .bind::<Text, _>(&record.account_id.station_id)
        .bind::<Text, _>(&record.backup_id)
        .bind::<Text, _>(&record.request_id)
        .get_result::<KeyBackupDeleteChallengeRow>(&mut *conn)
        .await
        .map(KeyBackupDeleteChallengeRecord::from)
        .map_err(PersistenceError::database)
    }

    async fn delete_challenge(
        &self,
        challenge_id: &str,
    ) -> PersistenceResult<Option<KeyBackupDeleteChallengeRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(format!(
            "SELECT {DELETE_CHALLENGE_COLUMNS} FROM key_backup_delete_challenges              WHERE challenge_id = $1"
        ))
        .bind::<Text, _>(challenge_id)
        .get_result::<KeyBackupDeleteChallengeRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(KeyBackupDeleteChallengeRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn consume_delete_challenge(
        &self,
        challenge_id: &str,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        // `consumed_at IS NULL` in the predicate is the single-use guarantee:
        // two concurrent DELETEs both reach here, exactly one updates a row.
        sql_query(
            "UPDATE key_backup_delete_challenges SET consumed_at = $2              WHERE challenge_id = $1 AND consumed_at IS NULL",
        )
        .bind::<Text, _>(challenge_id)
        .bind::<Timestamptz, _>(now)
        .execute(&mut *conn)
        .await
        .map(|rows| rows > 0)
        .map_err(PersistenceError::database)
    }

    async fn prune_expired_delete_challenges(
        &self,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM key_backup_delete_challenges WHERE expires_at <= $1")
            .bind::<Timestamptz, _>(now)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)
    }
}
