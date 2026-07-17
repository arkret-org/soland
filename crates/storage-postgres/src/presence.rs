use super::*;
pub struct PgPresenceStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct PresenceRow {
    #[diesel(sql_type = Text)]
    actor: String,
    #[diesel(sql_type = Text)]
    device_id: String,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = Nullable<Text>)]
    status_message: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    last_active_at: Option<String>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
}
impl TryFrom<PresenceRow> for PresenceRecord {
    type Error = PersistenceError;

    fn try_from(row: PresenceRow) -> PersistenceResult<Self> {
        Ok(Self {
            actor: row.actor,
            device_id: row.device_id,
            status: row.status,
            status_message: row.status_message,
            last_active_at: row.last_active_at,
            expires_at: row.expires_at,
            updated_at: row.updated_at,
            envelope: serde_json::from_value(row.envelope).map_err(|error| {
                PersistenceError::SchemaViolation(format!(
                    "stored presence envelope is invalid: {error}"
                ))
            })?,
        })
    }
}
#[async_trait]
impl PresenceStore for PgPresenceStore {
    async fn put(&self, presence: PresenceRecord) -> PersistenceResult<()> {
        let envelope = serde_json::to_value(&presence.envelope).map_err(|error| {
            PersistenceError::Internal(format!("failed to encode presence envelope: {error}"))
        })?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO presence (id, device_id, status, status_message, last_active_at, expires_at, updated_at, envelope) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (id, device_id) DO UPDATE SET \
                status = EXCLUDED.status, \
                status_message = EXCLUDED.status_message, \
                last_active_at = EXCLUDED.last_active_at, \
                expires_at = EXCLUDED.expires_at, \
                updated_at = EXCLUDED.updated_at, \
                envelope = EXCLUDED.envelope",
        )
        .bind::<Text, _>(&presence.actor)
        .bind::<Text, _>(&presence.device_id)
        .bind::<Text, _>(&presence.status)
        .bind::<Nullable<Text>, _>(&presence.status_message)
        .bind::<Nullable<Text>, _>(&presence.last_active_at)
        .bind::<Nullable<Timestamptz>, _>(presence.expires_at)
        .bind::<Timestamptz, _>(presence.updated_at)
        .bind::<Jsonb, _>(&envelope)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<PresenceRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id AS actor, device_id, status, status_message, last_active_at, expires_at, updated_at, envelope \
             FROM presence WHERE id = $1",
        )
        .bind::<Text, _>(actor)
        .load::<PresenceRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(PresenceRecord::try_from)
        .collect()
    }

    async fn delete(&self, actor: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM presence WHERE id = $1")
            .bind::<Text, _>(actor)
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::database)
    }
}
/// PostgreSQL-backed `ak.call.signal` realm-broadcast relay
/// (`webrtc-signaling.md` §5). Durable so a restart / replica failover keeps
/// pending invites and the per-subscriber-device deliver-once watermark
/// (`call_signal_relay` + `call_signal_relay_position` +
/// `call_signal_relay_watermark`).
pub struct PgCallSignalRelayStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct CallSignalRelayPositionRow {
    #[diesel(sql_type = BigInt)]
    next_position: i64,
}
#[derive(QueryableByName)]
struct CallSignalRelayRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = BigInt)]
    position: i64,
    #[diesel(sql_type = Text)]
    sender_actor: String,
    #[diesel(sql_type = Text)]
    sender_device: String,
    #[diesel(sql_type = Text)]
    call_id: String,
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
}
impl TryFrom<CallSignalRelayRow> for CallSignalRelayRecord {
    type Error = PersistenceError;

    fn try_from(row: CallSignalRelayRow) -> PersistenceResult<Self> {
        Ok(Self {
            realm_id: row.realm_id,
            sender_actor: row.sender_actor,
            sender_device: row.sender_device,
            call_id: row.call_id,
            expires_at: row.expires_at,
            envelope: serde_json::from_value(row.envelope).map_err(|error| {
                PersistenceError::SchemaViolation(format!(
                    "stored call signal envelope is invalid: {error}"
                ))
            })?,
            position: row.position.max(0) as u64,
        })
    }
}
#[derive(QueryableByName)]
struct CallSignalWatermarkRow {
    #[diesel(sql_type = BigInt)]
    delivered_through: i64,
}
#[async_trait]
impl CallSignalRelayStore for PgCallSignalRelayStore {
    async fn append(&self, mut record: CallSignalRelayRecord) -> PersistenceResult<()> {
        let envelope = serde_json::to_value(&record.envelope).map_err(|error| {
            PersistenceError::Internal(format!("failed to encode call signal envelope: {error}"))
        })?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        // Assign the monotonic per-Realm position from a dedicated counter that
        // never decreases — even after the relay log is pruned — so a recycled
        // position can never re-cross a delivered-through watermark. The
        // `RETURNING` makes the read-increment atomic under concurrent appends.
        let position_row = sql_query(
            "INSERT INTO call_signal_relay_position (realm_id, next_position, updated_at) \
             VALUES ($1, 1, NOW()) \
             ON CONFLICT (realm_id) DO UPDATE SET \
                next_position = call_signal_relay_position.next_position + 1, \
                updated_at = NOW() \
             RETURNING next_position",
        )
        .bind::<Text, _>(&record.realm_id)
        .get_result::<CallSignalRelayPositionRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        let position = position_row.next_position;
        record.position = position.max(0) as u64;

        sql_query(
            "INSERT INTO call_signal_relay \
             (id, realm_id, position, sender_actor, sender_device, call_id, envelope, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8)",
        )
        .bind::<SqlUuid, _>(uuid::Uuid::now_v7())
        .bind::<Text, _>(&record.realm_id)
        .bind::<BigInt, _>(position)
        .bind::<Text, _>(&record.sender_actor)
        .bind::<Text, _>(&record.sender_device)
        .bind::<Text, _>(&record.call_id)
        .bind::<Jsonb, _>(&envelope)
        .bind::<Timestamptz, _>(record.expires_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;

        // Bound retained signals per Realm to the most recent
        // `CALL_SIGNAL_RELAY_MAX_PER_REALM` (mirrors the in-memory cap) so a
        // burst cannot grow the table unboundedly; the counter is untouched so
        // positions stay monotonic.
        sql_query(
            "DELETE FROM call_signal_relay \
             WHERE realm_id = $1 AND position <= $2 - $3",
        )
        .bind::<Text, _>(&record.realm_id)
        .bind::<BigInt, _>(position)
        .bind::<BigInt, _>(CALL_SIGNAL_RELAY_MAX_PER_REALM as i64)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        Ok(())
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<CallSignalRelayRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT realm_id, position, sender_actor, sender_device, call_id, envelope, expires_at \
             FROM call_signal_relay \
             WHERE realm_id = $1 AND expires_at > NOW() \
             ORDER BY position ASC",
        )
        .bind::<Text, _>(realm_id)
        .load::<CallSignalRelayRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(CallSignalRelayRecord::try_from)
            .collect()
    }

    async fn prune_expired(&self) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM call_signal_relay WHERE expires_at <= NOW()")
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)
    }

    async fn delivered_through(
        &self,
        actor: &str,
        device: &str,
        realm_id: &str,
    ) -> PersistenceResult<u64> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(
            "SELECT delivered_through FROM call_signal_relay_watermark \
             WHERE actor_id = $1 AND device_id = $2 AND realm_id = $3",
        )
        .bind::<Text, _>(actor)
        .bind::<Text, _>(device)
        .bind::<Text, _>(realm_id)
        .get_result::<CallSignalWatermarkRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        Ok(row.map(|r| r.delivered_through.max(0) as u64).unwrap_or(0))
    }

    async fn advance(
        &self,
        actor: &str,
        device: &str,
        realm_id: &str,
        position: u64,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        // Monotonic: `GREATEST` on conflict keeps the highest position so a
        // lower (out-of-order / replayed) advance is ignored.
        sql_query(
            "INSERT INTO call_signal_relay_watermark \
             (actor_id, device_id, realm_id, delivered_through, updated_at) \
             VALUES ($1, $2, $3, $4, NOW()) \
             ON CONFLICT (actor_id, device_id, realm_id) DO UPDATE SET \
                delivered_through = GREATEST(call_signal_relay_watermark.delivered_through, EXCLUDED.delivered_through), \
                updated_at = NOW()",
        )
        .bind::<Text, _>(actor)
        .bind::<Text, _>(device)
        .bind::<Text, _>(realm_id)
        .bind::<BigInt, _>(position as i64)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }
}
