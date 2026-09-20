use diesel::sql_types::SmallInt;

use super::{
    BigInt, Binary, Bool, CanonicalEventRecord, DirectConversationFoundingSlotRecord, EventStore,
    ExistsRow, FederationOutboxRecord, IdentityAnchorAccountSlot, Jsonb, MessageRecord,
    MessageStore, Nullable, OptionalExtension, PersistenceError, PersistenceResult, PgPool,
    QueryableByName, RealmEventStats, RunQueryDsl, Text, Timestamptz, Uuid, Value, async_trait,
    ids, pg_conn, sql_query, sql_types,
};
use crate::federation::{FederationOutboxRow, qualified_outbox_columns};

/// Read model for producer-signed Events. Event admission and ordering are
/// owned by `PgAuthorityCommitStore`; this store deliberately has no write API.
pub struct PgEventStore {
    pub pool: PgPool,
}

const EVENT_COLUMNS: &str =
    "id, digest_suite, digest, actor_id, realm_id, kind, canonical_bytes, envelope, received_at";

#[derive(QueryableByName)]
struct CanonicalEventRow {
    #[diesel(sql_type = Binary)]
    id: Vec<u8>,
    #[diesel(sql_type = SmallInt)]
    digest_suite: i16,
    #[diesel(sql_type = Binary)]
    digest: Vec<u8>,
    #[diesel(sql_type = Text)]
    actor_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    realm_id: Option<String>,
    #[diesel(sql_type = Text)]
    kind: String,
    #[diesel(sql_type = Binary)]
    canonical_bytes: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Timestamptz)]
    received_at: chrono::DateTime<chrono::Utc>,
}

impl TryFrom<CanonicalEventRow> for CanonicalEventRecord {
    type Error = PersistenceError;

    fn try_from(row: CanonicalEventRow) -> Result<Self, Self::Error> {
        let id: [u8; ids::EVENT_ID_BYTES] = row.id.try_into().map_err(|_| {
            PersistenceError::Internal("stored Event id has invalid length".to_owned())
        })?;
        let digest: [u8; ids::EVENT_DIGEST_BYTES] = row.digest.try_into().map_err(|_| {
            PersistenceError::Internal("stored Event digest has invalid length".to_owned())
        })?;
        let digest_suite = match row.digest_suite {
            1 => arkret_canonical::DigestSuite::Sha256,
            2 => arkret_canonical::DigestSuite::Blake3,
            other => {
                return Err(PersistenceError::Internal(format!(
                    "stored Event uses unsupported digest suite {other}"
                )));
            }
        };
        let canonical_digest = ids::format_event_digest(row.digest_suite as u8, &digest)
            .ok_or_else(|| PersistenceError::Internal("stored Event digest is invalid".into()))?;
        Ok(Self {
            event_id: ids::format_event_id(&id),
            actor_id: row.actor_id,
            realm_id: row.realm_id,
            kind: row.kind,
            schema_id: arkret_wire::SchemaId::EVENT_V1.to_owned(),
            digest_suite,
            canonical_digest,
            canonical_bytes: row.canonical_bytes,
            envelope: row.envelope,
            received_at: row.received_at,
        })
    }
}

fn decode_events(rows: Vec<CanonicalEventRow>) -> PersistenceResult<Vec<CanonicalEventRecord>> {
    rows.into_iter()
        .map(CanonicalEventRecord::try_from)
        .collect()
}

#[derive(QueryableByName)]
struct RealmEventStatsRow {
    #[diesel(sql_type = BigInt)]
    event_count: i64,
    #[diesel(sql_type = BigInt)]
    canonical_bytes: i64,
}

#[derive(QueryableByName)]
struct PkRow {
    #[diesel(sql_type = BigInt)]
    pk: i64,
}

#[derive(QueryableByName)]
struct DirectConversationFoundingSlotRow {
    #[diesel(sql_type = Text)]
    founder_id: String,
    #[diesel(sql_type = Text)]
    trust_domain_id: String,
    #[diesel(sql_type = Text)]
    pair_key: String,
    #[diesel(sql_type = Text)]
    founding_unit_digest: String,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    main_strand_id: String,
    #[diesel(sql_type = Jsonb)]
    event_ids: Value,
    #[diesel(sql_type = Text)]
    idempotency_key: String,
    #[diesel(sql_type = Binary)]
    receipt_bytes: Vec<u8>,
    #[diesel(sql_type = Timestamptz)]
    accepted_at: chrono::DateTime<chrono::Utc>,
}

impl TryFrom<DirectConversationFoundingSlotRow> for DirectConversationFoundingSlotRecord {
    type Error = PersistenceError;

    fn try_from(row: DirectConversationFoundingSlotRow) -> Result<Self, Self::Error> {
        Ok(Self {
            founder_id: row.founder_id,
            trust_domain_id: row.trust_domain_id,
            pair_key: row.pair_key,
            founding_unit_digest: row.founding_unit_digest,
            realm_id: row.realm_id,
            main_strand_id: row.main_strand_id,
            event_ids: serde_json::from_value(row.event_ids).map_err(PersistenceError::database)?,
            idempotency_key: row.idempotency_key,
            receipt_bytes: row.receipt_bytes,
            accepted_at: row.accepted_at,
        })
    }
}

#[async_trait]
impl EventStore for PgEventStore {
    async fn federation_outbox_for_event(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let event_id = ids::parse_event_id(event_id).ok_or_else(|| {
            PersistenceError::SchemaViolation(format!("malformed canonical Event id: {event_id:?}"))
        })?;
        let outbox_columns = qualified_outbox_columns("outbox");
        let rows = sql_query(format!(
            "SELECT {outbox_columns} FROM federation_outbox outbox \
             JOIN event_federation_outbox link ON link.outbox_id = outbox.id \
             JOIN canonical_events event ON event.pk = link.event_pk \
             WHERE event.id = $1 ORDER BY outbox.created_at ASC, outbox.id ASC"
        ))
        .bind::<Binary, _>(event_id.to_vec())
        .load::<FederationOutboxRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(FederationOutboxRecord::try_from)
            .collect()
    }

    async fn direct_conversation_founding_slot(
        &self,
        founder_id: &str,
        trust_domain_id: &str,
        pair_key: &str,
    ) -> PersistenceResult<Option<DirectConversationFoundingSlotRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT founder_id, trust_domain_id, pair_key, founding_unit_digest, realm_id, \
                    main_strand_id, event_ids, idempotency_key, receipt_bytes, accepted_at \
             FROM direct_conversation_founding_slots \
             WHERE founder_id = $1 AND trust_domain_id = $2 AND pair_key = $3",
        )
        .bind::<Text, _>(founder_id)
        .bind::<Text, _>(trust_domain_id)
        .bind::<Text, _>(pair_key)
        .get_result::<DirectConversationFoundingSlotRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(DirectConversationFoundingSlotRecord::try_from)
        .transpose()
    }

    async fn identity_anchor_account_slot(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<IdentityAnchorAccountSlot>> {
        #[derive(QueryableByName)]
        struct AccountSlotRow {
            #[diesel(sql_type = Text)]
            account_authority_id: String,
            #[diesel(sql_type = Text)]
            account_subject: String,
            #[diesel(sql_type = Text)]
            principal_id: arkret_identifiers::DidCoreId,
            #[diesel(sql_type = Text)]
            station_id: arkret_identifiers::DidCoreId,
            #[diesel(sql_type = Text)]
            realm_id: String,
            #[diesel(sql_type = Text)]
            create_event_id: String,
        }
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT account_authority_id, account_subject, principal_id, station_id, realm_id, \
                    create_event_id FROM identity_anchor_account_slots \
             WHERE principal_id = $1 AND station_id = $2 LIMIT 2",
        )
        .bind::<Text, _>(account_id.principal_id.as_str())
        .bind::<Text, _>(account_id.station_id.as_str())
        .load::<AccountSlotRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        match rows.as_slice() {
            [] => Ok(None),
            [row] => Ok(Some(IdentityAnchorAccountSlot {
                account_authority_id: row.account_authority_id.clone(),
                account_subject: row.account_subject.clone(),
                account_id: arkret_wire::AccountId::new(
                    row.principal_id.clone(),
                    row.station_id.clone(),
                ),
                realm_id: row.realm_id.clone(),
                create_event_id: row.create_event_id.clone(),
            })),
            _ => Err(PersistenceError::Conflict(
                "account has multiple identity-anchor account slots".to_owned(),
            )),
        }
    }

    async fn get(&self, event_id: &str) -> PersistenceResult<Option<CanonicalEventRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let event_id = ids::parse_event_id(event_id).ok_or_else(|| {
            PersistenceError::SchemaViolation(format!("malformed canonical Event id: {event_id:?}"))
        })?;
        let row = sql_query(format!(
            "SELECT {EVENT_COLUMNS} FROM canonical_events WHERE id = $1 AND state = 'committed'"
        ))
        .bind::<Binary, _>(event_id.to_vec())
        .get_result::<CanonicalEventRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(CanonicalEventRecord::try_from).transpose()
    }

    async fn contains(&self, event_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        let event_id = ids::parse_event_id(event_id).ok_or_else(|| {
            PersistenceError::SchemaViolation(format!("malformed canonical Event id: {event_id:?}"))
        })?;
        sql_query(
            "SELECT EXISTS(SELECT 1 FROM canonical_events WHERE id = $1 AND state = 'committed') AS present",
        )
        .bind::<Binary, _>(event_id.to_vec())
        .get_result::<ExistsRow>(&mut *conn)
        .await
        .map(|row| row.present)
        .map_err(PersistenceError::database)
    }

    async fn list_for_actor(&self, actor_id: &str) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(format!(
            "SELECT {EVENT_COLUMNS} FROM canonical_events WHERE actor_id = $1 AND state = 'committed' \
             ORDER BY received_at ASC, id ASC"
        ))
        .bind::<Text, _>(actor_id)
        .load::<CanonicalEventRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        decode_events(rows)
    }

    async fn franking_proofs_for_target(
        &self,
        realm_id: &str,
        received_by: &arkret_identifiers::DidCoreId,
        target_event_id: &str,
    ) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(format!(
            "SELECT {EVENT_COLUMNS} FROM canonical_events \
             WHERE realm_id = $1 AND actor_id = $2 AND kind = $3 AND state = 'committed' \
               AND envelope -> 'payload' ->> 'event_id' = $4 \
             ORDER BY received_at ASC, id ASC"
        ))
        .bind::<Text, _>(realm_id)
        .bind::<Text, _>(received_by.as_str())
        .bind::<Text, _>(arkret_wire::EventKind::ModerationFrankingProof.as_str())
        .bind::<Text, _>(target_event_id)
        .load::<CanonicalEventRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        decode_events(rows)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(format!(
            "SELECT {EVENT_COLUMNS} FROM canonical_events WHERE state = 'committed' \
             ORDER BY received_at ASC, id ASC"
        ))
        .load::<CanonicalEventRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        decode_events(rows)
    }

    async fn realm_event_stats(&self, realm_id: &str) -> PersistenceResult<RealmEventStats> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT COUNT(*)::bigint AS event_count, \
                    COALESCE(SUM(OCTET_LENGTH(canonical_bytes)), 0)::bigint AS canonical_bytes \
             FROM canonical_events WHERE realm_id = $1 AND state = 'committed'",
        )
        .bind::<Text, _>(realm_id)
        .get_result::<RealmEventStatsRow>(&mut *conn)
        .await
        .map(|row| RealmEventStats {
            count: row.event_count.max(0) as u64,
            canonical_bytes: row.canonical_bytes.max(0) as u64,
        })
        .map_err(PersistenceError::database)
    }

    async fn realm_events_newest_first(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(format!(
            "SELECT {EVENT_COLUMNS} FROM canonical_events WHERE realm_id = $1 AND state = 'committed' \
             ORDER BY received_at DESC, id DESC"
        ))
        .bind::<Text, _>(realm_id)
        .load::<CanonicalEventRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        decode_events(rows)
    }
}

const MESSAGE_COLUMNS: &str =
    "event_id, message_id, realm_id, sender, thread_id, content, encrypted, created_at";

pub struct PgMessageStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct MessageRow {
    #[diesel(sql_type = Text)]
    event_id: String,
    #[diesel(sql_type = Text)]
    message_id: String,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    sender: String,
    #[diesel(sql_type = Text)]
    thread_id: String,
    #[diesel(sql_type = Jsonb)]
    content: Value,
    #[diesel(sql_type = Bool)]
    encrypted: bool,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<MessageRow> for MessageRecord {
    fn from(row: MessageRow) -> Self {
        Self {
            event_id: row.event_id,
            message_id: row.message_id,
            realm_id: row.realm_id,
            sender: row.sender,
            thread_id: row.thread_id,
            content: row.content,
            encrypted: row.encrypted,
            created_at: row.created_at,
        }
    }
}

#[async_trait]
impl MessageStore for PgMessageStore {
    async fn get(&self, event_id: &str) -> PersistenceResult<Option<MessageRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {MESSAGE_COLUMNS} FROM messages WHERE event_id = $1"
        ))
        .bind::<Text, _>(event_id)
        .get_result::<MessageRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(MessageRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn put(&self, record: &MessageRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO messages \
             (event_id, message_id, realm_id, sender, thread_id, content, encrypted, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (event_id) DO NOTHING",
        )
        .bind::<Text, _>(&record.event_id)
        .bind::<Text, _>(&record.message_id)
        .bind::<Text, _>(&record.realm_id)
        .bind::<Text, _>(&record.sender)
        .bind::<Text, _>(&record.thread_id)
        .bind::<Jsonb, _>(&record.content)
        .bind::<Bool, _>(record.encrypted)
        .bind::<Timestamptz, _>(record.created_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<MessageRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {MESSAGE_COLUMNS} FROM messages WHERE realm_id = $1 \
             ORDER BY created_at DESC, pk DESC LIMIT $2"
        ))
        .bind::<Text, _>(realm_id)
        .bind::<BigInt, _>(limit as i64)
        .load::<MessageRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(MessageRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn list_for_thread(
        &self,
        thread_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<MessageRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {MESSAGE_COLUMNS} FROM messages WHERE thread_id = $1 \
             ORDER BY created_at ASC, pk ASC LIMIT $2"
        ))
        .bind::<Text, _>(thread_id)
        .bind::<BigInt, _>(limit as i64)
        .load::<MessageRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(MessageRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn delete(&self, event_id: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM messages WHERE event_id = $1")
            .bind::<Text, _>(event_id)
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::database)
    }
}
