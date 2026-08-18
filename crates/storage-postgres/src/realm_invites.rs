use super::{
    Binary, Jsonb, Nullable, OptionalExtension, PersistenceError, PersistenceResult, PgPool,
    QueryableByName, RealmInviteRecord, RealmInviteStore, RunQueryDsl, Text, Timestamptz, Utc,
    Value, async_trait, ids, pg_conn, sql_query,
};
pub struct PgRealmInviteStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct RealmInviteRow {
    #[diesel(sql_type = Binary)]
    id: Vec<u8>,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    inviter: String,
    #[diesel(sql_type = Nullable<Text>)]
    invitee: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    invite_delivery_target: Option<Value>,
    #[diesel(sql_type = Nullable<Text>)]
    introduction_evidence_digest: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    third_party_invite: Option<Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    #[diesel(sql_type = Text)]
    invite_token: String,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = Jsonb)]
    claim_nonces: Value,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}
impl From<RealmInviteRow> for RealmInviteRecord {
    fn from(row: RealmInviteRow) -> Self {
        Self {
            invite_id: {
                let token: [u8; ids::EVENT_ID_BYTES] = row
                    .id
                    .as_slice()
                    .try_into()
                    .expect("realm_invites.id must be 33 bytes");
                ids::format_event_token("invite", &token)
            },
            realm_id: row.realm_id,
            inviter: row.inviter,
            invitee: row.invitee,
            invite_delivery_target: row.invite_delivery_target,
            introduction_evidence_digest: row.introduction_evidence_digest,
            third_party_invite: row.third_party_invite,
            invite_token: row.invite_token,
            status: row.status,
            claim_nonces: serde_json::from_value(row.claim_nonces).unwrap_or_default(),
            expires_at: row.expires_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}
#[async_trait]
impl RealmInviteStore for PgRealmInviteStore {
    async fn get(&self, invite_id: &str) -> PersistenceResult<Option<RealmInviteRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let invite_id_token =
            ids::event_token_part_or_schema_violation(invite_id, "invite")?.to_vec();
        sql_query(
            "SELECT id, realm_id, inviter_id AS inviter, invitee_id AS invitee, invite_delivery_target, introduction_evidence_digest, third_party_invite, invite_token, status, claim_nonces, expires_at, created_at, updated_at \
             FROM realm_invites WHERE id = $1",
        )
        .bind::<Binary, _>(invite_id_token)
        .get_result::<RealmInviteRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(RealmInviteRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn put(&self, record: RealmInviteRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let invite_id_token =
            ids::event_token_part_or_schema_violation(&record.invite_id, "invite")?.to_vec();
        crate::realm_identity::ensure_realm_pk(&mut conn, &record.realm_id).await?;
        sql_query(
            "INSERT INTO realm_invites \
             (id, realm_id, inviter_id, invitee_id, invite_delivery_target, introduction_evidence_digest, third_party_invite, invite_token, status, claim_nonces, expires_at, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
             ON CONFLICT (id) DO UPDATE SET \
                realm_id = EXCLUDED.realm_id, \
                inviter_id = EXCLUDED.inviter_id, \
                invitee_id = EXCLUDED.invitee_id, \
                invite_delivery_target = EXCLUDED.invite_delivery_target, \
                introduction_evidence_digest = EXCLUDED.introduction_evidence_digest, \
                third_party_invite = EXCLUDED.third_party_invite, \
                invite_token = EXCLUDED.invite_token, \
                status = EXCLUDED.status, \
                claim_nonces = EXCLUDED.claim_nonces, \
                expires_at = EXCLUDED.expires_at, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<Binary, _>(invite_id_token)
        .bind::<Text, _>(&record.realm_id)
        .bind::<Text, _>(&record.inviter)
        .bind::<Nullable<Text>, _>(&record.invitee)
        .bind::<Nullable<Jsonb>, _>(&record.invite_delivery_target)
        .bind::<Nullable<Text>, _>(&record.introduction_evidence_digest)
        .bind::<Nullable<Jsonb>, _>(&record.third_party_invite)
        .bind::<Text, _>(&record.invite_token)
        .bind::<Text, _>(&record.status)
        .bind::<Jsonb, _>(serde_json::to_value(&record.claim_nonces).unwrap_or_default())
        .bind::<Nullable<Timestamptz>, _>(record.expires_at)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Nullable<Timestamptz>, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn consume_third_party_token(
        &self,
        token_digest: &str,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<Option<RealmInviteRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let consumed = sql_query(
            "UPDATE realm_invites \
             SET invite_token = '', updated_at = $2 \
             WHERE invite_token = $1 \
               AND third_party_invite IS NOT NULL \
               AND status = 'pending' \
               AND (expires_at IS NULL OR expires_at > $2) \
             RETURNING id, realm_id, inviter_id AS inviter, invitee_id AS invitee, invite_delivery_target, introduction_evidence_digest, third_party_invite, invite_token, status, claim_nonces, expires_at, created_at, updated_at",
        )
        .bind::<Text, _>(token_digest)
        .bind::<Timestamptz, _>(now)
        .get_result::<RealmInviteRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(RealmInviteRecord::from))
        .map_err(PersistenceError::database)?;
        if consumed.is_some() {
            return Ok(consumed);
        }
        sql_query(
            "UPDATE realm_invites \
             SET status = 'expired', \
                 invite_token = '', \
                 third_party_invite = ((((((third_party_invite - 'token_salt') - 'token_salt_id') - 'lookup_table_ref') - 'pepper') - 'pepper_id') - 'token_commitment'), \
                 updated_at = $2 \
             WHERE invite_token = $1 \
               AND third_party_invite IS NOT NULL \
               AND status = 'pending' \
               AND expires_at IS NOT NULL \
               AND expires_at <= $2",
        )
        .bind::<Text, _>(token_digest)
        .bind::<Timestamptz, _>(now)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)?;
        Ok(None)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<RealmInviteRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id, realm_id, inviter_id AS inviter, invitee_id AS invitee, invite_delivery_target, introduction_evidence_digest, third_party_invite, invite_token, status, claim_nonces, expires_at, created_at, updated_at \
             FROM realm_invites ORDER BY created_at ASC, pk ASC",
        )
        .load::<RealmInviteRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(RealmInviteRecord::from).collect())
        .map_err(PersistenceError::database)
    }
}
