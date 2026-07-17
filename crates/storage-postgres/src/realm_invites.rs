use super::*;
pub struct PgRealmInviteStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct RealmInviteRow {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    realm_id: Uuid,
    #[diesel(sql_type = Text)]
    inviter: String,
    #[diesel(sql_type = Nullable<Text>)]
    invitee: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    invite_delivery_target: Option<Value>,
    #[diesel(sql_type = Nullable<Text>)]
    introduction_evidence_digest: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    third_party_id: Option<Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    join_rule_snapshot: Option<Value>,
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
            invite_id: ids::format_typed_uuid("invite", &row.id),
            realm_id: ids::format_typed_uuid("realm", &row.realm_id),
            inviter: row.inviter,
            invitee: row.invitee,
            invite_delivery_target: row.invite_delivery_target,
            introduction_evidence_digest: row.introduction_evidence_digest,
            third_party_id: row.third_party_id,
            join_rule_snapshot: row.join_rule_snapshot,
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
        let invite_id_uuid = ids::typed_uuid_part_expect_internal(invite_id);
        sql_query(
            "SELECT id, realm_id, inviter_id AS inviter, invitee_id AS invitee, invite_delivery_target, introduction_evidence_digest, third_party_id, join_rule_snapshot, invite_token, status, claim_nonces, expires_at, created_at, updated_at \
             FROM realm_invites WHERE id = $1",
        )
        .bind::<SqlUuid, _>(invite_id_uuid)
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
        let invite_id_uuid = ids::typed_uuid_part_expect_internal(&record.invite_id);
        let realm_id_uuid = ids::typed_uuid_part_expect_internal(&record.realm_id);
        sql_query(
            "INSERT INTO realm_invites \
             (id, realm_id, inviter_id, invitee_id, invite_delivery_target, introduction_evidence_digest, third_party_id, join_rule_snapshot, invite_token, status, claim_nonces, expires_at, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
             ON CONFLICT (id) DO UPDATE SET \
                realm_id = EXCLUDED.realm_id, \
                inviter_id = EXCLUDED.inviter_id, \
                invitee_id = EXCLUDED.invitee_id, \
                invite_delivery_target = EXCLUDED.invite_delivery_target, \
                introduction_evidence_digest = EXCLUDED.introduction_evidence_digest, \
                third_party_id = EXCLUDED.third_party_id, \
                join_rule_snapshot = EXCLUDED.join_rule_snapshot, \
                invite_token = EXCLUDED.invite_token, \
                status = EXCLUDED.status, \
                claim_nonces = EXCLUDED.claim_nonces, \
                expires_at = EXCLUDED.expires_at, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<SqlUuid, _>(invite_id_uuid)
        .bind::<SqlUuid, _>(realm_id_uuid)
        .bind::<Text, _>(&record.inviter)
        .bind::<Nullable<Text>, _>(&record.invitee)
        .bind::<Nullable<Jsonb>, _>(&record.invite_delivery_target)
        .bind::<Nullable<Text>, _>(&record.introduction_evidence_digest)
        .bind::<Nullable<Jsonb>, _>(&record.third_party_id)
        .bind::<Nullable<Jsonb>, _>(&record.join_rule_snapshot)
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
               AND third_party_id IS NOT NULL \
               AND status = 'pending' \
               AND (expires_at IS NULL OR expires_at > $2) \
             RETURNING id, realm_id, inviter_id AS inviter, invitee_id AS invitee, invite_delivery_target, introduction_evidence_digest, third_party_id, join_rule_snapshot, invite_token, status, claim_nonces, expires_at, created_at, updated_at",
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
                 third_party_id = ((((((third_party_id - 'token_salt') - 'token_salt_id') - 'lookup_table_ref') - 'pepper') - 'pepper_id') - 'token_commitment'), \
                 updated_at = $2 \
             WHERE invite_token = $1 \
               AND third_party_id IS NOT NULL \
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
            "SELECT id, realm_id, inviter_id AS inviter, invitee_id AS invitee, invite_delivery_target, introduction_evidence_digest, third_party_id, join_rule_snapshot, invite_token, status, claim_nonces, expires_at, created_at, updated_at \
             FROM realm_invites ORDER BY created_at ASC, id ASC",
        )
        .load::<RealmInviteRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(RealmInviteRecord::from).collect())
        .map_err(PersistenceError::database)
    }
}
