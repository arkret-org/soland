use super::*;

/// realm invite tokens.
#[async_trait]
pub trait RealmInviteStore: Send + Sync {
    async fn get(&self, invite_id: &str) -> PersistenceResult<Option<RealmInviteRecord>>;
    async fn put(&self, record: RealmInviteRecord) -> PersistenceResult<()>;
    async fn consume_third_party_token(
        &self,
        token_digest: &str,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<Option<RealmInviteRecord>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<RealmInviteRecord>>;
}

#[derive(Default)]
pub(crate) struct MemoryRealmInviteStore {
    data: Mutex<BTreeMap<String, RealmInviteRecord>>,
}

impl MemoryRealmInviteStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RealmInviteStore for MemoryRealmInviteStore {
    async fn get(&self, invite_id: &str) -> PersistenceResult<Option<RealmInviteRecord>> {
        Ok(self
            .data
            .lock()
            .expect("realm invites lock")
            .get(invite_id)
            .cloned())
    }

    async fn put(&self, record: RealmInviteRecord) -> PersistenceResult<()> {
        let id = record.invite_id.clone();
        self.data
            .lock()
            .expect("realm invites lock")
            .insert(id, record);
        Ok(())
    }

    async fn consume_third_party_token(
        &self,
        token_digest: &str,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<Option<RealmInviteRecord>> {
        let mut data = self.data.lock().expect("realm invites lock");
        let Some(record) = data
            .values_mut()
            .find(|record| record.third_party_id.is_some() && record.invite_token == token_digest)
        else {
            return Ok(None);
        };
        if record.status != "pending" {
            record.invite_token.clear();
            record.updated_at = Some(now);
            return Ok(None);
        }
        if record
            .expires_at
            .is_some_and(|expires_at| expires_at <= now)
        {
            record.status = "expired".to_owned();
            record.invite_token.clear();
            remove_third_party_active_material(&mut record.third_party_id, true);
            record.updated_at = Some(now);
            return Ok(None);
        }
        record.invite_token.clear();
        record.updated_at = Some(now);
        Ok(Some(record.clone()))
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<RealmInviteRecord>> {
        Ok(self
            .data
            .lock()
            .expect("realm invites lock")
            .values()
            .cloned()
            .collect())
    }
}

pub(crate) struct PgRealmInviteStore {
    pub(crate) pool: PgPool,
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
        let mut conn = pg_conn(&self.pool).await?;
        let invite_id_uuid = ids::typed_uuid_part_or_panic(invite_id);
        sql_query(
            "SELECT id, realm_id, inviter_id AS inviter, invitee_id AS invitee, invite_delivery_target, introduction_evidence_digest, third_party_id, join_rule_snapshot, invite_token, status, claim_nonces, expires_at, created_at, updated_at \
             FROM realm_invites WHERE id = $1",
        )
        .bind::<SqlUuid, _>(invite_id_uuid)
        .get_result::<RealmInviteRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(RealmInviteRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn put(&self, record: RealmInviteRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let invite_id_uuid = ids::typed_uuid_part_or_panic(&record.invite_id);
        let realm_id_uuid = ids::typed_uuid_part_or_panic(&record.realm_id);
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
        .map_err(PersistenceError::from)
    }

    async fn consume_third_party_token(
        &self,
        token_digest: &str,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<Option<RealmInviteRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .map_err(PersistenceError::from)?;
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
        .map_err(PersistenceError::from)?;
        Ok(None)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<RealmInviteRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id, realm_id, inviter_id AS inviter, invitee_id AS invitee, invite_delivery_target, introduction_evidence_digest, third_party_id, join_rule_snapshot, invite_token, status, claim_nonces, expires_at, created_at, updated_at \
             FROM realm_invites ORDER BY created_at ASC, id ASC",
        )
        .load::<RealmInviteRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(RealmInviteRecord::from).collect())
        .map_err(PersistenceError::from)
    }
}

fn remove_third_party_active_material(third_party_id: &mut Option<Value>, remove_commitment: bool) {
    let Some(value) = third_party_id.as_mut() else {
        return;
    };
    let Some(object) = value.as_object_mut() else {
        return;
    };
    for key in [
        "token_salt",
        "token_salt_id",
        "lookup_table_ref",
        "pepper",
        "pepper_id",
    ] {
        object.remove(key);
    }
    if remove_commitment {
        object.remove("token_commitment");
    }
}

// ── Pg-backed recovery / realtime sub-stores ─────────────────────────────
//
// `PgKeyBackupStore` persists the encrypted-key-backup envelopes
// (`key_backups`, one row per `backup_id`).
//
// `PgPolicyDocumentStore` mirrors the round-26 schema-store pattern:
// typed `policy_id / owner / scope / subject_ref / policy_type` columns
// for query predicates plus the canonical `document` JSONB.
