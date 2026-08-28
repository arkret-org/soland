use super::{
    Bool, HandleClaimEvidenceRecord, Jsonb, MemberIdentityEventRecord, MemberIdentityStore,
    MemberIdentitySubjectKey, Nullable, PersistenceError, PersistenceResult, PgPool,
    QueryableByName, RunQueryDsl, Text, Timestamptz, Value, async_trait, pg_conn, sql_query,
};

/// PostgreSQL-backed member-identity registry store. `soland-http` keeps its
/// synchronous in-memory effective-set projection and writes through to this
/// store; startup hydration rebuilds the projection from these rows.
pub struct PgMemberIdentityStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct MemberIdentityEventRow {
    #[diesel(sql_type = Text)]
    event_id: String,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    actor_id: String,
    #[diesel(sql_type = Text)]
    segment: String,
    #[diesel(sql_type = Text)]
    payload_digest: String,
    #[diesel(sql_type = Jsonb)]
    replaces: Value,
    #[diesel(sql_type = Jsonb)]
    raw_event: Value,
}

impl From<MemberIdentityEventRow> for MemberIdentityEventRecord {
    fn from(row: MemberIdentityEventRow) -> Self {
        Self {
            event_id: row.event_id,
            subject: MemberIdentitySubjectKey {
                realm_id: row.realm_id,
                actor_id: row.actor_id,
                segment: row.segment,
            },
            payload_digest: row.payload_digest,
            replaces: serde_json::from_value(row.replaces).unwrap_or_default(),
            raw_event: row.raw_event,
        }
    }
}

#[derive(QueryableByName)]
struct HandleClaimRow {
    #[diesel(sql_type = Text)]
    digest: String,
    #[diesel(sql_type = Text)]
    subject_id: String,
    #[diesel(sql_type = Text)]
    issuer: String,
    #[diesel(sql_type = Nullable<Text>)]
    issuer_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    audience: Option<String>,
    #[diesel(sql_type = Text)]
    binding_state: String,
    #[diesel(sql_type = Nullable<Text>)]
    visibility: Option<String>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Bool)]
    revoked: bool,
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
}

impl From<HandleClaimRow> for HandleClaimEvidenceRecord {
    fn from(row: HandleClaimRow) -> Self {
        Self {
            digest: row.digest,
            subject_id: row.subject_id,
            issuer: row.issuer,
            issuer_id: row.issuer_id,
            audience: row.audience,
            binding_state: row.binding_state,
            visibility: row.visibility,
            expires_at: row.expires_at,
            revoked: row.revoked,
            envelope: row.envelope,
        }
    }
}

const HANDLE_CLAIM_COLUMNS: &str = "digest, subject_id, issuer, issuer_id, audience, \
     binding_state, visibility, expires_at, revoked, envelope";

#[async_trait]
impl MemberIdentityStore for PgMemberIdentityStore {
    async fn put_event(&self, record: &MemberIdentityEventRecord) -> PersistenceResult<()> {
        let replaces = serde_json::to_value(&record.replaces).map_err(|error| {
            PersistenceError::Internal(format!("cannot encode member identity replaces: {error}"))
        })?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        // Upsert: replay re-projection lands the same `event_id` row again.
        sql_query(
            "INSERT INTO member_identity_events \
             (event_id, realm_id, actor_id, segment, payload_digest, replaces, raw_event) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (event_id) DO UPDATE SET \
                realm_id = EXCLUDED.realm_id, \
                actor_id = EXCLUDED.actor_id, \
                segment = EXCLUDED.segment, \
                payload_digest = EXCLUDED.payload_digest, \
                replaces = EXCLUDED.replaces, \
                raw_event = EXCLUDED.raw_event",
        )
        .bind::<Text, _>(&record.event_id)
        .bind::<Text, _>(&record.subject.realm_id)
        .bind::<Text, _>(&record.subject.actor_id)
        .bind::<Text, _>(&record.subject.segment)
        .bind::<Text, _>(&record.payload_digest)
        .bind::<Jsonb, _>(&replaces)
        .bind::<Jsonb, _>(&record.raw_event)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn snapshot_events(&self) -> PersistenceResult<Vec<MemberIdentityEventRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT event_id, realm_id, actor_id, segment, payload_digest, replaces, raw_event \
             FROM member_identity_events ORDER BY event_id",
        )
        .load::<MemberIdentityEventRow>(&mut *conn)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(MemberIdentityEventRecord::from)
                .collect()
        })
        .map_err(PersistenceError::database)
    }

    async fn put_handle_claim(&self, record: &HandleClaimEvidenceRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO member_identity_handle_claims \
             (digest, subject_id, issuer, issuer_id, audience, binding_state, visibility, \
              expires_at, revoked, envelope) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (subject_id, digest) DO UPDATE SET \
                issuer = EXCLUDED.issuer, \
                issuer_id = EXCLUDED.issuer_id, \
                audience = EXCLUDED.audience, \
                binding_state = EXCLUDED.binding_state, \
                visibility = EXCLUDED.visibility, \
                expires_at = EXCLUDED.expires_at, \
                revoked = EXCLUDED.revoked, \
                envelope = EXCLUDED.envelope",
        )
        .bind::<Text, _>(&record.digest)
        .bind::<Text, _>(&record.subject_id)
        .bind::<Text, _>(&record.issuer)
        .bind::<Nullable<Text>, _>(&record.issuer_id)
        .bind::<Nullable<Text>, _>(&record.audience)
        .bind::<Text, _>(&record.binding_state)
        .bind::<Nullable<Text>, _>(&record.visibility)
        .bind::<Nullable<Timestamptz>, _>(record.expires_at)
        .bind::<Bool, _>(record.revoked)
        .bind::<Jsonb, _>(&record.envelope)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn delete_handle_claims_for_subject(&self, subject_id: &str) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM member_identity_handle_claims WHERE subject_id = $1")
            .bind::<Text, _>(subject_id)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)
    }

    async fn snapshot_handle_claims(&self) -> PersistenceResult<Vec<HandleClaimEvidenceRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(format!(
            "SELECT {HANDLE_CLAIM_COLUMNS} FROM member_identity_handle_claims \
             ORDER BY subject_id, digest"
        ))
        .load::<HandleClaimRow>(&mut *conn)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(HandleClaimEvidenceRecord::from)
                .collect()
        })
        .map_err(PersistenceError::database)
    }
}
