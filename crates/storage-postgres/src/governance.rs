use super::{
    BTreeMap, BTreeSet, BigInt, Bool, HandleReleaseStore, Jsonb, Nullable, OptionalExtension,
    OrganizationPolicyRecord, OrganizationPolicyStore, OrganizationRecord, OrganizationStore,
    PersistenceError, PersistenceResult, PgPool, QueryableByName, RealmModerationPolicyRecord,
    RealmModerationPolicyStore, RealmOrganizationStatementRecord, RealmOrganizationStatementStore,
    RealmOrganizationStore, RetentionPolicyRecord, RetentionPolicyStore, RetentionTombstoneRecord,
    RetentionTombstoneStore, RunQueryDsl, Text, Timestamptz, Value, async_trait, json_string_array,
    pg_conn, sql_query,
};
pub struct PgHandleReleaseStore {
    pub pool: PgPool,
}
#[async_trait]
impl HandleReleaseStore for PgHandleReleaseStore {
    async fn put(
        &self,
        localpart: &str,
        released_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO handle_releases (localpart, released_at) \
             VALUES ($1, $2) \
             ON CONFLICT (localpart) DO UPDATE SET released_at = EXCLUDED.released_at",
        )
        .bind::<Text, _>(localpart)
        .bind::<Timestamptz, _>(released_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn snapshot_all(
        &self,
    ) -> PersistenceResult<Vec<(String, chrono::DateTime<chrono::Utc>)>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("SELECT localpart, released_at FROM handle_releases ORDER BY localpart")
            .load::<HandleReleaseRow>(&mut *conn)
            .await
            .map(|rows| {
                rows.into_iter()
                    .map(|row| (row.localpart, row.released_at))
                    .collect()
            })
            .map_err(PersistenceError::database)
    }
}
#[derive(QueryableByName)]
struct HandleReleaseRow {
    #[diesel(sql_type = Text)]
    localpart: String,
    #[diesel(sql_type = Timestamptz)]
    released_at: chrono::DateTime<chrono::Utc>,
}
pub struct PgRetentionPolicyStore {
    pub pool: PgPool,
}
#[async_trait]
impl RetentionPolicyStore for PgRetentionPolicyStore {
    async fn get(&self, realm_id: &str) -> PersistenceResult<Option<RetentionPolicyRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT realm_id, ttl_seconds, updated_by, updated_at \
             FROM retention_policies WHERE realm_id = $1",
        )
        .bind::<Text, _>(realm_id)
        .get_result::<RetentionPolicyRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(RetentionPolicyRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn put(&self, record: &RetentionPolicyRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO retention_policies (realm_id, ttl_seconds, updated_by, updated_at) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (realm_id) DO UPDATE SET \
               ttl_seconds = EXCLUDED.ttl_seconds, \
               updated_by = EXCLUDED.updated_by, \
               updated_at = EXCLUDED.updated_at",
        )
        .bind::<Text, _>(&record.realm_id)
        .bind::<BigInt, _>(record.ttl_seconds)
        .bind::<Text, _>(&record.updated_by)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<RetentionPolicyRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT realm_id, ttl_seconds, updated_by, updated_at \
             FROM retention_policies ORDER BY realm_id",
        )
        .load::<RetentionPolicyRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(RetentionPolicyRecord::from).collect())
        .map_err(PersistenceError::database)
    }
}
#[derive(QueryableByName)]
struct RetentionPolicyRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = BigInt)]
    ttl_seconds: i64,
    #[diesel(sql_type = Text)]
    updated_by: String,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}
impl From<RetentionPolicyRow> for RetentionPolicyRecord {
    fn from(row: RetentionPolicyRow) -> Self {
        Self {
            realm_id: row.realm_id,
            ttl_seconds: row.ttl_seconds,
            updated_by: row.updated_by,
            updated_at: row.updated_at,
        }
    }
}
pub struct PgRetentionTombstoneStore {
    pub pool: PgPool,
}
#[async_trait]
impl RetentionTombstoneStore for PgRetentionTombstoneStore {
    async fn get(&self, event_id: &str) -> PersistenceResult<Option<RetentionTombstoneRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT event_id, realm_id, reason, policy_ttl_seconds, expired_at, tombstoned_at, sealed \
             FROM retention_tombstones WHERE event_id = $1",
        )
        .bind::<Text, _>(event_id)
        .get_result::<RetentionTombstoneRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(RetentionTombstoneRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn put(&self, record: &RetentionTombstoneRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO retention_tombstones \
             (event_id, realm_id, reason, policy_ttl_seconds, expired_at, tombstoned_at, sealed) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (event_id) DO UPDATE SET \
               realm_id = EXCLUDED.realm_id, \
               reason = EXCLUDED.reason, \
               policy_ttl_seconds = EXCLUDED.policy_ttl_seconds, \
               expired_at = EXCLUDED.expired_at, \
               tombstoned_at = EXCLUDED.tombstoned_at, \
               sealed = EXCLUDED.sealed",
        )
        .bind::<Text, _>(&record.event_id)
        .bind::<Text, _>(&record.realm_id)
        .bind::<Text, _>(&record.reason)
        .bind::<BigInt, _>(record.policy_ttl_seconds)
        .bind::<Timestamptz, _>(record.expired_at)
        .bind::<Timestamptz, _>(record.tombstoned_at)
        .bind::<Bool, _>(record.sealed)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<RetentionTombstoneRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT event_id, realm_id, reason, policy_ttl_seconds, expired_at, tombstoned_at, sealed \
             FROM retention_tombstones ORDER BY event_id",
        )
        .load::<RetentionTombstoneRow>(&mut *conn)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(RetentionTombstoneRecord::from)
                .collect()
        })
        .map_err(PersistenceError::database)
    }
}
#[derive(QueryableByName)]
struct RetentionTombstoneRow {
    #[diesel(sql_type = Text)]
    event_id: String,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    reason: String,
    #[diesel(sql_type = BigInt)]
    policy_ttl_seconds: i64,
    #[diesel(sql_type = Timestamptz)]
    expired_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    tombstoned_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Bool)]
    sealed: bool,
}
impl From<RetentionTombstoneRow> for RetentionTombstoneRecord {
    fn from(row: RetentionTombstoneRow) -> Self {
        Self {
            event_id: row.event_id,
            realm_id: row.realm_id,
            reason: row.reason,
            policy_ttl_seconds: row.policy_ttl_seconds,
            expired_at: row.expired_at,
            tombstoned_at: row.tombstoned_at,
            sealed: row.sealed,
        }
    }
}
pub struct PgOrganizationStore {
    pub pool: PgPool,
}
#[async_trait]
impl OrganizationStore for PgOrganizationStore {
    async fn get(&self, organization_id: &str) -> PersistenceResult<Option<OrganizationRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT organization_id, organization_did, handle, display_name, source_refs, \
                    policy_revision, verified, members, member_count, created_by, created_at, \
                    updated_at \
             FROM organizations WHERE organization_id = $1",
        )
        .bind::<Text, _>(organization_id)
        .get_result::<OrganizationRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(OrganizationRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn put(&self, record: &OrganizationRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let members = serde_json::to_value(record.members.iter().collect::<Vec<_>>())
            .unwrap_or_else(|_| Value::Array(Vec::new()));
        let member_count = i64::try_from(record.member_count).unwrap_or(i64::MAX);
        sql_query(
            "INSERT INTO organizations \
             (organization_id, organization_did, handle, display_name, source_refs, \
              policy_revision, verified, members, member_count, created_by, created_at, \
              updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
             ON CONFLICT (organization_id) DO UPDATE SET \
               organization_did = EXCLUDED.organization_did, \
               handle = EXCLUDED.handle, \
               display_name = EXCLUDED.display_name, \
               source_refs = EXCLUDED.source_refs, \
               policy_revision = EXCLUDED.policy_revision, \
               verified = EXCLUDED.verified, \
               members = EXCLUDED.members, \
               member_count = EXCLUDED.member_count, \
               updated_at = EXCLUDED.updated_at",
        )
        .bind::<Text, _>(&record.organization_id)
        .bind::<Text, _>(&record.organization_did)
        .bind::<Nullable<Text>, _>(&record.handle)
        .bind::<Text, _>(&record.display_name)
        .bind::<Jsonb, _>(
            &serde_json::to_value(&record.source_refs).unwrap_or_else(|_| Value::Array(Vec::new())),
        )
        .bind::<Text, _>(&record.policy_revision)
        .bind::<Bool, _>(record.verified)
        .bind::<Jsonb, _>(&members)
        .bind::<BigInt, _>(member_count)
        .bind::<Text, _>(&record.created_by)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn list(&self) -> PersistenceResult<Vec<OrganizationRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT organization_id, organization_did, handle, display_name, source_refs, \
                    policy_revision, verified, members, member_count, created_by, created_at, \
                    updated_at \
             FROM organizations ORDER BY organization_id",
        )
        .load::<OrganizationRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(OrganizationRecord::from).collect())
        .map_err(PersistenceError::database)
    }
}
#[derive(QueryableByName)]
struct OrganizationRow {
    #[diesel(sql_type = Text)]
    organization_id: String,
    #[diesel(sql_type = Text)]
    organization_did: String,
    #[diesel(sql_type = Nullable<Text>)]
    handle: Option<String>,
    #[diesel(sql_type = Text)]
    display_name: String,
    #[diesel(sql_type = Jsonb)]
    source_refs: Value,
    #[diesel(sql_type = Text)]
    policy_revision: String,
    #[diesel(sql_type = Bool)]
    verified: bool,
    #[diesel(sql_type = Jsonb)]
    members: Value,
    #[diesel(sql_type = BigInt)]
    member_count: i64,
    #[diesel(sql_type = Text)]
    created_by: String,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}
impl From<OrganizationRow> for OrganizationRecord {
    fn from(row: OrganizationRow) -> Self {
        let members = json_string_array(row.members)
            .into_iter()
            .collect::<BTreeSet<_>>();
        Self {
            organization_id: row.organization_id,
            organization_did: row.organization_did,
            handle: row.handle,
            display_name: row.display_name,
            source_refs: json_string_array(row.source_refs),
            policy_revision: row.policy_revision,
            verified: row.verified,
            member_count: usize::try_from(row.member_count.max(0)).unwrap_or(usize::MAX),
            members,
            created_by: row.created_by,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}
pub struct PgOrganizationPolicyStore {
    pub pool: PgPool,
}
#[async_trait]
impl OrganizationPolicyStore for PgOrganizationPolicyStore {
    async fn get(
        &self,
        organization_id: &str,
    ) -> PersistenceResult<Option<OrganizationPolicyRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT organization_id, policy_id, payload, version, updated_by, updated_at \
             FROM organization_policies WHERE organization_id = $1",
        )
        .bind::<Text, _>(organization_id)
        .get_result::<OrganizationPolicyRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(OrganizationPolicyRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn put(&self, record: &OrganizationPolicyRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let version = i64::try_from(record.version).unwrap_or(i64::MAX);
        sql_query(
            "INSERT INTO organization_policies \
             (organization_id, policy_id, payload, version, updated_by, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (organization_id) DO UPDATE SET \
               policy_id = EXCLUDED.policy_id, \
               payload = EXCLUDED.payload, \
               version = EXCLUDED.version, \
               updated_by = EXCLUDED.updated_by, \
               updated_at = EXCLUDED.updated_at",
        )
        .bind::<Text, _>(&record.organization_id)
        .bind::<Text, _>(&record.policy_id)
        .bind::<Jsonb, _>(&record.payload)
        .bind::<BigInt, _>(version)
        .bind::<Text, _>(&record.updated_by)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<OrganizationPolicyRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT organization_id, policy_id, payload, version, updated_by, updated_at \
             FROM organization_policies ORDER BY organization_id",
        )
        .load::<OrganizationPolicyRow>(&mut *conn)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(OrganizationPolicyRecord::from)
                .collect()
        })
        .map_err(PersistenceError::database)
    }
}
#[derive(QueryableByName)]
struct OrganizationPolicyRow {
    #[diesel(sql_type = Text)]
    organization_id: String,
    #[diesel(sql_type = Text)]
    policy_id: String,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
    #[diesel(sql_type = BigInt)]
    version: i64,
    #[diesel(sql_type = Text)]
    updated_by: String,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}
impl From<OrganizationPolicyRow> for OrganizationPolicyRecord {
    fn from(row: OrganizationPolicyRow) -> Self {
        Self {
            organization_id: row.organization_id,
            policy_id: row.policy_id,
            payload: row.payload,
            version: u64::try_from(row.version.max(0)).unwrap_or(u64::MAX),
            updated_by: row.updated_by,
            updated_at: row.updated_at,
        }
    }
}
pub struct PgRealmOrganizationStore {
    pub pool: PgPool,
}
#[async_trait]
impl RealmOrganizationStore for PgRealmOrganizationStore {
    async fn link(&self, realm_id: &str, organization_id: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO realm_owning_organizations (realm_id, organization_id, linked_at) \
             VALUES ($1, $2, NOW()) \
             ON CONFLICT (realm_id, organization_id) DO NOTHING",
        )
        .bind::<Text, _>(realm_id)
        .bind::<Text, _>(organization_id)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<(String, BTreeSet<String>)>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT realm_id, organization_id FROM realm_owning_organizations \
             ORDER BY realm_id, organization_id",
        )
        .load::<RealmOrganizationRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        let mut out = BTreeMap::<String, BTreeSet<String>>::new();
        for row in rows {
            out.entry(row.realm_id)
                .or_default()
                .insert(row.organization_id);
        }
        Ok(out.into_iter().collect())
    }
}
#[derive(QueryableByName)]
struct RealmOrganizationRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    organization_id: String,
}
pub struct PgRealmOrganizationStatementStore {
    pub pool: PgPool,
}
#[async_trait]
impl RealmOrganizationStatementStore for PgRealmOrganizationStatementStore {
    async fn put(&self, record: &RealmOrganizationStatementRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let control_scopes = serde_json::to_value(&record.control_scopes)
            .unwrap_or_else(|_| Value::Array(Vec::new()));
        sql_query(
            "INSERT INTO realm_organizations \
             (realm_id, organization_id, relationship, statement_id, status, control_scopes, \
              issued_at, not_before, expires_at, supersedes_statement_id, revokes_statement_id, \
              realm_frontier_digest, proof_digest, delegation_ref, issuer_role, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) \
             ON CONFLICT (realm_id, organization_id, relationship) DO UPDATE SET \
               statement_id = EXCLUDED.statement_id, \
               status = EXCLUDED.status, \
               control_scopes = EXCLUDED.control_scopes, \
               issued_at = EXCLUDED.issued_at, \
               not_before = EXCLUDED.not_before, \
               expires_at = EXCLUDED.expires_at, \
               supersedes_statement_id = EXCLUDED.supersedes_statement_id, \
               revokes_statement_id = EXCLUDED.revokes_statement_id, \
               realm_frontier_digest = EXCLUDED.realm_frontier_digest, \
               proof_digest = EXCLUDED.proof_digest, \
               delegation_ref = EXCLUDED.delegation_ref, \
               issuer_role = EXCLUDED.issuer_role, \
               updated_at = EXCLUDED.updated_at",
        )
        .bind::<Text, _>(&record.realm_id)
        .bind::<Text, _>(&record.organization_id)
        .bind::<Text, _>(&record.relationship)
        .bind::<Text, _>(&record.statement_id)
        .bind::<Text, _>(&record.status)
        .bind::<Jsonb, _>(&control_scopes)
        .bind::<Timestamptz, _>(record.issued_at)
        .bind::<Nullable<Timestamptz>, _>(record.not_before)
        .bind::<Nullable<Timestamptz>, _>(record.expires_at)
        .bind::<Nullable<Text>, _>(&record.supersedes_statement_id)
        .bind::<Nullable<Text>, _>(&record.revokes_statement_id)
        .bind::<Nullable<Text>, _>(&record.realm_frontier_digest)
        .bind::<Nullable<Text>, _>(&record.proof_digest)
        .bind::<Nullable<Text>, _>(&record.delegation_ref)
        .bind::<Text, _>(&record.issuer_role)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<RealmOrganizationStatementRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT realm_id, organization_id, relationship, statement_id, status, control_scopes, \
                    issued_at, not_before, expires_at, supersedes_statement_id, \
                    revokes_statement_id, realm_frontier_digest, proof_digest, delegation_ref, \
                    issuer_role, updated_at \
             FROM realm_organizations \
             ORDER BY realm_id, organization_id, relationship",
        )
        .load::<RealmOrganizationStatementRow>(&mut *conn)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(RealmOrganizationStatementRecord::from)
                .collect()
        })
        .map_err(PersistenceError::database)
    }
}
#[derive(QueryableByName)]
struct RealmOrganizationStatementRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    organization_id: String,
    #[diesel(sql_type = Text)]
    relationship: String,
    #[diesel(sql_type = Text)]
    statement_id: String,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = Jsonb)]
    control_scopes: Value,
    #[diesel(sql_type = Timestamptz)]
    issued_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    not_before: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Nullable<Text>)]
    supersedes_statement_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    revokes_statement_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    realm_frontier_digest: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    proof_digest: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    delegation_ref: Option<String>,
    #[diesel(sql_type = Text)]
    issuer_role: String,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}
impl From<RealmOrganizationStatementRow> for RealmOrganizationStatementRecord {
    fn from(row: RealmOrganizationStatementRow) -> Self {
        Self {
            realm_id: row.realm_id,
            organization_id: row.organization_id,
            relationship: row.relationship,
            statement_id: row.statement_id,
            status: row.status,
            control_scopes: json_string_array(row.control_scopes),
            issued_at: row.issued_at,
            not_before: row.not_before,
            expires_at: row.expires_at,
            supersedes_statement_id: row.supersedes_statement_id,
            revokes_statement_id: row.revokes_statement_id,
            realm_frontier_digest: row.realm_frontier_digest,
            proof_digest: row.proof_digest,
            delegation_ref: row.delegation_ref,
            issuer_role: row.issuer_role,
            updated_at: row.updated_at,
        }
    }
}
pub struct PgRealmModerationPolicyStore {
    pub pool: PgPool,
}
#[async_trait]
impl RealmModerationPolicyStore for PgRealmModerationPolicyStore {
    async fn get(&self, realm_id: &str) -> PersistenceResult<Option<RealmModerationPolicyRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT realm_id, payload, updated_by, updated_at \
             FROM realm_moderation_policies WHERE realm_id = $1",
        )
        .bind::<Text, _>(realm_id)
        .get_result::<RealmModerationPolicyRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(RealmModerationPolicyRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn put(&self, record: &RealmModerationPolicyRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO realm_moderation_policies (realm_id, payload, updated_by, updated_at) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (realm_id) DO UPDATE SET \
               payload = EXCLUDED.payload, \
               updated_by = EXCLUDED.updated_by, \
               updated_at = EXCLUDED.updated_at",
        )
        .bind::<Text, _>(&record.realm_id)
        .bind::<Jsonb, _>(&record.payload)
        .bind::<Text, _>(&record.updated_by)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<RealmModerationPolicyRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT realm_id, payload, updated_by, updated_at \
             FROM realm_moderation_policies ORDER BY realm_id",
        )
        .load::<RealmModerationPolicyRow>(&mut *conn)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(RealmModerationPolicyRecord::from)
                .collect()
        })
        .map_err(PersistenceError::database)
    }
}
#[derive(QueryableByName)]
struct RealmModerationPolicyRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
    #[diesel(sql_type = Text)]
    updated_by: String,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}
impl From<RealmModerationPolicyRow> for RealmModerationPolicyRecord {
    fn from(row: RealmModerationPolicyRow) -> Self {
        Self {
            realm_id: row.realm_id,
            payload: row.payload,
            updated_by: row.updated_by,
            updated_at: row.updated_at,
        }
    }
}
