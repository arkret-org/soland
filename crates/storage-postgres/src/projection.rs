use super::{
    BigInt, Jsonb, MorphProjectionRecord, MorphProjectionStore, Nullable, Operation,
    OptionalExtension, PersistenceError, PersistenceResult, PgPool, ProjectionEventAppendOutcome,
    ProjectionEventRecord, ProjectionEventStore, QueryableByName, RunQueryDsl,
    SpaceContainerProjectionRecord, SpaceContainerProjectionStore, SqlUuid, StrandProjectionRecord,
    StrandProjectionStore, Text, Timestamptz, Uuid, Value, async_trait, ids, pg_conn,
    projected_operation_realm_discoverability, projected_operation_realm_summary,
    projected_operation_realm_title, sql_query,
};
pub struct PgSpaceContainerProjectionStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct SpaceContainerProjectionRow {
    #[diesel(sql_type = SqlUuid)]
    container_space_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    realm_id: Uuid,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    scope_circle_id: Option<Uuid>,
    #[diesel(sql_type = Nullable<Text>)]
    child_scope_policy: Option<String>,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    child_scope_policy_scope_circle_id: Option<Uuid>,
    #[diesel(sql_type = Text)]
    kind: String,
    #[diesel(sql_type = Text)]
    title: String,
    #[diesel(sql_type = Jsonb)]
    fields: Value,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    parent_ref: Option<Uuid>,
    #[diesel(sql_type = Nullable<Text>)]
    rank: Option<String>,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Text)]
    created_by: String,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Jsonb)]
    history_basis_seals: Value,
    #[diesel(sql_type = Nullable<Text>)]
    updated_by: Option<String>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}
impl From<SpaceContainerProjectionRow> for SpaceContainerProjectionRecord {
    fn from(row: SpaceContainerProjectionRow) -> Self {
        Self {
            container_space_id: ids::format_typed_uuid("space", &row.container_space_id),
            realm_id: ids::format_typed_uuid("realm", &row.realm_id),
            kind: row.kind,
            title: row.title,
            fields: serde_json::from_value(row.fields).unwrap_or_default(),
            scope_circle_id: row
                .scope_circle_id
                .map(|u| ids::format_typed_uuid("circle", &u)),
            child_scope_policy: row.child_scope_policy,
            child_scope_policy_scope_circle_id: row
                .child_scope_policy_scope_circle_id
                .map(|u| ids::format_typed_uuid("circle", &u)),
            parent_ref: row.parent_ref.map(|u| ids::format_typed_uuid("space", &u)),
            rank: row.rank,
            state: row.state,
            state_changed_at: row.state_changed_at,
            created_by: row.created_by,
            created_at: row.created_at,
            history_basis_seals: serde_json::from_value(row.history_basis_seals)
                .unwrap_or_default(),
            updated_by: row.updated_by,
            updated_at: row.updated_at,
        }
    }
}
const SPACE_CONTAINER_PROJECTION_COLUMNS: &str = "id AS container_space_id, realm_id, scope_circle_id, \
     child_scope_policy, child_scope_policy_scope_circle_id, kind, title, fields, parent_ref, rank, state, \
     state_changed_at, created_by_id AS created_by, created_at, history_basis_seals, updated_by_id AS updated_by, updated_at";
#[async_trait]
impl SpaceContainerProjectionStore for PgSpaceContainerProjectionStore {
    async fn get(
        &self,
        container_space_id: &str,
    ) -> PersistenceResult<Option<SpaceContainerProjectionRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(format!(
            "SELECT {SPACE_CONTAINER_PROJECTION_COLUMNS} FROM projection_spaces WHERE id = $1"
        ))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(container_space_id))
        .get_result::<SpaceContainerProjectionRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(SpaceContainerProjectionRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn put(&self, record: &SpaceContainerProjectionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO projection_spaces \
             (id, realm_id, scope_circle_id, child_scope_policy, \
              child_scope_policy_scope_circle_id, \
              kind, title, fields, parent_ref, rank, state, state_changed_at, created_by_id, created_at, \
              history_basis_seals, updated_by_id, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17) \
             ON CONFLICT (id) DO UPDATE SET \
                realm_id = EXCLUDED.realm_id, \
                scope_circle_id = EXCLUDED.scope_circle_id, \
                child_scope_policy = EXCLUDED.child_scope_policy, \
                child_scope_policy_scope_circle_id = EXCLUDED.child_scope_policy_scope_circle_id, \
                kind = EXCLUDED.kind, \
                title = EXCLUDED.title, \
                fields = EXCLUDED.fields, \
                parent_ref = EXCLUDED.parent_ref, \
                rank = EXCLUDED.rank, \
                state = EXCLUDED.state, \
                state_changed_at = EXCLUDED.state_changed_at, \
                history_basis_seals = EXCLUDED.history_basis_seals, \
                updated_by_id = EXCLUDED.updated_by_id, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&record.container_space_id))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&record.realm_id))
        .bind::<Nullable<SqlUuid>, _>(
            record
                .scope_circle_id
                .as_deref()
                .map(ids::typed_uuid_part_expect_internal),
        )
        .bind::<Nullable<Text>, _>(&record.child_scope_policy)
        .bind::<Nullable<SqlUuid>, _>(
            record
                .child_scope_policy_scope_circle_id
                .as_deref()
                .map(ids::typed_uuid_part_expect_internal),
        )
        .bind::<Text, _>(&record.kind)
        .bind::<Text, _>(&record.title)
        .bind::<Jsonb, _>(&serde_json::json!(record.fields))
        .bind::<Nullable<SqlUuid>, _>(
            record
                .parent_ref
                .as_deref()
                .map(ids::typed_uuid_part_expect_internal),
        )
        .bind::<Nullable<Text>, _>(&record.rank)
        .bind::<Text, _>(&record.state)
        .bind::<Nullable<Timestamptz>, _>(record.state_changed_at)
        .bind::<Text, _>(&record.created_by)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Jsonb, _>(&serde_json::json!(record.history_basis_seals))
        .bind::<Nullable<Text>, _>(&record.updated_by)
        .bind::<Nullable<Timestamptz>, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<SpaceContainerProjectionRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(format!(
            "SELECT {SPACE_CONTAINER_PROJECTION_COLUMNS} FROM projection_spaces \
             WHERE realm_id = $1 ORDER BY id"
        ))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(realm_id))
        .load::<SpaceContainerProjectionRow>(&mut *conn)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(SpaceContainerProjectionRecord::from)
                .collect()
        })
        .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<SpaceContainerProjectionRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(format!(
            "SELECT {SPACE_CONTAINER_PROJECTION_COLUMNS} FROM projection_spaces ORDER BY id"
        ))
        .load::<SpaceContainerProjectionRow>(&mut *conn)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(SpaceContainerProjectionRecord::from)
                .collect()
        })
        .map_err(PersistenceError::database)
    }

    async fn delete(&self, container_space_id: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM projection_spaces WHERE id = $1")
            .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(container_space_id))
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::database)
    }
}
pub struct PgStrandProjectionStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct StrandProjectionRow {
    #[diesel(sql_type = SqlUuid)]
    strand_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    realm_id: Uuid,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    scope_circle_id: Option<Uuid>,
    #[diesel(sql_type = Jsonb)]
    tracks: serde_json::Value,
    #[diesel(sql_type = Text)]
    title: String,
    #[diesel(sql_type = Nullable<Text>)]
    summary: Option<String>,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Text)]
    created_by: String,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Jsonb)]
    history_basis_seals: Value,
    #[diesel(sql_type = Nullable<Text>)]
    updated_by: Option<String>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}
impl From<StrandProjectionRow> for StrandProjectionRecord {
    fn from(row: StrandProjectionRow) -> Self {
        Self {
            strand_id: ids::format_typed_uuid("strand", &row.strand_id),
            realm_id: ids::format_typed_uuid("realm", &row.realm_id),
            scope_circle_id: row
                .scope_circle_id
                .map(|u| ids::format_typed_uuid("circle", &u)),
            tracks: serde_json::from_value(row.tracks).unwrap_or_default(),
            title: row.title,
            summary: row.summary,
            state: row.state,
            state_changed_at: row.state_changed_at,
            created_by: row.created_by,
            created_at: row.created_at,
            history_basis_seals: serde_json::from_value(row.history_basis_seals)
                .unwrap_or_default(),
            updated_by: row.updated_by,
            updated_at: row.updated_at,
        }
    }
}
const STRAND_PROJECTION_COLUMNS: &str = "id AS strand_id, realm_id, scope_circle_id, tracks, title, summary, state, \
     state_changed_at, created_by_id AS created_by, created_at, history_basis_seals, updated_by_id AS updated_by, updated_at";
#[async_trait]
impl StrandProjectionStore for PgStrandProjectionStore {
    async fn get(&self, strand_id: &str) -> PersistenceResult<Option<StrandProjectionRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(format!(
            "SELECT {STRAND_PROJECTION_COLUMNS} FROM projection_strands WHERE id = $1"
        ))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(strand_id))
        .get_result::<StrandProjectionRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(StrandProjectionRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn put(&self, record: &StrandProjectionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let tracks = serde_json::to_value(&record.tracks)
            .unwrap_or_else(|_| Value::Object(Default::default()));
        sql_query(
            "INSERT INTO projection_strands \
             (id, realm_id, scope_circle_id, tracks, title, summary, state, state_changed_at, \
              created_by_id, created_at, history_basis_seals, updated_by_id, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
             ON CONFLICT (id) DO UPDATE SET \
                realm_id = EXCLUDED.realm_id, \
                scope_circle_id = EXCLUDED.scope_circle_id, \
                tracks = EXCLUDED.tracks, \
                title = EXCLUDED.title, \
                summary = EXCLUDED.summary, \
                state = EXCLUDED.state, \
                state_changed_at = EXCLUDED.state_changed_at, \
                history_basis_seals = EXCLUDED.history_basis_seals, \
                updated_by_id = EXCLUDED.updated_by_id, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&record.strand_id))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&record.realm_id))
        .bind::<Nullable<SqlUuid>, _>(
            record
                .scope_circle_id
                .as_deref()
                .map(ids::typed_uuid_part_expect_internal),
        )
        .bind::<Jsonb, _>(&tracks)
        .bind::<Text, _>(&record.title)
        .bind::<Nullable<Text>, _>(&record.summary)
        .bind::<Text, _>(&record.state)
        .bind::<Nullable<Timestamptz>, _>(record.state_changed_at)
        .bind::<Text, _>(&record.created_by)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Jsonb, _>(&serde_json::json!(record.history_basis_seals))
        .bind::<Nullable<Text>, _>(&record.updated_by)
        .bind::<Nullable<Timestamptz>, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<StrandProjectionRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(format!(
            "SELECT {STRAND_PROJECTION_COLUMNS} FROM projection_strands \
             WHERE realm_id = $1 ORDER BY id"
        ))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(realm_id))
        .load::<StrandProjectionRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(StrandProjectionRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<StrandProjectionRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(format!(
            "SELECT {STRAND_PROJECTION_COLUMNS} FROM projection_strands ORDER BY id"
        ))
        .load::<StrandProjectionRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(StrandProjectionRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn delete(&self, strand_id: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM projection_strands WHERE id = $1")
            .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(strand_id))
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::database)
    }
}
pub struct PgMorphProjectionStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct MorphProjectionRow {
    #[diesel(sql_type = SqlUuid)]
    morph_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    realm_id: Uuid,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    scope_circle_id: Option<Uuid>,
    #[diesel(sql_type = Text)]
    morph_type: String,
    #[diesel(sql_type = Nullable<Text>)]
    title: Option<String>,
    #[diesel(sql_type = Jsonb)]
    fields: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    schema_refs: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    facets: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    versions: serde_json::Value,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Text)]
    created_by: String,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Jsonb)]
    history_basis_seals: Value,
    #[diesel(sql_type = Nullable<Text>)]
    updated_by: Option<String>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}
impl From<MorphProjectionRow> for MorphProjectionRecord {
    fn from(row: MorphProjectionRow) -> Self {
        Self {
            morph_id: ids::format_typed_uuid("morph", &row.morph_id),
            realm_id: ids::format_typed_uuid("realm", &row.realm_id),
            scope_circle_id: row
                .scope_circle_id
                .map(|u| ids::format_typed_uuid("circle", &u)),
            morph_type: row.morph_type,
            title: row.title,
            fields: row.fields,
            schema_refs: row.schema_refs,
            facets: row.facets,
            versions: row.versions,
            state: row.state,
            state_changed_at: row.state_changed_at,
            created_by: row.created_by,
            created_at: row.created_at,
            history_basis_seals: serde_json::from_value(row.history_basis_seals)
                .unwrap_or_default(),
            updated_by: row.updated_by,
            updated_at: row.updated_at,
        }
    }
}
const MORPH_PROJECTION_COLUMNS: &str = "id AS morph_id, realm_id, scope_circle_id, morph_type, title, fields, \
     schema_refs, facets, versions, state, state_changed_at, created_by_id AS created_by, created_at, updated_by_id AS updated_by, \
     history_basis_seals, updated_at";
#[async_trait]
impl MorphProjectionStore for PgMorphProjectionStore {
    async fn get(&self, morph_id: &str) -> PersistenceResult<Option<MorphProjectionRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(format!(
            "SELECT {MORPH_PROJECTION_COLUMNS} FROM projection_morphs WHERE id = $1"
        ))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(morph_id))
        .get_result::<MorphProjectionRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(MorphProjectionRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn put(&self, record: &MorphProjectionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO projection_morphs \
             (id, realm_id, scope_circle_id, morph_type, title, fields, schema_refs, facets, versions, \
              state, state_changed_at, created_by_id, created_at, updated_by_id, history_basis_seals, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) \
             ON CONFLICT (id) DO UPDATE SET \
                realm_id = EXCLUDED.realm_id, \
                scope_circle_id = EXCLUDED.scope_circle_id, \
                morph_type = EXCLUDED.morph_type, \
                title = EXCLUDED.title, \
                fields = EXCLUDED.fields, \
                schema_refs = EXCLUDED.schema_refs, \
                facets = EXCLUDED.facets, \
                versions = EXCLUDED.versions, \
                state = EXCLUDED.state, \
                state_changed_at = EXCLUDED.state_changed_at, \
                updated_by_id = EXCLUDED.updated_by_id, \
                history_basis_seals = EXCLUDED.history_basis_seals, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&record.morph_id))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&record.realm_id))
        .bind::<Nullable<SqlUuid>, _>(
            record
                .scope_circle_id
                .as_deref()
                .map(ids::typed_uuid_part_expect_internal),
        )
        .bind::<Text, _>(&record.morph_type)
        .bind::<Nullable<Text>, _>(&record.title)
        .bind::<Jsonb, _>(&record.fields)
        .bind::<Jsonb, _>(&record.schema_refs)
        .bind::<Jsonb, _>(&record.facets)
        .bind::<Jsonb, _>(&record.versions)
        .bind::<Text, _>(&record.state)
        .bind::<Nullable<Timestamptz>, _>(record.state_changed_at)
        .bind::<Text, _>(&record.created_by)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Nullable<Text>, _>(&record.updated_by)
        .bind::<Jsonb, _>(&serde_json::json!(record.history_basis_seals))
        .bind::<Nullable<Timestamptz>, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<MorphProjectionRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(format!(
            "SELECT {MORPH_PROJECTION_COLUMNS} FROM projection_morphs \
             WHERE realm_id = $1 ORDER BY id"
        ))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(realm_id))
        .load::<MorphProjectionRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(MorphProjectionRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MorphProjectionRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(format!(
            "SELECT {MORPH_PROJECTION_COLUMNS} FROM projection_morphs ORDER BY id"
        ))
        .load::<MorphProjectionRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(MorphProjectionRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn delete(&self, morph_id: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM projection_morphs WHERE id = $1")
            .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(morph_id))
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::database)
    }
}
// ── Pg-backed projection_events store ────────────────────────────────────
// Append-only mirror of the in-memory ProjectionEventRecord stream
// stamped down by `routing::events::projection::append_projection_event`.
// `event_id` is unique so retries cannot create duplicate stream positions;
// the surrogate ordinal remains the storage primary key.

pub struct PgProjectionEventStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct ProjectionEventRow {
    #[diesel(sql_type = SqlUuid)]
    event_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    realm_id: Uuid,
    #[diesel(sql_type = Text)]
    event_kind: String,
    #[diesel(sql_type = Text)]
    operation_type: String,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    operation_id: Option<Uuid>,
    #[diesel(sql_type = Nullable<Text>)]
    sender: Option<String>,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    received_at: chrono::DateTime<chrono::Utc>,
}
impl From<ProjectionEventRow> for ProjectionEventRecord {
    fn from(row: ProjectionEventRow) -> Self {
        Self {
            event_id: ids::format_typed_uuid("event", &row.event_id),
            realm_id: ids::format_typed_uuid("realm", &row.realm_id),
            event_kind: row.event_kind,
            operation_type: row.operation_type,
            operation_id: row
                .operation_id
                .as_ref()
                .map(|u| ids::format_typed_uuid("operation", u)),
            sender: row.sender,
            payload: row.payload,
            created_at: row.created_at,
            received_at: row.received_at,
        }
    }
}
pub async fn load_projected_events_from_pg(
    pool: &PgPool,
    realm_id: &str,
) -> PersistenceResult<Vec<ProjectionEventRecord>> {
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    let realm_id_uuid = ids::typed_uuid_part_expect_internal(realm_id);
    sql_query(
        "SELECT e.id AS event_id, e.realm_id, e.event_type AS event_kind, 'event' AS operation_type, e.operation_id, e.sender_id AS sender, e.payload, e.created_at, COALESCE(ce.received_at, e.created_at) AS received_at \
         FROM events e LEFT JOIN canonical_events ce ON ce.id = e.id WHERE e.realm_id = $1 \
         UNION ALL \
         SELECT s.id AS event_id, s.realm_id, s.event_type AS event_kind, 'state' AS operation_type, s.operation_id, s.sender_id AS sender, s.payload, s.created_at, COALESCE(ce.received_at, s.created_at) AS received_at \
         FROM space_state_events s LEFT JOIN canonical_events ce ON ce.id = s.id OR ce.id = s.operation_id WHERE s.realm_id = $1 \
         ORDER BY received_at ASC, event_id ASC",
    )
    .bind::<SqlUuid, _>(realm_id_uuid)
    .load::<ProjectionEventRow>(&mut *conn)
    .await
    .map(|rows| rows.into_iter().map(ProjectionEventRecord::from).collect())
    .map_err(PersistenceError::database)
}
pub async fn persist_projected_operation_to_pg(
    pool: &PgPool,
    origin: &str,
    operation: &Operation,
    event_type: &str,
    is_message_create: bool,
    is_membership_or_realm_lifecycle: bool,
) -> PersistenceResult<()> {
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    if is_message_create {
        let event_id = operation
            .payload
            .get("event_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| {
                let op_uuid = ids::typed_uuid_part_expect_internal(operation.operation_id.as_str());
                ids::format_typed_uuid("event", &op_uuid)
            });
        let sender = operation
            .payload
            .get("sender")
            .and_then(Value::as_str)
            .unwrap_or(origin);
        let thread_id = operation.payload.get("thread_id").and_then(Value::as_str);
        let event_id_uuid = ids::typed_uuid_part_or_schema_violation(&event_id)?;
        let realm_id_uuid = ids::typed_uuid_part_expect_internal(operation.realm_id.as_str());
        let operation_id_uuid =
            ids::typed_uuid_part_expect_internal(operation.operation_id.as_str());
        sql_query(
            "INSERT INTO events (id, realm_id, event_type, sender_id, thread_id, operation_id, payload, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(event_id_uuid)
        .bind::<SqlUuid, _>(realm_id_uuid)
        .bind::<Text, _>(event_type)
        .bind::<Nullable<Text>, _>(Some(sender))
        .bind::<Nullable<Text>, _>(thread_id)
        .bind::<Nullable<SqlUuid>, _>(Some(operation_id_uuid))
        .bind::<Jsonb, _>(&operation.payload)
        .bind::<Timestamptz, _>(operation.created_at)
        .execute(&mut *conn)
        .await.map_err(PersistenceError::database)?;
    } else if is_membership_or_realm_lifecycle {
        let title = projected_operation_realm_title(operation);
        let title_for_insert = title.unwrap_or_else(|| operation.realm_id.as_str());
        let summary = projected_operation_realm_summary(operation);
        let discoverability =
            projected_operation_realm_discoverability(operation).unwrap_or_else(|| {
                if operation
                    .payload
                    .get("public")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    "public"
                } else {
                    "invite_only"
                }
            });
        let realm_id_uuid = ids::typed_uuid_part_expect_internal(operation.realm_id.as_str());
        let operation_id_uuid =
            ids::typed_uuid_part_expect_internal(operation.operation_id.as_str());
        if title.is_some() {
            sql_query(
                "INSERT INTO spaces (id, title, summary, owner_id, discoverability, payload, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $7) \
                 ON CONFLICT (id) DO UPDATE SET title = EXCLUDED.title, summary = COALESCE(EXCLUDED.summary, spaces.summary), updated_at = EXCLUDED.updated_at",
            )
            .bind::<SqlUuid, _>(realm_id_uuid)
            .bind::<Text, _>(title_for_insert)
            .bind::<Nullable<Text>, _>(summary)
            .bind::<Nullable<Text>, _>(Some(origin))
            .bind::<Text, _>(discoverability)
            .bind::<Jsonb, _>(&operation.payload)
            .bind::<Timestamptz, _>(operation.created_at)
            .execute(&mut *conn)
            .await.map_err(PersistenceError::database)?;
        } else {
            sql_query(
                "INSERT INTO spaces (id, title, summary, owner_id, discoverability, payload, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $7) \
                 ON CONFLICT (id) DO UPDATE SET summary = COALESCE(EXCLUDED.summary, spaces.summary), updated_at = EXCLUDED.updated_at",
            )
            .bind::<SqlUuid, _>(realm_id_uuid)
            .bind::<Text, _>(title_for_insert)
            .bind::<Nullable<Text>, _>(summary)
            .bind::<Nullable<Text>, _>(Some(origin))
            .bind::<Text, _>(discoverability)
            .bind::<Jsonb, _>(&operation.payload)
            .bind::<Timestamptz, _>(operation.created_at)
            .execute(&mut *conn)
            .await.map_err(PersistenceError::database)?;
        }

        if let Some(member) = operation.payload.get("actor_id").and_then(Value::as_str) {
            let membership = operation
                .payload
                .get("membership")
                .and_then(Value::as_str)
                .unwrap_or("join");
            sql_query(
                "INSERT INTO space_members (id, realm_id, actor_id, membership, payload, joined_at, left_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, CASE WHEN $4 = 'join' THEN $6 ELSE NULL END, CASE WHEN $4 <> 'join' THEN $6 ELSE NULL END, $6) \
                 ON CONFLICT (realm_id, actor_id) DO UPDATE SET membership = EXCLUDED.membership, payload = EXCLUDED.payload, left_at = EXCLUDED.left_at, updated_at = EXCLUDED.updated_at",
            )
            .bind::<SqlUuid, _>(Uuid::now_v7())
            .bind::<SqlUuid, _>(realm_id_uuid)
            .bind::<Text, _>(member)
            .bind::<Text, _>(membership)
            .bind::<Jsonb, _>(&operation.payload)
            .bind::<Timestamptz, _>(operation.created_at)
            .execute(&mut *conn)
            .await.map_err(PersistenceError::database)?;
        }

        sql_query(
            "INSERT INTO space_state_events (id, realm_id, event_type, subject, sender_id, operation_id, payload, created_at) \
             VALUES ($1, $2, $3, $4, $5, $1, $6, $7) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(operation_id_uuid)
        .bind::<SqlUuid, _>(realm_id_uuid)
        .bind::<Text, _>(event_type)
        .bind::<Text, _>(
            operation
                .payload
                .get("member")
                .and_then(Value::as_str)
                .unwrap_or(""),
        )
        .bind::<Nullable<Text>, _>(Some(origin))
        .bind::<Jsonb, _>(&operation.payload)
        .bind::<Timestamptz, _>(operation.created_at)
        .execute(&mut *conn)
        .await.map_err(PersistenceError::database)?;
    }
    Ok(())
}
#[async_trait]
impl ProjectionEventStore for PgProjectionEventStore {
    async fn append(
        &self,
        record: ProjectionEventRecord,
    ) -> PersistenceResult<ProjectionEventAppendOutcome> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO projection_events \
             (event_id, realm_id, event_kind, operation_type, operation_id, sender_id, payload, created_at, received_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (event_id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&record.event_id))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(&record.realm_id))
        .bind::<Text, _>(&record.event_kind)
        .bind::<Text, _>(&record.operation_type)
        .bind::<Nullable<SqlUuid>, _>(
            record
                .operation_id
                .as_deref()
                .map(ids::typed_uuid_part_expect_internal),
        )
        .bind::<Nullable<Text>, _>(&record.sender)
        .bind::<Jsonb, _>(&record.payload)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.received_at)
        .execute(&mut *conn)
        .await
        .map(|inserted| {
            if inserted == 0 {
                ProjectionEventAppendOutcome::AlreadyExists
            } else {
                ProjectionEventAppendOutcome::Inserted
            }
        })
        .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<ProjectionEventRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT event_id, realm_id, event_kind, operation_type, operation_id, sender_id AS sender, payload, created_at, received_at \
             FROM projection_events ORDER BY id",
        )
        .load::<ProjectionEventRow>(&mut *conn).await
        .map(|rows| rows.into_iter().map(ProjectionEventRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn snapshot_capped(&self, limit: usize) -> PersistenceResult<Vec<ProjectionEventRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT event_id, realm_id, event_kind, operation_type, operation_id, sender_id AS sender, payload, created_at, received_at \
             FROM projection_events ORDER BY id LIMIT $1",
        )
        .bind::<BigInt, _>(limit as i64)
        .load::<ProjectionEventRow>(&mut *conn).await
        .map(|rows| rows.into_iter().map(ProjectionEventRecord::from).collect())
        .map_err(PersistenceError::database)
    }
}
