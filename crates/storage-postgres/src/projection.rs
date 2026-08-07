use super::{
    AsyncConnection, BigInt, Jsonb, MorphProjectionRecord, MorphProjectionStore, Nullable,
    Operation, OptionalExtension, PersistenceError, PersistenceResult, PgPool, PgTransactionError,
    ProjectionEventAppendOutcome, ProjectionEventRecord, ProjectionEventStore, QueryableByName,
    RunQueryDsl, SpaceContainerProjectionRecord, SpaceContainerProjectionStore, SqlUuid,
    StrandProjectionRecord, StrandProjectionStore, Text, Timestamptz, Uuid, Value, async_trait,
    ids, pg_conn, projected_operation_realm_discoverability, projected_operation_realm_summary,
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
    morph_kind: String,
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
            morph_kind: row.morph_kind,
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
const MORPH_PROJECTION_COLUMNS: &str = "id AS morph_id, realm_id, scope_circle_id, morph_kind, title, fields, \
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
             (id, realm_id, scope_circle_id, morph_kind, title, fields, schema_refs, facets, versions, \
              state, state_changed_at, created_by_id, created_at, updated_by_id, history_basis_seals, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) \
             ON CONFLICT (id) DO UPDATE SET \
                realm_id = EXCLUDED.realm_id, \
                scope_circle_id = EXCLUDED.scope_circle_id, \
                morph_kind = EXCLUDED.morph_kind, \
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
        .bind::<Text, _>(&record.morph_kind)
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
// `id` is the full suite-tagged digest identity. A true hash collision must be
// rejected/quarantined by the canonical commit before materialization; this
// table must never choose a variant with first-row-wins semantics. The
// surrogate `pk` is only a local stream position.

pub struct PgProjectionEventStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct ProjectionEventRow {
    #[diesel(sql_type = diesel::sql_types::Binary)]
    event_id: Vec<u8>,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    event_kind: String,
    #[diesel(sql_type = Text)]
    operation_kind: String,
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
#[derive(QueryableByName)]
struct ProjectionEventPkRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    pk: i64,
}
impl From<ProjectionEventRow> for ProjectionEventRecord {
    fn from(row: ProjectionEventRow) -> Self {
        let event_id: [u8; ids::EVENT_ID_BYTES] = row
            .event_id
            .try_into()
            .expect("projection_events.id must be 33 bytes");
        Self {
            event_id: ids::format_event_id(&event_id),
            realm_id: row.realm_id,
            event_kind: row.event_kind,
            operation_kind: row.operation_kind,
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
        let event_id = ids::parse_event_id(&record.event_id).ok_or_else(|| {
            PersistenceError::SchemaViolation(format!(
                "malformed projection Event id: {:?}",
                record.event_id
            ))
        })?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        sql_query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1, 'hex'), 0))")
            .bind::<diesel::sql_types::Binary, _>(event_id.to_vec())
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        let event_pk =
            sql_query("SELECT pk FROM canonical_events WHERE state = 'accepted' AND id = $1")
                .bind::<diesel::sql_types::Binary, _>(event_id.to_vec())
                .get_result::<ProjectionEventPkRow>(&mut *conn)
                .await
                .optional()
                .map_err(PersistenceError::database)?
                .ok_or_else(|| PersistenceError::Conflict("event_not_accepted".to_owned()))?
                .pk;
        let inserted = sql_query(
            "INSERT INTO projection_events \
             (id, event_pk, realm_id, event_kind, operation_kind, operation_id, sender_id, payload, created_at, received_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<diesel::sql_types::Binary, _>(event_id.to_vec())
        .bind::<diesel::sql_types::BigInt, _>(event_pk)
        .bind::<Text, _>(&record.realm_id)
        .bind::<Text, _>(&record.event_kind)
        .bind::<Text, _>(&record.operation_kind)
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
        .map_err(PersistenceError::database)?;
        if inserted == 1 {
            return Ok(ProjectionEventAppendOutcome::Inserted);
        }
        let existing = sql_query(
            "SELECT id AS event_id, realm_id, event_kind, operation_kind, operation_id, \
                    sender_id AS sender, payload, created_at, received_at \
             FROM projection_events WHERE id = $1",
        )
        .bind::<diesel::sql_types::Binary, _>(event_id.to_vec())
        .get_result::<ProjectionEventRow>(&mut *conn)
        .await
        .map(ProjectionEventRecord::from)
        .map_err(PersistenceError::database)?;
        if existing.event_id == record.event_id
            && existing.realm_id == record.realm_id
            && existing.event_kind == record.event_kind
            && existing.operation_kind == record.operation_kind
            && existing.operation_id == record.operation_id
            && existing.sender == record.sender
            && existing.payload == record.payload
            && existing.created_at == record.created_at
            && existing.received_at == record.received_at
        {
            Ok(ProjectionEventAppendOutcome::AlreadyExists)
        } else {
            Err(PersistenceError::Conflict(
                "duplicate_conflict: projection differs for Event identity".to_owned(),
            ).into())
        }
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<ProjectionEventRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id AS event_id, realm_id, event_kind, operation_kind, operation_id, sender_id AS sender, payload, created_at, received_at \
             FROM projection_events ORDER BY pk",
        )
        .load::<ProjectionEventRow>(&mut *conn).await
        .map(|rows| rows.into_iter().map(ProjectionEventRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn snapshot_kind(
        &self,
        event_kind: &str,
    ) -> PersistenceResult<Vec<ProjectionEventRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id AS event_id, realm_id, event_kind, operation_kind, operation_id, sender_id AS sender, payload, created_at, received_at \
             FROM projection_events WHERE event_kind = $1 ORDER BY pk",
        )
        .bind::<Text, _>(event_kind)
        .load::<ProjectionEventRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(ProjectionEventRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn get(&self, event_id: &str) -> PersistenceResult<Option<ProjectionEventRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let event_id = ids::parse_event_id(event_id).ok_or_else(|| {
            PersistenceError::SchemaViolation(format!(
                "malformed projection Event id: {event_id:?}"
            ))
        })?;
        sql_query(
            "SELECT id AS event_id, realm_id, event_kind, operation_kind, operation_id, sender_id AS sender, payload, created_at, received_at \
             FROM projection_events WHERE id = $1",
        )
        .bind::<diesel::sql_types::Binary, _>(event_id.to_vec())
        .get_result::<ProjectionEventRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(ProjectionEventRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn get_by_operation_id(
        &self,
        operation_id: &str,
    ) -> PersistenceResult<Option<ProjectionEventRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id AS event_id, realm_id, event_kind, operation_kind, operation_id, sender_id AS sender, payload, created_at, received_at \
             FROM projection_events WHERE operation_id = $1 ORDER BY pk DESC LIMIT 1",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(operation_id))
        .get_result::<ProjectionEventRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(ProjectionEventRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn snapshot_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<ProjectionEventRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id AS event_id, realm_id, event_kind, operation_kind, operation_id, sender_id AS sender, payload, created_at, received_at \
             FROM projection_events WHERE realm_id = $1 ORDER BY pk",
        )
        .bind::<Text, _>(realm_id)
        .load::<ProjectionEventRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(ProjectionEventRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn snapshot_actor(
        &self,
        actor_id: &str,
    ) -> PersistenceResult<Vec<ProjectionEventRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id AS event_id, realm_id, event_kind, operation_kind, operation_id, sender_id AS sender, payload, created_at, received_at \
             FROM projection_events \
             WHERE sender_id = $1 OR payload ->> 'sender' = $1 OR payload ->> 'actor_id' = $1 \
                OR payload ->> 'actor' = $1 OR payload -> 'object' ->> 'created_by' = $1 \
             ORDER BY pk",
        )
        .bind::<Text, _>(actor_id)
        .load::<ProjectionEventRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(ProjectionEventRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn snapshot_capped(&self, limit: usize) -> PersistenceResult<Vec<ProjectionEventRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id AS event_id, realm_id, event_kind, operation_kind, operation_id, sender_id AS sender, payload, created_at, received_at \
             FROM projection_events ORDER BY pk LIMIT $1",
        )
        .bind::<BigInt, _>(limit as i64)
        .load::<ProjectionEventRow>(&mut *conn).await
        .map(|rows| rows.into_iter().map(ProjectionEventRecord::from).collect())
        .map_err(PersistenceError::database)
    }
}
