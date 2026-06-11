use super::*;

/// Trait for Realm metadata storage operations.
#[async_trait]
pub trait RealmMetaStore: Send + Sync {
    async fn get(&self, realm_id: &str) -> PersistenceResult<Option<RealmMetaRecord>>;
    async fn put(&self, realm_id: &str, record: &RealmMetaRecord) -> PersistenceResult<()>;
    async fn list(&self) -> PersistenceResult<Vec<(String, RealmMetaRecord)>>;
    async fn delete(&self, realm_id: &str) -> PersistenceResult<()>;
}

// ── Projection persistence traits ─────────────────────────────────────────
// Mirror the in-memory
// `reducer::ProjectionState::{space_containers,flows,morphs}`
// maps onto durable storage. The reducer continues to own the in-memory
// authoritative state; routing layers write through to these stores
// after each accepted state-changing event, and `AppState::new` hydrates
// from them on startup so restart doesn't lose Space-container/Flow/Morph
// lifecycle state.

/// Durable Space-container projection store (mirror of
/// `projection_space_containers` table).
#[async_trait]
pub trait SpaceContainerProjectionStore: Send + Sync {
    async fn get(
        &self,
        container_space_id: &str,
    ) -> PersistenceResult<Option<SpaceContainerProjectionRecord>>;
    async fn put(&self, record: &SpaceContainerProjectionRecord) -> PersistenceResult<()>;
    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<SpaceContainerProjectionRecord>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<SpaceContainerProjectionRecord>>;
    async fn delete(&self, container_space_id: &str) -> PersistenceResult<()>;
}

/// Durable Flow projection store (mirror of `projection_flows` table).
#[async_trait]
pub trait FlowProjectionStore: Send + Sync {
    async fn get(&self, flow_id: &str) -> PersistenceResult<Option<FlowProjectionRecord>>;
    async fn put(&self, record: &FlowProjectionRecord) -> PersistenceResult<()>;
    async fn list_for_realm(&self, realm_id: &str) -> PersistenceResult<Vec<FlowProjectionRecord>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<FlowProjectionRecord>>;
    async fn delete(&self, flow_id: &str) -> PersistenceResult<()>;
}

/// Durable Morph projection store (mirror of `projection_morphs` table).
#[async_trait]
pub trait MorphProjectionStore: Send + Sync {
    async fn get(&self, morph_id: &str) -> PersistenceResult<Option<MorphProjectionRecord>>;
    async fn put(&self, record: &MorphProjectionRecord) -> PersistenceResult<()>;
    async fn list_for_realm(&self, realm_id: &str)
    -> PersistenceResult<Vec<MorphProjectionRecord>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<MorphProjectionRecord>>;
    async fn delete(&self, morph_id: &str) -> PersistenceResult<()>;
}

/// Wire / persistence record for a Space-container projection. Mirrors fields on
/// `reducer::SpaceContainerProjection` (state stored as the canonical `&str` form
/// of `SpaceContainerLifecycleState`) so callers can convert without pulling the
/// reducer enum into the persistence layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceContainerProjectionRecord {
    pub container_space_id: String,
    pub realm_id: String,
    pub kind: String,
    pub title: String,
    pub parent_ref: Option<String>,
    pub rank: Option<String>,
    /// One of `active` / `archived` / `tombstoned` per spec.
    pub state: String,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowProjectionRecord {
    pub flow_id: String,
    pub realm_id: String,
    pub title: String,
    pub summary: Option<String>,
    /// One of `active` / `archived` / `deleted` / `redacted` per spec.
    pub state: String,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// CKP-0007 — the Circle (`ck:circle:…`) this Flow is scoped to, if any.
    /// Durable so circle-scoped message visibility survives restart.
    pub scope_circle_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MorphProjectionRecord {
    pub morph_id: String,
    pub realm_id: String,
    pub morph_type: String,
    pub title: Option<String>,
    pub fields: serde_json::Value,
    pub schema_refs: serde_json::Value,
    pub facets: serde_json::Value,
    pub versions: serde_json::Value,
    pub state: String,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Projection-side event log (append-only, index/debug surfaces).
#[async_trait]
pub trait ProjectionEventStore: Send + Sync {
    async fn append(&self, record: ProjectionEventRecord) -> PersistenceResult<()>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<ProjectionEventRecord>>;
}

// In-memory Realm meta store
pub(crate) struct MemoryRealmMetaStore {
    data: Arc<Mutex<BTreeMap<String, RealmMetaRecord>>>,
}

impl MemoryRealmMetaStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl RealmMetaStore for MemoryRealmMetaStore {
    async fn get(&self, realm_id: &str) -> PersistenceResult<Option<RealmMetaRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(realm_id).cloned())
    }

    async fn put(&self, realm_id: &str, record: &RealmMetaRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(realm_id.to_owned(), record.clone());
        Ok(())
    }

    async fn list(&self) -> PersistenceResult<Vec<(String, RealmMetaRecord)>> {
        let data = self.data.lock().expect("lock");
        Ok(data.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
    }

    async fn delete(&self, realm_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(realm_id);
        Ok(())
    }
}

// ── Memory impls for Space-container/Flow/Morph projection stores ────────

pub(crate) struct MemorySpaceContainerProjectionStore {
    data: Arc<Mutex<BTreeMap<String, SpaceContainerProjectionRecord>>>,
}

impl MemorySpaceContainerProjectionStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl SpaceContainerProjectionStore for MemorySpaceContainerProjectionStore {
    async fn get(
        &self,
        container_space_id: &str,
    ) -> PersistenceResult<Option<SpaceContainerProjectionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(container_space_id).cloned())
    }

    async fn put(&self, record: &SpaceContainerProjectionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(record.container_space_id.clone(), record.clone());
        Ok(())
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<SpaceContainerProjectionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .values()
            .filter(|r| r.realm_id == realm_id)
            .cloned()
            .collect())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<SpaceContainerProjectionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.values().cloned().collect())
    }

    async fn delete(&self, container_space_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(container_space_id);
        Ok(())
    }
}

pub(crate) struct MemoryFlowProjectionStore {
    data: Arc<Mutex<BTreeMap<String, FlowProjectionRecord>>>,
}

impl MemoryFlowProjectionStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl FlowProjectionStore for MemoryFlowProjectionStore {
    async fn get(&self, flow_id: &str) -> PersistenceResult<Option<FlowProjectionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(flow_id).cloned())
    }

    async fn put(&self, record: &FlowProjectionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(record.flow_id.clone(), record.clone());
        Ok(())
    }

    async fn list_for_realm(&self, realm_id: &str) -> PersistenceResult<Vec<FlowProjectionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .values()
            .filter(|r| r.realm_id == realm_id)
            .cloned()
            .collect())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<FlowProjectionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.values().cloned().collect())
    }

    async fn delete(&self, flow_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(flow_id);
        Ok(())
    }
}

pub(crate) struct MemoryMorphProjectionStore {
    data: Arc<Mutex<BTreeMap<String, MorphProjectionRecord>>>,
}

impl MemoryMorphProjectionStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl MorphProjectionStore for MemoryMorphProjectionStore {
    async fn get(&self, morph_id: &str) -> PersistenceResult<Option<MorphProjectionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(morph_id).cloned())
    }

    async fn put(&self, record: &MorphProjectionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(record.morph_id.clone(), record.clone());
        Ok(())
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<MorphProjectionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .values()
            .filter(|r| r.realm_id == realm_id)
            .cloned()
            .collect())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MorphProjectionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.values().cloned().collect())
    }

    async fn delete(&self, morph_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(morph_id);
        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct MemoryProjectionEventStore {
    data: Mutex<Vec<ProjectionEventRecord>>,
}

impl MemoryProjectionEventStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ProjectionEventStore for MemoryProjectionEventStore {
    async fn append(&self, record: ProjectionEventRecord) -> PersistenceResult<()> {
        self.data
            .lock()
            .expect("projection events lock")
            .push(record);
        Ok(())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<ProjectionEventRecord>> {
        Ok(self.data.lock().expect("projection events lock").clone())
    }
}

pub(crate) struct PgSpaceContainerProjectionStore {
    pub(crate) pool: PgPool,
}

#[derive(QueryableByName)]
struct SpaceContainerProjectionRow {
    #[diesel(sql_type = SqlUuid)]
    container_space_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    realm_id: Uuid,
    #[diesel(sql_type = Text)]
    kind: String,
    #[diesel(sql_type = Text)]
    title: String,
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
            parent_ref: row.parent_ref.map(|u| ids::format_typed_uuid("space", &u)),
            rank: row.rank,
            state: row.state,
            state_changed_at: row.state_changed_at,
            created_by: row.created_by,
            created_at: row.created_at,
            updated_by: row.updated_by,
            updated_at: row.updated_at,
        }
    }
}

const SPACE_CONTAINER_PROJECTION_COLUMNS: &str = "id AS container_space_id, realm_id, kind, title, parent_ref, rank, state, \
     state_changed_at, created_by_id AS created_by, created_at, updated_by_id AS updated_by, updated_at";

#[async_trait]
impl SpaceContainerProjectionStore for PgSpaceContainerProjectionStore {
    async fn get(
        &self,
        container_space_id: &str,
    ) -> PersistenceResult<Option<SpaceContainerProjectionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {SPACE_CONTAINER_PROJECTION_COLUMNS} FROM projection_spaces WHERE id = $1"
        ))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(container_space_id))
        .get_result::<SpaceContainerProjectionRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(SpaceContainerProjectionRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn put(&self, record: &SpaceContainerProjectionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO projection_spaces \
             (id, realm_id, kind, title, parent_ref, rank, state, \
              state_changed_at, created_by_id, created_at, updated_by_id, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
             ON CONFLICT (id) DO UPDATE SET \
                realm_id = EXCLUDED.realm_id, \
                kind = EXCLUDED.kind, \
                title = EXCLUDED.title, \
                parent_ref = EXCLUDED.parent_ref, \
                rank = EXCLUDED.rank, \
                state = EXCLUDED.state, \
                state_changed_at = EXCLUDED.state_changed_at, \
                updated_by_id = EXCLUDED.updated_by_id, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.container_space_id))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.realm_id))
        .bind::<Text, _>(&record.kind)
        .bind::<Text, _>(&record.title)
        .bind::<Nullable<SqlUuid>, _>(
            record
                .parent_ref
                .as_deref()
                .map(ids::typed_uuid_part_or_panic),
        )
        .bind::<Nullable<Text>, _>(&record.rank)
        .bind::<Text, _>(&record.state)
        .bind::<Nullable<Timestamptz>, _>(record.state_changed_at)
        .bind::<Text, _>(&record.created_by)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Nullable<Text>, _>(&record.updated_by)
        .bind::<Nullable<Timestamptz>, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<SpaceContainerProjectionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {SPACE_CONTAINER_PROJECTION_COLUMNS} FROM projection_spaces \
             WHERE realm_id = $1 ORDER BY id"
        ))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(realm_id))
        .load::<SpaceContainerProjectionRow>(&mut *conn)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(SpaceContainerProjectionRecord::from)
                .collect()
        })
        .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<SpaceContainerProjectionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .map_err(PersistenceError::from)
    }

    async fn delete(&self, container_space_id: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM projection_spaces WHERE id = $1")
            .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(container_space_id))
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::from)
    }
}

pub(crate) struct PgFlowProjectionStore {
    pub(crate) pool: PgPool,
}

#[derive(QueryableByName)]
struct FlowProjectionRow {
    #[diesel(sql_type = SqlUuid)]
    flow_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    realm_id: Uuid,
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
    #[diesel(sql_type = Nullable<Text>)]
    updated_by: Option<String>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    scope_circle_id: Option<Uuid>,
}

impl From<FlowProjectionRow> for FlowProjectionRecord {
    fn from(row: FlowProjectionRow) -> Self {
        Self {
            flow_id: ids::format_typed_uuid("flow", &row.flow_id),
            realm_id: ids::format_typed_uuid("realm", &row.realm_id),
            title: row.title,
            summary: row.summary,
            state: row.state,
            state_changed_at: row.state_changed_at,
            created_by: row.created_by,
            created_at: row.created_at,
            updated_by: row.updated_by,
            updated_at: row.updated_at,
            scope_circle_id: row
                .scope_circle_id
                .map(|u| ids::format_typed_uuid("circle", &u)),
        }
    }
}

const FLOW_PROJECTION_COLUMNS: &str = "id AS flow_id, realm_id, title, summary, state, \
     state_changed_at, created_by_id AS created_by, created_at, updated_by_id AS updated_by, updated_at, scope_circle_id";

#[async_trait]
impl FlowProjectionStore for PgFlowProjectionStore {
    async fn get(&self, flow_id: &str) -> PersistenceResult<Option<FlowProjectionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {FLOW_PROJECTION_COLUMNS} FROM projection_flows WHERE id = $1"
        ))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(flow_id))
        .get_result::<FlowProjectionRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(FlowProjectionRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn put(&self, record: &FlowProjectionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO projection_flows \
             (id, realm_id, title, summary, state, state_changed_at, \
              created_by_id, created_at, updated_by_id, updated_at, scope_circle_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
             ON CONFLICT (id) DO UPDATE SET \
                realm_id = EXCLUDED.realm_id, \
                title = EXCLUDED.title, \
                summary = EXCLUDED.summary, \
                state = EXCLUDED.state, \
                state_changed_at = EXCLUDED.state_changed_at, \
                updated_by_id = EXCLUDED.updated_by_id, \
                updated_at = EXCLUDED.updated_at, \
                scope_circle_id = EXCLUDED.scope_circle_id",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.flow_id))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.realm_id))
        .bind::<Text, _>(&record.title)
        .bind::<Nullable<Text>, _>(&record.summary)
        .bind::<Text, _>(&record.state)
        .bind::<Nullable<Timestamptz>, _>(record.state_changed_at)
        .bind::<Text, _>(&record.created_by)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Nullable<Text>, _>(&record.updated_by)
        .bind::<Nullable<Timestamptz>, _>(record.updated_at)
        .bind::<Nullable<SqlUuid>, _>(
            record
                .scope_circle_id
                .as_deref()
                .map(ids::typed_uuid_part_or_panic),
        )
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn list_for_realm(&self, realm_id: &str) -> PersistenceResult<Vec<FlowProjectionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {FLOW_PROJECTION_COLUMNS} FROM projection_flows \
             WHERE realm_id = $1 ORDER BY id"
        ))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(realm_id))
        .load::<FlowProjectionRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(FlowProjectionRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<FlowProjectionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {FLOW_PROJECTION_COLUMNS} FROM projection_flows ORDER BY id"
        ))
        .load::<FlowProjectionRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(FlowProjectionRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn delete(&self, flow_id: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM projection_flows WHERE id = $1")
            .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(flow_id))
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::from)
    }
}

pub(crate) struct PgMorphProjectionStore {
    pub(crate) pool: PgPool,
}

#[derive(QueryableByName)]
struct MorphProjectionRow {
    #[diesel(sql_type = SqlUuid)]
    morph_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    realm_id: Uuid,
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
            updated_by: row.updated_by,
            updated_at: row.updated_at,
        }
    }
}

const MORPH_PROJECTION_COLUMNS: &str = "id AS morph_id, realm_id, morph_type, title, fields, \
     schema_refs, facets, versions, state, state_changed_at, created_by_id AS created_by, created_at, updated_by_id AS updated_by, \
     updated_at";

#[async_trait]
impl MorphProjectionStore for PgMorphProjectionStore {
    async fn get(&self, morph_id: &str) -> PersistenceResult<Option<MorphProjectionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {MORPH_PROJECTION_COLUMNS} FROM projection_morphs WHERE id = $1"
        ))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(morph_id))
        .get_result::<MorphProjectionRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(MorphProjectionRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn put(&self, record: &MorphProjectionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO projection_morphs \
             (id, realm_id, morph_type, title, fields, schema_refs, facets, versions, \
              state, state_changed_at, created_by_id, created_at, updated_by_id, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
             ON CONFLICT (id) DO UPDATE SET \
                realm_id = EXCLUDED.realm_id, \
                morph_type = EXCLUDED.morph_type, \
                title = EXCLUDED.title, \
                fields = EXCLUDED.fields, \
                schema_refs = EXCLUDED.schema_refs, \
                facets = EXCLUDED.facets, \
                versions = EXCLUDED.versions, \
                state = EXCLUDED.state, \
                state_changed_at = EXCLUDED.state_changed_at, \
                updated_by_id = EXCLUDED.updated_by_id, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.morph_id))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.realm_id))
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
        .bind::<Nullable<Timestamptz>, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<MorphProjectionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {MORPH_PROJECTION_COLUMNS} FROM projection_morphs \
             WHERE realm_id = $1 ORDER BY id"
        ))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(realm_id))
        .load::<MorphProjectionRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(MorphProjectionRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MorphProjectionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {MORPH_PROJECTION_COLUMNS} FROM projection_morphs ORDER BY id"
        ))
        .load::<MorphProjectionRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(MorphProjectionRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn delete(&self, morph_id: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM projection_morphs WHERE id = $1")
            .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(morph_id))
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::from)
    }
}

// ── Pg-backed projection_events store ────────────────────────────────────
// Append-only mirror of the in-memory ProjectionEventRecord stream
// stamped down by `routing::events::projection::append_projection_event`.
// Surrogate `ordinal` BIGSERIAL handles retry collisions; the
// canonical_events table is where the `(actor_id, actor_seq)` uniqueness
// invariant lives.

pub(crate) struct PgProjectionEventStore {
    pub(crate) pool: PgPool,
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
        }
    }
}

#[async_trait]
impl ProjectionEventStore for PgProjectionEventStore {
    async fn append(&self, record: ProjectionEventRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO projection_events \
             (event_id, realm_id, event_kind, operation_type, operation_id, sender_id, payload, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.event_id))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.realm_id))
        .bind::<Text, _>(&record.event_kind)
        .bind::<Text, _>(&record.operation_type)
        .bind::<Nullable<SqlUuid>, _>(
            record
                .operation_id
                .as_deref()
                .map(ids::typed_uuid_part_or_panic),
        )
        .bind::<Nullable<Text>, _>(&record.sender)
        .bind::<Jsonb, _>(&record.payload)
        .bind::<Timestamptz, _>(record.created_at)
        .execute(&mut *conn).await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<ProjectionEventRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT event_id, realm_id, event_kind, operation_type, operation_id, sender_id AS sender, payload, created_at \
             FROM projection_events ORDER BY id",
        )
        .load::<ProjectionEventRow>(&mut *conn).await
        .map(|rows| rows.into_iter().map(ProjectionEventRecord::from).collect())
        .map_err(PersistenceError::from)
    }
}
