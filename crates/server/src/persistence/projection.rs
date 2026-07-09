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
// `reducer::ProjectionState::{space_containers,strands,morphs}`
// maps onto durable storage. The reducer continues to own the in-memory
// authoritative state; routing layers write through to these stores
// after each accepted state-changing event, and `AppState::new` hydrates
// from them on startup so restart doesn't lose Space-container/Strand/Morph
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

/// Durable Strand projection store (mirror of `projection_strands` table).
#[async_trait]
pub trait StrandProjectionStore: Send + Sync {
    async fn get(&self, strand_id: &str) -> PersistenceResult<Option<StrandProjectionRecord>>;
    async fn put(&self, record: &StrandProjectionRecord) -> PersistenceResult<()>;
    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<StrandProjectionRecord>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<StrandProjectionRecord>>;
    async fn delete(&self, strand_id: &str) -> PersistenceResult<()>;
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
    pub scope_circle_id: Option<String>,
    pub default_scope_circle_id: Option<String>,
    pub child_scope_policy: Option<String>,
    pub child_scope_policy_scope_circle_id: Option<String>,
    pub child_scope_policy_metadata_encryption_floor: Option<String>,
    pub parent_ref: Option<String>,
    pub rank: Option<String>,
    /// One of `active` / `archived` / `tombstoned` per spec.
    pub state: String,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub history_basis_seals: Vec<String>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StrandProjectionRecord {
    pub strand_id: String,
    pub realm_id: String,
    pub tracks: BTreeMap<String, arkret_sdk::StrandTrackConfig>,
    pub title: String,
    pub summary: Option<String>,
    /// One of `active` / `archived` / `deleted` / `redacted` per spec.
    pub state: String,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub history_basis_seals: Vec<String>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// CKP-0007 — the Circle (`ak:circle:…`) this Strand is scoped to, if any.
    /// Durable so circle-scoped message visibility survives restart.
    pub scope_circle_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MorphProjectionRecord {
    pub morph_id: String,
    pub realm_id: String,
    pub scope_circle_id: Option<String>,
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
    pub history_basis_seals: Vec<String>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Projection-side event log (append-only, index/debug surfaces).
#[async_trait]
pub trait ProjectionEventStore: Send + Sync {
    async fn append(&self, record: ProjectionEventRecord) -> PersistenceResult<()>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<ProjectionEventRecord>>;
    /// SOL-SEC-04 — bounded variant of [`snapshot_all`] that pushes a `LIMIT`
    /// into the query so a single (federation-reachable) request cannot load
    /// the entire `projection_events` table into memory. Returns at most
    /// `limit` rows in the same order as `snapshot_all`.
    async fn snapshot_capped(&self, limit: usize) -> PersistenceResult<Vec<ProjectionEventRecord>>;
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
        let data = self.data.lock();
        Ok(data.get(realm_id).cloned())
    }

    async fn put(&self, realm_id: &str, record: &RealmMetaRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.insert(realm_id.to_owned(), record.clone());
        Ok(())
    }

    async fn list(&self) -> PersistenceResult<Vec<(String, RealmMetaRecord)>> {
        let data = self.data.lock();
        Ok(data.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
    }

    async fn delete(&self, realm_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.remove(realm_id);
        Ok(())
    }
}

// ── Memory impls for Space-container/Strand/Morph projection stores ────────

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
        let data = self.data.lock();
        Ok(data.get(container_space_id).cloned())
    }

    async fn put(&self, record: &SpaceContainerProjectionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.insert(record.container_space_id.clone(), record.clone());
        Ok(())
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<SpaceContainerProjectionRecord>> {
        let data = self.data.lock();
        Ok(data
            .values()
            .filter(|r| r.realm_id == realm_id)
            .cloned()
            .collect())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<SpaceContainerProjectionRecord>> {
        let data = self.data.lock();
        Ok(data.values().cloned().collect())
    }

    async fn delete(&self, container_space_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.remove(container_space_id);
        Ok(())
    }
}

pub(crate) struct MemoryStrandProjectionStore {
    data: Arc<Mutex<BTreeMap<String, StrandProjectionRecord>>>,
}

impl MemoryStrandProjectionStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl StrandProjectionStore for MemoryStrandProjectionStore {
    async fn get(&self, strand_id: &str) -> PersistenceResult<Option<StrandProjectionRecord>> {
        let data = self.data.lock();
        Ok(data.get(strand_id).cloned())
    }

    async fn put(&self, record: &StrandProjectionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.insert(record.strand_id.clone(), record.clone());
        Ok(())
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<StrandProjectionRecord>> {
        let data = self.data.lock();
        Ok(data
            .values()
            .filter(|r| r.realm_id == realm_id)
            .cloned()
            .collect())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<StrandProjectionRecord>> {
        let data = self.data.lock();
        Ok(data.values().cloned().collect())
    }

    async fn delete(&self, strand_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.remove(strand_id);
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
        let data = self.data.lock();
        Ok(data.get(morph_id).cloned())
    }

    async fn put(&self, record: &MorphProjectionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        data.insert(record.morph_id.clone(), record.clone());
        Ok(())
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<MorphProjectionRecord>> {
        let data = self.data.lock();
        Ok(data
            .values()
            .filter(|r| r.realm_id == realm_id)
            .cloned()
            .collect())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MorphProjectionRecord>> {
        let data = self.data.lock();
        Ok(data.values().cloned().collect())
    }

    async fn delete(&self, morph_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock();
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
        self.data.lock().push(record);
        Ok(())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<ProjectionEventRecord>> {
        Ok(self.data.lock().clone())
    }

    async fn snapshot_capped(&self, limit: usize) -> PersistenceResult<Vec<ProjectionEventRecord>> {
        Ok(self.data.lock().iter().take(limit).cloned().collect())
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
    #[diesel(sql_type = Nullable<SqlUuid>)]
    scope_circle_id: Option<Uuid>,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    default_scope_circle_id: Option<Uuid>,
    #[diesel(sql_type = Nullable<Text>)]
    child_scope_policy: Option<String>,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    child_scope_policy_scope_circle_id: Option<Uuid>,
    #[diesel(sql_type = Nullable<Text>)]
    child_scope_policy_metadata_encryption_floor: Option<String>,
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
            scope_circle_id: row
                .scope_circle_id
                .map(|u| ids::format_typed_uuid("circle", &u)),
            default_scope_circle_id: row
                .default_scope_circle_id
                .map(|u| ids::format_typed_uuid("circle", &u)),
            child_scope_policy: row.child_scope_policy,
            child_scope_policy_scope_circle_id: row
                .child_scope_policy_scope_circle_id
                .map(|u| ids::format_typed_uuid("circle", &u)),
            child_scope_policy_metadata_encryption_floor: row
                .child_scope_policy_metadata_encryption_floor,
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
     default_scope_circle_id, child_scope_policy, child_scope_policy_scope_circle_id, \
     child_scope_policy_metadata_encryption_floor, kind, title, parent_ref, rank, state, \
     state_changed_at, created_by_id AS created_by, created_at, history_basis_seals, updated_by_id AS updated_by, updated_at";

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
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(container_space_id))
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
             (id, realm_id, scope_circle_id, default_scope_circle_id, child_scope_policy, \
              child_scope_policy_scope_circle_id, child_scope_policy_metadata_encryption_floor, \
              kind, title, parent_ref, rank, state, state_changed_at, created_by_id, created_at, \
              history_basis_seals, updated_by_id, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18) \
             ON CONFLICT (id) DO UPDATE SET \
                realm_id = EXCLUDED.realm_id, \
                scope_circle_id = EXCLUDED.scope_circle_id, \
                default_scope_circle_id = EXCLUDED.default_scope_circle_id, \
                child_scope_policy = EXCLUDED.child_scope_policy, \
                child_scope_policy_scope_circle_id = EXCLUDED.child_scope_policy_scope_circle_id, \
                child_scope_policy_metadata_encryption_floor = EXCLUDED.child_scope_policy_metadata_encryption_floor, \
                kind = EXCLUDED.kind, \
                title = EXCLUDED.title, \
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
        .bind::<Nullable<SqlUuid>, _>(
            record
                .default_scope_circle_id
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
        .bind::<Nullable<Text>, _>(&record.child_scope_policy_metadata_encryption_floor)
        .bind::<Text, _>(&record.kind)
        .bind::<Text, _>(&record.title)
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
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(realm_id))
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
            .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(container_space_id))
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::from)
    }
}

pub(crate) struct PgStrandProjectionStore {
    pub(crate) pool: PgPool,
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
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {STRAND_PROJECTION_COLUMNS} FROM projection_strands WHERE id = $1"
        ))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(strand_id))
        .get_result::<StrandProjectionRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(StrandProjectionRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn put(&self, record: &StrandProjectionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .map_err(PersistenceError::from)
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<StrandProjectionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {STRAND_PROJECTION_COLUMNS} FROM projection_strands \
             WHERE realm_id = $1 ORDER BY id"
        ))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(realm_id))
        .load::<StrandProjectionRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(StrandProjectionRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<StrandProjectionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {STRAND_PROJECTION_COLUMNS} FROM projection_strands ORDER BY id"
        ))
        .load::<StrandProjectionRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(StrandProjectionRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn delete(&self, strand_id: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM projection_strands WHERE id = $1")
            .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(strand_id))
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
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {MORPH_PROJECTION_COLUMNS} FROM projection_morphs WHERE id = $1"
        ))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(morph_id))
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
        .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(realm_id))
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
            .bind::<SqlUuid, _>(ids::typed_uuid_part_expect_internal(morph_id))
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
    let mut conn = pg_conn(pool).await?;
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
    .map_err(PersistenceError::from)
}

pub async fn persist_projected_operation_to_pg(
    pool: &PgPool,
    origin: &str,
    operation: &Operation,
) -> PersistenceResult<()> {
    let mut conn = pg_conn(pool).await?;
    let event_type = crate::kinds::canonical_kind_string(operation);
    if crate::kinds::operation_is_message_create(operation) {
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
        .bind::<Text, _>(&event_type)
        .bind::<Nullable<Text>, _>(Some(sender))
        .bind::<Nullable<Text>, _>(thread_id)
        .bind::<Nullable<SqlUuid>, _>(Some(operation_id_uuid))
        .bind::<Jsonb, _>(&operation.payload)
        .bind::<Timestamptz, _>(operation.created_at)
        .execute(&mut *conn)
        .await?;
    } else if crate::kinds::operation_is_membership(operation)
        || crate::kinds::operation_is_realm_lifecycle(operation)
    {
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
            .await?;
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
            .await?;
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
            .await?;
        }

        sql_query(
            "INSERT INTO space_state_events (id, realm_id, event_type, subject, sender_id, operation_id, payload, created_at) \
             VALUES ($1, $2, $3, $4, $5, $1, $6, $7) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(operation_id_uuid)
        .bind::<SqlUuid, _>(realm_id_uuid)
        .bind::<Text, _>(&event_type)
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
        .await?;
    }
    Ok(())
}

fn first_string_field<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
}

fn object_string_field<'a>(operation: &'a Operation, keys: &[&str]) -> Option<&'a str> {
    operation
        .payload
        .get("object")
        .and_then(|object| first_string_field(object, keys))
}

fn patch_string_field<'a>(operation: &'a Operation, field: &str) -> Option<&'a str> {
    let patch_value = operation
        .payload
        .get("patch")
        .and_then(|patch| patch.get(field))?;
    match patch_value {
        Value::String(value) => Some(value.as_str()),
        Value::Object(op) if op.get("$op").and_then(Value::as_str) == Some("set") => {
            op.get("value").and_then(Value::as_str)
        }
        _ => None,
    }
}

fn projected_operation_realm_title(operation: &Operation) -> Option<&str> {
    first_string_field(&operation.payload, &["realm_title", "title"])
        .or_else(|| object_string_field(operation, &["title"]))
        .or_else(|| patch_string_field(operation, "title"))
}

fn projected_operation_realm_summary(operation: &Operation) -> Option<&str> {
    first_string_field(&operation.payload, &["realm_summary", "summary"])
        .or_else(|| object_string_field(operation, &["summary"]))
        .or_else(|| patch_string_field(operation, "summary"))
}

fn projected_operation_realm_discoverability(operation: &Operation) -> Option<&str> {
    first_string_field(&operation.payload, &["discoverability"])
        .or_else(|| object_string_field(operation, &["default_discoverability", "discoverability"]))
        .or_else(|| patch_string_field(operation, "default_discoverability"))
        .or_else(|| patch_string_field(operation, "discoverability"))
}

#[async_trait]
impl ProjectionEventStore for PgProjectionEventStore {
    async fn append(&self, record: ProjectionEventRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO projection_events \
             (event_id, realm_id, event_kind, operation_type, operation_id, sender_id, payload, created_at, received_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
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
        .execute(&mut *conn).await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<ProjectionEventRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT event_id, realm_id, event_kind, operation_type, operation_id, sender_id AS sender, payload, created_at, received_at \
             FROM projection_events ORDER BY id",
        )
        .load::<ProjectionEventRow>(&mut *conn).await
        .map(|rows| rows.into_iter().map(ProjectionEventRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn snapshot_capped(&self, limit: usize) -> PersistenceResult<Vec<ProjectionEventRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT event_id, realm_id, event_kind, operation_type, operation_id, sender_id AS sender, payload, created_at, received_at \
             FROM projection_events ORDER BY id LIMIT $1",
        )
        .bind::<BigInt, _>(limit as i64)
        .load::<ProjectionEventRow>(&mut *conn).await
        .map(|rows| rows.into_iter().map(ProjectionEventRecord::from).collect())
        .map_err(PersistenceError::from)
    }
}
