use super::{
    BTreeMap, PersistenceResult, ProjectedEventOperation, ProjectionEventRecord, RealmMetaRecord,
    Value, async_trait,
};
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
/// Durable Circle projection store (mirror of `projection_circles` +
/// `projection_circle_members`).
///
/// Circle membership is the set the wire validator enforces
/// `Circle.members subset of Realm.members` against, so losing it on restart
/// would silently widen a Circle boundary until the log is replayed.
#[async_trait]
pub trait CircleProjectionStore: Send + Sync {
    async fn get(&self, circle_id: &str) -> PersistenceResult<Option<CircleProjectionRecord>>;
    async fn put(&self, record: &CircleProjectionRecord) -> PersistenceResult<()>;
    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<CircleProjectionRecord>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<CircleProjectionRecord>>;
    async fn delete(&self, circle_id: &str) -> PersistenceResult<()>;
    /// Replace the whole membership set of one Circle. Membership is a set,
    /// not a log: a row that disappeared from the reducer has to disappear
    /// here too, so a partial upsert would resurrect removed members.
    async fn put_members(
        &self,
        circle_id: &str,
        members: &[CircleMemberProjectionRecord],
    ) -> PersistenceResult<()>;
    async fn snapshot_all_members(&self) -> PersistenceResult<Vec<CircleMemberProjectionRecord>>;
}
/// Durable per-(Strand, Actor) watch preference store (mirror of
/// `projection_strand_watches`).
#[async_trait]
pub trait StrandWatchProjectionStore: Send + Sync {
    async fn put(&self, record: &StrandWatchProjectionRecord) -> PersistenceResult<()>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<StrandWatchProjectionRecord>>;
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
    pub fields: BTreeMap<String, Value>,
    pub scope_circle_id: Option<String>,
    pub child_scope_policy: Option<String>,
    pub child_scope_policy_scope_circle_id: Option<String>,
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
#[derive(Clone, Debug, PartialEq)]
pub struct StrandProjectionRecord {
    pub strand_id: String,
    pub realm_id: String,
    pub tracks: BTreeMap<String, arkret_models_collaboration::objects::profiles::StrandTrack>,
    pub title: String,
    pub summary: Option<String>,
    /// Canonical content slot; exactly one of the two is present on an active
    /// object and both are absent once `state=redacted` (common-fields.md 5.2).
    pub content: Option<serde_json::Value>,
    pub encrypted_content: Option<serde_json::Value>,
    /// One of `active` / `archived` / `deleted` / `redacted` per spec.
    pub state: String,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub history_basis_seals: Vec<String>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// AKP-0007 — the Circle (`ak:circle:…`) this Strand is scoped to, if any.
    /// Durable so circle-scoped message visibility survives restart.
    pub scope_circle_id: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MorphProjectionRecord {
    pub morph_id: String,
    pub realm_id: String,
    pub scope_circle_id: Option<String>,
    pub morph_kind: String,
    pub title: Option<String>,
    pub fields: serde_json::Value,
    pub schema_refs: serde_json::Value,
    pub facets: serde_json::Value,
    pub versions: serde_json::Value,
    /// Canonical content slot; exactly one of the two is present on an active
    /// object and both are absent once `state=redacted` (common-fields.md 5.2).
    pub content: Option<serde_json::Value>,
    pub encrypted_content: Option<serde_json::Value>,
    pub state: String,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub history_basis_seals: Vec<String>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircleProjectionRecord {
    pub circle_id: String,
    pub realm_id: String,
    pub profile_ref: Option<String>,
    pub title: String,
    pub summary: Option<String>,
    pub display: Value,
    pub directory_visibility: String,
    pub join_rule: String,
    pub history_access: String,
    pub content_encryption_floor: Option<String>,
    pub metadata_encryption_floor: Option<String>,
    pub encryption_profile: String,
    pub content_scheme: Option<String>,
    pub mls_group_ref: Option<String>,
    pub durability_policy: Option<String>,
    /// One of `active` / `archived` / `tombstoned` per spec.
    pub state: String,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub updated_by: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircleMemberProjectionRecord {
    pub circle_id: String,
    pub actor_id: String,
    /// One of `invited` / `active` / `removed` / `banned` / `left`.
    pub state: String,
    pub invited_at: Option<chrono::DateTime<chrono::Utc>>,
    pub joined_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StrandWatchProjectionRecord {
    pub strand_id: String,
    pub actor_id: String,
    pub level: Option<String>,
    pub level_public: bool,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}
/// Projection-side event log (append-only, index/debug surfaces).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectionEventAppendOutcome {
    Inserted,
    AlreadyExists,
}
#[async_trait]
pub trait ProjectionEventStore: Send + Sync {
    async fn append(
        &self,
        record: ProjectionEventRecord,
    ) -> PersistenceResult<ProjectionEventAppendOutcome>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<ProjectionEventRecord>>;
    /// Return one event kind in durable acceptance order. Security-critical
    /// reducers use this during startup so hydration does not need to load the
    /// unrelated global projection log.
    async fn snapshot_kind(
        &self,
        event_kind: &str,
    ) -> PersistenceResult<Vec<ProjectionEventRecord>>;
    async fn get(&self, event_id: &str) -> PersistenceResult<Option<ProjectionEventRecord>>;
    async fn get_by_operation_id(
        &self,
        operation_id: &str,
    ) -> PersistenceResult<Option<ProjectionEventRecord>>;
    async fn snapshot_realm(&self, realm_id: &str)
    -> PersistenceResult<Vec<ProjectionEventRecord>>;
    async fn snapshot_actor(&self, actor_id: &str)
    -> PersistenceResult<Vec<ProjectionEventRecord>>;
    /// SOL-SEC-04 — bounded variant of [`snapshot_all`] that pushes a `LIMIT`
    /// into the query so a single (federation-reachable) request cannot load
    /// the entire `projection_events` table into memory. Returns at most
    /// `limit` rows in the same order as `snapshot_all`.
    async fn snapshot_capped(&self, limit: usize) -> PersistenceResult<Vec<ProjectionEventRecord>>;
}
#[doc(hidden)]
pub fn first_string_field<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
}
#[doc(hidden)]
pub fn object_string_field<'a>(
    operation: &'a ProjectedEventOperation,
    keys: &[&str],
) -> Option<&'a str> {
    operation
        .payload
        .get("object")
        .and_then(|object| first_string_field(object, keys))
}
#[doc(hidden)]
pub fn patch_string_field<'a>(
    operation: &'a ProjectedEventOperation,
    field: &str,
) -> Option<&'a str> {
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
