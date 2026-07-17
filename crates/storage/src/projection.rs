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
    /// AKP-0007 — the Circle (`ak:circle:…`) this Strand is scoped to, if any.
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
pub fn object_string_field<'a>(operation: &'a Operation, keys: &[&str]) -> Option<&'a str> {
    operation
        .payload
        .get("object")
        .and_then(|object| first_string_field(object, keys))
}
#[doc(hidden)]
pub fn patch_string_field<'a>(operation: &'a Operation, field: &str) -> Option<&'a str> {
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
#[doc(hidden)]
pub fn projected_operation_realm_title(operation: &Operation) -> Option<&str> {
    first_string_field(&operation.payload, &["realm_title", "title"])
        .or_else(|| object_string_field(operation, &["title"]))
        .or_else(|| patch_string_field(operation, "title"))
}
#[doc(hidden)]
pub fn projected_operation_realm_summary(operation: &Operation) -> Option<&str> {
    first_string_field(&operation.payload, &["realm_summary", "summary"])
        .or_else(|| object_string_field(operation, &["summary"]))
        .or_else(|| patch_string_field(operation, "summary"))
}
#[doc(hidden)]
pub fn projected_operation_realm_discoverability(operation: &Operation) -> Option<&str> {
    first_string_field(&operation.payload, &["discoverability"])
        .or_else(|| object_string_field(operation, &["default_discoverability", "discoverability"]))
        .or_else(|| patch_string_field(operation, "default_discoverability"))
        .or_else(|| patch_string_field(operation, "discoverability"))
}
