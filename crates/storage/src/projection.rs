use super::{
    BTreeMap, PersistenceError, PersistenceResult, ProjectedEventOperation, ProjectionEventRecord,
    RealmMetaRecord, Value, async_trait,
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

/// Authoritative current Relation value for one typed primary conflict domain.
///
/// Unlike the rebuildable in-memory relation index, this row carries the exact
/// accepting RealmCommit revision used by admission CAS. Restart hydration
/// reads this port so queries and subsequent validation observe the same
/// current value the transaction boundary serialized.
#[derive(Clone, Debug)]
pub struct RelationCurrentResultRecord {
    pub realm_id: arkret_wire::RealmId,
    pub domain_key: String,
    pub primary_conflict_domain:
        arkret_models_collaboration::objects::relation::RelationPrimaryConflictDomain,
    pub relation: arkret_models_collaboration::objects::relation::Relation,
    pub revision: arkret_wire::CurrentRevision,
}

#[async_trait]
pub trait RelationCurrentResultStore: Send + Sync {
    async fn snapshot_all(&self) -> PersistenceResult<Vec<RelationCurrentResultRecord>>;
}

/// Authoritative current Capability Grant value accepted by the governing
/// Station.
///
/// `value` and `revision` are one durable row and therefore one read
/// snapshot.  Consumers must never replace this revision with the in-memory
/// facet counter, the effective-list digest, or an Event id.
#[derive(Clone, Debug, PartialEq)]
pub struct CapabilityGrantCurrentResultRecord {
    pub realm_id: arkret_wire::RealmId,
    pub grant_id: arkret_wire::GrantId,
    pub status: CapabilityGrantCurrentStatus,
    pub value: serde_json::Value,
    pub revision: arkret_wire::CurrentRevision,
}

impl CapabilityGrantCurrentResultRecord {
    /// Build one backend-neutral current row and fail closed if its canonical
    /// value disagrees with the storage key or lifecycle columns.
    pub fn try_new(
        realm_id: arkret_wire::RealmId,
        grant_id: arkret_wire::GrantId,
        status: CapabilityGrantCurrentStatus,
        value: serde_json::Value,
        revision: arkret_wire::CurrentRevision,
    ) -> PersistenceResult<Self> {
        let object = value.as_object().ok_or_else(|| {
            PersistenceError::Database("stored Capability Grant value is not an object".to_owned())
        })?;
        if object.get("schema").and_then(serde_json::Value::as_str)
            != Some("ak.schema.capability.v1")
            || object.get("id").and_then(serde_json::Value::as_str) != Some(grant_id.as_str())
            || object.get("status").and_then(serde_json::Value::as_str) != Some(status.as_str())
            || object
                .get("realm_id")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value_realm| value_realm != realm_id.as_str())
        {
            return Err(PersistenceError::Database(
                "stored Capability Grant value does not match its row identity".to_owned(),
            ));
        }
        Ok(Self {
            realm_id,
            grant_id,
            status,
            value,
            revision,
        })
    }
}

/// Closed lifecycle of the `capability_grant` typed current result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityGrantCurrentStatus {
    Active,
    Revoked,
    Relinquished,
}

impl CapabilityGrantCurrentStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Relinquished => "relinquished",
        }
    }
}

impl std::str::FromStr for CapabilityGrantCurrentStatus {
    type Err = PersistenceError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "active" => Ok(Self::Active),
            "revoked" => Ok(Self::Revoked),
            "relinquished" => Ok(Self::Relinquished),
            _ => Err(PersistenceError::Database(
                "stored Capability Grant lifecycle is invalid".to_owned(),
            )),
        }
    }
}

#[async_trait]
pub trait CapabilityGrantCurrentResultStore: Send + Sync {
    async fn get(
        &self,
        realm_id: &arkret_wire::RealmId,
        grant_id: &arkret_wire::GrantId,
    ) -> PersistenceResult<Option<CapabilityGrantCurrentResultRecord>>;

    /// Return one statement-level snapshot of every current grant in a Realm.
    /// Effective/subject filtering belongs above this persistence boundary.
    async fn snapshot_for_realm(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Vec<CapabilityGrantCurrentResultRecord>>;
}

#[cfg(test)]
mod capability_grant_current_result_tests {
    use super::*;

    const REALM_ID: &str = "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru";
    const GRANT_ID: &str = "ak:grant:AcFfzgdHkT6eFkto1gjLaKniVuMXx9sD0GKQwk8BXykz";
    const COMMIT_ID: &str = "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4";

    fn record(
        status: CapabilityGrantCurrentStatus,
    ) -> PersistenceResult<CapabilityGrantCurrentResultRecord> {
        CapabilityGrantCurrentResultRecord::try_new(
            REALM_ID.parse().unwrap(),
            GRANT_ID.parse().unwrap(),
            status,
            serde_json::json!({
                "id": GRANT_ID,
                "schema": "ak.schema.capability.v1",
                "realm_id": REALM_ID,
                "status": status.as_str()
            }),
            arkret_wire::CurrentRevision {
                commit_id: COMMIT_ID.parse().unwrap(),
                stream_position: 41,
            },
        )
    }

    #[test]
    fn value_and_exact_commit_revision_remain_one_record() {
        let record = record(CapabilityGrantCurrentStatus::Active).unwrap();
        assert_eq!(record.value["id"], GRANT_ID);
        assert_eq!(record.revision.commit_id.as_str(), COMMIT_ID);
        assert_eq!(record.revision.stream_position, 41);
    }

    #[test]
    fn lifecycle_mismatch_fails_closed() {
        let mut record = record(CapabilityGrantCurrentStatus::Active).unwrap();
        record.value["status"] = serde_json::json!("revoked");
        assert!(matches!(
            CapabilityGrantCurrentResultRecord::try_new(
                record.realm_id,
                record.grant_id,
                record.status,
                record.value,
                record.revision,
            ),
            Err(PersistenceError::Database(_))
        ));
    }
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
    pub fields: BTreeMap<String, serde_json::Value>,
    pub schema_refs: Vec<String>,
    /// One of `active` / `archived` / `deleted` / `redacted` per spec.
    pub state: String,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Wire spelling of the business-progression stage, absent when the object
    /// carries no stage (`common-fields.md` §5.3).
    pub stage: Option<String>,
    /// Reducer-derived timestamp of the last real stage transition; never
    /// present without `stage`.
    pub stage_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
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
    /// Wire spelling of the business-progression stage, absent when the object
    /// carries no stage (`common-fields.md` §5.3).
    pub stage: Option<String>,
    /// Reducer-derived timestamp of the last real stage transition; never
    /// present without `stage`.
    pub stage_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
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
    pub encryption_profile: String,
    pub mls_group_ref: Option<String>,
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
    /// Append a complete derived unit atomically. A conflict on any member
    /// rolls back every insertion; exact retries preserve the original rows.
    async fn append_batch(
        &self,
        records: Vec<ProjectionEventRecord>,
    ) -> PersistenceResult<Vec<ProjectionEventAppendOutcome>>;

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
