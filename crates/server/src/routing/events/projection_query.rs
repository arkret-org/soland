//! Read-side HTTP handlers for the server-side Space-container / Strand / Morph
//! lifecycle projection state maintained by `reducer::ProjectionState`.
//!
//! These endpoints let yougen (and other clients) re-hydrate the
//! optimistic Archive / Restore state after a page refresh, so a
//! `ck.space.archive` accepted by the server doesn't appear "unarchived"
//! again when the kanban view re-mounts.
//!
//! - `GET /_cokret/self/projection/spaces?realm_id=...` — canonical projection endpoint listing
//!   Space containers in a Realm scope, with `state` ∈ {active, archived, tombstoned} (spec
//!   `common-fields.md §5.1`).
//! - `GET /_cokret/self/projection/strands?realm_id=...` — same for Strands (state ∈ {active,
//!   archived, redacted}).
//! - `GET /_cokret/self/projection/morphs?realm_id=...` — same for Morphs (same enum as Strands).
//!
//! All three endpoints are authenticated. Resource visibility check
//! piggy-backs on `realm_id_accessible` so a non-member can't probe
//! Space-container / Strand / Morph lifecycle state via this surface.
//!
//! Handlers use the SDK response DTOs so generated OpenAPI stays aligned with
//! the spec artifact registry.
//!
//! Terminal-state visibility filter: each endpoint accepts an optional
//! `include_terminal=true|false` query parameter. Default is `false`:
//!   - Space container: tombstoned rows excluded.
//!   - Strand / Morph: redacted rows excluded.
//!
//! Spec rationale: tombstoned / redacted are unrecoverable terminals per
//! common-fields.md §5.1; clients hydrating a kanban view shouldn't see them by
//! default. Explicit `include_terminal=true` returns the full set for audit /
//! debugging UIs.

use cokret_sdk::{
    Did, MorphId, ProjectionAssignedToRelation, ProjectionMorphList, ProjectionMorphRow,
    ProjectionObjectState, ProjectionSpaceList, ProjectionSpaceRow, ProjectionSpaceState,
    ProjectionStrandList, ProjectionStrandRow, RealmId, RelationId, SpaceId, StrandId,
};
use salvo::http::StatusCode;
use salvo::oapi::extract::{PathParam, QueryParam};
use salvo::prelude::*;
use serde::Serialize;
use serde_json::{Value, json};

use super::realm_id_accessible;
use crate::error::{AppError, ErrorCode};
use crate::reducer::{
    MorphProjection, ObjectLifecycleState, ProjectionState, SolandRelationState,
    SpaceContainerLifecycleState,
};
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;

pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(Router::with_path("projection/spaces").get(list_space_container_projections))
        .push(Router::with_path("projection/strands").get(list_strand_projections))
        .push(Router::with_path("projection/morphs").get(list_morph_projections))
}

pub(super) fn legacy_router() -> Router {
    Router::new()
        .push(Router::with_path("projection/spaces").get(list_space_container_projections))
        .push(Router::with_path("projection/strands").get(list_strand_projections))
        .push(Router::with_path("projection/morphs").get(list_morph_projections))
        .push(Router::with_path("projection/documents/{morph_id}").get(read_document_projection))
}

// ── Helpers ────────────────────────────────────────────────────────────

/// Terminal-state check for Strand / Morph. Mirror of
/// `ObjectLifecycleState::is_terminal` but inlined here so the
/// `filter` chain in the handlers reads as
/// `!is_object_terminal(f.state)` for symmetry with the Space-container
/// check (`state != SpaceContainerLifecycleState::Tombstoned`).
fn is_object_terminal(state: ObjectLifecycleState) -> bool {
    state.is_terminal()
}

fn validate_realm_id(realm_id: String) -> Result<String, AppError> {
    RealmId::new(realm_id.clone())
        .map_err(|_| AppError::invalid_param("invalid realm_id format"))?;
    Ok(realm_id)
}

fn projection_space_state(state: SpaceContainerLifecycleState) -> ProjectionSpaceState {
    match state {
        SpaceContainerLifecycleState::Active => ProjectionSpaceState::Active,
        SpaceContainerLifecycleState::Archived => ProjectionSpaceState::Archived,
        SpaceContainerLifecycleState::Tombstoned => ProjectionSpaceState::Tombstoned,
    }
}

fn projection_object_state(state: ObjectLifecycleState) -> ProjectionObjectState {
    match state {
        ObjectLifecycleState::Active => ProjectionObjectState::Active,
        ObjectLifecycleState::Archived => ProjectionObjectState::Archived,
        ObjectLifecycleState::Redacted => ProjectionObjectState::Redacted,
    }
}

fn parse_projection_id<T>(value: &str, field: &str) -> Result<T, AppError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    value
        .parse::<T>()
        .map_err(|_| AppError::internal(format!("invalid {field} in projection state")))
}

fn total_count(len: usize) -> Result<u64, AppError> {
    u64::try_from(len).map_err(|_| AppError::internal("projection row count overflow"))
}

fn relation_string_field<'a>(
    relation: &'a SolandRelationState,
    field_name: &str,
) -> Option<&'a str> {
    relation
        .fields
        .get(field_name)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn strand_position_relation<'a>(
    projection: &'a ProjectionState,
    strand_id: &str,
) -> Option<&'a SolandRelationState> {
    projection
        .relations
        .values()
        .filter(|relation| relation.is_active())
        .filter(|relation| relation.relation_kind == "contains")
        .filter(|relation| relation.to_ref.as_deref() == Some(strand_id))
        .filter(|relation| relation_string_field(relation, "board_space_id").is_some())
        .filter(|relation| {
            relation_string_field(relation, "list_space_id")
                .or(relation.from_ref.as_deref())
                .is_some()
        })
        .max_by(|left, right| {
            left.updated_at
                .cmp(&right.updated_at)
                .then(left.relation_id.cmp(&right.relation_id))
        })
}

type StrandPositionFields = (Option<SpaceId>, Option<SpaceId>, Option<String>);

#[derive(Debug, Serialize, ToSchema)]
struct DocumentProjectionOutcome {
    document: DocumentProjectionDocument,
    versions: Vec<DocumentProjectionVersion>,
    relations: Vec<DocumentProjectionRelation>,
    comments: Vec<Value>,
    cursor_presence: Vec<Value>,
}

#[derive(Debug, Serialize, ToSchema)]
struct DocumentProjectionDocument {
    morph_id: String,
    realm_id: String,
    morph_type: String,
    title: Option<String>,
    state: String,
    fields: std::collections::BTreeMap<String, Value>,
    body: Value,
    schema_refs: Vec<String>,
    facets: Vec<String>,
    created_by: String,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_by: Option<String>,
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
    state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize, ToSchema)]
struct DocumentProjectionVersion {
    version_id: String,
    event_id: String,
    author: String,
    created_at: chrono::DateTime<chrono::Utc>,
    body_digest: String,
    body: Value,
}

#[derive(Debug, Serialize, ToSchema)]
struct DocumentProjectionRelation {
    relation_id: String,
    realm_id: String,
    relation_kind: String,
    from: Option<String>,
    to: Option<String>,
    fields: std::collections::BTreeMap<String, Value>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

fn strand_position_fields(
    projection: &ProjectionState,
    strand_id: &str,
) -> Result<StrandPositionFields, AppError> {
    let Some(relation) = strand_position_relation(projection, strand_id) else {
        return Ok((None, None, None));
    };
    let board_space_id = relation_string_field(relation, "board_space_id")
        .map(|value| parse_projection_id::<SpaceId>(value, "board_space_id"))
        .transpose()?;
    let list_space_id = relation_string_field(relation, "list_space_id")
        .or(relation.from_ref.as_deref())
        .map(|value| parse_projection_id::<SpaceId>(value, "list_space_id"))
        .transpose()?;
    let rank = relation_string_field(relation, "rank").map(ToOwned::to_owned);
    Ok((board_space_id, list_space_id, rank))
}

fn strand_assigned_to_relations(
    projection: &ProjectionState,
    strand_id: &str,
) -> Result<Vec<ProjectionAssignedToRelation>, AppError> {
    let mut relation_refs = projection
        .relations
        .values()
        .filter(|relation| relation.is_active())
        .filter(|relation| relation.relation_kind == "assigned_to")
        .filter(|relation| relation.from_ref.as_deref() == Some(strand_id))
        .filter_map(|relation| {
            relation
                .to_ref
                .as_deref()
                .map(|actor_id| (actor_id.to_owned(), relation.relation_id.clone()))
        })
        .collect::<Vec<_>>();
    relation_refs.sort();
    relation_refs
        .into_iter()
        .map(|(actor_id, relation_id)| {
            Ok(ProjectionAssignedToRelation {
                relation_id: parse_projection_id::<RelationId>(
                    &relation_id,
                    "assigned_to_relations.relation_id",
                )?,
                actor_id: parse_projection_id::<Did>(&actor_id, "assigned_to_relations.actor_id")?,
            })
        })
        .collect()
}

fn document_body_from_morph(morph: &MorphProjection) -> Value {
    morph
        .fields
        .get("document")
        .or_else(|| morph.fields.get("body"))
        .cloned()
        .unwrap_or(Value::Null)
}

fn document_text_len(value: &Value) -> usize {
    if let Some(text) = value.as_str() {
        return text.chars().count();
    }
    if let Some(blocks) = value.get("blocks").and_then(Value::as_array) {
        return blocks
            .iter()
            .map(|block| {
                block
                    .get("content")
                    .or_else(|| block.get("text"))
                    .and_then(Value::as_str)
                    .map(|text| text.chars().count())
                    .unwrap_or(0)
            })
            .sum::<usize>()
            + blocks.len().saturating_sub(1);
    }
    value.to_string().chars().count()
}

fn comment_anchor_range(content: &Value) -> Option<(u64, u64)> {
    let range = content.get("anchor_range")?;
    let start = range
        .get("start")
        .or_else(|| range.get("range_start"))
        .and_then(Value::as_u64)?;
    let end = range
        .get("end")
        .or_else(|| range.get("range_end"))
        .and_then(Value::as_u64)?;
    (end > start).then_some((start, end))
}

fn comment_target_ref(content: &Value) -> Option<&str> {
    content
        .get("morph_id")
        .or_else(|| content.get("document_id"))
        .or_else(|| content.get("target_ref"))
        .or_else(|| content.pointer("/anchor_range/morph_id"))
        .or_else(|| content.pointer("/anchor_range/document_id"))
        .or_else(|| content.pointer("/anchor_range/target_ref"))
        .and_then(Value::as_str)
}

fn comment_reply_to(content: &Value) -> Option<&str> {
    content
        .get("reply_to")
        .or_else(|| content.get("in_reply_to"))
        .and_then(Value::as_str)
}

fn comment_body(content: &Value) -> String {
    content
        .get("body")
        .or_else(|| content.get("text"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

fn document_comments_json(
    projection: &ProjectionState,
    morph_id: &str,
    document_len: usize,
) -> Vec<Value> {
    let mut roots = Vec::new();
    let mut replies: std::collections::BTreeMap<String, Vec<Value>> =
        std::collections::BTreeMap::new();
    for message in projection.messages.values() {
        let content = &message.content;
        if comment_target_ref(content) != Some(morph_id) {
            continue;
        }
        if let Some(parent) = comment_reply_to(content) {
            replies.entry(parent.to_owned()).or_default().push(json!({
                "event_id": message.event_id,
                "author": message.sender,
                "body": comment_body(content),
                "created_at": message.created_at,
            }));
            continue;
        }
        let Some((start, end)) = comment_anchor_range(content) else {
            continue;
        };
        let explicit_state = content
            .get("state")
            .or_else(|| content.get("comment_state"))
            .and_then(Value::as_str);
        let state = if matches!(explicit_state, Some("orphaned" | "locked")) {
            explicit_state.unwrap()
        } else if usize::try_from(end)
            .ok()
            .is_some_and(|end| end > document_len)
        {
            "orphaned"
        } else {
            "active"
        };
        roots.push(json!({
            "comment_id": message.event_id,
            "author": message.sender,
            "body": comment_body(content),
            "anchor_range": { "start": start, "end": end },
            "state": state,
            "created_at": message.created_at,
        }));
    }
    for root in &mut roots {
        if let Some(comment_id) = root.get("comment_id").and_then(Value::as_str)
            && let Some(children) = replies.remove(comment_id)
        {
            root["replies"] = Value::Array(children);
        }
    }
    roots
}

fn document_relations_json(
    projection: &ProjectionState,
    morph_id: &str,
) -> Vec<DocumentProjectionRelation> {
    projection
        .relations
        .values()
        .filter(|relation| relation.is_active())
        .filter(|relation| {
            relation.from_ref.as_deref() == Some(morph_id)
                || relation.to_ref.as_deref() == Some(morph_id)
        })
        .map(|relation| DocumentProjectionRelation {
            relation_id: relation.relation_id.clone(),
            realm_id: relation.realm_id.clone(),
            relation_kind: relation.relation_kind.clone(),
            from: relation.from_ref.clone(),
            to: relation.to_ref.clone(),
            fields: relation.fields.clone(),
            created_at: relation.created_at,
            updated_at: relation.updated_at,
        })
        .collect()
}

// ── Handlers ───────────────────────────────────────────────────────────

#[endpoint(
    operation_id = "ck.self.projection.spaces.query.list",
    tags("projection"),
    summary = "List Space lifecycle projection state for a Realm"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.projection.spaces.query.list"))]
async fn list_space_container_projections(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: QueryParam<String, true>,
    include_terminal: QueryParam<bool, false>,
) -> JsonResult<ProjectionSpaceList> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = validate_realm_id(realm_id.into_inner())?;
    let response_realm_id = RealmId::new(realm_id.clone())
        .map_err(|_| AppError::invalid_param("invalid realm_id format"))?;
    let include_terminal = include_terminal.into_inner().unwrap_or(false);
    if !realm_id_accessible(state, &realm_id, Some(&session)).await {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "Space not visible to this actor",
        )
        .with_status(StatusCode::FORBIDDEN));
    }
    let proj = state.projection.lock().map_err(|_| {
        AppError::new(
            ErrorCode::TemporarilyUnavailable,
            "projection state unavailable",
        )
        .with_status(StatusCode::INTERNAL_SERVER_ERROR)
    })?;
    let spaces: Vec<ProjectionSpaceRow> = proj
        .space_containers
        .values()
        .filter(|p| p.realm_id == realm_id)
        .filter(|p| include_terminal || p.state != SpaceContainerLifecycleState::Tombstoned)
        .map(|p| {
            Ok(ProjectionSpaceRow {
                space_id: parse_projection_id::<SpaceId>(&p.container_space_id, "space_id")?,
                realm_id: parse_projection_id::<RealmId>(&p.realm_id, "realm_id")?,
                kind: p.kind.clone(),
                title: p.title.clone(),
                parent_space_id: p
                    .parent_ref
                    .as_deref()
                    .map(|s| {
                        SpaceId::new(s.to_owned()).map_err(|err| {
                            AppError::internal(format!(
                                "stored parent_space_id is not a typed SpaceId: {err}"
                            ))
                        })
                    })
                    .transpose()?,
                rank: p.rank.clone(),
                state: projection_space_state(p.state),
                created_by: Some(parse_projection_id::<Did>(&p.created_by, "created_by")?),
                created_at: Some(p.created_at),
                updated_at: p.updated_at,
                state_changed_at: p.state_changed_at,
            })
        })
        .collect::<Result<_, AppError>>()?;
    drop(proj);
    let total = total_count(spaces.len())?;
    json_ok(ProjectionSpaceList {
        realm_id: response_realm_id,
        spaces,
        total,
        next_cursor: None,
        has_more: false,
    })
}

#[endpoint(
    operation_id = "ck.self.projection.strands.query.list",
    tags("projection"),
    summary = "List Strand lifecycle projection state for a Realm"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.projection.strands.query.list"))]
async fn list_strand_projections(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: QueryParam<String, true>,
    include_terminal: QueryParam<bool, false>,
) -> JsonResult<ProjectionStrandList> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = validate_realm_id(realm_id.into_inner())?;
    let response_realm_id = RealmId::new(realm_id.clone())
        .map_err(|_| AppError::invalid_param("invalid realm_id format"))?;
    let include_terminal = include_terminal.into_inner().unwrap_or(false);
    if !realm_id_accessible(state, &realm_id, Some(&session)).await {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "Space not visible to this actor",
        )
        .with_status(StatusCode::FORBIDDEN));
    }
    let proj = state.projection.lock().map_err(|_| {
        AppError::new(
            ErrorCode::TemporarilyUnavailable,
            "projection state unavailable",
        )
        .with_status(StatusCode::INTERNAL_SERVER_ERROR)
    })?;
    // COT-06-004 — the Realm's default-Strand pointer drives each row's
    // derived `is_default` flag (no per-Strand stored column).
    let default_strand_id = proj
        .realm_states
        .get(&realm_id)
        .and_then(|realm| realm.default_strand_id.clone());
    let strands: Vec<ProjectionStrandRow> = proj
        .strands
        .values()
        .filter(|f| f.realm_id == realm_id)
        .filter(|f| include_terminal || !is_object_terminal(f.state))
        .map(|f| {
            let (board_space_id, list_space_id, rank) =
                strand_position_fields(&proj, &f.strand_id)?;
            let assigned_to_relations = strand_assigned_to_relations(&proj, &f.strand_id)?;
            let mut assigned_actor_ids = assigned_to_relations
                .iter()
                .map(|relation| relation.actor_id.clone())
                .collect::<Vec<_>>();
            assigned_actor_ids.sort();
            assigned_actor_ids.dedup();
            Ok(ProjectionStrandRow {
                strand_id: parse_projection_id::<StrandId>(&f.strand_id, "strand_id")?,
                realm_id: parse_projection_id::<RealmId>(&f.realm_id, "realm_id")?,
                state: projection_object_state(f.state),
                state_changed_at: f.state_changed_at,
                title: Some(f.title.clone()),
                summary: f.summary.clone(),
                board_space_id,
                list_space_id,
                rank,
                assigned_actor_ids,
                assigned_to_relations,
                created_by: Some(parse_projection_id::<Did>(&f.created_by, "created_by")?),
                created_at: Some(f.created_at),
                updated_at: f.updated_at,
                is_default: default_strand_id.as_deref() == Some(f.strand_id.as_str()),
            })
        })
        .collect::<Result<_, AppError>>()?;
    drop(proj);
    let total = total_count(strands.len())?;
    json_ok(ProjectionStrandList {
        realm_id: response_realm_id,
        strands,
        total,
        next_cursor: None,
        has_more: false,
    })
}

#[endpoint(
    operation_id = "ck.self.projection.morphs.query.list",
    tags("projection"),
    summary = "List Morph lifecycle projection state for a Realm"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.projection.morphs.query.list"))]
async fn list_morph_projections(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: QueryParam<String, true>,
    include_terminal: QueryParam<bool, false>,
) -> JsonResult<ProjectionMorphList> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = validate_realm_id(realm_id.into_inner())?;
    let response_realm_id = RealmId::new(realm_id.clone())
        .map_err(|_| AppError::invalid_param("invalid realm_id format"))?;
    let include_terminal = include_terminal.into_inner().unwrap_or(false);
    if !realm_id_accessible(state, &realm_id, Some(&session)).await {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "Space not visible to this actor",
        )
        .with_status(StatusCode::FORBIDDEN));
    }
    let proj = state.projection.lock().map_err(|_| {
        AppError::new(
            ErrorCode::TemporarilyUnavailable,
            "projection state unavailable",
        )
        .with_status(StatusCode::INTERNAL_SERVER_ERROR)
    })?;
    let morphs: Vec<ProjectionMorphRow> = proj
        .morphs
        .values()
        .filter(|m| m.realm_id == realm_id)
        .filter(|m| include_terminal || !is_object_terminal(m.state))
        .map(|m| {
            Ok(ProjectionMorphRow {
                morph_id: parse_projection_id::<MorphId>(&m.morph_id, "morph_id")?,
                realm_id: parse_projection_id::<RealmId>(&m.realm_id, "realm_id")?,
                morph_type: m.morph_type.clone(),
                state: projection_object_state(m.state),
                title: m.title.clone(),
                created_by: Some(parse_projection_id::<Did>(&m.created_by, "created_by")?),
                created_at: Some(m.created_at),
                updated_at: m.updated_at,
                state_changed_at: m.state_changed_at,
            })
        })
        .collect::<Result<_, AppError>>()?;
    drop(proj);
    let total = total_count(morphs.len())?;
    json_ok(ProjectionMorphList {
        realm_id: response_realm_id,
        morphs,
        total,
        next_cursor: None,
        has_more: false,
    })
}

#[endpoint(
    operation_id = "org.cokret.soland.projection.document",
    tags("projection"),
    summary = "Read a document Morph projection with body, versions, relations, comments, and cursor presence"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.projection.document"))]
async fn read_document_projection(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    morph_id: PathParam<String>,
) -> JsonResult<DocumentProjectionOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let morph_id = morph_id.into_inner();
    let _ = parse_projection_id::<MorphId>(&morph_id, "morph_id")?;
    // Snapshot the morph + derived comments/relations out from under the
    // projection lock before the async access check (the guard is not Send
    // and must not cross an `.await`).
    let (morph, body, comments, relations) = {
        let proj = state.projection.lock().map_err(|_| {
            AppError::new(
                ErrorCode::TemporarilyUnavailable,
                "projection state unavailable",
            )
            .with_status(StatusCode::INTERNAL_SERVER_ERROR)
        })?;
        let morph = proj
            .morphs
            .get(&morph_id)
            .cloned()
            .ok_or_else(|| AppError::not_found("document Morph not found"))?;
        let body = document_body_from_morph(&morph);
        let document_len = document_text_len(&body);
        let comments = document_comments_json(&proj, &morph_id, document_len);
        let relations = document_relations_json(&proj, &morph_id);
        (morph, body, comments, relations)
    };
    if !realm_id_accessible(state, &morph.realm_id, Some(&session)).await {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "Document not visible to this actor",
        )
        .with_status(StatusCode::FORBIDDEN));
    }
    let versions = morph
        .versions
        .iter()
        .map(|version| DocumentProjectionVersion {
            version_id: version.version_id.clone(),
            event_id: version.event_id.clone(),
            author: version.author.clone(),
            created_at: version.created_at,
            body_digest: version.body_digest.clone(),
            body: version.body.clone(),
        })
        .collect::<Vec<_>>();
    let response = DocumentProjectionOutcome {
        document: DocumentProjectionDocument {
            morph_id: morph.morph_id,
            realm_id: morph.realm_id,
            morph_type: morph.morph_type,
            title: morph.title,
            state: morph.state.as_str().to_owned(),
            fields: morph.fields,
            body,
            schema_refs: morph.schema_refs,
            facets: morph.facets,
            created_by: morph.created_by,
            created_at: morph.created_at,
            updated_by: morph.updated_by,
            updated_at: morph.updated_at,
            state_changed_at: morph.state_changed_at,
        },
        versions,
        relations,
        comments,
        cursor_presence: Vec::new(),
    };
    json_ok(response)
}
