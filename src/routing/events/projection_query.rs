//! Read-side HTTP handlers for the server-side Space-container / Flow / Morph
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
//! - `GET /_cokret/self/projection/flows?realm_id=...` — same for Flows (state ∈ {active, archived,
//!   redacted}).
//! - `GET /_cokret/self/projection/morphs?realm_id=...` — same for Morphs (same enum as Flows).
//!
//! All three endpoints are authenticated. Resource visibility check
//! piggy-backs on `realm_id_accessible` so a non-member can't probe
//! Space-container / Flow / Morph lifecycle state via this surface.
//!
//! Handlers use the SDK response DTOs so generated OpenAPI stays aligned with
//! the spec artifact registry.
//!
//! Terminal-state visibility filter: each endpoint accepts an optional
//! `include_terminal=true|false` query parameter. Default is `false`:
//!   - Space container: tombstoned rows excluded.
//!   - Flow / Morph: redacted rows excluded.
//!
//! Spec rationale: tombstoned / redacted are unrecoverable terminals per
//! common-fields.md §5.1; clients hydrating a kanban view shouldn't see them by
//! default. Explicit `include_terminal=true` returns the full set for audit /
//! debugging UIs.

use cokret_sdk::{
    Did, FlowId, MorphId, ProjectionFlowRow, ProjectionFlowsResBody, ProjectionMorphRow,
    ProjectionMorphsResBody, ProjectionObjectState, ProjectionSpaceRow, ProjectionSpaceState,
    ProjectionSpacesResBody, RealmId, SpaceId,
};
use salvo::http::StatusCode;
use salvo::oapi::extract::{PathParam, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::realm_id_accessible;
use crate::error::{AppError, ErrorCode};
use crate::reducer::{
    MorphProjection, ObjectLifecycleState, ProjectionState, RelationState,
    SpaceContainerLifecycleState,
};
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;

pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(Router::with_path("projection/spaces").get(list_space_container_projections))
        .push(Router::with_path("projection/flows").get(list_flow_projections))
        .push(Router::with_path("projection/morphs").get(list_morph_projections))
}

pub(super) fn legacy_router() -> Router {
    Router::new()
        .push(Router::with_path("projection/spaces").get(list_space_container_projections))
        .push(Router::with_path("projection/flows").get(list_flow_projections))
        .push(Router::with_path("projection/morphs").get(list_morph_projections))
        .push(Router::with_path("projection/documents/{morph_id}").get(read_document_projection))
}

// ── Helpers ────────────────────────────────────────────────────────────

/// Terminal-state check for Flow / Morph. Mirror of
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

fn relation_string_field<'a>(relation: &'a RelationState, field_name: &str) -> Option<&'a str> {
    relation
        .fields
        .get(field_name)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn flow_position_relation<'a>(
    projection: &'a ProjectionState,
    flow_id: &str,
) -> Option<&'a RelationState> {
    projection
        .relations
        .values()
        .filter(|relation| relation.is_active())
        .filter(|relation| relation.relation_kind == "contains")
        .filter(|relation| relation.to_ref.as_deref() == Some(flow_id))
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

type FlowPositionFields = (Option<SpaceId>, Option<SpaceId>, Option<String>);

fn flow_position_fields(
    projection: &ProjectionState,
    flow_id: &str,
) -> Result<FlowPositionFields, AppError> {
    let Some(relation) = flow_position_relation(projection, flow_id) else {
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

fn document_relations_json(projection: &ProjectionState, morph_id: &str) -> Vec<Value> {
    projection
        .relations
        .values()
        .filter(|relation| relation.is_active())
        .filter(|relation| {
            relation.from_ref.as_deref() == Some(morph_id)
                || relation.to_ref.as_deref() == Some(morph_id)
        })
        .map(|relation| {
            json!({
                "relation_id": relation.relation_id,
                "realm_id": relation.realm_id,
                "relation_kind": relation.relation_kind,
                "from": relation.from_ref,
                "to": relation.to_ref,
                "fields": relation.fields,
                "created_at": relation.created_at,
                "updated_at": relation.updated_at,
            })
        })
        .collect()
}

// ── Handlers ───────────────────────────────────────────────────────────

#[endpoint(
    operation_id = "ck.self.projection.spaces",
    tags("projection"),
    summary = "List Space lifecycle projection state for a Realm"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.projection.spaces"))]
async fn list_space_container_projections(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: QueryParam<String, true>,
    include_terminal: QueryParam<bool, false>,
) -> JsonResult<ProjectionSpacesResBody> {
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
    json_ok(ProjectionSpacesResBody {
        realm_id: response_realm_id,
        spaces,
        total,
    })
}

#[endpoint(
    operation_id = "ck.self.projection.flows",
    tags("projection"),
    summary = "List Flow lifecycle projection state for a Realm"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.projection.flows"))]
async fn list_flow_projections(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: QueryParam<String, true>,
    include_terminal: QueryParam<bool, false>,
) -> JsonResult<ProjectionFlowsResBody> {
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
    let flows: Vec<ProjectionFlowRow> = proj
        .flows
        .values()
        .filter(|f| f.realm_id == realm_id)
        .filter(|f| include_terminal || !is_object_terminal(f.state))
        .map(|f| {
            let (board_space_id, list_space_id, rank) = flow_position_fields(&proj, &f.flow_id)?;
            Ok(ProjectionFlowRow {
                flow_id: parse_projection_id::<FlowId>(&f.flow_id, "flow_id")?,
                realm_id: parse_projection_id::<RealmId>(&f.realm_id, "realm_id")?,
                state: projection_object_state(f.state),
                title: Some(f.title.clone()),
                summary: f.summary.clone(),
                board_space_id,
                list_space_id,
                rank,
                created_by: Some(parse_projection_id::<Did>(&f.created_by, "created_by")?),
                created_at: Some(f.created_at),
                updated_at: f.updated_at,
                state_changed_at: f.state_changed_at,
            })
        })
        .collect::<Result<_, AppError>>()?;
    drop(proj);
    let total = total_count(flows.len())?;
    json_ok(ProjectionFlowsResBody {
        realm_id: response_realm_id,
        flows,
        total,
    })
}

#[endpoint(
    operation_id = "ck.self.projection.morphs",
    tags("projection"),
    summary = "List Morph lifecycle projection state for a Realm"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.projection.morphs"))]
async fn list_morph_projections(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: QueryParam<String, true>,
    include_terminal: QueryParam<bool, false>,
) -> JsonResult<ProjectionMorphsResBody> {
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
    json_ok(ProjectionMorphsResBody {
        realm_id: response_realm_id,
        morphs,
        total,
    })
}

#[endpoint(
    operation_id = "ck.extension.soland.projection.document",
    tags("projection"),
    summary = "Read a document Morph projection with body, versions, relations, comments, and cursor presence"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.projection.document"))]
async fn read_document_projection(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    morph_id: PathParam<String>,
) -> JsonResult<Value> {
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
        .map(|version| {
            json!({
                "version_id": version.version_id,
                "event_id": version.event_id,
                "author": version.author,
                "created_at": version.created_at,
                "body_digest": version.body_digest,
                "body": version.body,
            })
        })
        .collect::<Vec<_>>();
    let response = json!({
        "document": {
            "morph_id": morph.morph_id,
            "realm_id": morph.realm_id,
            "morph_type": morph.morph_type,
            "title": morph.title,
            "state": morph.state.as_str(),
            "fields": morph.fields,
            "body": body,
            "schema_refs": morph.schema_refs,
            "facets": morph.facets,
            "created_by": morph.created_by,
            "created_at": morph.created_at,
            "updated_by": morph.updated_by,
            "updated_at": morph.updated_at,
            "state_changed_at": morph.state_changed_at,
        },
        "versions": versions,
        "relations": relations,
        "comments": comments,
        "cursor_presence": [],
    });
    json_ok(response)
}
