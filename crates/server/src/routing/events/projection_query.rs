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

use chrono::{DateTime, Utc};
use cokret_sdk::{
    Did, MorphId, ProjectionAssignedToRelation, ProjectionMorphList, ProjectionMorphRow,
    ProjectionObjectState, ProjectionSpaceList, ProjectionSpaceRow, ProjectionSpaceState,
    ProjectionStrandList, ProjectionStrandRow, RealmId, RelationId, SpaceId, StrandId,
};
use salvo::http::StatusCode;
use salvo::oapi::extract::QueryParam;
use salvo::prelude::*;

use super::{realm_discoverability, realm_history_visibility, realm_id_accessible};
use crate::error::{AppError, ErrorCode};
use crate::reducer::{
    ObjectLifecycleState, ProjectionState, SolandRelationState, SpaceContainerLifecycleState,
};
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::{AppState, SessionRecord};

pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(Router::with_path("projection/spaces").get(list_space_container_projections))
        .push(Router::with_path("projection/strands").get(list_strand_projections))
        .push(Router::with_path("projection/morphs").get(list_morph_projections))
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

fn projection_row_visible_to_session(
    projection: &ProjectionState,
    realm_id: &str,
    session: &SessionRecord,
    sender: &str,
    created_at: DateTime<Utc>,
    scope_circle_id: Option<&str>,
    history_visibility: &str,
    discoverability: &str,
) -> bool {
    if sender == session.actor {
        return true;
    }
    if !projection_realm_history_allows(
        projection,
        realm_id,
        &session.actor,
        created_at,
        history_visibility,
        discoverability,
    ) {
        return false;
    }
    scope_circle_id.is_none_or(|circle_id| {
        projection.circle_scope_visible_to_actor_at(circle_id, &session.actor, created_at)
    })
}

fn projection_realm_history_allows(
    projection: &ProjectionState,
    realm_id: &str,
    actor: &str,
    created_at: DateTime<Utc>,
    history_visibility: &str,
    discoverability: &str,
) -> bool {
    match history_visibility {
        "world_readable" => true,
        "shared" => {
            discoverability == "public"
                || projection
                    .member(realm_id, actor)
                    .is_some_and(|member| member.state == "join")
        }
        "invited" => projection
            .member(realm_id, actor)
            .and_then(|member| {
                member.invited_at.or_else(|| {
                    matches!(member.state.as_str(), "invite" | "join").then_some(member.updated_at)
                })
            })
            .is_some_and(|visible_at| created_at >= visible_at),
        "joined" => projection
            .member(realm_id, actor)
            .filter(|member| member.state == "join")
            .is_some_and(|member| created_at >= member.joined_at),
        _ => false,
    }
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
    let history_visibility = realm_history_visibility(state, &realm_id).await;
    let discoverability = realm_discoverability(state, &realm_id).await;
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
        .filter(|p| {
            projection_row_visible_to_session(
                &proj,
                &realm_id,
                &session,
                &p.created_by,
                p.created_at,
                p.scope_circle_id.as_deref(),
                &history_visibility,
                &discoverability,
            )
        })
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
    let history_visibility = realm_history_visibility(state, &realm_id).await;
    let discoverability = realm_discoverability(state, &realm_id).await;
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
        .filter(|f| {
            projection_row_visible_to_session(
                &proj,
                &realm_id,
                &session,
                &f.created_by,
                f.created_at,
                f.scope_circle_id.as_deref(),
                &history_visibility,
                &discoverability,
            )
        })
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
    let history_visibility = realm_history_visibility(state, &realm_id).await;
    let discoverability = realm_discoverability(state, &realm_id).await;
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
        .filter(|m| {
            projection_row_visible_to_session(
                &proj,
                &realm_id,
                &session,
                &m.created_by,
                m.created_at,
                m.scope_circle_id.as_deref(),
                &history_visibility,
                &discoverability,
            )
        })
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
