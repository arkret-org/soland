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
    CellRef, Did, DocumentMorphProjectionOutcome, HistoryRangeContext, HistoryReaderContext,
    HistoryReaderEventState, HistorySharingPolicyPayloadValue, HistorySharingRestrictedScopeRef,
    HistorySharingScopeKind, HistoryVisibility, MorphId, ProjectionAssignedToRelation,
    ProjectionMorphList, ProjectionMorphRow, ProjectionObjectState, ProjectionSpaceList,
    ProjectionSpaceRow, ProjectionSpaceState, ProjectionStrandList, ProjectionStrandRow, RealmId,
    RelationId, SealId, SpaceId, StrandId, event_time_history_visible, matching_restricted_rules,
};
use salvo::http::StatusCode;
use salvo::oapi::extract::{PathParam, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{realm_history_visibility, realm_id_accessible};
use crate::error::{AppError, ErrorCode};
use crate::reducer::{
    MessageState, MorphProjection, ObjectLifecycleState, ProjectionState, SolandRelationState,
    SpaceContainerLifecycleState, morph_document_body,
};
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::{AppState, SessionRecord};

pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(Router::with_path("projection/spaces").get(list_space_container_projections))
        .push(Router::with_path("projection/strands").get(list_strand_projections))
        .push(Router::with_path("projection/morphs").get(list_morph_projections))
        .push(Router::with_path("projection/documents/{morph_id}").get(get_document_projection))
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

async fn realm_history_sharing_policy(
    state: &AppState,
    realm_id: &str,
) -> Option<HistorySharingPolicyPayloadValue> {
    let policy_value = state
        .persistence
        .realm_meta()
        .get(realm_id)
        .await
        .ok()
        .flatten()?
        .history_sharing_policy?;
    let policy = serde_json::from_value::<HistorySharingPolicyPayloadValue>(policy_value).ok()?;
    cokret_sdk::validate_history_sharing_policy(&policy).ok()?;
    Some(policy)
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
    state: &AppState,
    projection: &ProjectionState,
    realm_id: &str,
    session: &SessionRecord,
    sender: &str,
    created_at: DateTime<Utc>,
    history_basis_seals: &[String],
    scope_circle_id: Option<&str>,
    history_visibility: &str,
    history_policy: Option<&HistorySharingPolicyPayloadValue>,
) -> bool {
    if sender == session.actor {
        return true;
    }
    if !projection_realm_history_allows(
        state,
        projection,
        realm_id,
        &session.actor,
        history_basis_seals,
        scope_circle_id,
        history_visibility,
        history_policy,
    ) {
        return false;
    }
    scope_circle_id.is_none_or(|circle_id| {
        projection.circle_scope_visible_to_actor_at(circle_id, &session.actor, created_at)
    })
}

fn projection_realm_history_allows(
    state: &AppState,
    projection: &ProjectionState,
    realm_id: &str,
    actor: &str,
    history_basis_seals: &[String],
    scope_circle_id: Option<&str>,
    history_visibility: &str,
    history_policy: Option<&HistorySharingPolicyPayloadValue>,
) -> bool {
    let Ok(visibility) = history_visibility.parse::<HistoryVisibility>() else {
        return false;
    };
    let member_state_at_t0 =
        member_state_at_history_basis(state, realm_id, actor, history_basis_seals);
    let event_state = history_reader_event_state(member_state_at_t0.as_deref());
    let reader = HistoryReaderContext {
        current_active_member: projection
            .member(realm_id, actor)
            .is_some_and(|member| member.state == "join"),
        event_state,
        has_discoverability: true,
        has_preview_token: false,
    };
    let range = HistoryRangeContext::from_membership(
        matches!(
            event_state,
            HistoryReaderEventState::Invited | HistoryReaderEventState::Joined
        ),
        event_state == HistoryReaderEventState::Joined,
    );
    if visibility != HistoryVisibility::Restricted {
        return event_time_history_visible(visibility, reader, range, history_policy).allowed;
    }
    let Some(policy) = history_policy else {
        return false;
    };
    let Some(receiver_class) = reader.receiver_class() else {
        return false;
    };
    let scope = HistorySharingRestrictedScopeRef {
        kind: if scope_circle_id.is_some() {
            HistorySharingScopeKind::Circle
        } else {
            HistorySharingScopeKind::Realm
        },
        circle_id: scope_circle_id,
    };
    !matching_restricted_rules(
        policy,
        receiver_class,
        visibility,
        range,
        None,
        Some(&scope),
    )
    .is_empty()
}

fn history_reader_event_state(member_state: Option<&str>) -> HistoryReaderEventState {
    match member_state {
        Some("invite") => HistoryReaderEventState::Invited,
        Some("join") => HistoryReaderEventState::Joined,
        Some("leave" | "ban" | "remove" | "revoked" | "rejected" | "expired") => {
            HistoryReaderEventState::Removed
        }
        _ => HistoryReaderEventState::None,
    }
}

fn member_state_at_history_basis(
    state: &AppState,
    realm_id: &str,
    actor: &str,
    history_basis_seals: &[String],
) -> Option<String> {
    if history_basis_seals.is_empty() {
        return None;
    }
    let realm = RealmId::new(realm_id.to_owned()).ok()?;
    let seals = history_basis_seals
        .iter()
        .filter_map(|seal| SealId::new(seal.clone()).ok())
        .collect::<Vec<_>>();
    if seals.is_empty() {
        return None;
    }
    let cell = CellRef::new(format!("ck:cell:ck.component.member.state.v1:{actor}")).ok()?;
    let state_at_basis = cokret_sdk::state_res::effective_state_at(
        &seals,
        &realm,
        state.seal_store.as_ref(),
        state.cell_store.as_ref(),
        state.cell_registry.as_ref(),
    )
    .ok()?;
    match state_at_basis.get(&cell) {
        Some(cokret_sdk::lattice::CellState::Value(Value::String(member_state))) => {
            Some(member_state.clone())
        }
        Some(cokret_sdk::lattice::CellState::Value(Value::Object(object))) => object
            .get("state")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        _ => None,
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

fn projection_state_unavailable() -> AppError {
    AppError::new(
        ErrorCode::TemporarilyUnavailable,
        "projection state unavailable",
    )
    .with_status(StatusCode::INTERNAL_SERVER_ERROR)
}

fn document_projection_document(morph: &MorphProjection, body: Value) -> Result<Value, AppError> {
    parse_projection_id::<MorphId>(&morph.morph_id, "document.morph_id")?;
    parse_projection_id::<RealmId>(&morph.realm_id, "document.realm_id")?;
    parse_projection_id::<Did>(&morph.created_by, "document.created_by")?;
    if let Some(updated_by) = morph.updated_by.as_deref() {
        parse_projection_id::<Did>(updated_by, "document.updated_by")?;
    }

    let mut document = serde_json::Map::new();
    document.insert("morph_id".to_owned(), Value::String(morph.morph_id.clone()));
    document.insert("realm_id".to_owned(), Value::String(morph.realm_id.clone()));
    document.insert(
        "morph_type".to_owned(),
        Value::String(morph.morph_type.clone()),
    );
    if let Some(title) = &morph.title {
        document.insert("title".to_owned(), Value::String(title.clone()));
    }
    document.insert(
        "state".to_owned(),
        json!(projection_object_state(morph.state)),
    );
    if let Some(state_changed_at) = morph.state_changed_at {
        document.insert("state_changed_at".to_owned(), json!(state_changed_at));
    }
    document.insert("fields".to_owned(), json!(morph.fields));
    document.insert("body".to_owned(), body);
    document.insert("schema_refs".to_owned(), json!(morph.schema_refs));
    document.insert("facets".to_owned(), json!(morph.facets));
    document.insert(
        "created_by".to_owned(),
        Value::String(morph.created_by.clone()),
    );
    document.insert("created_at".to_owned(), json!(morph.created_at));
    if let Some(updated_by) = &morph.updated_by {
        document.insert("updated_by".to_owned(), Value::String(updated_by.clone()));
    }
    if let Some(updated_at) = morph.updated_at {
        document.insert("updated_at".to_owned(), json!(updated_at));
    }
    Ok(Value::Object(document))
}

fn document_projection_versions(morph: &MorphProjection) -> Vec<Value> {
    morph
        .versions
        .iter()
        .map(|version| {
            let author = if version.author.trim().is_empty() {
                morph.created_by.as_str()
            } else {
                version.author.as_str()
            };
            json!({
                "version_id": version.version_id,
                "event_id": version.event_id,
                "author": author,
                "created_at": version.created_at,
                "body_digest": version.body_digest,
                "body": version.body,
            })
        })
        .collect()
}

fn document_relation_visible_to_session(
    projection: &ProjectionState,
    relation: &SolandRelationState,
    session: &SessionRecord,
) -> bool {
    relation.scope_circle_id.as_deref().is_none_or(|circle_id| {
        projection.circle_scope_visible_to_actor_at(circle_id, &session.actor, relation.created_at)
    })
}

fn document_projection_relations(
    projection: &ProjectionState,
    morph_id: &str,
    realm_id: &str,
    session: &SessionRecord,
) -> Result<Vec<Value>, AppError> {
    let mut relations = projection
        .relations
        .values()
        .filter(|relation| relation.realm_id == realm_id)
        .filter(|relation| relation.is_active())
        .filter(|relation| {
            relation.from_ref.as_deref() == Some(morph_id)
                || relation.to_ref.as_deref() == Some(morph_id)
        })
        .filter(|relation| document_relation_visible_to_session(projection, relation, session))
        .map(|relation| {
            parse_projection_id::<RelationId>(&relation.relation_id, "relations.relation_id")?;
            Ok((
                relation.relation_kind.clone(),
                relation.relation_id.clone(),
                json!({
                    "relation_id": relation.relation_id,
                    "relation_kind": relation.relation_kind,
                    "from": relation.from_ref.clone().unwrap_or_default(),
                    "to": relation.to_ref.clone().unwrap_or_default(),
                    "fields": relation.fields,
                    "state": relation.state,
                    "created_at": relation.created_at,
                    "updated_at": relation.updated_at,
                }),
            ))
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    relations.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    Ok(relations
        .into_iter()
        .map(|(_, _, relation)| relation)
        .collect())
}

fn document_comment_anchor(content: &Value, morph_id: &str) -> Option<Value> {
    let anchor = content.get("anchor_range")?;
    (anchor.get("target_ref").and_then(Value::as_str) == Some(morph_id)).then(|| anchor.clone())
}

fn document_comment_body(content: &Value) -> Option<String> {
    content
        .get("body")
        .or_else(|| content.get("text"))
        .or_else(|| content.get("label"))
        .and_then(Value::as_str)
        .or_else(|| content.as_str())
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

fn document_body_text_len(body: &Value) -> usize {
    if let Some(text) = body.as_str() {
        return text.chars().count();
    }
    if let Some(blocks) = body.get("blocks").and_then(Value::as_array) {
        return blocks
            .iter()
            .filter_map(|block| {
                block
                    .get("content")
                    .or_else(|| block.get("text"))
                    .or_else(|| block.get("body"))
                    .and_then(Value::as_str)
            })
            .map(|text| text.chars().count())
            .sum();
    }
    body.get("content")
        .or_else(|| body.get("text"))
        .or_else(|| body.get("body"))
        .and_then(Value::as_str)
        .map(|text| text.chars().count())
        .unwrap_or_default()
}

fn document_comment_state(anchor_range: &Value, body: &Value) -> String {
    let Some(end) = anchor_range.get("end").and_then(Value::as_u64) else {
        return "active".to_owned();
    };
    let Ok(end) = usize::try_from(end) else {
        return "orphaned".to_owned();
    };
    if end > document_body_text_len(body) {
        "orphaned".to_owned()
    } else {
        "active".to_owned()
    }
}

fn message_scope_circle_id(message: &MessageState) -> Option<&str> {
    message
        .content
        .get("scope_circle_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn document_projection_comments(
    state: &AppState,
    projection: &ProjectionState,
    morph: &MorphProjection,
    body: &Value,
    session: &SessionRecord,
    history_visibility: &str,
    history_policy: Option<&HistorySharingPolicyPayloadValue>,
) -> Vec<Value> {
    let mut comments = projection
        .messages
        .values()
        .filter(|message| message.realm_id == morph.realm_id)
        .filter(|message| !projection.redactions.contains(&message.event_id))
        .filter_map(|message| {
            let anchor_range = document_comment_anchor(&message.content, &morph.morph_id)?;
            let body_text = document_comment_body(&message.content)?;
            Some((message, anchor_range, body_text))
        })
        .filter(|(message, ..)| {
            projection_row_visible_to_session(
                state,
                projection,
                &morph.realm_id,
                session,
                &message.sender,
                message.created_at,
                &message.history_basis_seals,
                message_scope_circle_id(message),
                history_visibility,
                history_policy,
            )
        })
        .map(|(message, anchor_range, body_text)| {
            let actor_id = if message.sender.trim().is_empty() {
                morph.created_by.as_str()
            } else {
                message.sender.as_str()
            };
            (
                message.created_at,
                message.event_id.clone(),
                json!({
                    "event_id": message.event_id,
                    "actor_id": actor_id,
                    "created_at": message.created_at,
                    "body": body_text,
                    "anchor_range": anchor_range,
                    "state": document_comment_state(&anchor_range, body),
                    "content": message.content,
                }),
            )
        })
        .collect::<Vec<_>>();
    comments.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    comments
        .into_iter()
        .map(|(_, _, comment)| comment)
        .collect()
}

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
    let history_policy = realm_history_sharing_policy(state, &realm_id).await;
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
                state,
                &proj,
                &realm_id,
                &session,
                &p.created_by,
                p.created_at,
                &p.history_basis_seals,
                p.scope_circle_id.as_deref(),
                &history_visibility,
                history_policy.as_ref(),
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
    let history_policy = realm_history_sharing_policy(state, &realm_id).await;
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
                state,
                &proj,
                &realm_id,
                &session,
                &f.created_by,
                f.created_at,
                &f.history_basis_seals,
                f.scope_circle_id.as_deref(),
                &history_visibility,
                history_policy.as_ref(),
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
    operation_id = "ck.self.projection.document.resource.get",
    tags("projection"),
    summary = "Get a derived document Morph projection"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.projection.document.resource.get"))]
async fn get_document_projection(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    morph_id: PathParam<String>,
) -> JsonResult<DocumentMorphProjectionOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let morph_id = morph_id.into_inner();
    MorphId::new(morph_id.clone())
        .map_err(|_| AppError::invalid_param("invalid morph_id format"))?;
    let realm_id = {
        let proj = state
            .projection
            .lock()
            .map_err(|_| projection_state_unavailable())?;
        let Some(morph) = proj.morphs.get(&morph_id) else {
            return Err(AppError::not_found("document Morph not found"));
        };
        morph.realm_id.clone()
    };
    if !realm_id_accessible(state, &realm_id, Some(&session)).await {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "Document not visible to this actor",
        )
        .with_status(StatusCode::FORBIDDEN));
    }
    let history_visibility = realm_history_visibility(state, &realm_id).await;
    let history_policy = realm_history_sharing_policy(state, &realm_id).await;
    let proj = state
        .projection
        .lock()
        .map_err(|_| projection_state_unavailable())?;
    let Some(morph) = proj.morphs.get(&morph_id) else {
        return Err(AppError::not_found("document Morph not found"));
    };
    if morph.morph_type != "document" {
        return Err(AppError::not_found("document Morph not found"));
    }
    if !projection_row_visible_to_session(
        state,
        &proj,
        &realm_id,
        &session,
        &morph.created_by,
        morph.created_at,
        &morph.history_basis_seals,
        morph.scope_circle_id.as_deref(),
        &history_visibility,
        history_policy.as_ref(),
    ) {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "Document not visible to this actor",
        )
        .with_status(StatusCode::FORBIDDEN));
    }
    let body = morph_document_body(&morph.fields).unwrap_or(Value::Null);
    let document = document_projection_document(morph, body.clone())?;
    let versions = document_projection_versions(morph);
    let relations = document_projection_relations(&proj, &morph_id, &realm_id, &session)?;
    let comments = document_projection_comments(
        state,
        &proj,
        morph,
        &body,
        &session,
        &history_visibility,
        history_policy.as_ref(),
    );
    drop(proj);
    json_ok(DocumentMorphProjectionOutcome {
        document,
        versions,
        relations,
        comments,
        cursor_presence: Vec::new(),
        frontier: None,
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
    let history_policy = realm_history_sharing_policy(state, &realm_id).await;
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
                state,
                &proj,
                &realm_id,
                &session,
                &m.created_by,
                m.created_at,
                &m.history_basis_seals,
                m.scope_circle_id.as_deref(),
                &history_visibility,
                history_policy.as_ref(),
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
