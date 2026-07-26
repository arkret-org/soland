//! Read-side HTTP handlers for the server-side Space-container / Strand / Morph
//! lifecycle projection state maintained by `reducer::ProjectionState`.
//!
//! These endpoints let inkson (and other clients) re-hydrate the
//! optimistic Archive / Restore state after a page refresh, so a
//! `ak.space.archive` accepted by the server doesn't appear "unarchived"
//! again when the kanban view re-mounts.
//!
//! - `GET /_arkret/self/realms/{realm_id}/spaces` — canonical projection endpoint listing Space
//!   containers in a Realm scope, with `state` ∈ {active, archived, tombstoned} (spec
//!   `common-fields.md §5.1`).
//! - `GET /_arkret/self/realms/{realm_id}/strands` — same for Strands (state ∈ {active, archived,
//!   redacted}).
//! - `GET /_arkret/self/realms/{realm_id}/morphs` — same for Morphs (same enum as Strands).
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

use std::collections::BTreeMap;

use arkret_identifiers::{CellRef, Did, MorphId, RealmId, RelationId, SealId, SpaceId, StrandId};
use arkret_models_collaboration::events_payloads::HistorySharingPolicyPayloadValue;
use arkret_models_collaboration::governance::history_visibility::{
    HistoryRangeContext, HistoryReaderContext, HistoryReaderEventState,
    HistorySharingRestrictedScopeRef, HistorySharingScopeKind,
};
use arkret_models_collaboration::http_bodies::{
    ProjectionAssignedToRelation, ProjectionMorphList, ProjectionMorphRow, ProjectionObjectState,
    ProjectionSpaceList, ProjectionSpaceRow, ProjectionSpaceState, ProjectionStrandList,
    ProjectionStrandRow,
};
use arkret_models_collaboration::objects::query_projection::{
    DocumentMorphProjectionOutcome, ReferenceProjectionState,
};
use arkret_policy::history_visibility::{event_time_history_visible, matching_restricted_rules};
use arkret_wire::HistoryVisibility;
use chrono::{DateTime, Utc};
use salvo::http::StatusCode;
use salvo::oapi::extract::{PathParam, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_http::error::{AppError, ErrorCode};
use soland_http::result::{JsonResult, json_ok};
use soland_services::identity::SessionIdentityState as SessionRecord;
use soland_services::projection::{
    MessageReadModel as MessageState, MorphReadModel as MorphProjection,
    ObjectLifecycle as ObjectLifecycleState, ProjectionSnapshot as ProjectionState,
    RelationReadModel as SolandRelationState,
    SpaceContainerLifecycle as SpaceContainerLifecycleState, morph_document_body,
};

use super::{realm_history_visibility, realm_id_accessible};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;

pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(Router::with_path("realms/{realm_id}/spaces").get(list_space_container_projections))
        .push(Router::with_path("realms/{realm_id}/strands").get(list_strand_projections))
        .push(Router::with_path("realms/{realm_id}/morphs").get(list_morph_projections))
        .push(Router::with_path("realms/{realm_id}/morphs/{morph_id}").get(get_document_projection))
}

/// Product-private read surface (`/_soland/self/*`). These are
/// implementation-private projection reads that are NOT canonical protocol
/// operations: per `service-http-binding.md` §2.1.3, relation / view / object
/// direct reads that go beyond the declared `/_arkret/self/realms/...` read
/// binding live on the implementation's own negative-space root. They expose
/// already-projected reducer state (single Strand object fields, the relation
/// edge list) so cotest can assert invariants the canonical list endpoints do
/// not surface (raw `fields`, per-(from_ref, relation_kind) active edge sets).
pub(super) fn local_router() -> Router {
    Router::new()
        .push(Router::with_path("strands/{strand_id}").get(get_strand_projection))
        .push(Router::with_path("relations").get(list_relation_projections))
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
        .realms()
        .realm_metadata(realm_id)
        .await
        .ok()
        .flatten()?
        .history_sharing_policy?;
    let policy = serde_json::from_value::<HistorySharingPolicyPayloadValue>(policy_value).ok()?;
    arkret_policy::history_visibility::validate_history_sharing_policy(&policy).ok()?;
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
    let cell = CellRef::new(format!("ak:cell:ak.component.member.state.v1:{actor}")).ok()?;
    let state_at_basis = state
        .projections()
        .effective_state_at(&seals, &realm)
        .ok()?;
    match state_at_basis.get(&cell) {
        Some(arkret_state::lattice::CellState::Value(Value::String(member_state))) => {
            Some(member_state.clone())
        }
        Some(arkret_state::lattice::CellState::Value(Value::Object(object))) => object
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

fn document_projection_document(
    morph: &MorphProjection,
    body: Value,
) -> Result<arkret_models_collaboration::objects::query_projection::DocumentMorphProjection, AppError>
{
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
        "morph_kind".to_owned(),
        Value::String(morph.morph_kind.clone()),
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
    serde_json::from_value(Value::Object(document))
        .map_err(|error| AppError::internal(format!("invalid document projection: {error}")))
}

fn document_projection_versions(morph: &MorphProjection) -> Vec<BTreeMap<String, Value>> {
    morph
        .versions
        .iter()
        .map(|version| {
            let author = if version.author.trim().is_empty() {
                morph.created_by.as_str()
            } else {
                version.author.as_str()
            };
            json_object(json!({
                "version_id": version.version_id,
                "event_id": version.event_id,
                "author": author,
                "created_at": version.created_at,
                "body_digest": version.body_digest,
                "body": version.body,
            }))
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

#[derive(Clone, Debug)]
struct DocumentRelationSnapshot {
    relation: SolandRelationState,
    anchor_ref: String,
    direction: &'static str,
    target_home_realm_id: Option<String>,
    target_row_visibility: Option<TargetRowVisibilitySnapshot>,
    target_projection_visible: bool,
    target_requires_projection: bool,
}

#[derive(Clone, Debug)]
struct TargetRowVisibilitySnapshot {
    sender: String,
    created_at: DateTime<Utc>,
    history_basis_seals: Vec<String>,
    scope_circle_id: Option<String>,
}

fn projection_ref_requires_lookup(ref_id: &str) -> bool {
    ref_id.starts_with("ak:realm:")
        || ref_id.starts_with("ak:space:")
        || ref_id.starts_with("ak:strand:")
        || ref_id.starts_with("ak:morph:")
        || ref_id.starts_with("ak:relation:")
        || ref_id.starts_with("ak:event:")
        || ref_id.starts_with("ak:message:")
}

fn message_event_id_from_projection_ref(ref_id: &str) -> String {
    ref_id
        .strip_prefix("ak:message:")
        .map(|suffix| format!("ak:event:{suffix}"))
        .unwrap_or_else(|| ref_id.to_owned())
}

fn target_info_for_relation_ref(
    projection: &ProjectionState,
    target_ref: Option<&str>,
    session: &SessionRecord,
) -> (
    Option<String>,
    bool,
    bool,
    Option<TargetRowVisibilitySnapshot>,
) {
    let Some(target_ref) = target_ref else {
        return (None, true, false, None);
    };
    if target_ref.starts_with("ak:realm:") {
        return (Some(target_ref.to_owned()), true, true, None);
    }
    if let Some(space) = projection.space_containers.get(target_ref) {
        return (
            Some(space.realm_id.clone()),
            space.state != SpaceContainerLifecycleState::Tombstoned
                && space.scope_circle_id.as_deref().is_none_or(|circle_id| {
                    projection.circle_scope_visible_to_actor_at(
                        circle_id,
                        &session.actor,
                        space.created_at,
                    )
                }),
            true,
            Some(TargetRowVisibilitySnapshot {
                sender: space.created_by.clone(),
                created_at: space.created_at,
                history_basis_seals: space.history_basis_seals.clone(),
                scope_circle_id: space.scope_circle_id.clone(),
            }),
        );
    }
    if let Some(strand) = projection.strands.get(target_ref) {
        return (
            Some(strand.realm_id.clone()),
            !strand.state.is_terminal()
                && strand.scope_circle_id.as_deref().is_none_or(|circle_id| {
                    projection.circle_scope_visible_to_actor_at(
                        circle_id,
                        &session.actor,
                        strand.created_at,
                    )
                }),
            true,
            Some(TargetRowVisibilitySnapshot {
                sender: strand.created_by.clone(),
                created_at: strand.created_at,
                history_basis_seals: strand.history_basis_seals.clone(),
                scope_circle_id: strand.scope_circle_id.clone(),
            }),
        );
    }
    if let Some(morph) = projection.morphs.get(target_ref) {
        return (
            Some(morph.realm_id.clone()),
            !morph.state.is_terminal()
                && morph.scope_circle_id.as_deref().is_none_or(|circle_id| {
                    projection.circle_scope_visible_to_actor_at(
                        circle_id,
                        &session.actor,
                        morph.created_at,
                    )
                }),
            true,
            Some(TargetRowVisibilitySnapshot {
                sender: morph.created_by.clone(),
                created_at: morph.created_at,
                history_basis_seals: morph.history_basis_seals.clone(),
                scope_circle_id: morph.scope_circle_id.clone(),
            }),
        );
    }
    if let Some(relation) = projection.relations.get(target_ref) {
        return (
            Some(relation.realm_id.clone()),
            relation.is_active()
                && document_relation_visible_to_session(projection, relation, session),
            true,
            None,
        );
    }
    if target_ref.starts_with("ak:event:") || target_ref.starts_with("ak:message:") {
        let event_id = message_event_id_from_projection_ref(target_ref);
        if let Some(message) = projection
            .messages
            .get(target_ref)
            .or_else(|| projection.messages.get(&event_id))
        {
            return (
                Some(message.realm_id.clone()),
                !projection.redactions.contains(&message.event_id)
                    && message_scope_circle_id(message).is_none_or(|circle_id| {
                        projection.circle_scope_visible_to_actor_at(
                            circle_id,
                            &session.actor,
                            message.created_at,
                        )
                    }),
                true,
                Some(TargetRowVisibilitySnapshot {
                    sender: message.sender.clone(),
                    created_at: message.created_at,
                    history_basis_seals: message.history_basis_seals.clone(),
                    scope_circle_id: message_scope_circle_id(message).map(ToOwned::to_owned),
                }),
            );
        }
        return (None, false, true, None);
    }
    (None, true, projection_ref_requires_lookup(target_ref), None)
}

fn document_relation_snapshot(
    projection: &ProjectionState,
    relation: &SolandRelationState,
    morph_id: &str,
    session: &SessionRecord,
) -> DocumentRelationSnapshot {
    let (target_ref, direction) = if relation.from_ref.as_deref() == Some(morph_id) {
        (relation.to_ref.clone(), "outgoing")
    } else {
        (relation.from_ref.clone(), "incoming")
    };
    let (
        target_home_realm_id,
        target_projection_visible,
        target_requires_projection,
        target_row_visibility,
    ) = target_info_for_relation_ref(projection, target_ref.as_deref(), session);
    DocumentRelationSnapshot {
        relation: relation.clone(),
        anchor_ref: morph_id.to_owned(),
        direction,
        target_home_realm_id,
        target_row_visibility,
        target_projection_visible,
        target_requires_projection,
    }
}

async fn document_relation_reference_status(
    state: &AppState,
    snapshot: &DocumentRelationSnapshot,
    realm_id: &str,
    session: &SessionRecord,
) -> ReferenceProjectionState {
    if !snapshot.target_projection_visible {
        return ReferenceProjectionState::Locked;
    }
    let Some(target_home_realm_id) = snapshot.target_home_realm_id.as_deref() else {
        return if snapshot.target_requires_projection {
            ReferenceProjectionState::Locked
        } else {
            ReferenceProjectionState::Accessible
        };
    };
    if target_home_realm_id == realm_id {
        return if document_relation_target_row_visible(
            state,
            snapshot,
            target_home_realm_id,
            session,
        )
        .await
        {
            ReferenceProjectionState::Accessible
        } else {
            ReferenceProjectionState::Locked
        };
    }
    if realm_id_accessible(state, target_home_realm_id, Some(session)).await
        && document_relation_target_row_visible(state, snapshot, target_home_realm_id, session)
            .await
    {
        ReferenceProjectionState::LazyLink
    } else {
        ReferenceProjectionState::Locked
    }
}

async fn document_relation_target_row_visible(
    state: &AppState,
    snapshot: &DocumentRelationSnapshot,
    target_realm_id: &str,
    session: &SessionRecord,
) -> bool {
    let Some(row) = snapshot.target_row_visibility.as_ref() else {
        return true;
    };
    let history_visibility = realm_history_visibility(state, target_realm_id).await;
    let history_policy = realm_history_sharing_policy(state, target_realm_id).await;
    let projection = state.projections().snapshot();
    projection_row_visible_to_session(
        state,
        &projection,
        target_realm_id,
        session,
        &row.sender,
        row.created_at,
        &row.history_basis_seals,
        row.scope_circle_id.as_deref(),
        &history_visibility,
        history_policy.as_ref(),
    )
}

fn document_relation_reference_projection(
    status: ReferenceProjectionState,
    relation: &SolandRelationState,
) -> Value {
    let mut projection = serde_json::Map::new();
    projection.insert("status".to_owned(), json!(status));
    if matches!(status, ReferenceProjectionState::LazyLink)
        && let Some(source_event_digest) = relation.source_event_digest.as_deref()
    {
        projection.insert(
            "source_event_digest".to_owned(),
            Value::String(source_event_digest.to_owned()),
        );
    }
    Value::Object(projection)
}

fn document_relation_row(
    snapshot: &DocumentRelationSnapshot,
    status: ReferenceProjectionState,
) -> Result<Value, AppError> {
    parse_projection_id::<RelationId>(&snapshot.relation.relation_id, "relations.relation_id")?;
    let reference_projection = document_relation_reference_projection(status, &snapshot.relation);
    if status == ReferenceProjectionState::Accessible {
        return Ok(json!({
            "relation_id": snapshot.relation.relation_id.clone(),
            "relation_kind": snapshot.relation.relation_kind.clone(),
            "from": snapshot.relation.from_ref.clone().unwrap_or_default(),
            "to": snapshot.relation.to_ref.clone().unwrap_or_default(),
            "fields": snapshot.relation.fields.clone(),
            "state": snapshot.relation.state.clone(),
            "created_at": snapshot.relation.created_at,
            "updated_at": snapshot.relation.updated_at,
            "reference_projection": reference_projection,
        }));
    }
    let mut row = serde_json::Map::new();
    row.insert(
        "relation_id".to_owned(),
        Value::String(snapshot.relation.relation_id.clone()),
    );
    row.insert(
        "relation_kind".to_owned(),
        Value::String(snapshot.relation.relation_kind.clone()),
    );
    row.insert(
        "anchor_ref".to_owned(),
        Value::String(snapshot.anchor_ref.clone()),
    );
    row.insert(
        "direction".to_owned(),
        Value::String(snapshot.direction.to_owned()),
    );
    row.insert(
        "state".to_owned(),
        Value::String(snapshot.relation.state.clone()),
    );
    row.insert("reference_projection".to_owned(), reference_projection);
    match status {
        ReferenceProjectionState::LazyLink => {
            row.insert("lazy_link".to_owned(), Value::Bool(true));
            if let Some(source_event_id) = snapshot.relation.source_event_id.as_deref() {
                row.insert(
                    "source_event_id".to_owned(),
                    Value::String(source_event_id.to_owned()),
                );
            }
        }
        ReferenceProjectionState::Locked => {
            row.insert("locked".to_owned(), Value::Bool(true));
        }
        ReferenceProjectionState::Accessible => {}
    }
    Ok(Value::Object(row))
}

async fn document_projection_relations(
    state: &AppState,
    morph_id: &str,
    realm_id: &str,
    session: &SessionRecord,
) -> Result<Vec<BTreeMap<String, Value>>, AppError> {
    let snapshots = {
        let projection = state.projections().snapshot();
        projection
            .relations
            .values()
            .filter(|relation| relation.realm_id == realm_id)
            .filter(|relation| relation.is_active())
            .filter(|relation| {
                relation.from_ref.as_deref() == Some(morph_id)
                    || relation.to_ref.as_deref() == Some(morph_id)
            })
            .filter(|relation| document_relation_visible_to_session(&projection, relation, session))
            .map(|relation| {
                parse_projection_id::<RelationId>(&relation.relation_id, "relations.relation_id")?;
                Ok(document_relation_snapshot(
                    &projection,
                    relation,
                    morph_id,
                    session,
                ))
            })
            .collect::<Result<Vec<_>, AppError>>()?
    };
    let mut relations = Vec::with_capacity(snapshots.len());
    for snapshot in snapshots {
        let status = document_relation_reference_status(state, &snapshot, realm_id, session).await;
        relations.push((
            snapshot.relation.relation_kind.clone(),
            snapshot.relation.relation_id.clone(),
            document_relation_row(&snapshot, status)?,
        ));
    }
    relations.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    Ok(relations
        .into_iter()
        .map(|(_, _, relation)| json_object(relation))
        .collect())
}

fn json_object(value: Value) -> BTreeMap<String, Value> {
    value
        .as_object()
        .expect("projection row must be an object")
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
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
) -> Vec<BTreeMap<String, Value>> {
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
        .map(|(_, _, comment)| json_object(comment))
        .collect()
}

#[salvo::oapi::endpoint(operation_id = "ak.self.space.query.list", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.space.query.list"))]
async fn list_space_container_projections(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    include_terminal: QueryParam<bool, false>,
) -> JsonResult<ProjectionSpaceList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
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
    let proj = state.projections().snapshot();
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

#[salvo::oapi::endpoint(operation_id = "ak.self.strand.query.list", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.strand.query.list"))]
async fn list_strand_projections(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    include_terminal: QueryParam<bool, false>,
) -> JsonResult<ProjectionStrandList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
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
    let proj = state.projections().snapshot();
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
                updated_by: f
                    .updated_by
                    .as_deref()
                    .map(|actor| parse_projection_id::<Did>(actor, "updated_by"))
                    .transpose()?,
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

/// Strongly-typed response body for `org.arkret.soland.strands.get`
/// (`GET /_soland/self/strands/{strand_id}`). This is a soland product-private
/// projection read (`/_soland/self/*` negative-space root); the SDK does not —
/// and per `service-http-binding.md` §2.1.3 should not — define a response type
/// for it, so the DTO lives here next to its only handler. Field set and JSON
/// shape mirror the materialized `StrandProjection` row plus the derived
/// board/list position fields. `state` / `fields` keep `serde_json` free-form
/// types: `state` is a small projected enum already rendered as a string and
/// `fields` is an arbitrary materialized key/value map.
#[derive(Debug, serde::Serialize, salvo::oapi::ToSchema)]
struct StrandProjectionView {
    strand_id: String,
    realm_id: String,
    state: ProjectionObjectState,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp"
    )]
    state_changed_at: Option<DateTime<Utc>>,
    title: String,
    summary: Option<String>,
    fields: BTreeMap<String, Value>,
    board_space_id: Option<String>,
    list_space_id: Option<String>,
    rank: Option<String>,
    created_by: String,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    created_at: DateTime<Utc>,
    updated_by: Option<String>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp"
    )]
    updated_at: Option<DateTime<Utc>>,
}

/// One relation edge in the `org.arkret.soland.relations.list` response.
/// Mirrors the projected [`SolandRelationState`] fields surfaced by the
/// product-private `/_soland/self/relations` read. `fields` stays a free-form
/// `serde_json` map (arbitrary relation payload values).
#[derive(Debug, serde::Serialize, salvo::oapi::ToSchema)]
struct RelationEdgeView {
    relation_id: String,
    realm_id: String,
    relation_kind: String,
    from_ref: Option<String>,
    to_ref: Option<String>,
    fields: BTreeMap<String, Value>,
    state: String,
    scope_circle_id: Option<String>,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    created_at: DateTime<Utc>,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    updated_at: DateTime<Utc>,
}

/// Strongly-typed response body for `org.arkret.soland.relations.list`
/// (`GET /_soland/self/relations`). soland product-private projection read;
/// the DTO lives here for the same reason as [`StrandProjectionView`].
#[derive(Debug, serde::Serialize, salvo::oapi::ToSchema)]
struct RelationEdgeList {
    items: Vec<RelationEdgeView>,
    total: u64,
}

/// `GET /_soland/self/strands/{strand_id}` — return a single Strand's
/// projected object state including the raw `fields` map (e.g.
/// `fields.status`). The canonical `/_arkret/self/realms/{realm_id}/strands`
/// list intentionally does NOT surface arbitrary `fields`, so this
/// product-private read backs invariant assertions (CAS read-back,
/// patch-merge effects) that need the materialized field values. Visibility
/// reuses the same Realm history / Circle scope gate as the list endpoint.
#[salvo::oapi::endpoint(operation_id = "org.arkret.soland.strands.get", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.strands.get"))]
async fn get_strand_projection(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    strand_id: PathParam<String>,
) -> JsonResult<StrandProjectionView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let strand_id = strand_id.into_inner();
    StrandId::new(strand_id.clone())
        .map_err(|_| AppError::invalid_param("invalid strand_id format"))?;
    let realm_id = {
        let proj = state.projections().snapshot();
        let Some(strand) = proj.strands.get(&strand_id) else {
            return Err(AppError::not_found("strand not found"));
        };
        strand.realm_id.clone()
    };
    if !realm_id_accessible(state, &realm_id, Some(&session)).await {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "Strand not visible to this actor",
        )
        .with_status(StatusCode::FORBIDDEN));
    }
    let history_visibility = realm_history_visibility(state, &realm_id).await;
    let history_policy = realm_history_sharing_policy(state, &realm_id).await;
    let proj = state.projections().snapshot();
    let Some(strand) = proj.strands.get(&strand_id).cloned() else {
        return Err(AppError::not_found("strand not found"));
    };
    if !projection_row_visible_to_session(
        state,
        &proj,
        &realm_id,
        &session,
        &strand.created_by,
        strand.created_at,
        &strand.history_basis_seals,
        strand.scope_circle_id.as_deref(),
        &history_visibility,
        history_policy.as_ref(),
    ) {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "Strand not visible to this actor",
        )
        .with_status(StatusCode::FORBIDDEN));
    }
    let (board_space_id, list_space_id, rank) = strand_position_fields(&proj, &strand_id)?;
    drop(proj);
    json_ok(StrandProjectionView {
        strand_id: strand.strand_id,
        realm_id: strand.realm_id,
        state: projection_object_state(strand.state),
        state_changed_at: strand.state_changed_at,
        title: strand.title,
        summary: strand.summary,
        fields: strand.fields,
        board_space_id: board_space_id.map(|id| id.to_string()),
        list_space_id: list_space_id.map(|id| id.to_string()),
        rank,
        created_by: strand.created_by,
        created_at: strand.created_at,
        updated_by: strand.updated_by,
        updated_at: strand.updated_at,
    })
}

/// `GET /_soland/self/relations?from_ref=&to_ref=&relation_kind=&state=` —
/// list relation edges projected from `ak.relation.*` events. Backs the
/// relation-cardinality invariant checks (e.g. asserting at most one active
/// `has_default_view` edge per `from_ref`). Filters are AND-combined; `state`
/// defaults to `active`. Only edges whose `realm_id` is accessible to the
/// caller are returned, so non-members can't enumerate another Realm's graph.
#[salvo::oapi::endpoint(operation_id = "org.arkret.soland.relations.list", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.relations.list"))]
async fn list_relation_projections(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RelationEdgeList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let from_ref = soland_http::util::query_param(req, "from_ref");
    let to_ref = soland_http::util::query_param(req, "to_ref");
    let relation_kind = soland_http::util::query_param(req, "relation_kind");
    let state_filter =
        soland_http::util::query_param(req, "state").unwrap_or_else(|| "active".to_owned());

    let candidates: Vec<SolandRelationState> = {
        let proj = state.projections().snapshot();
        proj.relations
            .values()
            .filter(|relation| match state_filter.as_str() {
                "any" | "all" => true,
                other => relation.state == other,
            })
            .filter(|relation| {
                from_ref
                    .as_deref()
                    .is_none_or(|value| relation.from_ref.as_deref() == Some(value))
            })
            .filter(|relation| {
                to_ref
                    .as_deref()
                    .is_none_or(|value| relation.to_ref.as_deref() == Some(value))
            })
            .filter(|relation| {
                relation_kind
                    .as_deref()
                    .is_none_or(|value| relation.relation_kind == value)
            })
            .filter(|relation| {
                relation.scope_circle_id.as_deref().is_none_or(|circle_id| {
                    proj.circle_scope_visible_to_actor_at(
                        circle_id,
                        &session.actor,
                        relation.created_at,
                    )
                })
            })
            .cloned()
            .collect()
    };

    let mut items = Vec::new();
    for relation in candidates {
        if !realm_id_accessible(state, &relation.realm_id, Some(&session)).await {
            continue;
        }
        items.push(RelationEdgeView {
            relation_id: relation.relation_id,
            realm_id: relation.realm_id,
            relation_kind: relation.relation_kind,
            from_ref: relation.from_ref,
            to_ref: relation.to_ref,
            fields: relation.fields,
            state: relation.state,
            scope_circle_id: relation.scope_circle_id,
            created_at: relation.created_at,
            updated_at: relation.updated_at,
        });
    }
    items.sort_by(|left, right| left.relation_id.cmp(&right.relation_id));
    let total = total_count(items.len())?;
    json_ok(RelationEdgeList { items, total })
}

#[salvo::oapi::endpoint(operation_id = "ak.self.morph.resource.get", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.morph.resource.get"))]
async fn get_document_projection(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    morph_id: PathParam<String>,
) -> JsonResult<DocumentMorphProjectionOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = validate_realm_id(realm_id.into_inner())?;
    let morph_id = morph_id.into_inner();
    MorphId::new(morph_id.clone())
        .map_err(|_| AppError::invalid_param("invalid morph_id format"))?;
    {
        let proj = state.projections().snapshot();
        let Some(morph) = proj.morphs.get(&morph_id) else {
            return Err(AppError::not_found("document Morph not found"));
        };
        if morph.realm_id != realm_id {
            return Err(AppError::not_found("document Morph not found"));
        }
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
    let (document, versions, comments) = {
        let proj = state.projections().snapshot();
        let Some(morph) = proj.morphs.get(&morph_id).cloned() else {
            return Err(AppError::not_found("document Morph not found"));
        };
        if morph.morph_kind != "document" {
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
        let document = document_projection_document(&morph, body.clone())?;
        let versions = document_projection_versions(&morph);
        let comments = document_projection_comments(
            state,
            &proj,
            &morph,
            &body,
            &session,
            &history_visibility,
            history_policy.as_ref(),
        );
        (document, versions, comments)
    };
    let relations = document_projection_relations(state, &morph_id, &realm_id, &session).await?;
    json_ok(DocumentMorphProjectionOutcome {
        document,
        versions,
        relations,
        comments,
        cursor_presence: Vec::new(),
        frontier: None,
    })
}

#[salvo::oapi::endpoint(operation_id = "ak.self.morph.query.list", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.morph.query.list"))]
async fn list_morph_projections(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    include_terminal: QueryParam<bool, false>,
) -> JsonResult<ProjectionMorphList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
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
    let proj = state.projections().snapshot();
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
                morph_kind: m.morph_kind.clone(),
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
