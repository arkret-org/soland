//! Realm lifecycle read surface and Space-container cell read surface.
//!
//! Surfaces that remain:
//! - `GET    /_arkret/self/realms/{realm_id}` — read a Realm lifecycle response.
//! - `GET    /_arkret/self/realms/{realm_id}/export` — full event log + projection dump.
//! - `GET    /_soland/self/spaces/{space_id}/cells/{cell_family}` — projected Space-container
//!   child-order cell.
//!
//! Everything else in this module is the visibility / membership / typing
//! query helper surface that every other domain (federation, message, blob,
//! directory, mimi, …) calls into to resolve "is this actor allowed to see /
//! write in this Realm?".

use arkret_core::{
    Did, HistoryRangeContext, HistoryReaderContext, HistoryReaderEventState,
    HistorySharingPolicyPayloadValue, HistorySharingRestrictedScopeRef, HistorySharingScopeKind,
    HistoryVisibility, Operation, OperationId, PlaintextDataClassKind, RealmArchivePayload,
    RealmDestroyPayload, RealmFreezePayload, RealmId, RealmLifecycleView,
    RealmModerationPolicyReplaceRequestBody, RealmTombstonePayload, STRAND_TRACK_NAME_DISCUSSION,
    SpaceId, matching_restricted_rules,
};
use chrono::{DateTime, Utc};
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde::Serialize;
use serde_json::Value;
use soland_application::identity::SessionIdentityState as SessionRecord;
use soland_application::operation_semantics::CHILD_ORDER_CELL_FAMILY;
use soland_http::error::{AppError, ErrorCode};

use super::{AuthArgs, accept_local_operations};
use crate::routing::events::operations::operation_policy_reason_code;
use crate::routing::organizations;
use crate::state::{AppState, RealmDirectoryEntry};
use crate::wire::now;
use crate::{JsonResult, ids, json_ok};

/// Spec `realm_read` operation group (`ak.self.realm.*`): Realm lifecycle read,
/// full export, and Realm moderation-policy effective/set. Canonical path
/// `/_arkret/self/realms/{realm_id}*`.
pub(super) fn protocol_router() -> Router {
    Router::new().push(
        Router::with_path("realms/{realm_id}")
            .get(get_realm)
            .push(
                Router::with_path("moderation-policy/effective")
                    .get(get_realm_effective_moderation_policy),
            )
            .push(Router::with_path("moderation-policy").put(upsert_realm_moderation_policy))
            .push(Router::with_path("archive").post(archive_realm))
            .push(Router::with_path("freeze").post(freeze_realm))
            .push(Router::with_path("tombstone").post(tombstone_realm))
            .push(Router::with_path("destroy").post(destroy_realm))
            .push(Router::with_path("export").get(export_realm)),
    )
}

/// Soland-local Space-container child-order cell read surface
/// (`org.arkret.soland.spaces.cells.get`); no canonical operation, stays on the
/// `/_soland` product surface.
pub(super) fn local_router() -> Router {
    Router::new()
        .push(Router::with_path("spaces/{space_id}/cells/{cell_family}").get(get_space_cell))
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct SpaceCellOutcome {
    cell_id: String,
    cell_family: String,
    space_id: String,
    state: String,
    lattice: String,
    value: Value,
    total: usize,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct RealmExportEvent {
    event_id: String,
    realm_id: String,
    event_kind: String,
    operation_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sender: Option<String>,
    payload: Value,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct RealmExportOperation {
    operation_id: String,
    realm_id: String,
    object_type: String,
    operation_type: String,
    payload: Value,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct RealmExportOutcome {
    schema: String,
    realm_id: String,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    generated_at: DateTime<Utc>,
    operations: Vec<RealmExportOperation>,
    events: Vec<RealmExportEvent>,
}

#[endpoint(
    operation_id = "ak.self.realm.resource.get",
    tags("realms"),
    summary = "Get a Realm lifecycle response (owner + members)"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm.resource.get"))]
async fn get_realm(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<RealmLifecycleView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    realm_lifecycle_response(state, &realm_id)
        .await
        .map(salvo::prelude::Json)
}

fn operation_reject_to_app_error(reason: &'static str) -> AppError {
    let (status, wire_code) = operation_policy_reason_code(reason);
    let error = AppError::new(ErrorCode::FailedPrecondition, reason.to_owned())
        .with_status(status)
        .with_wire_code(wire_code);
    if reason == arkret_wire::ReasonCode::REQUIRES_ORGANIZATION_APPROVAL {
        error.with_reason_code(reason)
    } else if wire_code == "failed_precondition" && reason != wire_code {
        error.with_top_level_reason(reason)
    } else {
        error
    }
}

async fn submit_realm_lifecycle_command(
    state: &AppState,
    actor: &str,
    realm_id: String,
    kind: &'static str,
    payload: Value,
) -> Result<RealmLifecycleView, AppError> {
    let realm_scope = RealmId::new(realm_id.clone())
        .map_err(|e| AppError::invalid_param(format!("realm_id: {e}")))?;
    let op_id = OperationId::new(ids::generate_operation_id())
        .map_err(|e| AppError::invalid_param(format!("operation_id: {e}")))?;
    let operation = Operation::create(op_id, realm_scope, kind, payload);
    accept_local_operations(state, actor, std::slice::from_ref(&operation))
        .await
        .map_err(operation_reject_to_app_error)?;
    realm_lifecycle_response(state, &realm_id).await
}

#[endpoint(
    operation_id = "ak.self.realm.command.archive",
    tags("realms"),
    summary = "Set or clear the Realm archived facet"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm.command.archive"))]
async fn archive_realm(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    body: JsonBody<RealmArchivePayload>,
) -> JsonResult<RealmLifecycleView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let payload = body
        .into_inner()
        .to_value()
        .map_err(|error| AppError::invalid_param(format!("realm archive payload: {error}")))?;
    submit_realm_lifecycle_command(
        state,
        &session.actor,
        realm_id.into_inner(),
        arkret_wire::events::EventKind::REALM_ARCHIVE,
        payload,
    )
    .await
    .map(salvo::prelude::Json)
}

#[endpoint(
    operation_id = "ak.self.realm.command.freeze",
    tags("realms"),
    summary = "Set or clear the Realm frozen read-only facet"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm.command.freeze"))]
async fn freeze_realm(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    body: JsonBody<RealmFreezePayload>,
) -> JsonResult<RealmLifecycleView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let payload = body
        .into_inner()
        .to_value()
        .map_err(|error| AppError::invalid_param(format!("realm freeze payload: {error}")))?;
    submit_realm_lifecycle_command(
        state,
        &session.actor,
        realm_id.into_inner(),
        arkret_wire::events::EventKind::REALM_FREEZE,
        payload,
    )
    .await
    .map(salvo::prelude::Json)
}

#[endpoint(
    operation_id = "ak.self.realm.command.tombstone",
    tags("realms"),
    summary = "Terminally tombstone a Realm in favor of a successor Realm"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm.command.tombstone"))]
async fn tombstone_realm(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    body: JsonBody<RealmTombstonePayload>,
) -> JsonResult<RealmLifecycleView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let payload = body
        .into_inner()
        .to_value()
        .map_err(|error| AppError::invalid_param(format!("realm tombstone payload: {error}")))?;
    submit_realm_lifecycle_command(
        state,
        &session.actor,
        realm_id.into_inner(),
        arkret_wire::events::EventKind::REALM_TOMBSTONE,
        payload,
    )
    .await
    .map(salvo::prelude::Json)
}

#[endpoint(
    operation_id = "ak.self.realm.command.destroy",
    tags("realms"),
    summary = "Terminally destroy a Realm without a successor"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm.command.destroy"))]
async fn destroy_realm(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    body: JsonBody<RealmDestroyPayload>,
) -> JsonResult<RealmLifecycleView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let payload = body
        .into_inner()
        .to_value()
        .map_err(|error| AppError::invalid_param(format!("realm destroy payload: {error}")))?;
    submit_realm_lifecycle_command(
        state,
        &session.actor,
        realm_id.into_inner(),
        arkret_wire::events::EventKind::REALM_DESTROY,
        payload,
    )
    .await
    .map(salvo::prelude::Json)
}

#[endpoint(
    operation_id = "ak.self.realm.moderation_policy.query.effective",
    tags("realms", "policy"),
    summary = "Get organization-inherited effective moderation policy"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.self.realm.moderation_policy.query.effective")
)]
async fn get_realm_effective_moderation_policy(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<organizations::RealmEffectiveModerationPolicyOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    RealmId::new(realm_id.clone()).map_err(|_| AppError::invalid_param("invalid realm_id"))?;
    if !realm_id_accessible(state, &realm_id, Some(&session)).await {
        return Err(AppError::not_found("not found"));
    }
    organizations::refresh_organization_projection(state)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(organizations::effective_policy_for_realm(state, &realm_id))
}

#[endpoint(
    operation_id = "ak.self.realm.moderation_policy.resource.replace",
    tags("realms", "policy"),
    summary = "Set a Realm moderation-policy override"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.self.realm.moderation_policy.resource.replace")
)]
async fn upsert_realm_moderation_policy(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    body: JsonBody<RealmModerationPolicyReplaceRequestBody>,
) -> JsonResult<organizations::RealmModerationPolicyOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    RealmId::new(realm_id.clone()).map_err(|_| AppError::invalid_param("invalid realm_id"))?;
    let record = state
        .realm_query_application()
        .realm_metadata(&realm_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("not found"))?;
    if record.owner != session.actor {
        return Err(AppError::capability_denied("missing_capability"));
    }
    let payload = serde_json::to_value(body.into_inner().policy).map_err(|error| {
        AppError::internal(format!("realm moderation policy serialize: {error}"))
    })?;
    if organizations::realm_policy_override_requires_approval(state, &realm_id, &payload).await
        && !organizations::realm_policy_override_has_approval(state, &realm_id, &payload).await
    {
        return Err(organizations::requires_organization_approval_error());
    }
    let policy =
        organizations::persist_realm_moderation_policy(state, &realm_id, payload, &session.actor)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(organizations::realm_policy_record_outcome(&policy))
}

#[endpoint(
    operation_id = "org.arkret.soland.spaces.cells.get",
    tags("spaces", "cells"),
    summary = "Get a projected Space-container child-order cell"
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.spaces.cells.get"))]
async fn get_space_cell(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: PathParam<String>,
    cell_family: PathParam<String>,
) -> JsonResult<SpaceCellOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let space_id = space_id.into_inner();
    let cell_family = cell_family.into_inner();
    if cell_family != CHILD_ORDER_CELL_FAMILY {
        return Err(AppError::not_found("cell family not found"));
    }
    validate_child_order_subject(&space_id)?;

    // Snapshot everything we need out of the projection under a short lock so
    // we never hold the (non-Send) guard across the async access check.
    let (realm_id, value) = {
        let proj = state.projection_application().snapshot();
        let realm_id = proj
            .space_containers
            .get(&space_id)
            .map(|container| container.realm_id.clone())
            .unwrap_or_else(|| space_id.clone());
        let value = proj.child_order_cell_value(&space_id);
        (realm_id, value)
    };
    if !realm_id_accessible(state, &realm_id, Some(&session)).await {
        return Err(AppError::not_found("not found"));
    }
    let total = value
        .get("children")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or_default();

    json_ok(SpaceCellOutcome {
        cell_id: format!("ak:cell:{CHILD_ORDER_CELL_FAMILY}:{space_id}"),
        cell_family: CHILD_ORDER_CELL_FAMILY.to_owned(),
        space_id,
        state: "value".to_owned(),
        lattice: arkret_state::lattice::LatticeKind::OrderedLog
            .as_wire_str()
            .to_owned(),
        value,
        total,
    })
}

#[endpoint(
    operation_id = "ak.self.realm.query.export",
    tags("realms"),
    summary = "Full event log + projection dump for a Realm"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm.query.export"))]
async fn export_realm(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<RealmExportOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    RealmId::new(realm_id.clone()).map_err(|_| AppError::invalid_param("invalid realm_id"))?;
    if !realm_id_accessible(state, &realm_id, Some(&session)).await {
        return Err(AppError::not_found("not found"));
    }
    let events = state
        .event_query_application()
        .projected_events()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|event| event.realm_id == realm_id)
        .map(|event| RealmExportEvent {
            event_id: event.event_id,
            realm_id: event.realm_id,
            event_kind: event.event_kind,
            operation_type: event.operation_type,
            operation_id: event.operation_id,
            sender: event.sender,
            payload: event.payload,
            created_at: event.created_at,
        })
        .collect::<Vec<_>>();
    let operations = events
        .iter()
        .filter_map(|event| {
            event
                .operation_id
                .as_ref()
                .map(|operation_id| RealmExportOperation {
                    operation_id: operation_id.clone(),
                    realm_id: event.realm_id.clone(),
                    object_type: event.event_kind.clone(),
                    operation_type: event.operation_type.clone(),
                    payload: event.payload.clone(),
                    created_at: event.created_at,
                })
        })
        .collect::<Vec<_>>();
    json_ok(RealmExportOutcome {
        schema: "ak.export.realm.v1".to_owned(),
        realm_id,
        generated_at: now(),
        operations,
        events,
    })
}

fn validate_child_order_subject(space_id: &str) -> Result<(), AppError> {
    SpaceId::new(space_id.to_owned()).map_err(|_| AppError::invalid_param("invalid space_id"))?;
    Ok(())
}

// ── Helpers shared with the parent module ───────────────────────────────────
//
// Each is re-exported from `crate::routing::*` so sibling modules use the
// same Realm metadata and membership checks.

pub async fn realm_lifecycle_response(
    state: &AppState,
    realm_id: &str,
) -> Result<RealmLifecycleView, AppError> {
    let realm_id_value = RealmId::new(realm_id.to_owned())
        .map_err(|_| AppError::invalid_param("invalid realm_id"))?;
    // Snapshot the member list off the realms lock before the async meta read
    // (the guard is not Send and must not cross the `.await`).
    let members: Vec<Did> = {
        let realms = state.realm_directory_application().snapshot();
        realms
            .get(&realm_id_value)
            .map(|realm| realm.members.iter().cloned().collect())
            .unwrap_or_default()
    };
    let (archived, frozen, terminal_state, successor_realm_id, freeze_expires_at) = {
        let projection = state.projection_application().snapshot();
        projection
            .realm_states
            .get(realm_id)
            .map(|realm| {
                (
                    realm.archived,
                    projection.realm_is_frozen_at(realm_id, now()),
                    realm.terminal_state.clone(),
                    realm
                        .successor_realm_id
                        .as_ref()
                        .and_then(|id| RealmId::new(id.clone()).ok()),
                    realm.freeze_expires_at,
                )
            })
            .unwrap_or((false, false, None, None, None))
    };
    let record = state
        .realm_query_application()
        .realm_metadata(realm_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("not found"))?;
    let owner = Did::new(record.owner.clone()).map_err(|error| {
        AppError::internal(format!("stored realm owner DID is invalid: {error}"))
    })?;
    Ok(RealmLifecycleView {
        ok: true,
        realm_id: realm_id_value,
        owner,
        members,
        deleted: record.deleted,
        archived,
        frozen,
        terminal_state,
        successor_realm_id,
        freeze_expires_at,
    })
}

pub async fn touch_realm_meta(state: &AppState, realm_id: &str) {
    let service = state.realm_query_application();
    if let Ok(Some(mut record)) = service.realm_metadata(realm_id).await {
        record.updated_at = now();
        if let Err(error) = service.store_realm_metadata(realm_id, record).await {
            tracing::warn!(%error, "failed to touch realm meta");
        }
    }
}

// ── Visibility + membership + typing query helpers ─────────────────────────

pub fn realm_scope_to_realm_id(scope_id: &str) -> Option<String> {
    RealmId::new(scope_id.to_owned())
        .ok()
        .map(|realm_id| realm_id.as_str().to_owned())
}

pub async fn touch_realm(state: &AppState, realm_or_internal_id: &str) {
    if let Some(realm_id) = realm_scope_to_realm_id(realm_or_internal_id) {
        touch_realm_meta(state, &realm_id).await;
    }
}

pub async fn is_realm_deleted(state: &AppState, realm_or_internal_id: &str) -> bool {
    match realm_scope_to_realm_id(realm_or_internal_id) {
        Some(realm_id) => realm_meta_deleted(state, &realm_id).await,
        None => false,
    }
}

pub async fn realm_discoverability(state: &AppState, realm_or_internal_id: &str) -> String {
    match realm_scope_to_realm_id(realm_or_internal_id) {
        Some(realm_id) => realm_discoverability_for_id(state, &realm_id).await,
        None => "invite_only".to_owned(),
    }
}

pub async fn realm_has_member(state: &AppState, realm_or_internal_id: &str, actor: &str) -> bool {
    match realm_scope_to_realm_id(realm_or_internal_id) {
        Some(realm_id) => realm_has_member_by_id(state, &realm_id, actor).await,
        None => false,
    }
}

pub async fn realm_id_accessible(
    state: &AppState,
    realm_or_internal_id: &str,
    session: Option<&SessionRecord>,
) -> bool {
    match realm_scope_to_realm_id(realm_or_internal_id) {
        Some(realm_id) => realm_id_accessible_for_id(state, &realm_id, session).await,
        None => false,
    }
}

pub async fn realm_visible_to(
    state: &AppState,
    realm: &RealmDirectoryEntry,
    session: Option<&SessionRecord>,
) -> bool {
    realm_visible_to_for_entry(state, realm, session).await
}

pub async fn realm_history_visibility(state: &AppState, realm_or_internal_id: &str) -> String {
    match realm_scope_to_realm_id(realm_or_internal_id) {
        Some(realm_id) => realm_history_visibility_for_id(state, &realm_id).await,
        None => "joined".to_owned(),
    }
}

pub async fn realm_member_joined_at(
    state: &AppState,
    realm_or_internal_id: &str,
    actor: &str,
) -> Option<DateTime<Utc>> {
    match realm_scope_to_realm_id(realm_or_internal_id) {
        Some(realm_id) => realm_member_joined_at_for_id(state, &realm_id, actor).await,
        None => None,
    }
}

pub async fn realm_event_visible_to_session(
    state: &AppState,
    realm_or_internal_id: &str,
    event_created_at: DateTime<Utc>,
    sender: Option<&str>,
    session: Option<&SessionRecord>,
) -> bool {
    if sender.is_some_and(|sender| session.is_some_and(|session| session.actor == sender)) {
        return true;
    }
    match realm_history_visibility(state, realm_or_internal_id)
        .await
        .as_str()
    {
        "world_readable" => true,
        "shared" => match session {
            Some(session) => {
                realm_active_member_at_read_time(state, realm_or_internal_id, &session.actor).await
            }
            None => false,
        },
        "invited" => {
            let Some(session) = session else {
                return false;
            };
            realm_member_invited_or_joined_at(state, realm_or_internal_id, &session.actor)
                .await
                .is_some_and(|visible_at| event_created_at >= visible_at)
        }
        "joined" => {
            let Some(session) = session else {
                return false;
            };
            realm_member_joined_at(state, realm_or_internal_id, &session.actor)
                .await
                .is_some_and(|joined_at| event_created_at >= joined_at)
        }
        "restricted" => {
            let Some(session) = session else {
                return false;
            };
            realm_restricted_history_policy_allows(
                state,
                realm_or_internal_id,
                &session.actor,
                event_created_at,
            )
            .await
        }
        _ => false,
    }
}

pub async fn realm_allows_plaintext_service_for_data_class(
    state: &AppState,
    realm_or_internal_id: &str,
    data_class: PlaintextDataClassKind,
) -> bool {
    match realm_scope_to_realm_id(realm_or_internal_id) {
        Some(realm_id) => {
            realm_allows_plaintext_service_for_data_class_id(state, &realm_id, data_class).await
        }
        None => false,
    }
}

pub async fn realm_meta_deleted(state: &AppState, realm_id: &str) -> bool {
    state
        .realm_query_application()
        .realm_metadata(realm_id)
        .await
        .ok()
        .flatten()
        .is_some_and(|record| record.deleted)
}

pub async fn realm_discoverability_for_id(state: &AppState, realm_id: &str) -> String {
    state
        .realm_query_application()
        .realm_metadata(realm_id)
        .await
        .ok()
        .flatten()
        .map(|record| record.discoverability)
        .unwrap_or_else(|| {
            if directory_realm_is_public(state, realm_id) {
                "public".to_owned()
            } else {
                "invite_only".to_owned()
            }
        })
}

pub async fn realm_has_member_by_id(state: &AppState, realm_id: &str, actor: &str) -> bool {
    if realm_meta_deleted(state, realm_id).await {
        tracing::warn!(%realm_id, %actor, "realm_has_member_by_id: realm marked deleted");
        return false;
    }
    let Ok(realm_id_typed) = RealmId::new(realm_id.to_owned()) else {
        tracing::warn!(%realm_id, %actor, "realm_has_member_by_id: invalid realm_id shape");
        return false;
    };
    let Ok(actor_typed) = Did::new(actor.to_owned()) else {
        tracing::warn!(%realm_id, %actor, "realm_has_member_by_id: invalid actor DID shape");
        return false;
    };
    if realm_id == soland_application::identity::principal_control_realm_for_did(actor) {
        return true;
    }
    let realms = state.realm_directory_application().snapshot();
    match realms.get(&realm_id_typed) {
        None => {
            let known: Vec<String> = realms
                .search_by_text("")
                .into_iter()
                .map(|entry| entry.realm_id.as_str().to_owned())
                .collect();
            tracing::warn!(
                %realm_id,
                %actor,
                known_realms = ?known,
                "realm_has_member_by_id: realm not present in in-memory index"
            );
            false
        }
        Some(realm) => {
            if realm.members.contains(&actor_typed) {
                true
            } else {
                tracing::trace!(
                    %realm_id,
                    %actor,
                    "realm_has_member_by_id: actor not in realm members"
                );
                false
            }
        }
    }
}

pub async fn realm_visible_to_for_entry(
    state: &AppState,
    realm: &RealmDirectoryEntry,
    session: Option<&SessionRecord>,
) -> bool {
    if realm_meta_deleted(state, realm.realm_id.as_str()).await {
        return false;
    }
    if realm_discoverability_for_id(state, realm.realm_id.as_str()).await == "public" {
        return true;
    }
    session.is_some_and(|session| {
        Did::new(session.actor.clone()).is_ok_and(|actor| realm.members.contains(&actor))
    })
}

pub async fn realm_search_visible_to(
    state: &AppState,
    realm: &RealmDirectoryEntry,
    session: Option<&SessionRecord>,
) -> bool {
    if realm_meta_deleted(state, realm.realm_id.as_str()).await {
        return false;
    }
    if session.is_some_and(|session| {
        Did::new(session.actor.clone()).is_ok_and(|actor| realm.members.contains(&actor))
    }) {
        return true;
    }
    matches!(
        realm_discoverability_for_id(state, realm.realm_id.as_str())
            .await
            .as_str(),
        "public" | "listed" | "restricted"
    )
}

pub async fn realm_resolvable_to(
    state: &AppState,
    realm: &RealmDirectoryEntry,
    session: Option<&SessionRecord>,
    invite_token: Option<&str>,
    signed_link: Option<&str>,
) -> bool {
    if realm_meta_deleted(state, realm.realm_id.as_str()).await {
        return false;
    }
    if session.is_some_and(|session| {
        Did::new(session.actor.clone()).is_ok_and(|actor| realm.members.contains(&actor))
    }) {
        return true;
    }
    match realm_discoverability_for_id(state, realm.realm_id.as_str())
        .await
        .as_str()
    {
        "public" | "listed" | "restricted" | "unlisted" => true,
        "invite_only" => match invite_token {
            Some(token) => invite_token_matches_realm(state, realm.realm_id.as_str(), token).await,
            None => false,
        },
        "secret" => signed_link.is_some_and(|link| !link.trim().is_empty()),
        _ => false,
    }
}

pub async fn invite_token_matches_realm(state: &AppState, realm_id: &str, token: &str) -> bool {
    invite_token_realm_id(state, token)
        .await
        .is_some_and(|resolved_realm_id| resolved_realm_id == realm_id)
}

pub async fn invite_token_realm_id(state: &AppState, token: &str) -> Option<String> {
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    let now = now();
    state
        .realm_invite_application()
        .snapshot_all()
        .await
        .unwrap_or_default()
        .into_iter()
        .find(|invite| {
            invite.status == "pending"
                && invite.invite_token == token
                && invite.expires_at.is_none_or(|expires_at| expires_at > now)
        })
        .map(|invite| invite.realm_id)
}

// `realm_id_accessible_for_id` is the visibility path with looser semantics
// for the backfill / subscribe edge.

/// Check if a Realm is accessible for backfill/subscribe.
///
/// Read-side authorization rules:
/// 1. `discoverability=public` → anyone.
/// 2. `history_visibility=world_readable` → anyone (including anonymous / non-member registered
///    actors). For MLS-backed Realms this state is valid only when the effective content scheme is
///    history-capable.
/// 3. Otherwise → caller MUST be an authenticated member.
pub async fn realm_id_accessible_for_id(
    state: &AppState,
    realm_id: &str,
    session: Option<&SessionRecord>,
) -> bool {
    let Ok(realm_id_typed) = RealmId::new(realm_id.to_owned()) else {
        return false;
    };
    // Snapshot the membership/realm_id off the in-memory index before any
    // `.await` so we never hold the std::sync Mutex guard across a suspension.
    let (realm_id, members) = {
        let realms = state.realm_directory_application().snapshot();
        let Some(realm) = realms.get(&realm_id_typed) else {
            return false;
        };
        (realm.realm_id.as_str().to_owned(), realm.members.clone())
    };
    if realm_discoverability_for_id(state, &realm_id).await == "public" {
        return true;
    }
    if realm_history_visibility_for_id(state, &realm_id).await == "world_readable" {
        return true;
    }
    session.is_some_and(|session| {
        Did::new(session.actor.clone()).is_ok_and(|actor| members.contains(&actor))
    })
}

/// encryption-and-audit.md §2.10.8 — recovery-grade read gate.
///
/// ## Recovery read design decision (non-member organizational recovery)
///
/// §2.10.8 requires that the organization holding the RRK can retrieve the
/// Realm's RRK-targeted `ak.realm_key.share` ciphertext events "after all member
/// devices are lost or all members leave" — i.e. while it is NOT a member of the
/// Realm and may never have been. The spec leaves "how a non-member org is
/// authorized to read realm events" as an open surface. soland resolves it with
/// a **dedicated recovery-grade read scope** that does NOT widen ordinary member
/// gating:
///
/// - A session whose `actor` equals a current
///   `durability_policy.recovery_recipients[].principal_id` is granted realm *scan admission* (so
///   `events.query` does not `not_found` it), but
/// - the per-event recovery filter ([`realm_recovery_event_visible`]) restricts such a session to
///   ONLY `ak.realm_key.share` events whose `recipient_principal_id` is that same recovery
///   recipient. The recovery org never sees the general timeline, message bodies, membership, or
///   shares addressed to other recipients.
///
/// This keeps the recovery face minimal-disclosure: the recovery org reads
/// exactly the opaque (HPKE-sealed) ciphertext it is entitled to HPKE-open, and
/// nothing else. Ordinary `realm_id_accessible` membership semantics are
/// untouched.
///
/// Returns `true` iff `actor` is a current recovery recipient of `realm_id`.
pub async fn realm_recovery_recipient_principal(
    state: &AppState,
    realm_id: &str,
    actor: &str,
) -> bool {
    use arkret_models_collaboration::objects::realm::DurabilityMode;
    let Some(realm_id) = realm_scope_to_realm_id(realm_id) else {
        return false;
    };
    let durability = {
        let projection = state.projection_application().snapshot();
        projection.realm_durability_policy(&realm_id)
    };
    let Some(durability) = durability else {
        return false;
    };
    if matches!(durability.mode, DurabilityMode::None) {
        return false;
    }
    durability
        .recovery_recipients
        .iter()
        .any(|recipient| recipient.principal_id.as_str() == actor)
}

/// encryption-and-audit.md §2.10.8 — per-event recovery visibility. For a
/// recovery-recipient (non-member) session, an event is visible ONLY when it is
/// a `ak.realm_key.share` addressed to that recipient's `principal_id`. Used by
/// the `events.query` per-event filter to keep the recovery face narrow.
pub fn realm_recovery_event_visible(
    event_kind: &str,
    recipient_principal_id: Option<&str>,
    actor: &str,
) -> bool {
    event_kind == arkret_wire::events::EventKind::REALM_KEY_SHARE
        && recipient_principal_id == Some(actor)
}

/// Look up the persisted `history_visibility` for a Realm, defaulting to
/// `joined` when no meta record exists (matches the spec default).
pub async fn realm_history_visibility_for_id(state: &AppState, realm_id: &str) -> String {
    state
        .realm_query_application()
        .realm_metadata(realm_id)
        .await
        .ok()
        .flatten()
        .map(|record| record.history_visibility.clone())
        .unwrap_or_else(|| "joined".to_owned())
}

fn directory_realm_is_public(state: &AppState, realm_id: &str) -> bool {
    let Ok(realm_id) = RealmId::new(realm_id.to_owned()) else {
        return false;
    };
    state
        .realm_directory_application()
        .snapshot()
        .get(&realm_id)
        .is_some_and(|entry| entry.public)
}

/// Best-effort joined-at timestamp for event history filtering.
///
/// The reducer's member projection is authoritative when present. Bootstrap
/// owners predate that side-band cache, so only the owner falls back to the
/// Realm creation time. Non-owner members without joined_at are hidden by
/// `history_visibility=joined` instead of leaking pre-join history.
pub async fn realm_member_joined_at_for_id(
    state: &AppState,
    realm_id: &str,
    actor: &str,
) -> Option<DateTime<Utc>> {
    {
        let projection = state.projection_application().snapshot();
        if let Some(member) = projection.member(realm_id, actor)
            && member.state == "join"
        {
            return Some(member.joined_at);
        }
    }
    let meta = state
        .realm_query_application()
        .realm_metadata(realm_id)
        .await
        .ok()
        .flatten();
    if meta.as_ref().is_some_and(|record| record.owner == actor) {
        return meta.map(|record| record.created_at);
    }
    None
}

pub async fn realm_member_invited_or_joined_at(
    state: &AppState,
    realm_or_internal_id: &str,
    actor: &str,
) -> Option<DateTime<Utc>> {
    match realm_scope_to_realm_id(realm_or_internal_id) {
        Some(realm_id) => realm_member_invited_or_joined_at_for_id(state, &realm_id, actor).await,
        None => None,
    }
}

pub async fn realm_member_invited_or_joined_at_for_id(
    state: &AppState,
    realm_id: &str,
    actor: &str,
) -> Option<DateTime<Utc>> {
    {
        let projection = state.projection_application().snapshot();
        if let Some(member) = projection.member(realm_id, actor) {
            if let Some(invited_at) = member.invited_at {
                return Some(invited_at);
            }
            if matches!(member.state.as_str(), "invite" | "join") {
                return Some(member.updated_at);
            }
        }
    }
    realm_member_joined_at_for_id(state, realm_id, actor).await
}

async fn realm_active_member_at_read_time(
    state: &AppState,
    realm_or_internal_id: &str,
    actor: &str,
) -> bool {
    match realm_scope_to_realm_id(realm_or_internal_id) {
        Some(realm_id) => {
            {
                let projection = state.projection_application().snapshot();
                if let Some(member) = projection.member(&realm_id, actor) {
                    return member.state == "join";
                }
            }
            realm_has_member_by_id(state, &realm_id, actor).await
        }
        None => false,
    }
}

async fn realm_restricted_history_policy_allows(
    state: &AppState,
    realm_or_internal_id: &str,
    actor: &str,
    event_created_at: DateTime<Utc>,
) -> bool {
    let Some(realm_id) = realm_scope_to_realm_id(realm_or_internal_id) else {
        return false;
    };
    let Some(meta) = state
        .realm_query_application()
        .realm_metadata(&realm_id)
        .await
        .ok()
        .flatten()
    else {
        return false;
    };
    let Some(policy_value) = meta.history_sharing_policy else {
        return false;
    };
    let Ok(policy) = serde_json::from_value::<HistorySharingPolicyPayloadValue>(policy_value)
    else {
        return false;
    };
    if arkret_core::validate_history_sharing_policy(&policy).is_err() {
        return false;
    }
    let active_member = realm_active_member_at_read_time(state, &realm_id, actor).await;
    let joined_at = realm_member_joined_at_for_id(state, &realm_id, actor).await;
    let invited_at = realm_member_invited_or_joined_at_for_id(state, &realm_id, actor).await;
    let since_invite = invited_at.is_some_and(|at| event_created_at >= at);
    let since_join = joined_at.is_some_and(|at| event_created_at >= at);
    let event_state = if active_member && since_join {
        HistoryReaderEventState::Joined
    } else if active_member && since_invite {
        HistoryReaderEventState::Invited
    } else if !active_member && (since_invite || since_join) {
        HistoryReaderEventState::Removed
    } else {
        HistoryReaderEventState::None
    };
    let reader = HistoryReaderContext {
        current_active_member: active_member,
        event_state,
        has_discoverability: true,
        has_preview_token: false,
    };
    let Some(receiver_class) = reader.receiver_class() else {
        return false;
    };
    let range = HistoryRangeContext::from_membership(since_invite, since_join);
    let scope = HistorySharingRestrictedScopeRef {
        kind: HistorySharingScopeKind::Realm,
        circle_id: None,
    };
    !matching_restricted_rules(
        &policy,
        receiver_class,
        HistoryVisibility::Restricted,
        range,
        None,
        Some(&scope),
    )
    .is_empty()
}

pub async fn realm_allows_plaintext_service_for_data_class_id(
    state: &AppState,
    realm_id: &str,
    data_class: PlaintextDataClassKind,
) -> bool {
    let Ok(realm_id_typed) = RealmId::new(realm_id.to_owned()) else {
        return false;
    };
    let directory_realm_id = {
        let realms = state.realm_directory_application().snapshot();
        realms
            .get(&realm_id_typed)
            .map(|realm| realm.realm_id.as_str().to_owned())
    };
    if let Some(directory_realm_id) = directory_realm_id
        && realm_public_content_for_id(state, &directory_realm_id).await
    {
        return true;
    }
    state
        .realm_query_application()
        .realm_metadata(realm_id)
        .await
        .ok()
        .flatten()
        .is_some_and(|record| record.allows_plaintext_data_class(state.service_id(), data_class))
}

async fn realm_public_content_for_id(state: &AppState, realm_id: &str) -> bool {
    state
        .realm_query_application()
        .realm_metadata(realm_id)
        .await
        .ok()
        .flatten()
        .is_some_and(|record| {
            record.discoverability == "public" && record.history_visibility == "world_readable"
        })
}

/// Number of Realm members other than `exclude_actor`. Used to report the
/// realm-broadcast fan-out breadth for relayed `ak.call.signal` envelopes
/// (`webrtc-signaling.md` §5) without resolving the per-device recipient set.
pub fn realm_member_count_excluding(state: &AppState, realm_id: &str, exclude_actor: &str) -> u64 {
    let Ok(realm_id_value) = RealmId::new(realm_id.to_owned()) else {
        return 0;
    };
    let realms = state.realm_directory_application().snapshot();
    realms
        .get(&realm_id_value)
        .map(|realm| {
            realm
                .members
                .iter()
                .filter(|member| member.as_str() != exclude_actor)
                .count() as u64
        })
        .unwrap_or(0)
}

pub async fn prune_expired_typing(state: &AppState) {
    if let Err(error) = state.delivery_application().prune_expired_typing().await {
        tracing::warn!(%error, "failed to prune expired typing entries");
    }
}

const ACCOUNT_DATA_TYPE_PRESENCE_VISIBILITY: &str = "ak.presence.visibility";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PresenceVisibilityPolicy {
    Public,
    ContactsOnly,
    Nobody,
}

pub(crate) async fn presence_visibility_for_actor(
    state: &AppState,
    actor: &str,
) -> PresenceVisibilityPolicy {
    match state
        .account_data_application()
        .entry(actor, ACCOUNT_DATA_TYPE_PRESENCE_VISIBILITY)
        .await
    {
        Ok(None) => PresenceVisibilityPolicy::Public,
        Ok(Some(record)) => presence_visibility_from_payload(&record.payload)
            .unwrap_or(PresenceVisibilityPolicy::Nobody),
        Err(error) => {
            tracing::warn!(%error, actor = %actor, "failed to read presence visibility policy");
            PresenceVisibilityPolicy::Nobody
        }
    }
}

fn presence_visibility_from_payload(payload: &Value) -> Option<PresenceVisibilityPolicy> {
    let object = payload.as_object()?;
    if object.len() != 1 {
        return None;
    }
    match object
        .get("presence_visibility")
        .and_then(Value::as_str)
        .map(str::trim)
    {
        Some("public") => Some(PresenceVisibilityPolicy::Public),
        Some("contacts_only") => Some(PresenceVisibilityPolicy::ContactsOnly),
        Some("nobody") => Some(PresenceVisibilityPolicy::Nobody),
        _ => None,
    }
}

pub(crate) async fn presence_visible_to_session(
    state: &AppState,
    actor: &str,
    session: Option<&SessionRecord>,
) -> bool {
    let Some(session) = session else {
        return false;
    };
    match presence_visibility_for_actor(state, actor).await {
        PresenceVisibilityPolicy::Nobody => false,
        PresenceVisibilityPolicy::ContactsOnly => {
            personal_blocklist_allows_actor(state, session, actor).await
                && accepted_contact_between(state, &session.actor, actor).await
        }
        PresenceVisibilityPolicy::Public => {
            personal_blocklist_allows_actor(state, session, actor).await
        }
    }
}

async fn accepted_contact_between(state: &AppState, left: &str, right: &str) -> bool {
    if left == right {
        return true;
    }
    for (requester, target) in [(left, right), (right, left)] {
        match state
            .contact_application()
            .contact_any(requester, target)
            .await
        {
            Ok(Some(contact)) if contact.status == "accepted" => return true,
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    %error,
                    actor = %left,
                    peer = %right,
                    "failed to read contact relationship for presence policy"
                );
                return false;
            }
        }
    }
    false
}

pub async fn typing_scope_allows_actor(
    state: &AppState,
    realm_id: &str,
    actor: &str,
    strand_id: Option<&str>,
) -> Result<(), AppError> {
    let Some(strand_id) = strand_id.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    if strand_id.starts_with("ak:realm:") || strand_id == realm_id {
        return Err(AppError::capability_denied(
            "ak.typing strand_id must name a visible ak:strand",
        ));
    }
    if !strand_id.starts_with("ak:strand:") {
        return Err(AppError::invalid_param(
            "ak.typing strand_id must name a visible ak:strand",
        ));
    }
    let projection = state.projection_application().snapshot();
    let Some(strand) = projection.strands.get(strand_id) else {
        if strand_id == crate::routing::events::strand::strand_id_from_realm_id(realm_id) {
            return Ok(());
        }
        return Err(AppError::capability_denied(
            "ak.typing strand is not visible",
        ));
    };
    if strand.realm_id != realm_id {
        return Err(AppError::capability_denied(
            "ak.typing strand belongs to another realm",
        ));
    }
    if strand.state.as_str() != "active" {
        return Err(AppError::capability_denied(
            "ak.typing strand is not active",
        ));
    }
    let Some(discussion_track) = strand.tracks.get(STRAND_TRACK_NAME_DISCUSSION) else {
        return Err(AppError::capability_denied(
            "ak.typing discussion track is disabled",
        ));
    };
    if discussion_track.enabled == Some(false) {
        return Err(AppError::capability_denied(
            "ak.typing discussion track is disabled",
        ));
    }
    if let Some(scope_circle_id) = strand.scope_circle_id.as_deref()
        && !projection.circle_scope_visible_to_actor(scope_circle_id, actor)
    {
        return Err(AppError::capability_denied(
            "ak.typing circle is not visible",
        ));
    }
    Ok(())
}

const ACCOUNT_DATA_TYPE_BLOCKLIST: &str = "ak.account.blocklist";

async fn personal_blocklist_allows_actor(
    state: &AppState,
    session: &SessionRecord,
    sender: &str,
) -> bool {
    if sender == session.actor {
        return true;
    }
    match state
        .account_data_application()
        .entry(&session.actor, ACCOUNT_DATA_TYPE_BLOCKLIST)
        .await
    {
        Ok(None) => true,
        Ok(Some(record)) => !blocklist_payload_blocks_sender(&record.payload, sender),
        Err(error) => {
            tracing::warn!(
                %error,
                actor = %session.actor,
                "failed to read personal blocklist policy"
            );
            false
        }
    }
}

fn blocklist_payload_blocks_sender(payload: &Value, sender: &str) -> bool {
    if payload
        .get("tombstone")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return false;
    }
    let Some(entries) = payload.get("entries").and_then(Value::as_array) else {
        // Account data is opaque unless the holder has authorized a readable
        // policy projection. An encrypted or otherwise unreadable blocklist
        // cannot prove that this sender is allowed, so cross-actor fanout must
        // fail closed.
        return true;
    };
    entries
        .iter()
        .any(|entry| blocklist_entry_blocks_sender(entry, sender))
}

fn blocklist_entry_blocks_sender(entry: &Value, sender: &str) -> bool {
    let mode = entry
        .get("mode")
        .or_else(|| entry.get("kind"))
        .and_then(Value::as_str)
        .unwrap_or("block");
    if mode != "block" {
        return false;
    }
    if entry.get("expires_at").is_some_and(|expires_at| {
        expires_at.as_str().is_some_and(|value| {
            chrono::DateTime::parse_from_rfc3339(value)
                .is_ok_and(|expires| expires <= chrono::Utc::now())
        })
    }) {
        return false;
    }
    let Some(target) = entry.get("target") else {
        return ["did", "actor", "id"]
            .iter()
            .any(|field| entry.get(*field).and_then(Value::as_str) == Some(sender));
    };
    if let Some(value) = target.as_str() {
        return value == sender;
    }
    let Some(object) = target.as_object() else {
        return false;
    };
    if object.get("kind").and_then(Value::as_str) != Some("actor") {
        return false;
    }
    ["did", "actor", "id"]
        .iter()
        .any(|field| object.get(*field).and_then(Value::as_str) == Some(sender))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_rejection_keeps_organization_approval_as_reason_code() {
        let reason = arkret_wire::ReasonCode::REQUIRES_ORGANIZATION_APPROVAL;
        let error = operation_reject_to_app_error(reason);

        assert_eq!(error.http_status(), salvo::http::StatusCode::CONFLICT);
        assert_eq!(error.wire_code(), "failed_precondition");
        assert_eq!(error.reason_code.as_deref(), Some(reason));
        assert_eq!(error.top_level_reason, None);
    }
}
