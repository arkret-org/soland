//! Realm lifecycle read surface and Space-container cell read surface.
//!
//! Surfaces that remain:
//! - `GET    /_arkret/self/realms/{realm_id}` — read a Realm lifecycle response.
//! - `GET    /_arkret/self/realms/{realm_id}/export` — full event log + projection dump.
//! - `GET    /_soland/self/spaces/{space_id}/cells/{cell_family}` — projected Space-container
//!   child-order cell.
//!
//! Everything else in this module is the visibility / membership
//! query helper surface that every other domain (federation, message, blob,
//! directory, mimi, …) calls into to resolve "is this actor allowed to see /
//! write in this Realm?".

use arkret_identifiers::{Did, RealmId, SpaceId};
use arkret_models_collaboration::events_payloads::HistorySharingPolicyPayloadValue;
use arkret_models_collaboration::governance::history_visibility::{
    HistoryRangeContext, HistoryReaderContext, HistoryReaderEventState,
    HistorySharingRestrictedScopeRef, HistorySharingScopeKind,
};
use arkret_models_collaboration::governance::realm_governance::{
    RealmArchiveRequestBody, RealmDestroyRequestBody, RealmFreezeRequestBody, RealmLifecycleView,
    RealmModerationPolicyReplaceRequestBody, RealmTombstoneRequestBody,
};
use arkret_policy::history_visibility::matching_restricted_rules;
use arkret_wire::{HistoryVisibility, PlaintextDataClassKind};
use chrono::{DateTime, Utc};
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde::Serialize;
use serde_json::Value;
use soland_http::error::AppError;
use soland_services::identity::SessionIdentityState as SessionRecord;
use soland_services::operation_semantics::CHILD_ORDER_CELL_FAMILY;

use super::AuthArgs;
use crate::routing::{is_valid_discoverability, organizations};
use crate::state::{AppState, RealmDirectoryEntry};
use crate::wire::now;
use crate::{JsonResult, json_ok};

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
    operation_kind: String,
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
    object_kind: String,
    operation_kind: String,
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

#[salvo::oapi::endpoint(operation_id = "ak.self.realm.resource.get", tags("spaces"))]
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

/// Submit a caller-signed Realm lifecycle Move through ordinary Event admission.
///
/// These four operations used to take the Event payload and let the service build
/// the Move around it, which meant the signature could only have come from a
/// service key. Now the caller signs and the service forwards those exact bytes;
/// the lifecycle transition matrix and the `ak.realm.*` capability are admission's
/// to enforce.
async fn submit_realm_lifecycle_command(
    state: &AppState,
    session: &SessionRecord,
    realm_id: String,
    kind: &'static str,
    submission: arkret_wire::EventInitialSubmission,
) -> Result<RealmLifecycleView, AppError> {
    caller_signed_realm_lifecycle_target(&session.actor, &realm_id, kind, &submission.event)?;
    crate::routing::events::event_log::submit_initial_event_submission(state, session, submission)
        .await
        .map(|_| ())
        .map_err(|error| {
            crate::routing::events::event_log::submit_one_error_to_app_error(
                &format!("{kind} submit failed"),
                error.status,
                error.code,
                &error.message,
            )
        })?;
    realm_lifecycle_response(state, &realm_id).await
}

/// Bind a caller-signed Realm lifecycle Event to the path it was submitted on.
///
/// The Realm is single-sourced by `event.realm_id`, so that is what the path is
/// checked against; a body naming another Realm would otherwise act on that one.
fn caller_signed_realm_lifecycle_target(
    actor: &str,
    realm_id: &str,
    kind: &'static str,
    event: &arkret_wire::Event,
) -> Result<(), AppError> {
    if event.kind.as_str() != kind {
        return Err(AppError::invalid_param(format!(
            "lifecycle_event.event.kind must be {kind}"
        )));
    }
    if event.actor_id.as_str() != actor {
        return Err(AppError::invalid_param(
            "lifecycle_event.event.actor_id must be the authenticated caller",
        ));
    }
    if event.realm_id.as_str() != realm_id {
        return Err(AppError::invalid_param(
            "lifecycle_event.event.realm_id must equal the path realm_id",
        ));
    }
    Ok(())
}

#[salvo::oapi::endpoint(operation_id = "ak.self.realm.command.archive", tags("spaces"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm.command.archive"))]
async fn archive_realm(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    body: JsonBody<RealmArchiveRequestBody>,
) -> JsonResult<RealmLifecycleView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    submit_realm_lifecycle_command(
        state,
        &session,
        realm_id.into_inner(),
        arkret_wire::EventKind::REALM_ARCHIVE,
        body.into_inner().lifecycle_event,
    )
    .await
    .map(salvo::prelude::Json)
}

#[salvo::oapi::endpoint(operation_id = "ak.self.realm.command.freeze", tags("spaces"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm.command.freeze"))]
async fn freeze_realm(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    body: JsonBody<RealmFreezeRequestBody>,
) -> JsonResult<RealmLifecycleView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    submit_realm_lifecycle_command(
        state,
        &session,
        realm_id.into_inner(),
        arkret_wire::EventKind::REALM_FREEZE,
        body.into_inner().lifecycle_event,
    )
    .await
    .map(salvo::prelude::Json)
}

#[salvo::oapi::endpoint(operation_id = "ak.self.realm.command.tombstone", tags("spaces"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm.command.tombstone"))]
async fn tombstone_realm(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    body: JsonBody<RealmTombstoneRequestBody>,
) -> JsonResult<RealmLifecycleView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    submit_realm_lifecycle_command(
        state,
        &session,
        realm_id.into_inner(),
        arkret_wire::EventKind::REALM_TOMBSTONE,
        body.into_inner().lifecycle_event,
    )
    .await
    .map(salvo::prelude::Json)
}

#[salvo::oapi::endpoint(operation_id = "ak.self.realm.command.destroy", tags("spaces"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm.command.destroy"))]
async fn destroy_realm(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    body: JsonBody<RealmDestroyRequestBody>,
) -> JsonResult<RealmLifecycleView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    submit_realm_lifecycle_command(
        state,
        &session,
        realm_id.into_inner(),
        arkret_wire::EventKind::REALM_DESTROY,
        body.into_inner().lifecycle_event,
    )
    .await
    .map(salvo::prelude::Json)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.realm.moderation_policy.read.effective",
    tags("spaces")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.self.realm.moderation_policy.read.effective")
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

#[salvo::oapi::endpoint(
    operation_id = "ak.self.realm.moderation_policy.resource.replace",
    tags("spaces")
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
        .realms()
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

#[salvo::oapi::endpoint(operation_id = "org.arkret.soland.spaces.cells.get", tags("spaces"))]
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
        let proj = state.projections().snapshot();
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

#[salvo::oapi::endpoint(operation_id = "ak.self.realm.read.export", tags("spaces"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm.read.export"))]
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
        .event_queries()
        .projected_events_for_realm(&realm_id)
        .await
        .map_err(|error| AppError::internal(format!("realm export failed: {error}")))?
        .into_iter()
        .map(|event| RealmExportEvent {
            event_id: event.event_id,
            realm_id: event.realm_id,
            event_kind: event.event_kind,
            operation_kind: event.operation_kind,
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
                    object_kind: event.event_kind.clone(),
                    operation_kind: event.operation_kind.clone(),
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
        let realms = state.realm_directory().snapshot();
        realms
            .get(&realm_id_value)
            .map(|realm| realm.members.iter().cloned().collect())
            .unwrap_or_default()
    };
    let (archived, frozen, terminal_state, successor_realm_id, freeze_expires_at) = {
        let projection = state.projections().snapshot();
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
        .realms()
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
    let service = state.realms();
    if let Ok(Some(mut record)) = service.realm_metadata(realm_id).await {
        record.updated_at = now();
        if let Err(error) = service.store_realm_metadata(realm_id, record).await {
            tracing::warn!(%error, "failed to touch realm meta");
        }
    }
}

// ── Visibility + membership query helpers ─────────────────────────────────

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
        .realms()
        .realm_metadata(realm_id)
        .await
        .ok()
        .flatten()
        .is_some_and(|record| record.deleted)
}

pub async fn realm_discoverability_for_id(state: &AppState, realm_id: &str) -> String {
    // The accepted control projection is authoritative. Live semantic apply
    // stores Realm create entries as `{object: Realm}`, while canonical Seal
    // replay stores the ordered-log value as `{value: Realm + entry_id}`.
    // Resolve both before consulting the service-local metadata mirror, which
    // may legitimately lag a freshly materialized Seal.
    let projected = {
        let projection = state.projections().snapshot();
        projection
            .realm_metadata_cell_value(realm_id)
            .and_then(discoverability_from_realm_value)
            .or_else(|| {
                projection
                    .realm_create_log(realm_id)
                    .and_then(|entries| entries.last())
                    .and_then(discoverability_from_realm_value)
            })
            .map(ToOwned::to_owned)
    };
    if let Some(discoverability) = projected {
        return discoverability;
    }
    state
        .realms()
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

fn discoverability_from_realm_value(value: &Value) -> Option<&str> {
    value
        .get("default_discoverability")
        .or_else(|| value.get("discoverability"))
        .or_else(|| value.pointer("/object/default_discoverability"))
        .or_else(|| value.pointer("/object/discoverability"))
        .or_else(|| value.pointer("/value/default_discoverability"))
        .or_else(|| value.pointer("/value/discoverability"))
        .and_then(Value::as_str)
        .filter(|value| is_valid_discoverability(value))
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
    if realm_id == soland_services::identity::principal_control_realm_for_did(actor) {
        return true;
    }
    let realms = state.realm_directory().snapshot();
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
        .realm_invites()
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
        let realms = state.realm_directory().snapshot();
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
///   `events.read` does not `not_found` it), but
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
        let projection = state.projections().snapshot();
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
/// the `events.read` per-event filter to keep the recovery face narrow.
pub fn realm_recovery_event_visible(
    event_kind: &str,
    recipient_principal_id: Option<&str>,
    actor: &str,
) -> bool {
    event_kind == arkret_wire::EventKind::REALM_KEY_SHARE && recipient_principal_id == Some(actor)
}

/// Look up the persisted `history_visibility` for a Realm, defaulting to
/// `joined` when no meta record exists (matches the spec default).
pub async fn realm_history_visibility_for_id(state: &AppState, realm_id: &str) -> String {
    state
        .realms()
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
        .realm_directory()
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
        let projection = state.projections().snapshot();
        if let Some(member) = projection.member(realm_id, actor)
            && member.state == "join"
        {
            return Some(member.joined_at);
        }
    }
    let meta = state.realms().realm_metadata(realm_id).await.ok().flatten();
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
        let projection = state.projections().snapshot();
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
                let projection = state.projections().snapshot();
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
        .realms()
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
    if arkret_policy::history_visibility::validate_history_sharing_policy(&policy).is_err() {
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
        let realms = state.realm_directory().snapshot();
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
        .realms()
        .realm_metadata(realm_id)
        .await
        .ok()
        .flatten()
        .is_some_and(|record| record.allows_plaintext_data_class(state.service_id(), data_class))
}

async fn realm_public_content_for_id(state: &AppState, realm_id: &str) -> bool {
    state
        .realms()
        .realm_metadata(realm_id)
        .await
        .ok()
        .flatten()
        .is_some_and(|record| {
            record.discoverability == "public" && record.history_visibility == "world_readable"
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIFECYCLE_ACTOR: &str = "did:web:owner.example";
    const LIFECYCLE_REALM: &str = "ak:realm:AQcksDTzb8Sxrn1BUVVlHtH4vBOy99RKUB4EwOq_413b";

    fn realm_lifecycle_event(kind: &str, actor: &str, realm_id: &str) -> arkret_wire::Event {
        serde_json::from_value(serde_json::json!({
            "event_id": "ak:event:AdMGtDS93qeltLI_MYwQqXktcIXSzfonrtSShq1Ca8MX",
            "kind": kind,
            "realm_id": realm_id,
            "scope_ref": { "kind": "realm", "realm_id": realm_id },
            "actor_id": actor,
            "actor_seq": 0,
            "created_at": "2026-07-06T00:00:00.000Z",
            "prev_refs": [],
            "refs": [],
            "payload": { "archived": true },
            "proofs": [],
        }))
        .expect("realm lifecycle envelope")
    }

    #[test]
    fn a_realm_lifecycle_event_binds_to_the_path_realm_and_its_own_kind() {
        caller_signed_realm_lifecycle_target(
            LIFECYCLE_ACTOR,
            LIFECYCLE_REALM,
            arkret_wire::EventKind::REALM_ARCHIVE,
            &realm_lifecycle_event(
                arkret_wire::EventKind::REALM_ARCHIVE,
                LIFECYCLE_ACTOR,
                LIFECYCLE_REALM,
            ),
        )
        .unwrap();

        // The archive endpoint must not be a way to submit a terminal destroy.
        caller_signed_realm_lifecycle_target(
            LIFECYCLE_ACTOR,
            LIFECYCLE_REALM,
            arkret_wire::EventKind::REALM_ARCHIVE,
            &realm_lifecycle_event(
                arkret_wire::EventKind::REALM_DESTROY,
                LIFECYCLE_ACTOR,
                LIFECYCLE_REALM,
            ),
        )
        .expect_err("the archive surface must not accept a destroy Event");

        // The Realm is single-sourced by event.realm_id, so a mismatch is a
        // request to act on a Realm the URL did not name.
        caller_signed_realm_lifecycle_target(
            LIFECYCLE_ACTOR,
            LIFECYCLE_REALM,
            arkret_wire::EventKind::REALM_ARCHIVE,
            &realm_lifecycle_event(
                arkret_wire::EventKind::REALM_ARCHIVE,
                LIFECYCLE_ACTOR,
                "ak:realm:AW6ST0TiEb2kdaVDQ-YtsKW8ig0EM-l6_Y5YiT16u7b-",
            ),
        )
        .expect_err("event.realm_id must equal the path realm_id");

        caller_signed_realm_lifecycle_target(
            LIFECYCLE_ACTOR,
            LIFECYCLE_REALM,
            arkret_wire::EventKind::REALM_ARCHIVE,
            &realm_lifecycle_event(
                arkret_wire::EventKind::REALM_ARCHIVE,
                "did:web:someone-else.example",
                LIFECYCLE_REALM,
            ),
        )
        .expect_err("the submitted Event must be authored by the authenticated caller");
    }
}
