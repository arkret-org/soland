//! Realm lifecycle read surface and Space-container cell read surface.
//!
//! Surfaces that remain:
//! - `GET    /_soland/self/realms/{realm_id}` — read a Realm lifecycle response.
//! - `GET    /_soland/self/realms/{realm_id}/export` — full event log + projection dump.
//! - `GET    /_soland/self/spaces/{space_id}/cells/{cell_family}` — projected Space-container
//!   child-order cell.
//!
//! Everything else in this module is the visibility / membership / typing
//! query helper surface that every other domain (federation, message, blob,
//! directory, mimi, …) calls into to resolve "is this actor allowed to see /
//! write in this Realm?".

use chrono::{DateTime, Utc};
use cokret_sdk::{Did, RealmId, RealmModerationPolicyReplaceRequestBody, SpaceId};
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde::Serialize;
use serde_json::{Value, json};

use super::AuthArgs;
use crate::error::AppError;
use crate::reducer::CHILD_ORDER_CELL_FAMILY;
use crate::routing::organizations;
use crate::state::{AppState, RealmDirectoryEntry, SessionRecord};
use crate::wire::{RealmLifecycleOutcome, now};
use crate::{JsonResult, json_ok};

/// Spec `realm_read` operation group (`ck.self.realm.*`): Realm lifecycle read,
/// full export, and Realm moderation-policy effective/set. Canonical path
/// `/_cokret/self/realms/{realm_id}*`.
pub(super) fn protocol_router() -> Router {
    Router::new().push(
        Router::with_path("realms/{realm_id}")
            .get(get_realm)
            .push(
                Router::with_path("moderation-policy/effective")
                    .get(get_realm_effective_moderation_policy),
            )
            .push(Router::with_path("moderation-policy").put(upsert_realm_moderation_policy))
            .push(Router::with_path("export").get(export_realm)),
    )
}

/// Soland-local Space-container child-order cell read surface
/// (`org.cokret.soland.spaces.cells.get`); no canonical operation, stays on the
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
    created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct RealmExportOperation {
    operation_id: String,
    realm_id: String,
    object_type: String,
    operation_type: String,
    payload: Value,
    created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct RealmExportOutcome {
    schema: String,
    realm_id: String,
    generated_at: DateTime<Utc>,
    operations: Vec<RealmExportOperation>,
    events: Vec<RealmExportEvent>,
}

#[endpoint(
    operation_id = "ck.self.realm.resource.get",
    tags("realms"),
    summary = "Get a Realm lifecycle response (owner + members)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.realm.resource.get"))]
async fn get_realm(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<RealmLifecycleOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    realm_lifecycle_response(state, &realm_id)
        .await
        .map(salvo::prelude::Json)
}

#[endpoint(
    operation_id = "ck.self.realm.moderation_policy.query.effective",
    tags("realms", "policy"),
    summary = "Get organization-inherited effective moderation policy"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ck.self.realm.moderation_policy.query.effective")
)]
async fn get_realm_effective_moderation_policy(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<organizations::RealmEffectiveModerationPolicyOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    RealmId::new(realm_id.clone()).map_err(|_| AppError::invalid_param("invalid realm_id"))?;
    if !realm_id_accessible(state, &realm_id, Some(&session)).await {
        return Err(AppError::not_found("not found"));
    }
    json_ok(organizations::effective_policy_for_realm(state, &realm_id))
}

#[endpoint(
    operation_id = "ck.self.realm.moderation_policy.resource.replace",
    tags("realms", "policy"),
    summary = "Set a Realm moderation-policy override"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ck.self.realm.moderation_policy.resource.replace")
)]
async fn upsert_realm_moderation_policy(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    body: JsonBody<RealmModerationPolicyReplaceRequestBody>,
) -> JsonResult<organizations::RealmModerationPolicyOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    RealmId::new(realm_id.clone()).map_err(|_| AppError::invalid_param("invalid realm_id"))?;
    let record = state
        .persistence
        .realm_meta()
        .get(&realm_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("not found"))?;
    if record.owner != session.actor {
        return Err(AppError::capability_denied("missing_capability"));
    }
    let payload = serde_json::to_value(body.into_inner().policy).map_err(|error| {
        AppError::internal(format!("realm moderation policy serialize: {error}"))
    })?;
    if organizations::realm_policy_override_requires_approval(state, &realm_id, &payload)
        && !organizations::realm_policy_override_has_approval(state, &realm_id, &payload)
    {
        return Err(organizations::requires_organization_approval_error());
    }
    let policy =
        organizations::persist_realm_moderation_policy(state, &realm_id, payload, &session.actor);
    json_ok(organizations::realm_policy_record_outcome(&policy))
}

#[endpoint(
    operation_id = "org.cokret.soland.spaces.cells.get",
    tags("spaces", "cells"),
    summary = "Get a projected Space-container child-order cell"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.spaces.cells.get"))]
async fn get_space_cell(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: PathParam<String>,
    cell_family: PathParam<String>,
) -> JsonResult<SpaceCellOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
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
        let proj = state
            .projection
            .lock()
            .map_err(|_| AppError::internal("projection state unavailable"))?;
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
        cell_id: format!("ck:cell:{CHILD_ORDER_CELL_FAMILY}:{space_id}"),
        cell_family: CHILD_ORDER_CELL_FAMILY.to_owned(),
        space_id,
        state: "value".to_owned(),
        lattice: "ordered-log".to_owned(),
        value,
        total,
    })
}

#[endpoint(
    operation_id = "ck.self.realm.query.export",
    tags("realms"),
    summary = "Full event log + projection dump for a Realm"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.realm.query.export"))]
async fn export_realm(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<RealmExportOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    RealmId::new(realm_id.clone()).map_err(|_| AppError::invalid_param("invalid realm_id"))?;
    if !realm_id_accessible(state, &realm_id, Some(&session)).await {
        return Err(AppError::not_found("not found"));
    }
    let events = state
        .persistence
        .projection_events()
        .snapshot_all()
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
                    created_at: event.created_at.clone(),
                })
        })
        .collect::<Vec<_>>();
    json_ok(RealmExportOutcome {
        schema: "ck.export.realm.v1".to_owned(),
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
) -> Result<RealmLifecycleOutcome, AppError> {
    let realm_id_value = RealmId::new(realm_id.to_owned())
        .map_err(|_| AppError::invalid_param("invalid realm_id"))?;
    // Snapshot the member list off the realms lock before the async meta read
    // (the guard is not Send and must not cross the `.await`).
    let members: Vec<String> = {
        let realms = state.realms.lock().expect("realms lock");
        realms
            .get(&realm_id_value)
            .map(|realm| realm.members.iter().map(ToString::to_string).collect())
            .unwrap_or_default()
    };
    let record = state
        .persistence
        .realm_meta()
        .get(realm_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("not found"))?;
    Ok(RealmLifecycleOutcome {
        ok: true,
        realm_id: realm_id.to_owned(),
        owner: record.owner.clone(),
        members,
        deleted: record.deleted,
    })
}

pub async fn touch_realm_meta(state: &AppState, realm_id: &str) {
    let store = state.persistence.realm_meta();
    if let Ok(Some(mut record)) = store.get(realm_id).await {
        record.updated_at = now();
        if let Err(error) = store.put(realm_id, &record).await {
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
        "shared" => {
            if realm_discoverability(state, realm_or_internal_id).await == "public" {
                return true;
            }
            match session {
                Some(session) => {
                    realm_active_member_at_read_time(state, realm_or_internal_id, &session.actor)
                        .await
                }
                None => false,
            }
        }
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

pub async fn realm_allows_plaintext_service(state: &AppState, realm_or_internal_id: &str) -> bool {
    match realm_scope_to_realm_id(realm_or_internal_id) {
        Some(realm_id) => realm_allows_plaintext_service_for_id(state, &realm_id).await,
        None => false,
    }
}

pub async fn realm_meta_deleted(state: &AppState, realm_id: &str) -> bool {
    state
        .persistence
        .realm_meta()
        .get(realm_id)
        .await
        .ok()
        .flatten()
        .is_some_and(|record| record.deleted)
}

pub async fn realm_discoverability_for_id(state: &AppState, realm_id: &str) -> String {
    state
        .persistence
        .realm_meta()
        .get(realm_id)
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
    if realm_id == crate::routing::identity::recovery::principal_control_realm_for_did(actor) {
        return true;
    }
    let realms = state.realms.lock().expect("realms lock");
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
                let members: Vec<String> = realm
                    .members
                    .iter()
                    .map(|did| did.as_str().to_owned())
                    .collect();
                tracing::warn!(
                    %realm_id,
                    %actor,
                    realm_members = ?members,
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
        .persistence
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
///    actors). MLS-encrypted Realms are explicitly forbidden from this state
///    (`incompatible_history_with_encryption`).
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
        let realms = state.realms.lock().expect("realms lock");
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

/// Look up the persisted `history_visibility` for a Realm, defaulting to
/// `joined` when no meta record exists (matches the spec default).
pub async fn realm_history_visibility_for_id(state: &AppState, realm_id: &str) -> String {
    state
        .persistence
        .realm_meta()
        .get(realm_id)
        .await
        .ok()
        .flatten()
        .map(|record| record.history_visibility.clone())
        .unwrap_or_else(|| {
            if directory_realm_is_public(state, realm_id) {
                "shared".to_owned()
            } else {
                "joined".to_owned()
            }
        })
}

fn directory_realm_is_public(state: &AppState, realm_id: &str) -> bool {
    let Ok(realm_id) = RealmId::new(realm_id.to_owned()) else {
        return false;
    };
    state
        .realms
        .lock()
        .expect("realms lock")
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
    if let Ok(projection) = state.projection.lock()
        && let Some(member) = projection.member(realm_id, actor)
        && member.state == "join"
    {
        return Some(member.joined_at);
    }
    let meta = state
        .persistence
        .realm_meta()
        .get(realm_id)
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
    if let Ok(projection) = state.projection.lock()
        && let Some(member) = projection.member(realm_id, actor)
    {
        if let Some(invited_at) = member.invited_at {
            return Some(invited_at);
        }
        if matches!(member.state.as_str(), "invite" | "join") {
            return Some(member.updated_at);
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
            if let Ok(projection) = state.projection.lock()
                && let Some(member) = projection.member(&realm_id, actor)
            {
                return member.state == "join";
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
        .persistence
        .realm_meta()
        .get(&realm_id)
        .await
        .ok()
        .flatten()
    else {
        return false;
    };
    let Some(policy) = meta.history_sharing_policy.as_ref() else {
        return false;
    };
    let Some(rules) = policy.get("restricted_rules").and_then(Value::as_array) else {
        return false;
    };
    let active_member = realm_active_member_at_read_time(state, &realm_id, actor).await;
    let joined_at = realm_member_joined_at_for_id(state, &realm_id, actor).await;
    let invited_at = realm_member_invited_or_joined_at_for_id(state, &realm_id, actor).await;
    rules.iter().any(|rule| {
        restricted_rule_matches_actor(rule, actor, active_member)
            && restricted_rule_matches_range(rule, event_created_at, invited_at, joined_at)
    })
}

fn restricted_rule_matches_actor(rule: &Value, actor: &str, active_member: bool) -> bool {
    let audiences: Vec<&str> = rule
        .get("audiences")
        .or_else(|| rule.get("audience"))
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if audiences.contains(&"realm_member") && active_member {
        return true;
    }
    if audiences.contains(&"authenticated") {
        return true;
    }
    rule.get("actors")
        .or_else(|| rule.get("principals"))
        .and_then(Value::as_array)
        .is_some_and(|actors| actors.iter().any(|value| value.as_str() == Some(actor)))
}

fn restricted_rule_matches_range(
    rule: &Value,
    event_created_at: DateTime<Utc>,
    invited_at: Option<DateTime<Utc>>,
    joined_at: Option<DateTime<Utc>>,
) -> bool {
    match rule
        .get("range")
        .or_else(|| rule.get("event_range"))
        .and_then(Value::as_str)
        .unwrap_or("rule_only")
    {
        "all" | "event_time_visibility" => true,
        "from_invite" => invited_at.is_some_and(|at| event_created_at >= at),
        "from_join" => joined_at.is_some_and(|at| event_created_at >= at),
        _ => false,
    }
}

pub async fn realm_allows_plaintext_service_for_id(state: &AppState, realm_id: &str) -> bool {
    let Ok(realm_id_typed) = RealmId::new(realm_id.to_owned()) else {
        return false;
    };
    let directory_realm_id = {
        let realms = state.realms.lock().expect("realms lock");
        realms
            .get(&realm_id_typed)
            .map(|realm| realm.realm_id.as_str().to_owned())
    };
    if let Some(directory_realm_id) = directory_realm_id {
        if realm_discoverability_for_id(state, &directory_realm_id).await == "public" {
            return true;
        }
    }
    state
        .persistence
        .realm_meta()
        .get(realm_id)
        .await
        .ok()
        .flatten()
        .is_some_and(|record| {
            record
                .plaintext_visible_services
                .contains(&state.config.service_did)
        })
}

pub async fn prune_expired_typing(state: &AppState) {
    if let Err(error) = state.persistence.typing().prune_expired().await {
        tracing::warn!(%error, "failed to prune expired typing entries");
    }
}

pub async fn typing_ephemeral_for_realm(
    state: &AppState,
    realm_id: &str,
    session: Option<&SessionRecord>,
) -> Vec<serde_json::Value> {
    if session.is_none() {
        return Vec::new();
    }
    let mut by_scope = std::collections::BTreeMap::<String, Vec<serde_json::Value>>::new();
    let typing_records = state
        .persistence
        .typing()
        .list_for_realm(realm_id)
        .await
        .unwrap_or_default();
    for record in &typing_records {
        let scope_id = record
            .scope_id
            .clone()
            .unwrap_or_else(|| record.realm_id.clone());
        by_scope.entry(scope_id).or_default().push(json!({
            "actor": record.actor.clone(),
            "expires_at": record.expires_at,
            "updated_at": record.updated_at,
        }));
    }
    by_scope
        .into_iter()
        .map(|(scope_id, actors)| {
            json!({
                "type": "ck.typing",
                "realm_id": realm_id,
                "scope_id": scope_id,
                "actors": actors,
            })
        })
        .collect()
}
