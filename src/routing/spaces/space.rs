//! Space read + visibility surface.
//!
//! The lifecycle / membership mutation REST endpoints that previously lived
//! here (POST/PATCH/PUT/DELETE on `/api/v1/spaces/*`) bypassed canonical
//! Event Envelope construction and maintained Realm-level state outside the
//! event log. They have been removed (see `_spec_report_claude.md` §2.5 and
//! `realm-and-space.md:140`); Realm state mutations MUST flow through the
//! canonical operation pipeline (`POST /api/v1/operations`).
//!
//! Surfaces that remain:
//! - `GET    /api/v1/spaces/{space_id}` — read a Space's lifecycle response
//! - `GET    /api/v1/spaces/{space_id}/export` — full event log + projection dump
//!
//! Everything else in this module is the visibility / membership / typing
//! query helper surface that every other domain (federation, message, blob,
//! directory, mimi, …) calls into to resolve "is this actor allowed to see /
//! write to this Space?".

use chrono::{DateTime, Utc};
use contrix_sdk::{Did, RealmId, SpaceId};
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::AuthArgs;
use crate::error::AppError;
use crate::reducer::CHILD_ORDER_CELL_FAMILY;
use crate::routing::organizations;
use crate::state::{AppState, RealmDirectoryEntry, SessionRecord};
use crate::wire::{SpaceLifecycleResponse, now};
use crate::{JsonResult, json_ok};

pub(super) fn router() -> Router {
    Router::with_path("spaces").push(
        Router::with_path("{space_id}")
            .get(get_space)
            .push(Router::with_path("cells/{cell_family}").get(get_space_cell))
            .push(Router::with_path("effective-policy").get(get_space_effective_policy))
            .push(Router::with_path("moderation-policy").post(upsert_space_moderation_policy))
            .push(Router::with_path("export").get(export_space)),
    )
}

#[endpoint(
    operation_id = "cx.extension.soland.spaces.get",
    tags("spaces"),
    summary = "Get a Space's lifecycle response (owner + members)"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.spaces.get"))]
async fn get_space(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: PathParam<String>,
) -> JsonResult<SpaceLifecycleResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req)?;
    let space_id = space_id.into_inner();
    space_lifecycle_response(state, &space_id).map(salvo::prelude::Json)
}

#[endpoint(
    operation_id = "cx.extension.soland.spaces.effective_policy.get",
    tags("spaces", "policy"),
    summary = "Get organization-inherited effective moderation policy"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "cx.extension.soland.spaces.effective_policy.get")
)]
async fn get_space_effective_policy(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: PathParam<String>,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let space_id = space_id.into_inner();
    RealmId::new(space_id.clone()).map_err(|_| AppError::invalid_param("invalid realm_id"))?;
    if !space_id_accessible(state, &space_id, Some(&session)) {
        return Err(AppError::not_found("not found"));
    }
    json_ok(organizations::effective_policy_for_space_json(
        state, &space_id,
    ))
}

#[endpoint(
    operation_id = "cx.extension.soland.spaces.moderation_policy.upsert",
    tags("spaces", "policy"),
    summary = "Set a Space moderation-policy override"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "cx.extension.soland.spaces.moderation_policy.upsert")
)]
async fn upsert_space_moderation_policy(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: PathParam<String>,
    body: JsonBody<Value>,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let space_id = space_id.into_inner();
    RealmId::new(space_id.clone()).map_err(|_| AppError::invalid_param("invalid realm_id"))?;
    let record = state
        .persistence
        .realm_meta()
        .get(&space_id)
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("not found"))?;
    if record.owner != session.actor {
        return Err(AppError::capability_denied("missing_capability"));
    }
    let payload = body.into_inner();
    if organizations::space_policy_override_requires_approval(state, &space_id, &payload)
        && !organizations::space_policy_override_has_approval(state, &space_id, &payload)
    {
        return Err(organizations::requires_organization_approval_error());
    }
    let policy =
        organizations::persist_space_moderation_policy(state, &space_id, payload, &session.actor);
    json_ok(json!({
        "kind": "cx.realm.moderation_policy",
        "space_id": policy.space_id,
        "policy": policy.payload,
        "updated_by": policy.updated_by,
        "updated_at": policy.updated_at.to_rfc3339(),
    }))
}

#[endpoint(
    operation_id = "cx.extension.soland.spaces.cells.get",
    tags("spaces", "cells"),
    summary = "Get a projected Space-container child-order cell"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.spaces.cells.get"))]
async fn get_space_cell(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: PathParam<String>,
    cell_family: PathParam<String>,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let space_id = space_id.into_inner();
    let cell_family = cell_family.into_inner();
    if cell_family != CHILD_ORDER_CELL_FAMILY {
        return Err(AppError::not_found("cell family not found"));
    }
    validate_child_order_subject(&space_id)?;

    let proj = state
        .projection
        .lock()
        .map_err(|_| AppError::internal("projection state unavailable"))?;
    let realm_id = proj
        .space_containers
        .get(&space_id)
        .map(|container| container.space_id.clone())
        .unwrap_or_else(|| space_id.clone());
    if !space_id_accessible(state, &realm_id, Some(&session)) {
        return Err(AppError::not_found("not found"));
    }
    let value = proj.child_order_cell_value(&space_id);
    let total = value
        .get("children")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or_default();
    drop(proj);

    json_ok(json!({
        "cell_id": format!("cx:cell:{CHILD_ORDER_CELL_FAMILY}:{space_id}"),
        "cell_family": CHILD_ORDER_CELL_FAMILY,
        "space_id": space_id,
        "state": "value",
        "lattice": "ordered-log",
        "value": value,
        "total": total,
    }))
}

#[endpoint(
    operation_id = "cx.extension.soland.spaces.export",
    tags("spaces"),
    summary = "Full event log + projection dump for a Space"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.spaces.export"))]
async fn export_space(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: PathParam<String>,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let space_id = space_id.into_inner();
    RealmId::new(space_id.clone()).map_err(|_| AppError::invalid_param("invalid realm_id"))?;
    if !space_id_accessible(state, &space_id, Some(&session)) {
        return Err(AppError::not_found("not found"));
    }
    let events = state
        .persistence
        .projection_events()
        .snapshot_all()
        .unwrap_or_default()
        .into_iter()
        .filter(|event| event.space_id == space_id)
        .map(|event| {
            json!({
                "event_id": event.event_id,
                "realm_id": event.space_id,
                "event_kind": event.event_kind,
                "operation_type": event.operation_type,
                "operation_id": event.operation_id,
                "sender": event.sender,
                "payload": event.payload,
                "created_at": event.created_at,
            })
        })
        .collect::<Vec<_>>();
    let operations = events
        .iter()
        .filter(|event| event["operation_id"].is_string())
        .map(|event| {
            json!({
                "operation_id": event["operation_id"],
                "realm_id": event["realm_id"],
                "object_type": event["event_kind"],
                "operation_type": event["operation_type"],
                "payload": event["payload"],
                "created_at": event["created_at"],
            })
        })
        .collect::<Vec<_>>();
    json_ok(json!({
        "schema": "cx.export.space.v1",
        "realm_id": space_id,
        "generated_at": now(),
        "operations": operations,
        "events": events,
    }))
}

fn validate_child_order_subject(space_id: &str) -> Result<(), AppError> {
    if space_id.starts_with("cx:space:") {
        SpaceId::new(space_id.to_owned())
            .map_err(|_| AppError::invalid_param("invalid space_id"))?;
        return Ok(());
    }
    RealmId::new(space_id.to_owned()).map_err(|_| AppError::invalid_param("invalid space_id"))?;
    Ok(())
}

// ── Helpers shared with the parent module ───────────────────────────────────
//
// Each is re-exported from `crate::routing::*` so sibling modules use the
// same Realm metadata and membership checks.

pub fn space_lifecycle_response(
    state: &AppState,
    space_id: &str,
) -> Result<SpaceLifecycleResponse, AppError> {
    let space_id_value = RealmId::new(space_id.to_owned())
        .map_err(|_| AppError::invalid_param("invalid realm_id"))?;
    let spaces = state.realms.lock().expect("spaces lock");
    let record = state
        .persistence
        .realm_meta()
        .get(space_id)
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("not found"))?;
    let members = spaces
        .get(&space_id_value)
        .map(|space| space.members.iter().map(ToString::to_string).collect())
        .unwrap_or_default();
    Ok(SpaceLifecycleResponse {
        ok: true,
        space_id: space_id.to_owned(),
        owner: record.owner.clone(),
        members,
        deleted: record.deleted,
    })
}

pub fn touch_space(state: &AppState, space_id: &str) {
    let store = state.persistence.realm_meta();
    if let Ok(Some(mut record)) = store.get(space_id) {
        record.updated_at = now();
        if let Err(error) = store.put(space_id, &record) {
            tracing::warn!(%error, "failed to touch space meta");
        }
    }
}

// ── Visibility + membership + typing query helpers ─────────────────────────

pub fn realm_scope_to_realm_id(scope_id: &str) -> Option<String> {
    RealmId::new(scope_id.to_owned())
        .ok()
        .map(|realm_id| realm_id.as_str().to_owned())
}

pub fn touch_realm(state: &AppState, realm_or_internal_id: &str) {
    if let Some(realm_id) = realm_scope_to_realm_id(realm_or_internal_id) {
        touch_space(state, &realm_id);
    }
}

pub fn is_realm_deleted(state: &AppState, realm_or_internal_id: &str) -> bool {
    realm_scope_to_realm_id(realm_or_internal_id)
        .is_some_and(|realm_id| is_space_deleted(state, &realm_id))
}

pub fn realm_discoverability(state: &AppState, realm_or_internal_id: &str) -> String {
    realm_scope_to_realm_id(realm_or_internal_id)
        .map(|realm_id| space_discoverability(state, &realm_id))
        .unwrap_or_else(|| "invite_only".to_owned())
}

pub fn realm_has_member(state: &AppState, realm_or_internal_id: &str, actor: &str) -> bool {
    realm_scope_to_realm_id(realm_or_internal_id)
        .is_some_and(|realm_id| space_has_member(state, &realm_id, actor))
}

pub fn realm_id_accessible(
    state: &AppState,
    realm_or_internal_id: &str,
    session: Option<&SessionRecord>,
) -> bool {
    realm_scope_to_realm_id(realm_or_internal_id)
        .is_some_and(|realm_id| space_id_accessible(state, &realm_id, session))
}

pub fn realm_visible_to(
    state: &AppState,
    space: &RealmDirectoryEntry,
    session: Option<&SessionRecord>,
) -> bool {
    space_visible_to(state, space, session)
}

pub fn realm_history_visibility(state: &AppState, realm_or_internal_id: &str) -> String {
    realm_scope_to_realm_id(realm_or_internal_id)
        .map(|realm_id| space_history_visibility(state, &realm_id))
        .unwrap_or_else(|| "joined".to_owned())
}

pub fn realm_member_joined_at(
    state: &AppState,
    realm_or_internal_id: &str,
    actor: &str,
) -> Option<DateTime<Utc>> {
    realm_scope_to_realm_id(realm_or_internal_id)
        .and_then(|realm_id| space_member_joined_at(state, &realm_id, actor))
}

pub fn realm_event_visible_to_session(
    state: &AppState,
    realm_or_internal_id: &str,
    event_created_at: DateTime<Utc>,
    sender: Option<&str>,
    session: Option<&SessionRecord>,
) -> bool {
    if sender.is_some_and(|sender| session.is_some_and(|session| session.actor == sender)) {
        return true;
    }
    match realm_history_visibility(state, realm_or_internal_id).as_str() {
        "world_readable" => true,
        "shared" => {
            realm_discoverability(state, realm_or_internal_id) == "public"
                || session.is_some_and(|session| {
                    realm_has_member(state, realm_or_internal_id, &session.actor)
                })
        }
        "joined" | "invited" => {
            let Some(session) = session else {
                return false;
            };
            realm_member_joined_at(state, realm_or_internal_id, &session.actor)
                .is_some_and(|joined_at| event_created_at >= joined_at)
        }
        _ => false,
    }
}

pub fn realm_allows_plaintext_service(state: &AppState, realm_or_internal_id: &str) -> bool {
    realm_scope_to_realm_id(realm_or_internal_id)
        .is_some_and(|realm_id| space_allows_plaintext_service(state, &realm_id))
}

pub fn is_space_deleted(state: &AppState, space_id: &str) -> bool {
    state
        .persistence
        .realm_meta()
        .get(space_id)
        .ok()
        .flatten()
        .is_some_and(|record| record.deleted)
}

pub fn space_discoverability(state: &AppState, space_id: &str) -> String {
    state
        .persistence
        .realm_meta()
        .get(space_id)
        .ok()
        .flatten()
        .map(|record| record.discoverability)
        .unwrap_or_else(|| "invite_only".to_owned())
}

pub fn space_has_member(state: &AppState, space_id: &str, actor: &str) -> bool {
    if is_space_deleted(state, space_id) {
        tracing::warn!(%space_id, %actor, "space_has_member: space marked deleted");
        return false;
    }
    let Ok(space_id_typed) = RealmId::new(space_id.to_owned()) else {
        tracing::warn!(%space_id, %actor, "space_has_member: invalid realm_id shape");
        return false;
    };
    let Ok(actor_typed) = Did::new(actor.to_owned()) else {
        tracing::warn!(%space_id, %actor, "space_has_member: invalid actor DID shape");
        return false;
    };
    let spaces = state.realms.lock().expect("spaces lock");
    match spaces.get(&space_id_typed) {
        None => {
            let known: Vec<String> = spaces
                .search_by_text("")
                .into_iter()
                .map(|entry| entry.realm_id.as_str().to_owned())
                .collect();
            tracing::warn!(
                %space_id,
                %actor,
                known_spaces = ?known,
                "space_has_member: space not present in in-memory index"
            );
            false
        }
        Some(space) => {
            if space.members.contains(&actor_typed) {
                true
            } else {
                let members: Vec<String> = space
                    .members
                    .iter()
                    .map(|did| did.as_str().to_owned())
                    .collect();
                tracing::warn!(
                    %space_id,
                    %actor,
                    space_members = ?members,
                    "space_has_member: actor not in space members"
                );
                false
            }
        }
    }
}

pub fn space_visible_to(
    state: &AppState,
    space: &RealmDirectoryEntry,
    session: Option<&SessionRecord>,
) -> bool {
    if is_space_deleted(state, space.realm_id.as_str()) {
        return false;
    }
    if space_discoverability(state, space.realm_id.as_str()) == "public" {
        return true;
    }
    session.is_some_and(|session| {
        Did::new(session.actor.clone()).is_ok_and(|actor| space.members.contains(&actor))
    })
}

pub fn space_search_visible_to(
    state: &AppState,
    space: &RealmDirectoryEntry,
    session: Option<&SessionRecord>,
) -> bool {
    if is_space_deleted(state, space.realm_id.as_str()) {
        return false;
    }
    if session.is_some_and(|session| {
        Did::new(session.actor.clone()).is_ok_and(|actor| space.members.contains(&actor))
    }) {
        return true;
    }
    matches!(
        space_discoverability(state, space.realm_id.as_str()).as_str(),
        "public" | "listed" | "restricted"
    )
}

pub fn space_resolvable_to(
    state: &AppState,
    space: &RealmDirectoryEntry,
    session: Option<&SessionRecord>,
    invite_token: Option<&str>,
    signed_link: Option<&str>,
) -> bool {
    if is_space_deleted(state, space.realm_id.as_str()) {
        return false;
    }
    if session.is_some_and(|session| {
        Did::new(session.actor.clone()).is_ok_and(|actor| space.members.contains(&actor))
    }) {
        return true;
    }
    match space_discoverability(state, space.realm_id.as_str()).as_str() {
        "public" | "listed" | "restricted" | "unlisted" => true,
        "invite_only" => invite_token
            .is_some_and(|token| invite_token_matches_space(state, space.realm_id.as_str(), token)),
        "secret" => signed_link.is_some_and(|link| !link.trim().is_empty()),
        _ => false,
    }
}

pub fn invite_token_matches_space(state: &AppState, space_id: &str, token: &str) -> bool {
    invite_token_space_id(state, token)
        .is_some_and(|resolved_space_id| resolved_space_id == space_id)
}

pub fn invite_token_space_id(state: &AppState, token: &str) -> Option<String> {
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    let now = now();
    state
        .persistence
        .space_invites()
        .snapshot_all()
        .unwrap_or_default()
        .into_iter()
        .find(|invite| {
            invite.status == "pending"
                && invite.invite_token == token
                && invite.expires_at.is_none_or(|expires_at| expires_at > now)
        })
        .map(|invite| invite.space_id)
}

pub fn space_search_discoverability(state: &AppState, space_id: &str) -> bool {
    matches!(
        space_discoverability(state, space_id).as_str(),
        "public" | "listed" | "restricted"
    )
}

// `space_id_accessible` is the visibility path with looser semantics
// for the backfill / subscribe edge (delete-tolerant for members).

/// Check if a space is accessible for backfill/subscribe (allows deleted spaces for members).
///
/// Read-side authorization rules (space-and-place.md §3.4 + §3.7):
/// 1. `discoverability=public` → anyone.
/// 2. `history_visibility=world_readable` → anyone (including anonymous /
///    non-member registered actors). MLS-encrypted Spaces are explicitly
///    forbidden from this state (`incompatible_history_with_encryption`).
/// 3. Otherwise → caller MUST be an authenticated member.
pub fn space_id_accessible(
    state: &AppState,
    space_id: &str,
    session: Option<&SessionRecord>,
) -> bool {
    let Ok(sid) = RealmId::new(space_id.to_owned()) else {
        return false;
    };
    let spaces = state.realms.lock().expect("spaces lock");
    let Some(space) = spaces.get(&sid) else {
        return false;
    };
    if space_discoverability(state, space.realm_id.as_str()) == "public" {
        return true;
    }
    if space_history_visibility(state, space.realm_id.as_str()) == "world_readable" {
        return true;
    }
    session.is_some_and(|session| {
        Did::new(session.actor.clone()).is_ok_and(|actor| space.members.contains(&actor))
    })
}

/// Look up the persisted `history_visibility` for a Space, defaulting to
/// `joined` when no meta record exists (matches the spec default).
pub fn space_history_visibility(state: &AppState, space_id: &str) -> String {
    state
        .persistence
        .realm_meta()
        .get(space_id)
        .ok()
        .flatten()
        .map(|record| record.history_visibility.clone())
        .unwrap_or_else(|| "joined".to_owned())
}

/// Best-effort joined-at timestamp for event history filtering.
///
/// The reducer's member projection is authoritative when present. Bootstrap
/// owners predate that side-band cache, so only the owner falls back to the
/// Space creation time. Non-owner members without joined_at are hidden by
/// `history_visibility=joined` instead of leaking pre-join history.
pub fn space_member_joined_at(
    state: &AppState,
    space_id: &str,
    actor: &str,
) -> Option<DateTime<Utc>> {
    if let Ok(projection) = state.projection.lock()
        && let Some(member) = projection.member(space_id, actor)
        && member.state == "join"
    {
        return Some(member.joined_at);
    }
    let meta = state.persistence.realm_meta().get(space_id).ok().flatten();
    if meta.as_ref().is_some_and(|record| record.owner == actor) {
        return meta.map(|record| record.created_at);
    }
    None
}

pub fn space_allows_plaintext_service(state: &AppState, space_id: &str) -> bool {
    let Ok(sid) = RealmId::new(space_id.to_owned()) else {
        return false;
    };
    {
        let spaces = state.realms.lock().expect("spaces lock");
        if spaces
            .get(&sid)
            .is_some_and(|space| space_discoverability(state, space.realm_id.as_str()) == "public")
        {
            return true;
        }
    }
    state
        .persistence
        .realm_meta()
        .get(space_id)
        .ok()
        .flatten()
        .is_some_and(|record| {
            record
                .plaintext_visible_services
                .contains(&state.config.service_did)
        })
}

pub fn prune_expired_typing(state: &AppState) {
    if let Err(error) = state.persistence.typing().prune_expired() {
        tracing::warn!(%error, "failed to prune expired typing entries");
    }
}

pub fn typing_ephemeral_for_space(
    state: &AppState,
    space_id: &str,
    session: Option<&SessionRecord>,
) -> Vec<serde_json::Value> {
    if session.is_none() {
        return Vec::new();
    }
    let mut by_scope = std::collections::BTreeMap::<String, Vec<serde_json::Value>>::new();
    let typing_records = state
        .persistence
        .typing()
        .list_for_space(space_id)
        .unwrap_or_default();
    for record in &typing_records {
        let scope_id = record
            .scope_id
            .clone()
            .unwrap_or_else(|| record.space_id.clone());
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
                "type": "cx.typing",
                "space_id": space_id,
                "scope_id": scope_id,
                "actors": actors,
            })
        })
        .collect()
}
