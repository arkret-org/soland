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

use std::collections::BTreeMap;

use arkret_identifiers::{RealmId, SpaceId};
use arkret_models_collaboration::governance::realm_governance::{
    RealmExport, RealmExportSchema, RealmLifecycleView,
};
use arkret_wire::PlaintextDataClassKind;
use chrono::{DateTime, Utc};
use salvo::oapi::extract::PathParam;
use salvo::prelude::*;
use serde::Serialize;
use serde_json::Value;
use soland_http::error::AppError;
use soland_services::identity::SessionIdentityState as SessionRecord;
use soland_services::operation_semantics::CHILD_ORDER_CELL_FAMILY;

use super::AuthArgs;
use crate::state::{AppState, RealmDirectoryEntry};
use crate::wire::now;
use crate::{JsonResult, json_ok};

/// Spec `realm_read` operation group (`ak.self.realm.*`): Realm lifecycle read
/// and full export. Canonical path
/// `/_arkret/self/realms/{realm_id}*`.
pub(super) fn protocol_router() -> Router {
    Router::new().push(
        Router::with_path("realms/{realm_id}")
            .get(get_realm)
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

#[salvo::oapi::endpoint(operation_id = "ak.self.realm.resource.get", tags("spaces"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm.resource.get.v1"))]
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
#[tracing::instrument(skip_all, fields(op = "ak.self.realm.read.export.v1"))]
async fn export_realm(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<RealmExport> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let typed_realm_id =
        RealmId::new(realm_id.clone()).map_err(|_| AppError::param_invalid("invalid realm_id"))?;
    if !realm_id_accessible(state, &realm_id, Some(&session)).await {
        return Err(AppError::not_found("not found"));
    }
    let projected_events = state
        .event_queries()
        .projected_events_for_realm(&realm_id)
        .await
        .map_err(|error| AppError::internal(format!("realm export failed: {error}")))?;
    let operations = projected_events
        .iter()
        .filter_map(|event| {
            event.operation_id.as_ref().map(|operation_id| {
                BTreeMap::from([
                    (
                        "operation_id".to_owned(),
                        Value::String(operation_id.clone()),
                    ),
                    ("realm_id".to_owned(), Value::String(event.realm_id.clone())),
                    (
                        "object_kind".to_owned(),
                        Value::String(event.event_kind.as_str().to_owned()),
                    ),
                    (
                        "operation_kind".to_owned(),
                        Value::String(event.operation_kind.clone()),
                    ),
                    ("payload".to_owned(), event.payload.clone()),
                    (
                        "created_at".to_owned(),
                        Value::String(arkret_canonical::format_timestamp_canonical(
                            event.created_at,
                        )),
                    ),
                ])
            })
        })
        .collect::<Vec<_>>();
    let events = projected_events
        .into_iter()
        .map(|event| {
            let mut exported = BTreeMap::from([
                ("event_id".to_owned(), Value::String(event.event_id)),
                ("realm_id".to_owned(), Value::String(event.realm_id)),
                (
                    "event_kind".to_owned(),
                    Value::String(event.event_kind.as_str().to_owned()),
                ),
                (
                    "operation_kind".to_owned(),
                    Value::String(event.operation_kind),
                ),
                ("payload".to_owned(), event.payload),
                (
                    "created_at".to_owned(),
                    Value::String(arkret_canonical::format_timestamp_canonical(
                        event.created_at,
                    )),
                ),
            ]);
            if let Some(operation_id) = event.operation_id {
                exported.insert("operation_id".to_owned(), Value::String(operation_id));
            }
            if let Some(sender) = event.sender {
                exported.insert("sender".to_owned(), Value::String(sender));
            }
            exported
        })
        .collect();
    json_ok(RealmExport {
        schema: RealmExportSchema::V1,
        realm_id: typed_realm_id,
        generated_at: now(),
        operations,
        events,
    })
}

fn validate_child_order_subject(space_id: &str) -> Result<(), AppError> {
    SpaceId::new(space_id.to_owned()).map_err(|_| AppError::param_invalid("invalid space_id"))?;
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
        .map_err(|_| AppError::param_invalid("invalid realm_id"))?;
    let members: Vec<arkret_wire::ActorId> = {
        let projection = state.projections().snapshot();
        projection
            .members
            .values()
            .filter(|member| member.realm_id == realm_id && member.state == "join")
            .map(|member| {
                serde_json::from_str(&member.member).map_err(|error| {
                    AppError::internal(format!("stored Realm member is invalid: {error}"))
                })
            })
            .collect::<Result<_, _>>()?
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
    let owner_id = serde_json::from_str::<arkret_wire::ActorId>(&record.owner)
        .map(|actor| actor.signing_principal_id().clone())
        .map_err(|error| AppError::internal(format!("stored realm owner is invalid: {error}")))?;
    Ok(RealmLifecycleView {
        realm_id: realm_id_value,
        owner_id,
        member_ids: members,
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

pub async fn realm_history_access(state: &AppState, realm_or_internal_id: &str) -> String {
    match realm_scope_to_realm_id(realm_or_internal_id) {
        Some(realm_id) => realm_history_access_for_id(state, &realm_id).await,
        None => "since_join".to_owned(),
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
    _sender: Option<&str>,
    session: Option<&SessionRecord>,
) -> bool {
    let Some(session) = session else {
        return false;
    };
    let Ok(actor) =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)
    else {
        return false;
    };
    let actor_key = actor.to_string();
    if !realm_active_member_at_read_time(state, realm_or_internal_id, &actor_key).await {
        return false;
    }
    match realm_history_access(state, realm_or_internal_id)
        .await
        .as_str()
    {
        "all_history_for_current_members" => true,
        "since_join" => realm_member_joined_at(state, realm_or_internal_id, &actor_key)
            .await
            .is_some_and(|joined_at| event_created_at >= joined_at),
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
            .realm_null_subject_cell_value(realm_id, arkret_wire::CellFamilyId::REALM_DISCOVERY_V1)
            .and_then(|value| {
                value
                    .get("value")
                    .and_then(Value::as_str)
                    .or_else(|| value.as_str())
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

pub async fn realm_has_member_by_id(state: &AppState, realm_id: &str, actor: &str) -> bool {
    if realm_meta_deleted(state, realm_id).await {
        tracing::warn!(%realm_id, %actor, "realm_has_member_by_id: realm marked deleted");
        return false;
    }
    let Ok(_realm_id_typed) = RealmId::new(realm_id.to_owned()) else {
        tracing::warn!(%realm_id, %actor, "realm_has_member_by_id: invalid realm_id shape");
        return false;
    };
    let Ok(actor_typed) = serde_json::from_str::<arkret_wire::ActorId>(actor) else {
        tracing::warn!(%realm_id, %actor, "realm_has_member_by_id: invalid ActorId shape");
        return false;
    };
    if state
        .projections()
        .snapshot()
        .realm_is_principal_control_for_actor(realm_id, actor)
    {
        return true;
    }
    {
        let projection = state.projections().snapshot();
        if !projection
            .member(realm_id, actor)
            .is_some_and(|member| member.state == "join")
        {
            return false;
        }
        if projection
            .agent_membership_binding(realm_id, actor)
            .is_none()
        {
            return true;
        }
        if !projection.effective_agent_membership_base(realm_id, actor) {
            return false;
        }
    }
    if matches!(&actor_typed, arkret_wire::ActorId::Account { account_id: arkret_wire::AccountId { station_id, .. } } if *station_id == state.service_core_id())
        && let Ok(Some(agent)) = state
            .agent_pairings()
            .agent(actor_typed.signing_principal_id().as_str())
            .await
        && crate::routing::identity::agent_pcr::validate_effective_agent_realm_membership(
            state,
            &agent,
            realm_id,
            chrono::Utc::now(),
        )
        .await
        .is_err()
    {
        return false;
    }
    // Only the exact projected member and its effective Agent binding prove
    // membership. Principal-only directory entries are not authority.
    true
}

pub async fn realm_search_visible_to(
    state: &AppState,
    realm: &RealmDirectoryEntry,
    session: Option<&SessionRecord>,
) -> bool {
    if realm_meta_deleted(state, realm.realm_id.as_str()).await {
        return false;
    }
    if realm_id_accessible_for_id(state, realm.realm_id.as_str(), session).await {
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
    if realm_id_accessible_for_id(state, realm.realm_id.as_str(), session).await {
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

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum InviteTokenRealmResolution {
    NotFound,
    FrontierUnavailable,
    Ready {
        realm_id: String,
        seal_basis: arkret_wire::SealBasis,
    },
}

pub async fn invite_token_realm_id(state: &AppState, token: &str) -> Option<String> {
    match invite_token_realm_resolution(state, token).await {
        InviteTokenRealmResolution::Ready { realm_id, .. } => Some(realm_id),
        InviteTokenRealmResolution::NotFound | InviteTokenRealmResolution::FrontierUnavailable => {
            None
        }
    }
}

/// Resolve an Invite token only after the Invite's registered lifecycle write
/// is part of the exact accepted control-Seal view that will be disclosed to
/// the pre-join client.
///
/// `realm_invites` is a live ingress projection: an accepted `invite.create`
/// can appear there before the notary has closed its `null -> pending` write
/// into a durable Seal. Returning the then-current Realm leaves would invite a
/// client to author `invite.accept` against a pre-create state and
/// deterministically produce the illegal `null -> accepted` transition. Keep
/// that provisional window distinct from an invalid token so the route can
/// return the canonical retryable `frontier_unavailable` error without
/// inventing a client-side wait.
pub(crate) async fn invite_token_realm_resolution(
    state: &AppState,
    token: &str,
) -> InviteTokenRealmResolution {
    let token = token.trim();
    if token.is_empty() {
        return InviteTokenRealmResolution::NotFound;
    }
    let now = now();
    let Ok(invites) = state.realm_invites().snapshot_all().await else {
        return InviteTokenRealmResolution::FrontierUnavailable;
    };
    let Some(invite) = invites.into_iter().find(|invite| {
        invite.status == "pending"
            && invite.invite_token == token
            && invite.expires_at.is_none_or(|expires_at| expires_at > now)
    }) else {
        return InviteTokenRealmResolution::NotFound;
    };

    let Ok(realm_id) = RealmId::new(invite.realm_id.clone()) else {
        return InviteTokenRealmResolution::FrontierUnavailable;
    };
    let Ok(mut leaves) = state.projections().realm_seal_leaves(&realm_id).await else {
        return InviteTokenRealmResolution::FrontierUnavailable;
    };
    leaves.sort();
    let seal_basis = arkret_wire::SealBasis { leaves };
    if seal_basis.validate_protocol_bounds().is_err() {
        return InviteTokenRealmResolution::FrontierUnavailable;
    }
    let Ok(covered_events) = state
        .projections()
        .predecessor_covered_events(&seal_basis.leaves)
        .await
    else {
        return InviteTokenRealmResolution::FrontierUnavailable;
    };
    let Ok(lifecycle_cell) = arkret_identifiers::CellRef::new(format!(
        "ak:cell:ak.component.invite.lifecycle.v1:{}",
        invite.invite_id
    )) else {
        return InviteTokenRealmResolution::FrontierUnavailable;
    };
    let Ok(batches) = state
        .projections()
        .sealed_op_batches_for_cell(&realm_id, &lifecycle_cell)
        .await
    else {
        return InviteTokenRealmResolution::FrontierUnavailable;
    };
    let batches = batches
        .into_iter()
        .filter_map(|(_, ops)| {
            let covered_ops = ops
                .into_iter()
                .filter(|issued| covered_events.contains(&issued.op.move_id))
                .collect::<Vec<_>>();
            (!covered_ops.is_empty()).then_some(covered_ops)
        })
        .collect::<Vec<_>>();
    if batches.is_empty() {
        return InviteTokenRealmResolution::FrontierUnavailable;
    }
    let Ok(binding) = state.projections().resolve_cell(&realm_id, &lifecycle_cell) else {
        return InviteTokenRealmResolution::FrontierUnavailable;
    };
    let lifecycle =
        arkret_state::join_cell_seal_batches(binding.lattice.as_ref(), &lifecycle_cell, &batches)
            .into_value();
    match lifecycle
        .as_ref()
        .and_then(|value| value.as_str().or_else(|| value.get("state")?.as_str()))
    {
        Some("pending") => InviteTokenRealmResolution::Ready {
            realm_id: invite.realm_id,
            seal_basis,
        },
        Some(_) => InviteTokenRealmResolution::NotFound,
        None => InviteTokenRealmResolution::FrontierUnavailable,
    }
}

// `realm_id_accessible_for_id` is the visibility path with looser semantics
// for the backfill / subscribe edge.

/// Check if a Realm is accessible for backfill/subscribe.
///
/// Data-plane backfill and subscription require current Realm membership.
/// Discoverability and the history range ratchet never grant timeline access.
pub async fn realm_id_accessible_for_id(
    state: &AppState,
    realm_id: &str,
    session: Option<&SessionRecord>,
) -> bool {
    let Some(session) = session else {
        return false;
    };
    let Ok(actor) =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)
    else {
        return false;
    };
    realm_has_member_by_id(state, realm_id, &actor.to_string()).await
}

/// Look up the current one-way `history_access` ratchet value. Missing or
/// unrecognized state fails closed to `since_join`.
pub async fn realm_history_access_for_id(state: &AppState, realm_id: &str) -> String {
    if let Some(value) = state
        .projections()
        .snapshot()
        .realm_history_access(realm_id)
    {
        return value;
    }
    state
        .realms()
        .realm_metadata(realm_id)
        .await
        .ok()
        .flatten()
        .map(|record| record.history_access.clone())
        .filter(|value| {
            matches!(
                value.as_str(),
                "since_join" | "all_history_for_current_members"
            )
        })
        .unwrap_or_else(|| "since_join".to_owned())
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
/// `history_access=since_join` instead of leaking pre-join history.
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
    let actor_id = serde_json::from_str::<arkret_wire::ActorId>(actor).ok()?;
    let account_key = actor_id
        .as_account_id()
        .and_then(|account| account.canonical_key().ok());
    {
        let projection = state.projections().snapshot();
        if let Some(member) = projection.member(realm_id, actor) {
            if let Some(invited_at) = member.invited_at {
                return Some(invited_at);
            }
            if member.state == "join" {
                return Some(member.updated_at);
            }
        }
    }
    // A private invite delivery is deliberately not projected as shared
    // Realm membership state, but it is still the invitee_id's authoritative
    // pre-join evidence. Account-client authoring surfaces must recognize it
    // so the invitee_id can obtain an empty actor frontier and submit the
    // invite-accept Control Move without widening general Realm reads.
    let now = now();
    if let Some(invited_at) = state
        .realm_invites()
        .snapshot_all()
        .await
        .ok()
        .into_iter()
        .flatten()
        .filter(|invite| {
            invite.realm_id == realm_id
                && account_key
                    .as_ref()
                    .is_some_and(|account| invite.invitee_id.as_ref() == Some(account))
                && invite.status == "pending"
                && invite.expires_at.is_none_or(|expires_at| expires_at > now)
        })
        .map(|invite| invite.created_at)
        .min()
    {
        return Some(invited_at);
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

pub async fn realm_allows_plaintext_service_for_data_class_id(
    state: &AppState,
    realm_id: &str,
    data_class: PlaintextDataClassKind,
) -> bool {
    state
        .realms()
        .realm_metadata(realm_id)
        .await
        .ok()
        .flatten()
        .is_some_and(|record| record.allows_plaintext_data_class(state.service_id(), data_class))
}

#[cfg(test)]
mod tests {
    use arkret_identifiers::DidCoreId;
    use chrono::TimeZone;
    use serde_json::json;
    use soland_services::events::RealmInviteState;

    use super::*;

    const LIFECYCLE_ACTOR: &str = "ak:did_core:web:owner.example";
    const LIFECYCLE_REALM: &str = "ak:realm:AQcksDTzb8Sxrn1BUVVlHtH4vBOy99RKUB4EwOq_413b";
    const LIFECYCLE_INVITE: &str = "ak:invite:ATDCCDepUfY2x8Ah8veGLjoJl1foYqzljIn1qxn7iDSg";

    fn test_hash(byte: u8) -> arkret_identifiers::Hash {
        arkret_identifiers::Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32)))
            .unwrap()
    }

    fn test_seal(
        predecessor_refs: Vec<arkret_identifiers::SealId>,
        delta: Vec<arkret_identifiers::Hash>,
        notary_seq: u64,
    ) -> arkret_wire::Seal {
        let mut seal = arkret_wire::Seal {
            id: arkret_identifiers::SealId::new(format!("ak:seal:sha256:{}", "0".repeat(64)))
                .unwrap(),
            realm_id: RealmId::new(LIFECYCLE_REALM.to_owned()).unwrap(),
            predecessor_refs,
            delta,
            control_event_set_root: test_hash(0x22),
            state_root: test_hash(0x77),
            completeness_root: test_hash(0x33),
            notary_seq,
            data_view_root: None,
            data_event_set_root: None,
            availability_receipt_digests: Vec::new(),
            covered_event_digests: Vec::new(),
            previous_state_root: None,
            previous_digest_algorithm: None,
            notary_signature: arkret_wire::seal::NotarySig::Single(arkret_wire::SealSignature {
                verification_method: arkret_wire::DidUrl::new("did:web:notary.example#k1").unwrap(),
                payload_digest: test_hash(0xff),
                jws: "AAAA.BBBB.CCCC".to_owned(),
            }),
            sealed_at: chrono::Utc
                .with_ymd_and_hms(2026, 8, 29, 0, 0, notary_seq as u32)
                .unwrap(),
            hlc: arkret_identifiers::Hlc::new(format!("019041000000-{notary_seq:04x}-aabbccdd"))
                .unwrap(),
        };
        seal.id = seal
            .derive_id(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        seal
    }

    fn test_state() -> AppState {
        AppState::new(
            crate::config::AppConfig {
                seed_demo_data: false,
                ..crate::config::AppConfig::test_default()
            },
            soland_storage_postgres::Db { pool: None },
        )
    }

    /// The durable invite row stores complete Account ids, so a fixture cannot
    /// use a bare principal core id for either party.
    fn lifecycle_account(state: &AppState, principal: &str) -> arkret_wire::AccountId {
        arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(principal).unwrap(),
            state.service_core_id(),
        )
    }

    async fn put_pending_invite(state: &AppState, token: &str) {
        state
            .realm_invites()
            .put(RealmInviteState {
                invite_id: LIFECYCLE_INVITE.to_owned(),
                realm_id: LIFECYCLE_REALM.to_owned(),
                inviter_id: lifecycle_account(state, LIFECYCLE_ACTOR)
                    .canonical_key()
                    .unwrap(),
                invitee_id: Some(
                    lifecycle_account(state, "ak:did_core:web:bob.example")
                        .canonical_key()
                        .unwrap(),
                ),
                introduction_evidence_digest: None,
                third_party_invite: None,
                invite_token: token.to_owned(),
                status: "pending".to_owned(),
                claim_nonces: Default::default(),
                expires_at: None,
                created_at: "2026-08-14T00:00:00.000Z".parse().unwrap(),
                updated_at: None,
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn invite_token_waits_for_pending_lifecycle_to_be_sealed() {
        let state = test_state();
        put_pending_invite(&state, "barrier-token").await;

        let old_seal = test_seal(Vec::new(), Vec::new(), 1);
        state
            .projections()
            .test_put_seal(&old_seal, arkret_canonical::DigestSuite::Sha256)
            .await
            .unwrap();

        assert_eq!(
            invite_token_realm_resolution(&state, "barrier-token").await,
            InviteTokenRealmResolution::FrontierUnavailable
        );

        let create_move = test_hash(0x44);
        let create_seal = test_seal(vec![old_seal.id], vec![create_move.clone()], 2);
        state
            .projections()
            .test_put_seal(&create_seal, arkret_canonical::DigestSuite::Sha256)
            .await
            .unwrap();
        let lifecycle_cell = arkret_identifiers::CellRef::new(format!(
            "ak:cell:ak.component.invite.lifecycle.v1:{LIFECYCLE_INVITE}"
        ))
        .unwrap();
        state
            .projections()
            .test_append_sealed_effects(
                &RealmId::new(LIFECYCLE_REALM.to_owned()).unwrap(),
                &create_seal.id,
                &[(
                    lifecycle_cell,
                    arkret_state::lattice::ordered_log::IssuedOp {
                        issuer_id: arkret_wire::ActorId::service(crate::test_actor_id_str(
                            "did:web:owner.example",
                        )),
                        op: arkret_state::lattice::SealedOp::new(
                            create_move,
                            arkret_wire::LatticeOp {
                                op_type: arkret_wire::LatticeOpType::Transition,
                                tag: None,
                                value: None,
                                from: Some(json!(null)),
                                to: Some(json!("pending")),
                                reason: None,
                                issuer_seq: None,
                            },
                        ),
                    },
                )],
            )
            .await
            .unwrap();

        assert_eq!(
            invite_token_realm_resolution(&state, "barrier-token").await,
            InviteTokenRealmResolution::Ready {
                realm_id: LIFECYCLE_REALM.to_owned(),
                seal_basis: arkret_wire::SealBasis {
                    leaves: vec![create_seal.id],
                },
            }
        );
    }

    #[tokio::test]
    async fn private_pending_invite_is_pre_join_authoring_evidence() {
        let state = test_state();
        let account = arkret_wire::AccountId::new(
            DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
            state.service_core_id().clone(),
        );
        let invitee_id = arkret_wire::ActorId::account(account.clone()).to_string();
        let invited_at = "2026-08-14T00:00:00.000Z".parse().unwrap();
        state
            .realm_invites()
            .put(RealmInviteState {
                invite_id: "ak:invite:ATDCCDepUfY2x8Ah8veGLjoJl1foYqzljIn1qxn7iDSg".to_owned(),
                realm_id: LIFECYCLE_REALM.to_owned(),
                inviter_id: lifecycle_account(&state, LIFECYCLE_ACTOR)
                    .canonical_key()
                    .unwrap(),
                invitee_id: Some(account.canonical_key().unwrap()),
                introduction_evidence_digest: None,
                third_party_invite: None,
                invite_token: "private-token".to_owned(),
                status: "pending".to_owned(),
                claim_nonces: Default::default(),
                expires_at: None,
                created_at: invited_at,
                updated_at: None,
            })
            .await
            .unwrap();

        assert_eq!(
            realm_member_invited_or_joined_at_for_id(&state, LIFECYCLE_REALM, &invitee_id).await,
            Some(invited_at)
        );
        assert_eq!(
            realm_member_invited_or_joined_at_for_id(
                &state,
                LIFECYCLE_REALM,
                "ak:did_core:web:mallory.example"
            )
            .await,
            None
        );
        let other_station_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            account.principal_id,
            DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        ));
        assert_eq!(
            realm_member_invited_or_joined_at_for_id(
                &state,
                LIFECYCLE_REALM,
                &other_station_actor.to_string()
            )
            .await,
            None
        );
    }

    #[tokio::test]
    async fn joined_agent_cannot_bypass_an_ineffective_controller_binding() {
        let state = test_state();
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
            state.service_core_id(),
        ));
        let actor_key = actor.to_string();
        let now = chrono::Utc::now();
        state.test_projection().lock().members.insert(
            (LIFECYCLE_REALM.to_owned(), actor_key.clone()),
            soland_domain::reducer::SolandMembershipState {
                member: actor_key.clone(),
                realm_id: LIFECYCLE_REALM.to_owned(),
                state: "join".to_owned(),
                role: "member".to_owned(),
                membership_event_ref: None,
                invited_at: None,
                joined_at: now,
                updated_at: now,
                reason: None,
            },
        );
        state.test_projection().lock().agent_membership_bindings.insert(
            (LIFECYCLE_REALM.to_owned(), actor_key.clone()),
            arkret_models_collaboration::governance::agent_membership_cascade::AgentControllerMembershipBinding {
                controller_account_id: arkret_wire::AccountId::new(
                    DidCoreId::new(LIFECYCLE_ACTOR).unwrap(), state.service_core_id()),
                controller_membership_generation_ref: arkret_identifiers::EventId::new(
                    "ak:event:AeJsr0sf3TZ_Cuzj2uLddhd-O-Cywvdj8ypnqpVG8zim").unwrap(),
                controller_terminal_event_ref: None,
            },
        );
        assert!(!realm_has_member_by_id(&state, LIFECYCLE_REALM, &actor_key).await);
    }

    #[tokio::test]
    async fn principal_directory_entry_does_not_authorize_an_account() {
        let state = test_state();
        let principal = DidCoreId::new(LIFECYCLE_ACTOR).unwrap();
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            state.service_core_id().clone(),
        ));
        let mut entry = soland_services::events::RealmDirectoryEntry::new(
            RealmId::new(LIFECYCLE_REALM).unwrap(),
            "discovery only",
            soland_services::events::DirectoryProvenance::LocalOnly,
        );
        entry.members.insert(principal);
        state.realm_directory().upsert(entry);
        assert!(!realm_has_member_by_id(&state, LIFECYCLE_REALM, &actor.to_string()).await);
    }
}
