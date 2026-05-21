//! Space lifecycle + membership handlers.
//!
//! Surfaces:
//! - `POST   /api/v1/spaces` — create a space, optionally invite peers
//! - `PATCH  /api/v1/spaces/{space_id}` — owner updates title / summary / visibility
//! - `PUT    /api/v1/spaces/{space_id}/policy` — owner updates coarse join/history policy
//! - `POST   /api/v1/spaces/{space_id}/members` — owner adds a member
//! - `DELETE /api/v1/spaces/{space_id}/members/{member_did}` — owner removes a member
//! - `DELETE /api/v1/spaces/{space_id}` — owner soft-deletes the space
//! - `GET    /api/v1/spaces/{space_id}/export` — full event log + projection dump
//!
//! Plus the visibility / membership / typing query helpers and the
//! `record_space_lifecycle_operation` writer: every other domain
//! (federation, message, blob, directory, mimi, …) calls into this layer to
//! resolve "is this actor allowed to see / write to this Space?".

use chrono::{DateTime, Duration, Utc};
use contrix_sdk::{Did, Operation, OperationId, RealmId, SpaceId};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{
    AuthArgs, accept_local_operations, append_audit_log, generate_invite_token,
    is_valid_discoverability, now, validate_did, validate_space_id,
};
use crate::error::{AppError, ErrorCode};
use crate::state::{AppState, RealmDirectoryEntry, RealmMetaRecord, SessionRecord, SpaceInviteRecord};
use crate::wire::{
    AcceptSpaceInviteRequest, AddSpaceMemberRequest, CreateSpaceInviteRequest, CreateSpaceRequest,
    SetSpacePolicyRequest, SpaceInviteResponse, SpaceLifecycleResponse, SpacePolicyResponse,
    UpdateSpaceRequest, UpdateSpaceResponse,
};
use crate::{JsonResult, ids, json_ok, kinds};

pub(super) fn router() -> Router {
    Router::with_path("spaces")
        .post(create_space)
        .push(
            Router::with_path("{space_id}")
                .get(get_space)
                .patch(update_space)
                .delete(delete_space),
        )
        .push(Router::with_path("{space_id}/policy").put(set_space_policy))
        .push(Router::with_path("{space_id}/export").get(export_space))
        .push(Router::with_path("{space_id}/members").post(add_space_member))
        .push(Router::with_path("{space_id}/members/{member_did}").delete(remove_space_member))
        .push(Router::with_path("{space_id}/invite").post(create_space_invite))
        .push(Router::with_path("{space_id}/invite/accept").post(accept_space_invite))
}

#[endpoint(
    operation_id = "cx.extension.soland.spaces.get",
    tags("spaces"),
    summary = "Get a Space's lifecycle response (owner + members)"
)]
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
    operation_id = "cx.extension.soland.spaces.create",
    tags("spaces"),
    summary = "Create a Space, optionally inviting peers",
    status_codes(201, 400, 401, 409, 500)
)]
async fn create_space(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
    body: JsonBody<CreateSpaceRequest>,
) -> JsonResult<SpaceLifecycleResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    if body.title.trim().is_empty() {
        return Err(AppError::missing_param("title is required"));
    }
    for invitee in &body.invitees {
        if validate_did(invitee).is_err() {
            return Err(AppError::invalid_param("invalid invitee did"));
        }
    }
    for service_did in &body.plaintext_visible_services {
        if validate_did(service_did).is_err() {
            return Err(AppError::invalid_param(
                "invalid plaintext_visible_services did",
            ));
        }
    }
    let discoverability = body.discoverability.clone().unwrap_or_else(|| {
        if body.public {
            "public".to_owned()
        } else {
            "invite_only".to_owned()
        }
    });
    if !is_valid_discoverability(&discoverability) {
        return Err(AppError::invalid_param("invalid discoverability"));
    }
    let history_visibility = body.history_visibility.clone().unwrap_or_else(|| {
        if discoverability == "public" {
            "shared".to_owned()
        } else {
            "joined".to_owned()
        }
    });
    if !matches!(
        history_visibility.as_str(),
        "shared" | "joined" | "invited" | "world_readable"
    ) {
        return Err(AppError::invalid_param("invalid history_visibility"));
    }
    let encryption_profile = body
        .encryption_profile
        .clone()
        .filter(|value| !value.trim().is_empty());
    if let Some(profile) = encryption_profile.as_deref() {
        if !matches!(profile, "plaintext" | "mls_rfc9420") {
            return Err(AppError::invalid_param("invalid encryption_profile"));
        }
        if profile == "mls_rfc9420" && history_visibility == "world_readable" {
            // space-and-place.md §3.1.3 — MLS-encrypted Spaces cannot be
            // world_readable because non-members lack the group key.
            return Err(AppError::invalid_param(
                "encryption_profile=mls_rfc9420 is incompatible with history_visibility=world_readable",
            )
            .with_wire_code("incompatible_history_with_encryption"));
        }
    }
    let invitees = body.invitees.clone();
    let plaintext_visible_services = body.plaintext_visible_services.clone();
    let space_id = ids::generate_realm_id();
    let mut entry = RealmDirectoryEntry::new(
        RealmId::new(space_id.clone()).expect("generated valid Realm id"),
        body.title.trim(),
    );
    entry.description = body.summary;
    entry.public = discoverability == "public";
    entry
        .members
        .insert(Did::new(session.actor.clone()).expect("session did is valid"));

    state.realms.lock().expect("spaces lock").upsert(entry);
    let meta = RealmMetaRecord {
        owner: session.actor.clone(),
        deleted: false,
        discoverability: discoverability.clone(),
        history_visibility: history_visibility.clone(),
        encryption_profile: encryption_profile.clone(),
        plaintext_visible_services: plaintext_visible_services.iter().cloned().collect(),
        created_at: now(),
        updated_at: now(),
    };
    if let Err(error) = state.persistence.realm_meta().put(&space_id, &meta) {
        tracing::error!(%error, "failed to persist Realm meta");
    }
    let invite_records: Vec<_> = invitees
        .iter()
        .map(|invitee| {
            let invite_id = ids::generate_invite_id();
            let invite_token = generate_invite_token(&invite_id, &space_id, invitee);
            SpaceInviteRecord {
                invite_id,
                space_id: space_id.clone(),
                inviter: session.actor.clone(),
                invitee: Some(invitee.clone()),
                invite_token,
                status: "pending".to_owned(),
                expires_at: Some(now() + Duration::days(7)),
                created_at: now(),
            }
        })
        .collect();
    for invite in &invite_records {
        if let Err(error) = state.persistence.space_invites().put(invite.clone()) {
            tracing::error!(%error, "failed to persist space invite");
        }
    }
    record_space_lifecycle_operation(
        state,
        &session.actor,
        &space_id,
        json!({
            "action": "create",
            "owner": session.actor.clone(),
            "members": [],
            "invitees": invitees,
            "invite_ids": invite_records
                .iter()
                .map(|invite| invite.invite_id.clone())
                .collect::<Vec<_>>(),
            "public": discoverability == "public",
            "discoverability": discoverability,
            "history_visibility": history_visibility,
            "encryption_profile": encryption_profile,
            "plaintext_visible_services": plaintext_visible_services,
        }),
    )
    .map_err(|error| {
        AppError::new(ErrorCode::Conflict, error.to_string()).with_status(StatusCode::CONFLICT)
    })?;

    res.status_code(StatusCode::CREATED);
    append_audit_log(
        state,
        Some(&session.actor),
        "space.create",
        json!({"space_id": space_id.clone()}),
        "accepted",
    );
    space_lifecycle_response(state, &space_id).map(salvo::prelude::Json)
}

#[endpoint(
    operation_id = "cx.extension.soland.spaces.update",
    tags("spaces"),
    summary = "Owner updates Space metadata and visibility"
)]
async fn update_space(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: PathParam<String>,
    body: JsonBody<UpdateSpaceRequest>,
) -> JsonResult<UpdateSpaceResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let space_id = space_id.into_inner();
    if !realm_owner_matches(state, &space_id, &session.actor) {
        return Err(AppError::capability_denied(
            "only the space owner can update the space",
        ));
    }
    let body = body.into_inner();
    if body
        .title
        .as_deref()
        .is_some_and(|title| title.trim().is_empty())
    {
        return Err(AppError::missing_param("title cannot be empty"));
    }
    let discoverability = body.discoverability.clone().or_else(|| {
        body.public
            .map(|public| if public { "public" } else { "invite_only" }.to_owned())
    });
    if discoverability
        .as_deref()
        .is_some_and(|value| !is_valid_discoverability(value))
    {
        return Err(AppError::invalid_param("invalid discoverability"));
    }
    if let Some(services) = body.plaintext_visible_services.as_ref() {
        for service_did in services {
            if validate_did(service_did).is_err() {
                return Err(AppError::invalid_param(
                    "invalid plaintext_visible_services did",
                ));
            }
        }
    }
    let space_id_value =
        RealmId::new(space_id.clone()).map_err(|_| AppError::invalid_param("invalid realm_id"))?;
    {
        let mut spaces = state.realms.lock().expect("spaces lock");
        let mut entry = spaces
            .get(&space_id_value)
            .cloned()
            .ok_or_else(|| AppError::not_found("not found"))?;
        if let Some(title) = body.title.as_deref() {
            entry.name = title.trim().to_owned();
        }
        if let Some(summary) = body.summary.clone() {
            entry.description = Some(summary);
        }
        if let Some(discoverability) = discoverability.as_deref() {
            entry.public = discoverability == "public";
        }
        spaces.upsert(entry);
    }
    {
        let store = state.persistence.realm_meta();
        let mut record = store
            .get(&space_id)
            .map_err(|error| AppError::internal(error.to_string()))?
            .ok_or_else(|| AppError::not_found("not found"))?;
        if let Some(discoverability) = discoverability.clone() {
            record.discoverability = discoverability;
        }
        if let Some(services) = body.plaintext_visible_services {
            record.plaintext_visible_services = services.into_iter().collect();
        }
        record.updated_at = now();
        store
            .put(&space_id, &record)
            .map_err(|error| AppError::internal(error.to_string()))?;
    }
    record_space_lifecycle_operation(
        state,
        &session.actor,
        &space_id,
        json!({
            "action": "update",
            "title": body.title,
            "summary": body.summary,
            "discoverability": discoverability,
        }),
    )
    .map_err(|error| {
        AppError::new(ErrorCode::Conflict, error.to_string()).with_status(StatusCode::CONFLICT)
    })?;
    append_audit_log(
        state,
        Some(&session.actor),
        "space.update",
        json!({"space_id": space_id.clone()}),
        "accepted",
    );
    json_ok(UpdateSpaceResponse { ok: true, space_id })
}

#[endpoint(
    operation_id = "cx.extension.soland.spaces.set_policy",
    tags("spaces"),
    summary = "Owner updates coarse Space join and history policy"
)]
async fn set_space_policy(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: PathParam<String>,
    body: JsonBody<SetSpacePolicyRequest>,
) -> JsonResult<SpacePolicyResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let space_id = space_id.into_inner();
    if !realm_owner_matches(state, &space_id, &session.actor) {
        return Err(AppError::capability_denied(
            "only the space owner can update policy",
        ));
    }
    let body = body.into_inner();
    let join_rule = body.join_rule;
    let history_visibility = body.history_visibility;
    if !matches!(
        join_rule.as_str(),
        "public" | "invite_only" | "restricted" | "knock"
    ) {
        return Err(AppError::invalid_param("invalid join_rule"));
    }
    if !matches!(
        history_visibility.as_str(),
        "shared" | "joined" | "invited" | "world_readable"
    ) {
        return Err(AppError::invalid_param("invalid history_visibility"));
    }
    let discoverability = match join_rule.as_str() {
        "public" => "public",
        "restricted" => "restricted",
        _ => "invite_only",
    };
    {
        let store = state.persistence.realm_meta();
        let mut record = store
            .get(&space_id)
            .map_err(|error| AppError::internal(error.to_string()))?
            .ok_or_else(|| AppError::not_found("not found"))?;
        // space-and-place.md §3.1.3 — MLS-encrypted Spaces MUST NOT be flipped
        // to world_readable; reject the policy update fail-closed.
        if record.encryption_profile.as_deref() == Some("mls_rfc9420")
            && history_visibility == "world_readable"
        {
            return Err(AppError::invalid_param(
                "encryption_profile=mls_rfc9420 is incompatible with history_visibility=world_readable",
            )
            .with_wire_code("incompatible_history_with_encryption"));
        }
        record.discoverability = discoverability.to_owned();
        record.history_visibility = history_visibility.clone();
        record.updated_at = now();
        store
            .put(&space_id, &record)
            .map_err(|error| AppError::internal(error.to_string()))?;
    }
    {
        let space_id_value = RealmId::new(space_id.clone())
            .map_err(|_| AppError::invalid_param("invalid realm_id"))?;
        let mut spaces = state.realms.lock().expect("spaces lock");
        let mut entry = spaces
            .get(&space_id_value)
            .cloned()
            .ok_or_else(|| AppError::not_found("not found"))?;
        entry.public = discoverability == "public";
        spaces.upsert(entry);
    }
    record_space_lifecycle_operation(
        state,
        &session.actor,
        &space_id,
        json!({
            "action": "policy",
            "join_rule": join_rule,
            "history_visibility": history_visibility,
            "discoverability": discoverability,
        }),
    )
    .map_err(|error| {
        AppError::new(ErrorCode::Conflict, error.to_string()).with_status(StatusCode::CONFLICT)
    })?;
    append_audit_log(
        state,
        Some(&session.actor),
        "space.policy",
        json!({"space_id": space_id.clone()}),
        "accepted",
    );
    json_ok(SpacePolicyResponse {
        ok: true,
        space_id,
        join_rule,
        history_visibility,
    })
}

#[endpoint(
    operation_id = "cx.extension.soland.spaces.add_member",
    tags("spaces"),
    summary = "Owner adds a member to a Space"
)]
async fn add_space_member(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: PathParam<String>,
    body: JsonBody<AddSpaceMemberRequest>,
) -> JsonResult<SpaceLifecycleResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let space_id = space_id.into_inner();
    if !realm_owner_matches(state, &space_id, &session.actor) {
        return Err(AppError::capability_denied(
            "only the space owner can add members",
        ));
    }
    let body = body.into_inner();
    if validate_did(&body.member).is_err() {
        return Err(AppError::invalid_param("invalid member did"));
    }
    let space_id_value =
        RealmId::new(space_id.clone()).map_err(|_| AppError::invalid_param("invalid realm_id"))?;
    {
        let mut spaces = state.realms.lock().expect("spaces lock");
        let mut entry = spaces
            .get(&space_id_value)
            .cloned()
            .ok_or_else(|| AppError::not_found("not found"))?;
        entry
            .members
            .insert(Did::new(body.member.clone()).expect("validated did"));
        spaces.upsert(entry);
    }
    touch_space(state, &space_id);
    record_member_state_operation(
        state,
        &session.actor,
        &space_id,
        &body.member,
        "join",
        json!({}),
    )
    .map_err(|error| {
        AppError::new(ErrorCode::Conflict, error.to_string()).with_status(StatusCode::CONFLICT)
    })?;
    // The spec's event-kind-registry ships `cx.member.state` (a CRDT
    // state op on `cx.component.space.members.v1`). Analytics / audit
    // consumers derive join/leave transitions from the `cx.member.state`
    // payload's `membership` field (`join` / `leave` / `invite`) — no
    // separate `cx.membership.*` event kind exists.
    append_audit_log(
        state,
        Some(&session.actor),
        "space.member.add",
        json!({"space_id": space_id.clone(), "member": body.member}),
        "accepted",
    );
    space_lifecycle_response(state, &space_id).map(salvo::prelude::Json)
}

#[endpoint(
    operation_id = "cx.extension.soland.spaces.accept_invite",
    tags("spaces"),
    summary = "Invitee accepts a pending space invite and becomes a member"
)]
async fn accept_space_invite(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: PathParam<String>,
    body: JsonBody<AcceptSpaceInviteRequest>,
) -> JsonResult<SpaceInviteResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let space_id = space_id.into_inner();
    let body = body.into_inner();
    let invite_id = body.invite_id;

    // Locate the invite. invitee must match the session actor; not already
    // consumed; not expired.
    let invites_store = state.persistence.space_invites();
    let now_ts = now();
    let mut invite = invites_store
        .snapshot_all()
        .unwrap_or_default()
        .into_iter()
        .find(|r| r.invite_id == invite_id && r.space_id == space_id)
        .ok_or_else(|| AppError::not_found("invite not found"))?;
    if invite.status != "pending" {
        return Err(
            AppError::new(ErrorCode::Conflict, "invite already consumed")
                .with_status(StatusCode::CONFLICT),
        );
    }
    if invite
        .invitee
        .as_deref()
        .is_none_or(|invitee| invitee != session.actor)
    {
        return Err(AppError::capability_denied(
            "only the invitee can accept this invite",
        ));
    }
    if invite.expires_at.is_some_and(|exp| exp < now_ts) {
        return Err(
            AppError::new(ErrorCode::Conflict, "invite expired").with_status(StatusCode::CONFLICT)
        );
    }

    invite.status = "accepted".to_owned();
    if let Err(error) = invites_store.put(invite.clone()) {
        tracing::error!(%error, "failed to mark invite accepted");
    }

    // Add invitee to space members.
    let space_id_value =
        RealmId::new(space_id.clone()).map_err(|_| AppError::invalid_param("invalid realm_id"))?;
    {
        let mut spaces = state.realms.lock().expect("spaces lock");
        let mut entry = spaces
            .get(&space_id_value)
            .cloned()
            .ok_or_else(|| AppError::not_found("space not found"))?;
        entry
            .members
            .insert(Did::new(session.actor.clone()).expect("session did is valid"));
        spaces.upsert(entry);
    }
    touch_space(state, &space_id);
    record_member_state_operation(
        state,
        &session.actor,
        &space_id,
        &session.actor,
        "join",
        json!({"via": "invite", "invite_id": invite_id.clone()}),
    )
    .map_err(|error| {
        AppError::new(ErrorCode::Conflict, error.to_string()).with_status(StatusCode::CONFLICT)
    })?;
    append_audit_log(
        state,
        Some(&session.actor),
        "space.invite.accept",
        json!({"space_id": space_id.clone(), "invite_id": invite_id.clone()}),
        "accepted",
    );

    let target = invite.invitee.unwrap_or_else(|| session.actor.clone());
    json_ok(SpaceInviteResponse {
        ok: true,
        invite_id,
        space_id,
        target,
        state: "accepted".to_owned(),
    })
}

#[endpoint(
    operation_id = "cx.extension.soland.spaces.create_invite",
    tags("spaces"),
    summary = "Owner creates an invite to a Space for a target DID"
)]
async fn create_space_invite(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: PathParam<String>,
    body: JsonBody<CreateSpaceInviteRequest>,
) -> JsonResult<SpaceInviteResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let space_id = space_id.into_inner();
    let body = body.into_inner();
    let target = body.target.trim().to_owned();
    if validate_did(&target).is_err() {
        return Err(AppError::invalid_param("invalid target did"));
    }
    if !realm_owner_matches(state, &space_id, &session.actor) {
        return Err(AppError::capability_denied(
            "only the space owner can create invites",
        ));
    }

    let invites_store = state.persistence.space_invites();
    // Idempotent: if a pending invite already exists for this (space, target),
    // return it unchanged rather than duplicating.
    if let Some(existing) = invites_store
        .snapshot_all()
        .unwrap_or_default()
        .into_iter()
        .find(|r| {
            r.space_id == space_id
                && r.status == "pending"
                && r.invitee.as_deref() == Some(target.as_str())
        })
    {
        return json_ok(SpaceInviteResponse {
            ok: true,
            invite_id: existing.invite_id,
            space_id: existing.space_id,
            target: existing.invitee.unwrap_or(target),
            state: existing.status,
        });
    }

    let invite_id = ids::generate_invite_id();
    let invite_token = generate_invite_token(&invite_id, &space_id, &target);
    let invite = SpaceInviteRecord {
        invite_id: invite_id.clone(),
        space_id: space_id.clone(),
        inviter: session.actor.clone(),
        invitee: Some(target.clone()),
        invite_token,
        status: "pending".to_owned(),
        expires_at: Some(now() + Duration::days(7)),
        created_at: now(),
    };
    if let Err(error) = invites_store.put(invite.clone()) {
        tracing::error!(%error, "failed to persist space invite");
        return Err(AppError::new(
            ErrorCode::Conflict,
            "failed to persist invite",
        ));
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "space.invite.create",
        json!({"space_id": space_id.clone(), "invite_id": invite_id.clone(), "target": target.clone()}),
        "accepted",
    );

    json_ok(SpaceInviteResponse {
        ok: true,
        invite_id,
        space_id,
        target,
        state: "pending".to_owned(),
    })
}

#[endpoint(
    operation_id = "cx.extension.soland.spaces.remove_member",
    tags("spaces"),
    summary = "Owner removes a member from a Space"
)]
async fn remove_space_member(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: PathParam<String>,
    member_did: PathParam<String>,
) -> JsonResult<SpaceLifecycleResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let space_id = space_id.into_inner();
    let member_did = member_did.into_inner();
    if !realm_owner_matches(state, &space_id, &session.actor) {
        return Err(AppError::capability_denied(
            "only the space owner can remove members",
        ));
    }
    if member_did == session.actor {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "owner cannot remove self",
        ));
    }
    let space_id_value =
        RealmId::new(space_id.clone()).map_err(|_| AppError::invalid_param("invalid realm_id"))?;
    let member = Did::new(member_did).map_err(|_| AppError::invalid_param("invalid member did"))?;
    {
        let mut spaces = state.realms.lock().expect("spaces lock");
        let mut entry = spaces
            .get(&space_id_value)
            .cloned()
            .ok_or_else(|| AppError::not_found("not found"))?;
        entry.members.remove(&member);
        spaces.upsert(entry);
    }
    touch_space(state, &space_id);
    record_member_state_operation(
        state,
        &session.actor,
        &space_id,
        member.as_str(),
        "leave",
        json!({}),
    )
    .map_err(|error| {
        AppError::new(ErrorCode::Conflict, error.to_string()).with_status(StatusCode::CONFLICT)
    })?;
    // See `add_space_member`: `cx.member.state` (already recorded above
    // via `record_member_state_operation`) is the spec-correct
    // membership signal; no separate `cx.membership.leave` event exists.
    append_audit_log(
        state,
        Some(&session.actor),
        "space.member.remove",
        json!({"space_id": space_id.clone(), "member": member.to_string()}),
        "accepted",
    );
    space_lifecycle_response(state, &space_id).map(salvo::prelude::Json)
}

#[endpoint(
    operation_id = "cx.extension.soland.spaces.delete",
    tags("spaces"),
    summary = "Owner soft-deletes a Space"
)]
async fn delete_space(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: PathParam<String>,
) -> JsonResult<SpaceLifecycleResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let space_id = space_id.into_inner();
    if !realm_owner_matches(state, &space_id, &session.actor) {
        return Err(AppError::capability_denied(
            "only the space owner can delete the space",
        ));
    }
    {
        let store = state.persistence.realm_meta();
        let mut record = store
            .get(&space_id)
            .map_err(|error| AppError::internal(error.to_string()))?
            .ok_or_else(|| AppError::not_found("not found"))?;
        record.deleted = true;
        record.updated_at = now();
        store
            .put(&space_id, &record)
            .map_err(|error| AppError::internal(error.to_string()))?;
    }
    record_space_lifecycle_operation(
        state,
        &session.actor,
        &space_id,
        json!({
            "action": "delete",
            "deleted": true,
        }),
    )
    .map_err(|error| {
        AppError::new(ErrorCode::Conflict, error.to_string()).with_status(StatusCode::CONFLICT)
    })?;
    append_audit_log(
        state,
        Some(&session.actor),
        "space.delete",
        json!({"space_id": space_id.clone()}),
        "accepted",
    );
    space_lifecycle_response(state, &space_id).map(salvo::prelude::Json)
}

#[endpoint(
    operation_id = "cx.extension.soland.spaces.export",
    tags("spaces"),
    summary = "Full event log + projection dump for a Space"
)]
async fn export_space(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: PathParam<String>,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let space_id = space_id.into_inner();
    if validate_space_id(&space_id).is_err() {
        return Err(AppError::invalid_param("invalid space_id"));
    }
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
                "space_id": event["space_id"],
                "object_type": event["event_kind"],
                "operation_type": event["operation_type"],
                "payload": event["payload"],
                "created_at": event["created_at"],
            })
        })
        .collect::<Vec<_>>();
    json_ok(json!({
        "schema": "cx.export.space.v1",
        "space_id": space_id,
        "generated_at": now(),
        "operations": operations,
        "events": events,
    }))
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

pub fn space_owner_matches(state: &AppState, space_id: &str, actor: &str) -> bool {
    state
        .persistence
        .realm_meta()
        .get(space_id)
        .ok()
        .flatten()
        .is_some_and(|record| !record.deleted && record.owner == actor)
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

pub fn realm_owner_matches(state: &AppState, realm_or_internal_id: &str, actor: &str) -> bool {
    realm_scope_to_realm_id(realm_or_internal_id)
        .is_some_and(|realm_id| space_owner_matches(state, &realm_id, actor))
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
/// The reducer's member projection is authoritative when present. Older
/// rows and bootstrap owners predate that side-band cache, so current
/// members without a projected row fall back to the Space creation time.
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
    if space_has_member(state, space_id, actor) {
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

pub fn record_space_lifecycle_operation(
    state: &AppState,
    actor: &str,
    space_id: &str,
    payload: serde_json::Value,
) -> contrix_sdk::Result<Option<String>> {
    let Ok(space_id) = SpaceId::new(space_id.to_owned()) else {
        return Ok(None);
    };
    let operation = Operation::create(
        OperationId::new(ids::generate_operation_id()).expect("generated valid operation id"),
        space_id,
        match payload.get("action").and_then(serde_json::Value::as_str) {
            Some("create") => kinds::CX_SPACE_CREATE,
            Some("destroy") | Some("delete") => kinds::CX_SPACE_DESTROY,
            _ => kinds::CX_SPACE_UPDATE,
        },
        payload,
    );
    accept_local_operations(state, actor, std::slice::from_ref(&operation))
        .map_err(|message| contrix_sdk::Error::Protocol(message.to_owned()))?;
    Ok(None)
}

pub fn record_member_state_operation(
    state: &AppState,
    actor: &str,
    space_id: &str,
    member: &str,
    membership: &str,
    mut payload: serde_json::Value,
) -> contrix_sdk::Result<Option<String>> {
    payload["member"] = json!(member);
    payload["actor_id"] = json!(member);
    payload["membership"] = json!(membership);
    if membership == "join" && payload.get("delivery_status").is_none() {
        payload["delivery_status"] = json!("unroutable");
    }
    let Ok(space_id) = SpaceId::new(space_id.to_owned()) else {
        return Ok(None);
    };
    let operation = Operation::create(
        OperationId::new(ids::generate_operation_id()).expect("generated valid operation id"),
        space_id,
        kinds::CX_MEMBER_STATE,
        payload,
    );
    accept_local_operations(state, actor, std::slice::from_ref(&operation))
        .map_err(|message| contrix_sdk::Error::Protocol(message.to_owned()))?;
    Ok(None)
}
