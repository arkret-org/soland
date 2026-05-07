//! Space lifecycle + membership handlers.
//!
//! Surfaces:
//! - `POST   /api/v1/spaces` — create a space, optionally invite peers
//! - `POST   /api/v1/spaces/{space_id}/members` — owner adds a member
//! - `DELETE /api/v1/spaces/{space_id}/members/{member_did}` — owner removes a member
//! - `DELETE /api/v1/spaces/{space_id}` — owner soft-deletes the space
//! - `GET    /api/v1/spaces/{space_id}/export` — full event log + projection dump
//!
//! Plus the visibility / membership / typing query helpers and the
//! `record_space_lifecycle_operation` writer (round 10): every other domain
//! (federation, message, blob, directory, mimi, …) calls into this layer to
//! resolve "is this actor allowed to see / write to this Space?". These were
//! the last-but-one chunk to leave `mod.rs`; `next_author_seq` rides along
//! because the lifecycle writer needs it.

use chrono::Duration;
use contrix_sdk::{Commit, CommitId, Did, Hash, Operation, OperationId, SpaceId, SpaceSearchEntry};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use crate::{
    JsonResult,
    error::{AppError, ErrorCode},
    ids, json_ok, kinds,
    state::{AppState, SessionRecord, SpaceInviteRecord, SpaceMetaRecord},
    wire::{
        AddSpaceMemberRequest, CreateSpaceRequest, SpaceLifecycleResponse,
    },
};

use super::{
    AuthArgs, ProofVerifier, append_audit_log, append_projection_event, dev_proof,
    generate_invite_token, is_valid_discoverability, now, projection_event_from_operation,
    validate_did, validate_space_id,
};

#[endpoint(
    operation_id = "cx.spaces.create",
    tags("spaces"),
    summary = "Create a Space, optionally inviting peers",
    status_codes(201, 400, 401, 409, 500),
)]
pub async fn create_space(
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
    let invitees = body.invitees.clone();
    let plaintext_visible_services = body.plaintext_visible_services.clone();
    let space_id = ids::generate_space_id();
    let mut entry = SpaceSearchEntry::new(
        SpaceId::new(space_id.clone()).expect("generated valid space id"),
        body.title.trim(),
    );
    entry.description = body.summary;
    entry.public = discoverability == "public";
    entry
        .members
        .insert(Did::new(session.actor.clone()).expect("session did is valid"));

    state.spaces.lock().expect("spaces lock").upsert(entry);
    let meta = SpaceMetaRecord {
        owner: session.actor.clone(),
        deleted: false,
        discoverability: discoverability.clone(),
        plaintext_visible_services: plaintext_visible_services.iter().cloned().collect(),
        created_at: now(),
        updated_at: now(),
    };
    if let Err(error) = state.persistence.space_meta().put(&space_id, &meta) {
        tracing::error!(%error, "failed to persist space meta");
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
    operation_id = "cx.spaces.add_member",
    tags("spaces"),
    summary = "Owner adds a member to a Space",
)]
pub async fn add_space_member(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: PathParam<String>,
    body: JsonBody<AddSpaceMemberRequest>,
) -> JsonResult<SpaceLifecycleResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let space_id = space_id.into_inner();
    if !space_owner_matches(state, &space_id, &session.actor) {
        return Err(AppError::capability_denied(
            "only the space owner can add members",
        ));
    }
    let body = body.into_inner();
    if validate_did(&body.member).is_err() {
        return Err(AppError::invalid_param("invalid member did"));
    }
    let space_id_value = SpaceId::new(space_id.clone())
        .map_err(|_| AppError::invalid_param("invalid space_id"))?;
    {
        let mut spaces = state.spaces.lock().expect("spaces lock");
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
    record_space_lifecycle_operation(
        state,
        &session.actor,
        &space_id,
        json!({
            "action": "member.add",
            "member": body.member.clone(),
            "membership": "join",
        }),
    )
    .map_err(|error| {
        AppError::new(ErrorCode::Conflict, error.to_string()).with_status(StatusCode::CONFLICT)
    })?;
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
    operation_id = "cx.spaces.remove_member",
    tags("spaces"),
    summary = "Owner removes a member from a Space",
)]
pub async fn remove_space_member(
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
    if !space_owner_matches(state, &space_id, &session.actor) {
        return Err(AppError::capability_denied(
            "only the space owner can remove members",
        ));
    }
    if member_did == session.actor {
        return Err(AppError::new(ErrorCode::Conflict, "owner cannot remove self"));
    }
    let space_id_value = SpaceId::new(space_id.clone())
        .map_err(|_| AppError::invalid_param("invalid space_id"))?;
    let member = Did::new(member_did).map_err(|_| AppError::invalid_param("invalid member did"))?;
    {
        let mut spaces = state.spaces.lock().expect("spaces lock");
        let mut entry = spaces
            .get(&space_id_value)
            .cloned()
            .ok_or_else(|| AppError::not_found("not found"))?;
        entry.members.remove(&member);
        spaces.upsert(entry);
    }
    touch_space(state, &space_id);
    record_space_lifecycle_operation(
        state,
        &session.actor,
        &space_id,
        json!({
            "action": "member.remove",
            "member": member.to_string(),
            "membership": "leave",
        }),
    )
    .map_err(|error| {
        AppError::new(ErrorCode::Conflict, error.to_string()).with_status(StatusCode::CONFLICT)
    })?;
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
    operation_id = "cx.spaces.delete",
    tags("spaces"),
    summary = "Owner soft-deletes a Space",
)]
pub async fn delete_space(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: PathParam<String>,
) -> JsonResult<SpaceLifecycleResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let space_id = space_id.into_inner();
    if !space_owner_matches(state, &space_id, &session.actor) {
        return Err(AppError::capability_denied(
            "only the space owner can delete the space",
        ));
    }
    {
        let store = state.persistence.space_meta();
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
    operation_id = "cx.spaces.export",
    tags("spaces"),
    summary = "Full event log + projection dump for a Space",
)]
pub async fn export_space(
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
    let operations = state
        .repo
        .sync_space_operations(&space_id, None, 500)
        .map(|page| page.items)
        .map_err(|error| {
            AppError::new(ErrorCode::Conflict, error.to_string()).with_status(StatusCode::CONFLICT)
        })?;
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
                "event_type": event.event_type,
                "operation_type": event.operation_type,
                "operation_id": event.operation_id,
                "sender": event.sender,
                "payload": event.payload,
                "created_at": event.created_at,
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
// Each is re-exported from `crate::routing::*` so existing callers in `mod.rs`
// (e.g. `touch_space` from the projection writer at line ~12670) keep working.

pub fn space_lifecycle_response(
    state: &AppState,
    space_id: &str,
) -> Result<SpaceLifecycleResponse, AppError> {
    let space_id_value = SpaceId::new(space_id.to_owned())
        .map_err(|_| AppError::invalid_param("invalid space_id"))?;
    let spaces = state.spaces.lock().expect("spaces lock");
    let record = state
        .persistence
        .space_meta()
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
        .space_meta()
        .get(space_id)
        .ok()
        .flatten()
        .is_some_and(|record| !record.deleted && record.owner == actor)
}

pub fn touch_space(state: &AppState, space_id: &str) {
    let store = state.persistence.space_meta();
    if let Ok(Some(mut record)) = store.get(space_id) {
        record.updated_at = now();
        if let Err(error) = store.put(space_id, &record) {
            tracing::warn!(%error, "failed to touch space meta");
        }
    }
}

// ── Visibility + membership + typing query helpers ─────────────────────────

pub fn is_space_deleted(state: &AppState, space_id: &str) -> bool {
    state
        .persistence
        .space_meta()
        .get(space_id)
        .ok()
        .flatten()
        .is_some_and(|record| record.deleted)
}

pub fn space_discoverability(state: &AppState, space_id: &str) -> String {
    state
        .persistence
        .space_meta()
        .get(space_id)
        .ok()
        .flatten()
        .map(|record| record.discoverability)
        .unwrap_or_else(|| "invite_only".to_owned())
}

pub fn space_has_member(state: &AppState, space_id: &str, actor: &str) -> bool {
    if is_space_deleted(state, space_id) {
        return false;
    }
    let Ok(space_id) = SpaceId::new(space_id.to_owned()) else {
        return false;
    };
    let Ok(actor) = Did::new(actor.to_owned()) else {
        return false;
    };
    state
        .spaces
        .lock()
        .expect("spaces lock")
        .get(&space_id)
        .is_some_and(|space| space.members.contains(&actor))
}

pub fn space_visible_to(
    state: &AppState,
    space: &contrix_sdk::SpaceSearchEntry,
    session: Option<&SessionRecord>,
) -> bool {
    if is_space_deleted(state, space.space_id.as_str()) {
        return false;
    }
    if space_discoverability(state, space.space_id.as_str()) == "public" {
        return true;
    }
    session.is_some_and(|session| {
        Did::new(session.actor.clone()).is_ok_and(|actor| space.members.contains(&actor))
    })
}

pub fn space_search_visible_to(
    state: &AppState,
    space: &contrix_sdk::SpaceSearchEntry,
    session: Option<&SessionRecord>,
) -> bool {
    if is_space_deleted(state, space.space_id.as_str()) {
        return false;
    }
    if session.is_some_and(|session| {
        Did::new(session.actor.clone()).is_ok_and(|actor| space.members.contains(&actor))
    }) {
        return true;
    }
    matches!(
        space_discoverability(state, space.space_id.as_str()).as_str(),
        "public" | "listed" | "restricted"
    )
}

pub fn space_resolvable_to(
    state: &AppState,
    space: &contrix_sdk::SpaceSearchEntry,
    session: Option<&SessionRecord>,
    invite_token: Option<&str>,
    signed_link: Option<&str>,
) -> bool {
    if is_space_deleted(state, space.space_id.as_str()) {
        return false;
    }
    if session.is_some_and(|session| {
        Did::new(session.actor.clone()).is_ok_and(|actor| space.members.contains(&actor))
    }) {
        return true;
    }
    match space_discoverability(state, space.space_id.as_str()).as_str() {
        "public" | "listed" | "restricted" | "unlisted" => true,
        "invite_only" => invite_token
            .is_some_and(|token| invite_token_matches_space(state, space.space_id.as_str(), token)),
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

pub fn space_id_visible_to(state: &AppState, space_id: &str, session: Option<&SessionRecord>) -> bool {
    if is_space_deleted(state, space_id) {
        return false;
    }
    let Ok(sid) = SpaceId::new(space_id.to_owned()) else {
        return false;
    };
    state
        .spaces
        .lock()
        .expect("spaces lock")
        .get(&sid)
        .is_some_and(|space| space_visible_to(state, space, session))
}

/// Check if a space is accessible for backfill/subscribe (allows deleted spaces for members).
pub fn space_id_accessible(state: &AppState, space_id: &str, session: Option<&SessionRecord>) -> bool {
    let Ok(sid) = SpaceId::new(space_id.to_owned()) else {
        return false;
    };
    let spaces = state.spaces.lock().expect("spaces lock");
    let Some(space) = spaces.get(&sid) else {
        return false;
    };
    if space_discoverability(state, space.space_id.as_str()) == "public" {
        return true;
    }
    session.is_some_and(|session| {
        Did::new(session.actor.clone()).is_ok_and(|actor| space.members.contains(&actor))
    })
}

pub fn space_allows_plaintext_service(state: &AppState, space_id: &str) -> bool {
    let Ok(sid) = SpaceId::new(space_id.to_owned()) else {
        return false;
    };
    {
        let spaces = state.spaces.lock().expect("spaces lock");
        if spaces
            .get(&sid)
            .is_some_and(|space| space_discoverability(state, space.space_id.as_str()) == "public")
        {
            return true;
        }
    }
    state
        .persistence
        .space_meta()
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
    let operation = Operation::create(
        OperationId::new(ids::generate_operation_id()).expect("generated valid operation id"),
        SpaceId::new(space_id.to_owned()).expect("validated space id"),
        kinds::canonical_kind_for_local_payload("space.lifecycle", &payload)
            .unwrap_or(kinds::CX_SPACE_UPDATE),
        payload,
    );
    let projection_event = projection_event_from_operation(&operation, Some(actor));
    let operation_digest = Hash::new(operation.operation_digest()?)?;
    let mut commit = Commit::new(
        CommitId::new(ids::generate_commit_id()).expect("generated valid commit id"),
        actor.to_owned(),
        Did::new(actor.to_owned()).expect("session actor is valid"),
        next_author_seq(state, actor),
    );
    commit.prev_commit = state.repo.head(actor)?.map(Hash::new).transpose()?;
    commit.operations.push(operation_digest);
    commit.proofs.push(dev_proof(actor));

    let expected_head = commit.prev_commit.as_ref().map(ToString::to_string);
    let head = state.repo.submit_commit(
        actor,
        expected_head.as_deref(),
        vec![operation],
        commit,
        &ProofVerifier::for_state(state),
    )?;
    append_projection_event(state, projection_event);
    Ok(head)
}

pub fn next_author_seq(state: &AppState, repo_id: &str) -> u64 {
    state
        .repo
        .list_commits(repo_id, None, 100)
        .map(|page| {
            page.items
                .iter()
                .map(|commit| commit.author_seq)
                .max()
                .unwrap_or(0)
                + 1
        })
        .unwrap_or(1)
}
