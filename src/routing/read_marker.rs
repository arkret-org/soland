//! Read marker handlers (per-actor read position within a Space).
//!
//! Surfaces:
//! - `POST /api/v1/read-markers` — set the actor's read marker
//! - `GET  /api/v1/read-markers` — list the actor's read markers, optionally
//!   filtered by `?space_id=...`

use contrix_sdk::{Commit, CommitId, Did, Hash, Operation, OperationId, SpaceId};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use crate::{
    JsonResult,
    error::{AppError, ErrorCode},
    ids, json_ok, kinds,
    state::AppState,
    wire::{ReadMarkerResponse, SetReadMarkerRequest},
};

use super::{
    AuthArgs, DevProofVerifier, dev_proof, next_author_seq, now, project_accepted_operations,
};

#[endpoint(
    operation_id = "cx.read_markers.set",
    tags("read_markers"),
    summary = "Set the authenticated actor's read marker for a Space",
)]
pub async fn set_read_marker(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<SetReadMarkerRequest>,
) -> JsonResult<ReadMarkerResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    let operation_id = ids::generate_operation_id();
    let commit_id = ids::generate_commit_id();
    let scope_id = body
        .scope_id
        .clone()
        .unwrap_or_else(|| "_default".to_owned());
    let payload = json!({
        "event_id": body.event_id,
        "sender": session.actor,
        "scope_id": scope_id
    });
    let operation = Operation::create(
        OperationId::new(operation_id.clone()).unwrap(),
        SpaceId::new(body.space_id.clone()).unwrap(),
        kinds::CX_READ_MARKER,
        payload,
    );
    let operation_digest = operation
        .operation_digest()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut commit = Commit::new(
        CommitId::new(commit_id.clone()).unwrap(),
        &session.actor,
        Did::new(session.actor.clone()).unwrap(),
        next_author_seq(state, &session.actor),
    );
    commit.operations.push(Hash::new(operation_digest).unwrap());
    commit.proofs.push(dev_proof(&session.actor));
    let expected_head = commit.prev_commit.as_ref().map(ToString::to_string);
    state
        .repo
        .submit_commit(
            &session.actor,
            expected_head.as_deref(),
            vec![operation.clone()],
            commit,
            &DevProofVerifier,
        )
        .map_err(|error| {
            AppError::new(ErrorCode::Conflict, error.to_string()).with_status(StatusCode::CONFLICT)
        })?;
    project_accepted_operations(state, &session.actor, &[operation]);
    json_ok(ReadMarkerResponse {
        space_id: body.space_id,
        actor: session.actor.clone(),
        scope_id,
        event_id: body.event_id,
        read_at: now().to_rfc3339(),
    })
}

#[endpoint(
    operation_id = "cx.read_markers.list",
    tags("read_markers"),
    summary = "List the authenticated actor's read markers, optionally filtered by space",
)]
pub async fn get_read_markers(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: QueryParam<String, false>,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let space_id = space_id.into_inner();
    let space_id = space_id.unwrap_or_default();
    let markers = {
        let proj = state.projection.lock().expect("projection lock");
        proj.read_markers
            .values()
            .filter(|m| m.actor == session.actor && (space_id.is_empty() || m.space_id == space_id))
            .map(|m| ReadMarkerResponse {
                space_id: m.space_id.clone(),
                actor: m.actor.clone(),
                scope_id: m.scope_id.clone(),
                event_id: m.event_id.clone(),
                read_at: m.read_at.to_rfc3339(),
            })
            .collect::<Vec<_>>()
    };
    json_ok(json!({ "markers": markers }))
}
