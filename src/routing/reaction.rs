//! Reaction add / remove handlers.
//!
//! Surfaces:
//! - `POST   /api/v1/reactions` — add a reaction
//! - `DELETE /api/v1/reactions` — remove a reaction
//!
//! Both routes commit a `cx.reaction.add` / `cx.reaction.remove` operation
//! into `state.repo` and re-project via `project_accepted_operations`.

use contrix_sdk::{Commit, CommitId, Did, Hash, Operation, OperationId, SpaceId};
use salvo::http::StatusCode;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::json;

use crate::{
    JsonResult,
    error::{AppError, ErrorCode},
    ids, json_ok, kinds,
    state::AppState,
    wire::{AddReactionRequest, ReactionResponse, RemoveReactionRequest},
};

use super::{
    AuthArgs, DevProofVerifier, dev_proof, next_author_seq, project_accepted_operations,
};

#[endpoint(
    operation_id = "cx.reactions.add",
    tags("reactions"),
    summary = "Add a reaction to an event",
)]
pub async fn add_reaction(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<AddReactionRequest>,
) -> JsonResult<ReactionResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    let operation_id = ids::generate_operation_id();
    let commit_id = ids::generate_commit_id();
    let payload = json!({
        "event_id": body.event_id,
        "actor": session.actor,
        "key": body.key
    });
    let operation = Operation::create(
        OperationId::new(operation_id.clone()).unwrap(),
        SpaceId::new(body.space_id.clone()).unwrap(),
        kinds::CX_REACTION_ADD,
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
    json_ok(ReactionResponse {
        event_id: body.event_id,
        actor: session.actor.clone(),
        key: body.key,
        active: true,
    })
}

#[endpoint(
    operation_id = "cx.reactions.remove",
    tags("reactions"),
    summary = "Remove a previously-added reaction",
)]
pub async fn remove_reaction(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<RemoveReactionRequest>,
) -> JsonResult<ReactionResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    let operation_id = ids::generate_operation_id();
    let commit_id = ids::generate_commit_id();
    let payload = json!({
        "event_id": body.event_id,
        "actor": session.actor,
        "key": body.key
    });
    let operation = Operation::create(
        OperationId::new(operation_id.clone()).unwrap(),
        SpaceId::new(body.space_id.clone()).unwrap(),
        kinds::CX_REACTION_REMOVE,
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
    json_ok(ReactionResponse {
        event_id: body.event_id,
        actor: session.actor.clone(),
        key: body.key,
        active: false,
    })
}
