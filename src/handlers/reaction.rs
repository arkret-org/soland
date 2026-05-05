//! Reaction add / remove handlers.
//!
//! Surfaces:
//! - `POST   /api/v1/reactions` — add a reaction
//! - `DELETE /api/v1/reactions` — remove a reaction
//!
//! Both routes commit a `cx.reaction.add` / `cx.reaction.remove` operation
//! into `state.repo` and re-project via `project_accepted_operations`.

use contrix_sdk::{Commit, CommitId, Did, Hash, Operation, OperationId, SpaceId};
use salvo::{http::StatusCode, prelude::*};
use serde_json::json;

use crate::{
    ids, kinds,
    state::AppState,
    wire::{AddReactionRequest, ReactionResponse, RemoveReactionRequest},
};

use super::{
    DevProofVerifier, auth_or_render, dev_proof, next_author_seq, project_accepted_operations,
    render_error,
};

#[handler]
pub async fn add_reaction(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<AddReactionRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid reaction request",
            );
            return;
        }
    };
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
    let operation_digest = match operation.operation_digest() {
        Ok(d) => d,
        Err(e) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "digest_error",
                &e.to_string(),
            );
            return;
        }
    };
    let mut commit = Commit::new(
        CommitId::new(commit_id.clone()).unwrap(),
        &session.actor,
        Did::new(session.actor.clone()).unwrap(),
        next_author_seq(state, &session.actor),
    );
    commit.operations.push(Hash::new(operation_digest).unwrap());
    commit.proofs.push(dev_proof(&session.actor));
    let expected_head = commit.prev_commit.as_ref().map(ToString::to_string);
    match state.repo.submit_commit(
        &session.actor,
        expected_head.as_deref(),
        vec![operation.clone()],
        commit,
        &DevProofVerifier,
    ) {
        Ok(_head_commit) => {
            project_accepted_operations(state, &session.actor, &[operation]);
            res.render(Json(ReactionResponse {
                event_id: body.event_id,
                actor: session.actor.clone(),
                key: body.key,
                active: true,
            }));
        }
        Err(error) => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "repo_conflict",
                &error.to_string(),
            );
        }
    }
}

#[handler]
pub async fn remove_reaction(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<RemoveReactionRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid reaction request",
            );
            return;
        }
    };
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
    let operation_digest = match operation.operation_digest() {
        Ok(d) => d,
        Err(e) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "digest_error",
                &e.to_string(),
            );
            return;
        }
    };
    let mut commit = Commit::new(
        CommitId::new(commit_id.clone()).unwrap(),
        &session.actor,
        Did::new(session.actor.clone()).unwrap(),
        next_author_seq(state, &session.actor),
    );
    commit.operations.push(Hash::new(operation_digest).unwrap());
    commit.proofs.push(dev_proof(&session.actor));
    let expected_head = commit.prev_commit.as_ref().map(ToString::to_string);
    match state.repo.submit_commit(
        &session.actor,
        expected_head.as_deref(),
        vec![operation.clone()],
        commit,
        &DevProofVerifier,
    ) {
        Ok(_head_commit) => {
            project_accepted_operations(state, &session.actor, &[operation]);
            res.render(Json(ReactionResponse {
                event_id: body.event_id,
                actor: session.actor.clone(),
                key: body.key,
                active: false,
            }));
        }
        Err(error) => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "repo_conflict",
                &error.to_string(),
            );
        }
    }
}
