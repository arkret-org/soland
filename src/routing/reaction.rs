//! Reaction add / remove handlers.
//!
//! Surfaces:
//! - `POST   /api/v1/reactions` — add a reaction
//! - `DELETE /api/v1/reactions` — remove a reaction
//!
//! Both routes validate a `cx.reaction.add` / `cx.reaction.remove` operation
//! and project it through the canonical projection layer.

use contrix_sdk::{Operation, OperationId, SpaceId};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::json;

use crate::{
    JsonResult,
    error::AppError,
    ids, json_ok, kinds,
    state::AppState,
    wire::{AddReactionRequest, ReactionResponse, RemoveReactionRequest},
};

use super::{AuthArgs, accept_local_operations};

pub fn router() -> Router {
    Router::with_path("reactions")
        .post(add_reaction)
        .delete(remove_reaction)
}

#[endpoint(
    operation_id = "cx.reactions.add",
    tags("reactions"),
    summary = "Add a reaction to an event"
)]
async fn add_reaction(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<AddReactionRequest>,
) -> JsonResult<ReactionResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    let operation_id = ids::generate_operation_id();
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
    accept_local_operations(state, &session.actor, &[operation])
        .map_err(|error| AppError::invalid_param(error))?;
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
    summary = "Remove a previously-added reaction"
)]
async fn remove_reaction(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<RemoveReactionRequest>,
) -> JsonResult<ReactionResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    let operation_id = ids::generate_operation_id();
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
    accept_local_operations(state, &session.actor, &[operation])
        .map_err(|error| AppError::invalid_param(error))?;
    json_ok(ReactionResponse {
        event_id: body.event_id,
        actor: session.actor.clone(),
        key: body.key,
        active: false,
    })
}
