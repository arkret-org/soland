//! Reaction add / remove handlers.
//!
//! Surfaces:
//! - `POST   /_soland/self/reactions` — add a reaction
//! - `DELETE /_soland/self/reactions` — remove a reaction
//!
//! Both routes validate a `ck.reaction.add` / `ck.reaction.remove` operation
//! and project it through the canonical projection layer.

use cokret_sdk::{Operation, OperationId, RealmId};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::json;

use super::{AuthArgs, accept_local_operations};
use crate::error::AppError;
use crate::state::AppState;
use crate::wire::{AddReactionRequest, ReactionResponse, RemoveReactionRequest};
use crate::{JsonResult, ids, json_ok, kinds};

pub(super) fn router() -> Router {
    Router::with_path("reactions")
        .post(add_reaction)
        .delete(remove_reaction)
}

#[endpoint(
    operation_id = "ck.reactions.add",
    tags("reactions"),
    summary = "Add a reaction to an event"
)]
#[tracing::instrument(skip_all, fields(op = "ck.reactions.add"))]
async fn add_reaction(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<AddReactionRequest>,
) -> JsonResult<ReactionResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let operation_id = ids::generate_operation_id();
    let payload = json!({
        "event_id": body.event_id,
        "actor": session.actor,
        "key": body.key
    });
    let operation = Operation::create(
        OperationId::new(operation_id.clone()).unwrap(),
        RealmId::new(body.realm_id.clone()).unwrap(),
        kinds::CK_REACTION_ADD,
        payload,
    );
    accept_local_operations(state, &session.actor, &[operation])
        .await
        .map_err(AppError::invalid_param)?;
    json_ok(ReactionResponse {
        event_id: body.event_id,
        actor: session.actor.clone(),
        key: body.key,
        active: true,
    })
}

#[endpoint(
    operation_id = "ck.reactions.remove",
    tags("reactions"),
    summary = "Remove a previously-added reaction"
)]
#[tracing::instrument(skip_all, fields(op = "ck.reactions.remove"))]
async fn remove_reaction(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<RemoveReactionRequest>,
) -> JsonResult<ReactionResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let operation_id = ids::generate_operation_id();
    let payload = json!({
        "event_id": body.event_id,
        "actor": session.actor,
        "key": body.key
    });
    let operation = Operation::create(
        OperationId::new(operation_id.clone()).unwrap(),
        RealmId::new(body.realm_id.clone()).unwrap(),
        kinds::CK_REACTION_REMOVE,
        payload,
    );
    accept_local_operations(state, &session.actor, &[operation])
        .await
        .map_err(AppError::invalid_param)?;
    json_ok(ReactionResponse {
        event_id: body.event_id,
        actor: session.actor.clone(),
        key: body.key,
        active: false,
    })
}
