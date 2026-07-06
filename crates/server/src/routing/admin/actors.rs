//! Actor admin detail projection.
//!
//! `GET /_soland/admin/actors/{actor_id}` mirrors the admin actors collection row
//! and adds the account lifecycle linkage needed by sodmin.

use salvo::oapi::extract::PathParam;
use salvo::prelude::*;
use serde_json::json;

use super::{AuthArgs, append_audit_log, require_admin_principal};
use crate::state::AppState;
use crate::{JsonResult, json_ok};

pub(super) fn router() -> Router {
    Router::with_path("actors/{actor_id}").get(get_actor)
}

#[endpoint(
    operation_id = "org.cokret.soland.admin.actors.get",
    tags("soland-admin", "actors"),
    summary = "Read an admin actor projection row"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.admin.actors.get"))]
async fn get_actor(
    aa: AuthArgs,
    actor_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<super::collection::AdminActorProjection> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    let actor_id = actor_id.into_inner();
    let actor = super::collection::admin_actor_items(state)
        .await
        .into_iter()
        .find(|actor| actor.matches_actor_id(&actor_id))
        .ok_or_else(|| crate::error::AppError::not_found("actor not found"))?;

    append_audit_log(
        state,
        Some(&session.actor),
        "admin.actors.get",
        json!({
            "actor_id": actor_id,
            "device_id": session.device_id,
        }),
        "accepted",
    )
    .await;

    json_ok(actor)
}
