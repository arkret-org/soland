//! Actor admin surface (production, D14).
//!
//! `GET /_soland/admin/actors` — typed cursor-paginated list (see
//! [`super::queries`]); `GET /_soland/admin/actors/{actor_id}` — one
//! [`AdminActor`] row with the account lifecycle linkage sodmin needs.

use arkret_sdk::models::product::AdminActor;
use salvo::oapi::extract::PathParam;
use salvo::prelude::*;
use serde_json::json;

use super::{AuthArgs, append_audit_log, queries, require_admin_principal};
use crate::state::AppState;
use crate::{JsonResult, json_ok};

pub(super) fn router() -> Router {
    Router::with_path("actors")
        .get(queries::admin_list_actors)
        .push(Router::with_path("{actor_id}").get(get_actor))
}

#[endpoint(
    operation_id = "org.arkret.soland.admin.actors.get",
    tags("soland-admin", "actors"),
    summary = "Read one production admin actor row",
    status_codes(200, 400, 401, 403, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.actors.get"))]
async fn get_actor(
    aa: AuthArgs,
    actor_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminActor> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    let actor_id = actor_id.into_inner();

    let account = state
        .persistence
        .accounts()
        .list()
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to list accounts");
            soland_http::error::AppError::internal("account store unavailable")
        })?
        .into_iter()
        .find(|account| account.did == actor_id || account.id == actor_id)
        .ok_or_else(|| soland_http::error::AppError::not_found("actor not found"))?;
    let (device_counts, realm_counts) = queries::actor_count_maps(state).await;
    let actor = queries::admin_actor_row(state, &account, &device_counts, &realm_counts)
        .ok_or_else(|| soland_http::error::AppError::not_found("actor not found"))?;

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
