//! Profile / presence handlers.
//!
//! Surfaces:
//! - `GET /api/v1/profile/presence?did=…` — render the actor's current presence record together
//!   with display name and avatar.
//!
//! Production note: presence is currently in-memory (see `AppState.presence`).
//! Durable presence + ephemeral/durable channel split is tracked under `_todos.md` F-11.

use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::json;

use super::{now, query_param, render_error, validate_did};
use crate::state::AppState;

pub(super) fn router() -> Router {
    Router::with_path("profile/presence").get(profile_presence)
}

#[endpoint]
async fn profile_presence(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let did = query_param(req, "did").unwrap_or_else(|| "did:web:alice.example".to_owned());
    if validate_did(&did).is_err() {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", "invalid did");
        return;
    }
    let account = match state.persistence.accounts().get(&did) {
        Ok(account) => account,
        Err(error) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &error.to_string(),
            );
            return;
        }
    };
    let presence = state.persistence.presence().get(&did).ok().flatten();
    let presence_json = presence
        .map(|record| {
            json!({
                "status": record.status,
                "updated_at": record.updated_at,
            })
        })
        .unwrap_or_else(|| json!({"status": "offline", "updated_at": now()}));
    res.render(Json(json!({
        "actor": did,
        "display_name": account
            .and_then(|account| account.display_name)
            .unwrap_or_else(|| did.clone()),
        "avatar_url": null,
        "presence": presence_json
    })));
}
