//! Legacy profile / presence compatibility handler.
//!
//! Protocol clients use `ck.self.account.subscribe?set_presence=...` and read
//! presence from the account aggregate. This module is mounted only under the
//! `/_soland/self/profile/presence` path.
//!
//! Production note: presence is currently in-memory (see
//! `AppState.presence`). Durable presence + ephemeral/durable channel
//! split is future work.

use salvo::oapi::extract::QueryParam;
use salvo::prelude::*;
use serde::Serialize;
use serde_json::{Value, json};

use super::{now, validate_did};
use crate::error::AppError;
use crate::result::{JsonResult, json_ok};
use crate::state::{AppState, PresenceRecord};

const PRESENCE_ONLINE_TTL_SECONDS: i64 = 3;

pub(super) fn router() -> Router {
    Router::with_path("profile/presence").get(profile_presence)
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ProfilePresenceOutcome {
    pub actor: String,
    pub display_name: String,
    pub avatar_url: Option<String>,
    pub presence: Value,
}

#[endpoint(
    operation_id = "org.cokret.soland.profile.presence",
    tags("profile"),
    summary = "Read an actor's presence record + display name"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.profile.presence"))]
async fn profile_presence(
    did: QueryParam<String, false>,
    depot: &mut Depot,
) -> JsonResult<ProfilePresenceOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let did = did
        .into_inner()
        .unwrap_or_else(|| "did:web:alice.example".to_owned());
    if validate_did(&did).is_err() {
        return Err(AppError::invalid_param("invalid did"));
    }
    let account = state
        .persistence
        .accounts()
        .get(&did)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let presence = state.persistence.presence().get(&did).await.ok().flatten();
    let presence_json = presence
        .map(presence_record_json)
        .unwrap_or_else(|| json!({"status": "offline", "updated_at": now()}));
    json_ok(ProfilePresenceOutcome {
        actor: did.clone(),
        display_name: account
            .and_then(|account| account.display_name)
            .unwrap_or_else(|| did.clone()),
        avatar_url: None,
        presence: presence_json,
    })
}

fn presence_record_json(record: PresenceRecord) -> Value {
    let is_stale_online = record.status == "online"
        && now().signed_duration_since(record.updated_at)
            > chrono::Duration::seconds(PRESENCE_ONLINE_TTL_SECONDS);
    if is_stale_online {
        json!({
            "status": "offline",
            "updated_at": record.updated_at,
            "last_seen": record.updated_at,
        })
    } else {
        json!({
            "status": record.status,
            "updated_at": record.updated_at,
        })
    }
}
