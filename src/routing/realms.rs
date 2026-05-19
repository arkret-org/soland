//! Realm governance HTTP surface (R3.1).
//!
//! Surfaces:
//! - `GET /api/v1/realms/{realm_id}/links?direction=outbound|inbound|both&link_kind_allow=...`
//!   — list the typed cross-Realm links projected from `cx.realm.link`
//!   events. Powered by [`crate::reducer::ProjectionState::realm_links_query`].
//!
//! These endpoints are read-only and observe the structured side-band
//! cache populated by the reducer; write paths flow through the
//! standard Event-Envelope ingestion (`POST /api/v1/events`).

use salvo::oapi::extract::{PathParam, QueryParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

use super::AuthArgs;
use crate::error::AppError;
use crate::reducer::RealmLinkState;
use crate::result::{JsonResult, json_ok};
use crate::state::AppState;

pub(crate) fn router() -> Router {
    Router::with_path("realms").push(
        Router::with_path("{realm_id}/links").get(list_realm_links),
    )
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct RealmLinkResponseEntry {
    pub realm_id: String,
    pub target_realm_id: String,
    pub link_kind: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct ListRealmLinksResponse {
    pub realm_id: String,
    pub direction: String,
    pub links: Vec<RealmLinkResponseEntry>,
}

impl From<&RealmLinkState> for RealmLinkResponseEntry {
    fn from(row: &RealmLinkState) -> Self {
        Self {
            realm_id: row.realm_id.clone(),
            target_realm_id: row.target_realm_id.clone(),
            link_kind: row.link_kind.clone(),
            status: row.status.clone(),
            label: row.label.clone(),
            commitment: row.commitment.clone(),
            created_at: row.created_at.to_rfc3339(),
            updated_at: row.updated_at.to_rfc3339(),
        }
    }
}

#[endpoint(
    operation_id = "cx.realms.links.list",
    tags("realms"),
    summary = "List typed cross-Realm links projected from cx.realm.link"
)]
async fn list_realm_links(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    direction: QueryParam<String, false>,
    link_kind_allow: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ListRealmLinksResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req)?;
    let realm_id = realm_id.into_inner();
    let direction_str = direction.into_inner().unwrap_or_else(|| "both".to_owned());
    let direction_enum = contrix_sdk::RealmLinkDirection::parse(&direction_str).ok_or_else(|| {
        AppError::invalid_param("direction MUST be one of outbound|inbound|both")
    })?;
    // `link_kind_allow` is a comma-separated list — keeps the query
    // surface dense and avoids repeated query params.
    let allow_raw = link_kind_allow.into_inner();
    let allow: Option<Vec<String>> = allow_raw.as_ref().map(|s| {
        s.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    });
    if let Some(values) = allow.as_ref() {
        // Reject unknown link_kinds eagerly with a clear error.
        for value in values {
            if contrix_sdk::RealmLinkKind::parse(value).is_none() {
                return Err(AppError::invalid_param(format!(
                    "link_kind_allow contains unknown kind '{value}'"
                )));
            }
        }
    }

    let projection = state.projection.lock().expect("projection mutex");
    let rows = projection.realm_links_query(&realm_id, direction_enum, allow.as_deref());
    let entries = rows.iter().map(RealmLinkResponseEntry::from).collect::<Vec<_>>();

    json_ok(ListRealmLinksResponse {
        realm_id,
        direction: direction_str,
        links: entries,
    })
}
