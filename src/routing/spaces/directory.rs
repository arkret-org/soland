//! Directory + handle / actor / organization resolution handlers.
//!
//! Surfaces:
//! - `GET  /api/v1/directory/describe`            — capability + profile probe
//! - `POST /api/v1/directory/search-spaces`       — fuzzy text + visibility filter
//! - `POST /api/v1/directory/resolve-space`       — by id / alias / invite_token / signed_link
//! - `POST /api/v1/directory/search-organizations`
//! - `POST /api/v1/directory/resolve-organization`
//! - `POST /api/v1/directory/search-actors`
//! - `POST /api/v1/directory/search-users`        — same as search-actors via body `q`
//! - `POST /api/v1/directory/resolve-handle`
//!
//! Demo data lives here too — `demo_organization` / `demo_actors` are
//! placeholders until a real `actors` / `organizations` / `handles`
//! PgStore lands.

use std::collections::BTreeMap;

use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{
    authenticated_session, device_inventory_to_json, handle_for_did, invite_token_space_id,
    is_space_deleted, normalize_handle, now, space_discoverability, space_resolvable_to,
    space_search_discoverability, space_search_visible_to,
};
use crate::error::AppError;
use crate::result::{JsonResult, json_ok};
use crate::state::{AppState, SessionRecord};
use crate::wire::{
    DirectoryDescribeResBody, DirectoryValueSearchResponse, ResolveHandleRequest,
    ResolveHandleResponse, ResolveOrganizationRequest, ResolveOrganizationResponse,
    ResolveSpaceRequest, ResolveSpaceResponse, SearchActorsRequest, SearchOrganizationsRequest,
    SearchSpacesRequest, SearchSpacesResponse, SearchUsersRequest,
};

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("directory/describe").get(directory_describe))
        .push(Router::with_path("directory/search-spaces").post(search_spaces))
        .push(Router::with_path("directory/resolve-space").post(resolve_space))
        .push(Router::with_path("directory/search-organizations").post(search_organizations))
        .push(Router::with_path("directory/resolve-organization").post(resolve_organization))
        .push(Router::with_path("directory/search-actors").post(search_actors))
        .push(Router::with_path("directory/search-users").post(search_users))
        .push(Router::with_path("directory/resolve-handle").post(resolve_handle))
}

#[endpoint]
async fn directory_describe(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    res.render(Json(DirectoryDescribeResBody {
        service_did: state.config.service_did.clone(),
        resource_types: vec![
            "space".to_owned(),
            "organization".to_owned(),
            "actor".to_owned(),
        ],
        discovery_profiles: vec!["cx.profile.directory_service.v1".to_owned()],
        restricted_query_proof: false,
    }));
}

#[endpoint(
    operation_id = "cx.directory.search_spaces",
    tags("directory"),
    summary = "Fuzzy-text + visibility-filtered space search"
)]
async fn search_spaces(
    body: JsonBody<SearchSpacesRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SearchSpacesResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    let query = contrix_sdk::SpaceSearchQuery {
        text: body.query,
        public_only: false,
        limit: body.limit,
        ..Default::default()
    };
    let session = authenticated_session(state, req).ok();
    let spaces = state.spaces.lock().expect("spaces lock");
    let results = spaces
        .search(query)
        .into_iter()
        .filter(|space| space_search_visible_to(state, space, session.as_ref()))
        .cloned()
        .collect();
    json_ok(SearchSpacesResponse {
        results,
        next_cursor: None,
    })
}

#[endpoint(
    operation_id = "cx.directory.resolve_space",
    tags("directory"),
    summary = "Resolve a space by id / alias / invite_token / signed_link"
)]
async fn resolve_space(
    body: JsonBody<ResolveSpaceRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ResolveSpaceResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    if body.space_id.is_none()
        && body.alias.is_none()
        && body.invite_token.is_none()
        && body.signed_link.is_none()
    {
        return Err(AppError::missing_param(
            "one of space_id, alias, invite_token, or signed_link is required",
        ));
    }

    let session = authenticated_session(state, req).ok();
    let invite_space_id = body
        .invite_token
        .as_deref()
        .and_then(|token| invite_token_space_id(state, token));
    let spaces = state.spaces.lock().expect("spaces lock");
    let space = spaces.search(Default::default()).into_iter().find(|entry| {
        space_resolvable_to(
            state,
            entry,
            session.as_ref(),
            body.invite_token.as_deref(),
            body.signed_link.as_deref(),
        ) && (body
            .space_id
            .as_deref()
            .is_some_and(|id| id == entry.space_id.as_str())
            || invite_space_id
                .as_deref()
                .is_some_and(|id| id == entry.space_id.as_str())
            || body
                .alias
                .as_deref()
                .is_some_and(|alias| alias.eq_ignore_ascii_case(&entry.name)))
    });
    match space {
        Some(space) => json_ok(ResolveSpaceResponse {
            space_preview: space.clone(),
            stripped_state: vec![json!({
                "type": "cx.space.discovery",
                "subject": "",
                "content": {
                    "discoverability": space_discoverability(state, space.space_id.as_str()),
                    "directory_visibility": {
                        "searchable": space_search_discoverability(state, space.space_id.as_str())
                    }
                }
            })],
            join_rule: if space_discoverability(state, space.space_id.as_str()) == "public" {
                "public".to_owned()
            } else {
                "invite_or_request".to_owned()
            },
            via_services: vec![state.config.service_did.clone()],
        }),
        None => Err(AppError::not_found("not found")),
    }
}

#[endpoint(
    operation_id = "cx.directory.search_organizations",
    tags("directory"),
    summary = "Fuzzy-text search across known organizations (demo data for now)"
)]
async fn search_organizations(
    body: JsonBody<SearchOrganizationsRequest>,
    depot: &mut Depot,
) -> JsonResult<DirectoryValueSearchResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    let limit = checked_limit(body.limit)?;
    let spaces = state.spaces.lock().expect("spaces lock");
    let space_entries: Vec<_> = spaces
        .search(Default::default())
        .into_iter()
        .filter(|space| !is_space_deleted(state, space.space_id.as_str()))
        .collect();
    let organization = demo_organization(&space_entries, &state.config.service_did);
    let results = if query_matches(&organization, body.query.as_deref()) {
        vec![organization]
    } else {
        Vec::new()
    };
    json_ok(DirectoryValueSearchResponse {
        results: results.into_iter().take(limit).collect(),
        next_cursor: None,
    })
}

#[endpoint(
    operation_id = "cx.directory.resolve_organization",
    tags("directory"),
    summary = "Resolve an organization by organization_id or handle"
)]
async fn resolve_organization(
    body: JsonBody<ResolveOrganizationRequest>,
    depot: &mut Depot,
) -> JsonResult<ResolveOrganizationResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    if body.organization_id.is_none() && body.handle.is_none() {
        return Err(AppError::missing_param(
            "organization_id or handle is required",
        ));
    }

    let spaces = state.spaces.lock().expect("spaces lock");
    let space_entries: Vec<_> = spaces
        .search(Default::default())
        .into_iter()
        .filter(|space| !is_space_deleted(state, space.space_id.as_str()))
        .collect();
    let organization = demo_organization(&space_entries, &state.config.service_did);
    let matches_id = body
        .organization_id
        .as_deref()
        .is_some_and(|id| id == organization["organization_id"].as_str().unwrap_or_default());
    let matches_handle = body
        .handle
        .as_deref()
        .is_some_and(|handle| handle.eq_ignore_ascii_case("@contrix-demo"));
    if !matches_id && !matches_handle {
        return Err(AppError::not_found("not found"));
    }

    let spaces = space_entries
        .into_iter()
        .map(|space| {
            json!({
                "space_id": space.space_id,
                "name": space.name,
                "description": space.description,
                "category": space.category,
            })
        })
        .collect();
    json_ok(ResolveOrganizationResponse {
        organization,
        spaces,
    })
}

#[endpoint(
    operation_id = "cx.directory.search_actors",
    tags("directory"),
    summary = "Search actors visible to the calling session"
)]
async fn search_actors(
    body: JsonBody<SearchActorsRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryValueSearchResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    let limit = checked_limit(body.limit)?;
    if let Some(organization_id) = body.organization_id.as_deref()
        && organization_id != "cx:org:demo"
    {
        return json_ok(DirectoryValueSearchResponse {
            results: Vec::new(),
            next_cursor: None,
        });
    }

    let session = authenticated_session(state, req).ok();
    let results: Vec<_> = demo_actors(state)
        .into_iter()
        .filter(|actor| actor_visible_to(state, actor, session.as_ref()))
        .filter(|actor| query_matches(actor, body.query.as_deref()))
        .take(limit)
        .collect();
    json_ok(DirectoryValueSearchResponse {
        results,
        next_cursor: None,
    })
}

#[endpoint(
    operation_id = "cx.directory.search_users",
    tags("directory"),
    summary = "Search users via a POST body to avoid query-string leakage"
)]
async fn search_users(
    body: JsonBody<SearchUsersRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryValueSearchResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    let limit = checked_limit(body.limit)?;
    let query = body.query;
    let session = authenticated_session(state, req).ok();
    let results: Vec<_> = demo_actors(state)
        .into_iter()
        .filter(|actor| actor_visible_to(state, actor, session.as_ref()))
        .filter(|actor| query_matches(actor, query.as_deref()))
        .take(limit)
        .collect();
    json_ok(DirectoryValueSearchResponse {
        results,
        next_cursor: None,
    })
}

#[endpoint(
    operation_id = "cx.directory.resolve_handle",
    tags("directory"),
    summary = "Resolve a normalized actor handle (e.g. `@alice`) to a DID"
)]
async fn resolve_handle(
    body: JsonBody<ResolveHandleRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ResolveHandleResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    if body.handle.trim().is_empty() {
        return Err(AppError::missing_param("handle is required"));
    }
    let normalized = normalize_handle(&body.handle);
    let session = authenticated_session(state, req).ok();
    let actor = demo_actors(state).into_iter().find(|actor| {
        actor_visible_to(state, actor, session.as_ref())
            && actor["handle"]
                .as_str()
                .is_some_and(|handle| handle == normalized)
    });
    match actor {
        Some(actor) => json_ok(ResolveHandleResponse {
            handle: normalized,
            did: actor["did"].as_str().unwrap_or_default().to_owned(),
            actor,
        }),
        None => Err(AppError::not_found("not found")),
    }
}

// ── Helpers shared with the rest of `crate::routing` ───────────────────────
//
// These remain public for sibling routing modules that share directory
// authorization and visibility checks.

pub fn has_accepted_contact(state: &AppState, left: &str, right: &str) -> bool {
    state
        .persistence
        .contacts()
        .list_for_actor(left)
        .unwrap_or_default()
        .iter()
        .any(|contact| {
            contact.status == "accepted"
                && ((contact.requester == left && contact.target == right)
                    || (contact.requester == right && contact.target == left))
        })
}

pub fn actor_visible_to(state: &AppState, actor: &Value, session: Option<&SessionRecord>) -> bool {
    let Some(did) = actor["did"].as_str() else {
        return false;
    };
    if did == "did:web:alice.example" {
        return true;
    }
    session.is_some_and(|session| {
        session.actor == did || has_accepted_contact(state, &session.actor, did)
    })
}

pub fn demo_organization(spaces: &[&contrix_sdk::SpaceSearchEntry], service_did: &str) -> Value {
    json!({
        "organization_id": "cx:org:demo",
        "handle": "@contrix-demo",
        "name": "Contrix Demo Organization",
        "description": "Demo organization projected by soland",
        "service_did": service_did,
        "space_count": spaces.len(),
        "actor_count": 1,
    })
}

pub fn demo_actors(state: &AppState) -> Vec<Value> {
    let mut actors = vec![json!({
        "did": "did:web:alice.example",
        "handle": "@alice",
        "display_name": "Alice Example",
        "organization_id": "cx:org:demo",
        "avatar_url": null,
        "presence": {"status": "online", "updated_at": now()},
    })];

    let accounts = state.persistence.accounts().list().unwrap_or_default();
    let erased = state
        .erased_actors
        .lock()
        .expect("erased_actors lock")
        .clone();
    for account in accounts {
        if actors
            .iter()
            .any(|actor| actor["did"].as_str() == Some(account.did.as_str()))
        {
            continue;
        }
        // GDPR erasure (account-lifecycle.md §3): erased actors MUST NOT
        // surface in directory results.
        if erased.contains(&account.did) {
            continue;
        }
        actors.push(json!({
            "did": account.did,
            "handle": account.handle,
            "display_name": account.display_name.as_deref().unwrap_or(account.did.as_str()),
            "bio": account.bio,
            "organization_id": "cx:org:demo",
            "avatar_url": account.avatar_url,
            "presence": {"status": "offline", "updated_at": now()},
        }));
    }

    let devices = state
        .persistence
        .devices()
        .list()
        .map(|devices| {
            let mut grouped: BTreeMap<String, BTreeMap<String, Value>> = BTreeMap::new();
            for device in devices {
                grouped
                    .entry(device.actor.clone())
                    .or_default()
                    .insert(device.device_id.clone(), device_inventory_to_json(&device));
            }
            grouped
        })
        .unwrap_or_default();
    for (did, actor_devices) in devices.iter() {
        if actors
            .iter()
            .any(|actor| actor["did"].as_str().is_some_and(|known| known == did))
        {
            continue;
        }
        let display_name = actor_devices
            .values()
            .find_map(|device| device["display_name"].as_str())
            .unwrap_or(did);
        actors.push(json!({
            "did": did,
            "handle": handle_for_did(did),
            "display_name": display_name,
            "organization_id": "cx:org:demo",
            "avatar_url": null,
            "presence": {"status": "offline", "updated_at": now()},
        }));
    }
    actors
}

pub fn query_matches(value: &Value, query: Option<&str>) -> bool {
    let Some(query) = query.map(str::trim).filter(|query| !query.is_empty()) else {
        return true;
    };
    value
        .to_string()
        .to_ascii_lowercase()
        .contains(&query.to_ascii_lowercase())
}

pub fn checked_limit(limit: Option<usize>) -> Result<usize, AppError> {
    let limit = limit.unwrap_or(20);
    if !(1..=100).contains(&limit) {
        return Err(AppError::invalid_param("limit must be between 1 and 100"));
    }
    Ok(limit)
}
