//! Directory + handle / actor / organization resolution handlers.
//!
//! Surfaces:
//! - `GET  /api/v1/directory/describe`            — capability + profile probe
//! - `POST /api/v1/directory/search-spaces`       — fuzzy text + visibility filter
//! - `POST /api/v1/directory/resolve-space`       — by id / alias / invite_token / signed_link
//! - `POST /api/v1/directory/search-organizations`
//! - `POST /api/v1/directory/resolve-organization`
//! - `POST /api/v1/directory/search-actors`
//! - `GET  /api/v1/directory/search-users`        — same as search-actors via `?query`
//! - `POST /api/v1/directory/resolve-handle`
//!
//! Demo data lives here too — `demo_organization` / `demo_actors` are
//! placeholders until E1/E2/E3 (Stream-E in `_todos.md`) lands a real
//! `actors` / `organizations` / `handles` PgStore.

use std::collections::BTreeMap;

use salvo::{http::StatusCode, prelude::*};
use serde_json::{Value, json};

use crate::{
    state::{AppState, SessionRecord},
    wire::{
        DirectoryDescribeResponse, DirectoryValueSearchResponse, ResolveHandleRequest,
        ResolveHandleResponse, ResolveOrganizationRequest, ResolveOrganizationResponse,
        ResolveSpaceRequest, ResolveSpaceResponse, SearchActorsRequest, SearchOrganizationsRequest,
        SearchSpacesRequest, SearchSpacesResponse,
    },
};

use super::{
    authenticated_session, device_inventory_to_json, handle_for_did, invite_token_space_id,
    is_space_deleted, normalize_handle, now, query_param, render_error, space_discoverability,
    space_resolvable_to, space_search_discoverability, space_search_visible_to,
};

#[endpoint]
pub async fn directory_describe(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    res.render(Json(DirectoryDescribeResponse {
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

#[endpoint]
pub async fn search_spaces(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = req
        .parse_json::<SearchSpacesRequest>()
        .await
        .unwrap_or(SearchSpacesRequest {
            query: None,
            limit: Some(20),
        });
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
    res.render(Json(SearchSpacesResponse {
        results,
        next_cursor: None,
    }));
}

#[endpoint]
pub async fn resolve_space(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match req.parse_json::<ResolveSpaceRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid resolve space request",
            );
            return;
        }
    };
    if body.space_id.is_none()
        && body.alias.is_none()
        && body.invite_token.is_none()
        && body.signed_link.is_none()
    {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "one of space_id, alias, invite_token, or signed_link is required",
        );
        return;
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
        Some(space) => res.render(Json(ResolveSpaceResponse {
            space_preview: space.clone(),
            stripped_state: vec![json!({
                "type": "cx.space.discovery",
                // `cx.space.discovery` is a singleton cell keyed by
                // `(space_id, kind)` only — no subject on the wire.
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
        })),
        None => render_error(res, StatusCode::NOT_FOUND, "not_found", "not found"),
    }
}

#[endpoint]
pub async fn search_organizations(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = req
        .parse_json::<SearchOrganizationsRequest>()
        .await
        .unwrap_or(SearchOrganizationsRequest {
            query: None,
            limit: Some(20),
        });
    let Some(limit) = checked_limit(res, body.limit) else {
        return;
    };
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
    res.render(Json(DirectoryValueSearchResponse {
        results: results.into_iter().take(limit).collect(),
        next_cursor: None,
    }));
}

#[endpoint]
pub async fn resolve_organization(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match req.parse_json::<ResolveOrganizationRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid resolve organization request",
            );
            return;
        }
    };
    if body.organization_id.is_none() && body.handle.is_none() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "organization_id or handle is required",
        );
        return;
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
        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
        return;
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
    res.render(Json(ResolveOrganizationResponse {
        organization,
        spaces,
    }));
}

#[endpoint]
pub async fn search_actors(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = req
        .parse_json::<SearchActorsRequest>()
        .await
        .unwrap_or(SearchActorsRequest {
            query: None,
            organization_id: None,
            limit: Some(20),
        });
    let Some(limit) = checked_limit(res, body.limit) else {
        return;
    };
    if let Some(organization_id) = body.organization_id.as_deref()
        && organization_id != "cx:org:demo"
    {
        res.render(Json(DirectoryValueSearchResponse {
            results: Vec::new(),
            next_cursor: None,
        }));
        return;
    }

    let session = authenticated_session(state, req).ok();
    let results: Vec<_> = demo_actors(state)
        .into_iter()
        .filter(|actor| actor_visible_to(state, actor, session.as_ref()))
        .filter(|actor| query_matches(actor, body.query.as_deref()))
        .take(limit)
        .collect();
    res.render(Json(DirectoryValueSearchResponse {
        results,
        next_cursor: None,
    }));
}

#[endpoint]
pub async fn search_users(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(limit) = query_limit(req, res) else {
        return;
    };
    let query = query_param(req, "query").or_else(|| query_param(req, "q"));
    let session = authenticated_session(state, req).ok();
    let results: Vec<_> = demo_actors(state)
        .into_iter()
        .filter(|actor| actor_visible_to(state, actor, session.as_ref()))
        .filter(|actor| query_matches(actor, query.as_deref()))
        .take(limit)
        .collect();
    res.render(Json(DirectoryValueSearchResponse {
        results,
        next_cursor: None,
    }));
}

#[endpoint]
pub async fn resolve_handle(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match req.parse_json::<ResolveHandleRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid resolve handle request",
            );
            return;
        }
    };
    if body.handle.trim().is_empty() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "handle is required",
        );
        return;
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
        Some(actor) => res.render(Json(ResolveHandleResponse {
            handle: normalized,
            did: actor["did"].as_str().unwrap_or_default().to_owned(),
            actor,
        })),
        None => render_error(res, StatusCode::NOT_FOUND, "not_found", "not found"),
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
    for account in accounts {
        if actors
            .iter()
            .any(|actor| actor["did"].as_str() == Some(account.did.as_str()))
        {
            continue;
        }
        actors.push(json!({
            "did": account.did,
            "handle": account.handle,
            "display_name": account.display_name.as_deref().unwrap_or(account.did.as_str()),
            "organization_id": "cx:org:demo",
            "avatar_url": null,
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

pub fn facets_match(value: &Value, required: &[String]) -> bool {
    if required.is_empty() {
        return true;
    }
    let facets = value
        .get("facets")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str())
        .collect::<Vec<_>>();
    required
        .iter()
        .all(|required| facets.iter().any(|facet| facet == required))
}

pub fn checked_limit(res: &mut Response, limit: Option<usize>) -> Option<usize> {
    let limit = limit.unwrap_or(20);
    if !(1..=100).contains(&limit) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "limit must be between 1 and 100",
        );
        return None;
    }
    Some(limit)
}

pub fn query_limit(req: &Request, res: &mut Response) -> Option<usize> {
    match query_param(req, "limit") {
        Some(raw) => match raw.parse::<usize>() {
            Ok(limit) => checked_limit(res, Some(limit)),
            Err(_) => {
                render_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "limit must be an integer",
                );
                None
            }
        },
        None => Some(20),
    }
}
