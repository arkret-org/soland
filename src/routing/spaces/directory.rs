//! Directory + handle / actor / organization resolution handlers.
//!
//! Surfaces:
//! - `GET  /api/v1/directory/describe`            — capability + profile probe
//! - `POST /api/v1/directory/search-realms`       — fuzzy text + visibility filter
//! - `POST /api/v1/directory/resolve-realm`       — by id / alias / invite_token / signed_link
//! - `POST /api/v1/directory/search-organizations`
//! - `POST /api/v1/directory/resolve-organization`
//! - `POST /api/v1/directory/search-actors`
//! - `POST /api/v1/directory/search-users`        — same as search-actors via body `q`
//! - `POST /api/v1/directory/resolve-handle`
//!
//! Demo data lives here too — `demo_organization` / `demo_actors` are
//! placeholders until a real `actors` / `organizations` / `handles`
//! provider lands. They are gated to development mode so production
//! deployments do not expose built-in identities.

use std::collections::BTreeMap;

use contrix_sdk::{Did, Ed25519MoveSigner, MoveSigner, canonical};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{
    authenticated_session, device_inventory_to_json, handle_for_did, invite_token_space_id,
    is_space_deleted, normalize_handle, now, space_discoverability, space_resolvable_to,
    space_search_discoverability, space_search_visible_to,
};
use crate::error::AppError;
use crate::ids;
use crate::result::{JsonResult, json_ok};
use crate::state::{AppState, RealmDirectoryEntry, RealmDirectoryQuery, SessionRecord};
use crate::wire::{
    DirectoryDescribeResBody, DirectoryValueSearchResponse, HandleClaim,
    HandleClaimDeliveryBinding, HandleClaimProof, ResolveHandleRequest, ResolveHandleResponse,
    ResolveOrganizationRequest, ResolveOrganizationResponse, ResolveRealmRequest,
    ResolveRealmResponse, SearchActorsRequest, SearchOrganizationsRequest, SearchRealmsRequest,
    SearchRealmsResponse, SearchUsersRequest,
};

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("directory/describe").get(directory_describe))
        .push(Router::with_path("directory/search-realms").post(search_realms))
        .push(Router::with_path("directory/resolve-realm").post(resolve_realm))
        .push(Router::with_path("directory/search-organizations").post(search_organizations))
        .push(Router::with_path("directory/resolve-organization").post(resolve_organization))
        .push(Router::with_path("directory/search-actors").post(search_actors))
        .push(Router::with_path("directory/search-users").post(search_users))
        .push(Router::with_path("directory/resolve-handle").post(resolve_handle))
        .push(
            Router::with_path("directory/private-contact-discovery")
                .post(private_contact_discovery),
        )
        .push(Router::with_path("directory/announce").post(directory_announce))
        .push(Router::with_path("directory/withdraw").post(directory_withdraw))
        .push(Router::with_path("directory/subscribe").post(directory_subscribe))
}

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "directory_describe"))]
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
    operation_id = "cx.directory.search_realms",
    tags("directory"),
    summary = "Fuzzy-text + visibility-filtered realm search"
)]
#[tracing::instrument(skip_all, fields(op = "cx.directory.search_realms"))]
async fn search_realms(
    body: JsonBody<SearchRealmsRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SearchRealmsResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    let query = RealmDirectoryQuery {
        text: body.query,
        public_only: false,
        limit: body.limit,
        ..Default::default()
    };
    let session = authenticated_session(state, req).ok();
    let spaces = state.realms.lock().expect("spaces lock");
    let results = spaces
        .search(query)
        .into_iter()
        .filter(|space| space_search_visible_to(state, space, session.as_ref()))
        .cloned()
        .collect();
    json_ok(SearchRealmsResponse {
        results,
        next_cursor: None,
    })
}

#[endpoint(
    operation_id = "cx.directory.resolve_realm",
    tags("directory"),
    summary = "Resolve a realm by id / alias / invite_token / signed_link"
)]
#[tracing::instrument(skip_all, fields(op = "cx.directory.resolve_realm"))]
async fn resolve_realm(
    body: JsonBody<ResolveRealmRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ResolveRealmResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    if body.realm_id.is_none()
        && body.alias.is_none()
        && body.invite_token.is_none()
        && body.signed_link.is_none()
    {
        return Err(AppError::missing_param(
            "one of realm_id, alias, invite_token, or signed_link is required",
        ));
    }

    let session = authenticated_session(state, req).ok();
    let invite_space_id = body
        .invite_token
        .as_deref()
        .and_then(|token| invite_token_space_id(state, token));
    let spaces = state.realms.lock().expect("spaces lock");
    let space = spaces.search(Default::default()).into_iter().find(|entry| {
        space_resolvable_to(
            state,
            entry,
            session.as_ref(),
            body.invite_token.as_deref(),
            body.signed_link.as_deref(),
        ) && (body
            .realm_id
            .as_deref()
            .is_some_and(|id| id == entry.realm_id.as_str())
            || invite_space_id
                .as_deref()
                .is_some_and(|id| id == entry.realm_id.as_str())
            || body
                .alias
                .as_deref()
                .is_some_and(|alias| alias.eq_ignore_ascii_case(&entry.name)))
    });
    match space {
        Some(space) => json_ok(ResolveRealmResponse {
            space_preview: space.clone(),
            stripped_state: vec![json!({
                // R1.2 (Realm/Space reversal): security-namespace
                // event renamed from `cx.space.discovery` to
                // `cx.realm.discovery`.
                "type": "cx.realm.discovery",
                "subject": "",
                "content": {
                    "discoverability": space_discoverability(state, space.realm_id.as_str()),
                    "directory_visibility": {
                        "searchable": space_search_discoverability(state, space.realm_id.as_str())
                    }
                }
            })],
            join_rule: if space_discoverability(state, space.realm_id.as_str()) == "public" {
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
#[tracing::instrument(skip_all, fields(op = "cx.directory.search_organizations"))]
async fn search_organizations(
    body: JsonBody<SearchOrganizationsRequest>,
    depot: &mut Depot,
) -> JsonResult<DirectoryValueSearchResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    require_demo_directory_provider(state)?;
    let body = body.into_inner();
    let limit = checked_limit(body.limit)?;
    let spaces = state.realms.lock().expect("spaces lock");
    let space_entries: Vec<_> = spaces
        .search(Default::default())
        .into_iter()
        .filter(|space| !is_space_deleted(state, space.realm_id.as_str()))
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
#[tracing::instrument(skip_all, fields(op = "cx.directory.resolve_organization"))]
async fn resolve_organization(
    body: JsonBody<ResolveOrganizationRequest>,
    depot: &mut Depot,
) -> JsonResult<ResolveOrganizationResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    require_demo_directory_provider(state)?;
    let body = body.into_inner();
    if body.organization_id.is_none() && body.handle.is_none() {
        return Err(AppError::missing_param(
            "organization_id or handle is required",
        ));
    }

    let spaces = state.realms.lock().expect("spaces lock");
    let space_entries: Vec<_> = spaces
        .search(Default::default())
        .into_iter()
        .filter(|space| !is_space_deleted(state, space.realm_id.as_str()))
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
                "realm_id": space.realm_id,
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
#[tracing::instrument(skip_all, fields(op = "cx.directory.search_actors"))]
async fn search_actors(
    body: JsonBody<SearchActorsRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryValueSearchResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    require_demo_directory_provider(state)?;
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
#[tracing::instrument(skip_all, fields(op = "cx.directory.search_users"))]
async fn search_users(
    body: JsonBody<SearchUsersRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryValueSearchResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    require_demo_directory_provider(state)?;
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
#[tracing::instrument(skip_all, fields(op = "cx.directory.resolve_handle"))]
async fn resolve_handle(
    body: JsonBody<ResolveHandleRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ResolveHandleResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    require_demo_directory_provider(state)?;
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
        Some(actor) => {
            // Spec 0a5ab85: audience-bearing response. The directory MUST
            // bind the claim to the requester's invocation context. We
            // default to the explicit `audience` param, falling back to
            // `requester` (so a verifier checking `audience == self` passes).
            let audience = body
                .audience
                .or(body.requester)
                .unwrap_or_else(|| state.config.service_did.clone());
            let did = actor["did"].as_str().unwrap_or_default().to_owned();
            let handle_claim = signed_handle_claim(state, &normalized, &did, &audience)?;
            json_ok(ResolveHandleResponse {
                handle: normalized,
                did,
                actor,
                audience: Some(audience),
                handle_claim: Some(handle_claim),
            })
        }
        None => Err(AppError::not_found("not found")),
    }
}

fn signed_handle_claim(
    state: &AppState,
    handle: &str,
    did: &str,
    audience: &str,
) -> Result<HandleClaim, AppError> {
    let service_did = state.config.service_did.clone();
    let service_domain = service_did
        .strip_prefix("did:web:")
        .map(|value| value.replace(':', "."))
        .unwrap_or_else(|| "soland.local".to_owned());
    let localpart = handle
        .trim_start_matches('@')
        .split(':')
        .next()
        .unwrap_or(handle)
        .to_ascii_lowercase();
    let handle_uri = format!("contrix://{service_domain}/users/{localpart}");
    let created_at = now();
    let expires_at = created_at + chrono::Duration::hours(24);
    let unsigned = json!({
        "schema": "cx.schema.handle_claim.v1",
        "handle": handle,
        "handle_uri": handle_uri,
        "handle_aliases": [format!("acct:{localpart}@{service_domain}")],
        "subject": did,
        "issuer": service_did,
        "issuer_service_did": service_did,
        "binding_state": "verified",
        "claim_type": "service_handle",
        "visibility": "public",
        "audience": audience,
        "member_delivery_binding": {
            "recipient_service_did": service_did,
            "recipient_service_type": "principal_server",
            "binding_source": "explicit",
            "delivery_modes": ["events", "sync", "to_device", "push", "key_packages"],
        },
        "created_at": created_at.to_rfc3339(),
        "expires_at": expires_at.to_rfc3339(),
    });
    let canonical_bytes = canonical::canonical_json_bytes(&unsigned).map_err(|err| {
        AppError::internal(format!("handle claim canonicalization failed: {err}"))
    })?;
    let signer_did = Did::new(service_did.clone()).map_err(|err| {
        AppError::internal(format!("invalid service DID for handle claim: {err}"))
    })?;
    let signer = Ed25519MoveSigner::new(
        (*state.anchorer_signing_key()).clone(),
        signer_did,
        format!("{service_did}#directory-handle-claim"),
    );
    let signature = MoveSigner::sign_payload(&signer, &canonical_bytes)
        .map_err(|err| AppError::internal(format!("handle claim signing failed: {err}")))?;

    Ok(HandleClaim {
        schema: "cx.schema.handle_claim.v1".to_owned(),
        handle: handle.to_owned(),
        handle_uri: Some(handle_uri),
        handle_aliases: vec![format!("acct:{localpart}@{service_domain}")],
        subject: did.to_owned(),
        issuer: service_did.clone(),
        issuer_service_did: Some(service_did.clone()),
        binding_state: "verified".to_owned(),
        claim_type: Some("service_handle".to_owned()),
        visibility: Some("public".to_owned()),
        audience: Some(audience.to_owned()),
        challenge: None,
        claim_scope: BTreeMap::new(),
        member_delivery_binding: Some(HandleClaimDeliveryBinding {
            recipient_service_did: service_did,
            recipient_service_type: Some("principal_server".to_owned()),
            binding_source: "explicit".to_owned(),
            delivery_modes: vec![
                "events".to_owned(),
                "sync".to_owned(),
                "to_device".to_owned(),
                "push".to_owned(),
                "key_packages".to_owned(),
            ],
            service_acceptance_ref: None,
            policy_ref: None,
        }),
        claims: Vec::new(),
        created_at: created_at.to_rfc3339(),
        expires_at: Some(expires_at.to_rfc3339()),
        verified_at: None,
        source_refs: Vec::new(),
        proofs: vec![HandleClaimProof {
            kind: "detached_jws".to_owned(),
            alg: Some(signature.alg),
            verification_method: Some(signature.verification_method),
            payload_digest: Some(signature.payload_digest.as_str().to_owned()),
            created_at: Some(signature.created_at.to_rfc3339()),
            jws: Some(signature.jws),
        }],
    })
}

#[endpoint(
    operation_id = "cx.directory.private_contact_discovery",
    tags("directory"),
    summary = "Privacy-preserving contact discovery over padded identifier batches"
)]
#[tracing::instrument(skip_all, fields(op = "cx.directory.private_contact_discovery"))]
async fn private_contact_discovery(
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    require_demo_directory_provider(state)?;
    let session = authenticated_session(state, req).ok();
    let body = body.into_inner();
    let contacts = body
        .get("contacts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let visible = demo_actors(state)
        .into_iter()
        .filter(|actor| actor_visible_to(state, actor, session.as_ref()))
        .collect::<Vec<_>>();
    let mut matches = Vec::new();
    for contact in contacts {
        let needle = contact
            .get("identifier")
            .or_else(|| contact.get("handle"))
            .or_else(|| contact.get("did"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        if needle.is_empty() {
            continue;
        }
        if let Some(actor) = visible.iter().find(|actor| {
            actor
                .get("did")
                .and_then(Value::as_str)
                .is_some_and(|did| did.eq_ignore_ascii_case(&needle))
                || actor
                    .get("handle")
                    .and_then(Value::as_str)
                    .is_some_and(|handle| handle.eq_ignore_ascii_case(&needle))
        }) {
            matches.push(json!({
                "contact_ref": contact.get("ref").cloned().unwrap_or(Value::Null),
                "did": actor.get("did").cloned().unwrap_or(Value::Null),
                "handle": actor.get("handle").cloned().unwrap_or(Value::Null),
                "proof": {
                    "type": "directory_private_contact_discovery_dev",
                    "issued_at": now(),
                }
            }));
        }
    }
    json_ok(json!({
        "matches": matches,
        "proofs": [],
        "retry_after_ms": Value::Null,
        "privacy_profile": body.get("privacy_profile").cloned().unwrap_or_else(|| json!("padded_batch_dev")),
    }))
}

#[endpoint(
    operation_id = "cx.directory.announce",
    tags("directory"),
    summary = "Announce a discoverable directory resource"
)]
#[tracing::instrument(skip_all, fields(op = "cx.directory.announce"))]
async fn directory_announce(
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = authenticated_session(state, req).map_err(|(status, code, message)| {
        AppError::invalid_param(message)
            .with_status(status)
            .with_wire_code(code)
    })?;
    let body = body.into_inner();
    let resource_kind = body
        .get("resource_kind")
        .and_then(Value::as_str)
        .unwrap_or("realm");
    let resource_id = body
        .get("resource_id")
        .or_else(|| body.get("realm_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::missing_param("resource_id is required"))?;
    if resource_kind == "realm" && !super::space_has_member(state, resource_id, &session.actor) {
        return Err(AppError::capability_denied(
            "directory announcement requires realm membership",
        ));
    }
    let announcement_id = format!(
        "cx:announcement:{}",
        super::sha256_hex(
            format!("{}:{}:{}", session.actor, resource_kind, resource_id).as_bytes()
        )
    );
    json_ok(json!({
        "ok": true,
        "announcement_id": announcement_id,
        "resource_kind": resource_kind,
        "resource_id": resource_id,
        "announced_by": session.actor,
        "valid_until": (now() + chrono::Duration::hours(24)).to_rfc3339(),
    }))
}

#[endpoint(
    operation_id = "cx.directory.withdraw",
    tags("directory"),
    summary = "Withdraw a previously-announced directory resource"
)]
#[tracing::instrument(skip_all, fields(op = "cx.directory.withdraw"))]
async fn directory_withdraw(
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = authenticated_session(state, req).map_err(|(status, code, message)| {
        AppError::invalid_param(message)
            .with_status(status)
            .with_wire_code(code)
    })?;
    let body = body.into_inner();
    let announcement_id = body
        .get("announcement_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            body.get("resource_id")
                .and_then(Value::as_str)
                .map(|resource_id| {
                    format!(
                        "cx:announcement:{}",
                        super::sha256_hex(
                            format!("{}:realm:{}", session.actor, resource_id).as_bytes()
                        )
                    )
                })
        })
        .ok_or_else(|| AppError::missing_param("announcement_id or resource_id is required"))?;
    json_ok(json!({
        "ok": true,
        "announcement_id": announcement_id,
        "withdrawn_by": session.actor,
        "withdrawn_at": now().to_rfc3339(),
        "reason": body.get("reason").cloned().unwrap_or(Value::Null),
    }))
}

#[endpoint(
    operation_id = "cx.directory.push.register",
    tags("directory"),
    summary = "Subscribe to directory update notifications"
)]
#[tracing::instrument(skip_all, fields(op = "cx.directory.push.register"))]
async fn directory_subscribe(
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = authenticated_session(state, req).ok();
    let body = body.into_inner();
    json_ok(json!({
        "ok": true,
        "subscription_id": ids::generate("directory_subscription"),
        "cursor": crate::routing::sync_token(state),
        "subscriber": session.map(|session| session.actor).unwrap_or_else(|| "anonymous".to_owned()),
        "resource_kinds": body.get("resource_kinds").cloned().unwrap_or_else(|| json!(["realm", "actor", "organization"])),
        "updates": [],
    }))
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

fn require_demo_directory_provider(state: &AppState) -> Result<(), AppError> {
    if state.config.development_mode {
        return Ok(());
    }
    Err(AppError::not_found("directory provider not configured"))
}

pub fn demo_organization(spaces: &[&RealmDirectoryEntry], service_did: &str) -> Value {
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
