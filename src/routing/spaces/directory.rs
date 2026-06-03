//! Directory + handle / actor / organization resolution handlers.
//!
//! Surfaces:
//! - `GET  /_cokret/find/directory/describe`            — capability + profile probe
//! - `POST /_cokret/find/directory/search-realms`       — fuzzy text + visibility filter
//! - `POST /_cokret/find/directory/resolve-realm`       — by id / alias / invite_token /
//!   signed_link
//! - `POST /_cokret/find/directory/resolve-target`      — Realm / Flow / Message address preview
//! - `POST /_cokret/find/directory/search-organizations`
//! - `POST /_cokret/find/directory/resolve-organization`
//! - `POST /_cokret/find/directory/search-actors`
//! - `POST /_cokret/find/directory/search-users`        — same as search-actors via body `q`
//! - `POST /_cokret/find/directory/resolve-handle`
//!
//! Demo data lives here too — `demo_organization` / `demo_actors` are
//! placeholders until a real `actors` / `organizations` / `handles`
//! provider lands. They are gated to development mode so production
//! deployments do not expose built-in identities.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, TimeZone, Utc};
use cokret_sdk::{
    Did, Ed25519MoveSigner, LinkType, MoveSigner, RealmRef, TargetDescriptor, canonical,
    parse_address, target_digest,
};
use ed25519_dalek::{Signature, Verifier};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{
    authenticated_session, device_inventory_to_json, handle_for_did, invite_token_matches_space,
    invite_token_space_id, is_space_deleted, normalize_handle, now, space_discoverability,
    space_history_visibility, space_resolvable_to, space_search_discoverability,
    space_search_visible_to,
};
use crate::error::AppError;
use crate::ids;
use crate::result::{JsonResult, json_ok};
use crate::routing::organizations;
use crate::state::{AppState, RealmDirectoryEntry, RealmDirectoryQuery, SessionRecord};
use crate::wire::{
    DirectoryDescribeResBody, DirectoryValueSearchResponse, HandleClaim,
    HandleClaimDeliveryBinding, HandleClaimProof, RealmJoinCandidate, ResolveHandleRequest,
    ResolveHandleResponse, ResolveOrganizationRequest, ResolveOrganizationResponse,
    ResolveRealmRequest, ResolveRealmResponse, SearchActorsRequest, SearchOrganizationsRequest,
    SearchRealmsRequest, SearchRealmsResponse, SearchUsersRequest,
};

/// Snapshot the in-memory realm directory (under a short lock) and return the
/// owned entries that are not tombstoned. The deleted check is async (it reads
/// `realm_meta`), so we must not run it while holding the `realms` lock — we
/// collect candidates first, drop the guard, then filter with `.await`.
async fn live_realm_entries(state: &AppState) -> Vec<RealmDirectoryEntry> {
    let candidates: Vec<RealmDirectoryEntry> = {
        let spaces = state.realms.lock().expect("spaces lock");
        spaces
            .search(Default::default())
            .into_iter()
            .cloned()
            .collect()
    };
    let mut live = Vec::new();
    for space in candidates {
        if !is_space_deleted(state, space.realm_id.as_str()).await {
            live.push(space);
        }
    }
    live
}

pub(crate) fn router() -> Router {
    Router::new()
        .push(Router::with_path("directory/describe").get(directory_describe))
        .push(Router::with_path("directory/search-realms").post(search_realms))
        .push(Router::with_path("directory/resolve-realm").post(resolve_realm))
        .push(Router::with_path("directory/resolve-target").post(resolve_target))
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
        discovery_profiles: vec!["ck.profile.directory_service.v1".to_owned()],
        restricted_query_proof: false,
    }));
}

#[endpoint(
    operation_id = "ck.directory.search_realms",
    tags("directory"),
    summary = "Fuzzy-text + visibility-filtered realm search"
)]
#[tracing::instrument(skip_all, fields(op = "ck.directory.search_realms"))]
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
    let session = authenticated_session(state, req).await.ok();
    let candidates: Vec<RealmDirectoryEntry> = {
        let spaces = state.realms.lock().expect("spaces lock");
        spaces.search(query).into_iter().cloned().collect()
    };
    let mut results = Vec::new();
    for space in candidates {
        if space_search_visible_to(state, &space, session.as_ref()).await {
            results.push(space);
        }
    }
    json_ok(SearchRealmsResponse {
        results,
        next_cursor: None,
    })
}

#[endpoint(
    operation_id = "ck.directory.resolve_realm",
    tags("directory"),
    summary = "Resolve a realm by id / alias / invite_token / signed_link"
)]
#[tracing::instrument(skip_all, fields(op = "ck.directory.resolve_realm"))]
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

    let session = authenticated_session(state, req).await.ok();
    let invite_space_id = match body.invite_token.as_deref() {
        Some(token) => invite_token_space_id(state, token).await,
        None => None,
    };
    let candidates: Vec<RealmDirectoryEntry> = {
        let spaces = state.realms.lock().expect("spaces lock");
        spaces
            .search(Default::default())
            .into_iter()
            .cloned()
            .collect()
    };
    let mut space = None;
    for entry in candidates {
        let matches_query = body
            .realm_id
            .as_deref()
            .is_some_and(|id| id == entry.realm_id.as_str())
            || invite_space_id
                .as_deref()
                .is_some_and(|id| id == entry.realm_id.as_str())
            || body
                .alias
                .as_deref()
                .is_some_and(|alias| alias.eq_ignore_ascii_case(&entry.name));
        if matches_query
            && space_resolvable_to(
                state,
                &entry,
                session.as_ref(),
                body.invite_token.as_deref(),
                body.signed_link.as_deref(),
            )
            .await
        {
            space = Some(entry);
            break;
        }
    }
    match space {
        Some(space) => {
            let discoverability = space_discoverability(state, space.realm_id.as_str()).await;
            let searchable = space_search_discoverability(state, space.realm_id.as_str()).await;
            json_ok(ResolveRealmResponse {
                realm_preview: space.clone(),
                stripped_state: vec![json!({
                    // R1.2 (Realm/Space reversal): security-namespace
                    // event renamed from `ck.space.discovery` to
                    // `ck.realm.discovery`.
                    "type": "ck.realm.discovery",
                    "subject": "",
                    "content": {
                        "discoverability": discoverability,
                        "directory_visibility": {
                            "searchable": searchable
                        }
                    }
                })],
                join_rule: if discoverability == "public" {
                    "public".to_owned()
                } else {
                    "invite_or_request".to_owned()
                },
                join_candidates: join_candidates_for_resolved_realm(
                    state,
                    space.realm_id.as_str(),
                    discoverability.as_str(),
                ),
            })
        }
        None => Err(AppError::not_found("not found")),
    }
}

#[endpoint(
    operation_id = "ck.directory.resolve_target",
    tags("directory"),
    summary = "Resolve a Realm / Flow / Message share address to a policy-limited preview"
)]
#[tracing::instrument(skip_all, fields(op = "ck.directory.resolve_target"))]
async fn resolve_target(
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    let address = body
        .get("address")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::missing_param("address is required"))?;
    let parsed = parse_address(address).map_err(|_| AppError::not_found("not found"))?;
    let session = authenticated_session(state, req).await.ok();
    let token = body
        .get("token")
        .and_then(Value::as_str)
        .or(parsed.token.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty());

    let Some(space) = resolve_space_for_address(state, &parsed).await else {
        return Err(AppError::not_found("not found"));
    };
    if is_space_deleted(state, space.realm_id.as_str()).await {
        return Err(AppError::not_found("not found"));
    }

    let mut include_join_candidates = false;
    match parsed.link_type {
        LinkType::Reference => {
            if !space_resolvable_to(state, &space, session.as_ref(), None, None).await {
                return Err(AppError::not_found("not found"));
            }
            include_join_candidates = true;
        }
        LinkType::Invite => {
            let Some(token) = token else {
                return Err(AppError::not_found("not found"));
            };
            if !invite_token_matches_space(state, space.realm_id.as_str(), token).await {
                return Err(AppError::not_found("not found"));
            }
            if parsed.flow.is_some()
                && !optional_structured_token_target_matches(
                    token,
                    &parsed,
                    space.realm_id.as_str(),
                    LinkType::Invite,
                )
            {
                return Err(AppError::not_found("not found"));
            }
            include_join_candidates = true;
        }
        LinkType::Preview => {
            let Some(token) = token else {
                return Err(AppError::not_found("not found"));
            };
            if !preview_token_matches_policy(
                state,
                &parsed,
                space.realm_id.as_str(),
                token,
                session.as_ref(),
            )
            .await
            {
                return Err(AppError::not_found("not found"));
            }
        }
    }

    let discoverability = space_discoverability(state, space.realm_id.as_str()).await;
    let join_rule = join_rule_for_discoverability(&discoverability);
    let target_kind = target_kind_for_address(&parsed);
    let realm_preview = realm_preview_for_policy(state, &space).await;
    let mut response = serde_json::Map::new();
    response.insert("target_kind".to_owned(), json!(target_kind));
    response.insert("realm_preview".to_owned(), realm_preview);
    if let Some(object_preview) = object_preview_for_address(&parsed) {
        response.insert("object_preview".to_owned(), object_preview);
    }
    response.insert("join_rule".to_owned(), json!(join_rule));
    response.insert("as_of".to_owned(), json!(now()));
    response.insert("source_refs".to_owned(), json!([]));
    if parsed.link_type == LinkType::Preview
        && let Some(meta) = state
            .persistence
            .realm_meta()
            .get(space.realm_id.as_str())
            .await
            .ok()
            .flatten()
        && let Some(digest) = meta.preview_policy_digest
    {
        response.insert("policy_revision".to_owned(), json!(digest));
    }
    let join_candidates = if include_join_candidates {
        join_candidates_for_resolved_realm(state, space.realm_id.as_str(), discoverability.as_str())
    } else {
        Vec::new()
    };
    response.insert("join_candidates".to_owned(), json!(join_candidates));
    json_ok(Value::Object(response))
}

async fn resolve_space_for_address(
    state: &AppState,
    parsed: &cokret_sdk::ParsedAddress,
) -> Option<RealmDirectoryEntry> {
    let candidates: Vec<RealmDirectoryEntry> = {
        let spaces = state.realms.lock().expect("spaces lock");
        spaces
            .search(Default::default())
            .into_iter()
            .cloned()
            .collect()
    };
    candidates.into_iter().find(|entry| match &parsed.realm {
        RealmRef::RealmId(uuid) => entry.realm_id.as_str() == format!("ck:realm:{uuid}"),
        RealmRef::Alias(alias) => entry.name.eq_ignore_ascii_case(alias),
    })
}

fn target_kind_for_address(parsed: &cokret_sdk::ParsedAddress) -> &'static str {
    if parsed.message.is_some() {
        "message"
    } else if parsed.flow.is_some() {
        "flow"
    } else {
        "realm"
    }
}

fn join_rule_for_discoverability(discoverability: &str) -> &'static str {
    if discoverability == "public" {
        "public"
    } else {
        "invite_or_request"
    }
}

async fn realm_preview_for_policy(state: &AppState, space: &RealmDirectoryEntry) -> Value {
    let meta = state
        .persistence
        .realm_meta()
        .get(space.realm_id.as_str())
        .await
        .ok()
        .flatten();
    let fields = meta
        .as_ref()
        .and_then(|record| record.preview_policy.as_ref())
        .and_then(|policy| policy.get("fields"))
        .and_then(Value::as_array)
        .map(|fields| {
            fields
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<&str>>()
        })
        .filter(|fields| !fields.is_empty())
        .unwrap_or_else(|| vec!["title", "summary", "join_rule"]);

    let mut preview = serde_json::Map::new();
    if fields.contains(&"title") {
        preview.insert("title".to_owned(), json!(space.name));
    }
    if fields.contains(&"summary") {
        preview.insert("summary".to_owned(), json!(space.description));
    }
    if fields.contains(&"join_rule") {
        let discoverability = space_discoverability(state, space.realm_id.as_str()).await;
        preview.insert(
            "join_rule".to_owned(),
            json!(join_rule_for_discoverability(&discoverability)),
        );
    }
    if fields.contains(&"history_visibility") {
        preview.insert(
            "history_visibility".to_owned(),
            json!(space_history_visibility(state, space.realm_id.as_str()).await),
        );
    }
    if fields.contains(&"member_count_bucket") {
        preview.insert(
            "member_count_bucket".to_owned(),
            json!(member_count_bucket(space.members.len())),
        );
    }
    if fields.contains(&"preview_ref") {
        preview.insert("preview_ref".to_owned(), json!(space.realm_id.as_str()));
    }
    if fields.contains(&"server_hints") {
        preview.insert(
            "server_hints".to_owned(),
            json!({
                "service_did": state.config.service_did.clone(),
                "endpoint": state.config.public_base_url.clone(),
            }),
        );
    }

    json!({
        "realm_id": space.realm_id.as_str(),
        "title": space.name,
        "preview": preview,
    })
}

fn member_count_bucket(count: usize) -> &'static str {
    match count {
        0 => "0",
        1 => "1",
        2..=10 => "2_10",
        11..=100 => "11_100",
        _ => "100_plus",
    }
}

fn object_preview_for_address(parsed: &cokret_sdk::ParsedAddress) -> Option<Value> {
    let flow_id = parsed.flow.as_deref().map(|flow| format!("ck:flow:{flow}"));
    let message_id = parsed
        .message
        .as_deref()
        .map(|message| format!("ck:message:{message}"));
    flow_id.map(|flow_id| {
        let mut preview = serde_json::Map::new();
        preview.insert("flow_id".to_owned(), json!(flow_id));
        if let Some(message_id) = message_id {
            preview.insert("message_id".to_owned(), json!(message_id));
        }
        preview.insert("kind".to_owned(), json!(target_kind_for_address(parsed)));
        Value::Object(preview)
    })
}

async fn preview_token_matches_policy(
    state: &AppState,
    parsed: &cokret_sdk::ParsedAddress,
    realm_id: &str,
    token: &str,
    session: Option<&SessionRecord>,
) -> bool {
    let Some(meta) = state
        .persistence
        .realm_meta()
        .get(realm_id)
        .await
        .ok()
        .flatten()
    else {
        return false;
    };
    let Some(policy) = meta.preview_policy.as_ref() else {
        return false;
    };
    if policy.get("mode").and_then(Value::as_str) == Some("none") {
        return false;
    }
    if !policy_array_contains(policy, "audiences", "link_token_holder") {
        return false;
    }

    let Some(claim) = decode_preview_token(token) else {
        return false;
    };
    if claim.get("link_type").and_then(Value::as_str) != Some("preview") {
        return false;
    }
    if claim
        .get("nonce")
        .and_then(Value::as_str)
        .is_none_or(|nonce| nonce.trim().is_empty())
    {
        return false;
    }
    if token_expired(&claim) {
        return false;
    }
    if !token_audience_matches(&claim, session) {
        return false;
    }
    if !preview_token_signature_valid(state, &claim) {
        return false;
    }
    let expected_policy_digest = meta
        .preview_policy_digest
        .as_deref()
        .map(str::to_owned)
        .or_else(|| canonical_value_digest(policy));
    if claim
        .get("preview_policy_digest")
        .and_then(Value::as_str)
        .map(str::to_owned)
        != expected_policy_digest
    {
        return false;
    }
    token_target_matches_claim(&claim, parsed, realm_id, LinkType::Preview)
}

fn optional_structured_token_target_matches(
    token: &str,
    parsed: &cokret_sdk::ParsedAddress,
    realm_id: &str,
    effective_link_type: LinkType,
) -> bool {
    match decode_preview_token(token) {
        Some(claim) if claim.get("target_digest").is_some() => {
            token_target_matches_claim(&claim, parsed, realm_id, effective_link_type)
        }
        Some(_) => false,
        None => parsed.flow.is_none() && parsed.message.is_none(),
    }
}

fn token_target_matches_claim(
    claim: &Value,
    parsed: &cokret_sdk::ParsedAddress,
    realm_id: &str,
    effective_link_type: LinkType,
) -> bool {
    let Some(token_digest) = claim.get("target_digest").and_then(Value::as_str) else {
        return false;
    };
    let mut descriptor = TargetDescriptor::from_parsed(parsed);
    descriptor.set_realm_id(realm_id);
    descriptor.link_type = effective_link_type;
    target_digest(&descriptor)
        .ok()
        .as_deref()
        .is_some_and(|expected| expected == token_digest)
}

fn decode_preview_token(token: &str) -> Option<Value> {
    let encoded = token
        .trim()
        .strip_prefix("ck:preview-token:")
        .unwrap_or_else(|| token.trim());
    if encoded.starts_with('{') {
        return serde_json::from_str(encoded).ok();
    }
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn token_expired(claim: &Value) -> bool {
    let Some(expires_at) = parse_token_expiry(claim.get("exp")) else {
        return true;
    };
    expires_at <= Utc::now()
}

fn parse_token_expiry(value: Option<&Value>) -> Option<DateTime<Utc>> {
    match value? {
        Value::String(value) => DateTime::parse_from_rfc3339(value)
            .ok()
            .map(|datetime| datetime.with_timezone(&Utc)),
        Value::Number(value) => {
            let raw = value.as_i64()?;
            if raw > 10_000_000_000 {
                Utc.timestamp_millis_opt(raw).single()
            } else {
                Utc.timestamp_opt(raw, 0).single()
            }
        }
        _ => None,
    }
}

fn token_audience_matches(claim: &Value, session: Option<&SessionRecord>) -> bool {
    let matches_audience = |aud: &str| {
        aud == "anonymous"
            || session.is_some_and(|session| {
                aud == session.actor || aud == "authenticated" || aud == "link_token_holder"
            })
    };
    match claim.get("aud") {
        Some(Value::String(aud)) => matches_audience(aud),
        Some(Value::Array(audiences)) => audiences
            .iter()
            .filter_map(Value::as_str)
            .any(matches_audience),
        _ => false,
    }
}

fn preview_token_signature_valid(state: &AppState, claim: &Value) -> bool {
    if claim.get("iss").and_then(Value::as_str) != Some(state.config.service_did.as_str()) {
        return false;
    }
    let Some(proof) = claim.get("proof").and_then(Value::as_object) else {
        return false;
    };
    if proof.get("kind").and_then(Value::as_str) != Some("detached_jws")
        || proof.get("alg").and_then(Value::as_str) != Some("EdDSA")
    {
        return false;
    }
    let Some(verification_method) = proof.get("verification_method").and_then(Value::as_str) else {
        return false;
    };
    if verification_method != state.config.service_did
        && !verification_method.starts_with(&format!("{}#", state.config.service_did))
    {
        return false;
    }
    let mut unsigned = claim.clone();
    if let Value::Object(object) = &mut unsigned {
        object.remove("proof");
    } else {
        return false;
    }
    let Ok(canonical_bytes) = canonical::canonical_json_bytes(&unsigned) else {
        return false;
    };
    let expected_digest = canonical::sha256_digest(&canonical_bytes);
    if proof.get("payload_digest").and_then(Value::as_str) != Some(expected_digest.as_str()) {
        return false;
    }
    let Some(jws) = proof.get("jws").and_then(Value::as_str) else {
        return false;
    };
    verify_detached_jws_with_service_key(&canonical_bytes, jws, state)
}

fn verify_detached_jws_with_service_key(
    canonical_bytes: &[u8],
    jws: &str,
    state: &AppState,
) -> bool {
    let mut parts = jws.split('.');
    let (Some(protected_b64), Some(detached_payload), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    if !detached_payload.is_empty() {
        return false;
    }
    let Ok(protected) = URL_SAFE_NO_PAD.decode(protected_b64) else {
        return false;
    };
    let Ok(protected) = serde_json::from_slice::<Value>(&protected) else {
        return false;
    };
    if protected.get("alg").and_then(Value::as_str) != Some("EdDSA") {
        return false;
    }
    let Ok(signature_bytes) = URL_SAFE_NO_PAD.decode(signature_b64) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&signature_bytes) else {
        return false;
    };
    let signing_input = format!(
        "{protected_b64}.{}",
        URL_SAFE_NO_PAD.encode(canonical_bytes)
    );
    state
        .anchorer_signing_key()
        .verifying_key()
        .verify(signing_input.as_bytes(), &signature)
        .is_ok()
}

fn policy_array_contains(policy: &Value, field: &str, expected: &str) -> bool {
    policy
        .get(field)
        .and_then(Value::as_array)
        .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(expected)))
}

fn canonical_value_digest(value: &Value) -> Option<String> {
    canonical::canonical_sha256(value).ok()
}

fn join_candidates_for_resolved_realm(
    state: &AppState,
    realm_id: &str,
    discoverability: &str,
) -> Vec<RealmJoinCandidate> {
    let observed_at = now();
    let join_methods = if discoverability == "public" {
        vec!["member_join".to_owned(), "invite_accept".to_owned()]
    } else {
        vec![
            "invite_accept".to_owned(),
            "knock".to_owned(),
            "application".to_owned(),
        ]
    };
    vec![RealmJoinCandidate {
        realm_id: realm_id.to_owned(),
        service_did: state.config.service_did.clone(),
        service_type: "principal_server".to_owned(),
        role: "primary".to_owned(),
        endpoint: Some(state.config.public_base_url.clone()),
        operations: vec!["ck.events.submit".to_owned()],
        join_methods,
        priority: Some(0),
        source: "directory_ingest".to_owned(),
        source_refs: None,
        frontier_ref: None,
        as_of: observed_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        expires_at: (observed_at + chrono::Duration::minutes(10))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    }]
}

#[endpoint(
    operation_id = "ck.directory.search_organizations",
    tags("directory"),
    summary = "Fuzzy-text search across known organizations (demo data for now)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.directory.search_organizations"))]
async fn search_organizations(
    body: JsonBody<SearchOrganizationsRequest>,
    depot: &mut Depot,
) -> JsonResult<DirectoryValueSearchResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    let limit = checked_limit(body.limit)?;
    let mut results = organizations::organization_records_for_directory(state)
        .into_iter()
        .filter(|organization| query_matches(organization, body.query.as_deref()))
        .collect::<Vec<_>>();
    let space_entries = live_realm_entries(state).await;
    let space_refs: Vec<&RealmDirectoryEntry> = space_entries.iter().collect();
    let organization = demo_organization(&space_refs, &state.config.service_did);
    if state.config.development_mode && query_matches(&organization, body.query.as_deref()) {
        results.push(organization);
    }
    json_ok(DirectoryValueSearchResponse {
        results: results.into_iter().take(limit).collect(),
        next_cursor: None,
    })
}

#[endpoint(
    operation_id = "ck.directory.resolve_organization",
    tags("directory"),
    summary = "Resolve an organization by organization_id or handle"
)]
#[tracing::instrument(skip_all, fields(op = "ck.directory.resolve_organization"))]
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
    if let Some(organization) = organizations::organization_records_for_directory(state)
        .into_iter()
        .find(|organization| {
            body.organization_id.as_deref().is_some_and(|id| {
                organization["organization_id"].as_str() == Some(id)
                    || organization["organization_did"].as_str() == Some(id)
            }) || body.handle.as_deref().is_some_and(|handle| {
                organization["handle"]
                    .as_str()
                    .is_some_and(|candidate| candidate.eq_ignore_ascii_case(handle))
            })
        })
    {
        let spaces = organization["spaces"]
            .as_array()
            .into_iter()
            .flat_map(|array| array.iter())
            .filter_map(Value::as_str)
            .map(|realm_id| json!({ "realm_id": realm_id }))
            .collect();
        return json_ok(ResolveOrganizationResponse {
            organization,
            spaces,
        });
    }
    if !state.config.development_mode {
        return Err(AppError::not_found("not found"));
    }

    let space_entries = live_realm_entries(state).await;
    let space_refs: Vec<&RealmDirectoryEntry> = space_entries.iter().collect();
    let organization = demo_organization(&space_refs, &state.config.service_did);
    let matches_id = body
        .organization_id
        .as_deref()
        .is_some_and(|id| id == organization["organization_id"].as_str().unwrap_or_default());
    let matches_handle = body
        .handle
        .as_deref()
        .is_some_and(|handle| handle.eq_ignore_ascii_case("@cokret-demo"));
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
    operation_id = "ck.directory.search_actors",
    tags("directory"),
    summary = "Search actors visible to the calling session"
)]
#[tracing::instrument(skip_all, fields(op = "ck.directory.search_actors"))]
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
        && organization_id != "ck:org:demo"
    {
        return json_ok(DirectoryValueSearchResponse {
            results: Vec::new(),
            next_cursor: None,
        });
    }

    let session = authenticated_session(state, req).await.ok();
    let mut results: Vec<Value> = Vec::new();
    for actor in demo_actors(state).await {
        if results.len() >= limit {
            break;
        }
        if actor_visible_to(state, &actor, session.as_ref()).await
            && query_matches(&actor, body.query.as_deref())
        {
            results.push(actor);
        }
    }
    json_ok(DirectoryValueSearchResponse {
        results,
        next_cursor: None,
    })
}

#[endpoint(
    operation_id = "ck.directory.search_users",
    tags("directory"),
    summary = "Search users via a POST body to avoid query-string leakage"
)]
#[tracing::instrument(skip_all, fields(op = "ck.directory.search_users"))]
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
    let session = authenticated_session(state, req).await.ok();
    // DIR-1 (R3.1, cokret-spec @ 7157ee8) — `ck.directory.search_users`
    // response rows MUST NOT carry `handle_uri`. Only `handle` (canonical
    // `<localpart>:<domain>`) + optional `display_name`/`verified`/`subject`
    // survive the rename. Other actor metadata (presence, organization,
    // avatar) goes through `ck.directory.search_actors` or
    // `ck.directory.resolve-handle`.
    let mut results: Vec<Value> = Vec::new();
    for actor in demo_actors(state).await {
        if results.len() >= limit {
            break;
        }
        if actor_visible_to(state, &actor, session.as_ref()).await
            && query_matches(&actor, query.as_deref())
        {
            results.push(project_search_users_row(state, &actor));
        }
    }
    json_ok(DirectoryValueSearchResponse {
        results,
        next_cursor: None,
    })
}

/// DIR-1 — project a [`demo_actors`] row into the spec-shape
/// `ck.directory.search_users` response entry. Only `handle` (canonical
/// `<localpart>:<domain>` per handle-claim.schema.json, cokret-spec @
/// 7157ee8) + optional `display_name`/`verified`/`subject` survive.
fn project_search_users_row(state: &AppState, actor: &Value) -> Value {
    let service_domain = state
        .config
        .service_did
        .strip_prefix("did:web:")
        .map(|value| value.replace(':', "."))
        .unwrap_or_else(|| "soland.local".to_owned());
    let raw_handle = actor
        .get("handle")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim_start_matches('@')
        .to_ascii_lowercase();
    let canonical = if raw_handle.is_empty() {
        String::new()
    } else if raw_handle.contains(':') {
        raw_handle
    } else {
        format!("{raw_handle}:{service_domain}")
    };
    let mut row = serde_json::Map::new();
    row.insert("handle".to_owned(), json!(canonical));
    if let Some(display_name) = actor.get("display_name").and_then(Value::as_str) {
        row.insert("display_name".to_owned(), json!(display_name));
    }
    if let Some(did) = actor.get("did").and_then(Value::as_str) {
        row.insert("subject".to_owned(), json!(did));
    }
    if let Some(verified) = actor.get("verified") {
        row.insert("verified".to_owned(), verified.clone());
    }
    Value::Object(row)
}

#[endpoint(
    operation_id = "ck.directory.resolve_handle",
    tags("directory"),
    summary = "Resolve a normalized actor handle (e.g. `@alice`) to a DID"
)]
#[tracing::instrument(skip_all, fields(op = "ck.directory.resolve_handle"))]
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
    let session = authenticated_session(state, req).await.ok();
    let mut actor = None;
    for candidate in demo_actors(state).await {
        let handle_matches = candidate["handle"]
            .as_str()
            .is_some_and(|handle| handle == normalized);
        if handle_matches && actor_visible_to(state, &candidate, session.as_ref()).await {
            actor = Some(candidate);
            break;
        }
    }
    match actor {
        Some(actor) => {
            // Spec 0a5ab85: audience-bearing response. The directory MUST
            // bind the claim to the requester's invocation context. We
            // default to the explicit `audience` param, falling back to
            // `realm_id` for membership-builder resolves, then `requester`.
            let audience = body
                .audience
                .or(body.realm_id)
                .or(body.requester)
                .unwrap_or_else(|| state.config.service_did.clone());
            let did = actor["did"].as_str().unwrap_or_default().to_owned();
            let handle_claim = signed_handle_claim(state, &normalized, &did, &audience)?;
            // HDLREN-2 — surface the canonical `<localpart>:<domain>` handle
            // from the freshly signed claim so the top-level response field
            // matches handle-claim.schema.json (cokret-spec @ 7157ee8). The
            // request's `@alice` UI form is normalized away here.
            let canonical_handle = handle_claim.handle.clone();
            let member_delivery_binding = handle_claim.member_delivery_binding.clone();
            json_ok(ResolveHandleResponse {
                handle: canonical_handle,
                subject: did.clone(),
                did,
                actor,
                audience: Some(audience),
                handle_claim: Some(handle_claim),
                member_delivery_binding,
                source_refs: Vec::new(),
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
    // HC-SOL-2 (R3.2) — never issue a claim whose `subject` is not a
    // holder/principal DID (e.g. a `ck:actor:` / `ck:account:` typed id).
    // Delegates to the SDK rejection rule via the shared wire validator.
    if let Err(rejection) =
        crate::wire_validators::handle_claim_subject::validate_subject(&json!({ "subject": did }))
    {
        return Err(AppError::new(
            crate::error::ErrorCode::SchemaViolation,
            rejection.message,
        ));
    }
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
    // HDLREN-1 (cokret-spec @ 7157ee8) — canonical handle wire form is
    // `<localpart>:<domain>`. The retired `cokret://<domain>/users/<localpart>`
    // URI is dropped from R3.1 wire; `acct:<local>@<domain>` survives as an
    // interop alias only.
    let canonical_handle = format!("{localpart}:{service_domain}");
    let created_at = now();
    let expires_at = created_at + chrono::Duration::hours(24);
    let unsigned = json!({
        "schema": "ck.schema.handle_claim.v1",
        "handle": canonical_handle,
        "handle_aliases": [format!("acct:{localpart}@{service_domain}")],
        "subject": did,
        "issuer": service_did,
        "issuer_service_did": service_did,
        "binding_state": "verified",
        // HC-SOL-1 (R3.2, cokret-spec @ b56cab1) — `claim_type=service_handle`
        // is removed from `ck.schema.handle_claim.v1`. The demo directory
        // issues a user/principal handle claim, so `user_handle` is the
        // correct class here.
        "claim_kind": "handle_binding",
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

    let claim = HandleClaim {
        schema: "ck.schema.handle_claim.v1".to_owned(),
        handle: canonical_handle,
        handle_aliases: vec![format!("acct:{localpart}@{service_domain}")],
        subject: did.to_owned(),
        issuer: service_did.clone(),
        issuer_service_did: Some(service_did.clone()),
        binding_state: "verified".to_owned(),
        // HC-SOL-1 — see the unsigned-projection comment above; v1 dropped
        // `service_handle`.
        claim_kind: Some("handle_binding".to_owned()),
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
            policy_event_ref: None,
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
    };
    if let Ok(envelope) = serde_json::to_value(&claim) {
        let _ = state
            .member_identity
            .lock()
            .expect("member_identity lock")
            .upsert_handle_claim_envelope(envelope);
    }
    Ok(claim)
}

#[endpoint(
    operation_id = "ck.directory.private_contact_discovery",
    tags("directory"),
    summary = "Privacy-preserving contact discovery over padded identifier batches"
)]
#[tracing::instrument(skip_all, fields(op = "ck.directory.private_contact_discovery"))]
async fn private_contact_discovery(
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    require_demo_directory_provider(state)?;
    let session = authenticated_session(state, req).await.ok();
    let body = body.into_inner();
    let contacts = body
        .get("contacts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut visible: Vec<Value> = Vec::new();
    for actor in demo_actors(state).await {
        if actor_visible_to(state, &actor, session.as_ref()).await {
            visible.push(actor);
        }
    }
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
    operation_id = "ck.directory.announce",
    tags("directory"),
    summary = "Announce a discoverable directory resource"
)]
#[tracing::instrument(skip_all, fields(op = "ck.directory.announce"))]
async fn directory_announce(
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = authenticated_session(state, req)
        .await
        .map_err(|(status, code, message)| {
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
    if resource_kind == "realm"
        && !super::space_has_member(state, resource_id, &session.actor).await
    {
        return Err(AppError::capability_denied(
            "directory announcement requires realm membership",
        ));
    }
    let announcement_id = format!(
        "ck:announcement:{}",
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
        "expires_at": (now() + chrono::Duration::hours(24)).to_rfc3339(),
    }))
}

#[endpoint(
    operation_id = "ck.directory.withdraw",
    tags("directory"),
    summary = "Withdraw a previously-announced directory resource"
)]
#[tracing::instrument(skip_all, fields(op = "ck.directory.withdraw"))]
async fn directory_withdraw(
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = authenticated_session(state, req)
        .await
        .map_err(|(status, code, message)| {
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
                        "ck:announcement:{}",
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
    operation_id = "ck.directory.push.register",
    tags("directory"),
    summary = "Subscribe to directory update notifications"
)]
#[tracing::instrument(skip_all, fields(op = "ck.directory.push.register"))]
async fn directory_subscribe(
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = authenticated_session(state, req).await.ok();
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

pub async fn has_accepted_contact(state: &AppState, left: &str, right: &str) -> bool {
    state
        .persistence
        .contacts()
        .list_for_actor(left)
        .await
        .unwrap_or_default()
        .iter()
        .any(|contact| {
            contact.status == "accepted"
                && ((contact.requester == left && contact.target == right)
                    || (contact.requester == right && contact.target == left))
        })
}

pub async fn actor_visible_to(
    state: &AppState,
    actor: &Value,
    session: Option<&SessionRecord>,
) -> bool {
    let Some(did) = actor["did"].as_str() else {
        return false;
    };
    if did == "did:web:alice.example" {
        return true;
    }
    match session {
        Some(session) => {
            session.actor == did || has_accepted_contact(state, &session.actor, did).await
        }
        None => false,
    }
}

fn require_demo_directory_provider(state: &AppState) -> Result<(), AppError> {
    if state.config.development_mode {
        return Ok(());
    }
    Err(AppError::not_found("directory provider not configured"))
}

pub fn demo_organization(spaces: &[&RealmDirectoryEntry], service_did: &str) -> Value {
    json!({
        "organization_id": "ck:org:demo",
        "handle": "@cokret-demo",
        "name": "Cokret Demo Organization",
        "description": "Demo organization projected by soland",
        "service_did": service_did,
        "space_count": spaces.len(),
        "actor_count": 1,
    })
}

pub async fn demo_actors(state: &AppState) -> Vec<Value> {
    let mut actors = vec![json!({
        "did": "did:web:alice.example",
        "handle": "@alice",
        "display_name": "Alice Example",
        "organization_id": "ck:org:demo",
        "avatar_url": null,
        "presence": {"status": "online", "updated_at": now()},
    })];

    let accounts = state
        .persistence
        .accounts()
        .list()
        .await
        .unwrap_or_default();
    for account in accounts {
        if actors
            .iter()
            .any(|actor| actor["did"].as_str() == Some(account.did.as_str()))
        {
            continue;
        }
        let account_state = state.account_lifecycle_state(&account.did);
        // GDPR erasure / deactivation: terminal account states MUST NOT
        // surface in directory search results.
        if matches!(account_state.as_str(), "deactivated" | "erased") {
            continue;
        }
        actors.push(json!({
            "did": account.did,
            "handle": account.handle,
            "display_name": account.display_name.as_deref().unwrap_or(account.did.as_str()),
            "state": account_state.clone(),
            "account_state": account_state,
            "bio": account.bio,
            "organization_id": "ck:org:demo",
            "avatar_url": account.avatar_url,
            "presence": {"status": "offline", "updated_at": now()},
        }));
    }

    let devices = state
        .persistence
        .devices()
        .list()
        .await
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
        let account_state = state.account_lifecycle_state(did);
        if matches!(account_state.as_str(), "deactivated" | "erased") {
            continue;
        }
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
            "state": account_state.clone(),
            "account_state": account_state,
            "organization_id": "ck:org:demo",
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
