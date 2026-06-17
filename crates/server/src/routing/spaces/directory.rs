//! Directory + handle / actor / organization resolution handlers.
//!
//! Surfaces:
//! - `GET  /_cokret/find/directory/describe`            — capability + profile probe
//! - `POST /_cokret/find/directory/search-realms`       — fuzzy text + visibility filter
//! - `POST /_cokret/find/directory/resolve-realm`       — by id / alias / invite_token /
//!   signed_link
//! - `POST /_cokret/find/directory/resolve-target`      — Realm / Strand / Message address preview
//! - `POST /_cokret/find/directory/search-organizations`
//! - `POST /_cokret/find/directory/resolve-organization`
//! - `POST /_cokret/find/directory/search-actors`
//! - `POST /_cokret/find/directory/search-users`        — mention/user search via body `query`
//! - `POST /_cokret/find/directory/resolve-handle`
//! - `POST /_cokret/find/directory/resolve-agent-selector`
//! - `POST /_cokret/find/directory/list-handles-for-subject`
//! - `POST /_cokret/find/directory/announce`
//! - `POST /_cokret/find/directory/withdraw`
//! - `POST /_cokret/find/directory/push/register`
//!
//! Demo data lives here too — `demo_organization` / `demo_actors` are
//! placeholders until a real `actors` / `organizations` / `handles`
//! provider lands. They are gated to development mode so production
//! deployments do not expose built-in identities.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, TimeZone, Utc};
use cokret_sdk::models::{
    Handle as SdkHandle, HandleBindingState, HandleClaim as SdkHandleClaim, HandleVisibility,
};
use cokret_sdk::{
    AGENT_SELECTOR_CLAIM_SCHEMA, ActorPreview, AgentSelectorClaim, DeliveryBindingHint, Did,
    DirectoryActorSearchOutcome, DirectoryAgentSelectorResolutionOutcome, DirectoryAnnounceOutcome,
    DirectoryAnnounceRequestBody, DirectoryDescription, DirectoryHandleResolutionOutcome,
    DirectoryListHandlesForSubjectRequestBody, DirectoryOrganizationResolutionOutcome,
    DirectoryOrganizationSearchOutcome, DirectoryPrivateContactDiscoveryOutcome,
    DirectoryPrivateContactDiscoveryRequestBody, DirectoryPushRegisterOutcome,
    DirectoryPushRegisterRequestBody, DirectoryRealmResolutionOutcome, DirectoryRealmSearchOutcome,
    DirectoryResolveAgentSelectorRequestBody, DirectoryResolveHandleRequestBody,
    DirectoryResolveOrganizationRequestBody, DirectoryResolveRealmRequestBody,
    DirectoryResolveTargetRequestBody, DirectoryResourceKind, DirectorySearchActorsRequestBody,
    DirectorySearchOrganizationsRequestBody, DirectorySearchRealmsRequestBody,
    DirectorySearchUsersRequestBody, DirectorySubjectHandleList, DirectoryTargetResolutionOutcome,
    DirectoryUserSearchOutcome, DirectoryWithdrawOutcome, DirectoryWithdrawRequestBody,
    Ed25519MoveSigner, JoinRule, LinkType, MoveSigner, OrganizationPreview, RealmId,
    RealmJoinCandidate, RealmJoinCandidateRole, RealmJoinCandidateServiceType,
    RealmJoinCandidateSource, RealmJoinMethod, RealmMemberCountBucket, RealmMemberCountBucketLabel,
    RealmPreview, RealmRef, TargetDescriptor, TargetKind, UserSearchOutcome, canonical,
    parse_address, target_digest, validate_agent_slug,
};
use ed25519_dalek::{Signature, Verifier};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{
    authenticated_session, device_inventory_to_json, handle_for_did, invite_token_matches_realm,
    invite_token_realm_id, is_realm_deleted, now, realm_discoverability, realm_history_visibility,
    realm_resolvable_to, realm_search_visible_to,
};
use crate::error::AppError;
use crate::ids;
use crate::result::{JsonResult, json_ok};
use crate::routing::admin::audit::append_audit_log;
use crate::routing::organizations;
use crate::state::{AppState, RealmDirectoryEntry, RealmDirectoryQuery, SessionRecord};
use crate::wire::{SolandHandleClaim, SolandHandleClaimDeliveryBinding, SolandHandleClaimProof};

/// Snapshot the in-memory realm directory (under a short lock) and return the
/// owned entries that are not tombstoned. The deleted check is async (it reads
/// `realm_meta`), so we must not run it while holding the `realms` lock — we
/// collect candidates first, drop the guard, then filter with `.await`.
async fn live_realm_entries(state: &AppState) -> Vec<RealmDirectoryEntry> {
    let candidates: Vec<RealmDirectoryEntry> = {
        let realms = state.realms.lock().expect("realms lock");
        realms
            .search(Default::default())
            .into_iter()
            .cloned()
            .collect()
    };
    let mut live = Vec::new();
    for realm_entry in candidates {
        if !is_realm_deleted(state, realm_entry.realm_id.as_str()).await {
            live.push(realm_entry);
        }
    }
    live
}

pub(crate) fn protocol_router() -> Router {
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
        .push(Router::with_path("directory/resolve-agent-selector").post(resolve_agent_selector))
        .push(
            Router::with_path("directory/list-handles-for-subject").post(list_handles_for_subject),
        )
        .push(
            Router::with_path("directory/private-contact-discovery")
                .post(private_contact_discovery),
        )
        .push(Router::with_path("directory/announce").post(directory_announce))
        .push(Router::with_path("directory/withdraw").post(directory_withdraw))
        // Spec-canonical directory push-webhook registration
        // (`ck.find.directory.push.command.register`). The retired `/_soland/find/
        // directory/subscribe` mirror used the same handler under the
        // historical `subscribe` path; the protocol surface mounts only the
        // canonical `push/register` path.
        .push(Router::with_path("directory/push/register").post(directory_subscribe))
}

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "directory_describe"))]
async fn directory_describe(depot: &mut Depot) -> JsonResult<DirectoryDescription> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let service_did = Did::new(state.config.service_did.clone())
        .map_err(|error| AppError::internal(format!("invalid configured service_did: {error}")))?;
    json_ok(DirectoryDescription {
        service_did,
        resource_types: vec![
            "space".to_owned(),
            "organization".to_owned(),
            "actor".to_owned(),
        ],
        discovery_profiles: vec!["ck.profile.directory_service.v1".to_owned()],
        restricted_query_proof: Some(false),
    })
}

#[endpoint(
    operation_id = "ck.find.directory.query.search_realms",
    tags("directory"),
    summary = "Fuzzy-text + visibility-filtered realm search"
)]
#[tracing::instrument(skip_all, fields(op = "ck.find.directory.query.search_realms"))]
async fn search_realms(
    body: JsonBody<DirectorySearchRealmsRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryRealmSearchOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    let requested_limit = body.limit.unwrap_or(20).clamp(1, 100) as usize;
    let query = RealmDirectoryQuery {
        text: body.query,
        public_only: false,
        limit: Some(requested_limit + 1),
        ..Default::default()
    };
    let session = authenticated_session(state, req).await.ok();
    let candidates: Vec<RealmDirectoryEntry> = {
        let realms = state.realms.lock().expect("realms lock");
        realms.search(query).into_iter().cloned().collect()
    };
    let mut results = Vec::new();
    for realm_entry in candidates {
        if realm_search_visible_to(state, &realm_entry, session.as_ref()).await {
            results.push(realm_entry);
        }
    }
    let has_more = results.len() > requested_limit;
    if has_more {
        results.truncate(requested_limit);
    }
    json_ok(DirectoryRealmSearchOutcome {
        realms: results
            .iter()
            .map(realm_preview_from_directory_entry)
            .collect(),
        next_cursor: None,
        has_more,
    })
}

#[endpoint(
    operation_id = "ck.find.directory.query.resolve_realm",
    tags("directory"),
    summary = "Resolve a realm by id / alias / invite_token / signed_link"
)]
#[tracing::instrument(skip_all, fields(op = "ck.find.directory.query.resolve_realm"))]
async fn resolve_realm(
    body: JsonBody<DirectoryResolveRealmRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryRealmResolutionOutcome> {
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
    let invite_realm_id = match body.invite_token.as_deref() {
        Some(token) => invite_token_realm_id(state, token).await,
        None => None,
    };
    let candidates: Vec<RealmDirectoryEntry> = {
        let realms = state.realms.lock().expect("realms lock");
        realms
            .search(Default::default())
            .into_iter()
            .cloned()
            .collect()
    };
    let mut matched_realm = None;
    for entry in candidates {
        let matches_query = body
            .realm_id
            .as_ref()
            .is_some_and(|id| id == &entry.realm_id)
            || invite_realm_id
                .as_deref()
                .is_some_and(|id| id == entry.realm_id.as_str())
            || body
                .alias
                .as_deref()
                .is_some_and(|alias| alias.eq_ignore_ascii_case(&entry.title));
        if matches_query
            && realm_resolvable_to(
                state,
                &entry,
                session.as_ref(),
                body.invite_token.as_deref(),
                body.signed_link.as_deref(),
            )
            .await
        {
            matched_realm = Some(entry);
            break;
        }
    }
    match matched_realm {
        Some(realm) => {
            let discoverability = realm_discoverability(state, realm.realm_id.as_str()).await;
            json_ok(DirectoryRealmResolutionOutcome {
                realm_preview: realm_preview_from_directory_entry(&realm),
                stripped_state: Vec::new(),
                join_rule: Some(join_rule_enum_for_discoverability(&discoverability)),
                join_candidates: join_candidates_for_resolved_realm(
                    state,
                    realm.realm_id.as_str(),
                    discoverability.as_str(),
                ),
            })
        }
        None => Err(AppError::not_found("not found")),
    }
}

#[endpoint(
    operation_id = "ck.find.directory.query.resolve_target",
    tags("directory"),
    summary = "Resolve a Realm / Strand / Message share address to a policy-limited preview"
)]
#[tracing::instrument(skip_all, fields(op = "ck.find.directory.query.resolve_target"))]
async fn resolve_target(
    body: JsonBody<DirectoryResolveTargetRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryTargetResolutionOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    let address = body.address.trim();
    if address.is_empty() {
        return Err(AppError::missing_param("address is required"));
    }
    let parsed = parse_address(address).map_err(|_| AppError::not_found("not found"))?;
    let session = authenticated_session(state, req).await.ok();
    let token = body
        .token
        .as_deref()
        .or(parsed.token.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty());

    let Some(realm_entry) = resolve_realm_for_address(state, &parsed).await else {
        return Err(AppError::not_found("not found"));
    };
    if is_realm_deleted(state, realm_entry.realm_id.as_str()).await {
        return Err(AppError::not_found("not found"));
    }

    let mut include_join_candidates = false;
    match parsed.link_type {
        LinkType::Reference => {
            if !realm_resolvable_to(state, &realm_entry, session.as_ref(), None, None).await {
                return Err(AppError::not_found("not found"));
            }
            include_join_candidates = true;
        }
        LinkType::Invite => {
            let Some(token) = token else {
                return Err(AppError::not_found("not found"));
            };
            if !invite_token_matches_realm(state, realm_entry.realm_id.as_str(), token).await {
                return Err(AppError::not_found("not found"));
            }
            if parsed.strand.is_some()
                && !optional_structured_token_target_matches(
                    token,
                    &parsed,
                    realm_entry.realm_id.as_str(),
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
                realm_entry.realm_id.as_str(),
                token,
                session.as_ref(),
            )
            .await
            {
                return Err(AppError::not_found("not found"));
            }
        }
    }

    let discoverability = realm_discoverability(state, realm_entry.realm_id.as_str()).await;
    let target_kind = target_kind_for_address(&parsed);
    let realm_preview = realm_preview_for_policy_typed(state, &realm_entry).await?;
    let policy_revision = if parsed.link_type == LinkType::Preview
        && let Some(meta) = state
            .persistence
            .realm_meta()
            .get(realm_entry.realm_id.as_str())
            .await
            .ok()
            .flatten()
        && let Some(digest) = meta.preview_policy_digest
    {
        Some(digest)
    } else {
        None
    };
    let join_candidates = if include_join_candidates {
        join_candidates_for_resolved_realm(
            state,
            realm_entry.realm_id.as_str(),
            discoverability.as_str(),
        )
    } else {
        Vec::new()
    };
    json_ok(DirectoryTargetResolutionOutcome {
        target_kind,
        realm_preview: Some(realm_preview),
        object_preview: object_preview_for_address(&parsed),
        join_rule: Some(join_rule_enum_for_discoverability(&discoverability)),
        as_of: now(),
        source_refs: Vec::new(),
        join_candidates,
        policy_revision,
        stale: None,
        divergent: None,
    })
}

async fn resolve_realm_for_address(
    state: &AppState,
    parsed: &cokret_sdk::ParsedAddress,
) -> Option<RealmDirectoryEntry> {
    let candidates: Vec<RealmDirectoryEntry> = {
        let realms = state.realms.lock().expect("realms lock");
        realms
            .search(Default::default())
            .into_iter()
            .cloned()
            .collect()
    };
    candidates.into_iter().find(|entry| match &parsed.realm {
        RealmRef::RealmId(uuid) => entry.realm_id.as_str() == format!("ck:realm:{uuid}"),
        RealmRef::Alias(alias) => entry.title.eq_ignore_ascii_case(alias),
    })
}

fn target_kind_for_address(parsed: &cokret_sdk::ParsedAddress) -> TargetKind {
    if parsed.message.is_some() {
        TargetKind::Message
    } else if parsed.strand.is_some() {
        TargetKind::Strand
    } else {
        TargetKind::Realm
    }
}

fn realm_preview_from_directory_entry(entry: &RealmDirectoryEntry) -> RealmPreview {
    let discoverability = if entry.public {
        "public"
    } else {
        "invite_only"
    };
    RealmPreview {
        realm_id: entry.realm_id.clone(),
        alias: None,
        title: Some(entry.title.clone()),
        avatar_blob_ref: None,
        organization_did: None,
        join_rule: Some(join_rule_for_discoverability(discoverability).to_owned()),
        member_count_bucket: entry
            .public
            .then_some(entry.members.len())
            .filter(|count| *count > 0)
            .map(member_count_bucket),
        summary: entry.description.clone(),
        owning_organizations: Vec::new(),
        preview_ref: None,
        discoverability: Some(discoverability.to_owned()),
        history_visibility: None,
        join_candidates: Vec::new(),
        as_of: entry.as_of,
        source_refs: entry.source_refs.clone(),
        policy_revision: entry.policy_revision.clone(),
        stale: None,
        divergent: None,
    }
}

fn join_rule_for_discoverability(discoverability: &str) -> &'static str {
    if discoverability == "public" {
        "public"
    } else {
        "invite_or_request"
    }
}

fn join_rule_enum_for_discoverability(discoverability: &str) -> JoinRule {
    if discoverability == "public" {
        JoinRule::Public
    } else {
        JoinRule::Invite
    }
}

fn organization_preview_from_value(
    organization: &Value,
    state: &AppState,
) -> Result<OrganizationPreview, AppError> {
    let organization_did = organization
        .get("organization_did")
        .and_then(Value::as_str)
        .unwrap_or(state.config.service_did.as_str());
    Ok(OrganizationPreview {
        organization_did: Did::new(organization_did.to_owned()).map_err(|error| {
            AppError::internal(format!("directory organization_did is invalid: {error}"))
        })?,
        handle: organization
            .get("handle")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        preview: organization.clone(),
    })
}

fn organization_preview_with_spaces(
    organization: &Value,
    spaces: Vec<Value>,
    state: &AppState,
) -> Result<OrganizationPreview, AppError> {
    let mut preview = organization.clone();
    if let Value::Object(object) = &mut preview {
        object.insert("spaces".to_owned(), Value::Array(spaces));
    }
    organization_preview_from_value(&preview, state)
}

fn actor_preview_from_value(actor: &Value) -> Result<ActorPreview, AppError> {
    let actor_id = actor
        .get("actor_id")
        .or_else(|| actor.get("did"))
        .or_else(|| actor.get("subject"))
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::internal("directory actor preview missing actor DID"))?;
    Ok(ActorPreview {
        actor_id: Did::new(actor_id.to_owned()).map_err(|error| {
            AppError::internal(format!("directory actor DID is invalid: {error}"))
        })?,
        display_name: actor
            .get("display_name")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        preview: actor.clone(),
    })
}

async fn realm_preview_for_policy(state: &AppState, realm_entry: &RealmDirectoryEntry) -> Value {
    let meta = state
        .persistence
        .realm_meta()
        .get(realm_entry.realm_id.as_str())
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
        preview.insert("title".to_owned(), json!(realm_entry.title));
    }
    if fields.contains(&"summary") {
        preview.insert("summary".to_owned(), json!(realm_entry.description));
    }
    if fields.contains(&"join_rule") {
        let discoverability = realm_discoverability(state, realm_entry.realm_id.as_str()).await;
        preview.insert(
            "join_rule".to_owned(),
            json!(join_rule_for_discoverability(&discoverability)),
        );
    }
    if fields.contains(&"history_visibility") {
        preview.insert(
            "history_visibility".to_owned(),
            json!(realm_history_visibility(state, realm_entry.realm_id.as_str()).await),
        );
    }
    if fields.contains(&"member_count_bucket") && !realm_entry.members.is_empty() {
        preview.insert(
            "member_count_bucket".to_owned(),
            json!(member_count_bucket_wire(realm_entry.members.len())),
        );
    }
    if fields.contains(&"preview_ref") {
        preview.insert(
            "preview_ref".to_owned(),
            json!(realm_entry.realm_id.as_str()),
        );
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

    preview.insert("realm_id".to_owned(), json!(realm_entry.realm_id.as_str()));
    preview.insert("as_of".to_owned(), json!(realm_entry.as_of));
    preview.insert(
        "source_refs".to_owned(),
        json!(realm_entry.source_refs.clone()),
    );
    preview.insert(
        "policy_revision".to_owned(),
        json!(realm_entry.policy_revision.clone()),
    );
    Value::Object(preview)
}

async fn realm_preview_for_policy_typed(
    state: &AppState,
    realm_entry: &RealmDirectoryEntry,
) -> Result<RealmPreview, AppError> {
    serde_json::from_value(realm_preview_for_policy(state, realm_entry).await)
        .map_err(|error| AppError::internal(format!("realm preview shape invalid: {error}")))
}

fn member_count_bucket(count: usize) -> RealmMemberCountBucket {
    RealmMemberCountBucket::Bucket(member_count_bucket_label(count))
}

fn member_count_bucket_wire(count: usize) -> &'static str {
    match member_count_bucket_label(count) {
        RealmMemberCountBucketLabel::OneToTen => "1-10",
        RealmMemberCountBucketLabel::ElevenToFifty => "11-50",
        RealmMemberCountBucketLabel::FiftyOneToOneHundred => "51-100",
        RealmMemberCountBucketLabel::OneHundredOneToFiveHundred => "101-500",
        RealmMemberCountBucketLabel::FiveHundredOneToTwoThousand => "501-2000",
        RealmMemberCountBucketLabel::TwoThousandPlus => "2000+",
    }
}

fn member_count_bucket_label(count: usize) -> RealmMemberCountBucketLabel {
    match count {
        0..=10 => RealmMemberCountBucketLabel::OneToTen,
        11..=50 => RealmMemberCountBucketLabel::ElevenToFifty,
        51..=100 => RealmMemberCountBucketLabel::FiftyOneToOneHundred,
        101..=500 => RealmMemberCountBucketLabel::OneHundredOneToFiveHundred,
        501..=2000 => RealmMemberCountBucketLabel::FiveHundredOneToTwoThousand,
        _ => RealmMemberCountBucketLabel::TwoThousandPlus,
    }
}

fn object_preview_for_address(parsed: &cokret_sdk::ParsedAddress) -> Option<Value> {
    let strand_id = parsed
        .strand
        .as_deref()
        .map(|strand| format!("ck:strand:{strand}"));
    let message_id = parsed
        .message
        .as_deref()
        .map(|message| format!("ck:message:{message}"));
    strand_id.map(|strand_id| {
        let mut preview = serde_json::Map::new();
        preview.insert("strand_id".to_owned(), json!(strand_id));
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
        None => parsed.strand.is_none() && parsed.message.is_none(),
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
        .notary_signing_key()
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
        vec![RealmJoinMethod::MemberJoin, RealmJoinMethod::InviteAccept]
    } else {
        vec![
            RealmJoinMethod::InviteAccept,
            RealmJoinMethod::Knock,
            RealmJoinMethod::Application,
        ]
    };
    vec![RealmJoinCandidate {
        realm_id: RealmId::new(realm_id.to_owned()).expect("directory realm id is validated"),
        service_did: Did::new(state.config.service_did.clone()).expect("service DID is validated"),
        service_type: RealmJoinCandidateServiceType::PrincipalServer,
        role: RealmJoinCandidateRole::Primary,
        endpoint: Some(state.config.public_base_url.clone()),
        operations: vec!["ck.self.events.command.submit".to_owned()],
        join_methods,
        priority: Some(0),
        source: RealmJoinCandidateSource::DirectoryIngest,
        source_refs: Vec::new(),
        frontier_ref: None,
        as_of: observed_at,
        expires_at: observed_at + chrono::Duration::minutes(10),
        proofs: Vec::new(),
    }]
}

#[endpoint(
    operation_id = "ck.find.directory.query.search_organizations",
    tags("directory"),
    summary = "Fuzzy-text search across known organizations (demo data for now)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.find.directory.query.search_organizations"))]
async fn search_organizations(
    body: JsonBody<DirectorySearchOrganizationsRequestBody>,
    depot: &mut Depot,
) -> JsonResult<DirectoryOrganizationSearchOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    let limit = checked_limit(body.limit.map(|limit| limit as usize))?;
    let mut results = organizations::organization_records_for_directory(state)
        .into_iter()
        .filter(|organization| query_matches(organization, body.query.as_deref()))
        .collect::<Vec<_>>();
    let realm_entries = live_realm_entries(state).await;
    let realm_refs: Vec<&RealmDirectoryEntry> = realm_entries.iter().collect();
    let organization = demo_organization(&realm_refs, &state.config.service_did);
    if state.config.development_mode && query_matches(&organization, body.query.as_deref()) {
        results.push(organization);
    }
    let has_more = results.len() > limit;
    json_ok(DirectoryOrganizationSearchOutcome {
        organizations: results
            .into_iter()
            .take(limit)
            .map(|organization| organization_preview_from_value(&organization, state))
            .collect::<Result<Vec<_>, _>>()?,
        next_cursor: None,
        has_more,
    })
}

#[endpoint(
    operation_id = "ck.find.directory.query.resolve_organization",
    tags("directory"),
    summary = "Resolve an organization by organization_id or handle"
)]
#[tracing::instrument(skip_all, fields(op = "ck.find.directory.query.resolve_organization"))]
async fn resolve_organization(
    body: JsonBody<DirectoryResolveOrganizationRequestBody>,
    depot: &mut Depot,
) -> JsonResult<DirectoryOrganizationResolutionOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    if body.organization_did.is_none() && body.handle.is_none() {
        return Err(AppError::missing_param(
            "organization_did or handle is required",
        ));
    }
    if let Some(organization) = organizations::organization_records_for_directory(state)
        .into_iter()
        .find(|organization| {
            body.organization_did
                .as_ref()
                .is_some_and(|did| organization["organization_did"].as_str() == Some(did.as_str()))
                || body.handle.as_deref().is_some_and(|handle| {
                    organization["handle"]
                        .as_str()
                        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(handle))
                })
        })
    {
        let associated_realms: Vec<Value> = organization["realms"]
            .as_array()
            .into_iter()
            .flat_map(|array| array.iter())
            .filter_map(Value::as_str)
            .map(|realm_id| json!({ "realm_id": realm_id }))
            .collect();
        return json_ok(DirectoryOrganizationResolutionOutcome {
            organization_preview: organization_preview_with_spaces(
                &organization,
                associated_realms,
                state,
            )?,
            did_document_ref: None,
            endorsements: Vec::new(),
        });
    }
    if !state.config.development_mode {
        return Err(AppError::not_found("not found"));
    }

    let realm_entries = live_realm_entries(state).await;
    let realm_refs: Vec<&RealmDirectoryEntry> = realm_entries.iter().collect();
    let organization = demo_organization(&realm_refs, &state.config.service_did);
    let matches_id = body.organization_did.as_ref().is_some_and(|did| {
        did.as_str()
            == organization["organization_did"]
                .as_str()
                .unwrap_or_default()
            || did.as_str() == state.config.service_did
    });
    let matches_handle = body
        .handle
        .as_deref()
        .is_some_and(|handle| handle.eq_ignore_ascii_case("@cokret-demo"));
    if !matches_id && !matches_handle {
        return Err(AppError::not_found("not found"));
    }

    let associated_realms: Vec<Value> = realm_entries
        .into_iter()
        .map(|realm_entry| {
            json!({
                "realm_id": realm_entry.realm_id,
                "title": realm_entry.title,
                "description": realm_entry.description,
                "category": realm_entry.category,
            })
        })
        .collect();
    json_ok(DirectoryOrganizationResolutionOutcome {
        organization_preview: organization_preview_with_spaces(
            &organization,
            associated_realms,
            state,
        )?,
        did_document_ref: None,
        endorsements: Vec::new(),
    })
}

#[endpoint(
    operation_id = "ck.find.directory.query.search_actors",
    tags("directory"),
    summary = "Search actors visible to the calling session"
)]
#[tracing::instrument(skip_all, fields(op = "ck.find.directory.query.search_actors"))]
async fn search_actors(
    body: JsonBody<DirectorySearchActorsRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryActorSearchOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    require_demo_directory_provider(state)?;
    let body = body.into_inner();
    let limit = checked_limit(body.limit.map(|limit| limit as usize))?;
    if let Some(organization_did) = body.organization_did.as_ref()
        && organization_did.as_str() != state.config.service_did
    {
        return json_ok(DirectoryActorSearchOutcome {
            actors: Vec::new(),
            next_cursor: None,
            has_more: false,
        });
    }

    let session = authenticated_session(state, req).await.ok();
    let mut results: Vec<ActorPreview> = Vec::new();
    for actor in demo_actors(state).await {
        if results.len() > limit {
            break;
        }
        if actor_visible_to(state, &actor, session.as_ref()).await
            && query_matches(&actor, body.query.as_deref())
        {
            results.push(actor_preview_from_value(&actor)?);
        }
    }
    let has_more = results.len() > limit;
    if has_more {
        results.truncate(limit);
    }
    json_ok(DirectoryActorSearchOutcome {
        actors: results,
        next_cursor: None,
        has_more,
    })
}

#[endpoint(
    operation_id = "ck.find.directory.query.search_users",
    tags("directory"),
    summary = "Search users via a POST body to avoid query-string leakage"
)]
#[tracing::instrument(skip_all, fields(op = "ck.find.directory.query.search_users"))]
async fn search_users(
    body: JsonBody<DirectorySearchUsersRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryUserSearchOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    require_demo_directory_provider(state)?;
    let body = body.into_inner();
    let limit = checked_limit(body.limit.map(|limit| limit as usize))?;
    let query = body.query;
    let session = authenticated_session(state, req).await.ok();
    // DIR-1 (R3.1, cokret-spec @ 7157ee8) — `ck.find.directory.query.search_users`
    // response rows MUST NOT carry `handle_uri`. Only `handle` (canonical
    // `<localpart>:<domain>`) + optional `display_name`/`verified`/`subject`
    // survive the rename. Other actor metadata (presence, organization,
    // avatar) goes through `ck.find.directory.query.search_actors` or
    // `ck.directory.resolve-handle`.
    let mut results: Vec<UserSearchOutcome> = Vec::new();
    for actor in demo_actors(state).await {
        if results.len() > limit {
            break;
        }
        if actor_visible_to(state, &actor, session.as_ref()).await
            && query_matches(&actor, Some(query.as_str()))
        {
            results.push(project_search_users_row(state, &actor)?);
        }
    }
    let has_more = results.len() > limit;
    if has_more {
        results.truncate(limit);
    }
    json_ok(DirectoryUserSearchOutcome {
        users: results,
        next_cursor: None,
        has_more,
    })
}

/// DIR-1 — project a [`demo_actors`] row into the spec-shape
/// `ck.find.directory.query.search_users` response entry. Only `handle` (canonical
/// `<localpart>:<domain>` per handle-claim.schema.json, cokret-spec @
/// 7157ee8) + optional `display_name`/`verified`/`subject` survive.
fn project_search_users_row(
    state: &AppState,
    actor: &Value,
) -> Result<UserSearchOutcome, AppError> {
    let service_domain = service_handle_domain(&state.config.service_did);
    let canonical = actor
        .get("handle")
        .and_then(Value::as_str)
        .and_then(|handle| canonicalize_handle_for_service(handle, &service_domain))
        .unwrap_or_default();
    let did = actor
        .get("did")
        .or_else(|| actor.get("subject"))
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::internal("directory user search row missing DID"))?;
    Ok(UserSearchOutcome {
        handle: (!canonical.is_empty()).then_some(canonical),
        did: Some(Did::new(did.to_owned()).map_err(|error| {
            AppError::internal(format!("directory user DID is invalid: {error}"))
        })?),
        display_name: actor
            .get("display_name")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        avatar_blob_ref: None,
        membership: None,
        verified: actor.get("verified").and_then(Value::as_bool),
        member_delivery_binding: None,
    })
}

#[derive(Debug)]
struct HandleLookup {
    canonical: String,
    localpart: String,
    authority: String,
}

fn service_handle_domain(service_did: &str) -> String {
    service_did
        .strip_prefix("did:web:")
        .map(|value| value.replace(':', "."))
        .unwrap_or_else(|| "soland.local".to_owned())
}

fn handle_lookup(input: &str, default_domain: &str) -> Option<HandleLookup> {
    let (localpart, authority) = normalize_handle_parts(input, default_domain)?;
    Some(HandleLookup {
        canonical: format!("{localpart}:{authority}"),
        localpart,
        authority,
    })
}

fn local_actor_handle_matches(
    actor_handle: &str,
    lookup: &HandleLookup,
    service_domain: &str,
) -> bool {
    canonicalize_handle_for_service(actor_handle, service_domain)
        .is_some_and(|canonical| canonical == lookup.canonical)
}

fn canonicalize_handle_for_service(handle: &str, default_domain: &str) -> Option<String> {
    let (localpart, authority) = normalize_handle_parts(handle, default_domain)?;
    Some(format!("{localpart}:{authority}"))
}

fn normalize_handle_parts(handle: &str, default_domain: &str) -> Option<(String, String)> {
    let trimmed = handle.trim().to_ascii_lowercase();
    if trimmed.is_empty() || trimmed.starts_with("did:") {
        return None;
    }
    let without_acct = trimmed.strip_prefix("acct:").unwrap_or(trimmed.as_str());
    let without_at_prefix = without_acct.strip_prefix('@').unwrap_or(without_acct);
    let (localpart, authority) =
        if let Some((localpart, authority)) = without_at_prefix.rsplit_once('@') {
            (localpart, authority)
        } else if let Some((localpart, authority)) = without_at_prefix.split_once(':') {
            (localpart, authority)
        } else {
            (without_at_prefix, default_domain)
        };
    let localpart = localpart.trim();
    let authority = authority.trim();
    if localpart.is_empty() || authority.is_empty() {
        return None;
    }
    Some((localpart.to_owned(), authority.to_owned()))
}

async fn handle_resolvable_to(
    state: &AppState,
    actor: &Value,
    session: Option<&SessionRecord>,
    request: &DirectoryResolveHandleRequestBody,
) -> bool {
    if actor_visible_to(state, actor, session).await {
        return true;
    }
    membership_builder_resolve_allowed(state, session, request).await
}

async fn membership_builder_resolve_allowed(
    state: &AppState,
    session: Option<&SessionRecord>,
    request: &DirectoryResolveHandleRequestBody,
) -> bool {
    let Some(session) = session else {
        return false;
    };
    if !matches!(
        request.intent.as_deref().map(str::trim),
        Some("invite" | "member_add")
    ) {
        return false;
    }
    match request.requester.as_ref().map(Did::as_str) {
        Some(requester) if requester == session.actor => {}
        _ => return false,
    }
    let Some(realm_id) = request.realm_id.as_ref().map(RealmId::as_str) else {
        return false;
    };
    super::realm_has_member(state, realm_id, &session.actor).await
}

fn did_web_authority(authority: &str) -> String {
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()) => {
            format!("{host}%3A{port}")
        }
        _ => authority.to_owned(),
    }
}

fn remote_handle_resolution(
    lookup: &HandleLookup,
    audience: String,
) -> JsonResult<DirectoryHandleResolutionOutcome> {
    let did_authority = did_web_authority(&lookup.authority);
    let recipient_service_did = format!("did:web:{did_authority}");
    let subject = format!("{recipient_service_did}:users:{}", lookup.localpart);
    Did::new(recipient_service_did.clone()).map_err(|err| {
        AppError::invalid_param(format!(
            "resolved handle recipient service DID is invalid: {err}"
        ))
    })?;
    Did::new(subject.clone()).map_err(|err| {
        AppError::invalid_param(format!("resolved handle subject DID is invalid: {err}"))
    })?;
    let binding = SolandHandleClaimDeliveryBinding {
        recipient_service_did: recipient_service_did.clone(),
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
    };
    json_ok(DirectoryHandleResolutionOutcome {
        did: Did::new(subject.clone()).map_err(|err| {
            AppError::invalid_param(format!("resolved handle subject DID is invalid: {err}"))
        })?,
        handle: lookup.canonical.clone(),
        verified: false,
        claims: json!({
            "actor": {
                "did": subject,
                "handle": lookup.canonical,
                "display_name": lookup.canonical,
                "verified": false,
                "source": "remote_handle"
            }
        }),
        audience: Some(audience),
        handle_claim: None,
        member_delivery_binding: Some(sdk_delivery_binding_from_soland(&binding)?),
        as_of: Some(now()),
        source_refs: Vec::new(),
        policy_revision: None,
        stale: false,
        divergent: false,
        via_services: vec![recipient_service_did],
    })
}

fn sdk_delivery_binding_from_soland(
    binding: &SolandHandleClaimDeliveryBinding,
) -> Result<DeliveryBindingHint, AppError> {
    serde_json::from_value::<DeliveryBindingHint>(serde_json::to_value(binding).map_err(|err| {
        AppError::internal(format!("delivery binding serialization failed: {err}"))
    })?)
    .map_err(|err| AppError::internal(format!("delivery binding is not SDK-compatible: {err}")))
}

fn sdk_handle_claim_from_soland(claim: &SolandHandleClaim) -> Result<SdkHandleClaim, AppError> {
    let value = serde_json::to_value(claim)
        .map_err(|err| AppError::internal(format!("handle claim serialization failed: {err}")))?;
    let claim = serde_json::from_value::<SdkHandleClaim>(value)
        .map_err(|err| AppError::internal(format!("handle claim is not SDK-compatible: {err}")))?;
    claim
        .validate()
        .map_err(|err| AppError::internal(format!("handle claim validation failed: {err}")))?;
    Ok(claim)
}

/// Issue a Principal-Server-signed, SDK-validated handle claim for
/// `handle` → `did` as a JSON value. Used by the account viewer / register
/// outcome to expose the primary handle claim re-derived on demand from the
/// account's durable localpart (the claim itself is never persisted).
pub(crate) fn signed_handle_claim_value(
    state: &AppState,
    handle: &str,
    did: &str,
    audience: &str,
) -> Result<Value, AppError> {
    let claim = signed_handle_claim(state, handle, did, audience, false)?;
    let sdk = sdk_handle_claim_from_soland(&claim)?;
    serde_json::to_value(sdk)
        .map_err(|err| AppError::internal(format!("handle claim serialization failed: {err}")))
}

fn resolve_handle_audience(
    body: &DirectoryResolveHandleRequestBody,
    default_audience: &str,
) -> String {
    body.audience
        .clone()
        .or_else(|| {
            body.realm_id
                .as_ref()
                .map(|realm_id| realm_id.as_str().to_owned())
        })
        .or_else(|| body.requester.as_ref().map(|did| did.as_str().to_owned()))
        .unwrap_or_else(|| default_audience.to_owned())
}

fn local_handle_resolution_outcome(
    actor: Value,
    did: String,
    canonical_handle: String,
    audience: String,
    handle_claim: SolandHandleClaim,
) -> Result<DirectoryHandleResolutionOutcome, AppError> {
    let member_delivery_binding = handle_claim
        .member_delivery_binding
        .as_ref()
        .map(sdk_delivery_binding_from_soland)
        .transpose()?;
    Ok(DirectoryHandleResolutionOutcome {
        did: Did::new(did.clone())
            .map_err(|err| AppError::invalid_param(format!("invalid resolved actor DID: {err}")))?,
        handle: canonical_handle,
        verified: true,
        claims: json!({
            "actor": actor,
            "subject": did,
        }),
        audience: Some(audience),
        handle_claim: Some(sdk_handle_claim_from_soland(&handle_claim)?),
        member_delivery_binding,
        as_of: Some(now()),
        source_refs: Vec::new(),
        policy_revision: None,
        stale: false,
        divergent: false,
        via_services: Vec::new(),
    })
}

#[endpoint(
    operation_id = "ck.find.directory.query.resolve_handle",
    tags("directory"),
    summary = "Resolve a normalized actor handle (e.g. `@alice`) to a DID"
)]
#[tracing::instrument(skip_all, fields(op = "ck.find.directory.query.resolve_handle"))]
async fn resolve_handle(
    body: JsonBody<DirectoryResolveHandleRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryHandleResolutionOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    require_demo_directory_provider(state)?;
    let body = body.into_inner();
    if body.handle.trim().is_empty() {
        return Err(AppError::missing_param("handle is required"));
    }
    let service_domain = service_handle_domain(&state.config.service_did);
    let Some(lookup) = handle_lookup(&body.handle, &service_domain) else {
        return Err(AppError::not_found("not found"));
    };
    let session = authenticated_session(state, req).await.ok();
    let mut actor = None;
    for candidate in demo_actors(state).await {
        let handle_matches = candidate["handle"]
            .as_str()
            .is_some_and(|handle| local_actor_handle_matches(handle, &lookup, &service_domain));
        if handle_matches && handle_resolvable_to(state, &candidate, session.as_ref(), &body).await
        {
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
            let audience = resolve_handle_audience(&body, &state.config.service_did);
            let did = actor["did"].as_str().unwrap_or_default().to_owned();
            let handle_claim =
                signed_handle_claim(state, &lookup.canonical, &did, &audience, true)?;
            // HDLREN-2 — surface the canonical `<localpart>:<domain>` handle
            // from the freshly signed claim so the top-level response field
            // matches handle-claim.schema.json (cokret-spec @ 7157ee8). The
            // request's `@alice` UI form is normalized away here.
            let canonical_handle = handle_claim.handle.clone();
            json_ok(local_handle_resolution_outcome(
                actor,
                did,
                canonical_handle,
                audience,
                handle_claim,
            )?)
        }
        None if membership_builder_resolve_allowed(state, session.as_ref(), &body).await => {
            let audience = resolve_handle_audience(&body, &state.config.service_did);
            remote_handle_resolution(&lookup, audience)
        }
        None => Err(AppError::not_found("not found")),
    }
}

fn selector_not_found() -> AppError {
    AppError::not_found("not found")
}

fn selector_intent_allowed(intent: &str) -> bool {
    matches!(
        intent.trim(),
        "lookup" | "mention" | "invite" | "member_add"
    )
}

async fn selector_resolution_allowed(
    state: &AppState,
    session: Option<&SessionRecord>,
    controller_subject: &str,
    request: &DirectoryResolveAgentSelectorRequestBody,
) -> bool {
    if !selector_intent_allowed(&request.intent) {
        return false;
    }
    let Some(session) = session else {
        return false;
    };
    if request.requester.as_str() != session.actor {
        return false;
    }
    if request.requester.as_str() == controller_subject {
        return true;
    }
    let Some(realm_id) = request.realm_id.as_ref().map(RealmId::as_str) else {
        return false;
    };
    super::realm_has_member(state, realm_id, &session.actor).await
        && super::realm_has_member(state, realm_id, controller_subject).await
}

fn selector_claim_audience(request: &DirectoryResolveAgentSelectorRequestBody) -> String {
    request
        .realm_id
        .as_ref()
        .map(RealmId::as_str)
        .unwrap_or_else(|| request.requester.as_str())
        .to_owned()
}

fn signed_agent_selector_claim(
    state: &AppState,
    controller_subject: &str,
    agent_slug: &str,
    subject: &str,
    request: &DirectoryResolveAgentSelectorRequestBody,
) -> Result<AgentSelectorClaim, AppError> {
    let service_did = state.config.service_did.clone();
    let issuer = Did::new(service_did.clone())
        .map_err(|err| AppError::internal(format!("invalid service DID: {err}")))?;
    let controller_subject = Did::new(controller_subject.to_owned())
        .map_err(|err| AppError::internal(format!("invalid controller DID: {err}")))?;
    let subject = Did::new(subject.to_owned())
        .map_err(|err| AppError::internal(format!("invalid agent DID: {err}")))?;
    let audience = selector_claim_audience(request);
    let created_at = now();
    let expires_at = created_at + chrono::Duration::hours(24);
    let mut claim_scope = BTreeMap::new();
    claim_scope.insert("intent".to_owned(), json!(request.intent.as_str()));
    if let Some(realm_id) = request.realm_id.as_ref() {
        claim_scope.insert("realm_id".to_owned(), json!(realm_id.as_str()));
    }
    let unsigned = json!({
        "schema": AGENT_SELECTOR_CLAIM_SCHEMA,
        "controller_subject": controller_subject.as_str(),
        "agent_slug": agent_slug,
        "subject": subject.as_str(),
        "issuer": issuer.as_str(),
        "issuer_service_did": service_did.as_str(),
        "binding_state": "verified",
        "visibility": "restricted",
        "audience": audience,
        "claim_scope": claim_scope.clone(),
        "expires_at": expires_at.to_rfc3339(),
        "created_at": created_at.to_rfc3339(),
        "source_refs": [],
    });
    let canonical_bytes = canonical::canonical_json_bytes(&unsigned).map_err(|err| {
        AppError::internal(format!(
            "agent selector claim canonicalization failed: {err}"
        ))
    })?;
    let signer = Ed25519MoveSigner::new(
        (*state.notary_signing_key()).clone(),
        issuer.clone(),
        format!("{service_did}#directory-agent-selector-claim"),
    );
    let signature = MoveSigner::sign_payload(&signer, &canonical_bytes)
        .map_err(|err| AppError::internal(format!("agent selector claim signing failed: {err}")))?;
    let proof = json!({
        "kind": "detached_jws",
        "alg": signature.alg,
        "verification_method": signature.verification_method,
        "payload_digest": signature.payload_digest.as_str(),
        "created_at": signature.created_at.to_rfc3339(),
        "jws": signature.jws,
    });
    Ok(AgentSelectorClaim {
        schema: AGENT_SELECTOR_CLAIM_SCHEMA.to_owned(),
        controller_subject,
        agent_slug: agent_slug.to_owned(),
        subject,
        issuer,
        issuer_service_did: Some(
            Did::new(state.config.service_did.clone())
                .map_err(|err| AppError::internal(format!("invalid issuer service DID: {err}")))?,
        ),
        binding_state: HandleBindingState::Verified,
        visibility: HandleVisibility::Restricted,
        audience: Some(selector_claim_audience(request)),
        claim_scope,
        expires_at: Some(expires_at),
        created_at,
        verified_at: Some(created_at),
        source_refs: Vec::new(),
        proofs: vec![proof],
    })
}

#[endpoint(
    operation_id = "ck.find.directory.query.resolve_agent_selector",
    tags("directory"),
    summary = "Resolve a controller-scoped native personal agent selector exactly"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ck.find.directory.query.resolve_agent_selector")
)]
async fn resolve_agent_selector(
    body: JsonBody<DirectoryResolveAgentSelectorRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryAgentSelectorResolutionOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    require_demo_directory_provider(state)?;
    let body = body.into_inner();
    validate_agent_slug(&body.agent_slug).map_err(|_| selector_not_found())?;
    let session = authenticated_session(state, req).await.ok();
    let service_domain = service_handle_domain(&state.config.service_did);
    let Some(lookup) = handle_lookup(&body.controller_handle.to_string(), &service_domain) else {
        return Err(selector_not_found());
    };
    let controller_actor = demo_actors(state)
        .await
        .into_iter()
        .find(|candidate| {
            candidate["handle"]
                .as_str()
                .is_some_and(|handle| local_actor_handle_matches(handle, &lookup, &service_domain))
        })
        .ok_or_else(selector_not_found)?;
    let controller_subject = controller_actor
        .get("did")
        .and_then(Value::as_str)
        .ok_or_else(selector_not_found)?;
    if !selector_resolution_allowed(state, session.as_ref(), controller_subject, &body).await {
        return Err(selector_not_found());
    }

    let records = state
        .persistence
        .agents()
        .list_for_controller(controller_subject)
        .await
        .map_err(|err| AppError::internal(format!("agent selector lookup failed: {err}")))?;
    let matches: Vec<&Value> = records
        .iter()
        .filter(|record| {
            record.get("agent_slug").and_then(Value::as_str) == Some(body.agent_slug.as_str())
                && record.get("state").and_then(Value::as_str) == Some("active")
        })
        .collect();
    if matches.len() != 1 {
        return Err(selector_not_found());
    }
    let subject = matches[0]
        .get("agent_principal_id")
        .and_then(Value::as_str)
        .ok_or_else(selector_not_found)?;
    if body
        .expected_agent_did
        .as_ref()
        .is_some_and(|expected| expected.as_str() != subject)
    {
        return Err(selector_not_found());
    }
    let selector_claim =
        signed_agent_selector_claim(state, controller_subject, &body.agent_slug, subject, &body)?;
    let response = DirectoryAgentSelectorResolutionOutcome {
        controller_subject: selector_claim.controller_subject.clone(),
        subject: selector_claim.subject.clone(),
        agent_slug: body.agent_slug,
        verified: true,
        expires_at: selector_claim.expires_at.clone(),
        source_refs: Vec::new(),
        selector_claim,
    };
    response.validate().map_err(|err| {
        AppError::internal(format!("agent selector response validation failed: {err}"))
    })?;
    json_ok(response)
}

fn signed_handle_claim(
    state: &AppState,
    handle: &str,
    did: &str,
    audience: &str,
    cache: bool,
) -> Result<SolandHandleClaim, AppError> {
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
        (*state.notary_signing_key()).clone(),
        signer_did,
        format!("{service_did}#directory-handle-claim"),
    );
    let signature = MoveSigner::sign_payload(&signer, &canonical_bytes)
        .map_err(|err| AppError::internal(format!("handle claim signing failed: {err}")))?;

    let claim = SolandHandleClaim {
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
        member_delivery_binding: Some(SolandHandleClaimDeliveryBinding {
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
        proofs: vec![SolandHandleClaimProof {
            kind: "detached_jws".to_owned(),
            alg: Some(signature.alg),
            verification_method: Some(signature.verification_method),
            payload_digest: Some(signature.payload_digest.as_str().to_owned()),
            created_at: Some(signature.created_at.to_rfc3339()),
            jws: Some(signature.jws),
        }],
    };
    if cache && let Ok(envelope) = serde_json::to_value(&claim) {
        let _ = state
            .member_identity
            .lock()
            .expect("member_identity lock")
            .upsert_handle_claim_envelope(envelope);
    }
    Ok(claim)
}

#[endpoint(
    operation_id = "ck.find.directory.query.list_handles_for_subject",
    tags("directory"),
    summary = "List current context-visible handle claims for a known subject DID"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ck.find.directory.query.list_handles_for_subject")
)]
async fn list_handles_for_subject(
    body: JsonBody<DirectoryListHandlesForSubjectRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectorySubjectHandleList> {
    let state = depot.obtain::<AppState>().expect("state injected");
    require_demo_directory_provider(state)?;
    let body = body.into_inner();
    let subject_did = body.subject.clone();
    let subject = subject_did.as_str().to_owned();
    if subject.is_empty() {
        return Err(AppError::missing_param("subject is required"));
    }
    if let Err(rejection) = crate::wire_validators::handle_claim_subject::validate_subject(
        &json!({ "subject": subject.as_str() }),
    ) {
        return Err(AppError::new(
            crate::error::ErrorCode::SchemaViolation,
            rejection.message,
        ));
    }

    let limit = checked_limit(body.limit.map(|limit| limit as usize))?;
    let start = list_handles_cursor_start(body.cursor.as_deref())?;
    let requested_as_of = body.as_of.clone();
    let session = authenticated_session(state, req).await.ok();

    let mut generated_claim = None;
    for actor in demo_actors(state).await {
        if actor.get("did").and_then(Value::as_str) != Some(subject.as_str()) {
            continue;
        }
        if !actor_visible_to(state, &actor, session.as_ref()).await {
            continue;
        }
        if let Some(handle) = actor.get("handle").and_then(Value::as_str) {
            let audience = body
                .realm_id
                .as_ref()
                .map(RealmId::as_str)
                .or_else(|| body.requester.as_ref().map(Did::as_str))
                .unwrap_or(state.config.service_did.as_str());
            generated_claim = Some(signed_handle_claim(
                state, handle, &subject, audience, false,
            )?);
        }
        break;
    }

    let cached_claims = state
        .member_identity
        .lock()
        .expect("member_identity lock")
        .handle_claims_for_subject(&subject);
    let as_of = requested_as_of.unwrap_or_else(now);
    let mut claims = Vec::new();
    let mut seen = BTreeSet::new();
    if let Some(claim) = generated_claim {
        let claim = serde_json::to_value(claim).map_err(|err| {
            AppError::internal(format!("handle claim serialization failed: {err}"))
        })?;
        push_visible_subject_handle_claim(
            state,
            &body,
            &subject,
            as_of,
            claim,
            &mut claims,
            &mut seen,
        );
    }
    for claim in cached_claims {
        push_visible_subject_handle_claim(
            state,
            &body,
            &subject,
            as_of,
            claim.envelope,
            &mut claims,
            &mut seen,
        );
    }
    claims.sort_by(|left, right| {
        subject_handle_claim_sort_key(left).cmp(&subject_handle_claim_sort_key(right))
    });

    let total = claims.len();
    let page: Vec<Value> = claims.into_iter().skip(start).take(limit).collect();
    let consumed = start.saturating_add(page.len());
    let has_more = consumed < total;
    let next_cursor = has_more.then(|| consumed.to_string());
    let primary_handle = primary_handle_from_subject_claims(&page);
    let claims = page
        .into_iter()
        .map(|claim| {
            serde_json::from_value::<SdkHandleClaim>(claim).map_err(|err| {
                AppError::internal(format!("handle claim is not SDK-compatible: {err}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let primary_handle = primary_handle
        .as_deref()
        .map(SdkHandle::parse)
        .transpose()
        .map_err(|err| AppError::internal(format!("primary handle is invalid: {err}")))?;
    let response = DirectorySubjectHandleList {
        subject: subject_did,
        claims,
        primary_handle,
        as_of,
        next_cursor,
        has_more,
    };
    response.validate().map_err(|err| {
        AppError::internal(format!("handle list response validation failed: {err}"))
    })?;
    json_ok(response)
}

fn list_handles_cursor_start(cursor: Option<&str>) -> Result<usize, AppError> {
    let Some(cursor) = cursor.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(0);
    };
    cursor
        .parse::<usize>()
        .map_err(|_| AppError::invalid_param("cursor must be an unsigned integer offset"))
}

fn push_visible_subject_handle_claim(
    state: &AppState,
    request: &DirectoryListHandlesForSubjectRequestBody,
    subject: &str,
    as_of: DateTime<Utc>,
    claim: Value,
    claims: &mut Vec<Value>,
    seen: &mut BTreeSet<String>,
) {
    if !subject_handle_claim_visible(state, request, subject, as_of, &claim) {
        return;
    }
    let Some(key) = subject_handle_claim_dedupe_key(&claim) else {
        return;
    };
    if seen.insert(key) {
        claims.push(claim);
    }
}

fn subject_handle_claim_visible(
    state: &AppState,
    request: &DirectoryListHandlesForSubjectRequestBody,
    subject: &str,
    as_of: DateTime<Utc>,
    claim: &Value,
) -> bool {
    if claim.get("subject").and_then(Value::as_str) != Some(subject) {
        return false;
    }
    if subject_handle_claim_handle(claim).is_none() {
        return false;
    }
    if claim.get("binding_state").and_then(Value::as_str) != Some("verified") {
        return false;
    }
    if claim
        .get("revoked")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || claim.get("revoked_at").is_some()
    {
        return false;
    }
    if claim
        .get("visibility")
        .and_then(Value::as_str)
        .is_some_and(|visibility| visibility == "private")
    {
        return false;
    }
    if let Some(created_at) = subject_handle_claim_time(claim, "created_at")
        && created_at > as_of
    {
        return false;
    }
    let Some(expires_at) = subject_handle_claim_time(claim, "expires_at") else {
        return false;
    };
    if expires_at <= as_of {
        return false;
    }
    let issuer = claim.get("issuer").and_then(Value::as_str);
    let issuer_service_did = claim.get("issuer_service_did").and_then(Value::as_str);
    if issuer != Some(state.config.service_did.as_str())
        && issuer_service_did != Some(state.config.service_did.as_str())
    {
        return false;
    }
    let Some(audience) = claim.get("audience").and_then(Value::as_str) else {
        return true;
    };
    let mut allowed_audiences = BTreeSet::new();
    allowed_audiences.insert(state.config.service_did.as_str());
    if let Some(realm_id) = request.realm_id.as_ref() {
        allowed_audiences.insert(realm_id.as_str());
    }
    if let Some(requester) = request.requester.as_ref() {
        allowed_audiences.insert(requester.as_str());
    }
    allowed_audiences.contains(audience)
}

fn subject_handle_claim_time(claim: &Value, field: &str) -> Option<DateTime<Utc>> {
    claim
        .get(field)
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
}

fn subject_handle_claim_handle(claim: &Value) -> Option<&str> {
    claim.get("handle").and_then(Value::as_str)
}

fn subject_handle_claim_dedupe_key(claim: &Value) -> Option<String> {
    Some(format!(
        "{}|{}|{}|{}",
        subject_handle_claim_handle(claim)?,
        claim.get("subject").and_then(Value::as_str)?,
        claim
            .get("issuer")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        claim
            .get("audience")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    ))
}

fn subject_handle_claim_sort_key(claim: &Value) -> (String, String, String, String) {
    (
        subject_handle_claim_handle(claim)
            .unwrap_or_default()
            .to_owned(),
        claim
            .get("issuer")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        claim
            .get("audience")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        claim
            .get("created_at")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    )
}

fn primary_handle_from_subject_claims(claims: &[Value]) -> Option<String> {
    let handles: BTreeSet<String> = claims
        .iter()
        .filter_map(subject_handle_claim_handle)
        .map(ToOwned::to_owned)
        .collect();
    if handles.len() == 1 {
        handles.into_iter().next()
    } else {
        None
    }
}

#[endpoint(
    operation_id = "ck.find.directory.query.private_contact_discovery",
    tags("directory"),
    summary = "Privacy-preserving contact discovery over padded identifier batches"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ck.find.directory.query.private_contact_discovery")
)]
async fn private_contact_discovery(
    body: JsonBody<DirectoryPrivateContactDiscoveryRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryPrivateContactDiscoveryOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    require_demo_directory_provider(state)?;
    let session = authenticated_session(state, req).await.ok();
    let body = body.into_inner();
    let contacts = body.contacts;
    let mut visible: Vec<Value> = Vec::new();
    for actor in demo_actors(state).await {
        if actor_visible_to(state, &actor, session.as_ref()).await {
            visible.push(actor);
        }
    }
    // SEC-09 — the probing requester for the (requester, holder) rate limit /
    // audit dimension. Unauthenticated probes share a single conservative
    // `anonymous` bucket.
    let requester = session
        .as_ref()
        .map(|s| s.actor.clone())
        .unwrap_or_else(|| "anonymous".to_owned());
    let mut matches = Vec::new();
    // SEC-09 — max client backoff across all rate-limited (requester, holder)
    // pairs in this batch.
    let mut retry_after_ms: u64 = 0;
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
            let holder = actor
                .get("did")
                .and_then(Value::as_str)
                .unwrap_or(&needle)
                .to_owned();
            // SEC-09 — rate-limit this (requester, holder) probe and record it
            // in the holder-auditable access log so the holder can later detect
            // repeated probing.
            let outcome = state.record_psi_probe(&requester, &holder);
            append_audit_log(
                state,
                Some(&holder),
                "psi_contact_discovery_probe",
                json!({
                    "requester": requester,
                    "probe_count": outcome.count,
                    "rate_limited": outcome.rate_limited,
                }),
                if outcome.rate_limited {
                    "rate_limited"
                } else {
                    "ok"
                },
            )
            .await;
            // SEC-09 — once a pair exceeds the window cap, withhold the fresh
            // match result (so high-frequency probing cannot read the holder's
            // hit-bit flip timing) and surface a backoff.
            if outcome.rate_limited {
                retry_after_ms = retry_after_ms.max(outcome.retry_after_ms.max(0) as u64);
                continue;
            }
            matches.push(json!({
                "contact_ref": contact.get("ref").cloned().unwrap_or(Value::Null),
                "did": actor.get("did").cloned().unwrap_or(Value::Null),
                "handle": actor.get("handle").cloned().unwrap_or(Value::Null),
                "proof": {
                    "type": "directory_private_contact_discovery_dev",
                    // SEC-09 — coarse hit bucket: the moment a holder's
                    // reachability bit flipped is floored to PSI_HIT_BUCKET_SECS
                    // rather than exposed at second resolution.
                    "issued_at": AppState::psi_bucket_timestamp(now()),
                }
            }));
        }
    }
    json_ok(DirectoryPrivateContactDiscoveryOutcome {
        matches,
        proofs: Vec::new(),
        retry_after_ms: (retry_after_ms > 0).then_some(retry_after_ms),
    })
}

#[endpoint(
    operation_id = "ck.find.directory.command.announce",
    tags("directory"),
    summary = "Announce a discoverable directory resource"
)]
#[tracing::instrument(skip_all, fields(op = "ck.find.directory.command.announce"))]
async fn directory_announce(
    body: JsonBody<DirectoryAnnounceRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryAnnounceOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = authenticated_session(state, req)
        .await
        .map_err(|(status, code, message)| {
            AppError::invalid_param(message)
                .with_status(status)
                .with_wire_code(code)
        })?;
    let body = body.into_inner();
    let resource_kind = directory_resource_kind_str(body.resource_kind);
    let resource_id = body.resource_id.as_str();
    if resource_kind == "realm"
        && !super::realm_has_member(state, resource_id, &session.actor).await
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
    let indexed_at = now();
    let effective_ttl_seconds = body.ttl_seconds.unwrap_or(86_400);
    let next_revalidation_after = indexed_at.clone()
        + chrono::Duration::seconds(effective_ttl_seconds.min(i64::MAX as u64) as i64);
    json_ok(DirectoryAnnounceOutcome {
        announce_id: announcement_id,
        indexed_at,
        effective_ttl_seconds,
        next_revalidation_after,
        warnings: Vec::new(),
    })
}

#[endpoint(
    operation_id = "ck.find.directory.command.withdraw",
    tags("directory"),
    summary = "Withdraw a previously-announced directory resource"
)]
#[tracing::instrument(skip_all, fields(op = "ck.find.directory.command.withdraw"))]
async fn directory_withdraw(
    body: JsonBody<DirectoryWithdrawRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryWithdrawOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = authenticated_session(state, req)
        .await
        .map_err(|(status, code, message)| {
            AppError::invalid_param(message)
                .with_status(status)
                .with_wire_code(code)
        })?;
    let body = body.into_inner();
    let withdrawal_ref = format!(
        "ck:withdrawal:{}",
        super::sha256_hex(format!("{}:realm:{}", session.actor, body.resource_id).as_bytes())
    );
    json_ok(DirectoryWithdrawOutcome {
        withdrawal_ref,
        acked_at: now(),
    })
}

#[endpoint(
    operation_id = "ck.find.directory.push.command.register",
    tags("directory"),
    summary = "Subscribe to directory update notifications"
)]
#[tracing::instrument(skip_all, fields(op = "ck.find.directory.push.command.register"))]
async fn directory_subscribe(
    body: JsonBody<DirectoryPushRegisterRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryPushRegisterOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = authenticated_session(state, req).await.ok();
    let body = body.into_inner();
    let _ = body;
    json_ok(DirectoryPushRegisterOutcome {
        subscription_id: ids::generate("directory_subscription"),
        effective_at: now(),
    })
}

fn directory_resource_kind_str(kind: DirectoryResourceKind) -> &'static str {
    match kind {
        DirectoryResourceKind::Realm => "realm",
        DirectoryResourceKind::Organization => "organization",
        DirectoryResourceKind::Actor => "actor",
        DirectoryResourceKind::Applet => "applet",
        DirectoryResourceKind::Handle => "handle",
    }
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

pub fn demo_organization(realms: &[&RealmDirectoryEntry], service_did: &str) -> Value {
    json!({
        "organization_id": "ck:org:demo",
        "organization_did": service_did,
        "handle": "@cokret-demo",
        "name": "Cokret Demo Organization",
        "description": "Demo organization projected by soland",
        "service_did": service_did,
        "realm_count": realms.len(),
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
            "handle": account.handle(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_intent_is_exact_protocol_enum() {
        for intent in ["lookup", "mention", "invite", "member_add"] {
            assert!(selector_intent_allowed(intent));
        }
        for intent in ["", "search", "mention_all", "Mention"] {
            assert!(!selector_intent_allowed(intent));
        }
    }
}
