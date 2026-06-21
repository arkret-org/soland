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
    AGENT_SELECTOR_CLAIM_SCHEMA, ActorPreview, AgentSelectorClaim, Audience, DeliveryBindingHint,
    DeliveryMode, Did, DirectoryActorSearchOutcome, DirectoryAgentSelectorResolutionOutcome,
    DirectoryAnnounceOutcome, DirectoryAnnounceRequestBody, DirectoryDescription,
    DirectoryHandleResolutionOutcome, DirectoryIntent, DirectoryListHandlesForSubjectRequestBody,
    DirectoryOrganizationResolutionOutcome, DirectoryOrganizationSearchOutcome,
    DirectoryPrivateContactDiscoveryOutcome, DirectoryPrivateContactDiscoveryRequestBody,
    DirectoryPushRegisterOutcome, DirectoryPushRegisterRequestBody,
    DirectoryRealmResolutionOutcome, DirectoryRealmSearchOutcome,
    DirectoryResolveAgentSelectorRequestBody, DirectoryResolveHandleRequestBody,
    DirectoryResolveOrganizationRequestBody, DirectoryResolveRealmRequestBody,
    DirectoryResolveTargetRequestBody, DirectoryResourceKind, DirectorySearchActorsRequestBody,
    DirectorySearchOrganizationsRequestBody, DirectorySearchRealmsRequestBody,
    DirectorySearchUsersRequestBody, DirectorySubjectHandleList, DirectoryTargetResolutionOutcome,
    DirectoryUserSearchOutcome, DirectoryWithdrawOutcome, DirectoryWithdrawRequestBody,
    Ed25519MoveSigner, HandleClaimKind, HandleHintBindingSource, JoinRule, LinkType, MoveSigner,
    OrganizationPreview, PayloadProof, RealmId, RealmJoinCandidate, RealmJoinCandidateRole,
    RealmJoinCandidateServiceType, RealmJoinCandidateSource, RealmJoinMethod,
    RealmMemberCountBucket, RealmMemberCountBucketLabel, RealmPreview, RealmRef,
    RecipientServiceType, TargetDescriptor, TargetKind, UserSearchOutcome, canonical,
    parse_address, proof_kind, target_digest, validate_agent_slug,
};
use ed25519_dalek::{Signature, Verifier};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{
    authenticated_session, device_inventory_to_json, handle_for_did, invite_token_matches_realm,
    invite_token_realm_id, is_realm_deleted, now, realm_discoverability, realm_has_member,
    realm_history_visibility, realm_resolvable_to, realm_search_visible_to, sha256_hex,
};
use crate::error::AppError;
use crate::ids;
use crate::result::{JsonResult, json_ok};
use crate::routing::admin::audit::append_audit_log;
use crate::routing::organizations;
use crate::state::{AppState, RealmDirectoryEntry, RealmDirectoryQuery, SessionRecord};

mod actors_users;
mod agent_selector;
mod demo;
mod discovery;
mod handles;
mod organization_resolution;
mod preview_token;
mod realm_resolution;

use actors_users::*;
use agent_selector::*;
use demo::*;
pub use demo::{checked_limit, demo_actors, demo_organization, query_matches};
pub use discovery::actor_visible_to;
use discovery::*;
// Re-export the helpers that sibling routing modules reach for at their
// original visibility (the moved definitions now live in submodules).
pub(crate) use handles::signed_handle_claim_value;
use handles::*;
use organization_resolution::*;
use preview_token::*;
use realm_resolution::*;

const DIRECTORY_RESOURCE_TYPES: &[DirectoryResourceKind] = &[
    DirectoryResourceKind::Realm,
    DirectoryResourceKind::Organization,
    DirectoryResourceKind::Actor,
];
const DIRECTORY_DISCOVERY_PROFILES: &[&str] = &["ck.profile.directory_service.v1"];
const DIRECTORY_SUPPORTED_OPERATIONS: &[&str] = &[
    "ck.find.directory.query.describe",
    "ck.find.directory.query.search_realms",
    "ck.find.directory.query.resolve_realm",
    "ck.find.directory.query.resolve_target",
    "ck.find.directory.query.search_organizations",
    "ck.find.directory.query.resolve_organization",
    "ck.find.directory.query.search_actors",
    "ck.find.directory.query.search_users",
    "ck.find.directory.query.resolve_handle",
    "ck.find.directory.query.resolve_agent_selector",
    "ck.find.directory.query.list_handles_for_subject",
    "ck.find.directory.query.private_contact_discovery",
    "ck.find.directory.command.announce",
    "ck.find.directory.command.withdraw",
    "ck.find.directory.push.command.register",
];

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
    let trust_domain = cokret_sdk::TypedTrustDomainId::new(state.config.trust_domain.clone())
        .map_err(|error| AppError::internal(format!("invalid configured trust_domain: {error}")))?;
    let supported_profiles: Vec<String> = DIRECTORY_DISCOVERY_PROFILES
        .iter()
        .map(|profile| (*profile).to_owned())
        .collect();
    let supported_features = vec![
        "directory.search".to_owned(),
        "directory.resolve".to_owned(),
        "directory.ingest_push".to_owned(),
    ];
    let description = DirectoryDescription {
        service_did,
        trust_domain,
        service_type: "directory_service".to_owned(),
        protocol_version: cokret_sdk::PROTOCOL_VERSION.to_owned(),
        supported_profiles: supported_profiles.clone(),
        supported_operations: DIRECTORY_SUPPORTED_OPERATIONS
            .iter()
            .map(|operation| (*operation).to_owned())
            .collect(),
        supported_bindings: vec![
            cokret_sdk::SupportedBinding::new("http_json")
                .with_base_url(state.config.public_base_url.trim_end_matches('/')),
        ],
        supported_features: supported_features.clone(),
        auth_metadata: cokret_sdk::AuthMetadata::minimal("public_no_auth"),
        limits: json!({}),
        plaintext_visibility: cokret_sdk::PlaintextVisibility::none(),
        privacy_derivation: None,
        receive_policy_constraints: None,
        implemented_features: supported_features,
        claimed_profiles: supported_profiles
            .iter()
            .map(cokret_sdk::ClaimedProfileEntry::self_claimed)
            .collect(),
        verified_profiles: Vec::new(),
        experimental_features: Vec::new(),
        compat_surfaces: Vec::new(),
        development_mode: state.config.development_mode,
        rate_limit_policy: Some(cokret_sdk::RateLimitPolicy::unspecified()),
        rate_limit_policy_id: None,
        egress_network_policy: Some(cokret_sdk::EgressNetworkPolicy::deny_private_defaults()),
        resource_types: DIRECTORY_RESOURCE_TYPES.to_vec(),
        discovery_profiles: supported_profiles,
        restricted_query_proof: Some(false),
        ingest_modes: vec![cokret_sdk::DirectoryIngestMode::Push],
        accept_policy_kind: Some(cokret_sdk::DirectoryAcceptPolicyKind::Open),
        accept_policy_ref: None,
        default_ttl_seconds: Some(86_400),
        max_ttl_seconds: Some(604_800),
        revalidation_grace_seconds: Some(3_600),
        accepted_resource_kinds: DIRECTORY_RESOURCE_TYPES.to_vec(),
        accepted_did_methods: vec![
            "did:web".to_owned(),
            "did:webvh".to_owned(),
            "did:key".to_owned(),
        ],
        takedown_contact: None,
        rate_limits: Some(json!({})),
        supported_reducer_profiles: Vec::new(),
        supported_schema_profiles: Vec::new(),
        frontier: Vec::new(),
        snapshot_frontier: Vec::new(),
        reducer_profile: None,
        last_materialized_at: None,
    };
    description
        .validate()
        .map_err(|error| AppError::internal(format!("invalid directory describe: {error}")))?;
    json_ok(description)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_intent_is_exact_protocol_enum() {
        for intent in [
            DirectoryIntent::Lookup,
            DirectoryIntent::Mention,
            DirectoryIntent::Invite,
            DirectoryIntent::MemberAdd,
            DirectoryIntent::ContactRequest,
        ] {
            assert!(selector_intent_allowed(intent));
        }
        for intent in ["", "search", "mention_all", "Mention"] {
            assert!(intent.parse::<DirectoryIntent>().is_err());
        }
    }

    #[test]
    fn directory_describe_resource_types_exclude_private_message_search() {
        assert!(DIRECTORY_RESOURCE_TYPES.contains(&DirectoryResourceKind::Realm));
        assert!(DIRECTORY_RESOURCE_TYPES.contains(&DirectoryResourceKind::Organization));
        assert!(DIRECTORY_RESOURCE_TYPES.contains(&DirectoryResourceKind::Actor));
        assert!(!DIRECTORY_DISCOVERY_PROFILES.contains(&"ck.profile.search.client_index.v1"));
        assert!(!DIRECTORY_DISCOVERY_PROFILES.contains(&"ck.profile.search.blind_index.v1"));
    }
}
