//! Directory + handle / actor / organization resolution handlers.
//!
//! Surfaces:
//! - `GET  /_arkret/find/directory/describe`            — capability + profile probe
//! - `POST /_arkret/find/directory/search-realms`       — fuzzy text + visibility filter
//! - `POST /_arkret/find/directory/resolve-realm`       — by id / alias / invite_token /
//!   signed_link
//! - `POST /_arkret/find/directory/resolve-target`      — Realm / Strand / Message address preview
//! - `POST /_arkret/find/directory/search-organizations`
//! - `POST /_arkret/find/directory/resolve-organization`
//! - `POST /_arkret/find/directory/search-actors`
//! - `POST /_arkret/find/directory/search-users`        — mention/user search via body `query`
//! - `POST /_arkret/find/directory/resolve-handle`
//! - `POST /_arkret/find/directory/resolve-agent-selector`
//! - `POST /_arkret/find/directory/list-handles-for-subject`
//! - `POST /_arkret/find/directory/announce`
//! - `POST /_arkret/find/directory/withdraw`
//! - `POST /_arkret/find/directory/push/register`
//!
//! Demo data lives here too — `demo_organization` / `demo_actors` are
//! placeholders until a real `actors` / `organizations` / `handles`
//! provider lands. They are gated to development mode so production
//! deployments do not expose built-in identities.

use std::collections::{BTreeMap, BTreeSet};

use arkret_canonical as canonical;
use arkret_hlc::CursorPurpose;
use arkret_identifiers::{BlobRef, Did, MessageId, RealmId, StrandId, SubscriptionId};
use arkret_models_discovery::{
    ActorPreview, DirectoryActorSearchOutcome, DirectoryAgentSelectorResolutionOutcome,
    DirectoryAnnounceOutcome, DirectoryAnnounceRequestBody, DirectoryHandleResolutionOutcome,
    DirectoryIntent, DirectoryListHandlesForSubjectRequestBody,
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
    ObjectPreview, ObjectPreviewId, OrganizationPreview, RealmJoinCandidate,
    RealmJoinCandidateRole, RealmJoinCandidateServiceType, RealmJoinCandidateSource,
    RealmJoinMethod, RealmMemberCountBucket, RealmMemberCountBucketLabel, RealmPreview,
    ServiceDescribe, TargetKind, UserSearchOutcome,
};
use arkret_models_identity::claim_presentation::{AgentSelectorClaim, validate_agent_slug};
use arkret_models_identity::delivery_binding::{DeliveryMode, RecipientServiceType};
use arkret_models_identity::handle::{HandleClaimKind, HandleHintBindingSource};
use arkret_models_identity::handle_claim::DeliveryBindingHint;
use arkret_models_identity::{
    Handle as SdkHandle, HandleBindingState, HandleClaim as SdkHandleClaim, HandleVisibility,
};
use arkret_server::{
    CursorAuthority, CursorAuthorityError, CursorBindingContext, CursorBindingRecord,
};
use arkret_signatures::Ed25519MoveSigner;
use arkret_wire::{
    AGENT_SELECTOR_CLAIM_SCHEMA, Audience, JoinRule, LinkType, MoveSigner, PayloadProof, RealmRef,
    TargetDescriptor, parse_address, proof_kind, target_digest,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::{Signature, Verifier};
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_application::identity::SessionIdentityState as SessionRecord;
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};

use super::{
    authenticated_session, device_inventory_to_json, handle_for_did, invite_token_matches_realm,
    invite_token_realm_id, is_realm_deleted, now, realm_discoverability, realm_has_member,
    realm_history_visibility, realm_resolvable_to, realm_search_visible_to, sha256_hex,
};
use crate::extract::JsonBody;
use crate::ids;
use crate::routing::organizations;
use crate::state::{AppState, RealmDirectoryEntry, RealmDirectoryQuery};

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
const DIRECTORY_DISCOVERY_PROFILES: &[&str] = &["ak.profile.directory_service.v1"];
const DIRECTORY_SUPPORTED_OPERATIONS: &[&str] = &[
    "ak.find.directory.query.describe",
    "ak.find.directory.query.search_realms",
    "ak.find.directory.query.resolve_realm",
    "ak.find.directory.query.resolve_target",
    "ak.find.directory.query.search_organizations",
    "ak.find.directory.query.resolve_organization",
    "ak.find.directory.query.search_actors",
    "ak.find.directory.query.search_users",
    "ak.find.directory.query.resolve_handle",
    "ak.find.directory.query.resolve_agent_selector",
    "ak.find.directory.query.list_handles_for_subject",
    "ak.find.directory.command.announce",
    "ak.find.directory.command.withdraw",
    "ak.find.directory.push.command.register",
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
        // (`ak.find.directory.push.command.register`). The retired `/_soland/find/
        // directory/subscribe` mirror used the same handler under the
        // historical `subscribe` path; the protocol surface mounts only the
        // canonical `push/register` path.
        .push(Router::with_path("directory/push/register").post(directory_subscribe))
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "directory_describe"))]
async fn directory_describe(depot: &mut Depot) -> JsonResult<ServiceDescribe> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let service_id = Did::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("invalid configured service_id: {error}")))?;
    let trust_domain = arkret_identifiers::TypedTrustDomainId::new(
        state.config().trust_domain.clone(),
    )
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
    let description = ServiceDescribe {
        service_id,
        trust_domain,
        service_type: arkret_wire::ServiceType::DirectoryService,
        protocol_version: arkret_wire::constants::PROTOCOL_VERSION.to_owned(),
        supported_profiles: supported_profiles.clone(),
        profile_bindings: Default::default(),
        supported_operations: DIRECTORY_SUPPORTED_OPERATIONS
            .iter()
            .map(|operation| (*operation).to_owned())
            .collect(),
        supported_bindings: vec![
            arkret_models_discovery::service_description::SupportedBinding::new("http_json")
                .with_base_url(state.config().public_base_url.trim_end_matches('/')),
        ],
        supported_features: supported_features.clone(),
        auth_metadata: arkret_models_discovery::service_description::AuthMetadata::minimal("public_no_auth"),
        limits: Default::default(),
        plaintext_visibility: arkret_models_discovery::service_description::PlaintextVisibility::none(),
        privacy_derivation: None,
        receive_policy_constraints: None,
        implemented_features: supported_features,
        claimed_profiles: supported_profiles
            .iter()
            .map(arkret_models_discovery::service_description::ClaimedProfileEntry::self_claimed)
            .collect(),
        verified_profiles: Vec::new(),
        experimental_features: Vec::new(),
        compat_surfaces: Vec::new(),
        development_mode: state.config().development_mode,
        rate_limit_policy: Some(arkret_models_discovery::service_description::RateLimitPolicy::unspecified()),
        rate_limit_policy_id: None,
        egress_network_policy: Some(arkret_models_discovery::service_description::EgressNetworkPolicy::deny_private_defaults()),
        resource_types: DIRECTORY_RESOURCE_TYPES.to_vec(),
        discovery_profiles: supported_profiles,
        restricted_query_proof: Some(false),
        ingest_modes: vec![arkret_models_discovery::service_description::DirectoryIngestMode::Push],
        accept_policy_kind: Some(arkret_models_discovery::service_description::DirectoryAcceptPolicyKind::Open),
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
        rate_limits: Some(BTreeMap::new()),
        supported_reducer_profiles: Vec::new(),
        supported_schema_profiles: Vec::new(),
        frontier: Vec::new(),
        snapshot_frontier: Vec::new(),
        reducer_profile: None,
        last_materialized_at: None,
        extensions: Default::default(),
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
        assert!(!DIRECTORY_DISCOVERY_PROFILES.contains(&"ak.profile.search.client_index.v1"));
        assert!(!DIRECTORY_DISCOVERY_PROFILES.contains(&"ak.profile.search.blind_index.v1"));
    }
}
