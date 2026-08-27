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
use arkret_identifiers::{
    BlobRef, DidCoreId, DidFullId, MessageId, RealmId, StrandId, SubscriptionId,
    project_full_id_to_core_id,
};
use arkret_models_collaboration::governance::realm_governance::RealmAliasPayload;
use arkret_models_collaboration::objects::realm_alias::RealmAlias;
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
    RealmJoinCandidateRole, RealmJoinCandidateServiceKind, RealmJoinCandidateSource,
    RealmJoinMethod, RealmMemberCountBucket, RealmMemberCountBucketLabel, RealmPreview,
    ServiceDescribe, TargetKind, UserSearchOutcome,
};
use arkret_models_identity::claim_presentation::{AgentSelectorClaim, validate_agent_slug};
use arkret_models_identity::delivery_binding::{DeliveryMode, RecipientServiceKind};
use arkret_models_identity::handle::{HandleClaimKind, HandleHintBindingSource};
use arkret_models_identity::handle_claim::DeliveryBindingHint;
use arkret_models_identity::{
    Handle as SdkHandle, HandleBindingState, HandleClaim as SdkHandleClaim, HandleVisibility,
    ServiceResolutionCarrier,
};
use arkret_server::{CursorAuthority, CursorAuthorityError, CursorBindingContext};
use arkret_signatures::Ed25519PayloadSigner;
use arkret_wire::{
    AddressLinkKind, Audience, CellFamilyId, JoinRule, PayloadProof, PayloadSigner, RealmRef,
    TargetDescriptor, parse_address, proof_kind, target_digest,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::{Signature, Verifier};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_domain::reducer::ProjectionState;
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};
use soland_services::identity::SessionIdentityState as SessionRecord;

use super::{
    authenticated_session, device_inventory_to_json, handle_for_did, invite_token_matches_realm,
    invite_token_realm_id, is_realm_deleted, now, realm_discoverability, realm_has_member,
    realm_history_access, realm_resolvable_to, realm_search_visible_to, sha256_hex,
};
use crate::ids;
use crate::routing::organizations;
use crate::state::{AppState, RealmDirectoryEntry, RealmDirectoryQuery};

fn directory_actor_core_id(value: &str) -> Result<DidCoreId, AppError> {
    if let Ok(core_id) = DidCoreId::new(value.to_owned()) {
        return Ok(core_id);
    }
    let full_id = DidFullId::new(value.to_owned())
        .map_err(|error| AppError::internal(format!("directory actor DID is invalid: {error}")))?;
    project_full_id_to_core_id(&full_id).map_err(|error| {
        AppError::internal(format!("directory actor DID projection failed: {error}"))
    })
}

mod actors_users;
mod agent_selector;
mod demo;
mod discovery;
mod handles;
mod organization_resolution;
mod preview_token;
mod realm_resolution;
mod requester_proof;

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

const DIRECTORY_RESOURCE_KINDS: &[DirectoryResourceKind] = &[
    DirectoryResourceKind::Realm,
    DirectoryResourceKind::Organization,
    DirectoryResourceKind::Actor,
];
pub(crate) const DIRECTORY_OPERATION_BUNDLES: &[&str] = &[
    "ak.operation_bundle.directory_service.describe.v1",
    "ak.operation_bundle.directory_service.http_core.v1",
    "ak.operation_bundle.directory_service.resolve_agent_selector.v1",
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
        // (`ak.find.directory.push.command.register.v1`). The retired `/_soland/find/
        // directory/subscribe` mirror used the same handler under the
        // historical `subscribe` path; the protocol surface mounts only the
        // canonical `push/register` path.
        .push(Router::with_path("directory/push/register").post(directory_subscribe))
}

#[salvo::oapi::endpoint(operation_id = "ak.find.directory.read.describe", tags("spaces"))]
#[tracing::instrument(skip_all, fields(op = "ak.find.directory.read.describe.v1"))]
async fn directory_describe(depot: &mut Depot) -> JsonResult<ServiceDescribe> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let service_resolution = state.service_resolution_commitment();
    let service_id =
        arkret_wire::project_full_id_to_core_id(&service_resolution.full_id).map_err(|error| {
            AppError::internal(format!("service resolution projection failed: {error}"))
        })?;
    let trust_domain = state.config().trust_domain.clone();
    let description = ServiceDescribe {
        service_id,
        service_resolution: service_resolution.as_ref().clone(),
        trust_domain,
        service_kind: arkret_wire::ServiceKind::DirectoryService,
        protocol_version: arkret_wire::PROTOCOL_VERSION.to_owned(),
        supported_profiles: vec![arkret_wire::ProfileId::DIRECTORY_SERVICE_V1.to_owned()],
        profile_bindings: Default::default(),
        supported_operation_bundles: DIRECTORY_OPERATION_BUNDLES
            .iter()
            .map(|bundle| (*bundle).to_owned())
            .collect(),
        transport_bindings: vec![
            arkret_models_discovery::TransportBinding::HttpJson {
                base_url: format!("{}/", state.config().public_base_url.trim_end_matches('/')),
                extension_profile_required: (),
            },
        ],
        supported_features: Vec::new(),
        calendar_tzdb_versions: Vec::new(),
        auth_metadata: arkret_models_discovery::service_description::AuthMetadata::minimal("public_no_auth"),
        limits: Default::default(),
        plaintext_visibility: arkret_models_discovery::service_description::PlaintextVisibility::none(),
        privacy_derivation: None,
        receive_policy_constraints: None,
        claimed_profiles: vec![
            arkret_models_discovery::ClaimedProfileEntry::self_claimed(
                arkret_wire::ProfileId::DIRECTORY_SERVICE_V1,
            ),
        ],
        verified_profiles: Vec::new(),
        interop_surfaces: Vec::new(),
        invite_addressing: None,
        private_contact_discovery: None,
        development_mode: state.config().development_mode,
        rate_limit_policy: Some(arkret_models_discovery::service_description::RateLimitPolicy::unspecified()),
        rate_limit_policy_id: None,
        egress_network_policy: Some(arkret_models_discovery::service_description::EgressNetworkPolicy::deny_private_defaults()),
        resource_kinds: DIRECTORY_RESOURCE_KINDS.to_vec(),
        restricted_query_proof: Some(false),
        ingest_modes: vec![arkret_models_discovery::service_description::DirectoryIngestMode::Push],
        accept_policy_kind: Some(arkret_models_discovery::service_description::DirectoryAcceptPolicyKind::Open),
        accept_policy_ref: None,
        default_ttl_seconds: Some(86_400),
        max_ttl_seconds: Some(604_800),
        revalidation_grace_seconds: Some(3_600),
        accepted_resource_kinds: DIRECTORY_RESOURCE_KINDS.to_vec(),
        accepted_did_methods: vec![
            "did:web".to_owned(),
            "did:webvh".to_owned(),
            "did:key".to_owned(),
        ],
        takedown_contact: None,
        rate_limits: Some(BTreeMap::new()),
        supported_reducer_profiles: Vec::new(),
        frontier: Vec::new(),
        snapshot_frontier: Vec::new(),
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
    fn directory_describe_resource_kinds_exclude_private_message_search() {
        assert!(DIRECTORY_RESOURCE_KINDS.contains(&DirectoryResourceKind::Realm));
        assert!(DIRECTORY_RESOURCE_KINDS.contains(&DirectoryResourceKind::Organization));
        assert!(DIRECTORY_RESOURCE_KINDS.contains(&DirectoryResourceKind::Actor));
    }
}
