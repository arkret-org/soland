pub use arkret_models_collaboration::event_query::EventsQueryPostRequestBody;
pub use arkret_models_collaboration::http_bodies::{
    ContactListRow, ContactState, DirectConversationSummary, DirectConversationSummaryState,
};
pub use arkret_models_collaboration::session_grant_bodies::{
    SessionGrantIntrospectGrant, SessionGrantIntrospectOutcome, SessionGrantIntrospectRequestBody,
    SessionGrantIntrospectStatus, SessionGrantIntrospectionProof, SessionLoginOutcome,
};
pub use arkret_models_collaboration::sync_frames::account_sync::{
    DeviceMessageEnvelope, DeviceMessageTarget, DeviceMessagesAckOutcome,
    DeviceMessagesAckRequestBody, DeviceMessagesGetOutcome, DeviceMessagesSendOutcome,
    DeviceMessagesSendRequestBody,
};
pub use arkret_models_crypto::{
    DeviceStatus, KeysClaimOutcome, KeysClaimRequestBody, KeysQueryOutcome, KeysQueryRequestBody,
    KeysUploadOutcome, KeysUploadRequestBody, KeysUploadUnsignedRequest, QueryDeviceRecord,
};
pub use arkret_models_discovery::ops::HardeningStatus;
use arkret_models_discovery::{
    AccountAuthority, AuthGrantExchange, AuthMetadata, AuthMethod, AuthMethodKind,
    ClaimedProfileEntry, ServiceDescribe,
};
pub use arkret_models_discovery::{
    RealmJoinCandidate, RealmJoinCandidateRole, RealmJoinCandidateServiceKind,
    RealmJoinCandidateSource, RealmJoinMethod,
};
pub use arkret_models_identity::identity::IdentityResolveRequestBody;
use arkret_models_identity::session_credential::SessionGrantProofKind;
pub use arkret_models_integration::{OkOutcome, PushNotifyOutcome, PushNotifyRequestBody};
use arkret_wire::{
    MAX_AUTHORITY_CHAIN_DEPTH, MAX_AUTHORIZED_BY_REFS, MAX_EVENT_ENVELOPE_BYTES,
    MAX_EVENT_PREV_REFS, MAX_EVENT_REFS, MAX_EVENT_SUBMIT_BATCH, ProfileId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
pub use soland_contracts::admin::{
    AuthorizedDeviceSigningKey, DeviceSigningKeyDirectoryOutcome,
    DeviceSigningKeyDirectoryQueryRequestBody,
};
use soland_services::protocol_artifacts as artifacts;

/// Reducer profiles whose complete semantics this Soland build implements.
pub const SUPPORTED_REDUCER_PROFILES: &[&str] = &[arkret_wire::CORE_REDUCER_PROFILE];

#[derive(salvo::oapi::ToSchema, Debug, Serialize)]
pub struct HealthOutcome {
    pub ok: bool,
    pub service: &'static str,
    pub storage: &'static str,
    pub checks: Value,
    /// True when soland is running with `SOLAND_DEVELOPMENT_MODE=true`.
    /// Surfaced here so operators / dashboards (e.g. sodmin) can flag the
    /// deployment with a "DEVELOPMENT MODE — do not use in production"
    /// banner without having to scrape `/_arkret/describe`.
    pub development_mode: bool,
    /// String mirror of [`Self::development_mode`]: `"development"` when
    /// `development_mode == true`, `"production"` otherwise. The proof
    /// verifier path is gated on the same flag — dev mode currently
    /// accepts unsigned / weakly-signed envelopes.
    pub proof_verifier_mode: &'static str,
    /// Effective admin-API authentication posture:
    ///   - `"development"` — any authenticated session may call admin endpoints (dev mode lets
    ///     every session through)
    ///   - `"did_allowlist"` — production gate via `SOLAND_ADMIN_PRINCIPAL_DIDS`
    ///   - `"closed"` — production mode with no admin principals; admin endpoints are locked.
    pub admin_auth_mode: &'static str,
    /// T8.3 — non-sensitive production hardening checklist snapshot.
    /// Surfaced on `/health` so sodmin's `/hardening` dashboard can
    /// aggregate it across all services without scraping the more
    /// expensive describe payload.
    pub hardening: HardeningStatus,
}

#[derive(salvo::oapi::ToSchema, Debug, Serialize)]
pub struct SolandServerDescribeOutcome {
    #[serde(flatten)]
    pub service: ServiceDescribe,
    pub unsupported_profiles: Vec<UnsupportedProfileDescriptor>,
    pub proof_verifier_mode: String,
    pub admin_auth_mode: String,
    pub erasure_receipts_endpoint: String,
    pub hardening: HardeningStatus,
}

#[derive(salvo::oapi::ToSchema, Debug, Serialize)]
pub struct UnsupportedProfileDescriptor {
    pub profile: String,
    pub status: String,
    pub reason: String,
}

impl UnsupportedProfileDescriptor {
    pub fn unsupported(
        profile: impl Into<String>,
        reason: impl Into<String>,
    ) -> UnsupportedProfileDescriptor {
        UnsupportedProfileDescriptor {
            profile: profile.into(),
            status: "unsupported".to_owned(),
            reason: reason.into(),
        }
    }
}

#[derive(salvo::oapi::ToSchema, Debug, Serialize, Deserialize)]
pub struct AuthBridgeDescribeOutcome {
    pub contract: String,
    pub version: String,
    pub api_base_path: String,
    pub auth: AuthBridgeAuthDescriptor,
    pub push: AuthBridgePushDescriptor,
    pub examples: AuthBridgeExamples,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(salvo::oapi::ToSchema, Debug, Serialize, Deserialize)]
pub struct AuthBridgeAuthDescriptor {
    pub dev_login_path: String,
    pub session_grant_issuance_path: String,
    pub session_grant_presentation: String,
    pub principal_id_body_field: String,
}

#[derive(salvo::oapi::ToSchema, Debug, Serialize, Deserialize)]
pub struct AuthBridgePushDescriptor {
    pub register_device_path: String,
    pub unregister_device_path: String,
    pub session_grant_header: String,
    pub principal_id_body_field: String,
    pub register_device_mode: String,
}

#[derive(salvo::oapi::ToSchema, Debug, Serialize, Deserialize)]
pub struct AuthBridgeExamples {
    pub session_grant_issue_request: Value,
    pub register_device_request: Value,
    pub unregister_device_request: Value,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct OutboundPushBridgeDescribeOutcome {
    pub contract: String,
    pub version: String,
    pub api_base_path: String,
    pub gateway_contract: OutboundPushGatewayContractDescriptor,
    pub delivery: OutboundPushDeliveryDescriptor,
    pub examples: OutboundPushBridgeExamples,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct OutboundPushGatewayContractDescriptor {
    pub resolve_path: String,
    pub fetch_path: String,
    pub cache_status_path: String,
    pub cache_invalidate_path: String,
    pub cache_export_path: String,
    pub cache_import_path: String,
    pub bridge_describe_path: String,
    pub notify_path: String,
    pub accepted_contracts: Vec<String>,
    pub fetch_mode: String,
    pub cache_mode: String,
    pub snapshot_store_mode: String,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct OutboundPushDeliveryDescriptor {
    pub operation_id: String,
    pub source_service_id_header: String,
    pub destination_service_id_header: String,
    pub request_id_header: String,
    pub idempotency_key_header: String,
    pub payload_mode: String,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct OutboundPushBridgeExamples {
    pub resolve_request: Value,
    pub fetch_request: Value,
    pub notify_headers: Value,
    pub cache_import_request: Value,
    pub cache_export_response: Value,
}

// Shared `/_floria/integration/describe` manifest shape: re-exported from
// the SDK contracts crate (the authoritative definition shared by floria,
// soland, and coauth) instead of a local copy.
pub use arkret_models_integration::integration::{
    IntegrationDependencyDescriptor, IntegrationDescribeOutcome, IntegrationSurfaceDescriptor,
};

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct OutboundPushBridgeResolveRequestBody {
    pub push_gateway_url: String,
    #[serde(default)]
    pub refresh: bool,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct OutboundPushBridgeFetchRequestBody {
    pub push_gateway_url: String,
    #[serde(default)]
    pub force_refresh: bool,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct OutboundPushBridgeCacheInvalidateRequestBody {
    #[serde(default)]
    pub push_gateway_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct OutboundPushBridgeCacheSnapshot {
    pub push_gateway_url: String,
    pub service_base_url: String,
    pub bridge_describe_url: String,
    pub fetch_state: String,
    pub cache_state: String,
    pub contract_digest: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub fetched_at: DateTime<Utc>,
    pub remote_contract: Value,
    /// C33.1: trust state for the cached snapshot (`pending` / `trusted` /
    /// `revoked`). Imported snapshots default to `pending` if omitted.
    #[serde(default = "default_trust_pending")]
    pub trust_level: String,
    /// Last freshness check timestamp, distinct from `fetched_at`.
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub freshness_at: Option<DateTime<Utc>>,
    /// Opaque server ETag from the upstream describe response.
    #[serde(default)]
    pub etag: String,
}

fn default_trust_pending() -> String {
    "pending".to_owned()
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct OutboundPushBridgeCacheExportOutcome {
    #[serde(default)]
    pub entries: Vec<OutboundPushBridgeCacheSnapshot>,
    pub snapshot_store_kind: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct OutboundPushBridgeCacheImportRequestBody {
    #[serde(default)]
    pub entries: Vec<OutboundPushBridgeCacheSnapshot>,
    #[serde(default)]
    pub replace_existing: bool,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct OutboundPushBridgeCacheImportOutcome {
    pub imported_count: usize,
    pub skipped_count: usize,
    pub total_entries: usize,
    pub snapshot_store_kind: String,
    pub cache_state: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct OutboundPushBridgeResolveOutcome {
    pub push_gateway_url: String,
    pub service_base_url: String,
    pub bridge_describe_url: String,
    pub fetch_state: String,
    pub cache_state: String,
    pub contract_digest: String,
    pub fetched_contract: OutboundPushResolvedContract,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct OutboundPushResolvedContract {
    pub contract: String,
    pub expected_notify_path: String,
    pub expected_operation_id: String,
    pub expected_source_service_id_header: String,
    pub expected_destination_service_id_header: String,
    pub expected_request_id_header: String,
    pub expected_idempotency_key_header: String,
    /// Upstream-advertised authentication modes (`bearer`, `signed_request`,
    /// `mtls`, …). Outbound delivery binds its signing posture to this list
    /// instead of assuming a fixed mode.
    #[serde(default)]
    pub auth_modes: Vec<String>,
    /// Upstream-advertised privacy mode for the notify payload (`blind_wakeup`,
    /// `event_summary`, …). Used by the delivery loop to know whether the
    /// payload must remain opaque.
    #[serde(default)]
    pub privacy_mode: String,
    /// The upstream service DID. Required for trust-level promotion: imports
    /// only land at `trust_level=trusted` if this DID is in the operator's
    /// `push_bridge_trusted_service_ids` allowlist.
    #[serde(default)]
    pub service_id: String,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct OutboundPushBridgeFetchOutcome {
    pub push_gateway_url: String,
    pub service_base_url: String,
    pub bridge_describe_url: String,
    pub fetch_state: String,
    pub cache_state: String,
    pub contract_digest: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub fetched_at: Option<DateTime<Utc>>,
    pub fetched_contract: OutboundPushResolvedContract,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_contract: Option<Value>,
    /// C33.1: trust state of the cached snapshot returned by the fetch path.
    #[serde(default = "default_trust_pending")]
    pub trust_level: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub freshness_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub etag: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct OutboundPushBridgeCacheStatusOutcome {
    #[serde(default)]
    pub entries: Vec<OutboundPushBridgeCacheEntry>,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct OutboundPushBridgeCacheEntry {
    pub push_gateway_url: String,
    pub service_base_url: String,
    pub bridge_describe_url: String,
    pub fetch_state: String,
    pub cache_state: String,
    pub contract_digest: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub fetched_at: DateTime<Utc>,
    pub fetched_contract: OutboundPushResolvedContract,
    /// C33.1: trust state surfaced to status callers so dashboards can flag
    /// `pending` / `revoked` snapshots without round-tripping the export API.
    pub trust_level: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub freshness_at: DateTime<Utc>,
    pub etag: String,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct OutboundPushBridgeCacheInvalidateOutcome {
    pub removed_count: usize,
    pub remaining_entries: usize,
    pub cache_state: String,
}

// Client-sync family DTOs come straight from the SDK (`ServiceDescribe`
// answers `account/describe`, `SyncRequestBody` carries the subscribe/sync
// request); both are shared SDK wire types, so soland keeps
// no private copies that could drift. NOTE: the explicit `model::` path
// matters — the SDK root re-exports a different, client-side typed
// `sync::SyncRequestBody` under the same name.
// Snapshot head operations return the full signed `ak.schema.snapshot.v1`
// manifest. soland answers both operations with `not_implemented` until it can
// produce a real Snapshot detached proof.

// authz check DTOs are now the spec-authoritative SDK types. The SDK
// `AuthzDecision` enum was aligned to the spec five-valued form
// (allow / soft_deny / hard_deny / quarantine / require_review) and
// `AuthzCheckRequestBody` to `{ actor_id, action, resource?, context? }`,
// so soland re-uses them directly instead of carrying local copies.
pub use arkret_models_collaboration::governance::authorization::{
    AuthzCheckOutcome, AuthzCheckRequestBody,
};
// Moderation report request/outcome are the SDK DTOs (`arkret-models-collaboration` carries
// `service-operation-dtos.schema.json#/$defs/ModerationReportOutcome`:
// `status` enum `submitted|resolved`, `routed_to` is an array of bare DIDs);
// no soland mirrors.
pub use arkret_models_collaboration::governance::moderation::{
    ModerationReportOutcome, ModerationReportRequestBody,
};
pub use arkret_models_collaboration::sync_frames::client_sync::SyncRequestBody;
pub use arkret_models_integration::{
    PushRegisterDeviceRequestBody, PushUnregisterDeviceRequestBody,
};

fn default_true() -> bool {
    true
}

#[derive(salvo::oapi::ToSchema, Debug, Deserialize)]
pub struct UpsertPolicyDocumentRequestBody {
    #[serde(default)]
    pub policy_id: Option<String>,
    pub scope: String,
    pub subject_ref: String,
    pub policy_kind: String,
    pub effect: String,
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default)]
    pub resource: Value,
    #[serde(default)]
    pub obligations: Vec<Value>,
    #[serde(default = "default_true")]
    pub active: bool,
}

#[derive(salvo::oapi::ToSchema, Debug, Serialize)]
pub struct PolicyDocumentOutcome {
    pub policy_id: String,
    pub owner: String,
    pub scope: String,
    pub subject_ref: String,
    pub policy_kind: String,
    pub payload: Value,
    pub active: bool,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
}

#[derive(salvo::oapi::ToSchema, Debug, Serialize)]
pub struct PolicyDocumentsOutcome {
    pub policies: Vec<PolicyDocumentOutcome>,
    pub next_cursor: Option<String>,
}

#[derive(salvo::oapi::ToSchema, Debug, Deserialize)]
pub struct DevLoginRequestBody {
    pub actor: String,
    pub device_id: String,
    pub display_name: Option<String>,
}

pub type LogoutOutcome = arkret_models_identity::AccountLogoutOutcome;

#[derive(salvo::oapi::ToSchema, Debug, Serialize)]
pub struct SolandAccountRegisterOutcome {
    pub did: String,
    pub handle: String,
    pub display_name: Option<String>,
    pub state: String,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

// Identity log / receipts outcomes are owned by the corresponding SDK model crates;
// authoritative carrier for identity operation shapes); no soland mirrors.
// AKP-0008 / AKP-0009 — Personal Agent operations. Every request/response
// DTO is the SDK-authoritative `arkret_models_collaboration::agent_operations` shape (spec
// `agent-operations.schema.json`): `agent_view`/`agent_list` carry the spec
// `agent_projection`; the `agent_key_pair` outcome is
// `{ok, authorized_event_ref}`; grant attach/detach outcomes are
// `{ok, grant_id}` / `{ok, revoked_at}`; Sidecar ensure carries the typed
// event-derived `sidecar_id` and native `source_context_ref`. The lifecycle
// outcome (`agent_lifecycle_state` = `operation_status_outcome` =
// `{ok: true, status}`) has no struct mirror in the SDK and is emitted as a
// spec-exact JSON object by the agents handler. `AgentProvisionRequestBody` /
// `AgentProvisionOutcome` were already SDK-backed.
// ── AKP-0010 (R3 spec-sync 2026-05-27, arkret-spec b47ff6ec) — media
// token exchange wire shapes. Both the request body and the response types
// come straight from the SDK (`CallMediaTokenExchangeRequestBody` carries
// typed ids `realm_id`/`call_id`/`actor_id`/`device_id` plus the optional
// `capability_refs`/`desired_media` inputs; `CallMediaTokenExchangeOutcome`
// / `CallMediaParticipantBinding` are shared SDK wire types),
// so soland no longer mints private mirrors that can drift from the spec DTOs.
pub use arkret_models_collaboration::agent_operations::{
    AgentDeactivateRequestBody, AgentGrantAttachOutcome, AgentGrantAttachRequestBody,
    AgentGrantDetachOutcome, AgentGrantDetachRequestBody, AgentKeyPairOutcome,
    AgentKeyPairRequestBody, AgentList, AgentPauseRequestBody, AgentResumeRequestBody,
    AgentSidecarList, AgentSidecarView, AgentView,
};
pub use arkret_models_collaboration::objects::media::{
    CallMediaParticipantBinding, CallMediaServiceSignature, CallMediaTokenExchangeOutcome,
    CallMediaTokenExchangeRequestBody,
};
pub use arkret_models_collaboration::sidecar_operations::{
    SidecarEnsureOutcome as AgentSidecarEnsureOutcome,
    SidecarEnsureRequestBody as AgentSidecarEnsureRequestBody,
};
pub use arkret_models_crypto::KeysBackupsPutRequestBody;
// Key-backup replace/delete outcomes are the SDK server-side DTOs
// (`arkret-models-crypto` is the authoritative carrier for
// `keys-operations.schema.json#/$defs/keys_backups_replace_outcome` /
// `keys_backups_delete_outcome`); no soland mirrors.
pub use arkret_models_crypto::{
    KeyBackupPutStatus, KeysBackupsDeleteOutcome, KeysBackupsList, KeysBackupsReplaceOutcome,
};
pub use arkret_models_identity::identity::{IdentityLogListOutcome, IdentityReceiptListOutcome};

// Recovery policy / receipt endpoints validate against the spec REC-1 shapes in
// `routing::identity::recovery`: policy publish uses the SDK request body,
// while receipt write keeps a signed JSON wrapper so the raw signed fields can
// be verified before being projected into typed outcomes. The SDK carries the
// authoritative typed forms (`arkret_models_crypto::{RecoveryPolicy,
// RecoveryReceipt}`) for clients; no soland-private mirror exists.

const SUPPORTED_OPERATION_SURFACES: &[&str] = &[
    "service_discovery",
    "identity_registry",
    "identity_resolution",
    "principal_service_binding",
    "events_sync",
    "peer_federation",
    "directory_discovery",
    "contact_lifecycle",
    "consent_management",
    "account_data",
    "read_cursor",
    "blob_storage",
    "device_and_keys",
    "realtime_media",
    "authz_policy",
    "moderation_reports",
    "realm_object_read",
    "realm_read",
    "realm_governance_links",
    "circle_management",
    "push",
    "applet",
    "applet_install",
    "applet_ghost",
    "mimi_interop",
    "agent_pairing_handoff",
    "invite_locator_handoff",
    "agent_runtime",
];

const SUPPORTED_STANDALONE_OPERATION_IDS: &[&str] = &[
    "ak.gate.account.command.pair_device",
    "ak.gate.account.command.logout",
    "ak.gate.account.command.revoke_session",
    "ak.find.directory.read.describe",
    "ak.find.directory.read.search_realms",
    "ak.find.directory.read.resolve_realm",
    "ak.find.directory.read.resolve_target",
    "ak.find.directory.read.resolve_agent_selector",
    "ak.find.directory.read.list_handles_for_subject",
    "ak.self.blob.upload.create",
    "ak.self.blob.resource.head",
    "ak.self.blob.resource.get",
    "ak.self.keys.backups.resource.replace",
    "ak.self.keys.backups.read.list",
    "ak.self.keys.backups.command.unlock",
    "ak.self.keys.backups.resource.delete",
    "ak.peer.invites.command.submit",
    "ak.open.invite_locator.read.resolve",
];

/// Spec operations soland deliberately does NOT declare even though their
/// surface group is otherwise supported.
const UNDECLARED_OPERATION_IDS: &[&str] = &["ak.find.directory.command.takedown_appeal"];

fn canonical_supported_operations() -> Vec<String> {
    let missing_surfaces =
        artifacts::missing_operation_surface_groups(SUPPORTED_OPERATION_SURFACES);
    debug_assert!(
        missing_surfaces.is_empty(),
        "supported operation surface groups missing from artifact registry: {missing_surfaces:?}"
    );
    let missing = artifacts::missing_operation_ids(SUPPORTED_STANDALONE_OPERATION_IDS);
    debug_assert!(
        missing.is_empty(),
        "standalone supported operation ids missing from artifact registry: {missing:?}"
    );
    let mut supported = artifacts::operation_ids_for_surface_groups(SUPPORTED_OPERATION_SURFACES);
    for operation_id in artifacts::registered_operation_ids(SUPPORTED_STANDALONE_OPERATION_IDS) {
        if !supported.contains(&operation_id) {
            supported.push(operation_id);
        }
    }
    supported.retain(|operation_id| !UNDECLARED_OPERATION_IDS.contains(&operation_id.as_str()));
    debug_assert!(
        supported
            .iter()
            .all(|operation_id| artifacts::operation_ids().contains(operation_id)),
        "canonical_supported_operations must only contain spec operation ids"
    );
    supported
}

fn local_extension_operations() -> Vec<String> {
    crate::routing::soland_extension_operation_ids()
}

fn profile_limitations() -> Vec<Value> {
    vec![
        json!({
            "area": "federation.outbound_push",
            "status": "partial",
            "landed": [
                "per-peer durable fanout transcript",
                "signed fanout intent evidence",
                "retry/durability metadata"
            ],
            "remaining": [
                "network HTTP dispatch",
                "RFC 9421 HTTP Message Signatures header emission",
                "automatic retry worker"
            ],
            "reason": "outbound Move/Seal fanout persists a signed intent and retry boundary per peer; actual RFC 9421 HTTP delivery is still not claimed"
        }),
        json!({
            "area": "authz.capability_engine_depth",
            "status": "partial",
            "standard_self_surface": "implemented",
            "reason": "standard /_arkret/self/authz/check, effective-grants, and invites are advertised and SDK-backed; deeper selector, constraint, delegation, and policy lifecycle semantics are tracked by dedicated AUTHZ audit items"
        }),
        json!({
            "area": "policies.describe",
            "status": "scaffold_contract",
            "reason": "policy collection describe is artifact-shaped metadata for the local policy document store; it is not a complete policy profile claim"
        }),
        json!({
            "area": "admin.bottom.manual_repair",
            "status": "unsupported_signing_path",
            "reason": "manual Bottom repair validates effect scope but does not submit or sign arbitrary manual effects"
        }),
        json!({
            "area": "index.query",
            "status": "limited_projection",
            "reason": "index query is backed by the local materialized projection and demo fallback, not a full durable index-node profile"
        }),
        json!({
            "area": "event_submit.batch_receipt",
            "status": "unsupported",
            "reason": "current profile accepts one Event Envelope per request"
        }),
        json!({
            "area": "member_identity.proof",
            "status": "partial_fail_closed",
            "supported": "plaintext identity_payload.member_identity with Ed25519 raw signature verified against the subject_id DID verification method",
            "unsupported": [
                "encrypted identity_payload proof verification",
                "ES256 / ES384 MemberIdentityProof.signature_algorithm"
            ],
            "reason": "non-Ed25519 and encrypted MemberIdentity proof forms are refused rather than shape-accepted"
        }),
        json!({
            "area": "agents.runtime_attestation",
            "status": "unsupported_fail_closed",
            "reason": "runtime_attestation verifier/controller approval ledger is not wired; supplied attestations are rejected"
        }),
        json!({
            "area": "extensions.tsp",
            "status": "unmounted",
            "reason": "TSP transport/route/audit handlers remain unmounted until real envelope verify/decrypt and persistent signed audit chain exist"
        }),
        json!({
            "area": "extensions.bot_actor",
            "status": "unmounted",
            "reason": "bot/ghost actor HTTP handlers remain unmounted until durable provisioning, accountability grants, and restart-safe state exist"
        }),
        json!({
            "area": "extensions.sovereign",
            "status": "stub_contract",
            "reason": "sovereign deployment endpoints are local boundary/scenario scaffolding; outbound guard integration is incomplete outside startup/profile checks"
        }),
        json!({
            "area": "blob.presign",
            "status": "local_direct_serve",
            "reason": "presign issues a short-lived soland-signed local /blob/get URL; backend-native object-store presign is not claimed"
        }),
        json!({
            "area": "snapshot.head",
            "status": "standard_self_supported",
            "reason": "ak.self.snapshot.read.manifest_head returns a signed ak.schema.snapshot.v1 manifest; the /_soland dev bundle remains a product-face compatibility surface"
        }),
        json!({
            "area": "account_auth.device_pair",
            "status": "standard_gate_supported",
            "spec_operation": "ak.gate.account.command.pair_device",
            "canonical_path": "/_arkret/gate/account/device-pair",
            "reason": "ak.gate.account.command.pair_device is served on the spec path for existing-device-authorized sibling registration. The old soland-local device pairing scaffold and approval family are removed; v1 core does not define a self/devices pairing-requests approval surface (service-http-binding.md §85, key-management.md §384, device-lifecycle.md §499). ak.gate.account.exchange.complete_oidc is delegated to the bridges deployment and not served here."
        }),
        json!({
            "area": "consent.scope_any_cross_service_cascade",
            "status": "partial_local_only",
            "spec": "T17",
            "implemented": "a holder `ak.consent.revoke` with scope=any is honored on read: every child-scope grant resolution folds the `any` cell (see has_active_consent / has_active_consent_grant_evidence), so an any-revoke withdraws all child scopes for local consent decisions",
            "unsupported": "the cross-service cache-invalidation broadcast to downstream consumers (directory_reachability / mimi_consent / push_contact_psi / invite_gate / in_flight_invite on teabay / floria / coauth) and the per-child-scope `superseded_by_any_revoke` durable marker are not emitted; this deployment has no production cross-service consent-invalidation fanout path",
            "reason": "the local any-revoke effect is complete; the cross-service invalidation channels require a fanout transport soland does not implement"
        }),
        json!({
            "area": "identity.resolver_health_signal",
            "status": "unsupported",
            "spec": "SEC-01 / identity-did.md §3.4",
            "unsupported": "resolver degraded/health signal verification is not wired into production paths",
            "reason": "soland has no inbound resolver-health signal feed or per-write gate for this verdict"
        }),
        json!({
            "area": "federation.delivery_binding_handover_emit",
            "status": "implemented",
            "spec": "B1.9 / federation.md service-binding handover",
            "implemented": "the peer Event receive track compares the submitted delivery-binding frontier with the accepted member projection, applies handover grace, and emits typed delivery_binding_stale details only when a fresh verified new-service resolution carrier is available; otherwise it fails closed without redirecting",
            "reason": "member projection, accepted frontier witness, and verified service-route cache jointly supply the handover proof"
        }),
        json!({
            "area": "audit.policy_receipt_emit",
            "status": "unsupported",
            "spec": "B1.12 / B1.16",
            "unsupported": "soland does not emit signed audit policy receipts on any production route",
            "reason": "no production audit-receipt emission path is wired in this deployment"
        }),
    ]
}

fn full_principal_server_gap_summary() -> Vec<Value> {
    vec![json!({
        "profile": "ak.profile.principal_server.v1",
        "status": "not_claimed",
        "first_batch_landed": [
            "artifact-derived supported operation advertisement",
            "SDK-backed lattice family/kind/bottom registry bindings",
            "outbound Move/Seal fanout signed intent evidence",
            "per-peer retry/durability transcript metadata"
        ],
        "remaining_gaps": [
            "RFC 9421 HTTP Message Signatures on outbound and inbound federation HTTP",
            "automatic retry dispatcher with durable backoff lease",
            "full identity registry, directory service, blob node, and authorization profile coverage",
            "complete full-profile conformance matrix generated from artifacts"
        ]
    })]
}

/// Build the service description.
///
/// The seven configuration values this used to take positionally were, by its
/// own comment, "AppConfig fields" — so it takes `AppConfig`. Every caller
/// already had `state.config()` in hand, and threading them one by one is how
/// a tenth (`key_backup_daily_download_limit`) would otherwise have been added
/// to a signature that already carried a `too_many_arguments` waiver.
pub fn describe(
    service_resolution: &arkret_models_identity::ResolutionCommitment,
    storage: &'static str,
    config: &crate::config::AppConfig,
) -> ServiceDescribe {
    let public_base_url = config.public_base_url.as_str();
    let development_mode = config.development_mode;
    let account_authority_url = config.account_authority_url.as_deref();
    let oidc_client_id = config.oidc_client_id.as_deref();
    let trust_domain = config.trust_domain.as_str();
    let resumable_upload_incomplete_ttl_seconds = config.resumable_upload_incomplete_ttl_seconds;
    let to_device_queue_capacity = config.to_device_queue_capacity;
    // Account Authority discovery (service-surface §2.5.1): the client-visible
    // owner of the auth-side `/_arkret/gate/account/*` ops the client posts to
    // (session-grant issuance + hard logout). Those are served by the Auth
    // Server (coauth), which DPoP-binds holder proofs to its OWN origin. When
    // an external Account Authority is configured, clients post gate/account
    // requests there directly and the DPoP `htu` aligns with that public base.
    // Personal deployments may co-locate this role at the Principal origin.
    let account_origin = account_authority_url
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(public_base_url)
        .trim_end_matches('/')
        .to_owned();
    let gate_account_base = format!("{account_origin}/_arkret/gate/account");

    // Authentication methods are pure provider discovery; they do not decide
    // gate/account routing. Advertise OIDC when an Auth Server is configured;
    // the client uses standard OIDC discovery and submits an
    // `oidc_code_exchange` proof to the Account Authority's `session-grants`.
    let mut methods = Vec::new();
    if let Some(account_authority_url) =
        account_authority_url.filter(|value| !value.trim().is_empty())
    {
        let issuer = account_authority_url.trim_end_matches('/').to_owned();
        let openid_configuration = format!("{issuer}/.well-known/openid-configuration");
        methods.push(AuthMethod {
            method: AuthMethodKind::Oidc,
            issuer: Some(issuer.clone()),
            provider: None,
            openid_configuration: Some(openid_configuration.clone()),
            // Registered OAuth `client_id` (coauth keys clients by ULID). The
            // web client uses this verbatim; absent it, it has no valid id to
            // fall back to and coauth answers `could not find client`.
            client_id: oidc_client_id
                .filter(|value| !value.trim().is_empty())
                .map(str::to_owned),
            scopes: vec!["openid".to_owned(), "profile".to_owned()],
            grant_exchange: AuthGrantExchange {
                proof_kind: SessionGrantProofKind::OidcCodeExchange,
            },
        });
    }

    let auth_metadata = AuthMetadata {
        mode: if development_mode {
            "development".to_owned()
        } else {
            "production".to_owned()
        },
        account_authority: Some(AccountAuthority {
            origin: account_origin,
            gate_account_base,
        }),
        methods,
        did_binding_methods: Vec::new(),
        read: None,
        extra: Default::default(),
    };
    let supported_operations = canonical_supported_operations();
    let local_extension_operations = local_extension_operations();

    // Round 4 (B1) — ServiceDescribe: 17 required top-level fields.
    // Implemented / claimed / verified profiles are partitioned per spec
    // service-surface.md §3.0; `verified_profiles` MUST be empty when
    // `development_mode=true`. The full T6.1 claim-level partition layer
    // in routing::system::describe::apply_claim_level_partition still
    // overrides these typed fields before serialization — we keep typed
    // defaults here so out-of-tree typed consumers see the correct shape
    // and pass `ServiceDescribe::validate`.
    // Round 4 — typed entries match `service-describe.schema.json`
    // (`claimed_profiles[*]`, `compat_surfaces[*]`). The routing-layer
    // `apply_claim_level_partition` populates these SDK-typed fields
    // before the response is serialized so the JSON wire shape and the
    // typed surface can never drift.
    //
    // Profile catalogue per `arkret-spec/spec/v1/zh/conformance/conformance-profiles.md`
    // §1 / §7 / §8: a principal server self-claims the Event Store
    // interop floor AND the Principal Server + Principal Server Events
    // API stable-catalog profiles in addition to whatever interop
    // staging extensions it implements (MIMI here).
    let claimed_profiles = vec![
        ClaimedProfileEntry::self_claimed("ak.profile.core_event_store.v1"),
        ClaimedProfileEntry::self_claimed("ak.profile.principal_server.v1"),
        ClaimedProfileEntry::self_claimed("ak.profile.principal_server_events_api.v1"),
        ClaimedProfileEntry {
            notes: Some(
                "MIMI provider facade first round (not a full v1 core conformance claim)"
                    .to_owned(),
            ),
            ..ClaimedProfileEntry::self_claimed("ak.profile.mimi_interop.v1")
        },
    ];
    let verified_profiles = Vec::new();
    let implemented_features_seed: Vec<String> = Vec::new();
    let experimental_features = vec![
        "federation.outbound_push.signed_intent".to_owned(),
        "admin.bottom.manual_repair".to_owned(),
        "index.query.local_projection".to_owned(),
    ];
    let compat_surfaces = Vec::new();
    let service_id = arkret_wire::DidCoreId::from(
        arkret_wire::project_full_id_to_core_id(&service_resolution.full_id)
            .expect("service resolution DidFullId must project to a stable service id"),
    );
    let plaintext_visibility = arkret_models_discovery::service_description::PlaintextVisibility {
        data_classes: vec![
            arkret_wire::PlaintextDataClassKind::MessageContent,
            arkret_wire::PlaintextDataClassKind::AttachmentPlaintext,
            arkret_wire::PlaintextDataClassKind::AttachmentPreview,
            arkret_wire::PlaintextDataClassKind::Thumbnail,
            arkret_wire::PlaintextDataClassKind::FullTextIndex,
            arkret_wire::PlaintextDataClassKind::NotificationSummary,
            arkret_wire::PlaintextDataClassKind::MediaPlaintext,
        ],
        max_visibility: Some(arkret_models_discovery::service_description::PlaintextMaxVisibility::PrivatePlaintext),
        event_kinds: vec![
            "ak.message.create".to_owned(),
            "ak.realm.policy_bundle".to_owned(),
            "ak.realm.plaintext_visible_services".to_owned(),
        ],
        payload_paths: vec![
            "payload.content".to_owned(),
            "payload.body".to_owned(),
            "payload.media_service_decrypts".to_owned(),
        ],
        blob_purposes: vec![
            "download".to_owned(),
            "file_transfer".to_owned(),
            "attachment_preview".to_owned(),
            "thumbnail".to_owned(),
            "search_index_shard".to_owned(),
        ],
        projection_outputs: vec![
            "timeline.message_content".to_owned(),
            "blob.upload".to_owned(),
            "push.minimal_or_visible_notification".to_owned(),
            "search.encrypted_or_authorized_index".to_owned(),
        ],
        notes: Some(
            "Soland only accepts private plaintext when the current Realm policy lists this service DID with matching plaintext_visible_services.data_classes; otherwise it fails closed."
                .to_owned(),
        ),
        extra: Default::default(),
    };

    let mut description = ServiceDescribe {
        service_id: service_id.clone(),
        service_resolution: service_resolution.clone(),
        trust_domain: trust_domain
            .parse()
            .expect("trust_domain must be ak:trust_domain:<scope>"),
        service_kind: arkret_wire::ServiceKind::PrincipalServer,
        protocol_version: arkret_wire::PROTOCOL_VERSION.to_owned(),
        supported_profiles: {
            let mut profiles = vec![
                "ak.profile.core_event_store.v1".to_owned(),
                "ak.profile.principal_server.v1".to_owned(),
                "ak.profile.principal_server_events_api.v1".to_owned(),
                "ak.profile.mimi_interop.v1".to_owned(),
                "ak.profile.file_transfer.v1".to_owned(),
                "ak.profile.webrtc_media.v1".to_owned(),
                ProfileId::DIRECT_CONVERSATION_REALM_V1.to_owned(),
            ];
            // PROF-1 (R3 spec-sync 2026-05-27, arkret-spec b47ff6ec) —
            // advertise `ak.profile.media_service_binding.v1` whenever the
            // server exposes the `ak.self.call.media.exchange.issue_token`
            // handler. soland mounts the handler unconditionally, and also
            // claims the required `ak.profile.webrtc_media.v1` dependency above.
            profiles.push("ak.profile.media_service_binding.v1".to_owned());
            profiles
        },
        profile_bindings: Default::default(),
        plaintext_visibility,
        calendar_tzdb_versions: Vec::new(),
        implemented_features: implemented_features_seed,
        claimed_profiles,
        verified_profiles,
        experimental_features,
        compat_surfaces,
        development_mode,
        // service-describe.schema.json requires `rate_limit_policy` or
        // `rate_limit_policy_id` (the legacy top-level `rate_limit` field was
        // removed). Derive the advertised per-class policy from the SAME runtime
        // config the HTTP middleware enforces so wire and
        // enforcement can never drift — a conformant client budgeting against
        // this policy cannot trip a 429 it could not predict.
        rate_limit_policy: Some(
            config.rate_limiter.advertised_policy(),
        ),
        rate_limit_policy_id: None,
        egress_network_policy: Some(arkret_models_discovery::service_description::EgressNetworkPolicy::deny_private_defaults()),
        resource_kinds: Vec::new(),
        discovery_profiles: Vec::new(),
        restricted_query_proof: None,
        ingest_modes: Vec::new(),
        accept_policy_kind: None,
        accept_policy_ref: None,
        default_ttl_seconds: None,
        max_ttl_seconds: None,
        revalidation_grace_seconds: None,
        accepted_resource_kinds: Vec::new(),
        accepted_did_methods: Vec::new(),
        takedown_contact: None,
        rate_limits: None,
        supported_features: vec![
            arkret_models_collaboration::objects::direct_conversation::DIRECT_CONVERSATION_REALM_ROLE_FEATURE.to_owned(),
            arkret_models_collaboration::governance::history_visibility::DISCUSSION_HISTORY_VISIBILITY_FEATURE.to_owned(),
            "org.arkret.soland.feature.auth.logout".to_owned(),
            "org.arkret.soland.feature.contacts.request".to_owned(),
            "org.arkret.soland.feature.contacts.respond".to_owned(),
            "org.arkret.soland.feature.space.lifecycle".to_owned(),
            "org.arkret.soland.feature.schema.registry".to_owned(),
            "org.arkret.soland.feature.events.describe".to_owned(),
            "org.arkret.soland.feature.events.submit".to_owned(),
            "org.arkret.soland.feature.events.read".to_owned(),
            "events_query_range_completeness".to_owned(),
            "org.arkret.soland.feature.federation.transaction".to_owned(),
            "org.arkret.soland.feature.federation.operations".to_owned(),
            "org.arkret.soland.feature.sync.client_sync".to_owned(),
            "org.arkret.soland.feature.sync.bound_cursor".to_owned(),
            "org.arkret.soland.feature.sync.incremental_since".to_owned(),
            "org.arkret.soland.feature.sync.typing".to_owned(),
            "ak.feature.agent_runtime_approval_notifications.v1".to_owned(),
            "org.arkret.soland.feature.personal_productivity.scheduled_send_wake_only".to_owned(),
            "org.arkret.soland.feature.personal_productivity.reminder_snooze_private_wake"
                .to_owned(),
            "org.arkret.soland.feature.directory.search_realms".to_owned(),
            "org.arkret.soland.feature.directory.resolve_realm".to_owned(),
            "org.arkret.soland.feature.authz.check".to_owned(),
            "org.arkret.soland.feature.authz.effective_grants".to_owned(),
            "org.arkret.soland.feature.authz.invites".to_owned(),
            "org.arkret.soland.feature.policy.check_signed_decision".to_owned(),
            "org.arkret.soland.feature.profile.presence".to_owned(),
            "org.arkret.soland.feature.push.register_device".to_owned(),
            "org.arkret.soland.feature.push.target_id_hmac_rotation".to_owned(),
            "org.arkret.soland.feature.push.rules".to_owned(),
            "org.arkret.soland.feature.blob.upload".to_owned(),
            // Spec crypto-media/media-and-blob.md §2.1 — protocol-level
            // feature id for the resumable (tus) upload companion binding
            // of ak.self.blob.upload. Pairs with the `kind="tus"` entry in
            // supported_bindings below.
            "ak.feature.blob.resumable_upload.tus.v1".to_owned(),
            "ak.feature.mls_last_resort_keypackage.v1".to_owned(),
            // encryption-and-audit.md §2.10.7 — advertise support for the
            // history-shareable `mls_exporter_aead_v1` content scheme so clients
            // know late-joiner pre-join history decryption is reachable here.
            "ak.feature.mls_exporter_aead.v1".to_owned(),
            "org.arkret.soland.feature.blob.authenticated_download".to_owned(),
            "org.arkret.soland.feature.file_transfer".to_owned(),
            "org.arkret.soland.feature.blob.presigned_download.local_direct_serve".to_owned(),
            "org.arkret.soland.feature.blob.upload_policy".to_owned(),
            "org.arkret.soland.feature.federation.transaction_idempotency".to_owned(),
            "org.arkret.soland.feature.policy.documents".to_owned(),
            "org.arkret.soland.feature.moderation.report".to_owned(),
            "org.arkret.soland.feature.mimi.provider_facade".to_owned(),
            "org.arkret.soland.feature.mimi.discovery".to_owned(),
            "org.arkret.soland.feature.mimi.key_material_receipt".to_owned(),
            "org.arkret.soland.feature.mimi.room_projection".to_owned(),
            "org.arkret.soland.feature.mimi.identifier_privacy".to_owned(),
            "org.arkret.soland.feature.mimi.proxy_download_policy".to_owned(),
            "org.arkret.soland.feature.registry.artifacts".to_owned(),
            "org.arkret.soland.feature.plaintext_visible_services".to_owned(),
            // realm-and-space.md history-sharing — advertise the three
            // `ak.realm_key.request` / `ak.realm_key.share` retrieval modes the
            // server relays history keys through: backup-derived retrieval,
            // device-to-device peer relay (the ephemeral `ak.realm_key.request`
            // accepted by `routing::events::sync::ephemeral`), and
            // archive retrieval.
            "ak.feature.realm_key.backup_retrieval.v1".to_owned(),
            "ak.feature.realm_key.peer_relay.v1".to_owned(),
            "ak.feature.realm_key.archive_retrieval.v1".to_owned(),
        ],
        supported_operations,
        // service-surface.md §3 documents `base_url` (typed `format: uri` in
        // service-describe.schema.json) as the connectable service base.
        // Emit the same public base URL used by the HTTP describe handler so
        // clients can build `base_url + operation_path` directly.
        supported_bindings: vec![
            arkret_models_discovery::service_description::SupportedBinding::new(
                arkret_wire::BindingKind::HttpJson,
            )
                .with_base_url(format!("{}/", public_base_url.trim_end_matches('/'))),
            // Per-operation HTTP companion binding (transport-bindings.md
            // §6.1): tus 1.0.0 resumable upload for ak.self.blob.upload.
            // Versions/extensions mirror the OPTIONS probe answers of
            // routing::interop::blob_resumable — describe and wire MUST
            // agree.
            arkret_models_discovery::service_description::SupportedBinding::new(
                arkret_wire::BindingKind::Tus,
            )
                .with_base_url(format!(
                    "{}/_arkret/self/blob/resumable",
                    public_base_url.trim_end_matches('/')
                ))
                .with_extra(
                    "operations",
                    serde_json::json!(["ak.self.blob.upload.create"]),
                )
                .with_extra("extension_profile_required", serde_json::Value::Null)
                .with_extra(
                    "tus_version",
                    serde_json::json!(crate::routing::TUS_VERSIONS),
                )
                .with_extra(
                    "tus_extensions",
                    serde_json::json!(crate::routing::TUS_EXTENSIONS),
                ),
        ],
        supported_reducer_profiles: SUPPORTED_REDUCER_PROFILES
            .iter()
            .map(|profile| (*profile).to_owned())
            .collect(),
        supported_schema_profiles: vec!["ak.schema.core.v1".to_owned()],
        auth_metadata,
        privacy_derivation: Some(crate::routing::push_target_privacy_derivation_claim(now())),
        receive_policy_constraints: None,
        limits: arkret_models_discovery::service_description::ServerLimits {
            extensions: serde_json::from_value(serde_json::json!({
            "storage": storage,
            "max_limit": 100,
            // Spec media-and-blob.md §2.1 limits keys for the resumable
            // (tus) upload binding.
            "resumable_upload_incomplete_ttl_seconds": resumable_upload_incomplete_ttl_seconds,
            "resumable_upload_max_bytes": crate::routing::MAX_BLOB_UPLOAD_BYTES,
            "registries": artifacts::registry_summary(),
            "plaintext_visible_service_capability": {
                "supported": true,
                "service_id": service_id,
                "enforced_on": [
                    "self.events.message_content",
                    "federation.push_operations",
                    "federation.transaction",
                    "blob.upload.attachment_plaintext",
                    "blob.upload.attachment_preview",
                    "blob.upload.thumbnail",
                    "blob.upload.full_text_index",
                    "push.notify.visible_notification",
                    "search.index.full_text_index"
                ],
                "requires_data_classes": true
            },
            "authz_policy": {
                "surface": "authz_policy",
                "tier": "extension",
                "self_surface_status": "standard_self_supported",
                "operation_registry_source": "arkret-spec/spec/v1/artifacts/registry/operation-registry.json",
                "error_mapping_source": "arkret-spec/spec/v1/artifacts/registry/operations-error-mapping.json",
                "universal_error_codes_inherited": true,
                "supported_operations": [
                    "ak.self.authz.read.check",
                    "ak.self.authz.grants.read.effective",
                    "ak.self.authz.invites.read.list",
                    "ak.self.policy.read.check"
                ],
                "authz_check": {
                    "operation_id": "ak.self.authz.read.check",
                    "method": "POST",
                    "path": "/_arkret/self/authz/check",
                    "request_shape": "AuthzCheckRequestBody",
                    "response_shape": "AuthzCheckOutcome",
                    "operation_specific_error_codes": ["policy_unavailable"],
                    "decision_source": "local_projection_preflight_diagnostic",
                    "signed_decision": false,
                    "emits_dynamic_obligations": false,
                    "usable_as_event_auth_context": false,
                    "explain_fields": [
                        "matched_grants",
                        "applied_constraints",
                        "policy_results",
                        "missing_proofs",
                        "reason_code"
                    ],
                    "policy_boundary": {
                        "dynamic_claim_or_approval": false,
                        "usable_as_policy_obligation_proof": false,
                        "cross_service_signed_authorization_fact": false,
                        "dynamic_or_auditable_decision_operation": "ak.self.policy.read.check",
                        "dynamic_or_auditable_decision_path": "/_arkret/self/policy/check"
                    }
                },
                "effective_grants": {
                    "operation_id": "ak.self.authz.grants.read.effective",
                    "method": "GET",
                    "path": "/_arkret/self/authz/effective-grants",
                    "query": ["realm_id", "subject", "at"],
                    "response_shape": "GrantList",
                    "subject_scope": "authenticated_actor_or_realm_owner_for_realm_scoped_queries",
                    "operation_specific_error_codes": []
                },
                "invites": {
                    "operation_id": "ak.self.authz.invites.read.list",
                    "method": "GET",
                    "path": "/_arkret/self/authz/invites",
                    "query": ["realm_id", "subject", "cursor"],
                    "response_schema_ref": "schemas/authz-operations.schema.json#/$defs/authz_invite_list",
                    "subject_scope": "authenticated_actor_or_inviter_or_realm_owner",
                    "operation_specific_error_codes": []
                },
                "policy_check": {
                    "operation_id": "ak.self.policy.read.check",
                    "method": "POST",
                    "path": "/_arkret/self/policy/check",
                    "operation_specific_error_codes": ["policy_unavailable", "policy_stale"],
                    "decision_source": "policy_server_signed_decision",
                    "signed_decision": true,
                    "emits_dynamic_obligations": true,
                    "binds_auth_state_digest": true,
                    "binds_policy_frontier_digest": true,
                    "binds_membership_frontier_digest": true
                }
            },
            "search": {
                "directory": {
                    "operation_prefix": "ak.find.directory.",
                    "resource_kinds": ["realm", "organization", "actor"],
                    "returns_message_hits": false,
                    "returns_snippets": false
                },
                "client_index": {
                    "profile": "ak.profile.search.client_index.v1",
                    "manifest_account_data_key": "ak.search.index_manifest.v1",
                    "manifest_storage": "encrypted_private_account_data",
                    "shard_blob_purpose": "search_index_shard",
                    "shard_storage": "encrypted_blob_bytes",
                    "returns_hits": false,
                    "returns_snippets": false,
                    "term_metadata": false
                },
                "realm_private_message_search": {
                    "plaintext_remote_search": false,
                    "directory_surface": "directory_only",
                    "requires_plaintext_visible_services_for_plaintext": true
                }
            },
            "personal_productivity": {
                "reminders": {
                    "profile": "ak.profile.personal_productivity.v1",
                    "account_data_key": "ak.reminders.v1",
                    "storage": "encrypted_private_account_data",
                    "plaintext_payload_accepted": false,
                    "server_action": "local_or_push_wake_only",
                    "wakeup_kind": "reminder",
                    "target_ref_visible_in_shared_event": false,
                    "note_visible_in_shared_event": false
                },
                "scheduled_send": {
                    "profile": "ak.profile.personal_productivity.v1",
                    "account_data_key": "ak.scheduled_send.v1",
                    "storage": "encrypted_private_account_data",
                    "plaintext_payload_accepted": false,
                    "server_dispatches_message_create": false,
                    "server_action": "holder_wake_sync_only",
                    "wakeup_kind": "scheduled_send",
                    "planned_message_id_anchor": "ak.message.create.payload.message_id",
                    "shared_history_materialization": "client_submitted_ak.message.create_only"
                },
                "snooze": {
                    "profile": "ak.profile.personal_productivity.v1",
                    "account_data_key": "ak.snooze.v1",
                    "storage": "encrypted_private_account_data",
                    "plaintext_payload_accepted": false,
                    "target_key": "holder_derived_unlinkable",
                    "private_projection_scope": "holder_only",
                    "shared_state_mutation": false,
                    "target_ref_visible_in_shared_event": false
                }
            },
            "scalability_constraints": {
                "source": "arkret-spec/spec/v1/zh/conformance/scalability-constraints.md",
                "max_event_bytes": MAX_EVENT_ENVELOPE_BYTES,
                "max_events_batch_submit": MAX_EVENT_SUBMIT_BATCH,
                "max_page_items": 100,
                "max_prev_refs": MAX_EVENT_PREV_REFS,
                "max_refs": MAX_EVENT_REFS,
                "max_auth_refs": MAX_AUTHORIZED_BY_REFS,
                "max_relation_expansion_depth": 32,
                "max_authority_depth": MAX_AUTHORITY_CHAIN_DEPTH,
                "max_grants_per_decision": 1024,
                "max_grant_constraints": 64,
                "max_resource_selector_depth": 16,
                "daily_principal_download_limit": config.key_backup_daily_download_limit,
                "max_to_device_page": 1000,
                "max_to_device_queue_per_device": to_device_queue_capacity
            },
            "profile_status": {
                "conformance": "limited_reference",
                "unsupported_profiles": [
                    {
                        "profile": "ak.profile.soland_limited_server.v1",
                        "status": "unsupported",
                        "reason": "limited profile is a limitation descriptor, not a conformance claim"
                    }
                ],
                "full_profiles_not_claimed": [
                    "ak.profile.principal_server.v1",
                    "ak.profile.directory_service.v1",
                    "ak.profile.identity_registry.v1",
                    "ak.profile.blob_node.v1"
                ],
                "principal_server_full_profile_gaps": full_principal_server_gap_summary(),
                "supported_operation_catalog": {
                    "source": "arkret-spec/spec/v1/artifacts/registry/operation-registry.json",
                    "derived_surface_groups": SUPPORTED_OPERATION_SURFACES,
                    "standalone_operations": SUPPORTED_STANDALONE_OPERATION_IDS
                },
                "local_extension_operations": local_extension_operations,
                "local_extension_operation_source": "compact_registry+served_openapi",
                "implemented_surfaces": [
                    "principal_server",
                    "events_api_minimal",
                    "sync",
                    "index",
                    "authz_policy",
                    "circle_management",
                    "identity_registry_local_dev",
                    "blob_node_local",
                    "directory_service",
                    "mimi_provider_facade"
                ],
                "limitations": profile_limitations(),
                "mimi_interop": {
                    "status": "provider_facade_first_round",
                    "drafts": {
                        "protocol": "draft-ietf-mimi-protocol-06",
                        "content": "draft-ietf-mimi-content-08",
                        "room_policy": "draft-ietf-mimi-room-policy-03",
                        "identifiers": "draft-kohbrok-mimi-identifiers-01"
                    },
                    "not_replaced": [
                        "arkret_signed_event_reducer",
                        "realm_id",
                        "did",
                        "hlc",
                        "capability",
                        "auth_refs",
                        "mls_state"
                    ],
                    "principal_conformance": "not_claimed"
                }
            }
            }))
            .expect("server limits must be a JSON object"),
        },
        frontier: Vec::new(),
        snapshot_frontier: Vec::new(),
        last_materialized_at: None,
        extensions: std::collections::BTreeMap::new(),
    };
    description
        .install_current_arkret_build_identity()
        .expect("current Arkret SDK build identity must serialize");
    description
}

pub fn now() -> DateTime<Utc> {
    Utc::now()
}

// ── Conversation Model DTOs ──

pub type ReadScopeWire = arkret_wire::primitives::ReadCursorScope;
pub type ReadCursorPositionWire =
    arkret_models_collaboration::objects::read_receipts::ReadCursorPosition;
pub type ReadMarkerOutcome = arkret_models_collaboration::objects::read_receipts::ReadMarkerOutcome;

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_service_resolution() -> arkret_models_identity::ResolutionCommitment {
        arkret_models_identity::ResolutionCommitment {
            full_id: arkret_wire::DidFullId::new("did:web:soland.example").unwrap(),
            method_history_head: "fixture-history-head".to_owned(),
            version_id: "fixture-v1".to_owned(),
        }
    }

    #[test]
    fn service_describe_advertises_realm_key_history_features() {
        let description = describe(
            &fixture_service_resolution(),
            "memory",
            &crate::config::AppConfig {
                public_base_url: "https://soland.example/".to_owned(),
                development_mode: true,
                ..crate::config::AppConfig::test_default()
            },
        );
        let value = serde_json::to_value(description).expect("description serializes");
        let features = value["supported_features"]
            .as_array()
            .expect("features array");
        for feature in [
            "ak.feature.realm_key.backup_retrieval.v1",
            "ak.feature.realm_key.peer_relay.v1",
            "ak.feature.realm_key.archive_retrieval.v1",
        ] {
            assert!(
                features.contains(&json!(feature)),
                "describe must advertise {feature}"
            );
        }
    }

    #[test]
    fn service_describe_supported_bindings_advertise_public_base_url() {
        let description = describe(
            &fixture_service_resolution(),
            "memory",
            &crate::config::AppConfig {
                public_base_url: "https://soland.example/".to_owned(),
                development_mode: true,
                ..crate::config::AppConfig::test_default()
            },
        );
        let value = serde_json::to_value(description).expect("description serializes");
        assert_eq!(
            value["supported_bindings"][0],
            json!({"kind": "http_json", "base_url": "https://soland.example/"})
        );
        assert!(value["supported_bindings"][0].get("base_path").is_none());
        // Spec media-and-blob.md §2.1 — the resumable upload binding is
        // discoverable via feature id + tus binding entry + limits keys.
        assert_eq!(
            value["supported_bindings"][1]["kind"],
            json!("tus"),
            "tus companion binding advertised"
        );
        assert_eq!(
            value["supported_bindings"][1]["base_url"],
            json!("https://soland.example/_arkret/self/blob/resumable")
        );
        assert_eq!(
            value["supported_bindings"][1]["operations"],
            json!(["ak.self.blob.upload.create"])
        );
        assert!(value["supported_bindings"][1]["extension_profile_required"].is_null());
        assert!(
            value["supported_features"]
                .as_array()
                .expect("features array")
                .contains(&json!("ak.feature.blob.resumable_upload.tus.v1"))
        );
        assert!(
            value["supported_features"]
                .as_array()
                .expect("features array")
                .contains(&json!(
                    "org.arkret.soland.feature.personal_productivity.scheduled_send_wake_only"
                ))
        );
        assert!(
            value["supported_features"]
                .as_array()
                .expect("features array")
                .contains(&json!(
                    "org.arkret.soland.feature.personal_productivity.reminder_snooze_private_wake"
                ))
        );
        assert!(
            value["supported_features"]
                .as_array()
                .expect("features array")
                .contains(&json!(
                    "org.arkret.soland.feature.policy.check_signed_decision"
                ))
        );
        assert!(
            value["supported_features"]
                .as_array()
                .expect("features array")
                .contains(&json!(
                    "org.arkret.soland.feature.push.target_id_hmac_rotation"
                ))
        );
        assert_eq!(
            value["privacy_derivation"]["push_target_id"]["derivation_profile"],
            json!("ak.push_target_id.hmac_sha256.v1")
        );
        assert_eq!(
            value["privacy_derivation"]["push_target_id"]["secret_scope"],
            json!("per_service")
        );
        assert_eq!(
            value["privacy_derivation"]["push_target_id"]["salt_rotation_seconds"],
            json!(30 * 24 * 60 * 60)
        );
        assert_eq!(
            value["privacy_derivation"]["push_target_id"]["input_binding"],
            json!([
                "recipient_service_id",
                "principal_id",
                "device_id",
                "push_route_id",
                "salt_epoch_id"
            ])
        );
        assert_eq!(
            value["limits"]["resumable_upload_incomplete_ttl_seconds"],
            json!(86_400)
        );
        assert_eq!(
            value["limits"]["resumable_upload_max_bytes"],
            json!(10 * 1024 * 1024)
        );
        assert_eq!(
            value["limits"]["scalability_constraints"]["max_event_bytes"],
            json!(arkret_wire::event_envelope::MAX_EVENT_ENVELOPE_BYTES)
        );
        assert_eq!(
            value["limits"]["scalability_constraints"]["max_events_batch_submit"],
            json!(arkret_wire::event_envelope::MAX_EVENT_SUBMIT_BATCH)
        );
        assert_eq!(
            value["limits"]["scalability_constraints"]["max_prev_refs"],
            json!(arkret_wire::event_envelope::MAX_EVENT_PREV_REFS)
        );
        assert_eq!(
            value["limits"]["scalability_constraints"]["max_refs"],
            json!(arkret_wire::event_envelope::MAX_EVENT_REFS)
        );
        assert_eq!(
            value["limits"]["search"]["directory"]["returns_message_hits"],
            json!(false)
        );
        assert_eq!(
            value["limits"]["search"]["client_index"]["manifest_storage"],
            json!("encrypted_private_account_data")
        );
        assert_eq!(
            value["limits"]["search"]["client_index"]["shard_blob_purpose"],
            json!("search_index_shard")
        );
        assert_eq!(
            value["limits"]["search"]["realm_private_message_search"]["plaintext_remote_search"],
            json!(false)
        );
        assert_eq!(
            value["limits"]["authz_policy"]["self_surface_status"],
            json!("standard_self_supported")
        );
        assert_eq!(
            value["limits"]["authz_policy"]["supported_operations"],
            json!([
                "ak.self.authz.read.check",
                "ak.self.authz.grants.read.effective",
                "ak.self.authz.invites.read.list",
                "ak.self.policy.read.check"
            ])
        );
        assert_eq!(
            value["limits"]["authz_policy"]["authz_check"]["decision_source"],
            json!("local_projection_preflight_diagnostic")
        );
        assert_eq!(
            value["limits"]["authz_policy"]["authz_check"]["path"],
            json!("/_arkret/self/authz/check")
        );
        assert_eq!(
            value["limits"]["authz_policy"]["authz_check"]["operation_specific_error_codes"],
            json!(["policy_unavailable"])
        );
        assert_eq!(
            value["limits"]["authz_policy"]["authz_check"]["signed_decision"],
            json!(false)
        );
        assert_eq!(
            value["limits"]["authz_policy"]["authz_check"]["emits_dynamic_obligations"],
            json!(false)
        );
        assert_eq!(
            value["limits"]["authz_policy"]["authz_check"]["policy_boundary"]["dynamic_or_auditable_decision_path"],
            json!("/_arkret/self/policy/check")
        );
        assert_eq!(
            value["limits"]["authz_policy"]["effective_grants"]["path"],
            json!("/_arkret/self/authz/effective-grants")
        );
        assert_eq!(
            value["limits"]["authz_policy"]["effective_grants"]["subject_scope"],
            json!("authenticated_actor_or_realm_owner_for_realm_scoped_queries")
        );
        assert_eq!(
            value["limits"]["authz_policy"]["invites"]["path"],
            json!("/_arkret/self/authz/invites")
        );
        assert_eq!(
            value["limits"]["authz_policy"]["invites"]["response_schema_ref"],
            json!("schemas/authz-operations.schema.json#/$defs/authz_invite_list")
        );
        assert_eq!(
            value["limits"]["authz_policy"]["policy_check"]["decision_source"],
            json!("policy_server_signed_decision")
        );
        assert_eq!(
            value["limits"]["authz_policy"]["policy_check"]["operation_specific_error_codes"],
            json!(["policy_unavailable", "policy_stale"])
        );
        assert_eq!(
            value["limits"]["authz_policy"]["policy_check"]["signed_decision"],
            json!(true)
        );
        assert_eq!(
            value["limits"]["authz_policy"]["policy_check"]["emits_dynamic_obligations"],
            json!(true)
        );
        assert_eq!(
            value["limits"]["personal_productivity"]["reminders"]["storage"],
            json!("encrypted_private_account_data")
        );
        assert_eq!(
            value["limits"]["personal_productivity"]["reminders"]["wakeup_kind"],
            json!("reminder")
        );
        assert_eq!(
            value["limits"]["personal_productivity"]["reminders"]["target_ref_visible_in_shared_event"],
            json!(false)
        );
        assert_eq!(
            value["limits"]["personal_productivity"]["reminders"]["note_visible_in_shared_event"],
            json!(false)
        );
        assert_eq!(
            value["limits"]["personal_productivity"]["scheduled_send"]["storage"],
            json!("encrypted_private_account_data")
        );
        assert_eq!(
            value["limits"]["personal_productivity"]["scheduled_send"]["server_dispatches_message_create"],
            json!(false)
        );
        assert_eq!(
            value["limits"]["personal_productivity"]["scheduled_send"]["server_action"],
            json!("holder_wake_sync_only")
        );
        assert_eq!(
            value["limits"]["personal_productivity"]["scheduled_send"]["wakeup_kind"],
            json!("scheduled_send")
        );
        assert_eq!(
            value["limits"]["personal_productivity"]["snooze"]["storage"],
            json!("encrypted_private_account_data")
        );
        assert_eq!(
            value["limits"]["personal_productivity"]["snooze"]["target_key"],
            json!("holder_derived_unlinkable")
        );
        assert_eq!(
            value["limits"]["personal_productivity"]["snooze"]["shared_state_mutation"],
            json!(false)
        );
        assert_eq!(
            value["limits"]["scalability_constraints"]["max_to_device_queue_per_device"],
            json!(10_000)
        );
        assert_eq!(
            value["limits"]["scalability_constraints"]["daily_principal_download_limit"],
            json!(soland_services::runtime_guards::KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_DEFAULT)
        );
    }
}
