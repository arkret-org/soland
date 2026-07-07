use chrono::{DateTime, Utc};
pub use cokret_sdk::ops_api::HardeningStatus;
use cokret_sdk::{
    AccountAuthority, AuthGrantExchange, AuthMetadata, AuthMethod, AuthMethodKind,
    ClaimedProfileEntry, MAX_AUTHORIZED_BY_REFS, MAX_DELEGATION_CHAIN_DEPTH,
    MAX_EVENT_ENVELOPE_BYTES, MAX_EVENT_PREV_REFS, MAX_EVENT_REFS, MAX_EVENT_SUBMIT_BATCH,
    ServerDescription, SessionGrantProofKind,
};
pub use cokret_sdk::{
    AuthorizedDeviceSigningKey, ContactListRow, ContactState, DeviceMessageEnvelope,
    DeviceMessageTarget, DeviceMessagesAckOutcome, DeviceMessagesAckRequestBody,
    DeviceMessagesGetOutcome, DeviceMessagesSendOutcome, DeviceMessagesSendRequestBody,
    DeviceSigningKeyDirectoryOutcome, DeviceSigningKeyDirectoryQueryRequestBody, DeviceStatus,
    DirectConversationBindingState, DirectConversationSummary, EventsQueryPostRequestBody,
    IdentityResolveRequestBody, KeysClaimOutcome, KeysClaimRequestBody, KeysQueryOutcome,
    KeysQueryRequestBody, KeysUploadOutcome, KeysUploadRequestBody, OkOutcome, PushNotifyOutcome,
    PushNotifyRequestBody, QueryDeviceRecord, RealmJoinCandidate, RealmJoinCandidateRole,
    RealmJoinCandidateServiceType, RealmJoinCandidateSource, RealmJoinMethod,
    SessionGrantIntrospectGrant, SessionGrantIntrospectOutcome, SessionGrantIntrospectRequestBody,
    SessionGrantIntrospectStatus, SessionGrantIntrospectionProof, SessionLoginOutcome,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::artifacts;

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct HealthOutcome {
    pub ok: bool,
    pub service: &'static str,
    pub storage: &'static str,
    pub checks: Value,
    /// True when soland is running with `SOLAND_DEVELOPMENT_MODE=true`.
    /// Surfaced here so operators / dashboards (e.g. sodmin) can flag the
    /// deployment with a "DEVELOPMENT MODE — do not use in production"
    /// banner without having to scrape `/_cokret/describe`.
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

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SolandServerDescribeOutcome {
    #[serde(flatten)]
    pub service: ServerDescription,
    pub unsupported_profiles: Vec<UnsupportedProfileDescriptor>,
    pub proof_verifier_mode: String,
    pub admin_auth_mode: String,
    pub erasure_receipts_endpoint: String,
    pub hardening: HardeningStatus,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
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

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
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

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct AuthBridgeAuthDescriptor {
    pub dev_login_path: String,
    pub session_grant_issuance_path: String,
    pub session_grant_presentation: String,
    pub principal_id_body_field: String,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct AuthBridgePushDescriptor {
    pub register_device_path: String,
    pub unregister_device_path: String,
    pub session_grant_header: String,
    pub principal_id_body_field: String,
    pub register_device_mode: String,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
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
    pub origin_service_did_header: String,
    pub destination_service_did_header: String,
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
pub use cokret_sdk::integration_api::{
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
    pub fetched_at: DateTime<Utc>,
    pub remote_contract: Value,
    /// C33.1: trust state for the cached snapshot (`pending` / `trusted` /
    /// `revoked`). Imported snapshots default to `pending` if omitted.
    #[serde(default = "default_trust_pending")]
    pub trust_level: String,
    /// Last freshness check timestamp, distinct from `fetched_at`.
    #[serde(default)]
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
    pub expected_origin_service_did_header: String,
    pub expected_destination_service_did_header: String,
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
    /// `push_bridge_trusted_service_dids` allowlist.
    #[serde(default)]
    pub service_did: String,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct OutboundPushBridgeFetchOutcome {
    pub push_gateway_url: String,
    pub service_base_url: String,
    pub bridge_describe_url: String,
    pub fetch_state: String,
    pub cache_state: String,
    pub contract_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetched_at: Option<DateTime<Utc>>,
    pub fetched_contract: OutboundPushResolvedContract,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_contract: Option<Value>,
    /// C33.1: trust state of the cached snapshot returned by the fetch path.
    #[serde(default = "default_trust_pending")]
    pub trust_level: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    pub fetched_at: DateTime<Utc>,
    pub fetched_contract: OutboundPushResolvedContract,
    /// C33.1: trust state surfaced to status callers so dashboards can flag
    /// `pending` / `revoked` snapshots without round-tripping the export API.
    pub trust_level: String,
    pub freshness_at: DateTime<Utc>,
    pub etag: String,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct OutboundPushBridgeCacheInvalidateOutcome {
    pub removed_count: usize,
    pub remaining_entries: usize,
    pub cache_state: String,
}

// client-sync family DTOs come straight from the SDK (`SyncDescription`
// answers `account/describe`, `SyncRequestBody` carries the subscribe/sync
// request); both derive ToSchema under the `salvo` feature, so soland keeps
// no private copies that could drift. NOTE: the explicit `model::` path
// matters — the SDK root re-exports a different, client-side typed
// `sync::SyncRequestBody` under the same name.
pub use cokret_sdk::SyncRequestBody;
pub use cokret_sdk::models::SyncDescription;

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IndexDescribeOutcome {
    pub service_did: String,
    pub reducer_profiles: Vec<String>,
    pub schema_profiles: Vec<String>,
    pub query_features: Vec<String>,
    pub frontier: Value,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct IndexSearchRequestBody {
    pub query: String,
    #[serde(default)]
    pub realm_ids: Vec<String>,
    /// Filter by typed-id kinds drawn from the spec id-kind-registry. Replaces
    /// the round-5 `entity_types[]` alias.
    #[serde(default)]
    pub object_kinds: Vec<String>,
    #[serde(default)]
    pub facets: Vec<String>,
    pub renderer: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IndexSearchOutcome {
    pub results: Vec<Value>,
    pub next_cursor: Option<String>,
    pub frontier: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IndexThreadOutcome {
    pub thread: Value,
    pub events: Vec<Value>,
    pub next_cursor: Option<String>,
    pub frontier: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IndexNotificationsOutcome {
    pub notifications: Vec<Value>,
    pub next_cursor: Option<String>,
    pub unread_count: usize,
    pub frontier: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IndexInboxOutcome {
    pub strands: Vec<Value>,
    pub next_cursor: Option<String>,
    pub frontier: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IndexSpaceHierarchyOutcome {
    pub root_space_id: String,
    pub spaces: Vec<Value>,
    pub edges: Vec<Value>,
    pub frontier: Value,
}

// Snapshot head operations return the full signed `ck.schema.snapshot.v1`
// manifest. soland answers both operations with `not_implemented` until it can
// produce a real Snapshot detached proof.

// authz check DTOs are now the spec-authoritative SDK types. The SDK
// `AuthzDecision` enum was aligned to the spec five-valued form
// (allow / soft_deny / hard_deny / quarantine / require_review) and
// `AuthzCheckRequestBody` to `{ actor_id, action, resource?, context? }`,
// so soland re-uses them directly instead of carrying local copies.
pub use cokret_sdk::models::{
    AuthzCheckOutcome, AuthzCheckRequestBody, PushRegisterDeviceRequestBody,
    PushUnregisterDeviceRequestBody,
};

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct PushRulesOutcome {
    pub rules: Vec<Value>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct UpsertPushRuleOutcome {
    pub ok: bool,
    pub rule: Value,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct UpsertPushRuleRequestBody {
    pub rule_id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default)]
    pub conditions: Value,
}

// Moderation report request/outcome are the SDK DTOs (`model/api.rs` carries
// `service-operation-dtos.schema.json#/$defs/ModerationReportOutcome`:
// `status` enum `submitted|resolved`, `routed_to` is an array of bare DIDs);
// no soland mirrors.
pub use cokret_sdk::models::{ModerationReportOutcome, ModerationReportRequestBody};

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct UpsertPolicyDocumentRequestBody {
    #[serde(default)]
    pub policy_id: Option<String>,
    pub scope: String,
    pub subject_ref: String,
    pub policy_type: String,
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

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct PolicyDocumentOutcome {
    pub policy_id: String,
    pub owner: String,
    pub scope: String,
    pub subject_ref: String,
    pub policy_type: String,
    pub payload: Value,
    pub active: bool,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct PolicyDocumentsOutcome {
    pub policies: Vec<PolicyDocumentOutcome>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct DevLoginRequestBody {
    pub actor: String,
    pub device_id: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct LogoutOutcome {
    pub ok: bool,
    pub revoked: bool,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SolandAccountRegisterOutcome {
    pub did: String,
    pub handle: String,
    pub display_name: Option<String>,
    pub state: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SendMessageRequestBody {
    pub realm_id: String,
    /// Message-layer discussion grouping inside the projected Strand; this is
    /// not the Strand object's `strand_id`.
    #[serde(default)]
    pub thread_id: Option<String>,
    pub content: Value,
    #[serde(default)]
    pub encrypted: bool,
}

// Identity log / receipts outcomes are the SDK DTOs (`model/api.rs` is the
// authoritative carrier for identity operation shapes); no soland mirrors.
// CKP-0008 / CKP-0009 — Personal Agent operations. Every request/response
// DTO is the SDK-authoritative `cokret_sdk::models::Agent*` shape (spec
// `agent-operations.schema.json`): `agent_view`/`agent_list` carry the spec
// `agent_projection`; `agent_key_pair`/`rotate_key` outcomes are
// `{ok, authorized_event_ref}`; grant attach/detach outcomes are
// `{ok, grant_id}` / `{ok, revoked_at}`; sidecar ensure carries the typed
// `private_circle_id`/`private_strand_id`/`private_relation_id`. The lifecycle
// outcome (`agent_lifecycle_state` = `operation_status_outcome` =
// `{ok: true, status}`) has no struct mirror in the SDK and is emitted as a
// spec-exact JSON object by the agents handler. `AgentProvisionRequestBody` /
// `AgentProvisionOutcome` were already SDK-backed.
// ── CKP-0010 (R3 spec-sync 2026-05-27, cokret-spec b47ff6ec) — media
// token exchange wire shapes. Both the request body and the response types
// come straight from the SDK (`CallMediaTokenExchangeRequestBody` carries
// typed ids `realm_id`/`call_id`/`actor_id`/`device_id` plus the optional
// `capability_refs`/`desired_media` inputs; `CallMediaTokenExchangeOutcome`
// / `CallMediaParticipantBinding` derive ToSchema under the `salvo` feature),
// so soland no longer mints private mirrors that can drift from the spec DTOs.
pub use cokret_sdk::models::{
    AgentDeactivateRequestBody, AgentGrantAttachOutcome, AgentGrantAttachRequestBody,
    AgentGrantDetachOutcome, AgentKeyPairOutcome, AgentKeyPairRequestBody, AgentList,
    AgentPauseRequestBody, AgentResumeRequestBody, AgentRotateKeyOutcome,
    AgentRotateKeyRequestBody, AgentSidecarThreadEnsureOutcome,
    AgentSidecarThreadEnsureRequestBody, AgentView, CallMediaTokenExchangeRequestBody,
};
// Key-backup replace/delete outcomes are the SDK server-side DTOs
// (`cokret_sdk::models` is the authoritative carrier for
// `keys-operations.schema.json#/$defs/keys_backups_replace_outcome` /
// `keys_backups_delete_outcome`); no soland mirrors.
pub use cokret_sdk::models::{
    KeyBackupPutStatus, KeysBackupsDeleteOutcome, KeysBackupsList, KeysBackupsReplaceOutcome,
};
pub use cokret_sdk::{
    CallMediaParticipantBinding, CallMediaServiceSignature, CallMediaTokenExchangeOutcome,
    IdentityLogListOutcome, IdentityReceiptListOutcome, KeysBackupsPutRequestBody,
};

// Recovery policy / receipt endpoints validate against the spec REC-1 shapes in
// `routing::identity::recovery`: policy publish uses the SDK request body,
// while receipt write keeps a signed JSON wrapper so the raw signed fields can
// be verified before being projected into typed outcomes. The SDK carries the
// authoritative typed forms (`cokret_sdk::models::{RecoveryPolicy,
// RecoveryReceipt}`) for clients; no soland-private mirror exists.

const SUPPORTED_OPERATION_SURFACES: &[&str] = &[
    "service_discovery",
    "events_sync",
    "device_and_keys",
    "realtime_media",
    "authz_policy",
    "moderation_reports",
    "projection_lifecycle",
    "circle_management",
    "push",
    "mimi_interop",
    "invite_locator_handoff",
    "agent_runtime",
];

const SUPPORTED_STANDALONE_OPERATION_IDS: &[&str] = &[
    "ck.find.directory.query.describe",
    "ck.find.directory.query.search_realms",
    "ck.find.directory.query.resolve_realm",
    "ck.find.directory.query.resolve_target",
    "ck.find.directory.query.resolve_agent_selector",
    "ck.find.directory.query.list_handles_for_subject",
    "ck.self.blob.upload.create",
    "ck.self.blob.resource.head",
    "ck.self.blob.resource.get",
    "ck.self.keys.backups.resource.replace",
    "ck.self.keys.backups.query.list",
    "ck.self.keys.backups.command.unlock",
    "ck.self.keys.backups.resource.delete",
    "ck.peer.invites.command.submit",
    "ck.open.invite_locator.query.resolve",
];

/// Spec operations soland deliberately does NOT declare even though their
/// surface group is otherwise supported.
const UNDECLARED_OPERATION_IDS: &[&str] = &[];

fn canonical_supported_operations() -> Vec<String> {
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
            "reason": "standard /_cokret/self/authz/check, effective-grants, and invites are advertised and SDK-backed; deeper selector, constraint, delegation, and policy lifecycle semantics are tracked by dedicated AUTHZ audit items"
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
            "reason": "ck.self.snapshot.query.manifest_head returns a signed ck.schema.snapshot.v1 manifest; the /_soland dev bundle remains a product-face compatibility surface"
        }),
        json!({
            "area": "account_auth.device_pair",
            "status": "standard_gate_supported",
            "spec_operation": "ck.gate.account.command.pair_device",
            "canonical_path": "/_cokret/gate/account/device-pair",
            "reason": "ck.gate.account.command.pair_device is served on the spec path for existing-device-authorized sibling registration. The old soland-local device pairing scaffold and approval family are removed; v1 core does not define a self/devices pairing-requests approval surface (service-http-binding.md §85, key-management.md §384, device-lifecycle.md §499). ck.gate.account.exchange.complete_oidc is delegated to the bridges deployment and not served here."
        }),
        json!({
            "area": "federation.private_inbound_rail",
            "status": "deployment_local_only",
            "canonical_inbound": "/_cokret/peer/events",
            "private_paths": [
                "/_soland/peer/federation/*",
                "/_soland/peer/moves",
                "/_soland/peer/seals"
            ],
            "reason": "SPEC-CR-008 / federation.md §4.0 — the converged cross-deployment federation Event receive rail is the single protocol track POST /_cokret/peer/events (ck.peer.events.command.submit), which carries DataEvents and Control Moves (incl. Move/Anchor/Seal-bearing control events) as sealed Event Envelopes and is RFC 9421 service-signature gated. The /_soland/peer/* inbound *write* surface (transactions, operations push/backfill, moves/seals direct ingest) is fail-closed outside development_mode and is a deployment-local test/ops affordance only: it is not discoverable through describe/OpenAPI for remote peers and MUST NOT be relied on for cross-vendor interop. The read-only debug tracks (operations pull/frontier, realm-members, actor-events, seals pull) expose no interop write surface"
        }),
        json!({
            "area": "consent.scope_any_cross_service_cascade",
            "status": "partial_local_only",
            "spec": "T17",
            "implemented": "a holder `ck.consent.revoke` with scope=any is honored on read: every child-scope grant resolution folds the `any` cell (see has_active_consent / has_active_consent_grant_evidence), so an any-revoke withdraws all child scopes for local consent decisions",
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
            "status": "emit_shape_only_unwired",
            "spec": "B1.9 / federation.md service-binding handover",
            "implemented": "the 409 emit shapes for `delivery_binding_stale` and `delivery_binding_handed_over` are defined as reference contracts",
            "unsupported": "the protocol receive track does not yet detect a stale/handed-over delivery binding and therefore never emits these 409s; doing so requires the B1.7/B1.8 service-binding handover state machine (current recipient tracking + handover frontier) which is not implemented",
            "reason": "delivery-binding handover detection needs binding-state tracking soland does not maintain"
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
        "profile": "ck.profile.principal_server.v1",
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

#[allow(clippy::too_many_arguments)] // mirrors AppConfig fields; callers pass them positionally once
pub fn describe(
    service_did: &str,
    public_base_url: &str,
    storage: &'static str,
    development_mode: bool,
    account_authority_url: Option<&str>,
    oidc_client_id: Option<&str>,
    trust_domain: &str,
    resumable_upload_incomplete_ttl_seconds: u64,
    to_device_queue_capacity: usize,
) -> ServerDescription {
    // Account Authority discovery (service-surface §2.5.1): the client-visible
    // owner of the auth-side `/_cokret/gate/account/*` ops the client posts to
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
    let gate_account_base = format!("{account_origin}/_cokret/gate/account");

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
        extra: std::collections::BTreeMap::new(),
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
    // and pass `ServerDescription::validate`.
    // Round 4 — typed entries match `service-describe.schema.json`
    // (`claimed_profiles[*]`, `compat_surfaces[*]`). The routing-layer
    // `apply_claim_level_partition` populates these SDK-typed fields
    // before the response is serialized so the JSON wire shape and the
    // typed surface can never drift.
    //
    // Profile catalogue per `cokret-spec/spec/v1/zh/conformance/conformance-profiles.md`
    // §1 / §7 / §8: a principal server self-claims the Event Store
    // interop floor AND the Principal Server + Principal Server Events
    // API stable-catalog profiles in addition to whatever interop
    // staging extensions it implements (MIMI here).
    let claimed_profiles = vec![
        ClaimedProfileEntry::self_claimed("ck.profile.core_event_store.v1"),
        ClaimedProfileEntry::self_claimed("ck.profile.principal_server.v1"),
        ClaimedProfileEntry::self_claimed("ck.profile.principal_server_events_api.v1"),
        ClaimedProfileEntry {
            notes: Some(
                "MIMI provider facade first round (not a full v1 core conformance claim)"
                    .to_owned(),
            ),
            ..ClaimedProfileEntry::self_claimed("ck.profile.mimi_interop.v1")
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
    let plaintext_visibility = cokret_sdk::PlaintextVisibility {
        data_classes: vec![
            cokret_sdk::PlaintextDataClassKind::MessageContent,
            cokret_sdk::PlaintextDataClassKind::AttachmentPlaintext,
            cokret_sdk::PlaintextDataClassKind::AttachmentPreview,
            cokret_sdk::PlaintextDataClassKind::Thumbnail,
            cokret_sdk::PlaintextDataClassKind::FullTextIndex,
            cokret_sdk::PlaintextDataClassKind::NotificationSummary,
            cokret_sdk::PlaintextDataClassKind::MediaPlaintext,
        ],
        max_visibility: Some(cokret_sdk::PlaintextMaxVisibility::PrivatePlaintext),
        event_kinds: vec![
            "ck.message.create".to_owned(),
            "ck.realm.policy_components".to_owned(),
            "ck.realm.plaintext_visible_services".to_owned(),
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
        extra: std::collections::BTreeMap::new(),
    };

    ServerDescription {
        service_did: service_did.parse().expect("valid service DID"),
        trust_domain: trust_domain
            .parse()
            .expect("trust_domain must be ck:trust_domain:<scope>"),
        service_type: "principal_server".to_owned(),
        protocol_version: cokret_sdk::PROTOCOL_VERSION.to_owned(),
        supported_profiles: {
            let mut profiles = vec![
                "ck.profile.core_event_store.v1".to_owned(),
                "ck.profile.principal_server.v1".to_owned(),
                "ck.profile.principal_server_events_api.v1".to_owned(),
                "ck.profile.mimi_interop.v1".to_owned(),
                "ck.profile.file_transfer.v1".to_owned(),
                "ck.profile.webrtc_media.v1".to_owned(),
            ];
            // PROF-1 (R3 spec-sync 2026-05-27, cokret-spec b47ff6ec) —
            // advertise `ck.profile.media_service_binding.v1` whenever the
            // server exposes the `ck.self.call.media.exchange.issue_token`
            // handler. soland mounts the handler unconditionally, and also
            // claims the required `ck.profile.webrtc_media.v1` dependency above.
            profiles.push("ck.profile.media_service_binding.v1".to_owned());
            // PROF-1 — `ck.profile.accountable_principals.strict_reject.v1` is
            // gated by `SOLAND_ACCOUNTABLE_TO_STRICT_REJECT=true`.
            if matches!(
                std::env::var("SOLAND_ACCOUNTABLE_TO_STRICT_REJECT").as_deref(),
                Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes")
            ) {
                profiles.push("ck.profile.accountable_principals.strict_reject.v1".to_owned());
            }
            profiles
        },
        plaintext_visibility,
        implemented_features: implemented_features_seed,
        claimed_profiles,
        verified_profiles,
        experimental_features,
        compat_surfaces,
        development_mode,
        // service-describe.schema.json requires `rate_limit_policy` or
        // `rate_limit_policy_id` (the legacy top-level `rate_limit` field was
        // removed). Derive the advertised per-class policy from the SAME runtime
        // config the middleware enforces (`crate::ratelimit`) so wire and
        // enforcement can never drift — a conformant client budgeting against
        // this policy cannot trip a 429 it could not predict.
        rate_limit_policy: Some(
            crate::ratelimit::RateLimiterConfig::from_env(development_mode).advertised_policy(),
        ),
        rate_limit_policy_id: None,
        egress_network_policy: Some(cokret_sdk::EgressNetworkPolicy::deny_private_defaults()),
        resource_types: Vec::new(),
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
            "org.cokret.soland.feature.auth.logout".to_owned(),
            "org.cokret.soland.feature.contacts.request".to_owned(),
            "org.cokret.soland.feature.contacts.respond".to_owned(),
            "org.cokret.soland.feature.space.lifecycle".to_owned(),
            "org.cokret.soland.feature.schema.registry".to_owned(),
            "org.cokret.soland.feature.events.describe".to_owned(),
            "org.cokret.soland.feature.events.submit".to_owned(),
            "org.cokret.soland.feature.events.read".to_owned(),
            "org.cokret.soland.feature.federation.transaction".to_owned(),
            "org.cokret.soland.feature.federation.operations".to_owned(),
            "org.cokret.soland.feature.sync.client_sync".to_owned(),
            "org.cokret.soland.feature.sync.bound_cursor".to_owned(),
            "org.cokret.soland.feature.sync.incremental_since".to_owned(),
            "org.cokret.soland.feature.sync.typing".to_owned(),
            "org.cokret.soland.feature.personal_productivity.scheduled_send_wake_only".to_owned(),
            "org.cokret.soland.feature.personal_productivity.reminder_snooze_private_wake"
                .to_owned(),
            "org.cokret.soland.feature.directory.search_realms".to_owned(),
            "org.cokret.soland.feature.directory.resolve_realm".to_owned(),
            "org.cokret.soland.feature.authz.check".to_owned(),
            "org.cokret.soland.feature.authz.effective_grants".to_owned(),
            "org.cokret.soland.feature.authz.invites".to_owned(),
            "org.cokret.soland.feature.policy.check_signed_decision".to_owned(),
            "org.cokret.soland.feature.profile.presence".to_owned(),
            "org.cokret.soland.feature.push.register_device".to_owned(),
            "org.cokret.soland.feature.push.target_id_hmac_rotation".to_owned(),
            "org.cokret.soland.feature.push.rules".to_owned(),
            "org.cokret.soland.feature.blob.upload".to_owned(),
            // Spec crypto-media/media-and-blob.md §2.1 — protocol-level
            // feature id for the resumable (tus) upload companion binding
            // of ck.self.blob.upload. Pairs with the `kind="tus"` entry in
            // supported_bindings below.
            "ck.feature.blob.resumable_upload.tus.v1".to_owned(),
            "ck.feature.mls_last_resort_keypackage.v1".to_owned(),
            // encryption-and-audit.md §2.10.7 — advertise support for the
            // history-shareable `mls-exporter-aead-v1` content scheme so clients
            // know late-joiner pre-join history decryption is reachable here.
            "ck.feature.mls_exporter_aead.v1".to_owned(),
            "org.cokret.soland.feature.blob.authenticated_download".to_owned(),
            "org.cokret.soland.feature.file_transfer".to_owned(),
            "org.cokret.soland.feature.blob.presigned_download.local_direct_serve".to_owned(),
            "org.cokret.soland.feature.blob.upload_policy".to_owned(),
            "org.cokret.soland.feature.federation.transaction_idempotency".to_owned(),
            "org.cokret.soland.feature.policy.documents".to_owned(),
            "org.cokret.soland.feature.moderation.report".to_owned(),
            "org.cokret.soland.feature.mimi.provider_facade".to_owned(),
            "org.cokret.soland.feature.mimi.discovery".to_owned(),
            "org.cokret.soland.feature.mimi.key_material_receipt".to_owned(),
            "org.cokret.soland.feature.mimi.room_projection".to_owned(),
            "org.cokret.soland.feature.mimi.identifier_privacy".to_owned(),
            "org.cokret.soland.feature.mimi.proxy_download_policy".to_owned(),
            "org.cokret.soland.feature.registry.artifacts".to_owned(),
            "org.cokret.soland.feature.plaintext_visible_services".to_owned(),
            // realm-and-space.md history-sharing — advertise the three
            // `ck.realm_key.request` / `ck.realm_key.share` retrieval modes the
            // server relays history keys through: backup-derived retrieval,
            // device-to-device peer relay (the ephemeral `ck.realm_key.request`
            // relay implemented in `routing::events::realm_key_request`), and
            // archive retrieval.
            "ck.feature.realm_key.backup_retrieval.v1".to_owned(),
            "ck.feature.realm_key.peer_relay.v1".to_owned(),
            "ck.feature.realm_key.archive_retrieval.v1".to_owned(),
        ],
        supported_operations,
        // service-surface.md §3 documents `base_url` (typed `format: uri` in
        // service-describe.schema.json) as the connectable service base.
        // Emit the same public base URL used by the HTTP describe handler so
        // clients can build `base_url + operation_path` directly.
        supported_bindings: vec![
            cokret_sdk::SupportedBinding::new("http_json")
                .with_base_url(public_base_url.trim_end_matches('/')),
            // Per-operation HTTP companion binding (transport-bindings.md
            // §6.1): tus 1.0.0 resumable upload for ck.self.blob.upload.
            // Versions/extensions mirror the OPTIONS probe answers of
            // routing::interop::blob_resumable — describe and wire MUST
            // agree.
            cokret_sdk::SupportedBinding::new("tus")
                .with_base_url(format!(
                    "{}/_cokret/self/blob/resumable",
                    public_base_url.trim_end_matches('/')
                ))
                .with_extra(
                    "operations",
                    serde_json::json!(["ck.self.blob.upload.create"]),
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
        supported_reducer_profiles: vec!["ck.reducer.v1".to_owned()],
        supported_schema_profiles: vec!["ck.schema.core.v1".to_owned()],
        auth_metadata,
        privacy_derivation: Some(crate::routing::push_target_privacy_derivation_claim(now())),
        receive_policy_constraints: None,
        limits: serde_json::json!({
            "storage": storage,
            "max_limit": 100,
            // Spec media-and-blob.md §2.1 limits keys for the resumable
            // (tus) upload binding.
            "resumable_upload_incomplete_ttl_seconds": resumable_upload_incomplete_ttl_seconds,
            "resumable_upload_max_bytes": crate::routing::MAX_BLOB_UPLOAD_BYTES,
            "registries": artifacts::registry_summary(),
            "plaintext_visible_service_capability": {
                "supported": true,
                "service_did": service_did,
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
                "operation_registry_source": "cokret-spec/spec/v1/artifacts/registry/operation-registry.json",
                "error_mapping_source": "cokret-spec/spec/v1/artifacts/registry/operations-error-mapping.json",
                "universal_error_codes_inherited": true,
                "supported_operations": [
                    "ck.self.authz.query.check",
                    "ck.self.authz.grants.query.effective",
                    "ck.self.authz.invites.query.list",
                    "ck.self.policy.query.check"
                ],
                "authz_check": {
                    "operation_id": "ck.self.authz.query.check",
                    "method": "POST",
                    "path": "/_cokret/self/authz/check",
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
                        "dynamic_or_auditable_decision_operation": "ck.self.policy.query.check",
                        "dynamic_or_auditable_decision_path": "/_cokret/self/policy/check"
                    }
                },
                "effective_grants": {
                    "operation_id": "ck.self.authz.grants.query.effective",
                    "method": "GET",
                    "path": "/_cokret/self/authz/effective-grants",
                    "query": ["realm_id", "subject", "at"],
                    "response_shape": "GrantList",
                    "subject_scope": "authenticated_actor_or_realm_owner_for_realm_scoped_queries",
                    "operation_specific_error_codes": []
                },
                "invites": {
                    "operation_id": "ck.self.authz.invites.query.list",
                    "method": "GET",
                    "path": "/_cokret/self/authz/invites",
                    "query": ["realm_id", "subject", "cursor"],
                    "response_schema_ref": "schemas/authz-operations.schema.json#/$defs/authz_invite_list",
                    "subject_scope": "authenticated_actor_or_inviter_or_realm_owner",
                    "operation_specific_error_codes": []
                },
                "policy_check": {
                    "operation_id": "ck.self.policy.query.check",
                    "method": "POST",
                    "path": "/_cokret/self/policy/check",
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
                    "operation_prefix": "ck.find.directory.",
                    "resource_types": ["realm", "organization", "actor"],
                    "returns_message_hits": false,
                    "returns_snippets": false
                },
                "client_index": {
                    "profile": "ck.profile.search.client_index.v1",
                    "manifest_account_data_type": "ck.search.index_manifest.v1",
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
                    "profile": "ck.profile.personal_productivity.v1",
                    "account_data_type": "ck.reminders.v1",
                    "storage": "encrypted_private_account_data",
                    "plaintext_payload_accepted": false,
                    "server_action": "local_or_push_wake_only",
                    "wakeup_kind": "reminder",
                    "target_ref_visible_in_shared_event": false,
                    "note_visible_in_shared_event": false
                },
                "scheduled_send": {
                    "profile": "ck.profile.personal_productivity.v1",
                    "account_data_type": "ck.scheduled_send.v1",
                    "storage": "encrypted_private_account_data",
                    "plaintext_payload_accepted": false,
                    "server_dispatches_message_create": false,
                    "server_action": "holder_wake_sync_only",
                    "wakeup_kind": "scheduled_send",
                    "planned_message_id_anchor": "ck.message.create.payload.message_id",
                    "shared_history_materialization": "client_submitted_ck.message.create_only"
                },
                "snooze": {
                    "profile": "ck.profile.personal_productivity.v1",
                    "account_data_type": "ck.snooze.v1",
                    "storage": "encrypted_private_account_data",
                    "plaintext_payload_accepted": false,
                    "target_key": "holder_derived_unlinkable",
                    "private_projection_scope": "holder_only",
                    "shared_state_mutation": false,
                    "target_ref_visible_in_shared_event": false
                }
            },
            "scalability_constraints": {
                "source": "cokret-spec/spec/v1/zh/conformance/scalability-constraints.md",
                "max_event_bytes": MAX_EVENT_ENVELOPE_BYTES,
                "max_events_batch_submit": MAX_EVENT_SUBMIT_BATCH,
                "max_federation_transaction_events": 500,
                "max_page_items": 100,
                "max_prev_refs": MAX_EVENT_PREV_REFS,
                "max_refs": MAX_EVENT_REFS,
                "max_auth_refs": MAX_AUTHORIZED_BY_REFS,
                "max_relation_expansion_depth": 32,
                "max_delegation_depth": MAX_DELEGATION_CHAIN_DEPTH,
                "max_grants_per_decision": 1024,
                "max_grant_constraints": 64,
                "max_resource_selector_depth": 16,
                "daily_principal_download_limit": crate::state::key_backup_daily_download_limit(),
                "max_to_device_page": 1000,
                "max_to_device_queue_per_device": to_device_queue_capacity
            },
            "profile_status": {
                "conformance": "limited_reference",
                "unsupported_profiles": [
                    {
                        "profile": "ck.profile.soland_limited_server.v1",
                        "status": "unsupported",
                        "reason": "limited profile is a limitation descriptor, not a conformance claim"
                    }
                ],
                "full_profiles_not_claimed": [
                    "ck.profile.principal_server.v1",
                    "ck.profile.directory_service.v1",
                    "ck.profile.identity_registry.v1",
                    "ck.profile.blob_node.v1"
                ],
                "principal_server_full_profile_gaps": full_principal_server_gap_summary(),
                "supported_operation_catalog": {
                    "source": "cokret-spec/spec/v1/artifacts/registry/operation-registry.json",
                    "derived_surface_groups": SUPPORTED_OPERATION_SURFACES,
                    "standalone_operations": SUPPORTED_STANDALONE_OPERATION_IDS
                },
                "local_extension_operations": local_extension_operations,
                "local_extension_operation_source": "routing::SOLAND_EXTENSION_OPERATIONS",
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
                        "cokret_signed_event_reducer",
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
        }),
        frontier: Vec::new(),
        snapshot_frontier: Vec::new(),
        reducer_profile: Some("ck.reducer.v1".to_owned()),
        last_materialized_at: None,
    }
}

pub fn now() -> DateTime<Utc> {
    Utc::now()
}

// ── Conversation Model DTOs ──

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct ReviseMessageRequestBody {
    pub event_id: String,
    pub content: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ReviseMessageOutcome {
    pub event_id: String,
    pub revision_of: String,
    pub operation_id: String,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct RedactMessageRequestBody {
    pub event_id: String,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct RedactMessageOutcome {
    pub redacted: bool,
    pub event_id: String,
}

pub type SetReadMarkerRequestBody = cokret_sdk::ReadCursorAdvanceRequestBody;
pub type ReadScopeWire = cokret_sdk::ReadScope;
pub type ReadCursorPositionWire = cokret_sdk::ReadCursorPosition;
pub type ReadMarkerOutcome = cokret_sdk::ReadMarkerOutcome;

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct GetReadMarkersRequestBody {
    pub realm_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_describe_advertises_realm_key_history_features() {
        let description = describe(
            "did:web:soland.example",
            "https://soland.example/",
            "memory",
            true,
            None,
            None,
            "ck:trust_domain:soland.example",
            86_400,
            10_000,
        );
        let value = serde_json::to_value(description).expect("description serializes");
        let features = value["supported_features"]
            .as_array()
            .expect("features array");
        for feature in [
            "ck.feature.realm_key.backup_retrieval.v1",
            "ck.feature.realm_key.peer_relay.v1",
            "ck.feature.realm_key.archive_retrieval.v1",
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
            "did:web:soland.example",
            "https://soland.example/",
            "memory",
            true,
            None,
            None,
            "ck:trust_domain:soland.example",
            86_400,
            10_000,
        );
        let value = serde_json::to_value(description).expect("description serializes");
        assert_eq!(
            value["supported_bindings"][0],
            json!({"kind": "http_json", "base_url": "https://soland.example"})
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
            json!("https://soland.example/_cokret/self/blob/resumable")
        );
        assert_eq!(
            value["supported_bindings"][1]["operations"],
            json!(["ck.self.blob.upload.create"])
        );
        assert!(value["supported_bindings"][1]["extension_profile_required"].is_null());
        assert!(
            value["supported_features"]
                .as_array()
                .expect("features array")
                .contains(&json!("ck.feature.blob.resumable_upload.tus.v1"))
        );
        assert!(
            value["supported_features"]
                .as_array()
                .expect("features array")
                .contains(&json!(
                    "org.cokret.soland.feature.personal_productivity.scheduled_send_wake_only"
                ))
        );
        assert!(
            value["supported_features"]
                .as_array()
                .expect("features array")
                .contains(&json!(
                    "org.cokret.soland.feature.personal_productivity.reminder_snooze_private_wake"
                ))
        );
        assert!(
            value["supported_features"]
                .as_array()
                .expect("features array")
                .contains(&json!(
                    "org.cokret.soland.feature.policy.check_signed_decision"
                ))
        );
        assert!(
            value["supported_features"]
                .as_array()
                .expect("features array")
                .contains(&json!(
                    "org.cokret.soland.feature.push.target_id_hmac_rotation"
                ))
        );
        assert_eq!(
            value["privacy_derivation"]["push_target_id"]["derivation_profile"],
            json!("ck.push_target_id.hmac_sha256.v1")
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
                "recipient_service_did",
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
            json!(cokret_sdk::MAX_EVENT_ENVELOPE_BYTES)
        );
        assert_eq!(
            value["limits"]["scalability_constraints"]["max_events_batch_submit"],
            json!(cokret_sdk::MAX_EVENT_SUBMIT_BATCH)
        );
        assert_eq!(
            value["limits"]["scalability_constraints"]["max_prev_refs"],
            json!(cokret_sdk::MAX_EVENT_PREV_REFS)
        );
        assert_eq!(
            value["limits"]["scalability_constraints"]["max_refs"],
            json!(cokret_sdk::MAX_EVENT_REFS)
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
                "ck.self.authz.query.check",
                "ck.self.authz.grants.query.effective",
                "ck.self.authz.invites.query.list",
                "ck.self.policy.query.check"
            ])
        );
        assert_eq!(
            value["limits"]["authz_policy"]["authz_check"]["decision_source"],
            json!("local_projection_preflight_diagnostic")
        );
        assert_eq!(
            value["limits"]["authz_policy"]["authz_check"]["path"],
            json!("/_cokret/self/authz/check")
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
            json!("/_cokret/self/policy/check")
        );
        assert_eq!(
            value["limits"]["authz_policy"]["effective_grants"]["path"],
            json!("/_cokret/self/authz/effective-grants")
        );
        assert_eq!(
            value["limits"]["authz_policy"]["effective_grants"]["subject_scope"],
            json!("authenticated_actor_or_realm_owner_for_realm_scoped_queries")
        );
        assert_eq!(
            value["limits"]["authz_policy"]["invites"]["path"],
            json!("/_cokret/self/authz/invites")
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
            json!(crate::state::KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_DEFAULT)
        );
    }
}
