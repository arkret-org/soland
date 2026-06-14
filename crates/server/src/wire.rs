use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
pub use cokret_sdk::ops_api::HardeningStatus;
use cokret_sdk::{ClaimedProfileEntry, ServerDescription};
pub use cokret_sdk::{
    ContactListRow, ContactState, DeviceMessageEnvelope, DeviceMessageTarget,
    DeviceMessagesAckOutcome, DeviceMessagesAckRequestBody, DeviceMessagesGetOutcome,
    DeviceMessagesSendOutcome, DeviceMessagesSendRequestBody, DirectConversationBindingState,
    DirectConversationSummary, EventsQueryPostRequestBody, IdentityResolveRequestBody,
    KeysClaimOutcome, KeysClaimRequestBody, KeysQueryOutcome, KeysQueryRequestBody,
    KeysUploadOutcome, KeysUploadRequestBody, OkOutcome, PushNotifyOutcome, PushNotifyRequestBody,
    RealmJoinCandidate, RealmJoinCandidateRole, RealmJoinCandidateServiceType,
    RealmJoinCandidateSource, RealmJoinMethod, SessionGrantExchangeRequestBody,
    SessionGrantIntrospectionProof, SessionLoginOutcome,
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
    ///   - `"oauth_introspection"` — bearer tokens are introspected against
    ///     `SOLAND_OAUTH_INTROSPECTION_URL` (no admin allowlist configured)
    ///   - `"closed"` — production mode with no admin principals AND no introspection configured;
    ///     admin endpoints are effectively locked.
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
    pub session_grant_exchange_path: String,
    pub bearer_auth_scheme: String,
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
    pub session_grant_exchange_request: Value,
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
pub use cokret_sdk::model::SyncDescription;

#[derive(Debug, Clone, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct SolandHandleClaim {
    pub schema: String,
    /// Canonical handle in the spec form `<localpart>:<domain>(:<port>)?`
    /// (handle-claim.schema.json#/properties/handle, cokret-spec @ 7157ee8).
    /// The retired `cokret://<domain>/users/<localpart>` URI form is gone
    /// from R3.1 wire — any `acct:<local>@<domain>` interop form is carried
    /// separately in [`Self::handle_aliases`], NEVER in this field.
    pub handle: String,
    /// Interop aliases normalized to the canonical [`Self::handle`] above.
    /// Includes `acct:<local>@<domain>` cross-publication. The retired
    /// `cokret://` URI form MUST NOT appear here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub handle_aliases: Vec<String>,
    pub subject: String,
    pub issuer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_service_did: Option<String>,
    pub binding_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub claim_scope: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_delivery_binding: Option<SolandHandleClaimDeliveryBinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<Value>,
    // SOL-04-003: field order matches handle-claim.schema.json
    // (expires_at before created_at).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<String>,
    pub proofs: Vec<SolandHandleClaimProof>,
}

#[derive(Debug, Clone, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct SolandHandleClaimDeliveryBinding {
    pub recipient_service_did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_service_type: Option<String>,
    pub binding_source: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delivery_modes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_acceptance_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_event_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct SolandHandleClaimProof {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jws: Option<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct IndexQueryRequestBody {
    #[serde(default)]
    pub realm_ids: Vec<String>,
    /// Filter by typed-id kinds (`space`, `flow`, `message`, …) drawn from the
    /// spec id-kind-registry. Replaces the round-5 `entity_types[]` field that
    /// referenced the soland-local entity scaffold.
    #[serde(default)]
    pub object_kinds: Vec<String>,
    #[serde(default)]
    pub facets: Vec<String>,
    pub renderer: Option<String>,
    #[serde(default)]
    pub filters: Value,
    #[serde(default)]
    pub sort: Vec<Value>,
    pub cursor: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IndexQueryOutcome {
    pub results: Vec<Value>,
    pub next_cursor: Option<String>,
    pub frontier: Value,
}

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
    pub flows: Vec<Value>,
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

/// Spec-shape `ck.self.events.query.frontier` account-client response
/// (`service-operation-dtos.schema.json#/$defs/EventsFrontierAccountClientState`).
/// `frontier` is a single object whose shape follows the selector: actor
/// (`{actor_id, actor_seq, event_id}`) or Realm Seal view (`{realm_id,
/// seal_id, control_event_set_root, state_root, hlc?}`). The Realm shape is
/// the registered account-client source for minting a single-leaf Control
/// Move `seal_basis` / DataEvent `seal_ref` (SPEC-SOL-003 resolution).
#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct EventsFrontierAccountClientState {
    pub frontier: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipts: Option<Vec<Value>>,
}

// `SolandSnapshotHeadState` was deleted with the 2026-06-11 spec resolution:
// `ck.self.snapshot.query.manifest_head` / `ck.peer.snapshot.query.manifest_head` return the full
// signed `ck.schema.snapshot.v1` manifest (the spec `SnapshotHeadState` DTO was
// removed and hard-rejected in renames.json). soland answers both operations
// with `not_implemented` until it can produce a real Snapshot detached proof.

// authz check DTOs are now the spec-authoritative SDK types. The SDK
// `AuthzDecision` enum was aligned to the spec five-valued form
// (allow / soft_deny / hard_deny / quarantine / require_review) and
// `AuthzCheckRequestBody` to `{ actor_id, action, resource?, context? }`,
// so soland re-uses them directly instead of carrying local copies.
pub use cokret_sdk::model::{
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
pub use cokret_sdk::model::{ModerationReportOutcome, ModerationReportRequestBody};

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
pub struct SolandPolicyCheckRequestBody {
    pub request_id: String,
    #[serde(default)]
    pub realm_id: Option<String>,
    pub request_canonical_digest: String,
    pub action: String,
    pub actor_id: String,
    pub source: Value,
    #[serde(default)]
    pub event_preview: Option<Value>,
    #[serde(default)]
    pub auth_context: Option<Value>,
}

/// Frontier binding stamped onto every signed `SolandPolicyCheckOutcome`.
///
/// The four hashes pin the decision to a concrete authz universe so a
/// client (or auditor) can detect that the decision is stale once any
/// of the four frontiers move:
///   - `realm_id` — scope this binding applies to (canonical `ck:realm:<uuid>` form). May be empty
///     string when the request was realm-less (e.g. a global capability check).
///   - `auth_state_digest` — sha256 hex over canonical JSON `{actor_id, action, resource,
///     request_canonical_digest}`.
///   - `policy_frontier_digest` — sha256 hex over canonical JSON `{policy_documents: [<sorted
///     policy_ids>]}`.
///   - `membership_frontier_digest` — sha256 hex over canonical JSON `{realm_id, members: [<sorted
///     member DIDs>]}`.
///   - `expires_at` — soft TTL for the binding (now + 1h).
#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct PolicyBinding {
    pub realm_id: String,
    pub auth_state_digest: String,
    pub policy_frontier_digest: String,
    pub membership_frontier_digest: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SolandPolicyCheckOutcome {
    pub decision: String,
    pub reason_code: String,
    pub policy_id: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub obligations: Vec<Value>,
    pub decision_trace: Value,
    pub bound_to: PolicyBinding,
    pub signature: Value,
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

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct RegisterAccountRequestBody {
    pub did: String,
    pub handle: String,
    pub display_name: Option<String>,
    pub device_id: Option<String>,
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
pub struct ClaimHandleRequestBody {
    /// New handle (with or without leading `@`). Normalized server-side
    /// to lowercase + `@`-prefixed form per identity-handles.md §2.
    pub handle: String,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ClaimHandleOutcome {
    pub did: String,
    pub handle: String,
    pub previous_handle: Option<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct TransferHandleRequestBody {
    /// DID of the recipient. MUST be a registered account; otherwise
    /// the request fails with `principal_unknown`.
    pub target_did: String,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct TransferHandleOutcome {
    /// The handle string that was moved between accounts.
    pub handle: String,
    pub from_did: String,
    /// Synthetic placeholder handle that now belongs to the source actor.
    pub from_handle: String,
    pub to_did: String,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SolandAccountUpdateProfileRequestBody {
    /// Each field updates the corresponding `AccountRecord` slot.
    /// Send `null` / omit to leave the field unchanged; send `""` to
    /// explicitly clear it (server stores `None`).
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub bio: Option<String>,
    #[serde(default)]
    pub avatar_url: Option<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SolandAccountUpdateProfileOutcome {
    pub did: String,
    pub handle: String,
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct RealmLifecycleOutcome {
    pub ok: bool,
    pub realm_id: String,
    pub owner: String,
    pub members: Vec<String>,
    pub deleted: bool,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SendMessageRequestBody {
    pub realm_id: String,
    #[serde(default)]
    pub thread_id: Option<String>,
    pub content: Value,
    #[serde(default)]
    pub encrypted: bool,
}

// Identity log / receipts outcomes are the SDK DTOs (`model/api.rs` is the
// authoritative carrier for identity operation shapes); no soland mirrors.
// CKP-0008 / CKP-0009 — Personal Agent operations. Every request/response
// DTO is the SDK-authoritative `cokret_sdk::model::Agent*` shape (spec
// `agent-operations.schema.json`): `agent_view`/`agent_list` carry the spec
// `agent_projection`; `agent_key_pair`/`rotate_key` outcomes are
// `{ok, authorized_event_ref}`; grant attach/detach outcomes are
// `{ok, grant_id}` / `{ok, revoked_at}`; sidecar ensure carries the typed
// `private_circle_id`/`private_flow_id`/`private_relation_id`. The lifecycle
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
pub use cokret_sdk::model::{
    AgentDeactivateRequestBody, AgentGrantAttachOutcome, AgentGrantAttachRequestBody,
    AgentGrantDetachOutcome, AgentKeyPairOutcome, AgentKeyPairRequestBody, AgentList,
    AgentPauseRequestBody, AgentResumeRequestBody, AgentRotateKeyOutcome,
    AgentRotateKeyRequestBody, AgentSidecarThreadEnsureOutcome,
    AgentSidecarThreadEnsureRequestBody, AgentView, CallMediaTokenExchangeRequestBody,
};
// Key-backup replace/delete outcomes are the SDK server-side DTOs
// (`cokret_sdk::model` is the authoritative carrier for
// `keys-operations.schema.json#/$defs/keys_backups_replace_outcome` /
// `keys_backups_delete_outcome`); no soland mirrors.
pub use cokret_sdk::model::{
    KeyBackupPutStatus, KeysBackupsDeleteOutcome, KeysBackupsList, KeysBackupsReplaceOutcome,
};
pub use cokret_sdk::{
    CallMediaParticipantBinding, CallMediaTokenExchangeOutcome, IdentityLogOutcome,
    IdentityReceiptsOutcome, KeysBackupsPutRequestBody,
};

// Recovery policy / receipt endpoints (`recovery_policy_put` /
// `recovery_receipt_put`) take `JsonBody<Value>` and validate against the
// spec REC-1 shapes via `validate_recovery_policy` / `validate_recovery_receipt`
// in `routing::identity::recovery`. Recovery policy publish is the standard
// `ck.root.identity.recovery_policy.command.publish` surface; recovery receipt write remains
// product-local. The SDK carries the authoritative typed forms
// (`cokret_sdk::model::{RecoveryPolicy, RecoveryReceipt}`) for clients; no
// soland-private mirror exists.

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct CreateWebRtcSessionRequestBody {
    pub realm_id: String,
    #[serde(default)]
    pub participants: Vec<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub recording_policy: Option<String>,
    #[serde(default)]
    pub ttl_ms: Option<u64>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct CreateWebRtcSessionOutcome {
    pub session_id: String,
    pub realm_id: String,
    pub participants: Vec<String>,
    pub mode: String,
    pub recording_policy: String,
    pub call_state: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct WebRtcSignalRequestBody {
    pub message_type: String,
    #[serde(default)]
    pub seq: Option<u64>,
    #[serde(default)]
    pub payload: Value,
    #[serde(default)]
    pub proofs: Vec<Value>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct WebRtcSignalOutcome {
    pub ok: bool,
    pub session_id: String,
    pub seq: u64,
    pub next_cursor: String,
    pub call_state: String,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct WebRtcSignalsOutcome {
    pub session_id: String,
    pub call_state: String,
    pub events: Vec<Value>,
    pub next_cursor: String,
    pub limited: bool,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SolandBlobUploadOutcome {
    pub blob_ref: String,
    pub size_bytes: usize,
    pub media_type: String,
    pub content_digest: String,
    pub upload_receipt: Value,
}

const SUPPORTED_OPERATION_SURFACES: &[&str] = &[
    "service_discovery",
    "events_sync",
    "realtime_media",
    "authz_policy",
    "moderation_reports",
    "projection_lifecycle",
    "push",
    "mimi_interop",
    "invite_locator_handoff",
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
            "area": "authz.describe",
            "status": "scaffold_contract",
            "reason": "authz/describe publishes examples and current local evaluator boundaries; it is not a complete generated authorization profile"
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
            "status": "stub_contract",
            "reason": "TSP transport/route/audit endpoints are process-local scaffolding; real envelope verify/decrypt and persistent signed audit chain are not claimed"
        }),
        json!({
            "area": "extensions.bot_actor",
            "status": "stub_contract",
            "reason": "bot/ghost actor endpoints use a process-local registry; durable provisioning, accountability grants, and restart-safe state are not claimed"
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
            "reason": "ck.self.snapshot.query.manifest_head returns a signed ck.schema.snapshot.v1 manifest; the legacy /_soland dev bundle remains a product-face compatibility surface"
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
            "reason": "the /_soland/peer/* inbound federation surface (transactions, operations push/pull/backfill/frontier, moves/seals direct ingest, realm-members, verify-actor) is a deployment-local test/ops rail only; it is not discoverable through describe/OpenAPI for remote peers and MUST NOT be relied on for cross-vendor interop — the protocol S2S entry point is the /_cokret/peer/* surface group"
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
    oauth_introspection_enabled: bool,
    auth_server_url: Option<&str>,
    trust_domain: &str,
    resumable_upload_incomplete_ttl_seconds: u64,
) -> ServerDescription {
    let mut supported_auth_methods = Vec::new();
    if development_mode {
        supported_auth_methods.push("dev_bearer_token");
    }
    if oauth_introspection_enabled {
        supported_auth_methods.push("oauth2_bearer_introspection");
    }
    let mut auth_metadata = json!({
        "mode": if development_mode { "development" } else { "production" },
        "supported_auth_methods": supported_auth_methods,
    });
    if let Some(auth_server_url) = auth_server_url.filter(|value| !value.trim().is_empty()) {
        auth_metadata["auth_server_url"] = json!(auth_server_url);
    }
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
    let plaintext_visibility = serde_json::json!({
        "default": "encrypted",
        "services": [],
    });

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
            ];
            // PROF-1 (R3 spec-sync 2026-05-27, cokret-spec b47ff6ec) —
            // advertise `ck.profile.media_service_binding.v1` whenever the
            // server exposes the `ck.self.call.media.exchange.issue_token` handler.
            // soland mounts the handler unconditionally (see
            // `routing::interop::webrtc::router` — `/_cokret/self/rtc/token`),
            // so the claim is unconditional too.
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
        rate_limit: serde_json::json!({"kind": "windowed", "per_minute": 600}),
        egress_network_policy: Some(cokret_sdk::EgressNetworkPolicy::deny_private_defaults()),
        supported_features: vec![
            "org.cokret.soland.feature.account.register".to_owned(),
            "org.cokret.soland.feature.account.me".to_owned(),
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
            "org.cokret.soland.feature.sync.backfill".to_owned(),
            "org.cokret.soland.feature.directory.search_realms".to_owned(),
            "org.cokret.soland.feature.directory.resolve_realm".to_owned(),
            "org.cokret.soland.feature.index.query".to_owned(),
            "org.cokret.soland.feature.authz.check".to_owned(),
            "org.cokret.soland.feature.profile.presence".to_owned(),
            "org.cokret.soland.feature.push.register_device".to_owned(),
            "org.cokret.soland.feature.push.rules".to_owned(),
            "org.cokret.soland.feature.webrtc.signaling".to_owned(),
            "org.cokret.soland.feature.blob.upload".to_owned(),
            // Spec crypto-media/media-and-blob.md §2.1 — protocol-level
            // feature id for the resumable (tus) upload companion binding
            // of ck.self.blob.upload. Pairs with the `kind="tus"` entry in
            // supported_bindings below.
            "ck.feature.blob.resumable_upload.tus.v1".to_owned(),
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
        ],
        supported_operations,
        // service-surface.md §3 documents `base_url` (typed `format: uri` in
        // service-describe.schema.json) as the connectable service base.
        // Emit the same public base URL used by the HTTP describe handler so
        // clients can build `base_url + operation_path` directly.
        supported_bindings: vec![
            serde_json::json!({"kind": "http_json", "base_url": public_base_url.trim_end_matches('/')}),
            // Per-operation HTTP companion binding (transport-bindings.md
            // §6.1): tus 1.0.0 resumable upload for ck.self.blob.upload.
            // Versions/extensions mirror the OPTIONS probe answers of
            // routing::interop::blob_resumable — describe and wire MUST
            // agree.
            serde_json::json!({
                "kind": "tus",
                "base_url": format!(
                    "{}/_cokret/self/blob/resumable",
                    public_base_url.trim_end_matches('/')
                ),
                "operations": ["ck.self.blob.upload.create"],
                "extension_profile_required": serde_json::Value::Null,
                "tus_version": crate::routing::TUS_VERSIONS,
                "tus_extensions": crate::routing::TUS_EXTENSIONS,
            }),
        ],
        supported_reducer_profiles: vec!["ck.reducer.v1".to_owned()],
        supported_schema_profiles: vec!["ck.schema.core.v1".to_owned()],
        auth_metadata,
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
                    "federation.push_operations",
                    "federation.transaction",
                    "blob.upload"
                ]
            },
            "scalability_constraints": {
                "source": "cokret-spec/spec/v1/zh/conformance/scalability-constraints.md",
                "max_event_bytes": 65536,
                "max_events_batch_submit": 100,
                "max_federation_transaction_events": 500,
                "max_page_items": 100,
                "max_prev_refs": 32,
                "max_auth_refs": 64,
                "max_relation_expansion_depth": 32,
                "max_delegation_depth": 4,
                "max_grants_per_decision": 1024,
                "max_grant_constraints": 64,
                "max_resource_selector_depth": 16,
                "max_to_device_page": 1000
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

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct AddReactionRequestBody {
    pub event_id: String,
    pub key: String,
    pub realm_id: String,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ReactionOutcome {
    pub event_id: String,
    pub actor: String,
    pub key: String,
    pub active: bool,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct RemoveReactionRequestBody {
    pub event_id: String,
    pub key: String,
    pub realm_id: String,
}

pub type SetReadMarkerRequestBody = cokret_sdk::ReadCursorAdvanceRequestBody;
pub type ReadScopeWire = cokret_sdk::ReadScope;
pub type ReadScopeTrackScopeWire = cokret_sdk::ReadScopeTrackScope;
pub type ReadCursorPositionWire = cokret_sdk::ReadCursorPosition;
pub type ReadMarkerOutcome = cokret_sdk::ReadMarkerOutcome;

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct GetReadMarkersRequestBody {
    pub realm_id: String,
}

// ── Relation DTOs ──
//
// Relation DTOs — `ck:relation:` is a registered typed-id in
// `cokret-spec/v1/artifacts/registry/id-kind-registry.json`.

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct CreateRelationRequestBody {
    pub realm_id: String,
    pub relation_kind: String,
    pub from: Option<String>,
    pub to: Option<String>,
    #[serde(default)]
    pub fields: BTreeMap<String, Value>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct RelationOutcome {
    pub relation_id: String,
    pub realm_id: String,
    pub relation_kind: String,
    pub from: Option<String>,
    pub to: Option<String>,
    pub fields: BTreeMap<String, Value>,
    pub state: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct ListRelationsRequestBody {
    pub realm_id: String,
    pub relation_kind: Option<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ListRelationsOutcome {
    pub relations: Vec<RelationOutcome>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct TombstoneRelationOutcome {
    pub state: String,
    pub relation_id: String,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct CreateGrantOutcome {
    pub grant_id: String,
    pub subject: String,
    pub actions: Vec<String>,
    pub resource: String,
    pub created_at: String,
    /// Effective expiry of this grant (RFC 3339). `None` means never expires.
    /// capabilities.md §3 — denormalized from `constraints[temporal].expires_at`
    /// when only the constraint form was supplied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// `delegated_from` is set when this grant was issued via delegation
    /// (capabilities.md §10). Revoking the named parent cascades through
    /// every descendant including this one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegated_from: Option<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct RevokeGrantOutcome {
    pub revoked: bool,
    pub grant_id: String,
    /// Grant ids that flipped to revoked as part of this call's delegation
    /// cascade (does NOT include `grant_id` itself). capabilities.md §3.3.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cascade_revoked: Vec<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct CreateGrantRequestBody {
    pub realm_id: String,
    pub subject: String,
    pub resource: String,
    pub actions: Vec<String>,
    #[serde(default)]
    pub constraints: Vec<serde_json::Value>,
    /// Optional top-level expiry (RFC 3339). When set, server cross-checks
    /// against `constraints[temporal].expires_at` (stricter wins).
    #[serde(default)]
    pub expires_at: Option<String>,
    /// Parent grant_id when this request is a delegation. caller MUST be
    /// the subject of the parent grant; delegated actions/resource/expiry
    /// MUST fit within the parent's scope (capabilities.md §10).
    #[serde(default)]
    pub delegated_from: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_describe_supported_bindings_advertise_public_base_url() {
        let description = describe(
            "did:web:soland.example",
            "https://soland.example/",
            "memory",
            true,
            false,
            None,
            "ck:trust_domain:soland.example",
            86_400,
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
        assert_eq!(
            value["limits"]["resumable_upload_incomplete_ttl_seconds"],
            json!(86_400)
        );
        assert_eq!(
            value["limits"]["resumable_upload_max_bytes"],
            json!(10 * 1024 * 1024)
        );
    }

    #[test]
    fn handle_claim_serializes_spec_shape() {
        let claim = SolandHandleClaim {
            schema: "ck.schema.handle_claim.v1".to_owned(),
            handle: "alice:acme.example".to_owned(),
            handle_aliases: vec!["acct:alice@acme.example".to_owned()],
            subject: "did:web:alice.example".to_owned(),
            issuer: "did:web:acme.example".to_owned(),
            issuer_service_did: Some("did:web:principal.acme.example".to_owned()),
            binding_state: "verified".to_owned(),
            claim_kind: Some("organization_handle".to_owned()),
            visibility: Some("restricted".to_owned()),
            audience: Some("ck:realm:0196419b-0000-7000-8000-000000000000".to_owned()),
            challenge: None,
            claim_scope: BTreeMap::new(),
            member_delivery_binding: Some(SolandHandleClaimDeliveryBinding {
                recipient_service_did: "did:web:principal.acme.example".to_owned(),
                recipient_service_type: Some("principal_server".to_owned()),
                binding_source: "organization_policy".to_owned(),
                delivery_modes: vec!["events".to_owned(), "sync".to_owned()],
                service_acceptance_ref: None,
                policy_event_ref: None,
            }),
            claims: Vec::new(),
            created_at: "2026-05-19T00:00:00Z".to_owned(),
            expires_at: Some("2026-08-19T00:00:00Z".to_owned()),
            verified_at: None,
            source_refs: Vec::new(),
            proofs: vec![SolandHandleClaimProof {
                kind: "detached_jws".to_owned(),
                alg: Some("EdDSA".to_owned()),
                verification_method: Some("did:web:acme.example#key-1".to_owned()),
                payload_digest: Some(
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_owned(),
                ),
                created_at: Some("2026-05-19T00:00:00Z".to_owned()),
                jws: Some("aaa.bbb.ccc".to_owned()),
            }],
        };

        let value = serde_json::to_value(claim).expect("handle claim serializes");
        assert_eq!(value["schema"], "ck.schema.handle_claim.v1");
        assert_eq!(
            value["member_delivery_binding"]["recipient_service_did"],
            "did:web:principal.acme.example"
        );
        assert!(value.get("claim_scope").is_none());
        assert!(value.get("challenge").is_none());
    }
}
