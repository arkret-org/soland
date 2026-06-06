use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
pub use cokret_sdk::api::ops::HardeningStatus;
use cokret_sdk::{ClaimedProfileEntry, ServerDescription};
pub use cokret_sdk::{
    DeviceMessageEnvelope, DeviceMessageTarget, DeviceMessagesGetOutcome, DeviceMessagesPutOutcome,
    DeviceMessagesPutRequestBody, KeysClaimOutcome, KeysClaimRequestBody, KeysQueryOutcome,
    KeysQueryRequestBody, KeysUploadOutcome, KeysUploadRequestBody, OkOutcome, PushNotifyOutcome,
    PushNotifyRequestBody,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::artifacts;
use crate::state::RealmDirectoryEntry;

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct HealthResponse {
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
pub struct SolandServerDescribeResponse {
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
pub struct AuthBridgeDescribeResponse {
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
pub struct OutboundPushBridgeDescribeResponse {
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

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct IntegrationDescribeResponse {
    pub contract: String,
    pub version: String,
    pub service: String,
    pub service_kind: String,
    pub api_base_path: String,
    pub describe_path: String,
    pub dependencies: Vec<IntegrationDependencyDescriptor>,
    pub surfaces: Vec<IntegrationSurfaceDescriptor>,
    pub examples: Value,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct IntegrationDependencyDescriptor {
    pub service: String,
    pub purpose: String,
    pub required_contract: String,
    pub discovery_path: String,
    pub mode: String,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct IntegrationSurfaceDescriptor {
    pub name: String,
    pub method: String,
    pub path: String,
    pub contract: String,
    pub stability: String,
    pub todo: String,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct OutboundPushBridgeResolveRequest {
    pub push_gateway_url: String,
    #[serde(default)]
    pub refresh: bool,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct OutboundPushBridgeFetchRequest {
    pub push_gateway_url: String,
    #[serde(default)]
    pub force_refresh: bool,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct OutboundPushBridgeCacheInvalidateRequest {
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
pub struct OutboundPushBridgeCacheExportResponse {
    #[serde(default)]
    pub entries: Vec<OutboundPushBridgeCacheSnapshot>,
    pub snapshot_store_kind: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct OutboundPushBridgeCacheImportRequest {
    #[serde(default)]
    pub entries: Vec<OutboundPushBridgeCacheSnapshot>,
    #[serde(default)]
    pub replace_existing: bool,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct OutboundPushBridgeCacheImportResponse {
    pub imported_count: usize,
    pub skipped_count: usize,
    pub total_entries: usize,
    pub snapshot_store_kind: String,
    pub cache_state: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct OutboundPushBridgeResolveResponse {
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
pub struct OutboundPushBridgeFetchResponse {
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
pub struct OutboundPushBridgeCacheStatusResponse {
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
pub struct OutboundPushBridgeCacheInvalidateResponse {
    pub removed_count: usize,
    pub remaining_entries: usize,
    pub cache_state: String,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct AccountDescribeOutcome {
    pub service_did: String,
    pub supported_sync_profiles: Vec<String>,
    pub limits: Value,
    pub frontier: Value,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct ClientSyncRequest {
    pub after: Option<String>,
    #[serde(default)]
    pub catchup: Option<bool>,
    #[serde(default)]
    pub filter: Option<Value>,
    #[serde(default)]
    pub set_presence: Option<String>,
}

/// `POST /_cokret/self/account/cursor/revoke` request body
/// (`ck.self.account.cursor_revoke`).
#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct CursorRevokeRequest {
    /// The cursor authority to revoke (`ck:cursor:<...>`).
    pub cursor: String,
    /// Machine-readable revocation reason (audited).
    pub reason_code: String,
    /// Revocation breadth. Defaults to `this_cursor`.
    #[serde(default)]
    pub revoke_scope: Option<String>,
}

/// `POST /_cokret/self/account/cursor/revoke` response body.
#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct CursorRevokeResponse {
    pub revoked: bool,
    /// When the revocation record expires (the revoked cursor's maximum TTL).
    pub expires_at: String,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SearchRealmsRequest {
    pub query: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct DirectoryDescribeOutcome {
    pub service_did: String,
    pub resource_types: Vec<String>,
    pub discovery_profiles: Vec<String>,
    pub restricted_query_proof: bool,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct ResolveRealmRequest {
    pub realm_id: Option<String>,
    pub alias: Option<String>,
    pub invite_token: Option<String>,
    pub signed_link: Option<String>,
    #[serde(default)]
    pub requester: Option<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ResolveRealmResponse {
    pub realm_preview: RealmDirectoryEntry,
    pub stripped_state: Vec<Value>,
    pub join_rule: String,
    pub join_candidates: Vec<RealmJoinCandidate>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct RealmJoinCandidate {
    pub realm_id: String,
    pub service_did: String,
    pub service_type: String,
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    pub operations: Vec<String>,
    pub join_methods: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_refs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontier_ref: Option<String>,
    pub as_of: String,
    pub expires_at: String,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SearchRealmsResponse {
    pub results: Vec<RealmDirectoryEntry>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SearchOrganizationsRequest {
    pub query: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct ResolveOrganizationRequest {
    pub organization_id: Option<String>,
    pub handle: Option<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SearchActorsRequest {
    pub query: Option<String>,
    pub organization_id: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SearchUsersRequest {
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    /// Why the requester wants to enumerate users — gates anti-enumeration
    /// filtering. Spec 0a5ab85: `ck.find.directory.search_users` adds `intent`.
    #[serde(default)]
    pub intent: Option<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct ResolveHandleRequest {
    pub handle: String,
    /// Why the handle is being resolved — gates audience binding on the
    /// response handle claim. Spec 0a5ab85.
    #[serde(default)]
    pub intent: Option<String>,
    /// DID / service DID of the requester. Used to scope audience-bearing
    /// claims and apply Space `allowed_recipient_services` filtering.
    #[serde(default)]
    pub requester: Option<String>,
    /// Optional explicit audience the verifier expects the claim to bind
    /// to (typically a target Space DID or inviter service DID). When
    /// present, the directory MUST issue an audience-bearing claim.
    #[serde(default)]
    pub audience: Option<String>,
    /// Target Realm for membership-builder resolves (`member_add` / `invite`).
    /// Required by the protocol when the response is used as admission
    /// material rather than display-only lookup data.
    #[serde(default)]
    pub realm_id: Option<String>,
    /// Optional requester proofs for proof-gated disclosure.
    #[serde(default)]
    pub proofs: Vec<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct DirectoryValueSearchResponse {
    pub results: Vec<Value>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ResolveOrganizationResponse {
    pub organization: Value,
    pub spaces: Vec<Value>,
}

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
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
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

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ResolveHandleResponse {
    pub handle: String,
    pub did: String,
    /// Principal DID of the handle holder. Kept byte-identical with `did`
    /// while legacy clients still consume that field name.
    pub subject: String,
    pub actor: Value,
    /// Audience the claim is bound to (echoes the `audience` request param
    /// or the inferred default — typically the requester / target Space).
    /// Verifiers MUST reject claims whose audience does not match their
    /// invocation context. Spec 0a5ab85.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Embedded handle claim envelope when the resolver issued one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle_claim: Option<SolandHandleClaim>,
    /// Top-level membership-builder routing evidence. For
    /// `intent=member_add|invite` this mirrors
    /// `handle_claim.member_delivery_binding` so verifiers can consume the
    /// candidate shape defined by `member-delivery-binding-candidate.schema`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_delivery_binding: Option<SolandHandleClaimDeliveryBinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct IndexQueryRequest {
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
pub struct IndexQueryResponse {
    pub results: Vec<Value>,
    pub next_cursor: Option<String>,
    pub frontier: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IndexDescribeResponse {
    pub service_did: String,
    pub reducer_profiles: Vec<String>,
    pub schema_profiles: Vec<String>,
    pub query_features: Vec<String>,
    pub frontier: Value,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct IndexSearchRequest {
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
pub struct IndexSearchResponse {
    pub results: Vec<Value>,
    pub next_cursor: Option<String>,
    pub frontier: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IndexThreadResponse {
    pub thread: Value,
    pub events: Vec<Value>,
    pub next_cursor: Option<String>,
    pub frontier: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IndexNotificationsResponse {
    pub notifications: Vec<Value>,
    pub next_cursor: Option<String>,
    pub unread_count: usize,
    pub frontier: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IndexInboxResponse {
    pub flows: Vec<Value>,
    pub next_cursor: Option<String>,
    pub frontier: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IndexSpaceHierarchyResponse {
    pub root_space_id: String,
    pub spaces: Vec<Value>,
    pub edges: Vec<Value>,
    pub frontier: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct BackfillOutcome {
    pub events: Vec<Value>,
    pub prev_cursor: Option<String>,
    pub next_cursor: Option<String>,
    pub limited: bool,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct EventDescribeResponse {
    pub service_did: String,
    pub protocol_version: String,
    pub primary_write_path: String,
    pub event_envelope: Value,
    pub supported_profiles: Vec<String>,
    pub registry: Value,
    pub schema_profile: String,
    pub reducer_profile: String,
    pub limits: Value,
    pub capabilities: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct EventSubmitResponse {
    pub status: String,
    pub event_id: String,
    pub canonical_digest: String,
    pub sync_token: String,
    pub received_at: DateTime<Utc>,
    pub receipt: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct EventReadResponse {
    pub event: Value,
    pub metadata: Value,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct EventResolveRequest {
    #[serde(default)]
    pub event_ids: Vec<String>,
    #[serde(default)]
    pub event_digests: Vec<String>,
    #[serde(default)]
    pub include_payload: bool,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct EventResolveResponse {
    pub events: Vec<EventReadResponse>,
    pub missing: Vec<String>,
    pub unauthorized: Vec<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct EventsQueryPostRequestBody {
    #[serde(default)]
    pub realms: Vec<String>,
    #[serde(default)]
    pub actors: Vec<String>,
    #[serde(default)]
    pub after: Option<String>,
    #[serde(default)]
    pub before: Option<String>,
    #[serde(default)]
    pub order: Option<String>,
    #[serde(default)]
    pub filters: Option<Value>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct EventsPageResponse {
    pub events: Vec<EventReadResponse>,
    pub next_cursor: Option<String>,
    pub frontier: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SolandEventsFrontierState {
    pub actor_frontier: BTreeMap<String, u64>,
    pub realm_frontier: BTreeMap<String, Value>,
    pub frontier: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SolandSnapshotHeadState {
    pub snapshot_ref: String,
    pub state_digest: String,
    pub manifest: Value,
    pub chunks: Vec<Value>,
    pub frontier: Value,
    pub signature: Value,
    /// Snapshot v1: root of the binary Merkle tree built over chunk
    /// digests. Receivers cross-check `chunks[i].digest` reaching this
    /// root via the per-chunk `audit_path`.
    pub merkle_root: String,
    /// Snapshot v1: number of chunks in `chunks[]`. Equivalent to
    /// `generator_proof.chunk_count` but surfaced explicitly so clients
    /// don't have to parse the proof to plan fetches.
    pub chunk_count: u32,
    /// Snapshot v1: target per-chunk byte budget the chunker used. The
    /// last chunk MAY be smaller; all others are exactly this size.
    pub chunk_bytes: u32,
    /// Snapshot v1: sum of per-chunk byte lengths. Lets receivers size
    /// download buffers before fetching.
    pub total_bytes: u64,
    /// Snapshot v1: signed commitment from the snapshot generator
    /// binding `(generator_did, realm_id, state_root, merkle_root,
    /// chunk_count, total_bytes, chunk_bytes)`.
    pub generator_proof: Value,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SolandAuthzCheckRequestBody {
    pub actor: String,
    pub action: String,
    pub resource: Value,
    #[serde(default)]
    pub context: Option<Value>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SolandAuthzCheckOutcome {
    pub allowed: bool,
    pub reason_code: Option<String>,
    pub reason: Option<String>,
    pub grants: Vec<Value>,
    pub obligations: Vec<Value>,
    pub decision_trace: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SolandGrantList {
    pub grants: Vec<Value>,
    pub state_digest: Option<String>,
    pub evaluated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct InvitesResponse {
    pub invites: Vec<Value>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct PushRegisterRequest {
    pub operation_id: Option<String>,
    pub principal_id: Option<String>,
    pub device_id: String,
    pub push_gateway: String,
    pub push_key: String,
    pub platform: Option<String>,
    pub app_id: Option<String>,
    pub display_name: Option<String>,
    pub idempotency_key: Option<String>,
    pub request_id: Option<String>,
    pub proof: Option<Value>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct PushRegisterResponse {
    pub ok: bool,
    pub registration_id: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub accepted_gateway: Option<String>,
    pub request_id: Option<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct PushUnregisterRequest {
    pub device_id: String,
    pub push_key: Option<String>,
    pub app_id: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct PushRulesResponse {
    pub rules: Vec<Value>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct UpsertPushRuleResponse {
    pub ok: bool,
    pub rule: Value,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct UpsertPushRuleRequest {
    pub rule_id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default)]
    pub conditions: Value,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct ModerationReportRequestBody {
    pub realm_id: String,
    pub target_ref: String,
    pub report_reason_code: String,
    pub reporter: String,
    pub description: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SolandModerationReportOutcome {
    pub report_id: String,
    pub status: String,
    pub routed_to: Vec<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct UpsertPolicyDocumentRequest {
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
pub struct PolicyDocumentResponse {
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
pub struct PolicyDocumentsResponse {
    pub policies: Vec<PolicyDocumentResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SolandPolicyCheckRequestBody {
    pub request_id: String,
    #[serde(default)]
    pub realm_id: Option<String>,
    pub request_canonical_digest: String,
    pub action: String,
    pub actor: String,
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
///   - `auth_state_digest` — sha256 hex over canonical JSON `{actor, action, resource,
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
pub struct DevLoginRequest {
    pub actor: String,
    pub device_id: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SessionGrantExchangeRequest {
    pub grant_jwt: String,
    pub principal_id: String,
    pub device_id: String,
    pub display_name: Option<String>,
    #[serde(default)]
    pub introspection_proof: Option<SessionGrantIntrospectionProof>,
}

#[derive(Debug, Deserialize, serde::Serialize, salvo::oapi::ToSchema)]
pub struct SessionGrantIntrospectionProof {
    pub challenge: String,
    pub proof_jwt: String,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct DevLoginResponse {
    pub access_token: String,
    pub token_type: String,
    pub actor: String,
    pub device_id: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct LogoutResponse {
    pub ok: bool,
    pub revoked: bool,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct RegisterAccountRequest {
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
pub struct ClaimHandleRequest {
    /// New handle (with or without leading `@`). Normalized server-side
    /// to lowercase + `@`-prefixed form per identity-handles.md §2.
    pub handle: String,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ClaimHandleResponse {
    pub did: String,
    pub handle: String,
    pub previous_handle: Option<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct TransferHandleRequest {
    /// DID of the recipient. MUST be a registered account; otherwise
    /// the request fails with `target_did_unknown`.
    pub target_did: String,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct TransferHandleResponse {
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

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SolandContactRequestRequestBody {
    pub target: String,
    #[serde(default)]
    #[serde(rename = "consent_scope")]
    pub scope: Option<String>,
    #[serde(default)]
    pub requested_scopes: Vec<String>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SolandContactRespondRequestBody {
    #[serde(default)]
    pub request_id: Option<String>,
    pub requester: String,
    pub action: String,
    #[serde(default)]
    pub granted_scopes: Vec<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ContactResponse {
    pub requester: String,
    pub target: String,
    #[serde(rename = "consent_scope")]
    pub scope: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ContactsResponse {
    pub contacts: Vec<ContactListRow>,
    pub has_more: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct DirectConversationSummary {
    pub realm_id: String,
    pub main_flow_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_event_ref: Option<String>,
    pub state: String,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ContactListRow {
    pub peer: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_event_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_event_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tombstone_event_ref: Option<String>,
    pub granted_by_me: Vec<String>,
    pub granted_to_me: Vec<String>,
    pub bidirectional_scopes: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub effective_scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_conversation: Option<DirectConversationSummary>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SolandDirectConversationResolveRequestBody {
    pub peer: String,
    #[serde(default)]
    pub create: bool,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SolandDirectConversationResolveOutcome {
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub main_flow_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_event_ref: Option<String>,
    pub created: bool,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct RealmLifecycleResponse {
    pub ok: bool,
    pub realm_id: String,
    pub owner: String,
    pub members: Vec<String>,
    pub deleted: bool,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SendMessageRequest {
    pub realm_id: String,
    #[serde(default)]
    pub thread_id: Option<String>,
    pub content: Value,
    #[serde(default)]
    pub encrypted: bool,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IdentityDescribeOutcome {
    pub service_did: String,
    pub registry_mode: String,
    pub supported_receipts: Vec<String>,
    pub protocol_version: String,
    pub profiles: Vec<String>,
    pub resolver_policy: Value,
    pub did_webvh: Value,
    pub todos: Vec<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct IdentityResolveRequestBody {
    pub did: String,
    #[serde(default)]
    pub requested_evidence_kinds: Vec<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IdentityLogOutcome {
    pub events: Vec<Value>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IdentityReceiptsOutcome {
    pub receipts: Vec<Value>,
    pub threshold_met: bool,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SolandIdentityResolveOutcome {
    pub did_document: Value,
    pub key_log_head: Option<String>,
    pub seq: u64,
    pub receipts: Vec<Value>,
    pub method_evidence: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SolandKeysBackupsPutOutcome {
    pub ok: bool,
    pub backup: Value,
    pub state: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SolandKeysBackupsList {
    pub backups: Vec<Value>,
    pub next_cursor: Option<String>,
    pub state: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SolandKeysBackupsDeleteOutcome {
    pub ok: bool,
    pub backup_id: String,
    pub deleted: bool,
    pub state: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

// CKP-0008 / CKP-0009 (spec head 37ce729) — Personal Agent 11 operations.
//
// The shapes below carry the cross-project HTTP contract for sodmin /
// yougen / cotest; reducer-side semantics are P2-impl TODO stubs in
// `routing::events::agents`.

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SolandAgentKeyPairRequestBody {
    pub agent_principal_id: String,
    pub verification_method: String,
    #[serde(default)]
    pub runtime_attestation: Option<Value>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SolandAgentKeyPairOutcome {
    pub ok: bool,
    pub agent_principal_id: String,
    pub verification_method: String,
    pub authorized_at: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SolandAgentProvisionRequestBody {
    pub display_name: String,
    #[serde(default)]
    pub controller_did: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub initial_grants: Vec<Value>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SolandAgentView {
    pub agent_principal_id: String,
    pub controller_did: String,
    pub agent_id: String,
    pub display_name: String,
    pub state: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub grants: Vec<Value>,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SolandAgentList {
    pub agents: Vec<SolandAgentView>,
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SolandAgentLifecycleRequestBody {
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SolandAgentLifecycleOutcome {
    pub ok: bool,
    pub agent_principal_id: String,
    pub state: String,
    pub status_changed_at: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SolandAgentRotateKeyRequestBody {
    pub new_verification_method: String,
    #[serde(default)]
    pub previous_key_id: Option<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SolandAgentRotateKeyOutcome {
    pub ok: bool,
    pub agent_principal_id: String,
    pub authorized_verification_method: String,
    pub revoked_verification_method: Option<String>,
    pub at: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SolandAgentGrantAttachRequestBody {
    pub grant_kind: String,
    #[serde(rename = "agent_key_scope")]
    pub scope: Value,
    #[serde(default)]
    pub expires_at: Option<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SolandAgentGrantOutcome {
    pub ok: bool,
    pub agent_principal_id: String,
    pub grant_id: String,
    pub grant_kind: String,
    #[serde(rename = "agent_key_scope")]
    pub scope: Value,
    pub state: String,
    pub created_at: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SolandAgentGrantDetachOutcome {
    pub ok: bool,
    pub agent_principal_id: String,
    pub grant_id: String,
    pub detached_at: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SolandAgentSidecarThreadEnsureRequestBody {
    #[serde(default)]
    pub agent_principal_id: Option<String>,
    #[serde(default)]
    pub context_realm_id: Option<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SolandAgentSidecarThreadEnsureOutcome {
    pub ok: bool,
    pub agent_principal_id: String,
    pub sidecar_circle_id: String,
    pub realm_id: String,
    pub created: bool,
    #[serde(default)]
    pub todos: Vec<String>,
}

// ── CKP-0010 (R3 spec-sync 2026-05-27, cokret-spec b47ff6ec) — media
// token exchange wire shapes. Mirrors `MediaTokenResponse` /
// `ParticipantBinding` in `cokret_sdk::media`; soland mints the
// soland-side ToSchema-friendly copies so salvo-oapi can pick them up.

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SolandCallMediaTokenExchangeRequestBody {
    pub realm_id: String,
    pub call_id: String,
    pub actor_id: String,
    pub device_id: String,
    /// Focus id chosen by the caller. MUST equal the committed
    /// `ck.call.state.session_focus`; otherwise the handler rejects with
    /// `focus_mismatch`.
    pub focus_id: String,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SolandCallMediaParticipantBinding {
    /// `ck.media.participant_binding.v1`.
    pub scheme: String,
    /// Detached signature over the canonical binding body.
    pub sig: String,
    /// Key identifier of the signing media-service key. Receivers MUST
    /// verify this resolves to the current
    /// `ck.realm.media_service.service_id` epoch (MEDIA-1).
    pub issuer_kid: String,
    pub realm_id: String,
    pub call_id: String,
    pub focus_id: String,
    pub actor_id: String,
    pub device_id: String,
    pub participant_identity: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SolandCallMediaTokenExchangeOutcome {
    pub backend_token: String,
    pub participant_identity: String,
    pub participant_binding: SolandCallMediaParticipantBinding,
    pub expires_at: DateTime<Utc>,
    pub service_signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_url: Option<String>,
    #[serde(default)]
    pub todos: Vec<String>,
}

// ── B-C (R3 spec-sync 2026-05-27, cokret-spec b47ff6ec) — recovery
// policy / receipt endpoint wire shapes. Wire-level scaffold only — the
// internal proof verifier is TODO(R3.1).

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SolandRecoveryPolicyRequestBody {
    /// `ck.schema.recovery_policy.v1`.
    pub schema: String,
    pub policy_id: String,
    /// `pending` | `active` | `retired`.
    pub lifecycle: String,
    pub epoch: u64,
    pub body: Value,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SolandRecoveryPolicyOutcome {
    pub ok: bool,
    pub policy_id: String,
    pub policy_version: u64,
    pub lifecycle: String,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SolandRecoveryReceiptRequestBody {
    /// `ck.schema.recovery_receipt.v1`.
    pub schema: String,
    pub recovery_session_id: String,
    pub policy_id: String,
    pub policy_epoch: u64,
    pub evidence: Value,
    pub bound_proof: Value,
    pub issued_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SolandRecoveryReceiptOutcome {
    pub ok: bool,
    pub recovery_session_id: String,
    pub policy_id: String,
    pub issued_at: DateTime<Utc>,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct CreateWebrtcSessionRequest {
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
pub struct CreateWebrtcSessionResponse {
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
pub struct WebrtcSignalRequest {
    pub message_type: String,
    #[serde(default)]
    pub seq: Option<u64>,
    #[serde(default)]
    pub payload: Value,
    #[serde(default)]
    pub proofs: Vec<Value>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct WebrtcSignalResponse {
    pub ok: bool,
    pub session_id: String,
    pub seq: u64,
    pub next_cursor: String,
    pub call_state: String,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct WebrtcSignalsResponse {
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
];

const SUPPORTED_STANDALONE_OPERATION_IDS: &[&str] = &[
    "ck.find.directory.describe",
    "ck.find.directory.search_realms",
    "ck.find.directory.resolve_realm",
    "ck.find.directory.resolve_target",
    "ck.self.blob.upload",
    "ck.self.blob.head",
    "ck.self.blob.get",
    "ck.self.keys.backups.put",
    "ck.self.keys.backups.list",
    "ck.self.keys.backups.get",
    "ck.self.keys.backups.delete",
];

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
            "reason": "outbound Move/Anchor fanout persists a signed intent and retry boundary per peer; actual RFC 9421 HTTP delivery is still not claimed"
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
    ]
}

fn full_principal_server_gap_summary() -> Vec<Value> {
    vec![json!({
        "profile": "ck.profile.principal_server.v1",
        "status": "not_claimed",
        "first_batch_landed": [
            "artifact-derived supported operation advertisement",
            "artifact drift tests for lattice family/kind/bottom mappings",
            "outbound Move/Anchor fanout signed intent evidence",
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

pub fn describe(
    service_did: &str,
    public_base_url: &str,
    storage: &'static str,
    development_mode: bool,
    oauth_introspection_enabled: bool,
    auth_server_url: Option<&str>,
    trust_domain: &str,
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
            ];
            // PROF-1 (R3 spec-sync 2026-05-27, cokret-spec b47ff6ec) —
            // advertise `ck.profile.media_service_binding.v1` whenever the
            // server exposes the `ck.self.call.media.token_exchange` handler.
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
            "ck.feature.soland.account.register".to_owned(),
            "ck.feature.soland.account.me".to_owned(),
            "ck.feature.soland.auth.logout".to_owned(),
            "ck.feature.soland.contacts.request".to_owned(),
            "ck.feature.soland.contacts.respond".to_owned(),
            "ck.feature.soland.space.lifecycle".to_owned(),
            "ck.feature.soland.schema.registry".to_owned(),
            "ck.feature.soland.events.describe".to_owned(),
            "ck.feature.soland.events.submit".to_owned(),
            "ck.feature.soland.events.read".to_owned(),
            "ck.feature.soland.federation.transaction".to_owned(),
            "ck.feature.soland.federation.operations".to_owned(),
            "ck.feature.soland.sync.client_sync".to_owned(),
            "ck.feature.soland.sync.bound_cursor".to_owned(),
            "ck.feature.soland.sync.incremental_since".to_owned(),
            "ck.feature.soland.sync.typing".to_owned(),
            "ck.feature.soland.sync.backfill".to_owned(),
            "ck.feature.soland.directory.search_realms".to_owned(),
            "ck.feature.soland.directory.resolve_realm".to_owned(),
            "ck.feature.soland.index.query".to_owned(),
            "ck.feature.soland.authz.check".to_owned(),
            "ck.feature.soland.profile.presence".to_owned(),
            "ck.feature.soland.push.register_device".to_owned(),
            "ck.feature.soland.push.rules".to_owned(),
            "ck.feature.soland.webrtc.signaling".to_owned(),
            "ck.feature.soland.blob.upload".to_owned(),
            "ck.feature.soland.blob.authenticated_download".to_owned(),
            "ck.feature.soland.blob.presigned_download.local_direct_serve".to_owned(),
            "ck.feature.soland.blob.upload_policy".to_owned(),
            "ck.feature.soland.federation.transaction_idempotency".to_owned(),
            "ck.feature.soland.policy.documents".to_owned(),
            "ck.feature.soland.moderation.report".to_owned(),
            "ck.feature.soland.mimi.provider_facade".to_owned(),
            "ck.feature.soland.mimi.discovery".to_owned(),
            "ck.feature.soland.mimi.key_material_receipt".to_owned(),
            "ck.feature.soland.mimi.room_projection".to_owned(),
            "ck.feature.soland.mimi.identifier_privacy".to_owned(),
            "ck.feature.soland.mimi.proxy_download_policy".to_owned(),
            "ck.feature.soland.registry.artifacts".to_owned(),
            "ck.feature.soland.plaintext_visible_services".to_owned(),
        ],
        supported_operations,
        // service-surface.md §3 documents `base_url` (typed `format: uri` in
        // service-describe.schema.json) as the connectable service base.
        // Emit the same public base URL used by the HTTP describe handler so
        // clients can build `base_url + operation_path` directly.
        supported_bindings: vec![
            serde_json::json!({"kind": "http_json", "base_url": public_base_url.trim_end_matches('/')}),
        ],
        supported_reducer_profiles: vec!["ck.reducer.v1".to_owned()],
        supported_schema_profiles: vec!["ck.schema.core.v1".to_owned()],
        auth_metadata,
        limits: serde_json::json!({
            "storage": storage,
            "max_limit": 100,
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

pub fn sync_token() -> String {
    let now = Utc::now();
    let expires_at = now + chrono::Duration::hours(1);
    let cursor = json!({
        "v": "1",
        "purpose": "stream",
        "t": now.to_rfc3339(),
        "x": expires_at.timestamp_millis(),
        "h": format!("wire:{}", now.timestamp_micros())
    });
    let bytes = cokret_sdk::canonical::canonical_json_bytes(&cursor)
        .unwrap_or_else(|_| cursor.to_string().into_bytes());
    format!("ck:cursor:{}", URL_SAFE_NO_PAD.encode(bytes))
}

pub fn now() -> DateTime<Utc> {
    Utc::now()
}

// ── Conversation Model DTOs ──

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct ReviseMessageRequest {
    pub event_id: String,
    pub content: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ReviseMessageResponse {
    pub event_id: String,
    pub revision_of: String,
    pub operation_id: String,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct RedactMessageRequest {
    pub event_id: String,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct RedactMessageResponse {
    pub redacted: bool,
    pub event_id: String,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct AddReactionRequest {
    pub event_id: String,
    pub key: String,
    pub realm_id: String,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ReactionResponse {
    pub event_id: String,
    pub actor: String,
    pub key: String,
    pub active: bool,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct RemoveReactionRequest {
    pub event_id: String,
    pub key: String,
    pub realm_id: String,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SetReadMarkerRequest {
    pub realm_id: String,
    pub read_scope: ReadScopeWire,
    pub position: ReadCursorPositionWire,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, salvo::oapi::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadScopeWire {
    pub kind: String,
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub object_ref: Option<String>,
    #[serde(rename = "track_name", skip_serializing_if = "Option::is_none")]
    pub track: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub track_scope: Option<ReadScopeTrackScopeWire>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, salvo::oapi::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReadScopeTrackScopeWire {
    All,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, salvo::oapi::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadCursorPositionWire {
    pub event_id: String,
    pub hlc: String,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ReadMarkerResponse {
    pub realm_id: String,
    pub actor_id: String,
    pub device_id: String,
    pub read_scope: ReadScopeWire,
    pub position: ReadCursorPositionWire,
    pub updated_at: String,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct GetReadMarkersRequest {
    pub realm_id: String,
}

// ── Relation DTOs ──
//
// Relation DTOs — `ck:relation:` is a registered typed-id in
// `cokret-spec/v1/artifacts/registry/id-kind-registry.json`.

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct CreateRelationRequest {
    pub realm_id: String,
    pub relation_kind: String,
    pub from: Option<String>,
    pub to: Option<String>,
    #[serde(default)]
    pub fields: BTreeMap<String, Value>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct RelationResponse {
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
pub struct ListRelationsRequest {
    pub realm_id: String,
    pub relation_kind: Option<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ListRelationsResponse {
    pub relations: Vec<RelationResponse>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct TombstoneRelationResponse {
    pub state: String,
    pub relation_id: String,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct CreateGrantResponse {
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
pub struct RevokeGrantResponse {
    pub revoked: bool,
    pub grant_id: String,
    /// Grant ids that flipped to revoked as part of this call's delegation
    /// cascade (does NOT include `grant_id` itself). capabilities.md §3.3.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cascade_revoked: Vec<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct CreateGrantRequest {
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
        );
        let value = serde_json::to_value(description).expect("description serializes");
        assert_eq!(
            value["supported_bindings"],
            json!([{"kind": "http_json", "base_url": "https://soland.example"}])
        );
        assert!(value["supported_bindings"][0].get("base_path").is_none());
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
