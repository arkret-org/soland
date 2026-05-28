use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use contrix_sdk::{ClaimedProfileEntry, ServerDescription};
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
    /// banner without having to scrape `/api/v1/server/describe`.
    pub development_mode: bool,
    /// String mirror of [`Self::development_mode`]: `"development"` when
    /// `development_mode == true`, `"production"` otherwise. The proof
    /// verifier path is gated on the same flag — dev mode currently
    /// accepts unsigned / weakly-signed envelopes.
    pub proof_verifier_mode: &'static str,
    /// Effective admin-API authentication posture:
    ///   - `"development"` — any authenticated session may call admin endpoints
    ///     (dev mode lets every session through)
    ///   - `"did_allowlist"` — production gate via `SOLAND_ADMIN_PRINCIPAL_DIDS`
    ///   - `"oauth_introspection"` — bearer tokens are introspected against
    ///     `SOLAND_OAUTH_INTROSPECTION_URL` (no admin allowlist configured)
    ///   - `"closed"` — production mode with no admin principals AND no
    ///     introspection configured; admin endpoints are effectively locked.
    pub admin_auth_mode: &'static str,
    /// T8.3 — non-sensitive production hardening checklist snapshot.
    /// Surfaced on `/health` so sodmin's `/hardening` dashboard can
    /// aggregate it across all services without scraping the more
    /// expensive describe payload.
    pub hardening: HardeningStatus,
}

/// T8.3 — production deployment hardening checklist snapshot.
///
/// Returned on `/health` and embedded in `/api/v1/server/describe`.
/// Every field is derived from runtime config; nothing is hand-set by
/// the operator. Booleans are intentionally coarse so we don't leak
/// configured paths, hostnames, or token tails — sodmin renders the
/// chips, the operator runs the actual probes.
#[derive(Debug, Clone, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct HardeningStatus {
    pub development_mode: bool,
    pub tls_enabled: bool,
    pub csp_header_configured: bool,
    pub cors_strict: bool,
    pub secret_manager_in_use: bool,
    pub log_redaction_enabled: bool,
    pub admin_auth_mode: String,
    pub rate_limit_enabled: bool,
    pub provider_credential_rotation: String,
    pub checklist_score: u32,
    pub checklist_max: u32,
    pub warnings: Vec<String>,
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
    pub principal_did_body_field: String,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct AuthBridgePushDescriptor {
    pub register_device_path: String,
    pub unregister_device_path: String,
    pub session_grant_header: String,
    pub principal_did_body_field: String,
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
pub struct AccountDescribeResBody {
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

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SearchRealmsRequest {
    pub query: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct DirectoryDescribeResBody {
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
    pub space_preview: RealmDirectoryEntry,
    pub stripped_state: Vec<Value>,
    pub join_rule: String,
    pub via_services: Vec<String>,
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
    #[serde(default)]
    pub space_id: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SearchUsersRequest {
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub space_id: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    /// Why the requester wants to enumerate users — gates anti-enumeration
    /// filtering. Spec 0a5ab85: `cx.directory.search_users` adds `intent`.
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
pub struct HandleClaim {
    pub schema: String,
    /// Canonical handle in the spec form `<localpart>:<domain>(:<port>)?`
    /// (handle-claim.schema.json#/properties/handle, contrix-spec @ 7157ee8).
    /// The retired `contrix://<domain>/users/<localpart>` URI form is gone
    /// from R3.1 wire — any `acct:<local>@<domain>` interop form is carried
    /// separately in [`Self::handle_aliases`], NEVER in this field.
    pub handle: String,
    /// Interop aliases normalized to the canonical [`Self::handle`] above.
    /// Includes `acct:<local>@<domain>` cross-publication. The retired
    /// `contrix://` URI form MUST NOT appear here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub handle_aliases: Vec<String>,
    pub subject: String,
    pub issuer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_service_did: Option<String>,
    pub binding_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub claim_scope: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_delivery_binding: Option<HandleClaimDeliveryBinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<Value>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<String>,
    pub proofs: Vec<HandleClaimProof>,
}

#[derive(Debug, Clone, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct HandleClaimDeliveryBinding {
    pub recipient_service_did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_service_type: Option<String>,
    pub binding_source: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delivery_modes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_acceptance_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct HandleClaimProof {
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
    pub actor: Value,
    /// Audience the claim is bound to (echoes the `audience` request param
    /// or the inferred default — typically the requester / target Space).
    /// Verifiers MUST reject claims whose audience does not match their
    /// invocation context. Spec 0a5ab85.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Embedded handle claim envelope when the resolver issued one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle_claim: Option<HandleClaim>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct IndexQueryRequest {
    #[serde(default)]
    pub space_ids: Vec<String>,
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
    pub space_ids: Vec<String>,
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
pub struct BackfillResBody {
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
pub struct EventsQueryPostRequest {
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
pub struct EventsFrontierResBody {
    pub actor_frontier: BTreeMap<String, u64>,
    pub realm_frontier: BTreeMap<String, Value>,
    /// Legacy internal frontier keyed by the pre-R1.2 `cx:space:*` realm
    /// mirror. Kept while old clients and persistence rows still use the
    /// internal scope key.
    pub space_frontier: BTreeMap<String, Value>,
    pub frontier: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SnapshotHeadResponse {
    pub snapshot_ref: String,
    pub state_digest: String,
    pub manifest: Value,
    pub chunks: Vec<Value>,
    pub frontier: Value,
    pub signature: Value,
    /// Snapshot v2: root of the binary Merkle tree built over chunk
    /// digests. Receivers cross-check `chunks[i].digest` reaching this
    /// root via the per-chunk `audit_path`.
    pub merkle_root: String,
    /// Snapshot v2: number of chunks in `chunks[]`. Equivalent to
    /// `generator_proof.chunk_count` but surfaced explicitly so clients
    /// don't have to parse the proof to plan fetches.
    pub chunk_count: u32,
    /// Snapshot v2: target per-chunk byte budget the chunker used. The
    /// last chunk MAY be smaller; all others are exactly this size.
    pub chunk_bytes: u32,
    /// Snapshot v2: sum of per-chunk byte lengths. Lets receivers size
    /// download buffers before fetching.
    pub total_bytes: u64,
    /// Snapshot v2: signed commitment from the snapshot generator
    /// binding `(generator_did, realm_id, state_root, merkle_root,
    /// chunk_count, total_bytes, chunk_bytes)`.
    pub generator_proof: Value,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct AuthzCheckReqBody {
    pub actor: String,
    pub action: String,
    pub resource: Value,
    #[serde(default)]
    pub context: Option<Value>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct AuthzCheckResBody {
    pub allowed: bool,
    pub reason_code: Option<String>,
    pub reason: Option<String>,
    pub grants: Vec<Value>,
    pub obligations: Vec<Value>,
    pub decision_trace: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct EffectiveGrantsResBody {
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
    pub principal_did: Option<String>,
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

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct PushNotifyReqBody {
    pub notification: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct PushNotifyResBody {
    pub rejected: Vec<Value>,
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

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct OkResBody {
    pub ok: bool,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct ModerationReportReqBody {
    #[serde(alias = "space_id")]
    pub realm_id: String,
    pub target_ref: String,
    pub reason: String,
    pub reporter: String,
    pub description: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ModerationReportResBody {
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
pub struct PolicyCheckReqBody {
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

/// Frontier binding stamped onto every signed `PolicyCheckResBody`.
///
/// The four hashes pin the decision to a concrete authz universe so a
/// client (or auditor) can detect that the decision is stale once any
/// of the four frontiers move:
///   - `realm_id` — scope this binding applies to (canonical
///     `cx:realm:<uuid>` form). May be empty string when the request
///     was realm-less (e.g. a global capability check).
///   - `auth_state_digest` — sha256 hex over canonical JSON
///     `{actor, action, resource, request_canonical_digest}`.
///   - `policy_frontier_digest` — sha256 hex over canonical JSON
///     `{policy_documents: [<sorted policy_ids>]}`.
///   - `membership_frontier_digest` — sha256 hex over canonical JSON
///     `{realm_id, members: [<sorted member DIDs>]}`.
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
pub struct PolicyCheckResBody {
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
    pub principal_did: String,
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
pub struct AccountResponse {
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
pub struct UpdateProfileRequest {
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
pub struct UpdateProfileResponse {
    pub did: String,
    pub handle: String,
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct ContactRequestRequest {
    pub target: String,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct ContactRespondRequest {
    pub requester: String,
    pub action: String,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ContactResponse {
    pub requester: String,
    pub target: String,
    pub scope: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ContactsResponse {
    pub contacts: Vec<ContactResponse>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct CreateSpaceRequest {
    pub title: String,
    pub summary: Option<String>,
    #[serde(default)]
    pub public: bool,
    #[serde(default)]
    pub discoverability: Option<String>,
    /// One of `shared` / `joined` / `invited` / `world_readable`. Defaults to
    /// `shared` for public spaces, `joined` otherwise.
    #[serde(default)]
    pub history_visibility: Option<String>,
    /// One of `plaintext` / `mls_rfc9420`. When `mls_rfc9420` the space
    /// CANNOT be `world_readable` (space-and-place.md §3.1.3).
    #[serde(default)]
    pub encryption_profile: Option<String>,
    #[serde(default)]
    pub plaintext_visible_services: Vec<String>,
    #[serde(default)]
    pub invitees: Vec<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct UpdateSpaceRequest {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub public: Option<bool>,
    #[serde(default)]
    pub discoverability: Option<String>,
    #[serde(default)]
    pub plaintext_visible_services: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SetSpacePolicyRequest {
    pub join_rule: String,
    pub history_visibility: String,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct AddSpaceMemberRequest {
    pub member: String,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct AcceptSpaceInviteRequest {
    pub invite_id: String,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct CreateSpaceInviteRequest {
    pub target: String,
    #[serde(default)]
    pub role: Option<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SpaceInviteResponse {
    pub ok: bool,
    pub invite_id: String,
    pub space_id: String,
    pub target: String,
    pub state: String,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct UpdateSpaceResponse {
    pub ok: bool,
    pub space_id: String,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SpacePolicyResponse {
    pub ok: bool,
    pub space_id: String,
    pub join_rule: String,
    pub history_visibility: String,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SpaceLifecycleResponse {
    pub ok: bool,
    pub space_id: String,
    pub owner: String,
    pub members: Vec<String>,
    pub deleted: bool,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SendMessageRequest {
    pub space_id: String,
    #[serde(default)]
    pub thread_id: Option<String>,
    pub content: Value,
    #[serde(default)]
    pub encrypted: bool,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IdentityDescribeResBody {
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
pub struct IdentityResolveReqBody {
    pub did: String,
    #[serde(default)]
    pub include: Vec<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IdentityLogResBody {
    pub events: Vec<Value>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IdentityReceiptsResBody {
    pub receipts: Vec<Value>,
    pub threshold_met: bool,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IdentityResolveResBody {
    pub did_document: Value,
    pub key_log_head: Option<String>,
    pub seq: u64,
    pub receipts: Vec<Value>,
    pub method_evidence: Value,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct KeysUploadReqBody {
    pub device_id: String,
    #[serde(default)]
    pub device_keys: Value,
    #[serde(default)]
    pub principal_signing_keys: Vec<Value>,
    #[serde(default)]
    pub recovery_keys: Vec<Value>,
    #[serde(default)]
    pub session_keys: Vec<Value>,
    #[serde(default)]
    pub agent_keys: Vec<Value>,
    #[serde(default)]
    pub one_time_keys: Vec<Value>,
    #[serde(default)]
    pub fallback_keys: Value,
    #[serde(default)]
    pub mls_key_packages: Vec<Value>,
    #[serde(default)]
    pub backup_restore_keys: Vec<Value>,
    #[serde(default)]
    pub device_signature: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct KeysUploadResBody {
    pub one_time_key_counts: Value,
    pub fallback_keys: Value,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct KeysQueryReqBody {
    pub device_keys: std::collections::BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct KeysQueryResBody {
    pub device_keys: Value,
    pub failures: Value,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct KeysClaimReqBody {
    pub one_time_keys:
        std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct KeysClaimResBody {
    pub one_time_keys: Value,
    pub failures: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct KeysBackupsPutResBody {
    pub ok: bool,
    pub backup: Value,
    pub state: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct KeysBackupsListResBody {
    pub backups: Vec<Value>,
    pub next_cursor: Option<String>,
    pub state: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct KeysBackupsDeleteResBody {
    pub ok: bool,
    pub backup_id: String,
    pub deleted: bool,
    pub state: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct DeviceMessagesSendReqBody {
    pub messages: std::collections::BTreeMap<String, std::collections::BTreeMap<String, Value>>,
}

// CXP-0008 / CXP-0009 (spec head 37ce729) — Personal Agent 11 operations.
//
// The shapes below carry the cross-project HTTP contract for sodmin /
// yougen / cotest; reducer-side semantics are P2-impl TODO stubs in
// `routing::events::agents`.

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct AgentKeyPairReqBody {
    pub agent_principal_id: String,
    pub verification_method: String,
    #[serde(default)]
    pub runtime_attestation: Option<Value>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct AgentKeyPairResBody {
    pub ok: bool,
    pub agent_principal_id: String,
    pub verification_method: String,
    pub authorized_at: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct AgentProvisionReqBody {
    pub display_name: String,
    #[serde(default)]
    pub controller_did: Option<String>,
    #[serde(default)]
    pub agent_did: Option<String>,
    #[serde(default)]
    pub initial_grants: Vec<Value>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct AgentResBody {
    pub agent_principal_id: String,
    pub controller_did: String,
    pub agent_did: String,
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
pub struct AgentListResBody {
    pub agents: Vec<AgentResBody>,
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct AgentLifecycleReqBody {
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct AgentLifecycleResBody {
    pub ok: bool,
    pub agent_principal_id: String,
    pub state: String,
    pub at: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct AgentRotateKeyReqBody {
    pub new_verification_method: String,
    #[serde(default)]
    pub previous_key_id: Option<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct AgentRotateKeyResBody {
    pub ok: bool,
    pub agent_principal_id: String,
    pub authorized_verification_method: String,
    pub revoked_verification_method: Option<String>,
    pub at: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct AgentGrantAttachReqBody {
    pub grant_kind: String,
    pub scope: Value,
    #[serde(default)]
    pub expires_at: Option<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct AgentGrantResBody {
    pub ok: bool,
    pub agent_principal_id: String,
    pub grant_id: String,
    pub grant_kind: String,
    pub scope: Value,
    pub state: String,
    pub created_at: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct AgentGrantDetachResBody {
    pub ok: bool,
    pub agent_principal_id: String,
    pub grant_id: String,
    pub detached_at: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct AgentSidecarThreadEnsureReqBody {
    #[serde(default)]
    pub context_realm_id: Option<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct AgentSidecarThreadEnsureResBody {
    pub ok: bool,
    pub agent_principal_id: String,
    pub sidecar_circle_id: String,
    pub realm_id: String,
    pub created: bool,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct DeviceMessagesSendResBody {
    pub ok: bool,
    pub delivered: Value,
    pub unknown_devices: Value,
}

// ── CXP-0010 (R3 spec-sync 2026-05-27, contrix-spec b47ff6ec) — media
// token exchange wire shapes. Mirrors `MediaTokenResponse` /
// `ParticipantBinding` in `contrix_sdk::media`; soland mints the
// soland-side ToSchema-friendly copies so salvo-oapi can pick them up.

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct MediaTokenExchangeReqBody {
    pub realm_id: String,
    pub call_id: String,
    pub actor_id: String,
    pub device_id: String,
    /// Focus id chosen by the caller. MUST equal the committed
    /// `cx.call.state.session_focus`; otherwise the handler rejects with
    /// `focus_mismatch`.
    pub focus_id: String,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ParticipantBindingResBody {
    /// `cx.media.participant_binding.v1`.
    pub scheme: String,
    /// Detached signature over the canonical binding body.
    pub sig: String,
    /// Key identifier of the signing media-service key. Receivers MUST
    /// verify this resolves to the current
    /// `cx.realm.media_service.service_id` epoch (MEDIA-1).
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
pub struct MediaTokenExchangeResBody {
    pub backend_token: String,
    pub participant_identity: String,
    pub participant_binding: ParticipantBindingResBody,
    pub expires_at: DateTime<Utc>,
    pub service_signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_url: Option<String>,
    #[serde(default)]
    pub todos: Vec<String>,
}

// ── B-C (R3 spec-sync 2026-05-27, contrix-spec b47ff6ec) — recovery
// policy / receipt endpoint wire shapes. Wire-level scaffold only — the
// internal proof verifier is TODO(R3.1).

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct RecoveryPolicyReqBody {
    /// `cx.schema.recovery_policy.v1`.
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
pub struct RecoveryPolicyResBody {
    pub ok: bool,
    pub policy_id: String,
    pub policy_version: u64,
    pub lifecycle: String,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct RecoveryReceiptReqBody {
    /// `cx.schema.recovery_receipt.v1`.
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
pub struct RecoveryReceiptResBody {
    pub ok: bool,
    pub recovery_session_id: String,
    pub policy_id: String,
    pub issued_at: DateTime<Utc>,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct DeviceMessagesReceiveResBody {
    pub events: Vec<Value>,
    pub next_cursor: Option<String>,
    pub limited: bool,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct CreateWebrtcSessionRequest {
    pub space_id: String,
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
    pub space_id: String,
    pub participants: Vec<String>,
    pub mode: String,
    pub recording_policy: String,
    pub call_state: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
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
pub struct BlobUploadResBody {
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
    "cx.directory.describe",
    "cx.directory.search_realms",
    "cx.directory.resolve_realm",
    "cx.blob.upload",
    "cx.blob.head",
    "cx.blob.get",
    "cx.keys.backups.put",
    "cx.keys.backups.list",
    "cx.keys.backups.get",
    "cx.keys.backups.delete",
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
    ]
}

fn full_principal_server_gap_summary() -> Vec<Value> {
    vec![json!({
        "profile": "cx.profile.principal_server.v1",
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

    // Round 4 (B1) — ServiceDescribe v2: 17 required top-level fields.
    // Implemented / claimed / verified profiles are partitioned per spec
    // service-surface.md §3.0; `verified_profiles` MUST be empty when
    // `development_mode=true`. The full T6.1 claim-level partition layer
    // in routing::system::describe::apply_claim_level_partition still
    // overrides these values on the JSON wire response — we keep typed
    // defaults here so out-of-tree typed consumers see the correct shape
    // and pass `ServerDescription::validate_v2`.
    // Round 4 — typed entries match `service-describe.schema.json`
    // (`claimed_profiles[*]`, `compat_surfaces[*]`). The routing-layer
    // `apply_claim_level_partition` reserialises these via the SDK types
    // below so the JSON wire shape and the typed surface can never drift.
    //
    // Profile catalogue per `contrix-spec/spec/v1/zh/conformance/conformance-profiles.md`
    // §1 / §7 / §8: a principal server self-claims the Event Store
    // interop floor AND the Principal Server + Principal Server Events
    // API stable-catalog profiles in addition to whatever interop
    // staging extensions it implements (MIMI here).
    let claimed_profiles = vec![
        ClaimedProfileEntry::self_claimed("cx.profile.core_event_store.v1"),
        ClaimedProfileEntry::self_claimed("cx.profile.principal_server.v1"),
        ClaimedProfileEntry::self_claimed("cx.profile.principal_server_events_api.v1"),
        ClaimedProfileEntry {
            notes: Some(
                "MIMI provider facade first round (not a full v1 core conformance claim)"
                    .to_owned(),
            ),
            ..ClaimedProfileEntry::self_claimed("cx.profile.mimi_interop.v1")
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
            .expect("trust_domain must be cx:trust_domain:<scope>"),
        service_type: "principal_server".to_owned(),
        protocol_version: contrix_sdk::PROTOCOL_VERSION.to_owned(),
        supported_profiles: {
            let mut profiles = vec![
                "cx.profile.core_event_store.v1".to_owned(),
                "cx.profile.principal_server.v1".to_owned(),
                "cx.profile.principal_server_events_api.v1".to_owned(),
                "cx.profile.mimi_interop.v1".to_owned(),
            ];
            // PROF-1 (R3 spec-sync 2026-05-27, contrix-spec b47ff6ec) —
            // advertise `cx.profile.media_service_binding.v1` whenever the
            // server exposes the `cx.call.media.token_exchange` handler.
            // soland mounts the handler unconditionally (see
            // `routing::interop::webrtc::contrix_router`), so the claim is
            // unconditional too.
            profiles.push("cx.profile.media_service_binding.v1".to_owned());
            // PROF-1 — `cx.profile.accountable_to.strict_reject.v1` is
            // gated by `SOLAND_ACCOUNTABLE_TO_STRICT_REJECT=true`.
            if matches!(
                std::env::var("SOLAND_ACCOUNTABLE_TO_STRICT_REJECT").as_deref(),
                Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes")
            ) {
                profiles.push("cx.profile.accountable_to.strict_reject.v1".to_owned());
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
        egress_network_policy: Some(contrix_sdk::EgressNetworkPolicy::deny_private_defaults()),
        supported_features: vec![
            "account.register".to_owned(),
            "account.me".to_owned(),
            "auth.logout".to_owned(),
            "contacts.request".to_owned(),
            "contacts.respond".to_owned(),
            "space.lifecycle".to_owned(),
            "schema.registry".to_owned(),
            "events.describe".to_owned(),
            "events.submit".to_owned(),
            "events.read".to_owned(),
            "federation.transaction".to_owned(),
            "federation.operations".to_owned(),
            "sync.client_sync".to_owned(),
            "sync.bound_cursor".to_owned(),
            "sync.incremental_since".to_owned(),
            "sync.typing".to_owned(),
            "sync.backfill".to_owned(),
            "directory.search_realms".to_owned(),
            "directory.resolve_realm".to_owned(),
            "index.query".to_owned(),
            "authz.check".to_owned(),
            "profile.presence".to_owned(),
            "push.register_device".to_owned(),
            "push.rules".to_owned(),
            "webrtc.signaling".to_owned(),
            "blob.upload".to_owned(),
            "blob.authenticated_download".to_owned(),
            "blob.upload_policy".to_owned(),
            "federation.transaction_idempotency".to_owned(),
            "policy.documents".to_owned(),
            "moderation.report".to_owned(),
            "mimi.provider_facade".to_owned(),
            "mimi.discovery".to_owned(),
            "mimi.key_material_receipt".to_owned(),
            "mimi.room_projection".to_owned(),
            "mimi.identifier_privacy".to_owned(),
            "mimi.proxy_download_policy".to_owned(),
            "registry.artifacts".to_owned(),
            "plaintext_visible_services".to_owned(),
        ],
        supported_operations,
        supported_bindings: vec![serde_json::json!({"kind": "http_json", "base_path": "/api/v1"})],
        supported_reducer_profiles: vec!["cx.reducer.v1".to_owned()],
        supported_schema_profiles: vec!["cx.schema.core.v1".to_owned()],
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
                "source": "contrix-spec/spec/v1/zh/conformance/scalability-constraints.md",
                "max_event_bytes": 65536,
                "max_events_batch_submit": 1,
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
                        "profile": "cx.profile.soland_limited_server.v1",
                        "status": "unsupported",
                        "reason": "limited profile is a limitation descriptor, not a conformance claim"
                    }
                ],
                "full_profiles_not_claimed": [
                    "cx.profile.principal_server.v1",
                    "cx.profile.directory_service.v1",
                    "cx.profile.identity_registry.v1",
                    "cx.profile.blob_node.v1"
                ],
                "principal_server_full_profile_gaps": full_principal_server_gap_summary(),
                "supported_operation_catalog": {
                    "source": "contrix-spec/spec/v1/artifacts/registry/operation-registry.json",
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
                        "contrix_signed_event_reducer",
                        "space_id",
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
        reducer_profile: Some("cx.reducer.v1".to_owned()),
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
    let bytes = contrix_sdk::canonical::canonical_json_bytes(&cursor)
        .unwrap_or_else(|_| cursor.to_string().into_bytes());
    format!("cx:cursor:{}", URL_SAFE_NO_PAD.encode(bytes))
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
    pub space_id: String,
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
    pub space_id: String,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SetReadMarkerRequest {
    pub realm_id: String,
    pub read_scope: ReadScopeWire,
    pub position: ReadCursorPositionWire,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, salvo::oapi::ToSchema)]
pub struct ReadScopeWire {
    pub kind: String,
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub object_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub track: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, salvo::oapi::ToSchema)]
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
    pub space_id: String,
}

// ── Relation DTOs ──
//
// Relation DTOs — `cx:relation:` is a registered typed-id in
// `contrix-spec/v1/artifacts/registry/id-kind-registry.json`.

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct CreateRelationRequest {
    pub space_id: String,
    pub relation_kind: String,
    pub from: Option<String>,
    pub to: Option<String>,
    #[serde(default)]
    pub fields: BTreeMap<String, Value>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct RelationResponse {
    pub relation_id: String,
    pub space_id: String,
    pub relation_kind: String,
    pub from: Option<String>,
    pub to: Option<String>,
    pub fields: BTreeMap<String, Value>,
    pub deleted: bool,
    pub created_at: String,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct ListRelationsRequest {
    pub space_id: String,
    pub relation_kind: Option<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ListRelationsResponse {
    pub relations: Vec<RelationResponse>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct DeleteRelationResponse {
    pub deleted: bool,
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
    pub space_id: String,
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
    fn handle_claim_serializes_spec_shape() {
        let claim = HandleClaim {
            schema: "cx.schema.handle_claim.v1".to_owned(),
            handle: "alice:acme.example".to_owned(),
            handle_aliases: vec!["acct:alice@acme.example".to_owned()],
            subject: "did:web:alice.example".to_owned(),
            issuer: "did:web:acme.example".to_owned(),
            issuer_service_did: Some("did:web:principal.acme.example".to_owned()),
            binding_state: "verified".to_owned(),
            claim_type: Some("organization_handle".to_owned()),
            visibility: Some("restricted".to_owned()),
            audience: Some("cx:realm:0196419b-0000-7000-8000-000000000000".to_owned()),
            challenge: None,
            claim_scope: BTreeMap::new(),
            member_delivery_binding: Some(HandleClaimDeliveryBinding {
                recipient_service_did: "did:web:principal.acme.example".to_owned(),
                recipient_service_type: Some("principal_server".to_owned()),
                binding_source: "organization_policy".to_owned(),
                delivery_modes: vec!["events".to_owned(), "sync".to_owned()],
                service_acceptance_ref: None,
                policy_ref: None,
            }),
            claims: Vec::new(),
            created_at: "2026-05-19T00:00:00Z".to_owned(),
            expires_at: Some("2026-08-19T00:00:00Z".to_owned()),
            verified_at: None,
            source_refs: Vec::new(),
            proofs: vec![HandleClaimProof {
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
        assert_eq!(value["schema"], "cx.schema.handle_claim.v1");
        assert_eq!(
            value["member_delivery_binding"]["recipient_service_did"],
            "did:web:principal.acme.example"
        );
        assert!(value.get("claim_scope").is_none());
        assert!(value.get("challenge").is_none());
    }
}
