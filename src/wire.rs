use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use contrix_sdk::{ServerDescription, SpaceSearchEntry};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::artifacts;

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
pub struct SyncDescribeResBody {
    pub service_did: String,
    pub supported_sync_profiles: Vec<String>,
    pub limits: Value,
    pub frontier: Value,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct ClientSyncRequest {
    pub since: Option<String>,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub renderer: Option<String>,
    #[serde(default)]
    pub facets: Vec<String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub filter: Option<Value>,
    #[serde(default)]
    pub set_presence: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct ClientSyncResponse {
    pub next_batch: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub spaces: BTreeMap<String, Value>,
    /// Spaces the viewer no longer has access to since the supplied
    /// `since` cursor — left rooms, kicks, bans, server-side
    /// deletions. The client uses this list to remove the Space from
    /// every per-space cache so incremental syncs reconcile with the
    /// server view without forcing a full `since=None` re-sync. Empty
    /// for full syncs (the client treats omission of an id from
    /// `spaces` as authoritative there).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub left_spaces: Vec<String>,
    #[serde(default)]
    pub to_device: Vec<Value>,
    #[serde(default)]
    pub account_data: Vec<Value>,
    #[serde(default)]
    pub device_lists: Value,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SetTypingRequest {
    pub space_id: String,
    #[serde(default)]
    pub scope_id: Option<String>,
    #[serde(default)]
    pub typing: bool,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SetTypingResponse {
    pub ok: bool,
    pub space_id: String,
    pub actor: String,
    pub typing: bool,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SearchSpacesRequest {
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
pub struct ResolveSpaceRequest {
    pub space_id: Option<String>,
    pub alias: Option<String>,
    pub invite_token: Option<String>,
    pub signed_link: Option<String>,
    #[serde(default)]
    pub requester: Option<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ResolveSpaceResponse {
    pub space_preview: SpaceSearchEntry,
    pub stripped_state: Vec<Value>,
    pub join_rule: String,
    pub via_services: Vec<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SearchSpacesResponse {
    pub results: Vec<SpaceSearchEntry>,
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
    /// Embedded handle claim envelope when the resolver issued one. The
    /// inner shape MUST conform to `handle-claim.schema.json`.
    /// TODO(spec-sync 0a5ab85): replace `Value` with the typed `HandleClaim`
    /// once soland depends on the new SDK model + signs the envelope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle_claim: Option<Value>,
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
    pub prev_batch: Option<String>,
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
pub struct EventBatchGetRequest {
    #[serde(default)]
    pub event_ids: Vec<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct EventBatchGetResponse {
    pub events: Vec<EventReadResponse>,
    pub missing: Vec<String>,
    pub unauthorized: Vec<String>,
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
    pub space_frontier: BTreeMap<String, Value>,
    pub frontier: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SnapshotHeadResponse {
    pub snapshot_ref: String,
    pub state_hash: String,
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
    /// binding `(generator_did, space_id, state_root, merkle_root,
    /// chunk_count, total_bytes, chunk_bytes)`. Wire shape matches
    /// `contrix_sdk::GeneratorProof`.
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
    pub state_hash: Option<String>,
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
    pub space_id: String,
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
    pub space_id: Option<String>,
    pub request_canonical_hash: String,
    pub action: String,
    pub actor: String,
    pub source: Value,
    #[serde(default)]
    pub event_preview: Option<Value>,
    #[serde(default)]
    pub auth_context: Option<Value>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct PolicyCheckResBody {
    pub decision: String,
    pub reason_code: String,
    pub policy_id: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub obligations: Vec<Value>,
    pub decision_trace: Value,
    pub signature: Value,
}

/// Flat error envelope returned by every soland error path.
///
/// `errcode` is the canonical wire-form code from
/// `contrix_core::error::KNOWN_ERROR_CODES`; `error` is the human-readable
/// message; `request_id` is an opaque correlation token. Additional fields
/// (`retry_after_ms`, `details`, etc.) MAY be stamped in `details` without
/// breaking existing clients.
#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ApiErrorDetail {
    pub errcode: String,
    pub error: String,
    pub request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub details: std::collections::BTreeMap<String, Value>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ApiError {
    pub ok: bool,
    pub error: ApiErrorDetail,
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

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct DeviceMessagesSendResBody {
    pub ok: bool,
    pub delivered: Value,
    pub unknown_devices: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct DeviceMessagesReceiveResBody {
    pub events: Vec<Value>,
    pub next_batch: Option<String>,
    pub limited: bool,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct CreateWebrtcSessionRequest {
    pub space_id: String,
    #[serde(default)]
    pub participants: Vec<String>,
    #[serde(default)]
    pub ttl_ms: Option<u64>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct CreateWebrtcSessionResponse {
    pub session_id: String,
    pub space_id: String,
    pub participants: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct WebrtcSignalRequest {
    pub message_type: String,
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
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct WebrtcSignalsResponse {
    pub session_id: String,
    pub events: Vec<Value>,
    pub next_cursor: String,
    pub limited: bool,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct BlobUploadResBody {
    pub blob_ref: String,
    pub size: usize,
    pub media_type: String,
    pub sha256: String,
    pub upload_receipt: Value,
}

const SUPPORTED_OPERATION_SURFACES: &[&str] = &[
    "service_discovery",
    "events_sync",
    "realtime_media",
    "authz_policy",
    "moderation_reports",
    "push",
    "mimi_interop",
];

const SUPPORTED_STANDALONE_OPERATION_IDS: &[&str] = &[
    "cx.directory.describe",
    "cx.directory.search_spaces",
    "cx.directory.resolve_space",
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

    ServerDescription {
        service_did: service_did.parse().expect("valid service DID"),
        service_type: "principal_server".to_owned(),
        protocol_version: "1.0".to_owned(),
        supported_profiles: vec!["cx.profile.mimi_interop.v1".to_owned()],
        supported_features: vec![
            "account.register".to_owned(),
            "account.me".to_owned(),
            "auth.logout".to_owned(),
            "contacts.request".to_owned(),
            "contacts.respond".to_owned(),
            "space.lifecycle".to_owned(),
            "messages.send".to_owned(),
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
            "directory.search_spaces".to_owned(),
            "directory.resolve_space".to_owned(),
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
    pub space_id: String,
    pub event_id: String,
    pub scope_id: Option<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ReadMarkerResponse {
    pub space_id: String,
    pub actor: String,
    pub scope_id: String,
    pub event_id: String,
    pub read_at: String,
}

/// C14 / read-receipts §2.4-2.5: ephemeral `cx.receipt.read` request body.
/// `flow_id` / `track` are optional per §2.4 — receipts on a Flow track are
/// scoped, top-level receipts are Space-wide. The Sync Service applies the
/// effective Space `read_receipt_policy` before fanout: `disclosure="disabled"`
/// → drop with 403 + `policy_violation`; `visibility="private"` → fanout
/// only to the original sender.
#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SendReadReceiptRequest {
    pub space_id: String,
    pub event_id: String,
    #[serde(default)]
    pub flow_id: Option<String>,
    #[serde(default)]
    pub track: Option<String>,
}

/// C14: ephemeral `cx.receipt.read` accepted-for-fanout response. Soland
/// returns this when the receipt passed policy gating; clients use the
/// `fanout` field to know whether they're broadcast (members) or
/// echoed-only (private — only sender will receive).
#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SendReadReceiptResponse {
    pub space_id: String,
    pub actor: String,
    pub event_id: String,
    pub fanout: String,
    pub received_at: String,
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
